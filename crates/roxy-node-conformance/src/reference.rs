//! A minimal in-memory control plane. It exists so the harness can test
//! itself and so a node can be developed against something that answers
//! every code in the spec. It keeps everything in memory, renders one fixed
//! config, and takes the actions a real control plane would decide on
//! (revoke, forget, require a feature, exhaust a quota) over a plain-HTTP
//! admin listener on the loopback interface.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::convert::Infallible;
use std::fmt::Write as _;
use std::io::Read;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, anyhow};
use bytes::Bytes;
use http::header::{AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE, ETAG, IF_NONE_MATCH};
use http::{HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls::RootCertStore;
use rustls::server::WebPkiClientVerifier;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde_json::{Value, json};
use time::format_description::well_known::Rfc3339;
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

use crate::ca::{NodeCa, node_id_from_cert};
use crate::harness::Hook;
use crate::protocol::{
    EnrolRequest, EnrolResponse, ErrorBody, FlowAck, FlowBatch, FlowSettings, Lease, NodeState,
    SecretValue,
};
use crate::{
    LEASE_REFRESH_AFTER_HEADER, LEASE_VALID_FOR_HEADER, NODE_STATE_HEADER, PREFIX, sha256_tag,
};

/// Tunables for the reference server. The defaults are small so the harness
/// can exceed `batch_max_bytes` cheaply.
#[derive(Debug, Clone)]
pub struct Options {
    pub bind: SocketAddr,
    pub admin_bind: SocketAddr,
    pub tokens: usize,
    pub cert_lifetime: Duration,
    pub renew_after: Duration,
    pub valid_for: Duration,
    pub refresh_after: Duration,
    pub flow: FlowSettings,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:0".parse().expect("literal"),
            admin_bind: "127.0.0.1:0".parse().expect("literal"),
            tokens: 5,
            cert_lifetime: Duration::from_hours(30 * 24),
            renew_after: Duration::from_hours(15 * 24),
            valid_for: Duration::from_mins(15),
            refresh_after: Duration::from_mins(5),
            flow: FlowSettings {
                ship: true,
                batch_max_bytes: 64 * 1024,
                batch_max_events: 1000,
                flush_interval_seconds: 5,
                spool_high_water_bytes: 64 * 1024 * 1024,
                on_high_water: "hold".to_owned(),
            },
        }
    }
}

/// The rendered config every node gets. Secret values are not in it: the
/// `secrets:` entry is sourceless and the lease supplies the value.
const CONFIG: &str = "listeners:\n  proxy: 0.0.0.0:8080\nsecrets:\n  github: {}\nrules:\n  - id: github\n    match: {host: api.github.com}\n    action: allow\n";

/// The largest request body the server reads before answering `413`.
const BODY_READ_CAP: usize = 8 * 1024 * 1024;

struct Node {
    features: Vec<String>,
    revoked: bool,
    forgotten: bool,
    required_features: Vec<String>,
    quota_exhausted: bool,
    /// Bumped by anything that changes the lease; the lease id is derived
    /// from it, so every id ever issued to the node is `node_id/v` for
    /// `v <= lease_version`.
    lease_version: u64,
    events: BTreeMap<u64, Value>,
}

struct State {
    opts: Options,
    ca: NodeCa,
    tokens: Mutex<HashSet<String>>,
    nodes: Mutex<HashMap<String, Node>>,
}

type Reply = Response<Full<Bytes>>;

fn reply_json(status: StatusCode, body: &impl serde::Serialize) -> Reply {
    let bytes = serde_json::to_vec(body).expect("serialisable");
    let mut res = Response::new(Full::new(Bytes::from(bytes)));
    *res.status_mut() = status;
    res.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    res
}

fn error(status: StatusCode, code: &str, message: impl Into<String>) -> Reply {
    reply_json(status, &ErrorBody::new(code, message))
}

fn unsupported(missing: Vec<String>) -> Reply {
    let body = ErrorBody {
        error: "unsupported".to_owned(),
        message: format!("node lacks: {}", missing.join(", ")),
        missing: Some(missing),
    };
    reply_json(StatusCode::UPGRADE_REQUIRED, &body)
}

fn rfc3339(t: time::OffsetDateTime) -> String {
    t.format(&Rfc3339).expect("rfc3339")
}

fn random_id(prefix: &str) -> String {
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; 6];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .expect("system random");
    let mut id = prefix.to_owned();
    for b in bytes {
        let _ = write!(id, "{b:02x}");
    }
    id
}

impl State {
    fn lease_id(node_id: &str, version: u64) -> String {
        format!("{node_id}/{version}")
    }

    fn render_lease(&self, node_id: &str, node: &Node) -> Lease {
        let mut secrets = BTreeMap::new();
        secrets.insert(
            "github".to_owned(),
            SecretValue::Text("ghp_example".to_owned()),
        );
        Lease {
            lease_id: Self::lease_id(node_id, node.lease_version),
            issued_at: rfc3339(time::OffsetDateTime::now_utc()),
            valid_for_seconds: self.opts.valid_for.as_secs(),
            refresh_after_seconds: self.opts.refresh_after.as_secs(),
            config: CONFIG.to_owned(),
            config_hash: sha256_tag(CONFIG.as_bytes()),
            secrets,
            secrets_hash: format!("v{}", node.lease_version),
            state_epoch: "epoch-1".to_owned(),
            flow: self.opts.flow.clone(),
        }
    }

    fn issue(&self, node_id: &str, req: &EnrolRequest) -> Result<EnrolResponse, Box<Reply>> {
        let lifetime = time::Duration::try_from(self.opts.cert_lifetime).map_err(|_| {
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "lifetime out of range",
            )
        })?;
        let issued = self
            .ca
            .issue_node(&req.csr, node_id, lifetime)
            .map_err(|e| Box::new(error(StatusCode::BAD_REQUEST, "invalid_csr", e.to_string())))?;
        Ok(EnrolResponse {
            node_id: node_id.to_owned(),
            certificate_chain: issued.chain_pem,
            not_after: rfc3339(issued.not_after),
            renew_after_seconds: self.opts.renew_after.as_secs(),
        })
    }

    fn enrol(&self, bearer: Option<&str>, body: &[u8]) -> Reply {
        let Some(token) = bearer else {
            return error(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "missing bearer token",
            );
        };
        let req: EnrolRequest = match serde_json::from_slice(body) {
            Ok(r) => r,
            Err(e) => return error(StatusCode::BAD_REQUEST, "invalid_request", e.to_string()),
        };
        if req.protocol_version != 1 {
            return unsupported(vec!["protocol_version:1".to_owned()]);
        }
        // The token is only consumed by a successful enrolment, so validate
        // the request before taking it.
        if !self.tokens.lock().expect("lock").contains(token) {
            return error(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "enrolment token unknown or used",
            );
        }
        let node_id = random_id("node-");
        let res = match self.issue(&node_id, &req) {
            Ok(r) => r,
            Err(reply) => return *reply,
        };
        if !self.tokens.lock().expect("lock").remove(token) {
            return error(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "enrolment token unknown or used",
            );
        }
        self.nodes.lock().expect("lock").insert(
            node_id,
            Node {
                features: req.features,
                revoked: false,
                forgotten: false,
                required_features: Vec::new(),
                quota_exhausted: false,
                lease_version: 1,
                events: BTreeMap::new(),
            },
        );
        reply_json(StatusCode::OK, &res)
    }

    /// Resolve the client certificate to a live node, or the reply that says
    /// why not.
    fn authenticate(&self, peer: Option<&str>) -> Result<String, Box<Reply>> {
        let Some(node_id) = peer else {
            return Err(Box::new(error(
                StatusCode::UNAUTHORIZED,
                "no_certificate",
                "a node certificate is required",
            )));
        };
        let nodes = self.nodes.lock().expect("lock");
        match nodes.get(node_id) {
            None => Err(Box::new(error(
                StatusCode::UNAUTHORIZED,
                "unknown_node",
                "certificate is not a known node",
            ))),
            Some(n) if n.forgotten => Err(Box::new(error(
                StatusCode::UNAUTHORIZED,
                "unknown_node",
                "certificate is not a known node",
            ))),
            Some(n) if n.revoked => Err(Box::new(error(
                StatusCode::GONE,
                "revoked",
                "this node is revoked",
            ))),
            Some(_) => Ok(node_id.to_owned()),
        }
    }

    fn renew(&self, node_id: &str, body: &[u8]) -> Reply {
        let req: EnrolRequest = match serde_json::from_slice(body) {
            Ok(r) => r,
            Err(e) => return error(StatusCode::BAD_REQUEST, "invalid_request", e.to_string()),
        };
        if req.protocol_version != 1 {
            return unsupported(vec!["protocol_version:1".to_owned()]);
        }
        match self.issue(node_id, &req) {
            Ok(res) => {
                if let Some(n) = self.nodes.lock().expect("lock").get_mut(node_id) {
                    n.features = req.features;
                }
                reply_json(StatusCode::OK, &res)
            }
            Err(reply) => *reply,
        }
    }

    fn lease(&self, node_id: &str, req: &Request<Incoming>) -> Reply {
        let state: NodeState = match req
            .headers()
            .get(NODE_STATE_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(serde_json::from_str)
        {
            Some(Ok(s)) => s,
            Some(Err(e)) => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "invalid_state",
                    format!("roxy-node-state: {e}"),
                );
            }
            None => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "invalid_state",
                    "roxy-node-state header missing",
                );
            }
        };
        if state.protocol_version != 1 {
            return unsupported(vec!["protocol_version:1".to_owned()]);
        }
        let mut nodes = self.nodes.lock().expect("lock");
        let Some(node) = nodes.get_mut(node_id) else {
            return error(
                StatusCode::UNAUTHORIZED,
                "unknown_node",
                "certificate is not a known node",
            );
        };
        node.features = state.features;
        let missing: Vec<String> = node
            .required_features
            .iter()
            .filter(|f| !node.features.contains(f))
            .cloned()
            .collect();
        if !missing.is_empty() {
            return unsupported(missing);
        }
        let lease = self.render_lease(node_id, node);
        let etag = format!("\"{}\"", lease.lease_id);
        let unchanged = req
            .headers()
            .get(IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == etag);
        if unchanged {
            let mut res = Response::new(Full::new(Bytes::new()));
            *res.status_mut() = StatusCode::NOT_MODIFIED;
            let h = res.headers_mut();
            h.insert(ETAG, HeaderValue::from_str(&etag).expect("etag"));
            h.insert(
                LEASE_VALID_FOR_HEADER,
                HeaderValue::from(lease.valid_for_seconds),
            );
            h.insert(
                LEASE_REFRESH_AFTER_HEADER,
                HeaderValue::from(lease.refresh_after_seconds),
            );
            return res;
        }
        let mut res = reply_json(StatusCode::OK, &lease);
        res.headers_mut()
            .insert(ETAG, HeaderValue::from_str(&etag).expect("etag"));
        res
    }

    fn flows(&self, node_id: &str, body: &[u8]) -> Reply {
        let mut nodes = self.nodes.lock().expect("lock");
        let Some(node) = nodes.get_mut(node_id) else {
            return error(
                StatusCode::UNAUTHORIZED,
                "unknown_node",
                "certificate is not a known node",
            );
        };
        if body.len() as u64 > self.opts.flow.batch_max_bytes {
            return error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "batch_too_large",
                format!(
                    "batch is {} bytes; limit {}",
                    body.len(),
                    self.opts.flow.batch_max_bytes
                ),
            );
        }
        let batch: FlowBatch = match serde_json::from_slice(body) {
            Ok(b) => b,
            Err(e) => return error(StatusCode::BAD_REQUEST, "invalid_request", e.to_string()),
        };
        if batch.node_id != node_id {
            return error(
                StatusCode::BAD_REQUEST,
                "node_mismatch",
                "node_id does not match the certificate",
            );
        }
        let known_lease = batch
            .lease_id
            .strip_prefix(&format!("{node_id}/"))
            .and_then(|v| v.parse::<u64>().ok())
            .is_some_and(|v| v >= 1 && v <= node.lease_version);
        if !known_lease {
            return error(
                StatusCode::BAD_REQUEST,
                "unknown_lease",
                "lease_id was never issued to this node",
            );
        }
        if batch.events.is_empty() {
            return error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "events is empty",
            );
        }
        let mut expected = batch.seq_first;
        for ev in &batch.events {
            let seq = ev.get("seq").and_then(Value::as_u64);
            if seq != Some(expected) {
                return error(
                    StatusCode::BAD_REQUEST,
                    "bad_sequence",
                    format!("expected seq {expected}, got {seq:?}"),
                );
            }
            expected = expected.saturating_add(1);
        }
        if node.quota_exhausted {
            return error(
                StatusCode::INSUFFICIENT_STORAGE,
                "quota_exhausted",
                "flow quota exhausted for this node",
            );
        }
        for ev in batch.events {
            let seq = ev
                .get("seq")
                .and_then(Value::as_u64)
                .expect("checked above");
            node.events.entry(seq).or_insert(ev);
        }
        let acked_through = node.events.keys().next_back().copied().unwrap_or(0);
        reply_json(StatusCode::OK, &FlowAck { acked_through })
    }

    fn admin(&self, body: &[u8]) -> Reply {
        let v: Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(e) => return error(StatusCode::BAD_REQUEST, "invalid_request", e.to_string()),
        };
        let action = v.get("action").and_then(Value::as_str).unwrap_or("");
        let node_id = v.get("node_id").and_then(Value::as_str).unwrap_or("");
        let argument = v.get("argument").and_then(Value::as_str);
        match self.control(action, node_id, argument) {
            Ok(()) => reply_json(StatusCode::OK, &json!({})),
            Err(e) => error(StatusCode::BAD_REQUEST, "admin_failed", e.to_string()),
        }
    }

    fn control(&self, action: &str, node_id: &str, argument: Option<&str>) -> anyhow::Result<()> {
        let mut nodes = self.nodes.lock().expect("lock");
        let node = nodes
            .get_mut(node_id)
            .ok_or_else(|| anyhow!("unknown node {node_id}"))?;
        match action {
            "revoke" => node.revoked = true,
            "forget" => node.forgotten = true,
            "require-feature" => {
                let feature =
                    argument.ok_or_else(|| anyhow!("require-feature needs a feature name"))?;
                node.required_features.push(feature.to_owned());
                node.lease_version += 1;
            }
            "exhaust-flow-quota" => node.quota_exhausted = true,
            "re-lease" => node.lease_version += 1,
            other => return Err(anyhow!("unknown action {other}")),
        }
        Ok(())
    }
}

async fn read_body(req: Request<Incoming>) -> Result<(http::request::Parts, Vec<u8>), Box<Reply>> {
    let (parts, body) = req.into_parts();
    let gzip = parts
        .headers
        .get(CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("gzip"));
    let mut collected = Vec::new();
    let mut body = body;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| {
            Box::new(error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                e.to_string(),
            ))
        })?;
        if let Some(data) = frame.data_ref() {
            collected.extend_from_slice(data);
            if collected.len() > BODY_READ_CAP {
                return Err(Box::new(error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "batch_too_large",
                    "body exceeds read cap",
                )));
            }
        }
    }
    if gzip {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(&collected[..])
            .take(BODY_READ_CAP as u64 + 1)
            .read_to_end(&mut out)
            .map_err(|e| {
                Box::new(error(
                    StatusCode::BAD_REQUEST,
                    "invalid_encoding",
                    e.to_string(),
                ))
            })?;
        if out.len() > BODY_READ_CAP {
            return Err(Box::new(error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "batch_too_large",
                "body exceeds read cap",
            )));
        }
        collected = out;
    }
    Ok((parts, collected))
}

async fn route(state: Arc<State>, peer: Option<String>, req: Request<Incoming>) -> Reply {
    let path = req.uri().path().strip_prefix(PREFIX).map(str::to_owned);
    match (req.method().clone(), path.as_deref()) {
        (Method::POST, Some("/enrol")) => {
            let bearer = req
                .headers()
                .get(AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .map(str::to_owned);
            match read_body(req).await {
                Ok((_, body)) => state.enrol(bearer.as_deref(), &body),
                Err(reply) => *reply,
            }
        }
        (Method::POST, Some("/renew")) => match state.authenticate(peer.as_deref()) {
            Ok(node_id) => match read_body(req).await {
                Ok((_, body)) => state.renew(&node_id, &body),
                Err(reply) => *reply,
            },
            Err(reply) => *reply,
        },
        (Method::GET, Some("/lease")) => match state.authenticate(peer.as_deref()) {
            Ok(node_id) => state.lease(&node_id, &req),
            Err(reply) => *reply,
        },
        (Method::POST, Some("/flows")) => match state.authenticate(peer.as_deref()) {
            Ok(node_id) => match read_body(req).await {
                Ok((_, body)) => state.flows(&node_id, &body),
                Err(reply) => *reply,
            },
            Err(reply) => *reply,
        },
        _ => error(StatusCode::NOT_FOUND, "not_found", "no such endpoint"),
    }
}

/// A running reference server. Dropping it stops the listeners.
pub struct Server {
    url: String,
    admin_url: String,
    ca_pem: String,
    tokens: Vec<String>,
    state: Arc<State>,
    tasks: JoinSet<()>,
}

impl Server {
    pub async fn start(opts: Options) -> anyhow::Result<Self> {
        let ca = NodeCa::new("roxy-node-conformance CA")?;
        let (server_pem, server_key) = ca.issue_server(&["localhost", "127.0.0.1"])?;
        let tokens: Vec<String> = (0..opts.tokens).map(|_| random_id("tok-")).collect();
        let state = Arc::new(State {
            tokens: Mutex::new(tokens.iter().cloned().collect()),
            nodes: Mutex::new(HashMap::new()),
            ca,
            opts: opts.clone(),
        });

        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(state.ca.cert_der()))
            .context("add CA root")?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier =
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .allow_unauthenticated()
                .build()
                .context("client verifier")?;
        let chain = CertificateDer::pem_slice_iter(server_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .context("server cert pem")?;
        let key = PrivateKeyDer::from_pem_slice(server_key.serialize_pem().as_bytes())
            .context("server key pem")?;
        let mut tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .context("tls versions")?
            .with_client_cert_verifier(verifier)
            .with_single_cert(chain, key)
            .context("server identity")?;
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(tls));

        let tcp = TcpListener::bind(opts.bind).await.context("bind")?;
        let addr = tcp.local_addr()?;
        let admin_tcp = TcpListener::bind(opts.admin_bind)
            .await
            .context("bind admin")?;
        let admin_addr = admin_tcp.local_addr()?;

        let mut tasks = JoinSet::new();
        tasks.spawn(serve_tls(tcp, acceptor, state.clone()));
        tasks.spawn(serve_admin(admin_tcp, state.clone()));

        Ok(Self {
            url: format!("https://{addr}"),
            admin_url: format!("http://{admin_addr}/"),
            ca_pem: state.ca.cert_pem(),
            tokens,
            state,
            tasks,
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn admin_url(&self) -> &str {
        &self.admin_url
    }

    /// PEM of the CA that signs both the server certificate and node
    /// certificates: the node's bootstrap CA bundle.
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    pub fn tokens(&self) -> &[String] {
        &self.tokens
    }

    /// An in-process hook for the harness.
    pub fn hook(&self) -> Arc<dyn Hook> {
        Arc::new(InProcessHook(self.state.clone()))
    }

    /// Run until the listeners stop (they do not on their own).
    pub async fn run(mut self) {
        while self.tasks.join_next().await.is_some() {}
    }
}

struct InProcessHook(Arc<State>);

impl Hook for InProcessHook {
    fn call(
        &self,
        action: String,
        node_id: String,
        argument: Option<String>,
    ) -> std::pin::Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + '_>> {
        let r = self.0.control(&action, &node_id, argument.as_deref());
        Box::pin(async move { r })
    }
}

async fn serve_tls(tcp: TcpListener, acceptor: TlsAcceptor, state: Arc<State>) {
    loop {
        let Ok((stream, _)) = tcp.accept().await else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let acceptor = acceptor.clone();
        let state = state.clone();
        tokio::spawn(async move {
            let Ok(tls) = acceptor.accept(stream).await else {
                return;
            };
            let peer = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certs| certs.first())
                .and_then(|c| node_id_from_cert(c));
            let svc = service_fn(move |req| {
                let state = state.clone();
                let peer = peer.clone();
                async move { Ok::<_, Infallible>(route(state, peer, req).await) }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(tls), svc)
                .await;
        });
    }
}

async fn serve_admin(tcp: TcpListener, state: Arc<State>) {
    loop {
        let Ok((stream, _)) = tcp.accept().await else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let state = state.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req: Request<Incoming>| {
                let state = state.clone();
                async move {
                    let reply = if req.method() == Method::POST {
                        match read_body(req).await {
                            Ok((_, body)) => state.admin(&body),
                            Err(reply) => *reply,
                        }
                    } else {
                        error(
                            StatusCode::METHOD_NOT_ALLOWED,
                            "method_not_allowed",
                            "POST a JSON action",
                        )
                    };
                    Ok::<_, Infallible>(reply)
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), svc)
                .await;
        });
    }
}
