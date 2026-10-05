//! In-process test harness: a whole roxy [`Server`] with no bound
//! listeners, client connections over in-memory duplexes, and a scripted
//! upstream reached through the connector's test dial (after real DNS
//! overrides, the real address floor and real upstream TLS).
//!
//! ```text
//!   test client ──duplex──▶ conn::serve_explicit ─▶ … ─▶ Connector ──TestDial──▶ scripted upstream
//! ```
//!
//! * Names: `up.test` resolves to a public test address, `private.test` to a
//!   private one (denied by the floor unless `private_ok`), `down.test` to
//!   an address that refuses connections.
//! * The upstream answers by path (see [`upstream_answer`]) and records what
//!   reached it ([`Seen`]): the head, the body bytes, and whether the body
//!   completed or was cut.
//! * Flow events go to a [`MemorySink`]; [`MemorySink::wait_for`] waits on
//!   emits instead of polling.

#![allow(dead_code)]

#[cfg(test)]
mod addon_tests;
#[cfg(test)]
mod coding_tests;
#[cfg(test)]
mod core_tests;
#[cfg(test)]
mod direct_tests;
#[cfg(test)]
mod early_tests;
mod upstream;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::BodyExt as _;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use roxy_http::{Body, BodySender, HttpFlags, Limits};
use roxy_rules::{DefaultDecision, Policy, PolicyInput, RuleConfig};
use roxy_tls::{Ca, LeafMinter, UpstreamTlsOptions};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use ulid::Ulid;

#[allow(unused_imports)]
pub(crate) use upstream::{Seen, Upstream};

use crate::Server;
use crate::addons::{AddonMode, AddonSpec, StateLimits};
use crate::config::{PolicyUpdate, RuntimeConfig};
use crate::flowlog::{MemorySink, Redactor};
use crate::listener::{ClientConn, ListenerInfo, ListenerMode};
use crate::sources::{MetricSource, StateSource, UnavailableMetrics, UnavailableState};
use crate::upstream::{TestDial, UpstreamSettings};

/// The scripted upstream's public address (`up.test`).
pub(crate) const UP_IP: &str = "93.184.215.14";
/// A private address (`private.test`): the floor denies it without
/// `private_ok`.
pub(crate) const PRIVATE_IP: &str = "10.0.0.5";
/// An address whose dial is refused (`down.test`).
pub(crate) const DOWN_IP: &str = "93.184.215.99";
/// An address that accepts and reads but never answers (`stall.test`).
pub(crate) const STALL_IP: &str = "93.184.215.77";

/// Allows everything to `up.test`.
pub(crate) const ALLOW_UP: &str = r#"
- id: up
  when: host == "up.test"
  then: allow
"#;

/// The roxy-wasm test layer (`crates/roxy-wasm/test-components`).
pub(crate) const TEST_LAYER: &[u8] =
    include_bytes!("../../../roxy-wasm/tests/fixtures/test_layer.wasm");

/// One addon of the stack under test.
#[derive(Clone)]
pub(crate) struct AddonDef {
    pub name: String,
    pub wasm: &'static [u8],
    pub mode: AddonMode,
    pub caps: Vec<roxy_wasm::Capability>,
    pub config: serde_json::Value,
    pub limits: roxy_wasm::LayerLimits,
    pub when: Option<String>,
    pub sample: Option<f64>,
}

impl AddonDef {
    /// The test layer, named `name` (it reads `x-test-<name>` first).
    pub(crate) fn test_layer(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            wasm: TEST_LAYER,
            mode: AddonMode::Enforce,
            caps: Vec::new(),
            config: serde_json::json!({ "name": name }),
            limits: roxy_wasm::LayerLimits::default(),
            when: None,
            sample: None,
        }
    }

    #[must_use]
    pub(crate) fn observe(mut self) -> Self {
        self.mode = AddonMode::Observe;
        self
    }

    /// Runs only on requests `when` matches.
    #[must_use]
    pub(crate) fn when(mut self, when: &str) -> Self {
        self.when = Some(when.to_owned());
        self
    }

    /// Gets a copy of this share of exchanges (observe mode).
    #[must_use]
    pub(crate) fn sample(mut self, p: f64) -> Self {
        self.sample = Some(p);
        self
    }

    async fn load(self, rt: &roxy_wasm::WasmRuntime, input: &PolicyInput<'_>) -> Arc<AddonSpec> {
        let when = self.when.as_deref().map(|w| {
            roxy_rules::Condition::compile(input, &format!("{}.when", self.name), w)
                .unwrap_or_else(|d| panic!("when: {d:?}"))
        });
        let layer = roxy_wasm::Layer::load(
            rt,
            self.wasm.to_vec(),
            roxy_wasm::LayerConfig {
                name: self.name.clone(),
                capabilities: self.caps.into_iter().collect(),
                limits: self.limits,
                config_json: self.config.to_string(),
            },
        )
        .await
        .unwrap_or_else(|e| panic!("loading addon {}: {e}", self.name));
        Arc::new(AddonSpec {
            name: self.name,
            mode: self.mode,
            kind: crate::addons::AddonImpl::Wasm(layer),
            endpoints: HashMap::new(),
            state: StateLimits::default(),
            audit_endpoint: None,
            when,
            sample: self.sample,
        })
    }
}

/// Builds a [`Kit`].
pub(crate) struct KitBuilder {
    rules: String,
    addons: Vec<AddonDef>,
    limits: Limits,
    flags: HttpFlags,
    metrics: Arc<dyn MetricSource>,
    /// `metrics:` definitions (YAML); a real metric store holds them.
    metric_defs: String,
    state: Arc<dyn StateSource>,
    /// Capture every forwarded exchange into the kit's capture log.
    capture_all: bool,
}

impl KitBuilder {
    /// Opens a capture log that takes every forwarded exchange.
    #[must_use]
    pub(crate) fn capture_all(mut self) -> Self {
        self.capture_all = true;
        self
    }

    #[must_use]
    pub(crate) fn rules(mut self, yaml: &str) -> Self {
        yaml.clone_into(&mut self.rules);
        self
    }

    #[must_use]
    pub(crate) fn addon(mut self, a: AddonDef) -> Self {
        self.addons.push(a);
        self
    }

    #[must_use]
    pub(crate) fn limits(mut self, f: impl FnOnce(&mut Limits)) -> Self {
        f(&mut self.limits);
        self
    }

    #[must_use]
    pub(crate) fn flags(mut self, f: impl FnOnce(&mut HttpFlags)) -> Self {
        f(&mut self.flags);
        self
    }

    /// The metric store (default: none, every read unavailable).
    #[must_use]
    pub(crate) fn metrics(mut self, m: Arc<dyn MetricSource>) -> Self {
        self.metrics = m;
        self
    }

    /// Metric definitions (YAML, as under `metrics:`), held in a real
    /// metric store.
    #[must_use]
    pub(crate) fn metric_defs(mut self, yaml: &str) -> Self {
        yaml.clone_into(&mut self.metric_defs);
        self
    }

    /// The state store (default: none, every write fails).
    #[must_use]
    pub(crate) fn state(mut self, s: Arc<dyn StateSource>) -> Self {
        self.state = s;
        self
    }

    pub(crate) async fn start(self) -> Kit {
        roxy_tls::install_crypto_provider();
        let dir = tempfile::tempdir().unwrap();
        let ca = Arc::new(Ca::generate(dir.path()).unwrap());
        let minter = Arc::new(LeafMinter::new(ca.clone(), 64).unwrap());
        let sink = Arc::new(MemorySink::new());
        let upstream = Upstream::new(minter.clone());

        let rules: Vec<RuleConfig> = serde_yaml_ng::from_str(&self.rules).unwrap();
        let metric_defs: Vec<roxy_rules::MetricConfig> = if self.metric_defs.is_empty() {
            Vec::new()
        } else {
            serde_yaml_ng::from_str(&self.metric_defs).unwrap()
        };
        let none = std::collections::HashSet::new();
        let input = PolicyInput {
            rules: &rules,
            metrics: &metric_defs,
            secret_names: &none,
            address_lists: &none,
            transparent_listeners: false,
            default: DefaultDecision::Deny,
        };
        let policy = Policy::compile(&input).unwrap_or_else(|d| panic!("rules: {d:?}"));

        let metrics: Arc<dyn MetricSource> = if metric_defs.is_empty() {
            self.metrics
        } else {
            Arc::new(StoreMetrics(roxy_rules::MetricStore::new(
                policy.metric_defs(),
                1000,
            )))
        };

        let rt = roxy_wasm::WasmRuntime::new().unwrap();
        let mut addons = Vec::new();
        for a in self.addons {
            addons.push(a.load(&rt, &input).await);
        }

        let settings = upstream_settings(&upstream);
        let (limits, flags) = (self.limits.clone(), self.flags.clone());
        let capture = self
            .capture_all
            .then(|| Arc::new(capture_all_log(&dir.path().join("capture"))));
        let server = Server::start(RuntimeConfig {
            listeners: Vec::new(),
            ca_server: None,
            dns: None,
            ca: ca.clone(),
            minter,
            require_sni_match: true,
            enable_h2: true,
            upstream_tls: UpstreamTlsOptions {
                extra_roots_pem: vec![dir.path().join(roxy_tls::CA_CERT_FILE)],
                ..UpstreamTlsOptions::default()
            },
            max_connections: 1024,
            max_connections_per_client: 1024,
            connection_events: false,
            ws_message_every: 0,
            sink: sink.clone(),
            capture: capture.clone(),
            metrics,
            state: self.state,
            policy: PolicyUpdate {
                policy,
                secrets: HashMap::new(),
                redactor: Redactor::new(),
                users: HashMap::new(),
                limits: self.limits,
                flags: self.flags,
                upstream: settings.clone(),
                address_lists: Arc::new(HashMap::new()),
                deny_lists: Vec::new(),
                addons,
            },
        })
        .await
        .unwrap();
        Kit {
            server,
            sink,
            upstream,
            capture,
            ca_file: dir.path().join(roxy_tls::CA_CERT_FILE),
            limits,
            flags,
            settings,
            _dir: dir,
        }
    }
}

/// A running roxy with its scripted upstream and flow log.
pub(crate) struct Kit {
    pub server: Server,
    pub sink: Arc<MemorySink>,
    pub upstream: Arc<Upstream>,
    /// The capture log, with [`KitBuilder::capture_all`].
    pub capture: Option<Arc<crate::capture::CaptureLog>>,
    ca_file: std::path::PathBuf,
    pub(crate) limits: Limits,
    pub(crate) flags: HttpFlags,
    settings: UpstreamSettings,
    _dir: tempfile::TempDir,
}

impl Kit {
    pub(crate) fn builder() -> KitBuilder {
        KitBuilder {
            rules: ALLOW_UP.to_owned(),
            addons: Vec::new(),
            limits: Limits::default(),
            flags: HttpFlags::default(),
            metrics: Arc::new(UnavailableMetrics),
            metric_defs: String::new(),
            state: Arc::new(UnavailableState),
            capture_all: false,
        }
    }

    /// A raw client connection to a direct listener whose clients connect
    /// to `port`.
    pub(crate) fn connect_direct(&self, port: u16) -> tokio::io::DuplexStream {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let conn = ClientConn {
            id: Ulid::generate(),
            listener: Arc::new(ListenerInfo {
                name: "direct".to_owned(),
                mode: ListenerMode::Direct { port },
                auth_required: false,
            }),
            peer: "192.0.2.7:40000".parse().unwrap(),
            user: None,
            original_dst: None,
        };
        self.spawn_conn(crate::conn::serve_direct(
            Box::new(server),
            conn,
            port,
            self.server.shared().clone(),
        ));
        client
    }

    /// Serves a connection the way the accept loop does, so a server
    /// shutdown reaches it (`stop`, then the kill switch).
    fn spawn_conn(&self, fut: impl std::future::Future<Output = ()> + Send + 'static) {
        let shared = self.server.shared();
        let slot = crate::server::conn_slot(shared, "192.0.2.7".parse().unwrap()).unwrap();
        shared.spawn_conn(slot, fut);
    }

    /// A raw client connection to the proxy port.
    pub(crate) fn connect(&self) -> tokio::io::DuplexStream {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let conn = ClientConn {
            id: Ulid::generate(),
            listener: Arc::new(ListenerInfo {
                name: "main".to_owned(),
                mode: ListenerMode::Explicit,
                auth_required: false,
            }),
            peer: "192.0.2.7:40000".parse().unwrap(),
            user: None,
            original_dst: None,
        };
        self.spawn_conn(crate::conn::serve_explicit(
            Box::new(server),
            conn,
            self.server.shared().clone(),
        ));
        client
    }

    /// An HTTP/1.1 client on the proxy port (absolute-form requests).
    pub(crate) async fn h1(&self) -> Client {
        Client::h1(self.connect(), None).await
    }

    /// `CONNECT host:443`, TLS with roxy's leaf, then HTTP/2 (`h2`) or
    /// HTTP/1.1 inside.
    pub(crate) async fn tunnel(&self, host: &str, h2: bool) -> Client {
        let io = self.connect_tunnel(host, 443).await;
        self.tls_client(io, host, h2).await
    }

    /// `CONNECT host:port`, answered `200`; the raw tunnel.
    pub(crate) async fn connect_tunnel(&self, host: &str, port: u16) -> tokio::io::DuplexStream {
        let mut io = self.connect();
        let connect = format!("CONNECT {host}:{port} HTTP/1.1\r\nhost: {host}:{port}\r\n\r\n");
        io.write_all(connect.as_bytes()).await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut b = [0u8; 1];
            assert_eq!(io.read(&mut b).await.unwrap(), 1, "CONNECT: EOF");
            head.push(b[0]);
        }
        let head = String::from_utf8_lossy(&head);
        assert!(head.starts_with("HTTP/1.1 200"), "CONNECT: {head}");
        io
    }

    /// A direct listener on port 443: TLS with SNI `host` and roxy's leaf,
    /// then HTTP/2 (`h2`) or HTTP/1.1 inside.
    pub(crate) async fn direct_tls(&self, host: &str, h2: bool) -> Client {
        self.tls_client(self.connect_direct(443), host, h2).await
    }

    /// A plaintext HTTP/1.1 client on a direct listener on port 80, sending
    /// `host` as `Host`.
    pub(crate) async fn direct_plain(&self, host: &str) -> Client {
        Client::h1(self.connect_direct(80), Some(host)).await
    }

    /// Roxy's CA as a client trust store.
    pub(crate) fn client_tls(&self) -> rustls::ClientConfig {
        (*roxy_tls::client_config(&UpstreamTlsOptions {
            extra_roots_pem: vec![self.ca_file.clone()],
            ..UpstreamTlsOptions::default()
        })
        .unwrap())
        .clone()
    }

    async fn tls_client<IO>(&self, io: IO, host: &str, h2: bool) -> Client
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let mut cfg = self.client_tls();
        cfg.alpn_protocols = vec![if h2 {
            b"h2".to_vec()
        } else {
            b"http/1.1".to_vec()
        }];
        let name = roxy_tls::server_name_for_host(host).unwrap();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
            .connect(name, io)
            .await
            .unwrap();
        if h2 {
            Client::h2(tls, host).await
        } else {
            Client::h1(tls, Some(host)).await
        }
    }

    /// A WebSocket upgrade to `http://up.test<path>` on the proxy port.
    /// Returns the response status and, after a `101`, the upgraded
    /// stream.
    pub(crate) async fn websocket(
        &self,
        path: &str,
        headers: &[(&str, &str)],
    ) -> (u16, Option<TokioIo<hyper::upgrade::Upgraded>>) {
        let mut c = self.h1().await;
        let mut hs = vec![
            ("connection", "upgrade"),
            ("upgrade", "websocket"),
            ("sec-websocket-version", "13"),
            ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
        ];
        hs.extend_from_slice(headers);
        let req = c.request("GET", path, &hs).body(Body::empty()).unwrap();
        let res = c.send(req).await.unwrap();
        let status = res.status().as_u16();
        if status != 101 {
            return (status, None);
        }
        let up = hyper::upgrade::on(res).await.unwrap();
        (status, Some(TokioIo::new(up)))
    }

    /// Waits until `n` events of `kind` were logged; returns them.
    pub(crate) async fn events(&self, kind: &str, n: usize) -> Vec<serde_json::Value> {
        self.sink.wait_for(kind, n, Duration::from_secs(10)).await
    }

    /// The flow's single `request` event.
    pub(crate) async fn request_event(&self) -> serde_json::Value {
        self.events("request", 1).await.remove(0)
    }

    /// Swaps in a new policy with these rules (no metrics, no addons); the
    /// limits, flags and upstream settings stay.
    pub(crate) fn reload(&self, rules: &str) {
        let rules: Vec<RuleConfig> = serde_yaml_ng::from_str(rules).unwrap();
        let none = std::collections::HashSet::new();
        let input = PolicyInput {
            rules: &rules,
            metrics: &[],
            secret_names: &none,
            address_lists: &none,
            transparent_listeners: false,
            default: DefaultDecision::Deny,
        };
        let policy = Policy::compile(&input).unwrap_or_else(|d| panic!("rules: {d:?}"));
        self.server
            .reload(PolicyUpdate {
                policy,
                secrets: HashMap::new(),
                redactor: Redactor::new(),
                users: HashMap::new(),
                limits: self.limits.clone(),
                flags: self.flags.clone(),
                upstream: self.settings.clone(),
                address_lists: Arc::new(HashMap::new()),
                deny_lists: Vec::new(),
                addons: Vec::new(),
            })
            .unwrap();
    }

    /// Everything captured so far, as `(header, payload)` records.
    pub(crate) fn captured(&self) -> Vec<(serde_json::Value, Vec<u8>)> {
        let log = self.capture.as_ref().expect("capture_all");
        assert!(log.flush());
        crate::capture::tests::parse(&std::fs::read(log.path()).unwrap())
    }

    /// Waits until `n` requests have reached the upstream (their bodies may
    /// still be arriving).
    pub(crate) async fn wait_arrived(&self, n: usize) -> Vec<Seen> {
        let wait = async {
            loop {
                let seen = self.upstream.seen();
                if seen.len() >= n {
                    return seen;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(10), wait)
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "upstream: wanted {n} requests, have {:#?}",
                    self.upstream.seen()
                )
            })
    }
}

/// A client over HTTP/1.1 or HTTP/2.
pub(crate) enum Client {
    /// `tunnel`: the CONNECT host (origin-form requests), or `None` on the
    /// proxy port (absolute-form requests to `up.test`).
    H1 {
        send: hyper::client::conn::http1::SendRequest<Body>,
        tunnel: Option<String>,
        conn: tokio::task::JoinHandle<()>,
    },
    H2 {
        send: hyper::client::conn::http2::SendRequest<Body>,
        host: String,
        conn: tokio::task::JoinHandle<()>,
    },
}

impl Client {
    async fn h1<IO>(io: IO, tunnel: Option<&str>) -> Self
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let (send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
            .await
            .unwrap();
        let conn = tokio::spawn(async move {
            let _ = conn.with_upgrades().await;
        });
        Self::H1 {
            send,
            tunnel: tunnel.map(str::to_owned),
            conn,
        }
    }

    async fn h2<IO>(io: IO, host: &str) -> Self
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let (send, conn) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(io))
                .await
                .unwrap();
        let conn = tokio::spawn(async move {
            let _ = conn.await;
        });
        Self::H2 {
            send,
            host: host.to_owned(),
            conn,
        }
    }

    /// Drops the connection where it stands (no GOAWAY, no close frame):
    /// roxy sees the client vanish.
    pub(crate) fn kill(&self) {
        match self {
            Self::H1 { conn, .. } | Self::H2 { conn, .. } => conn.abort(),
        }
    }

    /// A request for `path` on `up.test` with `headers`; see
    /// [`Client::request_to`].
    pub(crate) fn request(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
    ) -> http::request::Builder {
        self.request_to("up.test", method, path, headers)
    }

    /// A request shaped for this client: an absolute `http://<host>` URI
    /// plus `host` on the proxy port, origin form plus `host` in an h1
    /// tunnel, an absolute `https` URI over h2. In a tunnel `host` is the
    /// tunnel's.
    pub(crate) fn request_to(
        &self,
        host: &str,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
    ) -> http::request::Builder {
        let mut b = http::Request::builder().method(method);
        b = match self {
            Self::H1 { tunnel: None, .. } => {
                b.uri(format!("http://{host}{path}")).header("host", host)
            }
            Self::H1 {
                tunnel: Some(t), ..
            } => b.uri(path).header("host", t.as_str()),
            Self::H2 { host: t, .. } => b.uri(format!("https://{t}{path}")),
        };
        for (n, v) in headers {
            b = b.header(*n, *v);
        }
        b
    }

    /// Sends `req`.
    pub(crate) async fn send(
        &mut self,
        req: http::Request<Body>,
    ) -> Result<http::Response<Incoming>, hyper::Error> {
        match self {
            Self::H1 { send, .. } => {
                send.ready().await?;
                send.send_request(req).await
            }
            Self::H2 { send, .. } => {
                send.ready().await?;
                send.send_request(req).await
            }
        }
    }

    /// Starts `req` on its own task, so the test can keep feeding its body
    /// while waiting for the answer. On h2 the connection stays usable
    /// through `self`.
    pub(crate) fn start(
        &mut self,
        req: http::Request<Body>,
    ) -> tokio::task::JoinHandle<Result<Answer, hyper::Error>> {
        match self {
            Self::H1 { send, .. } => {
                // The caller has not sent anything else on this connection,
                // so it is ready.
                let fut = send.send_request(req);
                tokio::spawn(async move { Ok(Answer::read(fut.await?).await) })
            }
            Self::H2 { send, .. } => {
                let mut send = send.clone();
                tokio::spawn(async move {
                    send.ready().await?;
                    Ok(Answer::read(send.send_request(req).await?).await)
                })
            }
        }
    }

    /// Sends a request with a fixed body and collects the answer.
    pub(crate) async fn call(
        &mut self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &'static [u8],
    ) -> Answer {
        let req = self
            .request(method, path, headers)
            .body(Body::from_bytes(Bytes::from_static(body)))
            .unwrap();
        let res = self.send(req).await.expect("response");
        Answer::read(res).await
    }
}

/// A collected response.
#[derive(Debug)]
pub(crate) struct Answer {
    pub status: u16,
    pub headers: http::HeaderMap,
    /// `Err` if the body was cut.
    pub body: Result<Bytes, String>,
}

impl Answer {
    pub(crate) async fn read(res: http::Response<Incoming>) -> Self {
        let (parts, body) = res.into_parts();
        let body = body
            .collect()
            .await
            .map(http_body_util::Collected::to_bytes)
            .map_err(|e| e.to_string());
        Self {
            status: parts.status.as_u16(),
            headers: parts.headers,
            body,
        }
    }

    pub(crate) fn text(&self) -> String {
        String::from_utf8_lossy(self.body.as_ref().expect("complete body")).into_owned()
    }

    pub(crate) fn json(&self) -> serde_json::Value {
        serde_json::from_slice(self.body.as_ref().expect("complete body")).expect("JSON body")
    }
}

/// The connector's settings: the test names, and the scripted upstream
/// behind the dial.
fn upstream_settings(upstream: &Arc<Upstream>) -> UpstreamSettings {
    let mut settings = UpstreamSettings::default();
    // Never consult real DNS: unknown names fail.
    settings.dns.servers = Some(vec!["127.0.0.1:9".parse().unwrap()]);
    for (name, ip) in [
        ("up.test", UP_IP),
        ("private.test", PRIVATE_IP),
        ("down.test", DOWN_IP),
        ("stall.test", STALL_IP),
    ] {
        settings
            .dns
            .static_hosts
            .insert(name.to_owned(), vec![ip.parse().unwrap()]);
    }
    settings.connect_timeout = Duration::from_secs(5);
    let up = upstream.clone();
    settings.dial = Some(TestDial(Arc::new(move |addr| {
        let up = up.clone();
        Box::pin(async move {
            if addr.ip().to_string() == STALL_IP {
                return Ok(stalled());
            }
            up.dial(addr)
        })
    })));
    settings
}

/// A connection whose peer reads everything and never writes.
fn stalled() -> crate::io::BoxIo {
    let (mut ours, theirs) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while matches!(ours.read(&mut buf).await, Ok(n) if n > 0) {}
    });
    Box::new(theirs)
}

/// A capture log in `dir` that takes every forwarded exchange.
fn capture_all_log(dir: &std::path::Path) -> crate::capture::CaptureLog {
    crate::capture::CaptureLog::open(
        dir,
        crate::capture::CaptureOptions {
            max_body_bytes: 16 * 1024 * 1024,
            all: true,
            writer: roxy_log::WriterOptions::default(),
            rotate: roxy_log::RotateOptions::default(),
        },
    )
    .unwrap()
}

/// A request body the test feeds chunk by chunk.
pub(crate) fn streaming_body() -> (BodySender, Body) {
    Body::channel(u64::MAX, None)
}

/// A real metric store behind the proxy's metric trait.
struct StoreMetrics(roxy_rules::MetricStore);

impl MetricSource for StoreMetrics {
    fn get(
        &self,
        id: &str,
        view: &dyn roxy_rules::FlowView,
    ) -> Result<i64, crate::sources::MetricSourceError> {
        self.0
            .get(id, view)
            .map_err(|e| crate::sources::MetricSourceError::Unknown(e.to_string()))
    }

    fn record(
        &self,
        view: &dyn roxy_rules::FlowView,
        sample: &crate::sources::Sample,
    ) -> Result<(), crate::sources::MetricSourceError> {
        let s = roxy_rules::Sample {
            head: sample.head,
            request_bytes: sample.request_bytes,
            response_bytes: sample.response_bytes,
            denied: sample.denied,
            error: sample.error,
        };
        self.0
            .record(view, &s)
            .map_err(|e| crate::sources::MetricSourceError::Unknown(e.to_string()))
    }
}

#[cfg(test)]
mod smoke {
    use super::*;

    #[tokio::test]
    async fn a_request_reaches_the_scripted_upstream() {
        let kit = Kit::builder().start().await;
        let mut c = kit.h1().await;
        let a = c.call("POST", "/hello", &[], b"abc").await;
        assert_eq!(a.status, 200, "{a:?}");
        assert_eq!(a.json()["path"], "/hello");
        assert_eq!(a.json()["body_len"], 3);
        let seen = kit.upstream.wait_seen(1).await;
        assert_eq!(seen[0].body, b"abc");
        assert_eq!(seen[0].complete, Some(true));
        let ev = kit.request_event().await;
        assert_eq!(ev["decision"], "allow", "{ev:#}");
    }

    #[tokio::test]
    async fn tunnels_carry_h1_and_h2() {
        let kit = Kit::builder().start().await;
        for h2 in [false, true] {
            let mut c = kit.tunnel("up.test", h2).await;
            let a = c.call("GET", "/t", &[], b"").await;
            assert_eq!(a.status, 200, "h2={h2} {a:?}");
            assert_eq!(a.json()["path"], "/t");
        }
        let seen = kit.upstream.wait_seen(2).await;
        assert!(seen.iter().all(|s| s.addr.port() == 443));
    }
}
