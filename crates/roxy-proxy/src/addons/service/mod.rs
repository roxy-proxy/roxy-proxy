//! Service layers: an external service in the network path.
//!
//! Each exchange is a stream (`roxy.layer.v3`) on one of a few pooled
//! WebSocket connections to the layer's named endpoint ([`mux`]). roxy
//! streams the request into it as it arrives; the service streams back
//! the request to forward (or answers itself, or denies); roxy forwards
//! that down the stack, streams the response it gets back into the
//! stream, and the service streams back the response to give the client:
//!
//! ```text
//! roxy → service   open, {"type":"request", method, url, headers}  bytes…  request_end
//! service → roxy   {"type":"request", …} bytes… request_end    forward this request
//!                  {"type":"response", status, headers} bytes… response_end
//!                                                              answer (instead of forwarding)
//!                  {"type":"deny", status?, message?}          refuse
//! roxy → service   {"type":"response", status, headers}  bytes…  response_end
//! service → roxy   {"type":"response", …} bytes… response_end | {"type":"deny", …}
//! ```
//!
//! The request and response bodies are independent: a response head goes
//! (either way) as soon as there is one, even while the request body is
//! still streaming.
//!
//! What the service forwards is held to the same checks as a WASM layer's
//! `next` (re-validated as strictly as a client request, then judged by
//! the rules). Fail closed (enforce mode): a failed connection or
//! handshake, a protocol violation, a missed deadline, a reset or a lost
//! connection deny the exchange before the response head and cut the body
//! after it. The connection goes through the connector (address floor,
//! deny lists) and never through other layers or the rules.

mod mux;

use std::sync::Arc;
use std::time::Duration;

use http::{HeaderMap, HeaderName, HeaderValue};
use roxy_http::Body;
use roxy_wasm::{HostError, LayerRequest, LayerResponse};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use tokio::sync::oneshot::error::TryRecvError;
use tokio::time::Instant as TokioInstant;

use super::{AddonMode, StackError, StackFlow};
use crate::watch::Dir;

pub(crate) use mux::Pools;
pub use mux::SUBPROTOCOL;

/// A `kind: service` layer.
#[derive(Debug, Clone)]
pub struct ServiceSpec {
    /// The addon's endpoint the exchange streams through.
    pub endpoint: String,
    /// From asking for a stream until the service's first head (or
    /// decision), and again from sending the response head until its
    /// second. Bodies have no clock.
    pub first_byte_timeout: Duration,
    /// Connections to the endpoint, at most.
    pub max_connections: usize,
    /// Streams on one connection, at most.
    pub max_streams: usize,
}

/// Why a service layer failed.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ServiceError {
    /// The connection or handshake failed.
    #[error("service connection failed: {0}")]
    Connect(String),
    /// A deadline passed.
    #[error("service missed its {0}")]
    Timeout(&'static str),
    /// The service broke the protocol (a bad message, a message out of
    /// order, an invalid head).
    #[error("service protocol violation: {0}")]
    Protocol(String),
    /// The connection closed or failed, or the stream was reset,
    /// mid-exchange.
    #[error("service stream lost: {0}")]
    Closed(String),
}

impl ServiceError {
    /// A stable code for the flow log (`layer_error.kind`).
    pub fn kind(&self) -> &'static str {
        match self {
            ServiceError::Connect(_) => "service:connect",
            ServiceError::Timeout(_) => "service:timeout",
            ServiceError::Protocol(_) => "service:protocol",
            ServiceError::Closed(_) => "service:closed",
        }
    }
}

/// roxy → service (each sent with its stream id).
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Out {
    Open {
        flow: String,
        conn: String,
        layer: String,
        mode: &'static str,
        client_ip: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        client_user: Option<String>,
        listener: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        sni: Option<String>,
        tags: Vec<String>,
    },
    Request {
        method: String,
        url: String,
        headers: Vec<(String, String)>,
    },
    RequestEnd,
    Response {
        status: u16,
        headers: Vec<(String, String)>,
    },
    ResponseEnd,
    Credit {
        dir: Dir,
        bytes: u64,
    },
    Reset {
        message: String,
    },
}

/// service → roxy (the stream id is read first).
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum In {
    Request {
        method: String,
        url: String,
        #[serde(default)]
        headers: Vec<(String, String)>,
    },
    RequestEnd,
    Response {
        status: u16,
        #[serde(default)]
        headers: Vec<(String, String)>,
    },
    ResponseEnd,
    Deny {
        #[serde(default)]
        status: Option<u16>,
        #[serde(default)]
        message: Option<String>,
    },
    Credit {
        dir: Dir,
        bytes: u64,
    },
    Reset {
        #[serde(default)]
        message: Option<String>,
    },
}

/// The service's first answer: forward a request, or answer the client.
enum First {
    Forward(LayerRequest),
    Answer(LayerResponse),
}

fn pairs(h: &HeaderMap) -> Vec<(String, String)> {
    h.iter()
        .map(|(n, v)| {
            (
                n.as_str().to_owned(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect()
}

fn header_map(pairs: &[(String, String)]) -> Result<HeaderMap, ServiceError> {
    let mut h = HeaderMap::new();
    for (n, v) in pairs {
        let name = HeaderName::from_bytes(n.as_bytes())
            .map_err(|_| ServiceError::Protocol(format!("invalid header name {n:?}")))?;
        let value = HeaderValue::from_str(v)
            .map_err(|_| ServiceError::Protocol(format!("invalid value for header {n}")))?;
        h.append(name, value);
    }
    Ok(h)
}

/// The `content-length` the service declared, if any: one field of
/// digits. The body is held to it as it streams.
fn declared_length(h: &HeaderMap) -> Result<Option<u64>, ServiceError> {
    let mut values = h.get_all(http::header::CONTENT_LENGTH).iter();
    let Some(v) = values.next() else {
        return Ok(None);
    };
    let n = v
        .to_str()
        .ok()
        .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|s| s.parse().ok());
    match (n, values.next()) {
        (Some(n), None) => Ok(Some(n)),
        _ => Err(ServiceError::Protocol("invalid content-length".into())),
    }
}

/// The answer a `deny` stands for.
fn deny_response(
    status: Option<u16>,
    message: Option<String>,
) -> Result<LayerResponse, ServiceError> {
    let status = status.unwrap_or(403);
    if !(400..=599).contains(&status) {
        return Err(ServiceError::Protocol(format!(
            "deny status {status} is not 4xx or 5xx"
        )));
    }
    let msg = message.unwrap_or_else(|| "request blocked".to_owned());
    let mut r = http::Response::new(Body::from_bytes(format!("{}\n", msg.trim_end())));
    *r.status_mut() =
        http::StatusCode::from_u16(status).map_err(|e| ServiceError::Protocol(e.to_string()))?;
    r.headers_mut().insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    Ok(r)
}

/// Runs enforce-mode service layer `index` on `req`.
pub(super) async fn handle(
    st: Arc<StackFlow>,
    index: usize,
    svc: &ServiceSpec,
    req: LayerRequest,
) -> Result<LayerResponse, HostError> {
    let name = st.snap.addons[index].name.clone();
    match run(&st, index, svc, req).await {
        Ok(r) => Ok(r),
        Err(Fail::Below(e)) => Err(e),
        Err(Fail::Service(e)) => {
            st.fail(&name, StackError::Service(e));
            Err(HostError::new(format!("service layer {name} failed")))
        }
    }
}

enum Fail {
    Service(ServiceError),
    /// The stack below failed (already recorded by whoever failed).
    Below(HostError),
}

impl From<ServiceError> for Fail {
    fn from(e: ServiceError) -> Self {
        Fail::Service(e)
    }
}

/// The head's fields, plus `content-length` when the body's length is
/// known (and not zero), so a service that passes the head on keeps it.
/// roxy checks it against the body the service sends back.
fn head_fields(h: &HeaderMap, body: &Body) -> Vec<(String, String)> {
    // Any `content-length` already there (passed on by a layer above) is
    // replaced, not repeated.
    let mut out = pairs(h);
    out.retain(|(n, _)| n != "content-length");
    if let Some(n) = body.known_length().filter(|n| *n > 0) {
        out.push(("content-length".to_owned(), n.to_string()));
    }
    out
}

fn request_head(parts: &http::request::Parts, body: &Body) -> Out {
    Out::Request {
        method: parts.method.to_string(),
        url: parts.uri.to_string(),
        headers: head_fields(&parts.headers, body),
    }
}

fn response_head(parts: &http::response::Parts, body: &Body) -> Out {
    Out::Response {
        status: parts.status.as_u16(),
        headers: head_fields(&parts.headers, body),
    }
}

async fn run(
    st: &Arc<StackFlow>,
    index: usize,
    svc: &ServiceSpec,
    req: LayerRequest,
) -> Result<LayerResponse, Fail> {
    let start = TokioInstant::now();
    let (stream, answers) = tokio::time::timeout_at(
        start + svc.first_byte_timeout,
        mux::open(st, index, svc, AddonMode::Enforce),
    )
    .await
    .map_err(|_| ServiceError::Timeout("first_byte_timeout"))??;
    let Some(answers) = answers else {
        return Err(ServiceError::Closed("no answers on an enforce stream".into()).into());
    };
    // Until the service has answered, an exchange that ends here (the
    // client went away, a missed head, a failure below) resets the stream.
    let guard = Guard(Some(stream.clone()));

    let (parts, body) = req.into_parts();
    let s = stream.clone();
    let head = request_head(&parts, &body);
    tokio::spawn(async move { s.pump(Dir::Request, head, body).await });

    let first = answer_by(start + svc.first_byte_timeout, answers.first).await??;
    let forward = match first {
        First::Answer(res) => {
            guard.disarm();
            return Ok(res);
        }
        First::Forward(r) => r,
    };
    let res = super::below(st.clone(), index, forward)
        .await
        .map_err(Fail::Below)?;
    if res.status() == http::StatusCode::SWITCHING_PROTOCOLS {
        // An upgrade is not the service's to change, and the WebSocket
        // bytes do not go through it.
        guard.disarm();
        stream.reset("the upstream switched protocols");
        return Ok(res);
    }
    // The response head goes at once, however far the client's upload
    // has got; the service's second clock starts with it.
    let sent = TokioInstant::now();
    let (parts, body) = res.into_parts();
    let s = stream.clone();
    let head = response_head(&parts, &body);
    tokio::spawn(async move { s.pump(Dir::Response, head, body).await });
    let res = answer_by(sent + svc.first_byte_timeout, answers.second).await??;
    guard.disarm();
    Ok(res)
}

/// The service's answer, within `first_byte_timeout`. An answer that lands
/// as the deadline passes is still an answer: the timeout polls the channel
/// and then the clock, so it reports elapsed with a value already queued.
async fn answer_by<T>(
    deadline: TokioInstant,
    mut answer: oneshot::Receiver<T>,
) -> Result<T, ServiceError> {
    match tokio::time::timeout_at(deadline, &mut answer).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(_)) => Err(ServiceError::Closed("the stream ended".into())),
        Err(_) => match answer.try_recv() {
            Ok(v) => Ok(v),
            Err(TryRecvError::Closed) => Err(ServiceError::Closed("the stream ended".into())),
            Err(TryRecvError::Empty) => Err(ServiceError::Timeout("first_byte_timeout")),
        },
    }
}

/// Resets a stream whose exchange ended before the service's answer.
struct Guard(Option<Arc<mux::Stream>>);

impl Guard {
    fn disarm(mut self) {
        self.0 = None;
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(s) = self.0.take() {
            s.reset("the exchange ended");
        }
    }
}

/// Runs observe-mode service layer `index`: the copies go to the service
/// on a stream of their own; what it sends back other than credit and
/// resets is ignored.
pub(super) async fn observe(
    st: &Arc<StackFlow>,
    index: usize,
    svc: &ServiceSpec,
    req: LayerRequest,
    next: &super::tee::ObserverNext,
) -> Result<(), ServiceError> {
    let start = TokioInstant::now();
    let opened = tokio::time::timeout_at(
        start + svc.first_byte_timeout,
        mux::open(st, index, svc, AddonMode::Observe),
    )
    .await
    .unwrap_or(Err(ServiceError::Timeout("first_byte_timeout")));
    let stream = match opened {
        Ok((s, _)) => s,
        Err(e) => {
            // Read the copies so the tee does not count them as lagging.
            drain(req.into_body()).await;
            if let Ok(res) = next.response().await {
                drain(res.into_body()).await;
            }
            return Err(e);
        }
    };
    // The copies go as the real exchange does: a response that comes
    // while the request copy is still streaming is not held behind it.
    let (parts, body) = req.into_parts();
    let s = stream.clone();
    let head = request_head(&parts, &body);
    let request = tokio::spawn(async move { s.pump(Dir::Request, head, body).await });
    match next.response().await {
        Ok(res) => {
            let (parts, body) = res.into_parts();
            stream
                .pump(Dir::Response, response_head(&parts, &body), body)
                .await;
        }
        Err(_) => stream.reset("the exchange ended"),
    }
    let _ = request.await;
    stream.finish()
}

async fn drain(body: Body) {
    drop(body.collect_up_to(u64::MAX).await);
}

/// A roxy with service layers, for tests: the test kit's server reloaded
/// with a stack of `kind: service` addons whose endpoint is the in-test
/// service behind the scripted upstream.
#[cfg(test)]
pub(crate) mod testing {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    use roxy_rules::{DefaultDecision, Policy, PolicyInput, RuleConfig};

    use super::ServiceSpec;
    use crate::addons::{AddonImpl, AddonMode, AddonSpec, EndpointSpec, StateLimits};
    use crate::config::PolicyUpdate;
    use crate::flowlog::Redactor;
    use crate::testkit::{DOWN_IP, Kit, PRIVATE_IP, UP_IP};
    use crate::upstream::{TestDial, UpstreamSettings};

    /// The port the in-test service answers on (`up.test`).
    const PORT: u16 = 9000;

    /// A service layer whose endpoint is the in-test service's `behaviour`
    /// (`pass`, `talk`, `flood`, `pause` or `stall`).
    pub(crate) fn addon(
        name: &str,
        behaviour: &str,
        mode: AddonMode,
        spec: impl FnOnce(&mut ServiceSpec),
    ) -> Arc<AddonSpec> {
        let mut svc = ServiceSpec {
            endpoint: "svc".to_owned(),
            first_byte_timeout: Duration::from_secs(10),
            max_connections: 2,
            max_streams: 8,
        };
        spec(&mut svc);
        let endpoint = EndpointSpec {
            url: format!("http://up.test:{PORT}/svc/{behaviour}")
                .parse()
                .unwrap(),
            headers: Vec::new(),
            timeout: Duration::from_secs(10),
            retries: 0,
            private: crate::addr::PrivateAddrs::Deny,
        };
        Arc::new(AddonSpec {
            name: name.to_owned(),
            mode,
            kind: AddonImpl::Service(svc),
            endpoints: HashMap::from([("svc".to_owned(), endpoint)]),
            state: StateLimits::default(),
            audit_endpoint: None,
            when: None,
            sample: None,
        })
    }

    /// A kit running `rules` with the stack `addons`, outermost first.
    pub(crate) async fn kit(rules: &str, addons: Vec<Arc<AddonSpec>>) -> Kit {
        let kit = Kit::builder().rules(rules).start().await;
        reload(&kit, rules, &[], addons);
        kit
    }

    /// Reloads `kit` with `rules`, the `secrets` they may use (redacted
    /// from the logs) and the stack `addons`, outermost first.
    pub(crate) fn reload(
        kit: &Kit,
        rules: &str,
        secrets: &[(&str, &str)],
        addons: Vec<Arc<AddonSpec>>,
    ) {
        let rules: Vec<RuleConfig> = serde_yaml_ng::from_str(rules).unwrap();
        let none = std::collections::HashSet::new();
        let secret_names = secrets.iter().map(|(n, _)| (*n).to_owned()).collect();
        let input = PolicyInput {
            rules: &rules,
            metrics: &[],
            secret_names: &secret_names,
            address_lists: &none,
            transparent_listeners: false,
            default: DefaultDecision::Deny,
        };
        let policy = Policy::compile(&input).unwrap_or_else(|d| panic!("rules: {d:?}"));
        let mut redactor = Redactor::new();
        for (_, v) in secrets {
            redactor.add_secret(*v);
        }
        let mut upstream = UpstreamSettings::default();
        upstream.dns.servers = Some(vec!["127.0.0.1:9".parse().unwrap()]);
        for (name, ip) in [
            ("up.test", UP_IP),
            ("private.test", PRIVATE_IP),
            ("down.test", DOWN_IP),
        ] {
            upstream
                .dns
                .static_hosts
                .insert(name.to_owned(), vec![ip.parse().unwrap()]);
        }
        upstream.connect_timeout = Duration::from_secs(5);
        let up = kit.upstream.clone();
        upstream.dial = Some(TestDial(Arc::new(move |addr| {
            let up = up.clone();
            Box::pin(async move { up.dial(addr) })
        })));
        kit.server
            .reload(PolicyUpdate {
                policy,
                secrets: secrets
                    .iter()
                    .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
                    .collect(),
                redactor,
                users: HashMap::new(),
                limits: kit.limits.clone(),
                flags: kit.flags.clone(),
                upstream,
                address_lists: Arc::new(HashMap::new()),
                deny_lists: Vec::new(),
                addons,
            })
            .unwrap();
    }
}
