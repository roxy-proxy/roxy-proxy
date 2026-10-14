//! Service layers: an external service in the network path.
//!
//! Each exchange is a stream on one of a few pooled WebSocket connections
//! to the layer's named endpoint ([`mux`]). The
//! stream carries the exchange's two lanes, each a head, bytes and an
//! end, each way: roxy streams the request into it as it arrives, and the
//! response from below once there is one; the service streams back the
//! request it forwards, if it forwards one, and the response the client
//! gets, which it owes:
//!
//! ```text
//! roxy → service   open, {"type":"request", method, url, headers}  bytes…  request_end
//! service → roxy   {"type":"request", …} bytes… request_end          forward this request
//! roxy → service   {"type":"response", status, headers}  bytes…  response_end
//! service → roxy   {"type":"response", …} bytes… response_end        the client's response
//! ```
//!
//! Nothing orders one lane against the other: the service may answer
//! before it forwards, while it forwards or without forwarding, and roxy
//! takes each head as it comes. A body that fails on its way to the
//! service ends its lane with the error (`"error"` on the end), and the
//! service's own lanes go on. A WebSocket is the same exchange,
//! long-lived: after the `101` the request body is the client's bytes and
//! the response body the upstream's, until each side closes.
//!
//! What the service forwards is held to the same checks as a WASM layer's
//! `next` (re-validated as strictly as a client request, then judged by
//! the rules). Fail closed (enforce mode): a failed connection or
//! handshake, a protocol violation, a missed deadline, a reset or a lost
//! connection deny the exchange before the response head and cut the body
//! after it. The connection goes through the connector (address floor,
//! deny lists) and never through other layers or the rules.

mod host;
mod mux;

use std::sync::Arc;
use std::time::Duration;

use http::{HeaderMap, HeaderName, HeaderValue};
use roxy_http::Body;
use roxy_wasm::{HostError, LayerError, LayerRequest, LayerResponse, LogLevel};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot::error::TryRecvError;
use tokio::sync::{oneshot, watch};
use tokio::time::Instant as TokioInstant;

use super::tee::CopyCut;
use super::{AddonMode, StackError, StackFlow, Subscription};
use crate::in_flight::Dir;

pub(crate) use mux::Pools;
pub use mux::SUBPROTOCOL;

/// A `kind: service` layer.
#[derive(Debug, Clone)]
pub struct ServiceSpec {
    /// The addon's endpoint the exchange streams through.
    pub endpoint: String,
    /// Bounds getting a stream, then the service's answer: from roxy's
    /// request head until the service answers or forwards, and again from
    /// the response head from below until it answers; no clock runs while
    /// its forward is below. On an observe stream, the service's end from
    /// roxy's last message. Bodies have no clock.
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
    /// The service sent bytes of a body it is subscribed to the head of
    /// only.
    #[error("service sent bytes of the {0} body it is not subscribed to")]
    Unsubscribed(&'static str),
    /// The service ended a lane it was sending short of complete, on
    /// purpose: the body is cut where it stopped.
    #[error("service cut the {dir} body: {why}")]
    Cut { dir: &'static str, why: String },
    /// Host-service call `call` failed, or called a service the layer was
    /// not granted: the same failures a WASM layer's host calls have, with
    /// the same flow-log kinds.
    #[error("{err}")]
    Layer {
        call: u64,
        #[source]
        err: LayerError,
    },
}

/// Why the service's answer will not come.
#[derive(Debug, Clone, thiserror::Error)]
pub(super) enum Unanswered {
    /// The service failed the stream.
    #[error(transparent)]
    Service(ServiceError),
    /// roxy gave up on the stream (the client went away, say), recorded by
    /// whoever gave it up: the service is not at fault.
    #[error("service stream lost: {0}")]
    Abandoned(String),
}

impl From<ServiceError> for Unanswered {
    fn from(e: ServiceError) -> Self {
        Unanswered::Service(e)
    }
}

impl ServiceError {
    /// A stable code for the flow log (`layer_error.kind`).
    pub fn kind(&self) -> String {
        match self {
            ServiceError::Connect(_) => "service:connect".into(),
            ServiceError::Timeout(_) => "service:timeout".into(),
            ServiceError::Protocol(_) => "service:protocol".into(),
            ServiceError::Closed(_) => "service:closed".into(),
            ServiceError::Unsubscribed(dir) => format!("unsubscribed:{dir}"),
            ServiceError::Cut { .. } => "service:cut".into(),
            ServiceError::Layer { err, .. } => super::layer_error_kind(err),
        }
    }
}

/// What the service will be sent of each direction (`head` or `full`).
#[derive(Serialize)]
struct SubscribeOut {
    request: &'static str,
    response: &'static str,
}

impl From<Subscription> for SubscribeOut {
    fn from(s: Subscription) -> Self {
        SubscribeOut {
            request: s.request.as_str(),
            response: s.response.as_str(),
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
        subscribe: SubscribeOut,
        client_ip: String,
        listener: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        sni: Option<String>,
        tags: Vec<String>,
        capabilities: Vec<&'static str>,
        config: serde_json::Value,
    },
    Request {
        method: String,
        url: String,
        headers: Vec<(String, String)>,
    },
    /// The end of the request lane; `error` when the body failed short of
    /// it, and is not complete.
    RequestEnd {
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// The answer to a host-service call, by the `id` the service gave it.
    Result {
        id: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        value: Option<serde_json::Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    Response {
        status: u16,
        headers: Vec<(String, String)>,
    },
    ResponseEnd {
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
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
    /// The end of a lane the service is sending; with `error`, the body
    /// is cut there rather than complete.
    RequestEnd {
        #[serde(default)]
        error: Option<String>,
    },
    Response {
        status: u16,
        #[serde(default)]
        headers: Vec<(String, String)>,
    },
    ResponseEnd {
        #[serde(default)]
        error: Option<String>,
    },
    Credit {
        dir: Dir,
        bytes: u64,
    },
    Reset {
        #[serde(default)]
        message: Option<String>,
    },
    /// A host-service call, run beside the stream rather than in it.
    #[serde(skip)]
    Call(Call),
}

impl In {
    /// Parses a control message. Its `type` says which kind it is, and
    /// each kind is parsed on its own so that a bad message is refused
    /// with what is wrong with it (the missing field, the unknown type),
    /// which an untagged fallback between the two would not say.
    fn parse(v: serde_json::Map<String, serde_json::Value>) -> Result<In, String> {
        let call = v
            .get("type")
            .is_some_and(|t| CallType::deserialize(t).is_ok());
        let v = serde_json::Value::Object(v);
        let parsed = if call {
            serde_json::from_value(v).map(In::Call)
        } else {
            serde_json::from_value(v)
        };
        parsed.map_err(|e| e.to_string())
    }
}

/// The `type` of each [`Call`], to tell a call from a stream message.
#[derive(Deserialize)]
#[serde(variant_identifier, rename_all = "snake_case")]
enum CallType {
    Log,
    Record,
    AddTag,
    StateGet,
    StatePut,
    MetricGet,
    Quarantine,
}

/// A host-service call: what a WASM layer reaches through an import,
/// with the service's `id` for it.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Call {
    Log {
        id: u64,
        level: LogLevelIn,
        message: String,
    },
    Record {
        id: u64,
        kind: String,
        data: serde_json::Value,
    },
    AddTag {
        id: u64,
        tag: String,
    },
    StateGet {
        id: u64,
        key: String,
    },
    StatePut {
        id: u64,
        key: String,
        value: String,
        #[serde(default)]
        ttl_ms: Option<u64>,
    },
    MetricGet {
        id: u64,
        metric: String,
    },
    Quarantine {
        id: u64,
    },
}

impl Call {
    /// The service's id for the call, which its `result` carries back.
    fn id(&self) -> u64 {
        match self {
            Call::Log { id, .. }
            | Call::Record { id, .. }
            | Call::AddTag { id, .. }
            | Call::StateGet { id, .. }
            | Call::StatePut { id, .. }
            | Call::MetricGet { id, .. }
            | Call::Quarantine { id } => *id,
        }
    }
}

/// `flow.log` levels on the wire.
#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum LogLevelIn {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl From<LogLevelIn> for LogLevel {
    fn from(l: LogLevelIn) -> Self {
        match l {
            LogLevelIn::Trace => LogLevel::Trace,
            LogLevelIn::Debug => LogLevel::Debug,
            LogLevelIn::Info => LogLevel::Info,
            LogLevelIn::Warn => LogLevel::Warn,
            LogLevelIn::Error => LogLevel::Error,
        }
    }
}

/// Header values on the wire are bytes, and JSON strings are text: each
/// byte goes as the code point of the same value (ISO-8859-1), so an
/// obs-text value (`http.allow_obs_text`) crosses losslessly either way.
fn pairs(h: &HeaderMap) -> Vec<(String, String)> {
    h.iter()
        .map(|(n, v)| {
            (
                n.as_str().to_owned(),
                v.as_bytes().iter().map(|&b| char::from(b)).collect(),
            )
        })
        .collect()
}

/// Builds the head's map, holding the count to `max_headers` like every
/// head roxy parses. The count is checked before anything is allocated,
/// and the map is grown fallibly: past its own capacity `HeaderMap`
/// panics on `append`, which would take the connection's reader with it.
fn header_map(pairs: &[(String, String)], max_headers: usize) -> Result<HeaderMap, ServiceError> {
    let count = pairs.len();
    if count > max_headers {
        return Err(ServiceError::Protocol(format!(
            "{count} header fields, more than max_headers ({max_headers})"
        )));
    }
    let too_many =
        |_| ServiceError::Protocol(format!("{count} header fields, more than a head holds"));
    let mut h = HeaderMap::try_with_capacity(count).map_err(too_many)?;
    for (n, v) in pairs {
        let name = HeaderName::from_bytes(n.as_bytes())
            .map_err(|_| ServiceError::Protocol(format!("invalid header name {n:?}")))?;
        let invalid = || ServiceError::Protocol(format!("invalid value for header {n}"));
        let bytes: Vec<u8> = v
            .chars()
            .map(|c| u8::try_from(u32::from(c)).map_err(|_| invalid()))
            .collect::<Result<_, _>>()?;
        let value = HeaderValue::from_bytes(&bytes).map_err(|_| invalid())?;
        h.try_append(name, value).map_err(too_many)?;
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
        Err(Unanswered::Abandoned(why)) => Err(HostError::new(why)),
        Err(Unanswered::Service(e)) => {
            st.fail(&name, StackError::Service(e));
            Err(HostError::new(format!("service layer {name} failed")))
        }
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
) -> Result<LayerResponse, Unanswered> {
    let (stream, answers) = tokio::time::timeout(
        svc.first_byte_timeout,
        mux::open(st, index, svc, AddonMode::Enforce),
    )
    .await
    .map_err(|_| ServiceError::Timeout("first_byte_timeout"))??;
    let Some(answers) = answers else {
        return Err(ServiceError::Closed("no answers on an enforce stream".into()).into());
    };
    // Until the service has answered, an exchange that ends here (the
    // client went away, a missed head) resets the stream.
    let guard = Guard(Some(stream.clone()));

    // The service's clock starts with the request head, however long
    // getting the stream took.
    let clock = Clock::new(svc.first_byte_timeout);
    let (parts, body) = req.into_parts();
    let s = stream.clone();
    let head = request_head(&parts, &body);
    tokio::spawn(async move { s.pump(Dir::Request, head, body).await });
    tokio::spawn(attend(
        st.clone(),
        index,
        stream.clone(),
        answers.forward,
        clock.clone(),
    ));

    let res = match clock
        .answer_by(answers.answer, || st.forward_requested(index))
        .await
    {
        Ok(answer) => answer?,
        // The service's own deadline: it is told which, as for any fault
        // of its own.
        Err(e) => {
            stream.fail(e.clone(), mux::Reset::Send);
            guard.disarm();
            return Err(e.into());
        }
    };
    guard.disarm();
    Ok(res)
}

/// Attends the stream for the life of the exchange: runs the request lane
/// below the service, then stays until the stream has ended (the service
/// may hold a body open long after its forward is through). The exchange
/// being torn down before that resets the stream, whatever the lane is
/// doing: nothing more happens on it.
async fn attend(
    st: Arc<StackFlow>,
    index: usize,
    stream: Arc<mux::Stream>,
    forward: oneshot::Receiver<LayerRequest>,
    clock: Clock,
) {
    let torn_down = st.torn_down();
    let lane = async {
        forward_lane(&st, index, &stream, forward, &clock).await;
        stream.until_ended().await;
    };
    tokio::select! {
        biased;
        () = torn_down.cancelled() => stream.abandon(),
        () = lane => {}
    }
}

/// The request lane below the service: the request it forwards, if it
/// forwards one, run through the layers below and the core, and the
/// response that comes back streamed into the service. Independent of the
/// service's answer: the forward runs to its end whether the service
/// answers before, during or after it. The service's own stream ending
/// does not end it, the response from below then has nowhere to go and is
/// dropped as it arrives.
async fn forward_lane(
    st: &Arc<StackFlow>,
    index: usize,
    stream: &mux::Stream,
    forward: oneshot::Receiver<LayerRequest>,
    clock: &Clock,
) {
    // `Err`: the stream ended without a forward.
    let Ok(req) = forward.await else {
        return;
    };
    // A stream reset as the forward arrived (a missed deadline, the client
    // gone) has told the service nothing more happens on it. One that
    // ended on the service's last message has not: the forward runs.
    if stream.is_broken() {
        st.forward_dropped(index);
        return;
    }
    clock.stop();
    // Only the client's own failure comes back as an error, and nothing
    // upstream answers it.
    let Ok(res) = super::below(st.clone(), index, req).await else {
        stream.abandon();
        return;
    };
    // The response head goes at once, however far the client's upload
    // has got. A `101` goes the same way: its body is the upstream's side
    // of the WebSocket, and the request body still streaming is the
    // client's.
    clock.restart();
    let (parts, body) = res.into_parts();
    let head = response_head(&parts, &body);
    stream.pump(Dir::Response, head, body).await;
}

/// The service's answer clock: `first_byte_timeout` from roxy's request
/// head, stopped while the service's forward is below, and
/// `first_byte_timeout` again from the response head from below. The
/// service's own time, never the time below it.
#[derive(Clone)]
struct Clock {
    limit: Duration,
    deadline: watch::Sender<Option<TokioInstant>>,
}

impl Clock {
    fn new(limit: Duration) -> Self {
        Self {
            limit,
            deadline: watch::Sender::new(Some(TokioInstant::now() + limit)),
        }
    }

    /// The service forwarded: no clock runs while the request is upstream.
    fn stop(&self) {
        self.deadline.send_replace(None);
    }

    /// Stops the clock if `at` is still its deadline: an expiry seen
    /// against a deadline that `restart` has since replaced (the response
    /// from upstream came back meanwhile) leaves the new one to run.
    fn stop_if(&self, at: Option<TokioInstant>) {
        self.deadline.send_if_modified(|d| {
            if *d == at {
                *d = None;
                true
            } else {
                false
            }
        });
    }

    /// The response from upstream is on its way to the service: it has the
    /// whole budget again to answer.
    fn restart(&self) {
        self.deadline
            .send_replace(Some(TokioInstant::now() + self.limit));
    }

    /// The service's answer, within the clock. An answer that lands as the
    /// deadline passes is still an answer, and so is a forward accepted by
    /// then (`forwarded`) that the task carrying it has yet to pick up:
    /// the timeout polls the channel and the stream's state before the
    /// clock, so it reports elapsed with a value already queued.
    async fn answer_by<T>(
        &self,
        mut answer: oneshot::Receiver<T>,
        forwarded: impl Fn() -> bool,
    ) -> Result<T, ServiceError> {
        let mut deadline = self.deadline.subscribe();
        loop {
            let at = *deadline.borrow_and_update();
            let expiry = async {
                match at {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                biased;
                r = &mut answer => {
                    return r.map_err(|_| ServiceError::Closed("the stream ended".into()));
                }
                // Cannot fail: this clock holds the sender.
                _ = deadline.changed() => {}
                () = expiry => {
                    match answer.try_recv() {
                        Ok(v) => return Ok(v),
                        Err(TryRecvError::Closed) => {
                            return Err(ServiceError::Closed("the stream ended".into()));
                        }
                        Err(TryRecvError::Empty) if forwarded() => self.stop_if(at),
                        Err(TryRecvError::Empty) => {
                            return Err(ServiceError::Timeout("first_byte_timeout"));
                        }
                    }
                }
            }
        }
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
            s.abandon();
        }
    }
}

/// Runs observe-mode service layer `index`: the copies go to the service
/// on a stream of their own. What it sends back goes nowhere, but its
/// last message ends the stream as it does an enforce one, so it may read
/// the copies and then call the host services before ending it.
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
    let cut = parts.extensions.get::<CopyCut>().cloned();
    let request = tokio::spawn(async move { pump_copy(&s, Dir::Request, head, body, cut).await });
    match next.response().await {
        Ok(res) => {
            let (parts, body) = res.into_parts();
            let head = response_head(&parts, &body);
            let cut = parts.extensions.get::<CopyCut>().cloned();
            pump_copy(&stream, Dir::Response, head, body, cut).await;
        }
        Err(_) => stream.reset("the exchange ended"),
    }
    let _ = request.await;
    // roxy has sent all it had. The time from here to the service's last
    // message is its own, bounded as each of its heads is in enforce mode.
    stream.finish(svc.first_byte_timeout).await
}

/// Pumps an observer's copy, resetting the stream as soon as the copy is
/// cut: the pump may be waiting for credit, not reading the copy.
async fn pump_copy(stream: &mux::Stream, dir: Dir, head: Out, body: Body, cut: Option<CopyCut>) {
    let Some(cut) = cut else {
        return stream.pump(dir, head, body).await;
    };
    tokio::select! {
        biased;
        () = stream.pump(dir, head, body) => {}
        () = cut.cancelled() => stream.reset("the observer's copy was cut"),
    }
}

async fn drain(body: Body) {
    drop(body.collect_up_to(u64::MAX).await);
}

#[cfg(test)]
mod tests {
    use super::{Call, Clock, In, header_map, pairs};
    use http::{HeaderMap, HeaderValue};
    use serde_json::json;
    use std::time::Duration;

    /// An expiry resolved against a deadline the forward's return has
    /// since replaced does not stop the fresh one: the service still has
    /// its clock to answer.
    #[tokio::test]
    async fn an_expiry_seen_late_does_not_stop_a_restarted_clock() {
        let clock = Clock::new(Duration::from_secs(1));
        let expired = *clock.deadline.borrow();
        clock.restart();
        clock.stop_if(expired);
        assert!(
            clock.deadline.borrow().is_some(),
            "the restarted deadline runs"
        );
        let current = *clock.deadline.borrow();
        clock.stop_if(current);
        assert!(
            clock.deadline.borrow().is_none(),
            "the deadline that expired is stopped"
        );
    }

    /// A header value's bytes above 0x7f reach the service as the code
    /// points of the same value and come back as the same bytes; a code
    /// point no byte has is a protocol violation.
    #[test]
    fn obs_text_header_values_cross_the_stream_unchanged() {
        let raw = b"caf\xe9 \xff";
        let mut h = HeaderMap::new();
        h.insert("x-obs", HeaderValue::from_bytes(raw).unwrap());
        let sent = pairs(&h);
        assert_eq!(sent, [("x-obs".to_owned(), "caf\u{e9} \u{ff}".to_owned())]);
        let back = header_map(&sent, 100).unwrap();
        assert_eq!(back["x-obs"].as_bytes(), raw);
        let wide = [("x-obs".to_owned(), "\u{100}".to_owned())];
        assert!(header_map(&wide, 100).is_err());
    }

    /// A message that does not parse is refused with what is wrong with
    /// it, whichever kind it is: the field a call or a head is missing, or
    /// the unknown type. The kind goes by `type` alone: a stray `id` on a
    /// head changes neither what it is nor what it is told.
    #[test]
    fn a_bad_message_is_refused_with_what_is_wrong() {
        let parse = |v: serde_json::Value| -> Result<In, String> {
            let serde_json::Value::Object(v) = v else {
                panic!("an object");
            };
            In::parse(v)
        };
        let e = parse(json!({"type": "log", "id": 1, "level": "info"}))
            .err()
            .unwrap();
        assert!(e.contains("missing field `message`"), "{e}");
        let e = parse(json!({"type": "log", "level": "info", "message": "m"}))
            .err()
            .unwrap();
        assert!(e.contains("missing field `id`"), "{e}");
        let e = parse(json!({"type": "request", "method": "GET"}))
            .err()
            .unwrap();
        assert!(e.contains("missing field `url`"), "{e}");
        let e = parse(json!({"type": "request", "id": 1, "method": "GET"}))
            .err()
            .unwrap();
        assert!(e.contains("missing field `url`"), "{e}");
        let e = parse(json!({"type": "frobnicate", "id": 1})).err().unwrap();
        assert!(e.contains("unknown variant `frobnicate`"), "{e}");
        assert!(matches!(
            parse(json!({"type": "log", "id": 1, "level": "info", "message": "m"})),
            Ok(In::Call(Call::Log { id: 1, .. }))
        ));
        assert!(matches!(
            parse(json!({"type": "request_end", "id": 1})),
            Ok(In::RequestEnd { error: None })
        ));
    }

    /// A `max_headers` above what a `HeaderMap` holds (2^15 fields) does
    /// not reopen the panic: the map's own limit is an error too.
    #[test]
    fn a_head_past_the_maps_capacity_is_an_error_not_a_panic() {
        let pairs: Vec<_> = (0..=1 << 15)
            .map(|i| (format!("x-{i}"), "v".to_owned()))
            .collect();
        let e = header_map(&pairs, usize::MAX).unwrap_err();
        assert!(e.to_string().contains("more than a head holds"), "{e}");
    }
}

/// A roxy with service layers, for tests: the test kit's server reloaded
/// with a stack of `kind: service` addons whose endpoint is the in-test
/// service behind the scripted upstream.
#[cfg(test)]
pub(crate) mod testing {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    use roxy_rules::{Policy, PolicyInput, RuleConfig};

    use super::ServiceSpec;
    use crate::addons::{AddonImpl, AddonMode, AddonSpec, EndpointSpec, Part, Subscription};
    use crate::config::PolicyUpdate;
    use crate::flowlog::Redactor;
    use crate::testkit::Kit;
    use crate::upstream::{TestDial, UpstreamSettings};

    /// The port the in-test service answers on (`up.test`).
    const PORT: u16 = 9000;

    /// A service layer whose endpoint is the in-test service's `behaviour`
    /// (one of the `/svc/<behaviour>` paths of `testkit::upstream::service`).
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
            path: crate::addons::EndpointPath::Fixed,
            headers: Vec::new(),
            timeout: Duration::from_secs(10),
            private: crate::addr::PrivateAddrs::Deny,
        };
        Arc::new(AddonSpec {
            name: name.to_owned(),
            mode,
            kind: AddonImpl::Service(svc),
            endpoints: HashMap::from([("svc".to_owned(), endpoint)]),
            capabilities: roxy_wasm::Capabilities::NONE,
            config: serde_json::Value::Null,
            when: None,
            sample: None,
            subscribe: Subscription::default(),
        })
    }

    /// `addon`, granted `caps`.
    pub(crate) fn granted(
        mut addon: Arc<AddonSpec>,
        caps: &[roxy_wasm::Capability],
    ) -> Arc<AddonSpec> {
        Arc::get_mut(&mut addon)
            .expect("a fresh addon")
            .capabilities = caps.iter().copied().collect();
        addon
    }

    /// `addon`, subscribed to `request` and `response`.
    pub(crate) fn subscribed(
        mut addon: Arc<AddonSpec>,
        request: Part,
        response: Part,
    ) -> Arc<AddonSpec> {
        Arc::get_mut(&mut addon).expect("a fresh addon").subscribe =
            Subscription { request, response };
        addon
    }

    /// `addon`, run only on requests `when` matches.
    pub(crate) fn only_when(mut addon: Arc<AddonSpec>, when: &str) -> Arc<AddonSpec> {
        let none = std::collections::HashSet::new();
        let input = PolicyInput {
            rules: &[],
            metrics: &[],
            secret_names: &none,
            address_lists: &none,
        };
        let a = Arc::get_mut(&mut addon).expect("a fresh addon");
        a.when = Some(
            roxy_rules::Condition::compile(&input, &format!("{}.when", a.name), when)
                .unwrap_or_else(|d| panic!("when: {d:?}")),
        );
        addon
    }

    /// A kit running `rules` with the stack `addons`, outermost first.
    pub(crate) async fn kit(rules: &str, addons: Vec<Arc<AddonSpec>>) -> Kit {
        kit_with(rules, addons, |b| b).await
    }

    /// [`kit`], with the builder adjusted by `with` first.
    pub(crate) async fn kit_with(
        rules: &str,
        addons: Vec<Arc<AddonSpec>>,
        with: impl FnOnce(crate::testkit::KitBuilder) -> crate::testkit::KitBuilder,
    ) -> Kit {
        let kit = with(Kit::builder().rules(rules)).start().await;
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
        let rules: Vec<RuleConfig> = roxy_rules::yaml::from_str(rules).unwrap();
        let none = std::collections::HashSet::new();
        let secret_names = secrets.iter().map(|(n, _)| (*n).to_owned()).collect();
        let input = PolicyInput {
            rules: &rules,
            metrics: &[],
            secret_names: &secret_names,
            address_lists: &none,
        };
        let policy = Policy::compile(&input).unwrap_or_else(|d| panic!("rules: {d:?}"));
        let mut upstream = UpstreamSettings {
            connect_timeout: Duration::from_secs(5),
            ..UpstreamSettings::default()
        };
        let up = kit.upstream.clone();
        upstream.dial = Some(TestDial(Arc::new(move |addr| {
            let up = up.clone();
            Box::pin(async move { up.dial(addr) })
        })));
        kit.server
            .reload(PolicyUpdate {
                policy,
                valid_until: None,
                secrets: secrets
                    .iter()
                    .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
                    .collect(),
                redactor: Redactor::new(),
                limits: kit.limits.clone(),
                flags: kit.flags.clone(),
                http: kit.http.clone(),
                upstream,
                address_lists: Arc::new(HashMap::new()),
                deny_lists: Vec::new(),
                addons,
            })
            .unwrap();
    }
}
