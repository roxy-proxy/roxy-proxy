//! Service layers (§11.6): an external service in the network path.
//!
//! Each exchange opens one WebSocket to the layer's named endpoint
//! (subprotocol `roxy.layer.v1`). roxy streams the request into it as it
//! arrives; the service streams back the request to forward (or answers
//! itself, or denies); roxy forwards that down the stack, streams the
//! response it gets back into the socket, and the service streams back the
//! response to give the client. Text frames are JSON control messages,
//! binary frames are body bytes of the message whose head came last:
//!
//! ```text
//! roxy → service   {"type":"request", method, url, headers}  bytes…  {"type":"request_end"}
//! service → roxy   {"type":"request", …} bytes… request_end    forward this request
//!                  {"type":"response", status, headers} bytes… response_end
//!                                                              answer (instead of forwarding)
//!                  {"type":"deny", status?, message?}          refuse
//! roxy → service   {"type":"response", status, headers}  bytes…  {"type":"response_end"}
//! service → roxy   {"type":"response", …} bytes… response_end | {"type":"deny", …}
//! ```
//!
//! What the service forwards is held to the same checks as a WASM layer's
//! `next` (re-validated as strictly as a client request, then judged by
//! the rules). Fail closed (enforce mode): a failed connection or
//! handshake, a protocol violation, a missed deadline or a dropped socket
//! deny the exchange before the response head and cut the body after it.
//! The connection goes through the connector (address floor, deny lists)
//! and never through other layers or the rules.

use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt as _, StreamExt as _};
use http::{HeaderMap, HeaderName, HeaderValue};
use http_body::Body as _;
use roxy_http::{Body, BodyError, BodySender, Scheme};
use roxy_wasm::{HostError, LayerRequest, LayerResponse};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant as TokioInstant;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use super::{StackError, StackFlow, endpoint};
use crate::flowlog::FlowEvent;
use crate::upstream::MaybeTls;

/// The WebSocket subprotocol a service must accept.
pub const SUBPROTOCOL: &str = "roxy.layer.v1";

/// Largest control message or body frame accepted from a service.
const MAX_FRAME: usize = 16 * 1024 * 1024;

/// A `kind: service` layer (§11.6).
#[derive(Debug, Clone)]
pub struct ServiceSpec {
    /// The addon's endpoint the exchange streams through.
    pub endpoint: String,
    /// From connecting, and again from sending the response head, until
    /// the service's next head (or decision).
    pub first_byte_timeout: Duration,
    /// The whole session, from connecting to the end of the last body.
    pub max_exchange_time: Duration,
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
    /// The socket closed or failed mid-exchange.
    #[error("service connection lost: {0}")]
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

/// roxy → service.
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Out {
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
}

/// service → roxy.
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
}

type Ws = WebSocketStream<MaybeTls>;
type Writer = mpsc::Sender<Message>;

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

fn text(m: &Out) -> Message {
    // `Out` always serializes.
    Message::text(serde_json::to_string(m).unwrap_or_default())
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
    let mut out = pairs(h);
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
    let end = start + svc.max_exchange_time;
    let ws = tokio::time::timeout_at(
        start + svc.first_byte_timeout,
        connect(st, index, svc, false),
    )
    .await
    .map_err(|_| ServiceError::Timeout("first_byte_timeout"))??;
    let (sink, stream) = ws.split();
    let writer = spawn_writer(sink);

    // The service's answers, read by one task in protocol order.
    let (first_tx, first_rx) = oneshot::channel();
    let (second_tx, second_rx) = oneshot::channel();
    let reader = Reader {
        st: st.clone(),
        index,
        stream,
        first: Some(first_tx),
        second: Some(second_tx),
        _open: writer.clone(),
    };
    let reader = tokio::spawn(reader.run(end));

    let (parts, body) = req.into_parts();
    tokio::spawn(pump(
        writer.clone(),
        request_head(&parts, &body),
        body,
        Out::RequestEnd,
    ));

    let first = tokio::time::timeout_at(start + svc.first_byte_timeout, first_rx)
        .await
        .map_err(|_| ServiceError::Timeout("first_byte_timeout"))?
        .map_err(|_| ServiceError::Closed("reader stopped".into()))??;
    let forward = match first {
        First::Answer(res) => return Ok(res),
        First::Forward(r) => r,
    };
    let res = super::below(st.clone(), index, forward)
        .await
        .map_err(Fail::Below)?;
    if res.status() == http::StatusCode::SWITCHING_PROTOCOLS {
        // An upgrade is not the service's to change, and the WebSocket
        // bytes do not go through it.
        reader.abort();
        return Ok(res);
    }
    let sent = TokioInstant::now();
    let (parts, body) = res.into_parts();
    tokio::spawn(pump(
        writer,
        response_head(&parts, &body),
        body,
        Out::ResponseEnd,
    ));
    let res = tokio::time::timeout_at(sent + svc.first_byte_timeout, second_rx)
        .await
        .map_err(|_| ServiceError::Timeout("first_byte_timeout"))?
        .map_err(|_| ServiceError::Closed("reader stopped".into()))??;
    Ok(res)
}

/// Runs observe-mode service layer `index`: the copies go to the service,
/// whose messages are read (so a broken connection is logged) and
/// discarded.
pub(super) async fn observe(
    st: &Arc<StackFlow>,
    index: usize,
    svc: &ServiceSpec,
    req: LayerRequest,
    next: &super::tee::ObserverNext,
) -> Result<(), ServiceError> {
    let start = TokioInstant::now();
    let end = start + svc.max_exchange_time;
    let connected = tokio::time::timeout_at(
        start + svc.first_byte_timeout,
        connect(st, index, svc, true),
    )
    .await
    .unwrap_or(Err(ServiceError::Timeout("first_byte_timeout")));
    let ws = match connected {
        Ok(ws) => ws,
        Err(e) => {
            // Read the copies so the tee does not count them as lagging.
            drain(req.into_body()).await;
            if let Ok(res) = next.response().await {
                drain(res.into_body()).await;
            }
            return Err(e);
        }
    };
    let (sink, mut stream) = ws.split();
    let writer = spawn_writer(sink);
    let reading = tokio::spawn(async move {
        tokio::time::timeout_at(end, async {
            while let Some(m) = stream.next().await {
                if let Err(e) = m {
                    return Err(ServiceError::Closed(e.to_string()));
                }
            }
            Ok(())
        })
        .await
        .map_err(|_| ServiceError::Timeout("max_exchange_time"))?
    });
    let (parts, body) = req.into_parts();
    pump(
        writer.clone(),
        request_head(&parts, &body),
        body,
        Out::RequestEnd,
    )
    .await;
    if let Ok(res) = next.response().await {
        let (parts, body) = res.into_parts();
        pump(writer, response_head(&parts, &body), body, Out::ResponseEnd).await;
    } else {
        drop(writer);
    }
    reading
        .await
        .unwrap_or_else(|e| Err(ServiceError::Closed(e.to_string())))
}

async fn drain(body: Body) {
    drop(body.collect_up_to(u64::MAX).await);
}

/// Connects and completes the handshake through the connector.
async fn connect(
    st: &StackFlow,
    index: usize,
    svc: &ServiceSpec,
    observe: bool,
) -> Result<Ws, ServiceError> {
    let addon = &st.snap.addons[index];
    let spec = addon
        .endpoints
        .get(&svc.endpoint)
        .ok_or_else(|| ServiceError::Connect(format!("no endpoint {:?}", svc.endpoint)))?;
    let uri = &spec.url;
    let (scheme, authority) = endpoint::authority_of(uri).map_err(ServiceError::Connect)?;
    let ws_scheme = if scheme == Scheme::Http { "ws" } else { "wss" };
    let path = uri.path_and_query().map_or("/", |p| p.as_str());
    let url = format!(
        "{ws_scheme}://{}{path}",
        uri.authority().map_or("", |a| a.as_str())
    );
    let mut request = url
        .into_client_request()
        .map_err(|e| ServiceError::Connect(e.to_string()))?;
    let h = request.headers_mut();
    for (n, v) in &spec.headers {
        let v = endpoint::expand(v, &st.snap.secrets).ok_or_else(|| {
            ServiceError::Connect(format!("endpoint header {n}: secret not loaded"))
        })?;
        let v = HeaderValue::from_str(&v)
            .map_err(|_| ServiceError::Connect(format!("endpoint header {n}")))?;
        h.insert(n.clone(), v);
    }
    h.insert(
        http::header::SEC_WEBSOCKET_PROTOCOL,
        HeaderValue::from_static(SUBPROTOCOL),
    );
    flow_headers(st, &addon.name, observe, h);

    let started = Instant::now();
    let result = async {
        let upstream = st.snap.upstream.clone();
        upstream
            .preflight(&authority, spec.private_ok)
            .await
            .map_err(|e| ServiceError::Connect(e.to_string()))?;
        let io = upstream
            .connect_h1(scheme, &authority, spec.private_ok)
            .await
            .map_err(|e| ServiceError::Connect(e.to_string()))?;
        let config = WebSocketConfig::default()
            .max_message_size(Some(MAX_FRAME))
            .max_frame_size(Some(MAX_FRAME));
        let (ws, res) = tokio_tungstenite::client_async_with_config(request, io, Some(config))
            .await
            .map_err(|e| ServiceError::Connect(e.to_string()))?;
        let proto = res
            .headers()
            .get(http::header::SEC_WEBSOCKET_PROTOCOL)
            .and_then(|v| v.to_str().ok());
        if proto != Some(SUBPROTOCOL) {
            return Err(ServiceError::Connect(format!(
                "the service did not accept subprotocol {SUBPROTOCOL}"
            )));
        }
        Ok(ws)
    }
    .await;
    st.shared.sink.emit(&FlowEvent::EndpointCall {
        ts: chrono::Utc::now(),
        flow: st.flow.to_string(),
        conn: st.client.id.to_string(),
        layer: addon.name.clone(),
        endpoint: svc.endpoint.clone(),
        method: "GET".to_owned(),
        path: uri.path().to_owned(),
        status: result.is_ok().then_some(101),
        attempts: 1,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        error: result.as_ref().err().map(ToString::to_string),
    });
    result
}

/// `roxy-flow-*` metadata on the handshake: who the client is and where
/// the exchange is, so the service can key its state. Values that are not
/// valid header values are left out.
fn flow_headers(st: &StackFlow, layer: &str, observe: bool, h: &mut HeaderMap) {
    let mut put = |name: &'static str, value: &str| {
        if let Ok(v) = HeaderValue::from_str(value) {
            h.insert(HeaderName::from_static(name), v);
        }
    };
    put("roxy-flow-id", &st.flow.to_string());
    put("roxy-flow-conn", &st.client.id.to_string());
    put("roxy-flow-layer", layer);
    put(
        "roxy-flow-mode",
        if observe { "observe" } else { "enforce" },
    );
    put("roxy-flow-client-ip", &st.client.peer.ip().to_string());
    if let Some(u) = &st.client.user {
        put("roxy-flow-client-user", u);
    }
    put("roxy-flow-listener", &st.client.listener.name);
    if let Some(sni) = st.tls.as_ref().and_then(|t| t.sni.as_deref()) {
        put("roxy-flow-sni", sni);
    }
    let tags = st.tags();
    if !tags.is_empty() {
        put("roxy-flow-tags", &tags.join(","));
    }
}

/// One task owns the socket's write half; everything that writes sends
/// through it. The socket closes once every sender is gone.
fn spawn_writer(mut sink: SplitSink<Ws, Message>) -> Writer {
    let (tx, mut rx) = mpsc::channel::<Message>(8);
    tokio::spawn(async move {
        while let Some(m) = rx.recv().await {
            if sink.send(m).await.is_err() {
                return;
            }
        }
        let _ = sink.close().await;
    });
    tx
}

/// Streams one message into the socket: head, body frames, end.
async fn pump(w: Writer, head: Out, mut body: Body, end: Out) {
    if w.send(text(&head)).await.is_err() {
        return;
    }
    loop {
        let frame = std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await;
        match frame {
            None => break,
            // A body that fails is not forwarded as complete: the message
            // is left unterminated.
            Some(Err(_)) => return,
            Some(Ok(f)) => {
                if let Ok(d) = f.into_data()
                    && !d.is_empty()
                    && w.send(Message::binary(d)).await.is_err()
                {
                    return;
                }
            }
        }
    }
    let _ = w.send(text(&end)).await;
}

/// Reads the service's messages in protocol order and hands them out.
struct Reader {
    st: Arc<StackFlow>,
    index: usize,
    stream: SplitStream<Ws>,
    first: Option<oneshot::Sender<Result<First, ServiceError>>>,
    second: Option<oneshot::Sender<Result<LayerResponse, ServiceError>>>,
    /// Keeps roxy's side of the socket open until the service's last
    /// message is read: a close frame would stop the service sending.
    _open: Writer,
}

/// A body being fed from the socket.
struct Feeding {
    /// `None` once its consumer went away (the client, or a deny below):
    /// the rest of the body is read and dropped.
    tx: Option<BodySender>,
    /// It is the request's (else the response's).
    request: bool,
}

impl Reader {
    fn waiting(&self, feeding: Option<&Feeding>) -> bool {
        feeding.is_some() || self.first.is_some() || self.second.is_some()
    }

    async fn run(mut self, end: TokioInstant) {
        let mut feeding: Option<Feeding> = None;
        let result = match tokio::time::timeout_at(end, self.read(&mut feeding)).await {
            Ok(r) => r,
            Err(_) => Err(ServiceError::Timeout("max_exchange_time")),
        };
        let Err(e) = result else {
            return;
        };
        // Whoever is waiting learns of the failure: a pending answer, or
        // the body being fed, which is cut (the failure is logged here,
        // since the head has gone on).
        if let Some(tx) = feeding.and_then(|f| f.tx) {
            tx.abort(BodyError::Upstream(e.to_string()));
        }
        if let Some(tx) = self.first.take() {
            let _ = tx.send(Err(e));
        } else if let Some(tx) = self.second.take()
            && !tx.is_closed()
        {
            let _ = tx.send(Err(e));
        } else {
            let name = self.st.snap.addons[self.index].name.clone();
            let err = StackError::Service(e);
            self.st.fail(&name, err.clone());
            super::emit_stack_error(&self.st, &name, &err, false);
        }
    }

    async fn read(&mut self, feeding: &mut Option<Feeding>) -> Result<(), ServiceError> {
        let lost = || ServiceError::Closed("the service closed the connection".into());
        loop {
            let msg = match self.stream.next().await {
                None | Some(Ok(Message::Close(_))) => {
                    return if self.waiting(feeding.as_ref()) {
                        Err(lost())
                    } else {
                        Ok(())
                    };
                }
                Some(Err(e)) => return Err(ServiceError::Closed(e.to_string())),
                Some(Ok(m)) => m,
            };
            match msg {
                Message::Binary(b) => {
                    let Some(f) = feeding.as_mut() else {
                        return Err(ServiceError::Protocol("body bytes before a head".into()));
                    };
                    if let Some(tx) = f.tx.as_mut() {
                        match tx.send_data(b).await {
                            Ok(()) => {}
                            // The consumer went away: nothing failed here.
                            Err(BodyError::Closed | BodyError::Stopped) => f.tx = None,
                            // More than declared, or than the limit.
                            Err(e) => return Err(ServiceError::Protocol(e.to_string())),
                        }
                    }
                }
                Message::Text(t) => {
                    let m: In = serde_json::from_str(t.as_str())
                        .map_err(|e| ServiceError::Protocol(format!("bad message: {e}")))?;
                    self.control(m, feeding).await?;
                    if !self.waiting(feeding.as_ref()) {
                        return Ok(());
                    }
                }
                // Ping and pong are answered by the library.
                _ => {}
            }
        }
    }

    async fn control(&mut self, m: In, feeding: &mut Option<Feeding>) -> Result<(), ServiceError> {
        let unexpected = |what: &str| ServiceError::Protocol(format!("unexpected {what}"));
        let limits = &self.st.snap.limits;
        match m {
            In::RequestEnd | In::ResponseEnd => {
                let request = matches!(m, In::RequestEnd);
                match feeding.take() {
                    Some(f) if f.request == request => match f.tx {
                        Some(tx) => match tx.finish().await {
                            Ok(()) | Err(BodyError::Closed | BodyError::Stopped) => Ok(()),
                            // Shorter than declared.
                            Err(e) => Err(ServiceError::Protocol(e.to_string())),
                        },
                        None => Ok(()),
                    },
                    _ if request => Err(unexpected("request_end")),
                    _ => Err(unexpected("response_end")),
                }
            }
            _ if feeding.is_some() => Err(ServiceError::Protocol(
                "a new head before the previous body ended".into(),
            )),
            In::Request {
                method,
                url,
                headers,
            } => {
                if self.first.is_none() {
                    return Err(unexpected("request"));
                }
                let method = http::Method::from_bytes(method.as_bytes())
                    .map_err(|_| ServiceError::Protocol(format!("invalid method {method:?}")))?;
                let uri: http::Uri = url
                    .parse()
                    .map_err(|_| ServiceError::Protocol(format!("invalid url {url:?}")))?;
                let headers = header_map(&headers)?;
                let (body_tx, body) =
                    Body::channel(limits.max_request_body_bytes, declared_length(&headers)?);
                let mut r = http::Request::new(body);
                *r.method_mut() = method;
                *r.uri_mut() = uri;
                *r.headers_mut() = headers;
                *feeding = Some(Feeding {
                    tx: Some(body_tx),
                    request: true,
                });
                if let Some(tx) = self.first.take() {
                    let _ = tx.send(Ok(First::Forward(r)));
                }
                Ok(())
            }
            In::Response { status, headers } => {
                if !(200..=599).contains(&status) {
                    return Err(ServiceError::Protocol(format!(
                        "response status {status} is not 200-599"
                    )));
                }
                let status = http::StatusCode::from_u16(status)
                    .map_err(|e| ServiceError::Protocol(e.to_string()))?;
                let headers = header_map(&headers)?;
                let (body_tx, body) =
                    Body::channel(limits.max_response_body_bytes, declared_length(&headers)?);
                let mut r = http::Response::new(body);
                *r.status_mut() = status;
                *r.headers_mut() = headers;
                *feeding = Some(Feeding {
                    tx: Some(body_tx),
                    request: false,
                });
                self.answer(r, "response")
            }
            In::Deny { status, message } => {
                let status = status.unwrap_or(403);
                if !(400..=599).contains(&status) {
                    return Err(ServiceError::Protocol(format!(
                        "deny status {status} is not 4xx or 5xx"
                    )));
                }
                let msg = message.unwrap_or_else(|| "request blocked".to_owned());
                let mut r = http::Response::new(Body::from_bytes(format!("{}\n", msg.trim_end())));
                *r.status_mut() = http::StatusCode::from_u16(status)
                    .map_err(|e| ServiceError::Protocol(e.to_string()))?;
                r.headers_mut().insert(
                    http::header::CONTENT_TYPE,
                    HeaderValue::from_static("text/plain; charset=utf-8"),
                );
                let name = self.st.snap.addons[self.index].name.clone();
                self.st.add_tag(format!("{name}:deny"));
                self.answer(r, "deny")
            }
        }
    }

    /// Hands a response to whoever is waiting: the first answer (the
    /// service answers instead of forwarding), or the second.
    fn answer(&mut self, r: LayerResponse, what: &str) -> Result<(), ServiceError> {
        if let Some(tx) = self.first.take() {
            // Answering instead of forwarding: no second answer follows.
            self.second = None;
            let _ = tx.send(Ok(First::Answer(r)));
            Ok(())
        } else if let Some(tx) = self.second.take() {
            let _ = tx.send(Ok(r));
            Ok(())
        } else {
            Err(ServiceError::Protocol(format!("unexpected {what}")))
        }
    }
}
