//! Service layers (§11.6): an external service in the stack.
//!
//! For each configured direction roxy makes one call to the layer's named
//! endpoint with `content-type: message/http`, streaming the message in
//! transit (head, then body as it arrives). The service answers `200
//! message/http` and streams back the message to forward, which roxy
//! decodes with its strict codec and the workload's limits; a request then
//! continues down the stack and is judged by the rules. Instead of a
//! message the service may answer `application/roxy-decision+json`
//! (`deny` or `respond`).
//!
//! Fail closed (enforce mode): a connection failure, a non-`200`, another
//! content type, an invalid message or decision, a missed deadline or a
//! dropped stream deny the exchange before the response head, and cut the
//! body after it. The call goes straight to the connector, like any
//! endpoint call, and never passes through other layers or the rules.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::header::{CONTENT_TYPE, HOST};
use http::{HeaderMap, HeaderName, HeaderValue};
use http_body::{Body as HttpBody, Frame, SizeHint};
use roxy_http::message::{self, decode_request, decode_response, encode_request, encode_response};
use roxy_http::{Body, BodyError, Headers};
use roxy_wasm::{HostError, LayerRequest, LayerResponse};
use serde::Deserialize;
use tokio::time::Instant as TokioInstant;

use super::{StackError, StackFlow, endpoint};
use crate::flowlog::FlowEvent;

/// The decision media type.
pub const DECISION_TYPE: &str = "application/roxy-decision+json";

/// Largest decision body roxy reads.
const MAX_DECISION_BYTES: u64 = 1024 * 1024;

/// A `kind: service` layer (§11.6).
#[derive(Debug, Clone)]
pub struct ServiceSpec {
    /// The addon's endpoint the exchange streams through.
    pub endpoint: String,
    /// Stream requests through the service.
    pub request: bool,
    /// Stream responses through the service.
    pub response: bool,
    /// Per direction: from the call to a complete message head (or
    /// decision).
    pub first_byte_timeout: Duration,
    /// Per direction: from the call to the end of the service's message.
    pub max_exchange_time: Duration,
}

/// Why a service layer failed.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ServiceError {
    /// The call could not be made (connection, address floor, transport).
    #[error("service call failed: {0}")]
    Call(String),
    /// A deadline passed.
    #[error("service missed its {0}")]
    Timeout(&'static str),
    /// The service answered with a status other than `200`.
    #[error("service answered {0}")]
    Status(u16),
    /// The service answered with neither `message/http` nor a decision.
    #[error("service answered with content-type {0:?}")]
    ContentType(String),
    /// The message the service returned is not valid.
    #[error("service returned an invalid message: {0}")]
    Message(String),
    /// The decision the service returned is not valid.
    #[error("service returned an invalid decision: {0}")]
    Decision(String),
    /// The service's stream failed after the head.
    #[error("service stream failed: {0}")]
    Stream(String),
}

impl ServiceError {
    /// A stable code for the flow log (`layer_error.kind`).
    pub fn kind(&self) -> &'static str {
        match self {
            ServiceError::Call(_) => "service:call",
            ServiceError::Timeout(_) => "service:timeout",
            ServiceError::Status(_) => "service:status",
            ServiceError::ContentType(_) => "service:content_type",
            ServiceError::Message(_) => "service:invalid_message",
            ServiceError::Decision(_) => "service:invalid_decision",
            ServiceError::Stream(_) => "service:stream",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    Request,
    Response,
}

impl Direction {
    fn as_str(self) -> &'static str {
        match self {
            Direction::Request => "request",
            Direction::Response => "response",
        }
    }
}

/// What the service answered.
enum Reply {
    /// A `message/http` body, still streaming.
    Message(Body),
    /// A decision, as the response to give.
    Decision(LayerResponse),
}

/// Why the exchange through the layer did not complete.
enum Fail {
    /// This layer failed.
    Service(ServiceError),
    /// The stack below failed (already recorded by whoever failed).
    Below(HostError),
}

impl From<ServiceError> for Fail {
    fn from(e: ServiceError) -> Self {
        Fail::Service(e)
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
        Err(Fail::Below(e)) => Err(e),
        Err(Fail::Service(e)) => {
            st.fail(&name, StackError::Service(e));
            Err(HostError::new(format!("service layer {name} failed")))
        }
    }
}

async fn run(
    st: &Arc<StackFlow>,
    index: usize,
    svc: &ServiceSpec,
    req: LayerRequest,
) -> Result<LayerResponse, Fail> {
    let req = if svc.request {
        let (deadline, reply) =
            call(st, index, svc, Direction::Request, encode_request(req)).await?;
        match reply {
            Reply::Decision(res) => return Ok(res),
            Reply::Message(body) => {
                let decoded = tokio::time::timeout_at(
                    deadline.head,
                    decode_request(body, &st.snap.limits, &st.snap.flags),
                )
                .await
                .map_err(|_| ServiceError::Timeout("first_byte_timeout"))?
                .map_err(|e| ServiceError::Message(e.to_string()))?;
                let (parts, body) = decoded.into_parts();
                http::Request::from_parts(parts, watched(st, index, body, deadline.end))
            }
        }
    } else {
        req
    };
    let res = super::below(st.clone(), index, req)
        .await
        .map_err(Fail::Below)?;
    // A `101` has no message to stream: the upgrade itself is not the
    // service's to change, and the WebSocket bytes do not go through it.
    if !svc.response || res.status() == http::StatusCode::SWITCHING_PROTOCOLS {
        return Ok(res);
    }
    let (deadline, reply) = call(st, index, svc, Direction::Response, encode_response(res)).await?;
    match reply {
        Reply::Decision(res) => Ok(res),
        Reply::Message(body) => {
            let decoded = tokio::time::timeout_at(
                deadline.head,
                decode_response(body, &st.snap.limits, &st.snap.flags),
            )
            .await
            .map_err(|_| ServiceError::Timeout("first_byte_timeout"))?
            .map_err(|e| ServiceError::Message(e.to_string()))?;
            let (parts, body) = decoded.into_parts();
            Ok(http::Response::from_parts(
                parts,
                watched(st, index, body, deadline.end),
            ))
        }
    }
}

/// Runs observe-mode service layer `index`: the copies go to the service,
/// whose answers are read (so its failures surface) and discarded.
pub(super) async fn observe(
    st: &Arc<StackFlow>,
    index: usize,
    svc: &ServiceSpec,
    req: LayerRequest,
    next: &super::tee::ObserverNext,
) -> Result<(), ServiceError> {
    if svc.request {
        let (deadline, reply) = call(st, index, svc, Direction::Request, encode_request(req))
            .await
            .map_err(fail_to_service)?;
        if let Reply::Message(body) = reply {
            let r = tokio::time::timeout_at(
                deadline.head,
                decode_request(body, &st.snap.limits, &st.snap.flags),
            )
            .await
            .map_err(|_| ServiceError::Timeout("first_byte_timeout"))?
            .map_err(|e| ServiceError::Message(e.to_string()))?;
            drain(r.into_body(), deadline.end).await?;
        }
    } else {
        // Read the copy so the tee does not count it as lagging.
        drop(req.into_body().collect_up_to(u64::MAX).await);
    }
    let Ok(res) = next.response().await else {
        return Ok(());
    };
    if !svc.response || res.status() == http::StatusCode::SWITCHING_PROTOCOLS {
        drop(res.into_body().collect_up_to(u64::MAX).await);
        return Ok(());
    }
    let (deadline, reply) = call(st, index, svc, Direction::Response, encode_response(res))
        .await
        .map_err(fail_to_service)?;
    if let Reply::Message(body) = reply {
        let r = tokio::time::timeout_at(
            deadline.head,
            decode_response(body, &st.snap.limits, &st.snap.flags),
        )
        .await
        .map_err(|_| ServiceError::Timeout("first_byte_timeout"))?
        .map_err(|e| ServiceError::Message(e.to_string()))?;
        drain(r.into_body(), deadline.end).await?;
    }
    Ok(())
}

fn fail_to_service(f: Fail) -> ServiceError {
    match f {
        Fail::Service(e) => e,
        Fail::Below(e) => ServiceError::Call(e.to_string()),
    }
}

async fn drain(body: Body, end: TokioInstant) -> Result<(), ServiceError> {
    tokio::time::timeout_at(end, body.collect_up_to(u64::MAX))
        .await
        .map_err(|_| ServiceError::Timeout("max_exchange_time"))?
        .map(drop)
        .map_err(|e| ServiceError::Stream(e.to_string()))
}

struct Deadlines {
    /// A complete head (or decision) by then.
    head: TokioInstant,
    /// The whole message by then.
    end: TokioInstant,
}

/// One call to the service for `direction`, up to its answer's head.
async fn call(
    st: &Arc<StackFlow>,
    index: usize,
    svc: &ServiceSpec,
    direction: Direction,
    body: Body,
) -> Result<(Deadlines, Reply), Fail> {
    let addon = &st.snap.addons[index];
    let now = TokioInstant::now();
    let deadline = Deadlines {
        head: now + svc.first_byte_timeout,
        end: now + svc.max_exchange_time,
    };
    let spec = addon
        .endpoints
        .get(&svc.endpoint)
        .ok_or_else(|| ServiceError::Call(format!("no endpoint {:?}", svc.endpoint)))?;
    let uri = spec.url.clone();
    let (_, authority) = endpoint::authority_of(&uri).map_err(ServiceError::Call)?;
    let headers = call_headers(st, &addon.name, spec, &uri, direction)?;

    let upstream = st.snap.upstream.clone();
    let started = Instant::now();
    let path = uri.path().to_owned();
    let emit = |status: Option<u16>, error: Option<String>| {
        st.shared.sink.emit(&FlowEvent::EndpointCall {
            ts: chrono::Utc::now(),
            flow: st.flow.to_string(),
            conn: st.client.id.to_string(),
            layer: addon.name.clone(),
            endpoint: svc.endpoint.clone(),
            method: "POST".to_owned(),
            path: path.clone(),
            status,
            attempts: 1,
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            error,
        });
    };
    if let Err(e) = upstream.preflight(&authority, spec.private_ok).await {
        let e = ServiceError::Call(e.to_string());
        emit(None, Some(e.to_string()));
        return Err(e.into());
    }
    let mut r = http::Request::new(body);
    *r.method_mut() = http::Method::POST;
    *r.uri_mut() = uri;
    *r.headers_mut() = headers;
    let sent =
        tokio::time::timeout_at(deadline.head, upstream.client(spec.private_ok).request(r)).await;
    let res = match sent {
        Err(_) => {
            let e = ServiceError::Timeout("first_byte_timeout");
            emit(None, Some(e.to_string()));
            return Err(e.into());
        }
        Ok(Err(e)) => {
            let e = ServiceError::Call(crate::upstream::describe(&e));
            emit(None, Some(e.to_string()));
            return Err(e.into());
        }
        Ok(Ok(res)) => res,
    };
    emit(Some(res.status().as_u16()), None);
    let reply = interpret(st, &addon.name, res, deadline.head).await?;
    Ok((deadline, reply))
}

/// The call's headers: the endpoint's (credentials expanded from secrets),
/// the content types, and the flow metadata.
fn call_headers(
    st: &StackFlow,
    layer: &str,
    spec: &super::EndpointSpec,
    uri: &http::Uri,
    direction: Direction,
) -> Result<HeaderMap, ServiceError> {
    let mut headers = HeaderMap::new();
    for (n, v) in &spec.headers {
        let v = endpoint::expand(v, &st.snap.secrets)
            .ok_or_else(|| ServiceError::Call(format!("endpoint header {n}: secret not loaded")))?;
        let v = HeaderValue::from_str(&v)
            .map_err(|_| ServiceError::Call(format!("endpoint header {n}")))?;
        headers.insert(n.clone(), v);
    }
    if let Some(a) = uri.authority()
        && let Ok(v) = HeaderValue::from_str(a.as_str())
    {
        headers.insert(HOST, v);
    }
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(message::MEDIA_TYPE));
    headers.insert(
        http::header::ACCEPT,
        HeaderValue::from_static("message/http, application/roxy-decision+json"),
    );
    flow_headers(st, layer, direction, &mut headers);
    Ok(headers)
}

/// What the service's answer means: a message to decode, or a decision.
async fn interpret(
    st: &StackFlow,
    layer: &str,
    res: http::Response<hyper::body::Incoming>,
    head_deadline: TokioInstant,
) -> Result<Reply, ServiceError> {
    if res.status() != http::StatusCode::OK {
        return Err(ServiceError::Status(res.status().as_u16()));
    }
    let ct = res
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        })
        .unwrap_or_default();
    let body = Body::wrap(res.into_body(), u64::MAX);
    if ct == message::MEDIA_TYPE {
        Ok(Reply::Message(body))
    } else if ct == DECISION_TYPE {
        let raw = tokio::time::timeout_at(head_deadline, body.collect_up_to(MAX_DECISION_BYTES))
            .await
            .map_err(|_| ServiceError::Timeout("first_byte_timeout"))?
            .map_err(|e| ServiceError::Decision(e.to_string()))?;
        let (name, res) = decision(st, &raw).map_err(ServiceError::Decision)?;
        st.add_tag(format!("{layer}:{name}"));
        Ok(Reply::Decision(res))
    } else {
        Err(ServiceError::ContentType(ct))
    }
}

/// `roxy-flow-*` metadata: who the client is and where the exchange is,
/// so the service can key its state. Values that are not valid header
/// values are left out.
fn flow_headers(st: &StackFlow, layer: &str, direction: Direction, h: &mut HeaderMap) {
    let mut put = |name: &'static str, value: &str| {
        if let Ok(v) = HeaderValue::from_str(value) {
            h.insert(HeaderName::from_static(name), v);
        }
    };
    put("roxy-flow-id", &st.flow.to_string());
    put("roxy-flow-conn", &st.client.id.to_string());
    put("roxy-flow-layer", layer);
    put("roxy-flow-direction", direction.as_str());
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

#[derive(Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum Decision {
    Deny(Deny),
    Respond(Respond),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Deny {
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    message: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Respond {
    status: u16,
    #[serde(default)]
    headers: HeaderList,
    #[serde(default)]
    body: String,
}

/// `{"name": "value"}`, or `[["name", "value"], ...]` for repeated fields.
#[derive(Deserialize)]
#[serde(untagged)]
enum HeaderList {
    Map(std::collections::BTreeMap<String, String>),
    Pairs(Vec<(String, String)>),
}

impl Default for HeaderList {
    fn default() -> Self {
        HeaderList::Pairs(Vec::new())
    }
}

impl HeaderList {
    fn pairs(&self) -> Vec<(&str, &str)> {
        match self {
            HeaderList::Map(m) => m.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect(),
            HeaderList::Pairs(p) => p.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect(),
        }
    }
}

/// Parses a decision into the response it gives, and its name.
fn decision(st: &StackFlow, raw: &Bytes) -> Result<(&'static str, LayerResponse), String> {
    let d: Decision = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    let (name, status, headers, body) = match d {
        Decision::Deny(d) => {
            let status = d.status.unwrap_or(403);
            if !(400..=599).contains(&status) {
                return Err(format!("deny status {status} is not 4xx or 5xx"));
            }
            let mut h = Headers::new();
            h.insert("content-type", "text/plain; charset=utf-8")
                .map_err(|e| e.to_string())?;
            let msg = d.message.unwrap_or_else(|| "request blocked".to_owned());
            (
                "deny",
                status,
                h,
                Bytes::from(format!("{}\n", msg.trim_end())),
            )
        }
        Decision::Respond(r) => {
            if !(200..=599).contains(&r.status) {
                return Err(format!("respond status {} is not 200-599", r.status));
            }
            let raw: Vec<(&[u8], &[u8])> = r
                .headers
                .pairs()
                .into_iter()
                .map(|(n, v)| (n.as_bytes(), v.as_bytes()))
                .collect();
            let h = Headers::try_from_raw(raw.iter().copied(), &st.snap.limits, &st.snap.flags)
                .map_err(|e| e.to_string())?;
            ("respond", r.status, h, Bytes::from(r.body))
        }
    };
    let status = http::StatusCode::from_u16(status).map_err(|e| e.to_string())?;
    let mut res = http::Response::new(Body::from_bytes(body));
    *res.status_mut() = status;
    *res.headers_mut() = headers.to_header_map();
    Ok((name, res))
}

/// A body from the service, cut (with the failure recorded against the
/// layer) if its stream fails or it runs past the layer's deadline.
fn watched(st: &Arc<StackFlow>, index: usize, body: Body, end: TokioInstant) -> Body {
    let known = body.known_length();
    Body::wrap_native(
        Watched {
            inner: body,
            st: st.clone(),
            index,
            sleep: Box::pin(tokio::time::sleep_until(end)),
            failed: false,
        },
        u64::MAX,
        known,
    )
}

struct Watched {
    inner: Body,
    st: Arc<StackFlow>,
    index: usize,
    sleep: Pin<Box<tokio::time::Sleep>>,
    failed: bool,
}

impl Watched {
    fn fail(&mut self, e: ServiceError) -> BodyError {
        self.failed = true;
        let name = self.st.snap.addons[self.index].name.clone();
        let msg = e.to_string();
        let err = StackError::Service(e);
        self.st.fail(&name, err.clone());
        super::emit_stack_error(&self.st, &name, &err, false);
        BodyError::Upstream(msg)
    }
}

impl HttpBody for Watched {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        if self.failed {
            return Poll::Ready(None);
        }
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Err(BodyError::Closed | BodyError::Stopped))) => {
                // The consumer went away: nothing failed here.
                Poll::Ready(Some(Err(BodyError::Stopped)))
            }
            Poll::Ready(Some(Err(e))) => {
                let e = self.fail(ServiceError::Stream(e.to_string()));
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(other) => Poll::Ready(other),
            Poll::Pending => {
                if self.sleep.as_mut().poll(cx).is_ready() {
                    let e = self.fail(ServiceError::Timeout("max_exchange_time"));
                    return Poll::Ready(Some(Err(e)));
                }
                Poll::Pending
            }
        }
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
