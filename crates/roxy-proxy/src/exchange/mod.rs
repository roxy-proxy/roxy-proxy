//! One request/response exchange: request steps → upstream → response
//! steps → client, on the h1 codec. A `101` hands the connection to the
//! relay in [`ws`].

mod ws;

use std::sync::Arc;
use std::time::Instant;

use http::header::HOST;
use http::{HeaderValue, StatusCode};
use hyper_util::rt::TokioIo;
use roxy_http::h1::ServerConn;
use roxy_http::upstream::{
    UriForm, from_upstream_response, to_upstream_request, to_upstream_upgrade_request,
};
use roxy_http::ws::{WsKey, validate_upgrade_request};
use roxy_http::{
    Body, BodyError, CanonicalRequest, CanonicalResponse, DriveError, Limits, ParseError, Reason,
    RequestMeta, WriteError,
};
use roxy_rules::RuleId;
use tokio_util::sync::CancellationToken;

use crate::addons::Reclaim;
use crate::addr::PrivateAddrs;
use crate::body::{Tally, counted, counted_until_sent, trailers_need_h2};
use crate::capture::{self, Tap};
use crate::flowlog::{DecisionKind, FlowEvent};
use crate::in_flight::{Dir, InFlight, in_flight_body};
use crate::io::ClientIo;
use crate::listener::ClientConn;
use crate::pipeline::{
    BodyIo, FlowCx, PerDir, Refusal, RefusalKind, ResponseVerdict, Verdict, body_failure, ms,
    request_steps, response_steps,
};
use crate::server::Shared;
use crate::upstream::{ConnectError, ConnectInfo, Protocols, UpstreamBody, classify, describe};
use crate::view::host_text;

pub(crate) use ws::{CLOSE_TIMEOUT, close_upstream_ws, prepare_websocket, relay_websocket};

/// The client connection after an exchange: `None` once it is closed.
pub(crate) type Next = Option<ServerConn<ClientIo>>;

/// Writes `res` (`res.meta.close` ends the connection after it).
pub(crate) async fn respond(mut conn: ServerConn<ClientIo>, res: CanonicalResponse) -> Next {
    if let Err(e) = conn.respond(res).await {
        tracing::debug!(error = %e, "writing response failed; closing");
        return None;
    }
    if conn.is_closed() {
        return None;
    }
    Some(conn)
}

/// Why a transport could not write a response.
#[derive(Debug)]
pub(crate) enum WriteFailure {
    /// An in-flight rule stopped the exchange mid-body; the transport cut the
    /// body (h1 closes the connection, h2 resets the stream).
    Stopped,
    /// The client stopped reading or went away.
    ClientGone(String),
    /// The client's HTTP/2 flow-control window stayed shut for
    /// `body_idle_timeout`; the transport cut the body.
    ClientStalled,
    /// The upstream sent no response-body frame for
    /// `response_body_idle_timeout`; the transport cut the body.
    UpstreamStalled,
    /// The client's request body was rejected (framing, a limit, a
    /// timeout) while the response was being written; the transport cut the
    /// body.
    Request(ParseError),
    /// Anything else: the upstream body failed mid-stream, a stalled or
    /// broken write.
    Io(String),
}

impl std::fmt::Display for WriteFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stopped => f.write_str("stopped by policy"),
            Self::ClientStalled => f.write_str("client flow-control window stalled"),
            Self::UpstreamStalled => f.write_str("response body idle timeout"),
            Self::Request(e) => write!(f, "{e}"),
            Self::ClientGone(s) | Self::Io(s) => f.write_str(s),
        }
    }
}

impl From<WriteError> for WriteFailure {
    fn from(e: WriteError) -> Self {
        match e {
            WriteError::Io(e) => Self::ClientGone(e.to_string()),
            WriteError::Body(BodyError::Stopped) => Self::Stopped,
            WriteError::Body(BodyError::Timeout) => Self::UpstreamStalled,
            WriteError::Request(e) => Self::Request(e),
            e @ (WriteError::Body(_) | WriteError::State(_)) => Self::Io(e.to_string()),
        }
    }
}

/// What a transport writes to end an exchange: the upstream's response (after
/// the response steps) or roxy's own answer.
pub(crate) enum Answer {
    Response(CanonicalResponse),
    Refusal(Refusal),
}

/// How a sent answer left the connection.
pub(crate) struct Sent {
    /// The write failed: the client got nothing, or a cut body.
    pub failed: bool,
    /// The exchange ends the connection: a closing refusal, or an in-flight
    /// stop that closes. The h1 codec sees the same value as
    /// `res.meta.close`; h2 sends GOAWAY on it.
    pub close: bool,
}

/// Sends `answer` through `write`, the transport's wire action, and does the
/// accounting around it: the flow record, a `response_error` event if the
/// write failed, the final metric sample and the `request` event. The
/// transport handlers write the bytes and observe client cancellation.
///
/// A layer's answer can reach the client while its forwarded request is
/// still running upstream. The final record waits for lane consumers,
/// drivers and accounting to finish. A refusal cancels the stack first.
pub(crate) async fn send(
    reclaim: Reclaim,
    answer: Answer,
    writer: &mut impl ResponseWriter,
) -> Sent {
    let (reclaim, mut res, refusal) = match answer {
        Answer::Response(res) => (reclaim, res, None),
        // A refusal is roxy's own answer: the stack, if there was one, is
        // done, and the record is to hand.
        Answer::Refusal(r) => {
            let mut cx = reclaim.take().await;
            let res = refusal_response(&mut cx, &r);
            (Reclaim::now(cx), res, Some(r))
        }
    };
    let (body, tally) = counted(std::mem::take(&mut res.body), reclaim.digest_response());
    res.body = body;
    let status = res.status.as_u16();
    let headers_bytes = res.headers.wire_len() as u64;
    // A refusal that travelled downstream through the stack as a response
    // carries its close here, where `Answer::Refusal` carries it in the
    // refusal.
    let closing = res.meta.close;
    let guard = reclaim.cancellation_guard();
    let r = writer.write(&mut res).await;
    let response_bytes = tally.bytes();
    let response_sha256 = tally.sha256_hex();
    match &r {
        Err(WriteFailure::ClientGone(_) | WriteFailure::ClientStalled) => {
            reclaim.tear_down(crate::addons::CLIENT_GONE);
        }
        Err(_) => reclaim.tear_down(crate::addons::ENDED),
        Ok(()) => {}
    }
    let body = if r.is_ok() {
        res.body
    } else {
        drop(res.body);
        Body::empty()
    };
    let (cx, cancellation) = writer.reclaim(reclaim, body).await;
    if let Some(guard) = guard {
        guard.complete();
    }
    let failed = r.is_err();
    let mut cx = Box::new(cx);
    // The response is complete. A later cancellation ends the remaining
    // upload or layer work without turning that response into a failed write.
    if let Some(e) = cancellation {
        record_cancellation(&mut cx, &e);
    }
    cx.record.response_status = Some(status);
    cx.record.response_headers_bytes = headers_bytes;
    cx.record.response_bytes = response_bytes;
    if cx.digest.response {
        cx.record.response_sha256 = response_sha256;
    }
    let stop = cx.in_flight.as_ref().and_then(|w| w.stopped());
    // Under a stop, the cut body is how the stop is delivered, not a
    // failure of its own.
    let failure = match r {
        Ok(()) | Err(WriteFailure::Stopped) => None,
        Err(e @ WriteFailure::ClientGone(_)) => Some(("client_gone".to_owned(), e)),
        Err(e @ WriteFailure::ClientStalled) => Some(("client_stalled".to_owned(), e)),
        Err(e @ WriteFailure::UpstreamStalled) => Some(("response_body_timeout".to_owned(), e)),
        Err(WriteFailure::Request(e)) => {
            Some((e.reason.as_str().to_owned(), WriteFailure::Request(e)))
        }
        // A body that failed into the addon stack was recorded there as
        // whoever's fault it was, before the cut reached the transport.
        Err(e @ WriteFailure::Io(_)) => {
            let reason = cx
                .stack
                .as_ref()
                .and_then(|st| st.fault_reason())
                .unwrap_or_else(|| "response_write_failed".to_owned());
            Some((reason, e))
        }
    };
    if stop.is_none()
        && let Some((reason, e)) = failure
    {
        emit_response_error(&cx, &reason, &e);
        cx.record.reason.get_or_insert(reason);
    }
    // One source for both transports: `refusal_response` sets `res.meta.close`
    // from the same field. A refusal of a forward made after the response
    // was written asked through the stack.
    let close = match &refusal {
        Some(r) => r.close,
        None => {
            closing
                || stop.as_ref().is_some_and(|s| s.refusal.close)
                || cx
                    .stack
                    .as_ref()
                    .is_some_and(|st| st.close.load(std::sync::atomic::Ordering::Relaxed))
        }
    };
    if let Some(r) = &refusal {
        finish_refusal(&mut cx, r);
    } else {
        // A client that stopped reading is not an upstream failure.
        cx.record_final_sample();
        cx.emit_request_event();
    }
    Sent { failed, close }
}

fn record_cancellation(cx: &mut FlowCx, e: &WriteFailure) {
    let reason = match e {
        WriteFailure::ClientGone(_) => cx
            .stack
            .as_ref()
            .and_then(|st| st.cancellation_reason())
            .unwrap_or("client_gone"),
        WriteFailure::Request(error) => {
            cx.shared.emit_parse_error(&cx.client, Some(cx), error);
            error.reason.as_str()
        }
        WriteFailure::Stopped => "in_flight_stopped",
        WriteFailure::ClientStalled => "client_stalled",
        WriteFailure::UpstreamStalled => "response_body_timeout",
        WriteFailure::Io(_) => "h2_stream_error",
    };
    cx.record.reason.get_or_insert_with(|| reason.to_owned());
}

pub(crate) fn emit_response_error(cx: &FlowCx, reason: &str, e: &dyn std::fmt::Display) {
    cx.shared.sink.emit(&FlowEvent::ResponseError {
        ts: chrono::Utc::now(),
        flow: cx.flow.to_string(),
        conn: cx.conn_id(),
        reason: reason.to_owned(),
        message: e.to_string(),
    });
}

/// Records a local refusal on the flow and builds its response. Pair with
/// [`finish_refusal`] once the response has been written.
pub(crate) fn refusal_response(cx: &mut FlowCx, refusal: &Refusal) -> CanonicalResponse {
    match refusal.kind {
        RefusalKind::Deny => {
            cx.record.decision = Some(DecisionKind::Deny);
            if refusal.rule.is_some() {
                cx.record.terminal_rule.clone_from(&refusal.rule);
            }
        }
        RefusalKind::UpstreamError => {
            if cx.record.decision.is_none() {
                cx.record.decision = Some(DecisionKind::Allow);
            }
        }
    }
    if refusal.reason.is_some() {
        cx.record.reason.clone_from(&refusal.reason);
    }
    let res = refusal.response(&cx.flow);
    cx.record.response_status = Some(refusal.status.as_u16());
    cx.record.response_headers_bytes = res.headers.wire_len() as u64;
    cx.record.response_bytes = res.body.known_length().unwrap_or(0);
    res
}

/// Final accounting for a refusal whose response has been written.
pub(crate) fn finish_refusal(cx: &mut FlowCx, refusal: &Refusal) {
    // Past the forwarding decision (the in-flight checker exists from then
    // on) the final sample is still due; admission denies were recorded then.
    if cx.in_flight.is_some() {
        cx.record_refusal_sample(refusal);
    }
    cx.emit_request_event();
}

/// Writes `answer` on the h1 codec and logs the exchange.
async fn answer(mut conn: ServerConn<ClientIo>, reclaim: Reclaim, answer: Answer) -> Next {
    let sent = send(reclaim, answer, &mut conn).await;
    (!sent.failed && !conn.is_closed()).then_some(conn)
}

/// Client output and reclamation share a transport owner. HTTP/1.1 pumps
/// the request body while writing the response. HTTP/2 also watches for
/// resets during reclamation, after an early response ended on the wire.
pub(crate) trait ResponseWriter {
    async fn write(&mut self, res: &mut CanonicalResponse) -> Result<(), WriteFailure>;

    async fn reclaim(&mut self, reclaim: Reclaim, body: Body) -> (FlowCx, Option<WriteFailure>);
}

impl ResponseWriter for ServerConn<ClientIo> {
    async fn write(&mut self, res: &mut CanonicalResponse) -> Result<(), WriteFailure> {
        self.respond_borrowed(res).await.map_err(WriteFailure::from)
    }

    async fn reclaim(&mut self, reclaim: Reclaim, body: Body) -> (FlowCx, Option<WriteFailure>) {
        reclaim
            .take_until(body, async {
                match self.client_lost().await {
                    Ok(()) => (
                        crate::addons::CLIENT_GONE,
                        WriteFailure::ClientGone("the HTTP/1 client closed".to_owned()),
                    ),
                    Err(error) => (crate::addons::ENDED, WriteFailure::Request(error)),
                }
            })
            .await
    }
}

/// Records a client-side failure (`status` is what the client was told, if
/// anything) on the flow and emits its `request` event.
pub(crate) fn record_client_failure(cx: &mut FlowCx, e: &ParseError, status: Option<u16>) {
    cx.record.decision.get_or_insert(DecisionKind::Deny);
    cx.record.reason = Some(e.reason.as_str().to_owned());
    cx.record.response_status = status;
    cx.emit_request_event();
}

/// The client went away mid-exchange (dropped the connection, or on h2
/// reset its stream): nothing is written; the flow is logged with reason
/// `client_gone`.
pub(crate) fn record_client_gone(cx: &mut FlowCx) {
    cx.record.decision.get_or_insert(DecisionKind::Deny);
    cx.record.reason = Some("client_gone".to_owned());
    cx.record.response_status = None;
    cx.emit_request_event();
}

/// roxy's own `100 Continue` could not be written: nothing more can reach
/// the client, so the flow is logged (reason `client_gone` when the client
/// went away, `continue_write_failed` otherwise) and the connection dropped.
pub(crate) fn record_continue_failure(cx: &mut FlowCx, e: WriteError) {
    let e = WriteFailure::from(e);
    let reason = match e {
        WriteFailure::ClientGone(_) => "client_gone",
        WriteFailure::Stopped
        | WriteFailure::ClientStalled
        | WriteFailure::UpstreamStalled
        | WriteFailure::Request(_)
        | WriteFailure::Io(_) => "continue_write_failed",
    };
    emit_response_error(cx, reason, &e);
    cx.record.reason = Some(reason.to_owned());
    cx.record.response_status = None;
    cx.emit_request_event();
}

/// The client body broke: answer with the parse error's status and close.
pub(crate) async fn close_on_parse_error(
    conn: ServerConn<ClientIo>,
    mut cx: Option<FlowCx>,
    client: &ClientConn,
    shared: &Shared,
    e: &ParseError,
) {
    shared.emit_parse_error(client, cx.as_ref(), e);
    let _ = conn
        .respond_error_and_close(e.reason.suggested_status(), &e.reason)
        .await;
    if let Some(cx) = cx.as_mut() {
        record_client_failure(cx, e, Some(e.reason.suggested_status().as_u16()));
    }
}

/// The exchange ended on the client side: a parse error is answered and
/// logged as the client's fault; a failed `100 Continue` is roxy's. EOF
/// is a client that left (h1 cannot tell a half-close from a departure):
/// there is nobody to answer, so nothing is written and the flow is
/// logged as `client_gone`, as on h2.
async fn close_on_drive_error(
    conn: ServerConn<ClientIo>,
    mut cx: FlowCx,
    shared: &Shared,
    e: DriveError,
) {
    match e {
        DriveError::Client(e) if e.reason == Reason::UnexpectedEof => {
            drop(conn);
            record_client_gone(&mut cx);
        }
        DriveError::Client(e) => {
            let client = cx.facts.client.clone();
            close_on_parse_error(conn, Some(cx), &client, shared, &e).await;
        }
        DriveError::Write(e) => {
            drop(conn);
            record_continue_failure(&mut cx, e);
        }
    }
}

/// The client side of an exchange, as the transport-agnostic core sees it:
/// body access for the inspecting steps ([`BodyIo`]) plus a way to wait for
/// the upstream while the client's request body keeps flowing.
pub(crate) trait ClientTransport: BodyIo {
    /// Runs `fut` (the upstream request) while the client's request body
    /// keeps flowing into it, answering `100 Continue` first if the client
    /// waits for it. `Err` means the client side ended the exchange (body
    /// invalid, too large, stalled, client gone, or the `100 Continue`
    /// could not be written): `fut` is dropped and the flow must not be
    /// answered as if it had been forwarded.
    fn drive<F>(
        &mut self,
        fut: F,
    ) -> impl std::future::Future<Output = Result<F::Output, DriveError>> + Send
    where
        F: std::future::Future + Send,
        F::Output: Send;
}

impl ClientTransport for ServerConn<ClientIo> {
    fn drive<F>(
        &mut self,
        fut: F,
    ) -> impl std::future::Future<Output = Result<F::Output, DriveError>> + Send
    where
        F: std::future::Future + Send,
        F::Output: Send,
    {
        ServerConn::drive(self, fut)
    }
}

/// The response or upgrade handoff returned to a transport. An outcome
/// can arrive while upload or layer work continues; reclamation waits for
/// that work before the final flow record is written.
pub(crate) enum Outcome {
    /// Send this response (from the upstream, after the response steps).
    Respond(CanonicalResponse),
    /// Answer locally (deny, fail-closed, upstream error).
    Refuse(Refusal),
    /// The client side ended the exchange: close (h1) or reset the stream
    /// (h2).
    Close(DriveError),
    /// An allowed WebSocket upgrade got its `101` (h1 only).
    Upgrade {
        res: CanonicalResponse,
        upstream: hyper::upgrade::Upgraded,
        key: WsKey,
    },
    /// A prepared upgrade whose relay is owned by the core stage.
    LayeredUpgrade {
        res: CanonicalResponse,
        client: crate::addons::WsClient,
    },
}

/// The transport-agnostic exchange: request steps → upstream → response
/// steps. `cx` carries the flow record and comes back with the outcome,
/// through the [`Reclaim`] when the addon stack may still hold it; the
/// caller writes the outcome and emits the flow's `request` event.
pub(crate) async fn process<F: ClientTransport>(
    transport: &mut F,
    mut cx: FlowCx,
    mut req: CanonicalRequest,
) -> (Reclaim, Outcome) {
    // Audit backpressure: an exchange starts only while the flow
    // log keeps up.
    crate::flowlog::sink_ready(&*cx.shared.sink).await;
    if cx.snap.http.strip_accept_encoding {
        // Before the layers and the rules, so all of them, and the flow
        // log, see the request as it will leave.
        req.headers.remove("accept-encoding");
        let facts = &mut cx.facts;
        for f in facts
            .client_request
            .iter_mut()
            .chain(facts.request.iter_mut())
        {
            f.headers.remove("accept-encoding");
        }
    }
    if let Some(refusal) = cx.quarantine_refusal() {
        return (Reclaim::now(cx), Outcome::Refuse(refusal));
    }
    if let Some(refusal) = cx.expiry_refusal() {
        return (Reclaim::now(cx), Outcome::Refuse(refusal));
    }
    let (reclaim, outcome) = if cx.snap.addons.is_empty() {
        let outcome = core(transport, &mut cx, req).await;
        (Reclaim::now(cx), outcome)
    } else {
        crate::addons::run(transport, cx, req).await
    };
    // A layer may have quarantined the process while it held the exchange:
    // whatever it answered, the client gets the refusal.
    match outcome {
        Outcome::Respond(_) | Outcome::Upgrade { .. } | Outcome::LayeredUpgrade { .. }
            if reclaim.quarantined() =>
        {
            match outcome {
                Outcome::Upgrade { upstream, .. } => {
                    tokio::spawn(close_upstream_ws(upstream));
                }
                other @ (Outcome::Respond(_)
                | Outcome::Refuse(_)
                | Outcome::Close(_)
                | Outcome::LayeredUpgrade { .. }) => drop(other),
            }
            reclaim.tear_down(crate::addons::ENDED);
            let mut cx = reclaim.take().await;
            let refusal = cx
                .late_quarantine_refusal()
                .unwrap_or_else(Refusal::quarantined);
            (Reclaim::now(cx), Outcome::Refuse(refusal))
        }
        Outcome::Respond(_)
        | Outcome::Upgrade { .. }
        | Outcome::LayeredUpgrade { .. }
        | Outcome::Refuse(_)
        | Outcome::Close(_) => (reclaim, outcome),
    }
}

/// The core stage validates policy, connects upstream and checks the
/// response. It runs directly without addons, or consumes the final
/// request lane after the enforcing layers.
pub(crate) async fn core<F: ClientTransport>(
    transport: &mut F,
    cx: &mut FlowCx,
    req: CanonicalRequest,
) -> Outcome {
    let verdict = request_steps(cx, req, transport).await;
    // Exhaustive, no wildcard: only `Continue` reaches the upstream.
    let outcome = match verdict {
        Verdict::Continue(req) => {
            cx.record.decision = Some(DecisionKind::Allow);
            forward(transport, cx, req).await
        }
        Verdict::Deny(refusal) => Outcome::Refuse(refusal),
        Verdict::Close(e) => Outcome::Close(e),
    };
    if matches!(outcome, Outcome::Refuse(_) | Outcome::Close(_)) {
        // A refusal has no remaining upload to deliver. Release its
        // adapters now, even if the HTTP client retains an unpolled body.
        drop(cx.request_delivery.take());
    }
    outcome
}

/// Runs one exchange on the h1 codec.
pub(crate) async fn run(
    mut conn: ServerConn<ClientIo>,
    req: CanonicalRequest,
    client: ClientConn,
    tls: Option<crate::flowlog::TlsInfo>,
    shared: &Arc<Shared>,
) -> Next {
    let snap = shared.snapshot();
    let cx = match FlowCx::new(shared.clone(), snap, client.clone(), tls, &req) {
        Ok(cx) => cx,
        Err(e) => {
            drop(req);
            close_on_parse_error(conn, None, &client, shared, &e).await;
            return None;
        }
    };
    let (reclaim, outcome) = process(&mut conn, cx, req).await;
    match outcome {
        Outcome::Respond(res) => answer(conn, reclaim, Answer::Response(res)).await,
        Outcome::Refuse(refusal) => answer(conn, reclaim, Answer::Refusal(refusal)).await,
        Outcome::Close(e) => {
            close_on_drive_error(conn, reclaim.take().await, shared, e).await;
            None
        }
        Outcome::Upgrade { res, upstream, key } => {
            ws::splice_websocket(conn, reclaim.take().await, res, upstream, &key).await
        }
        Outcome::LayeredUpgrade { res, client } => {
            ws::connect_stack(conn, reclaim, res, client).await
        }
    }
}

/// The `400` for a WebSocket handshake roxy will not relay, with and
/// without a stack.
pub(crate) fn bad_upgrade_refusal(reason: roxy_http::Reason) -> Refusal {
    Refusal {
        reason: Some(reason.as_str().to_owned()),
        ..Refusal::deny(
            StatusCode::BAD_REQUEST,
            "invalid websocket upgrade",
            RuleId::new("_websocket"),
            true,
        )
    }
}

fn upstream_refusal(cx: &FlowCx, e: &ConnectError, host: &str, port: u16) -> Refusal {
    if let ConnectError::Denied(d) = e {
        cx.shared.sink.emit(&FlowEvent::UpstreamDenied {
            ts: chrono::Utc::now(),
            flow: cx.flow.to_string(),
            conn: cx.conn_id(),
            host: host.to_owned(),
            port,
            resolved_ip: Some(d.ip),
            reason: d.reason.clone(),
            list: d.list.clone(),
            matched_cidr: d.matched_cidr.map(|c| c.to_string()),
        });
        tracing::info!(flow = %cx.flow, host, ip = %d.ip, reason = %d.reason, list = ?d.list, "upstream address denied");
        return Refusal::address_policy("address_policy");
    }
    let reason = e.reason();
    cx.shared.sink.emit(&FlowEvent::UpstreamError {
        ts: chrono::Utc::now(),
        flow: cx.flow.to_string(),
        conn: cx.conn_id(),
        host: host.to_owned(),
        port,
        reason: reason.to_owned(),
        message: e.to_string(),
    });
    tracing::info!(flow = %cx.flow, host, reason, error = %e, "upstream error");
    let status = if matches!(e, ConnectError::Timeout(_)) {
        StatusCode::GATEWAY_TIMEOUT
    } else {
        StatusCode::BAD_GATEWAY
    };
    Refusal::upstream(status, reason)
}

fn protocol_refusal(cx: &FlowCx, host: &str, port: u16, message: String) -> Refusal {
    cx.shared.sink.emit(&FlowEvent::UpstreamError {
        ts: chrono::Utc::now(),
        flow: cx.flow.to_string(),
        conn: cx.conn_id(),
        host: host.to_owned(),
        port,
        reason: "protocol_error".to_owned(),
        message,
    });
    Refusal::upstream(StatusCode::BAD_GATEWAY, "protocol_error")
}

/// What the upstream step produced.
enum Upstreamed {
    Response(http::Response<UpstreamBody>),
    /// A `101` for an allowed WebSocket upgrade, with the upgraded
    /// upstream connection.
    Upgrade {
        res: http::Response<hyper::body::Incoming>,
        upstream: hyper::upgrade::Upgraded,
        key: WsKey,
    },
}

/// Why the upstream leg produced no response.
enum Failed {
    /// Answer locally.
    Refuse(Refusal),
    /// The client side ended the exchange.
    Close(DriveError),
}

impl From<Failed> for Outcome {
    fn from(f: Failed) -> Self {
        match f {
            Failed::Refuse(r) => Self::Refuse(r),
            Failed::Close(e) => Self::Close(e),
        }
    }
}

/// The stop of an in-flight rule, as the outcome of an exchange whose
/// response has not started (answered with an error response).
fn stopped_outcome(in_flight: &InFlight) -> Option<Failed> {
    in_flight.stopped().map(|s| Failed::Refuse(s.refusal))
}

/// Waits for the upstream's response head.
///
/// `response_header_timeout` runs from the moment the request body has been
/// sent (`sent`), so a large upload on a slow link is not cut short by it.
/// While the body is still being sent, the wait fails only if the upstream
/// stops taking it: no body progress for twice `body_idle_timeout` (the
/// client side's own idle timeout, `body_idle_timeout`, catches a client
/// that stops sending first).
async fn response_head<F: Future>(
    fut: F,
    sent: CancellationToken,
    progress: Arc<Tally>,
    limits: &Limits,
) -> Result<F::Output, &'static str> {
    let mut fut = std::pin::pin!(fut);
    let stall = limits.body_idle_timeout.saturating_mul(2);
    let mut seen = progress.bytes();
    loop {
        tokio::select! {
            biased;
            out = &mut fut => return Ok(out),
            () = sent.cancelled() => break,
            () = tokio::time::sleep(stall) => {
                let now = progress.bytes();
                if now == seen {
                    return Err("upstream stopped reading the request body");
                }
                seen = now;
            }
        }
    }
    tokio::time::timeout(limits.response_header_timeout, fut)
        .await
        .map_err(|_| "upstream response headers")
}

/// The request asks for the one upgrade roxy can relay, a WebSocket. Any
/// other upgrade is stripped, and the request forwarded as an ordinary one.
pub(crate) fn wants_websocket(meta: &RequestMeta) -> bool {
    meta.upgrade
        .as_deref()
        .is_some_and(|u| u.eq_ignore_ascii_case("websocket"))
}

/// The forwarded exchange: the upstream leg (a plain request, or a
/// WebSocket upgrade), then the response steps. From here on the request
/// is on its way: in-flight rules re-check the exchange as values arrive,
/// and what is forwarded is teed to the capture log, heads included.
async fn forward<F: ClientTransport>(
    transport: &mut F,
    cx: &mut FlowCx,
    mut req: CanonicalRequest,
) -> Outcome {
    let in_flight = InFlight::new(cx);
    cx.in_flight = Some(in_flight.clone());
    let PerDir {
        request: mut up_tap,
        response: down_tap,
    } = taps(cx);
    let relay_ws = wants_websocket(&req.meta) && cx.opts.upgrade_websocket;
    if let Some(u) = &req.meta.upgrade
        && !relay_ws
    {
        // Plain `allow` strips the upgrade (the codec already removed
        // the hop-by-hop headers) and forwards an ordinary request.
        cx.shared.sink.emit(&FlowEvent::UpgradeStripped {
            ts: chrono::Utc::now(),
            flow: cx.flow.to_string(),
            conn: cx.conn_id(),
            upgrade: u.clone(),
        });
        req.meta.upgrade = None;
    }
    if let Err(e) = cx
        .snap
        .upstream
        .preflight(
            &req.authority,
            PrivateAddrs::from_private_ok(cx.opts.private_ok),
        )
        .await
    {
        let (host, port) = (host_text(&req.authority.host), req.authority.port);
        return Outcome::Refuse(upstream_refusal(cx, &e, &host, port));
    }
    let t0 = Instant::now();
    let upstreamed = if relay_ws {
        upgrade_upstream(cx, req, up_tap.as_mut()).await
    } else {
        plain_upstream(transport, cx, req, &in_flight, up_tap.take()).await
    };
    let upstreamed = match upstreamed {
        Ok(u) => u,
        Err(failed) => return failed.into(),
    };
    cx.record.ttfb_ms = Some(ms(t0.elapsed()));
    let (res, upgrade) = match upstreamed {
        Upstreamed::Response(res) => (res, None),
        Upstreamed::Upgrade { res, upstream, key } => {
            (res.map(UpstreamBody::untracked), Some((upstream, key)))
        }
    };
    let res = from_upstream_response(res, &cx.snap.limits);
    match response_steps(cx, res, transport).await {
        ResponseVerdict::Continue(mut res) => {
            let mut down_tap = down_tap;
            if let Some(t) = down_tap.as_mut() {
                t.response_head(&res);
            }
            if let Some((upstream, key)) = upgrade {
                // The relay takes the taps after the `101`.
                cx.taps = PerDir {
                    request: up_tap,
                    response: down_tap,
                };
                return Outcome::Upgrade { res, upstream, key };
            }
            let body = std::mem::take(&mut res.body);
            res.body = in_flight_body(body, in_flight, Dir::Response, down_tap);
            Outcome::Respond(res)
        }
        ResponseVerdict::Deny(r) => Outcome::Refuse(r),
        ResponseVerdict::Close(e) => Outcome::Close(e),
    }
}

/// The upstream leg of an allowed WebSocket upgrade: an HTTP/1.1
/// connection of its own, the whole handshake under
/// `response_header_timeout`. The upgraded connection is taken within the
/// same wait, so the client is only sent a `101` once roxy holds the
/// upstream side.
async fn upgrade_upstream(
    cx: &mut FlowCx,
    mut req: CanonicalRequest,
    up_tap: Option<&mut Tap>,
) -> Result<Upstreamed, Failed> {
    let (host, port) = (host_text(&req.authority.host), req.authority.port);
    let key = validate_upgrade_request(&req)
        .map_err(|e| Failed::Refuse(bad_upgrade_refusal(e.reason)))?;
    if crate::addons::ws_without_extensions(&cx.snap, cx.layer_reads_bytes) {
        // Messages are read, by the rules or by addon layers, so no
        // extension (permessage-deflate above all) may be negotiated.
        req.headers.remove("sec-websocket-extensions");
    }
    // The upgrade request is captured as it leaves, like any other.
    if let Some(t) = up_tap {
        t.request_head(&req);
    }
    let scheme = req.scheme;
    let authority = req.authority.clone();
    let mut http_req = to_upstream_upgrade_request(req, UriForm::Origin)
        .map_err(|e| Failed::Refuse(protocol_refusal(cx, &host, port, e.to_string())))?;
    set_host_override(cx, &mut http_req);
    let upstream_client = cx.snap.upstream.clone();
    let private = PrivateAddrs::from_private_ok(cx.opts.private_ok);
    let attempt = async {
        let dialled = Instant::now();
        let io = upstream_client
            .connect_h1(scheme, &authority, private)
            .await
            .map_err(Some)?;
        let dial = dialled.elapsed();
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake::<_, Body>(TokioIo::new(io))
                .await
                .map_err(|e| Some(ConnectError::Connect(format!("upstream handshake: {e}"))))?;
        tokio::spawn(async move {
            if let Err(e) = connection.with_upgrades().await {
                tracing::debug!(error = %e, "upstream websocket connection ended");
            }
        });
        let mut res = sender.send_request(http_req).await.map_err(|e| {
            tracing::debug!(error = %e, "websocket upgrade request failed");
            None
        })?;
        if res.status() != http::StatusCode::SWITCHING_PROTOCOLS {
            return Ok((res, None, dial));
        }
        let upgraded = hyper::upgrade::on(&mut res).await.map_err(|e| {
            tracing::debug!(error = %e, "upstream upgrade did not complete");
            None
        })?;
        Ok((res, Some(upgraded), dial))
    };
    let timeout = cx.snap.limits.response_header_timeout;
    match tokio::time::timeout(timeout, attempt).await {
        Err(_) => {
            let e = ConnectError::Timeout("upstream response headers");
            Err(Failed::Refuse(upstream_refusal(cx, &e, &host, port)))
        }
        Ok(Err(Some(e))) => Err(Failed::Refuse(upstream_refusal(cx, &e, &host, port))),
        Ok(Err(None)) => Err(Failed::Refuse(protocol_refusal(
            cx,
            &host,
            port,
            "upgrade request failed".into(),
        ))),
        Ok(Ok((res, upgraded, dial))) => {
            cx.record.upstream_connect_ms = Some(ms(dial));
            Ok(match upgraded {
                Some(upstream) => Upstreamed::Upgrade { res, upstream, key },
                None => Upstreamed::Response(res.map(UpstreamBody::untracked)),
            })
        }
    }
}

/// The upstream leg of an ordinary request through the pooled client,
/// the request body checked in flight and captured as it streams.
async fn plain_upstream<F: ClientTransport>(
    transport: &mut F,
    cx: &mut FlowCx,
    mut req: CanonicalRequest,
    in_flight: &Arc<InFlight>,
    up_tap: Option<Tap>,
) -> Result<Upstreamed, Failed> {
    let (host, port) = (host_text(&req.authority.host), req.authority.port);
    // Checked first: a chunk that makes a deny match is never counted
    // as forwarded nor handed to the upstream.
    let mut up_tap = up_tap;
    if let Some(t) = up_tap.as_mut() {
        t.request_head(&req);
    }
    let body = in_flight_body(
        std::mem::take(&mut req.body),
        in_flight.clone(),
        Dir::Request,
        up_tap,
    );
    let private = PrivateAddrs::from_private_ok(cx.opts.private_ok);
    let protocols = if cx.host_override.is_some() {
        Protocols::Http1Only
    } else {
        Protocols::Any
    };
    let body = trailers_need_h2(body, {
        let upstream = cx.snap.upstream.clone();
        let scheme = req.scheme.to_string();
        let authority = req.authority.to_host_header(req.scheme);
        move || upstream.may_be_h1(private, protocols, &scheme, &authority)
    });
    let (body, req_tally, sent) = counted_until_sent(body, cx.digest.request);
    // Read when the flow is logged, so bytes sent before an abandoned
    // forward, or after the response head, all count.
    cx.request_tally = Some(req_tally.clone());
    let (body, delivery) = crate::body::delivery(body);
    cx.request_delivery = Some(delivery);
    req.body = body;
    let mut http_req = to_upstream_request(req, UriForm::Absolute)
        .map_err(|e| Failed::Refuse(protocol_refusal(cx, &host, port, e.to_string())))?;
    set_host_override(cx, &mut http_req);
    let limits = cx.snap.limits.clone();
    let upstream = response_head(
        cx.snap
            .upstream
            .client(private, protocols)
            .request(http_req),
        sent,
        req_tally,
        &limits,
    );
    // A stop (from a request body chunk) abandons the upstream request
    // at once instead of waiting for its response.
    let stopped = in_flight.cancelled();
    let fut = async move {
        tokio::select! {
            biased;
            () = stopped => None,
            r = upstream => Some(r),
        }
    };
    let driven = transport.drive(fut).await;
    if let Some(o) = stopped_outcome(in_flight) {
        return Err(o);
    }
    match driven {
        Err(e) => Err(Failed::Close(e)),
        // Unreachable: a cancelled `InFlight` returned above. Fail closed.
        Ok(None) => Err(Failed::Refuse(Refusal::fail_closed("in_flight_stopped"))),
        Ok(Some(Err(what))) => {
            let e = ConnectError::Timeout(what);
            Err(Failed::Refuse(upstream_refusal(cx, &e, &host, port)))
        }
        Ok(Some(Ok(Err(e)))) => Err(match request_body_failure(&e) {
            Some(pe) => Failed::Close(DriveError::Client(pe)),
            None => Failed::Refuse(match classify(&e) {
                Some(ce) => upstream_refusal(cx, &ce, &host, port),
                None => protocol_refusal(cx, &host, port, describe(&e)),
            }),
        }),
        Ok(Some(Ok(Ok(res)))) => {
            if let Some(delivery) = &cx.request_delivery {
                delivery.start_monitor(limits.body_idle_timeout.saturating_mul(2), &cx.tasks);
            }
            cx.record.upstream_connect_ms = res
                .extensions()
                .get::<ConnectInfo>()
                .and_then(ConnectInfo::take_dial)
                .map(ms);
            Ok(Upstreamed::Response(res))
        }
    }
}

/// The request body failed while hyper was sending it (a frame roxy would
/// not forward, or the client side's own failure), which hyper reports as
/// its user's body error. That is the client's fault, mapped as body
/// failures are elsewhere; `None` leaves the error to be the upstream's.
fn request_body_failure(e: &hyper_util::client::legacy::Error) -> Option<ParseError> {
    let mut src: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(s) = src {
        if let Some(b) = s.downcast_ref::<BodyError>() {
            return Some(body_failure(b));
        }
        src = s.source();
    }
    None
}

fn set_host_override(cx: &FlowCx, req: &mut http::Request<Body>) {
    if let Some(h) = &cx.host_override {
        let v = HeaderValue::from_str(h)
            .expect("host_override is a to_host_header value, always a valid header value");
        req.headers_mut().insert(HOST, v);
    }
}

/// Capture taps for an exchange about to be forwarded: per direction, when
/// a `capture` effect selected it or the capture log takes everything.
fn taps(cx: &FlowCx) -> PerDir<Option<Tap>> {
    let Some(log) = &cx.shared.capture else {
        return PerDir::default();
    };
    let all = log.captures_all();
    let flow = cx.flow.to_string();
    let tap = |on: bool, dir| {
        (on || all).then(|| Tap::new(log.clone(), cx.secrets().clone(), &flow, dir))
    };
    PerDir {
        request: tap(cx.capture.request, capture::Dir::Request),
        response: tap(cx.capture.response, capture::Dir::Response),
    }
}
