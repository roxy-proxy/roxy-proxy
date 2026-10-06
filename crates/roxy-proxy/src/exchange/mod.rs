//! One request/response exchange: request steps → upstream → response
//! steps → client, on the h1 codec. A `101` hands the connection to the
//! relay in [`ws`].

mod ws;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
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

use crate::addr::PrivateAddrs;
use crate::body::{counted, counted_until_sent, trailers_need_h2};
use crate::capture::{self, Tap};
use crate::flowlog::{DecisionKind, FlowEvent};
use crate::io::ClientIo;
use crate::listener::ClientConn;
use crate::pipeline::{
    BodyIo, FlowCx, PerDir, Refusal, RefusalKind, ResponseVerdict, Verdict, body_failure,
    request_steps, response_steps,
};
use crate::server::Shared;
use crate::upstream::{ConnectError, Protocols, classify, describe};
use crate::view::host_text;
use crate::watch::{Dir, Watch, watched};

pub(crate) use ws::close_upstream_ws;

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

/// Why a front could not write a response.
#[derive(Debug)]
pub(crate) enum WriteFailure {
    /// A watching rule stopped the exchange mid-body; the front cut the
    /// body (h1 closes the connection, h2 resets the stream).
    Stopped,
    /// The client stopped reading or went away.
    ClientGone(String),
    /// The client's HTTP/2 flow-control window stayed shut for
    /// `body_idle_timeout`; the front cut the body.
    ClientStalled,
    /// The upstream sent no response-body frame for
    /// `response_body_idle_timeout`; the front cut the body.
    UpstreamStalled,
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
            e @ (WriteError::Body(_) | WriteError::Request(_) | WriteError::State(_)) => {
                Self::Io(e.to_string())
            }
        }
    }
}

/// What a front writes to end an exchange: the upstream's response (after
/// the response steps) or roxy's own answer.
pub(crate) enum Answer {
    Response(CanonicalResponse),
    Refusal(Refusal),
}

/// How a sent answer left the connection.
pub(crate) struct Sent {
    /// The write failed: the client got nothing, or a cut body.
    pub failed: bool,
    /// The exchange ends the connection: a closing refusal, or a watching
    /// stop that closes. The h1 codec sees the same value as
    /// `res.meta.close`; h2 sends GOAWAY on it.
    pub close: bool,
}

/// Sends `answer` through `write`, the front's wire action, and does the
/// accounting around it: the flow record, a `response_error` event if the
/// write failed, the final metric sample and the `request` event. The
/// fronts only write bytes.
pub(crate) async fn send<W, Fut>(cx: &mut FlowCx, answer: Answer, write: W) -> Sent
where
    W: FnOnce(CanonicalResponse) -> Fut,
    Fut: std::future::Future<Output = Result<(), WriteFailure>>,
{
    let (mut res, refusal) = match answer {
        Answer::Response(res) => (res, None),
        Answer::Refusal(r) => (refusal_response(cx, &r), Some(r)),
    };
    let (body, counter) = counted(std::mem::take(&mut res.body));
    res.body = body;
    cx.record.response_status = Some(res.status.as_u16());
    cx.record.response_headers_bytes = res.headers.wire_len() as u64;
    let r = write(res).await;
    let failed = r.is_err();
    cx.record.response_bytes = counter.load(Ordering::Relaxed);
    let stop = cx.watch.as_ref().and_then(|w| w.stopped());
    // Under a stop, the cut body is how the stop is delivered, not a
    // failure of its own.
    let failure = match r {
        Ok(()) | Err(WriteFailure::Stopped) => None,
        Err(e @ WriteFailure::ClientGone(_)) => Some(("client_gone", e)),
        Err(e @ WriteFailure::ClientStalled) => Some(("client_stalled", e)),
        Err(e @ WriteFailure::UpstreamStalled) => Some(("response_body_timeout", e)),
        Err(e @ WriteFailure::Io(_)) => Some(("response_write_failed", e)),
    };
    if stop.is_none()
        && let Some((reason, e)) = failure
    {
        emit_response_error(cx, reason, &e);
        cx.record.reason.get_or_insert_with(|| reason.to_owned());
    }
    // One source for both fronts: `refusal_response` sets `res.meta.close`
    // from the same field.
    let close = match &refusal {
        Some(r) => r.close,
        None => stop.as_ref().is_some_and(|s| s.refusal.close),
    };
    if let Some(r) = &refusal {
        finish_refusal(cx, r);
    } else {
        // A client that stopped reading is not an upstream failure.
        cx.record_final_sample();
        cx.emit_request_event();
    }
    Sent { failed, close }
}

fn emit_response_error(cx: &FlowCx, reason: &str, e: &dyn std::fmt::Display) {
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
    // Past the forwarding decision (the watcher exists from then on) the
    // final sample is still due; head denies were recorded at the head.
    if cx.watch.is_some() {
        cx.record_refusal_sample(refusal);
    }
    cx.emit_request_event();
}

/// Writes `answer` on the h1 codec and logs the exchange.
async fn answer(mut conn: ServerConn<ClientIo>, mut cx: FlowCx, answer: Answer) -> Next {
    let sent = send(&mut cx, answer, |res| async {
        conn.respond(res).await.map_err(WriteFailure::from)
    })
    .await;
    (!sent.failed && !conn.is_closed()).then_some(conn)
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
    shared.emit_parse_error(client, cx.as_ref().map(|c| c.flow.to_string()), e);
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
pub(crate) trait Front: BodyIo {
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

impl Front for ServerConn<ClientIo> {
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

/// What the transport-agnostic core decided. Each front end (h1 codec, h2
/// stream) turns this into wire actions. Nothing here forwards: the
/// upstream exchange has already happened (or was refused) by the time an
/// outcome exists.
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
}

/// The transport-agnostic exchange: request steps → upstream → response
/// steps. `cx` carries the flow record and comes back with the outcome
/// (through the addon stack, if there is one); the caller writes the
/// outcome and emits the flow's `request` event.
pub(crate) async fn process<F: Front>(
    front: &mut F,
    mut cx: FlowCx,
    mut req: CanonicalRequest,
) -> (FlowCx, Outcome) {
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
    if cx.snap.addons.is_empty() {
        let outcome = core(front, &mut cx, req).await;
        (cx, outcome)
    } else {
        crate::addons::run(front, cx, req).await
    }
}

/// The exchange below the addons: the request steps (the rules) → upstream →
/// the response steps. Reached directly when no addon is configured, and from
/// the last layer's `next` otherwise.
pub(crate) async fn core<F: Front>(
    front: &mut F,
    cx: &mut FlowCx,
    req: CanonicalRequest,
) -> Outcome {
    let verdict = request_steps(cx, req, front).await;
    // Exhaustive, no wildcard: only `Continue` reaches the upstream.
    match verdict {
        Verdict::Continue(req) => {
            cx.record.decision = Some(DecisionKind::Allow);
            forward(front, cx, req).await
        }
        Verdict::Deny(refusal) => Outcome::Refuse(refusal),
        Verdict::Close(e) => Outcome::Close(e),
    }
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
    let cx = FlowCx::new(shared.clone(), snap, client, tls, &req);
    let (cx, outcome) = process(&mut conn, cx, req).await;
    match outcome {
        Outcome::Respond(res) => answer(conn, cx, Answer::Response(res)).await,
        Outcome::Refuse(refusal) => answer(conn, cx, Answer::Refusal(refusal)).await,
        Outcome::Close(e) => {
            close_on_drive_error(conn, cx, shared, e).await;
            None
        }
        Outcome::Upgrade { res, upstream, key } => {
            ws::splice_websocket(conn, cx, res, upstream, &key).await
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
    Response(http::Response<hyper::body::Incoming>),
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

/// The stop of a watching rule, as the outcome of an exchange whose
/// response has not started (answered with an error response).
fn stopped_outcome(watch: &Watch) -> Option<Failed> {
    watch.stopped().map(|s| Failed::Refuse(s.refusal))
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
    progress: Arc<AtomicU64>,
    limits: &Limits,
) -> Result<F::Output, &'static str> {
    let mut fut = std::pin::pin!(fut);
    let stall = limits.body_idle_timeout.saturating_mul(2);
    let mut seen = progress.load(Ordering::Relaxed);
    loop {
        tokio::select! {
            biased;
            out = &mut fut => return Ok(out),
            () = sent.cancelled() => break,
            () = tokio::time::sleep(stall) => {
                let now = progress.load(Ordering::Relaxed);
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
/// is on its way: watching rules re-check the exchange as values arrive,
/// and what is forwarded is teed to the capture log, heads included.
async fn forward<F: Front>(front: &mut F, cx: &mut FlowCx, mut req: CanonicalRequest) -> Outcome {
    let watch = Watch::new(cx);
    cx.watch = Some(watch.clone());
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
        plain_upstream(front, cx, req, &watch, up_tap.take()).await
    };
    let upstreamed = match upstreamed {
        Ok(u) => u,
        Err(failed) => return failed.into(),
    };
    cx.record.ttfb_ms = Some(u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX));
    let (res, upgrade) = match upstreamed {
        Upstreamed::Response(res) => (res, None),
        Upstreamed::Upgrade { res, upstream, key } => (res, Some((upstream, key))),
    };
    let res = from_upstream_response(res, &cx.snap.limits);
    match response_steps(cx, res, front).await {
        ResponseVerdict::Continue(mut res) => {
            let mut down_tap = down_tap;
            if let Some(t) = down_tap.as_mut() {
                t.response_head(&res, &cx.snap.secrets.redactor());
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
            res.body = watched(body, watch, Dir::Response, down_tap);
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
    if crate::addons::ws_without_extensions(&cx.snap, cx.layer_ran) {
        // Messages are read, by the rules or by addon layers, so no
        // extension (permessage-deflate above all) may be negotiated.
        req.headers.remove("sec-websocket-extensions");
    }
    // The upgrade request is captured as it leaves, like any other.
    if let Some(t) = up_tap {
        t.request_head(&req, &cx.snap.secrets.redactor());
    }
    let scheme = req.scheme;
    let authority = req.authority.clone();
    let mut http_req = to_upstream_upgrade_request(req, UriForm::Origin)
        .map_err(|e| Failed::Refuse(protocol_refusal(cx, &host, port, e.to_string())))?;
    set_host_override(cx, &mut http_req);
    let upstream_client = cx.snap.upstream.clone();
    let private = PrivateAddrs::from_private_ok(cx.opts.private_ok);
    let attempt = async {
        let io = upstream_client
            .connect_h1(scheme, &authority, private)
            .await
            .map_err(Some)?;
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
            return Ok((res, None));
        }
        let upgraded = hyper::upgrade::on(&mut res).await.map_err(|e| {
            tracing::debug!(error = %e, "upstream upgrade did not complete");
            None
        })?;
        Ok((res, Some(upgraded)))
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
        Ok(Ok((res, Some(upstream)))) => Ok(Upstreamed::Upgrade { res, upstream, key }),
        Ok(Ok((res, None))) => Ok(Upstreamed::Response(res)),
    }
}

/// The upstream leg of an ordinary request through the pooled client,
/// the request body watched and captured as it streams.
async fn plain_upstream<F: Front>(
    front: &mut F,
    cx: &mut FlowCx,
    mut req: CanonicalRequest,
    watch: &Arc<Watch>,
    up_tap: Option<Tap>,
) -> Result<Upstreamed, Failed> {
    let (host, port) = (host_text(&req.authority.host), req.authority.port);
    // Watched first: a chunk that makes a deny match is never counted
    // as forwarded nor handed to the upstream.
    let mut up_tap = up_tap;
    if let Some(t) = up_tap.as_mut() {
        t.request_head(&req, &cx.snap.secrets.redactor());
    }
    let body = watched(
        std::mem::take(&mut req.body),
        watch.clone(),
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
    let (body, req_counter, sent) = counted_until_sent(body);
    // Read when the flow is logged, so bytes sent before an abandoned
    // forward, or after the response head, all count.
    cx.request_counter = Some(req_counter.clone());
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
        req_counter,
        &limits,
    );
    // A stop (from a request body chunk) abandons the upstream request
    // at once instead of waiting for its response.
    let stopped = watch.cancelled();
    let fut = async move {
        tokio::select! {
            biased;
            () = stopped => None,
            r = upstream => Some(r),
        }
    };
    let driven = front.drive(fut).await;
    if let Some(o) = stopped_outcome(watch) {
        return Err(o);
    }
    match driven {
        Err(e) => Err(Failed::Close(e)),
        // Unreachable: a cancelled watch returned above. Fail closed.
        Ok(None) => Err(Failed::Refuse(Refusal::fail_closed("watch_stopped"))),
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
        Ok(Some(Ok(Ok(res)))) => Ok(Upstreamed::Response(res)),
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
    if let Some(h) = &cx.host_override
        && let Ok(v) = HeaderValue::from_str(h)
    {
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
    let tap = |on: bool, dir| (on || all).then(|| Tap::new(log.clone(), &flow, dir));
    PerDir {
        request: tap(cx.capture.request, capture::Dir::Request),
        response: tap(cx.capture.response, capture::Dir::Response),
    }
}
