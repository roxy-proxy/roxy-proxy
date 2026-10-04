//! One request/response exchange: request steps → upstream → response
//! steps → client, plus the WebSocket relay and
//! its message-checking form.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use http::HeaderValue;
use http::header::HOST;
use hyper_util::rt::TokioIo;
use roxy_http::h1::ServerConn;
use roxy_http::upstream::{
    UriForm, from_upstream_response, to_upstream_request, to_upstream_upgrade_request,
};
use roxy_http::ws::frame::{self, Decoder, FrameError, Opcode, Peer, close};
use roxy_http::ws::{
    WsKey, validate_no_extensions, validate_upgrade_request, validate_upgrade_response,
};
use roxy_http::{Body, CanonicalRequest, CanonicalResponse, Limits, ParseError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use crate::body::{counted, counted_until_sent};
use crate::capture::{self, Tap};
use crate::flowlog::{DecisionKind, FlowEvent};
use crate::io::{ConnIo, Io};
use crate::listener::ClientConn;
use crate::pipeline::{
    BodyIo, FlowCx, Refusal, RefusalKind, ResponseVerdict, Verdict, request_steps, response_steps,
};
use crate::server::Shared;
use crate::upstream::{ConnectError, classify, describe};
use crate::view::host_text;
use crate::watch::{Dir, Watch, watched};

/// The client connection after an exchange: `None` once it is closed.
pub(crate) type Next = Option<ServerConn<ConnIo>>;

/// How the client asked to be treated (for `connection: close` injection).
#[derive(Debug, Clone, Copy)]
pub(crate) struct ClientFraming {
    /// The client sent `Connection: close` (the codec already closes).
    pub close: bool,
}

/// Writes `res`. With `close`, the response carries `connection: close`
/// and the connection is shut down
/// gracefully afterwards. `extra` are additional raw header lines.
pub(crate) async fn respond(
    mut conn: ServerConn<ConnIo>,
    handle: &ConnIo,
    res: CanonicalResponse,
    close: bool,
    framing: ClientFraming,
    extra: &[u8],
) -> Next {
    let mut lines = extra.to_vec();
    if close && !framing.close {
        lines.extend_from_slice(b"connection: close\r\n");
    }
    handle.inject_after_status_line(lines);
    let r = conn.respond(res).await;
    if let Err(e) = &r {
        tracing::debug!(error = %e, "writing response failed; closing");
    }
    if r.is_err() || conn.is_closed() {
        return None;
    }
    if close {
        drop(conn);
        handle.close_gracefully().await;
        return None;
    }
    Some(conn)
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
    cx.record.response_status = Some(refusal.status);
    cx.record.response_headers_bytes = res.headers.wire_len() as u64;
    cx.record.response_bytes = res.body.known_length().unwrap_or(0);
    res
}

/// Final accounting for a refusal whose response has been written.
pub(crate) fn finish_refusal(cx: &mut FlowCx, refusal: &Refusal) {
    // After a forwarded request (upstream failure, a watching stop) the
    // final sample is still due; head denies were recorded at the head.
    let upstream_error = refusal.kind == RefusalKind::UpstreamError;
    if cx.watch.is_some() {
        cx.record_final_sample(upstream_error);
    }
    cx.emit_request_event();
}

/// Answers a flow locally and logs it.
pub(crate) async fn refuse(
    conn: ServerConn<ConnIo>,
    handle: &ConnIo,
    mut cx: FlowCx,
    refusal: Refusal,
    framing: ClientFraming,
) -> Next {
    let res = refusal_response(&mut cx, &refusal);
    let next = respond(conn, handle, res, refusal.close, framing, b"").await;
    finish_refusal(&mut cx, &refusal);
    next
}

/// Records a client-side failure (`status` is what the client was told, if
/// anything) on the flow and emits its `request` event.
pub(crate) fn record_client_failure(cx: &mut FlowCx, e: &ParseError, status: Option<u16>) {
    cx.record.decision.get_or_insert(DecisionKind::Deny);
    cx.record.reason = Some(e.reason.as_str().to_owned());
    cx.record.response_status = status;
    cx.emit_request_event();
}

/// The client body broke: answer with the parse error's status and close.
pub(crate) async fn close_on_parse_error(
    conn: ServerConn<ConnIo>,
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

/// The client side of an exchange, as the transport-agnostic core sees it:
/// body access for the inspecting steps ([`BodyIo`]) plus a way to wait for
/// the upstream while the client's request body keeps flowing.
pub(crate) trait Front: BodyIo {
    /// Runs `fut` (the upstream request) while the client's request body
    /// keeps flowing into it, answering `100 Continue` first if the client
    /// waits for it. `Err` means the client side broke (body invalid, too
    /// large, stalled, client gone): `fut` is dropped and the flow must not
    /// be answered as if it had been forwarded.
    fn drive<F>(
        &mut self,
        fut: F,
    ) -> impl std::future::Future<Output = Result<F::Output, ParseError>> + Send
    where
        F: std::future::Future + Send,
        F::Output: Send;
}

impl Front for ServerConn<ConnIo> {
    fn drive<F>(
        &mut self,
        fut: F,
    ) -> impl std::future::Future<Output = Result<F::Output, ParseError>> + Send
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
    /// The client side broke: close (h1) or reset the stream (h2).
    Close(ParseError),
    /// An allowed WebSocket upgrade got its `101` (h1 only).
    Upgrade {
        res: CanonicalResponse,
        upstream: hyper::upgrade::Upgraded,
        key: WsKey,
    },
}

/// The transport-agnostic exchange: request steps → upstream → response
/// steps. `cx` carries the flow record; the caller writes the outcome and
/// emits the flow's `request` event.
pub(crate) async fn process<F: Front>(
    front: &mut F,
    cx: &mut FlowCx,
    mut req: CanonicalRequest,
) -> Outcome {
    // Audit backpressure: an exchange starts only while the flow
    // log keeps up.
    crate::flowlog::sink_ready(&*cx.shared.sink).await;
    if cx.snap.flags.strip_accept_encoding {
        // Before the layers and the rules, so all of them, and the flow
        // log, see the request as it will leave.
        req.headers.remove("accept-encoding");
        if let Some(f) = cx.facts.request.as_mut() {
            f.headers.remove("accept-encoding");
        }
    }
    if cx.snap.addons.is_empty() {
        core(front, cx, req).await
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
    mut conn: ServerConn<ConnIo>,
    handle: &ConnIo,
    req: CanonicalRequest,
    client: ClientConn,
    tls: Option<crate::flowlog::TlsInfo>,
    shared: &Arc<Shared>,
) -> Next {
    let snap = shared.snapshot();
    let framing = ClientFraming {
        close: req.meta.close,
    };
    let mut cx = FlowCx::new(shared.clone(), snap, client, tls, &req);
    match process(&mut conn, &mut cx, req).await {
        Outcome::Respond(res) => send_response(conn, cx, res).await,
        Outcome::Refuse(refusal) => refuse(conn, handle, cx, refusal, framing).await,
        Outcome::Close(e) => {
            let client = cx.facts.client.clone();
            close_on_parse_error(conn, Some(cx), &client, shared, &e).await;
            None
        }
        Outcome::Upgrade { res, upstream, key } => {
            splice_websocket(conn, handle, cx, res, upstream, &key, framing).await
        }
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
        504
    } else {
        502
    };
    Refusal::upstream(status, reason, "upstream unavailable")
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
    Refusal::upstream(502, "protocol_error", "upstream protocol error")
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

/// The stop of a watching rule, as the outcome of an exchange whose
/// response has not started (answered with an error response).
fn stopped_outcome(watch: &Watch) -> Option<Outcome> {
    watch.stopped().map(|s| Outcome::Refuse(s.refusal))
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

#[allow(clippy::too_many_lines)] // one linear flow; splitting it obscures the order
async fn forward<F: Front>(front: &mut F, cx: &mut FlowCx, mut req: CanonicalRequest) -> Outcome {
    // From here on the request is on its way: watching rules re-check the
    // exchange as values arrive.
    let watch = Watch::new(cx);
    cx.watch = Some(watch.clone());
    // Capture: what is forwarded from here on is teed to the
    // capture log, heads included.
    let (mut up_tap, down_tap) = taps(cx);
    let host = host_text(&req.authority.host);
    let port = req.authority.port;
    let private_ok = cx.opts.private_ok;
    let wants_ws = req
        .meta
        .upgrade
        .as_deref()
        .is_some_and(|u| u.eq_ignore_ascii_case("websocket"));
    let relay_ws = wants_ws && cx.opts.upgrade_websocket;
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
    let upstream_client = cx.snap.upstream.clone();
    if let Err(e) = upstream_client.preflight(&req.authority, private_ok).await {
        return Outcome::Refuse(upstream_refusal(cx, &e, &host, port));
    }
    let limits = cx.snap.limits.clone();
    let t0 = Instant::now();

    let upstreamed = if relay_ws {
        let key = match validate_upgrade_request(&req) {
            Ok(k) => k,
            Err(e) => {
                return Outcome::Refuse(Refusal {
                    reason: Some(e.reason.as_str().to_owned()),
                    ..Refusal::deny(400, "invalid websocket upgrade", "_websocket", true)
                });
            }
        };
        if crate::addons::ws_without_extensions(&cx.snap) {
            // Messages are read, by the rules or by `tunnel` layers, so no
            // extension (permessage-deflate above all) may be negotiated.
            req.headers.remove("sec-websocket-extensions");
        }
        // The upgrade request is captured as it leaves, like any other.
        if let Some(t) = up_tap.as_mut() {
            t.request_head(&req, &cx.snap.redactor);
        }
        let scheme = req.scheme;
        let authority = req.authority.clone();
        let mut http_req = match to_upstream_upgrade_request(req, UriForm::Origin) {
            Ok(r) => r,
            Err(e) => {
                return Outcome::Refuse(protocol_refusal(cx, &host, port, e.to_string()));
            }
        };
        set_host_override(cx, &mut http_req);
        let attempt = async {
            let io = upstream_client
                .connect_h1(scheme, &authority, private_ok)
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
            // The upgraded connection is taken within the same wait, so the
            // client is only sent a `101` once roxy holds the upstream side.
            let upgraded = hyper::upgrade::on(&mut res).await.map_err(|e| {
                tracing::debug!(error = %e, "upstream upgrade did not complete");
                None
            })?;
            Ok((res, Some(upgraded)))
        };
        match tokio::time::timeout(limits.response_header_timeout, attempt).await {
            Err(_) => {
                return Outcome::Refuse(upstream_refusal(
                    cx,
                    &ConnectError::Timeout("upstream response headers"),
                    &host,
                    port,
                ));
            }
            Ok(Err(Some(e))) => {
                return Outcome::Refuse(upstream_refusal(cx, &e, &host, port));
            }
            Ok(Err(None)) => {
                return Outcome::Refuse(protocol_refusal(
                    cx,
                    &host,
                    port,
                    "upgrade request failed".into(),
                ));
            }
            Ok(Ok((res, Some(upstream)))) => Upstreamed::Upgrade { res, upstream, key },
            Ok(Ok((res, None))) => Upstreamed::Response(res),
        }
    } else {
        // Watched first: a chunk that makes a deny match is never counted
        // as forwarded nor handed to the upstream.
        if let Some(t) = up_tap.as_mut() {
            t.request_head(&req, &cx.snap.redactor);
        }
        let body = watched(
            std::mem::take(&mut req.body),
            watch.clone(),
            Dir::Request,
            up_tap.take(),
        );
        let (body, req_counter, sent) = counted_until_sent(body);
        req.body = body;
        let mut http_req = match to_upstream_request(req, UriForm::Absolute) {
            Ok(r) => r,
            Err(e) => {
                return Outcome::Refuse(protocol_refusal(cx, &host, port, e.to_string()));
            }
        };
        set_host_override(cx, &mut http_req);
        let upstream = response_head(
            upstream_client
                .client(private_ok, cx.host_override.is_some())
                .request(http_req),
            sent,
            req_counter.clone(),
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
        cx.record.request_bytes = req_counter.load(Ordering::Relaxed);
        if let Some(o) = stopped_outcome(&watch) {
            return o;
        }
        match driven {
            Err(e) => return Outcome::Close(e),
            // Unreachable: a cancelled watch returned above. Fail closed.
            Ok(None) => return Outcome::Refuse(Refusal::fail_closed("watch_stopped")),
            Ok(Some(Err(what))) => {
                return Outcome::Refuse(upstream_refusal(
                    cx,
                    &ConnectError::Timeout(what),
                    &host,
                    port,
                ));
            }
            Ok(Some(Ok(Err(e)))) => {
                return Outcome::Refuse(match classify(&e) {
                    Some(ce) => upstream_refusal(cx, &ce, &host, port),
                    None => protocol_refusal(cx, &host, port, describe(&e)),
                });
            }
            Ok(Some(Ok(Ok(res)))) => Upstreamed::Response(res),
        }
    };
    cx.record.ttfb_ms = Some(u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX));

    let (res, upgrade) = match upstreamed {
        Upstreamed::Response(res) => (res, None),
        Upstreamed::Upgrade { res, upstream, key } => (res, Some((upstream, key))),
    };
    let res = from_upstream_response(res, &limits);
    let verdict = response_steps(cx, res, front).await;
    match verdict {
        ResponseVerdict::Continue(mut res) => {
            let mut down_tap = down_tap;
            if let Some(t) = down_tap.as_mut() {
                t.response_head(&res, &cx.snap.redactor);
            }
            if let Some((upstream, key)) = upgrade {
                // The relay takes the taps after the `101`.
                cx.taps = (up_tap, down_tap);
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

fn set_host_override(cx: &FlowCx, req: &mut http::Request<Body>) {
    if let Some(h) = &cx.host_override
        && let Ok(v) = HeaderValue::from_str(h)
    {
        req.headers_mut().insert(HOST, v);
    }
}

async fn send_response(
    mut conn: ServerConn<ConnIo>,
    mut cx: FlowCx,
    mut res: CanonicalResponse,
) -> Next {
    let (body, counter) = counted(std::mem::take(&mut res.body));
    res.body = body;
    cx.record.response_status = Some(res.status.as_u16());
    cx.record.response_headers_bytes = res.headers.wire_len() as u64;
    let r = conn.respond(res).await;
    // A watching stop mid-body ends the body with an error: the codec stops
    // before any terminating chunk and the connection is dropped.
    let stopped = cx.watch.as_ref().is_some_and(|w| w.stopped().is_some());
    let failed = r.is_err() && !stopped;
    let next = match r {
        Err(_) if stopped => None,
        Err(e) => {
            cx.shared.sink.emit(&FlowEvent::ResponseError {
                ts: chrono::Utc::now(),
                flow: cx.flow.to_string(),
                conn: cx.conn_id(),
                reason: "response_write_failed".to_owned(),
                message: e.to_string(),
            });
            None
        }
        Ok(()) if conn.is_closed() => None,
        Ok(()) => Some(conn),
    };
    cx.record.response_bytes = counter.load(Ordering::Relaxed);
    cx.record_final_sample(failed);
    cx.emit_request_event();
    next
}

async fn splice_websocket(
    conn: ServerConn<ConnIo>,
    handle: &ConnIo,
    mut cx: FlowCx,
    res: CanonicalResponse,
    upgraded: hyper::upgrade::Upgraded,
    key: &WsKey,
    framing: ClientFraming,
) -> Next {
    let parse = cx.snap.policy.reads_ws();
    let checked = validate_upgrade_response(&res, key).and_then(|()| {
        if crate::addons::ws_without_extensions(&cx.snap) {
            validate_no_extensions(&res)
        } else {
            Ok(())
        }
    });
    if let Err(e) = checked {
        let host = cx
            .facts
            .request
            .as_ref()
            .map(|r| host_text(&r.host))
            .unwrap_or_default();
        let port = cx.facts.request.as_ref().map_or(0, |r| r.port);
        let r = protocol_refusal(&cx, &host, port, e.to_string());
        return refuse(conn, handle, cx, r, framing).await;
    }
    cx.record.response_status = Some(101);
    let (client_io, leftover) = match conn.respond_upgrade(res).await {
        Ok(x) => x,
        Err(e) => {
            tracing::debug!(error = %e, "writing 101 failed");
            cx.emit_request_event();
            return None;
        }
    };
    let host = cx.facts.request.as_ref().map(|r| host_text(&r.host));
    cx.shared.sink.emit(&FlowEvent::WsOpen {
        ts: chrono::Utc::now(),
        flow: cx.flow.to_string(),
        conn: cx.conn_id(),
        host,
    });
    // Layers that export `tunnel` sit between the client and the relay;
    // the bytes that came with the upgrade request go through them.
    let (client_io, leftover): (crate::io::BoxIo, Vec<u8>) = match &cx.stack {
        Some(st) => crate::addons::chain_tunnels(st, Box::new(client_io), leftover.to_vec()),
        None => (Box::new(client_io), leftover.to_vec()),
    };
    let mut upstream = TokioIo::new(upgraded);
    let idle = cx.snap.limits.idle_timeout;
    let Some(watch) = cx.watch.clone() else {
        cx.emit_request_event();
        return None;
    };
    let (mut up_tap, down_tap) = std::mem::take(&mut cx.taps);
    if parse {
        let max = cx.snap.limits.max_ws_message_bytes;
        let taps = (up_tap, down_tap);
        let r = relay_messages(client_io, upstream, leftover, (idle, max), &watch, taps).await;
        finish_websocket(&mut cx, r);
        return None;
    }
    let c2s_extra = leftover.len() as u64;
    if !leftover.is_empty() {
        // Bytes that arrived with the upgrade request: checked before they
        // are written, like every other relayed chunk.
        if watch.on_ws_chunk(Dir::Request, c2s_extra).is_err() {
            cx.record_final_sample(false);
            cx.emit_request_event();
            return None;
        }
        if let Some(t) = up_tap.as_mut() {
            t.data(&leftover);
        }
        if upstream.write_all(&leftover).await.is_err() {
            cx.emit_request_event();
            return None;
        }
    }
    let (c2s, s2c) = splice(client_io, upstream, idle, &watch, (up_tap, down_tap)).await;
    let r = Relayed {
        c2s: c2s + c2s_extra,
        s2c,
        closed: None,
    };
    finish_websocket(&mut cx, r);
    None
}

/// Logs the end of a relayed WebSocket and its exchange.
fn finish_websocket(cx: &mut FlowCx, r: Relayed) {
    cx.shared.sink.emit(&FlowEvent::WsClose {
        ts: chrono::Utc::now(),
        flow: cx.flow.to_string(),
        conn: cx.conn_id(),
        bytes_c2s: r.c2s,
        bytes_s2c: r.s2c,
        close_code: r.closed.as_ref().map(|e| e.code),
        close_reason: r.closed.map(|e| e.detail.to_owned()),
    });
    cx.record.request_bytes = r.c2s;
    cx.record.response_bytes = r.s2c;
    cx.record_final_sample(false);
    cx.emit_request_event();
}

/// One direction of the WebSocket relay: what checks and records each chunk.
struct Relay<'a> {
    watch: &'a Watch,
    dir: Dir,
    tap: Option<Tap>,
}

async fn pump<R, W>(
    mut r: R,
    mut w: W,
    n: Arc<std::sync::atomic::AtomicU64>,
    last: Arc<std::sync::atomic::AtomicU64>,
    base: Instant,
    mut relay: Relay<'_>,
) where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    let watch = relay.watch;
    let sink = watch.sink();
    let mut completed = false;
    loop {
        // Audit backpressure: relay only while the flow log
        // and the capture log keep up.
        crate::flowlog::sink_ready(&*sink).await;
        if let Some(t) = &relay.tap {
            std::future::poll_fn(|cx| t.log().poll_ready(cx)).await;
        }
        let k = match r.read(&mut buf).await {
            Ok(0) => {
                completed = true;
                break;
            }
            Err(_) => break,
            Ok(k) => k,
        };
        // Checked before the write: bytes that make a deny match are never
        // relayed.
        if watch.on_ws_chunk(relay.dir, k as u64).is_err() {
            break;
        }
        if let Some(t) = relay.tap.as_mut() {
            t.data(&buf[..k]);
        }
        if w.write_all(&buf[..k]).await.is_err() {
            break;
        }
        let _ = w.flush().await;
        n.fetch_add(k as u64, Ordering::Relaxed);
        last.store(
            u64::try_from(base.elapsed().as_millis()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }
    if let Some(t) = relay.tap.as_mut() {
        t.end(!completed);
    }
    let _ = w.shutdown().await;
}

/// Copies bytes both ways until either side closes, nothing moves for
/// `idle`, or a watching rule stops the exchange (then both sides are
/// dropped, i.e. closed: the relay is byte-level, so a close frame could
/// land inside a half-written frame). Returns (client→server,
/// server→client) byte counts.
async fn splice(
    client: impl Io,
    upstream: impl Io,
    idle: Duration,
    watch: &Watch,
    taps: (Option<Tap>, Option<Tap>),
) -> (u64, u64) {
    use std::sync::atomic::AtomicU64;
    let base = Instant::now();
    let last = Arc::new(AtomicU64::new(0));
    let c2s = Arc::new(AtomicU64::new(0));
    let s2c = Arc::new(AtomicU64::new(0));
    let (cr, cw) = tokio::io::split(client);
    let (ur, uw) = tokio::io::split(upstream);
    let (up_tap, down_tap) = taps;
    let a = pump(
        cr,
        uw,
        c2s.clone(),
        last.clone(),
        base,
        Relay {
            watch,
            dir: Dir::Request,
            tap: up_tap,
        },
    );
    let b = pump(
        ur,
        cw,
        s2c.clone(),
        last.clone(),
        base,
        Relay {
            watch,
            dir: Dir::Response,
            tap: down_tap,
        },
    );
    tokio::select! {
        () = async { tokio::join!(a, b); } => {}
        () = idle_watchdog(&last, base, idle) => {}
        () = watch.cancelled() => {
            tracing::debug!("websocket relay stopped by policy");
        }
    }
    (c2s.load(Ordering::Relaxed), s2c.load(Ordering::Relaxed))
}

/// Resolves once nothing has moved through a relay for `idle`. `last` is
/// the time of the latest write, in milliseconds since `base`.
async fn idle_watchdog(last: &AtomicU64, base: Instant, idle: Duration) {
    loop {
        tokio::time::sleep(idle / 4 + Duration::from_millis(1)).await;
        let since = base
            .elapsed()
            .as_millis()
            .saturating_sub(u128::from(last.load(Ordering::Relaxed)));
        if since >= idle.as_millis() {
            tracing::debug!("websocket relay idle timeout");
            return;
        }
    }
}

/// How long roxy waits to write a close frame, or to shut a side down,
/// before giving up on a peer that does not read.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

/// Masks for frames toward the upstream, which must be unpredictable
/// (RFC 6455 §5.3). Drawn from the system RNG, 64 at a time.
struct Masks {
    rng: ring::rand::SystemRandom,
    buf: [u8; 256],
    at: usize,
}

impl Masks {
    fn new() -> Self {
        Self {
            rng: ring::rand::SystemRandom::new(),
            buf: [0; 256],
            at: 256,
        }
    }

    /// `None` if the RNG failed.
    fn next(&mut self) -> Option<[u8; 4]> {
        use ring::rand::SecureRandom as _;
        if self.at == self.buf.len() {
            self.rng.fill(&mut self.buf).ok()?;
            self.at = 0;
        }
        let b = &self.buf[self.at..self.at + 4];
        self.at += 4;
        Some([b[0], b[1], b[2], b[3]])
    }
}

/// The write half of one side of the message relay. It writes whole frames
/// and remembers whether one was cut short, so a close frame never lands
/// inside another frame.
struct FrameOut<W> {
    w: W,
    /// `Some` toward the upstream: client frames are masked.
    masks: Option<Masks>,
    buf: Vec<u8>,
    /// No frame is half-written.
    clean: bool,
    /// A close frame has gone out (relayed or roxy's own).
    close_sent: bool,
}

impl<W: tokio::io::AsyncWrite + Unpin> FrameOut<W> {
    fn new(w: W, masks: Option<Masks>) -> Self {
        Self {
            w,
            masks,
            buf: Vec::new(),
            clean: true,
            close_sent: false,
        }
    }

    /// Encodes one frame into `buf`. `Err` if no mask could be drawn.
    fn encode(&mut self, opcode: Opcode, payload: &[u8]) -> Result<(), ()> {
        let mask = match self.masks.as_mut() {
            Some(m) => Some(m.next().ok_or(())?),
            None => None,
        };
        self.buf.clear();
        frame::encode(opcode, payload, mask, &mut self.buf);
        Ok(())
    }

    async fn write_buf(&mut self) -> std::io::Result<()> {
        self.clean = false;
        self.w.write_all(&self.buf).await?;
        self.w.flush().await?;
        self.clean = true;
        Ok(())
    }

    /// Sends a close frame with `code`, unless one already went out or a
    /// frame was cut short, then shuts the side down.
    async fn close(&mut self, code: u16) {
        if self.clean && !self.close_sent {
            let mask = match self.masks.as_mut() {
                Some(m) => m.next(),
                None => None,
            };
            if mask.is_some() || self.masks.is_none() {
                self.buf.clear();
                frame::encode_close(code, mask, &mut self.buf);
                self.close_sent = true;
                let _ = tokio::time::timeout(CLOSE_TIMEOUT, self.write_buf()).await;
            }
        }
        self.shutdown().await;
    }

    async fn shutdown(&mut self) {
        let _ = tokio::time::timeout(CLOSE_TIMEOUT, self.w.shutdown()).await;
    }
}

/// How one direction of the message relay ended.
enum End {
    /// The sender closed its stream.
    Eof,
    /// A read or write failed, or no mask could be drawn.
    Broken,
    /// A rule denied a message, or the exchange was stopped.
    Stopped,
    /// The sender broke the protocol.
    Protocol(FrameError),
}

/// One direction of the message relay.
struct MessagePump<'a, W> {
    out: &'a mut FrameOut<W>,
    dec: Decoder,
    relay: Relay<'a>,
    /// Bytes written, and the time of the latest write (ms since `base`).
    n: &'a AtomicU64,
    last: &'a AtomicU64,
    base: Instant,
}

impl<W: tokio::io::AsyncWrite + Unpin> MessagePump<'_, W> {
    /// Decodes `input`; checks, re-encodes and writes each whole message.
    /// `Some` when this direction must end.
    async fn feed(&mut self, mut input: &[u8]) -> Option<End> {
        let watch = self.relay.watch;
        loop {
            let msg = match self.dec.decode(&mut input) {
                Ok(Some(m)) => m,
                Ok(None) => return None,
                Err(e) => return Some(End::Protocol(e)),
            };
            // Checked before the write: a message that makes a deny match
            // is never relayed.
            let (msg, r) = watch.on_ws_message(self.relay.dir, msg);
            if r.is_err() {
                return Some(End::Stopped);
            }
            if self.out.encode(msg.opcode, msg.payload()).is_err() {
                return Some(End::Broken);
            }
            let len = self.out.buf.len() as u64;
            if watch.on_ws_chunk(self.relay.dir, len).is_err() {
                return Some(End::Stopped);
            }
            if let Some(t) = self.relay.tap.as_mut() {
                t.data(&self.out.buf);
            }
            if self.out.write_buf().await.is_err() {
                return Some(End::Broken);
            }
            if msg.opcode == Opcode::Close {
                self.out.close_sent = true;
            }
            self.n.fetch_add(len, Ordering::Relaxed);
            self.last.store(
                u64::try_from(self.base.elapsed().as_millis()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
        }
    }

    /// Runs this direction until it ends: `first` (bytes that came with
    /// the upgrade request), then whatever `r` reads. Shuts the write side
    /// down when the sender closes.
    async fn run<R: tokio::io::AsyncRead + Unpin>(mut self, mut r: R, first: Vec<u8>) -> End {
        let sink = self.relay.watch.sink();
        let mut end = None;
        if !first.is_empty() {
            end = self.feed(&first).await;
        }
        let mut buf = vec![0u8; 16 * 1024];
        let end = loop {
            if let Some(e) = end.take() {
                break e;
            }
            // Audit backpressure.
            crate::flowlog::sink_ready(&*sink).await;
            if let Some(t) = &self.relay.tap {
                std::future::poll_fn(|cx| t.log().poll_ready(cx)).await;
            }
            match r.read(&mut buf).await {
                Ok(0) => break End::Eof,
                Err(_) => break End::Broken,
                Ok(k) => end = self.feed(&buf[..k]).await,
            }
        };
        if let Some(t) = self.relay.tap.as_mut() {
            t.end(!matches!(end, End::Eof));
        }
        if matches!(end, End::Eof) {
            self.out.shutdown().await;
        }
        end
    }
}

/// What the message relay did.
struct Relayed {
    c2s: u64,
    s2c: u64,
    /// The close roxy sent both sides, if it ended the WebSocket.
    closed: Option<FrameError>,
}

/// The message relay: each direction is
/// decoded into whole messages, each message is checked by the rules
/// reading `ws.*` and then re-encoded as one frame, masked with roxy's own
/// key toward the upstream. Runs until both sides close, nothing moves for
/// `idle`, a message breaks the protocol (both sides get its close code) or
/// a rule stops the exchange (both sides get `1008`).
async fn relay_messages(
    client: impl Io,
    upstream: impl Io,
    leftover: Vec<u8>,
    (idle, max): (Duration, u64),
    watch: &Watch,
    (up_tap, down_tap): (Option<Tap>, Option<Tap>),
) -> Relayed {
    let base = Instant::now();
    let last = AtomicU64::new(0);
    let c2s = AtomicU64::new(0);
    let s2c = AtomicU64::new(0);
    let (cr, cw) = tokio::io::split(client);
    let (ur, uw) = tokio::io::split(upstream);
    let mut to_up = FrameOut::new(uw, Some(Masks::new()));
    let mut to_client = FrameOut::new(cw, None);
    let end = {
        let a = MessagePump {
            out: &mut to_up,
            dec: Decoder::new(Peer::Client, max),
            relay: Relay {
                watch,
                dir: Dir::Request,
                tap: up_tap,
            },
            n: &c2s,
            last: &last,
            base,
        }
        .run(cr, leftover);
        let b = MessagePump {
            out: &mut to_client,
            dec: Decoder::new(Peer::Server, max),
            relay: Relay {
                watch,
                dir: Dir::Response,
                tap: down_tap,
            },
            n: &s2c,
            last: &last,
            base,
        }
        .run(ur, Vec::new());
        tokio::pin!(a, b);
        let watchdog = idle_watchdog(&last, base, idle);
        tokio::pin!(watchdog);
        let (mut a_done, mut b_done) = (false, false);
        loop {
            let e = tokio::select! {
                e = &mut a, if !a_done => { a_done = true; e }
                e = &mut b, if !b_done => { b_done = true; e }
                () = &mut watchdog => break End::Broken,
                () = watch.cancelled() => break End::Stopped,
            };
            match e {
                End::Eof if !(a_done && b_done) => {}
                e => break e,
            }
        }
    };
    let closed = match end {
        End::Stopped => Some(FrameError {
            code: close::POLICY,
            detail: "denied by policy",
        }),
        End::Protocol(e) => Some(e),
        End::Eof | End::Broken => None,
    };
    match &closed {
        Some(e) => {
            tracing::debug!(error = %e, "closing websocket");
            tokio::join!(to_up.close(e.code), to_client.close(e.code));
        }
        None => {
            tokio::join!(to_up.shutdown(), to_client.shutdown());
        }
    }
    Relayed {
        c2s: c2s.load(Ordering::Relaxed),
        s2c: s2c.load(Ordering::Relaxed),
        closed,
    }
}

/// Capture taps for an exchange about to be forwarded: per direction, when
/// a `capture` effect selected it or the capture log takes everything.
fn taps(cx: &FlowCx) -> (Option<Tap>, Option<Tap>) {
    let Some(log) = &cx.shared.capture else {
        return (None, None);
    };
    let all = log.captures_all();
    let flow = cx.flow.to_string();
    let tap = |on: bool, dir| (on || all).then(|| Tap::new(log.clone(), &flow, dir));
    (
        tap(cx.capture.0, capture::Dir::Request),
        tap(cx.capture.1, capture::Dir::Response),
    )
}
