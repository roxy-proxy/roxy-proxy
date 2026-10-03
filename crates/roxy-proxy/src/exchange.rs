//! One request/response exchange: request stages → upstream → response
//! stages → client, plus the WebSocket relay (§8.1).

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use http::HeaderValue;
use http::header::HOST;
use hyper_util::rt::TokioIo;
use roxy_http::h1::ServerConn;
use roxy_http::upstream::{
    UriForm, from_upstream_response, to_upstream_request, to_upstream_upgrade_request,
};
use roxy_http::ws::{WsKey, validate_upgrade_request, validate_upgrade_response};
use roxy_http::{Body, CanonicalRequest, CanonicalResponse, ParseError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::body::counted;
use crate::flowlog::{DecisionKind, FlowEvent};
use crate::io::{ConnIo, Io};
use crate::listener::ClientConn;
use crate::pipeline::{
    BodyIo, FlowCx, Refusal, RefusalKind, ResponseVerdict, Verdict, run_request_stages,
    run_response_stages,
};
use crate::server::Shared;
use crate::upstream::{ConnectError, classify, describe};
use crate::view::host_text;

/// The client connection after an exchange: `None` once it is closed.
pub(crate) type Next = Option<ServerConn<ConnIo>>;

/// How the client asked to be treated (for `connection: close` injection).
#[derive(Debug, Clone, Copy)]
pub(crate) struct ClientFraming {
    /// The client sent `Connection: close` (the codec already closes).
    pub close: bool,
}

/// Writes `res`. With `close`, the response carries `connection: close`
/// (§6.1 "a deny closes the connection") and the connection is shut down
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
pub(crate) fn finish_refusal(cx: &FlowCx, refusal: &Refusal) {
    // After an allowed request (upstream failure, response-phase deny) the
    // response-phase sample is still due; request-phase denies were
    // recorded at their decision.
    let upstream_error = refusal.kind == RefusalKind::UpstreamError;
    if upstream_error || cx.facts.response.is_some() {
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
    finish_refusal(&cx, &refusal);
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
/// body access for inspecting stages ([`BodyIo`]) plus a way to wait for
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
    /// Send this response (from the upstream, after the response stages).
    Respond(CanonicalResponse),
    /// Answer locally (deny, fail-closed, upstream error).
    Refuse(Refusal),
    /// The client side broke: close (h1) or reset the stream (h2).
    Close(ParseError),
    /// An allowed WebSocket upgrade got its `101` (h1 only).
    Upgrade {
        res: CanonicalResponse,
        on: hyper::upgrade::OnUpgrade,
        key: WsKey,
    },
}

/// The transport-agnostic exchange: request stages → upstream → response
/// stages. `cx` carries the flow record; the caller writes the outcome and
/// emits the flow's `request` event.
pub(crate) async fn process<F: Front>(
    front: &mut F,
    cx: &mut FlowCx,
    req: CanonicalRequest,
) -> Outcome {
    let shared = cx.shared.clone();
    let verdict = run_request_stages(&shared.pipeline, cx, req, front).await;
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
    on_proxy_port: bool,
) -> Next {
    let snap = shared.snapshot();
    let framing = ClientFraming {
        close: req.meta.close,
    };
    let mut cx = FlowCx::new(shared.clone(), snap, client, tls, &req, on_proxy_port);
    match process(&mut conn, &mut cx, req).await {
        Outcome::Respond(res) => send_response(conn, cx, res).await,
        Outcome::Refuse(refusal) => refuse(conn, handle, cx, refusal, framing).await,
        Outcome::Close(e) => {
            let client = cx.facts.client.clone();
            close_on_parse_error(conn, Some(cx), &client, shared, &e).await;
            None
        }
        Outcome::Upgrade { res, on, key } => {
            splice_websocket(conn, handle, cx, res, on, &key, framing).await
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
    /// A `101` for an allowed WebSocket upgrade.
    Upgrade {
        res: http::Response<hyper::body::Incoming>,
        key: WsKey,
    },
}

#[allow(clippy::too_many_lines)] // one linear flow; splitting it obscures the order
async fn forward<F: Front>(front: &mut F, cx: &mut FlowCx, mut req: CanonicalRequest) -> Outcome {
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
        // §8: plain `allow` strips the upgrade (the codec already removed
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
            sender.send_request(http_req).await.map_err(|e| {
                tracing::debug!(error = %e, "websocket upgrade request failed");
                None
            })
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
            Ok(Ok(res)) if res.status() == http::StatusCode::SWITCHING_PROTOCOLS => {
                Upstreamed::Upgrade { res, key }
            }
            Ok(Ok(res)) => Upstreamed::Response(res),
        }
    } else {
        let (body, req_counter) = counted(std::mem::take(&mut req.body));
        req.body = body;
        let mut http_req = match to_upstream_request(req, UriForm::Absolute) {
            Ok(r) => r,
            Err(e) => {
                return Outcome::Refuse(protocol_refusal(cx, &host, port, e.to_string()));
            }
        };
        set_host_override(cx, &mut http_req);
        let fut = tokio::time::timeout(
            limits.response_header_timeout,
            upstream_client.client(private_ok).request(http_req),
        );
        let driven = front.drive(fut).await;
        cx.record.request_bytes = req_counter.load(Ordering::Relaxed);
        match driven {
            Err(e) => return Outcome::Close(e),
            Ok(Err(_elapsed)) => {
                return Outcome::Refuse(upstream_refusal(
                    cx,
                    &ConnectError::Timeout("upstream response headers"),
                    &host,
                    port,
                ));
            }
            Ok(Ok(Err(e))) => {
                return Outcome::Refuse(match classify(&e) {
                    Some(ce) => upstream_refusal(cx, &ce, &host, port),
                    None => protocol_refusal(cx, &host, port, describe(&e)),
                });
            }
            Ok(Ok(Ok(res))) => Upstreamed::Response(res),
        }
    };
    cx.record.ttfb_ms = Some(u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX));

    let (res, upgrade) = match upstreamed {
        Upstreamed::Response(res) => (res, None),
        Upstreamed::Upgrade { mut res, key } => {
            let on = hyper::upgrade::on(&mut res);
            (res, Some((on, key)))
        }
    };
    let res = from_upstream_response(res, &limits);
    let shared = cx.shared.clone();
    let verdict = run_response_stages(&shared.pipeline, cx, res, front).await;
    match verdict {
        ResponseVerdict::Continue(res) => match upgrade {
            Some((on, key)) => Outcome::Upgrade { res, on, key },
            None => Outcome::Respond(res),
        },
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
    let failed = r.is_err();
    let next = match r {
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
    on: hyper::upgrade::OnUpgrade,
    key: &WsKey,
    framing: ClientFraming,
) -> Next {
    if let Err(e) = validate_upgrade_response(&res, key) {
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
    let Ok(Ok(upgraded)) = tokio::time::timeout(Duration::from_secs(10), on).await else {
        tracing::debug!("upstream upgrade did not complete");
        cx.emit_request_event();
        return None;
    };
    let host = cx.facts.request.as_ref().map(|r| host_text(&r.host));
    cx.shared.sink.emit(&FlowEvent::WsOpen {
        ts: chrono::Utc::now(),
        flow: cx.flow.to_string(),
        conn: cx.conn_id(),
        host,
    });
    let mut upstream = TokioIo::new(upgraded);
    let idle = cx.snap.limits.idle_timeout;
    let mut c2s_extra = 0u64;
    if !leftover.is_empty() {
        if upstream.write_all(&leftover).await.is_err() {
            cx.emit_request_event();
            return None;
        }
        c2s_extra = leftover.len() as u64;
    }
    let (c2s, s2c) = splice(client_io, upstream, idle).await;
    cx.shared.sink.emit(&FlowEvent::WsClose {
        ts: chrono::Utc::now(),
        flow: cx.flow.to_string(),
        conn: cx.conn_id(),
        bytes_c2s: c2s + c2s_extra,
        bytes_s2c: s2c,
    });
    cx.record.request_bytes = c2s + c2s_extra;
    cx.record.response_bytes = s2c;
    cx.record_final_sample(false);
    cx.emit_request_event();
    None
}

async fn pump<R, W>(
    mut r: R,
    mut w: W,
    n: Arc<std::sync::atomic::AtomicU64>,
    last: Arc<std::sync::atomic::AtomicU64>,
    base: Instant,
) where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let k = match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(k) => k,
        };
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
    let _ = w.shutdown().await;
}

/// Copies bytes both ways until either side closes or nothing moves for
/// `idle`. Returns (client→server, server→client) byte counts.
async fn splice(client: impl Io, upstream: impl Io, idle: Duration) -> (u64, u64) {
    use std::sync::atomic::AtomicU64;
    let base = Instant::now();
    let last = Arc::new(AtomicU64::new(0));
    let c2s = Arc::new(AtomicU64::new(0));
    let s2c = Arc::new(AtomicU64::new(0));
    let (cr, cw) = tokio::io::split(client);
    let (ur, uw) = tokio::io::split(upstream);
    let a = pump(cr, uw, c2s.clone(), last.clone(), base);
    let b = pump(ur, cw, s2c.clone(), last.clone(), base);
    let watchdog = async {
        loop {
            tokio::time::sleep(idle / 4 + Duration::from_millis(1)).await;
            let since = base
                .elapsed()
                .as_millis()
                .saturating_sub(u128::from(last.load(Ordering::Relaxed)));
            if since >= idle.as_millis() {
                tracing::debug!("websocket relay idle timeout");
                break;
            }
        }
    };
    tokio::select! {
        () = async { tokio::join!(a, b); } => {}
        () = watchdog => {}
    }
    (c2s.load(Ordering::Relaxed), s2c.load(Ordering::Relaxed))
}
