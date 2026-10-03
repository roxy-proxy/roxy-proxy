//! Client-side HTTP/2 inside a TLS tunnel (`DESIGN.md` §5.1a, §5.3).
//!
//! When the client negotiates ALPN `h2`, the tunnel is served by the `h2`
//! crate's server instead of the h1 codec. Each stream is mapped with
//! [`roxy_http::h2map::from_h2_parts`] and handed to the same
//! transport-agnostic exchange core as h1 ([`crate::exchange::process`]);
//! this module only adapts the [`Outcome`] to h2 frames.
//!
//! # Fail closed
//!
//! - A stream that does not map (bad pseudo-headers, connection-specific
//!   fields, `:authority` other than the tunnel host, ...) is reset with
//!   `PROTOCOL_ERROR` and logged as a `parse_error`; nothing is forwarded.
//! - A request body that breaks (cap, length mismatch, idle timeout,
//!   disallowed trailers, client reset) resets the stream; the upstream
//!   request is dropped mid-body, so a truncated body is never presented
//!   as complete.
//! - A deny writes roxy's deny response on that stream. When the decision
//!   closes (the default, §6.1), the connection then sends `GOAWAY`, refuses
//!   every stream it has not started (`REFUSED_STREAM`), lets in-flight
//!   streams finish for at most [`CLOSE_GRACE`], and closes.
//! - Connection-level protocol errors close the connection (the `h2` crate
//!   sends `GOAWAY` with the error code).
//! - Extended CONNECT (RFC 8441, WebSocket over h2) is not enabled, so a
//!   client cannot negotiate it; plain CONNECT is refused by the mapper.

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::Bytes;
use h2::server::{Connection, SendResponse};
use h2::{RecvStream, SendStream};
use http_body::Frame;
use roxy_http::h2map::{from_h2_parts, to_h2_response, validate_h2_trailers};
use roxy_http::{
    Authority, Body, BodyError, CanonicalResponse, HttpFlags, Limits, Method, ParseError, Reason,
    is_reserved, status_forbids_body,
};
use tokio::task::JoinSet;
use tokio::time::{Instant, Sleep, sleep, sleep_until, timeout};
use tokio_util::sync::CancellationToken;

use crate::body::{Collected, collect_prefix, counted};
use crate::exchange::{
    Front, Outcome, finish_refusal, process, record_client_failure, refusal_response,
};
use crate::flowlog::{FlowEvent, TlsInfo};
use crate::io::Io;
use crate::listener::ClientConn;
use crate::pipeline::{BodyIo, FlowCx, RefusalKind, StageFuture, body_failure};
use crate::server::Shared;

/// How long in-flight streams may continue after the connection started
/// closing (a closing deny, server shutdown, idle timeout).
pub(crate) const CLOSE_GRACE: Duration = Duration::from_secs(10);
/// Per-stream receive window. Large enough that a single upload is not
/// throttled by round trips; the connection window bounds the total.
const STREAM_WINDOW: u32 = 1024 * 1024;
/// Connection receive window: the most request-body data a client can have
/// buffered in roxy at once, across all of its streams.
const CONNECTION_WINDOW: u32 = 4 * 1024 * 1024;
/// Per-stream send buffer (response data queued but not yet written).
const MAX_SEND_BUFFER: usize = 256 * 1024;
/// Rapid-reset defence (CVE-2023-44487): streams the client opened and
/// reset before roxy accepted them. Exceeding this is `ENHANCE_YOUR_CALM`.
const MAX_PENDING_ACCEPT_RESETS: usize = 20;
/// Locally generated resets caused by client protocol errors before the
/// connection is torn down with `ENHANCE_YOUR_CALM`.
const MAX_LOCAL_ERROR_RESETS: usize = 256;
/// Recently reset streams remembered (to ignore their late frames).
const MAX_CONCURRENT_RESETS: usize = 50;

fn builder(limits: &Limits) -> h2::server::Builder {
    let mut b = h2::server::Builder::new();
    b.max_concurrent_streams(limits.h2_max_concurrent_streams)
        .max_header_list_size(u32::try_from(limits.h2_max_header_list_bytes).unwrap_or(u32::MAX))
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONNECTION_WINDOW)
        .max_send_buffer_size(MAX_SEND_BUFFER)
        .max_pending_accept_reset_streams(MAX_PENDING_ACCEPT_RESETS)
        .max_local_error_reset_streams(Some(MAX_LOCAL_ERROR_RESETS))
        .max_concurrent_reset_streams(MAX_CONCURRENT_RESETS);
    // Deliberately not `enable_connect_protocol()` (no RFC 8441).
    b
}

/// What every stream task of one connection shares.
struct ConnCx {
    shared: Arc<Shared>,
    client: ClientConn,
    authority: Authority,
    tls: TlsInfo,
    /// Cancelled by a stream whose deny closes the connection.
    closing: CancellationToken,
}

/// Serves an h2 connection on a terminated TLS tunnel to `authority`.
pub(crate) async fn serve<IO: Io>(
    io: IO,
    client: ClientConn,
    authority: Authority,
    tls: TlsInfo,
    shared: Arc<Shared>,
) {
    let limits = shared.snapshot().limits.clone();
    let handshake = builder(&limits).handshake::<_, Bytes>(io);
    let mut conn: Connection<IO, Bytes> = match timeout(limits.header_timeout, handshake).await {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            shared.emit_parse_reason(&client, None, "h2_handshake_failed", Some(&e.to_string()));
            return;
        }
        Err(_) => {
            shared.emit_parse_reason(&client, None, "h2_handshake_timeout", None);
            return;
        }
    };
    let ccx = Arc::new(ConnCx {
        shared: shared.clone(),
        client,
        authority,
        tls,
        closing: CancellationToken::new(),
    });
    // Dropping the set (connection over, or the server's kill switch)
    // aborts every stream task.
    let mut streams: JoinSet<()> = JoinSet::new();
    let mut closing = false;
    let mut close_deadline = Instant::now();
    let mut idle_deadline = Some(Instant::now() + limits.idle_timeout);
    loop {
        let idle_at = idle_deadline.unwrap_or_else(Instant::now);
        tokio::select! {
            // Closing triggers first, so a stream that arrives after a
            // closing deny is never started.
            biased;
            () = ccx.closing.cancelled(), if !closing => {
                closing = true;
                close_deadline = Instant::now() + CLOSE_GRACE;
                conn.graceful_shutdown();
            }
            () = ccx.shared.stop.cancelled(), if !closing => {
                closing = true;
                close_deadline = Instant::now() + CLOSE_GRACE;
                conn.graceful_shutdown();
            }
            () = sleep_until(idle_at), if idle_deadline.is_some() && !closing => {
                closing = true;
                close_deadline = Instant::now() + CLOSE_GRACE;
                conn.graceful_shutdown();
            }
            () = sleep_until(close_deadline), if closing => {
                tracing::debug!("h2 close grace over; dropping the connection");
                conn.abrupt_shutdown(h2::Reason::NO_ERROR);
                // Give the GOAWAY a moment to reach the socket.
                let _ = timeout(Duration::from_secs(1), poll_fn(|cx| conn.poll_closed(cx))).await;
                break;
            }
            accepted = conn.accept() => match accepted {
                None => break,
                Some(Err(e)) => {
                    if !e.is_io() && !e.is_go_away() {
                        ccx.shared.emit_parse_reason(
                            &ccx.client,
                            None,
                            "h2_protocol_error",
                            Some(&e.to_string()),
                        );
                    }
                    tracing::debug!(error = %e, "h2 connection ended");
                    break;
                }
                Some(Ok((req, mut respond))) => {
                    if closing {
                        // Not processed: the client may retry elsewhere.
                        respond.send_reset(h2::Reason::REFUSED_STREAM);
                        continue;
                    }
                    idle_deadline = None;
                    // Reap finished tasks even while new streams keep
                    // winning the (biased) select.
                    while streams.try_join_next().is_some() {}
                    streams.spawn(serve_stream(req, respond, ccx.clone()));
                }
            },
            Some(_) = streams.join_next(), if !streams.is_empty() => {
                if streams.is_empty() && !closing {
                    idle_deadline = Some(Instant::now() + limits.idle_timeout);
                }
            }
        }
    }
}

/// One stream: map, run the exchange core, write the outcome.
async fn serve_stream(
    req: http::Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    ccx: Arc<ConnCx>,
) {
    let snap = ccx.shared.snapshot();
    let (parts, recv) = req.into_parts();
    let fail = Arc::new(BodyFail::default());
    let raw = if recv.is_end_stream() {
        // END_STREAM on HEADERS: no body (and a known length of 0).
        Body::empty()
    } else {
        Body::wrap_native(
            H2Body::new(recv, &snap.limits, &snap.flags, fail.clone()),
            u64::MAX,
            None,
        )
    };
    let mut req = match from_h2_parts(parts, raw, &ccx.authority, &snap.limits, &snap.flags) {
        Ok(r) => r,
        Err(e) => {
            ccx.shared.emit_parse_error(&ccx.client, None, &e);
            respond.send_reset(h2::Reason::PROTOCOL_ERROR);
            return;
        }
    };
    // Observe failures of the whole body stack (caps, declared length)
    // so the exchange can tell a broken client body from an upstream
    // failure.
    let known = req.body.known_length();
    req.body = Body::wrap_native(
        Observed {
            inner: std::mem::take(&mut req.body),
            fail: fail.clone(),
        },
        u64::MAX,
        known,
    );
    let limits = snap.limits.clone();
    let flags = snap.flags.clone();
    let method = req.method.clone();
    let mut cx = FlowCx::new(
        ccx.shared.clone(),
        snap,
        ccx.client.clone(),
        Some(ccx.tls.clone()),
        &req,
    );
    let mut front = H2Front {
        respond,
        fail,
        expect_continue: req.meta.expect_continue,
    };
    let outcome = process(&mut front, &mut cx, req).await;
    let H2Front { mut respond, .. } = front;
    let out = Out {
        method: &method,
        idle: limits.body_idle_timeout,
        allow_trailers: flags.allow_trailers,
    };
    match outcome {
        Outcome::Respond(res) => send_upstream_response(&mut respond, cx, res, &out, &ccx).await,
        Outcome::Refuse(refusal) => {
            let res = refusal_response(&mut cx, &refusal);
            if let Err(e) = write_response(&mut respond, res, &out).await {
                tracing::debug!(error = %e, "writing h2 refusal failed");
            }
            // §6.1: a deny closes the connection (GOAWAY once written).
            // Upstream failures are not decisions about the client and
            // leave the other streams alone.
            if refusal.kind == RefusalKind::Deny && refusal.close {
                ccx.closing.cancel();
            }
            finish_refusal(&mut cx, &refusal);
        }
        Outcome::Close(e) => {
            ccx.shared
                .emit_parse_error(&ccx.client, Some(cx.flow.to_string()), &e);
            respond.send_reset(h2::Reason::PROTOCOL_ERROR);
            record_client_failure(&mut cx, &e, None);
        }
        Outcome::Upgrade { .. } => {
            // Unreachable: h2 requests never carry an upgrade. Fail closed.
            respond.send_reset(h2::Reason::INTERNAL_ERROR);
            let e = ParseError::new(Reason::H2UnsupportedMethod, "upgrade over h2");
            record_client_failure(&mut cx, &e, None);
        }
    }
}

/// Response-writing parameters for one stream.
struct Out<'a> {
    method: &'a Method,
    idle: Duration,
    allow_trailers: bool,
}

async fn send_upstream_response(
    respond: &mut SendResponse<Bytes>,
    mut cx: FlowCx,
    mut res: CanonicalResponse,
    out: &Out<'_>,
    ccx: &ConnCx,
) {
    let (body, counter) = counted(std::mem::take(&mut res.body));
    res.body = body;
    cx.record.response_status = Some(res.status.as_u16());
    cx.record.response_headers_bytes = res.headers.wire_len() as u64;
    let r = write_response(respond, res, out).await;
    // §6.1: a watching stop mid-body resets the stream (`CANCEL`, sent by
    // `write_response`), and a closing deny also ends the connection
    // (`GOAWAY`).
    let stop = cx.watch.as_ref().and_then(|w| w.stopped());
    if let Some(stop) = &stop {
        if stop.refusal.close {
            ccx.closing.cancel();
        }
    } else if let Err(e) = &r {
        cx.shared.sink.emit(&FlowEvent::ResponseError {
            ts: chrono::Utc::now(),
            flow: cx.flow.to_string(),
            conn: cx.conn_id(),
            reason: "response_write_failed".to_owned(),
            message: e.clone(),
        });
    }
    cx.record.response_bytes = counter.load(Ordering::Relaxed);
    cx.record_final_sample(r.is_err() && stop.is_none());
    cx.emit_request_event();
}

/// Writes `res` on the stream: head, then the body as DATA frames within
/// the peer's flow-control window, then trailers (only with
/// `http.allow_trailers`). A body that fails resets the stream, so the
/// client never sees a truncated body as complete.
async fn write_response(
    respond: &mut SendResponse<Bytes>,
    res: CanonicalResponse,
    out: &Out<'_>,
) -> Result<(), String> {
    let head = to_h2_response(&res, out.method)
        .body(())
        .map_err(|e| format!("response head: {e}"))?;
    let bodiless = status_forbids_body(res.status)
        || *out.method == Method::Head
        || res.body.known_length() == Some(0);
    let mut body = res.body;
    if bodiless {
        respond
            .send_response(head, true)
            .map_err(|e| e.to_string())?;
        return Ok(());
    }
    let mut send = respond
        .send_response(head, false)
        .map_err(|e| e.to_string())?;
    let r = stream_body(&mut send, &mut body, out).await;
    match &r {
        Err(BodyFailure::Stopped) => {
            tracing::debug!("h2 response stopped by policy; resetting the stream");
            send.send_reset(h2::Reason::CANCEL);
        }
        Err(BodyFailure::Other(e)) => {
            tracing::debug!(error = %e, "h2 response body failed; resetting the stream");
            send.send_reset(h2::Reason::INTERNAL_ERROR);
        }
        Ok(()) => {}
    }
    r.map_err(|e| e.to_string())
}

/// Why a response body could not be streamed.
enum BodyFailure {
    /// A watching rule stopped the exchange (§6.1).
    Stopped,
    Other(String),
}

impl From<String> for BodyFailure {
    fn from(s: String) -> Self {
        Self::Other(s)
    }
}

impl std::fmt::Display for BodyFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stopped => f.write_str("stopped by policy"),
            Self::Other(s) => f.write_str(s),
        }
    }
}

async fn stream_body(
    send: &mut SendStream<Bytes>,
    body: &mut Body,
    out: &Out<'_>,
) -> Result<(), BodyFailure> {
    loop {
        let frame = timeout(
            out.idle,
            poll_fn(|cx| http_body::Body::poll_frame(Pin::new(&mut *body), cx)),
        )
        .await
        .map_err(|_| "response body idle timeout".to_owned())?;
        let frame = match frame {
            None => {
                send.send_data(Bytes::new(), true)
                    .map_err(|e| e.to_string())?;
                return Ok(());
            }
            Some(Err(BodyError::Stopped)) => return Err(BodyFailure::Stopped),
            Some(Err(e)) => return Err(e.to_string().into()),
            Some(Ok(f)) => f,
        };
        match frame.into_data() {
            Ok(mut data) => {
                while !data.is_empty() {
                    send.reserve_capacity(data.len());
                    let cap = timeout(out.idle, poll_fn(|cx| send.poll_capacity(cx)))
                        .await
                        .map_err(|_| "client flow-control window stalled".to_owned())?;
                    let n = match cap {
                        None => return Err("stream closed by the client".to_owned().into()),
                        Some(Err(e)) => return Err(e.to_string().into()),
                        Some(Ok(n)) => n.min(data.len()),
                    };
                    if n == 0 {
                        continue;
                    }
                    send.send_data(data.split_to(n), false)
                        .map_err(|e| e.to_string())?;
                }
            }
            Err(frame) => {
                if let Ok(trailers) = frame.into_trailers()
                    && out.allow_trailers
                {
                    let mut t = http::HeaderMap::new();
                    for (n, v) in &trailers {
                        if !is_reserved(n.as_str()) {
                            t.append(n.clone(), v.clone());
                        }
                    }
                    send.send_trailers(t).map_err(|e| e.to_string())?;
                    return Ok(());
                }
                // Trailers not allowed: dropped; the body ends after the
                // data (the next poll returns `None`).
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The h2 front end of the exchange core
// ---------------------------------------------------------------------------

/// The first client-side body failure of a stream, recorded by the body
/// adapters so the exchange can stop waiting on the upstream at once.
#[derive(Default)]
struct BodyFail {
    error: Mutex<Option<ParseError>>,
    signal: CancellationToken,
}

impl BodyFail {
    fn set(&self, e: ParseError) {
        let mut g = self.error.lock().unwrap_or_else(PoisonError::into_inner);
        if g.is_none() {
            *g = Some(e);
        }
        drop(g);
        self.signal.cancel();
    }

    fn get(&self) -> Option<ParseError> {
        self.error
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

struct H2Front {
    respond: SendResponse<Bytes>,
    fail: Arc<BodyFail>,
    expect_continue: bool,
}

impl H2Front {
    /// `100 Continue` once, when the client waits for it.
    fn continue_once(&mut self) -> Result<(), ParseError> {
        if !std::mem::take(&mut self.expect_continue) {
            return Ok(());
        }
        let head = http::Response::builder()
            .status(http::StatusCode::CONTINUE)
            .body(())
            .map_err(|e| ParseError::new(Reason::Io, e.to_string()))?;
        self.respond
            .send_informational(head)
            .map_err(|e| ParseError::new(Reason::Io, e.to_string()))
    }
}

impl BodyIo for H2Front {
    fn collect<'a>(
        &'a mut self,
        body: &'a mut Body,
        cap: u64,
    ) -> StageFuture<'a, Result<Collected, ParseError>> {
        Box::pin(async move {
            self.continue_once()?;
            let c = collect_prefix(body, cap).await;
            if let Some(e) = self.fail.get() {
                return Err(e);
            }
            Ok(c)
        })
    }
}

impl Front for H2Front {
    async fn drive<F>(&mut self, fut: F) -> Result<F::Output, ParseError>
    where
        F: Future + Send,
        F::Output: Send,
    {
        self.continue_once()?;
        let fail = self.fail.clone();
        let respond = &mut self.respond;
        let out = tokio::select! {
            biased;
            () = fail.signal.cancelled() => None,
            // The client gave up on the stream: stop the upstream work too
            // (a reset-after-accept flood must not keep upstream requests
            // running).
            r = poll_fn(|cx| respond.poll_reset(cx)) => {
                let why = match r {
                    Ok(reason) => format!("client reset the stream ({reason})"),
                    Err(e) => format!("h2 connection failed: {e}"),
                };
                return Err(ParseError::new(Reason::UnexpectedEof, why));
            }
            out = fut => Some(out),
        };
        if let Some(e) = fail.get() {
            return Err(e);
        }
        out.ok_or_else(|| ParseError::new(Reason::Io, "request body failed"))
    }
}

// ---------------------------------------------------------------------------
// Request body adapters
// ---------------------------------------------------------------------------

/// An `h2::RecvStream` as an `http_body::Body`: flow-control capacity is
/// released as each DATA frame is handed on (so the client can only get as
/// far ahead as the windows allow: backpressure), the stream must make
/// progress within `body_idle_timeout`, and trailers are refused unless
/// `http.allow_trailers` (then validated).
struct H2Body {
    rx: RecvStream,
    idle: Duration,
    deadline: Pin<Box<Sleep>>,
    limits: Arc<Limits>,
    flags: Arc<HttpFlags>,
    data_done: bool,
    finished: bool,
    fail: Arc<BodyFail>,
}

impl H2Body {
    fn new(
        rx: RecvStream,
        limits: &Arc<Limits>,
        flags: &Arc<HttpFlags>,
        fail: Arc<BodyFail>,
    ) -> Self {
        let idle = limits.body_idle_timeout;
        Self {
            rx,
            idle,
            deadline: Box::pin(sleep(idle)),
            limits: limits.clone(),
            flags: flags.clone(),
            data_done: false,
            finished: false,
            fail,
        }
    }

    fn failed(
        &mut self,
        e: ParseError,
        out: BodyError,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        self.finished = true;
        self.fail.set(e);
        Poll::Ready(Some(Err(out)))
    }

    fn pending(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        if self.deadline.as_mut().poll(cx).is_ready() {
            let e = ParseError::new(Reason::BodyTimeout, "request body idle timeout");
            return self.failed(e, BodyError::Timeout);
        }
        Poll::Pending
    }
}

impl http_body::Body for H2Body {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = self.get_mut();
        if this.finished {
            return Poll::Ready(None);
        }
        if !this.data_done {
            match this.rx.poll_data(cx) {
                Poll::Ready(Some(Ok(d))) => {
                    // Release as the data moves on: the window refills only
                    // as fast as the consumer (the upstream) takes it.
                    let _ = this.rx.flow_control().release_capacity(d.len());
                    let next = Instant::now() + this.idle;
                    this.deadline.as_mut().reset(next);
                    return Poll::Ready(Some(Ok(Frame::data(d))));
                }
                Poll::Ready(Some(Err(e))) => {
                    let pe = ParseError::new(Reason::UnexpectedEof, format!("h2 stream: {e}"));
                    return this.failed(pe, BodyError::Incomplete);
                }
                Poll::Ready(None) => this.data_done = true,
                Poll::Pending => return this.pending(cx),
            }
        }
        match this.rx.poll_trailers(cx) {
            Poll::Ready(Ok(None)) => {
                this.finished = true;
                Poll::Ready(None)
            }
            Poll::Ready(Ok(Some(t))) => {
                if !this.flags.allow_trailers {
                    let e = ParseError::new(Reason::Trailers, "trailer section present");
                    return this.failed(e.clone(), BodyError::Invalid(e));
                }
                match validate_h2_trailers(&t, &this.limits, &this.flags) {
                    Ok(t) => {
                        this.finished = true;
                        Poll::Ready(Some(Ok(Frame::trailers(t))))
                    }
                    Err(e) => this.failed(e.clone(), BodyError::Invalid(e)),
                }
            }
            Poll::Ready(Err(e)) => {
                let pe = ParseError::new(Reason::UnexpectedEof, format!("h2 stream: {e}"));
                this.failed(pe, BodyError::Incomplete)
            }
            Poll::Pending => this.pending(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.finished || self.rx.is_end_stream()
    }
}

/// Records the first error of the (capped, length-checked) request body.
struct Observed {
    inner: Body,
    fail: Arc<BodyFail>,
}

impl http_body::Body for Observed {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let r = ready!(Pin::new(&mut self.inner).poll_frame(cx));
        if let Some(Err(e)) = &r {
            self.fail.set(body_failure(e));
        }
        Poll::Ready(r)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
}
