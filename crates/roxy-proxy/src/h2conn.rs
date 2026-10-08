//! Client-side HTTP/2 inside a TLS tunnel.
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
//!   disallowed trailers) resets the stream; the upstream request is
//!   dropped mid-body, so a truncated body is never presented as complete.
//! - A client that resets its stream or drops the connection gets nothing
//!   back (there is nobody to answer); the upstream request is dropped the
//!   same way and the flow is logged with reason `client_gone`.
//! - A deny writes roxy's deny response on that stream. When the decision
//!   closes (the default), the connection then sends `GOAWAY`, refuses
//!   every stream it has not started (`REFUSED_STREAM`), lets in-flight
//!   streams finish for at most [`CLOSE_GRACE`], and closes.
//! - Connection-level protocol errors close the connection (the `h2` crate
//!   sends `GOAWAY` with the error code).
//! - Extended CONNECT (RFC 8441, WebSocket over h2) is not enabled, so a
//!   client cannot negotiate it; plain CONNECT is refused by the mapper.

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::Bytes;
use h2::server::{Connection, SendResponse};
use h2::{RecvStream, SendStream};
use http_body::Frame;
use roxy_http::h2map::{from_h2_parts, to_h2_response, validate_h2_trailers};
use roxy_http::{
    Authority, Body, BodyError, CanonicalResponse, DriveError, HttpFlags, Limits, Method,
    ParseError, Reason, WriteError, status_forbids_body, validate_response_trailers,
};
use tokio::task::JoinSet;
use tokio::time::{Instant, Sleep, sleep, sleep_until, timeout};
use tokio_util::sync::CancellationToken;

use crate::body::{Collected, collect_prefix};
use crate::conn::ConnLimits;
use crate::exchange::{
    Answer, Front, Outcome, WriteFailure, process, record_client_failure, record_client_gone,
    record_continue_failure, send,
};
use crate::flowlog::TlsInfo;
use crate::io::Io;
use crate::listener::ClientConn;
use crate::pipeline::{BodyIo, CollectFuture, FlowCx, body_failure};
use crate::server::Shared;

/// How long in-flight streams may continue after the connection started
/// closing (a closing deny, server shutdown, idle timeout).
pub(crate) const CLOSE_GRACE: Duration = Duration::from_secs(10);
/// How long stream tasks may take to finish once their connection is gone.
const STREAM_DRAIN: Duration = Duration::from_secs(1);
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
    /// The codec's limits, fixed at accept like the h1 codec's: the
    /// connection's settings, the stream mapping, request body framing.
    cl: ConnLimits,
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
    cl: ConnLimits,
) {
    let limits = cl.limits.clone();
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
        cl,
        closing: CancellationToken::new(),
    });
    let mut streams: JoinSet<()> = JoinSet::new();
    let mut closing = false;
    let mut close_deadline = Instant::now();
    // The first request head is owed within `header_timeout`, as on h1;
    // `idle_timeout` is for the gaps between requests.
    let mut idle_deadline = Some(Instant::now() + limits.header_timeout);
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
    // Without the connection every stream operation fails, so the tasks
    // still running reach their outcome and log it on their own; one that
    // does not is aborted, and its flow logged as `aborted` as it drops.
    drop(conn);
    let _ = timeout(STREAM_DRAIN, async {
        while streams.join_next().await.is_some() {}
    })
    .await;
}

/// One stream: map, run the exchange core, write the outcome.
async fn serve_stream(
    req: http::Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    ccx: Arc<ConnCx>,
) {
    // Audit backpressure before anything is logged for this stream, a
    // `parse_error` included: one connection can open many streams.
    crate::flowlog::sink_ready(&*ccx.shared.sink).await;
    let snap = ccx.shared.snapshot();
    let ConnLimits { limits, flags, .. } = &ccx.cl;
    let (parts, recv) = req.into_parts();
    let fail = Arc::new(BodyFail::default());
    let raw = if recv.is_end_stream() {
        // END_STREAM on HEADERS: no body (and a known length of 0).
        Body::empty()
    } else {
        Body::wrap_native(
            H2Body::new(recv, limits, flags, fail.clone()),
            u64::MAX,
            None,
        )
    };
    let mut req = match from_h2_parts(parts, raw, &ccx.authority, limits, flags) {
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
    let method = req.method.clone();
    let cx = FlowCx::new(
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
    let (mut cx, outcome) = process(&mut front, cx, req).await;
    let H2Front {
        mut respond, fail, ..
    } = front;
    let out = Out {
        method: &method,
        idle: limits.body_idle_timeout,
        body_idle: limits.response_body_idle_timeout,
        limits,
        flags,
    };
    let answer = match outcome {
        Outcome::Respond(res) => Answer::Response(res),
        Outcome::Refuse(refusal) => Answer::Refusal(refusal),
        // The client went away: nothing to answer, nothing to reset.
        Outcome::Close(_) if fail.gone() => return record_client_gone(&mut cx),
        Outcome::Close(DriveError::Client(e)) => {
            ccx.shared
                .emit_parse_error(&ccx.client, Some(cx.flow.to_string()), &e);
            respond.send_reset(h2::Reason::PROTOCOL_ERROR);
            return record_client_failure(&mut cx, &e, None);
        }
        Outcome::Close(DriveError::Write(e)) => {
            respond.send_reset(h2::Reason::INTERNAL_ERROR);
            return record_continue_failure(&mut cx, e);
        }
        Outcome::Upgrade { .. } => {
            // Unreachable: h2 requests never carry an upgrade. Fail closed.
            respond.send_reset(h2::Reason::INTERNAL_ERROR);
            let e = ParseError::new(Reason::H2UnsupportedMethod, "upgrade over h2");
            return record_client_failure(&mut cx, &e, None);
        }
    };
    let sent = send(&mut cx, answer, |res| {
        write_response(&mut respond, res, &out)
    })
    .await;
    // A closing deny, or a watching stop that closes, ends the connection:
    // GOAWAY once the stream is written.
    if sent.close {
        ccx.closing.cancel();
    }
}

/// Response-writing parameters for one stream: the client's flow-control
/// window must open within `idle`, the body must yield its next frame
/// within `body_idle`; `flags` and `limits` decide whether trailers go out.
struct Out<'a> {
    method: &'a Method,
    idle: Duration,
    body_idle: Duration,
    limits: &'a Limits,
    flags: &'a HttpFlags,
}

/// Writes `res` on the stream: head, then the body as DATA frames within
/// the peer's flow-control window, then trailers (only with
/// `http.allow_response_trailers`). A body that fails resets the stream, so
/// the client never sees a truncated body as complete.
async fn write_response(
    respond: &mut SendResponse<Bytes>,
    res: CanonicalResponse,
    out: &Out<'_>,
) -> Result<(), WriteFailure> {
    let head = to_h2_response(&res, out.method)
        .body(())
        .map_err(|e| WriteFailure::Io(format!("response head: {e}")))?;
    // `content-length: 0` may still carry trailers when they are allowed,
    // so only a body that has nothing more to yield ends on the HEADERS.
    let bodiless = status_forbids_body(res.status)
        || *out.method == Method::Head
        || (res.body.known_length() == Some(0)
            && (!out.flags.allow_response_trailers || http_body::Body::is_end_stream(&res.body)));
    let mut body = res.body;
    if bodiless {
        respond
            .send_response(head, true)
            .map_err(|e| stream_error(&e))?;
        return Ok(());
    }
    let mut send = respond
        .send_response(head, false)
        .map_err(|e| stream_error(&e))?;
    let r = stream_body(&mut send, &mut body, out).await;
    match &r {
        Err(WriteFailure::Stopped) => {
            tracing::debug!("h2 response stopped by policy; resetting the stream");
            send.send_reset(h2::Reason::CANCEL);
        }
        // The upstream stalled, not roxy: the client sees a cancelled
        // stream rather than a proxy fault.
        Err(WriteFailure::UpstreamStalled) => {
            tracing::debug!("h2 response body stalled; resetting the stream");
            send.send_reset(h2::Reason::CANCEL);
        }
        // The client stopped taking the body: cancel rather than wait on
        // a window it may never open.
        Err(WriteFailure::ClientStalled) => {
            tracing::debug!("client flow-control window stalled; resetting the stream");
            send.send_reset(h2::Reason::CANCEL);
        }
        Err(e @ (WriteFailure::Io(_) | WriteFailure::Request(_))) => {
            tracing::debug!(error = %e, "h2 response body failed; resetting the stream");
            send.send_reset(h2::Reason::INTERNAL_ERROR);
        }
        // Nobody left to reset.
        Err(WriteFailure::ClientGone(_)) | Ok(()) => {}
    }
    r
}

/// A failed stream operation: the client's doing (reset, connection gone)
/// or not.
fn stream_error(e: &h2::Error) -> WriteFailure {
    if e.is_reset() || e.is_io() || e.is_go_away() {
        WriteFailure::ClientGone(e.to_string())
    } else {
        WriteFailure::Io(e.to_string())
    }
}

fn poll_frame(
    body: &mut Body,
    cx: &mut Context<'_>,
) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
    http_body::Body::poll_frame(Pin::new(body), cx)
}

async fn stream_body(
    send: &mut SendStream<Bytes>,
    body: &mut Body,
    out: &Out<'_>,
) -> Result<(), WriteFailure> {
    // One timer for the whole body. The two waits (next frame, then window
    // capacity for it) never overlap, so each re-arms it with its own limit.
    let mut stall = std::pin::pin!(sleep(out.body_idle));
    loop {
        let frame = match poll_fn(|cx| Poll::Ready(poll_frame(body, cx))).await {
            Poll::Ready(frame) => frame,
            Poll::Pending => {
                stall.as_mut().reset(Instant::now() + out.body_idle);
                poll_fn(|cx| {
                    if let Poll::Ready(f) = poll_frame(body, cx) {
                        return Poll::Ready(Ok(f));
                    }
                    stall
                        .as_mut()
                        .poll(cx)
                        .map(|()| Err(WriteFailure::UpstreamStalled))
                })
                .await?
            }
        };
        let frame = match frame {
            None => {
                send.send_data(Bytes::new(), true)
                    .map_err(|e| stream_error(&e))?;
                return Ok(());
            }
            Some(Err(BodyError::Stopped)) => return Err(WriteFailure::Stopped),
            Some(Err(BodyError::Timeout)) => return Err(WriteFailure::UpstreamStalled),
            Some(Err(e)) => return Err(WriteFailure::Io(e.to_string())),
            Some(Ok(f)) => f,
        };
        match frame.into_data() {
            Ok(mut data) => {
                while !data.is_empty() {
                    send.reserve_capacity(data.len());
                    stall.as_mut().reset(Instant::now() + out.idle);
                    let cap = poll_fn(|cx| {
                        if let Poll::Ready(c) = send.poll_capacity(cx) {
                            return Poll::Ready(Ok(c));
                        }
                        stall
                            .as_mut()
                            .poll(cx)
                            .map(|()| Err(WriteFailure::ClientStalled))
                    })
                    .await?;
                    let n = match cap {
                        None => {
                            return Err(WriteFailure::ClientGone(
                                "stream closed by the client".to_owned(),
                            ));
                        }
                        Some(Err(e)) => return Err(stream_error(&e)),
                        Some(Ok(n)) => n.min(data.len()),
                    };
                    if n == 0 {
                        continue;
                    }
                    send.send_data(data.split_to(n), false)
                        .map_err(|e| stream_error(&e))?;
                }
            }
            Err(frame) => {
                let Ok(trailers) = frame.into_trailers() else {
                    continue;
                };
                // A forbidden field fails the body: the stream is reset
                // rather than ended with trailers the client may merge into
                // the headers.
                let checked = validate_response_trailers(&trailers, out.limits, out.flags)
                    .map_err(|e| WriteFailure::Io(format!("response trailers: {e}")))?;
                if let Some(t) = checked {
                    send.send_trailers(t).map_err(|e| stream_error(&e))?;
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

/// The first client-side failure of a stream, recorded by the body
/// adapters and the front so the exchange can stop waiting on the upstream
/// at once.
#[derive(Default)]
struct BodyFail {
    error: Mutex<Option<ParseError>>,
    signal: CancellationToken,
    /// The client reset the stream or dropped the connection, as opposed
    /// to sending something roxy refused.
    gone: AtomicBool,
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

    /// The stream failed on the client's side: a reset, or the connection
    /// ending. Anything else the `h2` crate reports here is a protocol
    /// error it already answered on the connection.
    fn stream_failed(&self, e: &h2::Error) {
        if e.is_reset() || e.is_io() || e.is_go_away() {
            self.gone.store(true, Ordering::Relaxed);
        }
        self.set(ParseError::new(
            Reason::UnexpectedEof,
            format!("h2 stream: {e}"),
        ));
    }

    fn gone(&self) -> bool {
        self.gone.load(Ordering::Relaxed)
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
    fn continue_once(&mut self) -> Result<(), DriveError> {
        if !std::mem::take(&mut self.expect_continue) {
            return Ok(());
        }
        let head = http::Response::builder()
            .status(http::StatusCode::CONTINUE)
            .body(())
            .map_err(|e| WriteError::Io(std::io::Error::other(e)))?;
        self.respond
            .send_informational(head)
            .map_err(|e| WriteError::Io(std::io::Error::other(e)))?;
        Ok(())
    }
}

impl BodyIo for H2Front {
    fn collect<'a>(
        &'a mut self,
        body: &'a mut Body,
        cap: u64,
        meter: &'a mut (dyn FnMut(u64) -> bool + Send),
    ) -> CollectFuture<'a, Result<Collected, DriveError>> {
        Box::pin(async move {
            self.continue_once()?;
            let c = collect_prefix(body, cap, meter).await;
            if let Some(e) = self.fail.get() {
                return Err(e.into());
            }
            Ok(c)
        })
    }
}

impl Front for H2Front {
    async fn drive<F>(&mut self, fut: F) -> Result<F::Output, DriveError>
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
                fail.gone.store(true, Ordering::Relaxed);
                return Err(ParseError::new(Reason::UnexpectedEof, why).into());
            }
            out = fut => Some(out),
        };
        if let Some(e) = fail.get() {
            return Err(e.into());
        }
        out.ok_or_else(|| ParseError::new(Reason::Io, "request body failed").into())
    }
}

// ---------------------------------------------------------------------------
// Request body adapters
// ---------------------------------------------------------------------------

/// An `h2::RecvStream` as an `http_body::Body`: flow-control capacity is
/// released as each DATA frame is handed on (so the client can only get as
/// far ahead as the windows allow: backpressure), the stream must make
/// progress within `body_idle_timeout` of the consumer waiting for it, and
/// trailers are refused unless `http.allow_request_trailers` (then
/// validated).
///
/// The idle deadline is armed when a poll finds nothing and cleared by the
/// frame that ends the wait, so the time roxy itself spends before reading
/// the body (the rules, a `100 Continue` the client waits for) does not
/// count against the client.
struct H2Body {
    rx: RecvStream,
    idle: Duration,
    deadline: Option<Pin<Box<Sleep>>>,
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
        Self {
            rx,
            idle: limits.body_idle_timeout,
            deadline: None,
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
        let deadline = self
            .deadline
            .get_or_insert_with(|| Box::pin(sleep(self.idle)));
        if deadline.as_mut().poll(cx).is_ready() {
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
        while !this.data_done {
            match this.rx.poll_data(cx) {
                // An empty DATA frame (typically the one carrying
                // END_STREAM) has nothing to forward. Passing it on would
                // make the upstream h2 client send an empty non-final DATA
                // frame, which h2 servers count as a flood and answer with
                // GOAWAY(ENHANCE_YOUR_CALM) after about a hundred.
                Poll::Ready(Some(Ok(d))) if d.is_empty() => {}
                Poll::Ready(Some(Ok(d))) => {
                    // Release as the data moves on: the window refills only
                    // as fast as the consumer (the upstream) takes it.
                    let _ = this.rx.flow_control().release_capacity(d.len());
                    this.deadline = None;
                    return Poll::Ready(Some(Ok(Frame::data(d))));
                }
                Poll::Ready(Some(Err(e))) => {
                    this.fail.stream_failed(&e);
                    this.finished = true;
                    return Poll::Ready(Some(Err(BodyError::Incomplete)));
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
            Poll::Ready(Ok(Some(t))) => match validate_h2_trailers(&t, &this.limits, &this.flags) {
                Ok(t) => {
                    this.finished = true;
                    Poll::Ready(Some(Ok(Frame::trailers(t))))
                }
                Err(e) => this.failed(e.clone(), BodyError::Invalid(e)),
            },
            Poll::Ready(Err(e)) => {
                this.fail.stream_failed(&e);
                this.finished = true;
                Poll::Ready(Some(Err(BodyError::Incomplete)))
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
