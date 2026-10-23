//! The WebSocket relay, after a `101`: a byte splice when nothing reads
//! messages, or the message relay when a rule or an addon layer does.
//! Both are checked in flight (chunks and messages before they are
//! written), captured, held by audit backpressure, and ended by an idle
//! timeout or an in-flight stop.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use hyper_util::rt::TokioIo;
use roxy_http::CanonicalResponse;
use roxy_http::h1::ServerConn;
use roxy_http::ws::frame::{self, Decoder, FrameError, Opcode, Peer, close};
use roxy_http::ws::{WsKey, validate_no_extensions, validate_upgrade_response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use super::{Answer, Next, answer, protocol_refusal};
use crate::addons::Reclaim;
use crate::capture::Tap;
use crate::flowlog::FlowEvent;
use crate::in_flight::{Dir, InFlight};
use crate::io::{ClientIo, Io};
use crate::pipeline::{FlowCx, PerDir, Refusal};
use crate::view::host_text;

/// Validate the upgrade and reserve all memory needed by its relay before
/// publishing a `101` to the client or to the addon layers.
pub(crate) fn prepare_websocket(
    cx: &mut FlowCx,
    res: &CanonicalResponse,
    key: &WsKey,
) -> Result<(), Refusal> {
    let checked = validate_upgrade_response(res, key).and_then(|()| {
        if crate::addons::ws_without_extensions(&cx.snap, cx.layer_reads_bytes) {
            validate_no_extensions(res)
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
        return Err(protocol_refusal(cx, &host, port, e.to_string()));
    }
    if cx.snap.policy.reads_ws() {
        let per_direction = cx.snap.limits.max_ws_message_bytes;
        let lease = cx
            .shared
            .reserve_buffer(per_direction.saturating_mul(2))
            .ok_or_else(|| Refusal::fail_closed(crate::budget::EXHAUSTED))?;
        cx.buffers.push(lease);
    }
    Ok(())
}

/// Whose close ends the relay, besides an idle timeout, an in-flight stop
/// and a failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Until {
    /// Both sides have closed: a client that has read the upstream's EOF
    /// can still have bytes on their way to the upstream.
    BothClose,
    /// The upstream has closed. The client side is the layer stack's
    /// bodies: a layer carries the client's bytes for as long as the
    /// client sends, and the client sends until its socket closes, which
    /// only the relay's end does, so waiting for that side would be
    /// waiting for the idle timeout.
    UpstreamCloses,
}

/// The direct path when no addons are configured.
pub(super) async fn splice_websocket(
    conn: ServerConn<ClientIo>,
    mut cx: FlowCx,
    res: CanonicalResponse,
    upgraded: hyper::upgrade::Upgraded,
    key: &WsKey,
) -> Next {
    if let Err(r) = prepare_websocket(&mut cx, &res, key) {
        close_upstream_ws(upgraded).await;
        return answer(conn, Reclaim::now(cx), Answer::Refusal(r)).await;
    }
    let (client, leftover) = match conn.respond_upgrade(res).await {
        Ok(io) => io,
        Err(e) => {
            tracing::debug!(error = %e, "writing 101 failed");
            close_upstream_ws(upgraded).await;
            cx.emit_request_event();
            return None;
        }
    };
    relay_websocket(
        &mut cx,
        Box::new(client),
        upgraded,
        leftover.to_vec(),
        Until::BothClose,
        &CancellationToken::new(),
    )
    .await;
    cx.record_final_sample();
    cx.emit_request_event();
    None
}

/// The transport only writes the handshake and attaches the client to the
/// first lane pair. The core stage owns the relay through its completion.
pub(super) async fn connect_stack(
    conn: ServerConn<ClientIo>,
    reclaim: Reclaim,
    res: CanonicalResponse,
    client: crate::addons::WsClient,
) -> Next {
    let guard = reclaim.cancellation_guard();
    match conn.respond_upgrade(res).await {
        Ok((io, leftover)) => client.connect(Box::new(io), leftover.to_vec()),
        Err(e) => {
            tracing::debug!(error = %e, "writing 101 failed");
            reclaim.tear_down(crate::addons::CLIENT_GONE);
            drop(client);
        }
    }
    let mut cx = reclaim.take().await;
    if let Some(guard) = guard {
        guard.complete();
    }
    cx.record_final_sample();
    cx.emit_request_event();
    None
}

/// Run a prepared relay and record its byte counts and close event. The
/// caller emits the final request event after the entire exchange ends.
pub(crate) async fn relay_websocket(
    cx: &mut FlowCx,
    client: crate::io::BoxIo,
    upgraded: hyper::upgrade::Upgraded,
    leftover: Vec<u8>,
    until: Until,
    cancelled: &CancellationToken,
) {
    cx.record.response_status = Some(101);
    let host = cx.facts.request.as_ref().map(|r| host_text(&r.host));
    cx.shared.sink.emit(&FlowEvent::WsOpen {
        ts: chrono::Utc::now(),
        flow: cx.flow.to_string(),
        conn: cx.conn_id(),
        host,
    });
    let mut upstream = TokioIo::new(upgraded);
    let idle = cx.snap.limits.idle_timeout;
    let in_flight = cx
        .in_flight
        .clone()
        .expect("an allowed upgrade has in-flight rules");
    let mut taps = std::mem::take(&mut cx.taps);
    let result = if cx.snap.policy.reads_ws() {
        relay_messages(
            client,
            upstream,
            leftover,
            (idle, cx.snap.limits.max_ws_message_bytes),
            &in_flight,
            taps,
            until,
            cancelled,
        )
        .await
    } else {
        let mut extra = Some(0);
        if !leftover.is_empty() {
            let count = leftover.len() as u64;
            if in_flight.on_ws_chunk(Dir::Request, count).is_ok() {
                if let Some(t) = taps.request.as_mut() {
                    t.data(&leftover);
                }
                let sent = tokio::select! {
                    () = cancelled.cancelled() => false,
                    result = tokio::time::timeout(idle, upstream.write_all(&leftover)) => matches!(result, Ok(Ok(()))),
                };
                extra = sent.then_some(count);
            } else {
                extra = None;
            }
        }
        match extra {
            Some(extra) => {
                let (c2s, s2c, closed) =
                    splice(client, upstream, idle, &in_flight, taps, until, cancelled).await;
                Relayed {
                    c2s: c2s + extra,
                    s2c,
                    closed,
                }
            }
            None => Relayed {
                c2s: 0,
                s2c: 0,
                closed: None,
            },
        }
    };
    cx.shared.sink.emit(&FlowEvent::WsClose {
        ts: chrono::Utc::now(),
        flow: cx.flow.to_string(),
        conn: cx.conn_id(),
        bytes_c2s: result.c2s,
        bytes_s2c: result.s2c,
        close_code: result.closed.as_ref().map(|e| e.code),
        close_reason: result.closed.map(|e| e.detail.to_owned()),
    });
    cx.record.request_bytes = result.c2s;
    cx.record.response_bytes = result.s2c;
}

/// One direction of the WebSocket relay: what checks and records each chunk.
struct Relay<'a> {
    in_flight: &'a InFlight,
    dir: Dir,
    tap: Option<Tap>,
}

async fn pump<R, W>(
    mut r: R,
    w: &mut W,
    n: Arc<std::sync::atomic::AtomicU64>,
    last: Arc<std::sync::atomic::AtomicU64>,
    base: Instant,
    mut relay: Relay<'_>,
) where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    let in_flight = relay.in_flight;
    let sink = in_flight.sink();
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
        if in_flight.on_ws_chunk(relay.dir, k as u64).is_err() {
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

/// Copies bytes both ways until the sides close (both, or the upstream:
/// `until`), nothing moves for `idle` (then both sides get a `1001` close
/// frame: after that long a silence no frame is half-written), or an
/// in-flight rule stops the exchange (then both sides are dropped, i.e.
/// closed: the relay is byte-level, so a close frame could land inside a
/// half-written frame). Returns (client→server, server→client) byte
/// counts and the close roxy sent, if any.
async fn splice(
    client: impl Io,
    upstream: impl Io,
    idle: Duration,
    in_flight: &InFlight,
    taps: PerDir<Option<Tap>>,
    until: Until,
    cancelled: &CancellationToken,
) -> (u64, u64, Option<FrameError>) {
    use std::sync::atomic::AtomicU64;
    let base = Instant::now();
    let last = Arc::new(AtomicU64::new(0));
    let c2s = Arc::new(AtomicU64::new(0));
    let s2c = Arc::new(AtomicU64::new(0));
    let (cr, mut cw) = tokio::io::split(client);
    let (ur, mut uw) = tokio::io::split(upstream);
    let PerDir {
        request: up_tap,
        response: down_tap,
    } = taps;
    let a = pump(
        cr,
        &mut uw,
        c2s.clone(),
        last.clone(),
        base,
        Relay {
            in_flight,
            dir: Dir::Request,
            tap: up_tap,
        },
    );
    let b = pump(
        ur,
        &mut cw,
        s2c.clone(),
        last.clone(),
        base,
        Relay {
            in_flight,
            dir: Dir::Response,
            tap: down_tap,
        },
    );
    let closed = tokio::select! {
        () = cancelled.cancelled() => None,
        () = both_ways(a, b, until) => None,
        () = idle_watchdog(&last, base, idle) => {
            let mut to_up = FrameOut::new(&mut uw, Some(Masks::new()));
            let mut to_client = FrameOut::new(&mut cw, None);
            tokio::join!(to_up.close(IDLE.code), to_client.close(IDLE.code));
            Some(IDLE)
        }
        () = in_flight.cancelled() => {
            tracing::debug!("websocket relay stopped by policy");
            None
        }
    };
    (
        c2s.load(Ordering::Relaxed),
        s2c.load(Ordering::Relaxed),
        closed,
    )
}

/// Runs the two directions of a byte splice until the relay is over: both
/// have ended, or the upstream's has and the relay ends with the upstream.
async fn both_ways(
    to_upstream: impl std::future::Future<Output = ()>,
    to_client: impl std::future::Future<Output = ()>,
    until: Until,
) {
    match until {
        Until::BothClose => {
            tokio::join!(to_upstream, to_client);
        }
        Until::UpstreamCloses => {
            tokio::pin!(to_upstream, to_client);
            let client_side_first = tokio::select! {
                () = &mut to_upstream => true,
                () = &mut to_client => false,
            };
            if client_side_first {
                to_client.await;
            }
        }
    }
}

/// The close both sides get when nothing has moved for `limits.idle_timeout`.
const IDLE: FrameError = FrameError {
    code: close::GOING_AWAY,
    detail: "idle timeout",
};

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
pub(crate) const CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

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

/// Closes an upgraded upstream that nothing will relay: a `1008`, then a
/// shutdown.
pub(crate) async fn close_upstream_ws(upstream: hyper::upgrade::Upgraded) {
    FrameOut::new(TokioIo::new(upstream), Some(Masks::new()))
        .close(close::POLICY)
        .await;
}

/// How one direction of the message relay ended.
enum End {
    /// The sender closed its stream.
    Eof,
    /// A read or write failed, or no mask could be drawn.
    Broken,
    /// A rule denied a message, or the exchange was stopped.
    Stopped,
    /// Nothing moved either way for the idle timeout (the relay's end, not
    /// one direction's).
    Idle,
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
        let in_flight = self.relay.in_flight;
        loop {
            let msg = match self.dec.decode(&mut input) {
                Ok(Some(m)) => m,
                Ok(None) => return None,
                Err(e) => return Some(End::Protocol(e)),
            };
            // Checked before the write: a message that makes a deny match
            // is never relayed.
            let (msg, r) = in_flight.on_ws_message(self.relay.dir, msg);
            if r.is_err() {
                return Some(End::Stopped);
            }
            if self.out.encode(msg.opcode, msg.payload()).is_err() {
                return Some(End::Broken);
            }
            let len = self.out.buf.len() as u64;
            if in_flight.on_ws_chunk(self.relay.dir, len).is_err() {
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
        let sink = self.relay.in_flight.sink();
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
/// key toward the upstream. Runs until the sides close (both, or the
/// upstream: `until`), nothing moves for `idle` (both sides get `1001`), a
/// message breaks the protocol (both sides get its close code) or a rule
/// stops the exchange (both sides get `1008`).
async fn relay_messages(
    client: impl Io,
    upstream: impl Io,
    leftover: Vec<u8>,
    (idle, max): (Duration, u64),
    in_flight: &InFlight,
    PerDir {
        request: up_tap,
        response: down_tap,
    }: PerDir<Option<Tap>>,
    until: Until,
    cancelled: &CancellationToken,
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
                in_flight,
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
                in_flight,
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
                () = &mut watchdog => break End::Idle,
                () = cancelled.cancelled() => break End::Broken,
                () = in_flight.cancelled() => break End::Stopped,
            };
            let over = (a_done && b_done) || (b_done && until == Until::UpstreamCloses);
            match e {
                End::Eof if !over => {}
                e @ (End::Eof | End::Broken | End::Stopped | End::Idle | End::Protocol(_)) => {
                    break e;
                }
            }
        }
    };
    let closed = match end {
        End::Stopped => Some(FrameError {
            code: close::POLICY,
            detail: "denied by policy",
        }),
        End::Protocol(e) => Some(e),
        End::Idle => Some(IDLE),
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
