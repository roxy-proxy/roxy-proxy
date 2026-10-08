//! The WebSocket relay, after a `101`: a byte splice when nothing reads
//! messages, or the message relay when a rule or an addon layer does.
//! Both are watched (chunks and messages checked before they are
//! written), captured, held by audit backpressure, and ended by an idle
//! timeout or a stop from the watcher.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use hyper_util::rt::TokioIo;
use roxy_http::CanonicalResponse;
use roxy_http::h1::ServerConn;
use roxy_http::ws::frame::{self, Decoder, FrameError, Opcode, Peer, close};
use roxy_http::ws::{WsKey, validate_no_extensions, validate_upgrade_response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{Answer, Next, answer, protocol_refusal};
use crate::capture::Tap;
use crate::flowlog::FlowEvent;
use crate::io::{ClientIo, Io};
use crate::pipeline::{FlowCx, PerDir, Refusal};
use crate::view::host_text;
use crate::watch::{Dir, Watch};

/// Finishes an allowed upgrade: checks the upstream's `101`, writes it to
/// the client and relays until the WebSocket ends. The connection is spent
/// either way.
pub(super) async fn splice_websocket(
    conn: ServerConn<ClientIo>,
    mut cx: FlowCx,
    res: CanonicalResponse,
    upgraded: hyper::upgrade::Upgraded,
    key: &WsKey,
) -> Next {
    let parse = cx.snap.policy.reads_ws();
    let checked = validate_upgrade_response(&res, key).and_then(|()| {
        if crate::addons::ws_without_extensions(&cx.snap, cx.layer_reads_bytes) {
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
        return answer(conn, cx, Answer::Refusal(r)).await;
    }
    if parse {
        // Each direction reassembles up to a message's worth.
        let per_direction = cx.snap.limits.max_ws_message_bytes;
        let Some(lease) = cx.shared.reserve_buffer(per_direction.saturating_mul(2)) else {
            let r = Refusal::fail_closed(crate::budget::EXHAUSTED);
            return answer(conn, cx, Answer::Refusal(r)).await;
        };
        cx.buffers.push(lease);
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
    // Through an addon stack, the layers sit between the client and the
    // relay, carrying the WebSocket as the bodies of its exchange; the bytes
    // that came with the upgrade request go through them first.
    let leftover = leftover.to_vec();
    let mut spliced = None;
    let (client_io, leftover): (crate::io::BoxIo, Vec<u8>) = match &cx.stack {
        Some(st) => {
            let (bottom, client) = crate::addons::splice_client(st, Box::new(client_io), leftover);
            spliced = Some(client);
            (bottom, Vec::new())
        }
        None => (Box::new(client_io), leftover),
    };
    let mut upstream = TokioIo::new(upgraded);
    let idle = cx.snap.limits.idle_timeout;
    let Some(watch) = cx.watch.clone() else {
        cx.emit_request_event();
        return None;
    };
    let mut taps = std::mem::take(&mut cx.taps);
    if parse {
        let max = cx.snap.limits.max_ws_message_bytes;
        let r = relay_messages(client_io, upstream, leftover, (idle, max), &watch, taps).await;
        close_spliced(spliced).await;
        finish_websocket(&mut cx, r);
        return None;
    }
    let c2s_extra = leftover.len() as u64;
    if !leftover.is_empty() {
        // Bytes that arrived with the upgrade request: checked before they
        // are written, like every other relayed chunk.
        if watch.on_ws_chunk(Dir::Request, c2s_extra).is_err() {
            cx.record_final_sample();
            cx.emit_request_event();
            return None;
        }
        if let Some(t) = taps.request.as_mut() {
            t.data(&leftover);
        }
        if upstream.write_all(&leftover).await.is_err() {
            cx.emit_request_event();
            return None;
        }
    }
    let (c2s, s2c, closed) = splice(client_io, upstream, idle, &watch, taps).await;
    let r = Relayed {
        c2s: c2s + c2s_extra,
        s2c,
        closed,
    };
    close_spliced(spliced).await;
    finish_websocket(&mut cx, r);
    None
}

/// Through a stack, the relay's end closes the client too: the layers
/// hold its socket otherwise, for as long as they keep their bodies open.
async fn close_spliced(client: Option<crate::addons::SplicedClient>) {
    if let Some(c) = client {
        c.close(CLOSE_TIMEOUT).await;
    }
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
    cx.record_final_sample();
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
/// `idle` (then both sides get a `1001` close frame: after that long a
/// silence no frame is half-written), or a watching rule stops the
/// exchange (then both sides are dropped, i.e. closed: the relay is
/// byte-level, so a close frame could land inside a half-written frame).
/// Returns (client→server, server→client) byte counts and the close roxy
/// sent, if any.
async fn splice(
    client: impl Io,
    upstream: impl Io,
    idle: Duration,
    watch: &Watch,
    taps: PerDir<Option<Tap>>,
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
            watch,
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
            watch,
            dir: Dir::Response,
            tap: down_tap,
        },
    );
    let closed = tokio::select! {
        () = async { tokio::join!(a, b); } => None,
        () = idle_watchdog(&last, base, idle) => {
            let mut to_up = FrameOut::new(&mut uw, Some(Masks::new()));
            let mut to_client = FrameOut::new(&mut cw, None);
            tokio::join!(to_up.close(IDLE.code), to_client.close(IDLE.code));
            Some(IDLE)
        }
        () = watch.cancelled() => {
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
/// `idle` (both sides get `1001`), a message breaks the protocol (both
/// sides get its close code) or a rule stops the exchange (both sides get
/// `1008`).
async fn relay_messages(
    client: impl Io,
    upstream: impl Io,
    leftover: Vec<u8>,
    (idle, max): (Duration, u64),
    watch: &Watch,
    PerDir {
        request: up_tap,
        response: down_tap,
    }: PerDir<Option<Tap>>,
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
                () = &mut watchdog => break End::Idle,
                () = watch.cancelled() => break End::Stopped,
            };
            match e {
                End::Eof if !(a_done && b_done) => {}
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
