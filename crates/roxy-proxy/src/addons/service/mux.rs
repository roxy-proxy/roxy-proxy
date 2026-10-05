//! Streams over pooled connections (`roxy.layer.v3`).
//!
//! Each endpoint has a small pool of WebSocket connections; each exchange
//! is a stream on one of them. Text frames are JSON with a `stream` field;
//! binary frames are a 4-byte big-endian stream id, a direction byte
//! (request or response body), then body bytes. The two bodies of a
//! stream are fed independently, so a response head may arrive while the
//! request body is still streaming. Body bytes are flow-controlled per
//! stream, body and direction by credit, so one slow body never holds up
//! the connection or the other body: the reader hands each body's bytes
//! to its own feeder and never waits on a consumer.
//!
//! Broken framing fails the whole connection (every stream on it fails
//! closed); anything else fails only its stream, which is reset.
//!
//! The pools hang off the policy snapshot: a reload dials new connections
//! under the new policy and secrets, and retires the old snapshot's pools,
//! whose connections close as soon as no exchange is using them.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use bytes::BytesMut;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt as _, StreamExt as _};
use http::HeaderValue;
use roxy_http::{Body, BodyError, BodySender, Scheme};
use roxy_wasm::LayerResponse;
use serde::Serialize;
use tokio::sync::{Notify, OnceCell, mpsc, oneshot};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_util::sync::CancellationToken;

use super::super::{AddonMode, EndpointSpec, StackError, StackFlow, endpoint};
use super::{First, In, Out, ServiceError, ServiceSpec, Unanswered};
use crate::addr::PrivateAddrs;
use crate::flowlog::FlowEvent;
use crate::upstream::MaybeTls;
use crate::watch::Dir;

/// The WebSocket subprotocol a service must accept.
pub const SUBPROTOCOL: &str = "roxy.layer.v3";

/// Each body's starting credit, each way, in bytes.
pub(super) const WINDOW: u64 = 256 * 1024;

/// Largest control message or body frame accepted from a service.
const MAX_FRAME: usize = 16 * 1024 * 1024;

/// Bytes discarded from an observe stream before they are credited back
/// in one message, so the credit queue holds a few messages per stream
/// however small the service's frames.
const OBSERVE_GRANT: u64 = WINDOW / 4;

/// Largest body frame roxy sends, so streams share the socket fairly.
const MAX_BODY_FRAME: usize = 64 * 1024;

/// Body frames waiting for the socket, across all streams. Each stream
/// only queues what it has credit for.
const WRITE_QUEUE: usize = 64;

type Ws = WebSocketStream<MaybeTls>;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What makes two connections interchangeable: the endpoint as configured,
/// and the pool's sizing. Secrets are fixed for a snapshot, so the raw
/// header templates stand for their values.
#[derive(Clone, PartialEq, Eq, Hash)]
struct PoolKey {
    url: String,
    headers: Vec<(String, String)>,
    private: PrivateAddrs,
    max_connections: usize,
    max_streams: usize,
}

/// The service-layer connection pools of one policy snapshot.
#[derive(Default)]
pub(crate) struct Pools {
    by_key: Mutex<HashMap<PoolKey, Arc<Pool>>>,
    retired: AtomicBool,
}

impl Pools {
    /// A reload replaced this snapshot: its connections close once idle
    /// (now, for those that are). Client connections can hold an old
    /// snapshot for as long as they last, so this does not wait for it to
    /// be dropped.
    pub(crate) fn retire(&self) {
        self.retired.store(true, Ordering::SeqCst);
        for pool in lock(&self.by_key).values() {
            pool.retired.store(true, Ordering::SeqCst);
            lock(&pool.entries).retain(|e| e.reserved > 0);
        }
    }
}

struct Pool {
    entries: Mutex<Vec<Entry>>,
    /// A stream ended or a connection went away: waiters may find room.
    freed: Notify,
    max_connections: usize,
    max_streams: usize,
    /// Its snapshot was replaced: connections close once idle.
    retired: AtomicBool,
}

/// One connection of a pool. It counts against `max_connections` for as
/// long as anything holds a place on it, closed or not.
struct Entry {
    link: Arc<OnceCell<Arc<Link>>>,
    /// Streams on it, and exchanges waiting for it to connect.
    reserved: usize,
}

impl Entry {
    /// Takes no new streams: its connection failed, or ran out of ids.
    fn closed(&self) -> bool {
        self.link.get().is_some_and(|l| l.shared.closed())
    }
}

/// A place on one of the pool's connections, held until the stream ends.
pub(super) struct Reservation {
    pool: Arc<Pool>,
    link: Arc<OnceCell<Arc<Link>>>,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let mut entries = lock(&self.pool.entries);
        if let Some(i) = entries
            .iter()
            .position(|e| Arc::ptr_eq(&e.link, &self.link))
        {
            let e = &mut entries[i];
            e.reserved = e.reserved.saturating_sub(1);
            // Nobody is left on it, and it will take no one new: it never
            // connected, it closed, or its pool is retired.
            if e.reserved == 0
                && (e.link.get().is_none()
                    || e.closed()
                    || self.pool.retired.load(Ordering::SeqCst))
            {
                entries.remove(i);
            }
        }
        drop(entries);
        self.pool.freed.notify_waiters();
    }
}

impl Pool {
    /// A place on a connection with room, opening a new entry when every
    /// open one is full and the pool is not; else waits for one to free.
    async fn reserve(self: &Arc<Self>) -> Reservation {
        loop {
            let freed = self.freed.notified();
            tokio::pin!(freed);
            freed.as_mut().enable();
            {
                let mut entries = lock(&self.entries);
                entries.retain(|e| e.reserved > 0 || !e.closed());
                let pick = if let Some(e) = entries
                    .iter_mut()
                    .find(|e| !e.closed() && e.reserved < self.max_streams)
                {
                    e.reserved += 1;
                    Some(e.link.clone())
                } else if entries.len() < self.max_connections {
                    let link = Arc::new(OnceCell::new());
                    entries.push(Entry {
                        link: link.clone(),
                        reserved: 1,
                    });
                    Some(link)
                } else {
                    None
                };
                if let Some(link) = pick {
                    return Reservation {
                        pool: self.clone(),
                        link,
                    };
                }
            }
            freed.await;
        }
    }
}

/// One connection: what streams send through, and the state its reader
/// shares.
pub(super) struct Link {
    shared: Arc<LinkShared>,
    /// Ordered per stream: open, heads, body frames, ends. The socket
    /// closes once every sender is gone (the pool's, and each stream's).
    data: mpsc::Sender<Queued>,
}

/// A message on a connection's data queue.
struct Queued {
    msg: Message,
    wire: Arc<Wire>,
    /// It is the stream's `open`.
    open: bool,
}

/// How far a stream has got on the wire. Once it is reset, nothing more
/// of it is written. A reset before its `open` was written does not tell
/// the service (the reset would overtake the queued `open`): the service
/// never hears of the stream.
#[derive(Default)]
struct Wire(AtomicU8);

impl Wire {
    const UNSENT: u8 = 0;
    const WRITTEN: u8 = 1;
    const DROPPED: u8 = 2;

    /// Whether the writer writes a message of the stream (`open`: its
    /// `open` message).
    fn write(&self, open: bool) -> bool {
        if open {
            self.0
                .compare_exchange(
                    Self::UNSENT,
                    Self::WRITTEN,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                )
                .is_ok()
        } else {
            self.0.load(Ordering::SeqCst) != Self::DROPPED
        }
    }

    /// The stream is reset: whether the service is told, which it is
    /// once the `open` has been written.
    fn reset(&self) -> bool {
        self.0.swap(Self::DROPPED, Ordering::SeqCst) == Self::WRITTEN
    }
}

struct LinkShared {
    streams: Mutex<LinkState>,
    /// Credit and resets: never held up behind body frames, so the reader
    /// and feeders can always send them.
    ctl: mpsc::UnboundedSender<Message>,
}

struct LinkState {
    open: HashMap<u32, Arc<Stream>>,
    /// The next id to hand out; ids below it were opened.
    next_id: u32,
    /// The connection failed: no new streams.
    failed: bool,
}

impl LinkShared {
    fn closed(&self) -> bool {
        let s = lock(&self.streams);
        s.failed || s.next_id == u32::MAX
    }

    fn send_ctl(&self, stream: u32, m: &Out) {
        let _ = self.ctl.send(text(stream, m));
    }

    /// The connection failed: every stream on it fails, and it closes.
    fn fail(&self, e: &ServiceError) {
        let streams: Vec<_> = {
            let mut s = lock(&self.streams);
            s.failed = true;
            s.open.drain().map(|(_, st)| st).collect()
        };
        for s in streams {
            s.fail(e.clone(), Reset::Skip);
        }
        let _ = self.ctl.send(Message::Close(None));
    }
}

#[derive(Serialize)]
struct Envelope<'a> {
    stream: u32,
    #[serde(flatten)]
    msg: &'a Out,
}

fn text(stream: u32, m: &Out) -> Message {
    // `Out` always serializes.
    Message::text(serde_json::to_string(&Envelope { stream, msg: m }).unwrap_or_default())
}

/// The direction byte of a binary frame.
fn dir_byte(dir: Dir) -> u8 {
    match dir {
        Dir::Request => 0,
        Dir::Response => 1,
    }
}

fn dir_of(byte: u8) -> Option<Dir> {
    match byte {
        0 => Some(Dir::Request),
        1 => Some(Dir::Response),
        _ => None,
    }
}

fn binary(stream: u32, dir: Dir, data: &[u8]) -> Message {
    let mut b = BytesMut::with_capacity(5 + data.len());
    b.extend_from_slice(&stream.to_be_bytes());
    b.extend_from_slice(&[dir_byte(dir)]);
    b.extend_from_slice(data);
    Message::binary(b.freeze())
}

/// The service's answers to an enforce stream, in protocol order.
pub(super) struct Answers {
    pub first: oneshot::Receiver<Result<First, Unanswered>>,
    pub second: oneshot::Receiver<Result<LayerResponse, Unanswered>>,
}

/// One exchange on a connection.
pub(super) struct Stream {
    id: u32,
    link: Arc<Link>,
    st: Arc<StackFlow>,
    index: usize,
    mode: AddonMode,
    state: Mutex<StreamState>,
    more_credit: Notify,
    /// Wakes whatever is sending or waiting on the stream once it ended.
    ended: CancellationToken,
    wire: Arc<Wire>,
}

#[derive(Default)]
struct StreamState {
    first: Option<oneshot::Sender<Result<First, Unanswered>>>,
    second: Option<oneshot::Sender<Result<LayerResponse, Unanswered>>>,
    /// The request body and the response body, each on its own.
    req: Feed,
    res: Feed,
    /// Why an observe stream failed, for its driver to log.
    observe_error: Option<ServiceError>,
    slot: Option<Reservation>,
    /// Settled: nothing more is sent or delivered on it.
    ended: bool,
}

impl StreamState {
    fn feed(&mut self, dir: Dir) -> &mut Feed {
        match dir {
            Dir::Request => &mut self.req,
            Dir::Response => &mut self.res,
        }
    }

    /// The service still owes something: an answer, or the end of a body
    /// it is sending.
    fn waiting(&self) -> bool {
        self.req.inbox.is_some()
            || self.res.inbox.is_some()
            || self.first.is_some()
            || self.second.is_some()
    }
}

/// One body of a stream: what the service is sending of it, and the
/// credit each way.
struct Feed {
    /// Being fed from the stream: its head arrived and its end has not.
    inbox: Option<Arc<Inbox>>,
    /// Bytes received and not yet credited back.
    unacked: u64,
    /// Observe mode: bytes discarded since the last credit went back.
    discarded: u64,
    /// What roxy may still send: granted by the service.
    credit: u64,
}

impl Default for Feed {
    fn default() -> Self {
        Self {
            inbox: None,
            unacked: 0,
            discarded: 0,
            credit: WINDOW,
        }
    }
}

/// How a stream ends.
enum End<'a> {
    /// Nothing to tell anyone: the service's last message arrived, an
    /// observe stream sent all it had, or an `open` was given up before
    /// its message went.
    Quiet,
    /// The service failed it. `reset` tells the service, when it has not
    /// already closed or reset the stream itself.
    Failed { e: ServiceError, reset: Reset },
    /// roxy gave up on it (the client went away, a missed deadline, an
    /// upgrade): the service is told, whoever is waiting gets `why`, and
    /// nothing is logged as the service's fault.
    Abandoned(&'a str),
    /// The body roxy was sending in direction `dir` failed: abandoned, and
    /// whoever is waiting learns which body failed and how.
    BodyFailed(Dir, BodyError),
}

/// Whether failing a stream tells the service (a `reset` message).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reset {
    Send,
    /// The connection is gone, or the service already ended the stream.
    Skip,
}

/// Bytes for one body, between the reader and that body's feeder. At most
/// the body's credit is ever here.
#[derive(Default)]
struct Inbox {
    q: Mutex<InboxQ>,
    ready: Notify,
    abort: CancellationToken,
}

#[derive(Default)]
struct InboxQ {
    buf: BytesMut,
    end: bool,
    /// The consumer went away: bytes are credited back as they arrive.
    dropped: bool,
    abort: Option<String>,
}

impl Inbox {
    fn abort(&self, e: &Unanswered) {
        lock(&self.q).abort = Some(e.to_string());
        self.abort.cancel();
    }
}

impl Stream {
    fn name(&self) -> String {
        self.st.snap.addons[self.index].name.clone()
    }

    /// Ends the stream, once: nothing more goes on it, its place on the
    /// connection is released, the reader forgets it, and whoever was
    /// waiting on it (a pending answer, the body being fed) learns how it
    /// ended.
    fn settle(&self, end: End<'_>) {
        let (inboxes, first, second, slot) = {
            let mut s = lock(&self.state);
            if s.ended {
                return;
            }
            s.ended = true;
            if let End::Failed { e, .. } = &end
                && self.mode == AddonMode::Observe
            {
                s.observe_error = Some(e.clone());
            }
            (
                [s.req.inbox.take(), s.res.inbox.take()],
                s.first.take(),
                s.second.take(),
                s.slot.take(),
            )
        };
        self.ended.cancel();
        lock(&self.link.shared.streams).open.remove(&self.id);
        drop(slot);
        let (e, reset) = match end {
            End::Quiet => return,
            End::Failed { e, reset } => {
                let message = e.to_string();
                (
                    Unanswered::Service(e),
                    (reset == Reset::Send).then_some(message),
                )
            }
            End::Abandoned(why) => (Unanswered::Abandoned(why.to_owned()), Some(why.to_owned())),
            End::BodyFailed(dir, e) => {
                let message = format!("the {} body failed", dir.as_str());
                (Unanswered::Body(dir, e), Some(message))
            }
        };
        if let Some(message) = reset
            && self.wire.reset()
        {
            self.link.shared.send_ctl(self.id, &Out::Reset { message });
        }
        for inbox in inboxes.into_iter().flatten() {
            inbox.abort(&e);
        }
        if let Some(tx) = first {
            let _ = tx.send(Err(e));
        } else if let Some(tx) = second
            && !tx.is_closed()
        {
            let _ = tx.send(Err(e));
        } else if let Unanswered::Service(e) = e
            && self.mode == AddonMode::Enforce
        {
            // The head has gone on: the failure is logged here, since no
            // answer carries it.
            let name = self.name();
            let err = StackError::Service(e);
            self.st.fail(&name, err.clone());
            super::super::emit_stack_error(&self.st, &name, &err, AddonMode::Enforce);
        }
    }

    /// The service failed this stream.
    fn fail(&self, e: ServiceError, reset: Reset) {
        self.settle(End::Failed { e, reset });
    }

    /// roxy gives up on the stream.
    pub(super) fn reset(&self, why: &str) {
        self.settle(End::Abandoned(why));
    }

    /// An observe stream: roxy sent all it had.
    pub(super) fn finish(&self) -> Result<(), ServiceError> {
        self.settle(End::Quiet);
        lock(&self.state).observe_error.take().map_or(Ok(()), Err)
    }

    /// Sends a control message in stream order. False once the stream or
    /// the connection is gone.
    async fn send(&self, m: &Out) -> bool {
        let open = matches!(m, Out::Open { .. });
        self.queue(text(self.id, m), open).await
    }

    /// Queues a message of the stream for the socket. Nothing is queued
    /// once the stream has ended.
    async fn queue(&self, msg: Message, open: bool) -> bool {
        let q = Queued {
            msg,
            wire: self.wire.clone(),
            open,
        };
        tokio::select! {
            biased;
            () = self.ended.cancelled() => false,
            r = self.link.data.send(q) => r.is_ok(),
        }
    }

    /// Waits for credit to send up to `want` bytes of the `dir` body.
    async fn take_credit(&self, dir: Dir, want: usize) -> Option<usize> {
        loop {
            let more = self.more_credit.notified();
            tokio::pin!(more);
            more.as_mut().enable();
            {
                let mut s = lock(&self.state);
                let f = s.feed(dir);
                if f.credit > 0 {
                    let n = want.min(usize::try_from(f.credit).unwrap_or(usize::MAX));
                    f.credit -= n as u64;
                    return Some(n);
                }
            }
            tokio::select! {
                () = more => {}
                () = self.ended.cancelled() => return None,
            }
        }
    }

    /// Streams one message to the service: head, body frames (as credit
    /// allows), end. False if it did not get it all out.
    pub(super) async fn pump(&self, dir: Dir, head: Out, body: Body) -> bool {
        if !self.send(&head).await {
            return false;
        }
        // Nothing to read (and an empty observer copy may never be ended).
        if body.known_length() != Some(0) && !self.pump_body(dir, body).await {
            return false;
        }
        let end = match dir {
            Dir::Request => Out::RequestEnd,
            Dir::Response => Out::ResponseEnd,
        };
        self.send(&end).await
    }

    async fn pump_body(&self, dir: Dir, mut body: Body) -> bool {
        use http_body::Body as _;
        loop {
            let frame =
                std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await;
            let mut d = match frame {
                None => return true,
                // A body that fails is not forwarded as complete.
                Some(Err(e)) => {
                    self.settle(End::BodyFailed(dir, e));
                    return false;
                }
                Some(Ok(f)) => match f.into_data() {
                    Ok(d) => d,
                    Err(_) => continue,
                },
            };
            while !d.is_empty() {
                let Some(n) = self.take_credit(dir, d.len().min(MAX_BODY_FRAME)).await else {
                    return false;
                };
                let part = d.split_to(n);
                if !self.queue(binary(self.id, dir, &part), false).await {
                    return false;
                }
            }
        }
    }

    /// Credit back to the service for `n` bytes of the `dir` body consumed.
    fn grant(&self, dir: Dir, n: u64) {
        if n == 0 {
            return;
        }
        {
            let mut s = lock(&self.state);
            if s.ended {
                return;
            }
            let f = s.feed(dir);
            f.unacked = f.unacked.saturating_sub(n);
        }
        self.link
            .shared
            .send_ctl(self.id, &Out::Credit { dir, bytes: n });
    }

    /// Bytes of the `dir` body from the service. They count against that
    /// body's window in either mode. An observe stream's are discarded and
    /// credited back as they go, in steps: the service never waits on
    /// what it sends, and since it may only send what roxy has credited,
    /// the credit waiting for a stalled socket stays within the window.
    fn bytes(self: &Arc<Self>, dir: Dir, b: &[u8]) {
        if b.is_empty() {
            return;
        }
        let n = b.len() as u64;
        let mut s = lock(&self.state);
        let feed = s.feed(dir);
        let inbox = feed.inbox.clone();
        if inbox.is_none() && self.mode == AddonMode::Enforce {
            drop(s);
            return self.fail(
                ServiceError::Protocol(format!(
                    "bytes of a {} body that is not open",
                    dir.as_str()
                )),
                Reset::Send,
            );
        }
        if feed.unacked + n > WINDOW {
            drop(s);
            return self.fail(
                ServiceError::Protocol(format!(
                    "{} body bytes past the body's credit",
                    dir.as_str()
                )),
                Reset::Send,
            );
        }
        feed.unacked += n;
        let Some(inbox) = inbox else {
            feed.discarded += n;
            if feed.discarded < OBSERVE_GRANT {
                return;
            }
            let granted = std::mem::take(&mut feed.discarded);
            drop(s);
            return self.grant(dir, granted);
        };
        drop(s);
        let mut q = lock(&inbox.q);
        if q.dropped {
            drop(q);
            self.grant(dir, n);
        } else {
            q.buf.extend_from_slice(b);
            drop(q);
            inbox.ready.notify_one();
        }
    }

    /// A control message from the service.
    fn control(self: &Arc<Self>, m: In) {
        match m {
            In::Credit { dir, bytes } => {
                {
                    let mut s = lock(&self.state);
                    let f = s.feed(dir);
                    f.credit = f.credit.saturating_add(bytes);
                }
                self.more_credit.notify_waiters();
                return;
            }
            In::Reset { message } => {
                let why = message.map_or_else(
                    || "the service reset the stream".to_owned(),
                    |m| format!("the service reset the stream: {m}"),
                );
                return self.fail(ServiceError::Closed(why), Reset::Skip);
            }
            In::Request { .. }
            | In::RequestEnd
            | In::Response { .. }
            | In::ResponseEnd
            | In::Deny { .. } => {
                // An observer's answers are ignored.
                if self.mode == AddonMode::Observe {
                    return;
                }
            }
        }
        let mut s = lock(&self.state);
        let result = self.answer(&mut s, m);
        let done = !s.waiting();
        drop(s);
        match result {
            Err(e) => self.fail(e, Reset::Send),
            Ok(()) if done => self.settle(End::Quiet),
            Ok(()) => {}
        }
    }

    fn answer(self: &Arc<Self>, s: &mut StreamState, m: In) -> Result<(), ServiceError> {
        let unexpected = |what: &str| ServiceError::Protocol(format!("unexpected {what}"));
        let limits = &self.st.snap.limits;
        match m {
            In::RequestEnd | In::ResponseEnd => {
                let (dir, what) = if matches!(m, In::RequestEnd) {
                    (Dir::Request, "request_end")
                } else {
                    (Dir::Response, "response_end")
                };
                match s.feed(dir).inbox.take() {
                    Some(inbox) => {
                        lock(&inbox.q).end = true;
                        inbox.ready.notify_one();
                        Ok(())
                    }
                    None => Err(unexpected(what)),
                }
            }
            In::Request {
                method,
                url,
                headers,
            } => {
                if s.first.is_none() {
                    return Err(unexpected("request"));
                }
                let method = http::Method::from_bytes(method.as_bytes())
                    .map_err(|_| ServiceError::Protocol(format!("invalid method {method:?}")))?;
                let uri: http::Uri = url
                    .parse()
                    .map_err(|_| ServiceError::Protocol(format!("invalid url {url:?}")))?;
                let headers = super::header_map(&headers)?;
                let (body_tx, body) = Body::channel(
                    limits.max_request_body_bytes,
                    super::declared_length(&headers)?,
                );
                let mut r = http::Request::new(body);
                *r.method_mut() = method;
                *r.uri_mut() = uri;
                *r.headers_mut() = headers;
                s.req.inbox = Some(self.feed(body_tx, Dir::Request));
                if let Some(tx) = s.first.take() {
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
                let headers = super::header_map(&headers)?;
                let (body_tx, body) = Body::channel(
                    limits.max_response_body_bytes,
                    super::declared_length(&headers)?,
                );
                let mut r = http::Response::new(body);
                *r.status_mut() = status;
                *r.headers_mut() = headers;
                Self::give(s, r, "response")?;
                s.res.inbox = Some(self.feed(body_tx, Dir::Response));
                Ok(())
            }
            In::Deny { status, message } => {
                let r = super::deny_response(status, message)?;
                // Tagged before the answer goes, so the flow's record has it.
                self.st.add_tag(format!("{}:deny", self.name()));
                Self::give(s, r, "deny")
            }
            // Handled by `control`.
            In::Credit { .. } | In::Reset { .. } => Ok(()),
        }
    }

    /// Hands a response to whoever is waiting: the first answer (the
    /// service answers instead of forwarding), or the second.
    fn give(s: &mut StreamState, r: LayerResponse, what: &str) -> Result<(), ServiceError> {
        if let Some(tx) = s.first.take() {
            // Answering instead of forwarding: no second answer follows.
            s.second = None;
            let _ = tx.send(Ok(First::Answer(r)));
            Ok(())
        } else if let Some(tx) = s.second.take() {
            let _ = tx.send(Ok(r));
            Ok(())
        } else {
            Err(ServiceError::Protocol(format!("unexpected {what}")))
        }
    }

    /// Starts feeding the `dir` body from the stream.
    fn feed(self: &Arc<Self>, tx: BodySender, dir: Dir) -> Arc<Inbox> {
        let inbox = Arc::new(Inbox::default());
        tokio::spawn(feeder(self.clone(), inbox.clone(), tx, dir));
        inbox
    }
}

/// Moves one body's bytes from its inbox to its consumer, crediting the
/// service as they go.
async fn feeder(stream: Arc<Stream>, inbox: Arc<Inbox>, mut tx: BodySender, dir: Dir) {
    loop {
        let (chunk, end, abort) = {
            let mut q = lock(&inbox.q);
            (q.buf.split().freeze(), q.end, q.abort.take())
        };
        if let Some(why) = abort {
            tx.abort(BodyError::Upstream(why));
            return;
        }
        if !chunk.is_empty() {
            let n = chunk.len() as u64;
            let sent = tokio::select! {
                r = tx.send_data(chunk) => r,
                () = inbox.abort.cancelled() => continue,
            };
            match sent {
                Ok(()) => stream.grant(dir, n),
                Err(BodyError::Closed | BodyError::Stopped) => {
                    return consumer_gone(&stream, &inbox, dir, n);
                }
                // More than declared, or than the limit.
                Err(e) => return stream.fail(ServiceError::Protocol(e.to_string()), Reset::Send),
            }
            continue;
        }
        if end {
            match tx.finish().await {
                Ok(()) | Err(BodyError::Closed | BodyError::Stopped) => {}
                // Shorter than declared.
                Err(e) => stream.fail(ServiceError::Protocol(e.to_string()), Reset::Send),
            }
            return;
        }
        // A consumer that leaves is noticed here too, not only on the next
        // byte: a quiet service may send none for a long time.
        tokio::select! {
            () = inbox.ready.notified() => {}
            () = inbox.abort.cancelled() => {}
            () = tx.closed() => return consumer_gone(&stream, &inbox, dir, 0),
        }
    }
}

/// The consumer of the `dir` body went away, `n` bytes it was sent unread.
fn consumer_gone(stream: &Stream, inbox: &Inbox, dir: Dir, n: u64) {
    if dir == Dir::Request {
        // A deny below, say: the rest is read and dropped, and the service
        // still owes the response.
        let rest = {
            let mut q = lock(&inbox.q);
            q.dropped = true;
            q.buf.split().len() as u64
        };
        stream.grant(dir, n + rest);
    } else {
        stream.reset("the client went away");
    }
}

/// Ends a stream whose `open` was given up (a missed deadline) before its
/// message went, so it holds no place on the connection.
struct Opening<'a>(Option<&'a Arc<Stream>>);

impl Opening<'_> {
    fn sent(mut self) {
        self.0 = None;
    }
}

impl Drop for Opening<'_> {
    fn drop(&mut self) {
        if let Some(s) = self.0.take() {
            s.settle(End::Quiet);
        }
    }
}

/// A stream for service layer `index` of the flow `st`: a place on one of
/// its endpoint's connections (connecting one if needed), and the `open`
/// message sent. Cancel-safe: given up part way, it holds nothing.
pub(super) async fn open(
    st: &Arc<StackFlow>,
    index: usize,
    svc: &ServiceSpec,
    mode: AddonMode,
) -> Result<(Arc<Stream>, Option<Answers>), ServiceError> {
    let addon = &st.snap.addons[index];
    let spec = addon
        .endpoints
        .get(&svc.endpoint)
        .ok_or_else(|| ServiceError::Connect(format!("no endpoint {:?}", svc.endpoint)))?;
    let key = PoolKey {
        url: spec.url.to_string(),
        headers: spec
            .headers
            .iter()
            .map(|(n, v)| (n.as_str().to_owned(), v.clone()))
            .collect(),
        private: spec.private,
        max_connections: svc.max_connections,
        max_streams: svc.max_streams,
    };
    let pools = &st.snap.services;
    let pool = lock(&pools.by_key)
        .entry(key)
        .or_insert_with(|| {
            Arc::new(Pool {
                entries: Mutex::new(Vec::new()),
                freed: Notify::new(),
                max_connections: svc.max_connections,
                max_streams: svc.max_streams,
                retired: AtomicBool::new(pools.retired.load(Ordering::SeqCst)),
            })
        })
        .clone();
    let slot = pool.reserve().await;
    let link = slot
        .link
        .get_or_try_init(|| dial(st, &addon.name, &svc.endpoint, spec))
        .await?
        .clone();

    let (first_tx, first_rx) = oneshot::channel();
    let (second_tx, second_rx) = oneshot::channel();
    let (answers, state) = if mode == AddonMode::Observe {
        (None, StreamState::default())
    } else {
        (
            Some(Answers {
                first: first_rx,
                second: second_rx,
            }),
            StreamState {
                first: Some(first_tx),
                second: Some(second_tx),
                ..StreamState::default()
            },
        )
    };
    let stream = {
        let mut s = lock(&link.shared.streams);
        if s.failed || s.next_id == u32::MAX {
            return Err(ServiceError::Closed("the connection closed".into()));
        }
        let id = s.next_id;
        s.next_id += 1;
        let stream = Arc::new(Stream {
            id,
            link: link.clone(),
            st: st.clone(),
            index,
            mode,
            state: Mutex::new(StreamState {
                slot: Some(slot),
                ..state
            }),
            more_credit: Notify::new(),
            ended: CancellationToken::new(),
            wire: Arc::default(),
        });
        s.open.insert(id, stream.clone());
        stream
    };
    let opening = Opening(Some(&stream));
    if !stream.send(&open_message(st, &addon.name, mode)).await {
        drop(opening);
        return Err(ServiceError::Closed("the connection closed".into()));
    }
    opening.sent();
    Ok((stream, answers))
}

/// The `open` message: who the client is and where the exchange is, so
/// the service can key its state on (flow, layer).
fn open_message(st: &StackFlow, layer: &str, mode: AddonMode) -> Out {
    Out::Open {
        flow: st.flow.to_string(),
        conn: st.client.id.to_string(),
        layer: layer.to_owned(),
        mode: mode.as_str(),
        client_ip: st.client.peer.ip().to_string(),
        client_user: st.client.user.clone(),
        listener: st.client.listener.name.clone(),
        sni: st.tls.as_ref().and_then(|t| t.sni.clone()),
        tags: st.tags(),
    }
}

/// The handshake request for `spec`: the endpoint's URL as a WebSocket
/// one, its headers with secrets expanded, and the subprotocol.
fn handshake_request(
    st: &StackFlow,
    spec: &EndpointSpec,
) -> Result<(Scheme, roxy_http::Authority, http::Request<()>), ServiceError> {
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
    Ok((scheme, authority, request))
}

/// Connects and completes the handshake through the connector (which runs
/// the address floor on the address it dials), then starts the
/// connection's reader and writer.
async fn dial(
    st: &StackFlow,
    layer: &str,
    endpoint: &str,
    spec: &EndpointSpec,
) -> Result<Arc<Link>, ServiceError> {
    let started = Instant::now();
    let result = async {
        let (scheme, authority, request) = handshake_request(st, spec)?;
        let io = st
            .snap
            .upstream
            .connect_h1(scheme, &authority, spec.private)
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
        layer: layer.to_owned(),
        endpoint: endpoint.to_owned(),
        method: "GET".to_owned(),
        path: spec.url.path().to_owned(),
        status: result.is_ok().then_some(101),
        attempts: 1,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        error: result.as_ref().err().map(ToString::to_string),
    });
    let (sink, stream) = result?.split();
    let (data_tx, data_rx) = mpsc::channel(WRITE_QUEUE);
    let (ctl_tx, ctl_rx) = mpsc::unbounded_channel();
    let shared = Arc::new(LinkShared {
        streams: Mutex::new(LinkState {
            open: HashMap::new(),
            next_id: 1,
            failed: false,
        }),
        ctl: ctl_tx,
    });
    tokio::spawn(write(sink, data_rx, ctl_rx));
    tokio::spawn(read(shared.clone(), stream));
    Ok(Arc::new(Link {
        shared,
        data: data_tx,
    }))
}

/// Owns the socket's write half. Control messages go first, but a reset
/// never overtakes its stream's `open` ([`Wire`]). The socket closes once
/// every data sender is gone, or on a close.
async fn write(
    mut sink: SplitSink<Ws, Message>,
    mut data: mpsc::Receiver<Queued>,
    mut ctl: mpsc::UnboundedReceiver<Message>,
) {
    loop {
        let m = tokio::select! {
            biased;
            Some(m) = ctl.recv() => m,
            m = data.recv() => match m {
                Some(q) if q.wire.write(q.open) => q.msg,
                Some(_) => continue,
                None => break,
            },
        };
        let close = matches!(m, Message::Close(_));
        if sink.send(m).await.is_err() || close {
            return;
        }
    }
    let _ = sink.close().await;
}

/// Reads the connection and hands each message to its stream. Only broken
/// framing (or the socket going) ends it, failing every stream on it.
async fn read(shared: Arc<LinkShared>, mut ws: SplitStream<Ws>) {
    let framing = |what: &str| ServiceError::Protocol(what.to_owned());
    let err = loop {
        let routed = match ws.next().await {
            None | Some(Ok(Message::Close(_))) => {
                break ServiceError::Closed("the service closed the connection".into());
            }
            Some(Err(e)) => break ServiceError::Closed(e.to_string()),
            Some(Ok(Message::Binary(b))) => {
                if b.len() < 5 {
                    break framing("a binary frame shorter than its stream id and direction");
                }
                let id = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
                let Some(dir) = dir_of(b[4]) else {
                    break framing("a binary frame with an unknown direction");
                };
                route(&shared, id).map(|s| match s {
                    Some(s) => s.bytes(dir, &b[5..]),
                    // Ignored, and credited back, so a service still
                    // sending when the stream ended is never stalled.
                    None if b.len() > 5 => shared.send_ctl(
                        id,
                        &Out::Credit {
                            dir,
                            bytes: (b.len() - 5) as u64,
                        },
                    ),
                    None => {}
                })
            }
            Some(Ok(Message::Text(t))) => {
                let Ok(serde_json::Value::Object(v)) = serde_json::from_str(t.as_str()) else {
                    break framing("a text frame that is not a JSON object");
                };
                let Some(id) = v
                    .get("stream")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|n| u32::try_from(n).ok())
                else {
                    break framing("a message without a valid `stream`");
                };
                route(&shared, id).map(|s| {
                    if let Some(s) = s {
                        match serde_json::from_value::<In>(serde_json::Value::Object(v)) {
                            Ok(m) => s.control(m),
                            Err(e) => {
                                s.fail(
                                    ServiceError::Protocol(format!("bad message: {e}")),
                                    Reset::Send,
                                );
                            }
                        }
                    }
                })
            }
            // Ping and pong are answered by the library.
            Some(Ok(_)) => Ok(()),
        };
        if let Err(e) = routed {
            break e;
        }
    };
    shared.fail(&err);
}

/// The open stream `id`; `None` for one that has ended (a message that
/// crossed its end); an error for one roxy never opened.
fn route(shared: &LinkShared, id: u32) -> Result<Option<Arc<Stream>>, ServiceError> {
    let s = lock(&shared.streams);
    if let Some(stream) = s.open.get(&id) {
        return Ok(Some(stream.clone()));
    }
    if id == 0 || id >= s.next_id {
        return Err(ServiceError::Protocol(format!(
            "a message for stream {id}, which roxy never opened"
        )));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::addons::AddonImpl;
    use crate::addons::service::testing;
    use crate::testkit::ALLOW_UP;

    /// A link whose connection has failed, with nothing behind it.
    fn failed_link() -> Arc<Link> {
        let (ctl, _) = mpsc::unbounded_channel();
        let (data, _) = mpsc::channel(1);
        Arc::new(Link {
            shared: Arc::new(LinkShared {
                streams: Mutex::new(LinkState {
                    open: HashMap::new(),
                    next_id: 1,
                    failed: true,
                }),
                ctl,
            }),
            data,
        })
    }

    /// An enforce stream on a link with nothing behind it, with the
    /// answers an exchange would wait on. What the stream sends goes
    /// nowhere.
    async fn lone_stream() -> (Arc<Stream>, Answers, crate::testkit::Kit) {
        let kit = testing::kit(
            ALLOW_UP,
            vec![testing::addon("s", "pass", AddonMode::Enforce, |_| {})],
        )
        .await;
        let (st, _cx) = crate::addons::test_flow(&kit);
        let (first_tx, first) = oneshot::channel();
        let (second_tx, second) = oneshot::channel();
        let link = failed_link();
        let stream = Arc::new(Stream {
            id: 1,
            link: link.clone(),
            st,
            index: 0,
            mode: AddonMode::Enforce,
            state: Mutex::new(StreamState {
                first: Some(first_tx),
                second: Some(second_tx),
                ..StreamState::default()
            }),
            more_credit: Notify::new(),
            ended: CancellationToken::new(),
            wire: Arc::default(),
        });
        lock(&link.shared.streams).open.insert(1, stream.clone());
        (stream, Answers { first, second }, kit)
    }

    fn request_head() -> In {
        In::Request {
            method: "POST".to_owned(),
            url: "http://up.test/x".to_owned(),
            headers: Vec::new(),
        }
    }

    /// The service's response head is taken while the request body it is
    /// forwarding is still streaming; each body's bytes reach their own
    /// consumer, and the stream ends once both have.
    #[tokio::test]
    async fn a_response_head_arrives_while_the_request_body_streams() {
        let (stream, answers, _kit) = lone_stream().await;
        stream.control(request_head());
        let First::Forward(req) = answers.first.await.unwrap().unwrap() else {
            panic!("the request is forwarded");
        };
        stream.bytes(Dir::Request, b"up");
        stream.control(In::Response {
            status: 200,
            headers: Vec::new(),
        });
        let res = tokio::time::timeout(Duration::from_millis(100), answers.second)
            .await
            .expect("the response head is not held behind the request body")
            .unwrap()
            .unwrap();
        assert_eq!(res.status(), 200);
        stream.bytes(Dir::Response, b"down");
        stream.control(In::ResponseEnd);
        assert_eq!(
            res.into_body().collect_up_to(u64::MAX).await.unwrap(),
            &b"down"[..]
        );
        assert!(!lock(&stream.state).ended, "the request body is still owed");
        stream.bytes(Dir::Request, b"load");
        stream.control(In::RequestEnd);
        assert_eq!(
            req.into_body().collect_up_to(u64::MAX).await.unwrap(),
            &b"upload"[..]
        );
        assert!(lock(&stream.state).ended);
    }

    /// Bytes are owed to a head in their own direction: response bytes
    /// while only the request body is being fed fail the stream.
    #[tokio::test]
    async fn bytes_of_a_body_without_a_head_fail_the_stream() {
        let (stream, answers, _kit) = lone_stream().await;
        stream.control(request_head());
        let First::Forward(req) = answers.first.await.unwrap().unwrap() else {
            panic!("the request is forwarded");
        };
        stream.bytes(Dir::Response, b"early");
        assert!(lock(&stream.state).ended);
        assert!(req.into_body().collect_up_to(u64::MAX).await.is_err());
        let e = answers.second.await.unwrap().unwrap_err();
        assert!(
            e.to_string()
                .contains("bytes of a response body that is not open"),
            "{e}"
        );
    }

    /// A body that fails on its way to the service ends the stream without
    /// blaming the service: the pending answer says which body failed, and
    /// the exchange takes a request body's failure as the client's.
    #[tokio::test]
    async fn a_body_failing_on_its_way_to_the_service_is_not_its_failure() {
        let (stream, answers, _kit) = lone_stream().await;
        let (tx, body) = Body::channel(u64::MAX, None);
        tx.abort(BodyError::Incomplete);
        assert!(!stream.pump_body(Dir::Request, body).await);
        let lost = answers.first.await.unwrap().err().expect("no answer");
        assert!(
            matches!(lost, Unanswered::Body(Dir::Request, BodyError::Incomplete)),
            "{lost:?}"
        );
        assert!(matches!(
            super::super::unanswered(&stream.st, lost),
            super::super::Fail::Below(_)
        ));
        assert!(stream.st.failure().is_none(), "the service is not blamed");
        assert!(stream.st.take_client_fault().is_some());
    }

    /// A connection that failed keeps its place in the pool while streams
    /// still hold it; the pool opens another only once they are gone.
    #[tokio::test]
    async fn a_failed_connection_counts_until_its_streams_end() {
        let pool = Arc::new(Pool {
            entries: Mutex::new(Vec::new()),
            freed: Notify::new(),
            max_connections: 1,
            max_streams: 2,
            retired: AtomicBool::new(false),
        });
        let first = pool.reserve().await;
        let second = pool.reserve().await;
        assert!(Arc::ptr_eq(&first.link, &second.link));
        first.link.set(failed_link()).ok().unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), pool.reserve())
                .await
                .is_err(),
            "the pool is full: one connection, held by two streams"
        );
        drop(first);
        drop(second);
        assert!(lock(&pool.entries).is_empty());
        let fresh = tokio::time::timeout(Duration::from_millis(100), pool.reserve())
            .await
            .expect("room again");
        assert!(fresh.link.get().is_none(), "a new connection");
    }

    /// Fills the data queue of `stream`'s connection with body frames of
    /// its own, until the writer is stalled on a socket nobody reads and
    /// the queue stays full.
    async fn fill(stream: &Stream) {
        let frame = binary(stream.id, Dir::Request, &vec![0u8; MAX_BODY_FRAME]);
        let queued = || Queued {
            msg: frame.clone(),
            wire: stream.wire.clone(),
            open: false,
        };
        loop {
            while stream.link.data.try_send(queued()).is_ok() {}
            tokio::time::sleep(Duration::from_millis(50)).await;
            if stream.link.data.try_send(queued()).is_err() {
                break;
            }
        }
    }

    /// A stream reset while its `open` is still queued, behind a full
    /// data queue: the service sees its `open` before its `reset`, or
    /// neither.
    #[tokio::test]
    async fn a_reset_never_overtakes_its_open() {
        let kit = testing::kit(
            ALLOW_UP,
            vec![testing::addon("s", "pause", AddonMode::Enforce, |s| {
                s.max_connections = 1;
            })],
        )
        .await;
        let (st, _cx) = crate::addons::test_flow(&kit);
        let snap = st.snap.clone();
        let AddonImpl::Service(svc) = &snap.addons[0].kind else {
            panic!("a service layer");
        };

        let (first, _) = open(&st, 0, svc, AddonMode::Enforce).await.unwrap();
        // The service reads nothing until its pause is over.
        fill(&first).await;
        // Queued at the back once the writer moves again.
        let (second, _) = open(&st, 0, svc, AddonMode::Enforce).await.unwrap();
        second.reset("the exchange ended");
        // Everything before this is on the wire once its `open` is.
        let (third, _) = open(&st, 0, svc, AddonMode::Enforce).await.unwrap();

        let log = kit.upstream.service();
        let opened = |id: u32| log.opens().iter().any(|o| o["stream"] == id);
        tokio::time::timeout(Duration::from_secs(10), async {
            while !opened(third.id) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the third stream opens");
        assert_eq!(
            log.unknown_resets(),
            Vec::<u32>::new(),
            "a reset before its open"
        );
        let reset = log.resets().iter().any(|(id, _)| *id == second.id);
        assert_eq!(opened(second.id), reset, "open and reset, or neither");
    }

    /// An `open` given up while its message waits for the socket (a
    /// missed `first_byte_timeout`) leaves no stream behind: the next
    /// exchange gets its place.
    #[tokio::test]
    async fn an_open_given_up_mid_send_releases_its_place() {
        let kit = testing::kit(
            ALLOW_UP,
            vec![testing::addon("s", "stall", AddonMode::Enforce, |s| {
                s.max_connections = 1;
                s.max_streams = 2;
            })],
        )
        .await;
        let (st, _cx) = crate::addons::test_flow(&kit);
        let snap = st.snap.clone();
        let AddonImpl::Service(svc) = &snap.addons[0].kind else {
            panic!("a service layer");
        };

        let (first, _) = open(&st, 0, svc, AddonMode::Enforce).await.unwrap();
        // The service never reads.
        fill(&first).await;
        let given_up = tokio::time::timeout(
            Duration::from_millis(100),
            open(&st, 0, svc, AddonMode::Enforce),
        )
        .await;
        assert!(given_up.is_err(), "the open message cannot go");

        assert_eq!(lock(&first.link.shared.streams).open.len(), 1);
        let pool = lock(&snap.services.by_key).values().next().unwrap().clone();
        assert_eq!(lock(&pool.entries)[0].reserved, 1);
        let place = tokio::time::timeout(Duration::from_millis(100), pool.reserve()).await;
        assert!(place.is_ok(), "the given-up stream's place is free");
    }
}
