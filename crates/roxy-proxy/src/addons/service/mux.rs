//! Streams over pooled connections (`roxy.layer.v2`).
//!
//! Each endpoint has a small pool of WebSocket connections; each exchange
//! is a stream on one of them. Text frames are JSON with a `stream` field;
//! binary frames are a 4-byte big-endian stream id, then body bytes. Body
//! bytes are flow-controlled per stream and direction by credit, so one
//! slow body never holds up the connection: the reader hands each stream's
//! bytes to that stream's own feeder and never waits on a consumer.
//!
//! Broken framing fails the whole connection (every stream on it fails
//! closed); anything else fails only its stream, which is reset.
//!
//! The pools hang off the policy snapshot: a reload dials new connections
//! under the new policy and secrets, and retires the old snapshot's pools,
//! whose connections close as soon as no exchange is using them.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
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

use super::super::{StackError, StackFlow, endpoint};
use super::{First, In, Out, ServiceError, ServiceSpec};
use crate::addr::PrivateAddrs;
use crate::flowlog::FlowEvent;
use crate::upstream::MaybeTls;

/// The WebSocket subprotocol a service must accept.
pub const SUBPROTOCOL: &str = "roxy.layer.v2";

/// Each stream's starting credit, each way, in body bytes.
pub(super) const WINDOW: u64 = 256 * 1024;

/// Largest control message or body frame accepted from a service.
const MAX_FRAME: usize = 16 * 1024 * 1024;

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
            // Never connected, and nobody is waiting on it any more; or
            // idle in a retired pool.
            if e.reserved == 0
                && (e.link.get().is_none() || self.pool.retired.load(Ordering::SeqCst))
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
                entries.retain(|e| !e.closed());
                let pick =
                    if let Some(e) = entries.iter_mut().find(|e| e.reserved < self.max_streams) {
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
    data: mpsc::Sender<Message>,
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
            s.fail(e.clone(), false);
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

fn binary(stream: u32, data: &[u8]) -> Message {
    let mut b = BytesMut::with_capacity(4 + data.len());
    b.extend_from_slice(&stream.to_be_bytes());
    b.extend_from_slice(data);
    Message::binary(b.freeze())
}

/// The service's answers to an enforce stream, in protocol order.
pub(super) struct Answers {
    pub first: oneshot::Receiver<Result<First, ServiceError>>,
    pub second: oneshot::Receiver<Result<LayerResponse, ServiceError>>,
}

/// One exchange on a connection.
pub(super) struct Stream {
    id: u32,
    link: Arc<Link>,
    st: Arc<StackFlow>,
    index: usize,
    observe: bool,
    state: Mutex<StreamState>,
    /// What roxy may still send: granted by the service.
    credit: Mutex<u64>,
    more_credit: Notify,
    ended: CancellationToken,
    ending: AtomicBool,
    /// Why an observe stream failed, for its driver to log.
    observe_error: Mutex<Option<ServiceError>>,
    slot: Mutex<Option<Reservation>>,
}

#[derive(Default)]
struct StreamState {
    first: Option<oneshot::Sender<Result<First, ServiceError>>>,
    second: Option<oneshot::Sender<Result<LayerResponse, ServiceError>>>,
    feeding: Option<Feeding>,
    /// Body bytes received and not yet credited back.
    unacked: u64,
}

impl StreamState {
    fn waiting(&self) -> bool {
        self.feeding.is_some() || self.first.is_some() || self.second.is_some()
    }
}

/// A body being fed from the stream.
struct Feeding {
    inbox: Arc<Inbox>,
    /// It is the request's (else the response's).
    request: bool,
}

/// Bytes for one body, between the reader and that body's feeder. At most
/// the stream's credit is ever here.
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
    fn abort(&self, e: &ServiceError) {
        lock(&self.q).abort = Some(e.to_string());
        self.abort.cancel();
    }
}

impl Stream {
    fn name(&self) -> String {
        self.st.snap.addons[self.index].name.clone()
    }

    /// Ends the stream, once: no more is sent on it, its connection place
    /// is released, and the reader forgets it. True if this call ended it.
    fn end(&self) -> bool {
        if self.ending.swap(true, Ordering::SeqCst) {
            return false;
        }
        self.ended.cancel();
        lock(&self.link.shared.streams).open.remove(&self.id);
        drop(lock(&self.slot).take());
        true
    }

    /// The service failed this stream: whoever is waiting learns of it (a
    /// pending answer, or the body being fed, which is cut; the failure is
    /// logged here when the head has gone on).
    fn fail(&self, e: ServiceError, reset: bool) {
        if !self.end() {
            return;
        }
        if reset {
            self.link.shared.send_ctl(
                self.id,
                &Out::Reset {
                    message: e.to_string(),
                },
            );
        }
        let (feeding, first, second) = {
            let mut s = lock(&self.state);
            (s.feeding.take(), s.first.take(), s.second.take())
        };
        if let Some(f) = feeding {
            f.inbox.abort(&e);
        }
        if self.observe {
            *lock(&self.observe_error) = Some(e);
        } else if let Some(tx) = first {
            let _ = tx.send(Err(e));
        } else if let Some(tx) = second
            && !tx.is_closed()
        {
            let _ = tx.send(Err(e));
        } else {
            let name = self.name();
            let err = StackError::Service(e);
            self.st.fail(&name, err.clone());
            super::super::emit_stack_error(&self.st, &name, &err, false);
        }
    }

    /// roxy gives up on the stream (the client went away, a missed
    /// `first_byte_timeout`, an upgrade): the service is told, and anyone still waiting on an
    /// answer gets `why`, without it being logged as the service's fault.
    pub(super) fn reset(&self, why: &str) {
        if !self.end() {
            return;
        }
        self.link.shared.send_ctl(
            self.id,
            &Out::Reset {
                message: why.to_owned(),
            },
        );
        let (feeding, first, second) = {
            let mut s = lock(&self.state);
            (s.feeding.take(), s.first.take(), s.second.take())
        };
        let e = ServiceError::Closed(why.to_owned());
        if let Some(f) = feeding {
            f.inbox.abort(&e);
        }
        if let Some(tx) = first {
            let _ = tx.send(Err(e.clone()));
        }
        if let Some(tx) = second {
            let _ = tx.send(Err(e));
        }
    }

    /// An observe stream: roxy sent all it had.
    pub(super) fn finish(&self) -> Result<(), ServiceError> {
        self.end();
        lock(&self.observe_error).take().map_or(Ok(()), Err)
    }

    /// Sends a control message in stream order. False once the stream or
    /// the connection is gone.
    async fn send(&self, m: &Out) -> bool {
        let msg = text(self.id, m);
        tokio::select! {
            r = self.link.data.send(msg) => r.is_ok(),
            () = self.ended.cancelled() => false,
        }
    }

    /// Waits for credit to send up to `want` body bytes.
    async fn take_credit(&self, want: usize) -> Option<usize> {
        loop {
            let more = self.more_credit.notified();
            tokio::pin!(more);
            more.as_mut().enable();
            {
                let mut c = lock(&self.credit);
                if *c > 0 {
                    let n = want.min(usize::try_from(*c).unwrap_or(usize::MAX));
                    *c -= n as u64;
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
    pub(super) async fn pump(&self, head: Out, body: Body, end: Out) -> bool {
        if !self.send(&head).await {
            return false;
        }
        // Nothing to read (and an empty observer copy may never be ended).
        if body.known_length() != Some(0) && !self.pump_body(body).await {
            return false;
        }
        self.send(&end).await
    }

    async fn pump_body(&self, mut body: Body) -> bool {
        use http_body::Body as _;
        loop {
            let frame =
                std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await;
            let mut d = match frame {
                None => return true,
                // A body that fails is not forwarded as complete.
                Some(Err(_)) => {
                    self.reset("the body failed");
                    return false;
                }
                Some(Ok(f)) => match f.into_data() {
                    Ok(d) => d,
                    Err(_) => continue,
                },
            };
            while !d.is_empty() {
                let Some(n) = self.take_credit(d.len().min(MAX_BODY_FRAME)).await else {
                    return false;
                };
                let part = d.split_to(n);
                let sent = tokio::select! {
                    r = self.link.data.send(binary(self.id, &part)) => r.is_ok(),
                    () = self.ended.cancelled() => false,
                };
                if !sent {
                    return false;
                }
            }
        }
    }

    /// Credit back to the service for `n` bytes consumed.
    fn grant(&self, n: u64) {
        if n == 0 || self.ended.is_cancelled() {
            return;
        }
        {
            let mut s = lock(&self.state);
            s.unacked = s.unacked.saturating_sub(n);
        }
        self.link
            .shared
            .send_ctl(self.id, &Out::Credit { bytes: n });
    }

    /// Body bytes from the service.
    fn bytes(self: &Arc<Self>, b: &[u8]) {
        if b.is_empty() {
            return;
        }
        let n = b.len() as u64;
        if self.observe {
            // Ignored, and credited straight back so the service never
            // stalls on what it sends (and stops reading the copies).
            self.link
                .shared
                .send_ctl(self.id, &Out::Credit { bytes: n });
            return;
        }
        let mut s = lock(&self.state);
        let Some(inbox) = s.feeding.as_ref().map(|f| f.inbox.clone()) else {
            drop(s);
            return self.fail(
                ServiceError::Protocol("body bytes before a head".into()),
                true,
            );
        };
        if s.unacked + n > WINDOW {
            drop(s);
            return self.fail(
                ServiceError::Protocol("body bytes past the stream's credit".into()),
                true,
            );
        }
        s.unacked += n;
        drop(s);
        let mut q = lock(&inbox.q);
        if q.dropped {
            drop(q);
            self.grant(n);
        } else {
            q.buf.extend_from_slice(b);
            drop(q);
            inbox.ready.notify_one();
        }
    }

    /// A control message from the service.
    fn control(self: &Arc<Self>, m: In) {
        match m {
            In::Credit { bytes } => {
                {
                    let mut c = lock(&self.credit);
                    *c = c.saturating_add(bytes);
                }
                self.more_credit.notify_waiters();
                return;
            }
            In::Reset { message } => {
                let why = message.map_or_else(
                    || "the service reset the stream".to_owned(),
                    |m| format!("the service reset the stream: {m}"),
                );
                return self.fail(ServiceError::Closed(why), false);
            }
            // An observer's answers are ignored.
            _ if self.observe => return,
            _ => {}
        }
        let mut s = lock(&self.state);
        let result = self.answer(&mut s, m);
        let done = !s.waiting();
        drop(s);
        match result {
            Err(e) => self.fail(e, true),
            Ok(()) if done => {
                self.end();
            }
            Ok(()) => {}
        }
    }

    fn answer(self: &Arc<Self>, s: &mut StreamState, m: In) -> Result<(), ServiceError> {
        let unexpected = |what: &str| ServiceError::Protocol(format!("unexpected {what}"));
        let limits = &self.st.snap.limits;
        match m {
            In::RequestEnd | In::ResponseEnd => {
                let request = matches!(m, In::RequestEnd);
                match s.feeding.take() {
                    Some(f) if f.request == request => {
                        lock(&f.inbox.q).end = true;
                        f.inbox.ready.notify_one();
                        Ok(())
                    }
                    _ if request => Err(unexpected("request_end")),
                    _ => Err(unexpected("response_end")),
                }
            }
            _ if s.feeding.is_some() => Err(ServiceError::Protocol(
                "a new head before the previous body ended".into(),
            )),
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
                s.feeding = Some(self.feed(body_tx, true));
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
                s.feeding = Some(self.feed(body_tx, false));
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

    /// Starts feeding a body from the stream.
    fn feed(self: &Arc<Self>, tx: BodySender, request: bool) -> Feeding {
        let inbox = Arc::new(Inbox::default());
        tokio::spawn(feeder(self.clone(), inbox.clone(), tx, request));
        Feeding { inbox, request }
    }
}

/// Moves one body's bytes from its inbox to its consumer, crediting the
/// service as they go.
async fn feeder(stream: Arc<Stream>, inbox: Arc<Inbox>, mut tx: BodySender, request: bool) {
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
                Ok(()) => stream.grant(n),
                Err(BodyError::Closed | BodyError::Stopped) => {
                    if request {
                        // A deny below, say: the rest is read and dropped,
                        // and the service still owes the response.
                        let rest = {
                            let mut q = lock(&inbox.q);
                            q.dropped = true;
                            q.buf.split().len() as u64
                        };
                        stream.grant(n + rest);
                    } else {
                        stream.reset("the client went away");
                    }
                    return;
                }
                // More than declared, or than the limit.
                Err(e) => return stream.fail(ServiceError::Protocol(e.to_string()), true),
            }
            continue;
        }
        if end {
            match tx.finish().await {
                Ok(()) | Err(BodyError::Closed | BodyError::Stopped) => {}
                // Shorter than declared.
                Err(e) => stream.fail(ServiceError::Protocol(e.to_string()), true),
            }
            return;
        }
        tokio::select! {
            () = inbox.ready.notified() => {}
            () = inbox.abort.cancelled() => {}
        }
    }
}

/// A stream for service layer `index` of the flow `st`: a place on one of
/// its endpoint's connections (connecting one if needed), and the `open`
/// message sent.
pub(super) async fn open(
    st: &Arc<StackFlow>,
    index: usize,
    svc: &ServiceSpec,
    observe: bool,
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
        .get_or_try_init(|| dial(st, index, svc))
        .await?
        .clone();

    let (first_tx, first_rx) = oneshot::channel();
    let (second_tx, second_rx) = oneshot::channel();
    let (answers, state) = if observe {
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
            observe,
            state: Mutex::new(state),
            credit: Mutex::new(WINDOW),
            more_credit: Notify::new(),
            ended: CancellationToken::new(),
            ending: AtomicBool::new(false),
            observe_error: Mutex::new(None),
            slot: Mutex::new(Some(slot)),
        });
        s.open.insert(id, stream.clone());
        stream
    };
    if !stream.send(&open_message(st, &addon.name, observe)).await {
        stream.reset("the connection closed");
        return Err(ServiceError::Closed("the connection closed".into()));
    }
    Ok((stream, answers))
}

/// The `open` message: who the client is and where the exchange is, so
/// the service can key its state on (flow, layer).
fn open_message(st: &StackFlow, layer: &str, observe: bool) -> Out {
    Out::Open {
        flow: st.flow.to_string(),
        conn: st.client.id.to_string(),
        layer: layer.to_owned(),
        mode: if observe { "observe" } else { "enforce" },
        client_ip: st.client.peer.ip().to_string(),
        client_user: st.client.user.clone(),
        listener: st.client.listener.name.clone(),
        sni: st.tls.as_ref().and_then(|t| t.sni.clone()),
        tags: st.tags(),
    }
}

/// Connects and completes the handshake through the connector, then
/// starts the connection's reader and writer.
async fn dial(st: &StackFlow, index: usize, svc: &ServiceSpec) -> Result<Arc<Link>, ServiceError> {
    let addon = &st.snap.addons[index];
    let spec = addon
        .endpoints
        .get(&svc.endpoint)
        .ok_or_else(|| ServiceError::Connect(format!("no endpoint {:?}", svc.endpoint)))?;
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

    let started = Instant::now();
    let result = async {
        let upstream = st.snap.upstream.clone();
        upstream
            .preflight(&authority, spec.private)
            .await
            .map_err(|e| ServiceError::Connect(e.to_string()))?;
        let io = upstream
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
        layer: addon.name.clone(),
        endpoint: svc.endpoint.clone(),
        method: "GET".to_owned(),
        path: uri.path().to_owned(),
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

/// Owns the socket's write half. Control messages go first; the socket
/// closes once every data sender is gone, or on a close.
async fn write(
    mut sink: SplitSink<Ws, Message>,
    mut data: mpsc::Receiver<Message>,
    mut ctl: mpsc::UnboundedReceiver<Message>,
) {
    loop {
        let m = tokio::select! {
            biased;
            Some(m) = ctl.recv() => m,
            m = data.recv() => match m {
                Some(m) => m,
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
                if b.len() < 4 {
                    break framing("a binary frame shorter than its stream id");
                }
                let id = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
                route(&shared, id).map(|s| match s {
                    Some(s) => s.bytes(&b[4..]),
                    // Ignored, and credited back, so a service still
                    // sending when the stream ended is never stalled.
                    None if b.len() > 4 => shared.send_ctl(
                        id,
                        &Out::Credit {
                            bytes: (b.len() - 4) as u64,
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
                                s.fail(ServiceError::Protocol(format!("bad message: {e}")), true);
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
