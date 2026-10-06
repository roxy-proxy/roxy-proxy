//! One exchange as a stream on a connection: its lifecycle from `open`
//! to its end, the answers the service owes, and the bodies pumped to it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use roxy_http::{Body, BodyError, BodySender};
use roxy_wasm::LayerResponse;
use tokio::sync::{Notify, oneshot};
use tokio_util::sync::CancellationToken;

use super::super::super::{AddonMode, StackError, StackFlow};
use super::super::{First, In, Out, ServiceError, ServiceSpec, Unanswered};
use super::inbox::{Inbox, feeder};
use super::link::{Link, Message, Queued, Wire, binary, dial, text};
use super::lock;
use super::pool::{Pool, PoolKey, Reservation};
use super::window::Window;
use crate::watch::Dir;

/// Largest body frame roxy sends, so streams share the socket fairly.
pub(super) const MAX_BODY_FRAME: usize = 64 * 1024;

/// The service's answers to an enforce stream, in protocol order.
pub(crate) struct Answers {
    pub first: oneshot::Receiver<Result<First, Unanswered>>,
    pub second: oneshot::Receiver<Result<LayerResponse, Unanswered>>,
}

/// One exchange on a connection.
pub(crate) struct Stream {
    pub(super) id: u32,
    pub(super) link: Arc<Link>,
    pub(super) st: Arc<StackFlow>,
    pub(super) index: usize,
    pub(super) mode: AddonMode,
    pub(super) state: Mutex<StreamState>,
    pub(super) more_credit: Notify,
    /// Wakes whatever is sending or waiting on the stream once it ended.
    pub(super) ended: CancellationToken,
    pub(super) wire: Arc<Wire>,
}

pub(super) struct StreamState {
    phase: Phase,
    /// The request body and the response body, each on its own.
    req: Lane,
    res: Lane,
    pub(super) slot: Option<Reservation>,
}

/// Where the stream is in the protocol: what the service still owes roxy
/// besides the bodies it is sending.
pub(super) enum Phase {
    /// Enforce: the request head is on its way, and the service owes its
    /// first answer (a request to forward, a response, or a deny).
    AwaitingFirst {
        first: oneshot::Sender<Result<First, Unanswered>>,
        second: oneshot::Sender<Result<LayerResponse, Unanswered>>,
    },
    /// It forwarded: the response head goes when the stack below answers,
    /// and the service owes its second answer.
    AwaitingSecond {
        second: oneshot::Sender<Result<LayerResponse, Unanswered>>,
    },
    /// Answered (or observe mode, which is never answered): only the
    /// bodies in flight are owed.
    Answered,
    /// Settled: nothing more is sent or delivered on it.
    Ended {
        /// Why an observe stream failed, for its driver to log.
        observe_error: Option<ServiceError>,
    },
}

/// One body of a stream: the credit each way, and what the service is
/// sending of it.
#[derive(Default)]
struct Lane {
    window: Window,
    /// Being fed from the stream: its head arrived and its end has not.
    inbox: Option<Arc<Inbox>>,
}

/// What `settle` found when the stream ended: who was waiting on it.
struct Ending {
    inboxes: [Option<Arc<Inbox>>; 2],
    pending: Pending,
    slot: Option<Reservation>,
}

/// The answer the service still owed when the stream ended, to be told
/// why it will not come.
enum Pending {
    First(oneshot::Sender<Result<First, Unanswered>>),
    Second(oneshot::Sender<Result<LayerResponse, Unanswered>>),
    None,
}

impl StreamState {
    pub(super) fn new(phase: Phase, slot: Option<Reservation>) -> Self {
        Self {
            phase,
            req: Lane::default(),
            res: Lane::default(),
            slot,
        }
    }

    fn lane(&mut self, dir: Dir) -> &mut Lane {
        match dir {
            Dir::Request => &mut self.req,
            Dir::Response => &mut self.res,
        }
    }

    pub(super) fn ended(&self) -> bool {
        matches!(self.phase, Phase::Ended { .. })
    }

    /// The service still owes something: an answer, or the end of a body
    /// it is sending.
    fn waiting(&self) -> bool {
        !matches!(self.phase, Phase::Answered)
            || self.req.inbox.is_some()
            || self.res.inbox.is_some()
    }

    /// Ends the stream, once: what was pending goes to the caller to be
    /// told. `None` if it had already ended.
    fn end(&mut self, observe_error: Option<ServiceError>) -> Option<Ending> {
        let ended = Phase::Ended { observe_error };
        let pending = match std::mem::replace(&mut self.phase, ended) {
            Phase::AwaitingFirst { first, .. } => Pending::First(first),
            Phase::AwaitingSecond { second } => Pending::Second(second),
            Phase::Answered => Pending::None,
            Phase::Ended { observe_error } => {
                self.phase = Phase::Ended { observe_error };
                return None;
            }
        };
        Some(Ending {
            inboxes: [self.req.inbox.take(), self.res.inbox.take()],
            pending,
            slot: self.slot.take(),
        })
    }

    /// The service's first answer is a request to forward: it now owes the
    /// second.
    fn forwarded(&mut self) -> Result<oneshot::Sender<Result<First, Unanswered>>, ServiceError> {
        match std::mem::replace(&mut self.phase, Phase::Answered) {
            Phase::AwaitingFirst { first, second } => {
                self.phase = Phase::AwaitingSecond { second };
                Ok(first)
            }
            other @ (Phase::AwaitingSecond { .. } | Phase::Answered | Phase::Ended { .. }) => {
                self.phase = other;
                Err(ServiceError::Protocol("unexpected request".into()))
            }
        }
    }

    /// Hands a response to whoever is waiting: the first answer (the
    /// service answers instead of forwarding, so no second follows), or
    /// the second.
    fn answered(&mut self, r: LayerResponse, what: &str) -> Result<(), ServiceError> {
        match std::mem::replace(&mut self.phase, Phase::Answered) {
            Phase::AwaitingFirst { first, .. } => {
                let _ = first.send(Ok(First::Answer(r)));
                Ok(())
            }
            Phase::AwaitingSecond { second } => {
                let _ = second.send(Ok(r));
                Ok(())
            }
            other @ (Phase::Answered | Phase::Ended { .. }) => {
                self.phase = other;
                Err(ServiceError::Protocol(format!("unexpected {what}")))
            }
        }
    }
}

/// How a stream ends.
pub(super) enum End<'a> {
    /// Nothing to tell anyone: the service's last message arrived, an
    /// observe stream sent all it had, or an `open` was given up before
    /// its message went.
    Quiet,
    /// The service failed it. `reset` tells the service, when it has not
    /// already closed or reset the stream itself.
    Failed { e: ServiceError, reset: Reset },
    /// roxy gave up on it (the client went away, a missed deadline): the
    /// service is told, whoever is waiting gets `why`, and nothing is
    /// logged as the service's fault.
    Abandoned(&'a str),
    /// The body roxy was sending in direction `dir` failed: abandoned, and
    /// whoever is waiting learns which body failed and how.
    BodyFailed(Dir, BodyError),
}

/// Whether failing a stream tells the service (a `reset` message).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Reset {
    Send,
    /// The connection is gone, or the service already ended the stream.
    Skip,
}

impl Stream {
    fn name(&self) -> String {
        self.st.snap.addons[self.index].name.clone()
    }

    /// Ends the stream, once: nothing more goes on it, its place on the
    /// connection is released, the reader forgets it, and whoever was
    /// waiting on it (a pending answer, the body being fed) learns how it
    /// ended.
    pub(super) fn settle(&self, end: End<'_>) {
        let observe_error = match &end {
            End::Failed { e, .. } if self.mode == AddonMode::Observe => Some(e.clone()),
            End::Quiet | End::Failed { .. } | End::Abandoned(_) | End::BodyFailed(..) => None,
        };
        let Some(ending) = lock(&self.state).end(observe_error) else {
            return;
        };
        self.ended.cancel();
        lock(&self.link.shared.streams).open.remove(&self.id);
        drop(ending.slot);
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
        // Recorded before anything learns of the end: the exchange may
        // finish on a body aborted here (the core failing on the request
        // the service forwarded, say) before any answer is read.
        let blame = if let Unanswered::Service(e) = &e
            && self.mode == AddonMode::Enforce
        {
            let name = self.name();
            let err = StackError::Service(e.clone());
            self.st.fail(&name, err.clone());
            Some((name, err))
        } else {
            None
        };
        for inbox in ending.inboxes.into_iter().flatten() {
            inbox.abort(&e);
        }
        match ending.pending {
            Pending::First(tx) => {
                let _ = tx.send(Err(e));
            }
            Pending::Second(tx) if !tx.is_closed() => {
                let _ = tx.send(Err(e));
            }
            Pending::Second(_) | Pending::None => {
                if let Some((name, err)) = blame {
                    // The head has gone on: the failure is logged here,
                    // since no answer carries it.
                    super::super::super::emit_stack_error(
                        &self.st,
                        &name,
                        &err,
                        AddonMode::Enforce,
                    );
                }
            }
        }
    }

    /// The service failed this stream.
    pub(super) fn fail(&self, e: ServiceError, reset: Reset) {
        self.settle(End::Failed { e, reset });
    }

    /// roxy gives up on the stream.
    pub(crate) fn reset(&self, why: &str) {
        self.settle(End::Abandoned(why));
    }

    /// An observe stream: roxy sent all it had.
    pub(crate) fn finish(&self) -> Result<(), ServiceError> {
        self.settle(End::Quiet);
        match &mut lock(&self.state).phase {
            Phase::Ended { observe_error } => observe_error.take().map_or(Ok(()), Err),
            Phase::AwaitingFirst { .. } | Phase::AwaitingSecond { .. } | Phase::Answered => Ok(()),
        }
    }

    /// Sends a control message in stream order. False once the stream or
    /// the connection is gone.
    pub(super) async fn send(&self, m: &Out) -> bool {
        let open = matches!(m, Out::Open { .. });
        self.queue(text(self.id, m), open).await
    }

    /// Queues a message of the stream for the socket. Nothing is queued
    /// once the stream has ended.
    pub(super) async fn queue(&self, msg: Message, open: bool) -> bool {
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
    pub(super) async fn take_credit(&self, dir: Dir, want: usize) -> Option<usize> {
        loop {
            let more = self.more_credit.notified();
            tokio::pin!(more);
            more.as_mut().enable();
            if let Some(n) = lock(&self.state).lane(dir).window.take(want) {
                return Some(n);
            }
            tokio::select! {
                () = more => {}
                () = self.ended.cancelled() => return None,
            }
        }
    }

    /// Streams one message to the service: head, body frames (as credit
    /// allows), end. False if it did not get it all out.
    pub(crate) async fn pump(&self, dir: Dir, head: Out, body: Body) -> bool {
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

    pub(super) async fn pump_body(&self, dir: Dir, mut body: Body) -> bool {
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
    pub(super) fn grant(&self, dir: Dir, n: u64) {
        if n == 0 {
            return;
        }
        {
            let mut s = lock(&self.state);
            if s.ended() {
                return;
            }
            s.lane(dir).window.acked(n);
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
    pub(super) fn bytes(self: &Arc<Self>, dir: Dir, b: &[u8]) {
        if b.is_empty() {
            return;
        }
        let n = b.len() as u64;
        let mut s = lock(&self.state);
        let lane = s.lane(dir);
        let inbox = lane.inbox.clone();
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
        if lane.window.received(n).is_err() {
            drop(s);
            return self.fail(
                ServiceError::Protocol(format!(
                    "{} body bytes past the body's credit",
                    dir.as_str()
                )),
                Reset::Send,
            );
        }
        let Some(inbox) = inbox else {
            let granted = lane.window.discarded(n);
            drop(s);
            if let Some(granted) = granted {
                self.grant(dir, granted);
            }
            return;
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
    pub(super) fn control(self: &Arc<Self>, m: In) {
        match m {
            In::Credit { dir, bytes } => {
                lock(&self.state).lane(dir).window.granted(bytes);
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
        let limits = &self.st.snap.limits;
        match m {
            In::RequestEnd | In::ResponseEnd => {
                let (dir, what) = if matches!(m, In::RequestEnd) {
                    (Dir::Request, "request_end")
                } else {
                    (Dir::Response, "response_end")
                };
                match s.lane(dir).inbox.take() {
                    Some(inbox) => {
                        lock(&inbox.q).end = true;
                        inbox.ready.notify_one();
                        Ok(())
                    }
                    None => Err(ServiceError::Protocol(format!("unexpected {what}"))),
                }
            }
            In::Request {
                method,
                url,
                headers,
            } => {
                // Parsed before the first answer is taken: a head that fails
                // leaves the answer owed, so `settle` tells it the error.
                let method = http::Method::from_bytes(method.as_bytes())
                    .map_err(|_| ServiceError::Protocol(format!("invalid method {method:?}")))?;
                let uri: http::Uri = url
                    .parse()
                    .map_err(|_| ServiceError::Protocol(format!("invalid url {url:?}")))?;
                let headers = super::super::header_map(&headers)?;
                let declared = super::super::declared_length(&headers)?;
                let first = s.forwarded()?;
                // On an upgrade the forwarded body is the client's side of
                // the WebSocket, for as long as it is open: no cap.
                let cap = if self.st.is_upgrade() {
                    u64::MAX
                } else {
                    limits.max_request_body_bytes
                };
                let (body_tx, body) = Body::channel(cap, declared);
                let mut r = http::Request::new(body);
                *r.method_mut() = method;
                *r.uri_mut() = uri;
                *r.headers_mut() = headers;
                s.req.inbox = Some(self.feed(body_tx, Dir::Request));
                let _ = first.send(Ok(First::Forward(r)));
                Ok(())
            }
            In::Response { status, headers } => {
                // A `101` passes an upgrade on; its body is the upstream's
                // side of the WebSocket, uncapped like the request's.
                let upgrade = status == 101 && self.st.is_upgrade();
                if !upgrade && !(200..=599).contains(&status) {
                    return Err(ServiceError::Protocol(format!(
                        "response status {status} is not 200-599"
                    )));
                }
                let status = http::StatusCode::from_u16(status)
                    .map_err(|e| ServiceError::Protocol(e.to_string()))?;
                let headers = super::super::header_map(&headers)?;
                let cap = if upgrade {
                    u64::MAX
                } else {
                    limits.max_response_body_bytes
                };
                let (body_tx, body) = Body::channel(cap, super::super::declared_length(&headers)?);
                let mut r = http::Response::new(body);
                *r.status_mut() = status;
                *r.headers_mut() = headers;
                s.answered(r, "response")?;
                s.res.inbox = Some(self.feed(body_tx, Dir::Response));
                Ok(())
            }
            In::Deny { status, message } => {
                let r = super::super::deny_response(status, message)?;
                // Tagged before the answer goes, so the flow's record has it.
                // A flow at its tag cap loses the label; the deny stands.
                let _ = self.st.add_tag(format!("{}:deny", self.name()));
                s.answered(r, "deny")
            }
            // Handled by `control`.
            In::Credit { .. } | In::Reset { .. } => Ok(()),
        }
    }

    /// Starts feeding the `dir` body from the stream.
    fn feed(self: &Arc<Self>, tx: BodySender, dir: Dir) -> Arc<Inbox> {
        let inbox = Arc::new(Inbox::default());
        tokio::spawn(feeder(self.clone(), inbox.clone(), tx, dir));
        inbox
    }
}

/// Ends a stream whose `open` was given up (a missed deadline) before its
/// message went, so it holds no place on the connection.
pub(super) struct Opening<'a>(Option<&'a Arc<Stream>>);

impl Opening<'_> {
    pub(super) fn sent(mut self) {
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
pub(crate) async fn open(
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

    let (answers, phase) = match mode {
        // An observer's answers are ignored: nothing is owed but bodies.
        AddonMode::Observe => (None, Phase::Answered),
        AddonMode::Enforce => {
            let (first_tx, first_rx) = oneshot::channel();
            let (second_tx, second_rx) = oneshot::channel();
            (
                Some(Answers {
                    first: first_rx,
                    second: second_rx,
                }),
                Phase::AwaitingFirst {
                    first: first_tx,
                    second: second_tx,
                },
            )
        }
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
            state: Mutex::new(StreamState::new(phase, Some(slot))),
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
pub(super) fn open_message(st: &StackFlow, layer: &str, mode: AddonMode) -> Out {
    Out::Open {
        flow: st.flow.to_string(),
        conn: st.client.id.to_string(),
        layer: layer.to_owned(),
        mode: mode.as_str(),
        client_ip: st.client.peer.ip().to_string(),
        listener: st.client.listener.name.clone(),
        sni: st.tls.as_ref().and_then(|t| t.sni.clone()),
        tags: st.tags(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Receivers = (
        oneshot::Receiver<Result<First, Unanswered>>,
        oneshot::Receiver<Result<LayerResponse, Unanswered>>,
    );

    /// An enforce stream's state as opened, with the exchange's ends of
    /// its answers.
    fn enforce() -> (StreamState, Receivers) {
        let (first_tx, first) = oneshot::channel();
        let (second_tx, second) = oneshot::channel();
        let phase = Phase::AwaitingFirst {
            first: first_tx,
            second: second_tx,
        };
        (StreamState::new(phase, None), (first, second))
    }

    fn response() -> LayerResponse {
        http::Response::new(Body::empty())
    }

    /// Ending a stream tells the answer the service owed at that point,
    /// and nothing when it owed none; a second end is a no-op.
    #[test]
    fn the_pending_answer_follows_the_phase() {
        let (mut s, _answers) = enforce();
        assert!(s.waiting());
        assert!(matches!(
            s.end(None),
            Some(Ending {
                pending: Pending::First(_),
                ..
            })
        ));
        assert!(s.ended());
        assert!(s.end(None).is_none());

        let (mut s, _answers) = enforce();
        s.forwarded().unwrap();
        assert!(s.waiting());
        assert!(matches!(
            s.end(None),
            Some(Ending {
                pending: Pending::Second(_),
                ..
            })
        ));

        let (mut s, _answers) = enforce();
        s.forwarded().unwrap();
        s.answered(response(), "response").unwrap();
        assert!(!s.waiting());
        assert!(matches!(
            s.end(None),
            Some(Ending {
                pending: Pending::None,
                ..
            })
        ));

        let mut observe = StreamState::new(Phase::Answered, None);
        assert!(!observe.waiting());
        assert!(matches!(
            observe.end(None),
            Some(Ending {
                pending: Pending::None,
                ..
            })
        ));
    }

    /// A request may only come as the first answer, and a response or deny
    /// only as an answer that is owed: the second is not once the first
    /// answered instead of forwarding.
    #[test]
    fn heads_out_of_order_are_protocol_errors() {
        let (mut s, _answers) = enforce();
        s.forwarded().unwrap();
        assert!(s.forwarded().is_err(), "a second request");
        s.answered(response(), "response").unwrap();
        assert!(s.answered(response(), "response").is_err(), "a third head");
        assert!(s.forwarded().is_err());

        let (mut s, (first, mut second)) = enforce();
        s.answered(response(), "deny").unwrap();
        assert!(matches!(first.blocking_recv(), Ok(Ok(First::Answer(_)))));
        assert!(second.try_recv().is_err(), "no second answer follows");
        assert!(s.answered(response(), "response").is_err());
        assert!(!s.waiting());

        let mut ended = StreamState::new(
            Phase::Ended {
                observe_error: None,
            },
            None,
        );
        assert!(ended.forwarded().is_err());
        assert!(ended.answered(response(), "response").is_err());
        assert!(ended.ended());
    }
}
