//! One exchange as a stream on a connection: its lifecycle from `open`
//! to its end, the answers the service owes, and the bodies pumped to it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use roxy_http::{Body, BodyError, BodySender};
use roxy_wasm::{LayerHost as _, LayerRequest, LayerResponse};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use super::super::super::host::StackHost;
use super::super::super::{AddonMode, Part, StackError, StackFlow, emit_stack_error};
use super::super::{Call, In, Out, ServiceError, ServiceSpec, Unanswered};
use super::inbox::{Inbox, feeder};
use super::link::{Link, Message, Queued, Wire, binary, dial, text};
use super::lock;
use super::pool::{Pool, PoolKey, Reservation};
use super::window::Window;
use crate::in_flight::Dir;

/// Largest body frame roxy sends, so streams share the socket fairly.
pub(super) const MAX_BODY_FRAME: usize = 64 * 1024;

/// Most host-service calls a stream may have waiting. They run in order on
/// one task per stream, so a service that sends faster than the host
/// answers is bounded here rather than by memory.
pub(crate) const MAX_HOST_CALLS_WAITING: usize = 64;

/// What an enforce stream's service sends up, each on its own lane: the
/// request it forwards, if it forwards one, and the response the client
/// gets, which it owes. Neither waits on the other.
pub(crate) struct Answers {
    /// `Err` once the stream has ended without a forward.
    pub forward: oneshot::Receiver<LayerRequest>,
    pub answer: oneshot::Receiver<Result<LayerResponse, Unanswered>>,
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
    /// Host-service calls waiting for the stream's worker, once it has one.
    pub(super) calls: Mutex<Option<mpsc::Sender<Call>>>,
    /// The stream failed or was given up, as opposed to ending on the
    /// service's last message.
    pub(super) broken: AtomicBool,
    /// The stream's place on the connection, kept past its end while the
    /// worker runs the calls queued before it, so what a service leaves
    /// behind on ended streams is bounded by `max_streams` like its open
    /// ones.
    pub(super) draining: Mutex<Option<Reservation>>,
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
    /// Enforce: each head the service may still send, taken as it comes.
    /// A `request` is one forward, which it need not make; a `response`
    /// is the answer it owes. Neither orders against the other.
    Enforce {
        forward: Option<oneshot::Sender<LayerRequest>>,
        answer: Option<oneshot::Sender<Result<LayerResponse, Unanswered>>>,
    },
    /// Observe: nothing the service sends is taken, but its last message
    /// ends the stream as an enforce stream's does: its `response_end`,
    /// and the `request_end` of a request it sent.
    Observing { forwarding: bool, responded: bool },
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
    /// A head-only direction whose head arrived and whose end has not:
    /// nothing is fed, and the end is still the service's to send.
    end_owed: bool,
}

/// What `settle` found when the stream ended: who was waiting on it.
struct Ending {
    inboxes: [Option<Arc<Inbox>>; 2],
    pending: Pending,
    slot: Option<Reservation>,
}

/// The answer the service still owed when the stream ended, to be told
/// why it will not come.
type Pending = Option<oneshot::Sender<Result<LayerResponse, Unanswered>>>;

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

    /// The service still owes something: its answer, or the end of a body
    /// it is sending.
    fn waiting(&self) -> bool {
        match &self.phase {
            Phase::Enforce { answer, .. } => {
                answer.is_some()
                    || self.req.inbox.is_some()
                    || self.res.inbox.is_some()
                    || self.req.end_owed
                    || self.res.end_owed
            }
            Phase::Observing {
                forwarding,
                responded,
            } => *forwarding || !*responded,
            Phase::Ended { .. } => true,
        }
    }

    /// An observer's head or end: it goes nowhere, but marks what the
    /// service still has to send before the stream ends. Anything out of
    /// order is ignored, like the rest of what an observer sends.
    fn observed(&mut self, m: &In) {
        let Phase::Observing {
            forwarding,
            responded,
        } = &mut self.phase
        else {
            return;
        };
        match m {
            In::Request { .. } => *forwarding = true,
            In::RequestEnd { .. } => *forwarding = false,
            In::ResponseEnd { .. } => *responded = true,
            In::Response { .. } | In::Credit { .. } | In::Reset { .. } | In::Call(_) => {}
        }
    }

    /// Ends the stream, once: what was pending goes to the caller to be
    /// told. `None` if it had already ended.
    fn end(&mut self, observe_error: Option<ServiceError>) -> Option<Ending> {
        let ended = Phase::Ended { observe_error };
        let pending = match std::mem::replace(&mut self.phase, ended) {
            // The forward, if none came, is dropped: the exchange learns
            // there is none.
            Phase::Enforce { answer, .. } => answer,
            Phase::Observing { .. } => None,
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

    /// The service forwards a request: once per stream.
    fn forwarded(&mut self) -> Result<oneshot::Sender<LayerRequest>, ServiceError> {
        match &mut self.phase {
            Phase::Enforce { forward, .. } => forward
                .take()
                .ok_or_else(|| ServiceError::Protocol("a second request".into())),
            Phase::Observing { .. } | Phase::Ended { .. } => {
                Err(ServiceError::Protocol("unexpected request".into()))
            }
        }
    }

    /// The service answers: once per stream, whether or not it forwarded,
    /// before or after.
    fn answered(&mut self, r: LayerResponse) -> Result<(), ServiceError> {
        match &mut self.phase {
            Phase::Enforce { answer, .. } => match answer.take() {
                Some(tx) => {
                    let _ = tx.send(Ok(r));
                    Ok(())
                }
                None => Err(ServiceError::Protocol("a second response".into())),
            },
            Phase::Observing { .. } | Phase::Ended { .. } => {
                Err(ServiceError::Protocol("unexpected response".into()))
            }
        }
    }
}

/// Why a body stopped short of its end on its way to the service.
pub(super) enum Lost {
    /// The stream ended under it; whatever ended it has settled.
    Stream,
    /// The body itself failed.
    Body(BodyError),
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
}

/// Whether failing a stream tells the service (a `reset` message).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reset {
    Send,
    /// The connection is gone, or the service already ended the stream.
    Skip,
}

impl Stream {
    fn name(&self) -> String {
        self.st.snap.addons[self.index].name.clone()
    }

    /// The stream failed or was given up: nothing it accepted is acted on.
    /// A stream that ended on the service's last message is not broken,
    /// and a forward it accepted still runs.
    pub(crate) fn is_broken(&self) -> bool {
        self.broken.load(Ordering::SeqCst)
    }

    /// Ends the stream, once: nothing more goes on it, its place on the
    /// connection is released, the reader forgets it, and whoever was
    /// waiting on it (a pending answer, the body being fed) learns how it
    /// ended. False if it had already ended, in which case `end` is not
    /// told to anyone.
    pub(super) fn settle(&self, end: End<'_>) -> bool {
        let observe_error = match &end {
            End::Failed { e, .. } if self.mode == AddonMode::Observe => Some(e.clone()),
            End::Quiet | End::Failed { .. } | End::Abandoned(_) => None,
        };
        let Some(mut ending) = lock(&self.state).end(observe_error) else {
            return false;
        };
        // Handed over before the end wakes the worker, which lets the
        // place go once it has drained.
        if lock(&self.calls).is_some() {
            *lock(&self.draining) = ending.slot.take();
        }
        self.ended.cancel();
        lock(&self.link.shared.streams).open.remove(&self.id);
        drop(ending.slot);
        if self.mode == AddonMode::Enforce {
            // Nothing more comes off the stream: the layer forwards no
            // more, and one that failed gives up a forward still running.
            match &end {
                End::Failed { .. } => self.st.layer_failed(self.index),
                End::Quiet | End::Abandoned(_) => self.st.layer_done(self.index),
            }
        }
        let (e, reset) = match end {
            End::Quiet => return true,
            End::Failed { e, reset } => {
                self.broken.store(true, Ordering::SeqCst);
                let message = e.to_string();
                (
                    Unanswered::Service(e),
                    (reset == Reset::Send).then_some(message),
                )
            }
            End::Abandoned(why) => {
                self.broken.store(true, Ordering::SeqCst);
                (Unanswered::Abandoned(why.to_owned()), Some(why.to_owned()))
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
        if let Unanswered::Service(e) = &e
            && self.mode == AddonMode::Enforce
        {
            self.st.fail(&self.name(), StackError::Service(e.clone()));
        }
        for inbox in ending.inboxes.into_iter().flatten() {
            inbox.abort(&e);
        }
        if let Some(tx) = ending.pending {
            let _ = tx.send(Err(e));
        }
        true
    }

    /// The service failed this stream. False if it had already ended, so
    /// nobody was told.
    pub(crate) fn fail(&self, e: ServiceError, reset: Reset) -> bool {
        self.settle(End::Failed { e, reset })
    }

    /// roxy gives up on the stream.
    pub(crate) fn reset(&self, why: &str) {
        self.settle(End::Abandoned(why));
    }

    /// The exchange was torn down under the stream: the service is told
    /// why.
    pub(crate) fn abandon(&self) {
        self.reset(self.st.torn_down_why());
    }

    /// Resolves once the stream has ended, however it did.
    pub(crate) async fn until_ended(&self) {
        self.ended.cancelled().await;
    }

    /// An observe stream: roxy sent all it had, and the service has
    /// `within` to send its last message (or a reset) before roxy fails it.
    /// How it ended, if it failed.
    pub(crate) async fn finish(&self, within: Duration) -> Result<(), ServiceError> {
        if tokio::time::timeout(within, self.ended.cancelled())
            .await
            .is_err()
        {
            self.fail(ServiceError::Timeout("first_byte_timeout"), Reset::Send);
        }
        match &mut lock(&self.state).phase {
            Phase::Ended { observe_error } => observe_error.take().map_or(Ok(()), Err),
            Phase::Enforce { .. } | Phase::Observing { .. } => Ok(()),
        }
    }

    /// Logs the failure of a host-service call that ran after the stream
    /// had ended, which `settle` can no longer tell anyone.
    fn report(&self, e: ServiceError) {
        match self.mode {
            AddonMode::Enforce => self.st.fail(&self.name(), StackError::Service(e)),
            AddonMode::Observe => emit_stack_error(
                &self.st.meta,
                &self.name(),
                &StackError::Service(e),
                AddonMode::Observe,
            ),
        }
    }

    /// Sends a control message in stream order. False once the stream or
    /// the connection is gone.
    pub(super) async fn send(&self, m: &Out) -> bool {
        let open = matches!(m, Out::Open { .. });
        self.queue(text(self.id, m), open).await
    }

    /// Queues a message of the stream for the socket. Nothing is queued
    /// once the stream has ended. A connection whose writer has gone fails
    /// the stream closed at once, however long its reader takes to see
    /// the end; an `open` is left to its caller, which holds no stream yet.
    pub(super) async fn queue(&self, msg: Message, open: bool) -> bool {
        let q = Queued {
            msg,
            wire: self.wire.clone(),
            open,
        };
        let sent = tokio::select! {
            biased;
            () = self.ended.cancelled() => return false,
            r = self.link.data.send(q) => r.is_ok(),
        };
        if !sent && !open {
            self.fail(
                ServiceError::Closed("the connection closed".into()),
                Reset::Skip,
            );
        }
        sent
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
    /// allows), end. A body that fails ends its lane with the failure,
    /// never as complete; the stream, and the service's own lanes, go on.
    /// Stops at the stream's end, which whatever ended it has settled.
    pub(crate) async fn pump(&self, dir: Dir, head: Out, body: Body) {
        if !self.send(&head).await {
            return;
        }
        // Nothing to read (and an empty observer copy may never be ended).
        let error = if body.known_length() == Some(0) {
            None
        } else {
            match self.pump_body(dir, body).await {
                Ok(()) => None,
                Err(Lost::Stream) => return,
                Err(Lost::Body(e)) => Some(e.to_string()),
            }
        };
        let end = match dir {
            Dir::Request => Out::RequestEnd { error },
            Dir::Response => Out::ResponseEnd { error },
        };
        self.send(&end).await;
    }

    /// Sends `body`'s frames in direction `dir`, as credit allows.
    pub(super) async fn pump_body(&self, dir: Dir, mut body: Body) -> Result<(), Lost> {
        use http_body::Body as _;
        loop {
            let frame =
                std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await;
            let mut d = match frame {
                None => return Ok(()),
                Some(Err(e)) => return Err(Lost::Body(e)),
                Some(Ok(f)) => match f.into_data() {
                    Ok(d) => d,
                    Err(_) => continue,
                },
            };
            while !d.is_empty() {
                let Some(n) = self.take_credit(dir, d.len().min(MAX_BODY_FRAME)).await else {
                    return Err(Lost::Stream);
                };
                let part = d.split_to(n);
                if !self.queue(binary(self.id, dir, &part), false).await {
                    return Err(Lost::Stream);
                }
            }
        }
    }

    /// Credit back to the service for `n` bytes of the `dir` body
    /// consumed, in the window's batches.
    pub(super) fn grant(&self, dir: Dir, n: u64) {
        if n == 0 {
            return;
        }
        let due = {
            let mut s = lock(&self.state);
            if s.ended() {
                return;
            }
            s.lane(dir).window.acked(n)
        };
        if let Some(bytes) = due {
            self.link
                .shared
                .send_ctl(self.id, &Out::Credit { dir, bytes });
        }
    }

    /// Bytes of the `dir` body from the service. They count against that
    /// body's window in either mode. An observe stream's are discarded and
    /// credited back as they go: the service never waits on what it sends.
    /// An enforce stream's for a head-only direction are the layer's
    /// failure, whenever they come.
    pub(super) fn bytes(self: &Arc<Self>, dir: Dir, b: &[u8]) {
        if b.is_empty() {
            return;
        }
        if self.mode == AddonMode::Enforce && self.head_only(dir) {
            self.fail(ServiceError::Unsubscribed(dir.as_str()), Reset::Send);
            return;
        }
        let n = b.len() as u64;
        let mut s = lock(&self.state);
        let lane = s.lane(dir);
        let inbox = lane.inbox.clone();
        if inbox.is_none() && self.mode == AddonMode::Enforce {
            drop(s);
            self.fail(
                ServiceError::Protocol(format!(
                    "bytes of a {} body that is not open",
                    dir.as_str()
                )),
                Reset::Send,
            );
            return;
        }
        if lane.window.received(n).is_err() {
            drop(s);
            self.fail(
                ServiceError::Protocol(format!(
                    "{} body bytes past the body's credit",
                    dir.as_str()
                )),
                Reset::Send,
            );
            return;
        }
        let Some(inbox) = inbox else {
            drop(s);
            self.grant(dir, n);
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
            In::Call(call) => return self.queue_host_call(call),
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
                self.fail(ServiceError::Closed(why), Reset::Skip);
                return;
            }
            In::Request { .. }
            | In::RequestEnd { .. }
            | In::Response { .. }
            | In::ResponseEnd { .. } => {}
        }
        let mut s = lock(&self.state);
        let result = match self.mode {
            AddonMode::Observe => {
                s.observed(&m);
                Ok(())
            }
            AddonMode::Enforce => self.answer(&mut s, m),
        };
        let done = !s.waiting();
        drop(s);
        match result {
            Err(e) => {
                self.fail(e, Reset::Send);
            }
            Ok(()) if done => {
                self.settle(End::Quiet);
            }
            Ok(()) => {}
        }
    }

    fn answer(self: &Arc<Self>, s: &mut StreamState, m: In) -> Result<(), ServiceError> {
        let limits = &self.st.snap.limits;
        match m {
            In::RequestEnd { error } => self.lane_end(s, Dir::Request, error),
            In::ResponseEnd { error } => self.lane_end(s, Dir::Response, error),
            In::Request {
                method,
                url,
                headers,
            } => {
                // Parsed before the forward is taken: a head that fails
                // leaves the answer owed, so `settle` tells it the error.
                let method = http::Method::from_bytes(method.as_bytes())
                    .map_err(|_| ServiceError::Protocol(format!("invalid method {method:?}")))?;
                let uri: http::Uri = url
                    .parse()
                    .map_err(|_| ServiceError::Protocol(format!("invalid url {url:?}")))?;
                let headers = super::super::header_map(&headers, limits.max_headers)?;
                let declared = super::super::declared_length(&headers)?;
                let forward = s.forwarded()?;
                self.st.forwarding(self.index);
                // On an upgrade the forwarded body is the client's side of
                // the WebSocket, for as long as it is open: no cap.
                let cap = if self.st.is_upgrade() {
                    u64::MAX
                } else {
                    limits.max_request_body_bytes
                };
                let (body_tx, body) = self.own_body(Dir::Request, cap, declared);
                let mut r = http::Request::new(body);
                *r.method_mut() = method;
                *r.uri_mut() = uri;
                *r.headers_mut() = headers;
                self.expect_body(s, Dir::Request, body_tx);
                let _ = forward.send(r);
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
                let headers = super::super::header_map(&headers, limits.max_headers)?;
                let cap = if upgrade {
                    u64::MAX
                } else {
                    limits.max_response_body_bytes
                };
                let declared = super::super::declared_length(&headers)?;
                let (body_tx, body) = self.own_body(Dir::Response, cap, declared);
                let mut r = http::Response::new(body);
                *r.status_mut() = status;
                *r.headers_mut() = headers;
                s.answered(r)?;
                self.expect_body(s, Dir::Response, body_tx);
                Ok(())
            }
            // Handled by `control`.
            In::Credit { .. } | In::Reset { .. } | In::Call(_) => Ok(()),
        }
    }

    /// The service ended the `dir` lane it was sending. With `error` the
    /// body is cut where it is, never complete, and the cut is the
    /// service's fault unless an earlier one stands (a failure from below
    /// it is passing on). A head-only lane has no body to cut: an error on
    /// its end is a protocol violation.
    fn lane_end(
        &self,
        s: &mut StreamState,
        dir: Dir,
        error: Option<String>,
    ) -> Result<(), ServiceError> {
        let lane = s.lane(dir);
        match lane.inbox.take() {
            Some(inbox) => {
                if let Some(why) = &error {
                    // The service's text, bounded as its reset messages are.
                    let why: String = why.chars().take(200).collect();
                    self.st.fail(
                        &self.name(),
                        StackError::Service(ServiceError::Cut {
                            dir: dir.as_str(),
                            why,
                        }),
                    );
                }
                let mut q = lock(&inbox.q);
                match error {
                    Some(why) => q.abort = Some(why),
                    None => q.end = true,
                }
                drop(q);
                inbox.ready.notify_one();
                Ok(())
            }
            None if lane.end_owed && error.is_none() => {
                lane.end_owed = false;
                Ok(())
            }
            None if lane.end_owed => Err(ServiceError::Protocol(format!(
                "an error on the {}_end of a head-only body",
                dir.as_str()
            ))),
            None => Err(ServiceError::Protocol(format!(
                "unexpected {}_end",
                dir.as_str()
            ))),
        }
    }

    /// Hands a host-service call to the stream's worker, started on the
    /// first call. The queue is bounded: a service with more than
    /// [`MAX_HOST_CALLS_WAITING`] unanswered has broken the protocol.
    /// Accepted under the state lock, so a call is either queued before
    /// the stream ends or dropped: the reader may still hold a stream
    /// another task has just ended.
    fn queue_host_call(self: &Arc<Self>, call: Call) {
        let state = lock(&self.state);
        if state.ended() {
            return;
        }
        let mut calls = lock(&self.calls);
        let tx = calls.get_or_insert_with(|| {
            let (tx, rx) = mpsc::channel(MAX_HOST_CALLS_WAITING);
            tokio::spawn(self.clone().host_calls(rx));
            tx
        });
        let full = matches!(tx.try_send(call), Err(mpsc::error::TrySendError::Full(_)));
        drop(calls);
        drop(state);
        if full {
            self.fail(
                ServiceError::Protocol(format!(
                    "more than {MAX_HOST_CALLS_WAITING} host calls waiting"
                )),
                Reset::Send,
            );
        }
    }

    /// The stream's host-service worker: each call in turn, each answered
    /// with a `result`. The stream's end stops it taking calls, but what
    /// was queued before the end still runs: the service sent those calls
    /// before its last message, so their effects stand, though their
    /// results have nowhere to go. A failure on an open stream fails it, so
    /// the exchange, as it would a WASM layer's, and drops the calls behind
    /// it; after the end there is nothing left to fail, so a failing call
    /// is logged and the rest still run. The stream's place on the
    /// connection goes once the worker is done.
    async fn host_calls(self: Arc<Self>, rx: mpsc::Receiver<Call>) {
        self.run_calls(rx).await;
        drop(lock(&self.draining).take());
    }

    async fn run_calls(&self, mut rx: mpsc::Receiver<Call>) {
        loop {
            let next = tokio::select! {
                biased;
                m = rx.recv() => m,
                () = self.ended.cancelled() => {
                    rx.close();
                    rx.recv().await
                }
            };
            let Some(call) = next else {
                return;
            };
            let id = call.id();
            match super::super::host::call(&self.st, self.index, call).await {
                Ok(result) => {
                    let (value, error) = match result {
                        Ok(v) => (Some(v), None),
                        Err(e) => (None, Some(e)),
                    };
                    self.send(&Out::Result { id, value, error }).await;
                }
                Err(err) => {
                    let e = ServiceError::Layer { call: id, err };
                    if self.fail(e.clone(), Reset::Send) {
                        return;
                    }
                    self.report(e);
                }
            }
        }
    }

    /// Whether the layer is subscribed to the head of `dir` only: that
    /// body is a head and an end on the stream, with no bytes between.
    fn head_only(&self, dir: Dir) -> bool {
        self.st.snap.addons[self.index].subscribe.part(dir) == Part::Head
    }

    /// The body of a head the service sent in direction `dir`. For a
    /// head-only direction it is complete with the head, so the body
    /// bypassing the layer keeps its framing when spliced onto it; the
    /// service's end for it is owed, and its bytes refused, on the stream.
    fn own_body(&self, dir: Dir, cap: u64, declared: Option<u64>) -> (Option<BodySender>, Body) {
        if self.head_only(dir) {
            return (None, Body::empty());
        }
        let (tx, body) = Body::channel(cap, declared);
        (Some(tx), body)
    }

    /// What the service still owes of the `dir` body whose head it sent:
    /// the bytes and the end, fed through `tx`, or the end alone.
    fn expect_body(self: &Arc<Self>, s: &mut StreamState, dir: Dir, tx: Option<BodySender>) {
        let lane = s.lane(dir);
        match tx {
            Some(tx) => lane.inbox = Some(self.feed(tx, dir)),
            None => lane.end_owed = true,
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
        AddonMode::Observe => (
            None,
            Phase::Observing {
                forwarding: false,
                responded: false,
            },
        ),
        AddonMode::Enforce => {
            let (forward_tx, forward_rx) = oneshot::channel();
            let (answer_tx, answer_rx) = oneshot::channel();
            (
                Some(Answers {
                    forward: forward_rx,
                    answer: answer_rx,
                }),
                Phase::Enforce {
                    forward: Some(forward_tx),
                    answer: Some(answer_tx),
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
            calls: Mutex::new(None),
            broken: AtomicBool::new(false),
            draining: Mutex::new(None),
        });
        s.open.insert(id, stream.clone());
        stream
    };
    let opening = Opening(Some(&stream));
    if !stream.send(&open_message(st, index, mode)).await {
        drop(opening);
        return Err(ServiceError::Closed("the connection closed".into()));
    }
    opening.sent();
    Ok((stream, answers))
}

/// The `open` message: what a WASM layer reads through `flow.current`
/// and `flow.config`, so the service can key its state on (flow, layer).
pub(super) fn open_message(st: &Arc<StackFlow>, index: usize, mode: AddonMode) -> Out {
    let addon = &st.snap.addons[index];
    let info = StackHost {
        st: st.clone(),
        index,
        observer: None,
        call: None,
    }
    .flow_info();
    Out::Open {
        flow: info.flow_id,
        conn: info.conn_id,
        layer: addon.name.clone(),
        mode: mode.as_str(),
        subscribe: addon.subscribe.into(),
        client_ip: info.principal.client_ip.to_string(),
        listener: info.principal.listener,
        sni: info.principal.tls_sni,
        tags: info.tags,
        capabilities: roxy_wasm::Capability::ALL
            .into_iter()
            .filter(|c| addon.capabilities.contains(*c))
            .map(roxy_wasm::Capability::name)
            .collect(),
        config: addon.config.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Receivers = (
        oneshot::Receiver<LayerRequest>,
        oneshot::Receiver<Result<LayerResponse, Unanswered>>,
    );

    /// An enforce stream's state as opened, with the exchange's ends of
    /// its lanes.
    fn enforce() -> (StreamState, Receivers) {
        let (forward_tx, forward) = oneshot::channel();
        let (answer_tx, answer) = oneshot::channel();
        let phase = Phase::Enforce {
            forward: Some(forward_tx),
            answer: Some(answer_tx),
        };
        (StreamState::new(phase, None), (forward, answer))
    }

    fn response() -> LayerResponse {
        http::Response::new(Body::empty())
    }

    fn request() -> LayerRequest {
        http::Request::new(Body::empty())
    }

    /// Ending a stream tells the answer the service still owed, and drops
    /// the forward it never made; a stream that has answered owes nothing,
    /// whether or not it forwarded. A second end is a no-op.
    #[test]
    fn the_owed_answer_is_told_at_the_end() {
        let (mut s, (forward, mut answer)) = enforce();
        assert!(s.waiting());
        let ending = s.end(None).expect("ends once");
        assert!(ending.pending.is_some(), "the answer was owed");
        assert!(forward.blocking_recv().is_err(), "no forward came");
        assert!(answer.try_recv().is_err(), "nothing sent yet");
        assert!(s.ended());
        assert!(s.end(None).is_none());

        let (mut s, _rx) = enforce();
        s.forwarded().unwrap();
        assert!(s.waiting(), "the answer is still owed");
        assert!(s.end(None).expect("ends").pending.is_some());

        let (mut s, _rx) = enforce();
        s.forwarded().unwrap();
        s.answered(response()).unwrap();
        assert!(!s.waiting());
        assert!(s.end(None).expect("ends").pending.is_none());

        let (mut s, _rx) = enforce();
        s.answered(response()).unwrap();
        assert!(!s.waiting(), "an answer without a forward owes nothing");
        assert!(s.end(None).expect("ends").pending.is_none());
    }

    /// An observe stream owes no answer, but ends only on the service's
    /// last message: its `response_end`, and the `request_end` of a
    /// request it sent, whichever order they come in.
    #[test]
    fn an_observe_stream_ends_on_the_services_last_message() {
        let observing = || {
            StreamState::new(
                Phase::Observing {
                    forwarding: false,
                    responded: false,
                },
                None,
            )
        };
        let mut s = observing();
        assert!(s.waiting());
        s.observed(&In::Response {
            status: 200,
            headers: Vec::new(),
        });
        assert!(s.waiting(), "a head is not the end");
        s.observed(&In::ResponseEnd { error: None });
        assert!(!s.waiting());
        assert!(s.end(None).expect("ends").pending.is_none());

        let mut s = observing();
        s.observed(&In::Request {
            method: "GET".to_owned(),
            url: "http://up.test/".to_owned(),
            headers: Vec::new(),
        });
        s.observed(&In::ResponseEnd { error: None });
        assert!(s.waiting(), "the end of the request it sent is owed");
        s.observed(&In::RequestEnd { error: None });
        assert!(!s.waiting());
    }

    /// Each head comes once, in either order: a forward before or after
    /// the answer, or none at all. A second of either, or a head on an
    /// ended stream, is a protocol error.
    #[test]
    fn each_head_comes_once_in_either_order() {
        let (mut s, (forward, mut answer)) = enforce();
        s.answered(response()).unwrap();
        assert!(matches!(answer.try_recv(), Ok(Ok(_))));
        s.forwarded().unwrap().send(request()).ok().unwrap();
        assert!(
            forward.blocking_recv().is_ok(),
            "a forward after the answer"
        );
        assert!(s.forwarded().is_err(), "a second request");
        assert!(s.answered(response()).is_err(), "a second response");

        let (mut s, _rx) = enforce();
        s.forwarded().unwrap();
        assert!(s.forwarded().is_err(), "a second request");
        s.answered(response()).unwrap();
        assert!(s.answered(response()).is_err(), "a second response");

        let mut ended = StreamState::new(
            Phase::Ended {
                observe_error: None,
            },
            None,
        );
        assert!(ended.forwarded().is_err());
        assert!(ended.answered(response()).is_err());
        assert!(ended.ended());
    }
}
