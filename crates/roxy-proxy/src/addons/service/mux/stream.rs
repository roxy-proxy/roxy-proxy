//! One exchange as a stream on a connection: its lifecycle from `open`
//! to its end, the two lanes the service produces, and the bodies pumped
//! to it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http_body::Body as _;

use roxy_http::{Body, BodyError};
use roxy_wasm::LayerHost as _;
use tokio::sync::{Notify, mpsc};
use tokio_util::sync::CancellationToken;

use super::super::super::chain::{Head, LaneTx};
use super::super::super::host::StackHost;
use super::super::super::{AddonMode, Part, StackError, StackFlow, emit_stack_error};
use super::super::{Call, In, Out, ServiceError, ServiceSpec};
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

/// The two lanes an enforce stream's service produces, and the bodies
/// roxy holds back from it for a head-only direction, to go on with the
/// head it sends in that direction.
pub(crate) struct Lanes {
    pub(crate) req: LaneTx,
    pub(crate) res: LaneTx,
    /// The request body, when the layer sees the request head only.
    pub(crate) held_request: Arc<Mutex<Option<Body>>>,
    /// The response body from upstream with its status, when the layer
    /// sees the response head only.
    pub(crate) held_response: Arc<Mutex<Option<(http::StatusCode, Body)>>>,
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
    /// The service's response head is on its lane.
    pub(super) answered: CancellationToken,
    /// The service reads no more of the body roxy sends in each direction
    /// (its `stop`): what roxy still pumps of it is dropped.
    pub(super) stop_in: [CancellationToken; 2],
    /// The bodies roxy holds back for a head-only direction (see
    /// [`Lanes`]).
    pub(super) held_request: Arc<Mutex<Option<Body>>>,
    pub(super) held_response: Arc<Mutex<Option<(http::StatusCode, Body)>>>,
    pub(super) wire: Arc<Wire>,
    /// Host-service calls waiting for the stream's worker, once it has one.
    pub(super) calls: Mutex<Option<mpsc::Sender<Call>>>,
    /// The stream's place on the connection, kept past its end while the
    /// worker runs the calls queued before it, so what a service leaves
    /// behind on ended streams is bounded by `max_streams` like its open
    /// ones.
    pub(super) draining: Mutex<Option<Reservation>>,
}

pub(super) struct StreamState {
    lanes: [Lane; 2],
    pub(super) slot: Option<Reservation>,
    /// Settled: nothing more is sent or delivered on it.
    ended: bool,
    /// Why an observe stream failed, for its driver to log.
    observe_error: Option<ServiceError>,
}

/// One direction of a stream: the credit each way, and the lane the
/// service produces in it.
#[derive(Default)]
struct Lane {
    window: Window,
    /// Enforce: where the service's head in this direction goes, until it
    /// has sent one.
    out: Option<LaneTx>,
    /// The body of the head it sent, while it is sending it.
    inbox: Option<Arc<Inbox>>,
    /// How far the service has got on this lane.
    sent: Sent,
    /// Roxy reads no more of this lane: its end is no longer owed.
    stopped: bool,
}

/// What the service has sent of a lane, in the lane's order.
#[derive(Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Sent {
    #[default]
    Nothing,
    Head,
    Trailers,
    End,
}

impl Lane {
    /// The service has nothing more to send on this lane.
    fn done(&self) -> bool {
        self.sent == Sent::End || self.stopped
    }
}

/// What `settle` found when the stream ended: who was waiting on it.
struct Ending {
    inboxes: [Option<Arc<Inbox>>; 2],
    /// Lanes the service never put a head on, let go of outside the lock.
    outs: [Option<LaneTx>; 2],
    slot: Option<Reservation>,
}

impl StreamState {
    pub(super) fn new(lanes: Option<Lanes>, slot: Option<Reservation>) -> Self {
        let mut state = Self {
            lanes: [Lane::default(), Lane::default()],
            slot,
            ended: false,
            observe_error: None,
        };
        if let Some(lanes) = lanes {
            state.lanes[0].out = Some(lanes.req);
            state.lanes[1].out = Some(lanes.res);
        }
        state
    }

    fn lane(&mut self, dir: Dir) -> &mut Lane {
        &mut self.lanes[dir_index(dir)]
    }

    pub(super) fn ended(&self) -> bool {
        self.ended
    }

    /// The service still owes the end of a lane.
    fn waiting(&self) -> bool {
        self.lanes.iter().any(|l| !l.done())
    }

    /// Ends the stream, once: what was pending goes to the caller to be
    /// told. `None` if it had already ended.
    fn end(&mut self, observe_error: Option<ServiceError>) -> Option<Ending> {
        if self.ended {
            return None;
        }
        self.ended = true;
        self.observe_error = observe_error;
        let [req, res] = &mut self.lanes;
        Some(Ending {
            inboxes: [req.inbox.take(), res.inbox.take()],
            outs: [req.out.take(), res.out.take()],
            slot: self.slot.take(),
        })
    }

    /// The service sends the head of the `dir` lane: once, before its
    /// end. The lane it goes on, when the stream carries one.
    fn head(&mut self, dir: Dir) -> Result<Option<LaneTx>, ServiceError> {
        let lane = self.lane(dir);
        match lane.sent {
            Sent::Nothing => {}
            Sent::Head | Sent::Trailers => {
                return Err(ServiceError::Protocol(format!(
                    "a second {} head",
                    dir.as_str()
                )));
            }
            Sent::End => {
                return Err(ServiceError::Protocol(format!(
                    "a {} head after its end",
                    dir.as_str()
                )));
            }
        }
        lane.sent = Sent::Head;
        Ok(lane.out.take())
    }

    /// The service sends trailers on the `dir` lane: once, after its head
    /// and before its end.
    fn trailers(&mut self, dir: Dir) -> Result<Option<Arc<Inbox>>, ServiceError> {
        let lane = self.lane(dir);
        if lane.sent != Sent::Head {
            return Err(ServiceError::Protocol(format!(
                "{} trailers out of order",
                dir.as_str()
            )));
        }
        lane.sent = Sent::Trailers;
        Ok(lane.inbox.clone())
    }

    /// The service ends the `dir` lane: once. What the end moves: the lane
    /// still headless, or the body being fed.
    fn end_lane(&mut self, dir: Dir) -> Result<Ended, ServiceError> {
        let lane = self.lane(dir);
        if lane.sent == Sent::End {
            return Err(ServiceError::Protocol(format!(
                "a second {} end",
                dir.as_str()
            )));
        }
        let headless = lane.sent == Sent::Nothing;
        lane.sent = Sent::End;
        Ok(if headless {
            Ended::Headless(lane.out.take())
        } else {
            Ended::Body(lane.inbox.take())
        })
    }
}

/// What a lane's end from the service moves.
enum Ended {
    /// No head came: the lane, to end headless, when the stream carries one.
    Headless(Option<LaneTx>),
    /// The body being fed, if the service sends one.
    Body(Option<Arc<Inbox>>),
}

fn dir_index(dir: Dir) -> usize {
    match dir {
        Dir::Request => 0,
        Dir::Response => 1,
    }
}

/// Why a body stopped short of its end on its way to the service.
pub(super) enum Lost {
    /// The stream ended under it, or the service reads no more of it.
    Stream,
    /// The body itself failed.
    Body(BodyError),
}

/// How a stream ends.
pub(super) enum End<'a> {
    /// Nothing to tell anyone: the service ended both its lanes, an
    /// observe stream sent all it had, or an `open` was given up before
    /// its message went.
    Quiet,
    /// The service failed it. `reset` tells the service, when it has not
    /// already closed or reset the stream itself.
    Failed { e: ServiceError, reset: Reset },
    /// roxy gave up on it (the layer was torn down, a missed deadline):
    /// the service is told, and nothing is logged as its fault.
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

    /// Ends the stream, once: nothing more goes on it, its place on the
    /// connection is released, the reader forgets it, and whoever was
    /// waiting on it (a body being fed) learns how it ended. False if it
    /// had already ended, in which case `end` is not told to anyone.
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
        let (why, reset) = match end {
            End::Quiet => {
                drop(ending.outs);
                return true;
            }
            End::Failed { e, reset } => {
                // Recorded before anything learns of the end: the exchange
                // may finish on a body aborted here before any answer is
                // read. The layer is torn down with it, which cuts what it
                // produced and lets go of what it held.
                if self.mode == AddonMode::Enforce {
                    self.st
                        .layer_failed(self.index, StackError::Service(e.clone()));
                }
                let message = e.to_string();
                (message.clone(), (reset == Reset::Send).then_some(message))
            }
            End::Abandoned(why) => (why.to_owned(), Some(why.to_owned())),
        };
        if let Some(message) = reset
            && self.wire.reset()
        {
            self.link.shared.send_ctl(self.id, &Out::Reset { message });
        }
        for inbox in ending.inboxes.into_iter().flatten() {
            inbox.abort(why.clone());
        }
        // The lanes the service never put a head on are the layer's to
        // settle: cut by its teardown, or ended as nothing.
        drop(ending.outs);
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

    /// The layer was torn down under the stream: the service is told why.
    pub(crate) fn abandon(&self) {
        self.reset(self.st.layer_torn_down_why(self.index));
    }

    /// Cancelled once the service's response head is on its lane.
    pub(crate) fn answered(&self) -> CancellationToken {
        self.answered.clone()
    }

    /// Resolves once the stream has ended, however it did.
    pub(crate) async fn until_ended(&self) {
        self.ended.cancelled().await;
    }

    /// An observe stream: roxy sent all it had, and the service has
    /// `within` to end both its lanes (or reset) before roxy fails it.
    /// How it ended, if it failed.
    pub(crate) async fn finish(&self, within: Duration) -> Result<(), ServiceError> {
        if tokio::time::timeout(within, self.ended.cancelled())
            .await
            .is_err()
        {
            self.fail(ServiceError::Timeout("first_byte_timeout"), Reset::Send);
        }
        lock(&self.state).observe_error.take().map_or(Ok(()), Err)
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
    pub(crate) async fn send(&self, m: &Out) -> bool {
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
    /// `None` once the stream ended or the service reads no more of it.
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
                () = self.stop_in[dir_index(dir)].cancelled() => return None,
            }
        }
    }

    /// Streams one lane to the service: head, body frames (as credit
    /// allows), trailers, end. A body that fails ends its lane with the
    /// failure, never as complete; the stream, and the service's own
    /// lanes, go on. Stops at the stream's end, or when the service reads
    /// no more of it.
    pub(crate) async fn pump(&self, dir: Dir, head: Out, body: Body) {
        if self.stop_in[dir_index(dir)].is_cancelled() {
            return;
        }
        if !self.send(&head).await {
            return;
        }
        // Nothing to read (and an empty observer copy may never be ended).
        let error = if body.is_end_stream() {
            None
        } else {
            match self.pump_body(dir, body).await {
                Ok(()) => None,
                Err(Lost::Stream) => return,
                Err(Lost::Body(e)) => Some(e.to_string()),
            }
        };
        self.send(&end_of(dir, error)).await;
    }

    pub(crate) async fn stopped(&self, dir: Dir) {
        self.stop_in[dir_index(dir)].cancelled().await;
    }

    /// Sends `body`'s frames in direction `dir`, as credit allows. The
    /// stream ending, or the service's `stop`, drops the body where it
    /// is, a frame still to come notwithstanding: nothing reads what it
    /// would yield.
    pub(super) async fn pump_body(&self, dir: Dir, mut body: Body) -> Result<(), Lost> {
        use http_body::Body as _;
        let stopped = &self.stop_in[dir_index(dir)];
        loop {
            let frame = tokio::select! {
                biased;
                () = self.ended.cancelled() => return Err(Lost::Stream),
                () = stopped.cancelled() => return Err(Lost::Stream),
                f = std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)) => f,
            };
            let mut d = match frame {
                None => return Ok(()),
                Some(Err(e)) => return Err(Lost::Body(e)),
                Some(Ok(f)) => match f.into_data() {
                    Ok(d) => d,
                    Err(f) => {
                        if let Ok(trailers) = f.into_trailers() {
                            let headers = super::super::pairs(&trailers);
                            if !self.send(&Out::Trailers { dir, headers }).await {
                                return Err(Lost::Stream);
                            }
                        }
                        continue;
                    }
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

    /// Roxy reads no more of the `dir` lane the service sends: the
    /// service is told, and the lane's end is no longer owed. Skipped
    /// while the layer is being torn down: the teardown drops every lane,
    /// and it resets the stream itself with the reason.
    pub(super) fn stop(&self, dir: Dir) {
        if self.st.layer_torn(self.index) {
            return;
        }
        let done = {
            let mut s = lock(&self.state);
            if s.ended() {
                return;
            }
            s.lane(dir).stopped = true;
            !s.waiting()
        };
        self.link.shared.send_ctl(self.id, &Out::Stop { dir });
        if done {
            self.settle(End::Quiet);
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
        if self.mode == AddonMode::Enforce && lane.sent != Sent::Head {
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
        let inbox = lane.inbox.clone();
        drop(s);
        let Some(inbox) = inbox else {
            // An observe stream's bytes, or a lane roxy stopped reading.
            if self.mode == AddonMode::Observe {
                self.grant(dir, n);
            }
            return;
        };
        let mut q = lock(&inbox.q);
        if q.dropped {
            return;
        }
        q.buf.extend_from_slice(b);
        drop(q);
        inbox.ready.notify_one();
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
            In::Stop { dir } => {
                self.stop_in[dir_index(dir)].cancel();
                return;
            }
            In::Request { .. }
            | In::RequestEnd { .. }
            | In::Response { .. }
            | In::ResponseEnd { .. }
            | In::Trailers { .. } => {}
        }
        let result = self.lane_event(m);
        let done = !lock(&self.state).waiting();
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

    /// A head, trailers or an end from the service: checked against the
    /// lane's grammar, and put on the lane the service produces in that
    /// direction (an observe stream's go nowhere).
    fn lane_event(self: &Arc<Self>, m: In) -> Result<(), ServiceError> {
        let limits = &self.st.snap.limits;
        match m {
            In::Request {
                method,
                url,
                headers,
            } => {
                let method = http::Method::from_bytes(method.as_bytes())
                    .map_err(|_| ServiceError::Protocol(format!("invalid method {method:?}")))?;
                let uri: http::Uri = url
                    .parse()
                    .map_err(|_| ServiceError::Protocol(format!("invalid url {url:?}")))?;
                let headers = super::super::header_map(&headers, limits.max_headers)?;
                let declared = super::super::declared_length(&headers)?;
                let out = lock(&self.state).head(Dir::Request)?;
                let Some(out) = out else {
                    return Ok(());
                };
                let mut r = http::Request::new(());
                *r.method_mut() = method;
                *r.uri_mut() = uri;
                *r.headers_mut() = headers;
                let head = Head::Request(r.into_parts().0);
                if self.head_only(Dir::Request) {
                    // The body the layer did not see goes on with the head
                    // it passed on, framed as it came.
                    let bound = lock(&self.held_request).take().unwrap_or_default();
                    out.whole(head, bound);
                    return Ok(());
                }
                // On an upgrade the forwarded body is the client's side of
                // the WebSocket, for as long as it is open: no cap.
                let cap = if self.st.is_upgrade() {
                    u64::MAX
                } else {
                    limits.max_request_body_bytes
                };
                self.feed(Dir::Request, out.head(head, declared, cap));
                Ok(())
            }
            In::Response { status, headers } => {
                let status = http::StatusCode::from_u16(status)
                    .map_err(|e| ServiceError::Protocol(e.to_string()))?;
                let headers = super::super::header_map(&headers, limits.max_headers)?;
                let declared = super::super::declared_length(&headers)?;
                let out = lock(&self.state).head(Dir::Response)?;
                self.answered.cancel();
                let Some(out) = out else {
                    return Ok(());
                };
                let mut r = http::Response::new(());
                *r.status_mut() = status;
                *r.headers_mut() = headers;
                let head = Head::Response(r.into_parts().0);
                if self.head_only(Dir::Response) {
                    // The body from upstream goes on with the head the
                    // service passed on, when that is the same response:
                    // the same status. A different status is an answer of
                    // the service's own, whole.
                    let bound = lock(&self.held_response).take();
                    let body = match bound {
                        Some((s, body)) if s == status => body,
                        _ => Body::empty(),
                    };
                    out.whole(head, body);
                    return Ok(());
                }
                // A `101`'s body is the upstream's side of the WebSocket,
                // uncapped like the request's.
                let cap = if status == http::StatusCode::SWITCHING_PROTOCOLS && self.st.is_upgrade()
                {
                    u64::MAX
                } else {
                    limits.max_response_body_bytes
                };
                self.feed(Dir::Response, out.head(head, declared, cap));
                Ok(())
            }
            In::Trailers { dir, headers } => {
                if self.head_only(dir) {
                    return Err(ServiceError::Protocol(format!(
                        "trailers of a head-only {} body",
                        dir.as_str()
                    )));
                }
                let headers = super::super::header_map(&headers, limits.max_headers)?;
                let inbox = lock(&self.state).trailers(dir)?;
                if let Some(inbox) = inbox {
                    lock(&inbox.q).trailers = Some(headers);
                    inbox.ready.notify_one();
                }
                Ok(())
            }
            In::RequestEnd { error } => self.lane_end(Dir::Request, error),
            In::ResponseEnd { error } => self.lane_end(Dir::Response, error),
            In::Credit { .. } | In::Reset { .. } | In::Stop { .. } | In::Call(_) => Ok(()),
        }
    }

    /// The service ended the `dir` lane. With `error` the lane is cut
    /// where it is, never complete: a lane the service cuts of its own
    /// accord is its abort, not its fault. Before a head, the end carries
    /// nothing: no forward, or no answer.
    fn lane_end(&self, dir: Dir, error: Option<String>) -> Result<(), ServiceError> {
        // The service's text, bounded as its reset messages are.
        let error = error.map(|why| why.chars().take(200).collect::<String>());
        let ended = lock(&self.state).end_lane(dir)?;
        match ended {
            Ended::Headless(out) => {
                if let Some(out) = out {
                    match error {
                        Some(why) => out.cut_headless(why),
                        None => out.end_headless(),
                    }
                }
                Ok(())
            }
            Ended::Body(Some(inbox)) => {
                let mut q = lock(&inbox.q);
                match error {
                    Some(why) => q.abort = Some(why),
                    None => q.end = true,
                }
                drop(q);
                inbox.ready.notify_one();
                Ok(())
            }
            // A head-only lane carries no body to cut, and an observe
            // stream's lanes go nowhere.
            Ended::Body(None) => {
                if error.is_some() && self.mode == AddonMode::Enforce {
                    return Err(ServiceError::Protocol(format!(
                        "an error on the {}_end of a head-only body",
                        dir.as_str()
                    )));
                }
                Ok(())
            }
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
            let work = self.clone().host_calls(rx);
            if self.mode == AddonMode::Enforce {
                self.st.chain().spawn(work);
            } else {
                // Observers may finish after the real exchange; their
                // host calls cannot change its decision or final record.
                tokio::spawn(work);
            }
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

    /// Starts feeding the `dir` body from the stream into `body`.
    fn feed(self: &Arc<Self>, dir: Dir, body: super::super::super::chain::LaneBody) {
        // Observers have no outgoing lane; only enforcing streams reach here.
        debug_assert_eq!(self.mode, AddonMode::Enforce);
        let inbox = Arc::new(Inbox::default());
        lock(&self.state).lane(dir).inbox = Some(inbox.clone());
        self.st
            .chain()
            .spawn(feeder(self.clone(), inbox, body, dir));
    }
}

/// The end of the `dir` lane, with `error` when the body stopped short.
pub(super) fn end_of(dir: Dir, error: Option<String>) -> Out {
    match dir {
        Dir::Request => Out::RequestEnd { error },
        Dir::Response => Out::ResponseEnd { error },
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
/// message sent. An enforce stream takes the layer's two lanes, an
/// observe stream none. Cancel-safe: given up part way, it holds nothing,
/// and the lanes stay with the caller.
pub(crate) async fn open(
    st: &Arc<StackFlow>,
    index: usize,
    svc: &ServiceSpec,
    mode: AddonMode,
    lanes: &mut Option<Lanes>,
) -> Result<Arc<Stream>, ServiceError> {
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
    let held_request = lanes
        .as_ref()
        .map(|l| l.held_request.clone())
        .unwrap_or_default();
    let held_response = lanes
        .as_ref()
        .map(|l| l.held_response.clone())
        .unwrap_or_default();
    let stream = {
        let mut s = lock(&link.shared.streams);
        if s.failed || s.next_id == u32::MAX {
            return Err(ServiceError::Closed("the connection closed".into()));
        }
        let id = s.next_id;
        s.next_id += 1;
        let lanes = lanes.take();
        let stream = Arc::new(Stream {
            id,
            link: link.clone(),
            st: st.clone(),
            index,
            mode,
            state: Mutex::new(StreamState::new(lanes, Some(slot))),
            more_credit: Notify::new(),
            ended: CancellationToken::new(),
            answered: CancellationToken::new(),
            stop_in: [CancellationToken::new(), CancellationToken::new()],
            held_request,
            held_response,
            wire: Arc::default(),
            calls: Mutex::new(None),
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
    Ok(stream)
}

/// The `open` message: what a WASM layer reads through `flow.current`
/// and `flow.config`, so the service can key its state on (flow, layer).
pub(super) fn open_message(st: &Arc<StackFlow>, index: usize, mode: AddonMode) -> Out {
    let addon = &st.snap.addons[index];
    let info = StackHost::silent(st.clone(), index, None, None).flow_info();
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

    fn enforce() -> StreamState {
        StreamState::new(None, None)
    }

    /// A stream ends when the service has ended both its lanes, in either
    /// order, a headless end counting; a lane roxy stopped reading is no
    /// longer owed. A second end of a lane is a protocol error.
    #[test]
    fn a_stream_ends_when_both_its_lanes_have() {
        let mut s = enforce();
        assert!(s.waiting());
        assert!(matches!(
            s.end_lane(Dir::Response),
            Ok(Ended::Headless(None))
        ));
        assert!(s.waiting(), "the request lane is still owed");
        assert!(s.end_lane(Dir::Response).is_err(), "a second end");
        s.head(Dir::Request).unwrap();
        assert!(matches!(s.end_lane(Dir::Request), Ok(Ended::Body(None))));
        assert!(!s.waiting());

        let mut s = enforce();
        s.lane(Dir::Request).stopped = true;
        assert!(s.waiting());
        s.end_lane(Dir::Response).unwrap();
        assert!(!s.waiting());
        assert!(s.end(None).is_some());
        assert!(s.end(None).is_none(), "ends once");
        assert!(s.ended());
    }

    /// Each head comes once, before its lane's end; trailers once, after
    /// the head and before the end.
    #[test]
    fn each_head_comes_once_before_its_end() {
        let mut s = enforce();
        s.head(Dir::Response).unwrap();
        assert!(s.head(Dir::Response).is_err(), "a second response");
        s.head(Dir::Request).unwrap();
        assert!(s.head(Dir::Request).is_err(), "a second request");
        assert!(s.trailers(Dir::Request).is_ok());
        assert!(s.trailers(Dir::Request).is_err(), "trailers twice");
        s.end_lane(Dir::Request).unwrap();
        assert!(s.trailers(Dir::Request).is_err(), "trailers after the end");

        let mut s = enforce();
        assert!(s.trailers(Dir::Response).is_err(), "trailers before a head");
        s.end_lane(Dir::Response).unwrap();
        assert!(s.head(Dir::Response).is_err(), "a head after the end");
    }
}
