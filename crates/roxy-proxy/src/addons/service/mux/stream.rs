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
use super::window::{Feed, OBSERVE_GRANT, WINDOW};
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

#[derive(Default)]
pub(super) struct StreamState {
    pub(super) first: Option<oneshot::Sender<Result<First, Unanswered>>>,
    pub(super) second: Option<oneshot::Sender<Result<LayerResponse, Unanswered>>>,
    /// The request body and the response body, each on its own.
    pub(super) req: Feed,
    pub(super) res: Feed,
    /// Why an observe stream failed, for its driver to log.
    pub(super) observe_error: Option<ServiceError>,
    pub(super) slot: Option<Reservation>,
    /// Settled: nothing more is sent or delivered on it.
    pub(super) ended: bool,
}

impl StreamState {
    pub(super) fn feed(&mut self, dir: Dir) -> &mut Feed {
        match dir {
            Dir::Request => &mut self.req,
            Dir::Response => &mut self.res,
        }
    }

    /// The service still owes something: an answer, or the end of a body
    /// it is sending.
    pub(super) fn waiting(&self) -> bool {
        self.req.inbox.is_some()
            || self.res.inbox.is_some()
            || self.first.is_some()
            || self.second.is_some()
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
    pub(super) fn name(&self) -> String {
        self.st.snap.addons[self.index].name.clone()
    }

    /// Ends the stream, once: nothing more goes on it, its place on the
    /// connection is released, the reader forgets it, and whoever was
    /// waiting on it (a pending answer, the body being fed) learns how it
    /// ended.
    pub(super) fn settle(&self, end: End<'_>) {
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
        for inbox in inboxes.into_iter().flatten() {
            inbox.abort(&e);
        }
        if let Some(tx) = first {
            let _ = tx.send(Err(e));
        } else if let Some(tx) = second
            && !tx.is_closed()
        {
            let _ = tx.send(Err(e));
        } else if let Some((name, err)) = blame {
            // The head has gone on: the failure is logged here, since no
            // answer carries it.
            super::super::super::emit_stack_error(&self.st, &name, &err, AddonMode::Enforce);
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
        lock(&self.state).observe_error.take().map_or(Ok(()), Err)
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
    pub(super) fn bytes(self: &Arc<Self>, dir: Dir, b: &[u8]) {
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
    pub(super) fn control(self: &Arc<Self>, m: In) {
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

    pub(super) fn answer(self: &Arc<Self>, s: &mut StreamState, m: In) -> Result<(), ServiceError> {
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
                let headers = super::super::header_map(&headers)?;
                // On an upgrade the forwarded body is the client's side of
                // the WebSocket, for as long as it is open: no cap.
                let cap = if self.st.is_upgrade() {
                    u64::MAX
                } else {
                    limits.max_request_body_bytes
                };
                let (body_tx, body) = Body::channel(cap, super::super::declared_length(&headers)?);
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
                Self::give(s, r, "response")?;
                s.res.inbox = Some(self.feed(body_tx, Dir::Response));
                Ok(())
            }
            In::Deny { status, message } => {
                let r = super::super::deny_response(status, message)?;
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
    pub(super) fn give(
        s: &mut StreamState,
        r: LayerResponse,
        what: &str,
    ) -> Result<(), ServiceError> {
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
    pub(super) fn feed(self: &Arc<Self>, tx: BodySender, dir: Dir) -> Arc<Inbox> {
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
pub(super) fn open_message(st: &StackFlow, layer: &str, mode: AddonMode) -> Out {
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
