//! Observe mode: a layer gets a copy of both streams and can
//! neither change nor delay the real ones.
//!
//! The copy is fed as the real body is forwarded and buffered for the
//! observer, which sees every body in full for as long as it keeps up. An
//! observer with more than `limits.max_observer_lag_bytes` of copy unread
//! has it cut (it sees a body error) and an `observer_lagged` event is
//! logged; the real traffic never waits. The bytes a copy has queued are
//! charged to the buffer budget frame by frame, as they queue, and given
//! back as the observer reads them; a copy whose next frame the budget
//! cannot cover is cut the same way. This is deliberately lossy: the
//! observer is not the audit log, which keeps its own backpressure. An
//! observer that drops its copy is not lagging: the rest is simply not
//! copied.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use http_body::{Body as HttpBody, Frame, SizeHint};
use roxy_http::{Body, BodyError};
use roxy_wasm::{HostError, LayerRequest, LayerResponse};
use tokio::sync::{mpsc, oneshot};

use super::StackFlow;
use crate::budget::{self, BufferLease};
use crate::flowlog::FlowEvent;
use crate::server::Shared;
use crate::watch::Dir;

/// The copy outgrew `max_observer_lag_bytes`.
const BEHIND: &str = "observer_behind";

/// What an observer's `next` returns: the copy of the real response.
pub(crate) struct ObserverNext {
    rx: Mutex<Option<oneshot::Receiver<Result<LayerResponse, HostError>>>>,
}

impl ObserverNext {
    pub(crate) async fn response(&self) -> Result<LayerResponse, HostError> {
        let rx = self
            .rx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .ok_or_else(|| HostError::new("next called twice"))?;
        rx.await
            .unwrap_or_else(|_| Err(HostError::new("the exchange ended")))
    }
}

/// Reports a cut copy once per direction.
struct Lag {
    st: Arc<StackFlow>,
    layer: String,
    direction: Dir,
    reported: AtomicBool,
}

impl Lag {
    fn report(&self, reason: &str) {
        if !self.reported.swap(true, Ordering::Relaxed) {
            self.st.shared.sink.emit(&FlowEvent::ObserverLagged {
                ts: chrono::Utc::now(),
                flow: self.st.flow.to_string(),
                layer: self.layer.clone(),
                direction: self.direction.as_str().to_owned(),
                reason: reason.to_owned(),
            });
        }
    }
}

/// A frame of the copy, or how it ended.
enum Msg {
    /// A frame and its share of the budget, which the observer's read
    /// gives back; a frame dropped unread gives it back the same way.
    Data(Bytes, BufferLease),
    End,
    Cut(BodyError),
}

/// The feeding end of a copy. Frames queue without ever blocking the real
/// body; the queue is bounded in bytes, not frames, so an observer is cut
/// for being far behind, never for taking small frames slowly.
struct CopySender {
    tx: mpsc::UnboundedSender<Msg>,
    /// Bytes queued and not yet read by the observer.
    pending: Arc<AtomicU64>,
    /// `max_observer_lag_bytes`.
    window: u64,
    /// Bytes queued so far, against the real body's declared length.
    sent: u64,
    known: Option<u64>,
    /// The budget the queued bytes are charged to.
    shared: Arc<Shared>,
}

impl CopySender {
    fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }

    /// Queues `data` for the observer; `Err` names the reason it could
    /// not: the queue would pass the window, the budget cannot cover the
    /// frame, or the observer has dropped its copy.
    fn try_push(&mut self, data: Bytes) -> Result<(), &'static str> {
        if data.is_empty() {
            return Ok(());
        }
        let len = u64::try_from(data.len()).unwrap_or(u64::MAX);
        let pending = self.pending.load(Ordering::Relaxed);
        if pending.saturating_add(len) > self.window {
            return Err(BEHIND);
        }
        let Some(lease) = self.shared.reserve_buffer(len) else {
            return Err(budget::EXHAUSTED);
        };
        self.pending.fetch_add(len, Ordering::Relaxed);
        self.sent = self.sent.saturating_add(len);
        self.tx.send(Msg::Data(data, lease)).map_err(|_| BEHIND)
    }

    /// Whether the declared length has all been queued. A consumer that
    /// knows the length may drop the real body without polling it to its
    /// end, so the copy cannot wait for that to be finished.
    fn complete(&self) -> bool {
        self.known == Some(self.sent)
    }

    fn finish(self) {
        let _ = self.tx.send(Msg::End);
    }

    fn cut(self, e: BodyError) {
        let _ = self.tx.send(Msg::Cut(e));
    }
}

/// The observer's copy: what the real body has produced and the observer
/// has not yet read. Dropping it drops the queued frames, and their budget
/// with them.
struct CopyBody {
    rx: mpsc::UnboundedReceiver<Msg>,
    pending: Arc<AtomicU64>,
}

impl HttpBody for CopyBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        Poll::Ready(match ready!(self.rx.poll_recv(cx)) {
            Some(Msg::Data(d, lease)) => {
                drop(lease);
                let len = u64::try_from(d.len()).unwrap_or(u64::MAX);
                self.pending.fetch_sub(len, Ordering::Relaxed);
                Some(Ok(Frame::data(d)))
            }
            Some(Msg::End) => None,
            Some(Msg::Cut(e)) => Some(Err(e)),
            // The real body was dropped before it ended.
            None => Some(Err(BodyError::Incomplete)),
        })
    }
}

struct Tee {
    inner: Body,
    copy: Option<CopySender>,
    lag: Arc<Lag>,
}

impl Tee {
    /// The copy cannot go on for `reason`, unless the observer has let go
    /// of it already, which is not worth a word.
    fn cut(&mut self, reason: &str) {
        if let Some(c) = self.copy.take() {
            let gone = c.is_closed();
            c.cut(BodyError::Stopped);
            if !gone {
                self.lag.report(reason);
            }
        }
    }
}

impl HttpBody for Tee {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = &mut *self;
        let frame = ready!(Pin::new(&mut this.inner).poll_frame(cx));
        match &frame {
            Some(Ok(f)) => {
                if let (Some(data), Some(copy)) = (f.data_ref(), this.copy.as_mut()) {
                    if let Err(reason) = copy.try_push(data.clone()) {
                        this.cut(reason);
                    } else if copy.complete()
                        && let Some(c) = this.copy.take()
                    {
                        c.finish();
                    }
                }
            }
            Some(Err(_)) => {
                if let Some(c) = this.copy.take() {
                    c.cut(BodyError::Stopped);
                }
            }
            None => {
                if let Some(c) = this.copy.take() {
                    c.finish();
                }
            }
        }
        Poll::Ready(frame)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Splits `body` into the real body (unchanged, never delayed) and a
/// best-effort copy buffered up to `lag_bytes`, charged to the buffer
/// budget as it queues.
fn tee(st: &StackFlow, body: Body, lag: Arc<Lag>) -> (Body, Body) {
    let known = body.known_length();
    let (sender, copy) = copy(
        st.shared.clone(),
        st.snap.limits.max_observer_lag_bytes,
        known,
    );
    let real = Tee {
        inner: body,
        copy: Some(sender),
        lag,
    };
    (Body::wrap_native(real, u64::MAX, known), copy)
}

/// A copy's two ends: the sender the real body feeds, and the body the
/// observer reads, which declares the real body's length so an empty one
/// reads as empty even if nobody polls the real body to its end.
fn copy(shared: Arc<Shared>, lag_bytes: u64, known: Option<u64>) -> (CopySender, Body) {
    let pending = Arc::new(AtomicU64::new(0));
    let (tx, rx) = mpsc::unbounded_channel();
    let body = Body::wrap_native(
        CopyBody {
            rx,
            pending: pending.clone(),
        },
        u64::MAX,
        known,
    );
    let sender = CopySender {
        tx,
        pending,
        window: lag_bytes,
        sent: 0,
        known,
        shared,
    };
    (sender, body)
}

fn lag(st: &Arc<StackFlow>, layer: &str, direction: Dir) -> Arc<Lag> {
    Arc::new(Lag {
        st: st.clone(),
        layer: layer.to_owned(),
        direction,
        reported: AtomicBool::new(false),
    })
}

/// Runs observe-mode layer `index`: it gets copies, the real exchange
/// continues below it untouched.
pub(crate) async fn observe(
    st: Arc<StackFlow>,
    index: usize,
    req: LayerRequest,
) -> Result<LayerResponse, HostError> {
    let addon = st.snap.addons[index].clone();
    let (parts, body) = req.into_parts();
    let (real_body, copy_body) = tee(&st, body, lag(&st, &addon.name, Dir::Request));
    let mut copy_req = http::Request::new(copy_body);
    *copy_req.method_mut() = parts.method.clone();
    *copy_req.uri_mut() = parts.uri.clone();
    *copy_req.headers_mut() = parts.headers.clone();
    let real_req = http::Request::from_parts(parts, real_body);

    let (tx, rx) = oneshot::channel();
    let next = ObserverNext {
        rx: Mutex::new(Some(rx)),
    };
    let observer_st = st.clone();
    let observer_addon = addon.clone();
    let layer = match &addon.kind {
        super::AddonImpl::Wasm(l) => l.clone(),
        super::AddonImpl::Service(svc) => {
            let svc = svc.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    super::service::observe(&observer_st, index, &svc, copy_req, &next).await
                {
                    super::emit_stack_error(
                        &observer_st,
                        &observer_addon.name,
                        &super::StackError::Service(e),
                        super::AddonMode::Observe,
                    );
                }
            });
            return forward(st, index, &addon.name, real_req, tx).await;
        }
    };
    let host = Arc::new(super::host::StackHost {
        st: st.clone(),
        index,
        observer: Some(next),
    });
    tokio::spawn(async move {
        let result = match layer.handle(host, copy_req).await {
            Ok(resp) => {
                // Whatever it answers is discarded, but read to the end so
                // the layer's own failures surface.
                let outcome = resp.extensions().get::<roxy_wasm::LayerOutcome>().cloned();
                drop(resp.into_body().collect_up_to(u64::MAX).await);
                match outcome {
                    Some(o) => o.wait().await,
                    None => Ok(()),
                }
            }
            Err(e) => Err(e),
        };
        if let Err(e) = result {
            super::emit_layer_error(
                &observer_st,
                &observer_addon.name,
                &e,
                super::AddonMode::Observe,
            );
        }
    });

    forward(st, index, &addon.name, real_req, tx).await
}

/// The real exchange below observer `index`; the observer gets a copy of
/// the response through `tx`.
async fn forward(
    st: Arc<StackFlow>,
    index: usize,
    name: &str,
    real_req: LayerRequest,
    tx: oneshot::Sender<Result<LayerResponse, HostError>>,
) -> Result<LayerResponse, HostError> {
    let real = super::below(st.clone(), index, real_req).await;
    match real {
        Ok(resp) => {
            let (parts, body) = resp.into_parts();
            let (real_body, copy_body) = tee(&st, body, lag(&st, name, Dir::Response));
            let mut copy = http::Response::new(copy_body);
            *copy.status_mut() = parts.status;
            *copy.headers_mut() = parts.headers.clone();
            let _ = tx.send(Ok(copy));
            Ok(http::Response::from_parts(parts, real_body))
        }
        Err(e) => {
            let _ = tx.send(Err(e.clone()));
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use http_body_util::BodyExt as _;

    use super::*;
    use crate::testkit::Kit;

    /// A copy charges the budget by what it has queued: each frame as it
    /// queues, given back when the observer reads it or drops the copy,
    /// and a frame the budget cannot cover is refused without charging.
    #[tokio::test]
    async fn a_copy_charges_the_budget_by_what_it_has_queued() {
        let kit = Kit::builder()
            .limits(|l| l.max_buffered_bytes = 25)
            .start()
            .await;
        let shared = kit.server.shared().clone();
        let frame = Bytes::from_static(b"0123456789");
        let (mut sender, mut body) = copy(shared.clone(), 100, None);
        sender.try_push(frame.clone()).unwrap();
        sender.try_push(frame.clone()).unwrap();
        assert_eq!(shared.buffered(), 20);
        assert_eq!(sender.try_push(frame.clone()), Err(budget::EXHAUSTED));
        assert_eq!(shared.buffered(), 20);

        let read = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(read, frame);
        assert_eq!(shared.buffered(), 10);
        sender.try_push(frame.clone()).unwrap();
        assert_eq!(shared.buffered(), 20);

        drop(body);
        assert_eq!(shared.buffered(), 0);
        assert!(sender.try_push(frame.clone()).is_err());
        assert_eq!(shared.buffered(), 0);

        // The window is checked first, so a frame past it costs nothing.
        let (mut sender, _body) = copy(shared.clone(), 15, None);
        sender.try_push(frame.clone()).unwrap();
        assert_eq!(sender.try_push(frame), Err(BEHIND));
        assert_eq!(shared.buffered(), 10);
    }
}
