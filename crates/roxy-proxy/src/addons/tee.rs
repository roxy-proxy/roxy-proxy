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
use http_body_util::BodyExt as _;
use roxy_http::{Body, BodyError};
use roxy_wasm::{HostError, LayerRequest, LayerResponse};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

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
    shared: Arc<Shared>,
    flow: String,
    layer: String,
    direction: Dir,
    reported: AtomicBool,
}

impl Lag {
    fn report(&self, reason: &str) {
        if !self.reported.swap(true, Ordering::Relaxed) {
            self.shared.sink.emit(&FlowEvent::ObserverLagged {
                ts: chrono::Utc::now(),
                flow: self.flow.clone(),
                layer: self.layer.clone(),
                direction: self.direction.as_str().to_owned(),
                reason: reason.to_owned(),
            });
        }
    }
}

/// Fires when a copy ends short: cut, or its real body gone before the
/// end. Carried in the copy's extensions, since the error frame queues
/// behind the copy's unread bytes, where a reader that is waiting on
/// something else (credit, say) would not see it.
#[derive(Clone)]
pub(crate) struct CopyCut(CancellationToken);

impl CopyCut {
    pub(crate) async fn cancelled(&self) {
        self.0.cancelled().await;
    }
}

/// A frame of the copy, or how it ended.
enum Msg {
    /// A frame and its share of the budget, which the observer's read
    /// gives back; a frame dropped unread gives it back the same way.
    Data(Bytes, BufferLease),
    End,
    /// The copy ends short, with why: the real body's own error, or
    /// [`BodyError::Abandoned`] when the real body was dropped unread
    /// (refused at the head, say). An observer tells the two apart.
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
    cut: CancellationToken,
    finished: bool,
}

impl Drop for CopySender {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        if self.complete() {
            let _ = self.tx.send(Msg::End);
        } else {
            let _ = self.tx.send(Msg::Cut(BodyError::Abandoned));
            self.cut.cancel();
        }
    }
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

    fn finish(mut self) {
        let _ = self.tx.send(Msg::End);
        self.finished = true;
    }

    fn cut(mut self, e: BodyError) {
        let _ = self.tx.send(Msg::Cut(e));
        self.finished = true;
        self.cut.cancel();
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
            // The sender always says how the copy ended; a bare close is a
            // bug, not a complete body.
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
            Some(Err(e)) => {
                if let Some(c) = this.copy.take() {
                    c.cut(e.clone());
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
fn tee(st: &StackFlow, body: Body, lag: Arc<Lag>) -> (Body, Body, CopyCut) {
    tee_with(
        st.shared.clone(),
        st.snap.limits.max_observer_lag_bytes,
        body,
        lag,
    )
}

/// [`tee`] with the budget and window spelt out.
fn tee_with(
    shared: Arc<Shared>,
    lag_bytes: u64,
    body: Body,
    lag: Arc<Lag>,
) -> (Body, Body, CopyCut) {
    let known = body.known_length();
    let (sender, copy) = copy(shared, lag_bytes, known);
    let cut = CopyCut(sender.cut.clone());
    let real = Tee {
        inner: body,
        copy: Some(sender),
        lag,
    };
    (Body::wrap_native(real, u64::MAX, known), copy, cut)
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
        cut: CancellationToken::new(),
        finished: false,
    };
    (sender, body)
}

fn lag(st: &StackFlow, layer: &str, direction: Dir) -> Arc<Lag> {
    Arc::new(Lag {
        shared: st.shared.clone(),
        flow: st.flow.to_string(),
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
    let (real_body, copy_body, cut) = tee(&st, body, lag(&st, &addon.name, Dir::Request));
    let mut copy_req = http::Request::new(copy_body);
    copy_req.extensions_mut().insert(cut);
    *copy_req.method_mut() = parts.method.clone();
    *copy_req.uri_mut() = parts.uri.clone();
    *copy_req.headers_mut() = parts.headers.clone();
    let real_req = http::Request::from_parts(parts, real_body);

    let (tx, rx) = oneshot::channel();
    let next = ObserverNext {
        rx: Mutex::new(Some(rx)),
    };
    // Whether the real exchange failed below the observer, once known.
    let (below_failed, below_outcome) = oneshot::channel();
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
            return forward(st, index, &addon.name, real_req, tx, below_failed).await;
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
                discard(resp.into_body()).await;
                match outcome {
                    Some(o) => o.wait().await,
                    None => Ok(()),
                }
            }
            Err(e) => Err(e),
        };
        if let Err(e) = result {
            // The exchange failing below the observer, at the head or in
            // the body, ends its copies and its `next` early; what it makes
            // of that is a consequence, logged against the party at fault,
            // not as its own failure. A `forward` dropped before the head
            // is the client gone, which is nobody's failure.
            if below_outcome.await.unwrap_or(true) || observer_st.failed_below(index).await {
                return;
            }
            super::emit_layer_error(
                &observer_st,
                &observer_addon.name,
                &e,
                super::AddonMode::Observe,
            );
        }
    });

    forward(st, index, &addon.name, real_req, tx, below_failed).await
}

/// Reads `body` to its end or first error, holding one frame at a time.
async fn discard(mut body: Body) {
    while body.frame().await.is_some_and(|f| f.is_ok()) {}
}

/// The real exchange below observer `index`; the observer gets a copy of
/// the response through `tx`, or the failure below. `below_failed` learns
/// which, first.
async fn forward(
    st: Arc<StackFlow>,
    index: usize,
    name: &str,
    real_req: LayerRequest,
    tx: oneshot::Sender<Result<LayerResponse, HostError>>,
    below_failed: oneshot::Sender<bool>,
) -> Result<LayerResponse, HostError> {
    let real = super::below(st.clone(), index, real_req).await;
    let _ = below_failed.send(real.is_err());
    match real {
        Ok(resp) => {
            let (parts, body) = resp.into_parts();
            let (real_body, copy_body, cut) = tee(&st, body, lag(&st, name, Dir::Response));
            let mut copy = http::Response::new(copy_body);
            copy.extensions_mut().insert(cut);
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

    fn test_lag(kit: &Kit) -> Arc<Lag> {
        Arc::new(Lag {
            shared: kit.server.shared().clone(),
            flow: "flow".to_owned(),
            layer: "o".to_owned(),
            direction: Dir::Request,
            reported: AtomicBool::new(false),
        })
    }

    /// How a copy ends says what became of the real body. Dropped unread
    /// short of its declared length, the copy is abandoned, not failed;
    /// dropped once the declared length has all been queued, the copy is
    /// complete, however little of the real body was polled.
    #[tokio::test]
    async fn a_real_body_dropped_short_abandons_its_copy() {
        let kit = Kit::builder().start().await;
        let shared = kit.server.shared().clone();

        let (mut tx, body) = Body::channel(u64::MAX, Some(4));
        tx.send_data(Bytes::from_static(b"ab")).await.unwrap();
        let (mut real, mut copy, cut) = tee_with(shared.clone(), 100, body, test_lag(&kit));
        let first = real.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(first, Bytes::from_static(b"ab"));
        drop(real);
        cut.cancelled().await;
        let got = copy.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(got, Bytes::from_static(b"ab"));
        let end = copy.frame().await.unwrap().unwrap_err();
        assert_eq!(end, BodyError::Abandoned);

        let (_tx, body) = Body::channel(u64::MAX, Some(0));
        let (real, mut copy, _cut) = tee_with(shared, 100, body, test_lag(&kit));
        drop(real);
        assert!(copy.frame().await.is_none());
    }

    /// The real body failing (the client gone mid-upload, say) ends the
    /// copy with that failure, which is the observer's to tell from a copy
    /// the stack abandoned.
    #[tokio::test]
    async fn a_real_body_failing_fails_its_copy_the_same_way() {
        let kit = Kit::builder().start().await;
        let (mut tx, body) = Body::channel(u64::MAX, None);
        tx.send_data(Bytes::from_static(b"ab")).await.unwrap();
        tx.abort(BodyError::Incomplete);
        let (mut real, mut copy, cut) =
            tee_with(kit.server.shared().clone(), 100, body, test_lag(&kit));
        real.frame().await.unwrap().unwrap();
        assert_eq!(
            real.frame().await.unwrap().unwrap_err(),
            BodyError::Incomplete
        );
        cut.cancelled().await;
        copy.frame().await.unwrap().unwrap();
        assert_eq!(
            copy.frame().await.unwrap().unwrap_err(),
            BodyError::Incomplete
        );
    }

    /// A long body of `left` frames that samples the process's anonymous
    /// memory as it ends, while whoever reads it still holds what it kept.
    #[cfg(target_os = "linux")]
    struct Sampled {
        left: usize,
        rss_at_end: Arc<AtomicU64>,
    }

    #[cfg(target_os = "linux")]
    static FRAME: [u8; 1 << 20] = [7; 1 << 20];

    #[cfg(target_os = "linux")]
    impl HttpBody for Sampled {
        type Data = Bytes;
        type Error = BodyError;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
            if self.left == 0 {
                self.rss_at_end.store(rss_anon(), Ordering::SeqCst);
                return Poll::Ready(None);
            }
            self.left -= 1;
            Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(&FRAME)))))
        }
    }

    #[cfg(target_os = "linux")]
    fn rss_anon() -> u64 {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let line = status.lines().find(|l| l.starts_with("RssAnon:")).unwrap();
        let kib: u64 = line.split_whitespace().nth(1).unwrap().parse().unwrap();
        kib * 1024
    }

    /// Discarding an observer's answer keeps none of it: a 512 MiB body
    /// leaves the process no bigger by the time it ends. Frames are static,
    /// so any growth is the reader's own buffering; the margin absorbs
    /// other tests running alongside.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn discarding_a_long_body_costs_no_memory() {
        let rss_at_end = Arc::new(AtomicU64::new(0));
        let body = Body::wrap_native(
            Sampled {
                left: 512,
                rss_at_end: rss_at_end.clone(),
            },
            u64::MAX,
            None,
        );
        let before = rss_anon();
        discard(body).await;
        let grown = rss_at_end.load(Ordering::SeqCst).saturating_sub(before);
        assert!(grown < 128 << 20, "grew by {} MiB", grown >> 20);
    }
}
