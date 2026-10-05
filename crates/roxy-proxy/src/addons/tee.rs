//! Observe mode: a layer gets a copy of both streams and can
//! neither change nor delay the real ones.
//!
//! The copy is fed as the real body is forwarded and buffered for the
//! observer, which sees every body in full for as long as it keeps up. An
//! observer with more than `limits.max_observer_lag_bytes` of copy unread
//! has it cut (it sees a body error) and an `observer_lagged` event is
//! logged; the real traffic never waits. This is deliberately lossy: the observer is not the audit log,
//! which keeps its own backpressure. An observer that drops its copy is
//! not lagging: the rest is simply not copied.

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
use crate::flowlog::FlowEvent;
use crate::watch::Dir;

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

/// Reports a lagging observer once per direction.
struct Lag {
    st: Arc<StackFlow>,
    layer: String,
    direction: Dir,
    reported: AtomicBool,
}

impl Lag {
    fn report(&self) {
        if !self.reported.swap(true, Ordering::Relaxed) {
            self.st.shared.sink.emit(&FlowEvent::ObserverLagged {
                ts: chrono::Utc::now(),
                flow: self.st.flow.to_string(),
                layer: self.layer.clone(),
                direction: self.direction.as_str().to_owned(),
            });
        }
    }
}

/// A frame of the copy, or how it ended.
enum Msg {
    Data(Bytes),
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
    budget: u64,
    /// Bytes queued so far, against the real body's declared length.
    sent: u64,
    known: Option<u64>,
}

impl CopySender {
    fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }

    /// Queues `data` for the observer; `Err` when it would take the queue
    /// past the budget or the observer has dropped its copy.
    fn try_push(&mut self, data: Bytes) -> Result<(), ()> {
        if data.is_empty() {
            return Ok(());
        }
        let len = u64::try_from(data.len()).unwrap_or(u64::MAX);
        let pending = self.pending.load(Ordering::Relaxed);
        if pending.saturating_add(len) > self.budget {
            return Err(());
        }
        self.pending.fetch_add(len, Ordering::Relaxed);
        self.sent = self.sent.saturating_add(len);
        self.tx.send(Msg::Data(data)).map_err(drop)
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
/// has not yet read.
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
            Some(Msg::Data(d)) => {
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
    /// The copy could not take a frame: the observer fell behind, or let
    /// go of its copy. Only the first is worth a word.
    fn cut(&mut self) {
        if let Some(c) = self.copy.take() {
            let gone = c.is_closed();
            c.cut(BodyError::Stopped);
            if !gone {
                self.lag.report();
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
                    if copy.try_push(data.clone()).is_err() {
                        this.cut();
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
/// best-effort copy buffered up to `budget` bytes.
fn tee(body: Body, lag: Arc<Lag>, budget: u64) -> (Body, Body) {
    let known = body.known_length();
    let pending = Arc::new(AtomicU64::new(0));
    let (tx, rx) = mpsc::unbounded_channel();
    // The copy declares the real body's length, so an empty one reads as
    // empty even if nobody polls the real body to its end.
    let copy = Body::wrap_native(
        CopyBody {
            rx,
            pending: pending.clone(),
        },
        u64::MAX,
        known,
    );
    let real = Body::wrap_native(
        Tee {
            inner: body,
            copy: Some(CopySender {
                tx,
                pending,
                budget,
                sent: 0,
                known,
            }),
            lag,
        },
        u64::MAX,
        known,
    );
    (real, copy)
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
    let budget = st.snap.limits.max_observer_lag_bytes;
    let (real_body, copy_body) = tee(body, lag(&st, &addon.name, Dir::Request), budget);
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
            let budget = st.snap.limits.max_observer_lag_bytes;
            let (real_body, copy_body) = tee(body, lag(&st, name, Dir::Response), budget);
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
