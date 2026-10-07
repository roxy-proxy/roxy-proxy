//! Per-exchange shared state and the body adapters between the proxy's
//! [`Body`] and the guest's `wasi:http` bodies.
//!
//! The adapters are where "fail closed" meets streaming:
//!
//! * A body coming *out of* the guest (the request it passes to `next`, the
//!   response it answers with) never ends cleanly once the exchange has
//!   failed. `wasmtime-wasi-http` ends a guest body cleanly when its sender
//!   is dropped, which is also what happens when the store is dropped after
//!   a trap; the adapter checks the exchange status first, and the driver
//!   always records the failure before it drops the store. A response body
//!   additionally holds its end until the guest's handler has returned, so
//!   a trap after the last byte still fails it.
//! * The request body passed to `next` that the guest leaves unfinished is
//!   always cut. It fails the exchange only if the guest is still waiting on
//!   `next`'s response: a guest that dropped the response future (or already
//!   has the response) has abandoned the forwarded request, and may answer
//!   itself. See [`ExchangeShared::cut_next`].

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::Bytes;
use http_body::{Body as HttpBody, Frame, SizeHint};
use roxy_http::{Body, BodyError};
use tokio::sync::watch;
use tokio::task::AbortHandle;
use tokio::time::Instant;
use wasmtime_wasi_http::Error as WasiError;

use crate::error::LayerError;

/// Which way a body flows through the layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dir {
    /// Client → upstream.
    Request,
    /// Upstream → client.
    Response,
}

#[derive(Debug, Clone, Default)]
struct Status {
    /// The first failure; it decides the exchange's outcome.
    failure: Option<LayerError>,
    /// The guest's handler has returned (or the exchange was torn down).
    done: bool,
}

/// State shared by the exchange driver, the host-call implementations and
/// the body adapters.
#[derive(Debug)]
pub(crate) struct ExchangeShared {
    status: watch::Sender<Status>,
    /// `next` is running below the layer: the head clock is paused.
    below: watch::Sender<bool>,
    /// Why the request body passed to `next` was cut, if it was.
    next_cut: OnceLock<String>,
}

impl ExchangeShared {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            status: watch::Sender::new(Status::default()),
            below: watch::Sender::new(false),
            next_cut: OnceLock::new(),
        })
    }

    /// `next` started (`true`) or returned its response head (`false`).
    pub(crate) fn set_below(&self, below: bool) {
        self.below.send_replace(below);
    }

    /// Resolves once the layer has run for `limit` of its own time: the
    /// clock stops while `next` is below it. Drop it once the layer's
    /// response head is set.
    pub(crate) fn head_clock(&self, limit: Duration) -> impl Future<Output = ()> + Send + 'static {
        let mut below = self.below.subscribe();
        async move {
            let mut left = limit;
            loop {
                // The sender lives as long as the exchange; gone, nothing
                // is left to time.
                if below.wait_for(|b| !*b).await.is_err() {
                    return std::future::pending().await;
                }
                let started = Instant::now();
                let went_below = async { below.wait_for(|b| *b).await.is_ok() };
                tokio::select! {
                    () = tokio::time::sleep(left) => return,
                    ok = went_below => {
                        if !ok {
                            return std::future::pending().await;
                        }
                        left = left.saturating_sub(started.elapsed());
                    }
                }
            }
        }
    }

    /// The request body passed to `next` was cut. The forwarded body never
    /// ends cleanly either way; whether the layer failed is decided when
    /// `next` resolves ([`Self::check_next`]). A guest that dropped the
    /// response future never sees it resolve: its task is aborted, so the
    /// cut is an abandonment and the layer's own answer stands.
    pub(crate) fn cut_next(&self, msg: String) {
        let _ = self.next_cut.set(msg);
    }

    /// Called as `next` resolves, before the guest can see its result.
    /// A cut before this point happened while the guest was still waiting
    /// on the response: the layer failed. A cut after it (the guest has the
    /// response, or abandoned it) is not a failure.
    pub(crate) fn check_next(&self) -> Result<(), LayerError> {
        match self.next_cut.get() {
            Some(msg) => {
                let err = LayerError::InvalidRequest(msg.clone());
                self.fail(err.clone());
                Err(err)
            }
            None => Ok(()),
        }
    }

    /// Records a failure. The first one wins; failures after the exchange
    /// settled are ignored.
    pub(crate) fn fail(&self, err: LayerError) {
        self.status.send_if_modified(|s| {
            if s.failure.is_none() && !s.done {
                s.failure = Some(err);
                true
            } else {
                false
            }
        });
    }

    /// Marks the exchange settled: the handler returned and the driver
    /// decided the outcome.
    pub(crate) fn settle(&self) {
        self.status.send_if_modified(|s| {
            let changed = !s.done;
            s.done = true;
            changed
        });
    }

    pub(crate) fn failure(&self) -> Option<LayerError> {
        self.status.borrow().failure.clone()
    }

    pub(crate) fn is_settled(&self) -> bool {
        let s = self.status.borrow();
        s.done || s.failure.is_some()
    }

    /// Resolves with the first failure.
    pub(crate) fn wait_failure(&self) -> impl Future<Output = LayerError> + Send + 'static {
        let mut rx = self.status.subscribe();
        async move {
            match rx.wait_for(|s| s.failure.is_some()).await {
                Ok(s) => s.failure.clone().unwrap_or(LayerError::Cancelled),
                Err(_) => LayerError::Cancelled,
            }
        }
    }

    /// Resolves when the exchange has failed or settled, with its outcome so
    /// far (`Ok` only once settled without a failure).
    pub(crate) fn wait_settled(
        &self,
    ) -> impl Future<Output = Result<(), LayerError>> + Send + 'static {
        let mut rx = self.status.subscribe();
        async move {
            match rx.wait_for(|s| s.failure.is_some() || s.done).await {
                Ok(s) => s.failure.clone().map_or(Ok(()), Err),
                Err(_) => Err(LayerError::Cancelled),
            }
        }
    }

    pub(crate) fn outcome(&self) -> LayerOutcome {
        LayerOutcome(self.status.subscribe())
    }
}

/// The outcome of an exchange, for logging after the response head has
/// gone out. Found in the extensions of every [`crate::LayerResponse`] a
/// layer returns.
#[derive(Debug, Clone)]
pub struct LayerOutcome(watch::Receiver<Status>);

impl LayerOutcome {
    /// Waits until the layer has finished the exchange. `Err` is the
    /// failure that cut the response body.
    pub async fn wait(mut self) -> Result<(), LayerError> {
        match self.0.wait_for(|s| s.failure.is_some() || s.done).await {
            Ok(s) => s.failure.clone().map_or(Ok(()), Err),
            Err(_) => Err(LayerError::Cancelled),
        }
    }

    /// The failure, if one has been recorded yet.
    pub fn failure(&self) -> Option<LayerError> {
        self.0.borrow().failure.clone()
    }
}

/// Aborts the exchange driver when the caller abandons the exchange (both
/// the `handle` future and the response body are gone) before it settled.
#[derive(Debug)]
pub(crate) struct CancelGuard {
    pub(crate) abort: AbortHandle,
    pub(crate) shared: Arc<ExchangeShared>,
}

impl Drop for CancelGuard {
    fn drop(&mut self) {
        if !self.shared.is_settled() {
            self.shared.fail(LayerError::Cancelled);
            self.abort.abort();
        }
    }
}

fn to_wasi_error(err: &BodyError, dir: Dir) -> WasiError {
    match err {
        BodyError::TooLarge { limit } => match dir {
            Dir::Request => WasiError::HttpRequestBodySize(Some(*limit)),
            Dir::Response => WasiError::HttpResponseBodySize(Some(*limit)),
        },
        BodyError::Timeout => WasiError::ConnectionReadTimeout,
        BodyError::Incomplete => match dir {
            Dir::Request => WasiError::ConnectionTerminated,
            Dir::Response => WasiError::HttpResponseIncomplete,
        },
        other @ (BodyError::LengthMismatch
        | BodyError::Closed
        | BodyError::Abandoned
        | BodyError::Invalid(_)
        | BodyError::Upstream(_)
        | BodyError::Stopped
        | BodyError::Undecodable(_)
        | BodyError::BudgetExhausted) => WasiError::InternalError(Some(other.to_string())),
    }
}

/// A proxy [`Body`] handed into the guest (the request it handles, the
/// response `next` returned, an endpoint response).
pub(crate) struct IntoGuest {
    inner: Body,
    dir: Dir,
    failed: bool,
}

impl IntoGuest {
    pub(crate) fn new(inner: Body, dir: Dir) -> Self {
        Self {
            inner,
            dir,
            failed: false,
        }
    }
}

impl HttpBody for IntoGuest {
    type Data = Bytes;
    type Error = WasiError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, WasiError>>> {
        if self.failed {
            return Poll::Ready(None);
        }
        let this = &mut *self;
        match ready!(Pin::new(&mut this.inner).poll_frame(cx)) {
            Some(Ok(frame)) => Poll::Ready(Some(Ok(frame))),
            // An observer's copy whose real body the stack dropped unread
            // ends where the reading stopped. Nobody is at fault, and the
            // guest learns what became of the request from `next`.
            Some(Err(BodyError::Abandoned)) => {
                this.failed = true;
                Poll::Ready(None)
            }
            Some(Err(e)) => {
                this.failed = true;
                Poll::Ready(Some(Err(to_wasi_error(&e, this.dir))))
            }
            None => Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.failed || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

type GuestBody = wasmtime_wasi_http::p2::body::HyperOutgoingBody;
type Settled = Pin<Box<dyn Future<Output = Result<(), LayerError>> + Send>>;

/// A body produced by the guest, handed to the proxy.
#[allow(clippy::struct_excessive_bools)] // independent poll-state flags
pub(crate) struct FromGuest {
    inner: GuestBody,
    shared: Arc<ExchangeShared>,
    /// The exchange's own request or response; `None` for an endpoint
    /// request. Decides how a broken stream is reported.
    dir: Option<Dir>,
    /// The request body passed to `next`: an inner error is a cut, settled
    /// by [`ExchangeShared::check_next`], not a failure here.
    next: bool,
    /// Hold the end of the body until the exchange settles.
    hold_end: bool,
    settled: Option<Settled>,
    settled_ok: bool,
    inner_done: bool,
    finished: bool,
    _cancel: Option<Arc<CancelGuard>>,
}

impl FromGuest {
    /// The request body the guest passed to `next`.
    pub(crate) fn next_request(inner: GuestBody, shared: Arc<ExchangeShared>) -> Body {
        Self::build(inner, shared, Some(Dir::Request), true, false, None)
    }

    /// The request body the guest passed to an endpoint.
    pub(crate) fn endpoint_request(inner: GuestBody, shared: Arc<ExchangeShared>) -> Body {
        Self::build(inner, shared, None, false, false, None)
    }

    /// The response body the guest answered with.
    pub(crate) fn response(
        inner: GuestBody,
        shared: Arc<ExchangeShared>,
        cancel: Arc<CancelGuard>,
    ) -> Body {
        Self::build(
            inner,
            shared,
            Some(Dir::Response),
            false,
            true,
            Some(cancel),
        )
    }

    fn build(
        inner: GuestBody,
        shared: Arc<ExchangeShared>,
        dir: Option<Dir>,
        next: bool,
        hold_end: bool,
        cancel: Option<Arc<CancelGuard>>,
    ) -> Body {
        let settled: Settled = Box::pin(shared.wait_settled());
        let body = FromGuest {
            inner,
            shared,
            dir,
            next,
            hold_end,
            settled: Some(settled),
            settled_ok: false,
            inner_done: false,
            finished: false,
            _cancel: cancel,
        };
        Body::wrap_native(body, u64::MAX, None)
    }

    fn fail_frame(&mut self) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        self.finished = true;
        Poll::Ready(Some(Err(BodyError::Stopped)))
    }
}

impl HttpBody for FromGuest {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = &mut *self;
        if this.finished {
            return Poll::Ready(None);
        }
        if this.shared.failure().is_some() {
            return this.fail_frame();
        }
        if !this.inner_done {
            match Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => return Poll::Ready(Some(Ok(frame))),
                Poll::Ready(Some(Err(e))) => {
                    let msg = format!("body stream failed: {e}");
                    if this.next {
                        this.shared.cut_next(msg);
                    } else {
                        this.shared.fail(match this.dir {
                            Some(Dir::Response) => LayerError::InvalidResponse(msg),
                            _ => LayerError::InvalidRequest(msg),
                        });
                    }
                    return this.fail_frame();
                }
                Poll::Ready(None) => {
                    // A sender dropped by a failed (or failing) store also
                    // ends here; re-check after the inner end.
                    if this.shared.failure().is_some() {
                        return this.fail_frame();
                    }
                    if !this.hold_end || this.settled_ok {
                        this.finished = true;
                        return Poll::Ready(None);
                    }
                    this.inner_done = true;
                }
                Poll::Pending => {}
            }
        }
        // Wake on failure (or, for a held end, on settling).
        if let Some(settled) = this.settled.as_mut() {
            match settled.as_mut().poll(cx) {
                Poll::Ready(Ok(())) => {
                    this.settled = None;
                    this.settled_ok = true;
                    if this.inner_done {
                        this.finished = true;
                        return Poll::Ready(None);
                    }
                    // Settled cleanly while frames may still be queued:
                    // keep reading them.
                    cx.waker().wake_by_ref();
                }
                Poll::Ready(Err(_)) => {
                    this.settled = None;
                    return this.fail_frame();
                }
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }

    fn is_end_stream(&self) -> bool {
        self.finished
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn first_failure_wins_and_settle_freezes() {
        let s = ExchangeShared::new();
        s.fail(LayerError::NoResponse);
        s.fail(LayerError::Cancelled);
        assert_eq!(s.failure(), Some(LayerError::NoResponse));
        assert_eq!(s.wait_settled().await, Err(LayerError::NoResponse));

        let s = ExchangeShared::new();
        s.settle();
        s.fail(LayerError::Cancelled);
        assert_eq!(s.failure(), None);
        assert_eq!(s.outcome().wait().await, Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn the_head_clock_stops_while_next_is_below() {
        let s = ExchangeShared::new();
        let clock = s.head_clock(Duration::from_secs(10));
        tokio::pin!(clock);
        let start = Instant::now();
        let s2 = s.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(4)).await;
            s2.set_below(true);
            tokio::time::sleep(Duration::from_secs(100)).await;
            s2.set_below(false);
        });
        clock.await;
        // 4s before `next`, 100s below (not counted), then the last 6s.
        assert_eq!(start.elapsed().as_secs(), 110);
    }

    #[tokio::test]
    async fn into_guest_passes_errors_on() {
        let (tx, body) = Body::channel(u64::MAX, None);
        tx.abort(BodyError::Incomplete);
        let body = IntoGuest::new(body, Dir::Request);
        assert!(body.collect().await.is_err());
    }

    /// A body abandoned by its consumer ends for the guest where it stood,
    /// with the bytes that did flow; a body that failed does not.
    #[tokio::test]
    async fn into_guest_ends_an_abandoned_body_cleanly() {
        let (mut tx, body) = Body::channel(u64::MAX, Some(4));
        tx.send_data(Bytes::from_static(b"ab")).await.unwrap();
        tx.abort(BodyError::Abandoned);
        let body = IntoGuest::new(body, Dir::Request);
        let got = body.collect().await.unwrap().to_bytes();
        assert_eq!(got, Bytes::from_static(b"ab"));
    }
}
