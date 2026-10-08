//! Per-exchange shared state and the adapter that hands a guest-produced
//! body to the proxy.
//!
//! The adapter is where "fail closed" meets streaming. A body coming out of
//! the guest (the request it passes to `next`, the response it answers with)
//! never ends cleanly once the exchange has failed: the adapter checks the
//! exchange status before every frame, and the driver always records a
//! failure before it drops the store. A response body additionally holds
//! its end until the guest's handler has returned, so a trap after the last
//! byte still fails it. The request body passed to `next` that the guest
//! leaves unfinished is always cut; it fails the exchange only if the guest
//! is still waiting on `next`'s response (a guest that dropped the pending
//! response, or already has the response, has abandoned the forwarded
//! request and may answer itself; see [`ExchangeShared::cut_next`]).

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body::{Body as HttpBody, Frame};
use roxy_http::{Body, BodyError};
use tokio::sync::watch;
use tokio::task::AbortHandle;
use tokio::time::Instant;

use crate::error::LayerError;
use crate::host::LayerHost;

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
pub(crate) struct ExchangeShared {
    /// Told of the first failure as it is recorded.
    host: Arc<dyn LayerHost>,
    status: watch::Sender<Status>,
    /// `next` is running below the layer: the head clock is paused.
    below: watch::Sender<bool>,
    /// Why the request body passed to `next` was cut, if it was.
    next_cut: OnceLock<String>,
}

impl std::fmt::Debug for ExchangeShared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExchangeShared")
            .field("status", &*self.status.borrow())
            .finish_non_exhaustive()
    }
}

impl ExchangeShared {
    pub(crate) fn new(host: Arc<dyn LayerHost>) -> Arc<Self> {
        Arc::new(Self {
            host,
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
    /// settled are ignored. The host hears of it under the status lock, so
    /// nothing reading the status can act on the failure before the host
    /// has it.
    pub(crate) fn fail(&self, err: LayerError) {
        self.status.send_if_modified(|s| {
            if s.failure.is_none() && !s.done {
                self.host.failed(&err);
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

type Settled = Pin<Box<dyn Future<Output = Result<(), LayerError>> + Send>>;

/// A body produced by the guest, handed to the proxy.
#[allow(clippy::struct_excessive_bools)] // independent poll-state flags
pub(crate) struct FromGuest {
    inner: Body,
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
    pub(crate) fn next_request(inner: Body, shared: Arc<ExchangeShared>) -> Body {
        Self::build(inner, shared, Some(Dir::Request), true, false, None)
    }

    /// The request body the guest passed to an endpoint.
    pub(crate) fn endpoint_request(inner: Body, shared: Arc<ExchangeShared>) -> Body {
        Self::build(inner, shared, None, false, false, None)
    }

    /// The response body the guest answered with.
    pub(crate) fn response(
        inner: Body,
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
        inner: Body,
        shared: Arc<ExchangeShared>,
        dir: Option<Dir>,
        next: bool,
        hold_end: bool,
        cancel: Option<Arc<CancelGuard>>,
    ) -> Body {
        let settled: Settled = Box::pin(shared.wait_settled());
        let known_length = inner.known_length();
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
        Body::wrap_native(body, u64::MAX, known_length)
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
                // An observer's copy the stack dropped unread, passed
                // through: it ends where the reading stopped, at nobody's
                // fault.
                Poll::Ready(Some(Err(BodyError::Abandoned))) => {
                    this.finished = true;
                    return Poll::Ready(None);
                }
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
                    // Re-check after the inner end: the failure may have
                    // landed while the last frame was in flight.
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
    use crate::host::{
        EndpointError, FlowInfo, HostError, LayerRequest, LayerResponse, LogLevel, TagError,
    };

    /// A host that hears of failures and nothing else.
    struct Deaf;

    #[async_trait::async_trait]
    impl LayerHost for Deaf {
        async fn next(&self, _: LayerRequest) -> Result<LayerResponse, HostError> {
            unreachable!()
        }
        async fn endpoint_call(
            &self,
            _: &str,
            _: LayerRequest,
        ) -> Result<LayerResponse, EndpointError> {
            unreachable!()
        }
        fn flow_info(&self) -> FlowInfo {
            unreachable!()
        }
        fn add_tag(&self, _: String) -> Result<(), TagError> {
            unreachable!()
        }
        fn log(&self, _: LogLevel, _: &str) {}
        async fn record(&self, _: String, _: String) -> Result<(), HostError> {
            unreachable!()
        }
        async fn state_get(&self, _: String) -> Result<Option<String>, HostError> {
            unreachable!()
        }
        async fn state_put(
            &self,
            _: String,
            _: String,
            _: Option<u64>,
        ) -> Result<Result<(), String>, HostError> {
            unreachable!()
        }
        async fn metric_get(&self, _: String, _: Vec<String>) -> Result<Option<i64>, HostError> {
            unreachable!()
        }
        fn failed(&self, _: &LayerError) {}
    }

    fn shared() -> Arc<ExchangeShared> {
        ExchangeShared::new(Arc::new(Deaf))
    }

    #[tokio::test]
    async fn first_failure_wins_and_settle_freezes() {
        let s = shared();
        s.fail(LayerError::NoResponse);
        s.fail(LayerError::Cancelled);
        assert_eq!(s.failure(), Some(LayerError::NoResponse));
        assert_eq!(s.wait_settled().await, Err(LayerError::NoResponse));

        let s = shared();
        s.settle();
        s.fail(LayerError::Cancelled);
        assert_eq!(s.failure(), None);
        assert_eq!(s.outcome().wait().await, Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn the_head_clock_stops_while_next_is_below() {
        let s = shared();
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
}
