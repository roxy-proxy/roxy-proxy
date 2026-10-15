//! Per-exchange shared state and the adapter that hands a guest-produced
//! body to the proxy.
//!
//! The adapter is where "fail closed" meets streaming. A body coming out of
//! the guest (the request it passes to `next`, the response it answers with)
//! never ends cleanly once the exchange has failed: the adapter checks the
//! exchange status before every frame, and the driver always records a
//! failure before it drops the store. A response body additionally holds
//! its end until the guest's handler has returned, so a trap after the last
//! byte still fails it. A body the guest leaves unfinished is cut where it
//! stopped. For a forwarded request or answer, this is the guest's own
//! abort, not a layer fault. An unfinished endpoint request body does fail
//! the exchange, because the endpoint call must carry a complete request.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body::{Body as HttpBody, Frame};
use roxy_http::{Body, BodyError};
use tokio::sync::watch;

use crate::error::LayerError;
use crate::host::LayerHost;

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
    /// Odd while `next` runs upstream of the layer, so the head clock is stopped;
    /// each return of `next` makes it even again.
    upstream: watch::Sender<u64>,
    /// The guest has answered: its response head is out of its hands, and
    /// the head clock has nothing left to time.
    answered: watch::Sender<bool>,
    /// Guest driver and its children, retained through future destruction.
    pub(crate) tasks: tokio_util::task::TaskTracker,
    /// Scope cancellation remains meaningful after the guest has settled:
    /// a body-finish worker can still be waiting for its consumer.
    pub(crate) cancelled: tokio_util::sync::CancellationToken,
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
        let tasks = tokio_util::task::TaskTracker::new();
        tasks.close();
        Arc::new(Self {
            host,
            status: watch::Sender::new(Status::default()),
            upstream: watch::Sender::new(0),
            answered: watch::Sender::new(false),
            tasks,
            cancelled: tokio_util::sync::CancellationToken::new(),
        })
    }

    /// `next` started: the layer's time stops.
    pub(crate) fn next_started(&self) {
        self.upstream.send_modify(|n| *n += 1);
    }

    /// `next` returned its response head (or the guest abandoned it): the
    /// layer's time runs again, with a whole budget for the response head.
    pub(crate) fn next_returned(&self) {
        self.upstream.send_modify(|n| *n += 1);
    }

    /// Resolves once the layer has held a head for `limit` of its own time:
    /// the request head from the clock's start, less the `used` already
    /// spent on it (starting the instance), and the response head from the
    /// moment `next` returns. The clock does not run while `next` is upstream
    /// of the layer, and stops for good once the layer has answered.
    pub(crate) fn head_clock(
        &self,
        limit: Duration,
        used: Duration,
    ) -> impl Future<Output = ()> + Send + 'static {
        let mut upstream = self.upstream.subscribe();
        let mut answered = self.answered.subscribe();
        async move {
            let mut left = limit.saturating_sub(used);
            loop {
                // The sender lives as long as the exchange; gone, nothing
                // is left to time.
                if upstream.wait_for(|n| n % 2 == 0).await.is_err() {
                    return std::future::pending().await;
                }
                // Any change means `next` ran: it may have started and
                // returned between two looks, so a change restarts the
                // clock whether or not `next` is still upstream.
                let changed = async { upstream.changed().await.is_ok() };
                let answered = async { answered.wait_for(|a| *a).await.is_ok() };
                tokio::select! {
                    _ = answered => return std::future::pending().await,
                    () = tokio::time::sleep(left) => return,
                    ok = changed => {
                        if !ok {
                            return std::future::pending().await;
                        }
                        left = limit;
                    }
                }
            }
        }
    }

    /// The guest answered.
    pub(crate) fn answered(&self) {
        self.answered.send_replace(true);
    }

    pub(crate) fn has_answered(&self) -> bool {
        *self.answered.borrow()
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
}

type Settled = Pin<Box<dyn Future<Output = Result<(), LayerError>> + Send>>;

/// A body produced by the guest, handed to the proxy.
#[allow(clippy::struct_excessive_bools)] // independent poll-state flags
pub(crate) struct FromGuest {
    inner: Body,
    shared: Arc<ExchangeShared>,
    /// An endpoint request body: an error in it fails the exchange. The
    /// exchange's own bodies pass their errors on as the guest's own cut.
    endpoint: bool,
    /// Hold the end of the body until the exchange settles.
    hold_end: bool,
    settled: Option<Settled>,
    settled_ok: bool,
    inner_done: bool,
    finished: bool,
}

impl FromGuest {
    /// The request body the guest passed to `next`.
    pub(crate) fn next_request(inner: Body, shared: Arc<ExchangeShared>) -> Body {
        Self::build(inner, shared, false, false)
    }

    /// The request body the guest passed to an endpoint.
    pub(crate) fn endpoint_request(inner: Body, shared: Arc<ExchangeShared>) -> Body {
        Self::build(inner, shared, true, false)
    }

    /// The response body the guest answered with.
    pub(crate) fn response(inner: Body, shared: Arc<ExchangeShared>) -> Body {
        Self::build(inner, shared, false, true)
    }

    fn build(inner: Body, shared: Arc<ExchangeShared>, endpoint: bool, hold_end: bool) -> Body {
        let settled: Settled = Box::pin(shared.wait_settled());
        let known_length = inner.known_length();
        let body = FromGuest {
            inner,
            shared,
            endpoint,
            hold_end,
            settled: Some(settled),
            settled_ok: false,
            inner_done: false,
            finished: false,
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
                    if this.endpoint {
                        this.shared.fail(LayerError::InvalidRequest(format!(
                            "body stream failed: {e}"
                        )));
                        return this.fail_frame();
                    }
                    this.finished = true;
                    return Poll::Ready(Some(Err(e)));
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
        // An end that is not held is reached once the inner's is: an empty
        // `next` body is then complete before its first poll, and the body
        // bypassing the layer keeps its framing rather than being spliced
        // onto an own body still counted as open.
        self.finished || (!self.hold_end && self.inner.is_end_stream())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{
        EndpointError, EndpointPermit, FlowInfo, HostError, LayerRequest, LayerResponse, LogLevel,
        TagError,
    };
    use tokio::time::Instant;

    /// A host that hears of failures and nothing else.
    struct Deaf;

    #[async_trait::async_trait]
    impl LayerHost for Deaf {
        async fn next(&self, _: LayerRequest) -> Result<Option<LayerResponse>, HostError> {
            unreachable!()
        }
        fn respond(&self, _: LayerResponse) {
            unreachable!()
        }
        async fn endpoint_permit(&self) -> Result<EndpointPermit, EndpointError> {
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
        fn quarantine(&self) -> Result<(), HostError> {
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
        assert_eq!(s.wait_settled().await, Ok(()));
    }

    /// Each head gets the whole limit: time upstream is not counted, and the
    /// request-phase hold does not eat into the response-phase one.
    #[tokio::test(start_paused = true)]
    async fn the_head_clock_restarts_when_next_returns() {
        let s = shared();
        let clock = s.head_clock(Duration::from_secs(10), Duration::from_secs(2));
        tokio::pin!(clock);
        let start = Instant::now();
        let s2 = s.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(7)).await;
            s2.next_started();
            tokio::time::sleep(Duration::from_secs(100)).await;
            s2.next_returned();
        });
        clock.await;
        // 2s of instance start and 7s before `next` leave 1s of the first
        // budget; 100s upstream (not counted); then the full 10s again.
        assert_eq!(start.elapsed().as_secs(), 117);
    }

    /// A `next` that returns before the clock has seen it start still
    /// restarts the clock.
    #[tokio::test(start_paused = true)]
    async fn an_instant_next_restarts_the_head_clock() {
        let s = shared();
        let clock = s.head_clock(Duration::from_secs(10), Duration::ZERO);
        tokio::pin!(clock);
        let start = Instant::now();
        let s2 = s.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(7)).await;
            s2.next_started();
            s2.next_returned();
        });
        clock.await;
        assert_eq!(start.elapsed().as_secs(), 17);
    }

    #[tokio::test(start_paused = true)]
    async fn the_head_clock_expires_before_next() {
        let s = shared();
        let clock = s.head_clock(Duration::from_secs(10), Duration::from_secs(2));
        tokio::pin!(clock);
        let start = Instant::now();
        clock.await;
        assert_eq!(start.elapsed().as_secs(), 8);
    }

    /// The clock stops for good once the layer has answered.
    #[tokio::test(start_paused = true)]
    async fn the_head_clock_stops_at_the_answer() {
        let s = shared();
        let clock = s.head_clock(Duration::from_secs(10), Duration::ZERO);
        tokio::pin!(clock);
        let s2 = s.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            s2.answered();
        });
        assert!(
            tokio::time::timeout(Duration::from_secs(60), clock)
                .await
                .is_err()
        );
    }
}
