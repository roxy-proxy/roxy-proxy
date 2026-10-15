//! Keep the flow context available while the core stage processes the
//! upstream exchange. The HTTP transport handler retrieves it for the final
//! log only after lane consumers, drivers, and accounting have finished.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Notify;

use super::{StackFlow, lock};
use crate::pipeline::FlowCx;

/// Exclusive ownership of the context during core-stage processing. Drop
/// returns it to the stack, including when that processing is cancelled.
pub(super) struct Lease {
    pub(super) st: Arc<StackFlow>,
    pub(super) cx: Option<FlowCx>,
    /// The core ran to its outcome.
    pub(super) done: bool,
}

impl Lease {
    pub(super) fn cx(&mut self) -> &mut FlowCx {
        self.cx.as_mut().expect("leased until dropped")
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        let Some(mut cx) = self.cx.take() else {
            return;
        };
        drop(cx.request_delivery.take());
        if !self.done && cx.record.decision.is_some() {
            // The rules had decided and the request was on its way.
            cx.record
                .reason
                .get_or_insert_with(|| "upstream_aborted".to_owned());
        }
        self.st.loan.give_back(cx);
    }
}

/// Where the context is while the stack runs, and what waits on it.
pub(super) struct Loan {
    cx: std::sync::Mutex<Option<FlowCx>>,
    /// Something a waiter checks has changed: the context came back, or a
    /// layer's part in the exchange moved on.
    changed: Notify,
    /// The transport handler took the context back: nothing in the stack sees it
    /// again.
    gone: AtomicBool,
}

impl Loan {
    pub(super) fn new() -> Self {
        Self {
            cx: std::sync::Mutex::new(None),
            changed: Notify::new(),
            gone: AtomicBool::new(false),
        }
    }

    pub(super) fn park(&self, cx: FlowCx) {
        *lock(&self.cx) = Some(cx);
    }

    /// Takes the context to lend it. `None` if it is already lent.
    pub(super) fn take(&self) -> Option<FlowCx> {
        lock(&self.cx).take()
    }

    pub(super) fn give_back(&self, cx: FlowCx) {
        *lock(&self.cx) = Some(cx);
        self.changed();
    }

    /// Wakes whoever waits on the context.
    pub(super) fn changed(&self) {
        self.changed.notify_waiters();
    }

    /// Waits until `ready` yields: checked now, and again each time
    /// something changes. The wait is registered before the check, so a
    /// change between the two is not missed.
    pub(super) async fn wait_until<T>(&self, mut ready: impl FnMut(&Self) -> Option<T>) -> T {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if let Some(v) = ready(self) {
                return v;
            }
            changed.await;
        }
    }

    /// The context, once the core has returned it or if it never took
    /// it; a core still running keeps it. `None` once the transport handler has it: it
    /// is not coming back.
    pub(super) async fn returned(&self) -> Option<FlowCx> {
        self.wait_until(|loan| {
            if loan.gone.load(Ordering::SeqCst) {
                return Some(None);
            }
            loan.take().map(Some)
        })
        .await
    }

    /// Marks the context as the transport handler's.
    pub(super) fn taken(&self) {
        self.gone.store(true, Ordering::SeqCst);
        self.changed();
    }
}

/// The flow's [`FlowCx`] on its way back to the transport handler. The stack lends it
/// to the core while a forwarded request runs, and the transport handler takes it back
/// once nothing in the stack can still need it: a layer's answer reaches
/// the client first, the record is finished when the exchange has ended.
pub(crate) enum Reclaim {
    /// No stack, or the stack is done with it.
    Now(Box<FlowCx>),
    /// With the stack, whose core may still be running.
    Stack(Held),
}

/// Cancel the exchange if its transport task exits before collecting the
/// final context. This also covers tasks aborted with their connection.
pub(crate) struct Held {
    st: Arc<StackFlow>,
    taken: bool,
}

impl Drop for Held {
    fn drop(&mut self) {
        if !self.taken {
            self.st.tear_down(super::CLIENT_GONE);
        }
    }
}

impl Reclaim {
    pub(crate) fn now(cx: FlowCx) -> Self {
        Reclaim::Now(Box::new(cx))
    }

    pub(crate) fn stack(st: Arc<StackFlow>) -> Self {
        Reclaim::Stack(Held { st, taken: false })
    }

    /// The flow context, once the stack has let go of it. A stack that
    /// answered folds its answer into the record.
    pub(crate) async fn take(self) -> FlowCx {
        self.take_until(std::future::pending::<()>()).await.0
    }

    /// Keep observing the client while the exchange finishes. Cancellation
    /// tears down the drivers, then waits for their final accounting.
    pub(crate) async fn take_until<F: Future>(self, cancelled: F) -> (FlowCx, Option<F::Output>) {
        match self {
            Reclaim::Now(mut cx) => {
                let delivery = cx.request_delivery.take();
                let wait = async {
                    match &delivery {
                        Some(d) => {
                            d.wait(cx.snap.limits.body_idle_timeout.saturating_mul(2))
                                .await
                        }
                        None => true,
                    }
                };
                let (complete, cancellation) = tokio::select! {
                    complete = wait => (complete, None),
                    reason = cancelled => (true, Some(reason)),
                };
                drop(delivery);
                if !complete {
                    cx.record
                        .reason
                        .get_or_insert_with(|| "upstream_body_timeout".to_owned());
                }
                (*cx, cancellation)
            }
            Reclaim::Stack(mut held) => {
                let (mut cx, cancellation) = {
                    let take = held.st.reclaim();
                    tokio::pin!(take);
                    tokio::select! {
                        cx = &mut take => (cx, None),
                        reason = cancelled => {
                            held.st.tear_down(super::CLIENT_GONE);
                            (take.await, Some(reason))
                        }
                    }
                };
                held.taken = true;
                held.st.fold_answer(&mut cx);
                cx.stack = Some(held.st.clone());
                (cx, cancellation)
            }
        }
    }

    /// Cancel remaining work. Reclamation still waits for body disposal
    /// and driver completion; services receive `why` as the reset reason.
    pub(crate) fn tear_down(&self, why: &'static str) {
        match self {
            Reclaim::Stack(held) => held.st.tear_down(why),
            Reclaim::Now(cx) => {
                if let Some(delivery) = &cx.request_delivery {
                    delivery.cancel();
                }
            }
        }
    }

    /// The response has been written, whether or not its body was polled
    /// to its end.
    pub(crate) fn response_written(&self) {
        if let Reclaim::Stack(held) = self {
            held.st.response_written();
        }
    }

    /// Whether the response body is hashed. The admission decision says,
    /// and a core still running has not made it: a stacked response is
    /// hashed, and the hash kept if the decision asks for it.
    pub(crate) fn digest_response(&self) -> bool {
        match self {
            Reclaim::Now(cx) => cx.digest.response,
            Reclaim::Stack(_) => true,
        }
    }

    /// The process was quarantined while the exchange ran.
    pub(crate) fn quarantined(&self) -> bool {
        match self {
            Reclaim::Now(cx) => cx.shared.quarantined(),
            Reclaim::Stack(held) => held.st.shared.quarantined(),
        }
    }
}
