//! A flow sink whose readiness a test controls, to see traffic held back
//! while the log is behind.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use tokio::sync::Notify;

use crate::flowlog::{FlowEvent, FlowSink, MemorySink};

/// Closed: the sink reports not ready and remembers who asked.
#[derive(Default)]
pub(crate) struct LogGate {
    closed: AtomicBool,
    waiters: Mutex<Vec<Waker>>,
    asked: Notify,
}

impl LogGate {
    pub(crate) fn set_closed(&self, closed: bool) {
        self.closed.store(closed, Ordering::SeqCst);
        if !closed {
            let waiters = std::mem::take(&mut *lock(&self.waiters));
            for w in waiters {
                w.wake();
            }
        }
    }

    /// Waits until roxy asked the closed sink for readiness and was told to
    /// wait: traffic is held at that point.
    pub(crate) async fn wait_held(&self) {
        let wait = async {
            loop {
                let asked = self.asked.notified();
                if !lock(&self.waiters).is_empty() {
                    return;
                }
                asked.await;
            }
        };
        tokio::time::timeout(Duration::from_secs(10), wait)
            .await
            .expect("roxy waits on the flow log");
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A [`MemorySink`] whose readiness follows a [`LogGate`].
pub(crate) struct GatedSink {
    inner: Arc<MemorySink>,
    gate: Arc<LogGate>,
}

impl GatedSink {
    pub(crate) fn new(inner: Arc<MemorySink>, gate: Arc<LogGate>) -> Self {
        Self { inner, gate }
    }
}

impl FlowSink for GatedSink {
    fn emit(&self, event: &FlowEvent<'_>) {
        self.inner.emit(event);
    }

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<()> {
        let mut waiters = lock(&self.gate.waiters);
        if self.gate.closed.load(Ordering::SeqCst) {
            waiters.push(cx.waker().clone());
            self.gate.asked.notify_one();
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    }
}
