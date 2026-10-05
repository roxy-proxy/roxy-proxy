//! The process-wide budget for per-exchange buffers: bodies buffered for
//! inspection, WebSocket messages being reassembled, observers' copies.
//!
//! Each of those buffers is bounded by a `limits.*` cap on its own; the
//! budget bounds their sum. An exchange reserves a cap in full before it
//! fills the buffer, and holds the reservation until it ends, so what the
//! process can hold in such buffers at once is `limits.max_buffered_bytes`
//! whatever the number of exchanges. Nothing is evicted and nobody waits:
//! a reservation the budget cannot cover fails at once, and the exchange
//! fails closed (an observer's copy is cut).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// The reason code of an exchange (or observer copy) the budget could not
/// cover.
pub(crate) const EXHAUSTED: &str = "buffer_budget_exhausted";

/// Bytes reserved across the process.
#[derive(Default)]
pub(crate) struct BufferBudget {
    used: AtomicU64,
}

/// A reservation; released on drop.
pub(crate) struct BufferLease {
    budget: Arc<BufferBudget>,
    bytes: u64,
}

impl BufferBudget {
    /// Reserves `bytes` if that keeps the total within `cap`.
    pub(crate) fn reserve(self: &Arc<Self>, cap: u64, bytes: u64) -> Option<BufferLease> {
        let mut used = self.used.load(Ordering::Relaxed);
        loop {
            let after = used.checked_add(bytes).filter(|n| *n <= cap)?;
            match self
                .used
                .compare_exchange_weak(used, after, Ordering::AcqRel, Ordering::Relaxed)
            {
                Ok(_) => {
                    return Some(BufferLease {
                        budget: self.clone(),
                        bytes,
                    });
                }
                Err(now) => used = now,
            }
        }
    }

    /// Bytes reserved right now.
    #[cfg(test)]
    pub(crate) fn used(&self) -> u64 {
        self.used.load(Ordering::Acquire)
    }
}

impl Drop for BufferLease {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservations_fill_the_cap_and_free_it_on_drop() {
        let b = Arc::new(BufferBudget::default());
        let a = b.reserve(10, 4).unwrap();
        let c = b.reserve(10, 6).unwrap();
        assert_eq!(b.used(), 10);
        assert!(b.reserve(10, 1).is_none());
        drop(a);
        assert_eq!(b.used(), 6);
        assert!(b.reserve(10, 5).is_none());
        let d = b.reserve(10, 4).unwrap();
        drop(c);
        assert_eq!(b.used(), 4);
        // A lower cap after a reload refuses until enough is released.
        assert!(b.reserve(3, 1).is_none());
        assert!(b.reserve(4, 0).is_some());
        drop(d);
        let _e = b.reserve(3, 1).unwrap();
        // A total past `u64::MAX` is refused, not wrapped.
        assert!(b.reserve(u64::MAX, u64::MAX).is_none());
    }
}
