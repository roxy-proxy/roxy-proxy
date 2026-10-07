//! The process-wide budget for per-exchange buffers: bodies buffered for
//! inspection, WebSocket messages being reassembled, observers' copies.
//!
//! Each of those buffers is bounded by a `limits.*` cap on its own; the
//! budget bounds their sum, so what the process can hold in such buffers
//! at once is `limits.max_buffered_bytes` whatever the number of
//! exchanges. Inspection and reassembly reserve their cap in full before
//! they fill the buffer and hold it until the exchange ends: they fail
//! closed when they cannot reserve, so they must not find out part-way.
//! A chunked body buffered for signing grows its reservation as it is
//! read, since its size is unknown and the cap is large; it fails closed
//! at the frame the budget cannot cover. An observer's copy is charged
//! frame by frame for what it has queued, since a copy that cannot grow is
//! simply cut. Nothing is evicted and nobody waits: a reservation the
//! budget cannot cover fails at once.
//!
//! Every buffer the host holds for an exchange goes through a lease: the
//! collectors in `body` and the content decoders take a meter that grows
//! one, so what counts against the budget is whatever reaches a lease,
//! not a list kept elsewhere.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// The reason code of an exchange (or observer copy) the budget could not
/// cover.
pub(crate) const EXHAUSTED: &str = "buffer_budget_exhausted";

/// The budget could not cover a reservation.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Exhausted;

/// Bytes reserved across the process.
#[derive(Debug, Default)]
pub(crate) struct BufferBudget {
    used: AtomicU64,
}

/// A reservation; released on drop.
#[derive(Debug)]
pub(crate) struct BufferLease {
    budget: Arc<BufferBudget>,
    bytes: u64,
}

impl BufferBudget {
    /// Reserves `bytes` if that keeps the total within `cap`.
    pub(crate) fn reserve(self: &Arc<Self>, cap: u64, bytes: u64) -> Option<BufferLease> {
        self.add(cap, bytes).then(|| BufferLease {
            budget: self.clone(),
            bytes,
        })
    }

    /// Adds `bytes` to the total if that keeps it within `cap`.
    fn add(&self, cap: u64, bytes: u64) -> bool {
        let mut used = self.used.load(Ordering::Relaxed);
        loop {
            let Some(after) = used.checked_add(bytes).filter(|n| *n <= cap) else {
                return false;
            };
            match self
                .used
                .compare_exchange_weak(used, after, Ordering::AcqRel, Ordering::Relaxed)
            {
                Ok(_) => return true,
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

impl BufferLease {
    /// Grows the reservation to `bytes` if that keeps the total within
    /// `cap`; a `bytes` no larger than the reservation is a no-op. On
    /// `false` the lease is as it was.
    pub(crate) fn grow_to(&mut self, cap: u64, bytes: u64) -> bool {
        let Some(extra) = bytes.checked_sub(self.bytes).filter(|n| *n > 0) else {
            return true;
        };
        if self.budget.add(cap, extra) {
            self.bytes = bytes;
            return true;
        }
        false
    }

    /// Gives back all but `bytes` of the reservation, once what the lease
    /// covers is known to be no larger than that. A larger `bytes` is a
    /// no-op.
    pub(crate) fn shrink_to(&mut self, bytes: u64) {
        if bytes < self.bytes {
            self.budget
                .used
                .fetch_sub(self.bytes - bytes, Ordering::AcqRel);
            self.bytes = bytes;
        }
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
    fn a_lease_grows_within_the_cap_and_keeps_its_size_when_it_cannot() {
        let b = Arc::new(BufferBudget::default());
        let mut lease = b.reserve(10, 0).unwrap();
        assert!(lease.grow_to(10, 4));
        assert!(lease.grow_to(10, 2), "shrinking is a no-op");
        assert_eq!(b.used(), 4);
        let _other = b.reserve(10, 4).unwrap();
        assert!(!lease.grow_to(10, 7));
        assert_eq!(b.used(), 8);
        assert!(lease.grow_to(10, 6));
        assert_eq!(b.used(), 10);
        drop(lease);
        assert_eq!(b.used(), 4);
    }

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

    #[test]
    fn shrinking_releases_the_difference_and_never_grows() {
        let b = Arc::new(BufferBudget::default());
        let mut a = b.reserve(10, 8).unwrap();
        assert!(b.reserve(10, 3).is_none());
        a.shrink_to(5);
        assert_eq!(b.used(), 5);
        let _c = b.reserve(10, 3).unwrap();
        a.shrink_to(7);
        assert_eq!(b.used(), 8);
        drop(a);
        assert_eq!(b.used(), 3);
    }
}
