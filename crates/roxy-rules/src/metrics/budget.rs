//! The byte budget a [`super::MetricStore`] charges its series against.

use std::sync::atomic::{AtomicUsize, Ordering};

/// The byte budget: charged bytes and their ceiling.
#[derive(Debug)]
pub(super) struct Budget {
    used: AtomicUsize,
    pub(super) max: usize,
}

/// A growth was refused by the byte budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Refused;

impl Budget {
    pub(super) fn new(max: usize) -> Self {
        Self {
            used: AtomicUsize::new(0),
            max,
        }
    }

    /// Charge `n` bytes unless that would exceed the ceiling. A CAS loop,
    /// so concurrent takers can never overshoot together.
    pub(super) fn take(&self, n: usize) -> Result<(), Refused> {
        if n == 0 {
            return Ok(());
        }
        self.used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |u| {
                u.checked_add(n).filter(|&t| t <= self.max)
            })
            .map(|_| ())
            .map_err(|_| Refused)
    }

    pub(super) fn give(&self, n: usize) {
        if n > 0 {
            self.used.fetch_sub(n, Ordering::AcqRel);
        }
    }

    /// `reserved` bytes were taken for an allocation that turned out to be
    /// `actual` bytes: return the difference. (`Vec::reserve_exact` gives
    /// exactly what it is asked for, so `actual > reserved` does not occur
    /// with std; it is charged anyway so the books stay consistent.)
    pub(super) fn settle(&self, reserved: usize, actual: usize) {
        if actual > reserved {
            self.used.fetch_add(actual - reserved, Ordering::AcqRel);
        } else {
            self.give(reserved - actual);
        }
    }

    pub(super) fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }
}
