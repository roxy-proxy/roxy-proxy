//! Flow control for one body of a stream, in one direction of the
//! connection: what roxy may still send the service, and what the service
//! may still send roxy.

/// Each body's starting credit, each way, in bytes.
pub(super) const WINDOW: u64 = 256 * 1024;

/// Bytes consumed before they are credited back in one message, so the
/// credit queue holds a few messages per stream however small the
/// service's frames. The service always has the rest of the window to
/// send, so credit held back this way never stalls it.
const GRANT: u64 = WINDOW / 4;

/// The credit each way for one body. The service may have at most
/// [`WINDOW`] bytes in flight to roxy: what it has sent and roxy has not
/// yet credited back. roxy may send what the service has credited it.
/// These counters move nowhere else.
pub(super) struct Window {
    /// What roxy may still send: granted by the service.
    credit: u64,
    /// Bytes received from the service and not yet credited back.
    unacked: u64,
    /// Bytes consumed since the last credit went back.
    pending: u64,
}

/// The service sent more than its credit.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct PastCredit;

impl Default for Window {
    fn default() -> Self {
        Self {
            credit: WINDOW,
            unacked: 0,
            pending: 0,
        }
    }
}

impl Window {
    /// The service granted roxy `n` more bytes.
    pub(super) fn granted(&mut self, n: u64) {
        self.credit = self.credit.saturating_add(n);
    }

    /// Takes up to `want` bytes of roxy's credit; `None` while there is
    /// none.
    pub(super) fn take(&mut self, want: usize) -> Option<usize> {
        if self.credit == 0 {
            return None;
        }
        let n = want.min(usize::try_from(self.credit).unwrap_or(usize::MAX));
        self.credit -= n as u64;
        Some(n)
    }

    /// `n` bytes arrived from the service, against its window.
    pub(super) fn received(&mut self, n: u64) -> Result<(), PastCredit> {
        let total = self.unacked.saturating_add(n);
        if total > WINDOW {
            return Err(PastCredit);
        }
        self.unacked = total;
        Ok(())
    }

    /// `n` received bytes are consumed. Their credit goes back in batches
    /// of [`GRANT`]: the batch due now, if one is.
    pub(super) fn acked(&mut self, n: u64) -> Option<u64> {
        self.pending = self.pending.saturating_add(n);
        if self.pending < GRANT {
            return None;
        }
        let batch = std::mem::take(&mut self.pending);
        self.unacked = self.unacked.saturating_sub(batch);
        Some(batch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roxy_sends_only_what_the_service_granted() {
        let mut w = Window::default();
        assert_eq!(w.take(10), Some(10));
        assert_eq!(
            w.take(usize::MAX),
            Some(usize::try_from(WINDOW - 10).unwrap())
        );
        assert_eq!(w.take(1), None);
        w.granted(3);
        assert_eq!(w.take(5), Some(3));
        assert_eq!(w.take(5), None);
    }

    #[test]
    fn the_service_sends_only_within_its_window() {
        let mut w = Window::default();
        assert_eq!(w.received(WINDOW), Ok(()));
        assert_eq!(w.received(1), Err(PastCredit));
        assert_eq!(w.acked(GRANT), Some(GRANT));
        assert_eq!(w.received(GRANT), Ok(()));
        assert_eq!(w.received(1), Err(PastCredit));
        // A failed receive leaves the window as it was.
        assert_eq!(w.acked(WINDOW), Some(WINDOW));
        assert_eq!(w.received(WINDOW), Ok(()));
    }

    /// Credit held back for a batch is still the service's: its window
    /// opens only as the batch goes.
    #[test]
    fn consumed_bytes_are_credited_back_in_batches() {
        let mut w = Window::default();
        assert_eq!(w.received(WINDOW), Ok(()));
        assert_eq!(w.acked(GRANT - 1), None);
        assert_eq!(w.received(1), Err(PastCredit));
        assert_eq!(w.acked(2), Some(GRANT + 1));
        assert_eq!(w.received(GRANT + 1), Ok(()));
        assert_eq!(w.acked(1), None);
    }
}
