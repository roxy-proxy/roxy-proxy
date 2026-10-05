//! Flow control for one body of a stream: what the service may send
//! roxy, and what roxy may send the service.

use std::sync::Arc;

use super::inbox::Inbox;

/// Each body's starting credit, each way, in bytes.
pub(super) const WINDOW: u64 = 256 * 1024;

/// Bytes discarded from an observe stream before they are credited back
/// in one message, so the credit queue holds a few messages per stream
/// however small the service's frames.
pub(super) const OBSERVE_GRANT: u64 = WINDOW / 4;

/// One body of a stream: what the service is sending of it, and the
/// credit each way.
pub(super) struct Feed {
    /// Being fed from the stream: its head arrived and its end has not.
    pub(super) inbox: Option<Arc<Inbox>>,
    /// Bytes received and not yet credited back.
    pub(super) unacked: u64,
    /// Observe mode: bytes discarded since the last credit went back.
    pub(super) discarded: u64,
    /// What roxy may still send: granted by the service.
    pub(super) credit: u64,
}

impl Default for Feed {
    fn default() -> Self {
        Self {
            inbox: None,
            unacked: 0,
            discarded: 0,
            credit: WINDOW,
        }
    }
}
