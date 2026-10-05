//! Streams over pooled connections (`roxy.layer.v3`).
//!
//! Each endpoint has a small pool of WebSocket connections; each exchange
//! is a stream on one of them. Text frames are JSON with a `stream` field;
//! binary frames are a 4-byte big-endian stream id, a direction byte
//! (request or response body), then body bytes. The two bodies of a
//! stream are fed independently, so a response head may arrive while the
//! request body is still streaming. Body bytes are flow-controlled per
//! stream, body and direction by credit, so one slow body never holds up
//! the connection or the other body: the reader hands each body's bytes
//! to its own feeder and never waits on a consumer.
//!
//! Broken framing fails the whole connection (every stream on it fails
//! closed); anything else fails only its stream, which is reset.
//!
//! The pools hang off the policy snapshot: a reload dials new connections
//! under the new policy and secrets, and retires the old snapshot's pools,
//! whose connections close as soon as no exchange is using them.

mod inbox;
mod link;
mod pool;
mod stream;
#[cfg(test)]
mod tests;
mod window;

use std::sync::{Mutex, PoisonError};

pub use link::SUBPROTOCOL;
pub(crate) use pool::Pools;
pub(super) use stream::{Stream, open};

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}
