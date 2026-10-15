//! One body's bytes on their way from the connection's reader to the lane
//! the service produces, credited back to the service as they are
//! consumed.

use std::sync::{Arc, Mutex};

use bytes::{Bytes, BytesMut};
use http::HeaderMap;
use roxy_http::{BodyError, BodySender};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use super::super::super::chain::LaneBody;
use super::super::ServiceError;
use super::lock;
use super::stream::{Reset, Stream};
use crate::in_flight::Dir;

/// Bytes for one body, between the reader and that body's feeder. At most
/// the body's credit is ever here.
#[derive(Default)]
pub(super) struct Inbox {
    pub(super) q: Mutex<InboxQ>,
    pub(super) ready: Notify,
    pub(super) abort: CancellationToken,
}

#[derive(Default)]
pub(super) struct InboxQ {
    pub(super) buf: BytesMut,
    /// After the bytes, before the end.
    pub(super) trailers: Option<HeaderMap>,
    pub(super) end: bool,
    /// The consumer went away: bytes that still arrive are dropped.
    pub(super) dropped: bool,
    pub(super) abort: Option<String>,
}

impl Inbox {
    pub(super) fn abort(&self, why: String) {
        lock(&self.q).abort = Some(why);
        self.abort.cancel();
    }
}

/// Moves one body's bytes from its inbox to the lane, crediting the
/// service as they go.
pub(super) async fn feeder(stream: Arc<Stream>, inbox: Arc<Inbox>, mut body: Output, dir: Dir) {
    loop {
        let (chunk, trailers, end, abort) = {
            let mut q = lock(&inbox.q);
            let chunk = q.buf.split().freeze();
            // Bytes before an error end reach the consumer first: the
            // body is cut where the service cut it, not before.
            let abort = if chunk.is_empty() {
                q.abort.take()
            } else {
                None
            };
            let trailers = if chunk.is_empty() {
                q.trailers.take()
            } else {
                None
            };
            (chunk, trailers, q.end, abort)
        };
        if let Some(why) = abort {
            body.abort(why);
            return;
        }
        if !chunk.is_empty() {
            let n = chunk.len() as u64;
            let sent = tokio::select! {
                r = body.send_data(chunk) => r,
                () = inbox.abort.cancelled() => continue,
            };
            match sent {
                Ok(()) => stream.grant(dir, n),
                Err(BodyError::Closed | BodyError::Stopped) => {
                    return consumer_gone(&stream, &inbox, dir);
                }
                // More than declared, or than the limit.
                Err(e) => {
                    stream.fail(ServiceError::Protocol(e.to_string()), Reset::Send);
                    return;
                }
            }
            continue;
        }
        if let Some(trailers) = trailers {
            let sent = tokio::select! {
                r = body.send_trailers(trailers) => r,
                () = inbox.abort.cancelled() => continue,
            };
            if let Err(BodyError::Closed | BodyError::Stopped) = sent {
                return consumer_gone(&stream, &inbox, dir);
            }
            continue;
        }
        if end {
            match body.finish().await {
                Ok(()) | Err(BodyError::Closed | BodyError::Stopped) => {}
                // Shorter than declared.
                Err(e) => {
                    stream.fail(ServiceError::Protocol(e.to_string()), Reset::Send);
                }
            }
            return;
        }
        // A consumer that leaves is noticed here too, not only on the next
        // byte: a quiet service may send none for a long time.
        tokio::select! {
            () = inbox.ready.notified() => {}
            () = inbox.abort.cancelled() => {}
            () = body.closed() => return consumer_gone(&stream, &inbox, dir),
        }
    }
}

/// A full subscription writes the lane directly. A head-only subscription
/// supplies the empty producer body joined with the bypassed body by the
/// same adapter used for WASM. Its end completes only that producer body;
/// the lane still owes the bypassed body's end and consumption.
pub(super) enum Output {
    Lane(LaneBody),
    HeadOnly(BodySender),
}

impl Output {
    async fn send_data(&mut self, data: Bytes) -> Result<(), BodyError> {
        match self {
            Self::Lane(body) => body.send_data(data).await,
            Self::HeadOnly(body) => body.send_data(data).await,
        }
    }

    async fn send_trailers(&mut self, trailers: HeaderMap) -> Result<(), BodyError> {
        match self {
            Self::Lane(body) => body.send_trailers(trailers).await,
            Self::HeadOnly(body) => body.send_trailers(trailers).await,
        }
    }

    async fn finish(self) -> Result<(), BodyError> {
        match self {
            Self::Lane(body) => body.finish().await,
            Self::HeadOnly(body) => body.finish().await,
        }
    }

    fn abort(self, why: String) {
        match self {
            Self::Lane(body) => body.abort(why),
            // Head-only error ends are protocol faults, recorded before
            // this cancellation reaches the shared subscription adapter.
            Self::HeadOnly(body) => body.abort(BodyError::Stopped),
        }
    }

    async fn closed(&self) {
        match self {
            Self::Lane(body) => body.closed().await,
            Self::HeadOnly(body) => body.closed().await,
        }
    }
}

/// The consumer of the `dir` lane went away before its end: the service
/// is told to stop, and what it still sends of that lane is dropped,
/// uncredited.
fn consumer_gone(stream: &Stream, inbox: &Inbox, dir: Dir) {
    {
        let mut q = lock(&inbox.q);
        q.dropped = true;
        q.buf.clear();
    }
    stream.stop(dir);
}
