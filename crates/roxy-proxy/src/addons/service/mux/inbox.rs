//! One body's bytes on their way from the connection's reader to the
//! body's consumer, credited back to the service as they are consumed.

use std::sync::{Arc, Mutex};

use bytes::BytesMut;
use roxy_http::{BodyError, BodySender};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use super::super::{ServiceError, Unanswered};
use super::lock;
use super::stream::{Reset, Stream};
use crate::watch::Dir;

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
    pub(super) end: bool,
    /// The consumer went away: bytes are credited back as they arrive.
    pub(super) dropped: bool,
    pub(super) abort: Option<String>,
}

impl Inbox {
    pub(super) fn abort(&self, e: &Unanswered) {
        lock(&self.q).abort = Some(e.to_string());
        self.abort.cancel();
    }
}

/// Moves one body's bytes from its inbox to its consumer, crediting the
/// service as they go.
pub(super) async fn feeder(stream: Arc<Stream>, inbox: Arc<Inbox>, mut tx: BodySender, dir: Dir) {
    loop {
        let (chunk, end, abort) = {
            let mut q = lock(&inbox.q);
            (q.buf.split().freeze(), q.end, q.abort.take())
        };
        if let Some(why) = abort {
            tx.abort(BodyError::Upstream(why));
            return;
        }
        if !chunk.is_empty() {
            let n = chunk.len() as u64;
            let sent = tokio::select! {
                r = tx.send_data(chunk) => r,
                () = inbox.abort.cancelled() => continue,
            };
            match sent {
                Ok(()) => stream.grant(dir, n),
                Err(BodyError::Closed | BodyError::Stopped) => {
                    return consumer_gone(&stream, &inbox, dir, n);
                }
                // More than declared, or than the limit.
                Err(e) => return stream.fail(ServiceError::Protocol(e.to_string()), Reset::Send),
            }
            continue;
        }
        if end {
            match tx.finish().await {
                Ok(()) | Err(BodyError::Closed | BodyError::Stopped) => {}
                // Shorter than declared.
                Err(e) => stream.fail(ServiceError::Protocol(e.to_string()), Reset::Send),
            }
            return;
        }
        // A consumer that leaves is noticed here too, not only on the next
        // byte: a quiet service may send none for a long time.
        tokio::select! {
            () = inbox.ready.notified() => {}
            () = inbox.abort.cancelled() => {}
            () = tx.closed() => return consumer_gone(&stream, &inbox, dir, 0),
        }
    }
}

/// The consumer of the `dir` body went away, `n` bytes it was sent unread.
pub(super) fn consumer_gone(stream: &Stream, inbox: &Inbox, dir: Dir, n: u64) {
    if dir == Dir::Request {
        // A deny below, say: the rest is read and dropped, and the service
        // still owes the response.
        let rest = {
            let mut q = lock(&inbox.q);
            q.dropped = true;
            q.buf.split().len() as u64
        };
        stream.grant(dir, n + rest);
    } else {
        stream.reset("the client went away");
    }
}
