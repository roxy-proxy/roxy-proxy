//! What a layer subscribes to: the head of each direction, or the head and
//! the body. A body a layer is not subscribed to bypasses it: the layer gets
//! the head with an empty body and no `content-length`, and the body goes
//! on upstream (or downstream to the client) spliced onto the head the
//! layer passed on. Framing is roxy's on a bypassed body, so the layer's head carries
//! none of it; a layer that passes on bytes of a body it is not subscribed
//! to fails the exchange closed.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use http_body::{Body as HttpBody, Frame, SizeHint};
use roxy_http::{Body, BodyError};
use roxy_wasm::LayerError;

use super::StackFlow;
use crate::in_flight::Dir;

/// How much of one direction of the exchange a layer sees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Part {
    /// The head only; the body bypasses the layer.
    Head,
    /// The head and the body.
    #[default]
    Full,
}

impl Part {
    /// `head` or `full`, as the config and the service protocol write it.
    pub fn as_str(self) -> &'static str {
        match self {
            Part::Head => "head",
            Part::Full => "full",
        }
    }
}

/// A layer's subscription to each direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Subscription {
    pub request: Part,
    pub response: Part,
}

impl Subscription {
    pub(super) fn part(self, dir: Dir) -> Part {
        match dir {
            Dir::Request => self.request,
            Dir::Response => self.response,
        }
    }

    /// The layer reads at least one body.
    pub(super) fn reads_bytes(self) -> bool {
        self.request == Part::Full || self.response == Part::Full
    }
}

/// The head as a layer not subscribed to the body sees it: the body's
/// framing is roxy's, not the layer's to see or state.
pub(super) fn head_only(headers: &mut http::HeaderMap) {
    headers.remove(http::header::CONTENT_LENGTH);
}

/// The bypassed body goes on alone, framed as it came, when the layer's
/// own body is complete: a service layer's head-only direction always is
/// (its head and end carry no bytes, and the stream refuses any), a WASM
/// layer's when `next` was given an empty `bytes` body.
pub(super) fn splice(
    st: &Arc<StackFlow>,
    index: usize,
    dir: Dir,
    own: Body,
    bypassed: Body,
) -> Body {
    if own.is_end_stream() {
        return bypassed;
    }
    // The length is unknown while the own body is open, whatever the
    // bypassed body declared: with a `content-length` the client would have
    // a complete body once the bypassed bytes were through, and the end
    // held back for the own body, or its failure, nothing left to cut.
    Body::wrap_native(
        Spliced {
            st: st.clone(),
            index,
            dir,
            own: Some(own),
            bypassed,
        },
        u64::MAX,
        None,
    )
}

/// The bypassed body alongside the layer's own, which must end without a
/// byte or a trailer: the layer is not subscribed to this body, so anything
/// it passes on for it is its failure. The own body never holds the
/// bypassed bytes back (a guest body's end waits for the handler to return,
/// which on a WebSocket is the life of the socket), but the whole ends only
/// once it has, and declares no length: no body completes cleanly before
/// the exchange has settled.
struct Spliced {
    st: Arc<StackFlow>,
    index: usize,
    dir: Dir,
    own: Option<Body>,
    bypassed: Body,
}

impl Spliced {
    /// Polls the layer's own body for what it must not carry. Pending is
    /// not a reason to wait: the bypassed body is polled next.
    fn poll_own(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        while let Some(own) = &mut self.own {
            match ready!(Pin::new(own).poll_frame(cx)) {
                None => self.own = None,
                Some(Err(e)) => {
                    self.own = None;
                    return Poll::Ready(Some(Err(e)));
                }
                Some(Ok(f)) if f.data_ref().is_some_and(Bytes::is_empty) => {}
                Some(Ok(_)) => {
                    let name = self.st.snap.addons[self.index].name.clone();
                    self.st
                        .fail(&name, LayerError::Unsubscribed(self.dir.as_str()));
                    self.own = None;
                    return Poll::Ready(Some(Err(BodyError::Stopped)));
                }
            }
        }
        Poll::Ready(None)
    }
}

impl HttpBody for Spliced {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = &mut *self;
        if let Poll::Ready(Some(r)) = this.poll_own(cx) {
            return Poll::Ready(Some(r));
        }
        match ready!(Pin::new(&mut this.bypassed).poll_frame(cx)) {
            // The bypassed body has ended; the end waits for the own body,
            // whose poll above registered the waker.
            None if this.own.is_some() => Poll::Pending,
            frame => Poll::Ready(frame),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.own.is_none() && self.bypassed.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}
