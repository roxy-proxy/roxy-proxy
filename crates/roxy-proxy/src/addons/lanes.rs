//! The bodies at the two ends of the stack: the client's request as it
//! enters, and the response as it leaves for the client.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use http_body::{Body as HttpBody, Frame, SizeHint};
use roxy_http::{Body, BodyError};
use tokio_util::sync::WaitForCancellationFutureOwned;

use super::StackFlow;
use crate::flowlog::FlowSink;

/// The client's request body as it enters the stack: dropped where it is,
/// the rest unread, once the stack has snipped the lane.
pub(super) fn snipped(st: &Arc<StackFlow>, body: Body) -> Body {
    let known = body.known_length();
    Body::wrap_native(
        Snipped {
            inner: Some(body),
            snip: Box::pin(st.snip.clone().cancelled_owned()),
        },
        u64::MAX,
        known,
    )
}

/// A body dropped where it is when its lane is snipped: the reader sees
/// it abandoned, never complete.
struct Snipped {
    inner: Option<Body>,
    /// One future for the snip, so its waker stays registered across
    /// polls that found the inner body pending.
    snip: Pin<Box<WaitForCancellationFutureOwned>>,
}

impl HttpBody for Snipped {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = &mut *self;
        let Some(inner) = &mut this.inner else {
            return Poll::Ready(Some(Err(BodyError::Abandoned)));
        };
        if this.snip.as_mut().poll(cx).is_ready() {
            this.inner = None;
            return Poll::Ready(Some(Err(BodyError::Abandoned)));
        }
        Pin::new(inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        // Complete only if the inner body was; a snip is a cut.
        self.inner.as_ref().is_some_and(Body::is_end_stream)
    }

    fn size_hint(&self) -> SizeHint {
        self.inner
            .as_ref()
            .map_or_else(SizeHint::default, Body::size_hint)
    }
}

/// The response on its way to the client: its end tells the stack the
/// response is complete. An empty body is complete with its head.
pub(super) fn completing(st: &Arc<StackFlow>, body: Body) -> Body {
    if body.is_end_stream() {
        st.response_complete();
        return body;
    }
    let known = body.known_length();
    Body::wrap_native(
        Completing {
            inner: body,
            st: st.clone(),
            done: false,
        },
        u64::MAX,
        known,
    )
}

struct Completing {
    inner: Body,
    st: Arc<StackFlow>,
    done: bool,
}

impl HttpBody for Completing {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = &mut *self;
        let frame = ready!(Pin::new(&mut this.inner).poll_frame(cx));
        if !this.done && !matches!(frame, Some(Ok(_))) {
            this.done = true;
            this.st.response_complete();
        }
        Poll::Ready(frame)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// A layer's response body to the client, sent only while the flow log
/// keeps up (audit backpressure).
pub(super) fn gated(body: Body, sink: Arc<dyn FlowSink>) -> Body {
    let known = body.known_length();
    Body::wrap_native(Gated { inner: body, sink }, u64::MAX, known)
}

struct Gated {
    inner: Body,
    sink: Arc<dyn FlowSink>,
}

impl HttpBody for Gated {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        ready!(self.sink.poll_ready(cx));
        Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
