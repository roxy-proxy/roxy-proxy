//! What a layer subscribes to: the head of each direction, or the head and
//! the body. A body a layer is not subscribed to bypasses it: the layer gets
//! the head with an empty body and no `content-length`, and the body goes
//! on below (or up to the client) spliced onto the head the layer passed
//! on. Framing is roxy's on a bypassed body, so the layer's head carries
//! none of it; a layer that passes on bytes of a body it is not subscribed
//! to fails the exchange closed.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use http_body::{Body as HttpBody, Frame, SizeHint};
use roxy_http::{Body, BodyError};
use roxy_wasm::{LayerError, LayerRequest, LayerResponse};

use super::{StackFlow, lock};
use crate::watch::Dir;

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

/// The bodies bypassing one enforce layer of an exchange, parked between
/// the layer taking the head and passing one on.
#[derive(Default)]
pub(super) struct Bypass {
    request: Option<Body>,
    /// The response from below: its status, and its body.
    response: Option<(http::StatusCode, Body)>,
}

/// The head as a layer not subscribed to the body sees it: the body's
/// framing is roxy's, not the layer's to see or state.
pub(super) fn head_only(headers: &mut http::HeaderMap) {
    headers.remove(http::header::CONTENT_LENGTH);
}

/// Takes the request body away from enforce layer `index` when it is
/// subscribed to the head only.
pub(super) fn detach_request(
    st: &Arc<StackFlow>,
    index: usize,
    mut req: LayerRequest,
) -> LayerRequest {
    if st.snap.addons[index].subscribe.request == Part::Full {
        return req;
    }
    let body = std::mem::take(req.body_mut());
    head_only(req.headers_mut());
    lock(&st.layers[index].bypass).request = Some(body);
    req
}

/// Splices the request body that bypassed layer `index` onto the request
/// it passed on.
pub(super) fn reattach_request(
    st: &Arc<StackFlow>,
    index: usize,
    req: LayerRequest,
) -> LayerRequest {
    let Some(body) = lock(&st.layers[index].bypass).request.take() else {
        return req;
    };
    req.map(|own| splice(st, index, Dir::Request, own, body))
}

/// Drops a request body still parked at layer `index` once the layer has
/// answered: it never passed the head on, so the body goes the way of one
/// a layer dropped unread.
pub(super) fn release_request(st: &Arc<StackFlow>, index: usize) {
    drop(lock(&st.layers[index].bypass).request.take());
}

/// Takes the response body away from enforce layer `index` when it is
/// subscribed to the head only.
pub(super) fn detach_response(
    st: &Arc<StackFlow>,
    index: usize,
    mut res: LayerResponse,
) -> LayerResponse {
    if st.snap.addons[index].subscribe.response == Part::Full {
        return res;
    }
    let body = std::mem::take(res.body_mut());
    head_only(res.headers_mut());
    lock(&st.layers[index].bypass).response = Some((res.status(), body));
    res
}

/// Splices the response body that bypassed layer `index` onto the response
/// it answered with, when that is the response from below with its head
/// edited: the same status. A different status is an answer of the layer's
/// own, whole, and the body from below is dropped. A layer that answered
/// without `next` resolving has no bypassed body: its answer is whole.
pub(super) fn reattach_response(
    st: &Arc<StackFlow>,
    index: usize,
    res: LayerResponse,
) -> LayerResponse {
    let Some((status, body)) = lock(&st.layers[index].bypass).response.take() else {
        return res;
    };
    if res.status() != status {
        return res;
    }
    res.map(|own| splice(st, index, Dir::Response, own, body))
}

fn splice(st: &Arc<StackFlow>, index: usize, dir: Dir, own: Body, bypassed: Body) -> Body {
    if own.is_end_stream() {
        return bypassed;
    }
    let known = bypassed.known_length();
    Body::wrap_native(
        Spliced {
            st: st.clone(),
            index,
            dir,
            own: Some(own),
            bypassed,
        },
        u64::MAX,
        known,
    )
}

/// The bypassed body after the layer's own, which must end without a byte
/// or a trailer: the layer is not subscribed to this body, so anything it
/// passes on for it is its failure.
struct Spliced {
    st: Arc<StackFlow>,
    index: usize,
    dir: Dir,
    own: Option<Body>,
    bypassed: Body,
}

impl HttpBody for Spliced {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
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
        Pin::new(&mut self.bypassed).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.own.is_none() && self.bypassed.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.bypassed.size_hint()
    }
}
