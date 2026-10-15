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

/// The bodies bypassing one enforce layer of an exchange, parked between
/// the layer taking the head and passing one on.
#[derive(Default)]
pub(super) struct Bypass {
    request: Option<Body>,
    /// The response from below: its status, and its body.
    response: Option<(http::StatusCode, Body)>,
    /// The layer has answered: a response from below that arrives after
    /// this has no head of the layer's to be spliced onto.
    answered: bool,
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

/// Drops whatever is parked at layer `index`, and parks nothing more there:
/// the layer failed, or the exchange is being torn down, so no answer of
/// the layer's will take a body back. Dropped outside the lock: a body's
/// drop tells whoever fed it.
pub(super) fn release(st: &StackFlow, index: usize) {
    let parked = {
        let mut bypass = lock(&st.layers[index].bypass);
        bypass.answered = true;
        (bypass.request.take(), bypass.response.take())
    };
    drop(parked);
}

/// Layer `index` has answered: a response from below arriving from now on
/// is not the one its answer passes on, so no body of it is parked. One
/// parked before stays, for an answer that is the head from below.
pub(super) fn answered(st: &StackFlow, index: usize) {
    lock(&st.layers[index].bypass).answered = true;
}

/// Takes the response body away from enforce layer `index` when it is
/// subscribed to the head only. A layer that has already answered gets the
/// head with no body to park: its answer was whole.
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
    let mut bypass = lock(&st.layers[index].bypass);
    if !bypass.answered {
        bypass.response = Some((res.status(), body));
    }
    res
}

/// Splices the response body that bypassed layer `index` onto the response
/// it answered with, when that is the response from below with its head
/// edited: the same status. A different status is an answer of the layer's
/// own, whole, and the body from below is dropped. A layer that answered
/// before the response from below arrived has no bypassed body: its answer
/// is whole, and a body arriving later is dropped.
pub(super) fn reattach_response(
    st: &Arc<StackFlow>,
    index: usize,
    res: LayerResponse,
) -> LayerResponse {
    let parked = lock(&st.layers[index].bypass).response.take();
    let Some((status, body)) = parked else {
        return res;
    };
    if res.status() != status {
        return res;
    }
    res.map(|own| splice(st, index, Dir::Response, own, body))
}

/// The bypassed body goes on alone, framed as it came, when the layer's
/// own body is complete: a service layer's head-only direction always is
/// (its head and end carry no bytes, and the stream refuses any), a WASM
/// layer's when `next` was given an empty `bytes` body.
fn splice(st: &Arc<StackFlow>, index: usize, dir: Dir, own: Body, bypassed: Body) -> Body {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{AddonDef, Kit};

    /// A response from below that arrives after the layer answered is not
    /// parked for it: the answer was the layer's own, and the body from
    /// below must not be spliced onto it. One that arrived before stays.
    #[tokio::test]
    async fn a_body_from_below_is_not_parked_once_the_layer_has_answered() {
        let kit = Kit::builder()
            .addon(AddonDef::test_layer("a").subscribe(Part::Full, Part::Head))
            .start()
            .await;
        let from_below = || {
            http::Response::builder()
                .status(200)
                .body(Body::from_bytes("from below"))
                .unwrap()
        };
        let (st, _cx, _ends) = crate::addons::test_flow(&kit);
        answered(&st, 0);
        drop(detach_response(&st, 0, from_below()));
        assert!(lock(&st.layers[0].bypass).response.is_none());

        let (st, _cx, _ends) = crate::addons::test_flow(&kit);
        drop(detach_response(&st, 0, from_below()));
        answered(&st, 0);
        assert!(lock(&st.layers[0].bypass).response.is_some());
    }
}
