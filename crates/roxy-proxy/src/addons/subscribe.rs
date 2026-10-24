//! What a layer subscribes to: the head of each direction, or the head and
//! the body. A body a layer is not subscribed to bypasses it: the layer gets
//! the head with an empty body and no `content-length`, passes on a head
//! and no body of its own, and the body goes on upstream (or downstream to
//! the client) with the head the layer passed on. Framing is roxy's on a
//! bypassed body, so the layer's head carries none of it; a layer that
//! passes on bytes or trailers for it fails the exchange closed.

use std::sync::Arc;

use http_body_util::BodyExt;
use roxy_http::Body;
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

/// Watches what a head-only layer gave for the body of `dir`, which is not
/// part of the lane: the bypassed body is. Bytes or trailers in it fail the
/// layer; its end and any error are its own business, since nothing reads
/// it. Runs until the layer's body ends or the layer is torn down, on the
/// exchange's tracker.
pub(super) fn watch_own(st: &Arc<StackFlow>, index: usize, dir: Dir, own: Body) {
    if http_body::Body::is_end_stream(&own) {
        return;
    }
    let st2 = st.clone();
    let torn = st.chain().layer_torn_down(index);
    st.chain().spawn(async move {
        let mut own = own;
        loop {
            let frame = tokio::select! {
                () = torn.cancelled() => return,
                f = own.frame() => f,
            };
            let Some(Ok(frame)) = frame else {
                return;
            };
            if frame.data_ref().is_none_or(|d| !d.is_empty()) {
                st2.layer_failed(index, LayerError::Unsubscribed(dir.as_str()));
                return;
            }
        }
    });
}
