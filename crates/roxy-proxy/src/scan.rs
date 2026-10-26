//! Rules on body text, checked as the body streams.
//!
//! When a rule reads `body.text` or `response.body.text`, that body passes
//! through [`TextBody`] on its way. Each chunk is fed to the body's text
//! tests ([`InFlight::on_text`]) before any of it is forwarded, and the
//! last bytes, as many as the longest string the rules compare with, are
//! held back until more arrive, whatever they are, so a rule matching on
//! them stops the exchange before they leave. The end of the body is held
//! the same way: the last bytes and the trailers go only once every test
//! is decided.
//!
//! The tests read the body decoded from its `content-encoding`. A body that
//! streams is decoded, scanned and encoded again in the same codings
//! ([`crate::recode`]): its encoded bytes can carry a needle before a
//! decoder gives it up, so they cannot be passed on as they arrive. A
//! request already held whole (signed with `sign: aws_sigv4`) is decoded
//! and scanned whole before any of it goes, and goes as it came, so its
//! signature still holds.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use http::HeaderMap;
use http_body::{Frame, SizeHint};
use roxy_http::coding::{self, Coding, DecodeError, Decoder};
use roxy_http::{Body, BodyError, CanonicalRequest, CanonicalResponse};
use roxy_rules::BodySide;

use crate::in_flight::{Dir, InFlight, Stopped};
use crate::pipeline::{FlowCx, Refusal, known_empty, response_known_empty};
use crate::{budget, recode};

/// Flow-log `reason` of a body whose coding failed while it was scanned.
const UNDECODABLE: &str = "body_decode_failed";

/// Flow-log `reason` of a body in a coding roxy does not decode.
const UNSUPPORTED: &str = "unsupported_content_encoding";

/// Puts the request body through its text tests, if a rule reads
/// `body.text`. An empty body is decided here, before anything is sent.
pub(crate) fn request(
    cx: &FlowCx,
    req: &mut CanonicalRequest,
    in_flight: &Arc<InFlight>,
) -> Result<(), Refusal> {
    if cx.snap.policy.texts(BodySide::Request).is_empty() {
        return Ok(());
    }
    // Trailers alone, held to be signed, carry no data either; they must
    // go as they are, since an encoder would give them bytes the signature
    // does not cover.
    let held_empty = req.body.is_held() && req.body.as_bytes().is_none();
    if known_empty(&req.body) || held_empty {
        return in_flight.on_text_end(Dir::Request).map_err(refusal);
    }
    let Ok(codings) = coding::content_codings(&req.headers) else {
        return Err(Refusal::fail_closed(UNSUPPORTED));
    };
    let limit = cx.snap.limits.max_request_body_bytes;
    if codings.is_empty() {
        req.body = TextBody::wrap(std::mem::take(&mut req.body), in_flight, Dir::Request);
    } else if let Some(whole) = req.body.as_bytes() {
        scan_whole(cx, whole, &codings, limit, in_flight)?;
    } else {
        recode::decode(&cx.shared, &mut req.body, &codings, limit);
        req.body = TextBody::wrap(std::mem::take(&mut req.body), in_flight, Dir::Request);
        recode::encode(&cx.shared, &mut req.body, &codings);
        req.body = CoderFaults::wrap(std::mem::take(&mut req.body), in_flight, Dir::Request);
    }
    Ok(())
}

/// Puts the response body, decoded by now, through its text tests, if a
/// rule reads `response.body.text`.
pub(crate) fn response(
    cx: &FlowCx,
    res: &mut CanonicalResponse,
    in_flight: &Arc<InFlight>,
) -> Result<(), Refusal> {
    if cx.snap.policy.texts(BodySide::Response).is_empty() {
        return Ok(());
    }
    if response_known_empty(cx, res) {
        return in_flight.on_text_end(Dir::Response).map_err(refusal);
    }
    res.body = TextBody::wrap(std::mem::take(&mut res.body), in_flight, Dir::Response);
    Ok(())
}

/// Once the response is encoded again, names its coders' failures, if a
/// rule reads `response.body.text` ([`CoderFaults`]).
pub(crate) fn watch_response_coders(
    cx: &FlowCx,
    res: &mut CanonicalResponse,
    in_flight: &Arc<InFlight>,
) {
    if !cx.snap.policy.texts(BodySide::Response).is_empty() {
        res.body = CoderFaults::wrap(std::mem::take(&mut res.body), in_flight, Dir::Response);
    }
}

fn refusal(s: Stopped) -> Refusal {
    s.refusal
}

/// Decodes a body held whole and runs its text tests to the end, without
/// holding a decoded copy.
fn scan_whole(
    cx: &FlowCx,
    whole: &Bytes,
    codings: &[Coding],
    limit: u64,
    in_flight: &InFlight,
) -> Result<(), Refusal> {
    let mut dec = Decoder::new(codings, limit, cx.shared.window_meter());
    dec.feed(whole);
    dec.finish();
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = dec.read(&mut buf).map_err(|e| match e {
            DecodeError::BudgetExhausted => Refusal::fail_closed(budget::EXHAUSTED),
            DecodeError::Unsupported(_)
            | DecodeError::TooLarge { .. }
            | DecodeError::Invalid { .. } => Refusal::fail_closed(UNDECODABLE),
        })?;
        if n == 0 {
            return in_flight.on_text_end(Dir::Request).map_err(refusal);
        }
        in_flight
            .on_text(Dir::Request, &buf[..n])
            .map_err(refusal)?;
    }
}

/// Names the failures of the coders around a scanned body: a coding that
/// fails, or a window the budget refuses, is roxy's refusal, not a peer
/// cutting the body short. It sits outside the coders, so it sees both the
/// decoder's failures and the encoder's.
struct CoderFaults {
    inner: Body,
    in_flight: Arc<InFlight>,
    dir: Dir,
}

impl CoderFaults {
    fn wrap(body: Body, in_flight: &Arc<InFlight>, dir: Dir) -> Body {
        let known = body.known_length();
        Body::wrap_native(
            Self {
                inner: body,
                in_flight: in_flight.clone(),
                dir,
            },
            u64::MAX,
            known,
        )
    }
}

impl http_body::Body for CoderFaults {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = &mut *self;
        let polled = Pin::new(&mut this.inner).poll_frame(cx);
        if let Poll::Ready(Some(Err(e))) = &polled {
            this.in_flight.body_failed(this.dir, e);
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// A body whose bytes go only once the text tests let them.
struct TextBody {
    inner: Body,
    in_flight: Arc<InFlight>,
    dir: Dir,
    /// Scanned but not yet forwarded.
    held: BytesMut,
    trailers: Option<HeaderMap>,
    /// The inner body ended and every test is decided.
    ended: bool,
    done: bool,
}

impl TextBody {
    /// Framing (a known length) is kept: holding back moves no byte.
    fn wrap(body: Body, in_flight: &Arc<InFlight>, dir: Dir) -> Body {
        let known = body.known_length();
        Body::wrap_native(
            Self {
                inner: body,
                in_flight: in_flight.clone(),
                dir,
                held: BytesMut::new(),
                trailers: None,
                ended: false,
                done: false,
            },
            u64::MAX,
            known,
        )
    }

    fn stop(&mut self) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        self.done = true;
        self.held.clear();
        self.trailers = None;
        Poll::Ready(Some(Err(BodyError::Stopped)))
    }

    /// What is still held, then the trailers, once every test is decided.
    fn drain(&mut self) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        if !self.held.is_empty() {
            return Poll::Ready(Some(Ok(Frame::data(self.held.split().freeze()))));
        }
        self.done = true;
        Poll::Ready(self.trailers.take().map(|t| Ok(Frame::trailers(t))))
    }
}

impl http_body::Body for TextBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = &mut *self;
        loop {
            if this.done {
                return Poll::Ready(None);
            }
            if this.ended {
                return this.drain();
            }
            let data = match Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(d) => Some(d),
                    Err(frame) => {
                        this.trailers = frame.into_trailers().ok();
                        None
                    }
                },
                Poll::Ready(None) => None,
                Poll::Ready(Some(Err(e))) => {
                    this.done = true;
                    return Poll::Ready(Some(Err(e)));
                }
            };
            let Some(d) = data else {
                // The end, or trailers, which only come at it.
                if this.in_flight.on_text_end(this.dir).is_err() {
                    return this.stop();
                }
                this.ended = true;
                continue;
            };
            let Ok(hold) = this.in_flight.on_text(this.dir, &d) else {
                return this.stop();
            };
            // The consumer may not poll again once the body says it has
            // ended, so settle the end before handing anything on.
            if this.inner.is_end_stream() {
                this.held.extend_from_slice(&d);
                if this.in_flight.on_text_end(this.dir).is_err() {
                    return this.stop();
                }
                this.ended = true;
                continue;
            }
            if this.held.is_empty() && hold == 0 {
                if d.is_empty() {
                    continue;
                }
                return Poll::Ready(Some(Ok(Frame::data(d))));
            }
            this.held.extend_from_slice(&d);
            let release = this.held.len() - hold.min(this.held.len());
            if release > 0 {
                return Poll::Ready(Some(Ok(Frame::data(this.held.split_to(release).freeze()))));
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done || (self.ended && self.held.is_empty() && self.trailers.is_none())
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
