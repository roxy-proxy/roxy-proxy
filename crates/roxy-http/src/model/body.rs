//! Streaming bodies with size caps.

use std::fmt;
use std::future::poll_fn;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes, BytesMut};
use http::HeaderMap;
use http_body::{Frame, SizeHint};
use tokio::sync::mpsc;

use super::error::BodyError;
use crate::len_u64;

/// Frames buffered in a body channel before the sender blocks
/// (backpressure). With the h1 codec's read size this bounds per-request
/// buffering to a few hundred KiB.
pub const CHANNEL_DEPTH: usize = 8;

enum Msg {
    Data(Bytes),
    Trailers(HeaderMap),
    End,
    Error(BodyError),
}

enum Inner {
    Empty,
    Full(Option<Bytes>),
    Channel {
        rx: mpsc::Receiver<Msg>,
        done: bool,
    },
    Boxed {
        /// The mutex is never locked (only `get_mut`); it exists to make
        /// `Body: Sync` without requiring the wrapped body to be `Sync`.
        body: Mutex<BoxedBody>,
        done: bool,
    },
    /// `first` (a frame already read from `rest`), then `rest`. Boxed so
    /// `Body` (held by many connection futures) stays small.
    Prefixed(Box<Prefixed>),
}

struct Prefixed {
    first: Option<Frame<Bytes>>,
    rest: Body,
}

type BoxedBody = Pin<Box<dyn http_body::Body<Data = Bytes, Error = BodyError> + Send + 'static>>;

/// A request or response body: `'static + Send + Sync`, implements
/// [`http_body::Body`] so it can be handed straight to hyper.
///
/// A body that ends before it is complete (producer dropped, cap exceeded,
/// length mismatch) always yields an error as its last frame; it never ends
/// cleanly, so a truncated body cannot be forwarded as if it were whole.
pub struct Body {
    inner: Inner,
    known_length: Option<u64>,
}

impl fmt::Debug for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match &self.inner {
            Inner::Empty => "empty",
            Inner::Full(_) => "full",
            Inner::Channel { .. } => "channel",
            Inner::Boxed { .. } => "boxed",
            Inner::Prefixed(_) => "prefixed",
        };
        f.debug_struct("Body")
            .field("kind", &kind)
            .field("known_length", &self.known_length)
            .finish()
    }
}

impl Default for Body {
    fn default() -> Self {
        Self::empty()
    }
}

impl Body {
    /// An empty body of known length 0.
    pub fn empty() -> Self {
        Self {
            inner: Inner::Empty,
            known_length: Some(0),
        }
    }

    /// A body from a single buffer.
    pub fn from_bytes(b: impl Into<Bytes>) -> Self {
        let b = b.into();
        let len = len_u64(b.len());
        if len == 0 {
            return Self::empty();
        }
        Self {
            inner: Inner::Full(Some(b)),
            known_length: Some(len),
        }
    }

    /// A channel-backed body. The sender enforces `max_bytes` and (if given)
    /// `known_length`. At most [`CHANNEL_DEPTH`] frames are in flight.
    pub fn channel(max_bytes: u64, known_length: Option<u64>) -> (BodySender, Body) {
        let (tx, rx) = mpsc::channel(CHANNEL_DEPTH);
        (
            BodySender {
                tx,
                sent: 0,
                max: max_bytes,
                known_length,
                failed: false,
            },
            Body {
                inner: Inner::Channel { rx, done: false },
                known_length,
            },
        )
    }

    /// Adapts any body, applying `max_bytes` as frames flow through (no
    /// buffering). The known length is taken from the inner body's exact
    /// size hint. Inner errors become [`BodyError::Upstream`].
    pub fn wrap<B>(body: B, max_bytes: u64) -> Self
    where
        B: http_body::Body + Send + 'static,
        B::Data: Send,
        B::Error: fmt::Display,
    {
        let known = body.size_hint().exact();
        Self::wrap_with_length(body, max_bytes, known)
    }

    /// Like [`Body::wrap`] with an explicitly declared length (e.g. from a
    /// `content-length` field). Any mismatch between the declared length and
    /// the bytes that flow ends the body with [`BodyError::LengthMismatch`].
    pub fn wrap_with_length<B>(body: B, max_bytes: u64, known_length: Option<u64>) -> Self
    where
        B: http_body::Body + Send + 'static,
        B::Data: Send,
        B::Error: fmt::Display,
    {
        Self::capped(body, max_bytes, known_length, |e: B::Error| {
            BodyError::Upstream(e.to_string())
        })
    }

    /// Like [`Body::wrap_with_length`] for an adapter over a [`Body`]: its
    /// [`BodyError`]s pass through unchanged (so a [`BodyError::Stopped`]
    /// stays recognisable), instead of becoming [`BodyError::Upstream`].
    pub fn wrap_native<B>(body: B, max_bytes: u64, known_length: Option<u64>) -> Self
    where
        B: http_body::Body<Error = BodyError> + Send + 'static,
        B::Data: Send,
    {
        Self::capped(body, max_bytes, known_length, |e: BodyError| e)
    }

    fn capped<B>(
        body: B,
        max_bytes: u64,
        known_length: Option<u64>,
        map_err: fn(B::Error) -> BodyError,
    ) -> Self
    where
        B: http_body::Body + Send + 'static,
        B::Data: Send,
    {
        if known_length == Some(0) && body.is_end_stream() {
            return Self::empty();
        }
        Self {
            inner: Inner::Boxed {
                body: Mutex::new(Box::pin(Capped {
                    inner: Box::pin(body),
                    seen: 0,
                    max: max_bytes,
                    known: known_length,
                    map_err,
                })),
                done: false,
            },
            known_length,
        }
    }

    /// Declared length, when known (`content-length` framing on the wire).
    pub fn known_length(&self) -> Option<u64> {
        self.known_length
    }

    /// Buffers the whole body (for inspection paths). Fails with
    /// [`BodyError::TooLarge`] as soon as more than `max` bytes arrive.
    /// Trailers are discarded.
    pub async fn collect_up_to(mut self, max: u64) -> Result<Bytes, BodyError> {
        if let Some(n) = self.known_length
            && n > max
        {
            return Err(BodyError::TooLarge { limit: max });
        }
        let mut buf = BytesMut::new();
        loop {
            let frame = poll_fn(|cx| http_body::Body::poll_frame(Pin::new(&mut self), cx)).await;
            match frame {
                None => return Ok(buf.freeze()),
                Some(Err(e)) => return Err(e),
                Some(Ok(f)) => {
                    if let Ok(d) = f.into_data() {
                        if len_u64(buf.len() + d.len()) > max {
                            return Err(BodyError::TooLarge { limit: max });
                        }
                        buf.extend_from_slice(&d);
                    }
                }
            }
        }
    }
}

impl Body {
    /// Buffers at most the first `max` bytes of the body, for inspection,
    /// without losing the rest. Returns `(prefix, remainder)`:
    ///
    /// * `remainder == None`: the body ended cleanly and `prefix` is all of
    ///   it (`prefix.len() <= max`).
    /// * `remainder == Some(rest)`: `prefix` holds exactly `max` bytes (fewer
    ///   only if trailers followed the data) and `rest` yields everything
    ///   after them — the rest of the data, any trailers, and any error the
    ///   stream ends with — so `prefix` followed by `rest` is the original
    ///   stream. `rest` keeps the original's caps and length checks, and its
    ///   [`Body::known_length`] is the original's minus `prefix.len()`.
    ///
    /// An error before `max` bytes (or before the end of a shorter body) is
    /// returned as `Err` and the body is consumed. Allocates at most `max`
    /// bytes plus one frame. To decide whether a body is longer than `max`
    /// when the length is unknown, this waits for the frame after the
    /// first `max` bytes (or the end of the stream).
    pub async fn collect_prefix(mut self, max: u64) -> Result<(Bytes, Option<Body>), BodyError> {
        let cap = usize::try_from(max).unwrap_or(usize::MAX);
        let mut buf = BytesMut::with_capacity(
            cap.min(usize::try_from(self.known_length.unwrap_or(0)).unwrap_or(usize::MAX))
                .min(64 * 1024),
        );
        loop {
            let frame = poll_fn(|cx| http_body::Body::poll_frame(Pin::new(&mut self), cx)).await;
            let frame = match frame {
                None => return Ok((buf.freeze(), None)),
                Some(Err(e)) => return Err(e),
                Some(Ok(f)) => f,
            };
            let mut data = match frame.into_data() {
                Ok(d) if d.is_empty() => continue,
                Ok(d) => d,
                Err(trailers) => {
                    // Trailers end the data: hand them back as the rest.
                    let len = len_u64(buf.len());
                    return Ok((buf.freeze(), Some(self.prefixed(Some(trailers), len))));
                }
            };
            let room = cap - buf.len();
            if data.len() < room {
                buf.extend_from_slice(&data);
                continue;
            }
            if data.len() == room {
                // Exactly `max` bytes so far: the body is longer only if
                // anything else follows. Peek one more frame.
                buf.extend_from_slice(&data);
                let len = len_u64(buf.len());
                let next = poll_fn(|cx| http_body::Body::poll_frame(Pin::new(&mut self), cx)).await;
                return match next {
                    None => Ok((buf.freeze(), None)),
                    Some(Err(e)) => Err(e),
                    Some(Ok(f)) => Ok((buf.freeze(), Some(self.prefixed(Some(f), len)))),
                };
            }
            let tail = data.split_off(room);
            buf.extend_from_slice(&data);
            let len = len_u64(buf.len());
            return Ok((
                buf.freeze(),
                Some(self.prefixed(Some(Frame::data(tail)), len)),
            ));
        }
    }

    /// `first` then the rest of `self`, which has already yielded `taken`
    /// data bytes.
    fn prefixed(self, first: Option<Frame<Bytes>>, taken: u64) -> Body {
        let known_length = self.known_length.map(|k| k.saturating_sub(taken));
        Body {
            inner: Inner::Prefixed(Box::new(Prefixed { first, rest: self })),
            known_length,
        }
    }
}

impl http_body::Body for Body {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        match &mut self.inner {
            Inner::Empty => Poll::Ready(None),
            Inner::Full(b) => Poll::Ready(b.take().map(|b| Ok(Frame::data(b)))),
            Inner::Channel { rx, done } => {
                if *done {
                    return Poll::Ready(None);
                }
                let out = match rx.poll_recv(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Some(Msg::Data(b))) => Some(Ok(Frame::data(b))),
                    Poll::Ready(Some(Msg::Trailers(t))) => Some(Ok(Frame::trailers(t))),
                    Poll::Ready(Some(Msg::End)) => {
                        *done = true;
                        None
                    }
                    Poll::Ready(Some(Msg::Error(e))) => {
                        *done = true;
                        Some(Err(e))
                    }
                    Poll::Ready(None) => {
                        *done = true;
                        Some(Err(BodyError::Incomplete))
                    }
                };
                Poll::Ready(out)
            }
            Inner::Prefixed(p) => match p.first.take() {
                Some(f) => Poll::Ready(Some(Ok(f))),
                None => Pin::new(&mut p.rest).poll_frame(cx),
            },
            Inner::Boxed { body, done } => {
                if *done {
                    return Poll::Ready(None);
                }
                let body = match body.get_mut() {
                    Ok(b) => b,
                    Err(poisoned) => poisoned.into_inner(),
                };
                let r = body.as_mut().poll_frame(cx);
                if matches!(r, Poll::Ready(None | Some(Err(_)))) {
                    *done = true;
                }
                r
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.inner {
            Inner::Empty | Inner::Full(None) => true,
            Inner::Full(Some(_)) => false,
            Inner::Channel { done, .. } | Inner::Boxed { done, .. } => *done,
            Inner::Prefixed(p) => p.first.is_none() && p.rest.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self.known_length {
            Some(n) => SizeHint::with_exact(n),
            None => SizeHint::default(),
        }
    }
}

struct Capped<B: http_body::Body> {
    inner: Pin<Box<B>>,
    seen: u64,
    max: u64,
    known: Option<u64>,
    map_err: fn(B::Error) -> BodyError,
}

impl<B> http_body::Body for Capped<B>
where
    B: http_body::Body,
{
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = &mut *self;
        match this.inner.as_mut().poll_frame(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                if this.known.is_some_and(|k| k != this.seen) {
                    return Poll::Ready(Some(Err(BodyError::LengthMismatch)));
                }
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err((this.map_err)(e)))),
            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(mut d) => {
                    let bytes = d.copy_to_bytes(d.remaining());
                    this.seen += len_u64(bytes.len());
                    if this.seen > this.max {
                        return Poll::Ready(Some(Err(BodyError::TooLarge { limit: this.max })));
                    }
                    if this.known.is_some_and(|k| this.seen > k) {
                        return Poll::Ready(Some(Err(BodyError::LengthMismatch)));
                    }
                    Poll::Ready(Some(Ok(Frame::data(bytes))))
                }
                Err(frame) => {
                    if let Ok(t) = frame.into_trailers() {
                        Poll::Ready(Some(Ok(Frame::trailers(t))))
                    } else {
                        // Unknown frame kinds are dropped.
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                }
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Producer side of [`Body::channel`]. Not `Clone`: there is exactly one
/// producer, which makes [`BodySender::ready`] + [`BodySender::try_push`]
/// race-free.
///
/// The body completes cleanly only via [`BodySender::finish`]. Dropping the
/// sender without finishing makes the body end with
/// [`BodyError::Incomplete`].
#[derive(Debug)]
pub struct BodySender {
    tx: mpsc::Sender<Msg>,
    sent: u64,
    max: u64,
    known_length: Option<u64>,
    failed: bool,
}

impl BodySender {
    /// Whether the consumer has dropped the body.
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }

    /// Waits until a frame can be pushed without blocking. Cancel-safe.
    pub async fn ready(&mut self) -> Result<(), BodyError> {
        if self.failed {
            return Err(BodyError::Closed);
        }
        self.tx
            .reserve()
            .await
            .map(drop)
            .map_err(|_| BodyError::Closed)
    }

    fn fail(&mut self, e: BodyError) -> BodyError {
        self.failed = true;
        // Best effort: if the channel is full the consumer will see
        // `Incomplete` instead once the sender is dropped.
        let _ = self.tx.try_send(Msg::Error(e.clone()));
        e
    }

    /// Pushes a data frame. Enforces the byte cap and the declared length;
    /// on violation an error is delivered to the consumer and returned here.
    /// Call [`BodySender::ready`] first; if the channel is full this returns
    /// [`BodyError::Closed`] without consuming capacity semantics.
    pub fn try_push(&mut self, data: Bytes) -> Result<(), BodyError> {
        if self.failed {
            return Err(BodyError::Closed);
        }
        if data.is_empty() {
            return Ok(());
        }
        let total = self.sent + len_u64(data.len());
        if total > self.max {
            return Err(self.fail(BodyError::TooLarge { limit: self.max }));
        }
        if self.known_length.is_some_and(|k| total > k) {
            return Err(self.fail(BodyError::LengthMismatch));
        }
        match self.tx.try_send(Msg::Data(data)) {
            Ok(()) => {
                self.sent = total;
                Ok(())
            }
            Err(_) => Err(BodyError::Closed),
        }
    }

    /// Sends a data frame, waiting for capacity. Not cancel-safe (the frame
    /// is lost if the future is dropped); use `ready` + `try_push` in
    /// `select!` loops.
    pub async fn send_data(&mut self, data: Bytes) -> Result<(), BodyError> {
        self.ready().await?;
        self.try_push(data)
    }

    /// Pushes a trailers frame (only when the protocol layer allows
    /// trailers). Call [`BodySender::ready`] first.
    pub fn try_push_trailers(&mut self, trailers: HeaderMap) -> Result<(), BodyError> {
        if self.failed {
            return Err(BodyError::Closed);
        }
        self.tx
            .try_send(Msg::Trailers(trailers))
            .map_err(|_| BodyError::Closed)
    }

    /// Sends a trailers frame, waiting for capacity.
    pub async fn send_trailers(&mut self, trailers: HeaderMap) -> Result<(), BodyError> {
        self.ready().await?;
        self.try_push_trailers(trailers)
    }

    /// Completes the body without waiting. Fails (and errors the body) if
    /// fewer bytes than the declared length were sent. Call
    /// [`BodySender::ready`] first.
    pub fn try_finish(mut self) -> Result<(), BodyError> {
        if self.failed {
            return Err(BodyError::Closed);
        }
        if self.known_length.is_some_and(|k| k != self.sent) {
            return Err(self.fail(BodyError::LengthMismatch));
        }
        self.tx.try_send(Msg::End).map_err(|_| BodyError::Closed)
    }

    /// Completes the body, waiting for capacity.
    pub async fn finish(mut self) -> Result<(), BodyError> {
        if self.known_length.is_some_and(|k| k != self.sent) {
            return Err(self.fail(BodyError::LengthMismatch));
        }
        self.ready().await?;
        self.try_finish()
    }

    /// Ends the body with an error (best effort; if undeliverable the body
    /// still ends with [`BodyError::Incomplete`]).
    pub fn abort(mut self, err: BodyError) {
        let _ = self.fail(err);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body::Body as _;

    async fn frames(mut b: Body) -> Vec<Result<Bytes, BodyError>> {
        let mut out = Vec::new();
        while let Some(f) = poll_fn(|cx| Pin::new(&mut b).poll_frame(cx)).await {
            out.push(f.map(|f| f.into_data().unwrap_or_default()));
        }
        out
    }

    #[test]
    fn body_is_send_sync_static() {
        fn assert_bounds<T: Send + Sync + 'static>() {}
        assert_bounds::<Body>();
        assert_bounds::<BodySender>();
        assert_bounds::<crate::CanonicalRequest>();
        assert_bounds::<crate::CanonicalResponse>();
    }

    #[tokio::test]
    async fn channel_happy_path() {
        let (mut tx, body) = Body::channel(10, None);
        let h = tokio::spawn(async move {
            tx.send_data(Bytes::from_static(b"abc")).await.unwrap();
            tx.send_data(Bytes::from_static(b"de")).await.unwrap();
            tx.finish().await.unwrap();
        });
        assert_eq!(body.collect_up_to(100).await.unwrap(), "abcde");
        h.await.unwrap();
    }

    #[tokio::test]
    async fn channel_cap_enforced_on_sender() {
        let (mut tx, body) = Body::channel(4, None);
        tx.send_data(Bytes::from_static(b"abc")).await.unwrap();
        let e = tx.send_data(Bytes::from_static(b"de")).await.unwrap_err();
        assert_eq!(e, BodyError::TooLarge { limit: 4 });
        drop(tx);
        let f = frames(body).await;
        assert_eq!(f[0].as_ref().unwrap(), "abc");
        assert_eq!(f[1], Err(BodyError::TooLarge { limit: 4 }));
        assert_eq!(f.len(), 2);
    }

    #[tokio::test]
    async fn dropped_sender_is_incomplete() {
        let (mut tx, body) = Body::channel(100, None);
        tx.send_data(Bytes::from_static(b"x")).await.unwrap();
        drop(tx);
        let f = frames(body).await;
        assert_eq!(f.last().unwrap(), &Err(BodyError::Incomplete));
    }

    #[tokio::test]
    async fn known_length_enforced() {
        let (mut tx, body) = Body::channel(100, Some(3));
        assert_eq!(body.size_hint().exact(), Some(3));
        tx.send_data(Bytes::from_static(b"ab")).await.unwrap();
        assert_eq!(tx.finish().await.unwrap_err(), BodyError::LengthMismatch);
        assert_eq!(
            frames(body).await.last().unwrap(),
            &Err(BodyError::LengthMismatch)
        );

        let (mut tx, _body) = Body::channel(100, Some(1));
        assert_eq!(
            tx.send_data(Bytes::from_static(b"ab")).await.unwrap_err(),
            BodyError::LengthMismatch
        );
    }

    #[tokio::test]
    async fn closed_receiver() {
        let (mut tx, body) = Body::channel(100, None);
        drop(body);
        assert!(tx.is_closed());
        assert_eq!(
            tx.send_data(Bytes::from_static(b"x")).await.unwrap_err(),
            BodyError::Closed
        );
    }

    #[tokio::test]
    async fn wrap_caps() {
        let inner = http_body_util::Full::new(Bytes::from_static(b"hello world"));
        let b = Body::wrap(inner, 5);
        assert_eq!(b.known_length(), Some(11));
        assert_eq!(
            frames(b).await.last().unwrap(),
            &Err(BodyError::TooLarge { limit: 5 })
        );
        let inner = http_body_util::Full::new(Bytes::from_static(b"hello"));
        assert_eq!(
            Body::wrap(inner, 5).collect_up_to(5).await.unwrap(),
            "hello"
        );
    }

    async fn prefix_of(body: Body, max: u64) -> (Bytes, Option<Vec<Result<Bytes, BodyError>>>) {
        let (p, rest) = body.collect_prefix(max).await.unwrap();
        let rest = match rest {
            Some(r) => Some(frames(r).await),
            None => None,
        };
        (p, rest)
    }

    fn chunked(parts: &'static [&'static [u8]], known: Option<u64>) -> Body {
        let (mut tx, body) = Body::channel(1 << 20, known);
        tokio::spawn(async move {
            for p in parts {
                tx.send_data(Bytes::from_static(p)).await.unwrap();
            }
            tx.finish().await.unwrap();
        });
        body
    }

    #[tokio::test]
    async fn collect_prefix_known_length() {
        // Shorter than max: the whole body, no remainder.
        assert_eq!(
            prefix_of(Body::from_bytes("hello"), 10).await,
            (Bytes::from_static(b"hello"), None)
        );
        // Exactly max: no remainder.
        assert_eq!(
            prefix_of(Body::from_bytes("hello"), 5).await,
            (Bytes::from_static(b"hello"), None)
        );
        assert_eq!(prefix_of(Body::empty(), 0).await, (Bytes::new(), None));
        // Longer: split inside the frame; the rest keeps the length.
        let (p, rest) = Body::from_bytes("hello world")
            .collect_prefix(4)
            .await
            .unwrap();
        assert_eq!(p, "hell");
        let rest = rest.unwrap();
        assert_eq!(rest.known_length(), Some(7));
        assert_eq!(rest.size_hint().exact(), Some(7));
        assert_eq!(rest.collect_up_to(100).await.unwrap(), "o world");
        // max 0: everything is remainder.
        let (p, rest) = Body::from_bytes("abc").collect_prefix(0).await.unwrap();
        assert!(p.is_empty());
        assert_eq!(rest.unwrap().collect_up_to(3).await.unwrap(), "abc");
        // Channel with a declared length, split across frames.
        let (p, rest) = chunked(&[b"ab", b"cd", b"ef"], Some(6))
            .collect_prefix(3)
            .await
            .unwrap();
        assert_eq!(p, "abc");
        let rest = rest.unwrap();
        assert_eq!(rest.known_length(), Some(3));
        assert_eq!(rest.collect_up_to(3).await.unwrap(), "def");
    }

    #[tokio::test]
    async fn collect_prefix_unknown_length() {
        assert_eq!(
            prefix_of(chunked(&[b"ab", b"cd"], None), 10).await,
            (Bytes::from_static(b"abcd"), None)
        );
        // Ends exactly at max: the peek sees the clean end.
        assert_eq!(
            prefix_of(chunked(&[b"ab", b"cd"], None), 4).await,
            (Bytes::from_static(b"abcd"), None)
        );
        // Frame boundary at max with more to come: the next frame is the rest.
        let (p, rest) = prefix_of(chunked(&[b"ab", b"cd", b"ef"], None), 4).await;
        assert_eq!(p, "abcd");
        assert_eq!(rest.unwrap(), vec![Ok(Bytes::from_static(b"ef"))]);
        // Split mid-frame.
        let (p, rest) = prefix_of(chunked(&[b"abc", b"def", b"g"], None), 4).await;
        assert_eq!(p, "abcd");
        assert_eq!(
            rest.unwrap(),
            vec![Ok(Bytes::from_static(b"ef")), Ok(Bytes::from_static(b"g"))]
        );
    }

    #[tokio::test]
    async fn collect_prefix_errors_and_trailers() {
        // An error inside the prefix is returned.
        let (mut tx, body) = Body::channel(100, None);
        tx.send_data(Bytes::from_static(b"ab")).await.unwrap();
        drop(tx);
        assert_eq!(
            body.collect_prefix(10).await.unwrap_err(),
            BodyError::Incomplete
        );
        // An error after the prefix stays in the remainder: never a clean end.
        let (mut tx, body) = Body::channel(100, None);
        tx.send_data(Bytes::from_static(b"abcdef")).await.unwrap();
        drop(tx);
        let (p, rest) = prefix_of(body, 2).await;
        assert_eq!(p, "ab");
        assert_eq!(
            rest.unwrap(),
            vec![Ok(Bytes::from_static(b"cdef")), Err(BodyError::Incomplete)]
        );
        // The body's own cap still applies.
        let capped = Body::wrap(
            http_body_util::Full::new(Bytes::from_static(b"0123456789")),
            5,
        );
        assert_eq!(
            capped.collect_prefix(2).await.unwrap_err(),
            BodyError::TooLarge { limit: 5 }
        );
        // Trailers after the data come back as the remainder.
        let (mut tx, body) = Body::channel(100, None);
        tx.send_data(Bytes::from_static(b"ab")).await.unwrap();
        let mut t = HeaderMap::new();
        t.insert("x-t", http::HeaderValue::from_static("1"));
        tx.send_trailers(t).await.unwrap();
        tx.finish().await.unwrap();
        let (p, rest) = body.collect_prefix(10).await.unwrap();
        assert_eq!(p, "ab");
        let mut rest = rest.unwrap();
        let f = poll_fn(|cx| Pin::new(&mut rest).poll_frame(cx))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(f.into_trailers().unwrap()["x-t"], "1");
        assert!(
            poll_fn(|cx| Pin::new(&mut rest).poll_frame(cx))
                .await
                .is_none()
        );
        assert!(rest.is_end_stream());
    }

    #[tokio::test]
    async fn collect_cap() {
        assert_eq!(
            Body::from_bytes("abcdef")
                .collect_up_to(3)
                .await
                .unwrap_err(),
            BodyError::TooLarge { limit: 3 }
        );
        assert!(Body::empty().is_end_stream());
        assert_eq!(Body::from_bytes("").known_length(), Some(0));
    }
}
