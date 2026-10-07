//! Body helpers: byte counting and digesting as frames stream, bounded
//! buffering for body-inspecting rules that never loses the rest of the
//! stream, and the gate that keeps request trailers off HTTP/1.1 upstreams.

use std::future::poll_fn;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use http_body::{Frame, SizeHint};
use ring::digest::{Context as Digest, SHA256};
use roxy_http::{Body, BodyError, ParseError, Reason};
use tokio_util::sync::CancellationToken;

/// What a [`counted`] body has let through: the byte count as it grows,
/// and the SHA-256 of the whole body once it has completed.
#[derive(Debug, Default)]
pub(crate) struct Tally {
    bytes: AtomicU64,
    sha256: OnceLock<[u8; 32]>,
}

impl Tally {
    /// Data bytes that have flowed through so far.
    pub(crate) fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }

    /// Lower-case hex SHA-256 of the body, once it has ended cleanly.
    /// `None` while it is still flowing, and for good if it failed or was
    /// dropped before its end.
    pub(crate) fn sha256_hex(&self) -> Option<String> {
        self.sha256.get().map(|d| hex(d))
    }
}

/// Lower-case hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Counts and digests data bytes as they pass through.
struct Counted {
    inner: Body,
    tally: Arc<Tally>,
    known: Option<u64>,
    /// The running digest; taken at the body's end, or discarded when the
    /// body fails.
    digest: Option<Digest>,
    /// Cancelled once the body has ended, failed or been dropped.
    ended: Option<CancellationToken>,
}

impl Counted {
    /// Publishes the digest once the body is complete: it reported its
    /// end, or every byte of its declared length has passed (a sender
    /// that falls short fails the body instead). A consumer may not poll
    /// again once it has what it needs (hyper never polls an empty body,
    /// and its h1 client drops a body once the declared bytes are
    /// written), so this runs after each frame and on drop.
    fn finish_if_ended(&mut self) {
        let complete = http_body::Body::is_end_stream(&self.inner)
            || self.known.is_some_and(|n| n == self.tally.bytes());
        if complete && let Some(d) = self.digest.take() {
            let mut out = [0u8; 32];
            out.copy_from_slice(d.finish().as_ref());
            let _ = self.tally.sha256.set(out);
        }
    }
}

impl Drop for Counted {
    fn drop(&mut self) {
        self.finish_if_ended();
        if let Some(t) = &self.ended {
            t.cancel();
        }
    }
}

impl http_body::Body for Counted {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let r = Pin::new(&mut self.inner).poll_frame(cx);
        match &r {
            Poll::Ready(Some(Ok(f))) => {
                if let Some(d) = f.data_ref() {
                    self.tally
                        .bytes
                        .fetch_add(d.len() as u64, Ordering::Relaxed);
                    if let Some(h) = self.digest.as_mut() {
                        h.update(d);
                    }
                }
                self.finish_if_ended();
            }
            Poll::Ready(None) => {
                self.finish_if_ended();
                if let Some(t) = &self.ended {
                    t.cancel();
                }
            }
            Poll::Ready(Some(Err(_))) => {
                self.digest = None;
                if let Some(t) = &self.ended {
                    t.cancel();
                }
            }
            Poll::Pending => {}
        }
        r
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Wraps `body` so the returned tally tracks the data bytes that have
/// flowed through it, and their digest once it has ended. Framing (known
/// length) is preserved.
pub(crate) fn counted(body: Body) -> (Body, Arc<Tally>) {
    wrap_counted(body, None)
}

/// [`counted`], plus a token cancelled once the body is done with: it
/// ended, failed, or its consumer dropped it (an HTTP client drops a
/// request body once it has been sent, or never polls an empty one).
pub(crate) fn counted_until_sent(body: Body) -> (Body, Arc<Tally>, CancellationToken) {
    let ended = CancellationToken::new();
    let (body, tally) = wrap_counted(body, Some(ended.clone()));
    (body, tally, ended)
}

fn wrap_counted(body: Body, ended: Option<CancellationToken>) -> (Body, Arc<Tally>) {
    let tally = Arc::new(Tally::default());
    let known = body.known_length();
    let body = Body::wrap_native(
        Counted {
            inner: body,
            tally: tally.clone(),
            known,
            digest: Some(Digest::new(&SHA256)),
            ended,
        },
        u64::MAX,
        known,
    );
    (body, tally)
}

/// Fails instead of yielding trailers that would not reach the upstream.
struct TrailersGate {
    inner: Body,
    /// Whether the body may be on an HTTP/1.1 connection, asked only when
    /// a trailers frame arrives.
    may_be_h1: Box<dyn Fn() -> bool + Send + Sync>,
    done: bool,
}

impl http_body::Body for TrailersGate {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        if self.done {
            return Poll::Ready(None);
        }
        let r = Pin::new(&mut self.inner).poll_frame(cx);
        match &r {
            Poll::Ready(Some(Ok(f))) if f.is_trailers() && (self.may_be_h1)() => {
                self.done = true;
                let e =
                    ParseError::new(Reason::Trailers, "request trailers need an HTTP/2 upstream");
                return Poll::Ready(Some(Err(BodyError::Invalid(e))));
            }
            Poll::Ready(None | Some(Err(_))) => self.done = true,
            Poll::Ready(Some(Ok(_))) | Poll::Pending => {}
        }
        r
    }

    fn is_end_stream(&self) -> bool {
        self.done || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Request trailers reach an upstream only over HTTP/2: hyper's HTTP/1.1
/// encoder drops them, since nothing announced their names. When a
/// trailers frame arrives and `may_be_h1` says the body may be on an
/// HTTP/1.1 connection, the body fails with [`Reason::Trailers`] instead,
/// so the upstream never sees it complete and the exchange says why.
pub(crate) fn trailers_need_h2(
    body: Body,
    may_be_h1: impl Fn() -> bool + Send + Sync + 'static,
) -> Body {
    let known = body.known_length();
    Body::wrap_native(
        TrailersGate {
            inner: body,
            may_be_h1: Box::new(may_be_h1),
            done: false,
        },
        u64::MAX,
        known,
    )
}

/// Replays `prefix`, then the rest of `rest`.
struct Chain {
    prefix: Option<Bytes>,
    rest: Body,
}

impl http_body::Body for Chain {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        if let Some(p) = self.prefix.take()
            && !p.is_empty()
        {
            return Poll::Ready(Some(Ok(Frame::data(p))));
        }
        Pin::new(&mut self.rest).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.prefix.as_ref().is_none_or(Bytes::is_empty) && self.rest.is_end_stream()
    }
}

/// Result of [`collect_prefix`].
#[derive(Debug)]
pub(crate) enum Collected {
    /// The whole body, at most `cap` bytes. The original body is now an
    /// equivalent `Body::from_bytes`.
    Complete(Bytes),
    /// More than `cap` bytes. Nothing was lost: the original body was
    /// replaced by the bytes read so far chained with the unread rest.
    TooLarge,
    /// The meter refused to cover the bytes read so far. Nothing was lost,
    /// as for `TooLarge`.
    BudgetExhausted,
    /// The body failed (client went away, framing error, cap). The body is
    /// now an error body; the flow must not be forwarded.
    Failed(BodyError),
}

/// Buffers up to `cap` bytes of `body` for inspection, replacing
/// `*body` with a stream that yields exactly the same bytes downstream.
/// Never pre-allocates from a declared length.
pub(crate) async fn collect_prefix(body: &mut Body, cap: u64) -> Collected {
    collect_prefix_metered(body, cap, &mut |_| true).await
}

/// [`collect_prefix`] with `meter` asked, after each data frame, whether
/// the bytes held so far may be kept; `false` stops with
/// [`Collected::BudgetExhausted`].
pub(crate) async fn collect_prefix_metered(
    body: &mut Body,
    cap: u64,
    meter: &mut (dyn FnMut(u64) -> bool + Send),
) -> Collected {
    let declared = body.known_length();
    if declared.is_some_and(|n| n > cap) {
        // Known to be too large: do not touch the stream at all.
        return Collected::TooLarge;
    }
    let mut buf = BytesMut::new();
    loop {
        let frame = poll_fn(|cx| http_body::Body::poll_frame(Pin::new(&mut *body), cx)).await;
        match frame {
            None => {
                let b = buf.freeze();
                *body = Body::from_bytes(b.clone());
                return Collected::Complete(b);
            }
            Some(Err(e)) => {
                *body = Body::wrap_native(ErrorBody(Some(e.clone())), u64::MAX, None);
                return Collected::Failed(e);
            }
            Some(Ok(f)) => {
                // Trailers are dropped, as `Body::collect_up_to` does; roxy
                // only accepts them with `http.allow_request_trailers`.
                if let Ok(d) = f.into_data() {
                    buf.extend_from_slice(&d);
                    let held = buf.len() as u64;
                    let stop = if held > cap {
                        Some(Collected::TooLarge)
                    } else if !meter(held) {
                        Some(Collected::BudgetExhausted)
                    } else {
                        None
                    };
                    if let Some(stop) = stop {
                        let rest = std::mem::take(body);
                        *body = Body::wrap_native(
                            Chain {
                                prefix: Some(buf.freeze()),
                                rest,
                            },
                            u64::MAX,
                            declared,
                        );
                        return stop;
                    }
                }
            }
        }
    }
}

/// A body that yields one error.
struct ErrorBody(Option<BodyError>);

impl http_body::Body for ErrorBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        Poll::Ready(self.0.take().map(Err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn drain(mut b: Body) -> Result<Vec<u8>, BodyError> {
        let mut out = Vec::new();
        while let Some(f) = poll_fn(|cx| http_body::Body::poll_frame(Pin::new(&mut b), cx)).await {
            if let Ok(d) = f?.into_data() {
                out.extend_from_slice(&d);
            }
        }
        Ok(out)
    }

    #[tokio::test]
    async fn until_sent_fires_at_the_end_or_on_drop() {
        let (b, c, sent) = counted_until_sent(Body::from_bytes("hello"));
        assert!(!sent.is_cancelled());
        assert_eq!(drain(b).await.unwrap(), b"hello");
        assert!(sent.is_cancelled());
        assert_eq!(c.bytes(), 5);
        let (b, _, sent) = counted_until_sent(Body::from_bytes("never polled"));
        drop(b);
        assert!(sent.is_cancelled());
    }

    const HELLO_SHA256: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[tokio::test]
    async fn counts_and_digests_bytes() {
        let (b, t) = counted(Body::from_bytes("hello"));
        assert_eq!(b.known_length(), Some(5));
        assert_eq!(t.sha256_hex(), None, "not before the end");
        assert_eq!(drain(b).await.unwrap(), b"hello");
        assert_eq!(t.bytes(), 5);
        assert_eq!(t.sha256_hex().as_deref(), Some(HELLO_SHA256));
    }

    #[tokio::test]
    async fn digest_spans_the_chunks() {
        let (mut tx, b) = Body::channel(1 << 20, None);
        let (b, t) = counted(b);
        tokio::spawn(async move {
            for part in ["he", "l", "lo"] {
                tx.ready().await.unwrap();
                tx.try_push(Bytes::from_static(part.as_bytes())).unwrap();
            }
            tx.ready().await.unwrap();
            tx.try_finish().unwrap();
        });
        assert_eq!(drain(b).await.unwrap(), b"hello");
        assert_eq!(t.sha256_hex().as_deref(), Some(HELLO_SHA256));
    }

    /// hyper's h1 client drops a body once its declared bytes are
    /// written, without polling for the end.
    #[tokio::test]
    async fn declared_length_reached_completes_the_digest() {
        let (mut tx, b) = Body::channel(1 << 20, Some(5));
        let (mut b, t) = counted(b);
        for part in ["hel", "lo"] {
            tx.ready().await.unwrap();
            tx.try_push(Bytes::from_static(part.as_bytes())).unwrap();
            let f = poll_fn(|cx| http_body::Body::poll_frame(Pin::new(&mut b), cx)).await;
            assert!(f.unwrap().is_ok());
        }
        assert_eq!(t.sha256_hex().as_deref(), Some(HELLO_SHA256));
        drop(b);
        assert_eq!(t.sha256_hex().as_deref(), Some(HELLO_SHA256));
    }

    #[tokio::test]
    async fn empty_body_has_the_empty_digest_even_unpolled() {
        let (b, t) = counted(Body::empty());
        drop(b);
        assert_eq!(t.bytes(), 0);
        assert_eq!(t.sha256_hex().as_deref(), Some(EMPTY_SHA256));
    }

    #[tokio::test]
    async fn aborted_body_has_no_digest() {
        // Dropped by its consumer mid-stream.
        let (mut tx, b) = Body::channel(1 << 20, None);
        let (mut b, t) = counted(b);
        tx.ready().await.unwrap();
        tx.try_push(Bytes::from_static(b"hel")).unwrap();
        let f = poll_fn(|cx| http_body::Body::poll_frame(Pin::new(&mut b), cx)).await;
        assert!(f.unwrap().is_ok());
        drop(b);
        assert_eq!(t.bytes(), 3);
        assert_eq!(t.sha256_hex(), None);
        // Failed by its producer.
        let (mut tx, b) = Body::channel(1 << 20, None);
        let (b, t) = counted(b);
        tx.ready().await.unwrap();
        tx.try_push(Bytes::from_static(b"hel")).unwrap();
        drop(tx);
        assert!(drain(b).await.is_err());
        assert_eq!(t.sha256_hex(), None);
    }

    #[tokio::test]
    async fn collects_small_body() {
        let mut b = Body::from_bytes("abc");
        assert!(matches!(collect_prefix(&mut b, 10).await, Collected::Complete(x) if x == "abc"));
        assert_eq!(drain(b).await.unwrap(), b"abc");
    }

    #[tokio::test]
    async fn too_large_keeps_whole_stream() {
        let (mut tx, mut b) = Body::channel(1 << 20, None);
        tokio::spawn(async move {
            for _ in 0..4 {
                tx.ready().await.unwrap();
                tx.try_push(Bytes::from_static(b"0123456789")).unwrap();
            }
            tx.ready().await.unwrap();
            tx.try_finish().unwrap();
        });
        assert!(matches!(
            collect_prefix(&mut b, 15).await,
            Collected::TooLarge
        ));
        assert_eq!(drain(b).await.unwrap().len(), 40);
    }

    #[tokio::test]
    async fn declared_too_large_untouched() {
        let mut b = Body::from_bytes(vec![0u8; 100]);
        assert!(matches!(
            collect_prefix(&mut b, 10).await,
            Collected::TooLarge
        ));
        assert_eq!(drain(b).await.unwrap().len(), 100);
    }
}
