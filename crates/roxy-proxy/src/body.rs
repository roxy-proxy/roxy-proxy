//! Body helpers: byte counting as frames stream, and bounded buffering for
//! body-inspecting rules that never loses the rest of the stream.

use std::future::poll_fn;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use http_body::{Frame, SizeHint};
use roxy_http::{Body, BodyError};

/// Counts data bytes as they pass through.
struct Counted {
    inner: Body,
    counter: Arc<AtomicU64>,
}

impl http_body::Body for Counted {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let r = Pin::new(&mut self.inner).poll_frame(cx);
        if let Poll::Ready(Some(Ok(f))) = &r
            && let Some(d) = f.data_ref()
        {
            self.counter.fetch_add(d.len() as u64, Ordering::Relaxed);
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

/// Wraps `body` so the returned counter tracks the data bytes that have
/// flowed through it. Framing (known length) is preserved.
pub(crate) fn counted(body: Body) -> (Body, Arc<AtomicU64>) {
    let counter = Arc::new(AtomicU64::new(0));
    let known = body.known_length();
    let body = Body::wrap_with_length(
        Counted {
            inner: body,
            counter: counter.clone(),
        },
        u64::MAX,
        known,
    );
    (body, counter)
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
    /// The body failed (client went away, framing error, cap). The body is
    /// now an error body; the flow must not be forwarded.
    Failed(BodyError),
}

/// Buffers up to `cap` bytes of `body` for inspection (§6.2), replacing
/// `*body` with a stream that yields exactly the same bytes downstream.
/// Never pre-allocates from a declared length.
pub(crate) async fn collect_prefix(body: &mut Body, cap: u64) -> Collected {
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
                *body = Body::wrap(ErrorBody(Some(e.clone())), u64::MAX);
                return Collected::Failed(e);
            }
            Some(Ok(f)) => {
                // Trailers are dropped, as `Body::collect_up_to` does; roxy
                // only accepts them with `http.allow_trailers`.
                if let Ok(d) = f.into_data() {
                    buf.extend_from_slice(&d);
                    if buf.len() as u64 > cap {
                        let rest = std::mem::take(body);
                        *body = Body::wrap_with_length(
                            Chain {
                                prefix: Some(buf.freeze()),
                                rest,
                            },
                            u64::MAX,
                            declared,
                        );
                        return Collected::TooLarge;
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

/// Lossy UTF-8 view of an inspected body.
pub(crate) fn body_text(b: &Bytes) -> String {
    String::from_utf8_lossy(b).into_owned()
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
    async fn counts_bytes() {
        let (b, c) = counted(Body::from_bytes("hello"));
        assert_eq!(b.known_length(), Some(5));
        assert_eq!(drain(b).await.unwrap(), b"hello");
        assert_eq!(c.load(Ordering::Relaxed), 5);
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
