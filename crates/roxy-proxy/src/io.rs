//! Byte-stream adapters used by the connection state machine.
//!
//! * [`Rewind`] replays bytes that were read ahead (the sniffed TLS
//!   `ClientHello`) before reading from the socket again.
//! * [`ClientIo`] is the one concrete stream type the h1 codec is
//!   instantiated on, whatever the client connection is made of.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Any client or upstream byte stream.
pub trait Io: AsyncRead + AsyncWrite + Send + Unpin + 'static {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> Io for T {}

/// A boxed [`Io`].
pub type BoxIo = Box<dyn Io>;

/// Any client stream (TCP, a terminated TLS session, an in-memory duplex)
/// behind one concrete type, so the exchange code is compiled once. A
/// trait object cannot be the codec's type parameter directly: rustc's
/// auto-trait check for the nested exchange futures then reports a false
/// `Send is not general enough`.
pub struct ClientIo(pub BoxIo);

impl ClientIo {
    /// Boxes `io`.
    pub fn new(io: impl Io) -> Self {
        Self(Box::new(io))
    }
}

impl std::fmt::Debug for ClientIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClientIo")
    }
}

impl AsyncRead for ClientIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for ClientIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// Replays `prefix` before reading from the inner stream.
pub struct Rewind<IO> {
    prefix: Bytes,
    inner: IO,
}

impl<IO> Rewind<IO> {
    /// Wraps `inner`; `prefix` is returned by the first reads.
    pub fn new(inner: IO, prefix: Bytes) -> Self {
        Self { prefix, inner }
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for Rewind<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let n = self.prefix.len().min(buf.remaining());
            buf.put_slice(&self.prefix[..n]);
            self.prefix.advance(n);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for Rewind<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn rewind_replays_prefix() {
        let (a, mut b) = tokio::io::duplex(64);
        let mut r = Rewind::new(a, Bytes::from_static(b"hello "));
        b.write_all(b"world").await.unwrap();
        drop(b);
        let mut out = String::new();
        r.read_to_string(&mut out).await.unwrap();
        assert_eq!(out, "hello world");
    }
}
