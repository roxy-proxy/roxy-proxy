//! Byte-stream adapters used by the connection state machine.
//!
//! * [`Rewind`] replays bytes that were read ahead (the sniffed TLS
//!   `ClientHello`) before reading from the socket again.
//! * [`ConnIo`] is the stream handed to `roxy_http::h1::ServerConn`. It keeps
//!   a second handle to the underlying stream so the proxy can (a) add
//!   header lines to a response head the codec writes and (b) shut the
//!   connection down gracefully (half-close, then linger discarding input)
//!   after the codec has been dropped. Both exist because the codec cannot
//!   yet force `connection: close` on a response or emit
//!   `proxy-authenticate` (a reserved header); see the crate docs.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::{Instant, timeout, timeout_at};

/// Any client or upstream byte stream.
pub trait Io: AsyncRead + AsyncWrite + Send + Unpin + 'static {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> Io for T {}

/// A boxed [`Io`].
pub type BoxIo = Box<dyn Io>;

/// Lingering close budget: after a refusal roxy half-closes and discards
/// input for at most this long / this many bytes, so the client reads the
/// response instead of a reset.
pub(crate) const LINGER: Duration = Duration::from_secs(1);
const LINGER_BYTES: usize = 1024 * 1024;

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

enum Patch {
    Idle,
    /// Waiting for the end of the next status line; then inject these bytes.
    Scanning(Vec<u8>),
    /// Injecting before passing more caller bytes through.
    Injecting(Bytes),
}

struct Shared {
    io: BoxIo,
    patch: Patch,
}

/// A cloneable handle to one client stream (see the module docs).
///
/// All clones refer to the same stream; the lock is only held inside a
/// single `poll_*` call, never across an await.
#[derive(Clone)]
pub struct ConnIo {
    shared: Arc<Mutex<Shared>>,
}

impl std::fmt::Debug for ConnIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnIo").finish_non_exhaustive()
    }
}

impl ConnIo {
    /// Wraps a stream.
    pub fn new(io: BoxIo) -> Self {
        Self {
            shared: Arc::new(Mutex::new(Shared {
                io,
                patch: Patch::Idle,
            })),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Shared> {
        self.shared.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Inserts `lines` (complete `name: value\r\n` lines) right after the
    /// status line of the next response head written to this stream. Only
    /// call immediately before handing the codec a response, when nothing
    /// else is buffered for writing.
    pub fn inject_after_status_line(&self, lines: Vec<u8>) {
        if lines.is_empty() {
            return;
        }
        self.lock().patch = Patch::Scanning(lines);
    }

    /// Half-closes the write side and discards input for up to [`LINGER`],
    /// so a client that is still sending sees the response rather than a
    /// reset. Use after the codec has been dropped.
    pub async fn close_gracefully(&self) {
        let mut io = self.clone();
        let _ = timeout(LINGER, io.shutdown()).await;
        let deadline = Instant::now() + LINGER;
        let mut scratch = vec![0u8; 16 * 1024];
        let mut discarded = 0;
        while discarded < LINGER_BYTES {
            match timeout_at(deadline, io.read(&mut scratch)).await {
                Ok(Ok(n)) if n > 0 => discarded += n,
                _ => break,
            }
        }
    }
}

fn drain_injection(s: &mut Shared, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    while let Patch::Injecting(b) = &mut s.patch {
        if b.is_empty() {
            s.patch = Patch::Idle;
            break;
        }
        match Pin::new(&mut s.io).poll_write(cx, b) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
            Poll::Ready(Ok(n)) => b.advance(n),
        }
    }
    Poll::Ready(Ok(()))
}

impl AsyncRead for ConnIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut g = self.lock();
        Pin::new(&mut g.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for ConnIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut g = self.lock();
        let s = &mut *g;
        match drain_injection(s, cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        let Patch::Scanning(_) = &s.patch else {
            return Pin::new(&mut s.io).poll_write(cx, buf);
        };
        let Some(i) = buf.iter().position(|&b| b == b'\n') else {
            return Pin::new(&mut s.io).poll_write(cx, buf);
        };
        match Pin::new(&mut s.io).poll_write(cx, &buf[..=i]) {
            Poll::Ready(Ok(n)) if n == i + 1 => {
                if let Patch::Scanning(lines) = std::mem::replace(&mut s.patch, Patch::Idle) {
                    s.patch = Patch::Injecting(Bytes::from(lines));
                }
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut g = self.lock();
        let s = &mut *g;
        match drain_injection(s, cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut s.io).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut g = self.lock();
        let s = &mut *g;
        match drain_injection(s, cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut s.io).poll_shutdown(cx),
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[tokio::test]
    async fn injects_after_status_line() {
        let (a, mut b) = tokio::io::duplex(1024);
        let io = ConnIo::new(Box::new(a));
        io.inject_after_status_line(b"connection: close\r\n".to_vec());
        let mut w = io.clone();
        w.write_all(b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n")
            .await
            .unwrap();
        w.write_all(b"next").await.unwrap();
        w.flush().await.unwrap();
        drop(w);
        drop(io);
        let mut out = String::new();
        b.read_to_string(&mut out).await.unwrap();
        assert_eq!(
            out,
            "HTTP/1.1 403 Forbidden\r\nconnection: close\r\ncontent-length: 0\r\n\r\nnext"
        );
    }

    #[tokio::test]
    async fn injection_split_across_writes() {
        let (a, mut b) = tokio::io::duplex(1024);
        let io = ConnIo::new(Box::new(a));
        io.inject_after_status_line(b"x: y\r\n".to_vec());
        let mut w = io.clone();
        w.write_all(b"HTTP/1.1 4").await.unwrap();
        w.write_all(b"07 X\r").await.unwrap();
        w.write_all(b"\nrest\r\n\r\n").await.unwrap();
        w.flush().await.unwrap();
        drop(w);
        drop(io);
        let mut out = String::new();
        b.read_to_string(&mut out).await.unwrap();
        assert_eq!(out, "HTTP/1.1 407 X\r\nx: y\r\nrest\r\n\r\n");
    }
}
