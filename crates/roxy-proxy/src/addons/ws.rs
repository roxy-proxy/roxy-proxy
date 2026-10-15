//! A WebSocket through the stack.
//!
//! A WebSocket is a long-lived exchange: once upgraded, the client's bytes
//! are the request body and the upstream's the response body, and every
//! layer carries them in its bodies like any other exchange's. The core
//! stage owns the upstream relay. The transport connects the client socket
//! to the first lane pair after writing `101`.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use roxy_http::ws::WsKey;
use roxy_http::{Body, BodyError, BodySender, CanonicalResponse};
use roxy_wasm::LayerRequest;
use tokio::io::{AsyncRead, ReadBuf};

use super::StackFlow;
use super::client_edge::gated;
use crate::flowlog::FlowSink;
use crate::io::BoxIo;
use crate::server::Snapshot;

/// Metadata for an upstream upgrade, delivered before its response head.
/// The relay starts only after the transport writes the client's `101`
/// and hands ownership of the client I/O tasks to the core stage.
pub(super) struct Upgrade {
    pub(super) key: WsKey,
    pub(super) start: tokio::sync::oneshot::Sender<SplicedClient>,
}

/// Connect the last request and response bodies to the core's relay.
/// The upstream socket remains owned by the core stage.
pub(super) fn relay_io(st: &StackFlow, mut stream: Body, res: &mut CanonicalResponse) -> BoxIo {
    let (mut to_relay_w, to_relay_r) = tokio::io::duplex(64 * 1024);
    let (from_relay_w, from_relay_r) = tokio::io::duplex(64 * 1024);
    let failed = Arc::new(AtomicBool::new(false));
    let to_relay_r = FailedAtEof {
        inner: to_relay_r,
        failed: failed.clone(),
    };
    st.chain().spawn(async move {
        use tokio::io::AsyncWriteExt as _;
        match copy_body(&mut stream, &mut to_relay_w).await {
            Ok(()) => {
                let _ = to_relay_w.shutdown().await;
            }
            Err(()) => failed.store(true, Ordering::Release),
        }
    });
    res.body = reader_to_body(from_relay_r);
    Box::new(tokio::io::join(to_relay_r, from_relay_w))
}

/// A pipe's reading end whose end of stream is an error once `failed` is
/// set: the writer stopped because what it copied failed.
struct FailedAtEof<R> {
    inner: R,
    failed: Arc<AtomicBool>,
}

impl<R: AsyncRead + Unpin> AsyncRead for FailedAtEof<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        ready!(Pin::new(&mut self.inner).poll_read(cx, buf))?;
        if buf.filled().len() == before
            && buf.remaining() > 0
            && self.failed.load(Ordering::Acquire)
        {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "the stream from the layers failed",
            )));
        }
        Poll::Ready(Ok(()))
    }
}

/// The client edge's WebSocket bodies, connected to the socket after the
/// transport has written `101`. Dropping this rejects the upstream upgrade.
pub(crate) struct WsClient {
    client_tx: BodySender,
    to_client: Body,
    sink: Arc<dyn FlowSink>,
    start: tokio::sync::oneshot::Sender<SplicedClient>,
}

impl WsClient {
    pub(super) fn new(
        client_tx: BodySender,
        to_client: Body,
        sink: Arc<dyn FlowSink>,
        start: tokio::sync::oneshot::Sender<SplicedClient>,
    ) -> Self {
        Self {
            client_tx,
            to_client,
            sink,
            start,
        }
    }

    pub(crate) fn connect(self, client: BoxIo, leftover: Vec<u8>) {
        let (cr, cw) = tokio::io::split(client);
        let to_client = gated(self.to_client, self.sink);
        let client = SplicedClient {
            reader: tokio::spawn(reader_into(leftover, cr, self.client_tx)),
            writer: tokio::spawn(body_to_writer(to_client, cw)),
        };
        let _ = self.start.send(client);
    }
}

/// The client socket of a WebSocket through the stack, held by the two
/// tasks that connect it to the client-edge bodies. A layer decides when those
/// bodies end, so the socket is closed when the relay ends, not when the
/// layers let go of it. Dropping it closes the socket at once.
pub(crate) struct SplicedClient {
    reader: tokio::task::JoinHandle<()>,
    writer: tokio::task::JoinHandle<()>,
}

impl SplicedClient {
    /// Closes the client once the relay has ended: what the layers still
    /// pass on toward it gets up to `drain` to arrive, then the socket is
    /// dropped.
    pub(crate) async fn close(mut self, drain: std::time::Duration) {
        let _ = tokio::time::timeout(drain, &mut self.writer).await;
    }
}

impl Drop for SplicedClient {
    fn drop(&mut self) {
        self.reader.abort();
        self.writer.abort();
    }
}

/// Whether a WebSocket must be relayed with no extension negotiated, so
/// every message stays readable: message rules check them, or a layer on
/// the upgrade request reads its bytes.
pub(crate) fn ws_without_extensions(snap: &Snapshot, layer_reads_bytes: bool) -> bool {
    snap.policy.reads_ws() || (snap.http.decode_for_addons && layer_reads_bytes)
}

/// For an upgrade request, takes its body (the stream after the `101`)
/// out, so the head is validated as the bodiless request it is.
pub(super) fn split_upgrade_stream(
    st: &StackFlow,
    mut req: LayerRequest,
) -> (LayerRequest, Option<Body>) {
    if !st.is_upgrade() {
        return (req, None);
    }
    let stream = std::mem::take(req.body_mut());
    (req, Some(stream))
}

/// Puts the stream [`split_upgrade_stream`] took back.
pub(super) fn join_upgrade_stream(mut req: LayerRequest, stream: Option<Body>) -> LayerRequest {
    if let Some(s) = stream {
        *req.body_mut() = s;
    }
    req
}

/// Writes a body's bytes to `w`, then shuts it down. A failed body is not
/// shut down cleanly: the writer is dropped, and the far side sees the
/// stream end.
async fn body_to_writer(mut body: Body, mut w: impl tokio::io::AsyncWrite + Unpin) {
    use tokio::io::AsyncWriteExt as _;
    if copy_body(&mut body, &mut w).await.is_ok() {
        let _ = w.shutdown().await;
    }
}

/// Writes a body's bytes to `w` until the body ends. `Err` if the body or
/// the write failed.
async fn copy_body(
    body: &mut Body,
    w: &mut (impl tokio::io::AsyncWrite + Unpin),
) -> Result<(), ()> {
    use http_body_util::BodyExt as _;
    use tokio::io::AsyncWriteExt as _;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| ())?;
        if let Some(d) = frame.data_ref() {
            w.write_all(d).await.map_err(|_| ())?;
        }
    }
    Ok(())
}

/// A body read from `r` until its end.
fn reader_to_body(r: impl tokio::io::AsyncRead + Send + Unpin + 'static) -> Body {
    let (tx, body) = Body::channel(u64::MAX, None);
    tokio::spawn(reader_into(Vec::new(), r, tx));
    body
}

/// Sends `first`, then what `r` yields, into `tx`; ends the body with the
/// reader.
async fn reader_into(first: Vec<u8>, mut r: impl tokio::io::AsyncRead + Unpin, mut tx: BodySender) {
    use tokio::io::AsyncReadExt as _;
    if !first.is_empty() && tx.send_data(Bytes::from(first)).await.is_err() {
        return;
    }
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match r.read(&mut buf).await {
            Ok(0) => {
                let _ = tx.finish().await;
                return;
            }
            Ok(n) => {
                if tx
                    .send_data(Bytes::copy_from_slice(&buf[..n]))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            Err(e) => {
                tx.abort(BodyError::Upstream(e.to_string()));
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::AsyncReadExt as _;

    use super::*;
    use crate::testkit::{GatedSink, LogGate};

    /// What the layers send toward the client waits for the flow log, as
    /// the relay's bytes do.
    #[tokio::test]
    async fn bytes_toward_the_client_wait_for_the_flow_log() {
        let gate = Arc::new(LogGate::default());
        let sink = Arc::new(GatedSink::new(Arc::default(), gate.clone()));
        let (client_tx, _from_client) = Body::channel(u64::MAX, None);
        let (mut layer_tx, to_client) = Body::channel(u64::MAX, None);
        let (client, mut peer) = tokio::io::duplex(64);
        let (start, started) = tokio::sync::oneshot::channel();
        let plumbing = WsClient::new(client_tx, to_client, sink, start);
        gate.set_closed(true);
        plumbing.connect(Box::new(client), Vec::new());
        let _client = started.await.unwrap();
        tokio::spawn(async move {
            let _ = layer_tx.send_data(Bytes::from_static(b"hello")).await;
            std::future::pending::<()>().await;
        });
        gate.wait_held().await;
        let mut got = [0u8; 5];
        let early = tokio::time::timeout(Duration::from_millis(100), peer.read_exact(&mut got));
        assert!(
            early.await.is_err(),
            "bytes reached the client while the log was behind"
        );
        gate.set_closed(false);
        tokio::time::timeout(Duration::from_secs(10), peer.read_exact(&mut got))
            .await
            .expect("bytes flow once the log catches up")
            .unwrap();
        assert_eq!(&got, b"hello");
    }
}
