//! A WebSocket through the stack.
//!
//! A WebSocket is a long-lived exchange: once upgraded, the client's bytes
//! are the request body and the upstream's the response body, and every
//! layer carries them in its bodies like any other exchange's. The core
//! stage owns the upstream relay. The transport connects the client socket
//! to the first lane pair after writing `101`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use roxy_http::ws::WsKey;
use roxy_http::{Body, BodyError, BodySender, CanonicalResponse};
use roxy_wasm::LayerRequest;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

use super::StackFlow;
use super::chain::Chain;
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
    let (from_relay_w, mut from_relay_r) = tokio::io::duplex(64 * 1024);
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
            Err(_) => failed.store(true, Ordering::Release),
        }
    });
    let (tx, body) = Body::channel(u64::MAX, None);
    st.chain().spawn(async move {
        reader_into(Vec::new(), &mut from_relay_r, tx, std::future::pending()).await;
    });
    res.body = body;
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
    chain: Arc<Chain>,
}

impl WsClient {
    pub(super) fn new(
        client_tx: BodySender,
        to_client: Body,
        sink: Arc<dyn FlowSink>,
        start: tokio::sync::oneshot::Sender<SplicedClient>,
        chain: Arc<Chain>,
    ) -> Self {
        Self {
            client_tx,
            to_client,
            sink,
            start,
            chain,
        }
    }

    pub(crate) fn connect(self, client: BoxIo, leftover: Vec<u8>) {
        // Report transport failure at the I/O boundary, before it becomes
        // a recoverable lane error or a body is disposed of downstream.
        let (mut cr, cw) = tokio::io::split(ClientSocket {
            inner: client,
            chain: self.chain.clone(),
        });
        let to_client = gated(self.to_client, self.sink);
        let chain = self.chain.clone();
        let ended = CancellationToken::new();
        let until = ended.clone().cancelled_owned();
        let client = SplicedClient {
            reader: self.chain.spawn(async move {
                reader_into(leftover, &mut cr, self.client_tx, until).await;
                // A layer can stop consuming its request while holding
                // its response open. Keep observing the actual transport
                // after that directional stop, until the relay closes it.
                let _ = tokio::io::copy(&mut cr, &mut tokio::io::sink()).await;
            }),
            writer: self.chain.spawn(body_to_writer(to_client, cw, chain)),
            ended,
            chain: self.chain,
        };
        let _ = self.start.send(client);
    }
}

/// A failed socket reports client loss independently of lane-body errors.
/// A clean read EOF remains a half-close, allowing the response to drain.
struct ClientSocket {
    inner: BoxIo,
    chain: Arc<Chain>,
}

impl ClientSocket {
    fn observed<T>(&self, result: Poll<std::io::Result<T>>) -> Poll<std::io::Result<T>> {
        if matches!(result, Poll::Ready(Err(_))) {
            self.chain.tear_down(super::CLIENT_GONE);
        }
        result
    }
}

impl AsyncRead for ClientSocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        self.observed(result)
    }
}

impl AsyncWrite for ClientSocket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if matches!(result, Poll::Ready(Ok(0))) && !buf.is_empty() {
            self.chain.tear_down(super::CLIENT_GONE);
        }
        self.observed(result)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_flush(cx);
        self.observed(result)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_shutdown(cx);
        self.observed(result)
    }
}

/// The client socket of a WebSocket through the stack, held by the two
/// tasks that connect it to the client-edge bodies. A layer decides when those
/// bodies end, so the socket is closed when the relay ends, not when the
/// layers let go of it. Dropping it closes the socket at once.
pub(crate) struct SplicedClient {
    reader: tokio::task::JoinHandle<()>,
    writer: tokio::task::JoinHandle<Option<BodyError>>,
    /// Cancelled when the relay has ended: the client's bytes end for the
    /// layers, as they do when the client closes.
    ended: CancellationToken,
    chain: Arc<Chain>,
}

impl SplicedClient {
    /// Closes the client once the relay has ended. The client's request
    /// body ends for the layers, as it does when the client closes; what
    /// they still pass on toward the client gets up to `drain` to arrive,
    /// and the lanes that long to end on their own, before the socket is
    /// dropped and whatever a layer still holds is torn down.
    pub(crate) async fn close(mut self, drain: std::time::Duration) -> Option<BodyError> {
        let deadline = tokio::time::Instant::now() + drain;
        self.ended.cancel();
        // Return a failed response body to the core for final attribution.
        // Socket failure has already reported client loss to the chain.
        let drained = tokio::time::timeout_at(deadline, &mut self.writer).await;
        let _ = tokio::time::timeout_at(deadline, self.chain.lanes_over()).await;
        drained.ok().and_then(Result::ok).flatten()
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
async fn body_to_writer(
    mut body: Body,
    mut w: impl tokio::io::AsyncWrite + Unpin,
    chain: Arc<Chain>,
) -> Option<BodyError> {
    use tokio::io::AsyncWriteExt as _;
    match copy_body(&mut body, &mut w).await {
        Ok(()) => {
            let _ = w.shutdown().await;
            None
        }
        Err(error) => {
            // As with an HTTP response write, an incomplete answer ends
            // the exchange. ClientSocket separately reports client loss.
            chain.tear_down(super::ENDED);
            match error {
                CopyFailure::Body(error) => Some(error),
                CopyFailure::Io => None,
            }
        }
    }
}

enum CopyFailure {
    Body(BodyError),
    Io,
}

/// Writes a body's bytes to `w` until the body ends. `Err` if the body or
/// the write failed.
async fn copy_body(
    body: &mut Body,
    w: &mut (impl tokio::io::AsyncWrite + Unpin),
) -> Result<(), CopyFailure> {
    use http_body_util::BodyExt as _;
    use tokio::io::AsyncWriteExt as _;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(CopyFailure::Body)?;
        if let Some(d) = frame.data_ref() {
            w.write_all(d).await.map_err(|_| CopyFailure::Io)?;
        }
    }
    Ok(())
}

/// Sends `first`, then what `r` yields, into `tx`; ends the body with the
/// reader, or cleanly when `until` resolves first.
async fn reader_into(
    first: Vec<u8>,
    r: &mut (impl AsyncRead + Unpin),
    mut tx: BodySender,
    until: impl Future<Output = ()>,
) {
    use tokio::io::AsyncReadExt as _;
    if !first.is_empty() && tx.send_data(Bytes::from(first)).await.is_err() {
        return;
    }
    let mut buf = vec![0u8; 16 * 1024];
    tokio::pin!(until);
    loop {
        let read = tokio::select! {
            biased;
            () = &mut until => Ok(0),
            read = r.read(&mut buf) => read,
        };
        match read {
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

    /// EOF permits a final response; a write failure proves the client is
    /// gone. Both socket tasks must be destroyed before reclamation ends.
    #[tokio::test]
    async fn upgraded_half_close_and_write_failure_have_distinct_outcomes() {
        use tokio::io::AsyncWriteExt as _;

        let kit = crate::testkit::Kit::builder().start().await;
        for write_failure in [false, true] {
            let (st, _cx, _ends) = crate::addons::test_flow(&kit);
            let (client_tx, _from_client) = Body::channel(u64::MAX, None);
            let (mut response, to_client) = Body::channel(u64::MAX, None);
            let (socket, mut peer) = tokio::io::duplex(64);
            let (start, started) = tokio::sync::oneshot::channel();
            WsClient::new(
                client_tx,
                to_client,
                st.shared.sink.clone(),
                start,
                st.chain().clone(),
            )
            .connect(Box::new(socket), Vec::new());
            let client = started.await.unwrap();
            peer.shutdown().await.unwrap();
            if write_failure {
                drop(peer);
                response
                    .send_data(Bytes::from_static(b"reply"))
                    .await
                    .unwrap();
                tokio::time::timeout(Duration::from_secs(2), st.chain().torn_down().cancelled())
                    .await
                    .unwrap();
                assert_eq!(st.cancellation_reason(), Some("client_gone"));
            } else {
                response
                    .send_data(Bytes::from_static(b"reply"))
                    .await
                    .unwrap();
                response.finish().await.unwrap();
                let mut reply = Vec::new();
                tokio::time::timeout(Duration::from_secs(2), peer.read_to_end(&mut reply))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(reply, b"reply");
                assert_eq!(st.cancellation_reason(), None);
            }
            assert!(client.close(Duration::from_millis(10)).await.is_none());
            tokio::time::timeout(Duration::from_secs(2), st.chain().tasks.wait())
                .await
                .unwrap();
            assert!(st.chain().tasks.is_empty());
        }
    }

    /// What the layers send toward the client waits for the flow log, as
    /// the relay's bytes do.
    #[tokio::test]
    async fn bytes_toward_the_client_wait_for_the_flow_log() {
        let kit = crate::testkit::Kit::builder().start().await;
        let (st, _cx, _ends) = crate::addons::test_flow(&kit);
        let gate = Arc::new(LogGate::default());
        let sink = Arc::new(GatedSink::new(Arc::default(), gate.clone()));
        let (client_tx, _from_client) = Body::channel(u64::MAX, None);
        let (mut layer_tx, to_client) = Body::channel(u64::MAX, None);
        let (client, mut peer) = tokio::io::duplex(64);
        let (start, started) = tokio::sync::oneshot::channel();
        let plumbing = WsClient::new(client_tx, to_client, sink, start, st.chain().clone());
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
