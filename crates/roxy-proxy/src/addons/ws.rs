//! A WebSocket through the stack.
//!
//! A WebSocket is a long-lived exchange: once upgraded, the client's bytes
//! are the request body and the upstream's the response body, and every
//! layer carries them in its bodies like any other exchange's. The core
//! relays the real upgrade; the pieces gathered on the way down and up are
//! spliced to the client once the front has sent the `101`.

use bytes::Bytes;
use roxy_http::ws::WsKey;
use roxy_http::{Body, BodyError, BodySender, CanonicalResponse};
use roxy_wasm::LayerRequest;

use super::StackFlow;
use crate::io::BoxIo;
use crate::server::Snapshot;

/// What the core relayed: the upstream's upgraded connection, and the
/// relay's client side, which is the bottom of the stack.
pub(crate) struct Relay {
    pub(crate) upstream: hyper::upgrade::Upgraded,
    pub(crate) key: WsKey,
    /// What the last layer passes on goes in; what the relay gets from the
    /// upstream comes out.
    pub(crate) bottom: BoxIo,
}

impl Relay {
    /// Wires the bottom of the stack: `stream` (what the last layer passed
    /// on after the head) goes to the relay, and the relay's output becomes
    /// `res`'s body. One pipe per direction, each end held whole, so a
    /// close on either side is seen (#36).
    pub(crate) fn new(
        upstream: hyper::upgrade::Upgraded,
        key: WsKey,
        stream: Body,
        res: &mut CanonicalResponse,
    ) -> Self {
        let (to_relay_w, to_relay_r) = tokio::io::duplex(64 * 1024);
        let (from_relay_w, from_relay_r) = tokio::io::duplex(64 * 1024);
        tokio::spawn(body_to_writer(stream, to_relay_w));
        res.body = reader_to_body(from_relay_r);
        Self {
            upstream,
            key,
            bottom: Box::new(tokio::io::join(to_relay_r, from_relay_w)),
        }
    }
}

/// The client side of an upgraded exchange, ready to splice in once the
/// front has sent the `101`.
pub(crate) struct WsPlumbing {
    /// The client's bytes after the `101` go into the top request body
    /// through this.
    client_tx: BodySender,
    /// The top response body: the bytes for the client.
    to_client: Body,
    /// The relay's client side, the bottom of the stack.
    bottom: BoxIo,
}

impl WsPlumbing {
    pub(crate) fn new(client_tx: BodySender, to_client: Body, bottom: BoxIo) -> Self {
        Self {
            client_tx,
            to_client,
            bottom,
        }
    }

    /// Splices the client in: its bytes (those that came with the upgrade
    /// request first) go into the top request body, and the top response
    /// body goes to it. Returns the relay's client side.
    fn splice(self, client: BoxIo, leftover: Vec<u8>) -> BoxIo {
        let (cr, cw) = tokio::io::split(client);
        tokio::spawn(reader_into(leftover, cr, self.client_tx));
        tokio::spawn(body_to_writer(self.to_client, cw));
        self.bottom
    }
}

/// Splices the client into an exchange that went through the stack as a
/// WebSocket, returning the relay's client side; gives the client back
/// when it did not.
pub(crate) fn splice_client(
    st: &StackFlow,
    client: BoxIo,
    leftover: Vec<u8>,
) -> Result<BoxIo, BoxIo> {
    match st.take_ws() {
        Some(plumbing) => Ok(plumbing.splice(client, leftover)),
        None => Err(client),
    }
}

/// Whether a WebSocket must be relayed with no extension negotiated, so
/// every message stays readable: message rules check them, or a layer
/// that ran on the upgrade request reads its bytes.
pub(crate) fn ws_without_extensions(snap: &Snapshot, layer_ran: bool) -> bool {
    snap.policy.reads_ws() || (snap.flags.decode_for_addons && layer_ran)
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
    use http_body_util::BodyExt as _;
    use tokio::io::AsyncWriteExt as _;
    while let Some(frame) = body.frame().await {
        let Ok(frame) = frame else {
            return;
        };
        if let Some(d) = frame.data_ref()
            && w.write_all(d).await.is_err()
        {
            return;
        }
    }
    let _ = w.shutdown().await;
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
