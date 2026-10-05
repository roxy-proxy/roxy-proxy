//! HTTP/2 below hyper: an `h2` client in a tunnel, and hand-built frames
//! for what even that refuses to send (a connection-specific header, a
//! mismatched `:authority`).

use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::Kit;

/// An `h2` client over a tunnel to `up.test`. The connection task is
/// returned so tests can watch it end.
pub(crate) async fn h2_client(
    kit: &Kit,
) -> (
    h2::client::SendRequest<Bytes>,
    tokio::task::JoinHandle<Result<(), h2::Error>>,
) {
    let io = kit.connect_tunnel("up.test", 443).await;
    let tls = kit.tls_connect(io, "up.test", &[b"h2"]).await.unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    let (send, conn) = h2::client::handshake(tls).await.unwrap();
    (send, tokio::spawn(conn))
}

/// Sends one h2 request (no body) and returns the response head and body,
/// or the stream / connection error.
pub(crate) async fn h2_get(
    send: &h2::client::SendRequest<Bytes>,
    uri: &str,
    headers: &[(&str, &str)],
) -> Result<(http::response::Parts, Bytes), h2::Error> {
    let mut b = http::Request::builder().method("GET").uri(uri);
    for (n, v) in headers {
        b = b.header(*n, *v);
    }
    let req = b.body(()).unwrap();
    let mut ready = send.clone().ready().await?;
    let (resp, _) = ready.send_request(req, true)?;
    let resp = tokio::time::timeout(Duration::from_secs(10), resp)
        .await
        .expect("timed out waiting for an h2 response")?;
    let (parts, mut body) = resp.into_parts();
    let mut out = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        let _ = body.flow_control().release_capacity(chunk.len());
        out.extend_from_slice(&chunk);
    }
    Ok((parts, Bytes::from(out)))
}

pub(crate) const H2_HEADERS: u8 = 0x1;
pub(crate) const H2_RST_STREAM: u8 = 0x3;
pub(crate) const H2_SETTINGS: u8 = 0x4;
pub(crate) const H2_GOAWAY: u8 = 0x7;

/// A received frame: `(type, flags, stream id, payload)`.
pub(crate) type Frame = (u8, u8, u32, Vec<u8>);

/// A minimal HPACK encoder: every field as a literal without indexing, no
/// Huffman.
fn hpack_literal(out: &mut Vec<u8>, name: &str, value: &str) {
    fn len(out: &mut Vec<u8>, n: usize) {
        assert!(n < 127, "the test HPACK encoder only does short strings");
        out.push(u8::try_from(n).unwrap());
    }
    out.push(0x00);
    len(out, name.len());
    out.extend_from_slice(name.as_bytes());
    len(out, value.len());
    out.extend_from_slice(value.as_bytes());
}

fn frame(out: &mut Vec<u8>, kind: u8, flags: u8, stream: u32, payload: &[u8]) {
    let n = u32::try_from(payload.len()).unwrap();
    out.extend_from_slice(&n.to_be_bytes()[1..]);
    out.push(kind);
    out.push(flags);
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(payload);
}

/// Opens an h2 tunnel to `up.test` and sends stream 1 with exactly `fields`
/// (pseudo-headers included, in order) and `END_STREAM`. Returns the frames
/// received until stream 1 is reset or answered, or the connection ends.
pub(crate) async fn h2_raw_request(kit: &Kit, fields: &[(&str, &str)]) -> Vec<Frame> {
    let io = kit.connect_tunnel("up.test", 443).await;
    let mut tls = kit.tls_connect(io, "up.test", &[b"h2"]).await.unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    let mut out = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    frame(&mut out, H2_SETTINGS, 0, 0, &[]);
    let mut block = Vec::new();
    for (n, v) in fields {
        hpack_literal(&mut block, n, v);
    }
    // END_HEADERS | END_STREAM
    frame(&mut out, H2_HEADERS, 0x4 | 0x1, 1, &block);
    tls.write_all(&out).await.unwrap();
    let mut frames = Vec::new();
    loop {
        let mut head = [0u8; 9];
        let read = tokio::time::timeout(Duration::from_secs(10), tls.read_exact(&mut head)).await;
        let Ok(Ok(_)) = read else { break };
        let len = (usize::from(head[0]) << 16) | (usize::from(head[1]) << 8) | usize::from(head[2]);
        let mut payload = vec![0u8; len];
        if tls.read_exact(&mut payload).await.is_err() {
            break;
        }
        let (kind, flags) = (head[3], head[4]);
        let stream = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
        if kind == H2_SETTINGS && flags & 0x1 == 0 {
            let mut ack = Vec::new();
            frame(&mut ack, H2_SETTINGS, 0x1, 0, &[]);
            tls.write_all(&ack).await.unwrap();
        }
        let done =
            (stream == 1 && (kind == H2_RST_STREAM || kind == H2_HEADERS)) || kind == H2_GOAWAY;
        frames.push((kind, flags, stream, payload));
        if done {
            break;
        }
    }
    frames
}
