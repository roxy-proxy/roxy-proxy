//! WebSocket upgrade through `ServerConn` (relay tier hand-off).

use std::sync::Arc;

use http::StatusCode;
use roxy_http::h1::{Incoming, Role, ServerConn};
use roxy_http::upstream::{UriForm, to_upstream_upgrade_request};
use roxy_http::url::parse_authority;
use roxy_http::{CanonicalRequest, CanonicalResponse, HttpFlags, Limits, Scheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn read_head<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> String {
    let mut buf = Vec::new();
    while !buf.ends_with(b"\r\n\r\n") {
        let mut b = [0u8; 1];
        r.read_exact(&mut b).await.unwrap();
        buf.push(b[0]);
    }
    String::from_utf8(buf).unwrap()
}

#[tokio::test]
async fn upgrade_response_hands_back_stream() {
    let (mut client, server) = tokio::io::duplex(1 << 16);
    let mut c = ServerConn::new(
        server,
        Role::Tunnel {
            authority: parse_authority(b"example.com", 443).unwrap(),
            scheme: Scheme::Https,
        },
        Arc::new(Limits::default()),
        Arc::new(HttpFlags::default()),
    );
    client
        .write_all(b"GET /ws HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
        .await
        .unwrap();
    let Ok(Some(Incoming::Request(req))) = c.next_request().await else {
        panic!()
    };
    assert_eq!(req.meta.upgrade.as_deref(), Some("websocket"));
    assert!(!req.headers.contains("upgrade"));
    let key = roxy_http::ws::validate_upgrade_request(&req).unwrap();
    let up = to_upstream_upgrade_request(
        CanonicalRequest {
            method: req.method.clone(),
            scheme: req.scheme,
            authority: req.authority.clone(),
            path: req.path.clone(),
            query: req.query.clone(),
            headers: req.headers.clone(),
            body: roxy_http::Body::empty(),
            meta: req.meta.clone(),
        },
        UriForm::Origin,
    )
    .unwrap();
    assert_eq!(up.headers().get("connection").unwrap(), "upgrade");
    assert_eq!(up.headers().get("upgrade").unwrap(), "websocket");
    assert_eq!(up.headers().get("sec-websocket-key").unwrap(), key.as_str());
    let mut res = CanonicalResponse::new(StatusCode::SWITCHING_PROTOCOLS);
    res.headers
        .insert(
            "sec-websocket-accept",
            &roxy_http::ws::compute_accept(key.as_str()),
        )
        .unwrap();
    res.meta.upgrade = Some("websocket".into());
    roxy_http::ws::validate_upgrade_response(&res, &key).unwrap();
    let (mut io, leftover) = c.respond_upgrade(res).await.unwrap();
    assert!(leftover.is_empty());
    let head = read_head(&mut client).await;
    assert!(
        head.starts_with("HTTP/1.1 101 Switching Protocols\r\n"),
        "{head}"
    );
    assert!(head.contains("connection: upgrade\r\nupgrade: websocket\r\n"));
    assert!(head.contains("sec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
    client.write_all(b"\x81\x00").await.unwrap();
    let mut got = [0u8; 2];
    io.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"\x81\x00");
}
