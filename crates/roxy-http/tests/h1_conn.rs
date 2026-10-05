//! Behavioural tests of `h1::ServerConn`: streaming, backpressure,
//! 100-continue, caps, timeouts, response framing, CONNECT and upgrades.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::StatusCode;
use roxy_http::h1::{DRAIN_LIMIT, Incoming, Role, ServerConn};
use roxy_http::url::parse_authority;
use roxy_http::{
    Body, BodyError, CanonicalRequest, CanonicalResponse, HttpFlags, Limits, Reason, Scheme,
    WriteError,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, DuplexStream};

fn tunnel() -> Role {
    Role::Tunnel {
        authority: parse_authority(b"example.com", 443).unwrap(),
        scheme: Scheme::Https,
    }
}

fn conn_with(limits: Limits) -> (DuplexStream, ServerConn<DuplexStream>) {
    let (client, server) = tokio::io::duplex(1 << 16);
    let conn = ServerConn::new(
        server,
        tunnel(),
        Arc::new(limits),
        Arc::new(HttpFlags::default()),
    );
    (client, conn)
}

fn conn() -> (DuplexStream, ServerConn<DuplexStream>) {
    conn_with(Limits::default())
}

async fn expect_request(c: &mut ServerConn<DuplexStream>) -> CanonicalRequest {
    match c.next_request().await {
        Ok(Some(Incoming::Request(r))) => r,
        other => panic!("expected request, got {other:?}"),
    }
}

/// Reads one response: (head text, body bytes). Handles content-length,
/// chunked and no-body responses (`no_body` for HEAD/204/304/1xx).
async fn read_response<R: AsyncRead + Unpin>(r: &mut R, no_body: bool) -> (String, Vec<u8>) {
    let mut buf = Vec::new();
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let mut b = [0u8; 1];
        assert_eq!(
            r.read(&mut b).await.unwrap(),
            1,
            "EOF in response head: {buf:?}"
        );
        buf.push(b[0]);
    };
    let head = String::from_utf8(buf[..head_end].to_vec()).unwrap();
    let lower = head.to_ascii_lowercase();
    if no_body {
        return (head, Vec::new());
    }
    let mut body = Vec::new();
    if let Some(cl) = lower
        .lines()
        .find_map(|l| l.strip_prefix("content-length: "))
    {
        body.resize(cl.trim().parse().unwrap(), 0);
        r.read_exact(&mut body).await.unwrap();
    } else if lower.contains("transfer-encoding: chunked") {
        loop {
            let mut line = Vec::new();
            while !line.ends_with(b"\r\n") {
                let mut b = [0u8; 1];
                r.read_exact(&mut b).await.unwrap();
                line.push(b[0]);
            }
            let size =
                usize::from_str_radix(std::str::from_utf8(&line[..line.len() - 2]).unwrap(), 16)
                    .unwrap();
            let mut chunk = vec![0u8; size + 2];
            r.read_exact(&mut chunk).await.unwrap();
            assert_eq!(&chunk[size..], b"\r\n");
            if size == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..size]);
        }
    } else {
        r.read_to_end(&mut body).await.unwrap();
    }
    (head, body)
}

fn ok(body: Body) -> CanonicalResponse {
    let mut res = CanonicalResponse::new(StatusCode::OK);
    res.body = body;
    res
}

#[tokio::test]
async fn response_wire_form() {
    let (mut client, mut c) = conn();
    client
        .write_all(b"GET /a HTTP/1.1\r\nHost: example.com\r\n\r\nGET /b HTTP/1.1\r\nHost: example.com\r\n\r\nHEAD /c HTTP/1.1\r\nHost: example.com\r\n\r\nGET /d HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();

    // Known length -> content-length, date added, reason regenerated, cookies separate.
    let _ = expect_request(&mut c).await;
    let mut res = ok(Body::from_bytes("hello"));
    res.headers.append("set-cookie", "a=1").unwrap();
    res.headers.append("set-cookie", "b=2").unwrap();
    c.respond(res).await.unwrap();
    let (head, body) = read_response(&mut client, false).await;
    assert!(head.starts_with("HTTP/1.1 200 OK\r\ndate: "), "{head}");
    assert!(head.contains("\r\nset-cookie: a=1\r\nset-cookie: b=2\r\n"));
    assert!(head.contains("\r\ncontent-length: 5\r\n"));
    assert!(!head.contains("transfer-encoding"));
    assert!(!head.contains("connection"));
    assert_eq!(body, b"hello");

    // Unknown length -> clean chunked.
    let _ = expect_request(&mut c).await;
    let (mut tx, body) = Body::channel(1 << 20, None);
    let feeder = tokio::spawn(async move {
        tx.send_data(Bytes::from_static(b"abc")).await.unwrap();
        tx.send_data(Bytes::from_static(b"defgh")).await.unwrap();
        tx.finish().await.unwrap();
    });
    let mut res = ok(body);
    res.status = StatusCode::from_u16(299).unwrap();
    c.respond(res).await.unwrap();
    feeder.await.unwrap();
    let (head, body) = read_response(&mut client, false).await;
    assert!(head.starts_with("HTTP/1.1 299 \r\n"), "{head}");
    assert!(head.contains("\r\ntransfer-encoding: chunked\r\n"));
    assert_eq!(body, b"abcdefgh");

    // HEAD -> declared length, no body bytes.
    let req = expect_request(&mut c).await;
    assert_eq!(req.method.as_str(), "HEAD");
    let mut res = ok(Body::empty());
    res.meta.declared_length = Some(1234);
    c.respond(res).await.unwrap();
    let (head, _) = read_response(&mut client, true).await;
    assert!(head.contains("content-length: 1234"), "{head}");

    // 204 -> no framing headers at all.
    let _ = expect_request(&mut c).await;
    c.respond(CanonicalResponse::new(StatusCode::NO_CONTENT))
        .await
        .unwrap();
    let (head, _) = read_response(&mut client, true).await;
    assert!(head.starts_with("HTTP/1.1 204 No Content\r\n"));
    assert!(!head.contains("content-length") && !head.contains("transfer-encoding"));

    client.shutdown().await.unwrap();
    assert!(c.next_request().await.unwrap().is_none());
    drop(c);
    let mut rest = Vec::new();
    client.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty(), "no stray bytes after HEAD/204: {rest:?}");
}

#[tokio::test]
async fn response_length_mismatch_is_an_error() {
    let (mut client, mut c) = conn();
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    let _ = expect_request(&mut c).await;
    let (mut tx, body) = Body::channel(100, Some(10));
    tokio::spawn(async move {
        tx.send_data(Bytes::from_static(b"short")).await.unwrap();
        drop(tx);
    });
    let err = c.respond(ok(body)).await.unwrap_err();
    assert!(matches!(err, WriteError::Body(_)), "{err:?}");
    assert!(c.is_closed());
}

#[tokio::test]
async fn connection_close_header_on_close() {
    let (mut client, mut c) = conn();
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let _ = expect_request(&mut c).await;
    c.respond(ok(Body::from_bytes("x"))).await.unwrap();
    let (head, _) = read_response(&mut client, false).await;
    assert!(head.contains("\r\nconnection: close\r\n"));
    assert!(c.next_request().await.unwrap().is_none());
    let mut rest = Vec::new();
    client.read_to_end(&mut rest).await.unwrap();
    assert_eq!(rest, Vec::<u8>::new());
}

fn closing(mut res: CanonicalResponse) -> CanonicalResponse {
    res.meta.close = true;
    res
}

#[tokio::test]
async fn meta_close_closes_after_body_and_skips_pipelined() {
    let (mut client, mut c) = conn();
    client
        .write_all(b"GET /a HTTP/1.1\r\nHost: example.com\r\n\r\nGET /b HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    let req = expect_request(&mut c).await;
    assert_eq!(req.path.as_str(), "/a");
    let server = tokio::spawn(async move {
        c.respond(closing(ok(Body::from_bytes("bye"))))
            .await
            .unwrap();
        assert!(c.is_closed());
        // The pipelined /b is never parsed.
        assert!(c.next_request().await.unwrap().is_none());
    });
    let (head, body) = read_response(&mut client, false).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(head.contains("\r\nconnection: close\r\n"), "{head}");
    assert_eq!(body, b"bye");
    // EOF after the body: no response to /b.
    let mut rest = Vec::new();
    client.read_to_end(&mut rest).await.unwrap();
    assert_eq!(rest, Vec::<u8>::new());
    drop(client);
    server.await.unwrap();
}

#[tokio::test]
async fn meta_close_chunked_body_then_eof() {
    let (mut client, mut c) = conn();
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    let _ = expect_request(&mut c).await;
    let (mut tx, body) = Body::channel(1 << 20, None);
    let server = tokio::spawn(async move {
        c.respond(closing(ok(body))).await.unwrap();
        assert!(c.next_request().await.unwrap().is_none());
    });
    tx.send_data(Bytes::from_static(b"abc")).await.unwrap();
    tx.finish().await.unwrap();
    let (head, body) = read_response(&mut client, false).await;
    assert!(head.contains("transfer-encoding: chunked"), "{head}");
    assert!(head.contains("\r\nconnection: close\r\n"), "{head}");
    assert_eq!(body, b"abc");
    let mut rest = Vec::new();
    client.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty(), "EOF after the body: {rest:?}");
    drop(client);
    server.await.unwrap();
}

/// A deny with `meta.close` does not wait for (or drain) a request body the
/// consumer dropped: the client that never sends its body still gets the
/// response promptly.
#[tokio::test(start_paused = true)]
async fn meta_close_abandons_dropped_body() {
    let (mut client, mut c) = conn();
    client
        .write_all(
            b"POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1000000\r\n\r\npartial",
        )
        .await
        .unwrap();
    let req = expect_request(&mut c).await;
    drop(req);
    let start = tokio::time::Instant::now();
    let server = tokio::spawn(async move {
        c.respond(closing(CanonicalResponse::new(StatusCode::FORBIDDEN)))
            .await
            .unwrap();
        assert!(c.is_closed());
    });
    let (head, _) = read_response(&mut client, false).await;
    assert!(head.starts_with("HTTP/1.1 403"), "{head}");
    assert!(head.contains("\r\nconnection: close\r\n"), "{head}");
    let mut rest = Vec::new();
    client.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty(), "EOF after the body: {rest:?}");
    // The client keeps its side open: the server lingers at most ~1 s.
    server.await.unwrap();
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "{:?}",
        start.elapsed()
    );
}

/// Without `meta.close` the same 403 keeps the connection alive (draining
/// the dropped body), so `meta.close` is what closes it.
#[tokio::test]
async fn without_meta_close_connection_stays_open() {
    let (mut client, mut c) = conn();
    client
        .write_all(b"GET /a HTTP/1.1\r\nHost: example.com\r\n\r\nGET /b HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    let _ = expect_request(&mut c).await;
    c.respond(CanonicalResponse::new(StatusCode::FORBIDDEN))
        .await
        .unwrap();
    let (head, _) = read_response(&mut client, false).await;
    assert!(!head.contains("connection"), "{head}");
    assert_eq!(expect_request(&mut c).await.path.as_str(), "/b");
}

fn proxy_conn() -> (DuplexStream, ServerConn<DuplexStream>) {
    let (client, server) = tokio::io::duplex(1 << 16);
    let c = ServerConn::new(
        server,
        Role::ProxyPort,
        Arc::new(Limits::default()),
        Arc::new(HttpFlags::default()),
    );
    (client, c)
}

#[tokio::test]
async fn proxy_auth_required_on_connect() {
    let (mut client, mut c) = proxy_conn();
    client
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n\x16\x03\x01early-client-hello")
        .await
        .unwrap();
    let Ok(Some(Incoming::Connect { .. })) = c.next_request().await else {
        panic!()
    };
    let server = tokio::spawn(async move {
        c.respond_proxy_auth_required(
            "roxy proxy",
            "text/plain",
            Bytes::from_static(b"auth needed"),
        )
        .await
        .unwrap();
    });
    let (head, body) = read_response(&mut client, false).await;
    assert!(
        head.starts_with("HTTP/1.1 407 Proxy Authentication Required\r\n"),
        "{head}"
    );
    assert!(
        head.contains("\r\nproxy-authenticate: Basic realm=\"roxy proxy\"\r\n"),
        "{head}"
    );
    assert!(head.contains("\r\ncontent-length: 11\r\n"), "{head}");
    assert!(head.contains("\r\nconnection: close\r\n"), "{head}");
    assert_eq!(body, b"auth needed");
    let mut rest = Vec::new();
    client.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty(), "EOF after the response: {rest:?}");
    drop(client);
    server.await.unwrap();
}

#[tokio::test]
async fn proxy_auth_required_on_request_abandons_body() {
    let (mut client, mut c) = proxy_conn();
    client
        .write_all(b"POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhelloGET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    let Ok(Some(Incoming::Request(req))) = c.next_request().await else {
        panic!()
    };
    let server = tokio::spawn(async move {
        c.respond_proxy_auth_required("r", "text/plain", Bytes::new())
            .await
            .unwrap();
    });
    let (head, body) = read_response(&mut client, false).await;
    assert!(head.starts_with("HTTP/1.1 407"), "{head}");
    assert!(head.contains("\r\ncontent-length: 0\r\n"), "{head}");
    assert!(body.is_empty(), "{body:?}");
    let mut rest = Vec::new();
    client.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty(), "the pipelined request is not served");
    drop(client);
    server.await.unwrap();
    // The request body was abandoned, never a clean end.
    assert!(req.body.collect_up_to(100).await.is_err());
}

#[tokio::test]
async fn proxy_auth_required_on_head_sends_no_body() {
    let (mut client, mut c) = proxy_conn();
    client
        .write_all(b"HEAD http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    let Ok(Some(Incoming::Request(_))) = c.next_request().await else {
        panic!()
    };
    let server = tokio::spawn(async move {
        c.respond_proxy_auth_required("r", "text/plain", Bytes::from_static(b"body"))
            .await
            .unwrap();
    });
    let (head, _) = read_response(&mut client, true).await;
    assert!(head.contains("\r\ncontent-length: 4\r\n"), "{head}");
    let mut rest = Vec::new();
    client.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty(), "no body bytes after a HEAD response");
    drop(client);
    server.await.unwrap();
}

#[tokio::test]
async fn proxy_auth_realm_is_validated() {
    for bad in [
        "a\"b",
        "a\\b",
        "tab\there",
        "nl\r\nx: y",
        "caf\u{e9}",
        "\x7f",
    ] {
        let (mut client, mut c) = proxy_conn();
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let Ok(Some(Incoming::Connect { .. })) = c.next_request().await else {
            panic!()
        };
        assert!(
            matches!(
                c.respond_proxy_auth_required(bad, "text/plain", Bytes::new())
                    .await,
                Err(WriteError::State(_))
            ),
            "{bad:?}"
        );
        // Nothing was written; the connection is gone.
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty(), "{bad:?}");
    }
    // No pending request: refused.
    let (_client, c) = proxy_conn();
    assert!(matches!(
        c.respond_proxy_auth_required("r", "text/plain", Bytes::new())
            .await,
        Err(WriteError::State(_))
    ));
}

/// `collect_prefix` on a real chunked request: inspect the first bytes,
/// then forward prefix + remainder intact.
#[tokio::test]
async fn collect_prefix_on_chunked_request() {
    let (mut client, mut c) = conn();
    client
        .write_all(b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
        .await
        .unwrap();
    let mut req = expect_request(&mut c).await;
    let body = std::mem::take(&mut req.body);
    let (prefix, all) = c
        .drive(async move {
            let (prefix, rest) = body.collect_prefix(7).await.unwrap();
            let rest = rest.unwrap().collect_up_to(1 << 20).await.unwrap();
            (prefix, rest)
        })
        .await
        .unwrap();
    assert_eq!(prefix, "hello w");
    assert_eq!(all, "orld");
    c.respond(ok(Body::empty())).await.unwrap();
    let (head, _) = read_response(&mut client, false).await;
    assert!(head.starts_with("HTTP/1.1 200"));
}

#[tokio::test]
async fn collect_prefix_on_length_request() {
    let (mut client, mut c) = conn();
    client
        .write_all(b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nabcd")
        .await
        .unwrap();
    let mut req = expect_request(&mut c).await;
    let body = std::mem::take(&mut req.body);
    let (prefix, rest) = c
        .drive(async move { body.collect_prefix(16).await.unwrap() })
        .await
        .unwrap();
    assert_eq!(prefix, "abcd");
    assert!(rest.is_none());
    c.respond(ok(Body::empty())).await.unwrap();
    let (head, _) = read_response(&mut client, false).await;
    assert!(head.starts_with("HTTP/1.1 200"));
}

#[tokio::test]
async fn body_streams_before_it_is_complete() {
    let (mut client, mut c) = conn();
    client
        .write_all(b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nfirst\r\n")
        .await
        .unwrap();
    let mut req = expect_request(&mut c).await;
    assert_eq!(req.body.known_length(), None);
    let mut body = std::mem::take(&mut req.body);
    let (got_first_tx, got_first_rx) = tokio::sync::oneshot::channel();
    // The "upstream": reads the first frame, signals, then reads the rest.
    let upstream = async move {
        let first = std::future::poll_fn(|cx| {
            http_body::Body::poll_frame(std::pin::Pin::new(&mut body), cx)
        })
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
        got_first_tx.send(()).unwrap();
        let rest = body.collect_up_to(1 << 20).await.unwrap();
        (first, rest)
    };
    let client_task = tokio::spawn(async move {
        got_first_rx.await.unwrap();
        client.write_all(b"6\r\nsecond\r\n0\r\n\r\n").await.unwrap();
        client
    });
    let (first, rest) = c.drive(upstream).await.unwrap();
    assert_eq!(first, "first");
    assert_eq!(rest, "second");
    let mut client = client_task.await.unwrap();
    c.respond(ok(Body::empty())).await.unwrap();
    let (head, _) = read_response(&mut client, false).await;
    assert!(head.starts_with("HTTP/1.1 200"));
}

#[tokio::test]
async fn backpressure_bounds_reading() {
    // Consumer never polls: the server must stop reading from the socket
    // instead of buffering, and give up after body_idle_timeout.
    let limits = Limits {
        body_idle_timeout: Duration::from_millis(200),
        ..Limits::default()
    };
    let (mut client, mut c) = conn_with(limits);
    let total: usize = 8 << 20;
    client
        .write_all(
            format!("POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: {total}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut req = expect_request(&mut c).await;
    let held = std::mem::take(&mut req.body); // held, never polled
    let writer = tokio::spawn(async move {
        let chunk = vec![b'x'; 64 * 1024];
        let mut written = 0;
        while written < total {
            if tokio::time::timeout(Duration::from_secs(2), client.write_all(&chunk))
                .await
                .is_err()
            {
                break;
            }
            written += chunk.len();
        }
        written
    });
    let err = c.drive(std::future::pending::<()>()).await.unwrap_err();
    assert_eq!(err.reason, Reason::BodyTimeout);
    let written = writer.await.unwrap();
    // Duplex buffer (64 KiB) + channel depth * read chunk + read buffer.
    assert!(written < 2 << 20, "server buffered {written} bytes");
    drop(held);
}

#[tokio::test]
async fn expect_100_continue_handshake() {
    let (mut client, mut c) = conn();
    client
        .write_all(b"PUT /up HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n")
        .await
        .unwrap();
    let mut req = expect_request(&mut c).await;
    assert!(req.meta.expect_continue);
    assert!(!req.headers.contains("expect"));
    let body = std::mem::take(&mut req.body);
    let client_task = tokio::spawn(async move {
        let mut interim = [0u8; 25];
        client.read_exact(&mut interim).await.unwrap();
        assert_eq!(&interim, b"HTTP/1.1 100 Continue\r\n\r\n");
        client.write_all(b"hello").await.unwrap();
        client
    });
    // Policy allowed: driving the body sends 100 Continue first.
    let got = c.drive(body.collect_up_to(100)).await.unwrap().unwrap();
    assert_eq!(got, "hello");
    let mut client = client_task.await.unwrap();
    c.respond(ok(Body::empty())).await.unwrap();
    let (head, _) = read_response(&mut client, false).await;
    assert!(head.starts_with("HTTP/1.1 200"));
    assert!(!head.contains("connection: close"));
}

#[tokio::test]
async fn expect_100_denied_closes() {
    let (mut client, mut c) = conn();
    client
        .write_all(b"PUT /up HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n")
        .await
        .unwrap();
    let req = expect_request(&mut c).await;
    drop(req);
    let mut res = CanonicalResponse::new(StatusCode::FORBIDDEN);
    res.body = Body::from_bytes("no");
    c.respond(res).await.unwrap();
    let (head, body) = read_response(&mut client, false).await;
    assert!(head.starts_with("HTTP/1.1 403 Forbidden\r\n"));
    assert!(head.contains("connection: close"));
    assert_eq!(body, b"no");
    assert!(c.next_request().await.unwrap().is_none());
}

#[tokio::test]
async fn body_over_cap_mid_stream_closes() {
    let limits = Limits {
        max_request_body_bytes: 10,
        ..Limits::default()
    };
    let (mut client, mut c) = conn_with(limits);
    client
        .write_all(b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nabcdef\r\n6\r\nghijkl\r\n0\r\n\r\n")
        .await
        .unwrap();
    let mut req = expect_request(&mut c).await;
    let body = std::mem::take(&mut req.body);
    let consumer = tokio::spawn(body.collect_up_to(1 << 20));
    let err = c.drive(std::future::pending::<()>()).await.unwrap_err();
    assert_eq!(err.reason, Reason::BodyTooLarge);
    assert_eq!(
        consumer.await.unwrap().unwrap_err(),
        BodyError::TooLarge { limit: 10 }
    );
    assert!(c.is_closed());
    assert_eq!(
        c.next_request().await.unwrap_err().reason,
        Reason::InvalidState
    );
    c.respond_error_and_close(StatusCode::PAYLOAD_TOO_LARGE, &err.reason)
        .await
        .unwrap();
    let mut out = Vec::new();
    client.read_to_end(&mut out).await.unwrap();
    let out = String::from_utf8(out).unwrap();
    assert!(
        out.starts_with("HTTP/1.1 413 Payload Too Large\r\n"),
        "{out}"
    );
    assert!(out.contains("connection: close"));
    assert!(out.ends_with("{\"error\":\"rejected by roxy\",\"reason\":\"body_too_large\"}"));
}

#[tokio::test]
async fn dropped_body_is_drained_and_connection_reused() {
    let (mut client, mut c) = conn();
    client
        .write_all(b"POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 11\r\n\r\nhello worldGET /next HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    let req = expect_request(&mut c).await;
    drop(req); // e.g. denied by policy
    c.respond(CanonicalResponse::new(StatusCode::FORBIDDEN))
        .await
        .unwrap();
    let (head, _) = read_response(&mut client, false).await;
    assert!(!head.contains("connection: close"), "{head}");
    let req = expect_request(&mut c).await;
    assert_eq!(req.path.as_str(), "/next");
}

#[tokio::test]
async fn dropped_large_body_closes_after_drain_limit() {
    let (mut client, mut c) = conn();
    let total = DRAIN_LIMIT * 4;
    client
        .write_all(
            format!("POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: {total}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let req = expect_request(&mut c).await;
    drop(req);
    let writer = tokio::spawn(async move {
        let chunk = vec![b'x'; 64 * 1024];
        let (mut rd, mut wr) = tokio::io::split(client);
        let reader = tokio::spawn(async move {
            let mut out = Vec::new();
            let _ = rd.read_to_end(&mut out).await;
            out
        });
        for _ in 0..(total / chunk.len() as u64) {
            if wr.write_all(&chunk).await.is_err() {
                break;
            }
        }
        drop(wr);
        reader.await.unwrap()
    });
    c.respond(CanonicalResponse::new(StatusCode::FORBIDDEN))
        .await
        .unwrap();
    assert!(c.next_request().await.unwrap().is_none());
    drop(c);
    let out = String::from_utf8(writer.await.unwrap()).unwrap();
    assert!(out.starts_with("HTTP/1.1 403"), "{out}");
}

#[tokio::test(start_paused = true)]
async fn header_timeout() {
    let (mut client, mut c) = conn();
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: exa")
        .await
        .unwrap();
    let err = c.next_request().await.unwrap_err();
    assert_eq!(err.reason, Reason::HeaderTimeout);
}

#[tokio::test(start_paused = true)]
async fn header_timeout_applies_to_pipelined_partial_head() {
    let (mut client, mut c) = conn();
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\nGET /b HTTP/1.1\r\nHost: exa")
        .await
        .unwrap();
    let _ = expect_request(&mut c).await;
    c.respond(ok(Body::empty())).await.unwrap();
    let start = tokio::time::Instant::now();
    let err = c.next_request().await.unwrap_err();
    assert_eq!(err.reason, Reason::HeaderTimeout);
    assert!(start.elapsed() < Limits::default().idle_timeout);
}

#[tokio::test(start_paused = true)]
async fn first_request_never_sent_times_out() {
    let (_client, mut c) = conn();
    let err = c.next_request().await.unwrap_err();
    assert_eq!(err.reason, Reason::HeaderTimeout);
}

#[tokio::test(start_paused = true)]
async fn idle_timeout_between_requests() {
    let (mut client, mut c) = conn();
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    let _ = expect_request(&mut c).await;
    c.respond(ok(Body::empty())).await.unwrap();
    let start = tokio::time::Instant::now();
    assert!(c.next_request().await.unwrap().is_none());
    assert!(start.elapsed() >= Limits::default().idle_timeout);
}

#[tokio::test(start_paused = true)]
async fn client_close_during_bodiless_request_ends_drive() {
    let (mut client, mut c) = conn();
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    let _ = expect_request(&mut c).await;
    drop(client);
    let err = tokio::time::timeout(
        Duration::from_secs(5),
        c.drive(std::future::pending::<()>()),
    )
    .await
    .expect("drive notices the closed client")
    .unwrap_err();
    assert_eq!(err.reason, Reason::UnexpectedEof);
}

#[tokio::test(start_paused = true)]
async fn pipelined_bytes_during_bodiless_request_are_kept() {
    let (mut client, mut c) = conn();
    client
        .write_all(b"GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    let _ = expect_request(&mut c).await;
    // The pipelined head arrives while the response is pending, so the
    // idle-socket watch is what reads it.
    let upstream = async move {
        client
            .write_all(b"GET /b HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
        client
    };
    let mut client = c.drive(upstream).await.unwrap();
    c.respond(ok(Body::empty())).await.unwrap();
    let _ = read_response(&mut client, false).await;
    let second = expect_request(&mut c).await;
    assert_eq!(second.path.as_str(), "/b");
}

#[tokio::test(start_paused = true)]
async fn body_idle_timeout() {
    let (mut client, mut c) = conn();
    client
        .write_all(b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\n\r\nabc")
        .await
        .unwrap();
    let mut req = expect_request(&mut c).await;
    let body = std::mem::take(&mut req.body);
    let consumer = tokio::spawn(body.collect_up_to(100));
    let err = c.drive(std::future::pending::<()>()).await.unwrap_err();
    assert_eq!(err.reason, Reason::BodyTimeout);
    assert_eq!(consumer.await.unwrap().unwrap_err(), BodyError::Timeout);
}

#[tokio::test]
async fn connect_accept_hands_back_stream() {
    let (mut client, server) = tokio::io::duplex(1 << 16);
    let mut c = ServerConn::new(
        server,
        Role::ProxyPort,
        Arc::new(Limits::default()),
        Arc::new(HttpFlags::default()),
    );
    client
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nEARLY")
        .await
        .unwrap();
    let Ok(Some(Incoming::Connect { authority, .. })) = c.next_request().await else {
        panic!()
    };
    assert_eq!(authority.to_string(), "example.com:443");
    let (mut io, leftover) = c.accept_connect().await.unwrap();
    assert_eq!(&leftover[..], b"EARLY");
    let mut head = [0u8; 39];
    client.read_exact(&mut head).await.unwrap();
    assert_eq!(&head, b"HTTP/1.1 200 Connection Established\r\n\r\n");
    client.write_all(b"ping").await.unwrap();
    let mut got = [0u8; 4];
    io.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"ping");
}

#[tokio::test]
async fn connect_respond_2xx_refused_and_407_keeps_alive() {
    let (mut client, server) = tokio::io::duplex(1 << 16);
    let mut c = ServerConn::new(
        server,
        Role::ProxyPort,
        Arc::new(Limits::default()),
        Arc::new(HttpFlags::default()),
    );
    client
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\nCONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic eDp5\r\n\r\n")
        .await
        .unwrap();
    let Ok(Some(Incoming::Connect { meta, .. })) = c.next_request().await else {
        panic!()
    };
    assert!(meta.proxy_authorization.is_none());
    assert!(matches!(
        c.respond(CanonicalResponse::new(StatusCode::OK)).await,
        Err(WriteError::State(_))
    ));
    c.respond(CanonicalResponse::new(
        StatusCode::PROXY_AUTHENTICATION_REQUIRED,
    ))
    .await
    .unwrap();
    let (head, _) = read_response(&mut client, false).await;
    assert!(head.starts_with("HTTP/1.1 407"));
    let Ok(Some(Incoming::Connect { meta, .. })) = c.next_request().await else {
        panic!()
    };
    assert_eq!(meta.proxy_authorization.unwrap(), "Basic eDp5");
}

#[tokio::test]
async fn misuse_is_reported() {
    let (mut client, mut c) = conn();
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    let _ = expect_request(&mut c).await;
    assert_eq!(
        c.next_request().await.unwrap_err().reason,
        Reason::InvalidState
    );
}

/// The connection futures must be `Send` so `roxy-proxy` can spawn them.
#[test]
fn futures_are_send() {
    fn assert_send<T: Send>(_: &T) {}
    let (_client, mut c) = conn();
    let f = c.next_request();
    assert_send(&f);
    drop(f);
    let f = c.respond(CanonicalResponse::new(StatusCode::OK));
    assert_send(&f);
    drop(f);
    let f = c.drive(async {});
    assert_send(&f);
    drop(f);
    let f = c.send_100_continue();
    assert_send(&f);
    drop(f);
    let f = c.respond_error_and_close(StatusCode::BAD_REQUEST, &Reason::BareLf);
    assert_send(&f);
    let (_client, c) = conn();
    let f = c.accept_connect();
    assert_send(&f);
    let (_client, c) = conn();
    let f = c.respond_proxy_auth_required("r", "text/plain", Bytes::new());
    assert_send(&f);
    let (_client, c) = conn();
    let f = c.respond_upgrade(CanonicalResponse::new(StatusCode::SWITCHING_PROTOCOLS));
    assert_send(&f);
}
