//! hyper interop: what hyper actually puts on the wire for canonical
//! requests, and how upstream responses are adapted.

use std::sync::Arc;

use bytes::Bytes;
use hyper_util::rt::TokioIo;
use roxy_http::h1::{Head, Incoming, Role, ServerConn, parse_head};
use roxy_http::upstream::{UriForm, from_upstream_response, to_upstream_request};
use roxy_http::url::{parse_authority, parse_origin_form};
use roxy_http::{
    Body, BodyError, CanonicalRequest, Headers, HttpFlags, Limits, Method, RequestMeta, Scheme,
    TargetForm, Version,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

fn canon(method: Method, target: &str, headers: Headers, body: Body) -> CanonicalRequest {
    let (path, query) = parse_origin_form(target.as_bytes()).unwrap();
    CanonicalRequest {
        method,
        scheme: Scheme::Https,
        authority: parse_authority(b"example.com:8443", 443).unwrap(),
        path,
        query,
        headers,
        body,
        meta: RequestMeta::new(Version::H1_1, TargetForm::Origin),
    }
}

/// Reads one raw request from `raw`: the head plus a body framed by
/// content-length or chunked.
async fn read_raw_request(raw: &mut DuplexStream) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..i]).to_ascii_lowercase();
            let total = if let Some(cl) = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length: "))
            {
                Some(i + 4 + cl.parse::<usize>().unwrap())
            } else if head.contains("transfer-encoding: chunked") {
                buf.windows(5)
                    .position(|w| w == b"0\r\n\r\n")
                    .filter(|&p| p > i)
                    .map(|p| p + 5)
            } else {
                Some(i + 4)
            };
            if let Some(t) = total
                && buf.len() >= t
            {
                return buf;
            }
        }
        let n = raw.read(&mut tmp).await.unwrap();
        assert!(n > 0, "EOF before request complete: {buf:?}");
        buf.extend_from_slice(&tmp[..n]);
    }
}

/// Sends `req` through hyper's HTTP/1.1 client and returns the exact bytes
/// hyper wrote.
async fn capture(req: http::Request<Body>) -> String {
    let (client_io, mut raw) = tokio::io::duplex(1 << 16);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(client_io))
        .await
        .unwrap();
    tokio::spawn(conn);
    let resp = tokio::spawn(async move { sender.send_request(req).await });
    let bytes = read_raw_request(&mut raw).await;
    raw.write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
        .await
        .unwrap();
    let res = resp.await.unwrap().unwrap();
    assert_eq!(res.status(), 204);
    String::from_utf8(bytes).unwrap()
}

fn header_lines(wire: &str) -> Vec<&str> {
    let head = &wire[..wire.find("\r\n\r\n").unwrap()];
    head.split("\r\n").collect()
}

#[tokio::test]
async fn unknown_length_is_clean_chunked() {
    let (mut tx, body) = Body::channel(1 << 20, None);
    tokio::spawn(async move {
        tx.send_data(Bytes::from_static(b"hello")).await.unwrap();
        tx.send_data(Bytes::from_static(b"world!")).await.unwrap();
        tx.finish().await.unwrap();
    });
    let mut h = Headers::new();
    h.append("x-a", "1").unwrap();
    let req =
        to_upstream_request(canon(Method::Post, "/p?q=%2f", h, body), UriForm::Origin).unwrap();
    let wire = capture(req).await;
    assert_eq!(
        wire,
        "POST /p?q=%2F HTTP/1.1\r\nhost: example.com:8443\r\nx-a: 1\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\nworld!\r\n0\r\n\r\n"
    );
}

/// hyper's HTTP/1.1 encoder writes trailers only for names a `trailer`
/// header announces, which a canonical request never carries: trailers
/// handed to it end the body as plain `0\r\n\r\n`. The proxy's refusal of
/// trailers towards an HTTP/1.1 upstream rests on this. This pins hyper,
/// not roxy: if a hyper upgrade fails it, re-check whether roxy-proxy's
/// `trailers` refusal for HTTP/1.1 origins is still needed, and what the
/// encoder now does with a `Trailer` header the client sent.
#[tokio::test]
async fn h1_encoder_drops_trailers_without_a_trailer_header() {
    let (mut tx, body) = Body::channel(1 << 20, None);
    tokio::spawn(async move {
        tx.send_data(Bytes::from_static(b"abc")).await.unwrap();
        let mut t = http::HeaderMap::new();
        t.insert("x-checksum", http::HeaderValue::from_static("abc"));
        tx.send_trailers(t).await.unwrap();
        tx.finish().await.unwrap();
    });
    let req = to_upstream_request(
        canon(Method::Post, "/t", Headers::new(), body),
        UriForm::Origin,
    )
    .unwrap();
    let wire = capture(req).await;
    assert!(wire.ends_with("\r\n\r\n3\r\nabc\r\n0\r\n\r\n"), "{wire:?}");
    assert!(!wire.contains("x-checksum"), "{wire:?}");
}

#[tokio::test]
async fn known_length_uses_content_length() {
    let req = to_upstream_request(
        canon(Method::Put, "/x", Headers::new(), Body::from_bytes("hello")),
        UriForm::Origin,
    )
    .unwrap();
    let wire = capture(req).await;
    assert_eq!(
        wire,
        "PUT /x HTTP/1.1\r\nhost: example.com:8443\r\ncontent-length: 5\r\n\r\nhello"
    );
}

#[tokio::test]
async fn empty_post_and_get_framing() {
    let req = to_upstream_request(
        canon(Method::Post, "/x", Headers::new(), Body::empty()),
        UriForm::Origin,
    )
    .unwrap();
    let wire = capture(req).await;
    assert_eq!(
        wire,
        "POST /x HTTP/1.1\r\nhost: example.com:8443\r\ncontent-length: 0\r\n\r\n"
    );
    let req = to_upstream_request(
        canon(Method::Get, "/x", Headers::new(), Body::empty()),
        UriForm::Origin,
    )
    .unwrap();
    let wire = capture(req).await;
    assert_eq!(wire, "GET /x HTTP/1.1\r\nhost: example.com:8443\r\n\r\n");
}

#[tokio::test]
async fn no_hop_by_hop_and_host_first() {
    let raw: Vec<(&[u8], &[u8])> = vec![
        (b"Accept", b"*/*"),
        (b"Connection", b"keep-alive, X-Secret, Upgrade"),
        (b"X-Secret", b"s"),
        (b"Keep-Alive", b"timeout=5"),
        (b"TE", b"trailers"),
        (b"Trailer", b"x"),
        (b"Upgrade", b"websocket"),
        (b"Proxy-Authorization", b"Basic eDp5"),
        (b"Proxy-Connection", b"keep-alive"),
        (b"Host", b"attacker.example"),
        (b"Content-Length", b"999"),
        (b"Transfer-Encoding", b"chunked"),
    ];
    let h = Headers::try_from_raw(raw, &Limits::default(), &HttpFlags::default()).unwrap();
    let req =
        to_upstream_request(canon(Method::Get, "/", h, Body::empty()), UriForm::Origin).unwrap();
    let wire = capture(req).await;
    let lines = header_lines(&wire);
    assert_eq!(lines[0], "GET / HTTP/1.1");
    assert_eq!(lines[1], "host: example.com:8443");
    assert_eq!(lines[2..], ["accept: */*"]);
}

/// Absolute form carries the authority in the URI only: the pooled client
/// adds `host` itself over HTTP/1.1, and over HTTP/2 a `host` next to
/// `:authority` is a duplicate that origins such as nginx reject.
#[tokio::test]
async fn absolute_form_for_pooled_clients() {
    let mut h = Headers::new();
    h.insert("x-a", "1").unwrap();
    let req = to_upstream_request(
        canon(Method::Get, "/a?b", h, Body::empty()),
        UriForm::Absolute,
    )
    .unwrap();
    assert_eq!(req.uri().to_string(), "https://example.com:8443/a?b");
    assert!(!req.headers().contains_key("host"), "{:?}", req.headers());
    assert_eq!(req.headers()["x-a"], "1");
    let mut c = canon(Method::Get, "/", Headers::new(), Body::empty());
    c.authority.port = 443;
    let req = to_upstream_request(c, UriForm::Absolute).unwrap();
    assert_eq!(req.uri().to_string(), "https://example.com/");
    assert!(!req.headers().contains_key("host"), "{:?}", req.headers());
}

/// Client bytes → `ServerConn` → canonical → hyper → upstream bytes, then the
/// upstream bytes parsed again yield the same canonical request
/// (serialise → parse round trip).
#[tokio::test]
async fn end_to_end_reserialisation_round_trip() {
    let role = Role::Tunnel {
        authority: parse_authority(b"example.com:8443", 443).unwrap(),
        scheme: Scheme::Https,
    };
    let (mut client, server) = tokio::io::duplex(1 << 16);
    let mut conn = ServerConn::new(
        server,
        role.clone(),
        Arc::new(Limits::default()),
        Arc::new(HttpFlags::default()),
    );
    client
        .write_all(
            b"POST /a/./b/../c?x=%7e HTTP/1.1\r\nHOST: Example.COM:8443\r\nX-Custom:  v \r\nTransfer-Encoding: Chunked\r\nConnection: keep-alive\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n",
        )
        .await
        .unwrap();
    let Ok(Some(Incoming::Request(req))) = conn.next_request().await else {
        panic!()
    };
    let (path, query, headers) = (req.path.clone(), req.query.clone(), req.headers.clone());
    let up = to_upstream_request(req, UriForm::Origin).unwrap();
    let wire = conn.drive(capture(up)).await.unwrap();
    assert_eq!(
        wire,
        "POST /a/c?x=%7E HTTP/1.1\r\nhost: example.com:8443\r\nx-custom: v\r\ntransfer-encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n"
    );
    let head_len = wire.find("\r\n\r\n").unwrap() + 4;
    let Head::Request(again) = parse_head(
        &wire.as_bytes()[..head_len],
        &role,
        &Limits::default(),
        &HttpFlags::default(),
    )
    .unwrap() else {
        panic!()
    };
    assert_eq!(again.path, path);
    assert_eq!(again.query, query);
    assert_eq!(again.headers, headers);
}

#[tokio::test]
async fn upstream_response_adapted() {
    let (client_io, mut raw) = tokio::io::duplex(1 << 16);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(client_io))
        .await
        .unwrap();
    tokio::spawn(conn);
    let req = to_upstream_request(
        canon(Method::Get, "/", Headers::new(), Body::empty()),
        UriForm::Origin,
    )
    .unwrap();
    let resp = tokio::spawn(async move { sender.send_request(req).await });
    let _ = read_raw_request(&mut raw).await;
    raw.write_all(
        b"HTTP/1.1 200 OK\r\nConnection: X-Hop\r\nX-Hop: 1\r\nKeep-Alive: timeout=5\r\nTransfer-Encoding: chunked\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nContent-Type: text/plain\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
    )
    .await
    .unwrap();
    let res = resp.await.unwrap().unwrap();
    let canon_res = from_upstream_response(res, &Limits::default());
    let names: Vec<_> = canon_res.headers.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, ["set-cookie", "set-cookie", "content-type"]);
    assert_eq!(canon_res.body.known_length(), None);
    assert_eq!(
        canon_res.body.collect_up_to(1 << 20).await.unwrap().data,
        "hello world"
    );
}

#[tokio::test]
async fn upstream_response_cap_applies_while_streaming() {
    let (client_io, server_io) = tokio::io::duplex(1 << 16);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(client_io))
        .await
        .unwrap();
    tokio::spawn(conn);
    // A real hyper server on the other end.
    tokio::spawn(async move {
        let svc = hyper::service::service_fn(|_req: http::Request<hyper::body::Incoming>| async {
            Ok::<_, std::convert::Infallible>(
                http::Response::builder()
                    .header("content-type", "application/octet-stream")
                    .body(http_body_util::Full::new(Bytes::from(vec![b'x'; 10_000])))
                    .unwrap(),
            )
        });
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(server_io), svc)
            .await;
    });
    let req = to_upstream_request(
        canon(Method::Get, "/", Headers::new(), Body::empty()),
        UriForm::Origin,
    )
    .unwrap();
    let res = sender.send_request(req).await.unwrap();
    let limits = Limits {
        max_response_body_bytes: 4096,
        ..Limits::default()
    };
    let canon_res = from_upstream_response(res, &limits);
    assert_eq!(canon_res.body.known_length(), Some(10_000));
    assert_eq!(canon_res.meta.declared_length, Some(10_000));
    assert!(!canon_res.headers.contains("content-length"));
    assert_eq!(
        canon_res.body.collect_up_to(1 << 20).await.unwrap_err(),
        BodyError::TooLarge { limit: 4096 }
    );
}

#[test]
fn upgrade_detected_beside_a_malformed_connection_element() {
    let res = http::Response::builder()
        .status(http::StatusCode::SWITCHING_PROTOCOLS)
        .header("connection", "upgrade, (bad)")
        .header("upgrade", "WebSocket")
        .header("x-hop", "1")
        .body(Body::empty())
        .unwrap();
    let c = from_upstream_response(res, &Limits::default());
    assert_eq!(c.meta.upgrade.as_deref(), Some("websocket"));
    assert!(!c.headers.contains("upgrade"));
}
