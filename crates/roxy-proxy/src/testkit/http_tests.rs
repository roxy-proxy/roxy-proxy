//! The wire the client sees: refusals on h1 and h2 connections, request
//! framing, body caps, h2 streams, and what the flow log holds back.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::AsyncWriteExt as _;

use super::{Answer, Kit, LogGate, read_response, sha256_hex, streaming_body};

const SOFT_DENY: &str = r#"
- id: soft
  when: host == "up.test" and path == "/soft"
  then: { deny: { status: 451, message: "not here", close: false } }
- id: up
  when: host == "up.test"
  then: allow
"#;

const DIGEST_BOTH: &str = r#"
- id: up
  when: host == "up.test"
  then: [{ digest: both }, allow]
"#;

const DIGEST_REQUEST: &str = r#"
- id: up
  when: host == "up.test"
  then: [{ digest: request }, allow]
"#;

fn json(b: &[u8]) -> serde_json::Value {
    serde_json::from_slice(b)
        .unwrap_or_else(|e| panic!("not JSON ({e}): {}", String::from_utf8_lossy(b)))
}

async fn h2_or_h1(kit: &Kit, h2: bool) -> super::Client {
    if h2 {
        kit.tunnel("up.test", true).await
    } else {
        kit.h1().await
    }
}

// ---- refusals -------------------------------------------------------------

/// The default deny answers JSON naming the rule, with `x-roxy-rule`, and
/// closes the connection.
#[tokio::test]
async fn the_default_deny_answers_json_and_closes() {
    let kit = Kit::builder().rules("[]").start().await;
    let (out, eof) = kit
        .raw(b"GET http://up.test/x HTTP/1.1\r\nhost: up.test\r\n\r\n")
        .await;
    assert!(eof, "connection must close after a deny");
    assert!(out.starts_with("HTTP/1.1 403"), "{out}");
    assert!(out.contains("connection: close"), "{out}");
    assert!(out.contains("x-roxy-rule: _default"), "{out}");
    let body = json(out.split("\r\n\r\n").nth(1).unwrap().as_bytes());
    assert_eq!(body["rule"], "_default");
    assert_eq!(body["error"], "blocked by roxy");
    assert_eq!(body["flow"].as_str().unwrap().len(), 26);
    assert!(kit.upstream.seen().is_empty());
    let ev = kit.request_event().await;
    assert_eq!(ev["decision"], "deny", "{ev:#}");
}

/// A deny with `close: false` carries its status and message and leaves
/// the connection serving.
#[tokio::test]
async fn a_soft_deny_keeps_the_connection_and_carries_its_message() {
    let kit = Kit::builder().rules(SOFT_DENY).start().await;
    let mut io = kit.connect();
    io.write_all(b"GET http://up.test/soft HTTP/1.1\r\nhost: up.test\r\n\r\n")
        .await
        .unwrap();
    let (head, body) = read_response(&mut io).await;
    assert!(head.starts_with("HTTP/1.1 451"), "{head}");
    assert!(!head.contains("connection: close"), "{head}");
    assert!(head.contains("x-roxy-rule: soft"), "{head}");
    assert_eq!(json(&body)["error"], "not here");
    io.write_all(b"GET http://up.test/after HTTP/1.1\r\nhost: up.test\r\n\r\n")
        .await
        .unwrap();
    let (head, body) = read_response(&mut io).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(json(&body)["path"], "/after");
}

/// A CONNECT is accepted for inspection whatever the rules say about the
/// host; the request inside it is what gets decided.
#[tokio::test]
async fn a_connect_is_accepted_and_the_request_inside_decided() {
    let kit = Kit::builder().start().await;
    let mut c = kit.tunnel("other.test", false).await;
    let a = c.call("GET", "/admin/x", &[], b"").await;
    assert_eq!(a.status, 403, "{a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "_default");
    let ev = kit.request_event().await;
    assert_eq!(ev["stage"], "head", "{ev:#}");
    assert_eq!(ev["terminal_rule"], "_default");
    assert!(kit.upstream.seen().is_empty());
}

// ---- request framing ------------------------------------------------------

#[tokio::test]
async fn expect_100_continue_is_answered_then_the_body_forwarded() {
    let kit = Kit::builder().start().await;
    let mut io = kit.connect();
    io.write_all(
        b"POST http://up.test/e HTTP/1.1\r\nhost: up.test\r\ncontent-length: 5\r\nexpect: 100-continue\r\n\r\n",
    )
    .await
    .unwrap();
    let head = super::read_head(&mut io).await;
    assert!(head.starts_with("HTTP/1.1 100"), "{head}");
    io.write_all(b"hello").await.unwrap();
    let (head, body) = read_response(&mut io).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(json(&body)["body_len"], 5);
    assert_eq!(kit.upstream.wait_seen(1).await[0].body, b"hello");
}

/// Requests follow each other on one connection, and two in one write are
/// both served.
#[tokio::test]
async fn keep_alive_and_pipelining() {
    let kit = Kit::builder().start().await;
    let req = |p: &str| format!("GET http://up.test{p} HTTP/1.1\r\nhost: up.test\r\n\r\n");
    let mut io = kit.connect();
    for i in 0..5 {
        io.write_all(req(&format!("/seq/{i}")).as_bytes())
            .await
            .unwrap();
        let (head, body) = read_response(&mut io).await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert_eq!(json(&body)["path"], format!("/seq/{i}"));
    }
    io.write_all(format!("{}{}", req("/p1"), req("/p2")).as_bytes())
        .await
        .unwrap();
    let (_, b1) = read_response(&mut io).await;
    let (_, b2) = read_response(&mut io).await;
    assert_eq!(json(&b1)["path"], "/p1");
    assert_eq!(json(&b2)["path"], "/p2");
}

/// A bare LF line ending, and `content-length` with `transfer-encoding`,
/// are refused with `400` and the connection closed.
#[tokio::test]
async fn parse_errors_close_with_400() {
    let kit = Kit::builder().start().await;
    let (out, eof) = kit
        .raw(b"GET http://up.test/ HTTP/1.1\nhost: up.test\n\n")
        .await;
    assert!(eof);
    assert!(out.starts_with("HTTP/1.1 400"), "{out}");
    let (out, eof) = kit
        .raw(
            b"POST http://up.test/ HTTP/1.1\r\nhost: up.test\r\ncontent-length: 5\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n",
        )
        .await;
    assert!(eof);
    assert!(out.starts_with("HTTP/1.1 400"), "{out}");
    let ev = kit.events("parse_error", 2).await;
    let reasons: Vec<&str> = ev.iter().map(|e| e["reason"].as_str().unwrap()).collect();
    assert_eq!(reasons, ["bare_lf", "cl_and_te"]);
    assert!(kit.upstream.seen().is_empty());
}

#[tokio::test]
async fn garbage_after_a_connect_closes_the_tunnel() {
    let kit = Kit::builder().start().await;
    let mut io = kit.connect_tunnel("up.test", 443).await;
    io.write_all(b"\x00\x01\x02 not tls, not http\r\n\r\n")
        .await
        .unwrap();
    let (out, eof) = super::read_to_eof(&mut io).await;
    assert!(eof);
    assert!(out.is_empty(), "nothing may follow the 200: {out:?}");
    let ev = kit.events("parse_error", 1).await;
    assert_eq!(ev[0]["reason"], "non_http_in_connect");
    assert!(kit.upstream.seen().is_empty());
}

#[tokio::test]
async fn plaintext_in_a_connect_is_refused_by_default() {
    let kit = Kit::builder().start().await;
    let mut io = kit.connect_tunnel("up.test", 80).await;
    io.write_all(b"GET /x HTTP/1.1\r\nhost: up.test\r\n\r\n")
        .await
        .unwrap();
    let (out, eof) = super::read_to_eof(&mut io).await;
    assert!(eof);
    assert!(out.is_empty(), "{out:?}");
    let ev = kit.events("parse_error", 1).await;
    assert_eq!(ev[0]["reason"], "non_http_in_connect");
    assert!(kit.upstream.seen().is_empty());
}

/// TLS in a tunnel must name the CONNECT host: another SNI never completes
/// the handshake.
#[tokio::test]
async fn a_mismatched_sni_in_a_tunnel_closes() {
    let kit = Kit::builder().start().await;
    let io = kit.connect_tunnel("up.test", 443).await;
    let r = kit.tls_connect(io, "other.test", &[b"http/1.1"]).await;
    assert!(r.is_err(), "TLS must not complete with a mismatched SNI");
    let ev = kit.events("parse_error", 1).await;
    assert_eq!(ev[0]["reason"], "sni_mismatch");
}

// ---- bodies ---------------------------------------------------------------

/// Bodies arrive whole, with and without a declared length, on h1 and h2.
async fn large_uploads_stream_intact(h2: bool) {
    let kit = Kit::builder().start().await;
    let mut c = h2_or_h1(&kit, h2).await;
    let data: Vec<u8> = (0..8 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
    let req = c
        .request("POST", "/upload", &[])
        .body(roxy_http::Body::from_bytes(Bytes::from(data.clone())))
        .unwrap();
    let a = Answer::read(c.send(req).await.unwrap()).await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.json()["body_len"], data.len());

    let (mut tx, body) = streaming_body();
    let req = c.request("POST", "/chunked", &[]).body(body).unwrap();
    let pending = c.start(req);
    let chunk: Vec<u8> = (0..64 * 1024u32).map(|i| (i % 13) as u8).collect();
    for _ in 0..16 {
        tx.send_data(Bytes::from(chunk.clone())).await.unwrap();
    }
    tx.finish().await.unwrap();
    let a = pending.await.unwrap().unwrap();
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.json()["body_len"], 16 * chunk.len());

    let seen = kit.upstream.wait_seen(2).await;
    assert_eq!(seen[0].body, data);
    assert!(seen[1].body.chunks(chunk.len()).all(|c| c == chunk));
    assert!(!seen[1].headers.contains_key("content-length"));
    let ev = kit.events("request", 2).await;
    assert_eq!(ev[0]["req"]["body_bytes"], data.len(), "{ev:#?}");
}

#[tokio::test]
async fn h1_large_uploads_stream_intact() {
    large_uploads_stream_intact(false).await;
}

#[tokio::test]
async fn h2_large_uploads_stream_intact() {
    large_uploads_stream_intact(true).await;
}

/// Under `digest: both` the `request` record digests each body as
/// forwarded: a request body sent whole or in chunks, the echoed response,
/// and the empty body of a bare GET.
async fn the_request_record_digests_both_bodies(h2: bool) {
    let kit = Kit::builder().rules(DIGEST_BOTH).start().await;
    let mut c = h2_or_h1(&kit, h2).await;
    let data: Vec<u8> = (0..100 * 1024u32).map(|i| (i % 241) as u8).collect();
    let req = c
        .request("POST", "/echo", &[])
        .body(roxy_http::Body::from_bytes(Bytes::from(data.clone())))
        .unwrap();
    let a = Answer::read(c.send(req).await.unwrap()).await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.body.as_deref().ok(), Some(&data[..]));

    let (mut tx, body) = streaming_body();
    let req = c.request("POST", "/echo", &[]).body(body).unwrap();
    let pending = c.start(req);
    for chunk in data.chunks(7 * 1024) {
        tx.send_data(Bytes::copy_from_slice(chunk)).await.unwrap();
    }
    tx.finish().await.unwrap();
    let a = pending.await.unwrap().unwrap();
    assert_eq!(a.status, 200, "{a:?}");

    let a = c.call("GET", "/nothing", &[], b"").await;
    assert_eq!(a.status, 200, "{a:?}");
    let answer = a.body.unwrap();

    let ev = kit.events("request", 3).await;
    let digest = sha256_hex(&data);
    for e in &ev[..2] {
        assert_eq!(e["req"]["body_bytes"], data.len(), "{e:#}");
        assert_eq!(e["req"]["body_sha256"], digest, "{e:#}");
        assert_eq!(e["res"]["body_sha256"], digest, "{e:#}");
    }
    assert_eq!(
        ev[2]["req"]["body_sha256"],
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "{:#}",
        ev[2]
    );
    assert_eq!(
        ev[2]["res"]["body_sha256"],
        sha256_hex(&answer),
        "{:#}",
        ev[2]
    );
}

#[tokio::test]
async fn h1_the_request_record_digests_both_bodies() {
    the_request_record_digests_both_bodies(false).await;
}

#[tokio::test]
async fn h2_the_request_record_digests_both_bodies() {
    the_request_record_digests_both_bodies(true).await;
}

/// A response body the upstream cut short has no digest even when a rule
/// asked for one; the request body, which completed, keeps its own.
#[tokio::test]
async fn a_cut_response_body_has_no_digest() {
    let kit = Kit::builder().rules(DIGEST_BOTH).start().await;
    let a = kit.h1().await.call("POST", "/cut", &[], b"abc").await;
    assert_eq!(a.status, 200, "{a:?}");
    assert!(a.body.is_err(), "{a:?}");
    let ev = kit.request_event().await;
    assert_eq!(ev["req"]["body_sha256"], sha256_hex(b"abc"), "{ev:#}");
    assert_eq!(ev["res"]["body_bytes"], 3, "{ev:#}");
    assert!(ev["res"].get("body_sha256").is_none(), "{ev:#}");
}

/// Bodies are hashed only on the sides a `digest` rule selects: none
/// without a rule (the byte counts stay), the request alone under
/// `digest: request`.
#[tokio::test]
async fn bodies_are_hashed_only_where_a_digest_rule_asks() {
    let kit = Kit::builder().start().await;
    let a = kit.h1().await.call("POST", "/echo", &[], b"abc").await;
    assert_eq!(a.status, 200, "{a:?}");
    let ev = kit.request_event().await;
    assert_eq!(ev["req"]["body_bytes"], 3, "{ev:#}");
    assert_eq!(ev["res"]["body_bytes"], 3, "{ev:#}");
    assert!(ev["req"].get("body_sha256").is_none(), "{ev:#}");
    assert!(ev["res"].get("body_sha256").is_none(), "{ev:#}");

    let kit = Kit::builder().rules(DIGEST_REQUEST).start().await;
    let a = kit.h1().await.call("POST", "/echo", &[], b"abc").await;
    assert_eq!(a.status, 200, "{a:?}");
    let ev = kit.request_event().await;
    assert_eq!(ev["req"]["body_sha256"], sha256_hex(b"abc"), "{ev:#}");
    assert_eq!(ev["res"]["body_bytes"], 3, "{ev:#}");
    assert!(ev["res"].get("body_sha256").is_none(), "{ev:#}");
}

/// The upstream gets body bytes while the client still holds the rest.
#[tokio::test]
async fn the_upstream_receives_the_body_before_the_client_finishes() {
    let kit = Kit::builder().start().await;
    let mut c = kit.h1().await;
    let (mut tx, body) = streaming_body();
    let req = c.request("POST", "/stream", &[]).body(body).unwrap();
    let pending = c.start(req);
    tx.send_data(Bytes::from(vec![1u8; 64 * 1024]))
        .await
        .unwrap();
    let first = kit.wait_arrived(1).await;
    assert_eq!(first[0].complete, None, "{:?}", first[0]);
    for _ in 0..4 {
        tx.send_data(Bytes::from(vec![2u8; 64 * 1024]))
            .await
            .unwrap();
    }
    tx.finish().await.unwrap();
    let a = pending.await.unwrap().unwrap();
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.json()["body_len"], 5 * 64 * 1024);
}

/// `limits.max_request_body_bytes` stops a chunked upload at the cap: a
/// `413`, the connection closed, and the upstream never gets more.
#[tokio::test]
async fn h1_request_body_cap_closes_mid_stream() {
    let kit = Kit::builder()
        .limits(|l| l.max_request_body_bytes = 1024)
        .start()
        .await;
    let mut io = kit.connect();
    io.write_all(
        b"POST http://up.test/cap HTTP/1.1\r\nhost: up.test\r\ntransfer-encoding: chunked\r\n\r\n",
    )
    .await
    .unwrap();
    for _ in 0..4 {
        let _ = io.write_all(b"400\r\n").await;
        let _ = io.write_all(&[b'z'; 1024]).await;
        let _ = io.write_all(b"\r\n").await;
    }
    let (out, eof) = super::read_to_eof(&mut io).await;
    assert!(eof);
    let out = String::from_utf8_lossy(&out);
    assert!(out.starts_with("HTTP/1.1 413"), "{out}");
    let ev = kit.events("parse_error", 1).await;
    assert_eq!(ev[0]["reason"], "body_too_large");
    assert!(kit.upstream.seen().iter().all(|s| s.body.len() <= 1024));
}

/// A chunked request for `target` with trailers, as the client sends it.
pub(super) fn trailered(target: &str) -> Vec<u8> {
    format!(
        "POST {target} HTTP/1.1\r\nhost: up.test\r\ntransfer-encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nx-checksum: abc\r\n\r\n"
    )
    .into_bytes()
}

/// An HTTP/1.1 client inside a `CONNECT up.test:443` tunnel.
pub(super) async fn h1_in_tunnel(
    kit: &Kit,
) -> tokio_rustls::client::TlsStream<tokio::io::DuplexStream> {
    let io = kit.connect_tunnel("up.test", 443).await;
    kit.tls_connect(io, "up.test", &[b"http/1.1"])
        .await
        .unwrap()
}

/// With `http.allow_request_trailers`, the trailers of a chunked request
/// reach an h2 upstream as trailers.
#[tokio::test]
async fn request_trailers_reach_an_h2_upstream() {
    let kit = Kit::builder()
        .flags(|f| f.allow_request_trailers = true)
        .start()
        .await;
    let mut io = h1_in_tunnel(&kit).await;
    io.write_all(&trailered("/t")).await.unwrap();
    let (head, _) = super::read_response(&mut io).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].version, http::Version::HTTP_2);
    assert_eq!(seen[0].body, b"abc");
    let trailers = seen[0]
        .trailers
        .as_ref()
        .unwrap_or_else(|| panic!("{:?}", seen[0]));
    assert_eq!(trailers["x-checksum"], "abc");
}

/// The same request towards an upstream that speaks HTTP/1.1: the client
/// gets a `400` with the `trailers` reason, and the upstream never sees the
/// body complete.
async fn trailers_refused<IO>(kit: &Kit, mut io: IO, target: &str)
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    io.write_all(&trailered(target)).await.unwrap();
    let (out, _) = super::read_to_eof(&mut io).await;
    let out = String::from_utf8_lossy(&out);
    assert!(out.starts_with("HTTP/1.1 400"), "{out}");
    let ev = kit.events("parse_error", 1).await;
    assert_eq!(ev[0]["reason"], "trailers", "{ev:#?}");
    kit.upstream.wait_open(0).await;
    let seen = kit.upstream.seen();
    assert!(seen.iter().all(|s| s.complete != Some(true)), "{seen:#?}");
}

#[tokio::test]
async fn request_trailers_to_an_h1_tls_upstream_are_refused() {
    let kit = Kit::builder()
        .flags(|f| f.allow_request_trailers = true)
        .start()
        .await;
    kit.upstream.h1_only();
    let io = h1_in_tunnel(&kit).await;
    trailers_refused(&kit, io, "/t").await;
}

/// A plaintext upstream is always HTTP/1.1.
#[tokio::test]
async fn request_trailers_to_a_plaintext_upstream_are_refused() {
    let kit = Kit::builder()
        .flags(|f| f.allow_request_trailers = true)
        .start()
        .await;
    trailers_refused(&kit, kit.connect(), "http://up.test/t").await;
}

/// One h2 exchange with `up.test`, read whole: the response head, body and
/// trailers. The request body and trailers go out as given.
pub(super) async fn h2_exchange(
    send: &h2::client::SendRequest<Bytes>,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    trailers: Option<http::HeaderMap>,
) -> Result<(http::response::Parts, Bytes, Option<http::HeaderMap>), h2::Error> {
    let mut b = http::Request::builder()
        .method(method)
        .uri(format!("https://up.test{path}"));
    for (n, v) in headers {
        b = b.header(*n, *v);
    }
    let req = b.body(()).unwrap();
    let mut ready = send.clone().ready().await?;
    let end = body.is_empty() && trailers.is_none();
    let (resp, mut stream) = ready.send_request(req, end)?;
    if !end {
        stream.send_data(Bytes::copy_from_slice(body), trailers.is_none())?;
        if let Some(t) = trailers {
            stream.send_trailers(t)?;
        }
    }
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
    let trailers = tokio::time::timeout(Duration::from_secs(10), body.trailers())
        .await
        .expect("timed out waiting for h2 trailers")?;
    Ok((parts, Bytes::from(out), trailers))
}

fn trailer(name: &'static str, value: &'static str) -> http::HeaderMap {
    let mut t = http::HeaderMap::new();
    t.insert(name, http::HeaderValue::from_static(value));
    t
}

/// A gRPC-shaped response (the call's outcome in `grpc-status`) reaches an
/// h2 client with its trailers under the default flags.
#[tokio::test]
async fn grpc_response_trailers_reach_an_h2_client_by_default() {
    let kit = Kit::builder().start().await;
    let (send, _conn) = super::h2_client(&kit).await;
    let (parts, body, trailers) = h2_exchange(&send, "POST", "/grpc", &[], b"req", None)
        .await
        .unwrap();
    assert_eq!(parts.status, 200);
    assert_eq!(parts.headers["content-type"], "application/grpc");
    assert!(!parts.headers.contains_key("content-length"));
    assert_eq!(body, "hello");
    let trailers = trailers.expect("the trailers are delivered");
    assert_eq!(trailers["grpc-status"], "0");
    assert_eq!(trailers["grpc-message"], "OK");
}

/// With `http.allow_response_trailers: false` the body ends after its
/// data and the client sees no trailers.
#[tokio::test]
async fn response_trailers_are_dropped_when_not_allowed() {
    let kit = Kit::builder()
        .flags(|f| f.allow_response_trailers = false)
        .start()
        .await;
    let (send, _conn) = super::h2_client(&kit).await;
    let (parts, body, trailers) = h2_exchange(&send, "GET", "/grpc", &[], b"", None)
        .await
        .unwrap();
    assert_eq!(parts.status, 200);
    assert_eq!(body, "hello");
    assert_eq!(trailers, None);
}

/// A response trailer section with a forbidden field (one that frames,
/// routes or authenticates the message) fails the body: the stream is
/// reset, so the client never sees the response complete.
#[tokio::test]
async fn a_forbidden_response_trailer_resets_the_stream() {
    let kit = Kit::builder().start().await;
    let (send, _conn) = super::h2_client(&kit).await;
    let err = h2_exchange(
        &send,
        "GET",
        "/grpc",
        &[("x-forbidden-trailer", "1")],
        b"",
        None,
    )
    .await
    .expect_err("the stream is reset before the trailers");
    assert!(err.is_reset(), "{err}");
    let ev = kit.events("response_error", 1).await;
    assert_eq!(ev[0]["reason"], "response_write_failed", "{ev:#?}");
}

/// On HTTP/1.1 the trailers of a chunked response go out as its trailer
/// section, under the default flags.
#[tokio::test]
async fn response_trailers_reach_an_h1_client_as_chunked_trailers() {
    let kit = Kit::builder().start().await;
    let mut io = h1_in_tunnel(&kit).await;
    io.write_all(b"GET /grpc HTTP/1.1\r\nhost: up.test\r\nconnection: close\r\n\r\n")
        .await
        .unwrap();
    let (out, _) = super::read_to_eof(&mut io).await;
    let out = String::from_utf8_lossy(&out);
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    assert!(out.contains("\r\ntransfer-encoding: chunked\r\n"), "{out}");
    assert!(
        out.ends_with("\r\n5\r\nhello\r\n0\r\ngrpc-status: 0\r\ngrpc-message: OK\r\n\r\n"),
        "{out}"
    );
}

/// An h2 request that carries trailers is reset under the default flags
/// (`parse_error`, reason `trailers`); the upstream never sees the body
/// complete.
#[tokio::test]
async fn h2_request_trailers_are_reset_by_default() {
    let kit = Kit::builder().start().await;
    let (send, _conn) = super::h2_client(&kit).await;
    let err = h2_exchange(
        &send,
        "POST",
        "/t",
        &[],
        b"abc",
        Some(trailer("x-checksum", "abc")),
    )
    .await
    .expect_err("the stream is reset");
    assert!(err.is_reset(), "{err}");
    let ev = kit.events("parse_error", 1).await;
    assert_eq!(ev[0]["reason"], "trailers", "{ev:#?}");
    let seen = kit.upstream.seen();
    assert!(seen.iter().all(|s| s.complete != Some(true)), "{seen:#?}");
}

/// Rules that read the body, so the exchange buffers it in both directions.
const BODY_RULES: &str = r#"
- id: no-secret-out
  when: host == "up.test" and body.text contains "SECRET"
  then: deny
- id: no-secret-in
  when: host == "up.test" and response.body.text contains "SECRET"
  then: deny
- id: up
  when: host == "up.test"
  then: allow
"#;

/// A response a rule buffers to read keeps its trailers: the h2 client
/// gets `grpc-status` after the body, and an h1 client gets the chunked
/// trailer section.
#[tokio::test]
async fn an_inspected_response_keeps_its_trailers() {
    let kit = Kit::builder().rules(BODY_RULES).start().await;
    let (send, _conn) = super::h2_client(&kit).await;
    let (parts, body, trailers) = h2_exchange(&send, "GET", "/grpc", &[], b"", None)
        .await
        .unwrap();
    assert_eq!(parts.status, 200);
    assert_eq!(body, "hello");
    let trailers = trailers.expect("the trailers are delivered");
    assert_eq!(trailers["grpc-status"], "0");

    let mut io = h1_in_tunnel(&kit).await;
    io.write_all(b"GET /grpc HTTP/1.1\r\nhost: up.test\r\nconnection: close\r\n\r\n")
        .await
        .unwrap();
    let (out, _) = super::read_to_eof(&mut io).await;
    let out = String::from_utf8_lossy(&out);
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    assert!(
        out.ends_with("\r\n5\r\nhello\r\n0\r\ngrpc-status: 0\r\ngrpc-message: OK\r\n\r\n"),
        "{out}"
    );
}

/// A request a rule buffers to read keeps its trailers on the way to the
/// h2 upstream.
#[tokio::test]
async fn an_inspected_request_keeps_its_trailers() {
    let kit = Kit::builder()
        .rules(BODY_RULES)
        .flags(|f| f.allow_request_trailers = true)
        .start()
        .await;
    let (send, _conn) = super::h2_client(&kit).await;
    let (parts, _, _) = h2_exchange(
        &send,
        "POST",
        "/t",
        &[],
        b"abc",
        Some(trailer("x-checksum", "abc")),
    )
    .await
    .unwrap();
    assert_eq!(parts.status, 200);
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].body, b"abc");
    let trailers = seen[0]
        .trailers
        .as_ref()
        .unwrap_or_else(|| panic!("{:?}", seen[0]));
    assert_eq!(trailers["x-checksum"], "abc");
}

/// With `http.allow_request_trailers`, the same request passes and its
/// trailers reach the h2 upstream.
#[tokio::test]
async fn h2_request_trailers_pass_when_allowed() {
    let kit = Kit::builder()
        .flags(|f| f.allow_request_trailers = true)
        .start()
        .await;
    let (send, _conn) = super::h2_client(&kit).await;
    let (parts, _, _) = h2_exchange(
        &send,
        "POST",
        "/t",
        &[],
        b"abc",
        Some(trailer("x-checksum", "abc")),
    )
    .await
    .unwrap();
    assert_eq!(parts.status, 200);
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].version, http::Version::HTTP_2);
    assert_eq!(seen[0].body, b"abc");
    let trailers = seen[0]
        .trailers
        .as_ref()
        .unwrap_or_else(|| panic!("{:?}", seen[0]));
    assert_eq!(trailers["x-checksum"], "abc");
}

/// An h2 upstream gets the authority as `:authority` alone: a `host`
/// header beside it is a duplicate that origins such as nginx reject with
/// `400`.
#[tokio::test]
async fn an_h2_upstream_gets_authority_without_a_host_header() {
    let kit = Kit::builder().start().await;
    let mut c = kit.tunnel("up.test", false).await;
    let a = c.call("GET", "/x", &[("x-a", "1")], b"").await;
    assert_eq!(a.status, 200, "{a:?}");
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].version, http::Version::HTTP_2);
    assert_eq!(seen[0].authority.as_deref(), Some("up.test"));
    assert!(
        !seen[0].headers.contains_key("host"),
        "{:?}",
        seen[0].headers
    );
    assert_eq!(seen[0].headers["x-a"], "1");
}

/// An HTTP/1.1 upstream, TLS or plaintext, gets the canonical authority as
/// `host`, with a non-default port kept.
#[tokio::test]
async fn an_h1_upstream_gets_the_host_header() {
    let kit = Kit::builder().start().await;
    kit.upstream.h1_only();
    let mut c = kit.tunnel("up.test", false).await;
    assert_eq!(c.call("GET", "/tls", &[], b"").await.status, 200);
    let mut c = kit.h1().await;
    assert_eq!(c.call("GET", "/plain", &[], b"").await.status, 200);
    let req = c
        .request_to("up.test:8080", "GET", "/port", &[])
        .body(roxy_http::Body::empty())
        .unwrap();
    assert_eq!(Answer::read(c.send(req).await.unwrap()).await.status, 200);
    let seen = kit.upstream.wait_seen(3).await;
    for (path, host) in [
        ("/tls", "up.test"),
        ("/plain", "up.test"),
        ("/port", "up.test:8080"),
    ] {
        let s = seen.iter().find(|s| s.path == path).unwrap();
        assert_eq!(s.version, http::Version::HTTP_11, "{path}");
        assert_eq!(s.headers["host"], host, "{path}");
    }
}

/// Over h2 the cap resets the stream, whether crossed while streaming or
/// declared up front; the connection stays usable.
#[tokio::test]
async fn h2_request_body_cap_resets_the_stream() {
    let kit = Kit::builder()
        .limits(|l| l.max_request_body_bytes = 1024)
        .start()
        .await;
    let (send, _conn) = super::h2_client(&kit).await;

    let req = http::Request::post("https://up.test/cap").body(()).unwrap();
    let mut ready = send.clone().ready().await.unwrap();
    let (resp, mut stream) = ready.send_request(req, false).unwrap();
    for _ in 0..4 {
        let _ = stream.send_data(Bytes::from(vec![b'z'; 1024]), false);
    }
    let _ = stream.send_data(Bytes::new(), true);
    let r = tokio::time::timeout(Duration::from_secs(10), resp)
        .await
        .unwrap();
    let e = r.expect_err("the stream must be reset");
    assert_eq!(e.reason(), Some(h2::Reason::PROTOCOL_ERROR), "{e}");
    let ev = kit.events("parse_error", 1).await;
    assert_eq!(ev[0]["reason"], "body_too_large");

    let req = http::Request::post("https://up.test/cap2")
        .header("content-length", "4096")
        .body(())
        .unwrap();
    let mut ready = send.clone().ready().await.unwrap();
    let (resp, _stream) = ready.send_request(req, false).unwrap();
    let r = tokio::time::timeout(Duration::from_secs(10), resp)
        .await
        .unwrap();
    assert_eq!(
        r.expect_err("reset").reason(),
        Some(h2::Reason::PROTOCOL_ERROR)
    );
    let ev = kit.events("parse_error", 2).await;
    assert_eq!(ev[1]["reason"], "body_too_large");
    let seen = kit.upstream.seen();
    assert!(seen.iter().all(|s| s.body.len() <= 1024), "{seen:#?}");
    assert!(seen.iter().all(|s| s.path != "/cap2"));

    let (parts, _) = super::h2_get(&send, "https://up.test/ok", &[])
        .await
        .unwrap();
    assert_eq!(parts.status, 200);
}

/// `response_header_timeout` starts once the request body has been sent:
/// an upload that takes longer than it to send is not cut short.
#[tokio::test]
async fn a_slow_upload_outlasts_the_response_header_timeout() {
    let kit = Kit::builder()
        .limits(|l| l.response_header_timeout = Duration::from_millis(200))
        .start()
        .await;
    let mut c = kit.h1().await;
    let (mut tx, body) = streaming_body();
    let req = c.request("POST", "/trickle", &[]).body(body).unwrap();
    let pending = c.start(req);
    for i in 0..5u8 {
        tokio::time::sleep(Duration::from_millis(120)).await;
        tx.send_data(Bytes::from(vec![i; 1000])).await.unwrap();
    }
    tx.finish().await.unwrap();
    let a = pending.await.unwrap().unwrap();
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.json()["body_len"], 5000);
}

// ---- h2 connections -------------------------------------------------------

/// An h2 connection owes its first stream within `header_timeout`, as an
/// h1 tunnel owes its first request head; between requests it may idle
/// for `idle_timeout`, which is the one that closes it.
#[tokio::test]
async fn h2_first_stream_must_arrive_within_header_timeout() {
    let kit = Kit::builder()
        .limits(|l| {
            l.header_timeout = Duration::from_millis(300);
            l.idle_timeout = Duration::from_millis(1000);
        })
        .start()
        .await;
    let (_send, conn) = super::h2_client(&kit).await;
    tokio::time::timeout(Duration::from_secs(5), conn)
        .await
        .expect("the connection closes without a first stream")
        .unwrap()
        .unwrap();

    let (send, conn) = super::h2_client(&kit).await;
    let (parts, _) = super::h2_get(&send, "https://up.test/first", &[])
        .await
        .unwrap();
    assert_eq!(parts.status, 200);
    tokio::time::sleep(Duration::from_millis(600)).await;
    let (parts, _) = super::h2_get(&send, "https://up.test/second", &[])
        .await
        .expect("a gap past header_timeout but within idle_timeout is fine");
    assert_eq!(parts.status, 200);
    tokio::time::timeout(Duration::from_secs(5), conn)
        .await
        .expect("the connection closes once idle for idle_timeout")
        .unwrap()
        .unwrap();
}

/// A response of `content-length: 0` that ends with trailers delivers them
/// on h2 under the default flags.
#[tokio::test]
async fn h2_response_trailers_follow_an_empty_body() {
    let kit = Kit::builder().start().await;
    let (send, _conn) = super::h2_client(&kit).await;
    let req = http::Request::get("https://up.test/trailers")
        .body(())
        .unwrap();
    let mut ready = send.clone().ready().await.unwrap();
    let (resp, _) = ready.send_request(req, true).unwrap();
    let resp = tokio::time::timeout(Duration::from_secs(10), resp)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["content-length"], "0");
    let mut body = resp.into_body();
    while let Some(chunk) = body.data().await {
        assert!(chunk.unwrap().is_empty());
    }
    let trailers = tokio::time::timeout(Duration::from_secs(10), body.trailers())
        .await
        .unwrap()
        .unwrap()
        .expect("the trailers are delivered");
    assert_eq!(trailers["x-checksum"], "none");
}

#[tokio::test]
async fn h2_streams_multiplex_on_one_connection() {
    let kit = Kit::builder().connection_events().start().await;
    let mut c = kit.tunnel("up.test", true).await;
    let pending: Vec<_> = (0..5)
        .map(|i| {
            let req = c
                .request("GET", &format!("/m/{i}"), &[])
                .body(roxy_http::Body::empty())
                .unwrap();
            c.start(req)
        })
        .collect();
    for (i, p) in pending.into_iter().enumerate() {
        let a = p.await.unwrap().unwrap();
        assert_eq!(a.status, 200, "{a:?}");
        assert_eq!(a.json()["path"], format!("/m/{i}"));
    }
    let ev = kit.events("request", 5).await;
    let conn = &ev[0]["conn"];
    assert!(ev.iter().all(|e| &e["conn"] == conn), "{ev:#?}");
    assert!(ev.iter().all(|e| e["tls"]["alpn"] == "h2"), "{ev:#?}");
    assert_eq!(kit.events("connect", 1).await.len(), 1);
}

/// A closing deny over h2 is answered on its stream, then the connection
/// goes away; a new stream on it fails.
#[tokio::test]
async fn h2_a_closing_deny_answers_on_the_stream_then_goes_away() {
    let kit = Kit::builder().rules("[]").start().await;
    let (send, conn) = super::h2_client(&kit).await;
    let (parts, body) = super::h2_get(&send, "https://up.test/y", &[])
        .await
        .unwrap();
    assert_eq!(parts.status, 403);
    assert_eq!(parts.headers["content-type"], "application/json");
    assert_eq!(parts.headers["x-roxy-rule"], "_default");
    let v = json(&body);
    assert_eq!(v["rule"], "_default");
    assert_eq!(v["error"], "blocked by roxy");
    let ended = tokio::time::timeout(Duration::from_secs(10), conn).await;
    assert!(ended.is_ok(), "the connection must close after a deny");
    let again = super::h2_get(&send, "https://up.test/z", &[]).await;
    assert!(again.is_err(), "a new stream after GOAWAY must fail");
    let ev = kit.events("request", 1).await;
    assert_eq!(ev.len(), 1, "{ev:#?}");
    assert!(kit.upstream.seen().is_empty());
}

#[tokio::test]
async fn h2_a_soft_deny_keeps_serving() {
    let kit = Kit::builder()
        .rules(SOFT_DENY)
        .connection_events()
        .start()
        .await;
    let mut c = kit.tunnel("up.test", true).await;
    let a = c.call("GET", "/soft", &[], b"").await;
    assert_eq!(a.status, 451, "{a:?}");
    assert_eq!(a.json()["error"], "not here");
    let a = c.call("GET", "/after", &[], b"").await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.json()["path"], "/after");
    assert_eq!(kit.events("connect", 1).await.len(), 1);
}

/// Malformed h2 streams are reset, not forwarded, and the connection keeps
/// serving well-formed ones.
#[tokio::test]
async fn h2_malformed_streams_are_reset() {
    use super::{H2_HEADERS, H2_RST_STREAM, h2_raw_request};
    let kit = Kit::builder().start().await;

    // A connection-specific field: RST_STREAM(PROTOCOL_ERROR). The `h2`
    // crate rejects it before roxy's mapper sees the stream.
    let frames = h2_raw_request(
        &kit,
        &[
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", "up.test"),
            (":path", "/conn"),
            ("connection", "keep-alive"),
        ],
    )
    .await;
    let rst = frames
        .iter()
        .find(|f| f.0 == H2_RST_STREAM && f.2 == 1)
        .unwrap_or_else(|| panic!("no RST_STREAM: {frames:?}"));
    assert_eq!(rst.3, 1u32.to_be_bytes(), "PROTOCOL_ERROR");
    assert!(!frames.iter().any(|f| f.0 == H2_HEADERS && f.2 == 1));

    // `:authority` other than the tunnel host: roxy's mapper resets it and
    // logs a parse error.
    let frames = h2_raw_request(
        &kit,
        &[
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", "evil.test"),
            (":path", "/evil"),
        ],
    )
    .await;
    let rst = frames
        .iter()
        .find(|f| f.0 == H2_RST_STREAM && f.2 == 1)
        .unwrap_or_else(|| panic!("no RST_STREAM: {frames:?}"));
    assert_eq!(rst.3, 1u32.to_be_bytes(), "PROTOCOL_ERROR");
    let ev = kit.events("parse_error", 1).await;
    assert_eq!(ev[0]["reason"], "authority_mismatch");

    // Same through the h2 client, plus a mismatching `host`.
    let (send, _conn) = super::h2_client(&kit).await;
    let e = super::h2_get(&send, "https://evil.test/x", &[])
        .await
        .unwrap_err();
    assert_eq!(e.reason(), Some(h2::Reason::PROTOCOL_ERROR));
    let e = super::h2_get(&send, "https://up.test/x", &[("host", "evil.test")])
        .await
        .unwrap_err();
    assert_eq!(e.reason(), Some(h2::Reason::PROTOCOL_ERROR));
    let ev = kit.events("parse_error", 3).await;
    assert_eq!(ev[1]["reason"], "authority_mismatch");
    assert_eq!(ev[2]["reason"], "host_mismatch");
    let (parts, _) = super::h2_get(&send, "https://up.test/fine", &[])
        .await
        .unwrap();
    assert_eq!(parts.status, 200);

    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen.len(), 1, "{seen:#?}");
    assert_eq!(seen[0].path, "/fine");
}

/// An h2 client ends a streamed body with an empty `END_STREAM` DATA frame.
/// roxy must not pass that on as an empty non-final DATA frame: h2 servers
/// count those as a flood and GOAWAY the pooled upstream connection after
/// about a hundred.
#[tokio::test]
async fn many_streamed_h2_uploads_share_one_upstream_connection() {
    let kit = Kit::builder().start().await;
    let mut c = kit.tunnel("up.test", true).await;
    for i in 0..150 {
        let (mut tx, body) = streaming_body();
        let req = c.request("POST", "/streamed", &[]).body(body).unwrap();
        let pending = c.start(req);
        for _ in 0..4 {
            tx.send_data(Bytes::from(vec![7u8; 1024])).await.unwrap();
        }
        tx.finish().await.unwrap();
        let a = pending.await.unwrap().unwrap();
        assert_eq!(a.status, 200, "request {i}: {a:?}");
        assert_eq!(a.json()["body_len"], 4096);
    }
    assert_eq!(kit.upstream.open_connections(), 1, "one pooled connection");
}

/// Exchanges in flight at the same time to one h2 origin spread over
/// upstream connections up to `max_h2_connections_per_origin`; at 1 they
/// share the one connection.
#[tokio::test]
async fn concurrent_h2_exchanges_use_up_to_the_connection_limit() {
    for (limit, connections) in [(4, 2), (1, 1)] {
        let kit = Kit::builder()
            .upstream(move |s| s.max_h2_connections_per_origin = limit)
            .start()
            .await;
        let mut c = kit.tunnel("up.test", true).await;
        let mut pending = Vec::new();
        let mut senders = Vec::new();
        for i in 0..2 {
            let (tx, body) = streaming_body();
            let req = c.request("POST", &format!("/{i}"), &[]).body(body).unwrap();
            pending.push(c.start(req));
            senders.push(tx);
            kit.upstream.wait_arrived(i + 1).await;
        }
        assert_eq!(
            kit.upstream.open_connections(),
            connections,
            "limit {limit}"
        );
        for tx in senders {
            tx.finish().await.unwrap();
        }
        for p in pending {
            let a = p.await.unwrap().unwrap();
            assert_eq!(a.status, 200, "limit {limit}: {a:?}");
        }
    }
}

// ---- audit backpressure ---------------------------------------------------

/// A flow log that cannot keep up holds traffic back instead of dropping
/// records: a new exchange waits until the sink is ready again.
#[tokio::test]
async fn a_stalled_flow_log_holds_traffic() {
    let gate = Arc::new(LogGate::default());
    let kit = Kit::builder().log_gate(gate.clone()).start().await;
    let mut c = kit.h1().await;
    let a = c.call("GET", "/before", &[], b"").await;
    assert_eq!(a.status, 200, "{a:?}");
    gate.set_closed(true);
    let req = c
        .request("GET", "/held", &[])
        .body(roxy_http::Body::empty())
        .unwrap();
    let pending = c.start(req);
    gate.wait_held().await;
    assert!(
        !pending.is_finished(),
        "traffic moved while the log was behind"
    );
    assert!(kit.upstream.seen().iter().all(|s| s.path != "/held"));
    gate.set_closed(false);
    let a = tokio::time::timeout(Duration::from_secs(10), pending)
        .await
        .expect("traffic resumes once the log catches up")
        .unwrap()
        .unwrap();
    assert_eq!(a.status, 200, "{a:?}");
}

// ---- h2 streams and the connection -----------------------------------------

const UPLOAD_CAP_OPEN: &str = r#"
- id: upload-cap
  when: body.bytes > 10kb
  then: { deny: { status: 413, message: "upload too large", close: false } }
- id: up
  when: host == "up.test"
  then: allow
"#;

/// A client waiting on `Expect: 100-continue` over h2 gets the `100`
/// before it sends the body, and the body then reaches the upstream.
#[tokio::test]
async fn h2_expect_100_continue_is_answered_then_the_body_forwarded() {
    let kit = Kit::builder().start().await;
    let (send, _conn) = super::h2_client(&kit).await;
    let req = http::Request::builder()
        .method("POST")
        .uri("https://up.test/upload")
        .header("expect", "100-continue")
        .body(())
        .unwrap();
    let mut ready = send.clone().ready().await.unwrap();
    let (mut resp, mut stream) = ready.send_request(req, false).unwrap();
    let info = std::future::poll_fn(|cx| resp.poll_informational(cx))
        .await
        .expect("an informational response")
        .unwrap();
    assert_eq!(info.status(), 100);
    stream
        .send_data(Bytes::from_static(b"hello"), true)
        .unwrap();
    let res = resp.await.unwrap();
    assert_eq!(res.status(), 200);
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].body, b"hello");
    assert!(
        !seen[0].headers.contains_key("expect"),
        "{:?}",
        seen[0].headers
    );
}

/// A client that resets its stream after the `100` went away: the flow is
/// logged as `client_gone`, not as a parse error, and the connection keeps
/// serving.
#[tokio::test]
async fn h2_a_reset_after_the_100_is_the_client_going_away() {
    let kit = Kit::builder().start().await;
    let (send, _conn) = super::h2_client(&kit).await;
    let req = http::Request::builder()
        .method("POST")
        .uri("https://up.test/upload")
        .header("expect", "100-continue")
        .body(())
        .unwrap();
    let mut ready = send.clone().ready().await.unwrap();
    let (mut resp, mut stream) = ready.send_request(req, false).unwrap();
    let info = std::future::poll_fn(|cx| resp.poll_informational(cx))
        .await
        .expect("an informational response")
        .unwrap();
    assert_eq!(info.status(), 100);
    stream.send_reset(h2::Reason::CANCEL);
    drop(resp);
    let ev = kit.request_event().await;
    assert_eq!(ev["reason"], "client_gone", "{ev:#}");
    assert!(ev["res"].is_null(), "{ev:#}");
    let (parts, _) = super::h2_get(&send, "https://up.test/next", &[])
        .await
        .unwrap();
    assert_eq!(parts.status, 200);
    let events = kit.sink.events();
    assert!(
        events.iter().all(|e| e["event"] != "parse_error"),
        "{events:#?}"
    );
}

/// A deny with `close: false` that stops an upload mid-body answers on the
/// stream and ends it; the connection then serves the next stream.
#[tokio::test]
async fn h2_a_soft_deny_mid_upload_ends_the_stream_not_the_connection() {
    let kit = Kit::builder()
        .rules(UPLOAD_CAP_OPEN)
        .connection_events()
        .start()
        .await;
    let mut c = kit.tunnel("up.test", true).await;
    let (mut tx, body) = streaming_body();
    let req = c.request("POST", "/upload", &[]).body(body).unwrap();
    let pending = c.start(req);
    let chunk = Bytes::from(vec![b'x'; 4096]);
    for _ in 0..3 {
        tx.send_data(chunk.clone()).await.unwrap();
    }
    let a = pending.await.unwrap().unwrap();
    assert_eq!(a.status, 413, "{a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "upload-cap");
    // The stream is over: the rest of the upload has nowhere to go.
    let mut refused = false;
    for _ in 0..64 {
        if tx.send_data(chunk.clone()).await.is_err() {
            refused = true;
            break;
        }
    }
    assert!(refused, "the denied stream must not keep taking data");
    let b = c.call("GET", "/next", &[], b"").await;
    assert_eq!(b.status, 200, "{b:?}");
    assert_eq!(b.json()["path"], "/next");
    let ev = kit.events("request", 2).await;
    assert_eq!(ev[0]["stage"], "request_body", "{ev:#?}");
    assert_eq!(kit.events("connect", 1).await.len(), 1);
}

/// A closing deny starts the connection's GOAWAY, but a stream already
/// mid-upload is not cut: it finishes, within the close grace, and the
/// connection ends once it has.
#[tokio::test]
async fn h2_a_closing_deny_lets_a_stream_mid_upload_finish() {
    let rules = r#"
- id: denied
  when: host == "up.test" and path == "/denied"
  then: deny
- id: up
  when: host == "up.test"
  then: allow
"#;
    let kit = Kit::builder().rules(rules).start().await;
    let mut c = kit.tunnel("up.test", true).await;
    let (mut tx, body) = streaming_body();
    let req = c.request("POST", "/upload", &[]).body(body).unwrap();
    let pending = c.start(req);
    tx.send_data(Bytes::from_static(b"first ")).await.unwrap();
    kit.wait_arrived(1).await;

    let d = c.call("GET", "/denied", &[], b"").await;
    assert_eq!(d.status, 403, "{d:?}");

    tx.send_data(Bytes::from_static(b"second")).await.unwrap();
    tx.finish().await.unwrap();
    let a = pending.await.unwrap().unwrap();
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.json()["body_len"], 12);
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].body, b"first second");
    assert_eq!(seen[0].complete, Some(true));

    let closed = tokio::time::timeout(crate::h2conn::CLOSE_GRACE, c.closed()).await;
    assert!(
        closed.is_ok(),
        "the connection ends once the upload is done"
    );
    let ev = kit.events("request", 2).await;
    assert!(ev.iter().all(|e| e["reason"].is_null()), "{ev:#?}");
}

// ---- CONNECT and SNI ---------------------------------------------------------

/// The CONNECT host and the SNI are compared as names: case and a trailing
/// dot do not make them differ, the warm-up and the handshake share one
/// leaf under that name, and the request's `Host` is held to the
/// normalised CONNECT host.
#[tokio::test]
async fn a_tunnel_host_is_normalised_before_the_sni_check() {
    let kit = Kit::builder().start().await;
    let io = kit.connect_tunnel("UP.TEST.", 443).await;
    let mut tls = kit
        .tls_connect(io, "up.test", &[b"http/1.1"])
        .await
        .expect("the SNI names the CONNECT host");
    assert_eq!(kit.minter.cached(), 1);
    tls.write_all(b"GET /n HTTP/1.1\r\nhost: up.test\r\n\r\n")
        .await
        .unwrap();
    let (head, _) = read_response(&mut tls).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let ev = kit.request_event().await;
    assert_eq!(ev["req"]["host"], "up.test", "{ev:#}");
    assert_eq!(ev["tls"]["sni"], "up.test", "{ev:#}");
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].path, "/n");
}

/// An SNI with a trailing dot names the same host as the CONNECT: the
/// handshake completes and the flow records the canonical name.
#[tokio::test]
async fn a_trailing_dot_sni_is_compared_canonically() {
    let kit = Kit::builder().start().await;
    let io = kit.connect_tunnel("up.test", 443).await;
    let mut cfg = kit.client_tls();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let name = rustls::pki_types::ServerName::try_from("up.test.").unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(std::sync::Arc::new(cfg))
        .connect(name, io)
        .await
        .expect("the SNI names the CONNECT host");
    tls.write_all(b"GET /dot HTTP/1.1\r\nhost: up.test\r\n\r\n")
        .await
        .unwrap();
    let (head, _) = read_response(&mut tls).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let ev = kit.request_event().await;
    assert_eq!(ev["tls"]["sni"], "up.test", "{ev:#}");
}

/// With `require_sni_match: false` a foreign SNI completes the handshake
/// with a leaf for that SNI, but the requests inside are still the CONNECT
/// host's: a `Host` naming the SNI is a mismatch.
#[tokio::test]
async fn a_foreign_sni_gets_its_leaf_but_host_stays_the_connect_host() {
    let kit = Kit::builder()
        .http(|h| h.require_sni_match = false)
        .start()
        .await;
    let io = kit.connect_tunnel("up.test", 443).await;
    // rustls checks the leaf against the SNI, so a completed handshake is a
    // leaf minted for `other.test`.
    let mut tls = kit
        .tls_connect(io, "other.test", &[b"http/1.1"])
        .await
        .expect("a foreign SNI is allowed");
    tls.write_all(b"GET /a HTTP/1.1\r\nhost: other.test\r\n\r\n")
        .await
        .unwrap();
    let (head, _) = read_response(&mut tls).await;
    assert!(head.starts_with("HTTP/1.1 400"), "{head}");
    let ev = kit.events("parse_error", 1).await;
    assert_eq!(ev[0]["reason"], "host_mismatch", "{ev:#?}");
    assert!(kit.upstream.seen().is_empty());

    let io = kit.connect_tunnel("up.test", 443).await;
    let mut tls = kit
        .tls_connect(io, "other.test", &[b"http/1.1"])
        .await
        .unwrap();
    tls.write_all(b"GET /b HTTP/1.1\r\nhost: up.test\r\n\r\n")
        .await
        .unwrap();
    let (head, _) = read_response(&mut tls).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let ev = kit.request_event().await;
    assert_eq!(ev["req"]["host"], "up.test", "{ev:#}");
    assert_eq!(ev["tls"]["sni"], "other.test", "{ev:#}");
}
