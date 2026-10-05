//! The wire the client sees: refusals on h1 and h2 connections, request
//! framing, body caps, h2 streams, and what the flow log holds back.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::AsyncWriteExt as _;

use super::{Answer, Kit, LogGate, read_response, streaming_body};

const SOFT_DENY: &str = r#"
- id: soft
  when: host == "up.test" and path == "/soft"
  then: { deny: { status: 451, message: "not here", close: false } }
- id: up
  when: host == "up.test"
  then: allow
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
