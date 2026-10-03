//! End-to-end tests of `roxy run`: a real server from a YAML config, a local
//! TLS upstream signed by a test CA, and real clients.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use roxy_proxy::{MetricSource, MetricSourceError, Sample};
use roxy_rules::FlowView;

use bytes::Bytes;
use futures_util::{SinkExt as _, StreamExt as _};
use serde_json::Value;
use support::{
    H2_HEADERS, H2_RST_STREAM, Harness, LogGate, Opts, SECRET, capture_body, capture_of, fnv,
    h2_get, h2_raw_request, raw, read_head, read_response, read_to_eof,
};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;

const ALLOW_UPSTREAM: &str = r#"
  - id: upstream
    when: host == "upstream.test"
    then: { allow: { private_ok: true } }
"#;

fn json(b: &[u8]) -> Value {
    serde_json::from_slice(b).unwrap_or_else(|e| {
        panic!("not JSON ({e}): {}", String::from_utf8_lossy(b));
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn allow_get_end_to_end() {
    let h = Harness::start(ALLOW_UPSTREAM).await;
    let res = h
        .client()
        .get(h.https_url("/hello?x=1"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let v = json(&res.bytes().await.unwrap());
    assert_eq!(v["path"], "/hello?x=1");
    assert_eq!(v["method"], "GET");
    let ev = h.wait_events("request", 1).await;
    assert_eq!(ev.len(), 1, "{ev:#?}");
    let e = &ev[0];
    assert_eq!(e["decision"], "allow");
    assert_eq!(e["rules"], serde_json::json!(["upstream"]));
    assert_eq!(e["terminal_rule"], "upstream");
    assert_eq!(e["res"]["status"], 200);
    assert_eq!(e["tls"]["sni"], "upstream.test");
    assert_eq!(e["req"]["query"], "x=[REDACTED]");
    assert!(e["res"]["body_bytes"].as_u64().unwrap() > 0);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn default_deny_answers_json_and_closes() {
    let h = Harness::start("").await;
    let res = h.client().get(h.https_url("/x")).send().await.unwrap();
    assert_eq!(res.status(), 403);
    assert_eq!(res.headers()["x-roxy-rule"], "_default");
    let v = json(&res.bytes().await.unwrap());
    assert_eq!(v["rule"], "_default");
    assert_eq!(v["error"], "blocked by roxy");
    assert_eq!(v["flow"].as_str().unwrap().len(), 26);

    // Plain HTTP on the proxy port: the deny closes the connection.
    let port = h.upstream.http.port();
    let (out, eof) = raw(
        h.proxy,
        format!("GET http://upstream.test:{port}/x HTTP/1.1\r\nHost: upstream.test:{port}\r\n\r\n")
            .as_bytes(),
    )
    .await;
    assert!(eof, "connection must close after a deny");
    assert!(out.starts_with("HTTP/1.1 403"), "{out}");
    assert!(out.contains("connection: close"), "{out}");
    assert!(out.contains("x-roxy-rule: _default"), "{out}");
    assert!(h.upstream.seen().is_empty());
    let ev = h.wait_events("request", 2).await;
    assert!(ev.iter().all(|e| e["decision"] == "deny"));
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn deny_without_close_keeps_the_connection() {
    let h = Harness::start(&format!(
        r#"
  - id: soft
    when: path == "/soft"
    then: {{ deny: {{ status: 451, message: "not here", close: false }} }}
{ALLOW_UPSTREAM}"#
    ))
    .await;
    let port = h.upstream.http.port();
    let mut s = TcpStream::connect(h.proxy).await.unwrap();
    let req = |p: &str| {
        format!("GET http://upstream.test:{port}{p} HTTP/1.1\r\nHost: upstream.test:{port}\r\n\r\n")
    };
    s.write_all(req("/soft").as_bytes()).await.unwrap();
    let (head, body) = read_response(&mut s).await;
    assert!(head.starts_with("HTTP/1.1 451"), "{head}");
    assert!(!head.contains("connection: close"), "{head}");
    assert_eq!(json(&body)["error"], "not here");
    s.write_all(req("/after").as_bytes()).await.unwrap();
    let (head, body) = read_response(&mut s).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(json(&body)["path"], "/after");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn set_header_injects_secret_without_logging_it() {
    let h = Harness::start(
        r#"
  - id: inject
    when: host == "upstream.test"
    then:
      - set_header: { authorization: "Bearer ${secret:token}", x-extra: "yes" }
      - remove_header: [x-remove-me]
      - log: { level: info, message: "injected" }
      - allow: { private_ok: true }
"#,
    )
    .await;
    let res = h
        .client()
        .get(h.https_url("/inject"))
        .header("authorization", "Bearer placeholder")
        .header("x-remove-me", "1")
        .header("x-keep-me", "2")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let v = json(&res.bytes().await.unwrap());
    assert_eq!(v["headers"]["authorization"], format!("Bearer {SECRET}"));
    assert_eq!(v["headers"]["x-extra"], "yes");
    assert_eq!(v["headers"]["x-keep-me"], "2");
    assert!(v["headers"].get("x-remove-me").is_none());
    let ev = h.wait_events("request", 1).await;
    let muts = ev[0]["mutations"].as_array().unwrap();
    assert!(muts.contains(&Value::from("set_header:authorization")));
    assert!(muts.contains(&Value::from("remove_header:x-remove-me")));
    assert_eq!(h.events("log").len(), 1);
    let all = serde_json::to_string(&h.sink.events()).unwrap();
    assert!(!all.contains(SECRET), "secret leaked into the flow log");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn rewrite_path_and_query_effects() {
    let h = Harness::start(
        r#"
  - id: rw
    when: host == "upstream.test" and path starts_with "/old/"
    then:
      - rewrite_path: { match: "/old/(.*)", to: "/new/$1" }
      - set_query: { k: "v w" }
      - remove_query: [drop]
      - allow: { private_ok: true }
"#,
    )
    .await;
    let res = h
        .client()
        .get(h.https_url("/old/thing?drop=1&keep=2"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let v = json(&res.bytes().await.unwrap());
    assert_eq!(v["path"], "/new/thing?keep=2&k=v%20w");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn redirect_changes_target_and_checks_the_new_address() {
    let h = Harness::start(
        r#"
  - id: alias-rewrite
    when: host == "alias.test"
    then:
      - redirect: { host: upstream.test, port: {HTTP}, rewrite_host: true }
      - allow: { private_ok: true }
  - id: alias-keep
    when: host == "keep.test"
    then:
      - redirect: { host: upstream.test, port: {HTTP} }
      - allow: { private_ok: true }
  - id: alias-private
    when: host == "evil.test"
    then:
      - redirect: { host: upstream.test, port: {HTTP} }
      - allow
"#,
    )
    .await;
    let port = h.upstream.http.port();
    let c = h.client();
    let res = c.get("http://alias.test:1234/a").send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(
        json(&res.bytes().await.unwrap())["host"],
        format!("upstream.test:{port}")
    );
    let res = c.get("http://keep.test:1234/b").send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(json(&res.bytes().await.unwrap())["host"], "keep.test:1234");
    // The redirect target's address goes through the address floor: a
    // private address without `private_ok` is refused.
    let res = c.get("http://evil.test:1234/c").send().await.unwrap();
    assert_eq!(res.status(), 403);
    assert_eq!(res.headers()["x-roxy-rule"], "_address_policy");
    assert_eq!(h.upstream.seen().len(), 2);
    h.stop().await;
}

/// The upstream echo answers only after reading the whole body, and
/// `response_header_timeout` currently runs while the request body is
/// still being sent, so the harness's 2s default can 504 a 32 MiB debug-build
/// upload on a slow runner. These tests check streaming integrity, not that
/// timeout.
const BIG_UPLOAD_LIMITS: &str = "response_header_timeout: 60s";

#[tokio::test(flavor = "multi_thread")]
async fn large_uploads_stream_intact() {
    let h = Harness::start_with(Opts {
        rules: ALLOW_UPSTREAM,
        limits: BIG_UPLOAD_LIMITS,
        ..Opts::default()
    })
    .await;
    let c = h.client();
    // 32 MiB with content-length.
    let data: Vec<u8> = (0..32 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
    let want = fnv(&data);
    let res = c
        .post(h.https_url("/upload"))
        .body(data)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let v = json(&res.bytes().await.unwrap());
    assert_eq!(v["body_len"], 32 * 1024 * 1024);
    assert_eq!(v["body_hash"], want);

    // 8 MiB chunked (no content-length).
    let chunk: Vec<u8> = (0..64 * 1024u32).map(|i| (i % 13) as u8).collect();
    let mut all = Vec::new();
    for _ in 0..128 {
        all.extend_from_slice(&chunk);
    }
    let want = fnv(&all);
    let chunks: Vec<Result<Bytes, std::io::Error>> =
        (0..128).map(|_| Ok(Bytes::from(chunk.clone()))).collect();
    let res = c
        .post(h.https_url("/upload-chunked"))
        .body(reqwest::Body::wrap_stream(futures_util::stream::iter(
            chunks,
        )))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let v = json(&res.bytes().await.unwrap());
    assert_eq!(v["body_len"], 8 * 1024 * 1024);
    assert_eq!(v["body_hash"], want);
    let seen = h.upstream.seen();
    assert!(seen[1].header("content-length").is_none());
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_receives_before_client_finishes() {
    let h = Harness::start(ALLOW_UPSTREAM).await;
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(4);
    let stream =
        futures_util::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|x| (x, rx)) });
    let c = h.client();
    let url = h.https_url("/stream-probe");
    let req = tokio::spawn(async move {
        c.post(url)
            .body(reqwest::Body::wrap_stream(stream))
            .send()
            .await
            .unwrap()
    });
    tx.send(Ok(Bytes::from(vec![1u8; 64 * 1024])))
        .await
        .unwrap();
    // The upstream sees bytes while the client still holds the rest.
    tokio::time::timeout(Duration::from_secs(10), h.upstream.state.probe.notified())
        .await
        .expect("upstream did not receive the first chunk before the upload finished");
    for _ in 0..4 {
        tx.send(Ok(Bytes::from(vec![2u8; 64 * 1024])))
            .await
            .unwrap();
    }
    drop(tx);
    let res = req.await.unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(json(&res.bytes().await.unwrap())["body_len"], 5 * 64 * 1024);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn expect_100_continue() {
    let h = Harness::start(ALLOW_UPSTREAM).await;
    let port = h.upstream.http.port();
    let mut s = TcpStream::connect(h.proxy).await.unwrap();
    s.write_all(
        format!(
            "POST http://upstream.test:{port}/e HTTP/1.1\r\nHost: upstream.test:{port}\r\n\
             Content-Length: 5\r\nExpect: 100-continue\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let head = read_head(&mut s).await;
    assert!(head.starts_with("HTTP/1.1 100"), "{head}");
    s.write_all(b"hello").await.unwrap();
    let (head, body) = read_response(&mut s).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(json(&body)["body_len"], 5);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn keep_alive_and_pipelining() {
    let h = Harness::start(ALLOW_UPSTREAM).await;
    let port = h.upstream.http.port();
    let req = |p: &str| {
        format!("GET http://upstream.test:{port}{p} HTTP/1.1\r\nHost: upstream.test:{port}\r\n\r\n")
    };
    let mut s = TcpStream::connect(h.proxy).await.unwrap();
    for i in 0..5 {
        s.write_all(req(&format!("/seq/{i}")).as_bytes())
            .await
            .unwrap();
        let (head, body) = read_response(&mut s).await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert_eq!(json(&body)["path"], format!("/seq/{i}"));
    }
    // Two requests in one write: the second is preserved.
    s.write_all(format!("{}{}", req("/p1"), req("/p2")).as_bytes())
        .await
        .unwrap();
    let (_, b1) = read_response(&mut s).await;
    let (_, b2) = read_response(&mut s).await;
    assert_eq!(json(&b1)["path"], "/p1");
    assert_eq!(json(&b2)["path"], "/p2");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
/// There are no connect-time rules (§4.3): a CONNECT is accepted for
/// inspection and the request inside it is decided.
async fn connect_is_accepted_and_the_request_inside_decided() {
    let h = Harness::start(&format!(
        r#"{ALLOW_UPSTREAM}
  - id: no-admin
    when: host == "upstream.test" and path starts_with "/admin"
    then: deny
"#
    ))
    .await;
    let port = h.upstream.https.port();
    let mut s = h.connect_tunnel(&format!("upstream.test:{port}")).await;
    s.shutdown().await.ok();
    let res = h
        .client()
        .get(h.https_url("/admin/x"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
    assert_eq!(res.headers()["x-roxy-rule"], "no-admin");
    let ev = h.wait_events("request", 1).await;
    assert_eq!(ev[0]["stage"], "head");
    assert_eq!(ev[0]["terminal_rule"], "no-admin");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_then_garbage_closes() {
    let h = Harness::start(ALLOW_UPSTREAM).await;
    let mut s = h
        .connect_tunnel(&format!("upstream.test:{}", h.upstream.https.port()))
        .await;
    s.write_all(b"\x00\x01\x02 not tls, not http\r\n\r\n")
        .await
        .unwrap();
    let (out, eof) = read_to_eof(&mut s).await;
    assert!(eof);
    assert!(out.is_empty(), "nothing may follow the 200: {out:?}");
    let ev = h.wait_events("parse_error", 1).await;
    assert_eq!(ev[0]["reason"], "non_http_in_connect");
    assert!(h.upstream.seen().is_empty());
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_with_mismatched_sni_closes() {
    let h = Harness::start(ALLOW_UPSTREAM).await;
    let r = h
        .tls_tunnel(
            &format!("upstream.test:{}", h.upstream.https.port()),
            "other.test",
        )
        .await;
    assert!(r.is_err(), "TLS must not complete with a mismatched SNI");
    let ev = h.wait_events("parse_error", 1).await;
    assert_eq!(ev[0]["reason"], "sni_mismatch");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_plaintext_refused_by_default() {
    let h = Harness::start(ALLOW_UPSTREAM).await;
    let port = h.upstream.http.port();
    let mut s = h.connect_tunnel(&format!("upstream.test:{port}")).await;
    s.write_all(format!("GET /x HTTP/1.1\r\nHost: upstream.test:{port}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let (out, eof) = read_to_eof(&mut s).await;
    assert!(eof);
    assert!(out.is_empty(), "{out:?}");
    let ev = h.wait_events("parse_error", 1).await;
    assert_eq!(ev[0]["reason"], "non_http_in_connect");
    assert!(h.upstream.seen().is_empty());
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn private_upstreams_need_private_ok() {
    let h = Harness::start(
        "
  - id: no-private-ok
    when: port == {HTTP}
    then: allow
",
    )
    .await;
    let port = h.upstream.http.port();
    let c = h.client();
    for url in [
        format!("http://upstream.test:{port}/"),
        format!("http://127.0.0.1:{port}/"),
        format!("http://[::ffff:127.0.0.1]:{port}/"),
    ] {
        let res = c.get(&url).send().await.unwrap();
        assert_eq!(res.status(), 403, "{url}");
        assert_eq!(res.headers()["x-roxy-rule"], "_address_policy", "{url}");
    }
    let ev = h.wait_events("upstream_denied", 3).await;
    assert_eq!(ev[0]["reason"], "private_range:loopback");
    assert_eq!(ev[2]["resolved_ip"], "127.0.0.1");
    assert!(h.upstream.seen().is_empty());
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_down_is_502() {
    let h = Harness::start(
        r#"
  - id: down
    when: host == "down.test"
    then: { allow: { private_ok: true } }
"#,
    )
    .await;
    let res = h
        .client()
        .get(format!("http://down.test:{}/", h.upstream.down))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 502);
    let ev = h.wait_events("upstream_error", 1).await;
    assert_eq!(ev[0]["reason"], "connect_failed");
    let req = h.wait_events("request", 1).await;
    assert_eq!(req[0]["reason"], "connect_failed");
    assert_eq!(req[0]["res"]["status"], 502);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn slow_upstream_headers_are_504() {
    let h = Harness::start(ALLOW_UPSTREAM).await;
    let t = Instant::now();
    let res = h
        .client()
        .get(h.https_url("/slow-headers"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 504);
    assert!(
        t.elapsed() < Duration::from_millis(3900),
        "{:?}",
        t.elapsed()
    );
    let ev = h.wait_events("upstream_error", 1).await;
    assert_eq!(ev[0]["reason"], "timeout");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn parse_errors_close_with_400() {
    let h = Harness::start(ALLOW_UPSTREAM).await;
    let port = h.upstream.http.port();
    let (out, eof) = raw(
        h.proxy,
        format!("GET http://upstream.test:{port}/ HTTP/1.1\nHost: upstream.test:{port}\n\n")
            .as_bytes(),
    )
    .await;
    assert!(eof);
    assert!(out.starts_with("HTTP/1.1 400"), "{out}");
    let (out, eof) = raw(
        h.proxy,
        format!(
            "POST http://upstream.test:{port}/ HTTP/1.1\r\nHost: upstream.test:{port}\r\n\
             Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        )
        .as_bytes(),
    )
    .await;
    assert!(eof);
    assert!(out.starts_with("HTTP/1.1 400"), "{out}");
    let ev = h.wait_events("parse_error", 2).await;
    let reasons: Vec<&str> = ev.iter().map(|e| e["reason"].as_str().unwrap()).collect();
    assert_eq!(reasons, ["bare_lf", "cl_and_te"]);
    assert!(h.upstream.seen().is_empty());
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn body_inspection_denies_and_fails_closed_when_too_large() {
    let h = Harness::start(&format!(
        r#"
  - id: no-forbidden-body
    when: host == "upstream.test" and body.text contains "forbidden-word"
    then: deny
{ALLOW_UPSTREAM}"#
    ))
    .await;
    let c = h.client();
    let res = c
        .post(h.https_url("/b"))
        .body("this has a forbidden-word in it")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
    assert_eq!(res.headers()["x-roxy-rule"], "no-forbidden-body");
    let res = c
        .post(h.https_url("/b"))
        .body("perfectly fine")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(json(&res.bytes().await.unwrap())["body_len"], 14);
    // Over `max_inspect_body_bytes` (1 KiB): fails closed.
    let res = c
        .post(h.https_url("/b"))
        .body(vec![b'a'; 4096])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 503);
    assert_eq!(res.headers()["x-roxy-rule"], "_fail_closed");
    // Streams of one h2 connection log independently: find the event by
    // its outcome rather than by position.
    let ev = h.wait_events("request", 3).await;
    let failed = ev
        .iter()
        .find(|e| e["res"]["status"] == 503)
        .unwrap_or_else(|| panic!("{ev:#?}"));
    assert_eq!(failed["reason"], "body_too_large_to_inspect");
    assert_eq!(h.events("policy_input_unavailable").len(), 1);
    assert_eq!(h.upstream.seen().len(), 1);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn response_rule_replaces_upstream_5xx() {
    let h = Harness::start(&format!(
        r#"{ALLOW_UPSTREAM}
  - id: hide-5xx
    when: response.status >= 500
    then: {{ deny: {{ status: 502, message: "upstream failure hidden" }} }}
"#
    ))
    .await;
    let res = h
        .client()
        .get(h.https_url("/status/500"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 502);
    assert_eq!(res.headers()["x-roxy-rule"], "hide-5xx");
    let body = res.bytes().await.unwrap();
    assert!(!String::from_utf8_lossy(&body).contains("exploded"));
    assert_eq!(json(&body)["error"], "upstream failure hidden");
    let ev = h.wait_events("request", 1).await;
    assert_eq!(ev[0]["decision"], "deny");
    assert_eq!(ev[0]["stage"], "response_head");
    assert_eq!(ev[0]["terminal_rule"], "hide-5xx");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn websocket_relay_echo() {
    let h = Harness::start(
        r#"
  - id: ws
    when: host == "ws.test"
    then: { allow: { upgrade: websocket, private_ok: true } }
"#,
    )
    .await;
    let port = h.upstream.ws.port();
    let tls = h
        .tls_tunnel(&format!("ws.test:{port}"), "ws.test")
        .await
        .unwrap();
    let (mut ws, resp) = tokio_tungstenite::client_async(format!("wss://ws.test:{port}/echo"), tls)
        .await
        .unwrap();
    assert_eq!(resp.status(), 101);
    ws.send(Message::text("hello through roxy")).await.unwrap();
    let back = ws.next().await.unwrap().unwrap();
    assert_eq!(back.into_text().unwrap().as_str(), "hello through roxy");
    ws.send(Message::binary(vec![7u8; 100_000])).await.unwrap();
    let back = ws.next().await.unwrap().unwrap();
    assert_eq!(back.into_data().len(), 100_000);
    ws.close(None).await.unwrap();
    drop(ws);
    h.wait_events("ws_open", 1).await;
    let close = h.wait_events("ws_close", 1).await;
    assert!(close[0]["bytes_c2s"].as_u64().unwrap() > 100_000);
    assert!(close[0]["bytes_s2c"].as_u64().unwrap() > 100_000);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn websocket_upgrade_needs_the_rule() {
    let h = Harness::start(ALLOW_UPSTREAM).await;
    let port = h.upstream.https.port();
    let tls = h
        .tls_tunnel(&format!("upstream.test:{port}"), "upstream.test")
        .await
        .unwrap();
    let err = tokio_tungstenite::client_async(format!("wss://upstream.test:{port}/echo"), tls)
        .await
        .unwrap_err();
    match err {
        tokio_tungstenite::tungstenite::Error::Http(res) => assert_eq!(res.status(), 200),
        other => panic!("expected a plain HTTP answer, got {other:?}"),
    }
    let seen = h.upstream.seen();
    assert_eq!(seen.len(), 1);
    assert!(seen[0].header("upgrade").is_none());
    assert_eq!(
        h.wait_events("upgrade_stripped", 1).await[0]["upgrade"],
        "websocket"
    );
    assert_eq!(h.events("ws_open").len(), 0);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn ca_certificate_endpoints() {
    let h = Harness::start("").await;
    let res = h
        .client()
        .get("http://roxy.internal/roxy-ca.pem")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.headers()["content-type"], "application/x-pem-file");
    assert_eq!(res.text().await.unwrap(), h.roxy_ca_pem);
    let res = h
        .client()
        .get("http://roxy.internal/other")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);

    let ca = h.ca_server.unwrap();
    let direct = reqwest::Client::builder().no_proxy().build().unwrap();
    let res = direct
        .get(format!("http://{ca}/healthz"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.text().await.unwrap(), "ok");
    let res = direct
        .get(format!("http://{ca}/roxy-ca.pem"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.text().await.unwrap(), h.roxy_ca_pem);
    let res = direct
        .get(format!("http://{ca}/nope"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    // Origin-form for any other host on the proxy port is refused.
    let (out, eof) = raw(h.proxy, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
    assert!(eof);
    assert!(out.starts_with("HTTP/1.1 400"), "{out}");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn hot_reload_swaps_policy_and_keeps_it_on_failure() {
    let h = Harness::start(ALLOW_UPSTREAM).await;
    let c = h.client();
    let url = h.http_url("/r");
    assert_eq!(c.get(&url).send().await.unwrap().status(), 200);

    let denied = h.render(&Opts {
        rules: r#"
  - id: now-denied
    when: host == "upstream.test"
    then: { deny: { status: 403 } }
"#,
        ..Opts::default()
    });
    std::fs::write(&h.config_path, denied).unwrap();
    h.wait_events("config_reloaded", 1).await;
    let res = c.get(&url).send().await.unwrap();
    assert_eq!(res.status(), 403);
    assert_eq!(res.headers()["x-roxy-rule"], "now-denied");

    std::fs::write(&h.config_path, "version: 1\nrules: [ {").unwrap();
    let failed = h.wait_events("config_reload_failed", 1).await;
    assert_ne!(failed[0]["diagnostics"].as_array().unwrap().len(), 0);
    let res = c.get(&url).send().await.unwrap();
    assert_eq!(
        res.status(),
        403,
        "the old policy stays after a failed reload"
    );
    assert_eq!(res.headers()["x-roxy-rule"], "now-denied");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn proxy_auth() {
    let hash = bcrypt::hash("wonderland", 4).unwrap();
    let h = Harness::start_with(Opts {
        rules: r#"
  - id: alice-only
    when: client.user == "alice" and host == "upstream.test"
    then: { allow: { private_ok: true } }
"#,
        users: Some(format!("alice:{hash}\nbob:{hash}\n")),
        ..Opts::default()
    })
    .await;
    // No credentials: 407 with a challenge, connection closed.
    let port = h.upstream.http.port();
    let (out, eof) = raw(
        h.proxy,
        format!("GET http://upstream.test:{port}/ HTTP/1.1\r\nHost: upstream.test:{port}\r\n\r\n")
            .as_bytes(),
    )
    .await;
    assert!(eof);
    assert!(out.starts_with("HTTP/1.1 407"), "{out}");
    assert!(
        out.contains("proxy-authenticate: Basic realm=\"roxy\""),
        "{out}"
    );
    let with = |user: &str, pass: &str| {
        h.client_builder_with(
            reqwest::Proxy::all(format!("http://{}", h.proxy))
                .unwrap()
                .basic_auth(user, pass),
        )
        .build()
        .unwrap()
    };
    let res = with("alice", "wrong")
        .get(h.http_url("/x"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 407);
    let res = with("alice", "wonderland")
        .get(h.https_url("/x"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let res = with("alice", "wonderland")
        .get(h.http_url("/y"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    // bob authenticates but the rule only lets alice through.
    let res = with("bob", "wonderland")
        .get(h.http_url("/z"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
    let ev = h.wait_events("request", 3).await;
    assert!(ev.iter().any(|e| e["client"]["user"] == "alice"));
    assert!(ev.iter().any(|e| e["client"]["user"] == "bob"));
    let all = serde_json::to_string(&h.sink.events()).unwrap();
    assert!(!all.contains("wonderland"));
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn per_client_connection_cap() {
    let h = Harness::start_with(Opts {
        rules: ALLOW_UPSTREAM,
        limits: "max_connections_per_client: 2",
        ..Opts::default()
    })
    .await;
    let a = TcpStream::connect(h.proxy).await.unwrap();
    let b = TcpStream::connect(h.proxy).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut c = TcpStream::connect(h.proxy).await.unwrap();
    let port = h.upstream.http.port();
    let _ = c
        .write_all(
            format!(
                "GET http://upstream.test:{port}/ HTTP/1.1\r\nHost: upstream.test:{port}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await;
    let (out, eof) = read_to_eof(&mut c).await;
    assert!(eof);
    assert_eq!(out.len(), 0);
    let ev = h.wait_events("connection_refused", 1).await;
    assert_eq!(ev[0]["reason"], "max_connections_per_client");
    // Slots free up when connections close.
    drop((a, b));
    tokio::time::sleep(Duration::from_millis(200)).await;
    let res = h.client().get(h.http_url("/ok")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    h.stop().await;
}

/// A metric store whose answers the test controls.
#[derive(Default)]
struct StubMetrics {
    /// 0 ok, 1 unavailable, 2 table full on read, 3 table full on record.
    mode: AtomicU8,
    recorded: AtomicUsize,
}

impl MetricSource for StubMetrics {
    fn get(&self, id: &str, _view: &dyn FlowView) -> Result<i64, MetricSourceError> {
        match self.mode.load(Ordering::Relaxed) {
            1 => Err(MetricSourceError::Unknown(format!("{id}: store offline"))),
            2 => Err(MetricSourceError::TableFull(id.to_owned())),
            _ => Ok(0),
        }
    }

    fn record(&self, _view: &dyn FlowView, _sample: &Sample) -> Result<(), MetricSourceError> {
        self.recorded.fetch_add(1, Ordering::Relaxed);
        if self.mode.load(Ordering::Relaxed) == 3 {
            return Err(MetricSourceError::TableFull("hits".into()));
        }
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn unavailable_metrics_fail_closed() {
    let stub = Arc::new(StubMetrics::default());
    let h = Harness::start_with(Opts {
        rules: &format!(
            "
  - id: limit
    when: metric.hits >= 1000
    then: deny
{ALLOW_UPSTREAM}"
        ),
        extra: "metrics:\n  - id: hits\n    count: requests\n    key: [client.ip]\n",
        metrics: Some(stub.clone()),
        ..Opts::default()
    })
    .await;
    let c = h.client();
    let res = c.get(h.http_url("/m")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    // The allowed request's event is emitted after its body has streamed;
    // wait for it so later events cannot be reordered ahead of it.
    h.wait_events("request", 1).await;
    for (mode, reason) in [
        (1u8, "metric_unavailable"),
        (2, "metric_table_full"),
        (3, "metric_table_full"),
    ] {
        stub.mode.store(mode, Ordering::Relaxed);
        let res = c.get(h.http_url("/m")).send().await.unwrap();
        assert_eq!(res.status(), 503, "mode {mode}");
        assert_eq!(res.headers()["x-roxy-rule"], "_fail_closed");
        let ev = h.wait_events("request", 1 + usize::from(mode)).await;
        let n = ev.iter().filter(|e| e["reason"] == reason).count();
        assert!(
            n >= 1,
            "mode {mode}: no request event with reason {reason}: {ev:#?}"
        );
    }
    assert_eq!(h.events("metric_table_full").len(), 2);
    assert_eq!(h.events("policy_input_unavailable").len(), 2);
    assert_eq!(h.upstream.seen().len(), 1);
    assert!(stub.recorded.load(Ordering::Relaxed) >= 4);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn request_body_cap_closes_mid_stream() {
    let h = Harness::start_with(Opts {
        rules: ALLOW_UPSTREAM,
        limits: "max_request_body_bytes: 1kb",
        ..Opts::default()
    })
    .await;
    let port = h.upstream.http.port();
    let mut s = TcpStream::connect(h.proxy).await.unwrap();
    s.write_all(
        format!(
            "POST http://upstream.test:{port}/cap HTTP/1.1\r\nHost: upstream.test:{port}\r\n\
             Transfer-Encoding: chunked\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    for _ in 0..4 {
        let _ = s.write_all(b"400\r\n").await;
        let _ = s.write_all(&[b'z'; 1024]).await;
        let _ = s.write_all(b"\r\n").await;
    }
    let (out, eof) = read_to_eof(&mut s).await;
    assert!(eof);
    let out = String::from_utf8_lossy(&out);
    assert!(out.starts_with("HTTP/1.1 413"), "{out}");
    let ev = h.wait_events("parse_error", 1).await;
    assert_eq!(ev[0]["reason"], "body_too_large");
    // The upstream never saw a complete body.
    assert!(h.upstream.seen().iter().all(|s| s.body_len <= 1024));
    h.stop().await;
}

const RATE_LIMITED: &str = r#"
  - id: burst
    when: host == "upstream.test" and metric.hits >= 3
    then: { deny: { status: 429, close: false } }
  - id: upstream
    when: host == "upstream.test"
    then: { allow: { private_ok: true } }
"#;

const HITS_METRIC: &str = r#"metrics:
  - id: hits
    count: requests
    where: host == "upstream.test"
    key: [client.ip]
    window: 1h
"#;

/// The built-in metric store enforces a rate limit end to end, and an
/// unrelated config edit (hot reload) does not reset the counter (§6.5).
#[tokio::test(flavor = "multi_thread")]
async fn builtin_metric_store_rate_limits_and_survives_reload() {
    let h = Harness::start_with(Opts {
        rules: RATE_LIMITED,
        extra: HITS_METRIC,
        ..Opts::default()
    })
    .await;
    let c = h.client();
    let url = h.http_url("/m");
    for i in 0..3 {
        assert_eq!(
            c.get(&url).send().await.unwrap().status(),
            200,
            "request {i}"
        );
    }
    let res = c.get(&url).send().await.unwrap();
    assert_eq!(res.status(), 429, "the 4th request is over the limit");
    assert_eq!(res.headers()["x-roxy-rule"], "burst");

    // Reload with an extra, unrelated rule; the `hits` definition is unchanged.
    let edited = h.render(&Opts {
        rules: &format!(
            "{RATE_LIMITED}  - id: unrelated\n    when: host == \"nowhere.test\"\n    then: deny\n"
        ),
        extra: HITS_METRIC,
        ..Opts::default()
    });
    std::fs::write(&h.config_path, edited).unwrap();
    h.wait_events("config_reloaded", 1).await;
    let res = c.get(&url).send().await.unwrap();
    assert_eq!(res.status(), 429, "the counter survived the reload");
    h.stop().await;
}

/// A full metric key table denies flows that need a new key instead of
/// evicting existing ones (§6.4).
#[tokio::test(flavor = "multi_thread")]
async fn full_metric_table_denies_new_keys() {
    let h = Harness::start_with(Opts {
        rules: r#"
  - id: guarded
    when: host == "upstream.test" and metric.by_path < 1000
    then: { allow: { private_ok: true } }
"#,
        extra: r#"metrics:
  - id: by_path
    count: requests
    where: host == "upstream.test"
    key: [path]
    window: 1h
"#,
        limits: "max_metric_keys: 2",
        ..Opts::default()
    })
    .await;
    let c = h.client();
    assert_eq!(c.get(h.http_url("/a")).send().await.unwrap().status(), 200);
    assert_eq!(c.get(h.http_url("/b")).send().await.unwrap().status(), 200);
    let res = c.get(h.http_url("/c")).send().await.unwrap();
    assert_eq!(res.status(), 503, "a third key does not fit");
    assert_eq!(res.headers()["x-roxy-rule"], "_fail_closed");
    assert_eq!(
        c.get(h.http_url("/a")).send().await.unwrap().status(),
        200,
        "existing keys keep working"
    );
    h.stop().await;
}

/// `limits.max_metric_bytes` is enforced like the key cap: with a budget
/// too small for even one series, the first flow that needs a new key is
/// denied (`_fail_closed`, `metric_table_full`), never served by evicting
/// (§6.4, §12).
#[tokio::test(flavor = "multi_thread")]
async fn tiny_metric_byte_budget_denies_new_keys() {
    let h = Harness::start_with(Opts {
        rules: r#"
  - id: guarded
    when: host == "upstream.test" and metric.by_path < 1000
    then: { allow: { private_ok: true } }
"#,
        extra: r#"metrics:
  - id: by_path
    count: requests
    where: host == "upstream.test"
    key: [path]
    window: 1h
"#,
        limits: "max_metric_bytes: 1",
        ..Opts::default()
    })
    .await;
    let c = h.client();
    let res = c.get(h.http_url("/a")).send().await.unwrap();
    assert_eq!(res.status(), 503, "no series fits a 1-byte budget");
    assert_eq!(res.headers()["x-roxy-rule"], "_fail_closed");
    let ev = h.wait_events("request", 1).await;
    assert_eq!(ev[0]["reason"], "metric_table_full", "{ev:#?}");
    h.wait_events("metric_table_full", 1).await;
    assert!(h.upstream.seen().is_empty());
    h.stop().await;
}

// ----- address lists (§7.1) --------------------------------------------------

/// `upstream.deny_lists` is a hard floor: a hit denies with `403
/// _address_policy` and an `upstream_denied` event naming the list, and
/// `private_ok` does not bypass it, for names, IP literals (also written
/// as IPv4-mapped IPv6) and CONNECT-tunnelled HTTPS alike.
#[tokio::test(flavor = "multi_thread")]
async fn deny_list_is_a_floor_private_ok_does_not_bypass() {
    let h = Harness::start_with(Opts {
        rules: r"
  - id: everything-private-ok
    when: port in [{HTTP}, {HTTPS}]
    then: { allow: { private_ok: true } }
",
        extra: "address_lists:\n  - { name: blocked, inline: [192.0.2.0/24, 127.0.0.1] }\n",
        upstream: "deny_lists: [blocked]",
        ..Opts::default()
    })
    .await;
    let port = h.upstream.http.port();
    let c = h.client();
    let urls = [
        h.http_url("/a"),
        format!("http://127.0.0.1:{port}/b"),
        format!("http://[::ffff:127.0.0.1]:{port}/c"),
        h.https_url("/d"),
    ];
    for url in &urls {
        let res = c.get(url).send().await.unwrap();
        assert_eq!(res.status(), 403, "{url}");
        assert_eq!(res.headers()["x-roxy-rule"], "_address_policy", "{url}");
    }
    let ev = h.wait_events("upstream_denied", urls.len()).await;
    for (e, host) in ev.iter().zip([
        "upstream.test",
        "127.0.0.1",
        "::ffff:127.0.0.1",
        "upstream.test",
    ]) {
        assert_eq!(e["list"], "blocked", "{e}");
        assert_eq!(e["reason"], "list:blocked", "{e}");
        assert_eq!(e["matched_cidr"], "127.0.0.1/32", "{e}");
        assert_eq!(e["resolved_ip"], "127.0.0.1", "{e}");
        assert_eq!(e["host"], host, "{e}");
    }
    let req = h.wait_events("request", urls.len()).await;
    assert!(
        req.iter().all(|e| e["terminal_rule"] == "_address_policy"),
        "{req:#?}"
    );
    assert!(h.upstream.seen().is_empty(), "nothing reached the upstream");
    h.stop().await;
}

/// `client.ip in @list` and `not in @list` in rules use the loaded lists.
#[tokio::test(flavor = "multi_thread")]
async fn rules_can_use_address_lists() {
    let h = Harness::start_with(Opts {
        rules: r#"
  - id: loopback-listed
    when: client.ip in @loopback and path == "/listed"
    then: { deny: { status: 451 } }
  - id: client-listed
    when: client.ip in @clients and host == "alias.test"
    then: { deny: { status: 429 } }
  - id: client-not-listed
    when: client.ip not in @clients
    then: deny
  - id: upstream
    when: host in ["upstream.test", "alias.test"]
    then: { allow: { private_ok: true } }
"#,
        extra: "address_lists:\n  - { name: loopback, inline: [127.0.0.0/8] }\n  \
                - { name: clients, inline: [\"::ffff:127.0.0.1\"] }\n",
        ..Opts::default()
    })
    .await;
    let port = h.upstream.http.port();
    let c = h.client();
    let res = c.get(h.http_url("/listed")).send().await.unwrap();
    assert_eq!(res.status(), 451);
    assert_eq!(res.headers()["x-roxy-rule"], "loopback-listed");
    let res = c
        .get(format!("http://alias.test:{port}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 429);
    assert_eq!(res.headers()["x-roxy-rule"], "client-listed");
    let res = c.get(h.http_url("/ok")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(h.events("policy_input_unavailable"), Vec::<Value>::new());
    h.stop().await;
}

/// Editing a deny-list file reloads it: a pooled upstream connection that
/// served the previous request is not reused once the address is listed.
/// A malformed list file fails the reload and the old lists stay.
#[tokio::test(flavor = "multi_thread")]
async fn deny_list_file_reload_flips_allow_to_deny_and_keeps_old_lists_on_failure() {
    let lists = tempfile::tempdir().unwrap();
    let file = lists.path().join("blocked.txt");
    std::fs::write(&file, "# nothing local yet\n192.0.2.0/24\n").unwrap();
    let extra = format!(
        "address_lists:\n  - {{ name: blocked, file: {} }}\n",
        file.display()
    );
    let h = Harness::start_with(Opts {
        rules: ALLOW_UPSTREAM,
        extra: &extra,
        upstream: "deny_lists: [blocked]",
        ..Opts::default()
    })
    .await;
    let c = h.client();
    let url = h.http_url("/pooled");
    for _ in 0..3 {
        assert_eq!(c.get(&url).send().await.unwrap().status(), 200);
    }
    let served = h.upstream.seen().len();

    std::fs::write(&file, "192.0.2.0/24\n127.0.0.0/8 # now listed\n").unwrap();
    h.wait_events("config_reloaded", 1).await;
    let res = c.get(&url).send().await.unwrap();
    assert_eq!(res.status(), 403);
    assert_eq!(res.headers()["x-roxy-rule"], "_address_policy");
    let ev = h.wait_events("upstream_denied", 1).await;
    assert_eq!(ev[0]["list"], "blocked");
    assert_eq!(ev[0]["matched_cidr"], "127.0.0.0/8");
    assert_eq!(
        h.upstream.seen().len(),
        served,
        "the pooled connection was not used"
    );

    std::fs::write(&file, "127.0.0.0/8\n10.0.0.1/8\n").unwrap();
    let failed = h.wait_events("config_reload_failed", 1).await;
    let diags = failed[0]["diagnostics"].to_string();
    assert!(
        diags.contains(&format!("{}:2:", file.display())) && diags.contains("host bits"),
        "{diags}"
    );
    let res = c.get(&url).send().await.unwrap();
    assert_eq!(
        res.status(),
        403,
        "the old list stays after a failed reload"
    );
    assert_eq!(res.headers()["x-roxy-rule"], "_address_policy");

    // An emptied list (a valid file) allows again.
    std::fs::write(&file, "# cleared\n").unwrap();
    h.wait_events("config_reloaded", 2).await;
    assert_eq!(c.get(&url).send().await.unwrap().status(), 200);
    h.stop().await;
}

// ---------------------------------------------------------------------------
// Client-side HTTP/2 (§5.1a, §5.3)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn h2_allow_get_end_to_end() {
    let h = Harness::start(ALLOW_UPSTREAM).await;
    let res = h
        .client()
        .get(h.https_url("/hello?x=1"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.version(), reqwest::Version::HTTP_2);
    assert_eq!(res.status(), 200);
    let v = json(&res.bytes().await.unwrap());
    assert_eq!(v["path"], "/hello?x=1");
    assert_eq!(v["method"], "GET");
    let ev = h.wait_events("request", 1).await;
    let e = &ev[0];
    assert_eq!(e["decision"], "allow");
    assert_eq!(e["terminal_rule"], "upstream");
    assert_eq!(e["tls"]["alpn"], "h2");
    assert_eq!(e["tls"]["sni"], "upstream.test");
    assert_eq!(e["res"]["status"], 200);
    assert!(e["res"]["body_bytes"].as_u64().unwrap() > 0);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn h2_multiplexes_concurrent_streams_on_one_connection() {
    let h = Harness::start(ALLOW_UPSTREAM).await;
    let (send, _conn) = h.h2_client().await;
    let urls: Vec<String> = (0..5).map(|i| h.https_url(&format!("/m/{i}"))).collect();
    let results = futures_util::future::join_all(urls.iter().map(|u| h2_get(&send, u, &[]))).await;
    for (i, r) in results.into_iter().enumerate() {
        let (parts, body) = r.unwrap();
        assert_eq!(parts.status, 200);
        assert_eq!(json(&body)["path"], format!("/m/{i}"));
    }
    let ev = h.wait_events("request", 5).await;
    assert_eq!(ev.len(), 5);
    let conn = &ev[0]["conn"];
    assert!(ev.iter().all(|e| &e["conn"] == conn), "{ev:#?}");
    assert!(ev.iter().all(|e| e["tls"]["alpn"] == "h2"));
    assert_eq!(h.events("connect").len(), 1);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn h2_default_deny_answers_on_the_stream_then_goaway() {
    let h = Harness::start("").await;
    // reqwest over h2: the deny is an ordinary response.
    let res = h.client().get(h.https_url("/x")).send().await.unwrap();
    assert_eq!(res.version(), reqwest::Version::HTTP_2);
    assert_eq!(res.status(), 403);
    assert_eq!(res.headers()["x-roxy-rule"], "_default");
    assert_eq!(json(&res.bytes().await.unwrap())["rule"], "_default");

    // Raw h2: after the deny the connection sends GOAWAY and ends; a new
    // stream on it is refused.
    let (send, conn) = h.h2_client().await;
    let (parts, body) = h2_get(&send, &h.https_url("/y"), &[]).await.unwrap();
    assert_eq!(parts.status, 403);
    assert_eq!(parts.headers["content-type"], "application/json");
    let v = json(&body);
    assert_eq!(v["rule"], "_default");
    assert_eq!(v["error"], "blocked by roxy");
    let ended = tokio::time::timeout(Duration::from_secs(5), conn).await;
    assert!(ended.is_ok(), "the connection must close after a deny");
    let again = h2_get(&send, &h.https_url("/z"), &[]).await;
    assert!(again.is_err(), "a new stream after GOAWAY must fail");
    let ev = h.wait_events("request", 2).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(h.events("request").len(), 2, "{ev:#?}");
    assert!(h.upstream.seen().is_empty());
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn h2_deny_without_close_keeps_serving() {
    let h = Harness::start(&format!(
        r#"
  - id: soft
    when: path == "/soft"
    then: {{ deny: {{ status: 451, message: "not here", close: false }} }}
{ALLOW_UPSTREAM}"#
    ))
    .await;
    let (send, conn) = h.h2_client().await;
    let (parts, body) = h2_get(&send, &h.https_url("/soft"), &[]).await.unwrap();
    assert_eq!(parts.status, 451);
    assert_eq!(json(&body)["error"], "not here");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!conn.is_finished());
    let (parts, body) = h2_get(&send, &h.https_url("/after"), &[]).await.unwrap();
    assert_eq!(parts.status, 200);
    assert_eq!(json(&body)["path"], "/after");
    assert_eq!(h.events("connect").len(), 1);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn h2_large_upload_streams_intact() {
    let h = Harness::start_with(Opts {
        rules: ALLOW_UPSTREAM,
        limits: BIG_UPLOAD_LIMITS,
        ..Opts::default()
    })
    .await;
    let data: Vec<u8> = (0..32 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
    let want = fnv(&data);
    let res = h
        .client()
        .post(h.https_url("/upload"))
        .body(data)
        .send()
        .await
        .unwrap();
    assert_eq!(res.version(), reqwest::Version::HTTP_2);
    assert_eq!(res.status(), 200);
    let v = json(&res.bytes().await.unwrap());
    assert_eq!(v["body_len"], 32 * 1024 * 1024);
    assert_eq!(v["body_hash"], want);
    let ev = h.wait_events("request", 1).await;
    assert_eq!(ev[0]["req"]["body_bytes"], 32 * 1024 * 1024);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn h2_request_body_cap_resets_the_stream() {
    let h = Harness::start_with(Opts {
        rules: ALLOW_UPSTREAM,
        limits: "max_request_body_bytes: 1kb",
        ..Opts::default()
    })
    .await;
    let (send, _conn) = h.h2_client().await;

    // Streamed (no content-length): reset once the cap is crossed.
    let req = http::Request::post(h.https_url("/cap")).body(()).unwrap();
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
    let ev = h.wait_events("parse_error", 1).await;
    assert_eq!(ev[0]["reason"], "body_too_large");

    // Declared too large: reset before anything is forwarded.
    let req = http::Request::post(h.https_url("/cap2"))
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
    let ev = h.wait_events("parse_error", 2).await;
    assert_eq!(ev[1]["reason"], "body_too_large");
    // The upstream never saw a complete body, and never saw /cap2.
    let seen = h.upstream.seen();
    assert!(seen.iter().all(|s| s.body_len <= 1024), "{seen:#?}");
    assert!(seen.iter().all(|s| s.path_and_query != "/cap2"));

    // The connection is still usable.
    let (parts, _) = h2_get(&send, &h.https_url("/ok"), &[]).await.unwrap();
    assert_eq!(parts.status, 200);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn h2_malformed_streams_are_reset() {
    let h = Harness::start(ALLOW_UPSTREAM).await;
    let authority = format!("upstream.test:{}", h.upstream.https.port());

    // A connection-specific field: RST_STREAM(PROTOCOL_ERROR). The `h2`
    // crate rejects it before roxy's mapper sees the stream.
    let frames = h2_raw_request(
        &h,
        &[
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", &authority),
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
        &h,
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
    let ev = h.wait_events("parse_error", 1).await;
    assert_eq!(ev[0]["reason"], "authority_mismatch");

    // Same through the h2 client, plus a mismatching `host`; the
    // connection keeps serving well-formed streams.
    let (send, _conn) = h.h2_client().await;
    let e = h2_get(&send, "https://evil.test/x", &[]).await.unwrap_err();
    assert_eq!(e.reason(), Some(h2::Reason::PROTOCOL_ERROR));
    let e = h2_get(&send, &h.https_url("/x"), &[("host", "evil.test")])
        .await
        .unwrap_err();
    assert_eq!(e.reason(), Some(h2::Reason::PROTOCOL_ERROR));
    let ev = h.wait_events("parse_error", 3).await;
    assert_eq!(ev[1]["reason"], "authority_mismatch");
    assert_eq!(ev[2]["reason"], "host_mismatch");
    let (parts, _) = h2_get(&send, &h.https_url("/fine"), &[]).await.unwrap();
    assert_eq!(parts.status, 200);

    // Nothing malformed reached the upstream.
    let seen = h.upstream.seen();
    assert_eq!(seen.len(), 1, "{seen:#?}");
    assert_eq!(seen[0].path_and_query, "/fine");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn h2_disabled_offers_http11_only() {
    let h = Harness::start_with(Opts {
        rules: ALLOW_UPSTREAM,
        http: "enable_h2: false",
        ..Opts::default()
    })
    .await;
    let authority = format!("upstream.test:{}", h.upstream.https.port());
    let tls = h
        .tls_tunnel_alpn(&authority, "upstream.test", &[b"h2", b"http/1.1"])
        .await
        .unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
    drop(tls);
    let res = h.client().get(h.https_url("/h1")).send().await.unwrap();
    assert_eq!(res.version(), reqwest::Version::HTTP_11);
    assert_eq!(res.status(), 200);
    let ev = h.wait_events("request", 1).await;
    assert_eq!(ev[0]["tls"]["alpn"], "http/1.1");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn h1_only_client_works_with_h2_enabled() {
    let h = Harness::start(ALLOW_UPSTREAM).await;
    let c = h.client_builder().http1_only().build().unwrap();
    for p in ["/a", "/b"] {
        let res = c.get(h.https_url(p)).send().await.unwrap();
        assert_eq!(res.version(), reqwest::Version::HTTP_11);
        assert_eq!(res.status(), 200);
        assert_eq!(json(&res.bytes().await.unwrap())["path"], p);
    }
    let ev = h.wait_events("request", 2).await;
    assert!(ev.iter().all(|e| e["tls"]["alpn"] == "http/1.1"), "{ev:#?}");
    h.stop().await;
}

// ----- watching rules (§6.1) -------------------------------------------------

const UPLOAD_CAP: &str = r#"
  - id: upstream
    when: host == "upstream.test"
    then: { allow: { private_ok: true } }
  - id: upload-cap
    when: body.bytes > 100kb
    then: { deny: { status: 413, message: "upload too large" } }
"#;

/// A chunked upload, `n` chunks of 16 KiB.
fn chunked_upload(n: usize) -> reqwest::Body {
    let chunks: Vec<Result<Bytes, std::io::Error>> = (0..n)
        .map(|_| Ok(Bytes::from(vec![b'u'; 16 * 1024])))
        .collect();
    reqwest::Body::wrap_stream(futures_util::stream::iter(chunks))
}

/// The streaming upload cap stops an h1 upload at the chunk that crosses
/// it: the client gets the deny, the upstream never gets more than the cap.
#[tokio::test(flavor = "multi_thread")]
async fn upload_cap_stops_h1_upload_mid_stream() {
    let h = Harness::start(UPLOAD_CAP).await;
    let c = h.client();
    // Under the cap: forwarded intact.
    let res = c
        .post(h.http_url("/small"))
        .body(chunked_upload(4))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(json(&res.bytes().await.unwrap())["body_len"], 64 * 1024);
    // Over: stopped. reqwest may see the 413 or a reset (the server stops
    // reading the body); either way nothing past the cap is forwarded.
    let res = c
        .post(h.http_url("/big"))
        .body(chunked_upload(64))
        .send()
        .await;
    if let Ok(res) = res {
        assert_eq!(res.status(), 413);
        assert_eq!(res.headers()["x-roxy-rule"], "upload-cap");
    }
    let ev = h.wait_events("request", 2).await;
    let stopped = ev
        .iter()
        .find(|e| e["req"]["path"] == "/big")
        .expect("request event");
    assert_eq!(stopped["decision"], "deny");
    assert_eq!(stopped["stage"], "request_body");
    assert_eq!(stopped["terminal_rule"], "upload-cap");
    assert!(
        stopped["rules"]
            .as_array()
            .unwrap()
            .contains(&"upload-cap".into())
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    let seen = h.upstream.seen();
    assert!(
        seen.iter().all(|s| s.body_len <= 100 * 1024),
        "the upstream got more than the cap: {seen:#?}"
    );
    h.stop().await;
}

/// The same cap over h2: the stream gets the deny response (the response
/// has not started), and the upstream never sees more than the cap.
#[tokio::test(flavor = "multi_thread")]
async fn upload_cap_stops_h2_upload_mid_stream() {
    let h = Harness::start(UPLOAD_CAP).await;
    let (send, _conn) = h.h2_client().await;
    let req = http::Request::post(h.https_url("/h2big")).body(()).unwrap();
    let mut ready = send.clone().ready().await.unwrap();
    let (resp, mut stream) = ready.send_request(req, false).unwrap();
    let pump = tokio::spawn(async move {
        for _ in 0..64 {
            stream.reserve_capacity(16 * 1024);
            if stream
                .send_data(Bytes::from(vec![b'u'; 16 * 1024]), false)
                .is_err()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        let _ = stream.send_data(Bytes::new(), true);
    });
    let r = tokio::time::timeout(Duration::from_secs(10), resp)
        .await
        .unwrap();
    let res = r.expect("a deny response on the stream");
    assert_eq!(res.status(), 413);
    assert_eq!(res.headers()["x-roxy-rule"], "upload-cap");
    pump.abort();
    let ev = h.wait_events("request", 1).await;
    assert_eq!(ev[0]["stage"], "request_body");
    assert_eq!(ev[0]["terminal_rule"], "upload-cap");
    tokio::time::sleep(Duration::from_millis(200)).await;
    let seen = h.upstream.seen();
    assert!(seen.iter().all(|s| s.body_len <= 100 * 1024), "{seen:#?}");
    h.stop().await;
}

const RESPONSE_CAP: &str = r#"
  - id: upstream
    when: host == "upstream.test"
    then: { allow: { private_ok: true } }
  - id: download-cap
    when: response.body.bytes > 1mb
    then: deny
"#;

/// A response that crosses the byte cap after its head was sent is cut:
/// h1 breaks the connection without completing the body.
#[tokio::test(flavor = "multi_thread")]
async fn response_byte_cap_cuts_h1_response() {
    let h = Harness::start(RESPONSE_CAP).await;
    let c = h.client();
    // Under the cap: complete.
    let res = c.get(h.https_url("/big?n=500000")).send().await.unwrap();
    assert_eq!(res.bytes().await.unwrap().len(), 500_000);
    // Over: the head (200) went out; the body is cut short.
    let res = c.get(h.https_url("/big?n=4000000")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let body = res.bytes().await;
    assert!(body.is_err(), "the body must not complete");
    let ev = h.wait_events("request", 2).await;
    let cut = ev
        .iter()
        .find(|e| e["req"]["path"] == "/big")
        .filter(|e| e["decision"] == "deny")
        .or_else(|| ev.iter().find(|e| e["decision"] == "deny"))
        .expect("a deny event");
    assert_eq!(cut["stage"], "response_body");
    assert_eq!(cut["terminal_rule"], "download-cap");
    assert!(cut["res"]["body_bytes"].as_u64().unwrap() <= 1024 * 1024);
    h.stop().await;
}

/// Over h2 the stream is reset with `CANCEL`, then (the deny closes) the
/// connection ends with `GOAWAY`.
#[tokio::test(flavor = "multi_thread")]
async fn response_byte_cap_resets_h2_stream() {
    let h = Harness::start(RESPONSE_CAP).await;
    let (send, conn) = h.h2_client().await;
    let err = h2_get(&send, &h.https_url("/big?n=4000000"), &[])
        .await
        .expect_err("the stream must be reset");
    assert_eq!(err.reason(), Some(h2::Reason::CANCEL), "{err}");
    let ended = tokio::time::timeout(Duration::from_secs(15), conn).await;
    assert!(
        ended.is_ok(),
        "the connection must close after a closing deny"
    );
    let ev = h.wait_events("request", 1).await;
    assert_eq!(ev[0]["stage"], "response_body");
    assert_eq!(ev[0]["terminal_rule"], "download-cap");
    h.stop().await;
}

/// A byte budget (`request_bytes` metric) stops the upload that crosses
/// it, while it streams, and later requests are denied at the head.
#[tokio::test(flavor = "multi_thread")]
async fn byte_budget_stops_the_crossing_upload() {
    let h = Harness::start_with(Opts {
        rules: r#"
  - id: upstream
    when: host == "upstream.test"
    then: { allow: { private_ok: true } }
  - id: budget
    when: metric.up > 100kb
    then: { deny: { status: 429, message: "upload budget exhausted" } }
"#,
        extra: "metrics:\n  - { id: up, count: request_bytes, key: [client.ip] }\n",
        ..Opts::default()
    })
    .await;
    let c = h.client();
    let res = c
        .post(h.http_url("/one"))
        .body(chunked_upload(4))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "64 KiB fits the budget");
    // 64 KiB more crosses 100 KiB part-way through.
    let res = c
        .post(h.http_url("/two"))
        .body(chunked_upload(4))
        .send()
        .await;
    if let Ok(res) = res {
        assert_eq!(res.status(), 429);
    }
    // Over budget now: denied at the head.
    let res = c.get(h.http_url("/three")).send().await.unwrap();
    assert_eq!(res.status(), 429);
    assert_eq!(res.headers()["x-roxy-rule"], "budget");
    let ev = h.wait_events("request", 3).await;
    let stage = |path: &str| {
        ev.iter()
            .find(|e| e["req"]["path"] == path)
            .map(|e| (e["decision"].clone(), e["stage"].clone()))
            .unwrap()
    };
    assert_eq!(stage("/one"), ("allow".into(), "head".into()));
    assert_eq!(stage("/two"), ("deny".into(), "request_body".into()));
    assert_eq!(stage("/three"), ("deny".into(), "head".into()));
    let seen = h.upstream.seen();
    let total: u64 = seen.iter().map(|s| s.body_len).sum();
    assert!(
        total <= 100 * 1024,
        "forwarded {total} bytes past the budget"
    );
    h.stop().await;
}

/// A byte budget applies to the WebSocket relay: the relay closes before
/// writing the bytes that cross it.
#[tokio::test(flavor = "multi_thread")]
async fn websocket_byte_budget_closes_the_relay() {
    let h = Harness::start_with(Opts {
        rules: r#"
  - id: ws
    when: host == "ws.test"
    then: { allow: { upgrade: websocket, private_ok: true } }
  - id: ws-budget
    when: metric.ws_down > 50kb
    then: deny
"#,
        extra: "metrics:\n  - { id: ws_down, count: response_bytes, where: 'host == \"ws.test\"' }\n",
        ..Opts::default()
    })
    .await;
    let port = h.upstream.ws.port();
    let tls = h
        .tls_tunnel(&format!("ws.test:{port}"), "ws.test")
        .await
        .unwrap();
    let (mut ws, _) = tokio_tungstenite::client_async(format!("wss://ws.test:{port}/echo"), tls)
        .await
        .unwrap();
    ws.send(Message::text("small")).await.unwrap();
    assert_eq!(
        ws.next()
            .await
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap()
            .as_str(),
        "small"
    );
    // The echo of 100 KB crosses the 50 KiB budget: the relay closes.
    ws.send(Message::binary(vec![7u8; 100_000])).await.unwrap();
    let mut got = 0usize;
    loop {
        let next = tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await
            .expect("the relay did not close");
        match next {
            Some(Ok(m)) => got += m.into_data().len(),
            Some(Err(_)) | None => break,
        }
    }
    assert!(
        got < 100_000,
        "the over-budget echo was relayed ({got} bytes)"
    );
    let ev = h.wait_events("request", 1).await;
    assert_eq!(ev[0]["decision"], "deny");
    assert_eq!(ev[0]["stage"], "websocket");
    assert_eq!(ev[0]["terminal_rule"], "ws-budget");
    let close = h.wait_events("ws_close", 1).await;
    assert!(close[0]["bytes_s2c"].as_u64().unwrap() <= 50 * 1024 + 64);
    h.stop().await;
}

// ----- audit backpressure (§10.1) --------------------------------------------

/// A flow log that cannot keep up holds traffic back instead of dropping
/// records: new exchanges and streaming bodies wait until it is ready.
#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_flow_log_holds_traffic() {
    let gate = Arc::new(LogGate::default());
    let h = Harness::start_with(Opts {
        rules: ALLOW_UPSTREAM,
        log_gate: Some(gate.clone()),
        ..Opts::default()
    })
    .await;
    let c = h.client();
    assert_eq!(
        c.get(h.http_url("/before")).send().await.unwrap().status(),
        200
    );
    gate.set_closed(true);
    let url = h.http_url("/held");
    let req = tokio::spawn({
        let c = c.clone();
        async move { c.get(url).send().await.unwrap().status() }
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!req.is_finished(), "traffic moved while the log was behind");
    assert!(
        h.upstream
            .seen()
            .iter()
            .all(|s| s.path_and_query != "/held")
    );
    gate.set_closed(false);
    let status = tokio::time::timeout(Duration::from_secs(10), req)
        .await
        .expect("traffic resumes once the log catches up")
        .unwrap();
    assert_eq!(status, 200);
    h.stop().await;
}

// ----- capture (§10.2) -------------------------------------------------------

fn flow_of(ev: &[Value], path: &str) -> String {
    ev.iter()
        .find(|e| e["req"]["path"] == path)
        .unwrap_or_else(|| panic!("no request event for {path}"))["flow"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// `log.capture.all` tees every forwarded exchange: heads as forwarded and
/// bodies byte for byte, over h1 with a chunked upload.
#[tokio::test(flavor = "multi_thread")]
async fn capture_all_records_exactly_what_was_forwarded_h1() {
    let h = Harness::start_with(Opts {
        rules: ALLOW_UPSTREAM,
        capture: Some("all: true"),
        ..Opts::default()
    })
    .await;
    let chunks: Vec<Result<Bytes, std::io::Error>> = (0..20u8)
        .map(|i| Ok(Bytes::from(vec![i; 16 * 1024])))
        .collect();
    let sent: Vec<u8> = (0..20u8).flat_map(|i| vec![i; 16 * 1024]).collect();
    let res = h
        .client()
        .post(h.http_url("/upload?x=1"))
        .body(reqwest::Body::wrap_stream(futures_util::stream::iter(
            chunks,
        )))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let got = res.bytes().await.unwrap();
    let ev = h.wait_events("request", 1).await;
    let flow = flow_of(&ev, "/upload");
    let records = h.captured();
    let req = capture_of(&records, &flow, "request");
    assert_eq!(req[0].0["kind"], "head");
    let head: Value = serde_json::from_slice(&req[0].1).unwrap();
    assert_eq!(head["method"], "POST");
    assert!(
        head["url"].as_str().unwrap().ends_with("/upload?x=1"),
        "{head}"
    );
    assert_eq!(fnv(&capture_body(&req)), fnv(&sent));
    let end = req.last().unwrap();
    assert_eq!(end.0["kind"], "end");
    assert_eq!(end.0["bytes"], sent.len());
    assert!(end.0.get("aborted").is_none(), "{}", end.0);
    let res_recs = capture_of(&records, &flow, "response");
    let head: Value = serde_json::from_slice(&res_recs[0].1).unwrap();
    assert_eq!(head["status"], 200);
    assert_eq!(capture_body(&res_recs), got.to_vec());
    assert_eq!(res_recs.last().unwrap().0["kind"], "end");
    // Sequence numbers count up per direction.
    let seqs: Vec<u64> = req
        .iter()
        .map(|(h, _)| h["seq"].as_u64().unwrap())
        .collect();
    assert_eq!(seqs, (0..seqs.len() as u64).collect::<Vec<_>>());
    h.stop().await;
}

/// The `capture` action selects exchanges (and directions) at the head;
/// over h2.
#[tokio::test(flavor = "multi_thread")]
async fn capture_action_selects_exchanges_h2() {
    let h = Harness::start_with(Opts {
        rules: r#"
  - id: upstream
    when: host == "upstream.test"
    then: { allow: { private_ok: true } }
  - id: capture-uploads
    when: path starts_with "/cap"
    then: { capture: request }
"#,
        capture: Some(""),
        ..Opts::default()
    })
    .await;
    let (send, _conn) = h.h2_client().await;
    let body = vec![b'q'; 50_000];
    let req = http::Request::post(h.https_url("/cap/one"))
        .body(())
        .unwrap();
    let mut ready = send.clone().ready().await.unwrap();
    let (resp, mut stream) = ready.send_request(req, false).unwrap();
    stream.reserve_capacity(body.len());
    stream.send_data(Bytes::from(body.clone()), true).unwrap();
    let res = tokio::time::timeout(Duration::from_secs(10), resp)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(res.status(), 200);
    let (parts, _) = h2_get(&send, &h.https_url("/other"), &[]).await.unwrap();
    assert_eq!(parts.status, 200);
    let ev = h.wait_events("request", 2).await;
    let cap = flow_of(&ev, "/cap/one");
    let other = flow_of(&ev, "/other");
    let records = h.captured();
    let req = capture_of(&records, &cap, "request");
    assert_eq!(capture_body(&req), body);
    assert!(
        capture_of(&records, &cap, "response").is_empty(),
        "request only"
    );
    assert!(
        records.iter().all(|(h, _)| h["flow"] != other),
        "not selected"
    );
    h.stop().await;
}

/// Past `limits.max_capture_body_bytes` capture records `truncated` and the
/// end still carries the full forwarded byte count; forwarding is unaffected.
#[tokio::test(flavor = "multi_thread")]
async fn capture_cap_truncates_explicitly() {
    let h = Harness::start_with(Opts {
        rules: ALLOW_UPSTREAM,
        capture: Some("all: true"),
        limits: "max_capture_body_bytes: 1kb",
        ..Opts::default()
    })
    .await;
    let res = h
        .client()
        .post(h.http_url("/capped"))
        .body(vec![b'z'; 10_000])
        .send()
        .await
        .unwrap();
    assert_eq!(json(&res.bytes().await.unwrap())["body_len"], 10_000);
    let ev = h.wait_events("request", 1).await;
    let records = h.captured();
    let req = capture_of(&records, &flow_of(&ev, "/capped"), "request");
    assert_eq!(capture_body(&req).len(), 1024);
    let kinds: Vec<&str> = req
        .iter()
        .map(|(h, _)| h["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"truncated"), "{kinds:?}");
    assert_eq!(req.last().unwrap().0["bytes"], 10_000);
    h.stop().await;
}

/// The WebSocket relay is captured in both directions, byte for byte.
#[tokio::test(flavor = "multi_thread")]
async fn capture_websocket_relay() {
    let h = Harness::start_with(Opts {
        rules: r#"
  - id: ws
    when: host == "ws.test"
    then: [{ capture: both }, { allow: { upgrade: websocket, private_ok: true } }]
"#,
        capture: Some(""),
        ..Opts::default()
    })
    .await;
    let port = h.upstream.ws.port();
    let tls = h
        .tls_tunnel(&format!("ws.test:{port}"), "ws.test")
        .await
        .unwrap();
    let (mut ws, _) = tokio_tungstenite::client_async(format!("wss://ws.test:{port}/echo"), tls)
        .await
        .unwrap();
    ws.send(Message::text("captured hello")).await.unwrap();
    let back = ws.next().await.unwrap().unwrap();
    assert_eq!(back.into_text().unwrap().as_str(), "captured hello");
    ws.close(None).await.unwrap();
    drop(ws);
    let close = h.wait_events("ws_close", 1).await;
    let ev = h.wait_events("request", 1).await;
    let flow = ev[0]["flow"].as_str().unwrap().to_owned();
    let records = h.captured();
    let c2s = capture_of(&records, &flow, "request");
    let s2c = capture_of(&records, &flow, "response");
    assert_eq!(
        capture_body(&c2s).len() as u64,
        close[0]["bytes_c2s"].as_u64().unwrap()
    );
    assert_eq!(
        capture_body(&s2c).len() as u64,
        close[0]["bytes_s2c"].as_u64().unwrap()
    );
    // The server-to-client frame is unmasked: the text is visible.
    let down = String::from_utf8_lossy(&capture_body(&s2c)).into_owned();
    assert!(down.contains("captured hello"), "{down:?}");
    h.stop().await;
}

/// A capture destination that cannot keep up holds traffic back instead of
/// dropping captured bytes: `capture.rxc` is a FIFO whose reader does not
/// read until the test lets it.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_capture_log_holds_traffic() {
    use std::io::Read;
    let fifo_dir = tempfile::tempdir().unwrap();
    let fifo = fifo_dir.path().join("capture.rxc");
    let made = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(made.success(), "mkfifo");
    // The reader opens the FIFO (pairing with roxy's writer), then waits
    // for the go signal before draining it.
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    let (seen_tx, seen_rx) = std::sync::mpsc::channel::<usize>();
    std::thread::spawn(move || {
        let mut f = std::fs::File::open(&fifo).unwrap();
        go_rx.recv().unwrap();
        let mut buf = vec![0u8; 1 << 16];
        let mut total = 0usize;
        let mut reported = false;
        // Report once the whole upload has come through, then keep
        // draining until the writer closes (at shutdown).
        loop {
            match f.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => total += n,
            }
            if !reported && total > 1 << 20 {
                reported = true;
                let _ = seen_tx.send(total);
            }
        }
    });
    let h = Harness::start_with(Opts {
        rules: ALLOW_UPSTREAM,
        capture: Some("all: true\nhigh_water: 64kb"),
        capture_dir: Some(fifo_dir.path()),
        ..Opts::default()
    })
    .await;
    // 1 MiB: far more than the pipe buffer plus the high-water mark.
    let c = h.client();
    let url = h.http_url("/held");
    let req = tokio::spawn(async move {
        c.post(url)
            .body(vec![b'p'; 1 << 20])
            .send()
            .await
            .map(|r| r.status())
    });
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert!(
        !req.is_finished(),
        "traffic moved while capture was stalled"
    );
    go_tx.send(()).unwrap();
    let status = tokio::time::timeout(Duration::from_secs(20), req)
        .await
        .expect("traffic resumes once capture catches up")
        .unwrap()
        .unwrap();
    assert_eq!(status, 200);
    let seen = seen_rx
        .recv_timeout(Duration::from_secs(20))
        .expect("the whole upload was captured");
    assert!(seen > 1 << 20);
    h.stop().await;
}
