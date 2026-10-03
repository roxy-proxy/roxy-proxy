//! End-to-end tests of `roxy run`: a real server from a YAML config, a local
//! TLS upstream signed by a test CA, and real clients.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use roxy_proxy::{MetricSource, MetricSourceError, Sample};
use roxy_rules::{FlowView, Phase};

use bytes::Bytes;
use futures_util::{SinkExt as _, StreamExt as _};
use serde_json::Value;
use support::{Harness, Opts, SECRET, fnv, raw, read_head, read_response, read_to_eof};
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
async fn redirect_changes_target_and_reruns_connect_phase() {
    let h = Harness::start(
        r#"
  - id: no-blocked
    phase: connect
    when: dst.host == "blocked.test"
    then: deny
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
  - id: alias-blocked
    when: host == "evil.test"
    then:
      - redirect: { host: blocked.test, port: {HTTP} }
      - allow: { private_ok: true }
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
    let res = c.get("http://evil.test:1234/c").send().await.unwrap();
    assert_eq!(res.status(), 403);
    assert_eq!(res.headers()["x-roxy-rule"], "no-blocked");
    assert_eq!(h.upstream.seen().len(), 2);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn large_uploads_stream_intact() {
    let h = Harness::start(ALLOW_UPSTREAM).await;
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
async fn connect_phase_deny() {
    let h = Harness::start(
        r#"
  - id: no-blocked
    phase: connect
    when: dst.host == "blocked.test"
    then: deny
"#,
    )
    .await;
    let (out, eof) = raw(
        h.proxy,
        b"CONNECT blocked.test:443 HTTP/1.1\r\nHost: blocked.test:443\r\n\r\n",
    )
    .await;
    assert!(eof);
    assert!(out.starts_with("HTTP/1.1 403"), "{out}");
    assert!(out.contains("x-roxy-rule: no-blocked"), "{out}");
    let ev = h.wait_events("connect", 1).await;
    assert_eq!(ev[0]["decision"], "deny");
    assert_eq!(ev[0]["dst"]["host"], "blocked.test");
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
    let ev = h.wait_events("request", 3).await;
    assert_eq!(ev[2]["reason"], "body_too_large_to_inspect");
    assert_eq!(h.events("policy_input_unavailable").len(), 1);
    assert_eq!(h.upstream.seen().len(), 1);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn response_rule_replaces_upstream_5xx() {
    let h = Harness::start(&format!(
        r#"{ALLOW_UPSTREAM}
  - id: hide-5xx
    phase: response
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

    fn record(
        &self,
        _phase: Phase,
        _view: &dyn FlowView,
        _sample: &Sample,
    ) -> Result<(), MetricSourceError> {
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
        assert_eq!(ev[usize::from(mode)]["reason"], reason, "mode {mode}");
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
