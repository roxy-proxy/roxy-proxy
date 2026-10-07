//! The `http` listener: origin-form requests spoken to roxy as the server,
//! each to the host its `Host` names.

use tokio::io::AsyncWriteExt as _;

use super::{Answer, Kit};

const SECRET: &str = "sk-ant-gateway-secret-0123456789";

/// A gateway policy: `anthropic.gw.test` goes to `up.test` over TLS with
/// the real key injected; `up.test` is reachable as itself.
const GATEWAY: &str = r#"
- id: anthropic
  when: listener.name == "gateway" and host == "anthropic.gw.test" and path starts_with "/v1/"
  then:
    - redirect: { host: up.test, port: 443, scheme: https, rewrite_host: true }
    - set_header: { x-api-key: "${secret:anthropic}" }
    - allow
- id: up
  when: host == "up.test"
  then: allow
"#;

/// `GET path` on a fresh connection to the `http` listener, with `Host:
/// <host>`.
async fn get(kit: &Kit, host: &str, path: &str) -> Answer {
    let mut c = kit.http_client(host).await;
    let req = c
        .request_to(host, "GET", path, &[])
        .body(roxy_http::Body::empty())
        .unwrap();
    Answer::read(c.send(req).await.unwrap()).await
}

#[tokio::test]
async fn an_allowed_request_reaches_the_host_upstream() {
    let kit = Kit::builder().start().await;
    let a = get(&kit, "up.test", "/plain").await;
    assert_eq!(a.status, 200, "{a:?}");
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].addr.port(), 80, "scheme http, port from Host");
    assert_eq!(seen[0].path, "/plain");
    assert_eq!(seen[0].headers["host"], "up.test");
    let ev = kit.request_event().await;
    assert_eq!(ev["listener"], "gateway");
    assert_eq!(ev["req"]["host"], "up.test");
    assert_eq!(ev["req"]["port"], 80);
    assert!(ev["tls"].is_null(), "{ev:#}");
}

#[tokio::test]
async fn a_redirect_rule_reaches_its_target_with_the_injected_key() {
    let kit = Kit::builder()
        .secret("anthropic", SECRET)
        .rules(GATEWAY)
        .start()
        .await;
    let a = get(&kit, "anthropic.gw.test", "/v1/messages").await;
    assert_eq!(a.status, 200, "{a:?}");
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(
        seen[0].addr.port(),
        443,
        "redirect sets https on the way out"
    );
    assert_eq!(seen[0].headers["host"], "up.test");
    assert_eq!(seen[0].headers["x-api-key"], SECRET);
    let ev = kit.request_event().await;
    assert_eq!(ev["terminal_rule"], "anthropic");
    let all = serde_json::to_string(&kit.sink.events()).unwrap();
    assert!(!all.contains(SECRET), "secret leaked into the flow log");

    // Outside the gateway rule's path the default deny governs.
    let a = get(&kit, "anthropic.gw.test", "/other").await;
    assert_eq!(a.status, 403, "{a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "_default");
    assert_eq!(kit.upstream.seen().len(), 1);
}

/// `roxy.internal` is an HTTP-proxy convenience; on an `http` listener it
/// is a host like any other, and the rules deny it.
#[tokio::test]
async fn roxy_internal_is_not_served() {
    let kit = Kit::builder().start().await;
    let a = get(&kit, crate::conn::INTERNAL_HOST, "/roxy-ca.pem").await;
    assert_eq!(a.status, 403, "{a:?}");
    assert!(!a.text().contains("BEGIN CERTIFICATE"));
}

#[tokio::test]
async fn other_target_forms_and_bad_hosts_are_refused() {
    let kit = Kit::builder().start().await;
    let cases: [(&[u8], &str); 5] = [
        (
            b"GET http://up.test/ HTTP/1.1\r\nhost: up.test\r\n\r\n",
            "target_form_mismatch",
        ),
        (
            b"CONNECT up.test:443 HTTP/1.1\r\nhost: up.test:443\r\n\r\n",
            "target_form_mismatch",
        ),
        (b"GET / HTTP/1.1\r\n\r\n", "missing_host"),
        (b"GET / HTTP/1.1\r\nhost: up test\r\n\r\n", "bad_authority"),
        (
            b"GET / HTTP/1.1\r\nhost: up.test\r\nhost: other.test\r\n\r\n",
            "multiple_host",
        ),
    ];
    for (raw, _) in &cases {
        let (out, eof) = kit.raw_http(raw).await;
        assert!(eof, "{}", String::from_utf8_lossy(raw));
        assert!(out.starts_with("HTTP/1.1 400"), "{out}");
    }
    let ev = kit.events("parse_error", cases.len()).await;
    let reasons: Vec<&str> = ev.iter().map(|e| e["reason"].as_str().unwrap()).collect();
    let expected: Vec<&str> = cases.iter().map(|(_, r)| *r).collect();
    assert_eq!(reasons, expected);
    assert!(ev.iter().all(|e| e["listener"] == "gateway"), "{ev:#?}");
    assert!(kit.upstream.seen().is_empty());
}

/// One protocol per listener: a TLS handshake is closed before any of it
/// is read as HTTP.
#[tokio::test]
async fn a_tls_client_hello_is_closed() {
    let kit = Kit::builder().start().await;
    let io = kit.connect_http();
    let r = kit.tls_connect(io, "up.test", &[b"http/1.1"]).await;
    assert!(r.is_err(), "TLS must not complete on an http listener");
    let ev = kit.events("parse_error", 1).await;
    assert_eq!(ev[0]["reason"], "tls_on_http_listener");

    // Nothing is written back: an HTTP error would be garbage to the client.
    let mut io = kit.connect_http();
    io.write_all(b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03")
        .await
        .unwrap();
    let (out, eof) = super::read_to_eof(&mut io).await;
    assert!(eof);
    assert!(out.is_empty(), "{out:?}");
    assert_eq!(kit.events("parse_error", 2).await.len(), 2);
}

#[tokio::test]
async fn two_hosts_on_one_keep_alive_connection_are_two_exchanges() {
    let kit = Kit::builder()
        .rules(
            r#"
- id: up
  when: host == "up.test"
  then: allow
- id: alias
  when: host == "alias.test"
  then:
    - redirect: { host: up.test, port: 80, scheme: http }
    - allow
"#,
        )
        .start()
        .await;
    let mut c = kit.http_client("up.test").await;
    for (host, path) in [("up.test", "/first"), ("alias.test", "/second")] {
        let req = http::Request::builder()
            .method("GET")
            .uri(path)
            .header("host", host)
            .body(roxy_http::Body::empty())
            .unwrap();
        let a = Answer::read(c.send(req).await.unwrap()).await;
        assert_eq!(a.status, 200, "{host}{path}: {a:?}");
    }
    let seen = kit.upstream.wait_seen(2).await;
    assert_eq!(seen[0].headers["host"], "up.test");
    assert_eq!(seen[0].path, "/first");
    assert_eq!(seen[1].headers["host"], "alias.test");
    assert_eq!(seen[1].path, "/second");
    let ev = kit.events("request", 2).await;
    assert_eq!(ev[0]["conn"], ev[1]["conn"], "one connection");
    assert_ne!(ev[0]["flow"], ev[1]["flow"], "two exchanges");
    assert_eq!(ev[0]["req"]["host"], "up.test");
    assert_eq!(ev[1]["req"]["host"], "alias.test");
    assert_eq!(ev[1]["terminal_rule"], "alias");
}
