//! `respond`: a rule's fixed answer, sent without dialling the upstream,
//! and how it is logged, counted and recorded.

use bytes::Bytes;
use serde_json::Value;

use super::{AddonDef, Answer, Kit, sha256_hex, strs};

const BODY: &str = r#"{"access_token":"placeholder","expires_in":3600}"#;

const RULES: &str = r#"
- id: token
  when: host == "auth.test" and path == "/oauth/token"
  then:
    - digest: response
    - capture: response
    - respond:
        body: '{"access_token":"placeholder","expires_in":3600}'
        content_type: application/json
        headers: { x-stub: "yes" }
- id: token-close
  when: host == "auth.test" and path == "/close"
  then: { respond: { status: 503, body: "gone", close: true } }
- id: open
  when: host == "up.test" or header["x-allow"] == "1"
  then: allow
- id: block
  when: header["x-block"] == "1"
  then: deny
"#;

async fn kit() -> Kit {
    Kit::builder().rules(RULES).capture_selected().start().await
}

#[track_caller]
fn assert_the_answer(a: &Answer) {
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.headers["content-type"], "application/json");
    assert_eq!(a.headers["content-length"], BODY.len().to_string());
    assert_eq!(a.headers["cache-control"], "no-store");
    assert_eq!(a.headers["x-stub"], "yes");
    assert!(
        !a.headers.contains_key("x-roxy-rule"),
        "an answer is not a refusal: {a:?}"
    );
    assert_eq!(a.body.as_deref().unwrap(), BODY.as_bytes());
}

fn assert_answered_event(ev: &Value, rule: &str) {
    assert_eq!(ev["decision"], "answered", "{ev:#}");
    assert_eq!(ev["terminal_rule"], rule, "{ev:#}");
    assert_eq!(ev["stage"], "head", "{ev:#}");
    assert_eq!(strs(&ev["rules"]), [rule], "{ev:#}");
    assert!(ev["reason"].is_null(), "{ev:#}");
    assert!(ev["timing"]["upstream_connect_ms"].is_null(), "{ev:#}");
    assert!(ev["timing"]["upstream_ttfb_ms"].is_null(), "{ev:#}");
}

/// The answer as sent, on a connection that stays open for the next
/// request, and nothing dialled.
#[tokio::test]
async fn a_matching_request_gets_the_fixed_answer_and_nothing_is_dialled() {
    let kit = kit().await;
    let mut c = kit.http_client("auth.test").await;
    let a = c
        .call(
            "POST",
            "/oauth/token",
            &[],
            b"grant_type=client_credentials",
        )
        .await;
    assert_the_answer(&a);
    // `close` defaults to false: the same connection carries the next one.
    let a = c.call("POST", "/oauth/token", &[], b"again").await;
    assert_the_answer(&a);
    assert!(kit.upstream.seen().is_empty());
    assert_eq!(kit.upstream.open_connections(), 0);

    let ev = kit.events("request", 2).await;
    assert_answered_event(&ev[0], "token");
    assert_eq!(ev[0]["res"]["status"], 200, "{:#}", ev[0]);
    assert_eq!(ev[0]["res"]["body_bytes"], BODY.len(), "{:#}", ev[0]);
    assert_eq!(
        ev[0]["res"]["body_sha256"],
        sha256_hex(BODY.as_bytes()),
        "`digest: response` hashes the answer: {:#}",
        ev[0]
    );
    assert!(
        ev[0]["mutations"].as_array().unwrap().is_empty(),
        "{:#}",
        ev[0]
    );
}

/// Over HTTP/2 in a tunnel too.
#[tokio::test]
async fn an_answer_over_h2_dials_nothing() {
    let kit = kit().await;
    let mut c = kit.tunnel("auth.test", true).await;
    let a = c.call("POST", "/oauth/token", &[], b"x=1").await;
    assert_the_answer(&a);
    let a = c.call("GET", "/oauth/token", &[], b"").await;
    assert_the_answer(&a);
    assert!(kit.upstream.seen().is_empty());
    assert_eq!(kit.upstream.open_connections(), 0);
    let ev = kit.request_event().await;
    assert_answered_event(&ev, "token");
}

/// A request body is drained and discarded, so a keep-alive connection
/// carries the next request after it.
#[tokio::test]
async fn the_request_body_is_drained_and_the_connection_reused() {
    let kit = kit().await;
    let mut c = kit.http_client("auth.test").await;
    let req = c
        .request_to("auth.test", "POST", "/oauth/token", &[])
        .body(roxy_http::Body::from_bytes(Bytes::from(vec![
            b'b';
            200_000
        ])))
        .unwrap();
    let a = Answer::read(c.send(req).await.unwrap()).await;
    assert_the_answer(&a);
    let a = c.call("GET", "/oauth/token", &[], b"").await;
    assert_the_answer(&a);
    assert!(kit.upstream.seen().is_empty());
}

/// `close: true` ends the connection after the answer, unread body and
/// all.
#[tokio::test]
async fn close_ends_the_connection_after_the_answer() {
    let kit = kit().await;
    let (out, closed) = kit
        .raw_http(
            b"POST /close HTTP/1.1\r\nhost: auth.test\r\ncontent-length: 5\r\n\r\nhello\
              GET /oauth/token HTTP/1.1\r\nhost: auth.test\r\n\r\n",
        )
        .await;
    assert!(closed, "{out}");
    assert!(out.starts_with("HTTP/1.1 503 "), "{out}");
    assert!(out.contains("connection: close"), "{out}");
    assert!(
        out.ends_with("\r\n\r\ngone"),
        "the pipelined request is not answered: {out}"
    );
    let ev = kit.request_event().await;
    assert_answered_event(&ev, "token-close");
    assert_eq!(ev["res"]["status"], 503);
    assert!(kit.upstream.seen().is_empty());
}

/// An `Upgrade` request a respond rule matches gets the answer as an
/// ordinary response. Nothing was forwarded, so no upgrade was stripped.
#[tokio::test]
async fn an_upgrade_is_answered_without_upgrading() {
    let kit = kit().await;
    let (out, _) = kit
        .raw_http(
            b"GET /oauth/token HTTP/1.1\r\nhost: auth.test\r\nconnection: upgrade\r\n\
              upgrade: websocket\r\nsec-websocket-version: 13\r\n\
              sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
        )
        .await;
    assert!(out.starts_with("HTTP/1.1 200 "), "{out}");
    assert!(!out.to_ascii_lowercase().contains("upgrade:"), "{out}");
    assert!(out.ends_with(BODY), "{out}");
    let ev = kit.request_event().await;
    assert_answered_event(&ev, "token");
    assert!(
        kit.sink
            .events()
            .iter()
            .all(|e| e["event"] != "upgrade_stripped"),
        "{:#?}",
        kit.sink.events()
    );
    assert!(kit.upstream.seen().is_empty());
}

/// Deny wins over respond; respond beside allow fails closed.
#[tokio::test]
async fn deny_wins_and_respond_beside_allow_fails_closed() {
    let kit = kit().await;
    let mut c = kit.http_client("auth.test").await;
    let a = c
        .call("POST", "/oauth/token", &[("x-block", "1")], b"")
        .await;
    assert_eq!(a.status, 403, "{a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "block");
    let ev = kit.events("request", 1).await;
    assert_eq!(ev[0]["decision"], "deny", "{:#}", ev[0]);

    let mut c = kit.http_client("auth.test").await;
    let a = c
        .call("POST", "/oauth/token", &[("x-allow", "1")], b"")
        .await;
    assert_eq!(a.status, 503, "{a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "_fail_closed");
    let ev = kit.events("request", 2).await;
    assert_eq!(ev[1]["decision"], "deny", "{:#}", ev[1]);
    assert_eq!(ev[1]["terminal_rule"], "_fail_closed", "{:#}", ev[1]);
    assert_eq!(ev[1]["reason"], "terminal_conflict", "{:#}", ev[1]);
    // The policy contradicts itself; no input was unavailable.
    assert!(
        kit.sink
            .events()
            .iter()
            .all(|e| e["event"] != "policy_input_unavailable"),
        "{:#?}",
        kit.sink.events()
    );
    assert!(kit.upstream.seen().is_empty());
}

/// An answer counts as a request and not as a denial or an error.
#[tokio::test]
async fn an_answer_counts_as_a_request_not_a_denial() {
    let kit = Kit::builder()
        .rules(
            r#"
- id: token
  when: host == "auth.test"
  then: { respond: { body: ok } }
- id: denials
  when: host == "up.test" and (metric.denied_total >= 1 or metric.errors_total >= 1)
  then: deny
- id: after-one
  when: host == "up.test" and metric.requests_total >= 1
  then: allow
"#,
        )
        .metric_defs(
            r"
- { id: requests_total, count: requests }
- { id: denied_total, count: denied }
- { id: errors_total, count: errors }
",
        )
        .start()
        .await;
    let a = kit
        .http_client("auth.test")
        .await
        .call("GET", "/", &[], b"")
        .await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.body.as_deref().unwrap(), b"ok");
    kit.events("request", 1).await;
    // One request counted, no denial: `after-one` allows, `denials` does not.
    let a = kit.h1().await.call("GET", "/up", &[], b"").await;
    assert_eq!(a.status, 200, "{a:?}");
    let ev = kit.events("request", 2).await;
    assert_eq!(ev[1]["terminal_rule"], "after-one", "{:#}", ev[1]);
}

/// `capture: response` records the answer as sent, and nothing of the
/// request, which was never forwarded.
#[tokio::test]
async fn capture_records_the_answer() {
    let kit = kit().await;
    let a = kit
        .http_client("auth.test")
        .await
        .call("POST", "/oauth/token", &[], b"secret-form")
        .await;
    assert_the_answer(&a);
    let ev = kit.request_event().await;
    let flow = ev["flow"].as_str().unwrap();
    let records = kit.captured();
    let ours: Vec<_> = records.iter().filter(|(h, _)| h["flow"] == flow).collect();
    assert!(
        ours.iter().all(|(h, _)| h["dir"] == "response"),
        "{ours:#?}"
    );
    let kinds: Vec<&str> = ours
        .iter()
        .map(|(h, _)| h["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["head", "data", "end"], "{ours:#?}");
    let head: Value = serde_json::from_slice(&ours[0].1).unwrap();
    assert_eq!(head["status"], 200, "{head:#}");
    assert_eq!(ours[1].1, BODY.as_bytes());
    assert!(ours[2].0["aborted"].is_null(), "{ours:#?}");
}

/// Through an addon stack the answer passes back up the layers like a
/// response, and `close` still ends the connection.
#[tokio::test]
async fn an_answer_passes_through_the_addon_stack() {
    let kit = Kit::builder()
        .rules(RULES)
        .addon(AddonDef::test_layer("a"))
        .capture_selected()
        .start()
        .await;
    let mut c = kit.http_client("auth.test").await;
    let a = c
        .call("POST", "/oauth/token", &[("x-test-a", "pass")], b"x")
        .await;
    // The layer streams the body on, so it is framed as any response the
    // stack passes back; the rest is the answer as the rule wrote it.
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.headers["content-type"], "application/json");
    assert_eq!(a.headers["cache-control"], "no-store");
    assert_eq!(a.headers["x-stub"], "yes");
    assert!(!a.headers.contains_key("x-roxy-rule"), "{a:?}");
    assert_eq!(a.body.as_deref().unwrap(), BODY.as_bytes());
    let ev = kit.request_event().await;
    assert_answered_event(&ev, "token");
    assert_eq!(strs(&ev["addons"]), ["a"], "{ev:#}");

    let (out, closed) = kit
        .raw_http(b"GET /close HTTP/1.1\r\nhost: auth.test\r\nx-test-a: pass\r\n\r\n")
        .await;
    assert!(closed, "{out}");
    assert!(out.starts_with("HTTP/1.1 503 "), "{out}");
    assert!(kit.upstream.seen().is_empty());
}
