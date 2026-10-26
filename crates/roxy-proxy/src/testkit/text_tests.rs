//! Body text rules as the body streams: the bytes a test still waits on
//! are held back until it is decided, so a match never leaves roxy, and a
//! rule that fires mid-body stops the exchange there.

use std::time::Duration;

use bytes::Bytes;
use roxy_http::Body;

use super::{Answer, Client, Kit, streaming_body};

const RULES: &str = r#"
- id: no-secret
  when: host == "up.test" and body.text contains "SECRET"
  then: deny
- id: needs-marker
  when: host == "up.test" and path == "/marked" and not body.text contains "MARK"
  then: deny
- id: up
  when: host == "up.test"
  then: allow
"#;

async fn client(kit: &Kit, h2: bool) -> Client {
    if h2 {
        kit.tunnel("up.test", true).await
    } else {
        kit.h1().await
    }
}

/// The first request's body once the upstream has `n` bytes of it.
async fn upstream_body(kit: &Kit, n: usize) -> Vec<u8> {
    kit.upstream.wait_arrived(1).await;
    let wait = async {
        loop {
            let body = kit.upstream.seen()[0].body.clone();
            if body.len() >= n {
                return body;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(10), wait)
        .await
        .unwrap_or_else(|_| {
            panic!(
                "upstream: wanted {n} bytes, have {:#?}",
                kit.upstream.seen()
            )
        })
}

/// The bytes before a partial match go on as they arrive; the partial
/// match waits, and when the next chunk completes it the request is
/// denied with none of it sent.
async fn a_match_split_across_chunks_never_reaches_the_upstream(h2: bool) {
    let kit = Kit::builder().rules(RULES).start().await;
    let mut c = client(&kit, h2).await;
    let (mut tx, body) = streaming_body();
    let req = c.request("POST", "/x", &[]).body(body).unwrap();
    let answer = c.start(req);
    tx.send_data(Bytes::from_static(b"safe and SEC"))
        .await
        .unwrap();
    assert_eq!(upstream_body(&kit, 9).await, b"safe and ");
    tx.send_data(Bytes::from_static(b"RET and more"))
        .await
        .unwrap();
    let a = answer.await.unwrap().unwrap();
    assert_eq!(a.status, 403, "{a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "no-secret");
    let ev = kit.request_event().await;
    assert_eq!(ev["stage"], "request_body", "{ev:#}");
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].body, b"safe and ", "{seen:#?}");
    assert_eq!(seen[0].complete, Some(false), "{seen:#?}");
}

#[tokio::test]
async fn h1_a_match_split_across_chunks_never_reaches_the_upstream() {
    a_match_split_across_chunks_never_reaches_the_upstream(false).await;
}

#[tokio::test]
async fn h2_a_match_split_across_chunks_never_reaches_the_upstream() {
    a_match_split_across_chunks_never_reaches_the_upstream(true).await;
}

/// `not ... contains` is decided only at the end, so the end is held: the
/// last byte goes only once the body is known not to need the deny.
#[tokio::test]
async fn a_negated_test_holds_the_end_of_the_body() {
    for h2 in [false, true] {
        let kit = Kit::builder().rules(RULES).start().await;
        let mut c = client(&kit, h2).await;
        let (mut tx, body) = streaming_body();
        let req = c.request("POST", "/marked", &[]).body(body).unwrap();
        let answer = c.start(req);
        tx.send_data(Bytes::from_static(b"hello")).await.unwrap();
        assert_eq!(upstream_body(&kit, 4).await, b"hell");
        tx.finish().await.unwrap();
        let a = answer.await.unwrap().unwrap();
        assert_eq!(a.status, 403, "h2 {h2}: {a:?}");
        assert_eq!(a.headers["x-roxy-rule"], "needs-marker");
        let seen = kit.upstream.wait_seen(1).await;
        assert_eq!(seen[0].body, b"hell", "h2 {h2}: {seen:#?}");
        assert_eq!(seen[0].complete, Some(false), "h2 {h2}: {seen:#?}");
    }
    let kit = Kit::builder().rules(RULES).start().await;
    let a = kit
        .h1()
        .await
        .call("POST", "/marked", &[], b"hello MARK")
        .await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.json()["body_len"], 10);
}

/// A body rule's `quarantine` trips mid-body like its `deny`: the
/// matching chunk goes nowhere, and every exchange after it is refused.
#[tokio::test]
async fn a_body_rule_quarantines_mid_stream() {
    let dir = tempfile::tempdir().unwrap();
    let kit = Kit::builder()
        .rules(
            r#"
- id: trip
  when: host == "up.test" and body.text contains "exfil"
  then: quarantine
- id: up
  when: host == "up.test"
  then: allow
"#,
        )
        .quarantine_dir(dir.path())
        .start()
        .await;
    let mut c = kit.h1().await;
    let (mut tx, body) = streaming_body();
    let req = c.request("POST", "/upload", &[]).body(body).unwrap();
    let answer = c.start(req);
    tx.send_data(Bytes::from_static(b"first part, "))
        .await
        .unwrap();
    assert_eq!(upstream_body(&kit, 12).await, b"first part, ");
    tx.send_data(Bytes::from_static(b"then exfil"))
        .await
        .unwrap();
    let a = answer.await.unwrap().unwrap();
    assert_eq!(a.status, 403, "{a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "trip");
    let tripped = kit.events("quarantined", 1).await.remove(0);
    assert_eq!(tripped["cause"]["rule"], "trip", "{tripped:#}");
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].body, b"first part, ", "{seen:#?}");

    let a = kit.h1().await.call("GET", "/x", &[], b"").await;
    assert_eq!(a.status, 403, "{a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "_quarantined");
}

/// A response body rule reads the whole response: the client chooses a
/// range's bounds, so two ranges that each cut the needle would carry it
/// out in pieces past the rule. The request goes without `range` and
/// `if-range`, the in-flight rules see it without them (`saw-range` does
/// not fire), and a `206` that comes back anyway is refused.
#[tokio::test]
async fn a_response_body_rule_never_reads_a_range() {
    let kit = Kit::builder()
        .rules(
            r#"
- id: no-secret
  when: host == "up.test" and response.body.text contains "SECRET"
  then: deny
- id: saw-range
  when: host == "up.test" and header["range"] != null and response.status == 200
  then: deny
- id: up
  when: host == "up.test"
  then: allow
"#,
        )
        .start()
        .await;
    let mut c = kit.h1().await;
    let a = c
        .call(
            "GET",
            "/x",
            &[("range", "bytes=0-2"), ("if-range", "\"v1\"")],
            b"",
        )
        .await;
    assert_eq!(a.status, 200, "{a:?}");
    let seen = kit.upstream.wait_seen(1).await;
    assert!(
        !seen[0].headers.contains_key("range"),
        "{:?}",
        seen[0].headers
    );
    assert!(
        !seen[0].headers.contains_key("if-range"),
        "{:?}",
        seen[0].headers
    );
    let req = c
        .request("POST", "/echo", &[("x-echo-status", "206")])
        .body(Body::from_bytes(Bytes::from_static(b"[SEC")))
        .unwrap();
    let a = Answer::read(c.send(req).await.expect("response")).await;
    assert_eq!(a.status, 503, "{a:?}");
    let ev = kit.events("request", 2).await.remove(1);
    assert_eq!(ev["terminal_rule"], "_fail_closed", "{ev:#}");
    assert_eq!(ev["reason"], "partial_response", "{ev:#}");
}
