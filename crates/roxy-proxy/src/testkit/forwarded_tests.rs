//! `forwarded_for` on an `http` listener: the client is the entry
//! `trusted_hops` from the right of `X-Forwarded-For`, resolved per
//! request, and a header that does not name it refuses the request.

use super::{Answer, Client, Kit};

/// The kit's gateway clients connect from this peer: with `forwarded_for`
/// it plays the load balancer.
const LB: &str = "192.0.2.7";

/// Denies one client by its resolved address, and allows `up.test` only
/// for connections that came through the load balancer.
const RULES: &str = r#"
- id: banned
  when: client.ip == 198.51.100.1
  then: deny
- id: up
  when: host == "up.test" and client.peer_ip == 192.0.2.7
  then: allow
"#;

/// `GET /` on `c` with one `x-forwarded-for` line per entry of `xff`.
async fn get(c: &mut Client, xff: &[&str]) -> Answer {
    let headers: Vec<(&str, &str)> = xff.iter().map(|v| ("x-forwarded-for", *v)).collect();
    c.call("GET", "/", &headers, b"").await
}

/// With one trusted hop the client is the rightmost entry: what it wrote
/// itself sits to the left and is never read. Each request on a kept-alive
/// connection is resolved on its own, and the header goes upstream as
/// received.
#[tokio::test]
async fn the_client_is_the_trusted_hop_resolved_per_request() {
    let kit = Kit::builder().forwarded_for(1).rules(RULES).start().await;
    let mut c = kit.http_client("up.test").await;
    let a = get(&mut c, &["198.51.100.1, 203.0.113.9"]).await;
    assert_eq!(
        a.status, 200,
        "the banned address is client-supplied: {a:?}"
    );
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(
        seen[0].headers["x-forwarded-for"],
        "198.51.100.1, 203.0.113.9"
    );

    let a = get(&mut c, &["203.0.113.9, 198.51.100.1"]).await;
    assert_eq!(a.status, 403, "{a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "banned");

    let ev = kit.events("request", 2).await;
    assert_eq!(ev[0]["client"]["ip"], "203.0.113.9", "{:#}", ev[0]);
    assert_eq!(ev[0]["client"]["peer_ip"], LB);
    assert_eq!(ev[0]["client"]["port"], 40000);
    assert_eq!(ev[1]["client"]["ip"], "198.51.100.1", "{:#}", ev[1]);
    assert_eq!(ev[1]["client"]["peer_ip"], LB);
}

/// Two trusted hops: the client is the second entry from the right, with
/// every `X-Forwarded-For` line joined in order; a bare IPv6 address is a
/// client like any other; one entry is a hop short.
#[tokio::test]
async fn hops_count_from_the_right_across_header_lines() {
    let kit = Kit::builder().forwarded_for(2).rules(RULES).start().await;
    let mut c = kit.http_client("up.test").await;
    let a = get(&mut c, &["198.51.100.1, 203.0.113.9", "10.0.0.1"]).await;
    assert_eq!(a.status, 200, "{a:?}");
    let a = get(&mut c, &["2001:db8::1, 10.0.0.1"]).await;
    assert_eq!(a.status, 200, "{a:?}");
    let ev = kit.events("request", 2).await;
    assert_eq!(ev[0]["client"]["ip"], "203.0.113.9", "{:#}", ev[0]);
    assert_eq!(ev[1]["client"]["ip"], "2001:db8::1", "{:#}", ev[1]);

    let (out, eof) = kit
        .raw_http(b"GET / HTTP/1.1\r\nhost: up.test\r\nx-forwarded-for: 203.0.113.9\r\n\r\n")
        .await;
    assert!(eof);
    assert!(out.starts_with("HTTP/1.1 400"), "{out}");
    assert!(
        out.contains("\"reason\":\"forwarded_for_invalid\""),
        "{out}"
    );
    assert_eq!(kit.upstream.seen().len(), 2);
}

/// A header that does not account for the trusted hop, or whose trusted
/// entry is not a bare address, is a request from nobody: refused before
/// any rule, never attributed to the peer.
#[tokio::test]
async fn a_header_that_does_not_name_the_client_is_refused() {
    let kit = Kit::builder().forwarded_for(1).rules(RULES).start().await;
    let cases = [
        "",
        "x-forwarded-for: unknown\r\n",
        "x-forwarded-for: 203.0.113.9:443\r\n",
        "x-forwarded-for: [2001:db8::1]\r\n",
        "x-forwarded-for: 203.0.113.9,\r\n",
    ];
    for extra in cases {
        let raw = format!("GET / HTTP/1.1\r\nhost: up.test\r\n{extra}\r\n");
        let (out, eof) = kit.raw_http(raw.as_bytes()).await;
        assert!(eof, "{extra:?}");
        assert!(out.starts_with("HTTP/1.1 400"), "{extra:?}: {out}");
        assert!(
            out.contains("\"reason\":\"forwarded_for_invalid\""),
            "{extra:?}: {out}"
        );
    }
    let ev = kit.events("parse_error", cases.len()).await;
    for e in &ev {
        assert_eq!(e["reason"], "forwarded_for_invalid", "{e:#}");
        assert_eq!(e["client"]["ip"], LB, "{e:#}");
        assert_eq!(e["client"]["peer_ip"], LB, "{e:#}");
    }
    assert!(kit.upstream.seen().is_empty());
    assert!(
        kit.sink.events().iter().all(|e| e["event"] != "request"),
        "no exchange starts for a request from nobody"
    );
}

/// A metric keyed on `client.ip` keys on the resolved client: two clients
/// behind one load balancer have separate series.
#[tokio::test]
async fn rate_limits_key_on_the_resolved_client() {
    const LIMIT: &str = r#"
- id: limit
  when: metric.per_client >= 1
  then: deny
- id: up
  when: host == "up.test"
  then: allow
"#;
    let kit = Kit::builder()
        .forwarded_for(1)
        .rules(LIMIT)
        .metric_defs("- { id: per_client, count: requests, key: [client.ip], window: 1m }")
        .start()
        .await;
    let a = get(&mut kit.http_client("up.test").await, &["203.0.113.9"]).await;
    assert_eq!(a.status, 200, "{a:?}");
    let a = get(&mut kit.http_client("up.test").await, &["203.0.113.9"]).await;
    assert_eq!(a.status, 403, "{a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "limit");
    let a = get(&mut kit.http_client("up.test").await, &["203.0.113.10"]).await;
    assert_eq!(a.status, 200, "another client from the same peer: {a:?}");
}

/// Without `forwarded_for` the header is ignored, as a client could have
/// written it, and still forwarded as received.
#[tokio::test]
async fn without_forwarded_for_the_header_is_ignored() {
    let kit = Kit::builder().rules(RULES).start().await;
    let mut c = kit.http_client("up.test").await;
    let a = get(&mut c, &["198.51.100.1"]).await;
    assert_eq!(a.status, 200, "{a:?}");
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].headers["x-forwarded-for"], "198.51.100.1");
    let ev = kit.request_event().await;
    assert_eq!(ev["client"]["ip"], LB, "{ev:#}");
    assert_eq!(ev["client"]["peer_ip"], LB);
}
