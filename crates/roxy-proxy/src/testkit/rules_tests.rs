//! Rule effects and policy inputs as an exchange sees them: header and
//! path changes, redirects, body inspection, response rules, address lists
//! and metrics.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use bytes::Bytes;

use super::{Answer, Kit, UP_IP, streaming_body};
use crate::sources::{MetricSource, MetricSourceError, Sample};

const SECRET: &str = "s3cr3t-token-value-0123456789";

/// A request to `host` on a fresh h1 client (a refusal closes the
/// connection).
async fn get(kit: &Kit, host: &str, path: &str) -> Answer {
    let mut c = kit.h1().await;
    let req = c
        .request_to(host, "GET", path, &[])
        .body(roxy_http::Body::empty())
        .unwrap();
    Answer::read(c.send(req).await.unwrap()).await
}

#[tokio::test]
async fn set_header_injects_a_secret_without_logging_it() {
    let kit = Kit::builder()
        .secret("token", SECRET)
        .rules(
            r#"
- id: inject
  when: host == "up.test"
  then:
    - set_header: { authorization: "Bearer ${secret:token}", x-extra: "yes" }
    - remove_header: [x-remove-me]
    - log: { level: info, message: "injected" }
    - allow
"#,
        )
        .start()
        .await;
    let a = kit
        .h1()
        .await
        .call(
            "GET",
            "/inject",
            &[
                ("authorization", "Bearer placeholder"),
                ("x-remove-me", "1"),
                ("x-keep-me", "2"),
            ],
            b"",
        )
        .await;
    assert_eq!(a.status, 200, "{a:?}");
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].headers["authorization"], format!("Bearer {SECRET}"));
    assert_eq!(seen[0].headers["x-extra"], "yes");
    assert_eq!(seen[0].headers["x-keep-me"], "2");
    assert!(!seen[0].headers.contains_key("x-remove-me"));
    let ev = kit.request_event().await;
    let muts = ev["mutations"].as_array().unwrap();
    assert!(muts.contains(&"set_header:authorization".into()), "{ev:#}");
    assert!(muts.contains(&"remove_header:x-remove-me".into()), "{ev:#}");
    assert_eq!(kit.events("log", 1).await.len(), 1);
    let all = serde_json::to_string(&kit.sink.events()).unwrap();
    assert!(!all.contains(SECRET), "secret leaked into the flow log");
}

/// A secret swap takes effect on the next request without rebuilding the
/// snapshot, and the redactor scrubs the replaced value for an exchange
/// that was in flight across the swap as well as the new one.
#[tokio::test]
async fn swapped_secrets_reach_the_next_request_without_a_rebuild() {
    const OLD: &str = "old-token-value-abcdefghij";
    const NEW: &str = "new-token-value-0123456789";
    let kit = Kit::builder()
        .secret("token", OLD)
        .rules(
            r#"
- id: inject
  when: host == "up.test"
  then:
    - set_header: { authorization: "Bearer ${secret:token}" }
    - allow
"#,
        )
        .start()
        .await;
    let before = kit.server.shared().snapshot();

    // Request 1 is decided (OLD injected) and reaches the upstream, then
    // waits on its body; its request event is only logged once it ends.
    let mut c = kit.h1().await;
    let (tx, body) = streaming_body();
    let req = c
        .request("POST", &format!("/p/{OLD}"), &[])
        .body(body)
        .unwrap();
    let pending = c.start(req);
    let seen = kit.wait_arrived(1).await;
    assert_eq!(seen[0].headers["authorization"], format!("Bearer {OLD}"));

    kit.server
        .handle()
        .swap_secrets([("token".to_owned(), NEW.to_owned())].into());
    tx.finish().await.unwrap();
    let a = pending.await.unwrap().unwrap();
    assert_eq!(a.status, 200, "{a:?}");

    let a = get(&kit, "up.test", &format!("/p/{NEW}")).await;
    assert_eq!(a.status, 200, "{a:?}");
    let seen = kit.upstream.wait_seen(2).await;
    assert_eq!(seen[1].headers["authorization"], format!("Bearer {NEW}"));

    let after = kit.server.shared().snapshot();
    assert!(
        Arc::ptr_eq(&before, &after),
        "a secret swap must not rebuild the snapshot"
    );
    let events = kit.events("request", 2).await;
    let paths: Vec<&str> = events
        .iter()
        .map(|e| e["req"]["path"].as_str().unwrap())
        .collect();
    assert_eq!(paths, ["/p/[REDACTED]", "/p/[REDACTED]"], "{events:#?}");
    let all = serde_json::to_string(&kit.sink.events()).unwrap();
    assert!(
        !all.contains(OLD) && !all.contains(NEW),
        "secret leaked into the flow log"
    );
}

/// An exchange redacts with the secret generation it was evaluated under,
/// so a value it injected is scrubbed from its record even when it ends
/// after several swaps.
#[tokio::test]
async fn an_exchange_spanning_two_swaps_still_redacts_the_value_it_injected() {
    const GEN1: &str = "token-generation-one-abcdef";
    const GEN2: &str = "token-generation-two-ghijkl";
    const GEN3: &str = "token-generation-three-mnop";
    let kit = Kit::builder()
        .secret("token", GEN1)
        .rules(
            r#"
- id: inject
  when: host == "up.test"
  then:
    - set_header: { authorization: "Bearer ${secret:token}" }
    - allow
"#,
        )
        .start()
        .await;
    let mut c = kit.h1().await;
    let (tx, body) = streaming_body();
    let req = c
        .request("POST", &format!("/p/{GEN1}"), &[])
        .body(body)
        .unwrap();
    let pending = c.start(req);
    let seen = kit.wait_arrived(1).await;
    assert_eq!(seen[0].headers["authorization"], format!("Bearer {GEN1}"));

    let swap = |v: &str| {
        kit.server
            .handle()
            .swap_secrets([("token".to_owned(), v.to_owned())].into());
    };
    swap(GEN2);
    swap(GEN3);
    tx.finish().await.unwrap();
    let a = pending.await.unwrap().unwrap();
    assert_eq!(a.status, 200, "{a:?}");

    let ev = kit.request_event().await;
    assert_eq!(ev["req"]["path"], "/p/[REDACTED]", "{ev:#}");
}

#[tokio::test]
async fn rewrite_path_and_query_change_what_leaves() {
    let kit = Kit::builder()
        .rules(
            r#"
- id: rw
  when: host == "up.test" and path starts_with "/old/"
  then:
    - rewrite_path: { match: "/old/(.*)", to: "/new/$1" }
    - set_query: { k: "v w" }
    - remove_query: [drop]
    - allow
"#,
        )
        .start()
        .await;
    let a = kit
        .h1()
        .await
        .call("GET", "/old/thing?drop=1&keep=2", &[], b"")
        .await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.json()["path"], "/new/thing?keep=2&k=v%20w");
}

/// A `redirect` changes the target (rewriting `Host` only when asked), and
/// the new address goes through the floor like any other.
#[tokio::test]
async fn a_redirect_changes_the_target_and_the_new_address_is_checked() {
    let kit = Kit::builder()
        .rules(
            r#"
- id: alias-rewrite
  when: host == "alias.test"
  then:
    - redirect: { host: up.test, port: 443, scheme: https, rewrite_host: true }
    - allow
- id: alias-keep
  when: host == "keep.test"
  then:
    - redirect: { host: up.test, port: 443, scheme: https }
    - allow
- id: alias-private
  when: host == "evil.test"
  then:
    - redirect: { host: private.test, port: 443, scheme: https }
    - allow
"#,
        )
        .start()
        .await;
    let a = get(&kit, "alias.test", "/a").await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.json()["host"], "up.test");
    let a = get(&kit, "keep.test", "/b").await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.json()["host"], "keep.test");
    let a = get(&kit, "evil.test", "/c").await;
    assert_eq!(a.status, 403, "{a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "_address_policy");
    assert_eq!(kit.upstream.wait_seen(2).await.len(), 2);
}

/// A body rule denies what it matches, and a body over
/// `max_inspect_body_bytes` fails closed instead of going unread.
#[tokio::test]
async fn body_inspection_denies_and_fails_closed_when_too_large() {
    let kit = Kit::builder()
        .rules(
            r#"
- id: no-forbidden-body
  when: host == "up.test" and body.text contains "forbidden-word"
  then: deny
- id: up
  when: host == "up.test"
  then: allow
"#,
        )
        .limits(|l| l.max_inspect_body_bytes = 1024)
        .start()
        .await;
    let a = kit
        .h1()
        .await
        .call("POST", "/b", &[], b"this has a forbidden-word in it")
        .await;
    assert_eq!(a.status, 403, "{a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "no-forbidden-body");
    let a = kit
        .h1()
        .await
        .call("POST", "/b", &[], b"perfectly fine")
        .await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.json()["body_len"], 14);
    let mut c = kit.h1().await;
    let req = c
        .request("POST", "/b", &[])
        .body(roxy_http::Body::from_bytes(Bytes::from(vec![b'a'; 4096])))
        .unwrap();
    let a = Answer::read(c.send(req).await.unwrap()).await;
    assert_eq!(a.status, 503, "{a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "_fail_closed");
    let ev = kit.events("request", 3).await;
    let failed = ev
        .iter()
        .find(|e| e["res"]["status"] == 503)
        .unwrap_or_else(|| panic!("{ev:#?}"));
    assert_eq!(failed["reason"], "body_too_large_to_inspect");
    assert_eq!(kit.events("policy_input_unavailable", 1).await.len(), 1);
    assert_eq!(kit.upstream.seen().len(), 1);
}

#[tokio::test]
async fn a_response_rule_replaces_an_upstream_5xx() {
    let kit = Kit::builder()
        .rules(
            r#"
- id: up
  when: host == "up.test"
  then: allow
- id: hide-5xx
  when: response.status >= 500
  then: { deny: { status: 502, message: "upstream failure hidden" } }
"#,
        )
        .start()
        .await;
    let a = kit
        .h1()
        .await
        .call("POST", "/echo", &[("x-echo-status", "500")], b"exploded")
        .await;
    assert_eq!(a.status, 502, "{a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "hide-5xx");
    assert!(!a.text().contains("exploded"), "{a:?}");
    assert_eq!(a.json()["error"], "upstream failure hidden");
    let ev = kit.request_event().await;
    assert_eq!(ev["decision"], "deny", "{ev:#}");
    assert_eq!(ev["stage"], "response_head");
    assert_eq!(ev["terminal_rule"], "hide-5xx");
}

// ---- the address floor and address lists ----------------------------------

/// Without `private_ok` the floor refuses a private address however it is
/// written: by name, as an IPv4 literal, or as an IPv4-mapped IPv6 one.
#[tokio::test]
async fn the_floor_refuses_private_addresses_written_any_way() {
    let kit = Kit::builder()
        .rules("- id: any\n  when: port in [80, 443]\n  then: allow\n")
        .start()
        .await;
    for host in ["private.test", "10.0.0.5", "[::ffff:10.0.0.5]"] {
        let a = get(&kit, host, "/").await;
        assert_eq!(a.status, 403, "{host}: {a:?}");
        assert_eq!(a.headers["x-roxy-rule"], "_address_policy", "{host}");
    }
    let ev = kit.events("upstream_denied", 3).await;
    assert!(
        ev.iter().all(|e| e["reason"] == "private_range:private"),
        "{ev:#?}"
    );
    assert!(ev.iter().all(|e| e["resolved_ip"] == "10.0.0.5"), "{ev:#?}");
    assert!(kit.upstream.seen().is_empty());
}

/// `upstream.deny_lists` is a hard floor: a hit denies with
/// `_address_policy` and an `upstream_denied` event naming the list, and
/// `private_ok` does not bypass it, for names, IP literals (also written as
/// IPv4-mapped IPv6) and tunnelled requests alike.
#[tokio::test]
async fn a_deny_list_is_a_floor_private_ok_does_not_bypass() {
    let kit = Kit::builder()
        .rules("- id: any\n  when: port in [80, 443]\n  then: { allow: { private_ok: true } }\n")
        .address_list("blocked", &format!("192.0.2.0/24\n{UP_IP}\n"))
        .deny_lists(&["blocked"])
        .start()
        .await;
    let mapped = format!("[::ffff:{UP_IP}]");
    for host in ["up.test", UP_IP, mapped.as_str()] {
        let a = get(&kit, host, "/").await;
        assert_eq!(a.status, 403, "{host}: {a:?}");
        assert_eq!(a.headers["x-roxy-rule"], "_address_policy", "{host}");
    }
    let a = kit
        .tunnel("up.test", true)
        .await
        .call("GET", "/d", &[], b"")
        .await;
    assert_eq!(a.status, 403, "{a:?}");
    let ev = kit.events("upstream_denied", 4).await;
    for (e, host) in ev
        .iter()
        .zip(["up.test", UP_IP, &format!("::ffff:{UP_IP}"), "up.test"])
    {
        assert_eq!(e["list"], "blocked", "{e}");
        assert_eq!(e["reason"], "list:blocked", "{e}");
        assert_eq!(e["matched_cidr"], format!("{UP_IP}/32"), "{e}");
        assert_eq!(e["resolved_ip"], UP_IP, "{e}");
        assert_eq!(e["host"], host, "{e}");
    }
    let req = kit.events("request", 4).await;
    assert!(
        req.iter().all(|e| e["terminal_rule"] == "_address_policy"),
        "{req:#?}"
    );
    assert!(
        kit.upstream.seen().is_empty(),
        "nothing reached the upstream"
    );
}

/// `client.ip in @list` and `not in @list` use the loaded lists; an IPv4
/// client matches a list written in IPv4-mapped IPv6.
#[tokio::test]
async fn rules_can_use_address_lists() {
    let kit = Kit::builder()
        .rules(
            r#"
- id: peer-listed
  when: client.ip in @peers and path == "/listed"
  then: { deny: { status: 451 } }
- id: client-listed
  when: client.ip in @clients and path == "/mapped"
  then: { deny: { status: 429 } }
- id: client-not-listed
  when: client.ip not in @clients
  then: deny
- id: up
  when: host == "up.test"
  then: allow
"#,
        )
        .address_list("peers", "192.0.2.0/24\n")
        .address_list("clients", "::ffff:192.0.2.7\n")
        .start()
        .await;
    let a = get(&kit, "up.test", "/listed").await;
    assert_eq!(a.status, 451, "{a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "peer-listed");
    let a = get(&kit, "up.test", "/mapped").await;
    assert_eq!(a.status, 429, "{a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "client-listed");
    let a = get(&kit, "up.test", "/ok").await;
    assert_eq!(a.status, 200, "{a:?}");
    kit.events("request", 3).await;
    assert!(
        kit.sink
            .events()
            .iter()
            .all(|e| e["event"] != "policy_input_unavailable")
    );
}

// ---- metrics --------------------------------------------------------------

/// A metric store whose answers the test controls.
#[derive(Default)]
struct StubMetrics {
    /// 0 ok, 1 unavailable, 2 table full on read, 3 table full on record.
    mode: AtomicU8,
    recorded: AtomicUsize,
}

impl MetricSource for StubMetrics {
    fn get(&self, id: &str, _view: &dyn roxy_rules::FlowView) -> Result<i64, MetricSourceError> {
        match self.mode.load(Ordering::Relaxed) {
            1 => Err(MetricSourceError::Unknown(format!("{id}: store offline"))),
            2 => Err(MetricSourceError::TableFull(id.to_owned())),
            _ => Ok(0),
        }
    }

    fn record(
        &self,
        _view: &dyn roxy_rules::FlowView,
        _sample: &Sample,
    ) -> Result<(), MetricSourceError> {
        self.recorded.fetch_add(1, Ordering::Relaxed);
        if self.mode.load(Ordering::Relaxed) == 3 {
            return Err(MetricSourceError::TableFull("hits".into()));
        }
        Ok(())
    }
}

const BY_PATH: &str = r#"
- id: by_path
  count: requests
  where: host == "up.test"
  key: [path]
  window: 1h
"#;

/// A metric the store cannot answer, on read or on record, fails the flow
/// closed.
#[tokio::test]
async fn unavailable_metrics_fail_closed() {
    let stub = Arc::new(StubMetrics::default());
    let kit = Kit::builder()
        .rules(
            r#"
- id: limit
  when: metric.hits >= 1000
  then: deny
- id: up
  when: host == "up.test"
  then: allow
"#,
        )
        .metric_defs("- { id: hits, count: requests, key: [client.ip] }")
        .metrics(stub.clone())
        .start()
        .await;
    let a = kit.h1().await.call("GET", "/m", &[], b"").await;
    assert_eq!(a.status, 200, "{a:?}");
    // The allowed request's event is emitted after its body has streamed;
    // wait for it so later events cannot be reordered ahead of it.
    kit.events("request", 1).await;
    for (mode, reason) in [
        (1u8, "metric_unavailable"),
        (2, "metric_table_full"),
        (3, "metric_table_full"),
    ] {
        stub.mode.store(mode, Ordering::Relaxed);
        let a = kit.h1().await.call("GET", "/m", &[], b"").await;
        assert_eq!(a.status, 503, "mode {mode}: {a:?}");
        assert_eq!(a.headers["x-roxy-rule"], "_fail_closed");
        let ev = kit.events("request", 1 + usize::from(mode)).await;
        assert_eq!(ev.last().unwrap()["reason"], reason, "mode {mode}: {ev:#?}");
    }
    assert_eq!(kit.events("metric_table_full", 2).await.len(), 2);
    assert_eq!(kit.events("policy_input_unavailable", 2).await.len(), 2);
    assert_eq!(kit.upstream.seen().len(), 1);
    assert!(stub.recorded.load(Ordering::Relaxed) >= 4);
}

/// A full metric key table denies flows that need a new key instead of
/// evicting existing ones.
#[tokio::test]
async fn a_full_metric_table_denies_new_keys() {
    let kit = Kit::builder()
        .rules(
            r#"
- id: guarded
  when: host == "up.test" and metric.by_path < 1000
  then: allow
"#,
        )
        .metric_defs(BY_PATH)
        .metric_limits(|l| l.max_keys = 2)
        .start()
        .await;
    let mut c = kit.h1().await;
    assert_eq!(c.call("GET", "/a", &[], b"").await.status, 200);
    assert_eq!(c.call("GET", "/b", &[], b"").await.status, 200);
    let a = c.call("GET", "/c", &[], b"").await;
    assert_eq!(a.status, 503, "a third key does not fit: {a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "_fail_closed");
    let a = kit.h1().await.call("GET", "/a", &[], b"").await;
    assert_eq!(a.status, 200, "existing keys keep working: {a:?}");
}

/// `limits.max_metric_bytes` is enforced like the key cap: with a budget
/// too small for even one series, the first flow that needs a new key is
/// denied, never served by evicting.
#[tokio::test]
async fn a_tiny_metric_byte_budget_denies_new_keys() {
    let kit = Kit::builder()
        .rules(
            r#"
- id: guarded
  when: host == "up.test" and metric.by_path < 1000
  then: allow
"#,
        )
        .metric_defs(BY_PATH)
        .metric_limits(|l| l.max_bytes = 1)
        .start()
        .await;
    let a = kit.h1().await.call("GET", "/a", &[], b"").await;
    assert_eq!(a.status, 503, "no series fits a 1-byte budget: {a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "_fail_closed");
    let ev = kit.request_event().await;
    assert_eq!(ev["reason"], "metric_table_full", "{ev:#}");
    kit.events("metric_table_full", 1).await;
    assert!(kit.upstream.seen().is_empty());
}

/// A 64 KiB upload in 16 KiB chunks.
async fn upload(kit: &Kit, path: &str) -> Answer {
    let mut c = kit.h1().await;
    let (mut tx, body) = streaming_body();
    let req = c.request("POST", path, &[]).body(body).unwrap();
    let feed = tokio::spawn(async move {
        for _ in 0..4 {
            if tx
                .send_data(Bytes::from(vec![b'u'; 16 * 1024]))
                .await
                .is_err()
            {
                return;
            }
        }
        let _ = tx.finish().await;
    });
    let a = Answer::read(c.send(req).await.unwrap()).await;
    feed.abort();
    a
}

/// A byte budget (`request_bytes` metric) stops the upload that crosses
/// it, while it streams, and later requests are denied at the head.
#[tokio::test]
async fn a_byte_budget_stops_the_crossing_upload() {
    let kit = Kit::builder()
        .rules(
            r#"
- id: up
  when: host == "up.test"
  then: allow
- id: budget
  when: metric.up > 100kb
  then: { deny: { status: 429, message: "upload budget exhausted" } }
"#,
        )
        .metric_defs("- { id: up, count: request_bytes, key: [client.ip] }")
        .start()
        .await;
    let a = upload(&kit, "/one").await;
    assert_eq!(a.status, 200, "64 KiB fits the budget: {a:?}");
    // 64 KiB more crosses 100 KiB part-way through.
    let a = upload(&kit, "/two").await;
    assert_eq!(a.status, 429, "{a:?}");
    let a = kit.h1().await.call("GET", "/three", &[], b"").await;
    assert_eq!(a.status, 429, "over budget now: {a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "budget");
    let ev = kit.events("request", 3).await;
    let stage = |path: &str| {
        ev.iter()
            .find(|e| e["req"]["path"] == path)
            .map(|e| (e["decision"].clone(), e["stage"].clone()))
            .unwrap()
    };
    assert_eq!(stage("/one"), ("allow".into(), "head".into()));
    assert_eq!(stage("/two"), ("deny".into(), "request_body".into()));
    assert_eq!(stage("/three"), ("deny".into(), "head".into()));
    let seen = kit.upstream.wait_seen(1).await;
    let total: usize = seen.iter().map(|s| s.body.len()).sum();
    assert!(
        total <= 100 * 1024,
        "forwarded {total} bytes past the budget"
    );
    // The metric counts what roxy read: everything forwarded plus the
    // chunk whose arrival crossed the budget, which was refused.
    let (budget, chunk): (u64, u64) = (100 * 1024, 16 * 1024);
    let counted: u64 = kit
        .samples
        .lock()
        .unwrap()
        .iter()
        .map(|s| s.request_bytes)
        .sum();
    assert!(
        counted > total as u64 && counted <= budget + chunk,
        "counted {counted} bytes, forwarded {total}"
    );
}

/// A name that resolves to a public and a private address is denied as a
/// whole: the floor judges every address, not the one that would be
/// dialled. With `private_ok` the same name is reachable.
#[tokio::test]
async fn a_name_with_a_private_address_among_its_answers_is_denied() {
    let kit = Kit::builder()
        .rules("- id: any\n  when: port in [80, 443]\n  then: allow\n")
        .start()
        .await;
    let a = get(&kit, "mixed.test", "/").await;
    assert_eq!(a.status, 403, "{a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "_address_policy");
    let ev = kit.events("upstream_denied", 1).await;
    assert_eq!(ev[0]["reason"], "private_range:private", "{ev:#?}");
    assert_eq!(ev[0]["resolved_ip"], "10.0.0.5", "{ev:#?}");
    assert!(kit.upstream.seen().is_empty());

    let kit = Kit::builder()
        .rules("- id: any\n  when: port in [80, 443]\n  then: { allow: { private_ok: true } }\n")
        .start()
        .await;
    let a = get(&kit, "mixed.test", "/").await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(
        kit.upstream.wait_seen(1).await[0].addr.ip().to_string(),
        UP_IP
    );
}
