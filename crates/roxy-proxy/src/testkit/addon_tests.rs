//! Addon stacks of one to three layers: order, attribution, observe and
//! enforce mixed, answering versus passing on, and chained `tunnel` layers.
//!
//! The test layer is named per addon and reads `x-test-<name>`, so each
//! layer of a stack can be told what to do.

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use bytes::Bytes;

use super::{AddonDef, Answer, Kit, MemState, no_layer_error, streaming_body, strs};
use crate::addons::{EndpointPath, Part};

const RULES: &str = r#"
- id: no-rewritten
  when: host == "up.test" and path starts_with "/rewritten"
  then: deny
- id: ws
  when: host == "up.test" and path == "/ws"
  then: { allow: { upgrade: websocket } }
- id: up
  when: host == "up.test"
  then: allow
"#;

async fn stack(layers: &[AddonDef]) -> Kit {
    let mut b = Kit::builder().rules(RULES);
    for l in layers {
        b = b.addon(l.clone());
    }
    b.start().await
}

fn named(names: &[&str]) -> Vec<AddonDef> {
    names.iter().map(|n| AddonDef::test_layer(n)).collect()
}

fn gzip(b: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(b).unwrap();
    e.finish().unwrap()
}

#[tokio::test]
async fn layers_run_outermost_first() {
    let kit = stack(&named(&["a", "b", "c"])).await;
    let a = kit.h1().await.call("POST", "/x", &[], b"body").await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.json()["via"], "a,b,c");
    assert_eq!(a.json()["body_len"], 4);
    let ev = kit.request_event().await;
    assert_eq!(strs(&ev["addons"]), ["a", "b", "c"], "{ev:#}");
    let tags = strs(&ev["tags"]);
    assert_eq!(tags, ["via:a", "via:b", "via:c"], "{ev:#}");
    assert_eq!(ev["decision"], "allow");
    assert_eq!(ev["terminal_rule"], "up");
}

#[tokio::test]
async fn the_rules_judge_what_the_inner_layer_passed_on() {
    let kit = stack(&named(&["a", "b"])).await;
    let a = kit
        .h1()
        .await
        .call("POST", "/x", &[("x-test-b", "rewrite")], b"orig")
        .await;
    assert_eq!(a.status, 403, "{a:?}");
    let ev = kit.request_event().await;
    assert_eq!(ev["terminal_rule"], "no-rewritten", "{ev:#}");
    // `req` still describes what the client sent.
    assert_eq!(ev["req"]["path"], "/x");
    assert!(kit.upstream.seen().is_empty());
}

#[tokio::test]
async fn a_layer_answering_stops_the_stack_below_it() {
    let kit = stack(&named(&["a", "b", "c"])).await;
    let a = kit
        .h1()
        .await
        .call("GET", "/x", &[("x-test-b", "answer")], b"")
        .await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.text(), "answered by b");
    let ev = kit.request_event().await;
    assert_eq!(ev["terminal_rule"], "layer:b", "{ev:#}");
    assert_eq!(ev["decision"], "answered");
    assert_eq!(strs(&ev["tags"]), ["via:a"]);
    assert!(kit.upstream.seen().is_empty());
}

#[tokio::test]
async fn a_failure_is_attributed_to_the_layer_that_failed() {
    for failing in ["a", "b", "c"] {
        let kit = stack(&named(&["a", "b", "c"])).await;
        let header = format!("x-test-{failing}");
        let a = kit
            .h1()
            .await
            .call("GET", "/x", &[(header.as_str(), "trap")], b"")
            .await;
        assert_eq!(a.status, 503, "{failing}: {a:?}");
        let ev = kit.request_event().await;
        assert_eq!(ev["terminal_rule"], format!("layer:{failing}"), "{ev:#}");
        assert_eq!(ev["reason"], "layer_error");
        let errs = kit.events("layer_error", 1).await;
        assert_eq!(errs.len(), 1, "{errs:#?}");
        assert_eq!(errs[0]["layer"], failing);
        assert_eq!(errs[0]["kind"], "trap");
        assert_eq!(errs[0]["mode"], "enforce");
        assert!(kit.upstream.seen().is_empty());
    }
}

/// The outermost layer answering itself is `answered` and named; nothing
/// upstream of it runs.
#[tokio::test]
async fn an_outer_layer_answering_is_answered() {
    let kit = stack(&named(&["a", "b"])).await;
    let a = kit
        .h1()
        .await
        .call("GET", "/x", &[("x-test-a", "deny")], b"")
        .await;
    assert_eq!(a.status, 403, "{a:?}");
    let ev = kit.request_event().await;
    assert_eq!(ev["decision"], "answered", "{ev:#}");
    assert_eq!(ev["terminal_rule"], "layer:a");
    assert!(ev["reason"].is_null(), "{ev:#}");
    assert!(kit.upstream.seen().is_empty());
}

/// Metric keys come from the request that left the stack, for the core's
/// samples and for `metric-get` alike: a layer that sends the request to
/// another host reads the count keyed on that host.
#[tokio::test]
async fn metric_keys_follow_the_request_that_left() {
    let kit = Kit::builder()
        .rules(
            r#"
- id: both
  when: host == "up.test" or host == "private.test"
  then: { allow: { private_ok: true } }
"#,
        )
        .metric_defs("- { id: by_host, count: requests, key: [host], window: 1h }")
        .addon(AddonDef {
            caps: vec![roxy_wasm::Capability::Metrics],
            ..AddonDef::test_layer("a")
        })
        .start()
        .await;
    let mut c = kit.h1().await;
    let headers = [
        ("x-test-a", "elsewhere-then-metric"),
        ("x-to", "private.test"),
    ];
    let first = c.call("GET", "/m", &headers, b"").await;
    assert_eq!(first.status, 200, "{first:?}");
    assert_eq!(
        first.text(),
        "Some(1)",
        "keyed on private.test, not up.test"
    );
    let second = c.call("GET", "/m", &headers, b"").await;
    assert_eq!(second.text(), "Some(2)");
    let seen = kit.upstream.wait_seen(2).await;
    assert!(
        seen.iter().all(|s| s.headers["host"] == "private.test"),
        "{seen:?}"
    );
}

/// `metric-get` on a key the store has no series for is `none`, not 0:
/// a metric whose `where` excludes the flow never records its key.
#[tokio::test]
async fn metric_get_is_none_for_a_key_with_no_entry() {
    let kit = Kit::builder()
        .metric_defs("- { id: by_host, count: requests, key: [host], where: 'method == POST' }")
        .addon(AddonDef {
            caps: vec![roxy_wasm::Capability::Metrics],
            ..AddonDef::test_layer("a")
        })
        .start()
        .await;
    let mut c = kit.h1().await;
    let headers = [("x-test-a", "elsewhere-then-metric"), ("x-to", "up.test")];
    let get = c.call("GET", "/m", &headers, b"").await;
    assert_eq!(get.status, 200, "{get:?}");
    assert_eq!(
        get.text(),
        "None",
        "a GET is not counted, so its key has no entry"
    );
    let post = c.call("POST", "/m", &headers, b"").await;
    assert_eq!(post.text(), "Some(1)");
    let get = c.call("GET", "/m", &headers, b"").await;
    assert_eq!(
        get.text(),
        "Some(1)",
        "the key exists once any flow recorded it"
    );
}

#[tokio::test]
async fn an_inner_layer_failing_after_the_head_cuts_the_body() {
    let kit = stack(&named(&["a", "b"])).await;
    let a = kit
        .h1()
        .await
        .call("GET", "/x", &[("x-test-b", "trap-after-head")], b"")
        .await;
    assert_eq!(a.status, 200, "{a:?}");
    assert!(a.body.is_err(), "the body is cut: {a:?}");
    kit.events("layer_error", 1).await;
}

#[tokio::test]
async fn an_inner_layer_failing_after_the_head_is_the_one_blamed() {
    let kit = stack(&named(&["a", "b"])).await;
    let a = kit
        .h1()
        .await
        .call("GET", "/x", &[("x-test-b", "trap-after-head")], b"")
        .await;
    assert!(a.body.is_err(), "the body is cut: {a:?}");
    let errs = kit.events("layer_error", 1).await;
    // `a` may fail too (it reads the cut body), but `b` failed first.
    assert!(errs.iter().any(|e| e["layer"] == "b"), "{errs:#?}");
}

/// A client upload that breaks is the client's fault through a WASM layer
/// as without one. Before the response head the connection closes on the
/// parse error; after it the body is cut. Either way the layer that fails
/// on the broken body it was given is not blamed, and nothing is logged
/// against it.
#[tokio::test]
async fn a_client_upload_failing_mid_body_is_not_the_layers_fault() {
    // Before the head: the upstream answers only once the body is in.
    let kit = stack(&named(&["a"])).await;
    let (out, eof) = kit
        .raw(
            b"POST http://up.test/x HTTP/1.1\r\nhost: up.test\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\nzz\r\n",
        )
        .await;
    assert!(eof);
    assert!(out.starts_with("HTTP/1.1 400"), "{out}");
    let ev = kit.request_event().await;
    assert_eq!(ev["reason"], "bad_chunk_size", "{ev:#}");
    no_layer_error(&kit);

    // After the head: the upstream answers at once and keeps its body
    // coming, so the layer is still relaying both streams when the upload
    // stalls past `body_idle_timeout` under it. Over HTTP/2 the response
    // stream stays up on a request body failure, so the layer, not the
    // transport, is the first to act on it.
    let kit = Kit::builder()
        .rules(RULES)
        .addon(AddonDef::test_layer("a"))
        .limits(|l| l.body_idle_timeout = std::time::Duration::from_millis(300))
        .start()
        .await;
    let mut c = kit.tunnel("up.test", true).await;
    let (mut tx, body) = streaming_body();
    let req = c
        .request(
            "POST",
            "/early-drip?n=50&ms=100",
            &[("content-length", "10")],
        )
        .body(body)
        .unwrap();
    let answer = c.start(req);
    tx.send_data(Bytes::from_static(b"hello")).await.unwrap();
    let a = answer.await.unwrap().unwrap();
    assert_eq!(a.status, 200, "{a:?}");
    assert!(a.body.is_err(), "the body is cut: {a:?}");
    let ev = kit.request_event().await;
    assert_ne!(ev["terminal_rule"], "layer:a", "{ev:#}");
    // Best-effort: nothing marks the layer's task ending, so a `layer_error`
    // for its trap on the cut body would land just after the request event.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    no_layer_error(&kit);
}

/// A decoder window the buffer budget cannot cover fails the exchange
/// closed as the budget's refusal, through a WASM layer and a service
/// layer alike: the layer that fails on a body it was never given is not
/// blamed.
#[tokio::test]
async fn a_decoder_window_the_budget_cannot_cover_is_the_budgets_refusal() {
    use crate::addons::AddonMode;
    use crate::addons::service::testing::{addon, reload};
    // Under the 32 KiB window gzip charges on its first byte.
    let budget = |b: super::KitBuilder| b.limits(|l| l.max_buffered_bytes = 1024);
    let wasm = budget(Kit::builder().rules(RULES))
        .addon(AddonDef::test_layer("a"))
        .start()
        .await;
    let service = budget(Kit::builder().rules(RULES)).start().await;
    reload(
        &service,
        RULES,
        &[],
        vec![addon("s", "pass", AddonMode::Enforce, |_| {})],
    );
    for (kind, kit) in [("wasm", wasm), ("service", service)] {
        let mut c = kit.h1().await;
        let req = c
            .request("POST", "/x", &[("content-encoding", "gzip")])
            .body(roxy_http::Body::from_bytes(gzip(b"hello")))
            .unwrap();
        let a = Answer::read(c.send(req).await.unwrap()).await;
        assert_eq!(a.status, 503, "{kind}: {a:?}");
        let ev = kit.request_event().await;
        assert_eq!(ev["terminal_rule"], "_fail_closed", "{kind}: {ev:#}");
        assert_eq!(ev["reason"], "buffer_budget_exhausted", "{kind}: {ev:#}");
        no_layer_error(&kit);
        assert!(kit.upstream.seen().is_empty(), "{kind}");
    }
}

/// The same refusal on a response body the layer streams through cuts the
/// body after the head, and the `request` event says why: the budget's
/// code, not a bare write failure.
#[tokio::test]
async fn a_decoder_window_the_budget_cannot_cover_after_the_head_names_the_budget() {
    let kit = Kit::builder()
        .rules(RULES)
        .addon(AddonDef::test_layer("a"))
        .limits(|l| l.max_buffered_bytes = 1024)
        .start()
        .await;
    let mut c = kit.h1().await;
    let req = c
        .request("POST", "/echo", &[("x-echo-encoding", "gzip")])
        .body(roxy_http::Body::from_bytes(gzip(b"hello")))
        .unwrap();
    let a = Answer::read(c.send(req).await.unwrap()).await;
    assert_eq!(a.status, 200, "{a:?}");
    assert!(a.body.is_err(), "the body is cut: {a:?}");
    let ev = kit.request_event().await;
    assert_eq!(ev["reason"], "buffer_budget_exhausted", "{ev:#}");
    let errs = kit.events("response_error", 1).await;
    assert_eq!(errs[0]["reason"], "buffer_budget_exhausted", "{errs:#?}");
    no_layer_error(&kit);
}

#[tokio::test]
async fn an_observer_cannot_block_but_an_enforcer_below_it_can() {
    let kit = stack(&[
        AddonDef::test_layer("a").observe(),
        AddonDef::test_layer("b"),
    ])
    .await;
    let mut c = kit.h1().await;

    // The observer traps: logged only, the exchange goes through `b`.
    let a = c.call("POST", "/x", &[("x-test-a", "trap")], b"data").await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.json()["via"], "b");
    assert_eq!(a.json()["body_len"], 4);
    let errs = kit.events("layer_error", 1).await;
    assert_eq!(errs[0]["layer"], "a", "{errs:#?}");
    assert_eq!(errs[0]["mode"], "observe");

    // The observer answers: ignored. The enforcer denies: it wins.
    let a = c
        .call(
            "GET",
            "/y",
            &[("x-test-a", "answer"), ("x-test-b", "deny")],
            b"",
        )
        .await;
    assert_eq!(a.status, 403, "{a:?}");
    assert_eq!(a.text(), "denied by layer");
    let reqs = kit.events("request", 2).await;
    assert_eq!(reqs[1]["terminal_rule"], "layer:b", "{reqs:#?}");
}

/// An enforcer failing upstream of an observer ends the observer's `next` too;
/// the one `layer_error` is the enforcer's.
#[tokio::test]
async fn a_failure_below_an_observer_is_not_logged_as_the_observers() {
    let kit = stack(&[
        AddonDef::test_layer("o").observe(),
        AddonDef::test_layer("b"),
    ])
    .await;
    let a = kit
        .h1()
        .await
        .call("GET", "/x", &[("x-test-b", "trap")], b"")
        .await;
    assert_eq!(a.status, 503, "{a:?}");
    let ev = kit.request_event().await;
    assert_eq!(ev["terminal_rule"], "layer:b", "{ev:#}");
    let errs = kit.events("layer_error", 1).await;
    assert_eq!(errs[0]["layer"], "b", "{errs:#?}");
    assert_eq!(errs[0]["mode"], "enforce");
    // The observer's own end would be logged just after the enforcer's.
    // Nothing marks the observer's task ending, so this check is
    // best-effort: a late event lands after the window.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let errs: Vec<_> = kit
        .sink
        .events()
        .into_iter()
        .filter(|e| e["event"] == "layer_error")
        .collect();
    assert_eq!(errs.len(), 1, "{errs:#?}");
}

/// An enforcer failing upstream of an observer after the head cuts the real
/// body and the observer's copy with it; the observer's own end is a
/// consequence, and the one `layer_error` is the enforcer's.
#[tokio::test]
async fn an_enforcer_failing_after_the_head_below_an_observer_is_the_one_logged() {
    let kit = stack(&[
        AddonDef::test_layer("o").observe(),
        AddonDef::test_layer("b"),
    ])
    .await;
    // The delay lets the head reach the client before the trap; a trap
    // that lands first takes the `503` path instead, and the test fails
    // on the status rather than passing for the wrong reason.
    let a = kit
        .h1()
        .await
        .call(
            "GET",
            "/x",
            &[("x-test-b", "trap-after-head"), ("x-delay-ms", "1000")],
            b"",
        )
        .await;
    assert_eq!(a.status, 200, "{a:?}");
    assert!(a.body.is_err(), "the body is cut: {a:?}");
    let errs = kit.events("layer_error", 1).await;
    assert_eq!(errs[0]["layer"], "b", "{errs:#?}");
    assert_eq!(errs[0]["kind"], "trap", "{errs:#?}");
    // Best-effort, as above: nothing marks the observer's task ending.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let errs: Vec<_> = kit
        .sink
        .events()
        .into_iter()
        .filter(|e| e["event"] == "layer_error")
        .collect();
    assert_eq!(errs.len(), 1, "{errs:#?}");
}

/// A deny at admission, by the rules or by a layer, never reads the request
/// body. The observer downstream of it reads its copy to a clean end and sees the
/// deny from `next`; nothing is logged against it.
#[tokio::test]
async fn an_observer_above_a_deny_sees_its_copy_end_cleanly() {
    const RULES: &str = r#"
- id: blocked
  when: host == "blocked.test"
  then: deny
- id: up
  when: host == "up.test"
  then: allow
"#;
    let kit = Kit::builder()
        .rules(RULES)
        .addon(AddonDef::test_layer("o").observe())
        .addon(AddonDef::test_layer("b"))
        .start()
        .await;
    let mut c = kit.h1().await;

    let req = c
        .request_to("blocked.test", "POST", "/x", &[])
        .body(roxy_http::Body::from_bytes(bytes::Bytes::from_static(
            b"never read",
        )))
        .unwrap();
    let a = Answer::read(c.send(req).await.unwrap()).await;
    assert_eq!(a.status, 403, "{a:?}");
    let ev = kit.request_event().await;
    assert_eq!(ev["decision"], "deny", "{ev:#}");
    assert_eq!(ev["terminal_rule"], "blocked");
    assert_eq!(strs(&ev["addons"]), ["o", "b"]);

    // The connection closed with the unread body; a fresh one for the layer.
    let a = kit
        .h1()
        .await
        .call("POST", "/x", &[("x-test-b", "deny")], b"never read")
        .await;
    assert_eq!(a.status, 403, "{a:?}");
    let reqs = kit.events("request", 2).await;
    assert_eq!(reqs[1]["terminal_rule"], "layer:b", "{reqs:#?}");

    // The observer's trap, had its copy failed, would be logged after the
    // request. Nothing marks the observer's task ending, so this check is
    // best-effort.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let errs: Vec<_> = kit
        .sink
        .events()
        .into_iter()
        .filter(|e| e["event"] == "layer_error")
        .collect();
    assert!(errs.is_empty(), "{errs:#?}");
}

#[tokio::test]
async fn an_observer_sees_the_real_exchange_without_changing_it() {
    let kit = stack(&[
        AddonDef::test_layer("a"),
        AddonDef::test_layer("b").observe(),
        AddonDef::test_layer("c"),
    ])
    .await;
    // The observer's own rewrite goes nowhere.
    let a = kit
        .h1()
        .await
        .call("POST", "/x", &[("x-test-b", "rewrite")], b"payload")
        .await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.json()["path"], "/x");
    assert_eq!(a.json()["via"], "a,c");
    assert_eq!(a.json()["body_len"], 7);
}

#[tokio::test]
async fn h2_clients_go_through_the_whole_stack() {
    let kit = stack(&named(&["a", "b"])).await;
    let mut c = kit.tunnel("up.test", true).await;
    let a = c.call("POST", "/x", &[], b"over h2").await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.json()["via"], "a,b");
    let a = c.call("GET", "/x", &[("x-test-b", "deny")], b"").await;
    assert_eq!(a.status, 403, "{a:?}");
}

async fn echo(
    io: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
    msg: &[u8],
) -> Vec<u8> {
    io.write_all(msg).await.unwrap();
    let mut got = vec![0u8; msg.len()];
    tokio::time::timeout(std::time::Duration::from_secs(10), io.read_exact(&mut got))
        .await
        .expect("echo in time")
        .unwrap();
    got
}

/// A WebSocket is an exchange like any other: every layer carries it in
/// its bodies, the client's bytes in the request and the upstream's in the
/// response. The test layer upper-cases what it relays (`x-upper`).
#[tokio::test]
async fn layers_carry_a_websocket_in_their_bodies() {
    let kit = stack(&named(&["a", "b", "c"])).await;
    let (status, io) = kit.websocket("/ws", &[("x-upper", "1")]).await;
    assert_eq!(status, 101);
    let mut io = io.unwrap();
    // Upper-cased on the way up and down; the upstream echoes it.
    assert_eq!(echo(&mut io, b"hello").await, b"HELLO");
    assert_eq!(echo(&mut io, b"again").await, b"AGAIN");
    drop(io);
    let close = kit.events("ws_close", 1).await;
    assert_eq!(close[0]["bytes_c2s"], 10, "{close:#?}");
    assert_eq!(close[0]["bytes_s2c"], 10, "{close:#?}");
    let ev = kit.request_event().await;
    assert_eq!(strs(&ev["addons"]), ["a", "b", "c"], "{ev:#}");
    assert_eq!(ev["terminal_rule"], "ws");
    let tags = strs(&ev["tags"]);
    for t in ["via:a", "via:b", "via:c"] {
        assert!(tags.iter().any(|x| x == t), "{t} in {tags:?}");
    }
}

#[tokio::test]
async fn a_close_from_the_upstream_ends_a_websocket_through_layers() {
    let kit = stack(&named(&["a", "b"])).await;
    let (status, io) = kit
        .websocket("/ws", &[("x-echo", "once"), ("x-upper", "1")])
        .await;
    assert_eq!(status, 101);
    let mut io = io.unwrap();
    assert_eq!(echo(&mut io, b"hello").await, b"HELLO");
    // The upstream has closed: the client sees EOF through both layers,
    // without closing first.
    let mut rest = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        io.read_to_end(&mut rest),
    )
    .await
    .expect("EOF in time")
    .unwrap();
    assert!(rest.is_empty(), "{rest:?}");
    drop(io);
    let ev = kit.request_event().await;
    assert_eq!(strs(&ev["addons"]), ["a", "b"], "{ev:#}");
}

/// The relay's end closes the client even when a layer keeps its bodies
/// open (`x-hold`): the socket is roxy's, not the layer's.
#[tokio::test]
async fn the_relay_ending_closes_the_client_whatever_the_layer_holds() {
    let mut b = Kit::builder()
        .rules(RULES)
        .limits(|l| l.idle_timeout = std::time::Duration::from_millis(300));
    for l in named(&["a", "b"]) {
        b = b.addon(l);
    }
    let kit = b.start().await;
    let (status, io) = kit
        .websocket("/ws", &[("x-echo", "once"), ("x-hold", "1")])
        .await;
    assert_eq!(status, 101);
    let mut io = io.unwrap();
    assert_eq!(echo(&mut io, b"hello").await, b"hello");
    // The upstream has closed and the relay ends on its idle timeout; the
    // layers still hold their bodies, but the client sees EOF.
    let mut rest = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(5), io.read_to_end(&mut rest))
        .await
        .expect("EOF in time")
        .unwrap();
    assert!(rest.is_empty(), "{rest:?}");
    kit.events("ws_close", 1).await;
}

#[tokio::test]
async fn a_layer_can_refuse_an_upgrade() {
    let kit = stack(&named(&["a", "plain"])).await;
    let (status, io) = kit.websocket("/ws", &[("x-test-plain", "deny")]).await;
    assert_eq!(status, 403);
    assert!(io.is_none());
    assert!(kit.upstream.seen().is_empty());
}

/// A layer that turns the core's `101` into another status leaves the
/// relayed upgrade with nowhere to go: the exchange fails closed and the
/// upstream WebSocket is closed, both at once.
#[tokio::test]
async fn a_layer_that_rewrites_the_101_fails_closed() {
    let kit = stack(&named(&["a", "b"])).await;
    let mut c = kit.h1().await;
    let headers = [
        ("connection", "upgrade"),
        ("upgrade", "websocket"),
        ("sec-websocket-version", "13"),
        ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
        ("x-status", "200"),
    ];
    let a = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        c.call("GET", "/ws", &headers, b""),
    )
    .await
    .expect("the client's exchange ends");
    assert_eq!(a.status, 503, "{a:?}");
    assert!(a.body.is_ok(), "{a:?}");
    assert_eq!(kit.upstream.seen().len(), 1, "the upstream upgraded");
    kit.upstream.wait_open(0).await;
    let errs = kit.events("layer_error", 1).await;
    assert_eq!(errs[0]["layer"], "a", "{errs:#?}");
    assert_eq!(errs[0]["kind"], "invalid_response");
}

/// A `1xx` other than a relayed `101` is not a response the client can be
/// given: the stack refuses it as the layer's invalid response rather than
/// letting the codec choke on it.
#[tokio::test]
async fn a_layer_answering_1xx_fails_closed() {
    let kit = stack(&named(&["a"])).await;
    let a = kit
        .h1()
        .await
        .call("GET", "/x", &[("x-status", "100")], b"")
        .await;
    assert_eq!(a.status, 503, "{a:?}");
    let ev = kit.request_event().await;
    assert_eq!(ev["terminal_rule"], "layer:a", "{ev:#}");
    assert_eq!(ev["reason"], "layer_error");
    let errs = kit.events("layer_error", 1).await;
    assert_eq!(errs[0]["layer"], "a", "{errs:#?}");
    assert_eq!(errs[0]["kind"], "invalid_response");
}

#[tokio::test]
async fn a_layer_runs_only_where_its_when_matches() {
    let kit = stack(&[
        AddonDef::test_layer("a").when(r#"path starts_with "/a/""#),
        AddonDef::test_layer("b"),
    ])
    .await;
    let mut c = kit.h1().await;
    let a = c.call("POST", "/x", &[], b"body").await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.json()["via"], "b");
    assert_eq!(a.json()["body_len"], 4);
    let a = c.call("POST", "/a/x", &[], b"body").await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.json()["via"], "a,b");
    let reqs = kit.events("request", 2).await;
    // `addons` names the layers that ran.
    assert_eq!(strs(&reqs[0]["addons"]), ["b"], "{reqs:#?}");
    assert_eq!(strs(&reqs[1]["addons"]), ["a", "b"], "{reqs:#?}");
}

#[tokio::test]
async fn a_skipped_layer_passes_an_inner_answer_through() {
    let kit = stack(&[
        AddonDef::test_layer("a").when("false"),
        AddonDef::test_layer("b"),
    ])
    .await;
    let a = kit
        .h1()
        .await
        .call("GET", "/x", &[("x-test-b", "answer")], b"")
        .await;
    assert_eq!(a.text(), "answered by b");
    let ev = kit.request_event().await;
    assert_eq!(ev["terminal_rule"], "layer:b", "{ev:#}");
    assert_eq!(ev["decision"], "answered");
    assert_eq!(strs(&ev["addons"]), ["b"]);
}

/// A `when` sees the request as it reaches the layer: what the layer
/// downstream passed on, not what the client sent.
#[tokio::test]
async fn when_sees_the_request_the_downstream_layer_passed_on() {
    let kit = stack(&[
        AddonDef::test_layer("a"),
        AddonDef::test_layer("b").when(r#"path == "/rewritten""#),
        AddonDef::test_layer("c").when(r#"path == "/x""#),
    ])
    .await;
    let a = kit
        .h1()
        .await
        .call("POST", "/x", &[("x-test-a", "rewrite")], b"orig")
        .await;
    // The rules deny the rewritten path; what matters is who ran.
    assert_eq!(a.status, 403, "{a:?}");
    let ev = kit.request_event().await;
    assert_eq!(strs(&ev["addons"]), ["a", "b"], "{ev:#}");
}

/// An observer passes nothing on, so what reaches the layers upstream of it is
/// the nearest enforcing layer's: that layer is blamed when its request
/// does not validate, whether a `when` or the core finds out.
#[tokio::test]
async fn an_invalid_request_through_an_observer_blames_the_layer_that_passed_it_on() {
    let kit = stack(&[
        AddonDef::test_layer("a"),
        AddonDef::test_layer("o").observe(),
        AddonDef::test_layer("c").when(r#"path == "/x""#),
    ])
    .await;
    let a = kit
        .h1()
        .await
        .call("GET", "/x", &[("x-test-a", "invalid-next")], b"")
        .await;
    assert_eq!(a.status, 503, "{a:?}");
    let ev = kit.request_event().await;
    assert_eq!(ev["terminal_rule"], "layer:a", "{ev:#}");
    let errs = kit.events("layer_error", 1).await;
    assert_eq!(errs[0]["layer"], "a", "{errs:#?}");
    assert_eq!(errs[0]["kind"], "invalid_request");
}

#[tokio::test]
async fn when_sees_tags_set_by_layers_above() {
    let kit = stack(&[
        AddonDef::test_layer("a"),
        AddonDef::test_layer("b").when(r#"tag["via:a"]"#),
        AddonDef::test_layer("c").when(r#"tag["via:nobody"]"#),
    ])
    .await;
    let a = kit.h1().await.call("GET", "/x", &[], b"").await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.json()["via"], "a,b");
}

/// A tag an enforce layer adds is one of the flow's tags: `tag[..]` reads
/// it in the admission rules and in the in-flight rules, as it would a tag
/// an earlier rule set, and the flow log lists it once.
#[tokio::test]
async fn a_layers_tag_is_read_by_the_rules_below_it() {
    let kit = Kit::builder()
        .rules(
            r#"
- id: tagged
  when: tag["via:t"]
  then: deny
- id: up
  when: host == "up.test"
  then: allow
"#,
        )
        .addon(AddonDef::test_layer("t"))
        .start()
        .await;
    let a = kit.h1().await.call("GET", "/x", &[], b"").await;
    assert_eq!(a.status, 403, "{a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "tagged");
    let ev = kit.request_event().await;
    assert_eq!(ev["terminal_rule"], "tagged", "{ev:#}");
    assert_eq!(strs(&ev["tags"]), ["via:t"], "{ev:#}");

    let kit = Kit::builder()
        .rules(
            r#"
- id: up
  when: host == "up.test"
  then: allow
- id: tagged-ok
  when: tag["via:t"] and response.status == 200
  then: { deny: { status: 502, message: "tagged" } }
"#,
        )
        .addon(AddonDef::test_layer("t"))
        .start()
        .await;
    let a = kit.h1().await.call("GET", "/x", &[], b"").await;
    assert_eq!(a.status, 502, "{a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "tagged-ok");
    let ev = kit.request_event().await;
    assert_eq!(ev["terminal_rule"], "tagged-ok", "{ev:#}");
    assert_eq!(ev["stage"], "response_head", "{ev:#}");
    assert_eq!(strs(&ev["tags"]), ["via:t"], "{ev:#}");
}

/// An observer's tag is refused, so it cannot steer a lower layer's `when`:
/// the gate upstream stays skipped and the flow carries no such tag. The
/// refusal is the observer's failure, logged like any other.
#[tokio::test]
async fn an_observer_cannot_tag_a_flow_past_a_gate_below_it() {
    let kit = stack(&[
        AddonDef::test_layer("monitor").observe(),
        AddonDef::test_layer("gate").when(r#"tag["tagged"]"#),
    ])
    .await;
    let a = kit
        .h1()
        .await
        .call(
            "GET",
            "/x",
            &[("x-test-monitor", "caps"), ("x-cap", "add-tag")],
            b"",
        )
        .await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.json()["via"], serde_json::Value::Null, "{a:?}");
    let ev = kit.request_event().await;
    assert_eq!(strs(&ev["addons"]), ["monitor"], "{ev:#}");
    assert!(strs(&ev["tags"]).is_empty(), "{ev:#}");
    let errs = kit.events("layer_error", 1).await;
    assert_eq!(errs[0]["layer"], "monitor", "{errs:#?}");
    assert_eq!(errs[0]["mode"], "observe");
}

/// An input `when` cannot evaluate fails the flow closed; the layer is
/// never skipped on an error.
#[tokio::test]
async fn a_when_that_cannot_be_evaluated_fails_closed() {
    let kit = stack(&[
        AddonDef::test_layer("a"),
        AddonDef::test_layer("b").when(r#"header["x-missing"] starts_with "v""#),
    ])
    .await;
    let a = kit.h1().await.call("GET", "/x", &[], b"").await;
    assert_eq!(a.status, 503, "{a:?}");
    let ev = kit.request_event().await;
    assert_eq!(ev["terminal_rule"], "layer:b", "{ev:#}");
    assert_eq!(ev["reason"], "layer_error");
    let errs = kit.events("layer_error", 1).await;
    assert_eq!(errs[0]["layer"], "b", "{errs:#?}");
    assert_eq!(errs[0]["kind"], "when:missing_value");
    assert!(kit.upstream.seen().is_empty());
}

/// An observer's `when` failing is logged, like any observer failure, and
/// the observer gets no copy; the flow goes on.
#[tokio::test]
async fn an_observer_whose_when_cannot_be_evaluated_is_skipped() {
    let kit = stack(&[
        AddonDef::test_layer("o")
            .observe()
            .when(r#"header["x-missing"] starts_with "v""#),
        AddonDef::test_layer("b"),
    ])
    .await;
    let a = kit.h1().await.call("GET", "/x", &[], b"").await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.json()["via"], "b");
    let errs = kit.events("layer_error", 1).await;
    assert_eq!(errs[0]["layer"], "o", "{errs:#?}");
    assert_eq!(errs[0]["mode"], "observe");
    assert_eq!(errs[0]["kind"], "when:missing_value");
    let ev = kit.request_event().await;
    assert_eq!(strs(&ev["addons"]), ["b"], "{ev:#}");
}

#[tokio::test]
async fn sample_copies_a_share_of_matching_exchanges() {
    let kit = stack(&[
        AddonDef::test_layer("o")
            .observe()
            .when(r#"path == "/s""#)
            .sample(0.5),
        AddonDef::test_layer("b"),
    ])
    .await;
    let mut c = kit.h1().await;
    let n = 120;
    for _ in 0..n {
        let a = c.call("GET", "/s", &[], b"").await;
        assert_eq!(a.status, 200, "{a:?}");
    }
    let a = c.call("GET", "/other", &[], b"").await;
    assert_eq!(a.status, 200, "{a:?}");
    let reqs = kit.events("request", n + 1).await;
    let observed = reqs[..n]
        .iter()
        .filter(|r| strs(&r["addons"]).contains(&"o".to_owned()))
        .count();
    // Binomial(120, 0.5): outside 30..=90 is roughly a 1e-8 event.
    assert!((30..=90).contains(&observed), "{observed} of {n}");
    assert_eq!(strs(&reqs[n]["addons"]), ["b"]);
}

#[tokio::test]
async fn a_layer_its_when_skips_stays_out_of_the_websocket() {
    let kit = stack(&[AddonDef::test_layer("a").when(r#"path != "/ws""#)]).await;
    let (status, io) = kit.websocket("/ws", &[("x-upper", "1")]).await;
    assert_eq!(status, 101);
    let mut io = io.unwrap();
    // `a` would upper-case; it is not in the byte path.
    assert_eq!(echo(&mut io, b"hello").await, b"hello");
    drop(io);
    let ev = kit.request_event().await;
    assert!(strs(&ev["addons"]).is_empty(), "{ev:#}");
}

/// An observer that answers without reading its copy is not lagging: the
/// copy is dropped and the exchange is not reported.
#[tokio::test]
async fn an_observer_that_drops_its_copy_is_not_lagging() {
    let kit = stack(&[
        AddonDef::test_layer("o").observe(),
        AddonDef::test_layer("b"),
    ])
    .await;
    let mut c = kit.h1().await;
    let (mut tx, body) = super::streaming_body();
    let req = c
        .request("POST", "/x", &[("x-test-o", "answer")])
        .body(body)
        .unwrap();
    let answer = c.start(req);
    // The observer has answered (and dropped its copy) long before the
    // body arrives.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    tx.send_data(bytes::Bytes::from_static(b"late"))
        .await
        .unwrap();
    tx.finish().await.unwrap();
    let a = answer.await.unwrap().unwrap();
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.json()["body_len"], 4);
    // A lag report is emitted while the body streams, before the request
    // event, so once that is here the absence is settled.
    kit.request_event().await;
    let lagged: Vec<_> = kit
        .sink
        .events()
        .into_iter()
        .filter(|e| e["event"] == "observer_lagged")
        .collect();
    assert!(lagged.is_empty(), "{lagged:#?}");
}

/// Service layers: the in-test service (`testkit::upstream::service`)
/// behind a `kind: service` addon.
mod service {
    use std::time::Duration;

    use bytes::Bytes;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::{RULES, echo, no_layer_error, strs};
    use crate::addons::AddonMode;
    use std::sync::Arc;

    use crate::addons::AddonSpec;
    use crate::addons::service::ServiceSpec;
    use crate::addons::service::testing::{
        addon, granted, kit, kit_with, only_when, reload, subscribed,
    };
    use crate::testkit::upstream::service::{HOST_STATE_VALUE, SLOW};
    use crate::testkit::{AddonDef, Answer, Kit, streaming_body, timed};
    use roxy_http::Body;
    use roxy_wasm::Capability;

    /// Rules that read the request body, so the core consumes what the
    /// service forwards before anything reaches the upstream.
    const READS_BODY: &str = r#"
- id: secret
  when: host == "up.test" and body.text contains "SECRET"
  then: deny
- id: up
  when: host == "up.test"
  then: allow
"#;

    /// The `config:` a `host` service is given, as it should read it.
    fn host_config() -> serde_json::Value {
        serde_json::json!({"reject_at": 0.8, "tags": ["a", "b"], "nested": {"on": true}})
    }

    /// A service layer `s` with the `host` behaviour, granted `caps` and
    /// configured with [`host_config`].
    fn host_service(mode: AddonMode, caps: &[Capability]) -> Arc<AddonSpec> {
        let mut spec = granted(addon("s", "host", mode, |_| {}), caps);
        Arc::get_mut(&mut spec).expect("a fresh addon").config = host_config();
        spec
    }

    /// Every capability the `host` behaviour's calls need.
    const HOST_CAPS: [Capability; 4] = [
        Capability::Log,
        Capability::Record,
        Capability::State,
        Capability::Metrics,
    ];

    /// The metric the `host` behaviour reads.
    const BY_HOST: &str = "- { id: by_host, count: requests, key: [host], window: 1h }";

    /// The `result` replies the service was sent on stream `id`, by call id.
    fn results(kit: &Kit, id: u32) -> std::collections::HashMap<u64, serde_json::Value> {
        kit.upstream
            .service()
            .controls(id)
            .into_iter()
            .filter(|m| m["type"] == "result")
            .map(|m| (m["id"].as_u64().unwrap(), m))
            .collect()
    }

    /// A service granted the capabilities uses the host services a WASM
    /// layer has, through the same host: its `open` names its grants and
    /// carries its `config` as configured, its record (named by its call
    /// id) and tag reach the flow log, every call is answered with a
    /// `result`, and what it writes to the state store before forwarding
    /// is what the rules read on this very exchange, since it forwards
    /// only once the write is answered. Its `metric_get` reads the metric
    /// the rules read: no entry before any flow is counted, the count
    /// after.
    #[tokio::test]
    async fn a_service_uses_the_host_services_it_is_granted() {
        let kit = kit_with(
            r#"
- id: marked
  when: state["svc"] == "from-service"
  then: deny
- id: up
  when: host == "up.test"
  then: allow
"#,
            vec![host_service(AddonMode::Enforce, &HOST_CAPS)],
            |b| {
                b.state(Arc::new(super::MemState::default()))
                    .metric_defs(BY_HOST)
            },
        )
        .await;
        let a = kit.h1().await.call("GET", "/x", &[], b"").await;
        assert_eq!(a.status, 403, "the rules read the service's write: {a:?}");
        assert_eq!(a.headers["x-roxy-rule"], "marked");
        let open = &kit.upstream.service().until_opened(1).await[0];
        assert_eq!(
            super::strs(&open["capabilities"]),
            ["state", "record", "metrics", "log"],
            "{open:#}"
        );
        assert_eq!(open["config"], host_config(), "{open:#}");
        let r = kit.events("layer_record", 1).await;
        assert_eq!(r[0]["layer"], "s", "{r:#?}");
        assert_eq!(r[0]["call"], 2, "{r:#?}");
        assert_eq!(r[0]["kind"], "verdict");
        assert_eq!(r[0]["data"]["score"], 0.9);
        let ev = kit.request_event().await;
        assert!(
            super::strs(&ev["tags"]).iter().any(|t| t == "svc-tag"),
            "{ev:#}"
        );
        let first = results(&kit, stream_id(open));
        assert_eq!(first.len(), 6, "a result for every call: {first:#?}");
        for id in [1, 2, 3, 4] {
            assert_eq!(first[&id]["value"], serde_json::Value::Null, "{first:#?}");
            assert_eq!(first[&id]["error"], serde_json::Value::Null, "{first:#?}");
        }
        assert_eq!(first[&5]["value"], HOST_STATE_VALUE, "{first:#?}");
        assert_eq!(
            first[&6]["value"],
            serde_json::Value::Null,
            "no flow has been counted yet: {first:#?}"
        );
        super::no_layer_error(&kit);

        let a = kit.h1().await.call("GET", "/x", &[], b"").await;
        assert_eq!(a.status, 403, "{a:?}");
        let open = &kit.upstream.service().until_opened(2).await[1];
        let second = results(&kit, stream_id(open));
        assert_eq!(second[&6]["value"], 1, "the first flow: {second:#?}");
    }

    /// A host service the service was not granted fails the exchange with
    /// the capability's kind, as it does for a WASM layer, and the
    /// `layer_error` names the call.
    #[tokio::test]
    async fn a_service_without_the_capability_fails_closed() {
        let kit = kit(
            READS_BODY,
            vec![host_service(
                AddonMode::Enforce,
                &[Capability::Record, Capability::State, Capability::Metrics],
            )],
        )
        .await;
        let a = kit.h1().await.call("GET", "/x", &[], b"").await;
        assert_eq!(a.status, 503, "{a:?}");
        let errs = kit.events("layer_error", 1).await;
        assert_eq!(errs[0]["layer"], "s", "{errs:#?}");
        assert_eq!(errs[0]["kind"], "capability:log");
        assert_eq!(errs[0]["call"], 1, "{errs:#?}");
        assert!(
            kit.upstream.seen().is_empty(),
            "nothing reached the upstream"
        );
    }

    /// An observing service's record reaches the flow log, but its tag is
    /// refused like a WASM observer's: the failure is its own, named by
    /// its call, the exchange goes on and the flow carries no tag.
    #[tokio::test]
    async fn an_observing_service_cannot_tag() {
        let kit = kit_with(
            READS_BODY,
            vec![host_service(AddonMode::Observe, &HOST_CAPS)],
            |b| {
                b.state(Arc::new(super::MemState::default()))
                    .metric_defs(BY_HOST)
            },
        )
        .await;
        let a = kit.h1().await.call("GET", "/x", &[], b"").await;
        assert_eq!(a.status, 200, "{a:?}");
        let errs = kit.events("layer_error", 1).await;
        assert_eq!(errs[0]["layer"], "s", "{errs:#?}");
        assert_eq!(errs[0]["mode"], "observe");
        assert_eq!(errs[0]["kind"], "host");
        assert_eq!(errs[0]["call"], 3, "{errs:#?}");
        let r = kit.events("layer_record", 1).await;
        assert_eq!(r[0]["layer"], "s", "{r:#?}");
        assert_eq!(r[0]["call"], 2, "{r:#?}");
        let ev = kit.request_event().await;
        assert!(super::strs(&ev["tags"]).is_empty(), "{ev:#}");
    }

    /// An observing service reads the whole response and only then
    /// records what it saw, as a WASM observer can: the stream is still
    /// open after roxy's `response_end`, so the call runs and is answered,
    /// and the stream ends on the service's own `response_end`.
    #[tokio::test]
    async fn an_observing_service_records_after_reading_the_response() {
        let kit = kit(
            READS_BODY,
            vec![granted(
                addon("s", "audit", AddonMode::Observe, |_| {}),
                &[Capability::Record],
            )],
        )
        .await;
        let a = kit.h1().await.call("GET", "/x", &[], b"").await;
        assert_eq!(a.status, 200, "{a:?}");
        let r = kit.events("layer_record", 1).await;
        assert_eq!(r[0]["layer"], "s", "{r:#?}");
        assert_eq!(r[0]["kind"], "audit", "{r:#?}");
        assert_eq!(r[0]["call"], 1, "{r:#?}");
        let open = &kit.upstream.service().until_opened(1).await[0];
        let id = stream_id(open);
        let answered = tokio::time::timeout(Duration::from_secs(5), async {
            while !results(&kit, id).contains_key(&1) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(answered.is_ok(), "the call is answered on the open stream");
        assert!(
            kit.upstream.service().resets().is_empty(),
            "the service ended the stream itself"
        );
        super::no_layer_error(&kit);
    }

    /// An observing service that never ends its stream is failed on its
    /// own clock, `first_byte_timeout` from roxy's last message: the
    /// stream is reset, the failure is the observer's own (one
    /// `layer_error`, `service:timeout`), and the exchange, which never
    /// waited on it, is untouched.
    #[tokio::test]
    async fn an_observing_service_that_never_ends_its_stream_times_out() {
        let kit = kit(
            RULES,
            // `hold` passes the response head back and never its end.
            vec![addon("s", "hold", AddonMode::Observe, |s| {
                s.first_byte_timeout = Duration::from_millis(300);
            })],
        )
        .await;
        let a = kit.h1().await.call("GET", "/x", &[], b"").await;
        assert_eq!(a.status, 200, "{a:?}");
        let errs = kit.events("layer_error", 1).await;
        assert_eq!(errs[0]["layer"], "s", "{errs:#?}");
        assert_eq!(errs[0]["mode"], "observe");
        assert_eq!(errs[0]["kind"], "service:timeout", "{errs:#?}");
        let open = &kit.upstream.service().until_opened(1).await[0];
        let why = reset_of(&kit, stream_id(open)).await;
        assert!(why.contains("first_byte_timeout"), "{why}");
        tokio::time::sleep(Duration::from_millis(300)).await;
        let errs: Vec<_> = kit
            .sink
            .events()
            .into_iter()
            .filter(|e| e["event"] == "layer_error")
            .collect();
        assert_eq!(errs.len(), 1, "{errs:#?}");
    }

    /// A service's `quarantine` trips the process and refuses its own
    /// exchange as `_quarantined`; the cause names the layer and the call,
    /// and the call is answered.
    #[tokio::test]
    async fn a_service_can_quarantine_the_proxy() {
        let kit = kit(
            READS_BODY,
            vec![granted(
                addon("s", "quarantine", AddonMode::Enforce, |_| {}),
                &[Capability::Quarantine],
            )],
        )
        .await;
        let a = kit.h1().await.call("GET", "/x", &[], b"").await;
        assert_eq!(a.status, 403, "{a:?}");
        assert_eq!(a.headers["x-roxy-rule"], "_quarantined");
        let tripped = kit.events("quarantined", 1).await.remove(0);
        assert_eq!(tripped["cause"]["kind"], "layer", "{tripped:#}");
        assert_eq!(tripped["cause"]["layer"], "s", "{tripped:#}");
        assert_eq!(tripped["cause"]["call"], 1, "{tripped:#}");
        let open = &kit.upstream.service().until_opened(1).await[0];
        let results = results(&kit, stream_id(open));
        assert_eq!(
            results[&1]["error"],
            serde_json::Value::Null,
            "{results:#?}"
        );
        assert!(
            kit.upstream.seen().is_empty(),
            "nothing reached the upstream"
        );
    }

    /// A service that quarantines on the response head, after `next`:
    /// the client gets `_quarantined` in place of the response, and the
    /// flow keeps the one admission sample and the rules its admission
    /// recorded.
    #[tokio::test]
    async fn a_service_quarantining_after_next_refuses_without_a_second_sample() {
        let kit = kit_with(
            RULES,
            vec![granted(
                addon("s", "late-quarantine", AddonMode::Enforce, |_| {}),
                &[Capability::Quarantine],
            )],
            |b| b.metric_defs(BY_HOST),
        )
        .await;
        let a = kit.h1().await.call("GET", "/x", &[], b"").await;
        assert_eq!(a.status, 403, "{a:?}");
        assert_eq!(a.headers["x-roxy-rule"], "_quarantined");
        let tripped = kit.events("quarantined", 1).await.remove(0);
        assert_eq!(tripped["cause"]["layer"], "s", "{tripped:#}");
        assert_eq!(kit.upstream.seen().len(), 1, "the request was forwarded");
        let ev = kit.request_event().await;
        assert_eq!(ev["terminal_rule"], "_quarantined", "{ev:#}");
        assert_eq!(ev["decision"], "deny", "{ev:#}");
        assert_eq!(ev["rules"], serde_json::json!(["up"]), "{ev:#}");
        let samples = kit.samples.lock().unwrap();
        assert_eq!(
            samples.iter().filter(|s| s.admission).count(),
            1,
            "{samples:?}"
        );
    }

    /// The same on an upgrade: the relayed upstream WebSocket is closed
    /// with a `1008`, not dropped mid-handshake.
    #[tokio::test]
    async fn a_service_quarantining_on_a_101_closes_the_upstream() {
        let kit = kit(
            RULES,
            vec![granted(
                addon("s", "late-quarantine", AddonMode::Enforce, |_| {}),
                &[Capability::Quarantine],
            )],
        )
        .await;
        let (status, io) = kit.websocket("/ws", &[("x-echo", "frames")]).await;
        assert_eq!(status, 403);
        assert!(io.is_none());
        kit.upstream.wait_ws_closed(1).await;
        assert_eq!(kit.upstream.ws_close_codes(), vec![Some(1008)]);
        let ev = kit.request_event().await;
        assert_eq!(ev["terminal_rule"], "_quarantined", "{ev:#}");
    }

    /// The stream id of an `open` message.
    fn stream_id(open: &serde_json::Value) -> u32 {
        u32::try_from(open["stream"].as_u64().unwrap()).unwrap()
    }

    /// Waits until the service has been sent a reset for stream `id`; its
    /// message.
    async fn reset_of(kit: &Kit, id: u32) -> String {
        let service = kit.upstream.service();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some((_, m)) = service.resets().into_iter().find(|(s, _)| *s == id) {
                    return m;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("stream {id} is reset: {:?}", service.resets()))
    }

    /// A WASM layer upstream of the service fails after the response head: the
    /// service passes the cut body on, and the flow log names the layer
    /// that failed.
    #[tokio::test]
    async fn a_wasm_layer_failing_after_the_head_below_the_service_is_logged() {
        let kit = kit(
            RULES,
            vec![
                addon("s", "pass", AddonMode::Enforce, |_| {}),
                AddonDef::test_layer("w").spec().await,
            ],
        )
        .await;
        // The delay lets the head reach the client through the service
        // before the trap; a trap that lands first takes the `503` path
        // (the test below), and this one fails on the status.
        let a = kit
            .h1()
            .await
            .call(
                "GET",
                "/x",
                &[("x-test-w", "trap-after-head"), ("x-delay-ms", "1000")],
                b"",
            )
            .await;
        assert_eq!(a.status, 200, "{a:?}");
        assert!(a.body.is_err(), "the body is cut: {a:?}");
        let errs = kit.events("layer_error", 1).await;
        assert_eq!(errs[0]["layer"], "w", "{errs:#?}");
        assert_eq!(errs[0]["kind"], "trap", "{errs:#?}");
    }

    /// A service failing after the response head upstream of an observer cuts the
    /// real body and the observer's copy with it; the observer's own end is
    /// a consequence, and the one `layer_error` is the service's.
    #[tokio::test]
    async fn a_service_failing_after_the_head_below_an_observer_is_the_one_logged() {
        let kit = kit(
            RULES,
            vec![
                AddonDef::test_layer("o").observe().spec().await,
                addon("s", "sever", AddonMode::Enforce, |_| {}),
            ],
        )
        .await;
        // `sever` passes the response head on and resets the stream on
        // the first response body bytes.
        let a = kit.h1().await.call("GET", "/x", &[], b"").await;
        assert_eq!(a.status, 200, "{a:?}");
        assert!(a.body.is_err(), "the body is cut: {a:?}");
        let errs = kit.events("layer_error", 1).await;
        assert_eq!(errs[0]["layer"], "s", "{errs:#?}");
        assert_eq!(errs[0]["kind"], "service:closed", "{errs:#?}");
        // Best-effort: nothing marks the observer's task ending, so a late
        // event for it would land after the window.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let errs: Vec<_> = kit
            .sink
            .events()
            .into_iter()
            .filter(|e| e["event"] == "layer_error")
            .collect();
        assert_eq!(errs.len(), 1, "{errs:#?}");
    }

    /// Header values a service passes back are the bytes it was given.
    /// Under `allow_obs_text` that includes obs-text, which a UTF-8 service
    /// protocol must carry without rewriting.
    async fn service_header_round_trip(value: &'static [u8]) {
        let kit = Kit::builder()
            .rules(RULES)
            .flags(|f| f.allow_obs_text = true)
            .start()
            .await;
        reload(
            &kit,
            RULES,
            &[],
            vec![addon("s", "pass", AddonMode::Enforce, |_| {})],
        );
        let mut c = kit.h1().await;
        let req = c
            .request("GET", "/x", &[])
            .header("x-obs", http::HeaderValue::from_bytes(value).unwrap())
            .body(Body::empty())
            .unwrap();
        let a = Answer::read(c.send(req).await.unwrap()).await;
        assert_eq!(a.status, 200, "{a:?}");
        let seen = kit.upstream.wait_seen(1).await;
        assert_eq!(seen[0].headers["x-obs"].as_bytes(), value);
        let ev = kit.request_event().await;
        assert_eq!(strs(&ev["addons"]), ["s"], "{ev:#}");
    }

    #[tokio::test]
    async fn a_utf8_obs_text_header_survives_a_service_round_trip() {
        service_header_round_trip(b"caf\xc3\xa9").await;
    }

    #[tokio::test]
    async fn a_latin1_obs_text_header_survives_a_service_round_trip() {
        service_header_round_trip(b"caf\xe9").await;
    }

    /// A WASM layer upstream of the service fails before the service has
    /// answered the response head: the layer is blamed, not the upstream,
    /// and the client gets the layer's `503`.
    #[tokio::test]
    async fn a_wasm_layer_failing_before_the_services_answer_is_the_one_blamed() {
        let kit = kit(
            RULES,
            vec![
                addon("s", "forward", AddonMode::Enforce, |_| {}),
                AddonDef::test_layer("w").spec().await,
            ],
        )
        .await;
        let a = kit
            .h1()
            .await
            .call("GET", "/x", &[("x-test-w", "trap-after-head")], b"")
            .await;
        assert_eq!(a.status, 503, "{a:?}");
        let ev = kit.request_event().await;
        assert_eq!(ev["terminal_rule"], "layer:w", "{ev:#}");
        assert_eq!(ev["reason"], "layer_error", "{ev:#}");
        let errs = kit.events("layer_error", 1).await;
        assert_eq!(errs[0]["layer"], "w", "{errs:#?}");
        assert_eq!(errs[0]["kind"], "trap", "{errs:#?}");
    }

    /// An upstream that answers while the client is still uploading
    /// reaches the client through a pass-through layer at once: the
    /// response head and body go through the stream while the request
    /// body is still streaming, and the rest of the upload follows.
    #[tokio::test]
    async fn an_early_response_reaches_the_client_mid_upload() {
        let kit = kit(RULES, vec![addon("s", "pass", AddonMode::Enforce, |_| {})]).await;
        let mut c = kit.h1().await;
        let (mut tx, body) = streaming_body();
        let req = c.request("POST", "/early", &[]).body(body).unwrap();
        let answer = c.start(req);
        tx.send_data(Bytes::from_static(b"chunk")).await.unwrap();
        let a: Answer = tokio::time::timeout(Duration::from_secs(5), answer)
            .await
            .expect("the answer arrives while the client is still uploading")
            .unwrap()
            .unwrap();
        assert_eq!(a.status, 200, "{a:?}");
        assert_eq!(a.text(), "early");
        tx.send_data(Bytes::from_static(b"chunk")).await.unwrap();
        tx.finish().await.unwrap();
        let seen = kit.upstream.wait_seen(1).await;
        assert_eq!(seen[0].body, b"chunkchunk");
        let ev = kit.request_event().await;
        assert_eq!(strs(&ev["addons"]), ["s"], "{ev:#}");
        assert!(
            kit.sink
                .events()
                .iter()
                .all(|e| e["event"] != "layer_error"),
            "{:#?}",
            kit.sink.events()
        );
        assert_eq!(kit.upstream.service().resets(), []);
    }

    /// Getting a stream and the service's answer each have their own
    /// `first_byte_timeout`: an exchange that waited for the only stream
    /// still has all of it for the answer.
    #[tokio::test]
    async fn waiting_for_a_stream_does_not_shorten_the_answer() {
        let kit = kit(
            RULES,
            vec![addon("s", "slow", AddonMode::Enforce, |s| {
                s.max_connections = 1;
                s.max_streams = 1;
                s.first_byte_timeout = SLOW * 3 / 2;
            })],
        )
        .await;
        let mut a = kit.h1().await;
        let mut b = kit.h1().await;
        let first = a.request("GET", "/a", &[]).body(Body::empty()).unwrap();
        let first = a.start(first);
        tokio::time::sleep(SLOW / 4).await;
        // Waits for the stream until the service has answered `first`, and
        // is answered `SLOW` after that: past `first_byte_timeout` from
        // the start, within it from its request head.
        let second = b.request("GET", "/b", &[]).body(Body::empty()).unwrap();
        let second = b.start(second);
        for answer in [first, second] {
            let r: Answer = answer.await.unwrap().unwrap();
            assert_eq!(r.status, 200, "{r:?}");
        }
    }

    /// A connection whose write side has died while its read side is
    /// still open (the service stopped reading, and roxy has not yet seen
    /// EOF) fails the exchanges on it closed at once, not when
    /// `first_byte_timeout` runs out.
    #[tokio::test(start_paused = true)]
    async fn a_dead_write_side_fails_the_exchange_at_once() {
        let kit = kit(
            RULES,
            vec![addon("s", "pass", AddonMode::Enforce, |s| {
                s.max_connections = 1;
                s.first_byte_timeout = Duration::from_secs(5);
            })],
        )
        .await;
        let a = kit.h1().await.call("GET", "/x", &[], b"").await;
        assert_eq!(a.status, 200, "{a:?}");
        kit.upstream.fail_writes();
        let (a, took) = timed(async { kit.h1().await.call("GET", "/x", &[], b"").await }).await;
        assert_eq!(a.status, 503, "{a:?}");
        assert_eq!(took, Duration::ZERO, "fails at once, before any deadline");
        let errs = kit.events("layer_error", 1).await;
        assert_eq!(errs[0]["layer"], "s", "{errs:#?}");
        assert_eq!(errs[0]["kind"], "service:closed", "{errs:#?}");
    }

    /// A client that leaves mid-response resets the stream at once, even
    /// while the service is sending nothing (a long poll, an idle event
    /// stream), so the stream gives up its place on the connection.
    #[tokio::test]
    async fn a_client_leaving_mid_response_resets_a_quiet_stream() {
        for client in ["h1", "h1 tunnel", "h2"] {
            let kit = kit(RULES, vec![addon("s", "hold", AddonMode::Enforce, |_| {})]).await;
            let mut c = match client {
                "h1" => kit.h1().await,
                "h1 tunnel" => kit.tunnel("up.test", false).await,
                _ => kit.tunnel("up.test", true).await,
            };
            let req = c
                .request("GET", "/x", &[])
                .body(roxy_http::Body::empty())
                .unwrap();
            let res = c.send(req).await.unwrap();
            assert_eq!(res.status(), 200, "{client}");
            drop(res);
            drop(c);
            let service = kit.upstream.service();
            let stream = service.until_opened(1).await[0]["stream"].as_u64().unwrap();
            let reset = tokio::time::timeout(Duration::from_secs(2), async {
                while service.resets().is_empty() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await;
            assert!(
                reset.is_ok(),
                "{client}: the stream is reset once the client leaves"
            );
            let resets = service.resets();
            assert_eq!(resets[0].0, u32::try_from(stream).unwrap(), "{resets:?}");
            assert_eq!(resets[0].1, "the client went away", "{client}");
        }
    }

    /// A client upload that breaks mid-body is the client's fault through a
    /// service layer as without one: the connection closes on the parse
    /// error, and the service is not blamed.
    #[tokio::test]
    async fn a_client_upload_failing_mid_body_is_not_the_services_fault() {
        let kit = kit(RULES, vec![addon("s", "pass", AddonMode::Enforce, |_| {})]).await;
        let (out, eof) = kit
            .raw(
                b"POST http://up.test/x HTTP/1.1\r\nhost: up.test\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\nzz\r\n",
            )
            .await;
        assert!(eof, "{out}");
        assert!(out.starts_with("HTTP/1.1 400"), "{out}");
        let errs = kit.events("parse_error", 1).await;
        assert_eq!(errs[0]["reason"], "bad_chunk_size", "{errs:#?}");
        let ev = kit.request_event().await;
        assert_eq!(ev["reason"], "bad_chunk_size", "{ev:#}");
        no_layer_error(&kit);
    }

    /// An upstream response body that fails before the service has
    /// answered the response head is the upstream's fault: the client gets
    /// the `502` it would if the core had read the body, and the service is
    /// not blamed.
    #[tokio::test]
    async fn an_upstream_body_failing_before_the_services_answer_is_not_its_fault() {
        let kit = kit(
            RULES,
            vec![addon("s", "forward", AddonMode::Enforce, |_| {})],
        )
        .await;
        let a = kit.h1().await.call("GET", "/cut", &[], b"").await;
        assert_eq!(a.status, 502, "{a:?}");
        let ev = kit.request_event().await;
        assert_eq!(ev["reason"], "upstream_body_failed", "{ev:#}");
        no_layer_error(&kit);
    }

    /// A service that sends more of the request it forwards than it
    /// declared fails as a protocol violation, logged against it, though
    /// the exchange is still upstream of the layer when it happens: here the
    /// rules read the body, and the core ends on its failure.
    #[tokio::test]
    async fn a_forwarded_body_longer_than_declared_is_the_services_fault() {
        let kit = kit(
            READS_BODY,
            vec![addon("s", "overlong", AddonMode::Enforce, |_| {})],
        )
        .await;
        let a = kit.h1().await.call("POST", "/x", &[], b"body").await;
        assert_eq!(a.status, 503, "{a:?}");
        let errs = kit.events("layer_error", 1).await;
        assert_eq!(errs[0]["layer"], "s", "{errs:#?}");
        assert_eq!(errs[0]["kind"], "service:protocol", "{errs:#?}");
        let ev = kit.request_event().await;
        assert_eq!(ev["reason"], "layer_error", "{ev:#}");
    }

    /// What a service sends on an observe stream is discarded and credited
    /// back as it goes, so a service that keeps to its credit can send
    /// several windows' worth while the stream is open.
    #[tokio::test]
    async fn an_observe_stream_credits_back_what_it_discards() {
        let kit = kit(RULES, vec![addon("o", "talk", AddonMode::Observe, |_| {})]).await;
        let mut c = kit.h1().await;
        let (mut tx, body) = streaming_body();
        let req = c.request("POST", "/x", &[]).body(body).unwrap();
        let answer = c.start(req);
        kit.upstream.service().until_talked(1).await;
        tx.send_data(Bytes::from_static(b"body")).await.unwrap();
        tx.finish().await.unwrap();
        let a: Answer = answer.await.unwrap().unwrap();
        assert_eq!(a.status, 200, "{a:?}");
        kit.request_event().await;
        assert!(
            kit.sink
                .events()
                .iter()
                .all(|e| e["event"] != "layer_error"),
            "{:#?}",
            kit.sink.events()
        );
    }

    /// Body bytes on an observe stream are bounded by the window like any
    /// body: a frame past it fails the stream, and the exchange goes on.
    #[tokio::test]
    async fn an_observe_stream_flooded_past_its_window_fails_on_its_own() {
        let kit = kit(RULES, vec![addon("o", "flood", AddonMode::Observe, |_| {})]).await;
        let mut c = kit.h1().await;
        let (mut tx, body) = streaming_body();
        let req = c.request("POST", "/x", &[]).body(body).unwrap();
        let answer = c.start(req);
        // The flood lands while the observe stream still waits for the
        // request body.
        tokio::time::sleep(Duration::from_millis(500)).await;
        tx.send_data(Bytes::from_static(b"body")).await.unwrap();
        tx.finish().await.unwrap();
        let a: Answer = answer.await.unwrap().unwrap();
        assert_eq!(a.status, 200, "{a:?}");
        assert_eq!(a.json()["body_len"], 4);
        let errs = kit.events("layer_error", 1).await;
        assert_eq!(errs[0]["layer"], "o", "{errs:#?}");
        assert_eq!(errs[0]["mode"], "observe");
        assert_eq!(errs[0]["kind"], "service:protocol");
        let resets = kit.upstream.service().resets();
        assert!(
            resets
                .iter()
                .any(|(_, m)| m.contains("past the body's credit")),
            "{resets:?}"
        );
    }

    /// An observer that keeps up sees every body in full: the copy is
    /// buffered for it, so an upload that lands whole while the service is
    /// not yet reading still reaches it whole, with the response after it.
    #[tokio::test]
    async fn a_fast_upload_reaches_an_observer_whole() {
        let kit = kit(RULES, vec![addon("o", "pause", AddonMode::Observe, |_| {})]).await;
        let mut c = kit.h1().await;
        let upload = 4 * 1024 * 1024;
        let req = c
            .request("POST", "/x", &[])
            .body(roxy_http::Body::from_bytes(Bytes::from(vec![b'x'; upload])))
            .unwrap();
        let a = Answer::read(c.send(req).await.unwrap()).await;
        assert_eq!(a.status, 200, "{a:?}");
        assert_eq!(a.json()["body_len"], upload);
        kit.request_event().await;
        // Both copies travel on the observer's one stream.
        let stream = kit.upstream.service().until_opened(1).await[0]["stream"]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .unwrap();
        let copied = upload + a.body.as_ref().unwrap().len();
        kit.upstream.service().until_received(stream, copied).await;
        assert_eq!(kit.upstream.service().received(stream), copied);
        let lagged: Vec<_> = kit
            .sink
            .events()
            .into_iter()
            .filter(|e| e["event"] == "observer_lagged")
            .collect();
        assert!(lagged.is_empty(), "{lagged:#?}");
    }

    /// An observer that holds its copy without reading it is lagging: once
    /// the copy is `max_observer_lag_bytes` behind it is cut and reported,
    /// and the real body goes through whole. The cut resets the observer's
    /// stream and frees its place on the connection, which an enforce
    /// layer on the same endpoint shares.
    #[tokio::test]
    async fn a_slow_observer_is_cut_and_reported_while_the_body_goes_through() {
        // The service never grants credit: the copy stalls once the
        // stream's window is spent.
        let kit = Kit::builder()
            .rules(RULES)
            .limits(|l| l.max_observer_lag_bytes = 64 * 1024)
            .start()
            .await;
        let one_place = |s: &mut ServiceSpec| {
            s.max_connections = 1;
            s.max_streams = 1;
        };
        reload(
            &kit,
            RULES,
            &[],
            vec![
                only_when(
                    addon("o", "hoard", AddonMode::Observe, one_place),
                    r#"path == "/x""#,
                ),
                only_when(
                    addon("e", "hoard", AddonMode::Enforce, one_place),
                    r#"path == "/e""#,
                ),
            ],
        );
        let mut c = kit.h1().await;
        let (mut tx, body) = streaming_body();
        let req = c.request("POST", "/x", &[]).body(body).unwrap();
        let answer = c.start(req);
        let chunk = Bytes::from(vec![b'x'; 16 * 1024]);
        let chunks = 40;
        for _ in 0..chunks {
            tx.send_data(chunk.clone()).await.unwrap();
        }
        tx.finish().await.unwrap();
        let a: Answer = answer.await.unwrap().unwrap();
        assert_eq!(a.status, 200, "{a:?}");
        assert_eq!(a.json()["body_len"], chunks * chunk.len());
        let seen = kit.upstream.wait_seen(1).await;
        assert_eq!(seen[0].complete, Some(true));
        let lagged = kit.events("observer_lagged", 1).await;
        assert_eq!(lagged[0]["layer"], "o", "{lagged:#?}");
        assert_eq!(lagged[0]["direction"], "request");
        assert_eq!(lagged[0]["reason"], "observer_behind");

        let service = kit.upstream.service();
        let observed = service.until_opened(1).await[0]["stream"].as_u64().unwrap();
        let reset = tokio::time::timeout(Duration::from_secs(5), async {
            while service.resets().is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(reset.is_ok(), "the cut observer stream is reset");
        assert_eq!(service.resets()[0].0, u32::try_from(observed).unwrap());

        let enforced = tokio::time::timeout(
            Duration::from_secs(2),
            kit.h1().await.call("GET", "/e", &[], b""),
        )
        .await
        .expect("the enforce stream opens at once: the observer's place is free");
        assert_eq!(enforced.status, 200, "{enforced:?}");
    }

    /// A secret the rules inject is captured redacted, through the stack as
    /// without one; the upstream gets the real value.
    #[tokio::test]
    async fn a_captured_head_redacts_an_injected_secret() {
        const WITH_TOKEN: &str = r#"
- id: up
  when: host == "up.test"
  then:
    - set_header: { x-token: "Bearer ${secret:tok}" }
    - allow
"#;
        let kit = Kit::builder().rules(RULES).capture_all().start().await;
        reload(
            &kit,
            WITH_TOKEN,
            &[("tok", "sk-live-123")],
            vec![addon("s", "pass", AddonMode::Enforce, |_| {})],
        );
        let a = kit.h1().await.call("GET", "/x", &[], b"").await;
        assert_eq!(a.status, 200, "{a:?}");
        let seen = kit.upstream.wait_seen(1).await;
        assert_eq!(seen[0].headers["x-token"], "Bearer sk-live-123");
        kit.request_event().await;
        let captured = kit.captured();
        let (_, head) = captured
            .iter()
            .find(|(h, _)| h["dir"] == "request" && h["kind"] == "head")
            .expect("the request head is captured");
        let head: serde_json::Value = serde_json::from_slice(head).unwrap();
        let token = head["headers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|h| h[0] == "x-token")
            .expect("x-token captured");
        assert_eq!(token[1], "Bearer [REDACTED]", "{head:#}");
        assert!(
            !captured
                .iter()
                .any(|(_, p)| p.windows(11).any(|w| w == b"sk-live-123")),
            "the secret is nowhere in the capture"
        );
    }

    /// A service subscribed to the heads only is sent each head with its
    /// end and no bytes, is told so on `open`, and the bodies go through
    /// it untouched; an observer so subscribed holds no copy, so one that
    /// never reads is not lagging.
    #[tokio::test]
    async fn a_head_only_service_gets_heads_and_the_bodies_bypass_it() {
        use crate::addons::Part;
        let kit = Kit::builder()
            .rules(RULES)
            .limits(|l| l.max_observer_lag_bytes = 64 * 1024)
            .start()
            .await;
        reload(
            &kit,
            RULES,
            &[],
            vec![
                subscribed(
                    addon("o", "hoard", AddonMode::Observe, |_| {}),
                    Part::Head,
                    Part::Head,
                ),
                subscribed(
                    addon("s", "pass", AddonMode::Enforce, |_| {}),
                    Part::Head,
                    Part::Full,
                ),
            ],
        );
        let mut c = kit.h1().await;
        let (mut tx, body) = streaming_body();
        let req = c.request("POST", "/x", &[]).body(body).unwrap();
        let answer = c.start(req);
        let chunk = Bytes::from(vec![b'x'; 16 * 1024]);
        let chunks = 40;
        for _ in 0..chunks {
            tx.send_data(chunk.clone()).await.unwrap();
        }
        tx.finish().await.unwrap();
        let a: Answer = answer.await.unwrap().unwrap();
        assert_eq!(a.status, 200, "{a:?}");
        assert_eq!(a.json()["body_len"], chunks * chunk.len());
        let opens = kit.upstream.service().until_opened(2).await;
        let by_layer = |name: &str| {
            opens
                .iter()
                .find(|o| o["layer"] == name)
                .unwrap_or_else(|| panic!("{name} in {opens:#?}"))
                .clone()
        };
        assert_eq!(by_layer("o")["subscribe"]["request"], "head");
        assert_eq!(by_layer("o")["subscribe"]["response"], "head");
        assert_eq!(by_layer("s")["subscribe"]["request"], "head");
        assert_eq!(by_layer("s")["subscribe"]["response"], "full");
        let ev = kit.request_event().await;
        assert_eq!(strs(&ev["addons"]), ["o", "s"], "{ev:#}");
        let lagged: Vec<_> = kit
            .sink
            .events()
            .into_iter()
            .filter(|e| e["event"] == "observer_lagged")
            .collect();
        assert!(lagged.is_empty(), "{lagged:#?}");
        no_layer_error(&kit);
    }

    /// A head-only direction of a service is a head and an end, complete
    /// at once, so the body bypassing it keeps the framing it came with: to
    /// the upstream with the client's `content-length`, to the client with
    /// the upstream's. Bytes the service sends for that direction fail the
    /// exchange closed as the service's own.
    #[tokio::test]
    async fn a_head_only_service_keeps_the_bypassed_bodies_framing() {
        use crate::addons::Part;
        for (request, response) in [
            (Part::Head, Part::Full),
            (Part::Full, Part::Head),
            (Part::Head, Part::Head),
        ] {
            let kit = kit(
                RULES,
                vec![subscribed(
                    addon("s", "pass", AddonMode::Enforce, |_| {}),
                    request,
                    response,
                )],
            )
            .await;
            let a = kit
                .h1()
                .await
                .call("POST", "/x", &[], b"twelve bytes")
                .await;
            assert_eq!(a.status, 200, "{request:?}/{response:?}: {a:?}");
            assert_eq!(a.json()["body_len"], 12, "{request:?}/{response:?}");
            let seen = kit.upstream.wait_seen(1).await;
            assert_eq!(seen[0].complete, Some(true), "{request:?}/{response:?}");
            if request == Part::Head {
                assert_eq!(
                    seen[0].headers["content-length"], "12",
                    "{request:?}/{response:?}"
                );
                assert!(
                    !seen[0].headers.contains_key("transfer-encoding"),
                    "{request:?}/{response:?}: {:?}",
                    seen[0].headers
                );
            }
            if response == Part::Head {
                assert!(
                    a.headers.contains_key("content-length"),
                    "{request:?}/{response:?}: {a:?}"
                );
                assert!(
                    !a.headers.contains_key("transfer-encoding"),
                    "{request:?}/{response:?}: {a:?}"
                );
            }
            no_layer_error(&kit);
        }

        // `overlong` forwards the request head and sends bytes after it.
        let kit = kit(
            RULES,
            vec![subscribed(
                addon("s", "overlong", AddonMode::Enforce, |_| {}),
                Part::Head,
                Part::Full,
            )],
        )
        .await;
        let a = kit
            .h1()
            .await
            .call("POST", "/x", &[], b"twelve bytes")
            .await;
        assert_eq!(a.status, 503, "{a:?}");
        let ev = kit.request_event().await;
        assert_eq!(ev["terminal_rule"], "layer:s", "{ev:#}");
        let errs = kit.events("layer_error", 1).await;
        assert_eq!(errs[0]["kind"], "unsubscribed:request", "{errs:#?}");
    }

    /// A WebSocket through a pass-through service: the upstream's `101`
    /// reaches the service as roxy's `response` head, with no `request_end`
    /// before it, the service's `101` upgrades the client, and the bytes of
    /// both sides then go through the stream.
    #[tokio::test]
    async fn a_websocket_is_relayed_through_a_pass_through_service() {
        let kit = kit(RULES, vec![addon("s", "pass", AddonMode::Enforce, |_| {})]).await;
        let (status, io) = kit.websocket("/ws", &[]).await;
        assert_eq!(status, 101);
        let mut io = io.unwrap();
        assert_eq!(echo(&mut io, b"hello").await, b"hello");
        assert_eq!(echo(&mut io, b"again").await, b"again");
        let service = kit.upstream.service();
        let stream = stream_id(&service.until_opened(1).await[0]);
        assert_eq!(service.received_in(stream, "request"), 10);
        assert_eq!(service.received_in(stream, "response"), 10);
        let controls = service.controls(stream);
        let kinds: Vec<&str> = controls
            .iter()
            .map(|m| m["type"].as_str().unwrap())
            .collect();
        let response = kinds
            .iter()
            .position(|k| *k == "response")
            .unwrap_or_else(|| panic!("a response head in {kinds:?}"));
        assert_eq!(controls[response]["status"], 101, "{controls:#?}");
        assert_eq!(kinds[..response], ["open", "request"], "{kinds:?}");
        drop(io);
        let close = kit.events("ws_close", 1).await;
        assert_eq!(close[0]["bytes_c2s"], 10, "{close:#?}");
        assert_eq!(close[0]["bytes_s2c"], 10, "{close:#?}");
        no_layer_error(&kit);
    }

    /// The relayed bytes are the service's to rewrite: what it sends on
    /// each body is what the other side gets.
    #[tokio::test]
    async fn a_service_may_rewrite_the_relayed_bytes() {
        use futures_util::{SinkExt as _, StreamExt as _};
        use tokio_tungstenite::tungstenite::Message;
        let kit = kit(RULES, vec![addon("s", "shout", AddonMode::Enforce, |_| {})]).await;
        let mut ws = kit.ws("/ws", &[("x-echo", "frames")]).await;
        ws.send(Message::text("hello")).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("an echo in time")
            .unwrap()
            .unwrap();
        // Uppercased on the response side only: the upstream got, and
        // echoed, the client's bytes as sent.
        assert_eq!(got, Message::text("HELLO"));
        assert_eq!(kit.upstream.ws_received(), [b"hello"]);
        ws.close(None).await.unwrap();
        kit.upstream.wait_ws_closed(1).await;
        no_layer_error(&kit);
    }

    /// A service may answer an upgrade like any request: the client gets
    /// its response and nothing is relayed.
    #[tokio::test]
    async fn a_service_may_answer_an_upgrade_itself() {
        let kit = kit(
            RULES,
            vec![addon("s", "refuse", AddonMode::Enforce, |_| {})],
        )
        .await;
        let (status, io) = kit.websocket("/ws", &[]).await;
        assert_eq!(status, 403);
        assert!(io.is_none());
        assert!(kit.upstream.seen().is_empty());
        let ev = kit.request_event().await;
        assert_eq!(ev["terminal_rule"], "layer:s", "{ev:#}");
        assert_eq!(ev["decision"], "answered", "{ev:#}");
        no_layer_error(&kit);
    }

    /// The core reserves relay buffers before publishing a `101`. If that
    /// fails, the service receives a normal refusal and releases its slot.
    #[tokio::test]
    async fn an_upgrade_without_relay_buffers_is_refused_before_101() {
        let rules = format!(
            "{RULES}
- id: no-binary
  when: ws.opcode == 2
  then: deny
"
        );
        let kit = kit_with(
            &rules,
            vec![addon("s", "pass", AddonMode::Enforce, |s| {
                s.max_connections = 1;
                s.max_streams = 1;
            })],
            |b| b.limits(|l| l.max_buffered_bytes = l.max_ws_message_bytes),
        )
        .await;
        let (status, io) = kit.websocket("/ws", &[("x-echo", "frames")]).await;
        assert_eq!(status, 503, "fails closed on the budget");
        assert!(io.is_none());
        let service = kit.upstream.service();
        let stream = stream_id(&service.until_opened(1).await[0]);
        let controls = service.controls(stream);
        assert!(
            controls
                .iter()
                .any(|m| m["type"] == "response" && m["status"] == 503),
            "{controls:?}"
        );
        assert!(
            !controls
                .iter()
                .any(|m| m["type"] == "response" && m["status"] == 101),
            "{controls:?}"
        );
        let (status, _) = tokio::time::timeout(Duration::from_secs(5), kit.websocket("/ws", &[]))
            .await
            .expect("the first stream released its slot");
        assert_eq!(status, 503);
        service.until_opened(2).await;
    }

    /// The relay's end resets a stream whose bodies have not both ended:
    /// here the service holds the upstream's side of the WebSocket, so the
    /// client gets nothing, the relay ends on the idle timeout, and the
    /// client is closed and the stream reset.
    #[tokio::test]
    async fn the_relay_ending_resets_a_stream_with_a_body_still_open() {
        let kit = Kit::builder()
            .rules(RULES)
            .limits(|l| l.idle_timeout = Duration::from_millis(300))
            .start()
            .await;
        reload(
            &kit,
            RULES,
            &[],
            vec![addon("s", "hold", AddonMode::Enforce, |_| {})],
        );
        let (status, io) = kit.websocket("/ws", &[("x-echo", "once")]).await;
        assert_eq!(status, 101);
        let mut io = io.unwrap();
        io.write_all(b"hello").await.unwrap();
        let service = kit.upstream.service();
        let stream = stream_id(&service.until_opened(1).await[0]);
        // The upstream echoed and closed; the service passed the client's
        // bytes on and holds the upstream's.
        service.until_received(stream, 10).await;
        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), io.read_to_end(&mut rest))
            .await
            .expect("EOF in time")
            .unwrap();
        assert!(rest.is_empty(), "{rest:?}");
        reset_of(&kit, stream).await;
        kit.events("ws_close", 1).await;
    }

    /// roxy sends no `request_end` before the `101`: a service that holds
    /// the request until its body has ended never forwards an upgrade, and
    /// the exchange fails on `first_byte_timeout`. The same service forwards
    /// an ordinary request once its body has ended.
    #[tokio::test(start_paused = true)]
    async fn a_service_waiting_for_request_end_never_forwards_an_upgrade() {
        let kit = kit(
            RULES,
            vec![addon("s", "patient", AddonMode::Enforce, |s| {
                s.first_byte_timeout = Duration::from_millis(500);
            })],
        )
        .await;
        let a = kit.h1().await.call("POST", "/x", &[], b"body").await;
        assert_eq!(a.status, 200, "{a:?}");
        assert_eq!(a.json()["body_len"], 4);
        let ((status, io), took) = timed(kit.websocket("/ws", &[])).await;
        assert_eq!(status, 503);
        assert!(io.is_none());
        assert_eq!(
            took,
            Duration::from_millis(500),
            "fails on first_byte_timeout"
        );
        let errs = kit.events("layer_error", 1).await;
        assert_eq!(errs[0]["layer"], "s", "{errs:#?}");
        assert_eq!(errs[0]["kind"], "service:timeout", "{errs:#?}");
        assert!(
            kit.upstream.seen().iter().all(|s| s.path != "/ws"),
            "the upgrade never reached the upstream: {:#?}",
            kit.upstream.seen()
        );
    }

    /// A service that ends its forwarded request with an error has cut its
    /// own forward: an abort, not a fault. Nothing answers it (its
    /// response lane comes back cut, headless), and a service that passes
    /// that on rather than answering has given no answer: the client gets
    /// the `503` that earns, logged as `no_response`.
    #[tokio::test]
    async fn a_service_cutting_its_forward_gets_no_answer_for_it() {
        let kit = kit(
            RULES,
            vec![addon("s", "cut-forward", AddonMode::Enforce, |_| {})],
        )
        .await;
        let a = kit.h1().await.call("POST", "/x", &[], b"body").await;
        assert_eq!(a.status, 503, "{a:?}");
        assert_eq!(a.headers["x-roxy-rule"], "layer:s");
        let ev = kit.request_event().await;
        assert_eq!(ev["decision"], "deny", "{ev:#}");
        assert_eq!(ev["terminal_rule"], "layer:s");
        let errs = kit.events("layer_error", 1).await;
        assert_eq!(errs[0]["kind"], "no_response", "{errs:#?}");
        assert!(kit.upstream.seen().is_empty(), "nothing complete left");
    }

    /// A service that fails with the response from upstream open at it (its
    /// clock runs out while the body is idle) takes the body down with its
    /// stream, so the record is finished on the refusal the downstream layer
    /// passes on, not held until the body yields.
    #[tokio::test(start_paused = true)]
    async fn a_body_idle_at_a_failed_service_goes_with_its_stream() {
        let kit = kit(
            RULES,
            vec![
                AddonDef::test_layer("a").spec().await,
                addon("s", "forward", AddonMode::Enforce, |s| {
                    s.first_byte_timeout = Duration::from_millis(500);
                }),
            ],
        )
        .await;
        let ((a, ev), took) = timed(async {
            let a = kit
                .h1()
                .await
                .call("GET", "/drip?n=1&first=5000", &[("x-test-a", "pass")], b"")
                .await;
            (a, kit.request_event().await)
        })
        .await;
        assert_eq!(a.status, 503, "{a:?}");
        assert_eq!(a.headers["x-roxy-rule"], "layer:s");
        assert_eq!(ev["reason"], "layer_error", "{ev:#}");
        assert!(
            took < Duration::from_secs(1),
            "the record is not held for the idle body: {took:?}"
        );
    }

    /// The client leaving before the answer (an HTTP/2 connection closed
    /// with the stream open) tears the stack down: a service holding the
    /// exchange is reset, however far the downstream layers have got and
    /// whether or not its forward is through.
    #[tokio::test]
    async fn h2_the_client_leaving_before_the_answer_resets_the_service() {
        let kit = kit(
            RULES,
            vec![
                AddonDef::test_layer("a").spec().await,
                addon("s", "hold", AddonMode::Enforce, |_| {}),
            ],
        )
        .await;
        let mut c = kit.tunnel("up.test", true).await;
        let req = c
            .request("GET", "/x", &[("x-test-a", "buffer")])
            .body(roxy_http::Body::empty())
            .unwrap();
        let mut pending = Box::pin(c.send(req));
        assert!(futures_util::poll!(pending.as_mut()).is_pending());
        let service = kit.upstream.service();
        let stream = stream_id(&service.until_opened(1).await[0]);
        drop(pending);
        drop(c);
        reset_of(&kit, stream).await;
    }

    /// A response body that fails upstream of the service ends the response lane
    /// with the error and nothing more: the stream is not reset, the
    /// service passes the cut on, and the client's body is cut as it would
    /// be without a layer.
    #[tokio::test]
    async fn a_body_cut_below_ends_the_lane_and_leaves_the_stream() {
        let kit = kit(RULES, vec![addon("s", "pass", AddonMode::Enforce, |_| {})]).await;
        let a = kit.h1().await.call("GET", "/cut", &[], b"").await;
        assert_eq!(a.status, 200, "{a:?}");
        assert!(a.body.is_err(), "the cut reaches the client: {a:?}");
        let svc = kit.upstream.service();
        let opens = svc.until_opened(1).await;
        let id = stream_id(&opens[0]);
        let ended_with_error = svc.controls(id).iter().any(|c| {
            c["type"] == "response_end" && c["error"].as_str().is_some_and(|e| !e.is_empty())
        });
        assert!(ended_with_error, "{:#?}", svc.controls(id));
        assert!(svc.resets().is_empty(), "{:?}", svc.resets());
        no_layer_error(&kit);
    }

    /// The service's second deadline runs from roxy's `response` head, not
    /// from the end of the response body: a service that forwards and then
    /// holds the response head fails closed on `first_byte_timeout` while
    /// the upstream's body is still arriving.
    #[tokio::test(start_paused = true)]
    async fn a_held_response_head_times_out_from_the_response_head() {
        let kit = kit(
            RULES,
            vec![addon("s", "forward", AddonMode::Enforce, |s| {
                s.first_byte_timeout = Duration::from_millis(700);
            })],
        )
        .await;
        // The head at once, the body over 3 s.
        let (a, took) = timed(async {
            kit.h1()
                .await
                .call("GET", "/drip?n=3&ms=1000", &[], b"")
                .await
        })
        .await;
        assert_eq!(a.status, 503, "{a:?}");
        assert_eq!(
            took,
            Duration::from_millis(700),
            "fails on first_byte_timeout from the response head"
        );
        assert_eq!(kit.upstream.seen().len(), 1, "the request was forwarded");
        let errs = kit.events("layer_error", 1).await;
        assert_eq!(errs[0]["layer"], "s", "{errs:#?}");
        assert_eq!(errs[0]["kind"], "service:timeout", "{errs:#?}");
        let ev = kit.request_event().await;
        assert_eq!(ev["terminal_rule"], "layer:s", "{ev:#}");
    }

    /// A service that resets an enforce stream before answering fails the
    /// exchange closed as its own: a `503` against the layer, nothing
    /// forwarded.
    #[tokio::test]
    async fn a_reset_before_the_response_head_fails_the_exchange_closed() {
        let kit = kit(RULES, vec![addon("s", "abort", AddonMode::Enforce, |_| {})]).await;
        let a = kit.h1().await.call("GET", "/x", &[], b"").await;
        assert_eq!(a.status, 503, "{a:?}");
        assert!(kit.upstream.seen().is_empty());
        let errs = kit.events("layer_error", 1).await;
        assert_eq!(errs[0]["layer"], "s", "{errs:#?}");
        assert_eq!(errs[0]["kind"], "service:closed", "{errs:#?}");
        assert!(
            errs[0]["message"]
                .as_str()
                .is_some_and(|m| m.contains("aborted")),
            "{errs:#?}"
        );
        let ev = kit.request_event().await;
        assert_eq!(ev["terminal_rule"], "layer:s", "{ev:#}");
        assert_eq!(ev["reason"], "layer_error", "{ev:#}");
    }

    /// A service that ends the request it forwards short of the length it
    /// declared fails as a protocol violation, logged against it.
    #[tokio::test]
    async fn a_forwarded_body_shorter_than_declared_is_the_services_fault() {
        let kit = kit(
            READS_BODY,
            vec![addon("s", "short", AddonMode::Enforce, |_| {})],
        )
        .await;
        let a = kit.h1().await.call("POST", "/x", &[], b"body").await;
        assert_eq!(a.status, 503, "{a:?}");
        assert!(kit.upstream.seen().is_empty());
        let errs = kit.events("layer_error", 1).await;
        assert_eq!(errs[0]["layer"], "s", "{errs:#?}");
        assert_eq!(errs[0]["kind"], "service:protocol", "{errs:#?}");
        let ev = kit.request_event().await;
        assert_eq!(ev["reason"], "layer_error", "{ev:#}");
    }

    /// An exchange that finds every connection full waits for a stream
    /// within `first_byte_timeout`, and fails closed when none frees up:
    /// no stream is opened for it, and the service is not blamed for more
    /// than the timeout.
    #[tokio::test(start_paused = true)]
    async fn a_pool_full_for_the_whole_first_byte_timeout_fails_closed() {
        let kit = kit(
            RULES,
            vec![addon("s", "hold", AddonMode::Enforce, |s| {
                s.max_connections = 1;
                s.max_streams = 1;
                s.first_byte_timeout = Duration::from_millis(500);
            })],
        )
        .await;
        // The held response body keeps the one stream busy.
        let mut busy = kit.h1().await;
        let req = busy.request("GET", "/x", &[]).body(Body::empty()).unwrap();
        let held = busy.send(req).await.unwrap();
        assert_eq!(held.status(), 200);
        let (a, took) = timed(async { kit.h1().await.call("GET", "/y", &[], b"").await }).await;
        assert_eq!(a.status, 503, "{a:?}");
        assert_eq!(
            took,
            Duration::from_millis(500),
            "fails on first_byte_timeout"
        );
        let errs = kit.events("layer_error", 1).await;
        assert_eq!(errs[0]["layer"], "s", "{errs:#?}");
        assert_eq!(errs[0]["kind"], "service:timeout", "{errs:#?}");
        assert_eq!(
            kit.upstream.service().opens().len(),
            1,
            "no stream for the second exchange"
        );
        assert_eq!(kit.upstream.seen().len(), 1);
        drop(held);
    }
}

// ---- one layer: effects, limits, capabilities -----------------------------

const SECRET: &str = "s3cr3t-token-value-0123456789";

/// A single test layer `t` downstream of the default rules.
async fn one(def: AddonDef) -> Kit {
    Kit::builder().addon(def).start().await
}

/// A state store with no room for a new key.
struct FullState;

impl crate::sources::StateSource for FullState {
    fn get(&self, _key: &str) -> Option<String> {
        None
    }

    fn set(
        &self,
        _key: &str,
        _value: &str,
        _ttl: Option<std::time::Duration>,
    ) -> Result<(), crate::sources::StateFull> {
        Err(crate::sources::StateFull)
    }
}

/// `x-test-t: caps` with `x-cap`.
async fn cap(kit: &Kit, cap: &str) -> super::Answer {
    kit.h1()
        .await
        .call("POST", "/x", &[("x-test-t", "caps"), ("x-cap", cap)], b"")
        .await
}

#[tokio::test]
async fn a_rewrite_reaches_the_upstream() {
    let kit = one(AddonDef::test_layer("t")).await;
    let a = kit
        .h1()
        .await
        .call("POST", "/fine", &[("x-test-t", "rewrite")], b"original")
        .await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.json()["path"], "/rewritten");
    assert_eq!(a.json()["body_len"], 8, "replaced");
}

/// Each budget fails the exchange closed with a `layer_error` naming it.
#[tokio::test]
async fn limits_are_enforced() {
    let kit = one(AddonDef::test_layer("t").limits(|l| {
        l.max_memory = 16 << 20;
        l.first_byte_timeout = std::time::Duration::from_millis(500);
    }))
    .await;
    for (i, (test, kind)) in [
        ("loop", "budget:first_byte_timeout"),
        ("memory", "budget:max_memory"),
        ("host-loop", "budget:first_byte_timeout"),
        ("fields:200000", "budget:fields"),
    ]
    .into_iter()
    .enumerate()
    {
        let a = kit
            .h1()
            .await
            .call("GET", "/x", &[("x-test-t", test)], b"")
            .await;
        assert_eq!(a.status, 503, "{test}: {a:?}");
        let errs = kit.events("layer_error", i + 1).await;
        assert_eq!(errs[i]["kind"], kind, "{test}: {errs:#?}");
    }
}

/// A flow holds at most 64 tags and 4 KiB of them. A layer that tags
/// without end after its head is out has no clock to stop it, so the cap
/// does: the exchange fails `budget:tags`, cutting the body, and the flow
/// keeps the tags that fit.
#[tokio::test]
async fn tagging_without_end_after_the_head_is_cut_at_the_cap() {
    for (tag_len, fit) in [("2", 64), ("1024", 4)] {
        let kit = one(AddonDef::test_layer("t")).await;
        let a = kit
            .h1()
            .await
            .call(
                "GET",
                "/x",
                &[("x-test-t", "tags-after-head"), ("x-tag-len", tag_len)],
                b"",
            )
            .await;
        assert_eq!(a.status, 200, "{tag_len}: {a:?}");
        assert!(a.body.is_err(), "{tag_len}: the body is cut: {a:?}");
        let errs = kit.events("layer_error", 1).await;
        assert_eq!(errs[0]["kind"], "budget:tags", "{tag_len}: {errs:#?}");
        let ev = kit.request_event().await;
        assert_eq!(strs(&ev["tags"]).len(), fit, "{tag_len}: {ev:#}");
    }
}

/// Bodies have no clock: a response that streams for several times the
/// head deadline goes through a layer whole.
#[tokio::test]
async fn a_long_stream_goes_through_whole() {
    let kit = one(AddonDef::test_layer("t")
        .limits(|l| l.first_byte_timeout = std::time::Duration::from_millis(200)))
    .await;
    let a = kit
        .h1()
        .await
        .call("GET", "/drip?n=6&ms=100", &[], b"")
        .await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.text(), "chunk0;chunk1;chunk2;chunk3;chunk4;chunk5;");
}

/// A client that gives up frees the layer's instance: with one instance,
/// the next exchange gets it.
#[tokio::test]
async fn a_client_giving_up_frees_the_instance() {
    use http_body_util::BodyExt as _;
    let kit = one(AddonDef::test_layer("t").limits(|l| l.max_instances = 1)).await;
    let mut c = kit.h1().await;
    let req = c
        .request("GET", "/drip?n=1000&ms=50", &[])
        .body(roxy_http::Body::empty())
        .unwrap();
    let mut res = c.send(req).await.unwrap();
    assert_eq!(res.status(), 200);
    assert!(res.body_mut().frame().await.unwrap().is_ok());
    c.kill();
    drop(res);
    let a = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        kit.h1().await.call("GET", "/after", &[], b""),
    )
    .await
    .expect("the instance was freed");
    assert_eq!(a.status, 200, "{a:?}");
}

/// A client holding every instance cannot starve the layer: an exchange
/// that gets no instance within `first_byte_timeout` is denied,
/// `layer_error` kind `no_instance`, rather than queued for as long as the
/// holder likes. It waits the whole timeout first: an instance freed in
/// time would have served it.
#[tokio::test(start_paused = true)]
async fn an_exchange_without_an_instance_is_denied_within_the_bound() {
    use http_body_util::BodyExt as _;
    const FIRST_BYTE: std::time::Duration = std::time::Duration::from_millis(300);
    let kit = one(AddonDef::test_layer("t").limits(|l| {
        l.max_instances = 1;
        l.first_byte_timeout = FIRST_BYTE;
    }))
    .await;
    // The only instance relays a response that drips for a minute.
    let mut c = kit.h1().await;
    let req = c
        .request("GET", "/drip?n=1000&ms=50", &[])
        .body(roxy_http::Body::empty())
        .unwrap();
    let mut res = c.send(req).await.unwrap();
    assert_eq!(res.status(), 200);
    assert!(res.body_mut().frame().await.unwrap().is_ok());

    let (a, took) = super::timed(tokio::time::timeout(
        std::time::Duration::from_secs(10),
        kit.h1().await.call("GET", "/starved", &[], b""),
    ))
    .await;
    let a = a.expect("the exchange waited past the bound");
    assert_eq!(a.status, 503, "{a:?}");
    assert_eq!(took, FIRST_BYTE, "fails on first_byte_timeout");
    let errs = kit.events("layer_error", 1).await;
    assert_eq!(errs[0]["layer"], "t", "{errs:#?}");
    assert_eq!(errs[0]["kind"], "no_instance");
    assert_eq!(errs[0]["mode"], "enforce");
    assert!(
        !kit.upstream.seen().iter().any(|r| r.path == "/starved"),
        "a denied exchange reached the upstream"
    );
    c.kill();
    drop(res);
}

/// An observer that overruns its head deadline is logged, and the real
/// exchange goes through.
#[tokio::test]
async fn an_observer_that_times_out_is_logged_only() {
    let kit = one(AddonDef::test_layer("t")
        .observe()
        .limits(|l| l.first_byte_timeout = std::time::Duration::from_millis(200)))
    .await;
    let a = kit
        .h1()
        .await
        .call("POST", "/observed", &[("x-test-t", "loop")], b"payload")
        .await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.json()["body_len"], 7);
    let errs = kit.events("layer_error", 1).await;
    assert_eq!(errs[0]["mode"], "observe", "{errs:#?}");
    assert_eq!(errs[0]["kind"], "budget:first_byte_timeout");
}

fn endpoint_layer(url: &str, private_ok: bool) -> AddonDef {
    AddonDef::test_layer("t")
        .caps(&[roxy_wasm::Capability::Endpoints])
        .endpoint(
            "monitor",
            url,
            &[("x-api-key", "${secret:token}")],
            private_ok,
        )
}

/// The test layer's `endpoint` capability call, with the layer asking for
/// `path` on the endpoint.
async fn endpoint_call(kit: &Kit, path: &str) -> super::Answer {
    kit.h1()
        .await
        .call(
            "POST",
            "/x",
            &[
                ("x-test-t", "caps"),
                ("x-cap", "endpoint"),
                ("x-cap-path", path),
            ],
            b"",
        )
        .await
}

/// roxy attaches an endpoint's credential on the way out; the layer and
/// the flow log never see it. The default `path: fixed` sends the
/// configured URL, not the path the layer asked for.
#[tokio::test]
async fn endpoint_credentials_never_reach_the_layer() {
    let kit = Kit::builder()
        .secret("token", SECRET)
        .addon(endpoint_layer("https://up.test/monitor", true))
        .start()
        .await;
    let a = cap(&kit, "endpoint").await;
    assert_eq!(a.status, 200, "{a:?}");
    let text = a.text();
    assert!(text.starts_with("200 "), "{text}");
    assert!(!text.contains(SECRET));
    let seen = kit.upstream.wait_seen(1).await;
    let call = seen
        .iter()
        .find(|s| s.path == "/monitor")
        .unwrap_or_else(|| panic!("{seen:#?}"));
    assert_eq!(call.headers["x-api-key"], SECRET);
    let calls = kit.events("endpoint_call", 1).await;
    assert_eq!(calls[0]["endpoint"], "monitor");
    assert_eq!(calls[0]["status"], 200);
    assert!(!serde_json::to_string(&calls).unwrap().contains(SECRET));
}

/// An endpoint's headers all come from the secret generation of the
/// exchange making the call: a swap reaches the next exchange's call with
/// both values replaced, never one.
#[tokio::test]
async fn endpoint_credentials_follow_a_secret_swap_together() {
    let kit = Kit::builder()
        .secret("akid", "AKID1")
        .secret("sk", "SK1")
        .addon(
            AddonDef::test_layer("t")
                .caps(&[roxy_wasm::Capability::Endpoints])
                .endpoint(
                    "monitor",
                    "https://up.test/monitor",
                    &[
                        ("x-key-id", "${secret:akid}"),
                        ("authorization", "Bearer ${secret:sk}"),
                    ],
                    true,
                ),
        )
        .start()
        .await;
    let a = cap(&kit, "endpoint").await;
    assert_eq!(a.status, 200, "{a:?}");
    kit.server.handle().swap_secrets(
        [
            ("akid".to_owned(), "AKID2".to_owned()),
            ("sk".to_owned(), "SK2".to_owned()),
        ]
        .into(),
    );
    let a = cap(&kit, "endpoint").await;
    assert_eq!(a.status, 200, "{a:?}");

    let seen = kit.upstream.wait_seen(2).await;
    let calls: Vec<_> = seen.iter().filter(|s| s.path == "/monitor").collect();
    assert_eq!(calls.len(), 2, "{seen:#?}");
    assert_eq!(calls[0].headers["x-key-id"], "AKID1");
    assert_eq!(calls[0].headers["authorization"], "Bearer SK1");
    assert_eq!(calls[1].headers["x-key-id"], "AKID2");
    assert_eq!(calls[1].headers["authorization"], "Bearer SK2");
}

/// `path: prefix` appends the layer's path and query under the configured
/// path, with dot segments and percent-encodings normalised first.
#[tokio::test]
async fn prefix_endpoint_normalises_the_layers_path() {
    let kit = Kit::builder()
        .secret("token", SECRET)
        .addon(
            endpoint_layer("https://up.test/monitor/", true)
                .endpoint_path("monitor", EndpointPath::Prefix),
        )
        .start()
        .await;
    let a = endpoint_call(&kit, "/a/./b/?q=%2f").await;
    assert_eq!(a.status, 200, "{a:?}");
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].path, "/monitor/a/b/?q=%2F", "{seen:#?}");
}

/// A layer path with a `..` segment is refused before anything is dialled,
/// under both modes, and the refusal is in the flow log. The test layer
/// treats a failed call as fatal, so the exchange fails closed.
#[tokio::test]
async fn endpoint_paths_cannot_climb() {
    for mode in [EndpointPath::Fixed, EndpointPath::Prefix] {
        let kit = Kit::builder()
            .secret("token", SECRET)
            .addon(endpoint_layer("https://up.test/monitor", true).endpoint_path("monitor", mode))
            .start()
            .await;
        let a = endpoint_call(&kit, "/../admin").await;
        assert_eq!(a.status, 503, "{mode:?}: {a:?}");
        assert!(
            kit.upstream.seen().is_empty(),
            "{mode:?}: the endpoint was dialled"
        );
        let calls = kit.events("endpoint_call", 1).await;
        assert_eq!(calls[0]["status"], serde_json::Value::Null, "{mode:?}");
        let error = calls[0]["error"].as_str().unwrap_or_default();
        assert!(
            error.starts_with("endpoint path refused"),
            "{mode:?}: {error}"
        );
    }
}

/// An endpoint on a private address without `private_ok` is refused; the
/// test layer treats a failed call as fatal, so the exchange fails closed.
#[tokio::test]
async fn endpoints_respect_the_address_floor() {
    let kit = Kit::builder()
        .secret("token", SECRET)
        .addon(endpoint_layer("https://private.test/monitor", false))
        .start()
        .await;
    let a = cap(&kit, "endpoint").await;
    assert_eq!(a.status, 503, "{a:?}");
    assert!(
        kit.upstream.seen().is_empty(),
        "the private endpoint was not reached"
    );
    let calls = kit.events("endpoint_call", 1).await;
    assert_eq!(calls[0]["status"], serde_json::Value::Null);
    assert_eq!(calls[0]["error"], "endpoint address denied");
}

/// A record's `kind` is the guest's string as much as its document: a
/// secret in it is redacted in the flow log.
#[tokio::test]
async fn a_record_kind_is_redacted_like_its_document() {
    use roxy_wasm::Capability;
    let kit = Kit::builder()
        .secret("tok", "verdict")
        .addon(AddonDef::test_layer("t").caps(&[Capability::Record]))
        .start()
        .await;
    let a = cap(&kit, "record").await;
    assert_eq!(a.text(), "ok", "{a:?}");
    let r = kit.events("layer_record", 1).await;
    assert_eq!(r[0]["kind"], "[REDACTED]", "{r:#?}");
    assert_eq!(r[0]["data"]["score"], 0.9);
}

/// `record` and `state` work with their capabilities; a call without its
/// capability fails the flow closed.
#[tokio::test]
async fn records_and_state_reach_the_flow_log() {
    use roxy_wasm::Capability;
    let kit = Kit::builder()
        .addon(AddonDef::test_layer("t").caps(&[Capability::Record, Capability::State]))
        .state(std::sync::Arc::new(MemState::default()))
        .start()
        .await;
    let a = cap(&kit, "record").await;
    assert_eq!(a.text(), "ok", "{a:?}");
    let r = kit.events("layer_record", 1).await;
    assert_eq!(r[0]["kind"], "verdict");
    assert_eq!(r[0]["data"]["score"], 0.9);

    let a = cap(&kit, "state").await;
    assert_eq!(a.text(), "Ok(()) Some(\"from-layer\")", "{a:?}");

    let a = cap(&kit, "metric").await;
    assert_eq!(a.status, 503, "{a:?}");
    let errs = kit.events("layer_error", 1).await;
    assert_eq!(errs[0]["kind"], "capability:metrics");
}

/// `flow.quarantine` trips the process and refuses the calling exchange
/// as `_quarantined`, with the layer as the cause; without the capability
/// it fails the exchange and trips nothing; from an observer it is refused
/// and the exchange goes on.
#[tokio::test]
async fn a_layer_can_quarantine_the_proxy_if_granted() {
    use roxy_wasm::Capability;
    let kit = one(AddonDef::test_layer("t")).await;
    let a = cap(&kit, "quarantine").await;
    assert_eq!(a.status, 503, "{a:?}");
    let errs = kit.events("layer_error", 1).await;
    assert_eq!(errs[0]["kind"], "capability:quarantine", "{errs:#?}");
    assert!(kit.server.handle().quarantine().is_none());

    let kit = stack(&[
        AddonDef::test_layer("monitor")
            .observe()
            .caps(&[Capability::Quarantine]),
        AddonDef::test_layer("t"),
    ])
    .await;
    let a = kit
        .h1()
        .await
        .call(
            "GET",
            "/x",
            &[("x-test-monitor", "caps"), ("x-cap", "quarantine")],
            b"",
        )
        .await;
    assert_eq!(a.status, 200, "{a:?}");
    let errs = kit.events("layer_error", 1).await;
    assert_eq!(errs[0]["layer"], "monitor", "{errs:#?}");
    assert_eq!(errs[0]["kind"], "host");
    assert!(kit.server.handle().quarantine().is_none());

    // The probe answers without `next`: the refusal is the exchange's
    // admission decision, with its sample, as it would be at the client edge.
    let kit = Kit::builder()
        .addon(AddonDef::test_layer("t").caps(&[Capability::Quarantine]))
        .metric_defs("- { id: by_host, count: requests, key: [host], window: 1h }")
        .start()
        .await;
    let a = cap(&kit, "quarantine").await;
    assert_eq!(a.status, 403, "{a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "_quarantined");
    let tripped = kit.events("quarantined", 1).await.remove(0);
    assert_eq!(tripped["cause"]["kind"], "layer", "{tripped:#}");
    assert_eq!(tripped["cause"]["layer"], "t", "{tripped:#}");
    let ev = kit.request_event().await;
    assert_eq!(ev["terminal_rule"], "_quarantined", "{ev:#}");
    assert_eq!(ev["stage"], "head", "{ev:#}");
    {
        let samples = kit.samples.lock().unwrap();
        let admission: Vec<_> = samples.iter().filter(|s| s.admission).collect();
        assert_eq!(admission.len(), 1, "{samples:?}");
        assert!(admission[0].denied, "{samples:?}");
    }
    let a = kit.h1().await.call("GET", "/x", &[], b"").await;
    assert_eq!(a.status, 403, "every exchange after it: {a:?}");
}

/// A layer's `state-put` writes the store the rules read: a rule keyed on
/// the value denies the next exchange, and a `set_state` by a rule is what
/// the layer's `state-get` returns.
#[tokio::test]
async fn layer_state_is_the_rules_state() {
    use roxy_wasm::Capability;
    let kit = Kit::builder()
        .addon(AddonDef::test_layer("t").caps(&[Capability::State]))
        .state(std::sync::Arc::new(MemState::default()))
        .rules(
            r#"
- id: marked
  when: state["k"] == "from-layer"
  then: deny
- id: mark
  when: path == "/mark"
  then: [{ set_state: { key: r, value: from-rule } }, deny]
- id: up
  when: host == "up.test"
  then: allow
"#,
        )
        .start()
        .await;
    let a = kit.h1().await.call("GET", "/before", &[], b"").await;
    assert_eq!(a.status, 200, "{a:?}");

    let a = cap(&kit, "state").await;
    assert_eq!(a.text(), "Ok(()) Some(\"from-layer\")", "{a:?}");

    let a = kit.h1().await.call("GET", "/after", &[], b"").await;
    assert_eq!(a.status, 403, "{a:?}");
    let ev = kit.events("request", 3).await;
    assert_eq!(ev[2]["terminal_rule"], "marked", "{ev:#?}");

    // The other way: a rule's set_state is what the layer reads.
    let a = kit
        .h1()
        .await
        .call(
            "GET",
            "/mark",
            &[
                ("x-test-t", "caps"),
                ("x-cap", "state-get"),
                ("x-cap-key", "r"),
            ],
            b"",
        )
        .await;
    assert_eq!(a.text(), "None", "{a:?}");
    let a = kit.h1().await.call("GET", "/mark", &[], b"").await;
    assert_eq!(a.status, 403, "{a:?}");
    let a = kit
        .h1()
        .await
        .call(
            "GET",
            "/x",
            &[
                ("x-test-t", "caps"),
                ("x-cap", "state-get"),
                ("x-cap-key", "r"),
            ],
            b"",
        )
        .await;
    assert_eq!(a.text(), "Some(\"from-rule\")", "{a:?}");
}

/// An observer's `state-put` is refused: the store steers every flow's
/// rules, so a write is an effect on traffic. The refusal is the observer's
/// failure, and the key stays unwritten.
#[tokio::test]
async fn an_observer_cannot_write_state() {
    use roxy_wasm::Capability;
    let kit = Kit::builder()
        .addon(
            AddonDef::test_layer("monitor")
                .observe()
                .caps(&[Capability::State]),
        )
        .addon(AddonDef::test_layer("t").caps(&[Capability::State]))
        .state(std::sync::Arc::new(MemState::default()))
        .start()
        .await;
    let a = kit
        .h1()
        .await
        .call(
            "GET",
            "/x",
            &[("x-test-monitor", "caps"), ("x-cap", "state")],
            b"",
        )
        .await;
    assert_eq!(a.status, 200, "{a:?}");
    let errs = kit.events("layer_error", 1).await;
    assert_eq!(errs[0]["layer"], "monitor", "{errs:#?}");
    assert_eq!(errs[0]["mode"], "observe");
    let a = cap(&kit, "state-get").await;
    assert_eq!(a.text(), "None", "{a:?}");
}

/// A full store fails the exchange closed, as it does a rule's `set_state`:
/// the guest never sees it as an error it can ignore.
#[tokio::test]
async fn a_full_state_store_fails_the_exchange() {
    use roxy_wasm::Capability;
    let kit = Kit::builder()
        .addon(AddonDef::test_layer("t").caps(&[Capability::State]))
        .state(std::sync::Arc::new(FullState))
        .start()
        .await;
    let a = cap(&kit, "state").await;
    assert_eq!(a.status, 503, "{a:?}");
    let errs = kit.events("layer_error", 1).await;
    assert_eq!(errs[0]["kind"], "host", "{errs:#?}");
}

// ---- guest bodies ---------------------------------------------------------

/// A layer that traps after answering with a whole body still has the
/// body cut on the wire: its end is held until the handler returns, so the
/// client never gets a complete response from a layer that then failed.
#[tokio::test]
async fn a_trap_after_a_whole_answer_still_cuts_it() {
    let kit = one(AddonDef::test_layer("t")).await;
    let a = kit
        .h1()
        .await
        .call("GET", "/x", &[("x-test-t", "trap-after-finish")], b"")
        .await;
    assert_eq!(a.status, 200, "{a:?}");
    assert!(a.body.is_err(), "the body is cut: {a:?}");
    let errs = kit.events("layer_error", 1).await;
    assert_eq!(errs[0]["kind"], "trap", "{errs:#?}");
}

/// A whole body over the host's cap fails the exchange as the budget's;
/// one under it goes through.
#[tokio::test]
async fn a_whole_body_is_capped() {
    let kit = one(AddonDef::test_layer("t")).await;
    let mut c = kit.h1().await;
    let a = c
        .call(
            "GET",
            "/x",
            &[("x-test-t", "big-bytes"), ("x-bytes", "65536")],
            b"",
        )
        .await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.body.as_ref().map(bytes::Bytes::len), Ok(65536), "{a:?}");
    let a = c.call("GET", "/x", &[("x-test-t", "big-bytes")], b"").await;
    assert_eq!(a.status, 503, "{a:?}");
    let errs = kit.events("layer_error", 1).await;
    assert_eq!(errs[0]["kind"], "budget:body", "{errs:#?}");
}

/// An endpoint call refused for its path hands the error to the layer,
/// which goes on; the body it passed to the call is spent, not left to fail
/// the exchange when the handler returns.
#[tokio::test]
async fn a_refused_endpoint_path_spends_the_body_it_was_given() {
    use roxy_wasm::Capability;
    let kit = one(AddonDef::test_layer("t")
        .caps(&[Capability::Endpoints])
        .endpoint("monitor", "https://up.test/score", &[], false))
    .await;
    let a = kit
        .h1()
        .await
        .call(
            "POST",
            "/x",
            &[("x-test-t", "endpoint-bad-path")],
            b"payload",
        )
        .await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.text(), "recovered");
    no_layer_error(&kit);
}

// ---- subscriptions --------------------------------------------------------

/// A layer subscribed to a head only is given an empty body without
/// framing, and the body it did not see goes on past it: to the upstream
/// with its length, and to the client. The layer's head still takes effect.
#[tokio::test]
async fn a_head_only_layer_sees_no_body_and_the_bodies_go_through() {
    use crate::addons::Part;
    for (request, response, saw_request, saw_response_body) in [
        (Part::Head, Part::Head, "0", false),
        (Part::Head, Part::Full, "0", true),
        (Part::Full, Part::Head, "12", false),
        (Part::Full, Part::Full, "12", true),
    ] {
        let kit = one(AddonDef::test_layer("t").subscribe(request, response)).await;
        let a = kit
            .h1()
            .await
            .call("POST", "/x", &[("x-test-t", "probe")], b"twelve bytes")
            .await;
        assert_eq!(a.status, 200, "{request:?}/{response:?}: {a:?}");
        assert_eq!(a.json()["body_len"], 12, "{request:?}/{response:?}");
        assert_eq!(a.json()["via"], "t", "{request:?}/{response:?}");
        let saw_response = a.headers["x-saw-response"].to_str().unwrap();
        if saw_response_body {
            assert_ne!(saw_response, "0", "{request:?}/{response:?}");
        } else {
            assert_eq!(saw_response, "0", "{request:?}/{response:?}");
        }
        let seen = kit.upstream.wait_seen(1).await;
        assert_eq!(
            seen[0].headers["x-saw-request"], saw_request,
            "{request:?}/{response:?}"
        );
        // A bypassed body keeps its framing; one the layer streamed is its
        // own, of unknown length.
        if request == Part::Head {
            assert_eq!(
                seen[0].headers["content-length"], "12",
                "{request:?}/{response:?}"
            );
        }
        assert_eq!(seen[0].complete, Some(true));
        no_layer_error(&kit);
    }
}

/// A layer that passes on bytes of a body it is not subscribed to fails
/// the exchange closed as its own: before the response head a refusal,
/// after it a cut body.
#[tokio::test]
async fn bytes_on_an_unsubscribed_body_fail_the_layer() {
    use crate::addons::Part;
    let kit = one(AddonDef::test_layer("t").subscribe(Part::Head, Part::Full)).await;
    let a = kit
        .h1()
        .await
        .call("POST", "/x", &[("x-test-t", "inject-request")], b"original")
        .await;
    assert_eq!(a.status, 503, "{a:?}");
    let ev = kit.request_event().await;
    assert_eq!(ev["terminal_rule"], "layer:t", "{ev:#}");
    let errs = kit.events("layer_error", 1).await;
    assert_eq!(errs[0]["kind"], "unsubscribed:request", "{errs:#?}");
    assert!(
        kit.upstream.seen().iter().all(|s| s.complete != Some(true)),
        "nothing complete reached the upstream"
    );

    let kit = one(AddonDef::test_layer("t").subscribe(Part::Full, Part::Head)).await;
    let a = kit
        .h1()
        .await
        .call(
            "POST",
            "/x",
            &[("x-test-t", "inject-response")],
            b"original",
        )
        .await;
    assert_eq!(a.status, 200, "{a:?}");
    // The response declares no length while the layer's own body is open:
    // with the upstream's `content-length` the client would have a complete
    // body once the bypassed bytes were through, and the failure that
    // follows nothing to cut.
    assert!(!a.headers.contains_key("content-length"), "{a:?}");
    assert_eq!(a.headers["transfer-encoding"], "chunked", "{a:?}");
    assert!(a.body.is_err(), "the body is cut: {a:?}");
    let errs = kit.events("layer_error", 1).await;
    assert_eq!(errs[0]["kind"], "unsubscribed:response", "{errs:#?}");
}

/// A head-only layer that answers itself answers whole: there is no body
/// from upstream to splice onto its own. The client's body, which the layer
/// never took, is dropped like one a layer left unread: a large upload
/// does not hold the connection.
#[tokio::test]
async fn a_head_only_layer_may_still_answer_itself() {
    use crate::addons::Part;
    let kit = one(AddonDef::test_layer("t").subscribe(Part::Head, Part::Head)).await;
    let mut c = kit.h1().await;
    let req = c
        .request("POST", "/x", &[("x-test-t", "deny")])
        .body(roxy_http::Body::from_bytes(vec![b'x'; 4 << 20]))
        .unwrap();
    let a = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        Answer::read(c.send(req).await.unwrap()),
    )
    .await
    .expect("answered without waiting on the body");
    assert_eq!(a.status, 403, "{a:?}");
    assert_eq!(a.text(), "denied by layer");
    let ev = kit.request_event().await;
    assert_eq!(ev["decision"], "answered", "{ev:#}");
    assert!(kit.upstream.seen().is_empty());
    no_layer_error(&kit);
}

/// A response head-only layer that answers with another status has
/// answered itself: its body stands and the body from upstream is dropped,
/// where the same status passes the response on with the head edited.
#[tokio::test]
async fn a_head_only_layer_refuses_at_the_response_head_by_changing_the_status() {
    use crate::addons::Part;
    let kit = one(AddonDef::test_layer("t").subscribe(Part::Full, Part::Head)).await;
    let mut c = kit.h1().await;
    let a = c
        .call(
            "GET",
            "/x",
            &[("x-test-t", "pass"), ("x-status", "451")],
            b"",
        )
        .await;
    assert_eq!(a.status, 451, "{a:?}");
    assert_eq!(a.text(), "", "the body from upstream is dropped: {a:?}");
    let a = c.call("GET", "/x", &[("x-test-t", "pass")], b"").await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(
        a.json()["via"],
        "t",
        "the head went through, with the body: {a:?}"
    );
    no_layer_error(&kit);
}

/// An observer subscribed to the heads only holds no copy of either body:
/// a body far past the lag budget is not reported, and the heads still
/// reach it.
#[tokio::test]
async fn a_head_only_observer_costs_no_copy() {
    use crate::addons::Part;
    use roxy_wasm::Capability;
    let kit = Kit::builder()
        .rules(RULES)
        .limits(|l| l.max_observer_lag_bytes = 1024)
        .addon(
            AddonDef::test_layer("o")
                .observe()
                .caps(&[Capability::Record])
                .subscribe(Part::Head, Part::Head),
        )
        .start()
        .await;
    let body = vec![b'x'; 256 * 1024];
    let mut c = kit.h1().await;
    let req = c
        .request(
            "POST",
            "/x",
            &[("x-test-o", "probe"), ("x-probe-record", "1")],
        )
        .body(roxy_http::Body::from_bytes(body.clone()))
        .unwrap();
    let a = Answer::read(c.send(req).await.unwrap()).await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.json()["body_len"], body.len());
    let r = kit.events("layer_record", 1).await;
    assert_eq!(r[0]["data"]["request"], 0, "{r:#?}");
    assert_eq!(r[0]["data"]["response"], 0, "{r:#?}");
    kit.request_event().await;
    let lagged: Vec<_> = kit
        .sink
        .events()
        .into_iter()
        .filter(|e| e["event"] == "observer_lagged")
        .collect();
    assert!(lagged.is_empty(), "{lagged:#?}");
    no_layer_error(&kit);
}

/// A body no layer is subscribed to is not decoded: the upstream gets the
/// client's bytes with their `content-encoding`, where a layer that reads
/// the body gets it decoded and the upstream the decoded bytes.
#[tokio::test]
async fn an_unsubscribed_body_is_not_decoded() {
    use crate::addons::Part;
    let gz = gzip(b"hello");
    for (request, upstream_body, encoded) in [
        (Part::Head, gz.clone(), true),
        (Part::Full, b"hello".to_vec(), false),
    ] {
        let kit = one(AddonDef::test_layer("t").subscribe(request, Part::Head)).await;
        let mut c = kit.h1().await;
        let req = c
            .request("POST", "/x", &[("content-encoding", "gzip")])
            .body(roxy_http::Body::from_bytes(gz.clone()))
            .unwrap();
        let a = Answer::read(c.send(req).await.unwrap()).await;
        assert_eq!(a.status, 200, "{request:?}: {a:?}");
        let seen = kit.upstream.wait_seen(1).await;
        assert_eq!(seen[0].body, upstream_body, "{request:?}");
        assert_eq!(
            seen[0].headers.contains_key("content-encoding"),
            encoded,
            "{request:?}: {:?}",
            seen[0].headers
        );
    }
}

/// A head-only layer on an upgrade sees the upgrade and the `101`; the
/// WebSocket's bytes bypass it, so it is not in the byte path.
#[tokio::test]
async fn a_head_only_layer_stays_out_of_a_websockets_bytes() {
    use crate::addons::Part;
    let kit = stack(&[
        AddonDef::test_layer("a").subscribe(Part::Head, Part::Head),
        AddonDef::test_layer("b"),
    ])
    .await;
    let (status, io) = kit.websocket("/ws", &[("x-upper", "1")]).await;
    assert_eq!(status, 101);
    let mut io = io.unwrap();
    // `a` would upper-case too; only `b` is in the byte path.
    assert_eq!(echo(&mut io, b"hello").await, b"HELLO");
    drop(io);
    let ev = kit.request_event().await;
    assert_eq!(strs(&ev["addons"]), ["a", "b"], "{ev:#}");
    let tags = strs(&ev["tags"]);
    assert!(tags.iter().any(|t| t == "via:a"), "{tags:?}");
}

/// A layer subscribed to one body of an upgrade is in that direction's
/// byte path and out of the other's: the bytes it is not subscribed to
/// flow past it while its handler lives on with the socket, relaying the
/// body it is subscribed to (`x-keep-request`, as the SDK does). The
/// upper-casing tells the directions apart at the upstream: it sees
/// upper case only when the layer is on the request side.
#[tokio::test]
async fn a_layer_subscribed_to_one_body_is_in_one_direction_of_a_websocket() {
    use crate::addons::Part;
    for (request, response) in [(Part::Full, Part::Head), (Part::Head, Part::Full)] {
        let kit = stack(&[AddonDef::test_layer("t").subscribe(request, response)]).await;
        let (status, io) = kit
            .websocket("/ws", &[("x-upper", "1"), ("x-keep-request", "1")])
            .await;
        assert_eq!(status, 101, "{request:?}/{response:?}");
        let mut io = io.unwrap();
        for msg in [&b"hello"[..], b"again"] {
            assert_eq!(
                echo(&mut io, msg).await,
                msg.to_ascii_uppercase(),
                "{request:?}/{response:?}"
            );
        }
        let at_upstream: Vec<u8> = kit.upstream.ws_received().concat();
        let expected = if request == Part::Full {
            b"HELLOAGAIN".to_vec()
        } else {
            b"helloagain".to_vec()
        };
        assert_eq!(at_upstream, expected, "{request:?}/{response:?}");
        drop(io);
        kit.events("ws_close", 1).await;
        no_layer_error(&kit);
    }
}

/// A layer subscribed to the response head that fails once the head from
/// upstream has reached it: the body parked for it goes with it, so the
/// response is not left open at a layer that will never answer, and the
/// record is finished once the refusal is written.
#[tokio::test]
async fn a_layer_failing_with_a_response_parked_for_it_lets_the_record_go() {
    let kit = stack(&[
        AddonDef::test_layer("a"),
        AddonDef::test_layer("b").subscribe(Part::Full, Part::Head),
    ])
    .await;
    let a = kit
        .h1()
        .await
        .call(
            "POST",
            "/x",
            &[("x-test-a", "pass"), ("x-test-b", "next-then-trap")],
            b"hello",
        )
        .await;
    assert_eq!(a.status, 503, "{a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "layer:b");
    let ev = kit.request_event().await;
    assert_eq!(ev["decision"], "deny", "{ev:#}");
    assert_eq!(ev["reason"], "layer_error");
    let errs = kit.events("layer_error", 1).await;
    assert_eq!(errs[0]["kind"], "trap", "{errs:#?}");
}

/// A layer upstream that fails is a response on the lane downstream of it:
/// the `503 layer:<name>` roxy writes for a refusal, which the next layer
/// passes on or reshapes. The record keeps the refusal either way: the
/// failure is logged as the failing layer's, and the decision is the deny,
/// whatever the client got.
#[tokio::test]
async fn a_failure_below_arrives_as_a_response_the_layer_above_may_reshape() {
    let kit = stack(&named(&["a", "b"])).await;
    let a = kit
        .h1()
        .await
        .call(
            "GET",
            "/x",
            &[("x-test-a", "pass"), ("x-test-b", "trap")],
            b"",
        )
        .await;
    assert_eq!(a.status, 503, "{a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "layer:b");
    let ev = kit.request_event().await;
    assert_eq!(ev["decision"], "deny", "{ev:#}");
    assert_eq!(ev["terminal_rule"], "layer:b");
    assert_eq!(ev["reason"], "layer_error");
    let errs = kit.events("layer_error", 1).await;
    assert_eq!(errs[0]["layer"], "b", "{errs:#?}");
    assert_eq!(errs[0]["kind"], "trap");

    let kit = stack(&named(&["a", "b"])).await;
    let a = kit
        .h1()
        .await
        .call(
            "GET",
            "/x",
            &[
                ("x-test-a", "pass"),
                ("x-status", "200"),
                ("x-test-b", "trap"),
            ],
            b"",
        )
        .await;
    assert_eq!(a.status, 200, "a reshaped the refusal: {a:?}");
    let ev = kit.request_event().await;
    assert_eq!(ev["decision"], "deny", "{ev:#}");
    assert_eq!(ev["terminal_rule"], "layer:b");
    assert_eq!(ev["res"]["status"], 200);
}
