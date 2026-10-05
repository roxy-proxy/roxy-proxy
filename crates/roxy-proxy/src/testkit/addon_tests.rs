//! Addon stacks of one to three layers: order, attribution, observe and
//! enforce mixed, answering versus passing on, and chained `tunnel` layers.
//!
//! The test layer is named per addon and reads `x-test-<name>`, so each
//! layer of a stack can be told what to do.

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::{AddonDef, Kit};

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

fn strs(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_owned())
        .collect()
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
/// below it runs.
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
/// above passed on, not what the client sent.
#[tokio::test]
async fn when_sees_the_request_the_layer_above_passed_on() {
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

    use super::{RULES, strs};
    use crate::addons::AddonMode;
    use crate::addons::service::testing::{addon, kit, reload};
    use crate::testkit::{Answer, Kit, streaming_body};

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
    /// and the real body goes through whole.
    #[tokio::test]
    async fn a_slow_observer_is_cut_and_reported_while_the_body_goes_through() {
        // The service never reads (and so never grants credit): the copy
        // stalls once the stream's window is spent.
        let kit = Kit::builder()
            .rules(RULES)
            .limits(|l| l.max_observer_lag_bytes = 64 * 1024)
            .start()
            .await;
        reload(
            &kit,
            RULES,
            &[],
            vec![addon("o", "stall", AddonMode::Observe, |_| {})],
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
}

// ---- one layer: effects, limits, capabilities -----------------------------

const SECRET: &str = "s3cr3t-token-value-0123456789";

/// A single test layer `t` in front of the default rules.
async fn one(def: AddonDef) -> Kit {
    Kit::builder().addon(def).start().await
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

/// roxy attaches an endpoint's credential on the way out; the layer and
/// the flow log never see it.
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
        .find(|s| s.path == "/monitor/score?q=1")
        .unwrap_or_else(|| panic!("{seen:#?}"));
    assert_eq!(call.headers["x-api-key"], SECRET);
    let calls = kit.events("endpoint_call", 1).await;
    assert_eq!(calls[0]["endpoint"], "monitor");
    assert_eq!(calls[0]["status"], 200);
    assert!(!serde_json::to_string(&calls).unwrap().contains(SECRET));
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

/// `record` and `state` work with their capabilities; a call without its
/// capability fails the flow closed.
#[tokio::test]
async fn records_and_state_reach_the_flow_log() {
    use roxy_wasm::Capability;
    let kit = one(AddonDef::test_layer("t").caps(&[Capability::Record, Capability::State])).await;
    let a = cap(&kit, "record").await;
    assert_eq!(a.text(), "ok", "{a:?}");
    let r = kit.events("layer_record", 1).await;
    assert_eq!(r[0]["kind"], "verdict");
    assert_eq!(r[0]["data"]["score"], 0.9);
    assert_eq!(r[0]["audit"], true);

    let a = cap(&kit, "state").await;
    assert_eq!(a.text(), "Ok(()) Some(\"{\\\"n\\\":1}\")", "{a:?}");

    let a = cap(&kit, "metric").await;
    assert_eq!(a.status, 503, "{a:?}");
    let errs = kit.events("layer_error", 1).await;
    assert_eq!(errs[0]["kind"], "capability:metrics");
}
