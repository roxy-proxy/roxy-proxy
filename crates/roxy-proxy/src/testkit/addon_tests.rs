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

#[tokio::test]
async fn tunnel_layers_chain_in_the_byte_path() {
    let kit = stack(&[
        AddonDef::tunnel_layer("t1", false),
        AddonDef::test_layer("plain"),
        AddonDef::tunnel_layer("t2", true),
    ])
    .await;
    let (status, io) = kit.websocket("/ws", &[]).await;
    assert_eq!(status, 101);
    let mut io = io.unwrap();
    // t2 upper-cases client → upstream bytes; the upstream echoes them.
    assert_eq!(echo(&mut io, b"hello").await, b"HELLO");
    drop(io);
    let ev = kit.request_event().await;
    let tags = strs(&ev["tags"]);
    for t in ["tunnel:t1", "tunnel:t2", "via:plain"] {
        assert!(tags.iter().any(|x| x == t), "{t} in {tags:?}");
    }
}

#[tokio::test]
async fn a_close_from_the_upstream_ends_a_flow_through_tunnel_layers() {
    let kit = stack(&[
        AddonDef::tunnel_layer("t1", false),
        AddonDef::tunnel_layer("t2", true),
    ])
    .await;
    let (status, io) = kit.websocket("/ws", &[("x-echo", "once")]).await;
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
    let tags = strs(&ev["tags"]);
    for t in ["tunnel:t1", "tunnel:t2"] {
        assert!(tags.iter().any(|x| x == t), "{t} in {tags:?}");
    }
}

#[tokio::test]
async fn a_plain_layer_can_refuse_an_upgrade() {
    let kit = stack(&[
        AddonDef::tunnel_layer("t1", false),
        AddonDef::test_layer("plain"),
    ])
    .await;
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
async fn a_tunnel_layer_its_when_skips_stays_out_of_the_websocket() {
    let kit = stack(&[
        AddonDef::tunnel_layer("t1", true).when(r#"path != "/ws""#),
        AddonDef::tunnel_layer("t2", false),
    ])
    .await;
    let (status, io) = kit.websocket("/ws", &[]).await;
    assert_eq!(status, 101);
    let mut io = io.unwrap();
    // t1 would upper-case; it is not in the byte path.
    assert_eq!(echo(&mut io, b"hello").await, b"hello");
    drop(io);
    let ev = kit.request_event().await;
    let tags = strs(&ev["tags"]);
    assert!(!tags.iter().any(|x| x == "tunnel:t1"), "{tags:?}");
    assert!(tags.iter().any(|x| x == "tunnel:t2"), "{tags:?}");
}
