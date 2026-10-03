//! End-to-end tests of the addon layer stack (DESIGN.md §11): `roxy run`
//! with roxy-wasm's test layer (`crates/roxy-wasm/test-components`) in
//! front of the rules.

mod support;

use std::time::Duration;

use serde_json::Value;
use support::{Harness, Opts, SECRET, h2_get};

const TEST_LAYER: &[u8] = include_bytes!("../../roxy-wasm/tests/fixtures/test_layer.wasm");

const ALLOW_UPSTREAM: &str = r#"
  - id: upstream
    when: host == "upstream.test"
    then: { allow: { private_ok: true } }
"#;

/// Writes the test layer into a temp dir and returns the `addons:` YAML for
/// one addon named `t` with `extra` lines (indented 4) under it.
fn addon_yaml(dir: &std::path::Path, extra: &str) -> String {
    let path = dir.join("test_layer.wasm");
    std::fs::write(&path, TEST_LAYER).unwrap();
    let mut out = format!("addons:\n  - name: t\n    path: {}\n", path.display());
    for l in extra.lines() {
        out.push_str("    ");
        out.push_str(l);
        out.push('\n');
    }
    out
}

/// Starts roxy with the test layer (`addon` lines under the addon) and
/// `rules`.
async fn start(addon: &str, rules: &str) -> Harness {
    let tmp = tempfile::tempdir().unwrap();
    let extra = addon_yaml(tmp.path(), addon);
    let h = Harness::start_with(Opts {
        rules,
        extra: &extra,
        ..Opts::default()
    })
    .await;
    // The wasm file must outlive the harness start only (it is compiled
    // at load); keep the dir alive anyway for reloads.
    std::mem::forget(tmp);
    h
}

fn json(b: &[u8]) -> Value {
    serde_json::from_slice(b)
        .unwrap_or_else(|e| panic!("not JSON ({e}): {}", String::from_utf8_lossy(b)))
}

async fn send(h: &Harness, test: &str, path: &str, body: &'static str) -> reqwest::Response {
    h.client()
        .post(h.https_url(path))
        .header("x-test", test)
        .body(body)
        .send()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn passes_through_a_layer_and_logs_it() {
    let h = start("", ALLOW_UPSTREAM).await;
    let res = h
        .client()
        .post(h.https_url("/hello"))
        .header("x-upper", "1")
        .body("payload")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    // The layer upper-cased the request body on the way down and the
    // response on the way up.
    let seen = h.upstream.seen();
    assert_eq!(seen.last().unwrap().body_len, 7);
    let body = res.text().await.unwrap();
    assert!(body.contains("\"PATH\":\"/HELLO\""), "{body}");

    let ev = h.wait_events("request", 1).await;
    assert_eq!(ev[0]["decision"], "allow");
    assert_eq!(ev[0]["addons"], serde_json::json!(["t"]));
    assert_eq!(ev[0]["terminal_rule"], "upstream");
    h.stop().await;
}

/// Invariant 1: what a layer passes on is judged by the rules as if the
/// client had sent it.
#[tokio::test(flavor = "multi_thread")]
async fn a_rewritten_request_is_still_judged_by_the_rules() {
    let rules = r#"
  - id: no-rewritten
    when: path starts_with "/rewritten"
    then: { deny: { status: 451 } }
  - id: upstream
    when: host == "upstream.test"
    then: { allow: { private_ok: true } }
"#;
    let h = start("", rules).await;
    // The client asks for /fine; the layer rewrites it to /rewritten.
    let res = send(&h, "rewrite", "/fine", "original").await;
    assert_eq!(res.status(), 451);
    assert!(h.upstream.seen().is_empty(), "nothing reached the upstream");
    let ev = h.wait_events("request", 1).await;
    assert_eq!(ev[0]["decision"], "deny");
    assert_eq!(ev[0]["terminal_rule"], "no-rewritten");

    // Without the deny, the rewrite goes out as rewritten.
    let res = send(&h, "pass", "/fine", "original").await;
    assert_eq!(res.status(), 200);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rewrite_reaches_the_upstream() {
    let h = start("", ALLOW_UPSTREAM).await;
    let res = send(&h, "rewrite", "/fine", "original").await;
    assert_eq!(res.status(), 200);
    let v = json(&res.bytes().await.unwrap());
    assert_eq!(v["path"], "/rewritten");
    assert_eq!(v["body_len"], 8); // "replaced"
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_layer_can_answer_without_the_upstream() {
    let h = start("", ALLOW_UPSTREAM).await;
    let res = send(&h, "deny", "/x", "").await;
    assert_eq!(res.status(), 403);
    assert_eq!(res.text().await.unwrap(), "denied by layer");
    assert!(h.upstream.seen().is_empty());
    let ev = h.wait_events("request", 1).await;
    assert_eq!(ev[0]["decision"], "deny");
    assert_eq!(ev[0]["terminal_rule"], "layer:t");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_trap_denies() {
    let h = start("", ALLOW_UPSTREAM).await;
    let res = send(&h, "trap", "/x", "").await;
    assert_eq!(res.status(), 503);
    assert_eq!(res.headers()["x-roxy-rule"], "layer:t");
    assert!(h.upstream.seen().is_empty());
    let err = h.wait_events("layer_error", 1).await;
    assert_eq!(err[0]["layer"], "t");
    assert_eq!(err[0]["kind"], "trap");
    assert_eq!(err[0]["mode"], "enforce");
    let ev = h.wait_events("request", 1).await;
    assert_eq!(ev[0]["decision"], "deny");
    assert_eq!(ev[0]["reason"], "layer_error");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn budgets_are_enforced() {
    let h = start(
        "limits: { step_cpu: 20ms, fuel_per_step: 100_000_000_000, max_memory: 16mb, max_exchange_time: 2s }",
        ALLOW_UPSTREAM,
    )
    .await;
    for (test, kind) in [
        ("loop", "budget:step_cpu"),
        ("memory", "budget:max_memory"),
        ("host-loop", "budget:max_exchange_time"),
    ] {
        let res = send(&h, test, "/x", "").await;
        assert_eq!(res.status(), 503, "{test}");
        let errs = h.wait_events("layer_error", 1).await;
        assert!(errs.iter().any(|e| e["kind"] == kind), "{test}: {errs:#?}");
    }
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failure_after_the_head_cuts_the_body() {
    let h = start("", ALLOW_UPSTREAM).await;
    // Over h2 the cut is a stream reset, which may overtake the head; over
    // h1 the connection breaks mid-body. Either way, never a clean end.
    let res = h
        .client()
        .post(h.https_url("/x"))
        .header("x-test", "trap-after-head")
        .send()
        .await;
    if let Ok(res) = res {
        assert_eq!(res.status(), 200);
        assert!(res.bytes().await.is_err(), "the body must not end cleanly");
    }
    let err = h.wait_events("layer_error", 1).await;
    assert_eq!(err[0]["kind"], "trap");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn observe_mode_cannot_block() {
    let h = start("mode: observe\nlimits: { step_cpu: 20ms }", ALLOW_UPSTREAM).await;
    for test in ["trap", "deny", "loop", "rewrite"] {
        let res = send(&h, test, "/observed", "payload").await;
        assert_eq!(res.status(), 200, "{test}");
        let v = json(&res.bytes().await.unwrap());
        // The real request went out unchanged.
        assert_eq!(v["path"], "/observed", "{test}");
        assert_eq!(v["body_len"], 7, "{test}");
    }
    let errs = h.wait_events("layer_error", 2).await;
    assert!(errs.iter().all(|e| e["mode"] == "observe"), "{errs:#?}");
    h.stop().await;
}

fn endpoint_addon(private_ok: bool) -> String {
    format!(
        "capabilities: [endpoints]\nendpoints:\n  monitor:\n    url: https://upstream.test:{{HTTPS}}/no-echo\n    \
         headers: {{ x-api-key: \"${{secret:token}}\" }}\n    private_ok: {private_ok}\n"
    )
}

async fn start_endpoint(private_ok: bool) -> Harness {
    // `{HTTPS}` in `extra` is not rendered by the harness, so render the
    // port after starting: start once to learn the upstream, then reload.
    let h = start("", ALLOW_UPSTREAM).await;
    let port = h.upstream.https.port();
    let tmp = tempfile::tempdir().unwrap();
    let extra = addon_yaml(
        tmp.path(),
        &endpoint_addon(private_ok).replace("{HTTPS}", &port.to_string()),
    );
    let cfg = h.render(&Opts {
        rules: ALLOW_UPSTREAM,
        extra: &extra,
        ..Opts::default()
    });
    std::fs::write(&h.config_path, cfg).unwrap();
    assert!(h.running.as_ref().unwrap().reloader.reload_async().await);
    std::mem::forget(tmp);
    h
}

#[tokio::test(flavor = "multi_thread")]
async fn endpoint_credentials_never_reach_the_layer() {
    let h = start_endpoint(true).await;
    let res = h
        .client()
        .post(h.https_url("/x"))
        .header("x-test", "caps")
        .header("x-cap", "endpoint")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let text = res.text().await.unwrap();
    assert_eq!(text, "200 scored");
    // roxy attached the credential on the way out...
    let seen = h.upstream.seen();
    let call = seen
        .iter()
        .find(|s| s.path_and_query == "/no-echo/score?q=1")
        .unwrap();
    assert_eq!(call.header("x-api-key"), Some(SECRET));
    // ...the layer never had it, and the log does not either.
    assert!(!text.contains(SECRET));
    let calls = h.wait_events("endpoint_call", 1).await;
    assert_eq!(calls[0]["endpoint"], "monitor");
    assert_eq!(calls[0]["status"], 200);
    assert!(!serde_json::to_string(&calls).unwrap().contains(SECRET));
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn endpoints_respect_the_address_floor() {
    // The upstream is on 127.0.0.1 and the endpoint lacks `private_ok`.
    let h = start_endpoint(false).await;
    let res = h
        .client()
        .post(h.https_url("/x"))
        .header("x-test", "caps")
        .header("x-cap", "endpoint")
        .send()
        .await
        .unwrap();
    // The test layer treats a failed endpoint call as fatal: fail closed.
    assert_eq!(res.status(), 503);
    assert!(
        !h.upstream
            .seen()
            .iter()
            .any(|s| s.path_and_query.starts_with("/no-echo")),
        "the private upstream was not reached"
    );
    let calls = h.wait_events("endpoint_call", 1).await;
    assert_eq!(calls[0]["status"], Value::Null);
    assert_eq!(calls[0]["error"], "endpoint address denied");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn terminate_quarantines_the_principal() {
    let h = start("capabilities: [terminate]", ALLOW_UPSTREAM).await;
    let res = h
        .client()
        .post(h.https_url("/x"))
        .header("x-test", "caps")
        .header("x-cap", "terminate")
        .send()
        .await
        .unwrap();
    assert_eq!(res.text().await.unwrap(), "true");
    let q = h.wait_events("quarantined", 1).await;
    assert_eq!(q[0]["layer"], "t");
    assert_eq!(q[0]["principal"], "ip:127.0.0.1");

    // Every later request from the principal is denied by the gate, before
    // any layer runs...
    let res = h.client().get(h.https_url("/after")).send().await.unwrap();
    assert_eq!(res.status(), 403);
    assert_eq!(res.headers()["x-roxy-rule"], "_quarantined");
    // ...until the TTL (1s in the test layer) expires.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let res = h.client().get(h.https_url("/after")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn records_and_state_reach_the_flow_log() {
    let h = start("capabilities: [record, state]", ALLOW_UPSTREAM).await;
    let res = h
        .client()
        .post(h.https_url("/x"))
        .header("x-test", "caps")
        .header("x-cap", "record")
        .send()
        .await
        .unwrap();
    assert_eq!(res.text().await.unwrap(), "ok");
    let r = h.wait_events("layer_record", 1).await;
    assert_eq!(r[0]["kind"], "verdict");
    assert_eq!(r[0]["data"]["score"], 0.9);
    assert_eq!(r[0]["audit"], true);

    let res = h
        .client()
        .post(h.https_url("/x"))
        .header("x-test", "caps")
        .header("x-cap", "state")
        .send()
        .await
        .unwrap();
    assert_eq!(res.text().await.unwrap(), "Ok(()) Some(\"{\\\"n\\\":1}\")");

    // Without the capability, the call fails the flow closed.
    let res = h
        .client()
        .post(h.https_url("/x"))
        .header("x-test", "caps")
        .header("x-cap", "metric")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 503);
    let errs = h.wait_events("layer_error", 1).await;
    assert_eq!(errs[0]["kind"], "capability:metrics");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn layers_run_for_h2_clients() {
    let h = start("", ALLOW_UPSTREAM).await;
    let (send, _conn) = h.h2_client().await;
    let (parts, body) = h2_get(&send, &h.https_url("/via-h2"), &[("x-test", "deny")])
        .await
        .unwrap();
    assert_eq!(parts.status, 403);
    assert_eq!(body.as_ref(), b"denied by layer");
    let (parts, body) = h2_get(&send, &h.https_url("/via-h2"), &[]).await.unwrap();
    assert_eq!(parts.status, 200);
    assert_eq!(json(&body)["path"], "/via-h2");
    h.stop().await;
}
