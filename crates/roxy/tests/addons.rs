//! End-to-end smoke tests of the addon layer stack: `roxy run` with
//! roxy-wasm's test layer (`crates/roxy-wasm/test-components`) loaded from
//! a file, reloaded when it changes, and running in front of the rules.
//! Layer semantics are tested in-process in `roxy-proxy`'s testkit.

mod support;

use serde_json::Value;
use support::{Harness, Opts};

const TEST_LAYER: &[u8] = include_bytes!("../../roxy-wasm/tests/fixtures/test_layer.wasm");
/// A layer that knows no `x-test`: it passes every request on.
const REDACT_LAYER: &[u8] = include_bytes!("../../roxy-wasm/tests/fixtures/redact.wasm");

const ALLOW_UPSTREAM: &str = r#"
  - id: upstream
    when: host == "upstream.test"
    then: { allow: { private_ok: true } }
"#;

/// Writes the test layer into a temp dir and returns the `addons:` YAML for
/// one addon named `t` with `extra` lines (indented 4) under it.
fn addon_yaml(dir: &std::path::Path, extra: &str) -> String {
    addon_yaml_for(dir, TEST_LAYER, extra)
}

fn addon_yaml_for(dir: &std::path::Path, wasm: &[u8], extra: &str) -> String {
    let path = dir.join("layer.wasm");
    std::fs::write(&path, wasm).unwrap();
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
    start_layer(TEST_LAYER, addon, rules).await
}

async fn start_layer(wasm: &[u8], addon: &str, rules: &str) -> Harness {
    let tmp = tempfile::tempdir().unwrap();
    let extra = addon_yaml_for(tmp.path(), wasm, addon);
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

/// The addon file is watched like the config: replacing it reloads, and
/// the new component serves the next exchange.
#[tokio::test(flavor = "multi_thread")]
async fn a_changed_wasm_file_triggers_a_reload() {
    let tmp = tempfile::tempdir().unwrap();
    // The test layer ignores `config`; the redact layer needs its needles.
    let extra = addon_yaml(tmp.path(), "config: { needles: [hunter2] }");
    let h = Harness::start_with(Opts {
        rules: ALLOW_UPSTREAM,
        extra: &extra,
        ..Opts::default()
    })
    .await;
    let res = send(&h, "deny", "/x", "").await;
    assert_eq!(res.status(), 403, "the test layer denies on request");

    std::fs::write(tmp.path().join("layer.wasm"), REDACT_LAYER).unwrap();
    h.wait_events("config_reloaded", 1).await;
    let res = send(&h, "deny", "/x", "").await;
    assert_eq!(res.status(), 200);
    assert_eq!(json(&res.bytes().await.unwrap())["path"], "/x");
    h.stop().await;
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
