//! `roxy rule test` sees the request as `roxy run` would hand it to the
//! rules: canonical URL, hop-by-hop fields removed, framing from the flags.

use std::path::Path;
use std::process::Output;

fn roxy(args: &[&str]) -> Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_roxy"))
        .args(["--log-format", "json", "--log-level", "warn"])
        .args(args)
        .env_remove("RUST_LOG")
        .output()
        .expect("run roxy")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A config whose rules each pin one thing the dry run must see.
fn config(dir: &Path) -> String {
    let cfg = dir.join("roxy.yaml");
    std::fs::write(
        &cfg,
        "version: 1\nlisteners: [{ name: p, bind: 127.0.0.1:0 }]\nrules:\n  \
         - { id: canonical, when: 'path == \"/a/c\" and host == \"h.example\"', then: allow }\n  \
         - { id: literal-dot, when: 'path == \"/a/c.\" and host == \"h.example\"', then: allow }\n  \
         - { id: hop, when: 'header[\"connection\"] != null', then: allow }\n  \
         - { id: chunked, when: 'method == POST and body.size == null', then: allow }\n  \
         - { id: sized, when: 'method == POST and header[\"content-length\"] == \"5\"', then: allow }\n",
    )
    .unwrap();
    cfg.to_str().unwrap().to_owned()
}

fn rule_test(cfg: &str, args: &[&str]) -> (Option<i32>, String, String) {
    let mut all = vec!["rule", "test", "--config", cfg];
    all.extend_from_slice(args);
    let out = roxy(&all);
    (out.status.code(), text(&out.stdout), text(&out.stderr))
}

#[test]
fn the_url_is_normalised_before_the_rules_see_it() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    // Dot segments go, encoded unreserved bytes are decoded, the host is
    // lower-cased and loses its trailing dot.
    let (code, stdout, stderr) = rule_test(&cfg, &["GET", "https://H.example./a/%2e/b/../c"]);
    assert_eq!(code, Some(0), "{stdout}{stderr}");
    assert!(stdout.contains("rule:     canonical"), "{stdout}");

    // `%2e` inside a segment is a literal dot, not a dot segment.
    let (code, stdout, stderr) = rule_test(&cfg, &["GET", "https://H.example./a/./b/../c%2e"]);
    assert_eq!(code, Some(0), "{stdout}{stderr}");
    assert!(stdout.contains("rule:     literal-dot"), "{stdout}");

    // Without normalisation neither spelling matches.
    let (code, stdout, _) = rule_test(&cfg, &["GET", "https://h.example/a/b/../c"]);
    assert_eq!(code, Some(0), "{stdout}");
    assert!(stdout.contains("rule:     canonical"), "{stdout}");
    let (code, stdout, _) = rule_test(&cfg, &["GET", "https://h.example/x/../a/d"]);
    assert_eq!(code, Some(3), "{stdout}");
    assert!(stdout.contains("rule:     _default"), "{stdout}");
}

#[test]
fn hop_by_hop_headers_are_not_visible() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    let (code, stdout, stderr) = rule_test(
        &cfg,
        &["-H", "connection: x", "GET", "https://other.example/"],
    );
    assert_eq!(code, Some(3), "{stdout}{stderr}");
    assert!(stdout.contains("rule:     _default"), "{stdout}");
}

#[test]
fn chunked_bodies_have_no_size() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    let post = ["--body", "hello", "POST", "https://other.example/"];
    let (code, stdout, stderr) = rule_test(&cfg, &post);
    assert_eq!(code, Some(0), "{stdout}{stderr}");
    assert!(stdout.contains("rule:     sized"), "{stdout}");

    let mut chunked = vec!["--chunked"];
    chunked.extend_from_slice(&post);
    let (code, stdout, stderr) = rule_test(&cfg, &chunked);
    assert_eq!(code, Some(0), "{stdout}{stderr}");
    assert!(stdout.contains("rule:     chunked"), "{stdout}");
}

#[test]
fn what_the_proxy_rejects_is_rejected_with_its_reason() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    for (args, reason) in [
        (
            vec!["GET", "https://h.example/../x"],
            "path_climbs_above_root",
        ),
        (vec!["GET", "https://bücher.example/"], "non_ascii"),
        (
            vec!["-H", "host: other.example", "GET", "https://h.example/"],
            "host_mismatch",
        ),
        (
            vec!["-H", "connection: (x)", "GET", "https://h.example/"],
            "bad_connection_header",
        ),
    ] {
        let (code, _, stderr) = rule_test(&cfg, &args);
        assert_eq!(code, Some(1), "{args:?}: {stderr}");
        assert!(stderr.contains(reason), "{args:?}: {stderr}");
    }
}

#[test]
fn a_metric_the_config_does_not_define_gets_a_warning() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    let (code, stdout, stderr) = rule_test(
        &cfg,
        &["--metric", "nope=1", "GET", "https://h.example/a/c"],
    );
    assert_eq!(code, Some(0), "{stdout}{stderr}");
    assert!(
        stderr.contains("warning: --metric nope: no metric \"nope\" is defined"),
        "{stderr}"
    );
}
