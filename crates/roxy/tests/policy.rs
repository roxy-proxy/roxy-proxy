//! `roxy policy render` and `roxy policy test` end to end: the rendered
//! config passes `roxy check`, and the layers' tests have the documented
//! severities.

use std::path::{Path, PathBuf};
use std::process::Output;

fn roxy(args: &[&str]) -> Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_roxy"))
        .args(["--log-format", "json", "--log-level", "warn"])
        .args(args)
        .env_remove("RUST_LOG")
        .output()
        .expect("run roxy")
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/policy")
        .join(name)
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn render(base: &Path, layers: &[&Path], output: &Path) -> Output {
    let mut args = vec!["policy", "render", "--base", base.to_str().unwrap()];
    for l in layers {
        args.extend(["--layer", l.to_str().unwrap()]);
    }
    args.extend(["--output", output.to_str().unwrap(), "--print-hash"]);
    roxy(&args)
}

#[test]
fn rendered_config_passes_check_and_carries_the_hash() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("roxy.yaml");
    let r = render(
        &fixture("base.yaml"),
        &[&fixture("org.yaml"), &fixture("user.yaml")],
        &out,
    );
    assert!(r.status.success(), "{}", text(&r.stderr));
    let hash = text(&r.stdout).trim().to_owned();
    let rendered = std::fs::read_to_string(&out).unwrap();
    assert_eq!(
        rendered.lines().next().unwrap(),
        format!("# roxy policy render: inputs {hash}")
    );

    let check = roxy(&["check", "--config", out.to_str().unwrap()]);
    assert!(check.status.success(), "{}", text(&check.stderr));
    let stdout = text(&check.stdout);
    assert!(
        stdout.contains(": OK (1 listener(s), 6 rule(s), 1 metric(s), 1 secret(s), 0 addon(s))"),
        "{stdout}"
    );
    assert!(stdout.contains("  user:no-deletes    head\n"), "{stdout}");

    // The rendered policy behaves as the layers' tests say it should.
    let dry = roxy(&[
        "rule",
        "test",
        "--config",
        out.to_str().unwrap(),
        "DELETE",
        "https://api.github.com/repos/a/b",
    ]);
    assert_eq!(dry.status.code(), Some(3), "{}", text(&dry.stderr));
    assert!(
        text(&dry.stdout).contains("rule:     user:no-deletes"),
        "{}",
        text(&dry.stdout)
    );

    // Rendering again gives the same bytes and hash.
    let again = dir.path().join("again.yaml");
    let r2 = render(
        &fixture("base.yaml"),
        &[&fixture("org.yaml"), &fixture("user.yaml")],
        &again,
    );
    assert_eq!(text(&r2.stdout).trim(), hash);
    assert_eq!(std::fs::read_to_string(&again).unwrap(), rendered);
}

#[test]
fn a_failing_deny_test_is_an_error_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    // Wrong on purpose: a lower layer cannot widen the org's ceiling, so
    // its allow is dead; the deny test it also carries fails because the
    // org's `github` rule allows that request.
    let layer = dir.path().join("hole.yaml");
    std::fs::write(
        &layer,
        "rules:\n  - { id: widen, when: 'host == \"example.com\"', then: allow }\n\
         tests:\n  - { name: expects a hole, request: 'GET https://api.github.com/x', expect: deny }\n",
    )
    .unwrap();
    let out = dir.path().join("roxy.yaml");
    let r = render(&fixture("base.yaml"), &[&fixture("org.yaml"), &layer], &out);
    assert_eq!(r.status.code(), Some(1));
    let err = text(&r.stderr);
    assert!(
        err.contains("roxy policy: error: layer hole: expects a hole: expected deny, got allow (rule org:github)"),
        "{err}"
    );
    assert!(err.contains("1 test(s) failed (4 ran)"), "{err}");
    assert!(!out.exists(), "nothing is written when a test fails");
}

#[test]
fn a_failing_allow_test_is_a_warning() {
    let dir = tempfile::tempdir().unwrap();
    let layer = dir.path().join("narrow.yaml");
    std::fs::write(
        &layer,
        "rules:\n  - { id: no-reads, when: 'method == GET', then: deny }\n",
    )
    .unwrap();
    // The org's "reads are allowed" test now fails: a warning, not an error.
    let r = roxy(&[
        "policy",
        "test",
        "--base",
        fixture("base.yaml").to_str().unwrap(),
        "--layer",
        fixture("org.yaml").to_str().unwrap(),
        "--layer",
        layer.to_str().unwrap(),
    ]);
    assert!(r.status.success(), "{}", text(&r.stderr));
    let err = text(&r.stderr);
    assert!(
        err.contains(
            "roxy policy: warning: layer org: reads are allowed: expected allow by org:github, \
             got deny 403"
        ) && err.contains("(rule narrow:no-reads)"),
        "{err}"
    );
    assert!(
        text(&r.stdout).starts_with("3 test(s) ran, 1 warning(s); inputs sha256:"),
        "{}",
        text(&r.stdout)
    );
}

#[test]
fn base_and_layer_field_misuse_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("roxy.yaml");
    let bad_base = dir.path().join("base.yaml");
    std::fs::write(
        &bad_base,
        "version: 1\nlisteners: [{ name: p, bind: 127.0.0.1:0 }]\nrules: []\n",
    )
    .unwrap();
    let r = render(&bad_base, &[&fixture("org.yaml")], &out);
    assert_eq!(r.status.code(), Some(1));
    assert!(
        text(&r.stderr).contains("`rules` belongs in a layer"),
        "{}",
        text(&r.stderr)
    );

    let bad_layer = dir.path().join("org.yaml");
    std::fs::write(&bad_layer, "listeners: []\n").unwrap();
    let r = render(&fixture("base.yaml"), &[&bad_layer], &out);
    assert_eq!(r.status.code(), Some(1));
    let err = text(&r.stderr);
    assert!(err.contains("unknown field `listeners`"), "{err}");
    assert!(err.contains(&bad_layer.display().to_string()), "{err}");
}
