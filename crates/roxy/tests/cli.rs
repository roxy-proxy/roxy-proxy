//! End-to-end tests of the `roxy` CLI (M0 commands).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn roxy(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_roxy"))
        .args(["--log-format", "json", "--log-level", "warn"])
        .args(args)
        .env_remove("RUST_LOG")
        .output()
        .expect("run roxy")
}

fn example(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples")
        .join(name)
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn check_examples_pass() {
    for name in ["roxy.yaml", "minimal.yaml"] {
        let out = roxy(&["check", "--config", example(name).to_str().unwrap()]);
        assert!(out.status.success(), "{name}: {}", text(&out.stderr));
        assert!(text(&out.stdout).contains(": OK"));
    }
}

#[test]
fn check_reports_diagnostics() {
    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("bad.yaml");
    std::fs::write(
        &bad,
        "version: 1\nlisteners: [{ name: p, bind: 127.0.0.1:3128 }]\nrules:\n  \
         - { id: a, then: allow }\n  - { id: a, when: metric.nope > 1, then: deny }\n",
    )
    .unwrap();
    let out = roxy(&["check", "--config", bad.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    let err = text(&out.stderr);
    let prefix = format!("{}:rules[1]", bad.display());
    assert!(
        err.contains(&format!("{prefix}.id: duplicate rule id")),
        "{err}"
    );
    assert!(
        err.contains(&format!("{prefix}.when: reference to undefined metric")),
        "{err}"
    );
}

#[test]
fn check_reports_parse_errors() {
    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("bad.yaml");
    std::fs::write(
        &bad,
        "version: 1\nlisteners: [{ name: p, bind: 127.0.0.1:3128, colour: red }]\n",
    )
    .unwrap();
    let out = roxy(&["check", "--config", bad.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    let err = text(&out.stderr);
    assert!(
        err.contains(&format!(
            "{}:listeners[0]: unknown field `colour`",
            bad.display()
        )),
        "{err}"
    );
}

#[test]
fn ca_init_and_export() {
    let dir = tempfile::tempdir().unwrap();
    let ca_dir = dir.path().join("ca");
    let cfg = dir.path().join("roxy.yaml");
    std::fs::write(
        &cfg,
        format!(
            "version: 1\nlisteners: [{{ name: p, bind: 127.0.0.1:3128 }}]\ntls: {{ ca_dir: {:?} }}\n",
            ca_dir.to_str().unwrap()
        ),
    )
    .unwrap();
    let cfg = cfg.to_str().unwrap();

    let out = roxy(&["ca", "export", "--config", cfg]);
    assert_eq!(out.status.code(), Some(1), "export without a CA must fail");

    let out = roxy(&["ca", "init", "--config", cfg]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("roxy-ca.pem"));
    assert!(ca_dir.join("roxy-ca.key").exists());

    let out = roxy(&["ca", "init", "--config", cfg]);
    assert_eq!(out.status.code(), Some(1), "second init must refuse");

    let out = roxy(&["ca", "export", "--config", cfg]);
    assert!(out.status.success());
    let pem = text(&out.stdout);
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"), "{pem}");
    assert_eq!(
        pem,
        std::fs::read_to_string(ca_dir.join("roxy-ca.pem")).unwrap()
    );

    let out = roxy(&["ca", "export", "--der", "--config", cfg]);
    assert!(out.status.success());
    assert_eq!(
        out.stdout.first(),
        Some(&0x30),
        "DER starts with a SEQUENCE"
    );

    let out = roxy(&["ca", "init", "--force", "--config", cfg]);
    assert!(out.status.success());
    let out2 = roxy(&["ca", "export", "--config", cfg]);
    assert_ne!(text(&out2.stdout), pem, "--force must mint a new CA");
}

#[test]
fn run_fails_on_missing_secret() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("roxy.yaml");
    std::fs::write(
        &cfg,
        format!(
            "version: 1\nlisteners: [{{ name: p, bind: 127.0.0.1:3128 }}]\n\
             tls: {{ ca_dir: {:?} }}\nsecrets: {{ s: {{ env: ROXY_TEST_SURELY_UNSET_VAR }} }}\n",
            dir.path().join("ca").to_str().unwrap()
        ),
    )
    .unwrap();
    let out = roxy(&["run", "--config", cfg.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("ROXY_TEST_SURELY_UNSET_VAR"));
    assert!(
        !dir.path().join("ca").exists(),
        "no CA before secrets resolve"
    );
}

#[test]
fn rule_test_is_a_stub() {
    let out = roxy(&["rule", "test", "GET https://example.com/", "-H", "a: b"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("not implemented in M0"));
}
