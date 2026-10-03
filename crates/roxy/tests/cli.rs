//! End-to-end tests of the `roxy` CLI.

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
        err.contains(&format!("{prefix}.when:1:1: reference to undefined metric")),
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
fn run_refuses_features_not_in_this_build() {
    // The full example defines metrics and addons; `check` accepts it but
    // `run` must refuse with one clear line instead of failing every flow.
    let out = roxy(&["run", "--config", example("roxy.yaml").to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    let err = text(&out.stderr);
    assert!(err.contains("WASM addons are not in this build"), "{err}");
    assert!(!err.contains("metric store"), "{err}");
    assert_eq!(err.trim().lines().count(), 1, "{err}");
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
fn check_catches_expression_type_errors() {
    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("bad.yaml");
    std::fs::write(
        &bad,
        "version: 1\nlisteners: [{ name: p, bind: 127.0.0.1:3128 }]\nrules:\n  \
         - { id: ports, when: 'host under 443', then: allow }\n",
    )
    .unwrap();
    let out = roxy(&["check", "--config", bad.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    let err = text(&out.stderr);
    assert!(
        err.contains(&format!(
            "{}:rules[0].when:1:12: `under` needs a quoted domain on the right, found the number 443",
            bad.display()
        )),
        "{err}"
    );
    assert!(
        err.contains("    | host under 443\n    |            ^^^"),
        "{err}"
    );
    assert!(err.contains("1 problem(s) found"), "{err}");
}

fn rule_test(args: &[&str]) -> Output {
    let cfg = example("roxy.yaml");
    let mut all = vec!["rule", "test", "--config", cfg.to_str().unwrap()];
    all.extend_from_slice(args);
    roxy(&all)
}

#[test]
fn rule_test_allows_github_reads() {
    let out = rule_test(&["GET", "https://api.github.com/repos/a/b"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(stdout.contains("matched:  github-reads"), "{stdout}");
    assert!(
        stdout.contains("metrics:  github_writes=0 (default), egress_bytes=0 (default)\n"),
        "{stdout}"
    );
    assert!(stdout.contains("decision: allow\n"), "{stdout}");
    assert!(stdout.contains("rule:     github-reads"), "{stdout}");
}

#[test]
fn rule_test_denies_by_default_and_by_rule() {
    let out = rule_test(&["DELETE https://example.com/x"]);
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("decision: deny 403 \"blocked by roxy\""),
        "{stdout}"
    );
    assert!(stdout.contains("rule:     _default"), "{stdout}");

    let out = rule_test(&[
        "--metric",
        "egress_bytes=600000000",
        "--metric",
        "github_writes=0",
        "-H",
        "content-type: application/json",
        "POST",
        "https://api.github.com/repos/x/y/issues",
    ]);
    assert_eq!(out.status.code(), Some(3));
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("decision: deny 429 \"hourly egress budget exhausted\""),
        "{stdout}"
    );
    assert!(stdout.contains("rule:     egress-budget"), "{stdout}");
}

#[test]
fn rule_test_shows_secret_placeholders() {
    let out = rule_test(&["POST", "https://api.openai.com/v1/chat/completions"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("  - set_header authorization: Bearer [secret:openai]"),
        "{stdout}"
    );
}

#[test]
fn rule_test_response_phase_and_bad_input() {
    let out = rule_test(&[
        "--phase",
        "response",
        "--status",
        "503",
        "GET",
        "https://api.github.com/",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(stdout.contains("log warn: upstream 5xx"), "{stdout}");
    assert!(stdout.contains("rule:     _default"), "{stdout}");

    let out = rule_test(&["GET", "not-a-url"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("not an absolute URL"));
}

#[test]
fn rule_test_unavailable_metric_fails_closed() {
    let out = rule_test(&[
        "--metric",
        "github_writes=unavailable",
        "GET",
        "https://api.github.com/repos/a/b",
    ]);
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("decision: deny 503 \"policy input unavailable\" (close)"),
        "{stdout}"
    );
    assert!(stdout.contains("rule:     _fail_closed"), "{stdout}");
    assert!(
        stdout.contains("reason:   metric `github_writes` unavailable (fail closed)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("metrics:  github_writes=unavailable, egress_bytes=0 (default)"),
        "{stdout}"
    );

    let out = rule_test(&["--metric", "github_writes=lots", "GET", "https://x/"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("not an integer or `unavailable`"));
}

/// A config with a file list and an inline list, both deny lists.
fn list_config(dir: &Path, list_text: &str) -> PathBuf {
    let list = dir.join("blocked.txt");
    std::fs::write(&list, list_text).unwrap();
    let cfg = dir.join("roxy.yaml");
    std::fs::write(
        &cfg,
        format!(
            "version: 1\nlisteners: [{{ name: p, bind: 127.0.0.1:0 }}]\n\
             tls: {{ ca_dir: {:?} }}\n\
             address_lists:\n  - {{ name: blocked, file: {:?} }}\n  \
             - {{ name: meta, inline: [169.254.169.254, \"fd00:ec2::254/128\"] }}\n\
             upstream: {{ deny_lists: [blocked, meta] }}\n\
             rules:\n  - {{ id: any, when: 'port == 80', then: {{ allow: {{ private_ok: true }} }} }}\n",
            dir.join("ca").to_str().unwrap(),
            list.to_str().unwrap()
        ),
    )
    .unwrap();
    cfg
}

#[test]
fn check_prints_address_list_counts() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = list_config(
        dir.path(),
        "# feed\n203.0.113.0/24\n203.0.113.9\n\n198.51.100.0/24\n2001:db8::/32\n",
    );
    let out = roxy(&["check", "--config", cfg.to_str().unwrap()]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("address list blocked: 3 entries"),
        "{stdout}"
    );
    assert!(stdout.contains("address list meta: 2 entries"), "{stdout}");
    assert!(stdout.contains(": OK"), "{stdout}");
}

#[test]
fn check_and_run_fail_on_a_bad_list_line() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = list_config(dir.path(), "203.0.113.0/24\n# ok\nnot-an-address\n");
    let list = dir.path().join("blocked.txt");
    let out = roxy(&["check", "--config", cfg.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    let err = text(&out.stderr);
    assert!(
        err.contains(&format!(
            "{}:3: address list blocked: \"not-an-address\" is not an IP address or CIDR",
            list.display()
        )),
        "{err}"
    );
    // Startup is fatal, before the CA is generated.
    let out = roxy(&["run", "--config", cfg.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    let err = text(&out.stderr);
    assert!(err.contains(&format!("{}:3:", list.display())), "{err}");
    assert!(!dir.path().join("ca").exists());
}

#[test]
fn rule_test_shows_address_policy_hits_for_ip_literals() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = list_config(dir.path(), "203.0.113.0/24\n");
    let cfg = cfg.to_str().unwrap();
    let rt = |url: &str| roxy(&["rule", "test", "--config", cfg, "GET", url]);

    let out = rt("http://203.0.113.7/x");
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains(
            "address:  203.0.113.7 denied by the upstream address policy (list:blocked, matched 203.0.113.0/24)"
        ),
        "{stdout}"
    );
    assert!(stdout.contains("rule:     _address_policy"), "{stdout}");
    assert!(stdout.contains("decision: deny 403"), "{stdout}");

    // IPv4-mapped spelling and the inline list.
    let out = rt("http://[::ffff:169.254.169.254]/latest/meta-data");
    assert_eq!(out.status.code(), Some(3));
    assert!(text(&out.stdout).contains("(list:meta, matched 169.254.169.254/32)"));

    let out = rt("http://198.51.100.1/");
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stdout));
    assert!(text(&out.stdout).contains("address:  198.51.100.1 allowed"));

    // Names are not resolved in a dry run.
    let out = rt("http://example.com/");
    assert_eq!(out.status.code(), Some(0));
    assert!(!text(&out.stdout).contains("address:"));
}
