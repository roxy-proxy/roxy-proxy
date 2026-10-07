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

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn check_configs_pass() {
    // The test configs, and the image's default config.
    let image_default = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docker/roxy.yaml");
    for path in [fixture("full.yaml"), fixture("minimal.yaml"), image_default] {
        let out = roxy(&["check", "--config", path.to_str().unwrap()]);
        assert!(
            out.status.success(),
            "{}: {}",
            path.display(),
            text(&out.stderr)
        );
        assert!(text(&out.stdout).contains(": OK"));
    }
    // `check` says which rules are decided at the head and which watch.
    let out = roxy(&["check", "--config", fixture("full.yaml").to_str().unwrap()]);
    let stdout = text(&out.stdout);
    assert!(stdout.contains("\nrules:\n"), "{stdout}");
    assert!(stdout.contains("  github-reads      head\n"), "{stdout}");
    assert!(
        stdout.contains("  upload-cap        watching: body.bytes\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains(
            "  egress-budget     head, then watching: metric.egress_bytes (request_bytes)\n"
        ),
        "{stdout}"
    );
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

    // A reserved action is refused with its reason, not as an unknown word.
    std::fs::write(
        &bad,
        "version: 1\nlisteners: [{ name: p, bind: 127.0.0.1:3128 }]\nrules:\n  \
         - { id: b, then: [{ call: scan }, allow] }\n",
    )
    .unwrap();
    let out = roxy(&["check", "--config", bad.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    let err = text(&out.stderr);
    assert!(
        err.contains(&format!(
            "{}:rules[0].then[0]: `call` is reserved",
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
fn provided_ca_is_exported_and_never_generated() {
    let dir = tempfile::tempdir().unwrap();
    let write_cfg = |name: &str, tls: &str| {
        let p = dir.path().join(name);
        std::fs::write(
            &p,
            format!("version: 1\nlisteners: [{{ name: p, bind: 127.0.0.1:3128 }}]\ntls: {tls}\n"),
        )
        .unwrap();
        p.to_str().unwrap().to_owned()
    };

    // Mint a CA to stand in for one the operator brings.
    let gen_dir = dir.path().join("gen");
    let gen_cfg = write_cfg("gen.yaml", &format!("{{ ca_dir: {gen_dir:?} }}"));
    assert!(roxy(&["ca", "init", "--config", &gen_cfg]).status.success());
    let cert = dir.path().join("tls.crt");
    let key = dir.path().join("tls.key");
    std::fs::rename(gen_dir.join("roxy-ca.pem"), &cert).unwrap();
    std::fs::rename(gen_dir.join("roxy-ca.key"), &key).unwrap();

    let unused_dir = dir.path().join("unused");
    let cfg = write_cfg(
        "roxy.yaml",
        &format!("{{ ca_dir: {unused_dir:?}, ca_cert: {cert:?}, ca_key: {key:?} }}"),
    );
    let out = roxy(&["ca", "export", "--config", &cfg]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), std::fs::read_to_string(&cert).unwrap());

    for args in [&["ca", "init"][..], &["ca", "init", "--force"]] {
        let out = roxy(&[args, &["--config", &cfg]].concat());
        assert_eq!(out.status.code(), Some(1));
        assert!(
            text(&out.stderr).contains("tls.ca_cert is set"),
            "{}",
            text(&out.stderr)
        );
    }
    assert!(!unused_dir.exists(), "nothing may be generated in ca_dir");

    // A missing provided file fails; it is never replaced by a new CA.
    std::fs::remove_file(&key).unwrap();
    let out = roxy(&["ca", "export", "--config", &cfg]);
    assert_eq!(out.status.code(), Some(1));
    assert!(!key.exists());
}

#[test]
fn run_fails_closed_on_a_bad_addon() {
    // An addon that cannot be loaded refuses startup with one clear line;
    // roxy never starts without a configured layer.
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("ca");
    for (addon, expect) in [
        (dir.path().join("missing.wasm"), "addons[0].path: "),
        (dir.path().join("roxy.yaml"), "layer `a`: compile failed"),
    ] {
        let cfg = dir.path().join("roxy.yaml");
        std::fs::write(
            &cfg,
            format!(
                "version: 1\nlisteners: [{{ name: p, bind: 127.0.0.1:0 }}]\n\
                 tls: {{ ca_dir: {:?} }}\naddons: [{{ name: a, path: {:?} }}]\n",
                ca.to_str().unwrap(),
                addon.to_str().unwrap()
            ),
        )
        .unwrap();
        let out = roxy(&["run", "--config", cfg.to_str().unwrap()]);
        assert_eq!(out.status.code(), Some(1));
        let err = text(&out.stderr);
        assert!(err.contains(expect), "{err}");
    }
}

#[test]
fn check_fails_where_startup_would() {
    // `check` loads what startup loads before it binds a socket or writes a
    // file, and names the field and the file for each failure.
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("roxy.yaml");
    let write = |body: &str| {
        std::fs::write(
            &cfg,
            format!("version: 1\nlisteners: [{{ name: p, bind: 127.0.0.1:0 }}]\n{body}"),
        )
        .unwrap();
    };
    let check = || {
        let out = roxy(&["check", "--config", cfg.to_str().unwrap()]);
        assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
        text(&out.stderr)
    };

    // A file named `.wasm` that is not a WASM component.
    let wasm = dir.path().join("layer.wasm");
    std::fs::write(&wasm, "version: 1\n").unwrap();
    write(&format!("addons: [{{ name: a, path: {wasm:?} }}]\n"));
    let err = check();
    let prefix = format!("{}:addons: layer `a`: compile failed", cfg.display());
    assert!(err.contains(&prefix), "{err}");

    // A provided CA whose files are missing; nothing is generated instead.
    let cert = dir.path().join("tls.crt");
    let key = dir.path().join("tls.key");
    write(&format!("tls: {{ ca_cert: {cert:?}, ca_key: {key:?} }}\n"));
    let err = check();
    let expect = format!(
        "{}:tls.ca_cert: {}: No such file",
        cfg.display(),
        cert.display()
    );
    assert!(err.contains(&expect), "{err}");
    assert!(!cert.exists() && !key.exists());

    // An extra root the upstream TLS config cannot read.
    let roots = dir.path().join("roots.pem");
    write(&format!(
        "tls: {{ upstream: {{ verify: strict+extra_roots, extra_roots: [{roots:?}] }} }}\n"
    ));
    let err = check();
    let expect = format!(
        "{}:tls.upstream.extra_roots: {}: No such file",
        cfg.display(),
        roots.display()
    );
    assert!(err.contains(&expect), "{err}");

    // A CA in `tls.ca_dir` is startup's to generate: `check` passes without it.
    let ca_dir = dir.path().join("ca");
    write(&format!("tls: {{ ca_dir: {ca_dir:?} }}\n"));
    let out = roxy(&["check", "--config", cfg.to_str().unwrap()]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(!ca_dir.exists(), "check must not generate a CA");

    // One that is there but unloadable fails startup, so it fails `check`,
    // and is left as it is.
    std::fs::create_dir(&ca_dir).unwrap();
    let ca_cert = ca_dir.join(roxy_tls::CA_CERT_FILE);
    let ca_key = ca_dir.join(roxy_tls::CA_KEY_FILE);
    std::fs::write(&ca_cert, "not a certificate\n").unwrap();
    std::fs::write(&ca_key, "not a key\n").unwrap();
    let err = check();
    let expect = format!("{}:tls.ca_dir: ", cfg.display());
    assert!(err.contains(&expect), "{err}");
    assert_eq!(
        std::fs::read_to_string(&ca_cert).unwrap(),
        "not a certificate\n"
    );
    assert_eq!(std::fs::read_to_string(&ca_key).unwrap(), "not a key\n");
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

/// A lease secret is for the control plane to supply. `check` never resolves
/// secrets, so it passes; standalone `run` has no lease and refuses, naming
/// the secret, before it touches the CA dir.
#[test]
fn lease_secret_passes_check_and_fails_run() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("roxy.yaml");
    std::fs::write(
        &cfg,
        format!(
            "version: 1\nlisteners: [{{ name: p, bind: 127.0.0.1:3128 }}]\n\
             tls: {{ ca_dir: {:?} }}\nsecrets: {{ lease_token: {{ lease: true }} }}\n\
             rules: [{{ id: r, when: true, then: [{{ set_header: {{ authorization: \"Bearer ${{secret:lease_token}}\" }} }}, allow] }}]\n",
            dir.path().join("ca").to_str().unwrap()
        ),
    )
    .unwrap();
    let out = roxy(&["check", "--config", cfg.to_str().unwrap()]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("1 secret(s)"),
        "{}",
        text(&out.stdout)
    );

    let out = roxy(&["run", "--config", cfg.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    let err = text(&out.stderr);
    assert!(err.contains("\"lease_token\""), "{err}");
    assert!(err.contains("has no lease"), "{err}");
    assert!(
        !dir.path().join("ca").exists(),
        "no CA before secrets resolve"
    );
}

#[test]
fn check_warns_on_client_chosen_metric_keys() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("roxy.yaml");
    std::fs::write(
        &cfg,
        "version: 1\nlisteners: [{ name: p, bind: 127.0.0.1:3128 }]\nmetrics:\n  \
         - { id: paths, count: requests, key: [client.ip, path], window: 1m }\n  \
         - { id: bounded, count: requests, key: [path], where: 'host under \"example.com\"' }\n",
    )
    .unwrap();
    let out = roxy(&["check", "--config", cfg.to_str().unwrap()]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains(": OK"));
    let err = text(&out.stderr);
    assert!(
        err.contains(&format!(
            "{}:metrics[0].key[1]: warning: `path` is chosen by the client",
            cfg.display()
        )),
        "{err}"
    );
    assert_eq!(err.matches("warning:").count(), 1, "{err}");
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
    let cfg = fixture("full.yaml");
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
fn rule_test_watching_rules_and_bad_input() {
    // A response value runs the rules that read it; this one only logs.
    let out = rule_test(&["--response-status", "503", "GET", "https://api.github.com/"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("  log-upstream-5xx  watching: response.status\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains(
            "watching:\n  matched:  log-upstream-5xx\n  - log warn: upstream 5xx\n  stops:    no\n"
        ),
        "{stdout}"
    );
    assert!(stdout.contains("decision: allow\n"), "{stdout}");
    assert!(stdout.contains("rule:     github-reads"), "{stdout}");

    // Body bytes so far: the streaming upload cap stops the exchange.
    let out = rule_test(&[
        "--body-bytes",
        "20000000",
        "POST",
        "https://api.openai.com/v1/files",
    ]);
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("  stops:    deny 413 \"upload too large\" (close) (rule upload-cap)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("decision: deny 413 \"upload too large\""),
        "{stdout}"
    );
    assert!(stdout.contains("rule:     upload-cap"), "{stdout}");
    // Under the cap: allowed by the head rule.
    let out = rule_test(&[
        "--body-bytes",
        "1000",
        "POST",
        "https://api.openai.com/v1/files",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stdout));

    let out = rule_test(&["GET", "not-a-url"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("not an absolute URL"));

    // A method the proxy would refuse is not evaluated either.
    let out = rule_test(&["G{T", "https://api.github.com/"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("roxy would reject this request"),
        "{}",
        text(&out.stderr)
    );
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
        stdout.contains("decision: deny 503 \"blocked by roxy\" (close)"),
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

#[test]
fn rule_test_checks_a_websocket_message() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("roxy.yaml");
    std::fs::write(
        &cfg,
        "version: 1\nlisteners: [{ name: p, bind: 127.0.0.1:0 }]\nrules:\n  \
         - { id: ws, when: 'host == \"ws.test\"', then: { allow: { upgrade: websocket } } }\n  \
         - { id: no-binary, when: 'ws.direction == \"s2c\" and ws.opcode == 2', then: deny }\n",
    )
    .unwrap();
    let cfg = cfg.to_str().unwrap();
    let rt = |extra: &[&str]| {
        let mut args = vec!["rule", "test", "--config", cfg];
        args.extend_from_slice(extra);
        args.extend_from_slice(&["GET", "https://ws.test/"]);
        roxy(&args)
    };
    let out = rt(&["--ws-text", "hi", "--ws-direction", "s2c"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let out = rt(&["--ws-size", "10", "--ws-direction", "s2c"]);
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("rule:     no-binary"));
    let out = rt(&["--ws-opcode", "3"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("--ws-opcode 3"));
}

/// `check` reports `valid_until`, warns when it has already passed (the
/// document still passes: it loads and denies), and refuses a malformed one.
#[test]
fn check_reports_valid_until() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("roxy.yaml");
    let write = |valid_until: &str| {
        std::fs::write(
            &cfg,
            format!("version: 1\nvalid_until: {valid_until}\nlisteners: [{{ name: p, bind: 127.0.0.1:0 }}]\n"),
        )
        .unwrap();
        roxy(&["check", "--config", cfg.to_str().unwrap()])
    };

    let out = write("2999-01-01T00:00:00Z");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("valid until: 2999-01-01T00:00:00+00:00\n"),
        "{}",
        text(&out.stdout)
    );
    assert!(
        !text(&out.stderr).contains("warning"),
        "{}",
        text(&out.stderr)
    );

    let out = write("2000-01-01T00:00:00Z");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("valid until: 2000-01-01T00:00:00+00:00\n"),
        "{}",
        text(&out.stdout)
    );
    assert!(
        text(&out.stderr).contains("warning: valid_until has passed"),
        "{}",
        text(&out.stderr)
    );

    let out = write("2000-01-01");
    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("valid_until"),
        "{}",
        text(&out.stderr)
    );
    assert!(
        text(&out.stderr).contains("RFC 3339"),
        "{}",
        text(&out.stderr)
    );
}

// ----- health -----------------------------------------------------------------

/// A one-shot HTTP server answering `response`; yields the request it read.
fn stub_http(response: &'static str) -> (String, std::thread::JoinHandle<String>) {
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut req = Vec::new();
        let mut buf = [0u8; 512];
        while !req.ends_with(b"\r\n\r\n") {
            let n = s.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            req.extend_from_slice(&buf[..n]);
        }
        s.write_all(response.as_bytes()).unwrap();
        String::from_utf8(req).unwrap()
    });
    (format!("http://{addr}/healthz"), handle)
}

#[test]
fn health_ok_on_200() {
    let (url, server) = stub_http("HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok");
    let out = roxy(&["health", "--url", &url]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "ok\n");
    let req = server.join().unwrap();
    assert!(req.starts_with("GET /healthz HTTP/1.1\r\n"), "{req}");
    let host = url
        .trim_start_matches("http://")
        .trim_end_matches("/healthz");
    assert!(req.contains(&format!("\r\nHost: {host}\r\n")), "{req}");
}

/// The probe does not wait for the server to close the connection.
#[test]
fn health_ok_without_waiting_for_close() {
    use std::io::Write as _;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.write_all(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
        // Hold the connection open past the probe's timeout.
        std::thread::sleep(std::time::Duration::from_secs(3));
        drop(s);
    });
    let t = std::time::Instant::now();
    let out = roxy(&["health", "--timeout", "2", "--url", &url]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(t.elapsed() < std::time::Duration::from_secs(2));
    server.join().unwrap();
}

/// An expired lease is reported, not a failure: the process is up.
#[test]
fn health_reports_an_expired_policy() {
    let (url, server) =
        stub_http("HTTP/1.1 200 OK\r\nX-Roxy-Policy: expired\r\ncontent-length: 2\r\n\r\nok");
    let out = roxy(&["health", "--url", &url]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "ok (policy expired)\n");
    server.join().unwrap();
}

#[test]
fn health_fails_on_other_status_and_garbage() {
    for response in [
        "HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\r\n",
        "HTTP/1.1 2000 OK\r\n\r\n",
        "SSH-2.0-OpenSSH\r\n",
        "",
    ] {
        let (url, server) = stub_http(response);
        let out = roxy(&["health", "--url", &url]);
        assert_eq!(out.status.code(), Some(1), "{response:?}");
        assert!(out.stdout.is_empty(), "{response:?}");
        server.join().unwrap();
    }
}

#[test]
fn health_fails_when_refused_or_misused() {
    // Nothing can listen on port 0 (binding it picks an ephemeral port), so
    // the connect is refused whatever other tests have bound.
    for url in [
        "http://127.0.0.1:0/healthz",
        "https://127.0.0.1:3130/healthz",
        "http:///healthz",
    ] {
        let out = roxy(&["health", "--url", url]);
        assert_eq!(out.status.code(), Some(1), "{url}");
        assert!(text(&out.stderr).contains("roxy: error:"), "{url}");
    }
}

/// A failing probe reports the reason the endpoint answered with.
#[test]
fn health_reports_the_reason_body_on_failure() {
    let (url, server) =
        stub_http("HTTP/1.1 503 Service Unavailable\r\ncontent-length: 9\r\n\r\nno_policy");
    let out = roxy(&["health", "--url", &url]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("no_policy"),
        "{}",
        text(&out.stderr)
    );
    server.join().unwrap();
}

/// The bootstrap listener flags describe what a node runs before its first
/// lease; a file-mode run has no bootstrap.
#[test]
fn bootstrap_flags_need_control_plane() {
    for flag in ["--bootstrap-bind", "--bootstrap-ca-server"] {
        let out = roxy(&[
            "run",
            "--config",
            fixture("minimal.yaml").to_str().unwrap(),
            flag,
            "127.0.0.1:0",
        ]);
        assert_eq!(out.status.code(), Some(2), "{flag}");
        assert!(
            text(&out.stderr).contains("--control-plane"),
            "{flag}: {}",
            text(&out.stderr)
        );
    }
}

/// `--ready` picks the default URL's path, so it has no meaning with `--url`.
#[test]
fn health_ready_conflicts_with_url() {
    let out = roxy(&["health", "--ready", "--url", "http://127.0.0.1:0/readyz"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        text(&out.stderr).contains("cannot be used with"),
        "{}",
        text(&out.stderr)
    );
}

/// End to end: `roxy health` against a running roxy's `ca_server`. With
/// an expired lease the proxy is alive but not ready; a reload with a
/// later one makes it ready without a restart.
#[test]
fn health_probes_a_running_roxy() {
    let dir = tempfile::tempdir().unwrap();
    let free = || {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
    };
    let (proxy, ca) = (free(), free());
    let cfg = dir.path().join("roxy.yaml");
    let base = format!(
        "version: 1\nlisteners: [{{ name: p, bind: \"{proxy}\" }}]\n\
         ca_server: {{ bind: \"{ca}\" }}\ntls: {{ ca_dir: {:?} }}\n",
        dir.path().join("ca").to_str().unwrap()
    );
    std::fs::write(&cfg, format!("{base}valid_until: 2000-01-01T00:00:00Z\n")).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_roxy"))
        .args([
            "--log-level",
            "warn",
            "run",
            "--config",
            cfg.to_str().unwrap(),
        ])
        .env_remove("RUST_LOG")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let url = format!("http://{ca}/healthz");
    let ready_url = format!("http://{ca}/readyz");
    let probe_until_ok = |url: &str| {
        for _ in 0..100 {
            if roxy(&["health", "--url", url]).status.success() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        false
    };
    let healthy = probe_until_ok(&url);
    let not_ready = healthy.then(|| roxy(&["health", "--url", &ready_url]));
    if healthy {
        std::fs::write(&cfg, format!("{base}valid_until: 2999-01-01T00:00:00Z\n")).unwrap();
    }
    let ready = healthy && probe_until_ok(&ready_url);
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(healthy, "roxy never reported healthy at {url}");
    let not_ready = not_ready.unwrap();
    assert_eq!(not_ready.status.code(), Some(1), "expired lease: not ready");
    assert!(
        text(&not_ready.stderr).contains("policy_expired"),
        "{}",
        text(&not_ready.stderr)
    );
    assert!(ready, "roxy never reported ready at {ready_url}");
    let out = roxy(&["health", "--url", &url]);
    assert_eq!(out.status.code(), Some(1), "a stopped roxy is unhealthy");
}
