use super::*;

fn example(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn parse(yaml: &str) -> Config {
    Config::from_yaml(yaml).unwrap_or_else(|e| panic!("parse failed: {e}"))
}

fn diagnostics(yaml: &str) -> Vec<Diagnostic> {
    parse(yaml).validate().expect_err("expected diagnostics")
}

const BASE: &str = "version: 1\nlisteners: [{ name: proxy, bind: 127.0.0.1:3128 }]\n";

#[test]
fn full_example_parses_and_validates() {
    let cfg = parse(&example("roxy.yaml"));
    cfg.validate().unwrap();
    assert_eq!(cfg.listeners.len(), 1);
    assert_eq!(cfg.listeners[0].mode, ListenerMode::Explicit);
    assert_eq!(
        cfg.listeners[0].auth.as_ref().unwrap().basic.users_file,
        PathBuf::from("/etc/roxy/users")
    );
    assert_eq!(cfg.ca_server.as_ref().unwrap().bind.port(), 3130);
    assert_eq!(cfg.tls.upstream.min_version, TlsVersion::Tls12);
    assert!(cfg.http.enable_h2);
    assert_eq!(cfg.limits.max_inspect_body_bytes.as_u64(), 1024 * 1024);
    assert_eq!(cfg.upstream.dns.resolver, Resolver::System);
    assert_eq!(
        cfg.secrets["openai"],
        SecretSource::Env("OPENAI_API_KEY".into())
    );
    assert_eq!(
        cfg.secrets["gh"],
        SecretSource::File("/run/secrets/github_token".into())
    );
    assert_eq!(cfg.metrics.len(), 2);
    assert_eq!(cfg.metrics[0].count, MetricCount::Requests);
    assert_eq!(cfg.metrics[0].window, Some(Duration::from_secs(60)));
    assert_eq!(cfg.metrics[1].where_, Some(Expr("true".into())));
    assert_eq!(cfg.metrics[1].window, Some(Duration::from_secs(3600)));
    assert_eq!(cfg.rules.len(), 7);
    assert_eq!(cfg.rules[2].then.0.len(), 2);
    assert_eq!(cfg.rules[6].phase, Phase::Response);
    assert_eq!(
        cfg.addons[0].hooks,
        vec![AddonHook::Request, AddonHook::Response]
    );
    assert_eq!(
        cfg.addons[0].capabilities,
        vec![Capability::State, Capability::Log]
    );
}

#[test]
fn minimal_example_uses_defaults() {
    let cfg = parse(&example("minimal.yaml"));
    cfg.validate().unwrap();
    assert!(cfg.ca_server.is_none());
    assert_eq!(cfg.tls.ca_dir, PathBuf::from("/var/lib/roxy/ca"));
    assert!(cfg.tls.require_sni_match);
    assert_eq!(cfg.tls.leaf_cache_size, 10_000);
    assert_eq!(cfg.tls.upstream.verify, UpstreamVerify::Strict);
    assert!(!cfg.http.allow_http10);
    assert!(!cfg.http.enable_h2);
    let l = &cfg.limits;
    assert_eq!(l.max_header_bytes.as_u64(), 64 * 1024);
    assert_eq!(l.max_url_bytes.as_u64(), 8 * 1024);
    assert_eq!(l.max_headers, 100);
    assert_eq!(l.max_request_body_bytes.as_u64(), 1 << 30);
    assert_eq!(l.max_response_body_bytes.as_u64(), 1 << 30);
    assert_eq!(l.max_inspect_body_bytes.as_u64(), 1 << 20);
    assert_eq!(l.max_ws_message_bytes.as_u64(), 16 << 20);
    assert_eq!(l.header_timeout, Duration::from_secs(10));
    assert_eq!(l.body_idle_timeout, Duration::from_secs(30));
    assert_eq!(l.max_connections_per_client, 256);
    assert_eq!(l.max_metric_keys, 100_000);
    assert!(cfg.upstream.deny_private_ranges);
    assert_eq!(cfg.upstream.connect_timeout, Duration::from_secs(10));
    assert_eq!(cfg.upstream.dns.cache_ttl_cap, Duration::from_secs(60));
    assert!(cfg.log.flow.path.is_none());
    assert!(!cfg.log.flow.connection_events);
    assert_eq!(cfg.rules[0].phase, Phase::Request);
    assert_eq!(
        cfg.rules[0].then.0,
        vec![serde_yaml_ng::Value::from("allow")]
    );
}

#[test]
fn sizes_and_durations_parse() {
    let cfg = parse(&format!(
        "{BASE}limits:\n  max_header_bytes: 32kb\n  max_url_bytes: 4096\n  \
         max_request_body_bytes: 2gb\n  max_capture_body_bytes: 3 MiB\n  \
         header_timeout: 1m 30s\n  body_idle_timeout: 500ms\n\
         upstream:\n  connect_timeout: 2s\n  dns:\n    cache_ttl_cap: 1h\n    \
         resolver: [\"1.1.1.1:53\", \"[2606:4700::1111]:53\"]\n"
    ));
    assert_eq!(cfg.limits.max_header_bytes.as_u64(), 32 * 1024);
    assert_eq!(cfg.limits.max_url_bytes.as_u64(), 4096);
    assert_eq!(cfg.limits.max_request_body_bytes.as_u64(), 2 << 30);
    assert_eq!(cfg.limits.max_capture_body_bytes.as_u64(), 3 << 20);
    assert_eq!(cfg.limits.header_timeout, Duration::from_secs(90));
    assert_eq!(cfg.limits.body_idle_timeout, Duration::from_millis(500));
    // Unset keys in a partially specified section keep their defaults.
    assert_eq!(cfg.limits.max_headers, 100);
    assert_eq!(cfg.upstream.connect_timeout, Duration::from_secs(2));
    assert_eq!(cfg.upstream.dns.cache_ttl_cap, Duration::from_secs(3600));
    assert!(matches!(&cfg.upstream.dns.resolver, Resolver::Servers(s) if s.len() == 2));
}

#[test]
fn bad_size_and_duration_rejected() {
    for bad in [
        "limits: { max_header_bytes: 64 parsecs }",
        "limits: { max_header_bytes: -5 }",
        "limits: { header_timeout: soon }",
        "upstream: { dns: { resolver: google } }",
        "upstream: { deny_cidrs: [10.0.0.0/33] }",
    ] {
        assert!(
            Config::from_yaml(&format!("{BASE}{bad}\n")).is_err(),
            "{bad}"
        );
    }
}

#[test]
fn unknown_fields_rejected_everywhere() {
    for bad in [
        "bogus: 1",
        "listeners: [{ name: p, bind: 127.0.0.1:1, colour: red }]",
        "tls: { ca_dirr: /tmp }",
        "tls: { upstream: { verify: strict, extra: 1 } }",
        "http: { allow_http11: true }",
        "limits: { max_body: 1kb }",
        "upstream: { dns: { resolvers: system } }",
        "secrets: { a: { env: X, file: /y } }",
        "secrets: { a: { vault: X } }",
        "metrics: [{ id: m, count: requests, every: 1m }]",
        "rules: [{ id: r, then: allow, when_not: true }]",
        "addons: [{ name: a, path: /a.wasm, hooks: [request], fuel: 1 }]",
        "log: { flow: { file: /x } }",
    ] {
        let yaml = if bad.starts_with("listeners") {
            format!("version: 1\n{bad}\n")
        } else {
            format!("{BASE}{bad}\n")
        };
        assert!(Config::from_yaml(&yaml).is_err(), "should reject: {bad}");
    }
}

#[test]
fn unknown_enum_values_rejected() {
    for bad in [
        "rules: [{ id: r, phase: postflight, then: allow }]",
        "tls: { upstream: { verify: lax } }",
        "tls: { upstream: { min_version: \"1.1\" } }",
        "metrics: [{ id: m, count: bananas }]",
        "addons: [{ name: a, path: /a.wasm, hooks: [connect] }]",
        "addons: [{ name: a, path: /a.wasm, hooks: [request], capabilities: [network] }]",
    ] {
        assert!(
            Config::from_yaml(&format!("{BASE}{bad}\n")).is_err(),
            "should reject: {bad}"
        );
    }
}

#[test]
fn then_accepts_single_or_list() {
    let cfg = parse(&format!(
        "{BASE}rules:\n  - id: a\n    then: deny\n  - id: b\n    then: {{ deny: {{ status: 429 }} }}\n  \
         - id: c\n    then: [tag: x, allow]\n"
    ));
    assert_eq!(cfg.rules[0].then.0.len(), 1);
    assert_eq!(cfg.rules[1].then.0.len(), 1);
    assert_eq!(cfg.rules[2].then.0.len(), 2);
    assert!(cfg.rules[0].when.is_none());
    assert!(Config::from_yaml(&format!("{BASE}rules: [{{ id: a, then: [] }}]\n")).is_err());
    assert!(Config::from_yaml(&format!("{BASE}rules: [{{ id: a }}]\n")).is_err());
}

#[test]
fn metric_count_unique() {
    let cfg = parse(&format!(
        "{BASE}metrics: [{{ id: hosts, count: unique(host) }}]\n"
    ));
    assert_eq!(cfg.metrics[0].count, MetricCount::Unique("host".into()));
    assert!(cfg.metrics[0].window.is_none());
    assert_eq!(cfg.metrics[0].key, Vec::<String>::new());
}

#[test]
fn duplicate_rule_id_diagnosed() {
    let d = diagnostics(&format!(
        "{BASE}rules:\n  - {{ id: a, then: allow }}\n  - {{ id: a, then: deny }}\n"
    ));
    assert_eq!(d.len(), 1, "{d:?}");
    assert_eq!(d[0].path, "rules[1].id");
    assert!(d[0].message.contains("duplicate rule id"), "{}", d[0]);
}

#[test]
fn duplicate_metric_and_listener_diagnosed() {
    let d = diagnostics(
        "version: 1\nlisteners:\n  - { name: p, bind: 127.0.0.1:1 }\n  - { name: p, bind: 127.0.0.1:2 }\n\
         metrics:\n  - { id: m, count: requests }\n  - { id: m, count: errors }\n",
    );
    let paths: Vec<&str> = d.iter().map(|d| d.path.as_str()).collect();
    assert_eq!(paths, ["listeners[1].name", "metrics[1].id"]);
}

#[test]
fn undefined_metric_reference_diagnosed() {
    let d = diagnostics(&format!(
        "{BASE}metrics: [{{ id: writes, count: requests }}]\nrules:\n  \
         - {{ id: a, when: metric.writes > 3 and metric.nope > 1, then: deny }}\n"
    ));
    assert_eq!(d.len(), 1, "{d:?}");
    assert_eq!(d[0].path, "rules[0].when");
    assert!(d[0].message.contains("metric.nope"));
}

#[test]
fn undefined_secret_reference_diagnosed() {
    let d = diagnostics(&format!(
        "{BASE}secrets: {{ ok: {{ env: OK }} }}\nrules:\n  - id: a\n    then:\n      \
         - set_header: {{ authorization: \"Bearer ${{secret:ok}}\", x-other: \"${{secret:missing}}\" }}\n      \
         - allow\n"
    ));
    assert_eq!(d.len(), 1, "{d:?}");
    assert_eq!(d[0].path, "rules[0].then[0]");
    assert!(d[0].message.contains("\"missing\""));
}

#[test]
fn secret_outside_request_phase_diagnosed() {
    let d = diagnostics(&format!(
        "{BASE}secrets: {{ s: {{ env: S }} }}\nrules:\n  - id: a\n    phase: response\n    \
         then: {{ set_header: {{ x: \"${{secret:s}}\" }} }}\n"
    ));
    assert_eq!(d.len(), 1, "{d:?}");
    assert!(d[0].message.contains("request-phase"));
}

#[test]
fn transparent_listener_is_deferred() {
    let d = diagnostics(
        "version: 1\nlisteners:\n  - name: t\n    mode: transparent\n    bind: 127.0.0.1:1\n    \
         allow_passthrough: false\n    upstream_target: resolve\n",
    );
    assert_eq!(d.len(), 1, "{d:?}");
    assert_eq!(d[0].path, "listeners[0].mode");
    assert!(d[0].message.contains("deferred"));

    let d = diagnostics(
        "version: 1\nlisteners: [{ name: p, bind: 127.0.0.1:1, upstream_target: resolve }]\n",
    );
    assert_eq!(d[0].path, "listeners[0].upstream_target");
}

#[test]
fn misc_diagnostics() {
    let d = diagnostics(
        "version: 2\nlisteners: []\nca_server: { bind: 127.0.0.1:1 }\n\
         tls: { upstream: { verify: strict+extra_roots } }\n\
         metrics: [{ id: bad-id, count: requests }]\n\
         addons: [{ name: x, path: /x.wasm, hooks: [] }]\n\
         rules:\n  - { id: _default, then: allow }\n  - { id: c, then: { call: nope } }\n",
    );
    let paths: Vec<&str> = d.iter().map(|d| d.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "version",
            "listeners",
            "tls.upstream.verify",
            "metrics[0].id",
            "addons[0].hooks",
            "rules[0].id",
            "rules[1].then[0]",
        ]
    );
}

#[test]
fn duplicate_bind_diagnosed() {
    let d = diagnostics(
        "version: 1\nlisteners: [{ name: p, bind: 127.0.0.1:1 }]\nca_server: { bind: 127.0.0.1:1 }\n",
    );
    assert_eq!(d[0].path, "ca_server.bind");
}

#[test]
fn version_is_required() {
    assert!(Config::from_yaml("listeners: []\n").is_err());
}
