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
    assert_eq!(cfg.rules.len(), 8);
    assert_eq!(cfg.rules[3].then.0.len(), 2);
    assert_eq!(cfg.rules[7].phase, Phase::Response);
    assert_eq!(cfg.addons[0].kind, AddonKind::Wasm);
    assert_eq!(cfg.addons[0].mode, AddonMode::Enforce);
    assert_eq!(
        cfg.addons[0].limits.max_memory,
        Some(ByteSize::b(64 * 1024 * 1024))
    );
    assert_eq!(cfg.addons[0].limits.fuel_per_step, Some(100_000_000));
    assert_eq!(
        cfg.addons[0].limits.step_cpu,
        Some(Duration::from_millis(50))
    );
    assert_eq!(cfg.address_lists.len(), 1);
    assert_eq!(cfg.upstream.deny_lists, ["cloud-metadata"]);
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
        vec![Action::Allow(roxy_rules::AllowArgs::default())]
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
        "addons: [{ name: a, path: /a.wasm, fuel: 1 }]",
        "addons: [{ name: a, path: /a.wasm, hooks: [request] }]",
        "addons: [{ name: a, path: /a.wasm, limits: { max_cpu: 1s } }]",
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
        "addons: [{ name: a, path: /a.wasm, stage: before_rules }]",
        "addons: [{ name: a, path: /a.wasm, mode: passthrough }]",
        "addons: [{ name: a, path: /a.wasm, capabilities: [network] }]",
        "addons: [{ name: a, path: /a.wasm, on_error: deny }]",
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
         addons: [{ name: x, path: /x.wasm }, { name: x, path: /y.wasm }]\n\
         rules:\n  - { id: _default, then: allow }\n  - { id: c, then: { call: nope } }\n",
    );
    let paths: Vec<&str> = d.iter().map(|d| d.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "version",
            "listeners",
            "tls.upstream.verify",
            "addons[1].name",
            "metrics[0].id",
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

#[test]
fn action_parse_errors_name_action_and_rule() {
    let yaml = format!(
        "{BASE}rules:\n  - id: first\n    then: allow\n  - id: second\n    then:\n      \
         - tag: x\n      - deny: {{ stauts: 4 }}\n"
    );
    let err = Config::from_yaml(&yaml).unwrap_err();
    let msg = describe_parse_error(&yaml, &err);
    assert!(
        msg.starts_with("rules[1].then[1].deny: unknown field `stauts`"),
        "{msg}"
    );
    assert!(msg.ends_with("(rule \"second\")"), "{msg}");

    let yaml = format!("{BASE}rules: [{{ id: m, then: {{ deny: {{}}, allow: {{}} }} }}]\n");
    let err = Config::from_yaml(&yaml).unwrap_err();
    let msg = describe_parse_error(&yaml, &err);
    assert!(msg.contains("exactly one key"), "{msg}");
    assert!(msg.ends_with("(rule \"m\")"), "{msg}");
}

#[test]
fn expression_type_error_has_position() {
    let d = diagnostics(&format!(
        "{BASE}rules:\n  - id: a\n    when: host == \"x\" and port == \"443\"\n    then: allow\n"
    ));
    assert_eq!(d.len(), 1, "{d:?}");
    assert_eq!(d[0].path, "rules[0].when");
    assert_eq!((d[0].line, d[0].col), (1, 17));
    assert_eq!(
        d[0].rule.as_ref().map(roxy_rules::RuleId::as_str),
        Some("a")
    );
    assert!(
        d[0].to_string()
            .starts_with("rules[0].when:1:17: type mismatch"),
        "{}",
        d[0]
    );
    assert!(d[0].snippet.as_ref().unwrap().contains("^^^"));
}

#[test]
fn address_lists_parse_and_validate() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("blocked.txt");
    std::fs::write(&file, "203.0.113.0/24\n").unwrap();
    let cfg = parse(&format!(
        "{BASE}address_lists:\n  - {{ name: internal, inline: [10.0.0.0/8, \"::1\", 192.168.1.1] }}\n  \
         - {{ name: blocked-v4, file: {:?} }}\nupstream: {{ deny_lists: [blocked-v4] }}\n\
         rules:\n  - {{ id: a, when: 'client.ip in @internal', then: allow }}\n",
        file.to_str().unwrap()
    ));
    cfg.validate().unwrap();
    assert_eq!(cfg.address_lists.len(), 2);
    assert_eq!(cfg.address_lists[1].source, AddressListSource::File(file));
    assert_eq!(cfg.upstream.deny_lists, ["blocked-v4"]);

    let d = diagnostics(&format!(
        "{BASE}address_lists:\n  - {{ name: bad name, inline: [10.0.0.0/33, nope, 10.0.0.1/8] }}\n  \
         - {{ name: x, file: /surely/not/here.txt }}\n  - {{ name: x, inline: [] }}\n\
         upstream: {{ deny_lists: [missing] }}\n\
         rules:\n  - {{ id: a, when: 'client.ip in @undefined', then: allow }}\n"
    ));
    let paths: Vec<&str> = d.iter().map(|d| d.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "address_lists[0].name",
            "address_lists[0].inline[0]",
            "address_lists[0].inline[1]",
            "address_lists[0].inline[2]",
            "address_lists[1].file",
            "address_lists[2].name",
            "address_lists[2].inline",
            "upstream.deny_lists[0]",
            "rules[0].when",
        ]
    );
    assert!(d[3].message.contains("host bits set"), "{}", d[3]);
    assert!(d[8].message.contains("@undefined"), "{}", d[8]);

    for bad in [
        "address_lists: [{ name: a }]",
        "address_lists: [{ name: a, file: /x, inline: [] }]",
        "address_lists: [{ name: a, inline: [], colour: red }]",
    ] {
        assert!(
            Config::from_yaml(&format!("{BASE}{bad}\n")).is_err(),
            "{bad}"
        );
    }
}

#[test]
fn addon_on_error_has_no_pass() {
    let c = parse(&format!(
        "{BASE}addons: [{{ name: a, path: /a.wasm, mode: observe, \
         limits: {{ max_buffered_body_bytes: 2mb, fuel_per_step: 5 }} }}]\n"
    ));
    let a = &c.addons[0];
    assert_eq!(a.mode, AddonMode::Observe);
    assert_eq!(a.limits.max_buffered_body_bytes, Some(ByteSize::b(2 << 20)));
    assert_eq!(a.limits.fuel_per_step, Some(5));
    assert_eq!(a.limits.max_memory, None);
    assert_eq!(c.limits.max_address_list_bytes, ByteSize::b(256 << 20));
}
