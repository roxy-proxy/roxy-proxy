use super::*;

fn fixture(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
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

/// A file to name as an addon's `path`, which validation stats. Keep the
/// directory alive for as long as the config is validated.
fn wasm_file() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("a.wasm");
    std::fs::write(&file, b"").unwrap();
    let path = file.to_str().unwrap().to_owned();
    (dir, path)
}

#[test]
fn full_config_parses_and_validates() {
    let cfg = parse(&fixture("full.yaml"));
    cfg.validate().unwrap();
    assert_eq!(cfg.listeners.len(), 1);
    assert_eq!(cfg.listeners[0].mode, ListenerMode::HttpProxy);
    assert_eq!(cfg.ca_server.as_ref().unwrap().bind.port(), 3130);
    assert_eq!(cfg.tls.upstream.min_version, TlsVersion::Tls12);
    assert!(cfg.http.enable_h2);
    assert!(!cfg.http.strip_accept_encoding);
    assert!(cfg.http.decode_for_addons);
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
    assert_eq!(cfg.rules.len(), 9);
    assert_eq!(cfg.rules[4].then.0.len(), 2);
    let policy = cfg.validate().unwrap().policy;
    let kinds: Vec<&str> = policy
        .rule_info()
        .into_iter()
        .map(|r| match r.kind {
            roxy_rules::RuleKind::Head => "head",
            roxy_rules::RuleKind::Watching => "watching",
            roxy_rules::RuleKind::HeadAndWatching => "both",
        })
        .collect();
    assert_eq!(
        kinds,
        [
            "head", "both", "head", "watching", "head", "head", "head", "head", "watching"
        ]
    );
    assert_eq!(cfg.addons[0].kind, AddonKind::Wasm);
    assert_eq!(cfg.addons[0].mode, AddonMode::Enforce);
    assert_eq!(
        cfg.addons[0].limits.max_memory,
        Some(ByteSize::b(64 * 1024 * 1024))
    );
    assert_eq!(
        cfg.addons[0].limits.first_byte_timeout,
        Some(Duration::from_secs(30))
    );
    assert_eq!(cfg.address_lists.len(), 1);
    assert_eq!(cfg.upstream.deny_lists, ["cloud-metadata"]);
    assert_eq!(cfg.addons[0].capabilities, vec![Capability::Log]);
}

#[test]
fn minimal_config_uses_defaults() {
    let cfg = parse(&fixture("minimal.yaml"));
    cfg.validate().unwrap();
    assert!(cfg.ca_server.is_none());
    assert_eq!(cfg.tls.ca_dir, PathBuf::from("/var/lib/roxy/ca"));
    assert!(cfg.tls.require_sni_match);
    assert_eq!(cfg.tls.leaf_cache_size, 10_000);
    assert_eq!(cfg.tls.upstream.verify, UpstreamVerify::Strict);
    assert!(!cfg.http.allow_http10);
    assert!(!cfg.http.allow_request_trailers);
    assert!(cfg.http.allow_response_trailers);
    assert!(cfg.http.enable_h2);
    let l = &cfg.limits;
    assert_eq!(l.max_header_bytes.as_u64(), 64 * 1024);
    assert_eq!(l.max_url_bytes.as_u64(), 8 * 1024);
    assert_eq!(l.max_headers, 100);
    assert_eq!(l.max_request_body_bytes.as_u64(), 1 << 30);
    assert_eq!(l.max_response_body_bytes.as_u64(), 1 << 30);
    assert_eq!(l.max_inspect_body_bytes.as_u64(), 1 << 20);
    assert_eq!(l.max_sign_body_bytes.as_u64(), 100 << 20);
    assert_eq!(l.max_ws_message_bytes.as_u64(), 16 << 20);
    assert_eq!(l.max_observer_lag_bytes.as_u64(), 16 << 20);
    assert_eq!(l.max_buffered_bytes.as_u64(), 1 << 30);
    assert_eq!(l.header_timeout, Duration::from_secs(10));
    assert_eq!(l.body_idle_timeout, Duration::from_mins(10));
    assert_eq!(l.response_body_idle_timeout, Duration::from_mins(30));
    assert_eq!(l.response_header_timeout, Duration::from_mins(15));
    assert_eq!(l.idle_timeout, Duration::from_hours(1));
    assert_eq!(l.max_connections_per_client, None);
    assert_eq!(cfg.startup().per_client_cap(), l.max_connections);
    assert_eq!(l.max_metric_keys, 100_000);
    assert_eq!(l.max_metric_bytes.as_u64(), 256 << 20);
    assert_eq!(l.metric_limits(), roxy_rules::MetricLimits::default());
    assert!(cfg.upstream.deny_private_ranges);
    assert_eq!(cfg.upstream.connect_timeout, Duration::from_secs(10));
    assert_eq!(cfg.upstream.dns.cache_ttl_cap, Duration::from_secs(60));
    assert!(cfg.log.flow.path.is_none());
    assert!(!cfg.log.flow.connection_events);
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
         header_timeout: 1m 30s\n  body_idle_timeout: 500ms\n  \
         response_body_idle_timeout: 2m\n\
         upstream:\n  connect_timeout: 2s\n  dns:\n    cache_ttl_cap: 1h\n    \
         resolver: [\"1.1.1.1:53\", \"[2606:4700::1111]:53\"]\n"
    ));
    assert_eq!(cfg.limits.max_header_bytes.as_u64(), 32 * 1024);
    assert_eq!(cfg.limits.max_url_bytes.as_u64(), 4096);
    assert_eq!(cfg.limits.max_request_body_bytes.as_u64(), 2 << 30);
    assert_eq!(cfg.limits.max_capture_body_bytes.as_u64(), 3 << 20);
    assert_eq!(cfg.limits.header_timeout, Duration::from_secs(90));
    assert_eq!(cfg.limits.body_idle_timeout, Duration::from_millis(500));
    assert_eq!(
        cfg.limits.response_body_idle_timeout,
        Duration::from_secs(120)
    );
    // Unset keys in a partially specified section keep their defaults.
    assert_eq!(cfg.limits.max_headers, 100);
    assert_eq!(cfg.upstream.connect_timeout, Duration::from_secs(2));
    assert_eq!(cfg.upstream.max_h2_connections_per_origin, 4);
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

/// `{ lease: true }` names a secret whose value arrives with the lease; it
/// validates like any other, so a `${secret:..}` reference to it compiles.
#[test]
fn lease_secret_parses_and_validates() {
    let cfg = parse(&format!(
        "{BASE}secrets: {{ tok: {{ lease: true }} }}\n\
         rules: [{{ id: r, when: true, then: [{{ set_header: {{ authorization: \"Bearer ${{secret:tok}}\" }} }}, allow] }}]\n"
    ));
    assert_eq!(cfg.secrets["tok"], SecretSource::Lease);
    cfg.validate().unwrap();
}

/// `lease: false` is rejected with a hint, not read as "no lease".
#[test]
fn lease_false_is_an_error_naming_the_alternatives() {
    let err = Config::from_yaml(&format!("{BASE}secrets: {{ tok: {{ lease: false }} }}\n"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("use `env` or `file` instead"), "{err}");
}

#[test]
fn unknown_fields_rejected_everywhere() {
    for bad in [
        "bogus: 1",
        "listeners: [{ name: p, bind: 127.0.0.1:1, colour: red }]",
        "listeners: [{ name: p, bind: 127.0.0.1:1, auth: { basic: { users_file: /u } } }]",
        "tls: { ca_dirr: /tmp }",
        "tls: { upstream: { verify: strict, extra: 1 } }",
        "http: { allow_http11: true }",
        "limits: { max_body: 1kb }",
        "upstream: { dns: { resolvers: system } }",
        "secrets: { a: { env: X, file: /y } }",
        "secrets: { a: { vault: X } }",
        "secrets: { a: null }",
        "secrets: { a: env }",
        "secrets: { a: {} }",
        "secrets: { a: { env: X, lease: true } }",
        "secrets: { a: { lease: yes } }",
        "metrics: [{ id: m, count: requests, every: 1m }]",
        "rules: [{ id: r, then: allow, when_not: true }]",
        "addons: [{ name: a, path: /a.wasm, fuel: 1 }]",
        "addons: [{ name: a, path: /a.wasm, hooks: [request] }]",
        "addons: [{ name: a, path: /a.wasm, limits: { max_cpu: 1s } }]",
        "addons: [{ name: a, path: /a.wasm, limits: { max_exchange_time: 1s } }]",
        "addons: [{ name: a, path: /a.wasm, limits: { step_cpu: 1s } }]",
        "addons: [{ name: a, path: /a.wasm, limits: { fuel_per_step: 1 } }]",
        "addons: [{ name: a, path: /a.wasm, limits: { max_buffered_body_bytes: 1mb } }]",
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

/// `valid_until` is an RFC 3339 date-time, quoted or not, normalised to
/// UTC; a date alone, a space separator or a relative phrase is refused
/// with a message saying what was expected.
#[test]
fn valid_until_parses_rfc3339_only() {
    assert_eq!(parse(BASE).valid_until, None);
    for (yaml, utc) in [
        (
            "valid_until: 2026-10-06T12:00:00Z",
            "2026-10-06T12:00:00+00:00",
        ),
        (
            "valid_until: \"2026-10-06T12:00:00.5+01:00\"",
            "2026-10-06T11:00:00.500+00:00",
        ),
    ] {
        let t = parse(&format!("{BASE}{yaml}\n")).valid_until.unwrap();
        assert_eq!(t.to_rfc3339(), utc, "{yaml}");
    }
    for bad in [
        "valid_until: 2026-10-06",
        "valid_until: 2026-10-06T12:00:00",
        "valid_until: tomorrow",
        "valid_until: 1760000000",
    ] {
        let e = Config::from_yaml(&format!("{BASE}{bad}\n"))
            .err()
            .unwrap_or_else(|| panic!("should reject: {bad}"))
            .to_string();
        assert!(e.contains("RFC 3339"), "{bad}: {e}");
    }
}

/// A repeated key in a named map is a parse error that names the key and
/// the section, not a last-wins override.
#[test]
fn duplicate_map_keys_rejected() {
    for (yaml, path) in [
        (
            "secrets:\n  gh: { env: GH_PROD }\n  gh: { env: GH_SANDBOX }\n",
            "secrets",
        ),
        (
            "upstream:\n  dns:\n    static_hosts:\n      gh: 10.0.0.1\n      gh: 10.0.0.2\n",
            "upstream.dns.static_hosts",
        ),
        (
            "addons:\n  - name: a\n    path: /a.wasm\n    endpoints:\n      gh: { url: https://a.test }\n      \
             gh: { url: https://b.test }\n",
            "addons[0].endpoints",
        ),
        (
            "addons:\n  - name: a\n    path: /a.wasm\n    endpoints:\n      api:\n        url: https://a.test\n        \
             headers: { gh: one, gh: two }\n",
            "addons[0].endpoints.api.headers",
        ),
    ] {
        let msg = Config::from_yaml(&format!("{BASE}{yaml}"))
            .expect_err(path)
            .to_string();
        assert!(
            msg.starts_with(&format!("{path}: duplicate key `gh`")),
            "{path}: {msg}"
        );
    }
}

#[test]
fn unknown_enum_values_rejected() {
    for bad in [
        "rules: [{ id: r, phase: request, then: allow }]",
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
    // `secrets` is refused with the reason, not as a typo.
    let err = Config::from_yaml(&format!(
        "{BASE}addons: [{{ name: a, path: /a.wasm, capabilities: [log, secrets] }}]\n"
    ))
    .unwrap_err()
    .to_string();
    assert!(err.contains("addons[0].capabilities"), "{err}");
    assert!(
        err.contains("`secrets` capability is not provided"),
        "{err}"
    );
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
fn max_metric_bytes_parses_with_units() {
    let cfg = parse(&format!(
        "{BASE}limits:\n  max_metric_keys: 10\n  max_metric_bytes: 4 MiB\n"
    ));
    cfg.validate().unwrap();
    assert_eq!(
        cfg.limits.metric_limits(),
        roxy_rules::MetricLimits {
            max_keys: 10,
            max_bytes: 4 << 20,
        }
    );
    let cfg = parse(&format!("{BASE}limits:\n  max_metric_bytes: 64gb\n"));
    cfg.validate().unwrap();
}

#[test]
fn max_metric_bytes_out_of_range_diagnosed() {
    for bad in ["0", "65gb", "1tb"] {
        let d = diagnostics(&format!("{BASE}limits:\n  max_metric_bytes: {bad}\n"));
        assert_eq!(d.len(), 1, "{bad}: {d:?}");
        assert_eq!(d[0].path, "limits.max_metric_bytes", "{bad}");
    }
}

#[test]
fn metric_max_keys_is_bounded_by_the_shared_limit() {
    let metrics = |n: usize| {
        format!(
            "{BASE}limits: {{ max_metric_keys: 10 }}\nmetrics: [{{ id: a, count: requests, key: [client.ip], max_keys: {n} }}]\n"
        )
    };
    parse(&metrics(10)).validate().unwrap();
    let d = diagnostics(&metrics(11));
    assert_eq!(d.len(), 1, "{d:?}");
    assert_eq!(d[0].path, "metrics[0].max_keys");
    assert_eq!(d[0].message, "must not exceed limits.max_metric_keys (10)");
    let d = diagnostics(&metrics(0));
    assert_eq!(d.len(), 1, "{d:?}");
    assert_eq!(d[0].to_string(), "metrics[0].max_keys: must be at least 1");
}

/// A zero limit is a config error, not a way to switch something off: it
/// would refuse every request, hold no connection or fail every metric
/// and state rule closed.
#[test]
fn zero_limits_diagnosed() {
    for field in [
        "max_headers",
        "max_header_bytes",
        "max_url_bytes",
        "max_connections",
        "max_connections_per_client",
        "h2_max_concurrent_streams",
        "h2_max_header_list_bytes",
        "max_metric_keys",
        "max_metric_bytes",
        "max_state_entries",
        "max_address_list_bytes",
        "max_observer_lag_bytes",
    ] {
        let d = diagnostics(&format!("{BASE}limits: {{ {field}: 0 }}\n"));
        assert_eq!(d.len(), 1, "{field}: {d:?}");
        assert_eq!(d[0].path, format!("limits.{field}"));
        assert!(d[0].message.starts_with("must be at least 1"), "{}", d[0]);
    }
    parse(&format!(
        "{BASE}limits: {{ max_headers: 1, max_header_bytes: 1 }}\n"
    ))
    .validate()
    .unwrap();
    let d = diagnostics(&format!(
        "{BASE}upstream: {{ max_h2_connections_per_origin: 0 }}\n"
    ));
    assert_eq!(d.len(), 1, "{d:?}");
    assert_eq!(d[0].path, "upstream.max_h2_connections_per_origin");
    assert!(d[0].message.starts_with("must be at least 1"), "{}", d[0]);
    let cfg = parse(&format!(
        "{BASE}upstream: {{ max_h2_connections_per_origin: 1 }}\n"
    ));
    cfg.validate().unwrap();
    assert_eq!(cfg.upstream.max_h2_connections_per_origin, 1);
}

/// Inspection, signing and WebSocket reassembly reserve a whole cap at a
/// time, so a budget smaller than one of those caps would refuse every
/// exchange that needs that buffer; an observer's copy grows into the
/// budget and sets no floor.
#[test]
fn buffer_budget_under_one_exchange_diagnosed() {
    let d = diagnostics(&format!("{BASE}limits: {{ max_buffered_bytes: 99mb }}\n"));
    assert_eq!(d.len(), 1, "{d:?}");
    assert_eq!(d[0].path, "limits.max_buffered_bytes");
    parse(&format!("{BASE}limits: {{ max_buffered_bytes: 100mb }}\n"))
        .validate()
        .unwrap();
    let d = diagnostics(&format!(
        "{BASE}limits: {{ max_buffered_bytes: 31mb, max_sign_body_bytes: 1mb }}\n"
    ));
    assert_eq!(d.len(), 1, "{d:?}");
    parse(&format!(
        "{BASE}limits: {{ max_buffered_bytes: 32mb, max_sign_body_bytes: 1mb }}\n"
    ))
    .validate()
    .unwrap();
    parse(&format!(
        "{BASE}limits: {{ max_buffered_bytes: 2mb, max_sign_body_bytes: 1mb, max_ws_message_bytes: 1mb, max_observer_lag_bytes: 16mb }}\n"
    ))
    .validate()
    .unwrap();
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

/// `roxy check` refuses `unsigned_payload` for a service other than S3.
#[test]
fn sign_unsigned_payload_outside_s3_diagnosed() {
    let d = diagnostics(&format!(
        "{BASE}secrets: {{ akid: {{ env: AKID }}, sk: {{ env: SK }} }}\nrules:\n  - id: a\n    then:\n      \
         - sign: {{ aws_sigv4: {{ service: bedrock, region: eu-west-2, \
         access_key_id: \"${{secret:akid}}\", secret_access_key: \"${{secret:sk}}\", \
         unsigned_payload: true }} }}\n      \
         - allow\n"
    ));
    assert_eq!(d.len(), 1, "{d:?}");
    assert_eq!(d[0].path, "rules[0].then[0]");
    assert!(d[0].message.contains("`unsigned_payload`"), "{d:?}");
    parse(&format!(
        "{BASE}secrets: {{ akid: {{ env: AKID }}, sk: {{ env: SK }} }}\nrules:\n  - id: a\n    then:\n      \
         - sign: {{ aws_sigv4: {{ service: s3, region: eu-west-2, \
         access_key_id: \"${{secret:akid}}\", secret_access_key: \"${{secret:sk}}\", \
         unsigned_payload: true }} }}\n      \
         - allow\n"
    ))
    .validate()
    .unwrap();
}

#[test]
fn secret_in_watching_rule_diagnosed() {
    let d = diagnostics(&format!(
        "{BASE}secrets: {{ s: {{ env: S }} }}\nrules:\n  - id: a\n    \
         when: response.status == 200\n    \
         then: {{ set_header: {{ x: \"${{secret:s}}\" }} }}\n"
    ));
    assert_eq!(d.len(), 1, "{d:?}");
    assert!(
        d[0].message.contains("decided at the request head"),
        "{d:?}"
    );
}

/// Trailers are two settings, one per direction; the single flag is not a
/// field.
#[test]
fn allow_trailers_is_an_unknown_field() {
    let yaml = format!("{BASE}http: {{ allow_trailers: true }}\n");
    let err = Config::from_yaml(&yaml).unwrap_err();
    let msg = describe_parse_error(&yaml, &err);
    assert!(msg.contains("unknown field `allow_trailers`"), "{msg}");
}

#[test]
fn default_key_is_rejected() {
    // Nothing opens an empty rule set: a policy that allows says so in a rule.
    for value in ["allow", "deny"] {
        let yaml = format!("{BASE}default: {value}\n");
        let err = Config::from_yaml(&yaml).unwrap_err();
        let msg = describe_parse_error(&yaml, &err);
        assert!(msg.contains("unknown field `default`"), "{msg}");
    }
}

#[test]
fn listener_mode_defaults_to_http_proxy() {
    let omitted = parse(BASE);
    assert_eq!(omitted.listeners[0].mode, ListenerMode::HttpProxy);

    let named =
        parse("version: 1\nlisteners: [{ name: p, mode: http_proxy, bind: 127.0.0.1:1 }]\n");
    assert_eq!(named.listeners[0].mode, ListenerMode::HttpProxy);

    let yaml = "version: 1\nlisteners: [{ name: p, mode: explicit, bind: 127.0.0.1:1 }]\n";
    let err = Config::from_yaml(yaml).unwrap_err();
    let msg = describe_parse_error(yaml, &err);
    assert!(msg.contains("unknown variant `explicit`"), "{msg}");
}

#[test]
fn listener_mode_http_is_accepted() {
    let cfg = parse("version: 1\nlisteners: [{ name: gw, mode: http, bind: 127.0.0.1:8080 }]\n");
    assert_eq!(cfg.listeners[0].mode, ListenerMode::Http);
    cfg.validate().unwrap();

    // The transparent-only keys are refused on it as on the proxy.
    let d = diagnostics(
        "version: 1\nlisteners:\n  - { name: gw, mode: http, bind: 127.0.0.1:8080, \
         allow_passthrough: true, upstream_target: resolve }\n",
    );
    let paths: Vec<&str> = d.iter().map(|d| d.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "listeners[0].allow_passthrough",
            "listeners[0].upstream_target"
        ],
        "{d:?}"
    );
}

#[test]
fn transparent_listener_is_rejected() {
    let d = diagnostics(
        "version: 1\nlisteners:\n  - name: t\n    mode: transparent\n    bind: 127.0.0.1:1\n    \
         allow_passthrough: false\n    upstream_target: resolve\n",
    );
    assert_eq!(d.len(), 1, "{d:?}");
    assert_eq!(d[0].path, "listeners[0].mode");
    assert!(d[0].message.contains("no transparent listeners"));

    let d = diagnostics(
        "version: 1\nlisteners: [{ name: p, bind: 127.0.0.1:1, upstream_target: resolve }]\n",
    );
    assert_eq!(d[0].path, "listeners[0].upstream_target");
}

#[test]
fn provided_ca_needs_cert_and_key() {
    let base = "version: 1\nlisteners: [{ name: p, bind: 127.0.0.1:3128 }]\n";
    let d = diagnostics(&format!("{base}tls: {{ ca_cert: /c.pem }}\n"));
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].path, "tls.ca_key");
    let d = diagnostics(&format!("{base}tls: {{ ca_key: /c.key }}\n"));
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].path, "tls.ca_cert");
    assert!(
        parse(&format!("{base}tls: {{ ca_key: /c.key }}\n"))
            .tls
            .provided_ca()
            .is_err()
    );

    let cfg = parse(&format!(
        "{base}tls: {{ ca_cert: /c.pem, ca_key: /c.key }}\n"
    ));
    cfg.validate().unwrap();
    assert_eq!(
        cfg.tls.provided_ca().unwrap(),
        Some((Path::new("/c.pem"), Path::new("/c.key")))
    );
}

#[test]
fn listener_field_diagnostics() {
    let d = diagnostics(
        "version: 1\nlisteners:\n  - { name: e, bind: 127.0.0.1:2, upstream_target: resolve }\n",
    );
    assert_eq!(d.len(), 1, "{d:?}");
    assert_eq!(d[0].path, "listeners[0].upstream_target");
}

#[test]
fn misc_diagnostics() {
    let (_dir, wasm) = wasm_file();
    let d = diagnostics(&format!(
        "version: 2\nlisteners: []\nca_server: {{ bind: 127.0.0.1:1 }}\n\
         tls: {{ upstream: {{ verify: strict+extra_roots }} }}\n\
         metrics: [{{ id: bad-id, count: requests }}]\n\
         addons: [{{ name: x, path: {wasm} }}, {{ name: x, path: {wasm} }}]\n\
         rules:\n  - {{ id: _default, then: allow }}\n  - {{ id: c, when: 'body.bytes > 1', then: allow }}\n",
    ));
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

    let yaml = format!("{BASE}rules: [{{ id: r, then: [{{ call: scan }}, allow] }}]\n");
    let err = Config::from_yaml(&yaml).unwrap_err();
    let msg = describe_parse_error(&yaml, &err);
    assert!(msg.contains("`call` is reserved"), "{msg}");
    assert!(msg.ends_with("(rule \"r\")"), "{msg}");
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

/// Addon limits parse with units and are absent (not defaulted) when
/// unset; there is no `terminate` capability or endpoint to grant.
#[test]
fn addon_limits_parse_and_terminate_is_unknown() {
    let c = parse(&format!(
        "{BASE}addons: [{{ name: a, path: /a.wasm, mode: observe, \
         limits: {{ max_memory: 2mb, max_instances: 5 }} }}]\n"
    ));
    let a = &c.addons[0];
    assert_eq!(a.mode, AddonMode::Observe);
    assert_eq!(a.limits.max_memory, Some(ByteSize::b(2 << 20)));
    assert_eq!(a.limits.max_instances, Some(5));
    assert_eq!(a.limits.first_byte_timeout, None);
    assert_eq!(c.limits.max_address_list_bytes, ByteSize::b(256 << 20));

    for bad in ["capabilities: [terminate]", "terminate_endpoint: x"] {
        assert!(
            Config::from_yaml(&format!(
                "{BASE}addons: [{{ name: a, path: /a.wasm, {bad} }}]\n"
            ))
            .is_err(),
            "{bad}"
        );
    }
}

/// An endpoint's `path` is `fixed` unless the config says `prefix`; any
/// other spelling is a parse error.
#[test]
fn endpoint_path_mode() {
    let c = parse(&format!(
        "{BASE}addons: [{{ name: a, path: /a.wasm, endpoints: {{ \
         m: {{ url: https://a.test/v1 }}, p: {{ url: https://a.test/v1, path: prefix }} }} }}]\n"
    ));
    let e = &c.addons[0].endpoints;
    assert_eq!(e["m"].path, EndpointPath::Fixed);
    assert_eq!(e["p"].path, EndpointPath::Prefix);
    let err = Config::from_yaml(&format!(
        "{BASE}addons: [{{ name: a, path: /a.wasm, endpoints: {{ \
         m: {{ url: https://a.test/v1, path: append }} }} }}]\n"
    ))
    .unwrap_err()
    .to_string();
    assert!(err.contains("unknown variant `append`"), "{err}");
}

/// Endpoint header names are case-insensitive, so two spellings of one
/// name are a duplicate the map alone would not catch.
#[test]
fn endpoint_headers_differing_only_in_case_are_duplicates() {
    let d = diagnostics(&format!(
        "{BASE}addons: [{{ name: a, path: /a.wasm, endpoints: {{ \
         m: {{ url: https://a.test/v1, headers: {{ X-Token: a, x-token: b }} }} }} }}]\n"
    ));
    let dup: Vec<_> = d
        .iter()
        .filter(|d| d.message.contains("duplicate key"))
        .collect();
    assert_eq!(dup.len(), 1, "{d:#?}");
    assert_eq!(dup[0].path, "addons[0].endpoints.m.headers.x-token");
}

/// `deny_cidrs` and `allow_cidrs` are networks: host bits are refused as
/// they are in address lists and rule literals, not silently dropped.
#[test]
fn upstream_cidrs_with_host_bits_are_rejected() {
    let d = diagnostics(&format!(
        "{BASE}upstream: {{ deny_cidrs: [10.0.0.1/8, 192.0.2.0/24], allow_cidrs: [\"2001:db8::1/32\"] }}\n"
    ));
    let paths: Vec<&str> = d.iter().map(|d| d.path.as_str()).collect();
    assert_eq!(
        paths,
        ["upstream.deny_cidrs[0]", "upstream.allow_cidrs[0]"],
        "{d:#?}"
    );
    assert!(
        d[0].message.contains("did you mean 10.0.0.0/8?"),
        "{}",
        d[0]
    );
    assert!(
        d[1].message.contains("did you mean 2001:db8::/32?"),
        "{}",
        d[1]
    );
}

#[test]
fn flow_log_defaults_and_rotation_settings() {
    let cfg = parse(BASE);
    let f = &cfg.log.flow;
    assert_eq!(f.high_water.as_u64(), 8 << 20);
    assert_eq!(
        (f.max_file_bytes, f.max_files, f.compress),
        (None, None, false)
    );

    let cfg = parse(&format!(
        "{BASE}log:\n  flow:\n    path: /var/log/roxy/flow.jsonl\n    high_water: 16mb\n    \
         max_file_bytes: 100mb\n    max_files: 7\n    compress: true\n"
    ));
    cfg.validate().unwrap();
    let f = &cfg.log.flow;
    assert_eq!(f.high_water.as_u64(), 16 << 20);
    assert_eq!(f.max_file_bytes.map(|b| b.as_u64()), Some(100 << 20));
    assert_eq!(f.max_files, Some(7));
    assert!(f.compress);
}

#[test]
fn flow_log_settings_validated() {
    for (yaml, path, needle) in [
        ("high_water: 1kb", "log.flow.high_water", "at least 64kb"),
        ("max_file_bytes: 1mb", "log.flow", "need `path`"),
        (
            "path: /x.jsonl\n    max_files: 3",
            "log.flow.max_file_bytes",
            "set max_file_bytes",
        ),
        (
            "path: /x.jsonl\n    max_file_bytes: 1kb",
            "log.flow.max_file_bytes",
            "at least 4kb",
        ),
        (
            "path: /x.jsonl\n    max_file_bytes: 1mb\n    max_files: 0",
            "log.flow.max_files",
            "at least 1",
        ),
    ] {
        let d = diagnostics(&format!("{BASE}log:\n  flow:\n    {yaml}\n"));
        assert!(
            d.iter()
                .any(|d| d.path == path && d.message.contains(needle)),
            "{yaml}: {d:?}"
        );
    }
}

/// `log.capture` configures how captures are written; without
/// `capture_dir` nothing is captured, so any setting there is a mistake.
#[test]
fn capture_settings_without_a_capture_dir_diagnosed() {
    for yaml in [
        "high_water: 128mb",
        "max_file_bytes: 1mb",
        "max_file_bytes: 1mb\n    max_files: 3",
        "max_file_bytes: 1mb\n    compress: true",
    ] {
        let d = diagnostics(&format!("{BASE}log:\n  capture:\n    {yaml}\n"));
        assert_eq!(d.len(), 1, "{yaml}: {d:?}");
        assert_eq!(d[0].path, "log.capture");
        assert!(d[0].message.contains("need `capture_dir`"), "{}", d[0]);
    }
    // `all: true` is reported against `capture_dir`, once.
    let d = diagnostics(&format!(
        "{BASE}log:\n  capture:\n    all: true\n    max_file_bytes: 1mb\n"
    ));
    assert_eq!(d.len(), 1, "{d:?}");
    assert_eq!(d[0].path, "capture_dir");
    parse(&format!(
        "{BASE}capture_dir: /tmp/c\nlog:\n  capture:\n    max_file_bytes: 1mb\n    compress: true\n"
    ))
    .validate()
    .unwrap();
}

#[test]
fn service_addons_validate() {
    let (_dir, wasm) = wasm_file();
    let ok = format!(
        "{BASE}addons:\n  - name: s\n    kind: service\n    endpoint: svc\n    \
         limits: {{ first_byte_timeout: 2s, max_connections: 2, max_streams: 50 }}\n    \
         endpoints:\n      svc: {{ url: \"http://127.0.0.1:9000/layer\", private_ok: true }}\n"
    );
    parse(&ok).validate().unwrap();

    let d = diagnostics(&format!(
        "{BASE}addons:\n  - name: s\n    kind: service\n    endpoint: nope\n    \
         capabilities: [log]\n    config: {{ a: 1 }}\n    \
         limits: {{ max_memory: 1mb, max_connections: 0, max_streams: 0, first_byte_timeout: 0s }}\n    \
         endpoints:\n      svc: {{ url: \"http://127.0.0.1:9000/\" }}\n  \
         - name: w\n    path: {wasm}\n    limits: {{ first_byte_timeout: 0s, max_connections: 2 }}\n"
    ));
    let paths: Vec<&str> = d.iter().map(|d| d.path.as_str()).collect();
    for p in [
        "addons[0].endpoint",
        "addons[0].capabilities",
        "addons[0].config",
        "addons[0].limits.max_memory",
        "addons[0].limits.max_connections",
        "addons[0].limits.max_streams",
        "addons[0].limits.first_byte_timeout",
        "addons[1].limits.max_connections",
        "addons[1].limits.first_byte_timeout",
    ] {
        assert!(paths.contains(&p), "{p} not in {paths:?}");
    }
}

/// `roxy check` refuses what `roxy run` would refuse at load, or what
/// would fail every exchange: no limit may be zero, and an instance must
/// be able to reach `recycle_above_memory` under `max_memory`.
#[test]
fn addon_limits_check_matches_run() {
    let (_dir, wasm) = wasm_file();
    for (bad, path, says) in [
        (
            "limits: { first_byte_timeout: 0s }",
            "addons[0].limits.first_byte_timeout",
            "positive",
        ),
        (
            "limits: { max_memory: 0 }",
            "addons[0].limits.max_memory",
            "at least 1 byte",
        ),
        (
            "limits: { recycle_above_memory: 0 }",
            "addons[0].limits.recycle_above_memory",
            "at least 1 byte",
        ),
        (
            "limits: { max_memory: 16mb, recycle_above_memory: 17mb }",
            "addons[0].limits.recycle_above_memory",
            "must not exceed max_memory (16.0 MiB)",
        ),
        (
            "limits: { recycle_above_memory: 65mb }",
            "addons[0].limits.recycle_above_memory",
            "must not exceed max_memory (64.0 MiB)",
        ),
        (
            "limits: { max_instances: 0 }",
            "addons[0].limits.max_instances",
            "at least 1",
        ),
        (
            "endpoints: { e: { url: \"https://x.test/\", timeout: 0s } }",
            "addons[0].endpoints.e.timeout",
            "positive",
        ),
        (
            "endpoints: { e: { url: \"https://x.test/\", retries: 10 } }",
            "addons[0].endpoints.e.retries",
            "at most 9",
        ),
    ] {
        let d = diagnostics(&format!(
            "{BASE}addons: [{{ name: a, path: {wasm}, {bad} }}]\n"
        ));
        assert_eq!(d.len(), 1, "{bad}: {d:?}");
        assert_eq!(d[0].path, path, "{bad}");
        assert!(d[0].message.contains(says), "{bad}: {}", d[0]);
    }
    // `recycle_above_memory` may equal `max_memory`; lowering `max_memory`
    // alone is fine, since the unset threshold follows it.
    for ok in [
        "limits: { max_memory: 256mb, recycle_above_memory: 256mb }",
        "limits: { max_memory: 16mb }",
        "endpoints: { e: { url: \"https://x.test/\", retries: 9 } }",
    ] {
        parse(&format!(
            "{BASE}addons: [{{ name: a, path: {wasm}, {ok} }}]\n"
        ))
        .validate()
        .unwrap_or_else(|d| panic!("{ok}: {d:?}"));
    }

    let d = diagnostics(&format!(
        "{BASE}addons: [{{ name: a, path: {wasm}.missing }}]\n"
    ));
    assert_eq!(d.len(), 1, "{d:?}");
    assert_eq!(d[0].path, "addons[0].path");
    assert!(d[0].message.ends_with("does not exist"), "{}", d[0]);
}

#[test]
fn addon_when_and_sample() {
    let (_dir, wasm) = wasm_file();
    let cfg = parse(&format!(
        "{BASE}metrics: [{{ id: calls, count: requests }}]\n\
         addons:\n  \
         - {{ name: a, path: {wasm}, when: 'host == \"x.test\" and metric.calls < 10' }}\n  \
         - {{ name: b, path: {wasm}, mode: observe, when: 'method == POST', sample: 0.25 }}\n"
    ));
    let conditions = cfg.validate().unwrap().addon_conditions;
    assert_eq!(cfg.addons[1].sample, Some(0.25));
    assert!(conditions.iter().all(Option::is_some));
}

#[test]
fn addon_when_and_sample_diagnosed() {
    let (_dir, wasm) = wasm_file();
    for (bad, path, says) in [
        (
            "when: 'response.status == 200'",
            "addons[0].when",
            "head fields",
        ),
        (
            "when: 'body.text contains \"x\"'",
            "addons[0].when",
            "body.text",
        ),
        ("when: 'metric.nope > 1'", "addons[0].when", "nope"),
        ("when: 'host =='", "addons[0].when", ""),
        (
            "mode: observe, sample: 0",
            "addons[0].sample",
            "greater than 0",
        ),
        (
            "mode: observe, sample: 1.5",
            "addons[0].sample",
            "at most 1",
        ),
        ("sample: 0.5", "addons[0].sample", "mode: observe"),
    ] {
        let d = diagnostics(&format!(
            "{BASE}addons: [{{ name: a, path: {wasm}, {bad} }}]\n"
        ));
        assert_eq!(d.len(), 1, "{bad}: {d:?}");
        assert_eq!(d[0].path, path, "{bad}");
        assert!(d[0].to_string().contains(says), "{bad}: {}", d[0]);
    }
}

/// An absent `max_connections_per_client` follows `max_connections`, so
/// raising the global cap alone raises the per-client one; a value given
/// stands whatever `max_connections` is.
#[test]
fn per_client_cap_follows_max_connections_unless_set() {
    let raised = parse(&format!("{BASE}limits: {{ max_connections: 50000 }}\n"));
    raised.validate().unwrap();
    assert_eq!(raised.startup().per_client_cap(), 50_000);

    let lowered = parse(&format!(
        "{BASE}limits: {{ max_connections: 50000, max_connections_per_client: 200 }}\n"
    ));
    assert_eq!(lowered.startup().per_client_cap(), 200);
    let above = parse(&format!(
        "{BASE}limits: {{ max_connections: 10, max_connections_per_client: 200 }}\n"
    ));
    assert_eq!(above.startup().per_client_cap(), 200);
}

/// The restart-only changes from `running` to `new`; a second pass over
/// the result finds none, since every one was put back.
fn restart(running: &str, new: &str) -> Vec<&'static str> {
    let running = parse(running).startup();
    let mut new = parse(new);
    let changed = new.keep_startup(&running);
    assert!(new.keep_startup(&running).is_empty(), "kept");
    assert_eq!(new.startup(), running);
    changed
}

#[test]
fn listeners_need_a_restart() {
    let base = "version: 1\nlisteners: [{ name: p, bind: 127.0.0.1:443 }]\n";
    let moved = "version: 1\nlisteners: [{ name: p, bind: 127.0.0.1:8443 }]\n";
    let renamed = "version: 1\nlisteners: [{ name: q, bind: 127.0.0.1:8443 }]\n";
    assert_eq!(restart(base, moved), ["listeners"]);
    assert_eq!(restart(moved, renamed), ["listeners"]);
}

/// Every setting the server reads once, at start, is kept on reload and
/// named by its config path; the rest of the same sections reload.
#[test]
fn startup_only_settings_need_a_restart() {
    for (yaml, field) in [
        ("tls: { ca_dir: /tmp/elsewhere }", "tls.ca_dir"),
        ("tls: { leaf_cache_size: 5 }", "tls.leaf_cache_size"),
        (
            "tls: { upstream: { min_version: \"1.3\" } }",
            "tls.upstream",
        ),
        ("ca_server: { bind: 127.0.0.1:3130 }", "ca_server"),
        (
            "upstream: { dns: { static_hosts: { a.test: 10.0.0.1 } } }",
            "upstream.dns",
        ),
        ("upstream: { dns: { cache_ttl_cap: 5s } }", "upstream.dns"),
        ("limits: { max_connections: 5 }", "limits.max_connections"),
        (
            "limits: { max_connections_per_client: 5 }",
            "limits.max_connections_per_client",
        ),
        (
            "limits: { max_state_entries: 5 }",
            "limits.max_state_entries",
        ),
        (
            "limits: { max_capture_body_bytes: 1mb }",
            "limits.max_capture_body_bytes",
        ),
        ("log: { flow: { path: /tmp/x.jsonl } }", "log.flow"),
        ("log: { capture: { all: true } }", "log.capture"),
        ("log: { capture: { max_file_bytes: 1mb } }", "log.capture"),
        ("capture_dir: /tmp/c", "capture_dir"),
    ] {
        assert_eq!(restart(BASE, &format!("{BASE}{yaml}\n")), [field], "{yaml}");
    }
    let provided = format!("{BASE}tls: {{ ca_cert: /tmp/a.pem, ca_key: /tmp/a.key }}\n");
    assert_eq!(restart(BASE, &provided), ["tls.ca_cert", "tls.ca_key"]);
    assert_eq!(
        restart(
            BASE,
            &format!(
                "{BASE}http: {{ allow_http10: true, enable_h2: false }}\n\
                 limits: {{ max_headers: 5, max_header_bytes: 8kb }}\n\
                 tls: {{ require_sni_match: false }}\n\
                 upstream: {{ deny_private_ranges: false, connect_timeout: 3s }}\n\
                 log: {{ redact_headers: [x-a] }}\n"
            )
        ),
        Vec::<&str>::new()
    );
}

/// The operations guide lists the restart-only settings by hand; the list
/// is the type's.
#[test]
fn docs_list_the_restart_only_settings() {
    let doc = include_str!("../../../../docs/pages/guides/operations.md");
    let section = doc
        .split("### Restart-only settings")
        .nth(1)
        .and_then(|rest| rest.trim_start().split("\n\n").next())
        .expect("a restart-only settings section");
    let listed: Vec<&str> = section.split('`').skip(1).step_by(2).collect();
    assert_eq!(listed, Startup::NAMES, "{section}");
}
