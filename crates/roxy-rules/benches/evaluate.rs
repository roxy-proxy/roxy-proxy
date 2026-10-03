//! Rule evaluation for a 100-rule policy (DESIGN.md §14: target < 5 µs).

use std::collections::HashSet;
use std::fmt::Write as _;
use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use roxy_rules::{EvalContext, Field, MapView, Phase, Policy, PolicyInput, RuleConfig, Value};

/// 99 rules that do not match the benchmark request (a mix of every
/// operator kind), then the rule that allows it.
fn rules_yaml() -> String {
    let mut y = String::new();
    for i in 0..99 {
        let when = match i % 6 {
            0 => format!("host == \"svc{i}.example.com\" and method == GET"),
            1 => format!("host under \"dom{i}.example.org\" and path starts_with \"/api/\""),
            2 => format!("path matches \"/v[0-9]+/item{i}/.*\" and method in [POST, PUT]"),
            3 => format!("client.ip in [10.{i}.0.0/16, 192.168.{i}.0/24] and port == 8443"),
            4 => format!("header[\"x-tenant\"] == \"t{i}\" and path like \"/t{i}/*\""),
            _ => format!("metric.writes > {i}00 and host ends_with \".corp{i}\""),
        };
        let then = if i % 3 == 0 {
            "[{ tag: t }, allow]"
        } else {
            "deny"
        };
        writeln!(
            y,
            "- id: r{i}\n  when: '{}'\n  then: {then}",
            when.replace('\'', "''")
        )
        .unwrap();
    }
    y.push_str(
        "- id: github-reads\n  when: 'host under \"github.com\" and method in [GET, HEAD]'\n  \
         then: allow\n",
    );
    y
}

fn policy() -> Policy {
    let rules: Vec<RuleConfig> = serde_yaml_ng::from_str(&rules_yaml()).unwrap();
    let metrics: Vec<roxy_rules::MetricConfig> =
        serde_yaml_ng::from_str("[{ id: writes, count: requests, key: [client.ip], window: 1m }]")
            .unwrap();
    let none = HashSet::new();
    Policy::compile(&PolicyInput {
        rules: &rules,
        metrics: &metrics,
        secret_names: &none,
        addon_names: &none,
        address_lists: &none,
        transparent_listeners: false,
    })
    .unwrap()
}

fn request(host: &str) -> MapView {
    MapView::new()
        .with_str(Field::Method, "GET")
        .with_str(Field::Scheme, "https")
        .with_str(Field::Host, host)
        .with_int(Field::Port, 443)
        .with_str(Field::Path, "/repos/rust-lang/rust/issues")
        .with(Field::ClientIp, Value::Ip("172.17.0.2".parse().unwrap()))
        .with_header("user-agent", "curl/8.5")
        .with_header("x-tenant", "acme")
        .with_metric("writes", 12)
}

fn bench(c: &mut Criterion) {
    let p = policy();
    let ctx = EvalContext::empty();
    let allowed = request("api.github.com");
    let denied = request("evil.example.net");
    assert_eq!(
        p.evaluate(Phase::Request, &allowed, &ctx).terminal_rule,
        "github-reads"
    );
    assert!(p.evaluate(Phase::Request, &denied, &ctx).decision.is_deny());

    c.bench_function("evaluate_100_rules_last_matches", |b| {
        b.iter(|| p.evaluate(Phase::Request, black_box(&allowed), &ctx));
    });
    c.bench_function("evaluate_100_rules_default_deny", |b| {
        b.iter(|| p.evaluate(Phase::Request, black_box(&denied), &ctx));
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
