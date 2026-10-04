//! The rule language front end on arbitrary strings: lexer, parser,
//! type-checker and compiler (`roxy_rules::parse`, `Policy::compile`).
//!
//! Invariants:
//! - nothing panics, for any expression text, as an `allow` or a `deny`
//!   rule, and as a metric's `where` filter;
//! - a policy that compiles can be evaluated (head and watching) on an
//!   empty and on a populated flow without panicking, and a fail-closed
//!   head outcome is never an allow.
#![no_main]

use libfuzzer_sys::fuzz_target;
use roxy_rules::{EvalContext, Field, MapView, Reads};
use serde_json::json;

fuzz_target!(|data: &[u8]| {
    let Ok(src) = std::str::from_utf8(data) else {
        return;
    };
    let _ = roxy_rules::parse(src);

    // As a metric filter (head fields only; anything else is an error).
    let rules: Vec<roxy_rules::RuleConfig> = Vec::new();
    if let Ok(metrics) = serde_json::from_value::<Vec<roxy_rules::MetricConfig>>(json!([
        { "id": "f", "count": "requests", "where": src }
    ])) {
        let none = std::collections::HashSet::new();
        let _ = roxy_rules::Policy::compile(&roxy_rules::PolicyInput {
            rules: &rules,
            metrics: &metrics,
            secret_names: &none,
            address_lists: &none,
            transparent_listeners: false,
            default: roxy_rules::DefaultDecision::Deny,
        });
    }

    let populated = MapView::new()
        .with_str(Field::Host, "api.example.com")
        .with_str(Field::Method, "POST")
        .with_str(Field::Path, "/a/b")
        .with_int(Field::Port, 443)
        .with_int(Field::BodyBytes, 1 << 20)
        .with_int(Field::ResponseStatus, 500)
        .with_header("x-a", "1")
        .with_metric("m0", 5)
        .with_metric("m1", 1 << 20)
        .with_body("{\"k\": 1}");
    for then in [
        json!("allow"),
        json!("deny"),
        json!([{ "tag": "t0" }, "allow"]),
    ] {
        let Some(policy) =
            roxy_fuzz::rules::compile(json!([{ "id": "r", "when": src, "then": then }]), false)
        else {
            continue;
        };
        for view in [&MapView::new(), &populated] {
            let out = policy.evaluate_head(view, &EvalContext::empty());
            if out.fail_closed_reason.is_some() {
                assert!(!out.decision.is_allow(), "fail-closed allow: {out:?}");
            }
            let mut st = policy.watch_state(&out.tags);
            let _ = policy.evaluate_watching(
                Reads::ALL,
                Reads::ALL,
                &mut st,
                view,
                &EvalContext::empty(),
            );
        }
    }
});
