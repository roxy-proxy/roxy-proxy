//! Golden diagnostics for malformed rules and metrics.

mod common;

use std::fmt::Write as _;

use common::{METRICS, try_compile};
use proptest::prelude::*;
use roxy_rules::Policy;

/// (title, metrics yaml, rules yaml)
const CASES: &[(&str, &str, &str)] = &[
    (
        "unknown field",
        "",
        "- { id: a, when: 'hots == \"x\"', then: allow }",
    ),
    (
        "type mismatch",
        "",
        "- { id: a, when: 'port == \"443\"', then: allow }",
    ),
    (
        "under needs a domain",
        "",
        "- { id: a, when: 'host under 443', then: allow }",
    ),
    (
        "under with an empty label",
        "",
        "- { id: a, when: 'host under \"example.com..\"', then: allow }\n- { id: b, when: 'host under \"a..b\"', then: allow }",
    ),
    (
        "host literal that can never match",
        "",
        "- { id: a, when: 'host == \"evil.example.\"', then: deny }\n- { id: b, when: 'host in [\"ok.example\", \"evil.example.\"]', then: deny }\n- { id: c, when: 'host like \"*.example.com.\"', then: deny }\n- { id: d, when: 'host == \"b\u{fc}cher.example\"', then: deny }\n- { id: e, when: 'host == \"[::1]\"', then: deny }\n- { id: f, when: '\"evil.example.\" != host', then: deny }\n- { id: g, when: 'host ends_with \".example.\"', then: deny }\n- { id: h, when: 'tls.sni starts_with \"[fe80\"', then: deny }\n- { id: i, when: 'host under \"caf\u{e9}.example\"', then: deny }",
    ),
    (
        "null compared with a field that is never null",
        METRICS,
        "- { id: a, when: 'tag[\"x\"] == null', then: allow }\n- { id: b, when: 'metric.writes != null', then: allow }\n- { id: c, when: 'null != body.text', then: allow }",
    ),
    (
        "ordering on strings",
        "",
        "- { id: a, when: 'path < 5', then: allow }",
    ),
    (
        "wrong list element type",
        "",
        "- { id: a, when: 'port in [80, \"443\"]', then: allow }",
    ),
    (
        "method literal outside method",
        "",
        "- { id: a, when: 'path == GET', then: allow }",
    ),
    (
        "bare string field as condition",
        "",
        "- { id: a, when: 'host and method == GET', then: allow }",
    ),
    (
        "not-equal on a list",
        "",
        "- { id: a, when: 'header.all[\"accept\"] != \"x\"', then: allow }",
    ),
    (
        "bad regex",
        "",
        "- { id: a, when: 'path matches \"(unclosed\"', then: allow }",
    ),
    (
        "bad CIDR mask",
        "",
        "- { id: a, when: 'client.ip in [10.0.0.0/33]', then: allow }",
    ),
    (
        "CIDR with host bits",
        "",
        "- { id: a, when: 'client.ip in 192.168.1.1/16', then: allow }",
    ),
    (
        "unterminated string",
        "",
        "- { id: a, when: 'host == \"api.github.com', then: allow }",
    ),
    (
        "allow in a watching rule",
        "",
        "- { id: a, when: 'response.status >= 500', then: allow }",
    ),
    (
        "connect-time fields are gone",
        "",
        "- { id: a, when: 'dst.port == 22', then: deny }",
    ),
    (
        "unknown metric",
        METRICS,
        "- { id: a, when: 'metric.writes > 3 and metric.nope > 1', then: deny }",
    ),
    (
        "multi-line expression",
        "",
        "- id: a\n  when: |\n    host under \"github.com\"\n      and method in [GET, HEAD]\n      and path like 5\n  then: allow\n",
    ),
    (
        "unknown secret",
        "",
        "- id: a\n  then:\n    - set_header: { authorization: \"Bearer ${secret:openai}\", x-k: \"${secret:missing}\" }\n    - allow\n",
    ),
    (
        "secret in a watching rule",
        "",
        "- { id: a, when: 'response.status == 500', then: { set_header: { x-k: \"${secret:gh}\" } } }",
    ),
    (
        "secret outside set_header",
        "",
        "- { id: a, then: { log: { message: \"${secret:gh}\" } } }",
    ),
    (
        "secret in a when expression",
        "",
        "- { id: a, when: 'header[\"authorization\"] == \"Bearer ${secret:gh}\"', then: allow }\n- { id: b, when: 'state[\"${secret:gh}\"] == \"x\"', then: allow }\n- { id: c, when: 'path in [\"/a\", \"${secret:nope\"]', then: allow }",
    ),
    (
        "secret in a metric where",
        "- { id: t, count: requests, where: 'path == \"${secret:gh}\"' }",
        "[]",
    ),
    (
        "sign unsigned_payload outside S3",
        "",
        "- { id: a, then: [{ sign: { aws_sigv4: { service: bedrock, region: eu-west-2, access_key_id: \"${secret:openai}\", secret_access_key: \"${secret:gh}\", unsigned_payload: true } } }, allow] }",
    ),
    (
        "sign with undefined and misplaced secrets, and an empty credential",
        "",
        "- { id: a, then: [{ sign: { aws_sigv4: { service: \"${secret:gh}\", region: eu-west-2, access_key_id: \"${secret:missing}\", secret_access_key: \"\" } } }, allow] }",
    ),
    (
        "sign in a watching rule",
        "",
        "- { id: a, when: 'response.status == 500', then: { sign: { aws_sigv4: { service: s3, region: us-east-1, access_key_id: \"${secret:openai}\", secret_access_key: \"${secret:gh}\" } } } }",
    ),
    (
        "passthrough is reserved",
        "",
        "- { id: a, then: passthrough }",
    ),
    (
        "call is reserved",
        "",
        "- { id: a, then: [{ call: scan }, allow] }",
    ),
    (
        "tag read above the rule that sets it",
        "",
        "- { id: read, when: 'tag[\"risky\"]', then: deny }\n- { id: mark, when: 'path starts_with \"/admin\"', then: [{ tag: risky }] }",
    ),
    (
        "tag read at the head but set by a watching rule",
        "",
        "- { id: big, when: 'body.bytes > 10', then: [{ tag: big }] }\n- { id: read, when: 'tag[\"big\"]', then: deny }",
    ),
    (
        "tag read by a watching rule but set by a watching rule above it",
        "",
        "- { id: big, when: 'body.bytes > 10', then: [{ tag: big }] }\n- { id: cap, when: 'tag[\"big\"] and response.body.bytes > 1mb', then: deny }",
    ),
    (
        "tag read by a watching rule but set by a deny watching a byte metric",
        METRICS,
        "- { id: budget, when: 'metric.egress > 1mb', then: [{ tag: over }, deny] }\n- { id: note, when: 'tag[\"over\"] and response.body.bytes > 0', then: { log: { message: over } } }",
    ),
    (
        "rewrite_path group references",
        "",
        "- { id: a, then: [{ rewrite_path: { match: \"/v(\\\\d)/(?P<rest>.*)\", to: \"/$3/${nope}/$1a/${rest}/$$\" } }, allow] }",
    ),
    (
        "metric where reads a tag",
        "- { id: t, count: requests, where: 'tag[\"billing\"] and host == \"x\"' }",
        "[]",
    ),
    (
        "multi-key action map",
        "",
        "- { id: a, then: { set_header: { x: y }, allow: {} } }",
    ),
    (
        "terminal action followed by another",
        "",
        "- { id: a, then: [allow, { tag: late }] }",
    ),
    (
        "unknown action",
        "",
        "- { id: a, then: { sethead: { x: y } } }",
    ),
    (
        "request mutation in a watching rule",
        "",
        "- { id: a, when: 'body.bytes > 1mb', then: { rewrite_path: { match: \"/a\", to: \"/b\" } } }",
    ),
    (
        "request header change in a watching rule",
        "",
        "- { id: a, when: 'body.bytes > 1mb', then: { set_header: { x-a: b } } }",
    ),
    (
        "response header change that could fire after the head is sent",
        "",
        "- { id: a, when: 'response.status == 200 and response.body.bytes > 1mb', then: { remove_header: [x-a] } }",
    ),
    (
        "reserved header and bad value",
        "",
        "- { id: a, then: [{ set_header: { Host: evil } }, { set_header: { x-a: \"caf\u{e9}\" } }, allow] }",
    ),
    (
        "bad deny status",
        "",
        "- { id: a, then: { deny: { status: 200 } } }",
    ),
    (
        "duplicate and reserved ids",
        "",
        "- { id: a, then: allow }\n- { id: a, then: deny }\n- { id: _default, then: deny }\n- { id: _fail_closed, then: deny }",
    ),
    (
        "address list on a non-ip field",
        "",
        "- { id: a, when: 'host in @internal', then: deny }",
    ),
    (
        "address list with ==",
        "",
        "- { id: a, when: '@internal == 1', then: deny }",
    ),
    (
        "address list inside a list literal",
        "",
        "- { id: a, when: 'client.ip in [10.0.0.0/8, @internal]', then: deny }",
    ),
    (
        "address list as a condition",
        "",
        "- { id: a, when: '@internal', then: deny }",
    ),
    (
        "undefined address list",
        "",
        "- { id: a, when: 'client.ip not in @nope', then: deny }",
    ),
    (
        "nullable metric key without a guard",
        "- { id: a, count: requests, key: [client.ip, tls.sni] }\n- { id: b, count: unique(body.size), where: 'method == POST' }\n- { id: c, count: requests, key: [query.raw], where: 'query.raw != null or host == \"x\"' }\n- { id: d, count: requests, key: [tls.alpn], where: 'tls.sni != null' }",
        "[]",
    ),
    (
        "bad metrics",
        "- { id: bad-id, count: requests, key: [client.nope], window: 0s, max_keys: 0 }\n- { id: r, count: response_bytes, where: 'dst.port == 1' }\n- { id: u, count: unique(nope) }\n- { id: w, count: errors, where: 'response.status >= 500', key: [body.bytes] }\n- { id: v, count: unique(response.status) }",
        "[]",
    ),
];

#[test]
fn diagnostics_golden() {
    let mut out = String::new();
    for (title, metrics, rules) in CASES {
        let Err(diags) = try_compile(metrics, rules) else {
            panic!("{title}: expected diagnostics")
        };
        writeln!(out, "== {title}").unwrap();
        for d in diags {
            writeln!(out, "{d}").unwrap();
        }
        out.push('\n');
    }
    insta::assert_snapshot!("diagnostics_golden", out);
}

/// Host literals in the forms hosts are delivered in compile, as do
/// literals that only look wrong out of position: a dot can end a
/// `starts_with` prefix, a `like` pattern can end in `*`, and case is
/// irrelevant.
#[test]
fn well_formed_host_literals_compile() {
    for expr in [
        "host == \"evil.example\"",
        "host == \"API.GitHub.com\"",
        "host == \"10.0.0.1\"",
        "host == \"::1\"",
        "host in [\"xn--bcher-kva.example\", \"2001:db8::1\"]",
        "host like \"*.example.*\"",
        "host like \"api.?\"",
        "host starts_with \"api.\"",
        "host contains \".internal.\"",
        "host under \"example.com.\"",
        "host matches \"\\\\[::1\\\\]\"",
        "path == \"/a.\"",
        "header[\"x-host\"] == \"[::1]\"",
    ] {
        let rules = format!("- id: a\n  when: '{expr}'\n  then: allow\n");
        common::compile("", &rules);
    }
}

/// `roxy check` advice, not a compile error: a metric keyed on a field the
/// client picks freely needs a `where` to bound its series.
#[test]
fn client_chosen_key_without_where_warns() {
    let metrics: Vec<roxy_rules::MetricConfig> = roxy_rules::yaml::from_str(
        "- { id: a, count: requests, key: [host] }
- { id: b, count: requests, key: [client.ip, path] }
- { id: c, count: unique(url) }
- { id: d, count: requests, key: [path], where: 'host under \"example.com\"' }
- { id: e, count: unique(query.raw), where: 'query.raw != null' }
- { id: f, count: requests, key: [client.ip, client.port] }
- { id: g, count: requests, key: [host, client.port], where: 'host under \"example.com\"' }",
    )
    .unwrap();
    let warnings = Policy::metric_warnings(&metrics);
    let heads: Vec<String> = warnings
        .iter()
        .map(|d| format!("{}: {}", d.path, d.message.split(',').next().unwrap()))
        .collect();
    assert_eq!(
        heads,
        [
            "metrics[0].key[0]: `host` is chosen by the client",
            "metrics[1].key[1]: `path` is chosen by the client",
            "metrics[2].count: `url` is chosen by the client",
            "metrics[5].key[1]: `client.port` is chosen by the client",
        ]
    );
    // Only `host` is bounded by a `where` on host; the advice must not send
    // operators to a filter that silences the warning without removing the risk.
    assert!(warnings[0].message.contains("`where: host under"));
    for d in &warnings[1..] {
        assert!(
            !d.message.contains("host under") && d.message.contains("not how many"),
            "{}",
            d.message
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Type checking never panics on arbitrary (often ill-typed) input.
    #[test]
    fn compile_never_panics(toks in prop::collection::vec(prop::sample::select(vec![
        "host", "path", "port", "client.ip", "header[\"a\"]", "header.all[\"a\"]",
        "metric.writes", "metric.nope", "tag[\"t\"]", "state[\"s\"]", "body.text",
        "response.status", "body.bytes", "response.body.bytes", "\"x\"", "\"(\"", "\"*\"", "5", "1kb", "GET",
        "true", "10.0.0.0/8", "::1", "[1, 2]", "[\"a\"]", "[GET]", "[10.0.0.0/8, ::1]", "@internal", "@nope", "[@internal]",
        "==", "!=", "<", ">=", "in", "not in", "starts_with", "contains", "like",
        "matches", "under", "and", "or", "not", "(", ")",
    ]), 1..12)) {
        let expr = toks.join(" ");
        let rules = format!("- id: a\n  when: '{}'\n  then: allow\n", expr.replace('\'', "''"));
        let _ = try_compile(METRICS, &rules);
    }
}

/// A `like` pattern is bounded at compile time, below what the regex size
/// limit admits for the costliest globs (`?` and `*` on a case-insensitive
/// field), so every pattern within the bound compiles.
#[test]
fn like_pattern_length_is_bounded() {
    let rule = |pat: &str| format!("- id: a\n  when: 'host like \"{pat}\"'\n  then: allow\n");
    let over = rule(&"k".repeat(roxy_rules::MAX_GLOB_BYTES + 1));
    let diags = try_compile("", &over).expect_err("oversize pattern");
    assert_eq!(diags.len(), 1);
    assert!(
        diags[0].starts_with("rules[0].when:1:11: pattern is longer than"),
        "{}",
        diags[0]
    );
    for at_bound in [
        "?".repeat(roxy_rules::MAX_GLOB_BYTES),
        "*k".repeat(roxy_rules::MAX_GLOB_BYTES / 2),
    ] {
        try_compile("", &rule(&at_bound)).unwrap_or_else(|d| panic!("{}", d.join("\n")));
    }
}
