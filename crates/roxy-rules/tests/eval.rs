//! Evaluation tests against a map-backed `FlowView`.

mod common;

use std::net::IpAddr;
use std::time::Duration;

use common::{METRICS, compile, try_compile};
use roxy_rules::{
    AllowOpts, CaptureTarget, Decision, Deny, DenyStatus, Effect, EvalContext, FailClosedReason,
    Field, LogLevel, MapView, Policy, Reads, RuleKind, Scheme, Value, WatchOutcome,
};

fn ip(s: &str) -> Value<'static> {
    Value::Ip(s.parse::<IpAddr>().unwrap())
}

/// A rich request used by most tests.
fn flow() -> MapView {
    MapView::new()
        .with_str(Field::Method, "POST")
        .with_str(Field::Scheme, "https")
        .with_str(Field::Host, "api.github.com")
        .with_int(Field::Port, 443)
        .with_str(Field::Path, "/repos/a/b/issues")
        .with_str(Field::Url, "https://api.github.com/repos/a/b/issues?page=2")
        .with_str(Field::QueryRaw, "page=2")
        .with(Field::ClientIp, ip("10.1.2.3"))
        .with_int(Field::ClientPort, 50_000)
        .with_str(Field::ListenerName, "proxy")
        .with_str(Field::ListenerMode, "explicit")
        .with_str(Field::TlsSni, "api.github.com")
        .with_str(Field::TlsVersion, "1.3")
        .with_int(Field::BodySize, 1500)
        .with_header("User-Agent", "curl/8.5")
        .with_header("accept", "text/html")
        .with_header("accept", "application/json")
        .with_query("page", "2")
        .with_metric("writes", 30)
        .with_metric("egress", 600 << 20)
        .with_state("mode", "lockdown")
        .with_body("{\"token\": \"hunter2\"}")
}

/// One watching evaluation with every watched value known and changed.
fn watch(p: &Policy, view: &MapView, ctx: &EvalContext<'_>) -> Option<WatchOutcome> {
    let mut st = p.watch_state(ctx.initial_tags);
    p.evaluate_watching(Reads::ALL, Reads::ALL, &mut st, view)
}

/// Does `expr` match `view`? A deny rule reading it is evaluated at the
/// head, or, if it reads watched values, as a watching rule with every
/// watched value known.
fn eval_in(expr: &str, view: &MapView) -> bool {
    let rules = format!(
        "- id: r\n  when: '{}'\n  then: deny\n",
        expr.replace('\'', "''")
    );
    let p = compile(METRICS, &rules);
    let ctx = EvalContext::empty();
    if p.rule_info()[0].kind == RuleKind::Watching {
        watch(&p, view, &ctx)
            .is_some_and(|o| o.stops() && o.terminal_rule.is_some_and(|r| r == "r"))
    } else {
        let out = p.evaluate_head(view, &ctx);
        out.decision.is_deny() && out.terminal_rule == "r"
    }
}

fn eval(expr: &str) -> bool {
    eval_in(expr, &flow())
}

#[track_caller]
fn check(cases: &[(&str, bool)]) {
    for (expr, want) in cases {
        assert_eq!(eval(expr), *want, "{expr}");
    }
}

#[test]
fn equality_and_ordering() {
    check(&[
        ("host == \"api.github.com\"", true),
        ("host != \"api.github.com\"", false),
        ("host != \"x\"", true),
        ("port == 443", true),
        ("port != 443", false),
        (
            "port < 444 and port <= 443 and port > 442 and port >= 443",
            true,
        ),
        ("port < 443", false),
        ("443 == port", true),
        ("client.ip == 10.1.2.3", true),
        ("client.ip == ::ffff:10.1.2.3", true),
        ("listener.mode == \"explicit\"", true),
        ("tls.sni == host", true),
        ("true", true),
        ("false", false),
        ("not false", true),
    ]);
}

/// HTTP methods are case-sensitive: the proxy forwards `get` as an
/// extension method, which may carry a body, so a rule written for `GET`
/// must not match it.
#[test]
fn methods_compare_byte_exact() {
    let lower = flow().with_str(Field::Method, "get");
    for expr in [
        "method == GET",
        "method in [GET]",
        "method in [GET, HEAD]",
        "method starts_with \"GE\"",
        "method like \"G*\"",
        "method matches \"GET\"",
    ] {
        assert!(!eval_in(expr, &lower), "{expr} must not match `get`");
    }
    assert!(eval_in("method == \"get\"", &lower));
    assert!(eval_in("method not in [GET]", &lower));
    // Host comparisons stay case-insensitive.
    assert!(eval_in(
        "host == \"API.GITHUB.COM\"",
        &flow().with_str(Field::Host, "api.github.com")
    ));
}

#[test]
fn string_operators() {
    check(&[
        ("path starts_with \"/repos/\"", true),
        ("path starts_with \"/REPOS/\"", false),
        ("path ends_with \"/issues\"", true),
        ("path contains \"/a/b/\"", true),
        ("path contains \"/c/\"", false),
        ("url contains \"page=2\"", true),
        ("header[\"user-agent\"] starts_with \"curl/\"", true),
        ("header[\"User-Agent\"] == \"curl/8.5\"", true),
        ("query[\"page\"] == \"2\"", true),
        ("query.raw == \"page=2\"", true),
        ("path starts_with query[\"page\"]", false),
    ]);
}

#[test]
fn like_and_matches() {
    check(&[
        ("path like \"/repos/*/issues\"", true),
        ("path like \"/repos/*\"", true),
        ("path like \"/repos/?/b/issues\"", true),
        ("path like \"/repos/??/b/issues\"", false),
        ("path like \"/repos\"", false),
        ("path like \"*issues\"", true),
        ("path like \"**/issues\"", true),
        ("host like \"*.GITHUB.com\"", true),
        ("path matches \"/repos/[a-z]+/[a-z]+/issues\"", true),
        ("path matches \"/repos/[a-z]\"", false),
        ("path matches \"/repos/.*\"", true),
        ("path matches \"/REPOS/.*\"", false),
        ("path matches \"(?i)/REPOS/.*\"", true),
        ("host matches \"API\\\\.github\\\\.com\"", true),
        ("body.text matches \".*hunter2.*\"", true),
    ]);
    // Only `*` and `?` are special in `like`.
    let v = MapView::new().with_str(Field::Path, "/a[1]{x}\\");
    assert!(eval_in("path like \"/a[1]{x}\\\\\"", &v));
    assert!(!eval_in("path like \"/a[12]{x}\\\\\"", &v));
    // Alternation cannot escape the implicit anchors.
    assert!(!eval_in(
        "path matches \"x|/a.*\" and path matches \"zzz|/a\"",
        &v
    ));
}

#[test]
fn under_operator() {
    let host = |h: &str| MapView::new().with_str(Field::Host, h);
    for (h, want) in [
        ("github.com", true),
        ("api.github.com", true),
        ("a.b.github.com", true),
        ("github.com.", true),
        ("evilgithub.com", false),
        ("github.com.evil.org", false),
        ("com", false),
    ] {
        assert_eq!(eval_in("host under \"github.com\"", &host(h)), want, "{h}");
    }
    assert!(eval_in(
        "host under \"GitHub.COM.\"",
        &host("API.github.com")
    ));
}

#[test]
fn membership_and_cidrs() {
    check(&[
        ("method in [GET, POST]", true),
        ("method in [GET, HEAD]", false),
        ("method not in [GET, HEAD]", true),
        ("method in [\"post\"]", false),
        ("host in [\"pypi.org\", \"API.GITHUB.COM\"]", true),
        ("port in [80, 443]", true),
        ("port not in [80, 443]", false),
        ("client.ip in 10.0.0.0/8", true),
        ("client.ip in [192.168.0.0/16, 10.1.0.0/16]", true),
        ("client.ip in [10.1.2.3]", true),
        ("client.ip not in [10.0.0.0/8]", false),
        ("client.ip in [fd00::/8]", false),
        ("client.ip not in [fd00::/8, 172.16.0.0/12]", true),
    ]);
    let v6 = MapView::new().with(Field::ClientIp, ip("fd12::1"));
    assert!(eval_in("client.ip in [fd00::/8]", &v6));
    let mapped = MapView::new().with(Field::ClientIp, ip("::ffff:10.9.9.9"));
    assert!(eval_in("client.ip in 10.0.0.0/8", &mapped));
}

/// Flow addresses are canonicalised to IPv4 before matching, so an
/// IPv4-mapped CIDR literal must denote the IPv4 network it maps.
#[test]
fn ipv4_mapped_cidrs_match_ipv4_addresses() {
    let v4 = MapView::new().with(Field::ClientIp, ip("10.1.2.3"));
    let mapped = MapView::new().with(Field::ClientIp, ip("::ffff:10.1.2.3"));
    for view in [&v4, &mapped] {
        assert!(eval_in("client.ip in ::ffff:10.0.0.0/104", view));
        assert!(eval_in("client.ip in [::ffff:10.1.2.3/128]", view));
        assert!(eval_in("client.ip in ::ffff:0.0.0.0/96", view));
        assert!(!eval_in("client.ip in ::ffff:192.168.0.0/112", view));
        assert!(!eval_in(
            "client.ip not in [fd00::/8, ::ffff:10.0.0.0/104]",
            view
        ));
    }
    // A plain IPv6 network with a long prefix is left alone.
    let v6 = MapView::new().with(Field::ClientIp, ip("2001:db8::1"));
    assert!(eval_in("client.ip in 2001:db8::/112", &v6));
    assert!(!eval_in("client.ip in 2001:db8::/112", &v4));
}

#[test]
fn list_fields_match_any_element() {
    check(&[
        ("header.all[\"accept\"] == \"application/json\"", true),
        ("header.all[\"accept\"] contains \"json\"", true),
        ("header.all[\"accept\"] in [\"text/html\"]", true),
        ("header.all[\"accept\"] like \"*/xml\"", false),
        ("header[\"accept\"] == \"application/json\"", false),
        ("not (header.all[\"accept\"] == \"image/png\")", true),
        ("header.all[\"missing\"] == \"x\"", false),
    ]);
}

#[test]
fn units() {
    check(&[
        ("body.size > 1kb", true),
        ("body.size > 2kb", false),
        ("body.size == 1500", true),
        ("metric.egress > 500mb", true),
        ("metric.egress > 1gb", false),
        ("metric.writes == 30", true),
        ("metric.writes >= 30", true),
        ("30 == 30ms", true),
        ("1s == 1000", true),
        ("1m == 60s", true),
        ("1h == 60m", true),
        ("1kb == 1024", true),
        ("1mb == 1024kb", true),
        ("1gb == 1024mb", true),
    ]);
}

#[test]
fn null_is_a_value_for_equality_and_membership() {
    check(&[
        ("tls.alpn == null", true),
        ("tls.alpn != null", false),
        ("host != null", true),
        ("tls.alpn == \"x\"", false),
        ("tls.alpn != \"x\"", true),
        ("tls.alpn in [\"x\"]", false),
        ("tls.alpn not in [\"x\"]", true),
        ("header[\"x-missing\"] != \"a\"", true),
        ("header[\"x-missing\"] == null", true),
        ("query[\"nope\"] == \"\"", false),
        ("state[\"nope\"] == null", true),
        ("tls.alpn != \"h2\"", true),
        // Guarding with `!= null` short-circuits before the operator that
        // cannot answer for null.
        ("tls.alpn != null and tls.alpn starts_with \"a\"", false),
    ]);
}

/// Every other operator on a missing value fails the flow closed and names
/// the field.
#[test]
fn null_with_other_operators_fails_closed() {
    let ctx = EvalContext::empty();
    for (expr, field) in [
        ("tls.sni starts_with \"\"", "tls.sni"),
        ("tls.sni like \"*\"", "tls.sni"),
        ("tls.sni matches \".*\"", "tls.sni"),
        (
            "header[\"x-missing\"] contains \"a\"",
            "header[\"x-missing\"]",
        ),
        ("client.ip in 10.0.0.0/8", "client.ip"),
        ("body.size > 10mb", "body.size"),
    ] {
        let p = compile(
            "",
            &format!(
                "- {{ id: r, when: '{}', then: deny }}\n- {{ id: ok, then: allow }}",
                expr.replace('\'', "''")
            ),
        );
        let out = p.evaluate_head(&MapView::new(), &ctx);
        assert_eq!(out.terminal_rule, "_fail_closed", "{expr}");
        assert_eq!(
            out.fail_closed_reason,
            Some(FailClosedReason::MissingValue(field.into())),
            "{expr}"
        );
    }
}

#[test]
fn response_fields() {
    let v = flow()
        .with_int(Field::ResponseStatus, 503)
        .with_response_header("Content-Type", "text/html; charset=utf-8")
        .with_response_body("<h1>down</h1>");
    for (expr, want) in [
        ("response.status >= 500", true),
        ("response.status in [500, 502, 503]", true),
        (
            "response.header[\"content-type\"] starts_with \"text/html\"",
            true,
        ),
        (
            "response.header.all[\"content-type\"] contains \"utf-8\"",
            true,
        ),
        ("response.body.text contains \"down\"", true),
        (
            "host under \"github.com\" and header[\"accept\"] == \"text/html\"",
            true,
        ),
    ] {
        assert_eq!(eval_in(expr, &v), want, "{expr}");
    }
}

#[test]
fn state_reads() {
    check(&[
        ("state[\"mode\"] == \"lockdown\"", true),
        ("state[\"mode\"] != \"open\"", true),
    ]);
}

const CHAIN: &str = r#"
- id: tag-github
  when: host under "github.com"
  then: [tag: github, { log: { level: info, message: "github" } }]
- id: header
  when: tag["github"]
  then:
    - set_header: { x-team: platform }
    - remove_header: [x-debug]
- id: writes
  when: tag["github"] and method == POST
  then: { deny: { status: 429, message: "slow down" } }
- id: reads
  when: tag["github"]
  then: allow
- id: never
  then: allow
"#;

#[test]
fn deny_wins_and_a_refusal_keeps_only_log_and_state() {
    let p = compile("", CHAIN);
    let out = p.evaluate_head(&flow(), &EvalContext::empty());
    assert_eq!(
        out.decision,
        Decision::Deny(Deny {
            status: DenyStatus::new(429).unwrap(),
            message: "slow down".into(),
            close: true
        })
    );
    assert_eq!(out.terminal_rule, "writes");
    let matched: Vec<&str> = out.matched.iter().map(roxy_rules::RuleId::as_str).collect();
    // Every head rule is evaluated; the deny wins although allows follow.
    assert_eq!(
        matched,
        ["tag-github", "header", "writes", "reads", "never"]
    );
    // Refused: header changes are dropped, the log remains.
    assert_eq!(
        out.effects,
        vec![Effect::Log {
            level: LogLevel::Info,
            message: "github".into()
        }]
    );
    assert_eq!(out.tags, ["github"]);

    let get = flow().with_str(Field::Method, "GET");
    let out = p.evaluate_head(&get, &EvalContext::empty());
    assert_eq!(out.decision, Decision::Allow(AllowOpts::default()));
    assert_eq!(out.terminal_rule, "reads");
    assert_eq!(
        out.effects,
        vec![
            Effect::Log {
                level: LogLevel::Info,
                message: "github".into()
            },
            Effect::SetHeader {
                name: "x-team".into(),
                value: "platform".into()
            },
            Effect::RemoveHeader("x-debug".into()),
        ]
    );
}

#[test]
fn default_decisions() {
    let p = compile("", CHAIN);
    let other = MapView::new()
        .with_str(Field::Host, "example.com")
        .with_str(Field::Method, "GET");
    // `never` has no `when` and matches everything.
    let out = p.evaluate_head(&other, &EvalContext::empty());
    assert_eq!(out.terminal_rule, "never");

    let p = compile("", "- { id: only, when: 'host == \"x\"', then: allow }");
    let out = p.evaluate_head(&other, &EvalContext::empty());
    assert_eq!(
        out.decision,
        Decision::Deny(Deny {
            status: DenyStatus::new(403).unwrap(),
            message: "blocked by roxy".into(),
            close: true
        })
    );
    assert_eq!(out.terminal_rule, "_default");
    assert!(out.terminal_rule.is_default());
    assert_eq!(out.fail_closed_reason, None);
    assert_eq!(out.matched, Vec::<roxy_rules::RuleId>::new());

    // An empty policy denies everything, closing the connection.
    let empty = compile("", "[]");
    let out = empty.evaluate_head(&other, &EvalContext::empty());
    assert_eq!(out.decision, Decision::default_deny());
    assert_eq!(out.terminal_rule, "_default");
}

/// Deny wins regardless of order; the first matching deny is the terminal
/// rule; only the first matching allow's options apply.
#[test]
fn deny_wins_and_first_allow_options() {
    let p = compile(
        "",
        r#"
- id: plain
  when: host under "example.com"
  then: allow
- id: ws
  when: host under "example.com"
  then: { allow: { upgrade: websocket } }
- id: deny-a
  when: path == "/a"
  then: { deny: { status: 451 } }
- id: deny-a2
  when: path starts_with "/a"
  then: deny
"#,
    );
    let ctx = EvalContext::empty();
    let v = |path: &str| {
        MapView::new()
            .with_str(Field::Host, "www.example.com")
            .with_str(Field::Path, path)
    };
    let out = p.evaluate_head(&v("/a"), &ctx);
    assert!(matches!(out.decision, Decision::Deny(Deny { status, .. }) if status == 451));
    assert_eq!(out.terminal_rule, "deny-a");
    let matched: Vec<&str> = out.matched.iter().map(roxy_rules::RuleId::as_str).collect();
    assert_eq!(matched, ["plain", "ws", "deny-a", "deny-a2"]);
    let out = p.evaluate_head(&v("/b"), &ctx);
    assert_eq!(out.decision, Decision::Allow(AllowOpts::default()));
    assert_eq!(
        out.terminal_rule, "plain",
        "the first allow; options not merged"
    );
}

#[test]
fn deny_close_defaults_and_opt_out() {
    let p = compile(
        "",
        r#"
- id: keep
  when: path == "/keep"
  then: { deny: { status: 451, close: false } }
- id: bare
  when: path == "/bare"
  then: deny
- id: ok
  then: allow
- id: resp
  when: response.status == 500
  then: deny
- id: resp-keep
  when: response.status == 501
  then: { deny: { close: false } }
"#,
    );
    let ctx = EvalContext::empty();
    let close_of = |v: &MapView| match p.evaluate_head(v, &ctx).decision {
        Decision::Deny(Deny { close, .. }) => Some(close),
        Decision::Allow(_) => None,
    };
    let path = |s: &str| MapView::new().with_str(Field::Path, s);
    assert_eq!(close_of(&path("/keep")), Some(false));
    assert_eq!(close_of(&path("/bare")), Some(true));
    assert_eq!(close_of(&path("/other")), None);
    let watch_close = |status| match watch(
        &p,
        &MapView::new().with_int(Field::ResponseStatus, status),
        &ctx,
    )
    .and_then(|o| o.stop)
    {
        Some(Deny { close, .. }) => Some(close),
        _ => None,
    };
    assert_eq!(watch_close(500), Some(true));
    assert_eq!(watch_close(501), Some(false));
    assert_eq!(watch_close(200), None);
}

fn fail_closed(reason: FailClosedReason) -> impl Fn(&roxy_rules::Outcome) {
    move |out| {
        assert_eq!(
            out.decision,
            Decision::Deny(Deny {
                status: DenyStatus::new(503).unwrap(),
                message: "blocked by roxy".into(),
                close: true
            })
        );
        assert_eq!(out.terminal_rule, "_fail_closed");
        assert_eq!(out.fail_closed_reason.as_ref(), Some(&reason));
    }
}

#[test]
fn bodies_fail_closed() {
    let ctx = EvalContext::empty();
    let p = compile(
        "",
        "- { id: b, when: 'body.text contains \"secret\"', then: deny }\n- { id: ok, then: allow }",
    );
    let body = |s: &str| MapView::new().with_int(Field::BodySize, 10).with_body(s);
    assert_eq!(p.evaluate_head(&body("a secret"), &ctx).terminal_rule, "b");
    assert_eq!(p.evaluate_head(&body(""), &ctx).terminal_rule, "ok");
    let too_large = body("x").with_body_too_large(false);
    fail_closed(FailClosedReason::BodyTooLargeToInspect("body.text".into()))(
        &p.evaluate_head(&too_large, &ctx),
    );
    fail_closed(FailClosedReason::BodyUnavailable("body.text".into()))(
        &p.evaluate_head(&MapView::new(), &ctx),
    );

    // Scoping by size first means a large upload is never inspected.
    let p = compile(
        "",
        "- { id: b, when: 'body.size < 1mb and body.text contains \"secret\"', then: deny }\n\
         - { id: ok, then: allow }",
    );
    let big = MapView::new()
        .with_int(Field::BodySize, 5 << 20)
        .with_body_too_large(false);
    assert_eq!(p.evaluate_head(&big, &ctx).terminal_rule, "ok");

    // Response bodies too.
    let p = compile(
        "",
        "- { id: r, when: 'response.body.text contains \"x\"', then: deny }",
    );
    let v = MapView::new().with_body_too_large(true);
    let out = watch(&p, &v, &ctx).expect("stops");
    assert_eq!(out.stop, Some(Deny::fail_closed()));
    assert_eq!(out.terminal_rule.unwrap(), "_fail_closed");
    assert_eq!(
        out.fail_closed_reason,
        Some(FailClosedReason::BodyTooLargeToInspect(
            "response.body.text".into()
        ))
    );
}

#[test]
fn unavailable_inputs_fail_closed() {
    let p = compile(
        METRICS,
        r#"
- id: first
  then: { tag: seen }
- id: burst
  when: host == "api.github.com" and metric.writes >= 30
  then: deny
- id: internal
  when: client.ip in @internal
  then: allow
- id: rest
  then: allow
"#,
    );
    let ctx = EvalContext::empty();
    let base = || {
        MapView::new()
            .with_str(Field::Host, "api.github.com")
            .with(Field::ClientIp, ip("192.0.2.1"))
    };

    // The metric is reached but unavailable: fail closed, not "false".
    let out = p.evaluate_head(&base(), &ctx);
    fail_closed(FailClosedReason::MetricUnavailable("writes".into()))(&out);
    assert_eq!(out.matched, ["first"].map(roxy_rules::RuleId::new));
    assert_eq!(out.tags, ["seen"]);

    // Short-circuit: a different host never needs the metric.
    let other = base().with_str(Field::Host, "example.com");
    let out = p.evaluate_head(&other, &ctx);
    fail_closed(FailClosedReason::AddressListUnavailable("internal".into()))(&out);

    // With the metric (0 for a fresh series) and the list available, fine.
    let ok = base()
        .with_metric("writes", 0)
        .with_address_list("internal", vec!["10.0.0.0/8".parse().unwrap()]);
    let out = p.evaluate_head(&ok, &ctx);
    assert_eq!(out.terminal_rule, "rest");
    assert_eq!(out.fail_closed_reason, None);

    // Negation does not turn "could not check" into true either.
    let p = compile(
        METRICS,
        "- { id: n, when: 'not (metric.writes > 5)', then: allow }",
    );
    let out = p.evaluate_head(&MapView::new(), &ctx);
    fail_closed(FailClosedReason::MetricUnavailable("writes".into()))(&out);
    let p = compile(
        "",
        "- { id: n, when: 'client.ip not in @blocked', then: allow }",
    );
    let out = p.evaluate_head(&base(), &ctx);
    fail_closed(FailClosedReason::AddressListUnavailable("blocked".into()))(&out);

    // Metric filters report the same condition to the proxy.
    let p = compile(
        "- { id: w, count: requests }\n- { id: f, count: requests, where: 'metric.w > 1' }",
        "[]",
    );
    assert_eq!(
        p.metric_defs()[1].matches(&MapView::new()),
        Err(FailClosedReason::MetricUnavailable("w".into()))
    );

    // An unset state key is legitimately absent, not a failure.
    let p = compile(
        "",
        "- { id: s, when: 'state[\"k\"] == \"v\"', then: allow }",
    );
    let out = p.evaluate_head(&MapView::new(), &ctx);
    assert_eq!(out.terminal_rule, "_default");
    assert_eq!(out.fail_closed_reason, None);
}

/// Every head rule is evaluated, so an unavailable input anywhere in the
/// list fails the flow closed even when a deny above it already matched:
/// the flow log must say `_fail_closed`, not name a deny that masked an
/// outage.
#[test]
fn fail_closed_wins_over_an_earlier_deny() {
    let p = compile(
        METRICS,
        r#"
- id: block
  when: path starts_with "/admin"
  then: { deny: { status: 451 }, }
- id: burst
  when: metric.writes >= 30
  then: deny
"#,
    );
    let v = MapView::new().with_str(Field::Path, "/admin/x");
    let out = p.evaluate_head(&v, &EvalContext::empty());
    assert_eq!(out.decision, Decision::fail_closed());
    assert_eq!(out.terminal_rule, "_fail_closed");
    assert_eq!(
        out.fail_closed_reason,
        Some(FailClosedReason::MetricUnavailable("writes".into()))
    );
    assert_eq!(out.matched, ["block"].map(roxy_rules::RuleId::new));
    // With the metric available the deny stands.
    let out = p.evaluate_head(&v.with_metric("writes", 0), &EvalContext::empty());
    assert_eq!(out.terminal_rule, "block");
}

#[test]
fn head_and_watching_rules_share_one_list() {
    let p = compile(
        METRICS,
        r"
- id: r
  when: response.status == 418
  then: { deny: { status: 502 } }
- id: req
  then: allow
- id: budget
  when: metric.egress > 1mb
  then: deny
- id: count
  when: metric.writes > 1000
  then: deny
",
    );
    let kinds: Vec<RuleKind> = p.rule_info().iter().map(|r| r.kind).collect();
    assert_eq!(
        kinds,
        [
            RuleKind::Watching,
            RuleKind::Head,
            RuleKind::HeadAndWatching,
            RuleKind::Head
        ]
    );
    let info = p.rule_info();
    assert_eq!(info[0].watches, ["response.status"]);
    assert_eq!(info[2].watches, ["metric.egress (request_bytes)"]);
    assert_eq!(info[2].triggers, Reads::METRIC_REQUEST_BYTES);
    assert!(
        info[3].watches.is_empty(),
        "a requests metric does not watch"
    );

    // At the head the response rule is skipped, not false.
    let v = MapView::new()
        .with_metric("egress", 0)
        .with_metric("writes", 0);
    let out = p.evaluate_head(&v, &EvalContext::empty());
    assert_eq!(out.terminal_rule, "req");
    // After forwarding, the response rule stops the exchange.
    let res = v.with_int(Field::ResponseStatus, 418);
    let out = watch(&p, &res, &EvalContext::empty()).unwrap();
    assert_eq!(out.terminal_rule.unwrap(), "r");
    assert!(matches!(out.stop, Some(Deny { status, .. }) if status == 502));
    assert_eq!(p.rule_ids().count(), 4);
    assert_eq!(p.rule_count(), 4);
}

#[test]
fn tags_chain_and_initial_tags() {
    let p = compile(
        "",
        r#"
- id: a
  when: not tag["seen"]
  then: { tag: seen }
- id: b
  when: tag["seen"] and tag["from-addon"]
  then: { tag: both }
- id: c
  when: tag["both"]
  then: allow
"#,
    );
    let v = MapView::new();
    let out = p.evaluate_head(&v, &EvalContext::empty());
    assert!(out.decision.is_deny(), "no from-addon tag");
    assert_eq!(out.tags, ["seen"]);

    let initial = vec!["from-addon".to_owned()];
    let ctx = EvalContext {
        initial_tags: &initial,
        ..EvalContext::empty()
    };
    let out = p.evaluate_head(&v, &ctx);
    assert_eq!(out.terminal_rule, "c");
    assert_eq!(out.tags, ["from-addon", "seen", "both"]);

    // A tag already present is not duplicated, and `not tag[...]` sees it.
    let initial = vec!["seen".to_owned()];
    let ctx = EvalContext {
        initial_tags: &initial,
        ..EvalContext::empty()
    };
    let out = p.evaluate_head(&v, &ctx);
    assert_eq!(out.matched, Vec::<roxy_rules::RuleId>::new());
    assert_eq!(out.tags, ["seen"]);
}

/// A rule may read a tag set by head rules above it, or (a watching rule)
/// by any head rule, or its own; nothing about these depends on order.
#[test]
fn tags_read_after_every_setter_compile() {
    compile(
        "",
        r#"
- id: mark
  when: path starts_with "/admin"
  then: { tag: admin }
- id: block
  when: tag["admin"]
  then: deny
- id: once
  when: not tag["seen"]
  then: { tag: seen }
- id: big-admin-upload
  when: tag["late"] and body.bytes > 10
  then: deny
- id: late
  when: host == "x"
  then: { tag: late }
"#,
    );
}

#[test]
fn set_state_is_visible_later_in_the_chain() {
    let p = compile(
        "",
        r#"
- id: s
  then: { set_state: { key: mode, value: open, ttl: 10s } }
- id: t
  when: state["mode"] == "open"
  then: allow
"#,
    );
    // The view says lockdown; the earlier set_state wins within the chain.
    let out = p.evaluate_head(&flow(), &EvalContext::empty());
    assert_eq!(out.terminal_rule, "t");
    assert_eq!(
        out.effects,
        [Effect::SetState {
            key: "mode".into(),
            value: "open".into(),
            ttl: Some(Duration::from_secs(10))
        }]
    );
}

const SECRETS: &str = r#"
- id: openai
  when: host == "api.openai.com"
  then:
    - set_header: { authorization: "Bearer ${secret:openai}", x-both: "${secret:openai}/${secret:gh}" }
    - allow
"#;

fn openai() -> MapView {
    MapView::new().with_str(Field::Host, "api.openai.com")
}

#[test]
fn secrets_are_substituted() {
    let p = compile("", SECRETS);
    let lookup = |name: &str| match name {
        "openai" => Some("sk-123".to_owned()),
        "gh" => Some("ghp_x".to_owned()),
        _ => None,
    };
    let ctx = EvalContext {
        secrets: &lookup,
        initial_tags: &[],
    };
    let out = p.evaluate_head(&openai(), &ctx);
    assert!(out.decision.is_allow());
    assert_eq!(
        out.effects,
        [
            Effect::SetHeader {
                name: "authorization".into(),
                value: "Bearer sk-123".into()
            },
            Effect::SetHeader {
                name: "x-both".into(),
                value: "sk-123/ghp_x".into()
            },
        ]
    );
}

#[test]
fn missing_secret_fails_closed() {
    let p = compile("", SECRETS);
    let only_openai = |name: &str| (name == "openai").then(|| "sk-123".to_owned());
    let ctx = EvalContext {
        secrets: &only_openai,
        initial_tags: &[],
    };
    let out = p.evaluate_head(&openai(), &ctx);
    fail_closed(FailClosedReason::SecretMissing("gh".into()))(&out);
    assert_eq!(out.matched, ["openai"].map(roxy_rules::RuleId::new));
    // Failing closed refuses the request: no header effects survive.
    assert_eq!(out.effects, []);
    assert!(!format!("{out:?}").contains("ghp_"), "no secret values");

    // A secret that is not a valid header value also fails closed.
    let crlf = |_: &str| Some("a\r\nx-injected: 1".to_owned());
    let ctx = EvalContext {
        secrets: &crlf,
        initial_tags: &[],
    };
    let out = p.evaluate_head(&openai(), &ctx);
    fail_closed(FailClosedReason::SecretInvalid("openai".into()))(&out);
    assert!(
        out.effects
            .iter()
            .all(|e| !matches!(e, Effect::SetHeader { .. }))
    );
}

#[test]
fn every_effect_kind() {
    let p = compile(
        "",
        r#"
- id: all
  then:
    - set_header: { X-A: "1" }
    - remove_header: [X-B]
    - rewrite_path: { match: "/old/(.*)", to: "/new/$1" }
    - set_query: { k: v }
    - remove_query: [q]
    - redirect: { host: Mirror.Example.org, port: 8443, scheme: https, rewrite_host: true }
    - log: { level: warn, message: m }
    - set_state: { key: k, value: v }
    - capture: both
    - allow: { upgrade: websocket, private_ok: true }
"#,
    );
    let out = p.evaluate_head(&MapView::new(), &EvalContext::empty());
    assert_eq!(
        out.decision,
        Decision::Allow(AllowOpts {
            upgrade_websocket: true,
            private_ok: true
        })
    );
    let kinds: Vec<&str> = out.effects.iter().map(Effect::kind).collect();
    assert_eq!(
        kinds,
        [
            "set_header",
            "remove_header",
            "rewrite_path",
            "set_query",
            "remove_query",
            "redirect",
            "log",
            "set_state",
            "capture"
        ]
    );
    assert_eq!(
        out.effects[0],
        Effect::SetHeader {
            name: "x-a".into(),
            value: "1".into()
        }
    );
    let Effect::RewritePath { regex, to } = &out.effects[2] else {
        panic!()
    };
    assert_eq!(regex.replace("/old/x/y", to.as_str()), "/new/x/y");
    assert!(!regex.is_match("/prefix/old/x"), "anchored");
    assert_eq!(
        out.effects[5],
        Effect::Redirect {
            host: roxy_http::Host::Dns("mirror.example.org".into()),
            port: std::num::NonZeroU16::new(8443).unwrap(),
            scheme: Some(Scheme::Https),
            rewrite_host: true
        }
    );
    assert_eq!(out.effects[8], Effect::Capture(CaptureTarget::Both));
    let rendered: Vec<String> = out.effects.iter().map(ToString::to_string).collect();
    assert_eq!(rendered[2], "rewrite_path \"/old/(.*)\" -> \"/new/$1\"");
    assert_eq!(
        rendered[5],
        "redirect https://mirror.example.org:8443 (rewrite host)"
    );
}

#[test]
fn body_buffering_flags() {
    let p = compile("", "- { id: a, when: 'body.size > 1', then: allow }");
    assert!(!p.needs_request_body() && !p.needs_response_body());
    let p = compile(
        "",
        "- { id: a, when: 'body.text contains \"x\"', then: allow }",
    );
    assert!(p.needs_request_body() && !p.needs_response_body());
    let p = compile(
        "",
        "- { id: a, when: 'response.body.text contains \"x\"', then: deny }",
    );
    assert!(!p.needs_request_body() && p.needs_response_body());
}

#[test]
fn metric_defs_compile() {
    let p = compile(
        "- { id: w, count: requests, where: 'method == POST', key: [client.ip, host], window: 1m }\n\
         - { id: u, count: unique(host) }\n\
         - { id: e, count: errors, where: 'host == \"x\"' }",
        "[]",
    );
    let defs = p.metric_defs();
    assert_eq!(defs.len(), 3);
    assert_eq!(defs[0].key, [Field::ClientIp, Field::Host]);
    assert_eq!(defs[0].window, Some(Duration::from_secs(60)));
    assert_eq!(defs[1].unique, Some(Field::Host));
    assert_eq!(defs[2].count, roxy_rules::MetricCount::Errors);
    assert_eq!(defs[0].matches(&flow()), Ok(true));
    assert_eq!(
        defs[0].matches(&flow().with_str(Field::Method, "GET")),
        Ok(false)
    );
    assert_eq!(
        defs[1].matches(&MapView::new()),
        Ok(true),
        "no filter = always"
    );
}

#[test]
fn address_lists() {
    let nets =
        |xs: &[&str]| -> Vec<ipnet::IpNet> { xs.iter().map(|s| s.parse().unwrap()).collect() };
    let with_lists = |v: MapView| {
        v.with_address_list("internal", nets(&["10.0.0.0/8", "fd00::/8"]))
            .with_address_list("blocked", nets(&["203.0.113.7/32"]))
    };
    let client = |s: &str| with_lists(MapView::new().with(Field::ClientIp, ip(s)));
    assert!(eval_in("client.ip in @internal", &client("10.1.2.3")));
    assert!(eval_in("client.ip in @internal", &client("fd00::1")));
    assert!(eval_in(
        "client.ip in @internal",
        &client("::ffff:10.0.0.1")
    ));
    assert!(!eval_in("client.ip in @internal", &client("192.0.2.1")));
    assert!(eval_in("client.ip not in @internal", &client("192.0.2.1")));
    assert!(!eval_in("client.ip not in @internal", &client("10.0.0.1")));

    // A list the view cannot answer for fails closed (see
    // `unavailable_inputs_fail_closed`); an absent ip is just absent.
    let no_ip = with_lists(MapView::new());
    assert!(!eval_in("client.ip not in @internal", &no_ip));
}

#[test]
fn hostile_regex_is_rejected_at_compile_time() {
    let err = try_compile(
        "",
        "- { id: a, when: 'path matches \"(\\\\w{100}){100}\"', then: allow }",
    )
    .unwrap_err();
    assert!(err[0].contains("too large"), "{err:?}");
}

/// `x != null and x > N` works as expected: a missing size skips the rule,
/// a present one is compared. Unguarded, a missing size fails closed.
#[test]
fn guarded_size_rule() {
    let ctx = EvalContext::empty();
    let p = compile(
        "",
        "- { id: big, when: 'body.size != null and body.size > 10mb', then: deny }\n\
         - { id: ok, then: allow }",
    );
    let sized = |n: i64| MapView::new().with_int(Field::BodySize, n);
    assert_eq!(p.evaluate_head(&sized(20 << 20), &ctx).terminal_rule, "big");
    assert_eq!(p.evaluate_head(&sized(10), &ctx).terminal_rule, "ok");
    assert_eq!(p.evaluate_head(&MapView::new(), &ctx).terminal_rule, "ok");

    let unguarded = compile(
        "",
        "- { id: big, when: 'body.size > 10mb', then: deny }\n- { id: ok, then: allow }",
    );
    let out = unguarded.evaluate_head(&MapView::new(), &ctx);
    assert_eq!(out.terminal_rule, "_fail_closed");
}

#[test]
fn null_literal_misuse_is_a_compile_error() {
    for bad in [
        "body.size > null",
        "tls.sni contains null",
        "tls.sni in [null]",
        "null == null",
        "\"a\" == null",
        "null",
    ] {
        assert!(
            try_compile("", &format!("- {{ id: r, when: '{bad}', then: deny }}")).is_err(),
            "should reject: {bad}"
        );
    }
}

/// A `redirect` host is held to the request-target host grammar when the
/// policy compiles, so the proxy never meets one it can't parse.
#[test]
fn redirect_host_is_checked_at_compile_time() {
    for bad in ["127.1", "0x7f000001", "::1", "[::1", "a b", ""] {
        assert!(
            try_compile(
                "",
                &format!("- {{ id: r, then: {{ redirect: {{ host: '{bad}', port: 80 }} }} }}")
            )
            .is_err(),
            "should reject: {bad:?}"
        );
    }
    for good in ["10.0.0.1", "[::1]", "Mirror.Example.org."] {
        assert!(
            try_compile(
                "",
                &format!("- {{ id: r, then: {{ redirect: {{ host: '{good}', port: 80 }} }} }}")
            )
            .is_ok(),
            "should accept: {good:?}"
        );
    }
    assert!(
        try_compile("", "- { id: r, then: { redirect: { host: a, port: 0 } } }").is_err(),
        "port 0"
    );
}
