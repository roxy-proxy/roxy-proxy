//! Evaluation tests against a map-backed `FlowView`.

mod common;

use std::net::IpAddr;
use std::time::Duration;

use common::{METRICS, compile, try_compile};
use roxy_rules::{
    AllowOpts, CaptureTarget, Decision, Effect, EvalContext, FailClosedReason, Field, LogLevel,
    MapView, Phase, Scheme, Value,
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

/// Does `expr` match `view` in `phase`?
fn eval_in(phase: Phase, expr: &str, view: &MapView) -> bool {
    let rules = format!(
        "- id: r\n  phase: {phase}\n  when: '{}'\n  then: deny\n",
        expr.replace('\'', "''")
    );
    let p = compile(METRICS, &rules);
    let out = p.evaluate(phase, view, &EvalContext::empty());
    out.decision.is_deny() && out.terminal_rule == "r"
}

fn eval(expr: &str) -> bool {
    eval_in(Phase::Request, expr, &flow())
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
    assert!(eval_in(Phase::Request, "path like \"/a[1]{x}\\\\\"", &v));
    assert!(!eval_in(Phase::Request, "path like \"/a[12]{x}\\\\\"", &v));
    // Alternation cannot escape the implicit anchors.
    assert!(!eval_in(
        Phase::Request,
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
        assert_eq!(
            eval_in(Phase::Request, "host under \"github.com\"", &host(h)),
            want,
            "{h}"
        );
    }
    assert!(eval_in(
        Phase::Request,
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
        ("method in [\"post\"]", true),
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
    assert!(eval_in(Phase::Request, "client.ip in [fd00::/8]", &v6));
    let mapped = MapView::new().with(Field::ClientIp, ip("::ffff:10.9.9.9"));
    assert!(eval_in(Phase::Request, "client.ip in 10.0.0.0/8", &mapped));
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
fn absent_values_are_never_equal_or_unequal() {
    check(&[
        ("client.user == \"x\"", false),
        ("client.user != \"x\"", false),
        ("not client.user == \"x\"", true),
        ("not (client.user != \"x\")", true),
        ("client.user in [\"x\"]", false),
        ("client.user not in [\"x\"]", false),
        ("client.user starts_with \"\"", false),
        ("client.user like \"*\"", false),
        ("client.user matches \".*\"", false),
        ("header[\"x-missing\"] != \"a\"", false),
        ("query[\"nope\"] == \"\"", false),
        ("state[\"nope\"] == \"\"", false),
        ("tls.alpn != \"h2\"", false),
    ]);
    // Missing metrics, address lists and bodies are not absent: they fail
    // closed (see `unavailable_inputs_fail_closed`, `bodies_fail_closed`).
}

#[test]
fn response_phase_fields() {
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
        assert_eq!(eval_in(Phase::Response, expr, &v), want, "{expr}");
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
fn first_terminal_wins_with_effects_in_order() {
    let p = compile("", CHAIN);
    let out = p.evaluate(Phase::Request, &flow(), &EvalContext::empty());
    assert_eq!(
        out.decision,
        Decision::Deny {
            status: 429,
            message: "slow down".into(),
            close: true
        }
    );
    assert_eq!(out.terminal_rule, "writes");
    let matched: Vec<&str> = out.matched.iter().map(roxy_rules::RuleId::as_str).collect();
    assert_eq!(matched, ["tag-github", "header", "writes"]);
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
    assert_eq!(out.tags, ["github"]);

    let get = flow().with_str(Field::Method, "GET");
    let out = p.evaluate(Phase::Request, &get, &EvalContext::empty());
    assert_eq!(out.decision, Decision::Allow(AllowOpts::default()));
    assert_eq!(out.terminal_rule, "reads");
}

#[test]
fn default_decisions() {
    let p = compile("", CHAIN);
    let other = MapView::new()
        .with_str(Field::Host, "example.com")
        .with_str(Field::Method, "GET");
    // `never` has no `when` and matches everything.
    let out = p.evaluate(Phase::Request, &other, &EvalContext::empty());
    assert_eq!(out.terminal_rule, "never");

    let p = compile("", "- { id: only, when: 'host == \"x\"', then: allow }");
    let out = p.evaluate(Phase::Request, &other, &EvalContext::empty());
    assert_eq!(
        out.decision,
        Decision::Deny {
            status: 403,
            message: "blocked by roxy".into(),
            close: true
        }
    );
    assert_eq!(out.terminal_rule, "_default");
    assert!(out.terminal_rule.is_default());
    assert_eq!(out.fail_closed_reason, None);
    assert_eq!(out.matched, Vec::<roxy_rules::RuleId>::new());

    // An empty policy denies requests (closing) and ws messages (dropping,
    // not closing), and allows connect/response.
    let empty = compile("", "[]");
    let deny = |close| Decision::Deny {
        status: 403,
        message: "blocked by roxy".into(),
        close,
    };
    for (phase, want) in [
        (Phase::Request, deny(true)),
        (Phase::Ws, deny(false)),
        (Phase::Connect, Decision::Allow(AllowOpts::default())),
        (Phase::Response, Decision::Allow(AllowOpts::default())),
    ] {
        let out = empty.evaluate(phase, &other, &EvalContext::empty());
        assert_eq!(out.decision, want, "{phase}");
        assert_eq!(out.terminal_rule, "_default");
    }
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
- id: req-inspect
  then: { allow: { upgrade: websocket, inspect: true } }
- id: ws-drop
  phase: ws
  when: ws.size > 10
  then: deny
- id: ws-close
  phase: ws
  when: ws.size > 5
  then: { deny: { close: true } }
- id: ws-ok
  phase: ws
  then: allow
- id: resp
  phase: response
  when: response.status == 500
  then: deny
"#,
    );
    let ctx = EvalContext::empty();
    let close_of = |phase, v: &MapView| match p.evaluate(phase, v, &ctx).decision {
        Decision::Deny { close, .. } => Some(close),
        _ => None,
    };
    let path = |s: &str| MapView::new().with_str(Field::Path, s);
    assert_eq!(close_of(Phase::Request, &path("/keep")), Some(false));
    assert_eq!(close_of(Phase::Request, &path("/bare")), Some(true));
    let ws = |n| MapView::new().with_int(Field::WsSize, n);
    assert_eq!(
        close_of(Phase::Ws, &ws(11)),
        Some(false),
        "drop the message"
    );
    assert_eq!(close_of(Phase::Ws, &ws(6)), Some(true), "close the socket");
    assert_eq!(close_of(Phase::Ws, &ws(1)), None);
    let resp = MapView::new().with_int(Field::ResponseStatus, 500);
    assert_eq!(close_of(Phase::Response, &resp), Some(true));
}

fn fail_closed(reason: FailClosedReason) -> impl Fn(&roxy_rules::Outcome) {
    move |out| {
        assert_eq!(
            out.decision,
            Decision::Deny {
                status: 503,
                message: "policy input unavailable".into(),
                close: true
            }
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
    assert_eq!(
        p.evaluate(Phase::Request, &body("a secret"), &ctx)
            .terminal_rule,
        "b"
    );
    assert_eq!(
        p.evaluate(Phase::Request, &body(""), &ctx).terminal_rule,
        "ok"
    );
    let too_large = body("x").with_body_too_large(false);
    fail_closed(FailClosedReason::BodyTooLargeToInspect("body.text".into()))(&p.evaluate(
        Phase::Request,
        &too_large,
        &ctx,
    ));
    fail_closed(FailClosedReason::BodyUnavailable("body.text".into()))(&p.evaluate(
        Phase::Request,
        &MapView::new(),
        &ctx,
    ));

    // Scoping by size first means a large upload is never inspected.
    let p = compile(
        "",
        "- { id: b, when: 'body.size < 1mb and body.text contains \"secret\"', then: deny }\n\
         - { id: ok, then: allow }",
    );
    let big = MapView::new()
        .with_int(Field::BodySize, 5 << 20)
        .with_body_too_large(false);
    assert_eq!(p.evaluate(Phase::Request, &big, &ctx).terminal_rule, "ok");

    // Response bodies too.
    let p = compile(
        "",
        "- { id: r, phase: response, when: 'response.body.text contains \"x\"', then: deny }",
    );
    let v = MapView::new().with_body_too_large(true);
    fail_closed(FailClosedReason::BodyTooLargeToInspect(
        "response.body.text".into(),
    ))(&p.evaluate(Phase::Response, &v, &ctx));
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
    let out = p.evaluate(Phase::Request, &base(), &ctx);
    fail_closed(FailClosedReason::MetricUnavailable("writes".into()))(&out);
    assert_eq!(out.matched, ["first"].map(roxy_rules::RuleId::new));
    assert_eq!(out.tags, ["seen"]);

    // Short-circuit: a different host never needs the metric.
    let other = base().with_str(Field::Host, "example.com");
    let out = p.evaluate(Phase::Request, &other, &ctx);
    fail_closed(FailClosedReason::AddressListUnavailable("internal".into()))(&out);

    // With the metric (0 for a fresh series) and the list available, fine.
    let ok = base()
        .with_metric("writes", 0)
        .with_address_list("internal", vec!["10.0.0.0/8".parse().unwrap()]);
    let out = p.evaluate(Phase::Request, &ok, &ctx);
    assert_eq!(out.terminal_rule, "rest");
    assert_eq!(out.fail_closed_reason, None);

    // Negation does not turn "could not check" into true either.
    let p = compile(
        METRICS,
        "- { id: n, when: 'not (metric.writes > 5)', then: allow }",
    );
    let out = p.evaluate(Phase::Request, &MapView::new(), &ctx);
    fail_closed(FailClosedReason::MetricUnavailable("writes".into()))(&out);
    let p = compile(
        "",
        "- { id: n, when: 'client.ip not in @blocked', then: allow }",
    );
    let out = p.evaluate(Phase::Request, &base(), &ctx);
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
    let out = p.evaluate(Phase::Request, &MapView::new(), &ctx);
    assert_eq!(out.terminal_rule, "_default");
    assert_eq!(out.fail_closed_reason, None);
}

#[test]
fn phases_have_separate_chains() {
    let p = compile(
        "",
        r"
- id: c
  phase: connect
  when: dst.port != 443
  then: deny
- id: r
  phase: response
  when: response.status == 418
  then: { deny: { status: 502 } }
- id: req
  then: allow
",
    );
    let conn = MapView::new().with_int(Field::DstPort, 22);
    assert_eq!(
        p.evaluate(Phase::Connect, &conn, &EvalContext::empty())
            .terminal_rule,
        "c"
    );
    assert_eq!(
        p.evaluate(Phase::Request, &conn, &EvalContext::empty())
            .terminal_rule,
        "req"
    );
    let res = MapView::new().with_int(Field::ResponseStatus, 418);
    let out = p.evaluate(Phase::Response, &res, &EvalContext::empty());
    assert_eq!(out.terminal_rule, "r");
    assert!(matches!(out.decision, Decision::Deny { status: 502, .. }));
    assert_eq!(p.rule_count(Phase::Connect), 1);
    assert_eq!(p.rule_ids().count(), 3);
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
    let out = p.evaluate(Phase::Request, &v, &EvalContext::empty());
    assert!(out.decision.is_deny(), "no from-addon tag");
    assert_eq!(out.tags, ["seen"]);

    let initial = vec!["from-addon".to_owned()];
    let ctx = EvalContext {
        initial_tags: &initial,
        ..EvalContext::empty()
    };
    let out = p.evaluate(Phase::Request, &v, &ctx);
    assert_eq!(out.terminal_rule, "c");
    assert_eq!(out.tags, ["from-addon", "seen", "both"]);

    // A tag already present is not duplicated, and `not tag[...]` sees it.
    let initial = vec!["seen".to_owned()];
    let ctx = EvalContext {
        initial_tags: &initial,
        ..EvalContext::empty()
    };
    let out = p.evaluate(Phase::Request, &v, &ctx);
    assert_eq!(out.matched, Vec::<roxy_rules::RuleId>::new());
    assert_eq!(out.tags, ["seen"]);
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
    let out = p.evaluate(Phase::Request, &flow(), &EvalContext::empty());
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
    let out = p.evaluate(Phase::Request, &openai(), &ctx);
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
    let out = p.evaluate(Phase::Request, &openai(), &ctx);
    fail_closed(FailClosedReason::SecretMissing("gh".into()))(&out);
    assert_eq!(out.matched, ["openai"].map(roxy_rules::RuleId::new));
    // The first header (resolved) was emitted; the failing one was not.
    assert_eq!(out.effects.len(), 1);
    assert!(!format!("{out:?}").contains("ghp_"), "no secret values");

    // A secret that is not a valid header value also fails closed.
    let crlf = |_: &str| Some("a\r\nx-injected: 1".to_owned());
    let ctx = EvalContext {
        secrets: &crlf,
        initial_tags: &[],
    };
    let out = p.evaluate(Phase::Request, &openai(), &ctx);
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
    - call: pii-scan
    - allow: { upgrade: websocket, private_ok: true }
"#,
    );
    let out = p.evaluate(Phase::Request, &MapView::new(), &EvalContext::empty());
    assert_eq!(
        out.decision,
        Decision::Allow(AllowOpts {
            upgrade_websocket: true,
            inspect_ws: false,
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
            "capture",
            "call"
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
            host: "mirror.example.org".into(),
            port: 8443,
            scheme: Some(Scheme::Https),
            rewrite_host: true
        }
    );
    assert_eq!(out.effects[8], Effect::Capture(CaptureTarget::Both));
    assert_eq!(out.effects[9], Effect::CallAddon("pii-scan".into()));
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
        "- { id: a, phase: response, when: 'response.body.text contains \"x\"', then: allow }",
    );
    assert!(!p.needs_request_body() && p.needs_response_body());
}

#[test]
fn metric_defs_compile() {
    let p = compile(
        "- { id: w, count: requests, where: 'method == POST', key: [client.ip, host], window: 1m }\n\
         - { id: u, count: unique(host) }\n\
         - { id: e, count: errors, where: 'response.status >= 500' }",
        "[]",
    );
    let defs = p.metric_defs();
    assert_eq!(defs.len(), 3);
    assert_eq!(defs[0].key, [Field::ClientIp, Field::Host]);
    assert_eq!(defs[0].window, Some(Duration::from_secs(60)));
    assert_eq!(defs[1].unique, Some(Field::Host));
    assert_eq!(defs[2].phase, Phase::Response);
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
    assert!(eval_in(
        Phase::Request,
        "client.ip in @internal",
        &client("10.1.2.3")
    ));
    assert!(eval_in(
        Phase::Request,
        "client.ip in @internal",
        &client("fd00::1")
    ));
    assert!(eval_in(
        Phase::Request,
        "client.ip in @internal",
        &client("::ffff:10.0.0.1")
    ));
    assert!(!eval_in(
        Phase::Request,
        "client.ip in @internal",
        &client("192.0.2.1")
    ));
    assert!(eval_in(
        Phase::Request,
        "client.ip not in @internal",
        &client("192.0.2.1")
    ));
    assert!(!eval_in(
        Phase::Request,
        "client.ip not in @internal",
        &client("10.0.0.1")
    ));

    let dst = |s: &str| with_lists(MapView::new().with(Field::DstIp, ip(s)));
    assert!(eval_in(
        Phase::Connect,
        "dst.ip in @blocked",
        &dst("203.0.113.7")
    ));
    assert!(eval_in(
        Phase::Connect,
        "dst.ip not in @blocked",
        &dst("203.0.113.8")
    ));

    // A list the view cannot answer for fails closed (see
    // `unavailable_inputs_fail_closed`); an absent ip is just absent.
    let no_ip = with_lists(MapView::new());
    assert!(!eval_in(
        Phase::Request,
        "client.ip not in @internal",
        &no_ip
    ));
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
