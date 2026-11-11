//! The `respond` action: its shape and compile-time limits, where it may
//! appear, and its place in the admission decision.

mod common;

use std::collections::HashSet;

use common::{compile, render, try_compile};
use roxy_rules::{
    CaptureTarget, DEFAULT_MAX_RESPOND_BODY_BYTES, Decision, Effect, EvalContext, FailClosedReason,
    Field, LogLevel, MapView, Policy, PolicyInput, Respond, RuleConfig, RuleId, TerminalConflict,
};

fn host(h: &str) -> MapView {
    MapView::new()
        .with_str(Field::Host, h)
        .with_str(Field::Method, "POST")
        .with_str(Field::Path, "/oauth/token")
}

fn answer(out: &roxy_rules::Outcome) -> &Respond {
    match &out.decision {
        Decision::Respond(r) => r,
        other @ (Decision::Allow(_) | Decision::Deny(_)) => {
            panic!("expected an answer, got {other}: {out:?}")
        }
    }
}

/// Compiles under a given `limits.max_respond_body_bytes`.
fn compile_with_limit(rules_yaml: &str, max: u64) -> Result<Policy, Vec<String>> {
    let rules: Vec<RuleConfig> = roxy_rules::yaml::from_str(rules_yaml).unwrap();
    let none = HashSet::new();
    Policy::compile(&PolicyInput {
        rules: &rules,
        metrics: &[],
        secret_names: &common::secret_names(),
        address_lists: &none,
        max_respond_body_bytes: max,
    })
    .map_err(|ds| ds.iter().map(render).collect())
}

#[track_caller]
fn compile_err(rules_yaml: &str) -> String {
    match try_compile(common::METRICS, rules_yaml) {
        Ok(_) => panic!("expected a compile error for\n{rules_yaml}"),
        Err(e) => e.join("\n"),
    }
}

#[test]
fn defaults_are_an_empty_200_that_keeps_the_connection() {
    for then in ["{ respond: {} }", "{ respond: null }"] {
        let p = compile("", &format!("- {{ id: stub, then: {then} }}"));
        let out = p.evaluate_admission(&host("a.test"), &EvalContext::empty());
        let r = answer(&out);
        assert_eq!(r.status, 200);
        assert_eq!(r.body, "");
        assert_eq!(r.content_type, "text/plain; charset=utf-8");
        assert_eq!(r.headers.len(), 0);
        assert!(!r.close, "an answer leaves the connection reusable");
        assert_eq!(out.terminal_rule, "stub");
        assert_eq!(out.fail_closed_reason, None);
    }
}

#[test]
fn every_field_compiles_and_header_names_are_lower_cased() {
    let p = compile(
        "",
        r#"
- id: token
  when: host == "auth.test" and path == "/oauth/token"
  then:
    respond:
      status: 201
      body: '{"access_token":"placeholder","expires_in":3600}'
      content_type: application/json
      headers: { X-Stub: "yes", vary: accept }
      close: true
"#,
    );
    let out = p.evaluate_admission(&host("auth.test"), &EvalContext::empty());
    let r = answer(&out);
    assert_eq!(r.status, 201);
    assert_eq!(
        r.body,
        r#"{"access_token":"placeholder","expires_in":3600}"#
    );
    assert_eq!(r.content_type, "application/json");
    assert_eq!(
        r.headers,
        [
            ("x-stub".to_owned(), "yes".to_owned()),
            ("vary".to_owned(), "accept".to_owned())
        ]
    );
    assert!(r.close);
    // The fields as sent: content-type, cache-control, then the headers.
    let fields: Vec<(&str, &str)> = r.header_fields().collect();
    assert_eq!(
        fields,
        [
            ("content-type", "application/json"),
            ("cache-control", "no-store"),
            ("x-stub", "yes"),
            ("vary", "accept"),
        ]
    );
    assert_eq!(out.decision.to_string(), "respond 201 (close)");
}

#[test]
fn respond_needs_its_map_form() {
    let e = compile_err("- { id: r, then: respond }");
    assert!(e.contains("action `respond` needs an argument"), "{e}");
    let e = compile_err("- { id: r, then: { respond: { status: 200, code: 1 } } }");
    assert!(e.contains("unknown field `code`"), "{e}");
}

#[test]
fn status_must_be_200_to_599() {
    for ok in [200, 204, 302, 404, 503, 599] {
        compile(
            "",
            &format!("- {{ id: r, then: {{ respond: {{ status: {ok} }} }} }}"),
        );
    }
    for bad in [0, 100, 101, 199, 600, 999] {
        let e = compile_err(&format!(
            "- {{ id: r, then: {{ respond: {{ status: {bad} }} }} }}"
        ));
        assert!(
            e.contains(&format!("respond status {bad} must be 200 to 599")),
            "{e}"
        );
    }
}

#[test]
fn a_bodiless_status_takes_no_body() {
    for status in [204, 304] {
        let e = compile_err(&format!(
            "- {{ id: r, then: {{ respond: {{ status: {status}, body: x }} }} }}"
        ));
        assert!(e.contains("has no body"), "{e}");
    }
}

#[test]
fn the_body_limit_is_enforced_at_compile_time() {
    let at = |n: usize| {
        format!(
            "- {{ id: r, then: {{ respond: {{ body: \"{}\" }} }} }}",
            "a".repeat(n)
        )
    };
    let max = usize::try_from(DEFAULT_MAX_RESPOND_BODY_BYTES).unwrap();
    compile("", &at(max));
    let e = compile_err(&at(max + 1));
    assert!(
        e.contains(&format!(
            "respond body is {} bytes, over `limits.max_respond_body_bytes` ({max})",
            max + 1
        )),
        "{e}"
    );
    // The configured limit is the one applied.
    assert!(compile_with_limit(&at(10), 10).is_ok());
    let e = compile_with_limit(&at(11), 10).unwrap_err().join("\n");
    assert!(
        e.contains("over `limits.max_respond_body_bytes` (10)"),
        "{e}"
    );
}

#[test]
fn framing_hop_by_hop_and_owned_headers_are_refused() {
    for name in [
        "content-length",
        "Transfer-Encoding",
        "connection",
        "keep-alive",
        "proxy-connection",
        "proxy-authenticate",
        "te",
        "trailer",
        "upgrade",
        "host",
        "expect",
    ] {
        let e = compile_err(&format!(
            "- {{ id: r, then: {{ respond: {{ headers: {{ {name}: x }} }} }} }}"
        ));
        let lower = name.to_ascii_lowercase();
        assert!(
            e.contains(&format!("respond header `{lower}` is managed by roxy")),
            "{name}: {e}"
        );
    }
    let e = compile_err("- { id: r, then: { respond: { headers: { content-type: x } } } }");
    assert!(e.contains("is set by `content_type`"), "{e}");
    let e = compile_err("- { id: r, then: { respond: { headers: { cache-control: x } } } }");
    assert!(e.contains("is always `no-store`"), "{e}");
    let e = compile_err("- { id: r, then: { respond: { headers: { \"x y\": x } } } }");
    assert!(e.contains("invalid header name"), "{e}");
    let e = compile_err("- { id: r, then: { respond: { headers: { x-a: \"a\\nb\" } } } }");
    assert!(e.contains("is not a valid header value"), "{e}");
    let e = compile_err("- { id: r, then: { respond: { content_type: \"\" } } }");
    assert!(e.contains("respond content_type"), "{e}");
    let e = compile_err("- { id: r, then: { respond: { content_type: \"a\\rb\" } } }");
    assert!(e.contains("respond content_type"), "{e}");
}

/// Header names are compared without case, so `X-A` beside `x-a` is one
/// header set twice, not two headers.
#[test]
fn a_header_set_twice_in_different_cases_is_refused() {
    let e = compile_err(r#"- { id: r, then: { respond: { headers: { X-A: "1", x-a: "2" } } } }"#);
    assert!(e.contains("respond header `x-a` is set twice"), "{e}");
    let e = compile_err(r"- { id: r, then: { respond: { headers: { Vary: a, VARY: b } } } }");
    assert!(e.contains("respond header `vary` is set twice"), "{e}");
}

#[test]
fn secrets_are_refused_anywhere_in_it() {
    for respond in [
        "{ body: \"${secret:gh}\" }",
        "{ content_type: \"${secret:gh}\" }",
        "{ headers: { x-token: \"${secret:gh}\" } }",
        "{ headers: { \"${secret:gh}\": x } }",
        // A broken reference is refused too, not served as text.
        "{ body: \"${secret:gh\" }",
    ] {
        let e = compile_err(&format!("- {{ id: r, then: {{ respond: {respond} }} }}"));
        assert!(
            e.contains("secret references are only allowed in `set_header` values")
                && e.contains("not in `respond`"),
            "{respond}: {e}"
        );
    }
}

#[test]
fn a_watching_rule_cannot_respond() {
    for when in [
        "response.status == 500",
        "body.bytes > 10",
        "ws.size > 1",
        "response.body.bytes > 1",
    ] {
        let e = compile_err(&format!(
            "- {{ id: r, when: '{when}', then: {{ respond: {{}} }} }}"
        ));
        assert!(
            e.contains("`respond` is only possible in admission rules"),
            "{when}: {e}"
        );
    }
    // Reading the body text or a byte metric is still decided at admission.
    compile(
        common::METRICS,
        "- { id: r, when: 'body.text contains \"x\" or metric.egress > 1', then: { respond: {} } }",
    );
}

#[test]
fn nothing_follows_respond() {
    let e = compile_err("- { id: r, then: [{ respond: {} }, { tag: t }] }");
    assert!(
        e.contains("`tag` follows the terminal action `respond`"),
        "{e}"
    );
    let e = compile_err("- { id: r, then: [{ respond: {} }, allow] }");
    assert!(
        e.contains("`allow` follows the terminal action `respond`"),
        "{e}"
    );
}

const PRECEDENCE: &str = r#"
- id: stub
  when: host == "auth.test"
  then: { respond: { body: stubbed } }
- id: stub2
  when: host == "auth.test" and header["x-second"] == "1"
  then: { respond: { body: second } }
- id: open
  when: host == "open.test" or header["x-allow"] == "1"
  then: allow
- id: block
  when: header["x-block"] == "1"
  then: deny
- id: lock
  when: header["x-lock"] == "1"
  then: quarantine
"#;

/// `PRECEDENCE` with its rules in reverse order: the decision must not
/// depend on rule position.
fn reversed(yaml: &str) -> String {
    let mut rules: Vec<&str> = yaml.split("\n- ").skip(1).collect();
    rules.reverse();
    rules.iter().fold(String::new(), |mut out, r| {
        out.push_str("\n- ");
        out.push_str(r);
        out
    })
}

#[test]
fn deny_and_quarantine_win_over_respond_in_any_order() {
    for yaml in [PRECEDENCE.to_owned(), reversed(PRECEDENCE)] {
        let p = compile("", &yaml);
        let ctx = EvalContext::empty();
        let out = p.evaluate_admission(&host("auth.test").with_header("x-block", "1"), &ctx);
        assert!(out.decision.is_deny(), "{out:?}");
        assert_eq!(out.terminal_rule, "block");

        let out = p.evaluate_admission(&host("auth.test").with_header("x-lock", "1"), &ctx);
        assert!(out.decision.is_deny(), "{out:?}");
        assert_eq!(out.terminal_rule, "lock");
        assert_eq!(
            out.quarantine.as_ref().map(roxy_rules::RuleId::as_str),
            Some("lock")
        );

        // A deny still wins when an allow and a respond also match.
        let out = p.evaluate_admission(
            &host("auth.test")
                .with_header("x-allow", "1")
                .with_header("x-block", "1"),
            &ctx,
        );
        assert_eq!(out.terminal_rule, "block");
        assert_eq!(out.fail_closed_reason, None);
    }
}

/// The conflict an outcome failed closed on, or a panic.
fn conflict(out: &roxy_rules::Outcome) -> &TerminalConflict {
    assert_eq!(out.decision, Decision::fail_closed());
    assert_eq!(out.terminal_rule, "_fail_closed");
    match &out.fail_closed_reason {
        Some(FailClosedReason::TerminalConflict(c)) => c,
        other => panic!("expected a terminal conflict, got {other:?}: {out:?}"),
    }
}

#[test]
fn respond_and_allow_conflict_and_fail_closed_in_any_order() {
    for yaml in [PRECEDENCE.to_owned(), reversed(PRECEDENCE)] {
        let p = compile("", &yaml);
        let out = p.evaluate_admission(
            &host("auth.test").with_header("x-allow", "1"),
            &EvalContext::empty(),
        );
        assert_eq!(
            conflict(&out),
            &TerminalConflict::AllowAndRespond {
                allow: RuleId::new("open"),
                respond: RuleId::new("stub"),
            }
        );
        assert_eq!(
            out.fail_closed_reason.as_ref().unwrap().to_string(),
            "rule \"open\" allows and rule \"stub\" responds; only one can decide"
        );
        // An allow beside two responds is reported as the allow's conflict.
        let out = p.evaluate_admission(
            &host("auth.test")
                .with_header("x-allow", "1")
                .with_header("x-second", "1"),
            &EvalContext::empty(),
        );
        assert!(
            matches!(conflict(&out), TerminalConflict::AllowAndRespond { allow, .. } if *allow == "open"),
            "{out:?}"
        );
    }
}

#[test]
fn two_responds_conflict_and_fail_closed_in_any_order() {
    for yaml in [PRECEDENCE.to_owned(), reversed(PRECEDENCE)] {
        let p = compile("", &yaml);
        let out = p.evaluate_admission(
            &host("auth.test").with_header("x-second", "1"),
            &EvalContext::empty(),
        );
        // Named in list order, so the pair swaps with the rules; the
        // outcome does not.
        let (first, second) = if yaml == PRECEDENCE {
            ("stub", "stub2")
        } else {
            ("stub2", "stub")
        };
        assert_eq!(
            conflict(&out),
            &TerminalConflict::TwoResponds {
                first: RuleId::new(first),
                second: RuleId::new(second),
            }
        );
        assert_eq!(
            out.fail_closed_reason.as_ref().unwrap().to_string(),
            format!("rules {first:?} and {second:?} both respond; only one can decide")
        );
        let matched: Vec<&str> = out.matched.iter().map(RuleId::as_str).collect();
        assert_eq!(matched.len(), 2, "{out:?}");
        // A deny still wins over both.
        let out = p.evaluate_admission(
            &host("auth.test")
                .with_header("x-second", "1")
                .with_header("x-block", "1"),
            &EvalContext::empty(),
        );
        assert_eq!(out.terminal_rule, "block");
        assert_eq!(out.fail_closed_reason, None);
    }
}

#[test]
fn the_one_matching_respond_answers() {
    for yaml in [PRECEDENCE.to_owned(), reversed(PRECEDENCE)] {
        let p = compile("", &yaml);
        let out = p.evaluate_admission(&host("auth.test"), &EvalContext::empty());
        assert_eq!(answer(&out).body, "stubbed");
        assert_eq!(out.terminal_rule, "stub");
        // A request no respond rule matches is decided as before.
        let out = p.evaluate_admission(&host("open.test"), &EvalContext::empty());
        assert!(out.decision.is_allow());
        let out = p.evaluate_admission(&host("other.test"), &EvalContext::empty());
        assert_eq!(out.terminal_rule, "_default");
    }
}

#[test]
fn an_answer_keeps_log_state_capture_and_digest_only() {
    let p = compile(
        "",
        r#"
- id: everything
  when: host == "auth.test"
  then:
    - set_header: { x-a: "1" }
    - remove_header: [x-b]
    - rewrite_path: { match: "/(.*)", to: "/v2/$1" }
    - set_query: { k: v }
    - redirect: { host: elsewhere.test, port: 443 }
    - tag: stubbed
    - log: { message: answered }
    - set_state: { key: k, value: v }
    - capture: response
    - digest: both
    - respond: { body: ok }
"#,
    );
    let out = p.evaluate_admission(&host("auth.test"), &EvalContext::empty());
    assert!(out.decision.is_respond());
    assert_eq!(
        out.effects,
        vec![
            Effect::Log {
                level: LogLevel::Info,
                message: "answered".into()
            },
            Effect::SetState {
                key: "k".into(),
                value: "v".into(),
                ttl: None
            },
            Effect::Capture(CaptureTarget::Response),
            // Only the answer is recorded: the request is never forwarded.
            Effect::Digest(CaptureTarget::Response),
        ]
    );
    assert_eq!(out.tags, ["stubbed"]);
}

#[test]
fn request_side_actions_beside_respond_warn() {
    let rules: Vec<RuleConfig> = roxy_rules::yaml::from_str(
        r#"
- id: stub
  then:
    - set_header: { x-a: "1" }
    - remove_header: [x-b]
    - rewrite_path: { match: "/(.*)", to: "/v2/$1" }
    - set_query: { k: v }
    - remove_query: [k]
    - redirect: { host: elsewhere.test, port: 443 }
    - sign: { aws_sigv4: { service: s3, region: eu-west-2, access_key_id: a, secret_access_key: b } }
    - capture: request
    - digest: both
    - capture: response
    - tag: t
    - log: { message: m }
    - set_state: { key: k, value: v }
    - respond: {}
- id: plain
  then: [{ set_header: { x-a: "1" } }, allow]
"#,
    )
    .unwrap();
    let warnings = Policy::rule_warnings(&rules);
    let paths: Vec<&str> = warnings.iter().map(|w| w.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "rules[0].then[0]",
            "rules[0].then[1]",
            "rules[0].then[2]",
            "rules[0].then[3]",
            "rules[0].then[4]",
            "rules[0].then[5]",
            "rules[0].then[6]",
            "rules[0].then[7]",
            "rules[0].then[8]",
        ]
    );
    assert!(
        warnings
            .iter()
            .all(|w| w.rule.as_ref().is_some_and(|r| r == "stub"))
    );
    assert_eq!(
        warnings[0].message,
        "`set_header` changes the request and has no effect: this rule answers with \
         `respond`, so the request is never forwarded"
    );
    assert_eq!(
        warnings[7].message,
        "`capture: request` has no effect: this rule answers with `respond`, so the request \
         is never forwarded; write `capture: response` to record the answer"
    );
    assert_eq!(
        warnings[8].message,
        "`digest: both` records only the answer: this rule answers with `respond`, so the \
         request is never forwarded; write `digest: response`"
    );
}
