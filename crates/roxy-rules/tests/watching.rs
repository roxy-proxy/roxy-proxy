//! Watching evaluation (docs/rules.md#evaluation): rules re-checked after forwarding.

mod common;

use common::{compile, try_compile};
use roxy_rules::{
    Decision, Effect, EvalContext, FailClosedReason, Field, LogLevel, MapView, Reads, RuleKind,
};

const ALL: Reads = Reads::ALL;

const POLICY: &str = r#"
- id: allow-all
  then: allow
- id: upload-log
  when: body.bytes > 1kb
  then: [tag: big-upload, { log: { level: info, message: "big upload" } }]
- id: upload-cap
  when: body.bytes > 10kb
  then: { deny: { status: 413, message: "upload too large" } }
- id: fix-ct
  when: response.status == 200
  then: { set_header: { x-checked: "1" } }
- id: download-cap
  when: tag["big-upload"] and response.body.bytes > 1mb
  then: deny
"#;

#[test]
fn classification() {
    let p = compile("", POLICY);
    let kinds: Vec<RuleKind> = p.rule_info().iter().map(|r| r.kind).collect();
    assert_eq!(
        kinds,
        [
            RuleKind::Head,
            RuleKind::Watching,
            RuleKind::Watching,
            RuleKind::Watching,
            RuleKind::Watching,
        ]
    );
    assert!(p.watches(Reads::BODY_BYTES));
    assert!(p.watches(Reads::RESPONSE_HEAD));
    assert!(!p.watches(Reads::WS));
    assert!(!p.reads_ws());
    // A policy without watching rules watches nothing.
    let head_only = compile("", "- { id: a, then: allow }");
    assert!(!head_only.watches(ALL));
    assert_eq!(head_only.byte_metrics(), Reads::NONE);
}

#[test]
fn effects_apply_once_and_a_deny_stops() {
    let p = compile("", POLICY);
    let ctx = EvalContext::empty();
    let head = p.evaluate_head(&MapView::new(), &ctx);
    assert_eq!(head.terminal_rule, "allow-all");
    let mut st = p.watch_state(&head.tags);
    let at = |n: i64| MapView::new().with_int(Field::BodyBytes, n);
    let changed = Reads::BODY_BYTES;

    // Nothing matches: `None`.
    assert_eq!(
        p.evaluate_watching(changed, changed, &mut st, &at(10), &ctx),
        None
    );
    // Crossing 1 KiB: effects and a tag, once.
    let o = p
        .evaluate_watching(changed, changed, &mut st, &at(2048), &ctx)
        .unwrap();
    assert!(!o.stops());
    assert_eq!(o.matched, ["upload-log"].map(roxy_rules::RuleId::new));
    assert_eq!(o.tags, ["big-upload"]);
    assert_eq!(
        o.effects,
        [Effect::Log {
            level: LogLevel::Info,
            message: "big upload".into()
        }]
    );
    assert_eq!(st.tags, ["big-upload"]);
    assert_eq!(
        p.evaluate_watching(changed, changed, &mut st, &at(4096), &ctx),
        None,
        "a watching rule's effects apply once"
    );
    // Crossing 10 KiB: stop.
    let o = p
        .evaluate_watching(changed, changed, &mut st, &at(20_000), &ctx)
        .unwrap();
    assert_eq!(
        o.stop,
        Some(Decision::Deny {
            status: 413,
            message: "upload too large".into(),
            close: true
        })
    );
    assert_eq!(o.terminal_rule.unwrap(), "upload-cap");
    assert!(st.is_stopped());
    // After a stop nothing is evaluated again.
    assert_eq!(
        p.evaluate_watching(ALL, ALL, &mut st, &at(1 << 30), &ctx),
        None
    );
}

#[test]
fn rules_wait_until_everything_they_read_is_known() {
    let p = compile("", POLICY);
    let ctx = EvalContext::empty();
    let mut st = p.watch_state(&["big-upload".to_owned()]);
    let v = MapView::new()
        .with_int(Field::BodyBytes, 10)
        .with_int(Field::ResponseStatus, 500)
        .with_int(Field::ResponseBodyBytes, 2 << 20);
    // A body-bytes event does not re-check response rules.
    assert_eq!(
        p.evaluate_watching(Reads::BODY_BYTES, Reads::BODY_BYTES, &mut st, &v, &ctx),
        None
    );
    // Response head known, but `response.body.bytes` is not yet.
    assert_eq!(
        p.evaluate_watching(
            Reads::RESPONSE_HEAD,
            Reads::BODY_BYTES | Reads::RESPONSE_HEAD,
            &mut st,
            &v,
            &ctx
        ),
        None
    );
    let o = p
        .evaluate_watching(Reads::RESPONSE_BODY_BYTES, ALL, &mut st, &v, &ctx)
        .unwrap();
    assert_eq!(o.terminal_rule.unwrap(), "download-cap");
}

#[test]
fn response_header_effects() {
    let p = compile("", POLICY);
    let ctx = EvalContext::empty();
    let mut st = p.watch_state(&[]);
    let v = MapView::new().with_int(Field::ResponseStatus, 200);
    let o = p
        .evaluate_watching(
            Reads::RESPONSE_HEAD,
            Reads::RESPONSE_HEAD,
            &mut st,
            &v,
            &ctx,
        )
        .unwrap();
    assert!(!o.stops());
    assert_eq!(
        o.effects,
        [Effect::SetHeader {
            name: "x-checked".into(),
            value: "1".into()
        }]
    );
}

#[test]
fn errors_stop_the_exchange() {
    let ctx = EvalContext::empty();
    // A missing value under an ordering operator: fail closed, stop.
    let p = compile(
        "",
        "- { id: a, then: allow }\n- { id: w, when: 'response.body.size > 1mb', then: deny }",
    );
    let mut st = p.watch_state(&[]);
    let o = p
        .evaluate_watching(
            Reads::RESPONSE_HEAD,
            Reads::RESPONSE_HEAD,
            &mut st,
            &MapView::new(),
            &ctx,
        )
        .unwrap();
    assert_eq!(o.stop, Some(Decision::fail_closed()));
    assert_eq!(o.terminal_rule.unwrap(), "_fail_closed");
    assert_eq!(
        o.fail_closed_reason,
        Some(FailClosedReason::MissingValue("response.body.size".into()))
    );
    assert!(st.is_stopped());

    // A non-deny watching rule that fails also stops: errors never let the
    // exchange continue.
    let p = compile(
        "",
        "- { id: w, when: 'response.header[\"x\"] contains \"y\"', then: { log: { level: info, message: m } } }",
    );
    let mut st = p.watch_state(&[]);
    let o = p
        .evaluate_watching(ALL, ALL, &mut st, &MapView::new(), &ctx)
        .unwrap();
    assert!(o.stops());
    assert_eq!(o.effects, [], "no effects from a failed evaluation");

    // An unavailable metric.
    let p = compile(
        "- { id: egress, count: request_bytes }",
        "- { id: cap, when: 'metric.egress > 1mb', then: deny }",
    );
    let mut st = p.watch_state(&[]);
    let o = p
        .evaluate_watching(
            Reads::METRIC_REQUEST_BYTES,
            Reads::NONE,
            &mut st,
            &MapView::new(),
            &ctx,
        )
        .unwrap();
    assert_eq!(
        o.fail_closed_reason,
        Some(FailClosedReason::MetricUnavailable("egress".into()))
    );
}

/// A deny reading a byte metric takes part in the head decision and is
/// re-checked as this exchange adds bytes. A deny reading a request-count
/// metric is not re-checked (it would deny the 30th request of a `>= 30`
/// limit, counting itself).
#[test]
fn byte_metric_denies_watch() {
    let metrics = "- { id: egress, count: request_bytes }\n- { id: n, count: requests }";
    let p = compile(
        metrics,
        r"
- id: ok
  then: allow
- id: budget
  when: metric.egress > 1mb
  then: deny
- id: burst
  when: metric.n >= 30
  then: deny
",
    );
    let info = p.rule_info();
    assert_eq!(info[1].kind, RuleKind::HeadAndWatching);
    assert_eq!(info[2].kind, RuleKind::Head);
    assert_eq!(p.byte_metrics(), Reads::METRIC_REQUEST_BYTES);
    let ctx = EvalContext::empty();
    let v = |egress: i64, n: i64| {
        MapView::new()
            .with_metric("egress", egress)
            .with_metric("n", n)
    };
    // At the head, already over: deny.
    assert_eq!(
        p.evaluate_head(&v(2 << 20, 0), &ctx).terminal_rule,
        "budget"
    );
    let head = p.evaluate_head(&v(0, 29), &ctx);
    assert_eq!(head.terminal_rule, "ok");
    let mut st = p.watch_state(&head.tags);
    // `n` grew to 30 because of this exchange: not re-checked.
    assert_eq!(
        p.evaluate_watching(ALL, ALL, &mut st, &v(1000, 30), &ctx),
        None
    );
    // The upload pushes egress over the budget: stop.
    let o = p
        .evaluate_watching(
            Reads::BODY_BYTES | Reads::METRIC_REQUEST_BYTES,
            Reads::BODY_BYTES,
            &mut st,
            &v(2 << 20, 30),
            &ctx,
        )
        .unwrap();
    assert_eq!(o.terminal_rule.unwrap(), "budget");
    // A non-deny rule reading a byte metric is a head rule.
    let p = compile(
        metrics,
        "- { id: t, when: 'metric.egress > 1mb', then: { tag: heavy } }",
    );
    assert_eq!(p.rule_info()[0].kind, RuleKind::Head);
}

#[test]
fn watching_rules_cannot_allow_or_change_the_request() {
    for (rule, want) in [
        (
            "{ id: a, when: 'body.bytes > 1', then: allow }",
            "`allow` is only possible",
        ),
        (
            "{ id: a, when: 'response.status == 1', then: { redirect: { host: x, port: 1 } } }",
            "changes the request",
        ),
        (
            "{ id: a, when: 'body.bytes > 1', then: { set_query: { a: b } } }",
            "changes the request",
        ),
        (
            "{ id: a, when: 'ws.size > 1', then: { remove_header: [x] } }",
            "would change the request",
        ),
        (
            "{ id: a, when: 'response.status == 1 and body.bytes > 1', then: { set_header: { x: y } } }",
            "known before the response head is sent",
        ),
        (
            "{ id: a, when: 'body.bytes > 1', then: { capture: both } }",
            "`capture` is decided at the request head",
        ),
        (
            "{ id: a, when: 'response.status == 1', then: { set_header: { x: \"${secret:gh}\" } } }",
            "secret references are only allowed in rules decided at the request head",
        ),
    ] {
        let err = try_compile("", &format!("- {rule}"))
            .unwrap_err()
            .join("\n");
        assert!(err.contains(want), "{rule}: {err}");
    }
    // A response header change in a rule reading only response-head values
    // (and the buffered body) is fine.
    compile(
        "",
        "- { id: a, when: 'response.status == 200 and response.body.text contains \"x\"', then: { remove_header: [x-a] } }",
    );
}
