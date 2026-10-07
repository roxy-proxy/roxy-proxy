//! Watching evaluation: rules re-checked after forwarding.

mod common;

use common::{compile, try_compile};
use roxy_rules::{
    Deny, DenyStatus, EvalContext, FailClosedReason, Field, LogLevel, MapView, Reads, RuleKind,
    Type, WatchEffect,
};

const ALL: Reads = Reads::ALL;

const POLICY: &str = r#"
- id: allow-all
  then: [{ tag: metered }, allow]
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
  when: tag["metered"] and response.body.bytes > 1mb
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

/// Classification follows the catalogue: for every field, a rule reading
/// it watches exactly when `Field::watched` says so, and is re-checked by
/// exactly that value. A field added to the catalogue is covered without a
/// case here.
#[test]
fn every_field_classifies_by_its_own_metadata() {
    for f in Field::ALL {
        let literal = match f.ty() {
            Type::Int => "1",
            Type::Str => "\"x\"",
            Type::Ip => "10.0.0.1",
            Type::Bool => "true",
            Type::StrList => unreachable!("no scalar field is a list"),
        };
        let p = compile(
            "",
            &format!("- {{ id: r, when: {f} == {literal}, then: deny }}"),
        );
        let info = &p.rule_info()[0];
        let reads = Reads::from(f.watched());
        let want = if reads.is_empty() {
            RuleKind::Head
        } else {
            RuleKind::Watching
        };
        assert_eq!(info.kind, want, "{f}");
        assert_eq!(info.triggers, reads, "{f}");
        assert_eq!(f.is_head(), reads.is_empty(), "{f}");
        if !reads.is_empty() {
            assert_eq!(info.watches, [f.name()], "{f}");
        }
    }
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
        p.evaluate_watching(changed, changed, &mut st, &at(10),),
        None
    );
    // Crossing 1 KiB: effects and a tag, once.
    let o = p
        .evaluate_watching(changed, changed, &mut st, &at(2048))
        .unwrap();
    assert!(!o.stops());
    assert_eq!(o.matched, ["upload-log"].map(roxy_rules::RuleId::new));
    assert_eq!(o.tags, ["big-upload"]);
    assert_eq!(
        o.effects,
        [WatchEffect::Log {
            level: LogLevel::Info,
            message: "big upload".into()
        }]
    );
    assert_eq!(st.tags, ["metered", "big-upload"]);
    assert_eq!(
        p.evaluate_watching(changed, changed, &mut st, &at(4096),),
        None,
        "a watching rule's effects apply once"
    );
    // Crossing 10 KiB: stop.
    let o = p
        .evaluate_watching(changed, changed, &mut st, &at(20_000))
        .unwrap();
    assert_eq!(
        o.stop,
        Some(Deny {
            status: DenyStatus::new(413).unwrap(),
            message: "upload too large".into(),
            close: true
        })
    );
    assert_eq!(o.terminal_rule.unwrap(), "upload-cap");
    assert!(st.is_stopped());
    // After a stop nothing is evaluated again.
    assert_eq!(p.evaluate_watching(ALL, ALL, &mut st, &at(1 << 30),), None);
}

#[test]
fn rules_wait_until_everything_they_read_is_known() {
    let p = compile("", POLICY);
    let mut st = p.watch_state(&["metered".to_owned()]);
    let v = MapView::new()
        .with_int(Field::BodyBytes, 10)
        .with_int(Field::ResponseStatus, 500)
        .with_int(Field::ResponseBodyBytes, 2 << 20);
    // A body-bytes event does not re-check response rules.
    assert_eq!(
        p.evaluate_watching(Reads::BODY_BYTES, Reads::BODY_BYTES, &mut st, &v,),
        None
    );
    // Response head known, but `response.body.bytes` is not yet.
    assert_eq!(
        p.evaluate_watching(
            Reads::RESPONSE_HEAD,
            Reads::BODY_BYTES | Reads::RESPONSE_HEAD,
            &mut st,
            &v,
        ),
        None
    );
    let o = p
        .evaluate_watching(Reads::RESPONSE_BODY_BYTES, ALL, &mut st, &v)
        .unwrap();
    assert_eq!(o.terminal_rule.unwrap(), "download-cap");
}

#[test]
fn response_header_effects() {
    let p = compile("", POLICY);
    let mut st = p.watch_state(&[]);
    let v = MapView::new().with_int(Field::ResponseStatus, 200);
    let o = p
        .evaluate_watching(Reads::RESPONSE_HEAD, Reads::RESPONSE_HEAD, &mut st, &v)
        .unwrap();
    assert!(!o.stops());
    assert_eq!(
        o.effects,
        [WatchEffect::SetHeader {
            name: "x-checked".into(),
            value: "1".into()
        }]
    );
}

#[test]
fn errors_stop_the_exchange() {
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
        )
        .unwrap();
    assert_eq!(o.stop, Some(Deny::fail_closed()));
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
        .evaluate_watching(ALL, ALL, &mut st, &MapView::new())
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
    assert_eq!(p.evaluate_watching(ALL, ALL, &mut st, &v(1000, 30),), None);
    // The upload pushes egress over the budget: stop.
    let o = p
        .evaluate_watching(
            Reads::BODY_BYTES | Reads::METRIC_REQUEST_BYTES,
            Reads::BODY_BYTES,
            &mut st,
            &v(2 << 20, 30),
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

/// Watching rules fire when the values they read arrive, not in list
/// order, so a tag set by one is visible to another watching rule only by
/// timing: the reader below would see it after a slow upload and not after
/// a fast one. The compiler rejects the read wherever the setter sits.
#[test]
fn watching_rules_cannot_read_tags_set_by_watching_rules() {
    for rules in [
        r#"
- id: big
  when: body.bytes > 1kb
  then: { tag: big }
- id: cap
  when: tag["big"] and response.body.bytes > 1mb
  then: deny
"#,
        r#"
- id: cap
  when: tag["big"] and response.body.bytes > 1mb
  then: deny
- id: big
  when: body.bytes > 1kb
  then: { tag: big }
"#,
    ] {
        let err = try_compile("", rules).unwrap_err().join("\n");
        assert!(err.contains("reads `tag[\"big\"]`"), "{err}");
        assert!(err.contains("(\"big\"), a watching rule"), "{err}");
    }
    // A head setter anywhere in the list is fine for a watching reader.
    compile(
        "",
        r#"
- id: cap
  when: tag["big"] and response.body.bytes > 1mb
  then: deny
- id: big
  when: body.size != null and body.size > 1kb
  then: { tag: big }
"#,
    );
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
            "{ id: a, when: 'body.bytes > 1', then: { digest: both } }",
            "`digest` is decided at the request head",
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

/// A deny watching a byte metric can fire while watching, and a pass runs
/// every triggered rule even after a deny matched, so a watching reader of
/// its tag would see the tag only when both fire in the same pass. The
/// compiler rejects that read wherever the reader sits; a head reader below
/// the setter sees the tag exactly when the setter matched at the head.
#[test]
fn watching_reader_of_a_head_and_watching_setters_tag_is_rejected() {
    let metrics = "- { id: egress, count: request_bytes }";
    let setter = r"
- id: budget
  when: metric.egress > 1mb
  then: [{ tag: over }, deny]
";
    let reader = r#"
- id: note
  when: tag["over"] and response.body.bytes > 0
  then: { log: { level: info, message: over } }
"#;
    let tail = "- { id: ok, then: allow }\n";
    for rules in [
        format!("{setter}{reader}{tail}"),
        format!("{reader}{setter}{tail}"),
    ] {
        let err = try_compile(metrics, &rules).unwrap_err().join("\n");
        assert!(err.contains("reads `tag[\"over\"]`"), "{err}");
        assert!(err.contains("a deny watching a byte metric"), "{err}");
    }
    let p = compile(
        metrics,
        &format!(
            "{setter}- {{ id: note, when: 'tag[\"over\"]', then: {{ log: {{ level: info, message: over }} }} }}\n{tail}"
        ),
    );
    assert_eq!(p.rule_info()[0].kind, RuleKind::HeadAndWatching);
    assert_eq!(p.rule_info()[1].kind, RuleKind::Head);
}

/// A watching deny does not cut the pass short: the rules below it that
/// the same event triggers are still checked, and their `log` and
/// `set_state` effects and tags apply, as they do at the head. The first
/// deny in list order is the terminal rule.
#[test]
fn a_watching_deny_keeps_the_effects_of_the_rules_below_it() {
    let p = compile(
        "",
        r#"
- id: ok
  then: allow
- id: cap
  when: body.bytes > 10kb
  then: { deny: { status: 413, message: "upload too large" } }
- id: note
  when: body.bytes > 1kb
  then:
    - tag: big
    - set_state: { key: last-big, value: "1" }
    - log: { level: info, message: "big upload" }
- id: second-cap
  when: body.bytes > 10kb
  then: { deny: { status: 400 } }
"#,
    );
    let mut st = p.watch_state(&[]);
    let changed = Reads::BODY_BYTES;
    let o = p
        .evaluate_watching(
            changed,
            changed,
            &mut st,
            &MapView::new().with_int(Field::BodyBytes, 20_000),
        )
        .unwrap();
    assert_eq!(
        o.stop,
        Some(Deny {
            status: DenyStatus::new(413).unwrap(),
            message: "upload too large".into(),
            close: true
        })
    );
    assert_eq!(o.terminal_rule.unwrap(), "cap");
    assert_eq!(
        o.matched,
        ["cap", "note", "second-cap"].map(roxy_rules::RuleId::new)
    );
    assert_eq!(o.tags, ["big"]);
    assert_eq!(
        o.effects,
        [
            WatchEffect::SetState {
                key: "last-big".into(),
                value: "1".into(),
                ttl: None,
            },
            WatchEffect::Log {
                level: LogLevel::Info,
                message: "big upload".into(),
            },
        ]
    );
    assert!(st.is_stopped());

    // An unavailable input below a matching deny fails closed, as at the
    // head: the log must not name a deny that masked it.
    let p = compile(
        "",
        r"
- id: cap
  when: body.bytes > 10kb
  then: deny
- id: w
  when: response.body.size > 1mb
  then: deny
",
    );
    let mut st = p.watch_state(&[]);
    let o = p
        .evaluate_watching(
            ALL,
            ALL,
            &mut st,
            &MapView::new().with_int(Field::BodyBytes, 20_000),
        )
        .unwrap();
    assert_eq!(o.stop, Some(Deny::fail_closed()));
    assert_eq!(o.terminal_rule.unwrap(), "_fail_closed");
    assert_eq!(
        o.fail_closed_reason,
        Some(FailClosedReason::MissingValue("response.body.size".into()))
    );
    assert_eq!(o.matched, ["cap"].map(roxy_rules::RuleId::new));
}

/// A rule reading two watched fields is checked only once both are known:
/// a change to one of them while the other is still unknown is skipped
/// rather than evaluated against a missing value, and an event the rule
/// does not read never checks it, however much is known.
#[test]
fn a_rule_waits_for_a_field_that_arrives_on_a_later_event() {
    let p = compile(
        "",
        r"
- id: w
  when: body.bytes > 1kb and response.status == 200
  then: deny
",
    );
    let info = p.rule_info();
    assert_eq!(info[0].triggers, Reads::BODY_BYTES | Reads::RESPONSE_HEAD);
    let v = |body: i64| {
        MapView::new()
            .with_int(Field::BodyBytes, body)
            .with_int(Field::ResponseStatus, 200)
    };
    let mut st = p.watch_state(&[]);
    // Body bytes known and over the limit, response head not yet: skipped.
    assert_eq!(
        p.evaluate_watching(Reads::BODY_BYTES, Reads::BODY_BYTES, &mut st, &v(2048)),
        None
    );
    assert!(!st.is_stopped());
    // Everything known, but the event is one the rule does not read.
    assert_eq!(
        p.evaluate_watching(Reads::RESPONSE_BODY_BYTES, ALL, &mut st, &v(2048)),
        None
    );
    // The response head arrives: both fields known, the rule fires.
    let o = p
        .evaluate_watching(
            Reads::RESPONSE_HEAD,
            Reads::BODY_BYTES | Reads::RESPONSE_HEAD,
            &mut st,
            &v(2048),
        )
        .unwrap();
    assert_eq!(o.terminal_rule.unwrap(), "w");

    // Evaluated false once everything is known, a rule is re-checked when
    // one of its fields changes again.
    let mut st = p.watch_state(&[]);
    assert_eq!(
        p.evaluate_watching(
            Reads::RESPONSE_HEAD,
            Reads::BODY_BYTES | Reads::RESPONSE_HEAD,
            &mut st,
            &v(10),
        ),
        None
    );
    let o = p
        .evaluate_watching(
            Reads::BODY_BYTES,
            Reads::BODY_BYTES | Reads::RESPONSE_HEAD,
            &mut st,
            &v(2048),
        )
        .unwrap();
    assert_eq!(o.terminal_rule.unwrap(), "w");
}
