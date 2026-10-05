//! Standalone head conditions (`Condition`): an addon's `when`.

mod common;

use std::collections::HashSet;

use roxy_rules::{
    Condition, DefaultDecision, FailClosedReason, Field, MapView, MetricConfig, PolicyInput,
};

fn try_condition(src: &str) -> Result<Condition, Vec<String>> {
    let metrics: Vec<MetricConfig> = serde_yaml_ng::from_str(common::METRICS).unwrap();
    let secrets = common::secret_names();
    let lists: HashSet<String> = ["internal".to_owned()].into_iter().collect();
    let input = PolicyInput {
        rules: &[],
        metrics: &metrics,
        secret_names: &secrets,
        address_lists: &lists,
        default: DefaultDecision::Deny,
    };
    Condition::compile(&input, "addons[0].when", src)
        .map_err(|ds| ds.iter().map(common::render).collect())
}

fn condition(src: &str) -> Condition {
    try_condition(src).unwrap_or_else(|d| panic!("{}", d.join("\n")))
}

fn post(host: &str, path: &str) -> MapView {
    MapView::new()
        .with_str(Field::Method, "POST")
        .with_str(Field::Host, host)
        .with_str(Field::Path, path)
}

#[test]
fn matches_head_fields() {
    let c =
        condition(r#"host under "anthropic.com" and method == POST and path starts_with "/v1/""#);
    assert_eq!(
        c.matches(&post("api.anthropic.com", "/v1/messages"), &[]),
        Ok(true)
    );
    assert_eq!(
        c.matches(&post("api.openai.com", "/v1/chat"), &[]),
        Ok(false)
    );
}

#[test]
fn reads_tags_it_is_given() {
    let c = condition(r#"tag["llm"]"#);
    let flow = MapView::new();
    assert_eq!(c.matches(&flow, &[]), Ok(false));
    assert_eq!(c.matches(&flow, &["llm".to_owned()]), Ok(true));
}

#[test]
fn reads_metrics_and_state() {
    let c = condition(r#"metric.writes > 3 or state["mode"] == "strict""#);
    assert_eq!(
        c.matches(&MapView::new().with_metric("writes", 4), &[]),
        Ok(true)
    );
    let flow = MapView::new()
        .with_metric("writes", 0)
        .with_state("mode", "strict");
    assert_eq!(c.matches(&flow, &[]), Ok(true));
}

#[test]
fn byte_metrics_are_read_at_the_head() {
    let c = condition("metric.egress > 1mb");
    assert_eq!(
        c.matches(&MapView::new().with_metric("egress", 0), &[]),
        Ok(false)
    );
}

#[test]
fn unavailable_input_is_an_error_not_a_mismatch() {
    let c = condition("metric.writes > 3");
    // MapView reports a metric it was not given as unavailable.
    assert!(matches!(
        c.matches(&MapView::new(), &[]),
        Err(FailClosedReason::MetricUnavailable(_))
    ));
}

#[test]
fn rejects_late_fields() {
    for (src, field) in [
        ("body.bytes > 10", "`body.bytes`"),
        (r#"body.text contains "x""#, "`body.text`"),
        ("response.status == 200", "`response.status`"),
        (r#"response.header["x"] == "y""#, "`response.header"),
        ("ws.opcode == 1", "`ws.opcode`"),
    ] {
        let err = try_condition(src).expect_err(src).join("\n");
        assert!(err.starts_with("addons[0].when: "), "{err}");
        assert!(err.contains("may only read head fields"), "{err}");
        assert!(err.contains(field), "{src}: {err}");
    }
}

#[test]
fn rejects_unknown_names() {
    let err = try_condition("metric.nope > 1").unwrap_err().join("\n");
    assert!(err.contains("nope"), "{err}");
    let err = try_condition("client.ip in @nope").unwrap_err().join("\n");
    assert!(err.contains("nope"), "{err}");
    let err = try_condition("host ==").unwrap_err().join("\n");
    assert!(err.starts_with("addons[0].when"), "{err}");
}
