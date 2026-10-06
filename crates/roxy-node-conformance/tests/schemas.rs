//! Every example body on the reference page validates against the schema
//! its fence names, every schema has at least one example, and the schemas
//! reject the shapes the spec rules out.

use roxy_node_conformance::schema;
use serde_json::{Value, json};

const PAGE: &str = include_str!("../../../docs/pages/reference/node-protocol.md");

/// `(schema name, example)` for each fenced block written as
/// ```` ```json title="<name>.json" ````.
fn examples() -> Vec<(String, Value)> {
    let mut out = Vec::new();
    let mut lines = PAGE.lines();
    while let Some(line) = lines.next() {
        let Some(rest) = line.strip_prefix("```json title=\"") else {
            continue;
        };
        let name = rest
            .split('"')
            .next()
            .unwrap()
            .trim_end_matches(".json")
            .to_owned();
        let body: String = lines
            .by_ref()
            .take_while(|l| !l.starts_with("```"))
            .collect::<Vec<_>>()
            .join("\n");
        let value: Value = serde_json::from_str(&body)
            .unwrap_or_else(|e| panic!("example for {name} is not JSON: {e}\n{body}"));
        out.push((name, value));
    }
    out
}

#[test]
fn page_examples_validate_against_their_schemas() {
    let examples = examples();
    assert!(!examples.is_empty(), "no examples found on the page");
    for (name, value) in &examples {
        if let Err(e) = schema::validate(name, value) {
            panic!("example does not validate: {e}\n{value}");
        }
    }
}

#[test]
fn every_schema_has_an_example_on_the_page() {
    let examples = examples();
    for (name, _) in schema::SCHEMAS {
        assert!(
            examples.iter().any(|(n, _)| n == name),
            "no example for {name}.json on the page"
        );
    }
}

fn page_example(name: &str) -> Value {
    examples()
        .into_iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v)
        .unwrap()
}

#[test]
fn lease_rejects_the_reserved_interception_ca() {
    let mut lease = page_example("lease");
    lease["interception_ca"] = json!({"certificate": "..."});
    assert!(schema::validate("lease", &lease).is_err());
}

#[test]
fn lease_rejects_a_non_sha256_config_hash_and_a_bad_on_high_water() {
    let mut lease = page_example("lease");
    lease["config_hash"] = json!("md5:abc");
    assert!(schema::validate("lease", &lease).is_err());
    let mut lease = page_example("lease");
    lease["flow"]["on_high_water"] = json!("drop");
    assert!(schema::validate("lease", &lease).is_err());
}

#[test]
fn lease_secret_values_are_text_or_b64_only() {
    let mut lease = page_example("lease");
    lease["secrets"]["bad"] = json!({"hex": "00ff"});
    assert!(schema::validate("lease", &lease).is_err());
    lease["secrets"]["bad"] = json!(42);
    assert!(schema::validate("lease", &lease).is_err());
}

#[test]
fn unsupported_error_must_name_what_is_missing() {
    let err = json!({"error": "unsupported", "message": "no"});
    assert!(schema::validate("error", &err).is_err());
    let err = json!({"error": "unsupported", "message": "no", "missing": ["addon:wasm"]});
    assert!(schema::validate("error", &err).is_ok());
    let err = json!({"error": "invalid_token", "message": "used"});
    assert!(schema::validate("error", &err).is_ok());
}

#[test]
fn enrol_request_pins_protocol_version_one() {
    let mut req = page_example("enrol-request");
    req["protocol_version"] = json!(2);
    assert!(schema::validate("enrol-request", &req).is_err());
}

#[test]
fn node_state_policy_state_is_an_enum_and_hashes_may_be_null() {
    let mut state = page_example("node-state");
    state["policy_state"] = json!("loading");
    assert!(schema::validate("node-state", &state).is_err());
    let mut state = page_example("node-state");
    state["lease_id"] = Value::Null;
    state["config_hash"] = Value::Null;
    state["secrets_hash"] = Value::Null;
    state["policy_state"] = json!("none");
    assert!(schema::validate("node-state", &state).is_ok());
}

#[test]
fn flow_batch_needs_events_with_seq() {
    let mut batch = page_example("flow-batch");
    batch["events"] = json!([]);
    assert!(schema::validate("flow-batch", &batch).is_err());
    let mut batch = page_example("flow-batch");
    batch["events"][0].as_object_mut().unwrap().remove("seq");
    assert!(schema::validate("flow-batch", &batch).is_err());
}
