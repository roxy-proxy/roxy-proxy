//! The document is valid `OpenAPI` 3.1, every `$ref` in it resolves,
//! every body it names has an example on the reference page, every example
//! validates against its schema, and the schemas reject the shapes the spec
//! rules out.

use std::collections::BTreeSet;

use roxy_node_spec::{OPENAPI_META_SCHEMA, document, validate};
use serde_json::{Value, json};

const PAGE: &str = include_str!("../../../docs/pages/reference/node-protocol.md");

#[test]
fn document_is_valid_openapi_3_1() {
    let meta: Value = serde_json::from_str(OPENAPI_META_SCHEMA).unwrap();
    let validator = jsonschema::options().build(&meta).unwrap();
    let errors: Vec<String> = validator
        .iter_errors(document())
        .map(|e| format!("{e} at {}", e.instance_path()))
        .collect();
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

/// Every `$ref` string in the document, with the JSON pointer it sits at.
fn refs(value: &Value, at: &str, out: &mut Vec<(String, String)>) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                let here = format!("{at}/{}", k.replace('~', "~0").replace('/', "~1"));
                if k == "$ref"
                    && let Value::String(target) = v
                {
                    out.push((here.clone(), target.clone()));
                }
                refs(v, &here, out);
            }
        }
        Value::Array(items) => {
            for (i, v) in items.iter().enumerate() {
                refs(v, &format!("{at}/{i}"), out);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

#[test]
fn every_ref_resolves_inside_the_document() {
    let mut found = Vec::new();
    refs(document(), "", &mut found);
    assert!(found.len() > 10, "only {} $refs found", found.len());
    for (at, target) in found {
        let pointer = target
            .strip_prefix('#')
            .unwrap_or_else(|| panic!("{at}: external $ref {target}"));
        assert!(
            document().pointer(pointer).is_some(),
            "{at}: $ref {target} does not resolve"
        );
    }
}

/// `(schema name, example)` for each fenced block on the page written as
/// ```` ```json title="<SchemaName>" ````.
fn examples() -> Vec<(String, Value)> {
    let mut out = Vec::new();
    let mut lines = PAGE.lines();
    while let Some(line) = lines.next() {
        let Some(rest) = line.strip_prefix("```json title=\"") else {
            continue;
        };
        let name = rest.split('"').next().unwrap().to_owned();
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

fn page_example(name: &str) -> Value {
    examples()
        .into_iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v)
        .unwrap()
}

#[test]
fn page_examples_validate_against_their_schemas() {
    let examples = examples();
    assert!(
        examples.len() >= 7,
        "only {} examples found on the page",
        examples.len()
    );
    for (name, value) in &examples {
        if let Err(e) = validate(name, value) {
            panic!("example does not validate: {e}\n{value}");
        }
    }
}

/// The schemas the operations send or receive: every request body and
/// response body, by the component they reference.
fn body_schemas() -> BTreeSet<String> {
    let mut found = Vec::new();
    refs(&document()["paths"], "/paths", &mut found);
    refs(
        &document()["components"]["responses"],
        "/components/responses",
        &mut found,
    );
    refs(
        &document()["components"]["requestBodies"],
        "/components/requestBodies",
        &mut found,
    );
    found
        .into_iter()
        .filter(|(at, _)| at.ends_with("/schema/$ref"))
        .filter_map(|(_, target)| {
            target
                .strip_prefix("#/components/schemas/")
                .map(str::to_owned)
        })
        .collect()
}

#[test]
fn every_body_schema_has_an_example_on_the_page() {
    let bodies = body_schemas();
    assert!(bodies.len() >= 7, "found only {bodies:?}");
    let examples = examples();
    for name in &bodies {
        assert!(
            examples.iter().any(|(n, _)| n == name),
            "no example for {name} on the page"
        );
    }
}

#[test]
fn lease_rejects_the_reserved_interception_ca() {
    let mut lease = page_example("Lease");
    lease["interception_ca"] = json!({"certificate": "..."});
    assert!(validate("Lease", &lease).is_err());
}

#[test]
fn lease_rejects_a_bad_on_high_water() {
    let mut lease = page_example("Lease");
    lease["flow"]["on_high_water"] = json!("drop");
    assert!(validate("Lease", &lease).is_err());
}

#[test]
fn lease_secret_values_are_strings_only() {
    let mut lease = page_example("Lease");
    lease["secrets"]["bad"] = json!({"b64": "AAECAwQFBgc="});
    assert!(validate("Lease", &lease).is_err());
    lease["secrets"]["bad"] = json!(42);
    assert!(validate("Lease", &lease).is_err());
    lease["secrets"]["bad"] = json!("plain");
    assert!(validate("Lease", &lease).is_ok());
}

#[test]
fn unsupported_error_must_name_what_is_missing() {
    assert!(validate("Error", &json!({"error": "unsupported", "message": "no"})).is_err());
    assert!(
        validate(
            "Error",
            &json!({"error": "unsupported", "message": "no", "missing": ["roxy_version:0.2.0"]})
        )
        .is_ok()
    );
    assert!(
        validate(
            "Error",
            &json!({"error": "invalid_token", "message": "used"})
        )
        .is_ok()
    );
}

#[test]
fn enrol_request_pins_protocol_version_one() {
    let mut req = page_example("EnrolRequest");
    req["protocol_version"] = json!(2);
    assert!(validate("EnrolRequest", &req).is_err());
}

#[test]
fn node_state_policy_state_is_an_enum_and_only_lease_id_may_be_null() {
    let mut state = page_example("NodeState");
    state["policy_state"] = json!("loading");
    assert!(validate("NodeState", &state).is_err());
    let mut state = page_example("NodeState");
    state["lease_id"] = Value::Null;
    state["policy_state"] = json!("none");
    assert!(validate("NodeState", &state).is_ok());
    state["roxy_version"] = Value::Null;
    assert!(validate("NodeState", &state).is_err());
}

#[test]
fn flow_batch_needs_events_with_seq() {
    let mut batch = page_example("FlowBatch");
    batch["events"] = json!([]);
    assert!(validate("FlowBatch", &batch).is_err());
    let mut batch = page_example("FlowBatch");
    batch["events"][0].as_object_mut().unwrap().remove("seq");
    assert!(validate("FlowBatch", &batch).is_err());
}
