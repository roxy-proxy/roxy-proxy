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

/// The enrol body carries only the versions; a server may ignore more,
/// but nothing it needs is optional.
#[test]
fn enrol_request_needs_both_versions_and_no_more() {
    let req = page_example("EnrolRequest");
    assert_eq!(
        req.as_object().unwrap().keys().collect::<Vec<_>>(),
        ["protocol_version", "roxy_version"]
    );
    let mut missing = req.clone();
    missing.as_object_mut().unwrap().remove("roxy_version");
    assert!(validate("EnrolRequest", &missing).is_err());
    let mut empty = req;
    empty["roxy_version"] = json!("");
    assert!(validate("EnrolRequest", &empty).is_err());
}

/// The node token is required and must fit an `Authorization` header
/// unchanged: visible ASCII, 1 to 512 bytes.
#[test]
fn enrol_response_token_is_required_and_header_safe() {
    let res = page_example("EnrolResponse");
    assert!(res.get("certificate_chain").is_none());
    let mut missing = res.clone();
    missing.as_object_mut().unwrap().remove("token");
    assert!(validate("EnrolResponse", &missing).is_err());
    for bad in ["", "with space", "tab\tin", "ünïcode", &"x".repeat(513)] {
        let mut r = res.clone();
        r["token"] = json!(bad);
        assert!(validate("EnrolResponse", &r).is_err(), "{bad:?}");
    }
    let mut longest = res.clone();
    longest["token"] = json!("x".repeat(512));
    assert!(validate("EnrolResponse", &longest).is_ok());
    let mut not_a_time = res;
    not_a_time["not_after"] = json!("soon");
    assert!(validate("EnrolResponse", &not_a_time).is_err());
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
fn node_state_seq_unreserved_is_a_boolean_and_an_older_node_may_omit_it() {
    let mut state = page_example("NodeState");
    state["seq_unreserved"] = json!("yes");
    assert!(validate("NodeState", &state).is_err());
    state.as_object_mut().unwrap().remove("seq_unreserved");
    assert!(validate("NodeState", &state).is_ok());
}

/// A node reports `quarantine` as the report object or `null`; the report
/// needs its id, time and a cause of a known kind.
#[test]
fn node_state_quarantine_is_a_report_or_null() {
    let mut state = page_example("NodeState");
    state["quarantine"] = page_example("QuarantineReport");
    assert!(validate("NodeState", &state).is_ok());
    state["quarantine"]["cause"]["kind"] = json!("mood");
    assert!(validate("NodeState", &state).is_err());
    state["quarantine"]["cause"] = json!({"kind": "rule"});
    assert!(
        validate("NodeState", &state).is_err(),
        "a rule cause names the rule"
    );
    state["quarantine"]["cause"] = json!({
        "kind": "threshold", "listener": "proxy", "counter": "parse_errors",
        "count": 20, "window_seconds": 60,
    });
    assert!(validate("NodeState", &state).is_ok());
    state["quarantine"]["cause"]["window_seconds"] = json!(0);
    assert!(validate("NodeState", &state).is_err());
    state["quarantine"] = json!({"id": "q-1"});
    assert!(validate("NodeState", &state).is_err());
    state["quarantine"] = json!("q-1");
    assert!(validate("NodeState", &state).is_err());
    state.as_object_mut().unwrap().remove("quarantine");
    assert!(validate("NodeState", &state).is_ok());
}

/// `quarantine.release` is a list of ids, and the whole object is optional.
#[test]
fn lease_quarantine_release_is_a_list_of_ids() {
    let mut lease = page_example("Lease");
    lease["quarantine"]["release"] = json!("q-1");
    assert!(validate("Lease", &lease).is_err());
    lease["quarantine"]["release"] = json!([""]);
    assert!(validate("Lease", &lease).is_err());
    lease["quarantine"] = json!({"release": []});
    assert!(validate("Lease", &lease).is_ok());
    lease.as_object_mut().unwrap().remove("quarantine");
    assert!(validate("Lease", &lease).is_ok());
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
