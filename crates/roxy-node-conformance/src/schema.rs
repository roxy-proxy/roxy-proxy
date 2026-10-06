//! The v1 schemas, embedded from `spec/node-protocol/v1/` so the harness
//! validates bodies against exactly what the repository publishes.

use std::sync::OnceLock;

use jsonschema::Validator;
use serde_json::Value;

/// One schema file: its name without `.json`, and its text.
pub const SCHEMAS: &[(&str, &str)] = &[
    (
        "enrol-request",
        include_str!("../../../spec/node-protocol/v1/enrol-request.json"),
    ),
    (
        "enrol-response",
        include_str!("../../../spec/node-protocol/v1/enrol-response.json"),
    ),
    (
        "node-state",
        include_str!("../../../spec/node-protocol/v1/node-state.json"),
    ),
    (
        "lease",
        include_str!("../../../spec/node-protocol/v1/lease.json"),
    ),
    (
        "flow-batch",
        include_str!("../../../spec/node-protocol/v1/flow-batch.json"),
    ),
    (
        "flow-ack",
        include_str!("../../../spec/node-protocol/v1/flow-ack.json"),
    ),
    (
        "error",
        include_str!("../../../spec/node-protocol/v1/error.json"),
    ),
];

fn validators() -> &'static [(&'static str, Validator)] {
    static VALIDATORS: OnceLock<Vec<(&'static str, Validator)>> = OnceLock::new();
    VALIDATORS.get_or_init(|| {
        SCHEMAS
            .iter()
            .map(|(name, text)| {
                let schema: Value = serde_json::from_str(text)
                    .unwrap_or_else(|e| panic!("schema {name} is not JSON: {e}"));
                let v = jsonschema::options()
                    .should_validate_formats(true)
                    .build(&schema)
                    .unwrap_or_else(|e| panic!("schema {name} does not compile: {e}"));
                (*name, v)
            })
            .collect()
    })
}

/// The compiled validator for schema `name`. Panics on an unknown name: the
/// set is fixed at compile time.
pub fn validator(name: &str) -> &'static Validator {
    validators()
        .iter()
        .find(|(n, _)| *n == name)
        .map_or_else(|| panic!("no schema named {name}"), |(_, v)| v)
}

/// Validate `instance` against schema `name`, listing every violation.
pub fn validate(name: &str, instance: &Value) -> Result<(), String> {
    let errors: Vec<String> = validator(name)
        .iter_errors(instance)
        .map(|e| format!("{} at {}", e, e.instance_path()))
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!("{name}: {}", errors.join("; ")))
    }
}
