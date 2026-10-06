//! The node protocol contract, `spec/node-protocol/v1/openapi.yaml`, embedded
//! so tests can validate bodies against its `components/schemas`.

use std::sync::OnceLock;

use jsonschema::Validator;
use serde_json::Value;

/// The `OpenAPI` document as published.
pub const OPENAPI_YAML: &str = include_str!("../../../spec/node-protocol/v1/openapi.yaml");

/// The `OpenAPI` 3.1 meta-schema (2022-10-07), from spec.openapis.org, used to
/// validate the document itself.
pub const OPENAPI_META_SCHEMA: &str = include_str!("../schemas/openapi-3.1-2022-10-07.json");

/// The document parsed to JSON.
pub fn document() -> &'static Value {
    static DOC: OnceLock<Value> = OnceLock::new();
    DOC.get_or_init(|| serde_yaml_ng::from_str(OPENAPI_YAML).expect("openapi.yaml parses"))
}

/// A validator for `#/components/schemas/<name>`. Built by wrapping the whole
/// document in a root schema whose `$ref` points at the component, so the
/// component's own `$ref`s into `#/components/schemas/...` resolve.
pub fn schema_validator(name: &str) -> Validator {
    let doc = document();
    assert!(
        doc.pointer(&format!("/components/schemas/{name}"))
            .is_some(),
        "no component schema named {name}"
    );
    let root = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": format!("#/components/schemas/{name}"),
        "components": doc["components"],
    });
    jsonschema::options()
        .should_validate_formats(true)
        .build(&root)
        .unwrap_or_else(|e| panic!("component schema {name} does not compile: {e}"))
}

/// Validate `instance` against `#/components/schemas/<name>`, listing every
/// violation.
pub fn validate(name: &str, instance: &Value) -> Result<(), String> {
    let errors: Vec<String> = schema_validator(name)
        .iter_errors(instance)
        .map(|e| format!("{e} at {}", e.instance_path()))
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!("{name}: {}", errors.join("; ")))
    }
}
