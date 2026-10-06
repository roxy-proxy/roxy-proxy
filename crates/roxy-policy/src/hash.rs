//! The content hash of a render's inputs.
//!
//! Two stacks that mean the same thing hash the same: each document is
//! written in a canonical form (mapping keys sorted, JSON-style scalars)
//! before hashing, so key order and YAML quoting style do not matter.
//! Layer names are part of the input, since they are part of the output.

use std::fmt::Write as _;

use serde_yaml_ng::Value;

/// `sha256:<hex>` over the canonical form of the base and the layers, in
/// stack order.
pub(crate) fn inputs(base: &Value, layers: &[(&str, &Value)]) -> String {
    let mut text = String::from("base:");
    canonical(base, &mut text);
    for (name, doc) in layers {
        let _ = write!(text, "\nlayer {name}:");
        canonical(doc, &mut text);
    }
    let digest = ring::digest::digest(&ring::digest::SHA256, text.as_bytes());
    let mut hex = String::with_capacity(7 + 64);
    hex.push_str("sha256:");
    for b in digest.as_ref() {
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

/// Writes `v` with mapping keys sorted by their own canonical text. Every
/// scalar is written as JSON so the result never depends on how the YAML
/// was quoted.
fn canonical(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => {
            let _ = write!(out, "{b}");
        }
        Value::Number(n) => {
            let _ = write!(out, "{n}");
        }
        Value::String(s) => {
            let _ = write!(out, "{}", serde_json::Value::String(s.clone()));
        }
        Value::Sequence(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical(item, out);
            }
            out.push(']');
        }
        Value::Mapping(m) => {
            let mut entries: Vec<(String, &Value)> = m
                .iter()
                .map(|(k, v)| {
                    let mut key = String::new();
                    canonical(k, &mut key);
                    (key, v)
                })
                .collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            out.push('{');
            for (i, (k, v)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(k);
                out.push(':');
                canonical(v, out);
            }
            out.push('}');
        }
        Value::Tagged(t) => {
            let _ = write!(out, "!{} ", t.tag);
            canonical(&t.value, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml(s: &str) -> Value {
        serde_yaml_ng::from_str(s).unwrap()
    }

    #[test]
    fn key_order_and_quoting_do_not_change_the_hash() {
        let a = yaml("version: 1\nrules:\n  - {id: a, when: 'host == \"x\"', then: allow}\n");
        let b =
            yaml("rules:\n- then: allow\n  when: \"host == \\\"x\\\"\"\n  id: \"a\"\nversion: 1\n");
        assert_eq!(inputs(&a, &[]), inputs(&b, &[]));
    }

    #[test]
    fn content_layer_order_and_names_do() {
        let base = yaml("version: 1");
        let x = yaml("rules: [{id: a, then: allow}]");
        let y = yaml("rules: [{id: a, then: deny}]");
        let base_only = inputs(&base, &[]);
        let xy = inputs(&base, &[("x", &x), ("y", &y)]);
        assert_ne!(base_only, xy);
        assert_ne!(xy, inputs(&base, &[("y", &y), ("x", &x)]));
        assert_ne!(xy, inputs(&base, &[("x", &x), ("z", &y)]));
        assert!(xy.starts_with("sha256:") && xy.len() == 7 + 64, "{xy}");
    }
}
