//! Shared helpers for roxy-rules integration tests.

#![allow(dead_code)]

use std::collections::HashSet;
use std::fmt::Write as _;

use roxy_rules::{DefaultDecision, Diagnostic, MetricConfig, Policy, PolicyInput, RuleConfig};

pub(crate) fn secret_names() -> HashSet<String> {
    ["openai", "gh"].into_iter().map(String::from).collect()
}

/// Deserialise and compile. Structural (serde) errors are returned as a
/// single message, compile diagnostics as their rendered form.
pub(crate) fn try_compile(metrics_yaml: &str, rules_yaml: &str) -> Result<Policy, Vec<String>> {
    try_compile_with(metrics_yaml, rules_yaml, DefaultDecision::Deny)
}

/// [`try_compile`] with an explicit `default:`.
pub(crate) fn try_compile_with(
    metrics_yaml: &str,
    rules_yaml: &str,
    default: DefaultDecision,
) -> Result<Policy, Vec<String>> {
    let metrics: Vec<MetricConfig> = if metrics_yaml.trim().is_empty() {
        Vec::new()
    } else {
        serde_yaml_ng::from_str(metrics_yaml).map_err(|e| vec![format!("parse: {e}")])?
    };
    let rules: Vec<RuleConfig> =
        serde_yaml_ng::from_str(rules_yaml).map_err(|e| vec![format!("parse: {e}")])?;
    let secrets = secret_names();
    let lists: HashSet<String> = ["internal", "blocked"]
        .into_iter()
        .map(String::from)
        .collect();
    Policy::compile(&PolicyInput {
        rules: &rules,
        metrics: &metrics,
        secret_names: &secrets,
        address_lists: &lists,
        transparent_listeners: false,
        default,
    })
    .map_err(|ds| ds.iter().map(render).collect())
}

pub(crate) fn render(d: &Diagnostic) -> String {
    let mut s = d.to_string();
    if let Some(rule) = &d.rule {
        let _ = write!(s, "  [rule {rule}]");
    }
    if let Some(snippet) = &d.snippet {
        for line in snippet.lines() {
            let _ = write!(s, "\n    | {line}");
        }
    }
    s
}

pub(crate) fn compile(metrics_yaml: &str, rules_yaml: &str) -> Policy {
    try_compile(metrics_yaml, rules_yaml).unwrap_or_else(|d| panic!("{}", d.join("\n")))
}

pub(crate) const METRICS: &str = r"
- id: writes
  count: requests
  where: method in [POST, PUT, PATCH, DELETE]
  key: [client.ip]
  window: 1m
- id: egress
  count: request_bytes
";
