//! Composition of policy layers into one roxy config.
//!
//! A *layer* carries policy: `rules`, `metrics`, `address_lists`, the names
//! of the `secrets` it uses, `addons` and a `tests` suite. A *base* carries
//! the per-node configuration (listeners, TLS, limits, log, upstream) and
//! the sources of the secrets the layers name. [`render`] concatenates the
//! layers onto the base, first layer outermost, into one config document
//! that the proxy loads like any other.
//!
//! Three things make concatenation sound. A deny wins wherever it sits, so a
//! higher layer's denies bound every layer below. Rule order orders effects
//! and tag visibility, never decisions, so a layer's position only decides
//! whose `set_header` wins and whose tags it can see. And every name a layer
//! defines is prefixed with the layer's name, so layers cannot collide or
//! redefine each other's rules, metrics, lists, secrets or addons.
//!
//! The renderer refuses what it cannot make sound: a rule reading a tag that
//! only a lower layer sets (the read would silently be false), a reference
//! to a lower layer's metric or list, a layer using another layer's secret,
//! and a layer carrying anything the base owns or the base carrying policy.
#![forbid(unsafe_code)]

mod expr;
mod hash;
mod render;

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;

use serde::Deserialize;
use serde_yaml_ng::{Mapping, Value};

pub use render::{Rendered, render};
pub use roxy_rules::Diagnostic;

/// Separates a layer name from a rule id, addon name or secret name.
pub const NAME_SEP: char = ':';
/// Separates a layer name from a metric id or address-list name: those are
/// identifiers in the expression grammar, so `:` cannot appear in them.
pub const IDENT_SEP: &str = "__";

/// The sections a layer carries. A base must not carry them.
const LAYER_SECTIONS: [&str; 4] = ["rules", "metrics", "address_lists", "addons"];

/// Why a stack could not be rendered.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A document does not parse or has the wrong shape.
    #[error("{doc}: {message}")]
    Document { doc: String, message: String },
    /// An expression in a layer does not parse.
    #[error("layer {layer}: {path}: {message}")]
    Expr {
        layer: String,
        path: String,
        message: String,
    },
    /// A layer names something it may not.
    #[error("layer {layer}: {message}")]
    Layer { layer: String, message: String },
    /// A rule reads a tag that only a lower layer sets.
    #[error(
        "rule {reader} (layer {reader_layer}) reads tag {tag:?}, which rule {setter} (layer \
         {setter_layer}) sets; a layer may read tags set by the layers above it, not below"
    )]
    TagOrder {
        reader: String,
        reader_layer: String,
        setter: String,
        setter_layer: String,
        tag: String,
    },
    /// The composed policy does not compile.
    #[error("composed policy does not compile:\n{}", render::diagnostics(.0))]
    Compile(Vec<Diagnostic>),
}

impl Error {
    fn document(doc: &str, message: impl fmt::Display) -> Self {
        Self::Document {
            doc: doc.to_owned(),
            message: message.to_string(),
        }
    }

    fn layer(layer: &str, message: impl fmt::Display) -> Self {
        Self::Layer {
            layer: layer.to_owned(),
            message: message.to_string(),
        }
    }
}

/// `[A-Za-z_][A-Za-z0-9_]*`: what the expression grammar accepts as a path
/// segment, so a layer name can prefix a metric id.
fn is_ident(s: &str) -> bool {
    let mut b = s.bytes();
    b.next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
        && b.all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

// ----- tests ------------------------------------------------------------------

/// What a test expects the composed policy to decide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Expect {
    Allow,
    Deny,
}

impl fmt::Display for Expect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        })
    }
}

/// One entry of a layer's `tests`: a request in `roxy rule test` form and
/// the decision expected of the composed policy. Names (metric ids, the
/// expected `rule`) are the layer's own, unprefixed.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestCase {
    #[serde(default)]
    pub name: Option<String>,
    /// `METHOD URL`.
    pub request: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
    /// `client.ip`; default 127.0.0.1.
    #[serde(default)]
    pub client_ip: Option<IpAddr>,
    /// Metric values by id; a metric not given is 0.
    #[serde(default)]
    pub metrics: BTreeMap<String, i64>,
    #[serde(default)]
    pub state: BTreeMap<String, String>,
    /// Tags set before the rules run.
    #[serde(default)]
    pub tags: Vec<String>,
    pub expect: Expect,
    /// The rule expected to decide, if it matters.
    #[serde(default)]
    pub rule: Option<String>,
}

/// A [`TestCase`] with every name prefixed, ready to run against the
/// rendered config.
#[derive(Debug, Clone)]
pub struct Test {
    pub layer: String,
    pub name: String,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub client_ip: Option<IpAddr>,
    pub metrics: Vec<(String, i64)>,
    pub state: Vec<(String, String)>,
    pub tags: Vec<String>,
    pub expect: Expect,
    pub rule: Option<String>,
}

impl Test {
    /// `layer org: <name>`, for reports.
    pub fn label(&self) -> String {
        format!("layer {}: {}", self.layer, self.name)
    }
}

// ----- layers -----------------------------------------------------------------

/// YAML shape of a layer.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LayerDoc {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    rules: Vec<Value>,
    #[serde(default)]
    metrics: Vec<Value>,
    #[serde(default)]
    address_lists: Vec<Value>,
    #[serde(default)]
    secrets: Option<Value>,
    #[serde(default)]
    addons: Vec<Value>,
    #[serde(default)]
    tests: Vec<TestCase>,
}

/// One parsed layer. Its sections are kept as YAML so they reach the
/// output as written, apart from the names the renderer prefixes.
#[derive(Debug, Clone)]
pub struct Layer {
    pub name: String,
    doc: Value,
    rules: Vec<Value>,
    metrics: Vec<Value>,
    address_lists: Vec<Value>,
    secrets: Vec<String>,
    addons: Vec<Value>,
    tests: Vec<TestCase>,
    /// Names defined here, for resolving references.
    metric_ids: Vec<String>,
    list_names: Vec<String>,
}

impl Layer {
    /// Parses a layer. Its name is the document's `name`, else
    /// `default_name` (the file stem).
    pub fn parse(yaml: &str, default_name: &str) -> Result<Self, Error> {
        let doc: Value =
            serde_yaml_ng::from_str(yaml).map_err(|e| Error::document(default_name, e))?;
        let parsed: LayerDoc =
            serde_yaml_ng::from_value(doc.clone()).map_err(|e| Error::document(default_name, e))?;
        let name = parsed.name.unwrap_or_else(|| default_name.to_owned());
        if !is_ident(&name) || name.contains(IDENT_SEP) {
            return Err(Error::document(
                default_name,
                format!(
                    "layer name {name:?} must match [A-Za-z_][A-Za-z0-9_]* without `{IDENT_SEP}`, \
                     so it can prefix metric ids; set `name:` in the layer"
                ),
            ));
        }
        let err = |m: String| Error::layer(&name, m);
        // Typed parses catch shape errors here, with the layer named, rather
        // than in the rendered output.
        let rules: Vec<roxy_rules::RuleConfig> =
            serde_yaml_ng::from_value(Value::Sequence(parsed.rules.clone()))
                .map_err(|e| err(format!("rules{}", strip_leading_path(&e.to_string()))))?;
        let metrics: Vec<roxy_rules::MetricConfig> =
            serde_yaml_ng::from_value(Value::Sequence(parsed.metrics.clone()))
                .map_err(|e| err(format!("metrics{}", strip_leading_path(&e.to_string()))))?;
        for r in &rules {
            if r.id.contains(NAME_SEP) {
                return Err(err(format!(
                    "rule id {:?} contains `{NAME_SEP}`, which separates a layer name from an id",
                    r.id
                )));
            }
        }
        let metric_ids = metrics.iter().map(|m| m.id.clone()).collect::<Vec<_>>();
        for id in &metric_ids {
            if id.contains(IDENT_SEP) {
                return Err(err(format!(
                    "metric id {id:?} contains `{IDENT_SEP}`, which separates a layer name from \
                     an id"
                )));
            }
        }
        let list_names = named(&parsed.address_lists, "address_lists", &err)?;
        for n in &list_names {
            if n.contains(IDENT_SEP) {
                return Err(err(format!(
                    "address list {n:?} contains `{IDENT_SEP}`, which separates a layer name \
                     from a name"
                )));
            }
        }
        for n in named(&parsed.addons, "addons", &err)? {
            if n.contains(NAME_SEP) {
                return Err(err(format!(
                    "addon name {n:?} contains `{NAME_SEP}`, which separates a layer name from \
                     a name; a layer cannot change another layer's addons, so give a new addon \
                     a name of its own"
                )));
            }
        }
        let secrets = placeholder_names(parsed.secrets.as_ref(), &err)?;
        Ok(Self {
            name,
            doc,
            rules: parsed.rules,
            metrics: parsed.metrics,
            address_lists: parsed.address_lists,
            secrets,
            addons: parsed.addons,
            tests: parsed.tests,
            metric_ids,
            list_names,
        })
    }
}

/// `serde_yaml_ng` prefixes a sequence item's error with `[i]` only when the
/// sequence has a path; a bare sequence's errors start with the message.
fn strip_leading_path(msg: &str) -> String {
    if msg.starts_with('[') {
        msg.to_owned()
    } else {
        format!(": {msg}")
    }
}

/// The `name` of every entry in a list of named mappings.
fn named(
    items: &[Value],
    section: &str,
    err: &impl Fn(String) -> Error,
) -> Result<Vec<String>, Error> {
    items
        .iter()
        .enumerate()
        .map(|(i, item)| {
            item.get("name")
                .and_then(Value::as_str)
                .filter(|n| !n.trim().is_empty())
                .map(str::to_owned)
                .ok_or_else(|| err(format!("{section}[{i}]: an entry needs a `name`")))
        })
        .collect()
}

/// A layer's `secrets`: a list of names. The config file's map form, with
/// sources, is refused: where a value comes from is per-node.
fn placeholder_names(
    v: Option<&Value>,
    err: &impl Fn(String) -> Error,
) -> Result<Vec<String>, Error> {
    let items = match v {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Sequence(items)) => items,
        Some(Value::Mapping(_)) => {
            return Err(err(
                "secrets: a layer names the secrets it uses (`secrets: [name, ...]`); where a \
                 value comes from is per-node and belongs in the base"
                    .to_owned(),
            ));
        }
        Some(Value::Bool(_) | Value::Number(_) | Value::String(_) | Value::Tagged(_)) => {
            return Err(err("secrets: expected a list of names".to_owned()));
        }
    };
    items
        .iter()
        .enumerate()
        .map(|(i, item)| {
            let name = item
                .as_str()
                .filter(|n| !n.trim().is_empty())
                .ok_or_else(|| err(format!("secrets[{i}]: expected a secret name")))?;
            if name.contains(NAME_SEP) || name.contains('}') {
                return Err(err(format!(
                    "secrets[{i}]: name {name:?} must not contain `{NAME_SEP}` or `}}`"
                )));
            }
            Ok(name.to_owned())
        })
        .collect()
}

// ----- base -------------------------------------------------------------------

/// The per-node document the layers render onto: everything a config has
/// except the sections layers carry. Its `secrets` map gives the source of
/// each secret the layers name, keyed by the prefixed name.
#[derive(Debug, Clone)]
pub struct Base {
    doc: Mapping,
}

impl Base {
    pub fn parse(yaml: &str) -> Result<Self, Error> {
        let doc: Value = serde_yaml_ng::from_str(yaml).map_err(|e| Error::document("base", e))?;
        let Value::Mapping(doc) = doc else {
            return Err(Error::document("base", "expected a mapping"));
        };
        for section in LAYER_SECTIONS {
            if doc.contains_key(section) {
                return Err(Error::document(
                    "base",
                    format!(
                        "`{section}` belongs in a layer; the base carries per-node configuration \
                         only"
                    ),
                ));
            }
        }
        if let Some(secrets) = doc.get("secrets")
            && !matches!(secrets, Value::Mapping(_) | Value::Null)
        {
            return Err(Error::document(
                "base",
                "`secrets` must map each prefixed secret name to its source",
            ));
        }
        Ok(Self { doc })
    }

    /// The prefixed names the base gives a source for.
    fn source_names(&self) -> Vec<String> {
        self.doc
            .get("secrets")
            .and_then(Value::as_mapping)
            .map(|m| {
                m.keys()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layer_names_must_be_identifiers() {
        let err = Layer::parse("rules: []", "org-policy")
            .unwrap_err()
            .to_string();
        assert!(err.contains("must match"), "{err}");
        assert!(err.contains("set `name:`"), "{err}");
        let ok = Layer::parse("name: org\nrules: []", "org-policy").unwrap();
        assert_eq!(ok.name, "org");
        let err = Layer::parse("name: a__b", "x").unwrap_err().to_string();
        assert!(err.contains("without `__`"), "{err}");
    }

    #[test]
    fn layer_refuses_base_sections_and_unknown_keys() {
        for yaml in ["listeners: []", "tls: {}", "version: 1", "bogus: 1"] {
            let err = Layer::parse(yaml, "org").unwrap_err().to_string();
            assert!(err.contains("unknown field"), "{yaml}: {err}");
        }
    }

    #[test]
    fn layer_secrets_are_names_only() {
        let err = Layer::parse("secrets: { token: { env: T } }", "org")
            .unwrap_err()
            .to_string();
        assert!(err.contains("belongs in the base"), "{err}");
        let err = Layer::parse("secrets: [\"a:b\"]", "org")
            .unwrap_err()
            .to_string();
        assert!(err.contains("must not contain `:`"), "{err}");
        let ok = Layer::parse("secrets: [token]", "org").unwrap();
        assert_eq!(ok.secrets, ["token"]);
    }

    #[test]
    fn layer_refuses_prefixed_names() {
        let cases = [
            ("rules: [{ id: 'org:x', then: deny }]", "rule id"),
            ("metrics: [{ id: a__b, count: requests }]", "metric id"),
            (
                "address_lists: [{ name: a__b, inline: [] }]",
                "address list",
            ),
            ("addons: [{ name: 'org:scan', path: x }]", "addon name"),
        ];
        for (yaml, what) in cases {
            let err = Layer::parse(yaml, "user").unwrap_err().to_string();
            assert!(err.contains(what), "{yaml}: {err}");
        }
    }

    #[test]
    fn layer_shape_errors_name_the_layer_and_the_entry() {
        let err = Layer::parse("rules: [{ id: a, then: deny, phase: x }]", "org")
            .unwrap_err()
            .to_string();
        assert!(err.starts_with("layer org: rules"), "{err}");
        assert!(err.contains("`phase` was removed"), "{err}");
    }

    #[test]
    fn base_refuses_layer_sections() {
        for section in LAYER_SECTIONS {
            let err = Base::parse(&format!("version: 1\n{section}: []"))
                .unwrap_err()
                .to_string();
            assert!(
                err.contains(&format!("`{section}` belongs in a layer")),
                "{err}"
            );
        }
        let ok = Base::parse("version: 1\nsecrets: { 'org:t': { env: T } }").unwrap();
        assert_eq!(ok.source_names(), ["org:t"]);
    }
}
