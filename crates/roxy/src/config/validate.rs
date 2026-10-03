//! Semantic validation that serde cannot express (§6.5).

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::sync::LazyLock;

use regex::Regex;
use roxy_rules::config::Action;

use super::{CONFIG_VERSION, Config, ListenerMode, Phase, UpstreamVerify};

/// One problem found in a config, located by a YAML path such as
/// `rules[2].when`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub path: String,
    pub message: String,
}

impl Diagnostic {
    fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

/// `metric.<id>` references in expressions. M0 uses a plain scan; the M1
/// compiler resolves references properly (and ignores string literals).
static METRIC_REF: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bmetric\.([A-Za-z0-9_\-]+)").expect("valid regex"));

/// `${secret:name}` references in action values.
static SECRET_REF: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$\{secret:([^}]*)\}").expect("valid regex"));

/// Identifiers usable as `metric.<id>` in the DSL.
static IDENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").expect("valid regex"));

impl Config {
    /// Check cross-references and constraints. Returns every problem found,
    /// not just the first.
    pub fn validate(&self) -> Result<(), Vec<Diagnostic>> {
        let mut d = Vec::new();

        if self.version != CONFIG_VERSION {
            d.push(Diagnostic::new(
                "version",
                format!(
                    "unsupported config version {} (expected {CONFIG_VERSION})",
                    self.version
                ),
            ));
        }

        self.validate_listeners(&mut d);
        self.validate_tls(&mut d);
        self.validate_secrets(&mut d);
        self.validate_metrics(&mut d);
        self.validate_addons(&mut d);
        self.validate_rules(&mut d);

        // M1: Policy::compile — compile `when`/`where` expressions and typed
        // actions with roxy-rules here and append its diagnostics (with
        // line/column within the expression).

        if d.is_empty() { Ok(()) } else { Err(d) }
    }

    fn validate_listeners(&self, d: &mut Vec<Diagnostic>) {
        if self.listeners.is_empty() {
            d.push(Diagnostic::new(
                "listeners",
                "at least one listener is required",
            ));
        }
        let mut names: HashMap<&str, usize> = HashMap::new();
        let mut binds = HashMap::new();
        for (i, l) in self.listeners.iter().enumerate() {
            let path = format!("listeners[{i}]");
            if l.name.trim().is_empty() {
                d.push(Diagnostic::new(
                    format!("{path}.name"),
                    "listener name must not be empty",
                ));
            } else if let Some(first) = names.insert(l.name.as_str(), i) {
                d.push(Diagnostic::new(
                    format!("{path}.name"),
                    format!(
                        "duplicate listener name {:?} (first defined at listeners[{first}])",
                        l.name
                    ),
                ));
            }
            if let Some(first) = binds.insert(l.bind, path.clone()) {
                d.push(Diagnostic::new(
                    format!("{path}.bind"),
                    format!("bind address {} is already used by {first}", l.bind),
                ));
            }
            match l.mode {
                ListenerMode::Explicit => {
                    if l.allow_passthrough.is_some() {
                        d.push(Diagnostic::new(
                            format!("{path}.allow_passthrough"),
                            "only valid on transparent listeners",
                        ));
                    }
                    if l.upstream_target.is_some() {
                        d.push(Diagnostic::new(
                            format!("{path}.upstream_target"),
                            "only valid on transparent listeners",
                        ));
                    }
                }
                ListenerMode::Transparent => d.push(Diagnostic::new(
                    format!("{path}.mode"),
                    "transparent mode is deferred and not yet supported (DESIGN.md §4.2); use `explicit`",
                )),
            }
        }
        if let Some(ca) = &self.ca_server
            && let Some(first) = binds.get(&ca.bind)
        {
            d.push(Diagnostic::new(
                "ca_server.bind",
                format!("bind address {} is already used by {first}", ca.bind),
            ));
        }
    }

    fn validate_tls(&self, d: &mut Vec<Diagnostic>) {
        let up = &self.tls.upstream;
        match up.verify {
            UpstreamVerify::Strict if !up.extra_roots.is_empty() => d.push(Diagnostic::new(
                "tls.upstream.extra_roots",
                "extra_roots is set but verify is `strict`; use `strict+extra_roots` to trust them",
            )),
            UpstreamVerify::StrictExtraRoots if up.extra_roots.is_empty() => {
                d.push(Diagnostic::new(
                    "tls.upstream.verify",
                    "`strict+extra_roots` requires at least one entry in extra_roots",
                ));
            }
            _ => {}
        }
        if self.tls.leaf_cache_size == 0 {
            d.push(Diagnostic::new("tls.leaf_cache_size", "must be at least 1"));
        }
    }

    fn validate_secrets(&self, d: &mut Vec<Diagnostic>) {
        for (name, source) in &self.secrets {
            if name.trim().is_empty() || name.contains('}') {
                d.push(Diagnostic::new(
                    format!("secrets.{name}"),
                    "secret names must be non-empty and must not contain `}`",
                ));
            }
            let empty = match source {
                super::SecretSource::Env(var) => var.trim().is_empty(),
                super::SecretSource::File(path) => path.as_os_str().is_empty(),
            };
            if empty {
                d.push(Diagnostic::new(
                    format!("secrets.{name}"),
                    "secret source must not be empty",
                ));
            }
        }
    }

    fn validate_metrics(&self, d: &mut Vec<Diagnostic>) {
        let mut ids: HashMap<&str, usize> = HashMap::new();
        for (i, m) in self.metrics.iter().enumerate() {
            let path = format!("metrics[{i}]");
            if !IDENT.is_match(&m.id) {
                d.push(Diagnostic::new(
                    format!("{path}.id"),
                    format!(
                        "invalid metric id {:?}: must match [A-Za-z_][A-Za-z0-9_]* so it can be used as metric.<id>",
                        m.id
                    ),
                ));
            }
            if let Some(first) = ids.insert(m.id.as_str(), i) {
                d.push(Diagnostic::new(
                    format!("{path}.id"),
                    format!(
                        "duplicate metric id {:?} (first defined at metrics[{first}])",
                        m.id
                    ),
                ));
            }
            if m.window.is_some_and(|w| w.is_zero()) {
                d.push(Diagnostic::new(
                    format!("{path}.window"),
                    "window must be greater than zero",
                ));
            }
        }
        for (i, m) in self.metrics.iter().enumerate() {
            if let Some(expr) = &m.where_ {
                self.check_metric_refs(expr.as_str(), &format!("metrics[{i}].where"), d);
            }
        }
    }

    fn validate_addons(&self, d: &mut Vec<Diagnostic>) {
        let mut names: HashMap<&str, usize> = HashMap::new();
        for (i, a) in self.addons.iter().enumerate() {
            let path = format!("addons[{i}]");
            if a.name.trim().is_empty() {
                d.push(Diagnostic::new(
                    format!("{path}.name"),
                    "addon name must not be empty",
                ));
            } else if let Some(first) = names.insert(a.name.as_str(), i) {
                d.push(Diagnostic::new(
                    format!("{path}.name"),
                    format!(
                        "duplicate addon name {:?} (first defined at addons[{first}])",
                        a.name
                    ),
                ));
            }
            if a.hooks.is_empty() {
                d.push(Diagnostic::new(
                    format!("{path}.hooks"),
                    "at least one hook is required",
                ));
            }
        }
    }

    fn validate_rules(&self, d: &mut Vec<Diagnostic>) {
        let mut ids: HashMap<&str, usize> = HashMap::new();
        for (i, rule) in self.rules.iter().enumerate() {
            let path = format!("rules[{i}]");
            if rule.id.trim().is_empty() {
                d.push(Diagnostic::new(
                    format!("{path}.id"),
                    "rule id must not be empty",
                ));
            } else if rule.id.starts_with('_') {
                d.push(Diagnostic::new(
                    format!("{path}.id"),
                    format!(
                        "rule id {:?}: ids starting with `_` are reserved (e.g. `_default`)",
                        rule.id
                    ),
                ));
            }
            if let Some(first) = ids.insert(rule.id.as_str(), i) {
                d.push(Diagnostic::new(
                    format!("{path}.id"),
                    format!(
                        "duplicate rule id {:?} (first defined at rules[{first}])",
                        rule.id
                    ),
                ));
            }
            if let Some(expr) = &rule.when {
                self.check_metric_refs(expr.as_str(), &format!("{path}.when"), d);
            }
            for (j, action) in rule.then.0.iter().enumerate() {
                let apath = format!("{path}.then[{j}]");
                let strings = action_strings(action);
                let mut seen = BTreeSet::new();
                for s in strings {
                    for cap in SECRET_REF.captures_iter(s) {
                        let name = &cap[1];
                        if !seen.insert(name.to_owned()) {
                            continue;
                        }
                        if !self.secrets.contains_key(name) {
                            d.push(Diagnostic::new(
                                apath.clone(),
                                format!("reference to undefined secret {name:?} (define it under `secrets`)"),
                            ));
                        }
                        if rule.phase != Phase::Request {
                            d.push(Diagnostic::new(
                                apath.clone(),
                                format!(
                                    "secret references are only allowed in request-phase rules (this rule is `{}`)",
                                    rule.phase.as_str()
                                ),
                            ));
                        }
                    }
                }
                if let Action::Call(addon) = action
                    && !self.addons.iter().any(|a| &a.name == addon)
                {
                    d.push(Diagnostic::new(
                        apath,
                        format!("`call` names undefined addon {addon:?}"),
                    ));
                }
            }
        }
    }

    fn check_metric_refs(&self, expr: &str, path: &str, d: &mut Vec<Diagnostic>) {
        let mut seen = BTreeSet::new();
        for cap in METRIC_REF.captures_iter(expr) {
            let id = &cap[1];
            if seen.insert(id.to_owned()) && !self.metrics.iter().any(|m| m.id == id) {
                d.push(Diagnostic::new(
                    path,
                    format!("reference to undefined metric `metric.{id}`"),
                ));
            }
        }
    }
}

/// Every string argument (map keys included) of an action.
fn action_strings(action: &Action) -> Vec<&str> {
    match action {
        Action::SetHeader(pairs) | Action::SetQuery(pairs) => pairs
            .iter()
            .flat_map(|(k, v)| [k.as_str(), v.as_str()])
            .collect(),
        Action::RemoveHeader(names) | Action::RemoveQuery(names) => {
            names.iter().map(String::as_str).collect()
        }
        Action::Deny(d) => d.message.as_deref().into_iter().collect(),
        Action::RewritePath(r) => vec![&r.pattern, &r.to],
        Action::Redirect(r) => vec![&r.host],
        Action::Tag(s) | Action::Call(s) => vec![s],
        Action::Log(l) => vec![&l.message],
        Action::SetState(s) => vec![&s.key, &s.value],
        Action::Allow(_) | Action::Passthrough | Action::Capture(_) => Vec::new(),
    }
}
