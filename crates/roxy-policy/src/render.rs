//! Rendering a stack of layers onto a base.

use std::collections::HashSet;

use roxy_rules::template::{self, Part};
use roxy_rules::{Action, Condition, Diagnostic, MetricConfig, Policy, PolicyInput, RuleConfig};
use serde_yaml_ng::{Mapping, Value};

use crate::expr::{self, Kind};
use crate::{Base, Error, IDENT_SEP, Layer, NAME_SEP, Test, hash};

/// What [`render`] produces.
#[derive(Debug, Clone)]
pub struct Rendered {
    /// The config document, with the content hash as its first line.
    pub yaml: String,
    /// `sha256:<hex>` of the inputs.
    pub hash: String,
    /// Every layer's tests, in stack order, with names prefixed.
    pub tests: Vec<Test>,
}

/// Renders `layers` (first layer outermost) onto `base`.
///
/// The output's `rules`, `metrics` and `address_lists` are the layers'
/// concatenated in stack order; `addons` likewise, so a higher layer's
/// addons sit first, in its order, and a lower layer can only add after
/// them. Every defined name is prefixed with its layer's name. The composed
/// policy is compiled before anything is returned, so the output always
/// compiles under the node's own check.
pub fn render(base: &Base, layers: &[Layer]) -> Result<Rendered, Error> {
    let mut seen = HashSet::new();
    for l in layers {
        if !seen.insert(l.name.as_str()) {
            return Err(Error::document(
                &l.name,
                "two layers have this name; names must be unique in a stack",
            ));
        }
    }
    let stack = Stack { layers };
    let mut out = Output::default();
    for i in 0..layers.len() {
        stack.render_layer(i, &mut out)?;
    }
    check_tag_order(&out.rule_tags, layers)?;
    let secrets = check_secrets(base, layers)?;
    compile(&out, &secrets)?;
    let tests = (0..layers.len())
        .map(|i| stack.tests(i))
        .collect::<Result<Vec<_>, _>>()?
        .concat();

    let docs: Vec<(&str, &Value)> = layers.iter().map(|l| (l.name.as_str(), &l.doc)).collect();
    let hash = hash::inputs(&Value::Mapping(base.doc.clone()), &docs);
    let mut doc = base.doc.clone();
    for (key, items) in [
        ("address_lists", out.lists),
        ("metrics", out.metrics),
        ("rules", out.rules),
        ("addons", out.addons),
    ] {
        if !items.is_empty() {
            doc.insert(Value::String(key.to_owned()), Value::Sequence(items));
        }
    }
    let body =
        serde_yaml_ng::to_string(&Value::Mapping(doc)).map_err(|e| Error::document("output", e))?;
    Ok(Rendered {
        yaml: format!("# roxy policy render: inputs {hash}\n{body}"),
        hash,
        tests,
    })
}

/// `path: message` per diagnostic, with the rule named where there is one.
pub(crate) fn diagnostics(diags: &[Diagnostic]) -> String {
    diags
        .iter()
        .map(|d| match &d.rule {
            Some(r) => format!("  {d} (rule {r})"),
            None => format!("  {d}"),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The output sections as they accumulate, plus the typed forms the
/// composed compile and the tag-order check need.
#[derive(Default)]
struct Output {
    rules: Vec<Value>,
    metrics: Vec<Value>,
    lists: Vec<Value>,
    addons: Vec<Value>,
    typed_rules: Vec<RuleConfig>,
    typed_metrics: Vec<MetricConfig>,
    list_names: HashSet<String>,
    /// Each addon's `when`, as rendered.
    addon_whens: Vec<Option<String>>,
    rule_tags: Vec<RuleTags>,
}

/// The tags one rendered rule reads and sets.
struct RuleTags {
    layer: usize,
    id: String,
    reads: Vec<String>,
    sets: Vec<String>,
}

struct Stack<'a> {
    layers: &'a [Layer],
}

impl Stack<'_> {
    fn render_layer(&self, i: usize, out: &mut Output) -> Result<(), Error> {
        let layer = &self.layers[i];
        let prefix = |name: &str| format!("{}{NAME_SEP}{name}", layer.name);
        for (k, list) in layer.address_lists.iter().enumerate() {
            let mut m = mapping(list, &layer.name, &format!("address_lists[{k}]"))?;
            let name = self.resolve(i, Kind::AddressList, str_field(&m, "name"))?;
            out.list_names.insert(name.clone());
            m.insert("name".into(), Value::String(name));
            out.lists.push(Value::Mapping(m));
        }
        for (k, metric) in layer.metrics.iter().enumerate() {
            let path = format!("metrics[{k}]");
            let mut m = mapping(metric, &layer.name, &path)?;
            let id = self.resolve(i, Kind::Metric, str_field(&m, "id"))?;
            m.insert("id".into(), Value::String(id));
            if let Some(w) = m.get("where") {
                let (w, _) = self.rewrite_expr(i, &format!("{path}.where"), w)?;
                m.insert("where".into(), w);
            }
            out.typed_metrics.push(typed(&m, &layer.name, &path)?);
            out.metrics.push(Value::Mapping(m));
        }
        for (k, rule) in layer.rules.iter().enumerate() {
            let path = format!("rules[{k}]");
            let mut m = mapping(rule, &layer.name, &path)?;
            let id = prefix(str_field(&m, "id"));
            m.insert("id".into(), Value::String(id.clone()));
            let mut reads = Vec::new();
            if let Some(w) = m.get("when") {
                let (w, tags) = self.rewrite_expr(i, &format!("{path}.when"), w)?;
                m.insert("when".into(), w);
                reads = tags;
            }
            if let Some(then) = m.get("then") {
                let then = self.rewrite_then(i, then)?;
                m.insert("then".into(), then);
            }
            let typed: RuleConfig = typed(&m, &layer.name, &path)?;
            let sets = typed
                .then
                .0
                .iter()
                .filter_map(|a| match a {
                    Action::Tag(t) => Some(t.clone()),
                    Action::Allow(_)
                    | Action::Deny(_)
                    | Action::SetHeader(_)
                    | Action::RemoveHeader(_)
                    | Action::RewritePath(_)
                    | Action::SetQuery(_)
                    | Action::RemoveQuery(_)
                    | Action::Redirect(_)
                    | Action::Log(_)
                    | Action::SetState(_)
                    | Action::Capture(_) => None,
                })
                .collect();
            out.rule_tags.push(RuleTags {
                layer: i,
                id,
                reads,
                sets,
            });
            out.typed_rules.push(typed);
            out.rules.push(Value::Mapping(m));
        }
        for (k, addon) in layer.addons.iter().enumerate() {
            let path = format!("addons[{k}]");
            let mut m = mapping(addon, &layer.name, &path)?;
            m.insert("name".into(), Value::String(prefix(str_field(&m, "name"))));
            let mut when = None;
            if let Some(w) = m.get("when") {
                let (w, _) = self.rewrite_expr(i, &format!("{path}.when"), w)?;
                when = Some(expr_text(&w));
                m.insert("when".into(), w);
            }
            if let Some(Value::Mapping(endpoints)) = m.get_mut("endpoints") {
                for endpoint in endpoints.values_mut() {
                    self.rewrite_headers(i, endpoint)?;
                }
            }
            out.addon_whens.push(when);
            out.addons.push(Value::Mapping(m));
        }
        Ok(())
    }

    /// The prefixed form of a metric or list `name` used in layer `i`. The
    /// layer's own names take the layer's prefix; a name already prefixed
    /// with a layer above resolves to that layer's definition.
    fn resolve(&self, i: usize, kind: Kind, name: &str) -> Result<String, Error> {
        let layer = &self.layers[i];
        let what = match kind {
            Kind::Metric => "metric",
            Kind::AddressList => "address list",
        };
        let defines = |l: &Layer, n: &str| match kind {
            Kind::Metric => l.metric_ids.iter().any(|m| m == n),
            Kind::AddressList => l.list_names.iter().any(|m| m == n),
        };
        if defines(layer, name) {
            return Ok(format!("{}{IDENT_SEP}{name}", layer.name));
        }
        if let Some((prefix, rest)) = name.split_once(IDENT_SEP)
            && let Some(j) = self.layers.iter().position(|l| l.name == prefix)
        {
            let other = &self.layers[j];
            if j > i {
                return Err(Error::layer(
                    &layer.name,
                    format!(
                        "reads {what} `{name}` of layer {}, which is below it; a layer may read \
                         the layers above it, not below",
                        other.name
                    ),
                ));
            }
            if defines(other, rest) {
                return Ok(name.to_owned());
            }
            return Err(Error::layer(
                &layer.name,
                format!(
                    "references {what} `{name}`, which layer {} does not define",
                    other.name
                ),
            ));
        }
        Err(Error::layer(
            &layer.name,
            format!("references {what} `{name}`, which it does not define"),
        ))
    }

    /// The prefixed form of a secret used in layer `i`: only its own.
    fn resolve_secret(&self, i: usize, name: &str) -> Result<String, Error> {
        let layer = &self.layers[i];
        if layer.secrets.iter().any(|s| s == name) {
            return Ok(format!("{}{NAME_SEP}{name}", layer.name));
        }
        let hint = if name.contains(NAME_SEP) {
            "a layer may only use the secrets it names itself"
        } else {
            "name it under `secrets`"
        };
        Err(Error::layer(
            &layer.name,
            format!("uses secret `{name}`, which it does not name; {hint}"),
        ))
    }

    /// Renames the references in an expression value (a string, or the
    /// boolean YAML makes of `when: true`). Returns the tags it reads.
    fn rewrite_expr(&self, i: usize, path: &str, v: &Value) -> Result<(Value, Vec<String>), Error> {
        let src = match v {
            Value::String(s) => s.clone(),
            Value::Bool(b) => b.to_string(),
            // Not an expression: the typed parse already refused it.
            Value::Null
            | Value::Number(_)
            | Value::Sequence(_)
            | Value::Mapping(_)
            | Value::Tagged(_) => {
                return Ok((v.clone(), Vec::new()));
            }
        };
        match expr::rewrite(&src, |kind, name| self.resolve(i, kind, name))? {
            Ok(rw) => {
                let value = if rw.text == src {
                    v.clone()
                } else {
                    Value::String(rw.text)
                };
                Ok((value, rw.tags))
            }
            Err(d) => Err(Error::Expr {
                layer: self.layers[i].name.clone(),
                path: path.to_owned(),
                message: format!("{}:{}: {}", d.line, d.col, d.message),
            }),
        }
    }

    /// `then`: one action or a list; `set_header` values may name secrets.
    fn rewrite_then(&self, i: usize, then: &Value) -> Result<Value, Error> {
        if let Value::Sequence(items) = then {
            return items
                .iter()
                .map(|a| self.rewrite_action(i, a))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Sequence);
        }
        self.rewrite_action(i, then)
    }

    fn rewrite_action(&self, i: usize, action: &Value) -> Result<Value, Error> {
        let Value::Mapping(m) = action else {
            return Ok(action.clone());
        };
        let mut m = m.clone();
        if let Some(Value::Mapping(headers)) = m.get_mut("set_header") {
            for value in headers.values_mut() {
                if let Value::String(s) = value {
                    *s = self.rewrite_template(i, s)?;
                }
            }
        }
        Ok(Value::Mapping(m))
    }

    /// An endpoint's `headers` values may name secrets.
    fn rewrite_headers(&self, i: usize, endpoint: &mut Value) -> Result<(), Error> {
        let Some(Value::Mapping(headers)) = endpoint.get_mut("headers") else {
            return Ok(());
        };
        for value in headers.values_mut() {
            if let Value::String(s) = value {
                *s = self.rewrite_template(i, s)?;
            }
        }
        Ok(())
    }

    /// `${secret:name}` placeholders take the layer's prefix. A value that
    /// is not a well-formed template is left for the compile to report.
    fn rewrite_template(&self, i: usize, s: &str) -> Result<String, Error> {
        let Ok(parts) = template::parse_template(s) else {
            return Ok(s.to_owned());
        };
        if !template::has_secrets(&parts) {
            return Ok(s.to_owned());
        }
        let mut out = String::with_capacity(s.len());
        for part in parts {
            match part {
                Part::Lit(t) => out.push_str(&t),
                Part::Secret(name) => {
                    out.push_str("${secret:");
                    out.push_str(&self.resolve_secret(i, &name)?);
                    out.push('}');
                }
            }
        }
        Ok(out)
    }

    /// Layer `i`'s tests with their names prefixed.
    fn tests(&self, i: usize) -> Result<Vec<Test>, Error> {
        let layer = &self.layers[i];
        layer
            .tests
            .iter()
            .enumerate()
            .map(|(k, t)| {
                let at = format!("tests[{k}]");
                let (method, url) = t
                    .request
                    .split_once(char::is_whitespace)
                    .map(|(m, u)| (m.to_owned(), u.trim().to_owned()))
                    .filter(|(m, u)| !m.is_empty() && !u.is_empty())
                    .ok_or_else(|| {
                        Error::layer(
                            &layer.name,
                            format!("{at}: `request` must be `METHOD URL`, got {:?}", t.request),
                        )
                    })?;
                let metrics = t
                    .metrics
                    .iter()
                    .map(|(id, v)| Ok((self.resolve(i, Kind::Metric, id)?, *v)))
                    .collect::<Result<Vec<_>, Error>>()?;
                let rule = t.rule.as_deref().map(|r| self.qualify_rule(i, r));
                Ok(Test {
                    layer: layer.name.clone(),
                    name: t.name.clone().unwrap_or(at),
                    method,
                    url,
                    headers: t
                        .headers
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                    body: t.body.clone(),
                    client_ip: t.client_ip,
                    metrics,
                    state: t
                        .state
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                    tags: t.tags.clone(),
                    expect: t.expect,
                    rule,
                })
            })
            .collect()
    }

    /// A rule id in a test: the layer's own unless written as a rule of a
    /// layer above (`org:ceiling`).
    fn qualify_rule(&self, i: usize, rule: &str) -> String {
        if let Some((prefix, _)) = rule.split_once(NAME_SEP)
            && self.layers[..=i].iter().any(|l| l.name == prefix)
        {
            return rule.to_owned();
        }
        format!("{}{NAME_SEP}{rule}", self.layers[i].name)
    }
}

/// A rule may read a tag set by its own layer or a layer above. A tag set
/// only below the reader would never be visible, so the stack is refused
/// rather than reordered.
fn check_tag_order(rules: &[RuleTags], layers: &[Layer]) -> Result<(), Error> {
    for reader in rules {
        for tag in &reader.reads {
            if let Some(setter) = rules
                .iter()
                .find(|s| s.layer > reader.layer && s.sets.contains(tag))
            {
                return Err(Error::TagOrder {
                    reader: reader.id.clone(),
                    reader_layer: layers[reader.layer].name.clone(),
                    setter: setter.id.clone(),
                    setter_layer: layers[setter.layer].name.clone(),
                    tag: tag.clone(),
                });
            }
        }
    }
    Ok(())
}

/// The base must give a source for exactly the secrets the layers name.
fn check_secrets(base: &Base, layers: &[Layer]) -> Result<HashSet<String>, Error> {
    let given = base.secret_names();
    let mut declared = HashSet::new();
    for layer in layers {
        for name in &layer.secrets {
            let full = format!("{}{NAME_SEP}{name}", layer.name);
            if !given.contains(&full) {
                return Err(Error::document(
                    "base",
                    format!(
                        "no source for secret {full}, which layer {} names; add it under `secrets`",
                        layer.name
                    ),
                ));
            }
            declared.insert(full);
        }
    }
    for name in &given {
        if !declared.contains(name) {
            return Err(Error::document(
                "base",
                format!("secret {name} is not named by any layer"),
            ));
        }
    }
    Ok(declared)
}

/// Compiles the composed rules, metrics and addon conditions exactly as
/// the node will.
fn compile(out: &Output, secrets: &HashSet<String>) -> Result<(), Error> {
    let input = PolicyInput {
        rules: &out.typed_rules,
        metrics: &out.typed_metrics,
        secret_names: secrets,
        address_lists: &out.list_names,
    };
    let mut diags = Policy::compile(&input).err().unwrap_or_default();
    for (k, when) in out.addon_whens.iter().enumerate() {
        if let Some(src) = when
            && let Err(d) = Condition::compile(&input, &format!("addons[{k}].when"), src)
        {
            diags.extend(d);
        }
    }
    if diags.is_empty() {
        Ok(())
    } else {
        Err(Error::Compile(diags))
    }
}

fn mapping(v: &Value, layer: &str, path: &str) -> Result<Mapping, Error> {
    match v {
        Value::Mapping(m) => Ok(m.clone()),
        Value::Null
        | Value::Bool(_)
        | Value::Number(_)
        | Value::String(_)
        | Value::Sequence(_)
        | Value::Tagged(_) => Err(Error::layer(layer, format!("{path}: expected a mapping"))),
    }
}

/// A string field the typed parse has already required.
fn str_field<'a>(m: &'a Mapping, key: &str) -> &'a str {
    m.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn expr_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Null
        | Value::Number(_)
        | Value::Sequence(_)
        | Value::Mapping(_)
        | Value::Tagged(_) => String::new(),
    }
}

fn typed<T: serde::de::DeserializeOwned>(m: &Mapping, layer: &str, path: &str) -> Result<T, Error> {
    serde_yaml_ng::from_value(Value::Mapping(m.clone()))
        .map_err(|e| Error::layer(layer, format!("{path}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "version: 1\nlisteners: [{ name: p, bind: 127.0.0.1:0 }]\n";

    fn layer(name: &str, yaml: &str) -> Layer {
        Layer::parse(yaml, name).unwrap()
    }

    fn render_str(base: &str, layers: &[Layer]) -> Result<Rendered, Error> {
        render(&Base::parse(base).unwrap(), layers)
    }

    fn doc(r: &Rendered) -> Value {
        serde_yaml_ng::from_str(&r.yaml).unwrap()
    }

    fn names(v: &Value, section: &str, key: &str) -> Vec<String> {
        v.get(section)
            .and_then(Value::as_sequence)
            .map(|s| {
                s.iter()
                    .map(|i| i.get(key).unwrap().as_str().unwrap().to_owned())
                    .collect()
            })
            .unwrap_or_default()
    }

    const ORG: &str = r#"
metrics:
  - { id: writes, count: requests, where: method == POST }
address_lists:
  - { name: internal, inline: [10.0.0.0/8] }
secrets: [token]
rules:
  - id: ceiling
    when: not host under "github.com"
    then: deny
  - id: tag-writes
    when: method == POST
    then: { tag: write }
  - id: budget
    when: metric.writes > 10 and client.ip in @internal
    then: deny
  - id: reads
    when: host under "github.com" and method == GET
    then: [{ set_header: { authorization: "Bearer ${secret:token}" } }, allow]
addons:
  - { name: monitor, path: monitor.wasm, when: metric.writes > 1 }
  - { name: audit, path: audit.wasm }
"#;

    const USER: &str = r#"
rules:
  - id: issues
    when: path starts_with "/repos" and (tag["write"] or metric.org__writes < 3)
    then: allow
addons:
  - { name: extra, path: extra.wasm }
"#;

    #[test]
    fn names_are_prefixed_and_references_follow() {
        let r = render_str(BASE_WITH_SECRET, &[layer("org", ORG), layer("user", USER)]).unwrap();
        let d = doc(&r);
        assert_eq!(
            names(&d, "rules", "id"),
            [
                "org:ceiling",
                "org:tag-writes",
                "org:budget",
                "org:reads",
                "user:issues"
            ]
        );
        assert_eq!(names(&d, "metrics", "id"), ["org__writes"]);
        assert_eq!(names(&d, "address_lists", "name"), ["org__internal"]);
        let rules = d.get("rules").unwrap().as_sequence().unwrap();
        assert_eq!(
            rules[2].get("when").unwrap().as_str().unwrap(),
            "metric.org__writes > 10 and client.ip in @org__internal"
        );
        // Untouched expressions keep the author's text.
        assert_eq!(
            rules[0].get("when").unwrap().as_str().unwrap(),
            "not host under \"github.com\""
        );
        assert_eq!(
            rules[4].get("when").unwrap().as_str().unwrap(),
            "path starts_with \"/repos\" and (tag[\"write\"] or metric.org__writes < 3)"
        );
        let header = &rules[3].get("then").unwrap()[0]["set_header"]["authorization"];
        assert_eq!(header.as_str().unwrap(), "Bearer ${secret:org:token}");
        let addon_when = d.get("addons").unwrap()[0].get("when").unwrap();
        assert_eq!(addon_when.as_str().unwrap(), "metric.org__writes > 1");
    }

    /// Wrong on purpose: the base must name the secret, so `BASE` alone
    /// fails and the fix is a source for `org:token`.
    #[test]
    fn base_supplies_exactly_the_named_secrets() {
        let err = render_str(BASE, &[layer("org", ORG)])
            .unwrap_err()
            .to_string();
        assert!(err.contains("no source for secret org:token"), "{err}");
        let with =
            format!("{BASE}secrets: {{ 'org:token': {{ env: T }}, 'org:other': {{ env: U }} }}\n");
        let err = render_str(&with, &[layer("org", ORG)])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("secret org:other is not named by any layer"),
            "{err}"
        );
    }

    const BASE_WITH_SECRET: &str = "version: 1\nlisteners: [{ name: p, bind: 127.0.0.1:0 }]\nsecrets: { 'org:token': { env: T } }\n";

    #[test]
    fn rendering_is_stable_across_re_renders_and_layer_additions() {
        let once = render_str(BASE_WITH_SECRET, &[layer("org", ORG)]).unwrap();
        let again = render_str(BASE_WITH_SECRET, &[layer("org", ORG)]).unwrap();
        assert_eq!(once.yaml, again.yaml);
        assert_eq!(once.hash, again.hash);
        // Adding a layer below changes nothing about the org's ids, so its
        // metric series survive.
        let with_user =
            render_str(BASE_WITH_SECRET, &[layer("org", ORG), layer("user", USER)]).unwrap();
        assert_ne!(with_user.hash, once.hash);
        let before = doc(&once);
        let after = doc(&with_user);
        assert_eq!(before.get("metrics"), after.get("metrics"));
        assert_eq!(
            names(&before, "rules", "id"),
            names(&after, "rules", "id")[..4]
        );
        assert!(with_user.yaml.starts_with(&format!(
            "# roxy policy render: inputs {}\n",
            with_user.hash
        )));
    }

    #[test]
    fn a_higher_layer_may_not_read_a_lower_layers_tag() {
        let org = layer(
            "org",
            "rules:\n  - { id: gate, when: 'tag[\"vip\"]', then: allow }\n",
        );
        let user = layer(
            "user",
            "rules:\n  - { id: mark, when: 'method == GET', then: { tag: vip } }\n",
        );
        let err = render_str(BASE, &[org.clone(), user.clone()]).unwrap_err();
        assert!(
            matches!(&err, Error::TagOrder { reader, setter, tag, .. }
                if reader == "org:gate" && setter == "user:mark" && tag == "vip"),
            "{err}"
        );
        // The other way round is the supported direction.
        render_str(BASE, &[user, org]).unwrap();
    }

    #[test]
    fn addons_keep_the_higher_layers_first_in_its_order() {
        let r = render_str(BASE_WITH_SECRET, &[layer("org", ORG), layer("user", USER)]).unwrap();
        assert_eq!(
            names(&doc(&r), "addons", "name"),
            ["org:monitor", "org:audit", "user:extra"]
        );
        // A lower layer that reuses a higher layer's addon name gets its
        // own prefixed addon; it cannot reach the org's.
        let user = layer("user", "addons: [{ name: monitor, path: mine.wasm }]");
        let r = render_str(BASE_WITH_SECRET, &[layer("org", ORG), user]).unwrap();
        let d = doc(&r);
        assert_eq!(
            names(&d, "addons", "name"),
            ["org:monitor", "org:audit", "user:monitor"]
        );
        assert_eq!(
            d["addons"][0]["path"].as_str().unwrap(),
            "monitor.wasm",
            "the org addon's config is unchanged"
        );
    }

    #[test]
    fn cross_layer_references_go_upwards_only() {
        let org = layer("org", "metrics: [{ id: a, count: requests }]");
        let user = layer(
            "user",
            "rules: [{ id: r, when: 'metric.org__a > 1', then: deny }]",
        );
        render_str(BASE, &[org.clone(), user.clone()]).unwrap();
        let err = render_str(BASE, &[user, org]).unwrap_err().to_string();
        assert!(err.contains("layer org, which is below it"), "{err}");
        let undefined = layer(
            "user",
            "rules: [{ id: r, when: 'metric.org__nope > 1', then: deny }]",
        );
        let err = render_str(
            BASE,
            &[
                layer("org", "metrics: [{ id: a, count: requests }]"),
                undefined,
            ],
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("which layer org does not define"), "{err}");
        let own = layer(
            "user",
            "rules: [{ id: r, when: 'metric.a > 1', then: deny }]",
        );
        let err = render_str(BASE, &[own]).unwrap_err().to_string();
        assert!(
            err.contains("references metric `a`, which it does not define"),
            "{err}"
        );
    }

    #[test]
    fn a_layer_may_only_use_its_own_secrets() {
        let user = layer(
            "user",
            "rules: [{ id: r, then: [{ set_header: { x: '${secret:org:token}' } }, allow] }]",
        );
        let err = render_str(BASE_WITH_SECRET, &[layer("org", ORG), user])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("a layer may only use the secrets it names itself"),
            "{err}"
        );
    }

    #[test]
    fn tests_are_prefixed() {
        let user = format!(
            "{USER}tests:\n  - {{ request: 'POST https://api.github.com/repos/x', metrics: {{ org__writes: 2 }}, expect: allow, rule: issues }}\n  - {{ request: 'GET https://x.example/', expect: deny, rule: 'org:ceiling' }}\n"
        );
        let r = render_str(BASE_WITH_SECRET, &[layer("org", ORG), layer("user", &user)]).unwrap();
        assert_eq!(r.tests.len(), 2);
        assert_eq!(r.tests[0].metrics, [("org__writes".to_owned(), 2)]);
        assert_eq!(r.tests[0].rule.as_deref(), Some("user:issues"));
        assert_eq!(r.tests[0].name, "tests[0]");
        assert_eq!(r.tests[1].rule.as_deref(), Some("org:ceiling"));
        let bad = layer("user", "tests: [{ request: 'nourl', expect: allow }]");
        let err = render_str(BASE, &[bad]).unwrap_err().to_string();
        assert!(err.contains("must be `METHOD URL`"), "{err}");
    }

    #[test]
    fn composed_policy_must_compile() {
        let bad = layer("org", "rules: [{ id: r, when: 'host == 1', then: deny }]");
        let err = render_str(BASE, &[bad]).unwrap_err();
        assert!(matches!(err, Error::Compile(_)), "{err}");
        assert!(err.to_string().contains("rules[0].when"), "{err}");
    }
}
