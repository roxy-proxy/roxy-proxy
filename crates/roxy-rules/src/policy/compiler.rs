//! Compiling rules and metrics into a [`Policy`]: ids, the `when`
//! expressions, action legality, header templates and tag ordering.

use std::collections::HashMap;
use std::fmt::Write as _;

use regex::Regex;

use super::{
    CAction, CompiledRule, Condition, MetricDef, PolicyInput, RuleKind, RuleShape, is_header_value,
    metric_reads,
};
use crate::compile::{Env, Needs, Pred, build_shared_regex, compile};
use crate::config::{
    Action, DenyArgs, MetricConfig, MetricCount, RedirectArgs, RewritePathArgs, RuleConfig, Upgrade,
};
use crate::diag::{Diagnostic, RuleId};
use crate::eval::{AllowOpts, DEFAULT_DENY_MESSAGE, DEFAULT_DENY_STATUS, Decision, Effect};
use crate::lexer::is_ident;
use crate::template::{Part, has_secrets, mentions_secret, parse_template, secret_names};
use crate::types::{Field, Reads, is_token};

impl Condition {
    /// Compiles `src`. `path` locates it in diagnostics (`addons[0].when`).
    pub fn compile(
        input: &PolicyInput<'_>,
        path: &str,
        src: &str,
    ) -> Result<Condition, Vec<Diagnostic>> {
        let mut c = PolicyCompiler::new(input);
        let Some((pred, needs)) = c.expr(None, path.to_owned(), src) else {
            return Err(c.finish().1);
        };
        // A byte metric's value is known at the head; only fields are late.
        let mut late: Vec<String> = needs
            .watched_names(Reads::WATCHED_FIELDS)
            .iter()
            .map(|n| format!("`{n}`"))
            .collect();
        if needs.request_body {
            late.push("`body.text`".to_owned());
        }
        if !late.is_empty() {
            return Err(vec![Diagnostic::new(
                path,
                format!(
                    "a condition here may only read head fields, and not `body.text`, because \
                     it is decided before the request body is read; it reads {}",
                    late.join(", ")
                ),
            )]);
        }
        Ok(Condition { pred })
    }
}

/// Headers rules may not set or remove: framing and hop-by-hop headers are
/// owned by roxy's canonicaliser, and `host` changes go
/// through `redirect: { rewrite_host: true }`.
const RESERVED_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authorization",
    "te",
    "trailer",
    "upgrade",
];

/// Backquoted names joined with commas, for messages.
fn quoted(names: &[String]) -> String {
    names
        .iter()
        .map(|n| format!("`{n}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) struct PolicyCompiler<'i, 'a> {
    input: &'i PolicyInput<'a>,
    d: Vec<Diagnostic>,
    /// Body buffering needed by any expression compiled so far.
    needs: Needs,
}

impl<'i, 'a> PolicyCompiler<'i, 'a> {
    pub(super) fn new(input: &'i PolicyInput<'a>) -> Self {
        Self {
            input,
            d: Vec::new(),
            needs: Needs::default(),
        }
    }

    /// The body-buffering needs of everything compiled, and every
    /// diagnostic found.
    pub(super) fn finish(self) -> (Needs, Vec<Diagnostic>) {
        (self.needs, self.d)
    }

    fn push(&mut self, rule: Option<&RuleId>, path: impl Into<String>, msg: impl Into<String>) {
        self.d
            .push(Diagnostic::new(path, msg).with_rule(rule.cloned()));
    }

    fn expr(&mut self, rule: Option<&RuleId>, path: String, src: &str) -> Option<(Pred, Needs)> {
        let input = self.input;
        let metric = |id: &str| {
            input
                .metrics
                .iter()
                .find(|m| m.id == id)
                .map(|m| metric_reads(&m.count))
        };
        let result = compile(
            src,
            &Env {
                metric: &metric,
                list_exists: &|name: &str| input.address_lists.contains(name),
            },
        );
        match result {
            Ok((pred, needs)) => {
                self.needs.request_body |= needs.request_body;
                self.needs.response_body |= needs.response_body;
                Some((pred, needs))
            }
            Err(e) => {
                self.d
                    .push(Diagnostic::from_expr(path, src, e).with_rule(rule.cloned()));
                None
            }
        }
    }

    pub(super) fn metrics(&mut self) -> Vec<MetricDef> {
        let mut ids: HashMap<&str, usize> = HashMap::new();
        let input = self.input;
        input
            .metrics
            .iter()
            .enumerate()
            .map(|(i, m)| {
                let path = format!("metrics[{i}]");
                if let Some(first) = ids.insert(m.id.as_str(), i) {
                    self.push(
                        None,
                        format!("{path}.id"),
                        format!(
                            "duplicate metric id {:?} (first defined at metrics[{first}])",
                            m.id
                        ),
                    );
                }
                self.metric(m, &path)
            })
            .collect()
    }

    fn metric(&mut self, m: &MetricConfig, path: &str) -> MetricDef {
        if !is_ident(&m.id) {
            self.push(
                None,
                format!("{path}.id"),
                format!(
                    "invalid metric id {:?}: must match [A-Za-z_][A-Za-z0-9_]* so it can be \
                     used as metric.<id>",
                    m.id
                ),
            );
        }
        if m.window.is_some_and(|w| w.is_zero()) {
            self.push(
                None,
                format!("{path}.window"),
                "window must be greater than zero",
            );
        }
        let key: Vec<Field> = m
            .key
            .iter()
            .enumerate()
            .filter_map(|(j, k)| self.metric_field(k, format!("{path}.key[{j}]"), "key"))
            .collect();
        let unique = match &m.count {
            MetricCount::Unique(f) => self.metric_field(f, format!("{path}.count"), "unique()"),
            _ => None,
        };
        let filter = m
            .where_
            .as_ref()
            .and_then(|w| self.metric_filter(w.as_str(), format!("{path}.where")));
        MetricDef {
            id: m.id.clone(),
            count: m.count.clone(),
            unique,
            key,
            window: m.window,
            filter,
        }
    }

    /// A metric `key` or `unique()` field, which must be a head field.
    fn metric_field(&mut self, name: &str, at: String, what: &str) -> Option<Field> {
        match Field::from_name(name) {
            Some(f) if f.is_head() => Some(f),
            Some(f) => {
                self.push(
                    None,
                    at,
                    format!(
                        "`{f}` is known only after forwarding; metric {what} fields must be \
                         head fields (https://roxy-proxy.github.io/roxy-proxy/policies/rate-limits#metrics)"
                    ),
                );
                None
            }
            None => {
                self.push(
                    None,
                    at,
                    format!(
                        "unknown {what} field `{name}`; metric fields must be scalar fields \
                         such as client.ip, client.user, host"
                    ),
                );
                None
            }
        }
    }

    /// A metric `where`: head fields only, and no tags, so that whether a
    /// flow counts is fixed at the request head and does not depend on the
    /// rules. A flow is counted outside the rules, where no tag is set, so
    /// a tag read here would always be false.
    fn metric_filter(&mut self, src: &str, at: String) -> Option<Pred> {
        let (pred, needs) = self.expr(None, at.clone(), src)?;
        if needs.reads.intersects(Reads::WATCHED_FIELDS) {
            self.push(
                None,
                at,
                format!(
                    "a metric's `where` may only read head fields, because whether an \
                     exchange counts is decided at the request head; it reads {} \
                     (https://roxy-proxy.github.io/roxy-proxy/policies/rate-limits#metrics)",
                    quoted(&needs.watched_names(Reads::WATCHED_FIELDS))
                ),
            );
            return None;
        }
        if !needs.tags.is_empty() {
            let tags: Vec<String> = needs.tags.iter().map(|t| format!("tag[{t:?}]")).collect();
            self.push(
                None,
                at,
                format!(
                    "a metric's `where` cannot read tags: tags are set by rules and addons on \
                     each flow, and whether a flow counts is decided without them; it reads {}",
                    quoted(&tags)
                ),
            );
            return None;
        }
        Some(pred)
    }

    pub(super) fn rules(&mut self) -> Vec<CompiledRule> {
        let mut out = Vec::new();
        let mut seen: HashMap<&str, usize> = HashMap::new();
        let mut tag_reads: Vec<Vec<Box<str>>> = Vec::new();
        let input = self.input;
        for (i, rule) in input.rules.iter().enumerate() {
            let path = format!("rules[{i}]");
            let rid = RuleId::new(&rule.id);
            if rule.id.trim().is_empty() {
                self.push(
                    Some(&rid),
                    format!("{path}.id"),
                    "rule id must not be empty",
                );
            } else if rule.id.starts_with('_') {
                self.push(
                    Some(&rid),
                    format!("{path}.id"),
                    format!(
                        "rule id {:?}: ids starting with `_` are reserved (`_default`, `_fail_closed`)",
                        rule.id
                    ),
                );
            }
            if let Some(first) = seen.insert(rule.id.as_str(), i) {
                self.push(
                    Some(&rid),
                    format!("{path}.id"),
                    format!(
                        "duplicate rule id {:?} (first defined at rules[{first}])",
                        rule.id
                    ),
                );
            }
            let (when, needs) = match &rule.when {
                Some(w) => match self.expr(Some(&rid), format!("{path}.when"), w.as_str()) {
                    Some((p, n)) => (Some(p), n),
                    None => (None, Needs::default()),
                },
                None => (None, Needs::default()),
            };
            tag_reads.push(needs.tags.clone());
            let shape = RuleShape::classify(&needs, rule);
            let actions = self.actions(rule, &rid, &path, &shape);
            out.push(CompiledRule {
                id: rid,
                when,
                actions: actions.into(),
                shape,
            });
        }
        self.tag_order(&out, &tag_reads);
        out
    }

    /// A rule may read `tag["x"]` only if every rule that can set `x` is
    /// decided at the head and, for a reader that is itself decided at the
    /// head, sits above it. Head rules run in list order, so what the
    /// reader sees is then fixed by the config. A watching setter fires
    /// when the values it reads arrive, not in list order, so whether its
    /// tag is visible would depend on timing. (A deny that watches a byte
    /// metric counts as head: if it fires later, the exchange stops.) A tag
    /// no rule sets can only come from an addon, before any rule runs; a
    /// rule's own tags are set after its own check wherever it sits.
    fn tag_order(&mut self, rules: &[CompiledRule], tag_reads: &[Vec<Box<str>>]) {
        let input = self.input;
        let sets = |i: usize, tag: &str| {
            input.rules[i]
                .then
                .0
                .iter()
                .any(|a| matches!(a, Action::Tag(t) if t == tag))
        };
        for (r, tags) in tag_reads.iter().enumerate() {
            for tag in tags {
                let late: Vec<String> = (0..rules.len())
                    .filter(|&s| sets(s, tag))
                    .filter_map(|s| {
                        let id = &input.rules[s].id;
                        if s == r {
                            None
                        } else if !rules[s].shape.kind.at_head() {
                            Some(format!(
                                "rules[{s}] ({id:?}), a watching rule, which fires when the \
                                 values it reads arrive rather than in list order"
                            ))
                        } else if s > r && rules[r].shape.kind.at_head() {
                            Some(format!("rules[{s}] ({id:?}), below this rule"))
                        } else {
                            None
                        }
                    })
                    .collect();
                if !late.is_empty() {
                    self.push(
                        Some(&rules[r].id),
                        format!("rules[{r}].when"),
                        format!(
                            "reads `tag[{tag:?}]`, which is set too late to be seen here, \
                             by {}; a rule sees only the tags set before it is checked",
                            late.join(" and by ")
                        ),
                    );
                }
            }
        }
    }

    fn actions(
        &mut self,
        rule: &RuleConfig,
        rid: &RuleId,
        path: &str,
        shape: &RuleShape,
    ) -> Vec<CAction> {
        let actions = &rule.then.0;
        let mut out = Vec::with_capacity(actions.len());
        for (j, action) in actions.iter().enumerate() {
            let apath = format!("{path}.then[{j}]");
            if j > 0 && actions[j - 1].is_terminal() {
                self.push(
                    Some(rid),
                    apath.clone(),
                    format!(
                        "`{}` follows the terminal action `{}` and would never run; move it \
                         before `{}`",
                        action.name(),
                        actions[j - 1].name(),
                        actions[j - 1].name()
                    ),
                );
            }
            if let Some(a) = self.action(shape, action, rid, &apath) {
                out.extend(a);
            }
        }
        out
    }

    /// Check one action; `None` if it has errors (already reported).
    fn action(
        &mut self,
        shape: &RuleShape,
        action: &Action,
        rid: &RuleId,
        apath: &str,
    ) -> Option<Vec<CAction>> {
        let errors_before = self.d.len();
        let rule = Some(rid);
        if let Some(msg) = shape.illegal(action) {
            self.push(rule, apath, msg);
        }
        if non_header_strings(action)
            .iter()
            .any(|s| mentions_secret(s))
        {
            self.push(
                rule,
                apath,
                format!(
                    "secret references are only allowed in `set_header` values, not in `{}`",
                    action.name()
                ),
            );
        }
        let out = match action {
            Action::Allow(_) | Action::Deny(_) | Action::Passthrough => {
                vec![CAction::Terminal(self.terminal(action, rule, apath))]
            }
            Action::SetHeader(pairs) => self.set_header(shape, pairs, rule, apath),
            Action::RemoveHeader(names) => names
                .iter()
                .filter_map(|n| self.header_name(rule, apath, n))
                .map(|n| CAction::Effect(Effect::RemoveHeader(n)))
                .collect(),
            Action::RewritePath(r) => self
                .rewrite_path(r, rule, apath)
                .into_iter()
                .map(CAction::Effect)
                .collect(),
            Action::SetQuery(pairs) => {
                if pairs.iter().any(|(k, _)| k.is_empty()) {
                    self.push(rule, apath, "query keys must not be empty");
                }
                pairs
                    .iter()
                    .map(|(k, v)| {
                        CAction::Effect(Effect::SetQuery {
                            key: k.clone(),
                            value: v.clone(),
                        })
                    })
                    .collect()
            }
            Action::RemoveQuery(keys) => {
                if keys.iter().any(String::is_empty) {
                    self.push(rule, apath, "query keys must not be empty");
                }
                keys.iter()
                    .map(|k| CAction::Effect(Effect::RemoveQuery(k.clone())))
                    .collect()
            }
            Action::Redirect(r) => vec![CAction::Effect(self.redirect(r, rule, apath))],
            Action::Tag(t) => {
                if t.is_empty() || t.chars().any(|c| c.is_whitespace() || c.is_control()) {
                    self.push(
                        rule,
                        apath,
                        format!("tag name {t:?} must be non-empty without whitespace"),
                    );
                }
                vec![CAction::Tag(t.clone())]
            }
            Action::Log(l) => vec![CAction::Effect(Effect::Log {
                level: l.level,
                message: l.message.clone(),
            })],
            Action::SetState(s) => {
                if s.key.is_empty() {
                    self.push(rule, apath, "set_state key must not be empty");
                }
                if s.ttl.is_some_and(|t| t.is_zero()) {
                    self.push(rule, apath, "set_state ttl must be greater than zero");
                }
                vec![CAction::Effect(Effect::SetState {
                    key: s.key.clone(),
                    value: s.value.clone(),
                    ttl: s.ttl,
                })]
            }
            Action::Capture(t) => vec![CAction::Effect(Effect::Capture(*t))],
            Action::Call(_) => {
                self.push(
                    rule,
                    apath,
                    "`call` is reserved: addons run above the rules, in config order, not \
                     from a rule",
                );
                Vec::new()
            }
        };
        (self.d.len() == errors_before).then_some(out)
    }

    /// The decision of a terminal action.
    fn terminal(&mut self, action: &Action, rule: Option<&RuleId>, apath: &str) -> Decision {
        match action {
            Action::Allow(a) => Decision::Allow(AllowOpts {
                upgrade_websocket: a.upgrade == Some(Upgrade::Websocket),
                private_ok: a.private_ok,
            }),
            Action::Deny(DenyArgs {
                status,
                message,
                close,
            }) => {
                let status = status.unwrap_or(DEFAULT_DENY_STATUS);
                if !(400..=599).contains(&status) {
                    self.push(
                        rule,
                        apath,
                        format!("deny status {status} must be a 4xx or 5xx code"),
                    );
                }
                Decision::Deny {
                    status,
                    message: message
                        .clone()
                        .unwrap_or_else(|| DEFAULT_DENY_MESSAGE.into()),
                    close: close.unwrap_or(true),
                }
            }
            _ => {
                if !self.input.transparent_listeners {
                    self.push(
                        rule,
                        apath,
                        "`passthrough` requires a transparent listener, which is not supported \
                         yet (issue #15)",
                    );
                }
                Decision::Passthrough
            }
        }
    }

    fn set_header(
        &mut self,
        shape: &RuleShape,
        pairs: &[(String, String)],
        rule: Option<&RuleId>,
        apath: &str,
    ) -> Vec<CAction> {
        let mut out = Vec::with_capacity(pairs.len());
        for (name, value) in pairs {
            let Some(name) = self.header_name(rule, apath, name) else {
                continue;
            };
            let Some(parts) = self.template(shape, rule, apath, &name, value) else {
                continue;
            };
            out.push(match parts.as_slice() {
                [] => CAction::Effect(Effect::SetHeader {
                    name,
                    value: String::new(),
                }),
                [Part::Lit(s)] => CAction::Effect(Effect::SetHeader {
                    name,
                    value: s.clone(),
                }),
                _ => CAction::SetHeader { name, parts },
            });
        }
        out
    }

    fn rewrite_path(
        &mut self,
        r: &RewritePathArgs,
        rule: Option<&RuleId>,
        apath: &str,
    ) -> Option<Effect> {
        let regex = match build_shared_regex(&r.pattern) {
            Ok(re) => Some(re),
            Err(e) => {
                self.push(rule, apath, format!("rewrite_path `match`: {e}"));
                None
            }
        };
        if !r.to.starts_with('/') {
            self.push(rule, apath, "rewrite_path `to` must start with `/`");
        }
        if let Some(re) = &regex {
            for problem in unknown_groups(&r.to, re) {
                self.push(rule, apath, format!("rewrite_path `to`: {problem}"));
            }
        }
        regex.map(|regex| Effect::RewritePath {
            regex,
            to: r.to.clone(),
        })
    }

    fn redirect(&mut self, r: &RedirectArgs, rule: Option<&RuleId>, apath: &str) -> Effect {
        let host = r.host.strip_suffix('.').unwrap_or(&r.host);
        let valid = !host.is_empty()
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b':'));
        if !valid {
            self.push(
                rule,
                apath,
                format!("redirect host {:?} is not a valid host name or IP", r.host),
            );
        }
        if r.port == 0 {
            self.push(rule, apath, "redirect port must not be 0");
        }
        Effect::Redirect {
            host: host.to_ascii_lowercase(),
            port: r.port,
            scheme: r.scheme,
            rewrite_host: r.rewrite_host,
        }
    }

    fn header_name(&mut self, rule: Option<&RuleId>, apath: &str, name: &str) -> Option<String> {
        if !is_token(name) {
            self.push(rule, apath, format!("invalid header name {name:?}"));
            return None;
        }
        let lower = name.to_ascii_lowercase();
        if RESERVED_HEADERS.contains(&lower.as_str()) {
            self.push(
                rule,
                apath,
                format!(
                    "header `{lower}` is managed by roxy and cannot be changed by rules{}",
                    if lower == "host" {
                        " (use `redirect: { ..., rewrite_host: true }`)"
                    } else {
                        ""
                    }
                ),
            );
            return None;
        }
        Some(lower)
    }

    /// Parse `${secret:name}` references out of a `set_header` value.
    fn template(
        &mut self,
        shape: &RuleShape,
        rule: Option<&RuleId>,
        apath: &str,
        header: &str,
        value: &str,
    ) -> Option<Vec<Part>> {
        let parts = match parse_template(value) {
            Ok(parts) => parts,
            Err(e) => {
                self.push(
                    rule,
                    apath,
                    format!("set_header {header}: {e} in {value:?}"),
                );
                return None;
            }
        };
        let mut ok = true;
        for name in secret_names(&parts) {
            if !self.input.secret_names.contains(name) {
                self.push(
                    rule,
                    apath,
                    format!("reference to undefined secret {name:?} (define it under `secrets`)"),
                );
                ok = false;
            }
        }
        if has_secrets(&parts) && shape.kind == RuleKind::Watching {
            self.push(
                rule,
                apath,
                format!(
                    "secret references are only allowed in rules decided at the request head \
                     (they set request headers); this rule watches {}",
                    shape.watched()
                ),
            );
            ok = false;
        }
        for p in &parts {
            if let Part::Lit(s) = p
                && !is_header_value(s)
            {
                self.push(
                    rule,
                    apath,
                    format!(
                        "set_header {header}: value {value:?} is not a valid header value \
                         (visible ASCII, space and tab only)"
                    ),
                );
                ok = false;
                break;
            }
        }
        ok.then_some(parts)
    }
}

impl RuleShape {
    /// Classify a rule from what its `when` reads. A rule reading a watched
    /// field watches; a `deny` reading a byte metric and no watched field
    /// takes part in the head decision and is re-checked as this exchange
    /// adds bytes; anything else is decided at the head.
    fn classify(needs: &Needs, rule: &RuleConfig) -> Self {
        let fields = needs.reads.minus(Reads::METRICS);
        let metrics = needs.reads.minus(Reads::WATCHED_FIELDS);
        let denies = rule.then.0.iter().any(|a| matches!(a, Action::Deny(_)));
        let (kind, triggers, watches) = if !fields.is_empty() {
            (
                RuleKind::Watching,
                needs.reads,
                needs.watched_names(Reads::ALL),
            )
        } else if denies && !metrics.is_empty() {
            (
                RuleKind::HeadAndWatching,
                metrics,
                needs.watched_names(Reads::METRICS),
            )
        } else {
            (RuleKind::Head, Reads::NONE, Vec::new())
        };
        Self {
            kind,
            fields,
            triggers,
            watches,
        }
    }

    fn watched(&self) -> String {
        quoted(&self.watches)
    }

    /// Why `a` is not allowed in this rule, if it is not.
    ///
    /// Head rules (including deny rules that also watch a byte metric) may
    /// use every action; their header changes apply to the request. A rule
    /// that reads a watched field runs after the request is on its way: it
    /// cannot allow or change the request. Its `set_header` /
    /// `remove_header` apply to the *response*, which is only possible when
    /// everything that can re-check the rule is known before the response
    /// head is sent (`response.status`, `response.header[..]`,
    /// `response.body.size`, `response.body.text`).
    fn illegal(&self, a: &Action) -> Option<String> {
        if self.kind != RuleKind::Watching {
            return None;
        }
        let why = || {
            format!(
                "this rule reads {}, which is known only after the request was forwarded \
                 (https://roxy-proxy.github.io/roxy-proxy/policies/overview#evaluation)",
                self.watched()
            )
        };
        match a {
            Action::Allow(_) => Some(format!(
                "`allow` is only possible in rules decided at the request head; {}. Write the \
                 allow as a head rule and this rule as a `deny`",
                why()
            )),
            Action::RewritePath(_)
            | Action::SetQuery(_)
            | Action::RemoveQuery(_)
            | Action::Redirect(_) => Some(format!(
                "`{}` changes the request, which is already on its way; {}",
                a.name(),
                why()
            )),
            Action::SetHeader(_) | Action::RemoveHeader(_) => {
                if !self.fields.intersects(Reads::BEFORE_RESPONSE_SENT) {
                    Some(format!(
                        "`{}` in this rule would change the request, which is already on its \
                         way; {}. (In a rule that reads response values it changes the \
                         response.)",
                        a.name(),
                        why()
                    ))
                } else if !self.triggers.is_subset(Reads::BEFORE_RESPONSE_SENT) {
                    Some(format!(
                        "`{}` changes the response head, so every value the rule reads must be \
                         known before the response head is sent; this rule also reads {}, which \
                         can change after that",
                        a.name(),
                        self.triggers
                            .minus(Reads::BEFORE_RESPONSE_SENT)
                            .names()
                            .join(", ")
                    ))
                } else {
                    None
                }
            }
            Action::Capture(_) => Some(format!(
                "`capture` is decided at the request head, so the whole exchange is captured \
                 from its first byte; {}. Capture in a head rule (e.g. the allow that \
                 forwards this traffic)",
                why()
            )),
            Action::Deny(_)
            | Action::Passthrough
            | Action::Tag(_)
            | Action::Log(_)
            | Action::SetState(_)
            | Action::Call(_) => None,
        }
    }
}

/// Group references in a `rewrite_path` replacement that `re` cannot
/// satisfy. The replacement syntax is the regex crate's: `$1`, `$name`,
/// `${name}`, with `$$` for a literal dollar. The crate expands a reference
/// to a group that does not exist as empty text, which would silently drop
/// part of the path, so every reference is checked here.
fn unknown_groups(to: &str, re: &Regex) -> Vec<String> {
    let mut problems = Vec::new();
    let mut rest = to;
    while let Some(i) = rest.find('$') {
        let after = &rest[i + 1..];
        let (name, consumed) = if let Some(braced) = after.strip_prefix('{') {
            match braced.find('}') {
                Some(end) => (&braced[..end], end + 2),
                None => break,
            }
        } else if let Some(stripped) = after.strip_prefix('$') {
            rest = stripped;
            continue;
        } else {
            let len = after
                .bytes()
                .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
                .count();
            (&after[..len], len)
        };
        rest = &after[consumed..];
        if name.is_empty() {
            continue;
        }
        let known = match name.parse::<usize>() {
            Ok(n) => n < re.captures_len(),
            Err(_) => re.capture_names().flatten().any(|g| g == name),
        };
        if known {
            continue;
        }
        let mut msg = format!("`${name}` refers to a group `match` does not have");
        if name.starts_with(|c: char| c.is_ascii_digit()) && name.parse::<usize>().is_err() {
            let digits: String = name.chars().take_while(char::is_ascii_digit).collect();
            let _ = write!(
                msg,
                "; a reference runs to the end of the word, write `${{{digits}}}{}`",
                &name[digits.len()..]
            );
        } else {
            let unnamed = re.capture_names().skip(1).filter(Option::is_none).count();
            let _ = write!(
                msg,
                " ({unnamed} unnamed group{}{})",
                if unnamed == 1 { "" } else { "s" },
                named_list(re)
            );
        }
        problems.push(msg);
    }
    problems
}

/// `, named: a, b` for messages; empty if the regex names no group.
fn named_list(re: &Regex) -> String {
    let names: Vec<&str> = re.capture_names().flatten().collect();
    if names.is_empty() {
        String::new()
    } else {
        format!("; named: {}", names.join(", "))
    }
}

/// Strings of an action other than `set_header` values, which must not
/// contain secret references.
fn non_header_strings(a: &Action) -> Vec<&str> {
    match a {
        Action::SetHeader(pairs) => pairs.iter().map(|(k, _)| k.as_str()).collect(),
        Action::SetQuery(pairs) => pairs
            .iter()
            .flat_map(|(k, v)| [k.as_str(), v.as_str()])
            .collect(),
        Action::RemoveHeader(v) | Action::RemoveQuery(v) => v.iter().map(String::as_str).collect(),
        Action::Deny(d) => d.message.as_deref().into_iter().collect(),
        Action::RewritePath(r) => vec![&r.pattern, &r.to],
        Action::Redirect(r) => vec![&r.host],
        Action::Tag(s) | Action::Call(s) => vec![s],
        Action::Log(l) => vec![&l.message],
        Action::SetState(s) => vec![&s.key, &s.value],
        Action::Allow(_) | Action::Passthrough | Action::Capture(_) => Vec::new(),
    }
}
