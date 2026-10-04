//! The compiled, immutable [`Policy`]: rule classification (head vs
//! watching), the head decision, and watching evaluation.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use regex::Regex;

use crate::compile::{Env, Needs, Pred, build_shared_regex, compile};
use crate::config::{
    Action, DefaultDecision, DenyArgs, MetricConfig, MetricCount, RuleConfig, Upgrade,
};
use crate::diag::{Diagnostic, RuleId};
use crate::eval::{
    AllowOpts, DEFAULT_DENY_MESSAGE, DEFAULT_DENY_STATUS, Decision, Effect, EvalContext,
    FailClosedReason, Outcome, Scope, WatchOutcome,
};
use crate::types::{Field, Reads, is_token};
use crate::view::FlowView;

/// Everything [`Policy::compile`] needs from the config.
#[derive(Debug, Clone, Copy)]
pub struct PolicyInput<'a> {
    pub rules: &'a [RuleConfig],
    pub metrics: &'a [MetricConfig],
    /// Names defined under `secrets:` (values are not needed to compile).
    pub secret_names: &'a HashSet<String>,
    /// Names defined under `addons:`.
    pub addon_names: &'a HashSet<String>,
    /// Names defined under `address_lists:` (for `ip in @name`; the data
    /// stays with the proxy).
    pub address_lists: &'a HashSet<String>,
    /// Whether any transparent listener exists. Always false in M1, which
    /// makes `passthrough` a compile error.
    pub transparent_listeners: bool,
    /// The top-level `default:` (deny unless the config says `allow`).
    pub default: DefaultDecision,
}

/// A compiled metric definition. Counting is the proxy's job; this
/// carries the shape and the compiled `where` filter, which reads head
/// fields only, so whether an exchange counts (and its series key) is
/// fixed at the request head.
#[derive(Debug, Clone)]
pub struct MetricDef {
    pub id: String,
    pub count: MetricCount,
    /// For `unique(<field>)`: the field whose distinct values are counted.
    pub unique: Option<Field>,
    /// Series key fields; empty = one global series.
    pub key: Vec<Field>,
    pub window: Option<Duration>,
    filter: Option<Pred>,
}

impl MetricDef {
    /// Whether a flow passes this metric's `where` filter (absent = always).
    /// `Err` if the filter needs an unavailable input; the proxy must then
    /// fail the flow closed rather than skip counting it.
    pub fn matches(&self, view: &dyn FlowView) -> Result<bool, FailClosedReason> {
        self.filter
            .as_ref()
            .map_or(Ok(true), |p| Scope::new(view, &[], &[]).check(p))
    }
}

/// A `set_header` value: literal text and `${secret:name}` references.
#[derive(Debug, Clone)]
enum Part {
    Lit(String),
    Secret(String),
}

#[derive(Debug, Clone)]
enum CAction {
    Effect(Effect),
    SetHeader { name: String, parts: Vec<Part> },
    Tag(String),
    Terminal(Decision),
}

/// When a rule runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleKind {
    /// Reads only head values: decided at the request head.
    Head,
    /// Reads a watched field (`body.bytes`, `response.*`, `ws.*`): skipped
    /// at the head, checked after forwarding when what it reads is known.
    Watching,
    /// A `deny` rule that reads a byte metric (`request_bytes` /
    /// `response_bytes`) and no watched field: takes part in the head
    /// decision like a head rule, and is re-checked as this exchange adds
    /// bytes to the metric.
    HeadAndWatching,
}

impl RuleKind {
    /// Whether the rule takes part in the head decision.
    pub fn at_head(self) -> bool {
        matches!(self, Self::Head | Self::HeadAndWatching)
    }

    /// Whether the rule is re-checked after forwarding.
    pub fn watches(self) -> bool {
        matches!(self, Self::Watching | Self::HeadAndWatching)
    }
}

/// How one rule was classified, for `roxy check` and `roxy rule test`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleInfo {
    pub id: RuleId,
    pub kind: RuleKind,
    /// What makes it watch: the watched fields and byte metrics it reads,
    /// as written (`body.bytes`, `metric.egress (request_bytes)`). Empty
    /// for a head rule.
    pub watches: Vec<String>,
    /// Events that re-check it (empty for a head rule).
    pub triggers: Reads,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    id: RuleId,
    when: Option<Pred>,
    actions: Box<[CAction]>,
    kind: RuleKind,
    /// Watched fields read: the rule is decidable once all are known.
    fields: Reads,
    /// Changes that re-check the rule (fields plus byte metrics).
    triggers: Reads,
    watches: Vec<String>,
}

/// A compiled policy: one ordered rule list, classified, plus metric
/// definitions. Immutable; the proxy shares it behind `Arc` and swaps it on
/// reload.
#[derive(Debug, Clone)]
pub struct Policy {
    rules: Vec<CompiledRule>,
    /// Indices of rules taking part in the head decision, in list order.
    head: Box<[usize]>,
    /// Indices of watching rules, in list order.
    watching: Box<[usize]>,
    /// Union of the watching rules' triggers: an event outside it costs one
    /// mask test.
    watch_triggers: Reads,
    /// Union of the byte-metric bits of the defined metrics.
    byte_metrics: Reads,
    metrics: Vec<MetricDef>,
    needs_request_body: bool,
    needs_response_body: bool,
    default: DefaultDecision,
    default_id: RuleId,
    fail_closed_id: RuleId,
}

const SECRET_OPEN: &str = "${secret:";

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

/// Valid header value bytes: visible ASCII, SP, HTAB.
pub(crate) fn is_header_value(s: &str) -> bool {
    s.bytes().all(|b| b == b'\t' || (b' '..=b'~').contains(&b))
}

/// Per-exchange state of the watching rules: which ones have fired (their
/// non-terminal effects apply once) and the tags set so far. Create with
/// [`Policy::watch_state`] after the head decision.
#[derive(Debug, Clone, Default)]
pub struct WatchState {
    fired: Vec<bool>,
    /// Tags visible to watching rules: the head's, plus those set by
    /// watching rules that fired.
    pub tags: Vec<String>,
    stopped: bool,
}

impl WatchState {
    /// Whether a watching evaluation has stopped the exchange. Every later
    /// evaluation returns `None`.
    pub fn is_stopped(&self) -> bool {
        self.stopped
    }
}

/// Keep only the effects that still apply when the exchange is refused.
fn refused_effects(effects: &mut Vec<Effect>) {
    effects.retain(|e| matches!(e, Effect::Log { .. } | Effect::SetState { .. }));
}

impl Policy {
    /// Compile rules and metrics. Returns every problem found.
    pub fn compile(input: &PolicyInput<'_>) -> Result<Policy, Vec<Diagnostic>> {
        let mut c = PolicyCompiler {
            input,
            d: Vec::new(),
            needs: Needs::default(),
        };
        let metrics = c.metrics();
        let rules = c.rules();
        if !c.d.is_empty() {
            return Err(c.d);
        }
        let head = (0..rules.len())
            .filter(|&i| rules[i].kind.at_head())
            .collect();
        let watching: Box<[usize]> = (0..rules.len())
            .filter(|&i| rules[i].kind.watches())
            .collect();
        let watch_triggers = watching
            .iter()
            .fold(Reads::NONE, |acc, &i| acc | rules[i].triggers);
        let byte_metrics = metrics
            .iter()
            .fold(Reads::NONE, |acc, m| acc | metric_reads(&m.count));
        Ok(Policy {
            rules,
            head,
            watching,
            watch_triggers,
            byte_metrics,
            metrics,
            needs_request_body: c.needs.request_body,
            needs_response_body: c.needs.response_body,
            default: input.default,
            default_id: RuleId::new(RuleId::DEFAULT),
            fail_closed_id: RuleId::new(RuleId::FAIL_CLOSED),
        })
    }

    /// The head decision: the forwarding decision at the request
    /// head.
    ///
    /// Every rule that takes part in it ([`RuleKind::at_head`]) is
    /// evaluated, top to bottom; rules that read a watched value are
    /// skipped (not false). The decision does not depend on order:
    ///
    /// * if any matching rule denies, the request is denied
    ///   (`terminal_rule` = the first matching deny in list order);
    /// * else if any matching rule allows, it is allowed (`terminal_rule` =
    ///   the first matching allow, whose options — `upgrade`, `private_ok`
    ///   — are the only ones granted; options are never merged);
    /// * else the `default:` applies (`_default`; an implicit allow grants
    ///   no options).
    ///
    /// Tags set by a matching rule are visible to the rules below it, and
    /// `state["k"]` sees earlier `set_state` effects. Effects of every
    /// matching rule are returned in list order when the request is
    /// allowed; when it is denied only `log` and `set_state` remain (tags
    /// are in [`Outcome::tags`]).
    ///
    /// Fail closed: if evaluating *any* head rule reaches a metric
    /// the view reports unavailable, an address list it cannot answer for,
    /// a missing value under an operator that cannot answer for `null`, an
    /// uninspectable body, or a `set_header` secret that cannot be resolved,
    /// the result is [`Decision::fail_closed`] (503, close) with
    /// `terminal_rule = "_fail_closed"`, whatever else matched.
    ///
    /// Allocation: nothing is allocated for rules that do not match, except
    /// what the view itself returns (e.g. `header.all`).
    pub fn evaluate_head(&self, view: &dyn FlowView, ctx: &EvalContext<'_>) -> Outcome {
        let mut tags: Vec<String> = ctx.initial_tags.to_vec();
        let mut effects: Vec<Effect> = Vec::new();
        let mut matched: Vec<RuleId> = Vec::new();
        let mut deny: Option<(usize, &Decision)> = None;
        let mut allow: Option<(usize, &Decision)> = None;
        for &i in &self.head {
            let rule = &self.rules[i];
            let hit = match &rule.when {
                None => Ok(true),
                Some(p) => Scope::new(view, &tags, &effects).check(p),
            };
            match hit {
                Ok(true) => {}
                Ok(false) => continue,
                Err(reason) => return self.fail(reason, matched, effects, tags),
            }
            matched.push(rule.id.clone());
            for action in &rule.actions {
                match action {
                    CAction::Effect(e) => effects.push(e.clone()),
                    CAction::Tag(t) => {
                        if !tags.contains(t) {
                            tags.push(t.clone());
                        }
                    }
                    CAction::SetHeader { name, parts } => match render(parts, ctx) {
                        Ok(value) => effects.push(Effect::SetHeader {
                            name: name.clone(),
                            value,
                        }),
                        Err(reason) => return self.fail(reason, matched, effects, tags),
                    },
                    CAction::Terminal(d @ Decision::Allow(_)) => {
                        allow.get_or_insert((i, d));
                    }
                    // `passthrough` is rejected by the compiler; were it
                    // ever reached it must not forward: it ranks with deny.
                    CAction::Terminal(d) => {
                        deny.get_or_insert((i, d));
                    }
                }
            }
        }
        let (decision, terminal_rule) = match (deny, allow) {
            // Deny wins; otherwise the first matching allow.
            (Some((i, d)), _) | (None, Some((i, d))) => (d.clone(), self.rules[i].id.clone()),
            (None, None) => (
                match self.default {
                    DefaultDecision::Deny => Decision::default_deny(),
                    DefaultDecision::Allow => Decision::Allow(AllowOpts::default()),
                },
                self.default_id.clone(),
            ),
        };
        if !decision.is_allow() {
            refused_effects(&mut effects);
        }
        Outcome {
            decision,
            matched,
            terminal_rule,
            fail_closed_reason: None,
            effects,
            tags,
        }
    }

    fn fail(
        &self,
        reason: FailClosedReason,
        matched: Vec<RuleId>,
        mut effects: Vec<Effect>,
        tags: Vec<String>,
    ) -> Outcome {
        refused_effects(&mut effects);
        Outcome {
            decision: Decision::fail_closed(),
            matched,
            terminal_rule: self.fail_closed_id.clone(),
            fail_closed_reason: Some(reason),
            effects,
            tags,
        }
    }

    /// Per-exchange watching state, starting from the tags the head
    /// decision produced.
    pub fn watch_state(&self, head_tags: &[String]) -> WatchState {
        WatchState {
            fired: vec![false; self.watching.len()],
            tags: head_tags.to_vec(),
            stopped: false,
        }
    }

    /// Whether an event changing `changed` can re-check any watching rule.
    /// One mask test; callers use it to skip per-chunk work entirely.
    pub fn watches(&self, changed: Reads) -> bool {
        self.watch_triggers.intersects(changed)
    }

    /// Re-check the watching rules after a value changed.
    ///
    /// `changed` is what just became known or changed (e.g.
    /// [`Reads::BODY_BYTES`] for a request body chunk, plus
    /// [`Reads::METRIC_REQUEST_BYTES`] if this exchange's bytes were just
    /// added to such a metric); `known` is every watched field known so far
    /// (a rule is only checked once everything it reads is known). Rules
    /// whose triggers intersect `changed` are checked top to bottom; the
    /// first matching deny stops the exchange. A watching rule's
    /// non-terminal effects apply once, the first time it matches; it is not
    /// checked again after that.
    ///
    /// Returns `None` when nothing matched (no allocation in that case:
    /// the steady-state per-chunk path). `Some` with `stop` set means the
    /// exchange must stop: a matching deny, or any fail-closed input (an
    /// error never lets the exchange continue). After a stop every call
    /// returns `None`.
    pub fn evaluate_watching(
        &self,
        changed: Reads,
        known: Reads,
        st: &mut WatchState,
        view: &dyn FlowView,
        ctx: &EvalContext<'_>,
    ) -> Option<WatchOutcome> {
        if st.stopped || !self.watch_triggers.intersects(changed) {
            return None;
        }
        let mut out: Option<WatchOutcome> = None;
        for (k, &i) in self.watching.iter().enumerate() {
            let rule = &self.rules[i];
            if st.fired[k] || !rule.triggers.intersects(changed) || !rule.fields.is_subset(known) {
                continue;
            }
            let pending: &[Effect] = out.as_ref().map_or(&[], |o| &o.effects);
            let hit = match &rule.when {
                None => Ok(true),
                Some(p) => Scope::new(view, &st.tags, pending).check(p),
            };
            let o = out.get_or_insert_with(WatchOutcome::default);
            match hit {
                Ok(true) => {}
                Ok(false) => continue,
                Err(reason) => {
                    return Some(self.watch_stop(st, o, None, Some(reason)));
                }
            }
            st.fired[k] = true;
            o.matched.push(rule.id.clone());
            for action in &rule.actions {
                match action {
                    CAction::Effect(e) => o.effects.push(e.clone()),
                    CAction::Tag(t) => {
                        if !st.tags.contains(t) {
                            st.tags.push(t.clone());
                            o.tags.push(t.clone());
                        }
                    }
                    CAction::SetHeader { name, parts } => match render(parts, ctx) {
                        Ok(value) => o.effects.push(Effect::SetHeader {
                            name: name.clone(),
                            value,
                        }),
                        Err(reason) => {
                            return Some(self.watch_stop(st, o, None, Some(reason)));
                        }
                    },
                    CAction::Terminal(Decision::Deny {
                        status,
                        message,
                        close,
                    }) => {
                        let d = Decision::Deny {
                            status: *status,
                            message: message.clone(),
                            close: *close,
                        };
                        return Some(self.watch_stop(st, o, Some((rule.id.clone(), d)), None));
                    }
                    // `allow` cannot appear in a watching rule (compile
                    // error) and `passthrough` is rejected; never continue
                    // on either: fail closed.
                    CAction::Terminal(_) => {
                        return Some(self.watch_stop(
                            st,
                            o,
                            None,
                            Some(FailClosedReason::Unsupported(rule.id.to_string())),
                        ));
                    }
                }
            }
        }
        out.filter(|o| !o.matched.is_empty())
    }

    fn watch_stop(
        &self,
        st: &mut WatchState,
        o: &mut WatchOutcome,
        deny: Option<(RuleId, Decision)>,
        reason: Option<FailClosedReason>,
    ) -> WatchOutcome {
        st.stopped = true;
        let mut o = std::mem::take(o);
        refused_effects(&mut o.effects);
        match (deny, reason) {
            (Some((id, d)), _) => {
                o.stop = Some(d);
                o.terminal_rule = Some(id);
            }
            (None, reason) => {
                o.stop = Some(Decision::fail_closed());
                o.terminal_rule = Some(self.fail_closed_id.clone());
                o.fail_closed_reason = reason;
            }
        }
        o
    }

    /// Whether any rule or metric filter reads `body.text`.
    pub fn needs_request_body(&self) -> bool {
        self.needs_request_body
    }

    /// Whether any rule reads `response.body.text`.
    pub fn needs_response_body(&self) -> bool {
        self.needs_response_body
    }

    /// The byte-metric bits ([`Reads::METRIC_REQUEST_BYTES`],
    /// [`Reads::METRIC_RESPONSE_BYTES`]) of the defined metrics: whether
    /// bytes must be recorded as they stream.
    pub fn byte_metrics(&self) -> Reads {
        self.byte_metrics
    }

    /// Whether any rule reads `ws.*`: the proxy then decodes and checks
    /// every WebSocket message.
    pub fn reads_ws(&self) -> bool {
        self.rules.iter().any(|r| r.fields.intersects(Reads::WS))
    }

    /// Rule ids in config order.
    pub fn rule_ids(&self) -> impl Iterator<Item = &RuleId> {
        self.rules.iter().map(|r| &r.id)
    }

    /// Every rule's classification, in config order.
    pub fn rule_info(&self) -> Vec<RuleInfo> {
        self.rules
            .iter()
            .map(|r| RuleInfo {
                id: r.id.clone(),
                kind: r.kind,
                watches: r.watches.clone(),
                triggers: r.triggers,
            })
            .collect()
    }

    pub fn metric_defs(&self) -> &[MetricDef] {
        &self.metrics
    }

    /// The `default:` decision.
    pub fn default_decision(&self) -> DefaultDecision {
        self.default
    }

    /// Number of rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

/// The watched bits a read of a metric counting `count` carries.
fn metric_reads(count: &MetricCount) -> Reads {
    match count {
        MetricCount::RequestBytes => Reads::METRIC_REQUEST_BYTES,
        MetricCount::ResponseBytes => Reads::METRIC_RESPONSE_BYTES,
        _ => Reads::NONE,
    }
}

/// Substitute secrets into a `set_header` value and validate the result.
fn render(parts: &[Part], ctx: &EvalContext<'_>) -> Result<String, FailClosedReason> {
    let mut out = String::new();
    for part in parts {
        match part {
            Part::Lit(s) => out.push_str(s),
            Part::Secret(name) => {
                let value = (ctx.secrets)(name)
                    .ok_or_else(|| FailClosedReason::SecretMissing(name.clone()))?;
                if !is_header_value(&value) {
                    return Err(FailClosedReason::SecretInvalid(name.clone()));
                }
                out.push_str(&value);
            }
        }
    }
    Ok(out)
}

struct PolicyCompiler<'i, 'a> {
    input: &'i PolicyInput<'a>,
    d: Vec<Diagnostic>,
    needs: Needs,
}

fn is_ident(s: &str) -> bool {
    let mut b = s.bytes();
    b.next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
        && b.all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

impl PolicyCompiler<'_, '_> {
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

    #[allow(clippy::too_many_lines)]
    fn metrics(&mut self) -> Vec<MetricDef> {
        let mut out = Vec::new();
        let mut ids: HashMap<&str, usize> = HashMap::new();
        let input = self.input;
        for (i, m) in input.metrics.iter().enumerate() {
            let path = format!("metrics[{i}]");
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
            if m.window.is_some_and(|w| w.is_zero()) {
                self.push(
                    None,
                    format!("{path}.window"),
                    "window must be greater than zero",
                );
            }
            let field = |this: &mut Self, name: &str, at: String, what: &str| -> Option<Field> {
                match Field::from_name(name) {
                    Some(f) if f.is_head() => Some(f),
                    Some(f) => {
                        this.push(
                            None,
                            at,
                            format!(
                                "`{f}` is known only after forwarding; metric {what} fields must \
                                 be head fields (https://roxy-proxy.github.io/roxy-proxy/policies/rate-limits#metrics)"
                            ),
                        );
                        None
                    }
                    None => {
                        this.push(
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
            };
            let key: Vec<Field> = m
                .key
                .iter()
                .enumerate()
                .filter_map(|(j, k)| field(self, k, format!("{path}.key[{j}]"), "key"))
                .collect();
            let unique = match &m.count {
                MetricCount::Unique(f) => field(self, f, format!("{path}.count"), "unique()"),
                _ => None,
            };
            let filter = m.where_.as_ref().and_then(|w| {
                let at = format!("{path}.where");
                let (pred, needs) = self.expr(None, at.clone(), w.as_str())?;
                if needs.reads.intersects(Reads::WATCHED_FIELDS) {
                    self.push(
                        None,
                        at,
                        format!(
                            "a metric's `where` may only read head fields, because whether an \
                             exchange counts is decided at the request head; it reads {} \
                             (https://roxy-proxy.github.io/roxy-proxy/policies/rate-limits#metrics)",
                            needs
                                .watched
                                .iter()
                                .map(|n| format!("`{n}`"))
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    );
                    return None;
                }
                Some(pred)
            });
            out.push(MetricDef {
                id: m.id.clone(),
                count: m.count.clone(),
                unique,
                key,
                window: m.window,
                filter,
            });
        }
        out
    }

    fn rules(&mut self) -> Vec<CompiledRule> {
        let mut out = Vec::new();
        let mut seen: HashMap<&str, usize> = HashMap::new();
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
            let fields = needs.reads.minus(Reads::METRICS);
            let metrics = needs.reads.minus(Reads::WATCHED_FIELDS);
            let denies = rule.then.0.iter().any(|a| matches!(a, Action::Deny(_)));
            let (kind, triggers, watches) = if !fields.is_empty() {
                (RuleKind::Watching, needs.reads, needs.watched)
            } else if denies && !metrics.is_empty() {
                (RuleKind::HeadAndWatching, metrics, needs.watched)
            } else {
                (RuleKind::Head, Reads::NONE, Vec::new())
            };
            let rcx = RuleCx {
                kind,
                fields,
                triggers,
                watches: &watches,
            };
            let actions = self.actions(rule, &rid, &path, &rcx);
            out.push(CompiledRule {
                id: rid,
                when,
                actions: actions.into(),
                kind,
                fields,
                triggers,
                watches,
            });
        }
        out
    }

    fn actions(
        &mut self,
        rule: &RuleConfig,
        rid: &RuleId,
        path: &str,
        rcx: &RuleCx<'_>,
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
            if let Some(a) = self.action(rcx, action, rid, &apath) {
                out.extend(a);
            }
        }
        out
    }

    /// Check one action; `None` if it has errors (already reported).
    #[allow(clippy::too_many_lines)]
    fn action(
        &mut self,
        rcx: &RuleCx<'_>,
        action: &Action,
        rid: &RuleId,
        apath: &str,
    ) -> Option<Vec<CAction>> {
        let errors_before = self.d.len();
        let rule = Some(rid);
        if let Some(msg) = rcx.illegal(action) {
            self.push(rule, apath, msg);
        }
        for s in non_header_strings(action) {
            if s.contains(SECRET_OPEN) {
                self.push(
                    rule,
                    apath,
                    format!(
                        "secret references are only allowed in `set_header` values, not in \
                         `{}`",
                        action.name()
                    ),
                );
                break;
            }
        }
        let out = match action {
            Action::Allow(a) => {
                let opts = AllowOpts {
                    upgrade_websocket: a.upgrade == Some(Upgrade::Websocket),
                    private_ok: a.private_ok,
                };
                vec![CAction::Terminal(Decision::Allow(opts))]
            }
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
                vec![CAction::Terminal(Decision::Deny {
                    status,
                    message: message
                        .clone()
                        .unwrap_or_else(|| DEFAULT_DENY_MESSAGE.into()),
                    close: close.unwrap_or(true),
                })]
            }
            Action::Passthrough => {
                if !self.input.transparent_listeners {
                    self.push(
                        rule,
                        apath,
                        "`passthrough` requires a transparent listener, which is not supported \
                         yet (issue #15)",
                    );
                }
                vec![CAction::Terminal(Decision::Passthrough)]
            }
            Action::SetHeader(pairs) => {
                let mut v = Vec::with_capacity(pairs.len());
                for (name, value) in pairs {
                    let Some(name) = self.header_name(rule, apath, name) else {
                        continue;
                    };
                    if let Some(parts) = self.template(rcx, rule, apath, &name, value) {
                        v.push(match parts.as_slice() {
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
                }
                v
            }
            Action::RemoveHeader(names) => names
                .iter()
                .filter_map(|n| self.header_name(rule, apath, n))
                .map(|n| CAction::Effect(Effect::RemoveHeader(n)))
                .collect(),
            Action::RewritePath(r) => {
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
                regex.map_or_else(Vec::new, |regex: Arc<Regex>| {
                    vec![CAction::Effect(Effect::RewritePath {
                        regex,
                        to: r.to.clone(),
                    })]
                })
            }
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
            Action::Redirect(r) => {
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
                vec![CAction::Effect(Effect::Redirect {
                    host: host.to_ascii_lowercase(),
                    port: r.port,
                    scheme: r.scheme,
                    rewrite_host: r.rewrite_host,
                })]
            }
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
            Action::Call(name) => {
                if !self.input.addon_names.contains(name) {
                    self.push(
                        rule,
                        apath,
                        format!("`call` names undefined addon {name:?}"),
                    );
                }
                vec![CAction::Effect(Effect::CallAddon(name.clone()))]
            }
        };
        (self.d.len() == errors_before).then_some(out)
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
        rcx: &RuleCx<'_>,
        rule: Option<&RuleId>,
        apath: &str,
        header: &str,
        value: &str,
    ) -> Option<Vec<Part>> {
        let mut parts = Vec::new();
        let mut rest = value;
        let mut ok = true;
        while let Some(i) = rest.find("${") {
            if i > 0 {
                parts.push(Part::Lit(rest[..i].to_owned()));
            }
            let after = &rest[i..];
            let Some(body) = after.strip_prefix(SECRET_OPEN) else {
                self.push(
                    rule,
                    apath,
                    format!(
                        "set_header {header}: unknown interpolation in {value:?}; only \
                         `${{secret:name}}` is supported"
                    ),
                );
                return None;
            };
            let Some(end) = body.find('}') else {
                self.push(
                    rule,
                    apath,
                    format!("set_header {header}: unterminated `${{secret:` in {value:?}"),
                );
                return None;
            };
            let name = &body[..end];
            if name.is_empty() {
                self.push(
                    rule,
                    apath,
                    format!("set_header {header}: empty secret name"),
                );
                ok = false;
            } else if !self.input.secret_names.contains(name) {
                self.push(
                    rule,
                    apath,
                    format!("reference to undefined secret {name:?} (define it under `secrets`)"),
                );
                ok = false;
            }
            parts.push(Part::Secret(name.to_owned()));
            rest = &body[end + 1..];
        }
        if !rest.is_empty() {
            parts.push(Part::Lit(rest.to_owned()));
        }
        if parts.iter().any(|p| matches!(p, Part::Secret(_))) && rcx.kind == RuleKind::Watching {
            self.push(
                rule,
                apath,
                format!(
                    "secret references are only allowed in rules decided at the request head \
                     (they set request headers); this rule watches {}",
                    rcx.watched()
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

/// What the action-legality checks need to know about a rule.
struct RuleCx<'a> {
    kind: RuleKind,
    /// Watched fields the rule reads.
    fields: Reads,
    triggers: Reads,
    watches: &'a [String],
}

impl RuleCx<'_> {
    fn watched(&self) -> String {
        self.watches
            .iter()
            .map(|n| format!("`{n}`"))
            .collect::<Vec<_>>()
            .join(", ")
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
