//! The compiled, immutable [`Policy`]: its types and classification. The
//! head decision and watching evaluation live in [`runtime`]; the compiler
//! in [`compiler`].

mod compiler;
mod runtime;

use std::collections::HashSet;
use std::time::Duration;

use crate::compile::Pred;
use crate::config::{DefaultDecision, MetricConfig, MetricCount, RuleConfig};
use crate::diag::{Diagnostic, RuleId};
use crate::eval::{Decision, Effect};
use crate::template::Part;
use crate::types::{Field, Reads};

/// Everything [`Policy::compile`] needs from the config.
#[derive(Debug, Clone, Copy)]
pub struct PolicyInput<'a> {
    pub rules: &'a [RuleConfig],
    pub metrics: &'a [MetricConfig],
    /// Names defined under `secrets:` (values are not needed to compile).
    pub secret_names: &'a HashSet<String>,
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

/// The parts of a [`MetricDef`] that determine what its series mean.
/// Two definitions with equal fingerprints can share series across a
/// reload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MetricFingerprint<'a> {
    count: &'a MetricCount,
    unique: Option<Field>,
    key: &'a [Field],
    window: Option<Duration>,
}

impl MetricDef {
    pub(crate) fn fingerprint(&self) -> MetricFingerprint<'_> {
        MetricFingerprint {
            count: &self.count,
            unique: self.unique,
            key: &self.key,
            window: self.window,
        }
    }
}

/// A standalone condition over head fields, compiled against a policy's
/// metrics and address lists: an addon's `when`.
///
/// It may not read a watched field, nor `body.text`: whatever it guards
/// owns the body stream, so nothing reads the body before it does.
#[derive(Debug, Clone)]
pub struct Condition {
    pred: Pred,
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

/// How a rule is classified from what its `when` reads: when it runs and
/// what re-checks it. Shared by the compiler's action checks and the
/// compiled rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuleShape {
    pub kind: RuleKind,
    /// Watched fields read: the rule is decidable once all are known.
    pub fields: Reads,
    /// Changes that re-check the rule (fields plus byte metrics).
    pub triggers: Reads,
    /// What makes it watch, as written; empty for a head rule.
    pub watches: Vec<String>,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    id: RuleId,
    when: Option<Pred>,
    actions: Box<[CAction]>,
    shape: RuleShape,
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

impl Policy {
    /// Compile rules and metrics. Returns every problem found.
    pub fn compile(input: &PolicyInput<'_>) -> Result<Policy, Vec<Diagnostic>> {
        let mut c = compiler::PolicyCompiler::new(input);
        let metrics = c.metrics();
        let rules = c.rules();
        let (needs, diagnostics) = c.finish();
        if !diagnostics.is_empty() {
            return Err(diagnostics);
        }
        let head = (0..rules.len())
            .filter(|&i| rules[i].shape.kind.at_head())
            .collect();
        let watching: Box<[usize]> = (0..rules.len())
            .filter(|&i| rules[i].shape.kind.watches())
            .collect();
        let watch_triggers = watching
            .iter()
            .fold(Reads::NONE, |acc, &i| acc | rules[i].shape.triggers);
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
            needs_request_body: needs.request_body,
            needs_response_body: needs.response_body,
            default: input.default,
            default_id: RuleId::new(RuleId::DEFAULT),
            fail_closed_id: RuleId::new(RuleId::FAIL_CLOSED),
        })
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
        self.rules
            .iter()
            .any(|r| r.shape.fields.intersects(Reads::WS))
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
                kind: r.shape.kind,
                watches: r.shape.watches.clone(),
                triggers: r.shape.triggers,
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
