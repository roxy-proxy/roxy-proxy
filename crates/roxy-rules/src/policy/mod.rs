//! The compiled, immutable [`Policy`]: its types and classification. The
//! admission decision and in-flight evaluation live in [`runtime`]; the
//! compiler in [`compiler`].

mod compiler;
mod runtime;

use std::collections::HashSet;
use std::time::Duration;

use crate::compile::Pred;
use crate::config::{MetricConfig, MetricCount, RuleConfig};
use crate::diag::{Diagnostic, RuleId};
use crate::eval::{Decision, Deny, Effect, InFlightEffect};
use crate::template::Part;
use crate::types::{Field, InFlightValue, Reads};

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
}

/// A compiled metric definition. Counting is the proxy's job; this
/// carries the shape and the compiled `where` filter, which reads admission
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
    /// Series this metric alone may hold; `None` = the store's shared limit.
    pub max_keys: Option<usize>,
    filter: Option<Pred>,
    /// The `where` as written, for [`MetricDef::fingerprint`].
    filter_src: Option<String>,
}

/// The identity of a metric across reloads: everything that decides which
/// flows a series counts and what its value means. Two definitions with
/// equal fingerprints keep each other's series; any other difference starts
/// the metric empty, since a count built under one definition would be
/// wrong under the other.
///
/// * `id`: how rules name the metric.
/// * `count`: what is counted (and, for `unique(..)`, of which field).
/// * `filter`: the `where` source. A narrowed filter must not inherit
///   counts from flows it excludes, or `metric.x >= N` denies on stale
///   totals. Compared as text, so a rewrite of an equivalent expression
///   also starts fresh (the fail-closed direction).
/// * `key`: which flows share a series.
/// * `window`: how long a recorded event counts.
///
/// `max_keys` is deliberately absent: it bounds how many series exist, not
/// what any of them means, and carried series may exceed a lowered bound
/// until they expire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricFingerprint<'a> {
    id: &'a str,
    count: &'a MetricCount,
    filter: Option<&'a str>,
    key: &'a [Field],
    window: Option<Duration>,
}

impl MetricDef {
    /// See [`MetricFingerprint`].
    pub fn fingerprint(&self) -> MetricFingerprint<'_> {
        MetricFingerprint {
            id: &self.id,
            count: &self.count,
            filter: self.filter_src.as_deref(),
            key: &self.key,
            window: self.window,
        }
    }
}

/// A standalone condition over admission fields, compiled against a policy's
/// metrics and address lists: an addon's `when`.
///
/// It may not read an in-flight field, nor `body.text`: whatever it guards
/// owns the body stream, so nothing reads the body before it does.
#[derive(Debug, Clone)]
pub struct Condition {
    pred: Pred,
}

/// An action as it runs at admission.
#[derive(Debug, Clone)]
enum CAction {
    Effect(Effect),
    SetHeader { name: String, parts: Vec<Part> },
    Sign(SignSpec),
    Tag(String),
    Terminal(Decision),
}

/// `sign: aws_sigv4` before its credentials are resolved.
#[derive(Debug, Clone)]
struct SignSpec {
    service: String,
    region: String,
    access_key_id: Vec<Part>,
    secret_access_key: Vec<Part>,
    session_token: Option<Vec<Part>>,
    unsigned_payload: bool,
}

/// An action as it runs after the request was forwarded. There is no
/// allow and nothing that changes the request; the compiler reports an
/// action it cannot express here.
#[derive(Debug, Clone)]
enum InFlightAction {
    Effect(InFlightEffect),
    Tag(String),
    Deny(Deny),
}

impl InFlightAction {
    /// What an admission action still does when its rule fires in flight
    /// on a byte metric: the deny, and the effects that apply whatever the
    /// outcome. Its request changes happened at admission.
    fn after_forwarding(a: &CAction) -> Option<Self> {
        match a {
            CAction::Terminal(Decision::Deny(d)) => Some(Self::Deny(d.clone())),
            CAction::Tag(t) => Some(Self::Tag(t.clone())),
            CAction::Effect(Effect::Log { level, message }) => {
                Some(Self::Effect(InFlightEffect::Log {
                    level: *level,
                    message: message.clone(),
                }))
            }
            CAction::Effect(Effect::SetState { key, value, ttl }) => {
                Some(Self::Effect(InFlightEffect::SetState {
                    key: key.clone(),
                    value: value.clone(),
                    ttl: *ttl,
                }))
            }
            CAction::Terminal(Decision::Allow(_))
            | CAction::SetHeader { .. }
            | CAction::Sign(_)
            | CAction::Effect(_) => None,
        }
    }
}

/// When a rule runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleKind {
    /// Reads only admission values: decided before the request is
    /// forwarded.
    Admission,
    /// Reads an in-flight field (`body.bytes`, `response.*`, `ws.*`):
    /// skipped at admission, checked after forwarding when what it reads
    /// is known.
    InFlight,
    /// A `deny` rule that reads a byte metric (`request_bytes` /
    /// `response_bytes`) and no in-flight field: takes part in the
    /// admission decision like an admission rule, and is re-checked as
    /// this exchange adds bytes to the metric.
    AdmissionAndInFlight,
}

impl RuleKind {
    /// Whether the rule takes part in the admission decision.
    pub fn at_admission(self) -> bool {
        matches!(self, Self::Admission | Self::AdmissionAndInFlight)
    }

    /// Whether the rule is re-checked after forwarding.
    pub fn in_flight(self) -> bool {
        matches!(self, Self::InFlight | Self::AdmissionAndInFlight)
    }
}

/// How one rule was classified, for `roxy check` and `roxy rule test`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleInfo {
    pub id: RuleId,
    pub kind: RuleKind,
    /// What puts it in flight: the in-flight fields and byte metrics it
    /// reads, as written (`body.bytes`, `metric.egress (request_bytes)`).
    /// Empty for an admission rule.
    pub in_flight_reads: Vec<String>,
    /// Events that re-check it (empty for an admission rule).
    pub triggers: Reads,
}

/// How a rule is classified from what its `when` reads: when it runs and
/// what re-checks it. Shared by the compiler's action checks and the
/// compiled rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuleShape {
    pub kind: RuleKind,
    /// In-flight fields read: the rule is decidable once all are known.
    pub fields: Reads,
    /// Changes that re-check the rule (fields plus byte metrics).
    pub triggers: Reads,
    /// What puts it in flight, as written; empty for an admission rule.
    pub in_flight_reads: Vec<String>,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    id: RuleId,
    when: Option<Pred>,
    /// Actions when the rule takes part in the admission decision; empty
    /// for a rule that only runs in flight.
    admission: Box<[CAction]>,
    /// Actions when the rule fires after forwarding; empty for an
    /// admission rule.
    in_flight: Box<[InFlightAction]>,
    /// Has a `quarantine` action: its deny is an ordinary 403 that closes,
    /// and the trip is recorded as soon as the rule matches, so a
    /// fail-closed later in the pass, or in this rule's own earlier
    /// actions, still trips the process.
    quarantines: bool,
    shape: RuleShape,
}

/// A compiled policy: one ordered rule list, classified, plus metric
/// definitions. Immutable; the proxy shares it behind `Arc` and swaps it on
/// reload.
#[derive(Debug, Clone)]
pub struct Policy {
    rules: Vec<CompiledRule>,
    /// Indices of rules taking part in the admission decision, in list
    /// order.
    admission: Box<[usize]>,
    /// Indices of in-flight rules, in list order.
    in_flight: Box<[usize]>,
    /// Union of the in-flight rules' triggers: an event outside it costs
    /// one mask test.
    in_flight_triggers: Reads,
    /// Union of the byte-metric bits of the defined metrics.
    byte_metrics: Reads,
    metrics: Vec<MetricDef>,
    needs_request_body: bool,
    needs_response_body: bool,
    default_id: RuleId,
    fail_closed_id: RuleId,
}

/// Valid header value bytes: visible ASCII, SP, HTAB.
pub(crate) fn is_header_value(s: &str) -> bool {
    s.bytes().all(|b| b == b'\t' || (b' '..=b'~').contains(&b))
}

/// Per-exchange state of the in-flight rules: which ones have fired (their
/// non-terminal effects apply once) and the tags set so far. Create with
/// [`Policy::in_flight_state`] after the admission decision.
#[derive(Debug, Clone, Default)]
pub struct InFlightState {
    fired: Vec<bool>,
    /// Tags visible to in-flight rules: the admission decision's, plus
    /// those set by in-flight rules that fired.
    pub tags: Vec<String>,
    stopped: bool,
}

impl InFlightState {
    /// Whether an in-flight evaluation has stopped the exchange. Every later
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
        let admission = (0..rules.len())
            .filter(|&i| rules[i].shape.kind.at_admission())
            .collect();
        let in_flight: Box<[usize]> = (0..rules.len())
            .filter(|&i| rules[i].shape.kind.in_flight())
            .collect();
        let in_flight_triggers = in_flight
            .iter()
            .fold(Reads::NONE, |acc, &i| acc | rules[i].shape.triggers);
        let byte_metrics = metrics.iter().filter_map(|m| m.count.in_flight()).collect();
        Ok(Policy {
            rules,
            admission,
            in_flight,
            in_flight_triggers,
            byte_metrics,
            metrics,
            needs_request_body: needs.request_body,
            needs_response_body: needs.response_body,
            default_id: RuleId::new(RuleId::DEFAULT),
            fail_closed_id: RuleId::new(RuleId::FAIL_CLOSED),
        })
    }

    /// Problems worth reporting that do not stop `metrics` compiling, for
    /// `roxy check`: a key field the client chooses freely (`host`, `path`,
    /// `url`, `query.raw`, `client.port`) on a metric with no `where`.
    pub fn metric_warnings(metrics: &[MetricConfig]) -> Vec<Diagnostic> {
        compiler::PolicyCompiler::metric_warnings(metrics)
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
            .any(|r| r.shape.fields.contains(InFlightValue::Ws))
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
                in_flight_reads: r.shape.in_flight_reads.clone(),
                triggers: r.shape.triggers,
            })
            .collect()
    }

    pub fn metric_defs(&self) -> &[MetricDef] {
        &self.metrics
    }

    /// Number of rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}
