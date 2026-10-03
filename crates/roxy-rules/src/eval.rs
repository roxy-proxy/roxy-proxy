//! Evaluation: predicate plans against a [`FlowView`], and the outcome of
//! running a rule chain.

use std::borrow::Cow;
use std::cell::Cell;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use regex::Regex;

use crate::compile::{Const, OrdOp, Pred, ROperand, StrOp};
use crate::config::{CaptureTarget, LogLevel, Phase, Scheme};
use crate::diag::RuleId;
use crate::types::Access;
use crate::view::{FlowView, Value};

/// Per-evaluation inputs that are not part of the flow.
#[derive(Clone, Copy)]
pub struct EvalContext<'a> {
    /// Resolves `${secret:name}` in `set_header` values. Returning `None`
    /// makes the flow fail closed (see [`crate::Policy::evaluate`]).
    pub secrets: &'a dyn Fn(&str) -> Option<String>,
    /// Tags already set on the flow (by an earlier phase or an addon);
    /// visible as `tag["x"]`.
    pub initial_tags: &'a [String],
}

fn no_secrets(_: &str) -> Option<String> {
    None
}

impl EvalContext<'static> {
    /// No secrets and no initial tags.
    pub fn empty() -> Self {
        Self {
            secrets: &no_secrets,
            initial_tags: &[],
        }
    }
}

impl fmt::Debug for EvalContext<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EvalContext")
            .field("initial_tags", &self.initial_tags)
            .finish_non_exhaustive()
    }
}

/// Options of an `allow` decision.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct AllowOpts {
    /// `allow: { upgrade: websocket }`: honour a WebSocket Upgrade.
    pub upgrade_websocket: bool,
    /// `inspect: true`: route messages through the `ws` phase (§8.2).
    pub inspect_ws: bool,
    /// `private_ok: true`: permit private upstream addresses (§7).
    pub private_ok: bool,
}

/// Final decision of a phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow(AllowOpts),
    /// `close`: in `connect`, `request` and `response` the proxy closes the
    /// client connection after writing the deny response (h1
    /// `connection: close`, h2 `GOAWAY`; §6.1). It defaults to `true` there
    /// and `deny: { close: false }` opts out per rule. In the `ws` phase a
    /// deny without `close` drops the message and `close: true` closes the
    /// socket; the default there is `false`.
    Deny {
        status: u16,
        message: String,
        close: bool,
    },
    /// Connect phase on transparent listeners only (deferred).
    Passthrough,
}

/// Default deny status and message (§5.7, §6.1).
pub const DEFAULT_DENY_STATUS: u16 = 403;
pub const DEFAULT_DENY_MESSAGE: &str = "blocked by roxy";

impl Decision {
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow(_))
    }

    pub fn is_deny(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }

    /// Whether a deny closes the connection when the rule does not say:
    /// `true` everywhere except the `ws` phase, where it drops the message.
    pub fn default_close(phase: Phase) -> bool {
        phase != Phase::Ws
    }

    /// Decision when a phase's chain is exhausted without a terminal action
    /// (§6.1):
    ///
    /// * `request`: deny 403, closing the connection.
    /// * `connect`: allow-to-inspect (§4.3): the request phase is the gate.
    /// * `response`: allow; the request was allowed and upstreams are trusted.
    /// * `ws`: deny 403 without close, i.e. drop the message. Opting into
    ///   inspection means writing the allow rules.
    pub fn default_for(phase: Phase) -> Self {
        match phase {
            Phase::Request | Phase::Ws => Self::Deny {
                status: DEFAULT_DENY_STATUS,
                message: DEFAULT_DENY_MESSAGE.into(),
                close: Self::default_close(phase),
            },
            Phase::Connect | Phase::Response => Self::Allow(AllowOpts::default()),
        }
    }

    /// The decision for a fail-closed outcome: 503, closing the connection.
    pub fn fail_closed() -> Self {
        Self::Deny {
            status: FAIL_CLOSED_STATUS,
            message: FAIL_CLOSED_MESSAGE.into(),
            close: true,
        }
    }
}

/// Status and message when a policy input is unavailable (§6.1).
pub const FAIL_CLOSED_STATUS: u16 = 503;
pub const FAIL_CLOSED_MESSAGE: &str = "policy input unavailable";

/// Why an evaluation failed closed (`terminal_rule = "_fail_closed"`), for
/// the proxy's `policy_input_unavailable` flow event. Carries names only,
/// never secret values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailClosedReason {
    /// `FlowView::metric(id)` returned `None`.
    MetricUnavailable(String),
    /// `FlowView::in_address_list(name, ip)` returned `None`.
    AddressListUnavailable(String),
    /// A `set_header` secret could not be resolved.
    SecretMissing(String),
    /// A resolved secret is not a valid header value (CR, LF, control or
    /// non-ASCII characters).
    SecretInvalid(String),
}

impl fmt::Display for FailClosedReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MetricUnavailable(id) => write!(f, "metric `{id}` unavailable"),
            Self::AddressListUnavailable(n) => write!(f, "address list @{n} unavailable"),
            Self::SecretMissing(n) => write!(f, "secret {n:?} missing"),
            Self::SecretInvalid(n) => write!(f, "secret {n:?} is not a valid header value"),
        }
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Decision::Allow(o) => {
                f.write_str("allow")?;
                let mut opts = Vec::new();
                if o.upgrade_websocket {
                    opts.push("upgrade: websocket");
                }
                if o.inspect_ws {
                    opts.push("inspect: true");
                }
                if o.private_ok {
                    opts.push("private_ok: true");
                }
                if !opts.is_empty() {
                    write!(f, " {{ {} }}", opts.join(", "))?;
                }
                Ok(())
            }
            Decision::Deny {
                status,
                message,
                close,
            } => {
                write!(f, "deny {status} {message:?}")?;
                if *close {
                    f.write_str(" (close)")?;
                }
                Ok(())
            }
            Decision::Passthrough => f.write_str("passthrough"),
        }
    }
}

/// A non-terminal action's effect, for the proxy to apply (mutations) or
/// perform (log, state, capture, addon call), in chain order.
#[derive(Debug, Clone)]
pub enum Effect {
    /// Lower-case name; value already secret-substituted and validated as a
    /// header value (visible ASCII, SP, HTAB; no CR/LF/NUL).
    SetHeader {
        name: String,
        value: String,
    },
    /// Lower-case name.
    RemoveHeader(String),
    /// Replace the whole path with `to` (expanding `$1`, `${name}`) if the
    /// anchored `regex` matches; the result must be re-normalised (§5.4).
    RewritePath {
        regex: Arc<Regex>,
        to: String,
    },
    SetQuery {
        key: String,
        value: String,
    },
    RemoveQuery(String),
    Redirect {
        host: String,
        port: u16,
        /// `None` keeps the request's scheme.
        scheme: Option<Scheme>,
        rewrite_host: bool,
    },
    Log {
        level: LogLevel,
        message: String,
    },
    SetState {
        key: String,
        value: String,
        ttl: Option<Duration>,
    },
    Capture(CaptureTarget),
    CallAddon(String),
}

impl Effect {
    /// The action name that produced this effect.
    pub fn kind(&self) -> &'static str {
        match self {
            Effect::SetHeader { .. } => "set_header",
            Effect::RemoveHeader(_) => "remove_header",
            Effect::RewritePath { .. } => "rewrite_path",
            Effect::SetQuery { .. } => "set_query",
            Effect::RemoveQuery(_) => "remove_query",
            Effect::Redirect { .. } => "redirect",
            Effect::Log { .. } => "log",
            Effect::SetState { .. } => "set_state",
            Effect::Capture(_) => "capture",
            Effect::CallAddon(_) => "call",
        }
    }

    /// Whether the effect mutates the request or response.
    pub fn is_mutation(&self) -> bool {
        matches!(
            self,
            Effect::SetHeader { .. }
                | Effect::RemoveHeader(_)
                | Effect::RewritePath { .. }
                | Effect::SetQuery { .. }
                | Effect::RemoveQuery(_)
                | Effect::Redirect { .. }
        )
    }
}

#[allow(clippy::many_single_char_names)]
impl PartialEq for Effect {
    fn eq(&self, other: &Self) -> bool {
        use Effect as E;
        match (self, other) {
            (E::SetHeader { name: a, value: b }, E::SetHeader { name: c, value: d })
            | (E::SetQuery { key: a, value: b }, E::SetQuery { key: c, value: d }) => {
                a == c && b == d
            }
            (E::RemoveHeader(a), E::RemoveHeader(b))
            | (E::RemoveQuery(a), E::RemoveQuery(b))
            | (E::CallAddon(a), E::CallAddon(b)) => a == b,
            (E::RewritePath { regex: a, to: b }, E::RewritePath { regex: c, to: d }) => {
                a.as_str() == c.as_str() && b == d
            }
            (
                E::Redirect {
                    host: a,
                    port: b,
                    scheme: c,
                    rewrite_host: d,
                },
                E::Redirect {
                    host: e,
                    port: f,
                    scheme: g,
                    rewrite_host: h,
                },
            ) => a == e && b == f && c == g && d == h,
            (
                E::Log {
                    level: a,
                    message: b,
                },
                E::Log {
                    level: c,
                    message: d,
                },
            ) => a == c && b == d,
            (
                E::SetState {
                    key: a,
                    value: b,
                    ttl: c,
                },
                E::SetState {
                    key: d,
                    value: e,
                    ttl: f,
                },
            ) => a == d && b == e && c == f,
            (E::Capture(a), E::Capture(b)) => a == b,
            _ => false,
        }
    }
}

impl fmt::Display for Effect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Effect::SetHeader { name, value } => write!(f, "set_header {name}: {value}"),
            Effect::RemoveHeader(n) => write!(f, "remove_header {n}"),
            Effect::RewritePath { regex, to } => {
                write!(f, "rewrite_path {:?} -> {to:?}", anchored_source(regex))
            }
            Effect::SetQuery { key, value } => write!(f, "set_query {key}={value}"),
            Effect::RemoveQuery(k) => write!(f, "remove_query {k}"),
            Effect::Redirect {
                host,
                port,
                scheme,
                rewrite_host,
            } => {
                let scheme = scheme.map_or("<same>", Scheme::as_str);
                write!(
                    f,
                    "redirect {scheme}://{host}:{port}{}",
                    if *rewrite_host { " (rewrite host)" } else { "" }
                )
            }
            Effect::Log { level, message } => write!(f, "log {}: {message}", level.as_str()),
            Effect::SetState { key, value, ttl } => {
                write!(f, "set_state {key}={value}")?;
                if let Some(ttl) = ttl {
                    write!(
                        f,
                        " (ttl {})",
                        humantime_serde::re::humantime::format_duration(*ttl)
                    )?;
                }
                Ok(())
            }
            Effect::Capture(t) => write!(f, "capture {}", t.as_str()),
            Effect::CallAddon(a) => write!(f, "call {a}"),
        }
    }
}

/// The pattern as written, without the implicit anchors.
fn anchored_source(re: &Regex) -> &str {
    let s = re.as_str();
    s.strip_prefix("^(?:")
        .and_then(|s| s.strip_suffix(")$"))
        .unwrap_or(s)
}

/// Result of evaluating one phase's chain.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    pub decision: Decision,
    /// Every rule whose `when` matched, in order (including the terminal one).
    pub matched: Vec<RuleId>,
    /// The rule that decided; `_default` when the chain was exhausted;
    /// `_fail_closed` when a policy input was unavailable.
    pub terminal_rule: RuleId,
    /// Set exactly when `terminal_rule` is `_fail_closed`.
    pub fail_closed_reason: Option<FailClosedReason>,
    /// Effects of non-terminal actions of matched rules, in order.
    pub effects: Vec<Effect>,
    /// `initial_tags` plus tags set by matched rules, without duplicates.
    pub tags: Vec<String>,
}

// ----- predicate evaluation -------------------------------------------------

/// What a predicate can see: the flow plus the chain's running state.
pub(crate) struct Scope<'a> {
    pub view: &'a dyn FlowView,
    pub tags: &'a [String],
    /// Effects so far; `state["k"]` sees earlier `set_state` in the chain.
    pub effects: &'a [Effect],
    /// First unavailable input met during evaluation, if any.
    pub failed: Cell<Option<Unavailable<'a>>>,
}

impl<'a> Scope<'a> {
    pub(crate) fn new(view: &'a dyn FlowView, tags: &'a [String], effects: &'a [Effect]) -> Self {
        Self {
            view,
            tags,
            effects,
            failed: Cell::new(None),
        }
    }

    fn fail(&self, what: Unavailable<'a>) {
        if self.failed.get().is_none() {
            self.failed.set(Some(what));
        }
    }

    /// Evaluate `p`; `Err` if it needed an unavailable input.
    pub(crate) fn check(&self, p: &'a Pred) -> Result<bool, FailClosedReason> {
        let r = p.eval(self);
        match self.failed.get() {
            Some(what) => Err(what.reason()),
            None => Ok(r),
        }
    }
}

/// A policy input the view could not provide. Evaluation stops and the flow
/// fails closed; this is never treated as an absent value (§6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unavailable<'a> {
    Metric(&'a str),
    List(&'a str),
}

impl Unavailable<'_> {
    pub(crate) fn reason(self) -> FailClosedReason {
        match self {
            Unavailable::Metric(id) => FailClosedReason::MetricUnavailable(id.to_owned()),
            Unavailable::List(n) => FailClosedReason::AddressListUnavailable(n.to_owned()),
        }
    }
}

fn get<'a>(op: &'a ROperand, s: &Scope<'a>) -> Value<'a> {
    match op {
        ROperand::Const(c) => match c {
            Const::Str(v) => Value::Str(Cow::Borrowed(v)),
            Const::Int(n) => Value::Int(*n),
            Const::Bool(b) => Value::Bool(*b),
            Const::Ip(ip) => Value::Ip(*ip),
        },
        ROperand::Get(access) => match access {
            Access::Scalar(f) => s.view.field(*f),
            Access::Header(n) => opt(s.view.header(n)),
            Access::HeaderAll(n) => list(s.view.header_all(n)),
            Access::RespHeader(n) => opt(s.view.response_header(n)),
            Access::RespHeaderAll(n) => list(s.view.response_header_all(n)),
            Access::Query(k) => opt(s.view.query(k)),
            Access::State(k) => {
                let pending = s.effects.iter().rev().find_map(|e| match e {
                    Effect::SetState { key, value, .. } if **key == **k => Some(value.as_str()),
                    _ => None,
                });
                match pending {
                    Some(v) => Value::Str(Cow::Borrowed(v)),
                    // An unset key is a legitimate state: absent, not unavailable.
                    None => opt(s.view.state(k)),
                }
            }
            Access::Tag(t) => Value::Bool(s.tags.iter().any(|x| **x == **t)),
            Access::Metric(id) => s.view.metric(id).map_or_else(
                || {
                    s.fail(Unavailable::Metric(id));
                    Value::Absent
                },
                Value::Int,
            ),
            Access::BodyText => opt(s.view.body_text()),
            Access::RespBodyText => opt(s.view.response_body_text()),
        },
    }
}

fn opt(v: Option<Cow<'_, str>>) -> Value<'_> {
    v.map_or(Value::Absent, Value::Str)
}

fn list(v: Vec<Cow<'_, str>>) -> Value<'_> {
    if v.is_empty() {
        Value::Absent
    } else {
        Value::List(v)
    }
}

fn bytes_eq(a: &[u8], b: &[u8], ci: bool) -> bool {
    if ci {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

fn str_eq(a: &str, b: &str, ci: bool) -> bool {
    bytes_eq(a.as_bytes(), b.as_bytes(), ci)
}

fn str_test(a: &str, b: &str, op: StrOp, ci: bool) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if b.len() > a.len() {
        return false;
    }
    match op {
        StrOp::StartsWith => bytes_eq(&a[..b.len()], b, ci),
        StrOp::EndsWith => bytes_eq(&a[a.len() - b.len()..], b, ci),
        StrOp::Contains => b.is_empty() || a.windows(b.len()).any(|w| bytes_eq(w, b, ci)),
    }
}

/// `host == suffix || host ends_with "." + suffix`, ASCII case-insensitive,
/// ignoring one trailing dot on the host (`suffix` is pre-normalised).
fn under(host: &str, suffix: &str) -> bool {
    let h = host.strip_suffix('.').unwrap_or(host).as_bytes();
    let s = suffix.as_bytes();
    match h.len().checked_sub(s.len()) {
        Some(0) => h.eq_ignore_ascii_case(s),
        Some(n) => h[n - 1] == b'.' && h[n..].eq_ignore_ascii_case(s),
        None => false,
    }
}

/// True if the (string or list) value has an element satisfying `f`.
fn any_str(v: &Value<'_>, f: impl Fn(&str) -> bool) -> bool {
    match v {
        Value::Str(s) => f(s),
        Value::List(items) => items.iter().any(|s| f(s)),
        _ => false,
    }
}

/// `Some(result)` if both sides are present and comparable, else `None`.
fn eq(a: &Value<'_>, b: &Value<'_>, ci: bool) -> Option<bool> {
    match (a, b) {
        (Value::Str(x), Value::Str(y)) => Some(str_eq(x, y, ci)),
        (Value::List(xs), Value::Str(y)) | (Value::Str(y), Value::List(xs)) => {
            Some(xs.iter().any(|x| str_eq(x, y, ci)))
        }
        (Value::Int(x), Value::Int(y)) => Some(x == y),
        (Value::Bool(x), Value::Bool(y)) => Some(x == y),
        (Value::Ip(x), Value::Ip(y)) => Some(x.to_canonical() == y.to_canonical()),
        _ => None,
    }
}

impl Pred {
    /// Evaluate with short-circuiting `and`/`or`: an input is only "needed"
    /// (and can only fail closed) if evaluation actually reaches it. An
    /// unavailable input is recorded in the scope (see [`Scope::failed`]); the
    /// returned bool is then meaningless and the caller must fail closed.
    /// Recording instead of returning `Result` keeps the hot path cheap.
    pub(crate) fn eval<'a>(&'a self, s: &Scope<'a>) -> bool {
        match self {
            Pred::Const(b) => *b,
            Pred::All(ps) => {
                for p in ps {
                    if !p.eval(s) {
                        return false;
                    }
                }
                true
            }
            Pred::Any(ps) => {
                for p in ps {
                    if p.eval(s) {
                        return true;
                    }
                }
                false
            }
            Pred::Not(p) => !p.eval(s),
            Pred::Truthy(o) => matches!(get(o, s), Value::Bool(true)),
            Pred::Eq {
                lhs,
                rhs,
                ci,
                negate,
            } => eq(&get(lhs, s), &get(rhs, s), *ci).is_some_and(|r| r != *negate),
            Pred::Ord { lhs, rhs, op } => match (get(lhs, s), get(rhs, s)) {
                (Value::Int(a), Value::Int(b)) => match op {
                    OrdOp::Lt => a < b,
                    OrdOp::Le => a <= b,
                    OrdOp::Gt => a > b,
                    OrdOp::Ge => a >= b,
                },
                _ => false,
            },
            Pred::Str { lhs, rhs, op, ci } => {
                let rv = get(rhs, s);
                let Value::Str(needle) = &rv else {
                    return false;
                };
                any_str(&get(lhs, s), |h| str_test(h, needle, *op, *ci))
            }
            Pred::Glob { lhs, glob } => any_str(&get(lhs, s), |v| glob.is_match(v)),
            Pred::Regex { lhs, re } => any_str(&get(lhs, s), |v| re.is_match(v)),
            Pred::Under { lhs, suffix } => match get(lhs, s) {
                Value::Str(h) => under(&h, suffix),
                _ => false,
            },
            Pred::InStr {
                lhs,
                set,
                ci,
                negate,
            } => {
                let v = get(lhs, s);
                matches!(v, Value::Str(_) | Value::List(_))
                    && any_str(&v, |x| set.iter().any(|m| str_eq(x, m, *ci))) != *negate
            }
            Pred::InInt { lhs, set, negate } => match get(lhs, s) {
                Value::Int(n) => set.contains(&n) != *negate,
                _ => false,
            },
            Pred::InNet { lhs, nets, negate } => match get(lhs, s) {
                Value::Ip(ip) => {
                    let ip = ip.to_canonical();
                    nets.iter().any(|n| n.contains(&ip)) != *negate
                }
                _ => false,
            },
            Pred::InList { lhs, list, negate } => match get(lhs, s) {
                Value::Ip(ip) => {
                    if let Some(hit) = s.view.in_address_list(list, ip.to_canonical()) {
                        hit != *negate
                    } else {
                        s.fail(Unavailable::List(list));
                        false
                    }
                }
                // No ip to check (e.g. `dst.ip` before resolution) is an
                // absent value, not an unavailable list.
                _ => false,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn under_semantics() {
        assert!(under("github.com", "github.com"));
        assert!(under("api.github.com", "github.com"));
        assert!(under("API.GitHub.com.", "github.com"));
        assert!(!under("evilgithub.com", "github.com"));
        assert!(!under("github.com.evil", "github.com"));
        assert!(!under("com", "github.com"));
        assert!(!under(".github.com", "x.github.com"));
    }

    #[test]
    fn string_tests() {
        assert!(str_test("Hello", "he", StrOp::StartsWith, true));
        assert!(!str_test("Hello", "he", StrOp::StartsWith, false));
        assert!(str_test("Hello", "LLO", StrOp::EndsWith, true));
        assert!(str_test("Hello", "ell", StrOp::Contains, false));
        assert!(str_test("Hello", "", StrOp::Contains, false));
        assert!(!str_test("He", "Hello", StrOp::Contains, false));
        // Byte-level comparison never splits a UTF-8 sequence wrongly.
        assert!(str_test("héllo", "é", StrOp::Contains, true));
        assert!(!str_test("é", "\u{e9}x", StrOp::StartsWith, true));
    }
}
