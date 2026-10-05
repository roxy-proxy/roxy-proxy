//! Rule engine for roxy.
//!
//! Responsibilities: the rule-related config types ([`config`]), the
//! expression DSL (lexer, parser, type-checker, compiler), the one
//! ordered rule list with its head/watching classification and typed
//! actions, and the immutable [`Policy`] snapshot that the proxy swaps
//! atomically on reload. It also provides the in-process stores behind
//! `metric.<id>` and `state["k"]`: [`MetricStore`] and [`StateStore`],
//! exposed to the proxy as [`MetricSource`] and [`StateSource`].
//!
//! This crate performs no network I/O and does not depend on the HTTP model:
//! the proxy exposes a flow through the [`FlowView`] trait.
//!
//! # Using it
//!
//! ```
//! use std::collections::HashSet;
//! use roxy_rules::{
//!     DefaultDecision, EvalContext, Field, MapView, Policy, PolicyInput, Reads, RuleConfig,
//! };
//!
//! let rules: Vec<RuleConfig> = serde_yaml_ng::from_str(r#"
//! - id: github-reads
//!   when: host under "github.com" and method in [GET, HEAD]
//!   then: allow
//! - id: upload-cap
//!   when: body.bytes > 10mb
//!   then: { deny: { status: 413 } }
//! "#).unwrap();
//! let none = HashSet::new();
//! let policy = Policy::compile(&PolicyInput {
//!     rules: &rules, metrics: &[], secret_names: &none, address_lists: &none,
//!     default: DefaultDecision::Deny,
//! }).unwrap();
//! let flow = MapView::new()
//!     .with_str(Field::Host, "api.github.com")
//!     .with_str(Field::Method, "GET");
//! // The head decision: `upload-cap` reads `body.bytes`, so it is skipped.
//! let out = policy.evaluate_head(&flow, &EvalContext::empty());
//! assert!(out.decision.is_allow());
//! assert_eq!(out.terminal_rule, "github-reads");
//! // After forwarding: re-check the watching rules as body bytes arrive.
//! let mut st = policy.watch_state(&out.tags);
//! let flow = flow.with_int(Field::BodyBytes, 11 << 20);
//! let w = policy
//!     .evaluate_watching(Reads::BODY_BYTES, Reads::BODY_BYTES, &mut st, &flow, &EvalContext::empty())
//!     .unwrap();
//! assert!(w.stops());
//! ```
//!
//! # Semantics
//!
//! * **One list, two kinds of rule**. Compiling records what each
//!   rule's `when` reads. A rule that reads only *head* values (known when
//!   the request head arrives) is a **head rule**. A rule that reads a
//!   *watched* field (`body.bytes`, `response.*`, `ws.*`) is a **watching
//!   rule**. A `deny` rule that reads a byte metric (`count: request_bytes`
//!   or `response_bytes`) and no watched field is both
//!   ([`RuleKind::HeadAndWatching`]): it takes part in the head decision and
//!   is re-checked as this exchange adds bytes to that metric. Metrics that
//!   count `requests`, `denied`, `errors` or `unique(..)` do not change
//!   while an exchange streams, so reading them does not make a rule watch.
//! * **The head decision** ([`Policy::evaluate_head`]) evaluates every head
//!   rule top to bottom (watching rules are skipped, not false). A matching
//!   deny anywhere wins (`terminal_rule` = the first matching deny); else a
//!   matching allow (the first one; only its `upgrade`/`private_ok` options
//!   apply); else `default:` (`deny` unless configured `allow`; the
//!   implicit allow grants no options), `terminal_rule = "_default"`. Tags
//!   set by a matching rule are visible to the rules below it. If allowed,
//!   every matching rule's effects apply in list order (a later
//!   `set_header` of the same name wins); if denied, only `log`, `tag` and
//!   `set_state` remain.
//! * **Watching** ([`Policy::evaluate_watching`]): after forwarding, the
//!   proxy reports each change (`changed`, a [`Reads`] mask) and what is
//!   known so far. Rules whose triggers intersect the change and whose
//!   watched fields are all known are checked top to bottom; the first
//!   matching deny stops the exchange. Non-terminal effects of a watching
//!   rule apply once, the first time it matches. Each rule's reads are a
//!   bit mask, so an event no rule watches costs one `and`, and an
//!   evaluation in which nothing matches allocates nothing.
//! * **Legal actions**. Head rules may use every action; their
//!   `set_header`/`remove_header` change the request. A watching rule
//!   cannot `allow`, `rewrite_path`, `set_query`, `remove_query`,
//!   `redirect` or use `${secret:..}` (the request is already on its way):
//!   compile errors. **In a watching rule, `set_header` and
//!   `remove_header` change the response**: they are legal only when the
//!   rule reads response values and everything that can re-check it is
//!   known before the response head is sent (`response.status`,
//!   `response.header[..]`, `response.body.size`, `response.body.text`); a
//!   watching rule that does not read the response would change the
//!   request, and one that also reads `body.bytes`, `response.body.bytes`
//!   or a byte metric could match after the head was sent. Both are
//!   compile errors. There is no explicit target key: the rule's reads
//!   decide it.
//! * **Denies close.** A deny closes the client connection after the
//!   response unless the rule says `deny: { close: false }`.
//! * **Unavailable inputs fail closed.** If evaluation reaches a metric the
//!   view reports unavailable ([`FlowView::metric`] → `None`), an address
//!   list it cannot answer for, a body predicate whose body is too large to
//!   inspect or not available ([`BodyText`]), a missing value under an
//!   operator that cannot answer for `null`, or a `set_header` secret that
//!   is missing or not a valid header value: at the head, the result is
//!   [`Decision::fail_closed`] (503, close), `terminal_rule =
//!   "_fail_closed"` and [`Outcome::fail_closed_reason`] says why, whatever
//!   else matched; in a watching evaluation the same stops the exchange.
//!   This is never "predicate false". `and`/`or` short-circuit, so only
//!   inputs actually reached count.
//! * **Missing values (`null`).** A field the flow does not have
//!   (`client.user` without proxy auth, an unset header or state key,
//!   `body.size` of a chunked body) is [`Value::Absent`]. It equals only
//!   `null` under `==`, `!=`, `in` and `not in`; any other operator on it
//!   fails closed with [`FailClosedReason::MissingValue`].
//! * **Case.** String comparisons are byte-exact, except operands involving
//!   `host`, `tls.sni` and `scheme`, which compare ASCII case-insensitively
//!   (also for `like`/`matches`/`in`). `method` compares byte-exact, as HTTP
//!   methods are case-sensitive: `get` is not `GET`. Header names in
//!   `header["X-Y"]` are lower-cased at compile time.
//! * **Operators.** `like` is a full-match glob (`*` any run including `/`,
//!   `?` one char, nothing else special). `matches` is a full-match regex
//!   (`^(?:…)$`) compiled with [`REGEX_SIZE_LIMIT`]. `under "x"` is
//!   `host == "x" or host ends_with ".x"`, case-insensitive, ignoring a
//!   trailing dot. `in` takes a literal list of the left operand's type, or
//!   CIDRs / IP addresses for ips (IPv4-mapped IPv6 addresses match IPv4
//!   CIDRs). Ordering operators take ints only.
//! * **Address lists.** `ip in @name` / `ip not in @name` checks a
//!   named list defined under `address_lists:` (see
//!   [`PolicyInput::address_lists`]). The engine holds only the name and asks
//!   [`FlowView::in_address_list`]; `None` (list unavailable) fails closed.
//!   `@name` anywhere else is a compile error.
//! * **Lists.** `header.all["x"]` satisfies `==`, `in`, `starts_with`,
//!   `ends_with`, `contains`, `like`, `matches` if any value does; `!=` and
//!   `not in` on it are compile errors.
//! * **Literals.** Size units `kb mb gb` are 1024-based bytes; duration
//!   units `ms s m h` are milliseconds. IP addresses without a mask are
//!   accepted too. Bare `UPPERCASE` identifiers are method literals and only
//!   valid against `method`.
//! * **Tags and state.** `tag["t"]` is true if `t` is in
//!   [`EvalContext::initial_tags`] or a `tag` action of an earlier matching
//!   rule set it. `state["k"]` sees `set_state` effects of earlier matching
//!   rules, then [`FlowView::state`]. `metric.<id>` is
//!   [`FlowView::metric`], which must return `Some(0)` for a series with no
//!   data yet; `None` means unavailable.
//! * **Metrics**. A metric's `where`, `key` and `unique(..)` may
//!   only read head fields, so whether an exchange counts, and its series,
//!   are fixed at the head.
//! * **Secrets.** `${secret:name}` is only allowed in `set_header` values
//!   of rules decided at the head and must name a defined secret. A secret
//!   missing at evaluation time (or not a valid header value) fails closed.
#![forbid(unsafe_code)]

/// The expression syntax tree: the return type of [`parse`], which exists
/// for the fuzz targets. Rules are compiled from source text through
/// [`Policy::compile`]; nothing else needs the tree.
#[doc(hidden)]
pub mod ast;
mod compile;
pub mod config;
mod diag;
mod eval;
mod lexer;
mod metrics;
mod parser;
mod policy;
mod state;
pub mod template;
mod types;
mod view;

pub use compile::{REGEX_DFA_SIZE_LIMIT, REGEX_SIZE_LIMIT};
pub use config::{
    Action, AllowArgs, CaptureTarget, DefaultDecision, DenyArgs, Expr, LogArgs, LogLevel,
    MetricConfig, MetricCount, PHASE_REMOVED, RedirectArgs, RewritePathArgs, RuleConfig, Scheme,
    SetStateArgs, Then, Upgrade,
};
pub use diag::{Diagnostic, RuleId, Span};
pub use eval::{
    AllowOpts, DEFAULT_DENY_MESSAGE, DEFAULT_DENY_STATUS, Decision, DenyStatus, Effect,
    EvalContext, FAIL_CLOSED_STATUS, FailClosedReason, Outcome, WatchOutcome,
};
pub use metrics::{
    CarryOverReport, Clock, DEFAULT_MAX_METRIC_BYTES, DEFAULT_MAX_METRIC_KEYS, MetricError,
    MetricLimits, MetricSnapshot, MetricSource, MetricStore, Sample,
};
#[doc(hidden)]
pub use parser::parse;
pub use policy::{Condition, MetricDef, Policy, PolicyInput, RuleInfo, RuleKind, WatchState};
pub use state::{StateFull, StateSource, StateStore};
pub use template::{Part, TemplateError, expand, parse_template};
pub use types::{Field, Reads, Type};
pub use view::{BodyText, FlowView, MapView, Value};
