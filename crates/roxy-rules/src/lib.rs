//! Rule engine for roxy (`DESIGN.md` §6).
//!
//! Responsibilities: the rule-related config types ([`config`]), the
//! expression DSL (lexer, [`parser`], type-checker, compiler), the rule
//! chains per phase with typed actions, and the immutable [`Policy`]
//! snapshot that the proxy swaps atomically on reload.
//!
//! This crate performs no network I/O and does not depend on the HTTP model:
//! the proxy exposes a flow through the [`FlowView`] trait.
//!
//! # Using it
//!
//! ```
//! use std::collections::HashSet;
//! use roxy_rules::{EvalContext, Field, MapView, Phase, Policy, PolicyInput, RuleConfig};
//!
//! let rules: Vec<RuleConfig> = serde_yaml_ng::from_str(r#"
//! - id: github-reads
//!   when: host under "github.com" and method in [GET, HEAD]
//!   then: allow
//! "#).unwrap();
//! let none = HashSet::new();
//! let policy = Policy::compile(&PolicyInput {
//!     rules: &rules, metrics: &[], secret_names: &none, addon_names: &none, address_lists: &none,
//!     transparent_listeners: false,
//! }).unwrap();
//! let flow = MapView::new()
//!     .with_str(Field::Host, "api.github.com")
//!     .with_str(Field::Method, "GET");
//! let out = policy.evaluate(Phase::Request, &flow, &EvalContext::empty());
//! assert!(out.decision.is_allow());
//! assert_eq!(out.terminal_rule, "github-reads");
//! ```
//!
//! # Semantics
//!
//! * **Chains.** Rules run top to bottom per phase; non-terminal actions
//!   take effect and evaluation continues; the first terminal action
//!   (`allow`, `deny`, `passthrough`) decides. An exhausted chain yields
//!   [`Decision::default_for`] the phase: deny 403 in `request` and `ws`
//!   (in `ws` that drops the message), allow in `connect` (§4.3) and
//!   `response`; `terminal_rule` is `_default`.
//! * **Denies close.** Outside `ws`, a deny closes the client connection
//!   after the response unless the rule says `deny: { close: false }`. In
//!   `ws`, `close: true` closes the socket; the default drops the message.
//! * **Unavailable inputs fail closed.** If evaluation reaches a metric the
//!   view reports unavailable ([`FlowView::metric`] → `None`), an address
//!   list it cannot answer for, or a `set_header` secret that is missing or
//!   not a valid header value, evaluation stops: [`Decision::fail_closed`]
//!   (503, close), `terminal_rule = "_fail_closed"`, and
//!   [`Outcome::fail_closed_reason`] says why. This is never "predicate
//!   false". `and`/`or` short-circuit, so only inputs actually reached count.
//! * **Absent values.** A field the flow does not have (`client.user`
//!   without proxy auth, an unset header or state key) is
//!   [`Value::Absent`]. *Every* comparison involving an absent operand is
//!   false, including `!=` and `not in`; `not (x == "a")` is true.
//! * **Case.** String comparisons are byte-exact, except operands involving
//!   `host`, `dst.host`, `tls.sni`, `method` and `scheme`, which compare
//!   ASCII case-insensitively (also for `like`/`matches`/`in`). Header names
//!   in `header["X-Y"]` are lower-cased at compile time.
//! * **Operators.** `like` is a full-match glob (`*` any run including `/`,
//!   `?` one char, nothing else special). `matches` is a full-match regex
//!   (`^(?:…)$`) compiled with [`REGEX_SIZE_LIMIT`]. `under "x"` is
//!   `host == "x" or host ends_with ".x"`, case-insensitive, ignoring a
//!   trailing dot. `in` takes a literal list of the left operand's type, or
//!   CIDRs / IP addresses for ips (IPv4-mapped IPv6 addresses match IPv4
//!   CIDRs). Ordering operators take ints only.
//! * **Address lists.** `ip in @name` / `ip not in @name` (§7.1) checks a
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
//!   rule in the same chain set it. `state["k"]` sees `set_state` effects
//!   earlier in the chain, then [`FlowView::state`]. `metric.<id>` is
//!   [`FlowView::metric`], which must return `Some(0)` for a series with no
//!   data yet; `None` means unavailable.
//! * **Secrets.** `${secret:name}` is only allowed in request-phase
//!   `set_header` values and must name a defined secret. A secret missing at
//!   evaluation time (or not a valid header value) fails closed (see above).

#![forbid(unsafe_code)]

pub mod ast;
mod compile;
pub mod config;
mod diag;
mod eval;
mod lexer;
pub mod parser;
mod policy;
mod types;
mod view;

pub use compile::{REGEX_DFA_SIZE_LIMIT, REGEX_SIZE_LIMIT};
pub use config::{
    Action, AllowArgs, CaptureTarget, DenyArgs, Expr, LogArgs, LogLevel, MetricConfig, MetricCount,
    Phase, RedirectArgs, RewritePathArgs, RuleConfig, Scheme, SetStateArgs, Then, Upgrade,
};
pub use diag::{Diagnostic, RuleId, Span};
pub use eval::{
    AllowOpts, DEFAULT_DENY_MESSAGE, DEFAULT_DENY_STATUS, Decision, Effect, EvalContext,
    FAIL_CLOSED_MESSAGE, FAIL_CLOSED_STATUS, FailClosedReason, Outcome,
};
pub use parser::parse;
pub use policy::{MetricDef, Policy, PolicyInput};
pub use types::{Field, Type};
pub use view::{FlowView, MapView, Value};
