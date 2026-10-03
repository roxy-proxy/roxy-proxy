//! Rule engine for roxy (`DESIGN.md` §6).
//!
//! Responsibilities: the rule-related config types ([`config`]), the
//! expression DSL (lexer, parser, type-checker, compiler), the rule chains
//! per phase with typed actions, and the immutable `Policy` snapshot that
//! the proxy swaps atomically on reload.
//!
//! This crate performs no network I/O and does not depend on the HTTP model:
//! the proxy exposes a flow through the [`FlowView`] trait.

#![forbid(unsafe_code)]

pub mod ast;
mod compile;
pub mod config;
mod diag;
mod lexer;
pub mod parser;
mod types;
mod view;

pub use compile::{REGEX_DFA_SIZE_LIMIT, REGEX_SIZE_LIMIT};
pub use config::{
    Action, AllowArgs, CaptureTarget, DenyArgs, Expr, LogArgs, LogLevel, MetricConfig, MetricCount,
    Phase, RedirectArgs, RewritePathArgs, RuleConfig, Scheme, SetStateArgs, Then, Upgrade,
};
pub use diag::{Diagnostic, RuleId, Span};
pub use parser::parse;
pub use types::{Field, Type};
pub use view::{FlowView, MapView, Value};
