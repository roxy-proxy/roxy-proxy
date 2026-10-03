//! Rule engine for roxy (`DESIGN.md` §6).
//!
//! Responsibilities: the rule-related config types ([`config`]), the
//! expression DSL (lexer, parser, type-checker, compiler), the rule chains
//! per phase with typed actions, and the immutable [`Policy`] snapshot that
//! the proxy swaps atomically on reload.
//!
//! This crate performs no network I/O and does not depend on the HTTP model:
//! the proxy exposes a flow through the [`FlowView`] trait.

#![forbid(unsafe_code)]

pub mod config;

pub use config::{
    Action, AllowArgs, CaptureTarget, DenyArgs, Expr, LogArgs, LogLevel, MetricConfig, MetricCount,
    Phase, RedirectArgs, RewritePathArgs, RuleConfig, Scheme, SetStateArgs, Then, Upgrade,
};
