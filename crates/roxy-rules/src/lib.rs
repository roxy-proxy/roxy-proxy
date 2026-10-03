//! Rule engine for roxy.
//!
//! Responsibilities (see `DESIGN.md` §3 and §6): the expression DSL (lexer,
//! parser, type-checker, compiler), the rule set and its phases, typed
//! actions, metrics and the state store, and the hot-reload-safe `Policy`
//! snapshot that is swapped atomically on reload.
//!
//! This crate performs no network I/O. It is filled in during milestone M1.
