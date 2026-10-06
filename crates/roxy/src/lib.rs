//! Library half of the `roxy` binary: configuration schema and loading,
//! validation, and secret resolution. Kept as a library so integration tests
//! and later wiring code can use it directly.

pub mod addons;
pub mod config;
pub mod lists;
pub mod node;
pub mod ruletest;
pub mod run;
pub mod secrets;
pub mod stores;
