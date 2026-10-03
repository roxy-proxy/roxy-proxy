//! Library half of the `roxy` binary: configuration schema and loading,
//! validation, and secret resolution. Kept as a library so integration tests
//! and later wiring code can use it directly.

pub mod config;
pub mod secrets;
