//! The current flow and roxy's host services.
//!
//! Each function names the capability it needs. Calling one the layer was
//! not granted in roxy's config traps, failing the exchange closed.

use std::time::Duration;

use crate::bindings::roxy::addon::flow as raw;

pub use raw::{FlowInfo, LogLevel, Principal};

fn ttl_ms(ttl: Option<Duration>) -> Option<u64> {
    ttl.map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// The current flow: ids, the principal roxy established, and tags.
pub fn current() -> FlowInfo {
    raw::current()
}

/// A stable key for per-principal state: the client IP.
pub fn principal_key() -> String {
    format!("ip:{}", current().principal.client_ip)
}

/// Adds a tag to the flow's log record. Enforce layers only: from an
/// observer the call fails the exchange.
pub fn add_tag(tag: &str) {
    raw::add_tag(tag);
}

/// The layer's `config:` value as a JSON document (`"null"` when unset).
pub fn config() -> String {
    raw::config()
}

/// Writes to roxy's operational log (capability `log`).
pub fn log(level: LogLevel, msg: &str) {
    raw::log(level, msg);
}

/// Writes a structured event to the flow log (capability `record`). `json`
/// must be a JSON value. Waits if the log is behind; records are never
/// dropped.
pub fn record(kind: &str, json: &str) {
    raw::record(kind, json);
}

/// Reads a JSON value from the layer's keyed store (capability `state`).
/// `None` means no history: treat it as a fresh start.
pub fn state_get(key: &str) -> Option<String> {
    raw::state_get(key)
}

/// Writes a JSON value to the layer's keyed store (capability `state`).
/// Fails when the store is full or the value too large; nothing is evicted.
pub fn state_put(key: &str, json: &str, ttl: Option<Duration>) -> Result<(), String> {
    raw::state_put(key, json, ttl_ms(ttl))
}

/// Reads a metric (capability `metrics`) by id and key-field values.
pub fn metric_get(id: &str, key: &[String]) -> Option<i64> {
    raw::metric_get(id, key)
}
