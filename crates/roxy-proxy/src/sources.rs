//! Policy inputs that live outside the proxy: metric values and the state
//! store (`DESIGN.md` §6.4).
//!
//! The pipeline codes against these two traits; the real stores (sliding
//! windows, bounded TTL map) plug in behind them. Until they exist,
//! [`UnavailableMetrics`] and [`UnavailableState`] stand in, and `roxy run`
//! refuses policies that would need them (metrics, `set_state`) instead of
//! failing every request closed.

use std::time::Duration;

use roxy_rules::FlowView;

/// What one exchange contributed since its last sample, reported to
/// [`MetricSource::record`] (§6.4). An exchange reports:
///
/// * one `head` sample right after the forwarding decision (counts
///   `requests` and `unique`, and `denied` if the head denied);
/// * one sample per forwarded body chunk (`request_bytes` or
///   `response_bytes`), so byte metrics grow while the exchange streams;
/// * one final sample (`error`, and `denied` if a watching rule stopped
///   the exchange).
///
/// Invariant: summing `request_bytes` over every sample of an exchange
/// gives the request-body bytes roxy accepted for forwarding (the same for
/// `response_bytes`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Sample {
    /// The exchange's head sample.
    pub head: bool,
    /// Request-body bytes not reported by an earlier sample.
    pub request_bytes: u64,
    /// Response-body bytes not reported by an earlier sample.
    pub response_bytes: u64,
    /// The exchange was denied (at the head, or stopped by a watching rule).
    pub denied: bool,
    /// The upstream exchange failed (connect, TLS, DNS, timeout, protocol).
    pub error: bool,
}

/// Why a metric could not be read or recorded. Every variant fails the flow
/// closed (`_fail_closed`, 503).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MetricSourceError {
    /// The store cannot answer (not configured, overloaded, unknown metric).
    #[error("metric store unavailable: {0}")]
    Unknown(String),
    /// A new series key was needed but the key table is full (§6.4: no
    /// eviction; the flow is denied with `metric_table_full`).
    #[error("metric key table full: {0}")]
    TableFull(String),
    /// The series key could not be computed for this flow.
    #[error("metric key unavailable: {0}")]
    KeyUnavailable(String),
}

impl MetricSourceError {
    /// Stable reason code for the flow log.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unknown(_) => "metric_unavailable",
            Self::TableFull(_) => "metric_table_full",
            Self::KeyUnavailable(_) => "metric_key_unavailable",
        }
    }
}

/// Metric values as seen by a flow, and the counting side.
pub trait MetricSource: Send + Sync {
    /// `Ok(value)` for the metric as seen by this flow (0 for a fresh key).
    /// `Err` → the flow fails closed.
    fn get(&self, id: &str, view: &dyn FlowView) -> Result<i64, MetricSourceError>;
    /// Called after the head decision (so denied flows count too), per
    /// streamed chunk and at the end. `Err` → the exchange fails closed.
    fn record(&self, view: &dyn FlowView, sample: &Sample) -> Result<(), MetricSourceError>;
}

/// The state store is full; the `set_state` that hit it denies its flow.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("state store full or unavailable")]
pub struct StateFull;

/// The bounded TTL key/value map behind `state["k"]` and `set_state`.
pub trait StateSource: Send + Sync {
    /// Current value; `None` = unset (a legitimate absent value).
    fn get(&self, key: &str) -> Option<String>;
    /// Write a value. `Err` denies the flow that tried.
    fn set(&self, key: &str, value: &str, ttl: Option<Duration>) -> Result<(), StateFull>;
}

/// Used when the build has no metric store: every read is unavailable (so
/// any rule reaching `metric.x` fails closed) and recording is a no-op.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailableMetrics;

impl MetricSource for UnavailableMetrics {
    fn get(&self, id: &str, _view: &dyn FlowView) -> Result<i64, MetricSourceError> {
        Err(MetricSourceError::Unknown(format!(
            "no metric store in this build (metric `{id}`)"
        )))
    }

    fn record(&self, _view: &dyn FlowView, _sample: &Sample) -> Result<(), MetricSourceError> {
        Ok(())
    }
}

/// Used when the build has no state store: reads are absent, writes fail.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailableState;

impl StateSource for UnavailableState {
    fn get(&self, _key: &str) -> Option<String> {
        None
    }

    fn set(&self, _key: &str, _value: &str, _ttl: Option<Duration>) -> Result<(), StateFull> {
        Err(StateFull)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxy_rules::MapView;

    #[test]
    fn unavailable_sources_fail_closed() {
        let v = MapView::new();
        assert!(matches!(
            UnavailableMetrics.get("x", &v),
            Err(MetricSourceError::Unknown(_))
        ));
        assert!(UnavailableMetrics.record(&v, &Sample::default()).is_ok());
        assert_eq!(UnavailableState.get("k"), None);
        assert_eq!(UnavailableState.set("k", "v", None), Err(StateFull));
        assert_eq!(
            MetricSourceError::TableFull(String::new()).code(),
            "metric_table_full"
        );
    }
}
