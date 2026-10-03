//! Adapters from the `roxy-rules` metric and state stores to the proxy's
//! [`MetricSource`] / [`StateSource`] traits (docs/rules.md#metrics, docs/rules.md#reload).
//!
//! The metric store is built from the compiled policy's metric definitions,
//! so it is rebuilt on every successful reload. Series whose definition is
//! unchanged are carried over ([`MetricStore::carry_over`]) so an unrelated
//! config edit never resets a rate limit.
//!
//! Reload ordering: the new store is prepared (and the old series copied
//! into it) before the policy swap, and swapped in immediately after the
//! policy swap succeeds. In the microseconds between the two swaps a flow
//! may see a metric id that only one side knows about; that resolves to
//! `MetricSourceError::Unknown`, which fails the flow closed. Records landing
//! on the old store after the carry-over copy are lost; the window is the
//! duration of one `ArcSwap::store`, so the undercount is bounded by the
//! flows recorded in that instant.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use roxy_proxy::{MetricSource, MetricSourceError, Sample, StateFull, StateSource};
use roxy_rules::{FlowView, MetricError, MetricLimits, MetricStore, Policy, StateStore};

/// Default TTL for `set_state` entries written without an explicit `ttl`.
pub const STATE_DEFAULT_TTL: Duration = Duration::from_secs(3600);

/// The built-in metric store behind an atomically swappable pointer.
#[derive(Debug)]
pub struct ReloadableMetrics {
    inner: ArcSwap<MetricStore>,
}

impl ReloadableMetrics {
    /// A store for `policy`'s metric definitions, bounded by `limits`
    /// (`limits.max_metric_keys` and `limits.max_metric_bytes`).
    pub fn new(policy: &Policy, limits: MetricLimits) -> Self {
        Self {
            inner: ArcSwap::from_pointee(MetricStore::with_limits(policy.metric_defs(), limits)),
        }
    }

    /// Builds the store for a new policy and copies over every series whose
    /// definition is unchanged. Call [`ReloadableMetrics::install`] with the
    /// result once the policy swap has succeeded; drop it otherwise.
    ///
    /// `limits` are the new config's: a smaller budget than the old store's
    /// is respected, and series that no longer fit are dropped (and logged)
    /// rather than carried past it.
    pub fn prepare(&self, policy: &Policy, limits: MetricLimits) -> MetricStore {
        let next = MetricStore::with_limits(policy.metric_defs(), limits);
        let report = next.carry_over(&self.inner.load());
        if report.skipped_budget > 0 {
            tracing::warn!(
                carried = report.carried,
                skipped = report.skipped_budget,
                max_bytes = next.max_bytes(),
                "metric series not carried over on reload: byte budget exhausted"
            );
        }
        next
    }

    /// Swaps in a store returned by [`ReloadableMetrics::prepare`].
    pub fn install(&self, next: MetricStore) {
        self.inner.store(Arc::new(next));
    }

    /// Live key count, for diagnostics.
    pub fn key_count(&self) -> usize {
        self.inner.load().key_count()
    }
}

fn map_err(e: MetricError) -> MetricSourceError {
    match e {
        MetricError::Unknown(id) => MetricSourceError::Unknown(format!("unknown metric {id}")),
        // Out of bytes is the same condition as out of keys: deny, never
        // evict (docs/rules.md#metrics, docs/limits.md).
        MetricError::TableFull { metric } | MetricError::BudgetExhausted { metric } => {
            MetricSourceError::TableFull(metric)
        }
        MetricError::KeyUnavailable { metric, field } => {
            MetricSourceError::KeyUnavailable(format!("{metric}: key field {field:?}"))
        }
        // A filter that hit an unavailable input cannot say whether the flow
        // counts; treat it as the store being unable to answer.
        MetricError::FilterFailed { metric, reason } => {
            MetricSourceError::Unknown(format!("{metric}: filter input unavailable ({reason})"))
        }
    }
}

impl MetricSource for ReloadableMetrics {
    fn get(&self, id: &str, view: &dyn FlowView) -> Result<i64, MetricSourceError> {
        self.inner.load().get(id, view).map_err(map_err)
    }

    fn record(&self, view: &dyn FlowView, sample: &Sample) -> Result<(), MetricSourceError> {
        let s = roxy_rules::Sample {
            head: sample.head,
            request_bytes: sample.request_bytes,
            response_bytes: sample.response_bytes,
            denied: sample.denied,
            error: sample.error,
        };
        self.inner.load().record(view, &s).map_err(map_err)
    }
}

/// The built-in bounded TTL state store.
#[derive(Debug)]
pub struct BuiltinState(pub StateStore);

impl BuiltinState {
    pub fn new(max_entries: usize) -> Self {
        Self(StateStore::new(max_entries, STATE_DEFAULT_TTL))
    }
}

impl StateSource for BuiltinState {
    fn get(&self, key: &str) -> Option<String> {
        self.0.get(key)
    }

    fn set(&self, key: &str, value: &str, ttl: Option<Duration>) -> Result<(), StateFull> {
        self.0.set(key, value, ttl).map_err(|_| StateFull)
    }
}

#[cfg(test)]
mod tests {
    use roxy_rules::{Field, MapView};

    use super::*;
    use crate::config::Config;

    const CONFIG: &str = "version: 1\nmetrics:\n  \
        - { id: by_path, count: requests, key: [path], window: 1h }\n";

    fn policy() -> Policy {
        let config = Config::from_yaml(CONFIG).unwrap();
        crate::run::policy_update(&config).unwrap().policy
    }

    fn limits(max_bytes: usize) -> MetricLimits {
        MetricLimits {
            max_keys: 1000,
            max_bytes,
        }
    }

    fn record(m: &ReloadableMetrics, path: &str) -> Result<(), MetricSourceError> {
        let sample = Sample {
            head: true,
            ..Sample::default()
        };
        m.record(&MapView::new().with_str(Field::Path, path), &sample)
    }

    /// A reload that shrinks `limits.max_metric_bytes` carries over only the
    /// series that fit the new budget, and the new store then refuses new
    /// keys instead of evicting (docs/rules.md#metrics).
    #[test]
    fn reload_respects_a_smaller_byte_budget() {
        let policy = policy();
        let m = ReloadableMetrics::new(&policy, limits(roxy_rules::DEFAULT_MAX_METRIC_BYTES));
        record(&m, "/a").unwrap();
        let per_series = m.inner.load().byte_count();
        assert!(per_series > 0);
        for p in ["/b", "/c", "/d"] {
            record(&m, p).unwrap();
        }
        assert_eq!(m.key_count(), 4);

        let budget = 2 * per_series + per_series / 2;
        let next = m.prepare(&policy, limits(budget));
        assert_eq!(next.max_bytes(), budget);
        assert_eq!(next.key_count(), 2, "only two series fit the new budget");
        assert!(next.byte_count() <= budget);
        m.install(next);

        let view = |p: &str| MapView::new().with_str(Field::Path, p);
        let carried = ["/a", "/b", "/c", "/d"]
            .iter()
            .filter(|p| m.get("by_path", &view(p)) == Ok(1))
            .count();
        assert_eq!(carried, 2);
        assert!(matches!(
            record(&m, "/e"),
            Err(MetricSourceError::TableFull(id)) if id == "by_path"
        ));
        assert_eq!(m.key_count(), 2);
    }

    /// Growing the budget on reload carries everything over.
    #[test]
    fn reload_with_a_larger_byte_budget_carries_everything() {
        let policy = policy();
        let m = ReloadableMetrics::new(&policy, limits(1 << 20));
        for p in ["/a", "/b", "/c"] {
            record(&m, p).unwrap();
        }
        let next = m.prepare(&policy, limits(2 << 20));
        assert_eq!(next.key_count(), 3);
        assert_eq!(next.max_bytes(), 2 << 20);
    }
}
