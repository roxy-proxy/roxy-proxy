//! Adapters from the `roxy-rules` metric and state stores to the proxy's
//! [`MetricSource`] / [`StateSource`] traits.
//!
//! The metric store is built from the compiled policy's metric definitions,
//! so it is rebuilt on every successful reload. Series whose definition is
//! unchanged are carried over ([`MetricStore::carry_over`]) so an unrelated
//! config edit never resets a rate limit.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use arc_swap::ArcSwap;
use roxy_proxy::{MetricSource, MetricSourceError, Sample, StateFull, StateSource};
use roxy_rules::{FlowView, MetricDef, MetricLimits, MetricStore, Policy, StateStore};

/// Default TTL for `set_state` entries written without an explicit `ttl`.
pub const STATE_DEFAULT_TTL: Duration = Duration::from_secs(3600);

/// The built-in metric store behind an atomically swappable pointer.
#[derive(Debug)]
pub struct ReloadableMetrics {
    inner: ArcSwap<MetricStore>,
    /// The definitions the live store was built for, and the lock that
    /// serialises installs.
    defs: Mutex<Vec<MetricDef>>,
}

/// Whether two definitions keep each other's series: the same shape, so
/// a value recorded under one reads the same under the other.
fn same_shape(a: &MetricDef, b: &MetricDef) -> bool {
    a.id == b.id
        && a.count == b.count
        && a.unique == b.unique
        && a.key == b.key
        && a.window == b.window
}

impl ReloadableMetrics {
    /// A store for `policy`'s metric definitions, bounded by `limits`
    /// (`limits.max_metric_keys` and `limits.max_metric_bytes`).
    pub fn new(policy: &Policy, limits: MetricLimits) -> Self {
        Self {
            inner: ArcSwap::from_pointee(MetricStore::with_limits(policy.metric_defs(), limits)),
            defs: Mutex::new(policy.metric_defs().to_vec()),
        }
    }

    /// Whether a store built for `policy` also serves the policy the live
    /// store was built for: every metric it defines is in `policy` with the
    /// same shape. Then the new store can go in before the policy swap, and
    /// no flow on either side meets a metric its store does not know.
    pub fn keeps_every_metric(&self, policy: &Policy) -> bool {
        let defs = self.defs.lock().unwrap_or_else(PoisonError::into_inner);
        defs.iter()
            .all(|old| policy.metric_defs().iter().any(|new| same_shape(old, new)))
    }

    /// Builds the store for `policy`, copies over every series whose
    /// definition is unchanged and swaps it in. The copy and the swap are
    /// one step under the install lock, so a record on the old store can
    /// be lost only in the instant of the pointer swap itself.
    ///
    /// `limits` are the new config's: a smaller budget than the old store's
    /// is respected, and series that no longer fit are dropped (and logged)
    /// rather than carried past it.
    pub fn install(&self, policy: &Policy, limits: MetricLimits) {
        let mut defs = self.defs.lock().unwrap_or_else(PoisonError::into_inner);
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
        self.inner.store(Arc::new(next));
        *defs = policy.metric_defs().to_vec();
    }

    /// Builds the store for `policy` with nothing carried over: every
    /// window starts empty.
    pub fn reset(&self, policy: &Policy, limits: MetricLimits) {
        let mut defs = self.defs.lock().unwrap_or_else(PoisonError::into_inner);
        self.inner.store(Arc::new(MetricStore::with_limits(
            policy.metric_defs(),
            limits,
        )));
        *defs = policy.metric_defs().to_vec();
    }

    /// Live key count, for diagnostics.
    pub fn key_count(&self) -> usize {
        self.inner.load().key_count()
    }
}

impl MetricSource for ReloadableMetrics {
    fn get(&self, id: &str, view: &dyn FlowView) -> Result<i64, MetricSourceError> {
        self.inner.load().get(id, view).map_err(Into::into)
    }

    fn record(&self, view: &dyn FlowView, sample: &Sample) -> Result<(), MetricSourceError> {
        let s = roxy_rules::Sample {
            head: sample.head,
            request_bytes: sample.request_bytes,
            response_bytes: sample.response_bytes,
            denied: sample.denied,
            error: sample.error,
        };
        self.inner.load().record(view, &s).map_err(Into::into)
    }
}

/// The built-in bounded TTL state store.
#[derive(Debug)]
pub struct BuiltinState(pub StateStore);

impl BuiltinState {
    pub fn new(max_entries: usize) -> Self {
        Self(StateStore::new(max_entries, STATE_DEFAULT_TTL))
    }

    /// Drops every `set_state` entry.
    pub fn clear(&self) {
        self.0.clear();
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

    const CONFIG: &str = "version: 1\nlisteners: [{ name: p, bind: 127.0.0.1:3128 }]\nmetrics:\n  \
        - { id: by_path, count: requests, key: [path], window: 1h }\n";

    fn policy() -> Policy {
        Config::from_yaml(CONFIG)
            .unwrap()
            .validate()
            .unwrap()
            .policy
    }

    /// `yaml` is the config after the listener line.
    fn policy_for(yaml: &str) -> Policy {
        let yaml = format!(
            "version: 1\nlisteners: [{{ name: p, bind: 127.0.0.1:3128 }}]\n{}",
            yaml.trim_start_matches("version: 1\n")
        );
        Config::from_yaml(&yaml).unwrap().validate().unwrap().policy
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
    /// keys instead of evicting.
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
        m.install(&policy, limits(budget));
        let store = m.inner.load();
        assert_eq!(store.max_bytes(), budget);
        assert_eq!(store.key_count(), 2, "only two series fit the new budget");
        assert!(store.byte_count() <= budget);
        drop(store);

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

    /// `reset` is the install with nothing carried: the series are gone
    /// and the next record starts a fresh window, while a plain install
    /// of the same policy keeps them.
    #[test]
    fn reset_drops_every_series_where_install_keeps_them() {
        let policy = policy();
        let m = ReloadableMetrics::new(&policy, limits(1 << 20));
        record(&m, "/a").unwrap();
        record(&m, "/a").unwrap();
        let view = MapView::new().with_str(Field::Path, "/a");
        m.install(&policy, limits(1 << 20));
        assert_eq!(m.get("by_path", &view), Ok(2));
        m.reset(&policy, limits(1 << 20));
        assert_eq!(m.get("by_path", &view), Ok(0));
        assert_eq!(m.key_count(), 0);
        record(&m, "/a").unwrap();
        assert_eq!(m.get("by_path", &view), Ok(1));
        assert!(m.keeps_every_metric(&policy));

        let state = BuiltinState::new(10);
        state.set("quarantine", "1", None).unwrap();
        state.clear();
        assert_eq!(state.get("quarantine"), None);
        assert!(state.0.is_empty());
    }

    /// Growing the budget on reload carries everything over.
    #[test]
    fn reload_with_a_larger_byte_budget_carries_everything() {
        let policy = policy();
        let m = ReloadableMetrics::new(&policy, limits(1 << 20));
        for p in ["/a", "/b", "/c"] {
            record(&m, p).unwrap();
        }
        m.install(&policy, limits(2 << 20));
        assert_eq!(m.key_count(), 3);
        assert_eq!(m.inner.load().max_bytes(), 2 << 20);
    }

    /// Adding a metric, or leaving them alone, keeps every running one;
    /// removing one or changing its shape does not. Only in the first case
    /// may the new store go in ahead of the policy swap.
    #[test]
    fn keeps_every_metric_means_same_shape_for_every_running_metric() {
        let m = ReloadableMetrics::new(&policy(), limits(1 << 20));
        assert!(m.keeps_every_metric(&policy()));
        assert!(m.keeps_every_metric(&policy_for(
            "version: 1\nmetrics:\n  - { id: by_path, count: requests, key: [path], window: 1h }\n  \
             - { id: errors, count: errors }\n"
        )));
        for changed in [
            "version: 1\n",
            "version: 1\nmetrics: [{ id: by_path, count: requests, key: [path], window: 2h }]\n",
            "version: 1\nmetrics: [{ id: by_path, count: requests, key: [host], window: 1h }]\n",
            "version: 1\nmetrics: [{ id: by_path, count: errors, key: [path], window: 1h }]\n",
        ] {
            assert!(!m.keeps_every_metric(&policy_for(changed)), "{changed}");
        }
        // Installing moves the baseline.
        m.install(&policy_for("version: 1\n"), limits(1 << 20));
        assert!(m.keeps_every_metric(&policy_for("version: 1\n")));
    }
}
