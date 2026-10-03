//! Adapters from the `roxy-rules` metric and state stores to the proxy's
//! [`MetricSource`] / [`StateSource`] traits (`DESIGN.md` §6.4, §6.5).
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
use roxy_rules::{FlowView, MetricError, MetricStore, Phase, Policy, StateStore};

/// Default TTL for `set_state` entries written without an explicit `ttl`.
pub const STATE_DEFAULT_TTL: Duration = Duration::from_secs(3600);

/// The built-in metric store behind an atomically swappable pointer.
#[derive(Debug)]
pub struct ReloadableMetrics {
    inner: ArcSwap<MetricStore>,
}

impl ReloadableMetrics {
    /// A store for `policy`'s metric definitions, capped at `max_keys`.
    pub fn new(policy: &Policy, max_keys: usize) -> Self {
        Self {
            inner: ArcSwap::from_pointee(MetricStore::new(policy.metric_defs(), max_keys)),
        }
    }

    /// Builds the store for a new policy and copies over every series whose
    /// definition is unchanged. Call [`ReloadableMetrics::install`] with the
    /// result once the policy swap has succeeded; drop it otherwise.
    pub fn prepare(&self, policy: &Policy, max_keys: usize) -> MetricStore {
        let next = MetricStore::new(policy.metric_defs(), max_keys);
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
        // evict (§6.4, §12).
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

    fn record(
        &self,
        phase: Phase,
        view: &dyn FlowView,
        sample: &Sample,
    ) -> Result<(), MetricSourceError> {
        let s = roxy_rules::Sample {
            request_bytes: sample.request_bytes,
            response_bytes: sample.response_bytes,
            denied: sample.denied,
            error: sample.error,
        };
        self.inner.load().record(phase, view, &s).map_err(map_err)
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
