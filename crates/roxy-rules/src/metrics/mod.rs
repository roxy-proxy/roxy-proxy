//! The in-process stateful metric store.
//!
//! # Design
//!
//! * **Series table.** One [`DashMap`] per metric, keyed by the tuple of
//!   key-field values, each series behind its own `parking_lot` mutex. A hot
//!   path `get`/`record` on an existing key takes a shared shard lock plus
//!   that series' mutex; only admitting a new key (or reclaiming) takes a
//!   shard write lock. There is no global lock.
//! * **Bounded keys, no eviction.** `max_keys` counts series across all
//!   metrics, and a metric's own `max_keys` (default: the shared one) counts
//!   its series alone, so one metric fed client-chosen key values cannot
//!   take every slot from the others. Admission reserves a slot in each with
//!   a compare-and-swap on an atomic counter *while holding the shard entry
//!   for the new key*, so both bounds are exact: [`MetricStore::key_count`]
//!   never exceeds `max_keys` through admission, under any number of
//!   concurrent writers, and no key is admitted once either count has
//!   reached its cap. (The only way past a bound is
//!   [`MetricStore::carry_over`] into a store with a smaller cap; carried
//!   keys are kept and new keys are refused until enough expire.) A flow
//!   that needs a new key when its metric or the table is full gets
//!   [`MetricError::TableFull`] and must be denied. Series are only removed
//!   by [`MetricStore::reclaim`] once their whole window has expired, so
//!   reclaiming never changes a value; cumulative series are never removed.
//! * **Windows.** `window: d` uses fixed buckets of width
//!   `w = max(ceil(d / 60), 1 ms)`, `n = ceil(d / w)` (60 unless `d < 60 ms`).
//!   The store keeps `n + 1` buckets: the `n` complete ones covering `d` plus
//!   the current partial one, rotated lazily by `record` (reads never
//!   mutate). A value therefore counts every event younger than `d` and
//!   nothing older than `d + w`: at the window edge the store may *over*count
//!   by up to one bucket, never undercount. That is the fail-closed
//!   direction (a limit trips slightly early rather than late).
//!   `window` omitted = one cumulative bucket since store creation.
//! * **Unique.** `unique(<field>)` keeps one `HyperLogLog` sketch per bucket
//!   (2^12 registers, standard error ≈ 1.6 %, Ertl's improved estimator,
//!   no empirical bias tables), merged on read. A bucket holds an exact
//!   sorted set of 64-bit hashes until it has 256 distinct values, then
//!   switches to dense registers (4 KiB). So a window with ≤ 256 distinct
//!   values is counted exactly (up to 64-bit hash collisions). Hashes use a
//!   per-process random `SipHash` key so an attacker cannot pick values that
//!   collide or that land in low registers to keep the estimate down.
//!   A single windowed unique series can therefore reach 61 × 4 KiB ≈
//!   244 KiB, which is why `max_keys` alone does not bound memory; the byte
//!   budget below does.
//! * **Byte budget, no eviction.** Besides `max_keys`, the store has a byte
//!   budget `max_bytes` ([`MetricLimits`], default 256 MiB). Every series is
//!   *charged* an approximate byte cost, and the sum of charges is kept in
//!   one atomic counter ([`MetricStore::byte_count`]):
//!   - a fixed [`SERIES_OVERHEAD`] (table slot with 2× hash-table slack,
//!     mutex, series header), plus the key (`size_of::<KeyPart>()` per part
//!     plus the bytes of every string in it), plus the bucket array
//!     (`n + 1` slots of 8 bytes for a count, 24 bytes for a unique);
//!   - for each `unique` bucket, its exact set's *capacity* × 8 bytes
//!     (capacity grows in steps of [`SPARSE_CHUNK`] entries, never beyond
//!     256), or 4096 bytes once it is dense.
//!
//!   Every growth (admitting a key, growing an exact set, converting it to
//!   dense) first reserves its bytes with a compare-and-swap that refuses
//!   to take the total past `max_bytes`; a refused growth leaves the series
//!   unchanged and `record` returns [`MetricError::BudgetExhausted`], which
//!   must deny the flow exactly like `TableFull`. Nothing is evicted or
//!   dropped to make room. Bytes come back only when a bucket rotates out of
//!   its window (its set is freed) or a fully expired series is reclaimed.
//!   **Bound:** [`MetricStore::byte_count`] `≤ max_bytes` at all times,
//!   under any concurrency, including after [`MetricStore::carry_over`]
//!   (series that do not fit the destination's budget are not carried).
//!   The charge tracks the store's long-lived heap closely; it does not
//!   include allocator overhead, `DashMap` shard bookkeeping, or the
//!   transient buffer a `get` on a `unique` metric builds (at most
//!   61 × 256 × 8 + 4096 bytes ≈ 129 KiB per concurrent call, freed on
//!   return).
//! * **Keys.** Values of `host`, `tls.sni` and `scheme` are
//!   ASCII-lower-cased before keying or hashing, because the rule language
//!   compares them case-insensitively: otherwise `Example.com` and
//!   `example.com` would be two series and an attacker could split a
//!   counter. `method` is keyed as sent, as the rule language compares it.

mod budget;
#[cfg(test)]
mod budget_tests;
mod hll;
mod window;

use std::collections::HashMap;
use std::fmt;
use std::hash::{BuildHasher, RandomState};
use std::net::IpAddr;
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use parking_lot::Mutex;

use self::budget::{Budget, Refused};
use self::hll::{Hll, cardinality};
use self::window::{Geometry, Window};
use crate::config::MetricCount;
use crate::eval::FailClosedReason;
use crate::policy::MetricDef;
use crate::types::Field;
use crate::view::{FlowView, Value};

#[cfg(test)]
use self::hll::SPARSE_CHUNK;

/// A monotonic time source; injectable for tests.
pub type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

/// `record` runs a reclaim pass every this many calls.
const RECLAIM_EVERY: u64 = 4096;
/// When the table is full, a new key may trigger a reclaim pass at most
/// this often (a reclaim is O(keys), so an attacker must not be able to
/// force one per request).
const FULL_RECLAIM_INTERVAL_NS: i64 = 100_000_000;

/// Default [`MetricLimits::max_bytes`]: 256 MiB.
pub const DEFAULT_MAX_METRIC_BYTES: usize = 256 << 20;
/// Default [`MetricLimits::max_keys`] (matches `limits.max_metric_keys`).
pub const DEFAULT_MAX_METRIC_KEYS: usize = 100_000;
/// Fixed bytes charged per series on top of its key and buckets: the
/// table slot (doubled for hash-table growth slack), the mutex and the
/// series header.
pub(crate) const SERIES_OVERHEAD: usize = 2 * (size_of::<Key>() + size_of::<Mutex<Series>>()) + 16;

/// Bounds on a [`MetricStore`]'s size. Both are hard: a flow that would
/// take the store past either is denied, never served by evicting data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricLimits {
    /// Series across all metrics.
    pub max_keys: usize,
    /// Approximate bytes across all series (see the module docs for what
    /// is charged).
    pub max_bytes: usize,
}

impl Default for MetricLimits {
    fn default() -> Self {
        Self {
            max_keys: DEFAULT_MAX_METRIC_KEYS,
            max_bytes: DEFAULT_MAX_METRIC_BYTES,
        }
    }
}

/// What [`MetricStore::carry_over`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CarryOverReport {
    /// Series copied into the new store.
    pub carried: usize,
    /// Live series not copied because they did not fit the new store's
    /// byte budget. Their history is lost (the new store starts them at 0
    /// if they are recorded again), so a non-zero count should be logged.
    pub skipped_budget: usize,
}

/// The proxy-facing interface to a metric store (the adapter behind
/// [`FlowView::metric`] and the post-decision `record` call).
pub trait MetricSource: Send + Sync {
    fn get(&self, id: &str, view: &dyn FlowView) -> Result<i64, MetricError>;
    fn record(&self, view: &dyn FlowView, sample: &Sample) -> Result<(), MetricError>;
}

/// What one exchange contributed since its last [`MetricStore::record`].
/// An exchange records several samples over its life:
///
/// * one with `head` set, right after the forwarding decision: it counts
///   `requests` and `unique(..)` (and `denied` if the head decision
///   denied);
/// * one per streamed chunk, carrying that chunk's `request_bytes` or
///   `response_bytes`, so a byte metric grows while the exchange streams;
/// * one at the end with `error` (and `denied`, if a watching rule stopped
///   the exchange).
///
/// A sample whose contribution to a metric is zero does not touch it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Sample {
    /// This is the exchange's head sample: count `requests` and
    /// `unique(..)`. Exactly one sample per exchange sets it.
    pub head: bool,
    pub request_bytes: u64,
    pub response_bytes: u64,
    /// The exchange was denied (at the head, or stopped by a watching
    /// rule). Set on at most one sample per exchange.
    pub denied: bool,
    /// The exchange ended in an error (upstream failure, 5xx from roxy).
    pub error: bool,
}

/// Why the store could not answer or record. Every variant must fail the
/// flow closed.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum MetricError {
    #[error("unknown metric {0}")]
    Unknown(String),
    #[error("metric table full (metric {metric})")]
    TableFull { metric: String },
    /// Recording would take the store past its byte budget
    /// ([`MetricLimits::max_bytes`]). Treat exactly like `TableFull`.
    #[error("metric byte budget exhausted (metric {metric})")]
    BudgetExhausted { metric: String },
    #[error("metric {metric}: key field {field:?} unavailable")]
    KeyUnavailable { metric: String, field: Field },
    #[error("metric {metric}: {reason}")]
    FilterFailed {
        metric: String,
        reason: FailClosedReason,
    },
}

/// One series for export (`/metrics`, debugging).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricSnapshot {
    pub id: String,
    /// Key-field values in `key:` order, rendered as text; empty for a
    /// global series.
    pub key: Vec<String>,
    pub value: i64,
}

// ----- keys -----------------------------------------------------------------

/// One owned key-field value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum KeyPart {
    Str(Box<str>),
    Int(i64),
    Bool(bool),
    Ip(IpAddr),
    List(Box<[Box<str>]>),
}

impl fmt::Display for KeyPart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Str(s) => f.write_str(s),
            Self::Int(n) => write!(f, "{n}"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Ip(ip) => write!(f, "{ip}"),
            Self::List(items) => f.write_str(&items.join(",")),
        }
    }
}

type Key = Box<[KeyPart]>;

fn key_part(metric: &str, view: &dyn FlowView, f: Field) -> Result<KeyPart, MetricError> {
    let fold = |s: &str| -> Box<str> {
        if f.case_insensitive() {
            s.to_ascii_lowercase().into()
        } else {
            s.into()
        }
    };
    Ok(match view.field(f) {
        Value::Str(s) => KeyPart::Str(fold(&s)),
        Value::Int(n) => KeyPart::Int(n),
        Value::Bool(b) => KeyPart::Bool(b),
        Value::Ip(ip) => KeyPart::Ip(ip),
        Value::List(items) => KeyPart::List(items.iter().map(|s| fold(s)).collect()),
        Value::Absent => {
            return Err(MetricError::KeyUnavailable {
                metric: metric.to_owned(),
                field: f,
            });
        }
    })
}

/// Process-wide hash key for `unique` values. Shared by every store so
/// sketches survive [`MetricStore::carry_over`].
fn unique_hasher() -> &'static RandomState {
    static H: OnceLock<RandomState> = OnceLock::new();
    H.get_or_init(RandomState::new)
}

#[derive(Debug, Clone)]
enum Data {
    Count(Window<u64>),
    Unique(Window<Hll>),
}

/// One series and the bytes it is charged against the store's budget.
/// Invariant: the budget's total is the sum of `bytes` over all series.
#[derive(Debug, Clone)]
struct Series {
    bytes: usize,
    data: Data,
}

enum Delta {
    Add(u64),
    Insert(u64),
}

/// Bytes charged for a key: the part array plus every string in it.
fn key_bytes(key: &[KeyPart]) -> usize {
    size_of_val(key)
        + key
            .iter()
            .map(|p| match p {
                KeyPart::Str(s) => s.len(),
                KeyPart::List(items) => {
                    size_of_val::<[Box<str>]>(items) + items.iter().map(|s| s.len()).sum::<usize>()
                }
                KeyPart::Int(_) | KeyPart::Bool(_) | KeyPart::Ip(_) => 0,
            })
            .sum::<usize>()
}

impl Series {
    /// A new, empty series. Its `bytes` are computed but *not* charged.
    fn new(unique: bool, geom: Option<Geometry>, now: i64, key: &[KeyPart]) -> Self {
        let data = if unique {
            Data::Unique(Window::new(geom, now))
        } else {
            Data::Count(Window::new(geom, now))
        };
        let mut s = Self { bytes: 0, data };
        s.bytes = s.compute_bytes(key);
        s
    }

    /// Recompute this series' charge from its contents.
    fn compute_bytes(&self, key: &[KeyPart]) -> usize {
        SERIES_OVERHEAD
            + key_bytes(key)
            + match &self.data {
                Data::Count(w) => w.bytes(),
                Data::Unique(w) => w.bytes(),
            }
    }

    /// Apply `delta` at `now`, charging growth to `budget` (and returning
    /// bytes freed by bucket rotation). On `Err` the value is unchanged.
    fn apply(
        &mut self,
        geom: Option<Geometry>,
        now: i64,
        delta: &Delta,
        budget: &Budget,
    ) -> Result<(), Refused> {
        match (&mut self.data, delta) {
            (Data::Count(w), Delta::Add(n)) => {
                // Count buckets are preallocated: rotation frees nothing
                // and an increment never grows.
                let (slot, _) = w.current(geom, now);
                *slot = slot.saturating_add(*n);
                Ok(())
            }
            (Data::Unique(w), Delta::Insert(h)) => {
                let (slot, rotated) = w.current(geom, now);
                let r = slot.insert(*h, budget);
                if rotated > 0 {
                    budget.give(rotated);
                    self.bytes -= rotated;
                }
                let change = r?;
                self.bytes = self.bytes + change.added - change.freed;
                Ok(())
            }
            // A series' kind is fixed by its metric; mismatches cannot occur.
            _ => Ok(()),
        }
    }

    fn value(&self, geom: Option<Geometry>, now: i64) -> i64 {
        let v = match &self.data {
            Data::Count(w) => w.live(geom, now).fold(0u64, |a, b| a.saturating_add(*b)),
            Data::Unique(w) => cardinality(w.live(geom, now)),
        };
        i64::try_from(v).unwrap_or(i64::MAX)
    }

    fn expired(&self, geom: Option<Geometry>, now: i64) -> bool {
        match &self.data {
            Data::Count(w) => w.expired(geom, now),
            Data::Unique(w) => w.expired(geom, now),
        }
    }

    fn shift(&mut self, geom: Option<Geometry>, shift: i64) {
        match &mut self.data {
            Data::Count(w) => w.shift(geom, shift),
            Data::Unique(w) => w.shift(geom, shift),
        }
    }
}

// ----- the store ------------------------------------------------------------

/// One metric's definition and its series table.
struct Metric {
    def: MetricDef,
    geom: Option<Geometry>,
    series: DashMap<Key, Mutex<Series>>,
    /// Series this metric alone may hold (its `max_keys`, or the shared
    /// limit), with a CAS-reserved count like the store's `live`.
    max_keys: usize,
    live: AtomicUsize,
}

impl Metric {
    /// Whether `sample` contributes to this metric at all. Checked before
    /// the `where` filter and the key, so a per-chunk byte sample costs
    /// nothing for metrics that do not count bytes.
    fn counts(&self, sample: &Sample) -> bool {
        match self.def.count {
            MetricCount::Requests | MetricCount::Unique(_) => sample.head,
            MetricCount::RequestBytes => sample.request_bytes > 0,
            MetricCount::ResponseBytes => sample.response_bytes > 0,
            MetricCount::Errors => sample.error,
            MetricCount::Denied => sample.denied,
        }
    }

    fn key(&self, view: &dyn FlowView) -> Result<Key, MetricError> {
        self.def
            .key
            .iter()
            .map(|&f| key_part(&self.def.id, view, f))
            .collect()
    }
}

/// Stateful metric series for one compiled policy. `Send + Sync`;
/// share it behind an `Arc`. See the module docs for the design and bounds.
pub struct MetricStore {
    metrics: Vec<Metric>,
    by_id: HashMap<String, usize>,
    max_keys: usize,
    live: AtomicUsize,
    budget: Budget,
    clock: Clock,
    origin: Instant,
    records: AtomicU64,
    last_full_reclaim: AtomicI64,
}

impl fmt::Debug for MetricStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MetricStore")
            .field("metrics", &self.by_id.len())
            .field("keys", &self.key_count())
            .field("max_keys", &self.max_keys)
            .field("bytes", &self.byte_count())
            .field("max_bytes", &self.budget.max)
            .finish_non_exhaustive()
    }
}

impl MetricStore {
    /// A store for `defs` holding at most `max_keys` series in total, with
    /// the default byte budget ([`DEFAULT_MAX_METRIC_BYTES`]).
    pub fn new(defs: &[MetricDef], max_keys: usize) -> Self {
        Self::with_clock(defs, max_keys, Arc::new(Instant::now))
    }

    /// A store for `defs` bounded by `limits` (at most `max_keys` series and
    /// at most `max_bytes` charged bytes; see the module docs).
    pub fn with_limits(defs: &[MetricDef], limits: MetricLimits) -> Self {
        Self::with_limits_and_clock(defs, limits, Arc::new(Instant::now))
    }

    /// Like [`MetricStore::new`] with an injected clock (tests).
    pub fn with_clock(defs: &[MetricDef], max_keys: usize, clock: Clock) -> Self {
        Self::with_limits_and_clock(
            defs,
            MetricLimits {
                max_keys,
                max_bytes: DEFAULT_MAX_METRIC_BYTES,
            },
            clock,
        )
    }

    /// Like [`MetricStore::with_limits`] with an injected clock (tests).
    pub fn with_limits_and_clock(defs: &[MetricDef], limits: MetricLimits, clock: Clock) -> Self {
        let max_keys = limits.max_keys;
        let origin = clock();
        let metrics: Vec<Metric> = defs
            .iter()
            .map(|d| Metric {
                def: d.clone(),
                geom: d.window.map(Geometry::new),
                series: DashMap::new(),
                max_keys: d.max_keys.unwrap_or(max_keys),
                live: AtomicUsize::new(0),
            })
            .collect();
        let by_id = metrics
            .iter()
            .enumerate()
            .map(|(i, m)| (m.def.id.clone(), i))
            .collect();
        Self {
            metrics,
            by_id,
            max_keys,
            live: AtomicUsize::new(0),
            budget: Budget::new(limits.max_bytes),
            clock,
            origin,
            records: AtomicU64::new(0),
            last_full_reclaim: AtomicI64::new(i64::MIN),
        }
    }

    /// Signed nanoseconds since this store's origin.
    fn now(&self) -> i64 {
        signed_nanos((self.clock)(), self.origin)
    }

    fn metric(&self, id: &str) -> Result<&Metric, MetricError> {
        self.by_id
            .get(id)
            .map(|&i| &self.metrics[i])
            .ok_or_else(|| MetricError::Unknown(id.to_owned()))
    }

    /// Value of `id` for the key derived from `view`, over the live window.
    /// A key that has never been recorded reads 0 *without* being admitted
    /// (reads never allocate a series). `Err` on an unknown id or an
    /// unavailable key field.
    pub fn get(&self, id: &str, view: &dyn FlowView) -> Result<i64, MetricError> {
        let m = self.metric(id)?;
        let key = m.key(view)?;
        let now = self.now();
        Ok(m.series
            .get(&key)
            .map_or(0, |s| s.lock().value(m.geom, now)))
    }

    /// Record one [`Sample`] for every metric whose
    /// `where` filter matches `view`. Admits new keys. All matching metrics
    /// are attempted; the first error is returned: `TableFull` if a key
    /// would be new and the table is full, `BudgetExhausted` if the series
    /// (new or existing) would need bytes the budget does not have (the
    /// series is left unchanged), `FilterFailed` if a filter hit an
    /// unavailable input, `KeyUnavailable` if a key (or the `unique` field)
    /// is absent. Any `Err` means the caller must deny the flow.
    pub fn record(&self, view: &dyn FlowView, sample: &Sample) -> Result<(), MetricError> {
        let now = self.now();
        let mut first_err = None;
        for m in self.metrics.iter().filter(|m| m.counts(sample)) {
            if let Err(e) = self.record_one(m, view, sample, now) {
                first_err.get_or_insert(e);
            }
        }
        if self.records.fetch_add(1, Ordering::Relaxed) % RECLAIM_EVERY == RECLAIM_EVERY - 1 {
            self.reclaim_at(now);
        }
        first_err.map_or(Ok(()), Err)
    }

    fn record_one(
        &self,
        m: &Metric,
        view: &dyn FlowView,
        sample: &Sample,
        now: i64,
    ) -> Result<(), MetricError> {
        match m.def.matches(view) {
            Ok(true) => {}
            Ok(false) => return Ok(()),
            Err(reason) => {
                return Err(MetricError::FilterFailed {
                    metric: m.def.id.clone(),
                    reason,
                });
            }
        }
        let key = m.key(view)?;
        let delta = match &m.def.count {
            MetricCount::Requests => Delta::Add(u64::from(sample.head)),
            MetricCount::RequestBytes => Delta::Add(sample.request_bytes),
            MetricCount::ResponseBytes => Delta::Add(sample.response_bytes),
            MetricCount::Errors => Delta::Add(u64::from(sample.error)),
            MetricCount::Denied => Delta::Add(u64::from(sample.denied)),
            MetricCount::Unique(_) => {
                // Compiled defs always carry the field; be closed if not.
                let f = m
                    .def
                    .unique
                    .ok_or_else(|| MetricError::Unknown(m.def.id.clone()))?;
                let part = key_part(&m.def.id, view, f)?;
                Delta::Insert(unique_hasher().hash_one(&part))
            }
        };
        if matches!(delta, Delta::Add(0)) {
            // Nothing to count: do not occupy (or be refused) a key.
            return Ok(());
        }
        let exhausted = || MetricError::BudgetExhausted {
            metric: m.def.id.clone(),
        };
        if let Some(s) = m.series.get(&key) {
            let r = s.lock().apply(m.geom, now, &delta, &self.budget);
            drop(s);
            if r.is_ok() {
                return Ok(());
            }
            // Out of bytes: reclaim (never while holding an entry of this
            // map, which `retain` would deadlock on) and retry once.
            if self.reclaim_if_due(now)
                && let Some(s) = m.series.get(&key)
                && s.lock().apply(m.geom, now, &delta, &self.budget).is_ok()
            {
                return Ok(());
            }
            return Err(exhausted());
        }
        // New key (probably). Reclaim first if full: never while holding an
        // entry of this map.
        if self.live.load(Ordering::Acquire) >= self.max_keys
            || m.live.load(Ordering::Acquire) >= m.max_keys
            || self.budget.used().saturating_add(SERIES_OVERHEAD) > self.budget.max
        {
            self.reclaim_if_due(now);
        }
        match m.series.entry(key) {
            Entry::Occupied(e) => e
                .get()
                .lock()
                .apply(m.geom, now, &delta, &self.budget)
                .map_err(|Refused| exhausted())?,
            Entry::Vacant(v) => {
                if !self.reserve(m) {
                    return Err(MetricError::TableFull {
                        metric: m.def.id.clone(),
                    });
                }
                let mut s = Series::new(m.def.unique.is_some(), m.geom, now, v.key());
                // Charge the empty series, then its first value; undo both
                // (and the key slot) if either is refused.
                let admitted = self.budget.take(s.bytes).is_ok()
                    && (s.apply(m.geom, now, &delta, &self.budget).is_ok() || {
                        self.budget.give(s.bytes);
                        false
                    });
                if !admitted {
                    self.release(m, 1);
                    return Err(exhausted());
                }
                v.insert(Mutex::new(s));
            }
        }
        Ok(())
    }

    /// Take one key slot in `m` and in the table; false if either is full.
    /// CAS loops, so neither count exceeds its cap through admission.
    fn reserve(&self, m: &Metric) -> bool {
        if !take_slot(&m.live, m.max_keys) {
            return false;
        }
        if take_slot(&self.live, self.max_keys) {
            return true;
        }
        m.live.fetch_sub(1, Ordering::AcqRel);
        false
    }

    /// Give back `n` key slots taken by [`MetricStore::reserve`] for `m`.
    fn release(&self, m: &Metric, n: usize) {
        m.live.fetch_sub(n, Ordering::AcqRel);
        self.live.fetch_sub(n, Ordering::AcqRel);
    }

    /// Run a reclaim pass unless one ran in the last 100 ms. Returns whether
    /// this call ran one.
    fn reclaim_if_due(&self, now: i64) -> bool {
        let last = self.last_full_reclaim.load(Ordering::Acquire);
        let due = now.saturating_sub(last) >= FULL_RECLAIM_INTERVAL_NS
            && self
                .last_full_reclaim
                .compare_exchange(last, now, Ordering::AcqRel, Ordering::Acquire)
                .is_ok();
        if due {
            self.reclaim_at(now);
        }
        due
    }

    /// Remove windowed series whose whole window has expired (their value
    /// is 0, so nothing is lost) and return their bytes to the budget.
    /// Cumulative series are never removed. Returns the number of series
    /// removed. Also run every 4096 `record` calls, and (at most every
    /// 100 ms) when a record meets a full table or an exhausted budget.
    pub fn reclaim(&self) -> usize {
        self.reclaim_at(self.now())
    }

    fn reclaim_at(&self, now: i64) -> usize {
        let mut removed = 0;
        let mut freed = 0;
        for m in self.metrics.iter().filter(|m| m.geom.is_some()) {
            let mut from_m = 0;
            m.series.retain(|_, s| {
                let s = s.get_mut();
                let keep = !s.expired(m.geom, now);
                if !keep {
                    from_m += 1;
                    freed += s.bytes;
                }
                keep
            });
            if from_m > 0 {
                self.release(m, from_m);
                removed += from_m;
            }
        }
        if freed > 0 {
            self.budget.give(freed);
        }
        removed
    }

    /// Reload retention: copy series from `previous` for every metric
    /// whose [`MetricDef::fingerprint`] is unchanged; every other metric
    /// starts empty. Carried series are kept even
    /// beyond this store's `max_keys` or the metric's (new keys are then
    /// refused until enough expire), but *not* beyond its byte budget: a
    /// series whose charge does not fit is skipped and counted in
    /// [`CarryOverReport::skipped_budget`], so `byte_count() <= max_bytes`
    /// still holds afterwards. Call before the store takes traffic.
    pub fn carry_over(&self, previous: &MetricStore) -> CarryOverReport {
        let mut report = CarryOverReport::default();
        if std::ptr::eq(self, previous) {
            return report;
        }
        // Event at previous-store time t is at this store's time t + shift.
        let shift = signed_nanos(previous.origin, self.origin);
        let prev_now = previous.now();
        for m in &self.metrics {
            let Some(&pi) = previous.by_id.get(&m.def.id) else {
                continue;
            };
            let pm = &previous.metrics[pi];
            if pm.def.fingerprint() != m.def.fingerprint() {
                continue;
            }
            for entry in &pm.series {
                let mut s = entry.value().lock().clone();
                if s.expired(pm.geom, prev_now) {
                    continue;
                }
                s.shift(m.geom, shift);
                // A clone's exact sets may be smaller than the original's.
                s.bytes = s.compute_bytes(entry.key());
                if self.budget.take(s.bytes).is_err() {
                    report.skipped_budget += 1;
                    continue;
                }
                match m.series.insert(entry.key().clone(), Mutex::new(s)) {
                    None => {
                        m.live.fetch_add(1, Ordering::AcqRel);
                        self.live.fetch_add(1, Ordering::AcqRel);
                    }
                    Some(old) => self.budget.give(old.into_inner().bytes),
                }
                report.carried += 1;
            }
        }
        report
    }

    /// Series currently held across all metrics.
    pub fn key_count(&self) -> usize {
        self.live.load(Ordering::Acquire)
    }

    /// Bytes currently charged across all series; never exceeds
    /// [`MetricStore::max_bytes`].
    pub fn byte_count(&self) -> usize {
        self.budget.used()
    }

    /// The byte budget this store was built with.
    pub fn max_bytes(&self) -> usize {
        self.budget.max
    }

    /// Every series and its current value, sorted by id then key.
    pub fn snapshot(&self) -> Vec<MetricSnapshot> {
        let now = self.now();
        let mut out = Vec::new();
        for m in &self.metrics {
            for entry in &m.series {
                out.push(MetricSnapshot {
                    id: m.def.id.clone(),
                    key: entry.key().iter().map(ToString::to_string).collect(),
                    value: entry.value().lock().value(m.geom, now),
                });
            }
        }
        out.sort_by(|a, b| (&a.id, &a.key).cmp(&(&b.id, &b.key)));
        out
    }
}

impl MetricSource for MetricStore {
    fn get(&self, id: &str, view: &dyn FlowView) -> Result<i64, MetricError> {
        MetricStore::get(self, id, view)
    }

    fn record(&self, view: &dyn FlowView, sample: &Sample) -> Result<(), MetricError> {
        MetricStore::record(self, view, sample)
    }
}

/// Take one slot of `cap` from `live`; false if it is full. A CAS loop, so
/// the count never passes `cap` through admission.
fn take_slot(live: &AtomicUsize, cap: usize) -> bool {
    live.try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
        (n < cap).then_some(n + 1)
    })
    .is_ok()
}

/// `a - b` in signed nanoseconds, saturating.
fn signed_nanos(a: Instant, b: Instant) -> i64 {
    match a.checked_duration_since(b) {
        Some(d) => i64::try_from(d.as_nanos()).unwrap_or(i64::MAX),
        None => i64::try_from(b.duration_since(a).as_nanos()).map_or(i64::MIN, |n| -n),
    }
}
