//! The in-process stateful metric store (`DESIGN.md` §6.4).
//!
//! # Design
//!
//! * **Series table.** One [`DashMap`] per metric, keyed by the tuple of
//!   key-field values, each series behind its own `parking_lot` mutex. A hot
//!   path `get`/`record` on an existing key takes a shared shard lock plus
//!   that series' mutex; only admitting a new key (or reclaiming) takes a
//!   shard write lock. There is no global lock.
//! * **Bounded keys, no eviction.** `max_keys` counts series across all
//!   metrics. Admission reserves a slot with a compare-and-swap on one
//!   atomic counter *while holding the shard entry for the new key*, so the
//!   bound is exact: [`MetricStore::key_count`] never exceeds `max_keys`
//!   through admission, under any number of concurrent writers, and no key is
//!   admitted once the count has reached `max_keys`. (The only way past the
//!   bound is [`MetricStore::carry_over`] into a store with a smaller
//!   `max_keys`; carried keys are kept and new keys are refused until enough
//!   expire.) A flow that needs a new key when the table is full gets
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
//!   Memory per windowed unique series is at most 61 × 4 KiB ≈ 244 KiB and
//!   grows by at most ~16 bytes amortised per recorded flow until then.
//! * **Keys.** Values of `host`, `dst.host`, `tls.sni`, `method` and
//!   `scheme` are ASCII-lower-cased before keying or hashing, because the
//!   rule language compares them case-insensitively: otherwise `GET` and
//!   `get` would be two series and an attacker could split a counter.

use std::collections::HashMap;
use std::fmt;
use std::hash::{BuildHasher, RandomState};
use std::net::IpAddr;
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use parking_lot::Mutex;

use crate::config::{MetricCount, Phase};
use crate::eval::FailClosedReason;
use crate::policy::MetricDef;
use crate::types::Field;
use crate::view::{FlowView, Value};

/// A monotonic time source; injectable for tests.
pub type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

/// Buckets per window.
const BUCKETS: u64 = 60;
/// Smallest bucket width.
const MIN_BUCKET_NS: u64 = 1_000_000;
/// `record` runs a reclaim pass every this many calls.
const RECLAIM_EVERY: u64 = 4096;
/// When the table is full, a new key may trigger a reclaim pass at most
/// this often (a reclaim is O(keys), so an attacker must not be able to
/// force one per request).
const FULL_RECLAIM_INTERVAL_NS: i64 = 100_000_000;

/// The proxy-facing interface to a metric store (the adapter behind
/// [`FlowView::metric`] and the post-decision `record` call).
pub trait MetricSource: Send + Sync {
    fn get(&self, id: &str, view: &dyn FlowView) -> Result<i64, MetricError>;
    fn record(&self, phase: Phase, view: &dyn FlowView, sample: &Sample)
    -> Result<(), MetricError>;
}

/// What one flow contributed in a phase.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Sample {
    pub request_bytes: u64,
    pub response_bytes: u64,
    /// The flow was denied in this phase.
    pub denied: bool,
    /// The flow ended in an error (upstream failure, 5xx from roxy).
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

/// Fields the rule language compares ASCII case-insensitively.
fn case_insensitive(f: Field) -> bool {
    matches!(
        f,
        Field::Host | Field::DstHost | Field::TlsSni | Field::Method | Field::Scheme
    )
}

fn key_part(metric: &str, view: &dyn FlowView, f: Field) -> Result<KeyPart, MetricError> {
    let fold = |s: &str| -> Box<str> {
        if case_insensitive(f) {
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

// ----- HyperLogLog ----------------------------------------------------------

const HLL_P: u32 = 12;
const HLL_M: usize = 1 << HLL_P;
const HLL_Q: u32 = 64 - HLL_P;
/// Distinct hashes kept exactly before a bucket switches to registers.
const SPARSE_MAX: usize = 256;

type Registers = [u8; HLL_M];

/// A `HyperLogLog` sketch over pre-hashed 64-bit values: an exact sorted
/// hash set while small, dense registers after [`SPARSE_MAX`] values.
#[derive(Debug, Clone)]
enum Hll {
    Sparse(Vec<u64>),
    Dense(Box<Registers>),
}

impl Default for Hll {
    fn default() -> Self {
        Self::Sparse(Vec::new())
    }
}

fn set_register(regs: &mut Registers, h: u64) {
    let idx = usize::try_from(h >> HLL_Q).unwrap_or(0);
    let w = h & ((1 << HLL_Q) - 1);
    let rho = if w == 0 {
        HLL_Q + 1
    } else {
        w.leading_zeros() - HLL_P + 1
    };
    let rho = u8::try_from(rho).unwrap_or(u8::MAX);
    if regs[idx] < rho {
        regs[idx] = rho;
    }
}

impl Hll {
    fn insert(&mut self, h: u64) {
        match self {
            Self::Sparse(v) => match v.binary_search(&h) {
                Ok(_) => {}
                Err(i) if v.len() < SPARSE_MAX => v.insert(i, h),
                Err(_) => {
                    let mut regs = Box::new([0u8; HLL_M]);
                    for &x in v.iter() {
                        set_register(&mut regs, x);
                    }
                    set_register(&mut regs, h);
                    *self = Self::Dense(regs);
                }
            },
            Self::Dense(regs) => set_register(regs, h),
        }
    }
}

/// Cardinality of the union of `sketches`: exact if all are sparse,
/// otherwise the `HyperLogLog` estimate of the merged registers.
fn cardinality<'a>(sketches: impl Iterator<Item = &'a Hll>) -> u64 {
    let mut exact: Vec<u64> = Vec::new();
    let mut dense: Option<Box<Registers>> = None;
    for s in sketches {
        match s {
            Hll::Sparse(v) => exact.extend_from_slice(v),
            Hll::Dense(r) => {
                let acc = dense.get_or_insert_with(|| Box::new([0u8; HLL_M]));
                for (a, b) in acc.iter_mut().zip(r.iter()) {
                    *a = (*a).max(*b);
                }
            }
        }
    }
    match dense {
        None => {
            exact.sort_unstable();
            exact.dedup();
            exact.len() as u64
        }
        Some(mut regs) => {
            for h in exact {
                set_register(&mut regs, h);
            }
            round_estimate(estimate(&regs))
        }
    }
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "a finite, non-negative estimate far below u64::MAX"
)]
fn round_estimate(e: f64) -> u64 {
    if e.is_finite() && e > 0.0 {
        e.round() as u64
    } else {
        0
    }
}

/// Ertl's improved raw estimator ("New cardinality estimation algorithms
/// for `HyperLogLog` sketches", 2017): unbiased over the whole range without
/// empirical correction tables.
fn estimate(regs: &Registers) -> f64 {
    let q = HLL_Q as usize;
    let mut hist = [0u32; HLL_Q as usize + 2];
    for &r in regs {
        hist[usize::from(r).min(q + 1)] += 1;
    }
    let m = f64::from(1u32 << HLL_P);
    let mut z = m * tau(1.0 - f64::from(hist[q + 1]) / m);
    for k in (1..=q).rev() {
        z = f64::midpoint(z, f64::from(hist[k]));
    }
    z += m * sigma(f64::from(hist[0]) / m);
    let alpha_inf = 0.5 / std::f64::consts::LN_2;
    alpha_inf * m * m / z
}

#[allow(
    clippy::float_cmp,
    reason = "fixed-point iteration ends when z stops changing"
)]
fn sigma(mut x: f64) -> f64 {
    if x == 1.0 {
        return f64::INFINITY;
    }
    let mut y = 1.0;
    let mut z = x;
    loop {
        x *= x;
        let prev = z;
        z += x * y;
        y += y;
        if z == prev {
            return z;
        }
    }
}

#[allow(
    clippy::float_cmp,
    reason = "fixed-point iteration ends when z stops changing"
)]
fn tau(mut x: f64) -> f64 {
    if x == 0.0 || x == 1.0 {
        return 0.0;
    }
    let mut y = 1.0;
    let mut z = 1.0 - x;
    loop {
        x = x.sqrt();
        let prev = z;
        y *= 0.5;
        z -= (1.0 - x).powi(2) * y;
        if z == prev {
            return z / 3.0;
        }
    }
}

// ----- windows --------------------------------------------------------------

/// Bucket layout of a windowed metric. Times are signed nanoseconds since
/// the store's origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Geometry {
    width: i64,
    /// Buckets covering the window; `n + 1` are kept (plus the partial one).
    n: i64,
}

impl Geometry {
    fn new(window: Duration) -> Self {
        let d = u64::try_from(window.as_nanos())
            .unwrap_or(u64::MAX)
            .clamp(1, i64::MAX.unsigned_abs());
        let width = d.div_ceil(BUCKETS).max(MIN_BUCKET_NS);
        let n = d.div_ceil(width).max(1);
        Self {
            width: i64::try_from(width).unwrap_or(i64::MAX),
            n: i64::try_from(n).unwrap_or(1),
        }
    }

    fn bucket(self, t: i64) -> i64 {
        t.div_euclid(self.width)
    }
}

trait Slot: Default + Clone {
    fn clear(&mut self);
}

impl Slot for u64 {
    fn clear(&mut self) {
        *self = 0;
    }
}

impl Slot for Hll {
    fn clear(&mut self) {
        *self = Self::default();
    }
}

/// A ring of buckets. `head` is the bucket number of the newest slot;
/// cumulative metrics use one slot and ignore `head`.
#[derive(Debug, Clone)]
struct Window<T> {
    head: i64,
    slots: Box<[T]>,
}

fn ring_index(bucket: i64, len: usize) -> usize {
    let len_i = i64::try_from(len).unwrap_or(i64::MAX);
    usize::try_from(bucket.rem_euclid(len_i)).unwrap_or(0)
}

impl<T: Slot> Window<T> {
    fn new(geom: Option<Geometry>, now: i64) -> Self {
        let (len, head) = match geom {
            Some(g) => (usize::try_from(g.n + 1).unwrap_or(1), g.bucket(now)),
            None => (1, 0),
        };
        Self {
            head,
            slots: vec![T::default(); len].into_boxed_slice(),
        }
    }

    /// The slot for an event at `now`, rotating out expired buckets. An
    /// event "before" `head` (clock skew across a reload) goes into the head
    /// bucket, which only makes it live longer.
    fn current(&mut self, geom: Option<Geometry>, now: i64) -> &mut T {
        let len = self.slots.len();
        let Some(g) = geom else {
            return &mut self.slots[0];
        };
        let b = g.bucket(now);
        if b > self.head {
            let steps = (b - self.head).min(g.n + 1);
            for k in 1..=steps {
                self.slots[ring_index(self.head + k, len)].clear();
            }
            self.head = b;
        }
        &mut self.slots[ring_index(self.head, len)]
    }

    /// Buckets still inside the window at `now`.
    fn live(&self, geom: Option<Geometry>, now: i64) -> impl Iterator<Item = &T> {
        let len = self.slots.len();
        let oldest = geom.map_or(i64::MIN, |g| g.bucket(now) - g.n);
        let head = self.head;
        (0..len).filter_map(move |k| {
            let b = head - i64::try_from(k).unwrap_or(0);
            (b >= oldest).then(|| &self.slots[ring_index(b, len)])
        })
    }

    /// Every bucket has left the window (never true for cumulative).
    fn expired(&self, geom: Option<Geometry>, now: i64) -> bool {
        geom.is_some_and(|g| self.head < g.bucket(now) - g.n)
    }

    /// Move to a store whose clock origin is `shift` ns earlier (event at
    /// old time `t` is at new time `t + shift`). Rounds to the later bucket.
    fn shift(&mut self, geom: Option<Geometry>, shift: i64) {
        if let Some(g) = geom {
            let whole = shift.div_euclid(g.width) + i64::from(shift.rem_euclid(g.width) != 0);
            self.head = self.head.saturating_add(whole);
            // Keep bucket b in ring slot b mod len.
            let len = self.slots.len();
            self.slots.rotate_right(ring_index(whole, len));
        }
    }
}

#[derive(Debug, Clone)]
enum Series {
    Count(Window<u64>),
    Unique(Window<Hll>),
}

enum Delta {
    Add(u64),
    Insert(u64),
}

impl Series {
    fn new(unique: bool, geom: Option<Geometry>, now: i64) -> Self {
        if unique {
            Self::Unique(Window::new(geom, now))
        } else {
            Self::Count(Window::new(geom, now))
        }
    }

    fn apply(&mut self, geom: Option<Geometry>, now: i64, delta: &Delta) {
        match (self, delta) {
            (Self::Count(w), Delta::Add(n)) => {
                let slot = w.current(geom, now);
                *slot = slot.saturating_add(*n);
            }
            (Self::Unique(w), Delta::Insert(h)) => w.current(geom, now).insert(*h),
            // A series' kind is fixed by its metric; mismatches cannot occur.
            _ => {}
        }
    }

    fn value(&self, geom: Option<Geometry>, now: i64) -> i64 {
        let v = match self {
            Self::Count(w) => w.live(geom, now).fold(0u64, |a, b| a.saturating_add(*b)),
            Self::Unique(w) => cardinality(w.live(geom, now)),
        };
        i64::try_from(v).unwrap_or(i64::MAX)
    }

    fn expired(&self, geom: Option<Geometry>, now: i64) -> bool {
        match self {
            Self::Count(w) => w.expired(geom, now),
            Self::Unique(w) => w.expired(geom, now),
        }
    }

    fn shift(&mut self, geom: Option<Geometry>, shift: i64) {
        match self {
            Self::Count(w) => w.shift(geom, shift),
            Self::Unique(w) => w.shift(geom, shift),
        }
    }
}

// ----- the store ------------------------------------------------------------

/// The parts of a [`MetricDef`] that determine what its series mean. Two
/// definitions with equal fingerprints can share series across a reload.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Fingerprint {
    count: MetricCount,
    unique: Option<Field>,
    key: Vec<Field>,
    window: Option<Duration>,
    phase: Phase,
}

struct Metric {
    def: MetricDef,
    fingerprint: Fingerprint,
    geom: Option<Geometry>,
    series: DashMap<Key, Mutex<Series>>,
}

impl Metric {
    fn key(&self, view: &dyn FlowView) -> Result<Key, MetricError> {
        self.def
            .key
            .iter()
            .map(|&f| key_part(&self.def.id, view, f))
            .collect()
    }
}

/// Stateful metric series for one compiled policy (§6.4). `Send + Sync`;
/// share it behind an `Arc`. See the module docs for the design and bounds.
pub struct MetricStore {
    metrics: Vec<Metric>,
    by_id: HashMap<String, usize>,
    max_keys: usize,
    live: AtomicUsize,
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
            .finish_non_exhaustive()
    }
}

impl MetricStore {
    /// A store for `defs` holding at most `max_keys` series in total.
    pub fn new(defs: &[MetricDef], max_keys: usize) -> Self {
        Self::with_clock(defs, max_keys, Arc::new(Instant::now))
    }

    /// Like [`MetricStore::new`] with an injected clock (tests).
    pub fn with_clock(defs: &[MetricDef], max_keys: usize, clock: Clock) -> Self {
        let origin = clock();
        let metrics: Vec<Metric> = defs
            .iter()
            .map(|d| Metric {
                def: d.clone(),
                fingerprint: Fingerprint {
                    count: d.count.clone(),
                    unique: d.unique,
                    key: d.key.clone(),
                    window: d.window,
                    phase: d.phase,
                },
                geom: d.window.map(Geometry::new),
                series: DashMap::new(),
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

    /// Record one flow for every metric whose `phase` is `phase` and whose
    /// `where` filter matches `view`. Admits new keys. All matching metrics
    /// are attempted; the first error is returned: `TableFull` if a key
    /// would be new and the table is full, `FilterFailed` if a filter hit an
    /// unavailable input, `KeyUnavailable` if a key (or the `unique` field)
    /// is absent. Any `Err` means the caller must deny the flow.
    pub fn record(
        &self,
        phase: Phase,
        view: &dyn FlowView,
        sample: &Sample,
    ) -> Result<(), MetricError> {
        let now = self.now();
        let mut first_err = None;
        for m in self.metrics.iter().filter(|m| m.def.phase == phase) {
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
            MetricCount::Requests => Delta::Add(1),
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
        if let Some(s) = m.series.get(&key) {
            s.lock().apply(m.geom, now, &delta);
            return Ok(());
        }
        // New key (probably). Reclaim first if full: never while holding an
        // entry of this map, which `retain` would deadlock on.
        if self.live.load(Ordering::Acquire) >= self.max_keys {
            self.reclaim_if_due(now);
        }
        match m.series.entry(key) {
            Entry::Occupied(e) => e.get().lock().apply(m.geom, now, &delta),
            Entry::Vacant(v) => {
                if !self.reserve() {
                    return Err(MetricError::TableFull {
                        metric: m.def.id.clone(),
                    });
                }
                let mut s = Series::new(m.def.unique.is_some(), m.geom, now);
                s.apply(m.geom, now, &delta);
                v.insert(Mutex::new(s));
            }
        }
        Ok(())
    }

    /// Take one key slot; false if the table is full. A CAS loop, so the
    /// count never exceeds `max_keys` through admission.
    fn reserve(&self) -> bool {
        self.live
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < self.max_keys).then_some(n + 1)
            })
            .is_ok()
    }

    fn reclaim_if_due(&self, now: i64) {
        let last = self.last_full_reclaim.load(Ordering::Acquire);
        if now.saturating_sub(last) >= FULL_RECLAIM_INTERVAL_NS
            && self
                .last_full_reclaim
                .compare_exchange(last, now, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            self.reclaim_at(now);
        }
    }

    /// Remove windowed series whose whole window has expired (their value
    /// is 0, so nothing is lost). Cumulative series are never removed.
    /// Returns the number of series removed. Also run every 4096 `record`
    /// calls, and (at most every 100 ms) when a new key meets a full table.
    pub fn reclaim(&self) -> usize {
        self.reclaim_at(self.now())
    }

    fn reclaim_at(&self, now: i64) -> usize {
        let mut removed = 0;
        for m in self.metrics.iter().filter(|m| m.geom.is_some()) {
            m.series.retain(|_, s| {
                let keep = !s.get_mut().expired(m.geom, now);
                removed += usize::from(!keep);
                keep
            });
        }
        if removed > 0 {
            self.live.fetch_sub(removed, Ordering::AcqRel);
        }
        removed
    }

    /// Reload retention (§6.5): copy series from `previous` for metric ids
    /// whose definition has the same `count`, `unique`, `key`, `window` and
    /// `phase`; every other metric starts empty. Carried series are kept even
    /// beyond this store's `max_keys` (new keys are then refused until
    /// enough expire). Call before the store takes traffic.
    pub fn carry_over(&self, previous: &MetricStore) {
        if std::ptr::eq(self, previous) {
            return;
        }
        // Event at previous-store time t is at this store's time t + shift.
        let shift = signed_nanos(previous.origin, self.origin);
        let prev_now = previous.now();
        for m in &self.metrics {
            let Some(&pi) = previous.by_id.get(&m.def.id) else {
                continue;
            };
            let pm = &previous.metrics[pi];
            if pm.fingerprint != m.fingerprint {
                continue;
            }
            for entry in &pm.series {
                let mut s = entry.value().lock().clone();
                if s.expired(pm.geom, prev_now) {
                    continue;
                }
                s.shift(m.geom, shift);
                if m.series
                    .insert(entry.key().clone(), Mutex::new(s))
                    .is_none()
                {
                    self.live.fetch_add(1, Ordering::AcqRel);
                }
            }
        }
    }

    /// Series currently held across all metrics.
    pub fn key_count(&self) -> usize {
        self.live.load(Ordering::Acquire)
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

    fn record(
        &self,
        phase: Phase,
        view: &dyn FlowView,
        sample: &Sample,
    ) -> Result<(), MetricError> {
        MetricStore::record(self, phase, view, sample)
    }
}

/// `a - b` in signed nanoseconds, saturating.
fn signed_nanos(a: Instant, b: Instant) -> i64 {
    match a.checked_duration_since(b) {
        Some(d) => i64::try_from(d.as_nanos()).unwrap_or(i64::MAX),
        None => i64::try_from(b.duration_since(a).as_nanos()).map_or(i64::MIN, |n| -n),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed, well-mixed hash (splitmix64) so accuracy tests are
    /// deterministic.
    fn mix(mut x: u64) -> u64 {
        x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
        x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        x ^ (x >> 31)
    }

    fn count(n: u64) -> u64 {
        let mut h = Hll::default();
        for i in 0..n {
            h.insert(mix(i));
            h.insert(mix(i)); // duplicates do not count
        }
        cardinality(std::iter::once(&h))
    }

    #[test]
    #[allow(clippy::cast_precision_loss, reason = "test arithmetic")]
    fn hll_accuracy() {
        for n in 0..=SPARSE_MAX as u64 {
            assert_eq!(count(n), n, "exact below the sparse threshold");
        }
        for n in [257, 1_000, 3_000, 10_000, 30_000, 100_000, 1_000_000] {
            let e = count(n) as f64;
            let err = (e - n as f64).abs() / n as f64;
            assert!(err < 0.05, "n={n} estimate={e} err={err}");
        }
    }

    #[test]
    fn hll_merge_is_union() {
        let mut a = Hll::default();
        let mut b = Hll::default();
        for i in 0..5_000 {
            a.insert(mix(i));
        }
        for i in 2_500..7_500 {
            b.insert(mix(i));
        }
        let small = {
            let mut s = Hll::default();
            s.insert(mix(1));
            s.insert(mix(100_000));
            s
        };
        #[allow(clippy::cast_precision_loss, reason = "test arithmetic")]
        let e = cardinality([&a, &b, &small].into_iter()) as f64;
        assert!((e - 7_501.0).abs() / 7_501.0 < 0.05, "{e}");
        // Sparse-only unions are exact.
        let mut c = Hll::default();
        c.insert(mix(1));
        c.insert(mix(2));
        assert_eq!(cardinality([&small, &c].into_iter()), 3);
    }

    #[test]
    fn geometry() {
        let g = Geometry::new(Duration::from_secs(60));
        assert_eq!((g.width, g.n), (1_000_000_000, 60));
        let g = Geometry::new(Duration::from_millis(10));
        assert_eq!((g.width, g.n), (1_000_000, 10));
        let g = Geometry::new(Duration::from_nanos(1));
        assert_eq!((g.width, g.n), (1_000_000, 1));
    }

    #[test]
    fn window_shift_rounds_later() {
        let g = Some(Geometry::new(Duration::from_secs(60)));
        let mut w: Window<u64> = Window::new(g, 0);
        *w.current(g, 0) += 1;
        w.shift(g, -1); // within the bucket: rounds to the later one
        assert_eq!(w.head, 0);
        w.shift(g, -1_500_000_000);
        assert_eq!(w.head, -1);
        assert_eq!(w.live(g, -1).copied().sum::<u64>(), 1);
        assert_eq!(w.slots[ring_index(-1, w.slots.len())], 1);
        w.shift(g, 1);
        assert_eq!(w.head, 0);
        assert_eq!(w.slots[0], 1);
    }
}
