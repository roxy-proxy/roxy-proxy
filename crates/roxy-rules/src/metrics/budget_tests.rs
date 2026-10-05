//! Byte-budget behaviour of the store, pinned against the charges it
//! makes per series ([`SERIES_OVERHEAD`]) and per exact-set chunk
//! ([`SPARSE_CHUNK`]).

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use super::{
    Clock, DEFAULT_MAX_METRIC_BYTES, MetricError, MetricLimits, MetricStore, SERIES_OVERHEAD,
    SPARSE_CHUNK, Sample,
};
use crate::{Field, MapView, MetricConfig, Policy, PolicyInput, Value};

/// A manually advanced clock.
#[derive(Clone)]
struct TestClock {
    base: Instant,
    offset_ns: Arc<AtomicU64>,
}

impl TestClock {
    fn new() -> Self {
        Self {
            base: Instant::now(),
            offset_ns: Arc::new(AtomicU64::new(0)),
        }
    }

    fn advance(&self, d: Duration) {
        self.offset_ns
            .fetch_add(u64::try_from(d.as_nanos()).unwrap(), Ordering::SeqCst);
    }

    fn clock(&self) -> Clock {
        let this = self.clone();
        Arc::new(move || this.base + Duration::from_nanos(this.offset_ns.load(Ordering::SeqCst)))
    }
}

fn compile(metrics_yaml: &str) -> Policy {
    let metrics: Vec<MetricConfig> = serde_yaml_ng::from_str(metrics_yaml).unwrap();
    let none = HashSet::new();
    Policy::compile(&PolicyInput {
        rules: &[],
        metrics: &metrics,
        secret_names: &none,
        address_lists: &none,
    })
    .unwrap()
}

fn store_with(metrics_yaml: &str, max_keys: usize, clock: &TestClock) -> MetricStore {
    MetricStore::with_clock(compile(metrics_yaml).metric_defs(), max_keys, clock.clock())
}

fn client(n: u8) -> MapView {
    MapView::new().with(
        Field::ClientIp,
        Value::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))),
    )
}

/// A head sample: counts `requests` and `unique`.
const REQ: Sample = Sample {
    head: true,
    request_bytes: 0,
    response_bytes: 0,
    denied: false,
    error: false,
};

fn rec(s: &MetricStore, v: &MapView) {
    s.record(v, &REQ).unwrap();
}

fn store_limits(
    metrics_yaml: &str,
    max_keys: usize,
    max_bytes: usize,
    clock: &TestClock,
) -> MetricStore {
    MetricStore::with_limits_and_clock(
        compile(metrics_yaml).metric_defs(),
        MetricLimits {
            max_keys,
            max_bytes,
        },
        clock.clock(),
    )
}

const UNIQUE_PATHS: &str = "- { id: u, count: unique(path), key: [client.ip], window: 60s }";

fn path(n: u8, i: usize) -> MapView {
    client(n).with_str(Field::Path, &format!("/p/{i}"))
}

/// Bytes charged for one `UNIQUE_PATHS` series holding a single value:
/// the empty series plus one exact-set chunk.
fn one_value_series_bytes() -> usize {
    let c = TestClock::new();
    let s = store_with(UNIQUE_PATHS, 10, &c);
    rec(&s, &path(1, 0));
    let b = s.byte_count();
    assert!(b > SERIES_OVERHEAD + SPARSE_CHUNK * 8, "{b}");
    b
}

#[test]
fn default_limits() {
    let c = TestClock::new();
    let s = store_with(UNIQUE_PATHS, 10, &c);
    assert_eq!(s.max_bytes(), DEFAULT_MAX_METRIC_BYTES);
    assert_eq!(DEFAULT_MAX_METRIC_BYTES, 256 << 20);
    assert_eq!(MetricLimits::default().max_bytes, 256 << 20);
    assert_eq!(s.byte_count(), 0);
}

#[test]
fn budget_exhausted_at_the_expected_point() {
    let per = one_value_series_bytes();
    let chunk = SPARSE_CHUNK * 8;
    // Room for three one-value series plus less than one more chunk.
    let max = 3 * per + chunk - 1;
    let c = TestClock::new();
    let s = store_limits(
        &format!("{UNIQUE_PATHS}\n- {{ id: r, count: requests }}"),
        100,
        max,
        &c,
    );
    // The global `r` series is charged too; it is cheaper than a unique one.
    rec(&s, &path(1, 0));
    rec(&s, &path(2, 0));
    let r_bytes = s.byte_count() - 2 * per;
    assert!(r_bytes < per);
    // Third unique key: fits only if its bytes fit alongside `r`.
    let third = s.record(&path(3, 0), &REQ);
    if 3 * per + r_bytes <= max {
        third.unwrap();
    } else {
        assert_eq!(
            third,
            Err(MetricError::BudgetExhausted { metric: "u".into() })
        );
    }
    let used = s.byte_count();
    assert!(used <= max);
    // A new key that does not fit is refused and admits nothing.
    let keys = s.key_count();
    let err = s.record(&path(4, 0), &REQ);
    assert_eq!(
        err,
        Err(MetricError::BudgetExhausted { metric: "u".into() })
    );
    assert_eq!(
        err.unwrap_err().to_string(),
        "metric byte budget exhausted (metric u)"
    );
    assert_eq!(s.key_count(), keys);
    assert_eq!(s.byte_count(), used);
    // Existing global count still records alongside the refusal.
    assert_eq!(s.get("r", &MapView::new()), Ok(4));

    // Key 1 fills its first chunk with no new bytes...
    for i in 1..SPARSE_CHUNK {
        rec(&s, &path(1, i));
    }
    assert_eq!(
        s.get("u", &client(1)),
        Ok(i64::try_from(SPARSE_CHUNK).unwrap())
    );
    assert_eq!(s.byte_count(), used);
    // ...and the next distinct value needs a chunk that is not there.
    if used + chunk > max {
        assert_eq!(
            s.record(&path(1, SPARSE_CHUNK), &REQ),
            Err(MetricError::BudgetExhausted { metric: "u".into() })
        );
        assert_eq!(
            s.get("u", &client(1)),
            Ok(i64::try_from(SPARSE_CHUNK).unwrap())
        );
        assert_eq!(s.byte_count(), used);
        // Values already counted need no bytes and still record.
        rec(&s, &path(1, 3));
    }
    assert!(s.byte_count() <= max);
}

#[test]
fn many_keys_many_values_never_exceed_budget() {
    let max = 1 << 20;
    let c = TestClock::new();
    let s = store_limits(UNIQUE_PATHS, 1_000_000, max, &c);
    let mut refused = 0;
    let mut i = 0;
    for round in 0..20 {
        for n in 0..=255u8 {
            for _ in 0..40 {
                i += 1;
                match s.record(&path(n, i), &REQ) {
                    Ok(()) => {}
                    Err(MetricError::BudgetExhausted { .. }) => refused += 1,
                    Err(e) => panic!("{e}"),
                }
                assert!(s.byte_count() <= max, "round {round}");
            }
        }
        // Spread values over many buckets of the window.
        c.advance(Duration::from_secs(2));
    }
    assert!(refused > 0);
    // Close to full: within one dense sketch of the budget.
    assert!(s.byte_count() > max - 4096 - one_value_series_bytes());
}

#[test]
fn concurrent_growth_never_exceeds_budget() {
    let max = 512 << 10;
    let c = TestClock::new();
    let s = store_limits(UNIQUE_PATHS, 1_000_000, max, &c);
    std::thread::scope(|scope| {
        for t in 0..8usize {
            let s = &s;
            scope.spawn(move || {
                for i in 0..20_000usize {
                    let n = u8::try_from((i + t * 7) % 251).unwrap();
                    let _ = s.record(&path(n, i * 8 + t), &REQ);
                    assert!(s.byte_count() <= max);
                }
            });
        }
    });
    assert!(s.byte_count() <= max);
    // Accounting is exact: removing everything returns every byte.
    c.advance(Duration::from_secs(120));
    let live = s.key_count();
    assert!(live > 0);
    assert_eq!(s.reclaim(), live);
    assert_eq!(s.byte_count(), 0);
    assert_eq!(s.key_count(), 0);
}

#[test]
fn reclaim_and_rotation_free_budget() {
    let per = one_value_series_bytes();
    let c = TestClock::new();
    let s = store_limits(
        "- { id: u, count: unique(path), key: [client.ip], window: 1s }",
        100,
        2 * per,
        &c,
    );
    rec(&s, &path(1, 0));
    rec(&s, &path(2, 0));
    assert_eq!(s.byte_count(), 2 * per);
    assert!(matches!(
        s.record(&path(3, 0), &REQ),
        Err(MetricError::BudgetExhausted { .. })
    ));
    // Once both windows have fully expired, reclaim returns their bytes.
    c.advance(Duration::from_secs(2));
    assert_eq!(s.reclaim(), 2);
    assert_eq!(s.byte_count(), 0);
    rec(&s, &path(3, 0));
    assert_eq!(s.byte_count(), per);

    // Without an explicit reclaim, an exhausted budget triggers one.
    rec(&s, &path(4, 0));
    c.advance(Duration::from_secs(2));
    rec(&s, &path(5, 0));
    assert_eq!(s.key_count(), 1);
    assert_eq!(s.byte_count(), per);

    // Rotation frees a bucket's set: two chunks in one bucket, then a new
    // value a full window later leaves one chunk.
    for i in 1..=SPARSE_CHUNK {
        rec(&s, &path(5, i));
    }
    assert_eq!(s.byte_count(), per + SPARSE_CHUNK * 8);
    c.advance(Duration::from_millis(1_100));
    rec(&s, &path(5, 0));
    assert_eq!(s.byte_count(), per);
    assert_eq!(s.get("u", &client(5)), Ok(1));
}

#[test]
fn reclaim_on_exhausted_budget_for_existing_key() {
    let per = one_value_series_bytes();
    let c = TestClock::new();
    let s = store_limits(
        "- { id: u, count: unique(path), key: [client.ip], window: 1s }",
        100,
        2 * per,
        &c,
    );
    rec(&s, &path(1, 0));
    rec(&s, &path(2, 0));
    for i in 1..SPARSE_CHUNK {
        rec(&s, &path(2, i));
    }
    // Key 2 needs a second chunk; key 1 holds the rest of the budget.
    assert!(s.record(&path(2, 99), &REQ).is_err());
    // Key 1 expires; key 2 stays live by recording.
    c.advance(Duration::from_millis(1_100));
    rec(&s, &path(2, 0));
    for i in 1..=SPARSE_CHUNK {
        rec(&s, &path(2, 1_000 + i));
    }
    assert_eq!(s.key_count(), 1);
}

#[test]
fn carry_over_respects_destination_budget() {
    let per = one_value_series_bytes();
    let c = TestClock::new();
    let old = store_with(UNIQUE_PATHS, 100, &c);
    for n in 0..10 {
        rec(&old, &path(n, 0));
    }
    assert_eq!(old.byte_count(), 10 * per);
    let new = store_limits(UNIQUE_PATHS, 100, 3 * per + 10, &c);
    let report = new.carry_over(&old);
    // A clone's exact set is trimmed to its length, so a carried one-value
    // series is cheaper than the original: more may fit than 3.
    assert_eq!(report.carried + report.skipped_budget, 10);
    assert!(report.skipped_budget > 0);
    assert!(new.byte_count() <= new.max_bytes());
    assert_eq!(new.key_count(), report.carried);
    assert_eq!(
        new.snapshot().iter().filter(|s| s.value == 1).count(),
        report.carried
    );
}
