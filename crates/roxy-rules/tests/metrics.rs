//! `MetricStore` behaviour (DESIGN.md §6.4, §6.5).

mod common;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use common::compile;
use proptest::prelude::*;
use roxy_rules::{
    Clock, EvalContext, FailClosedReason, Field, MapView, MetricError, MetricSnapshot,
    MetricSource, MetricStore, Phase, Sample, Value,
};

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

fn store_with(metrics_yaml: &str, max_keys: usize, clock: &TestClock) -> MetricStore {
    let p = compile(metrics_yaml, "[]");
    MetricStore::with_clock(p.metric_defs(), max_keys, clock.clock())
}

fn client(n: u8) -> MapView {
    MapView::new().with(
        Field::ClientIp,
        Value::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))),
    )
}

const REQ: Sample = Sample {
    request_bytes: 0,
    response_bytes: 0,
    denied: false,
    error: false,
};

fn rec(s: &MetricStore, v: &MapView) {
    s.record(Phase::Request, v, &REQ).unwrap();
}

#[test]
fn is_send_sync_and_object_safe() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<MetricStore>();
    let c = TestClock::new();
    let s: Arc<dyn MetricSource> = Arc::new(store_with("- { id: r, count: requests }", 10, &c));
    s.record(Phase::Request, &MapView::new(), &REQ).unwrap();
    assert_eq!(s.get("r", &MapView::new()), Ok(1));
}

#[test]
fn count_kinds() {
    let c = TestClock::new();
    let s = store_with(
        "- { id: req, count: requests }
- { id: rqb, count: request_bytes }
- { id: rsb, count: response_bytes }
- { id: err, count: errors }
- { id: den, count: denied }
- { id: uniq, count: unique(path) }",
        100,
        &c,
    );
    let v = MapView::new().with_str(Field::Path, "/a");
    let sample = Sample {
        request_bytes: 100,
        response_bytes: 1000,
        denied: true,
        error: true,
    };
    // Request phase: requests, request_bytes, denied, unique.
    s.record(Phase::Request, &v, &sample).unwrap();
    s.record(
        Phase::Request,
        &v,
        &Sample {
            request_bytes: 5,
            ..REQ
        },
    )
    .unwrap();
    s.record(
        Phase::Request,
        &MapView::new().with_str(Field::Path, "/b"),
        &REQ,
    )
    .unwrap();
    // Response phase: response_bytes, errors.
    s.record(Phase::Response, &v, &sample).unwrap();
    s.record(
        Phase::Response,
        &v,
        &Sample {
            response_bytes: 1,
            ..REQ
        },
    )
    .unwrap();
    // Other phases count nothing.
    s.record(Phase::Connect, &v, &sample).unwrap();
    s.record(Phase::Ws, &v, &sample).unwrap();

    let g = |id| s.get(id, &v).unwrap();
    assert_eq!(g("req"), 3);
    assert_eq!(g("rqb"), 105);
    assert_eq!(g("rsb"), 1001);
    assert_eq!(g("err"), 1);
    assert_eq!(g("den"), 1);
    assert_eq!(g("uniq"), 2);
}

#[test]
fn keyed_vs_global() {
    let c = TestClock::new();
    let s = store_with(
        "- { id: per, count: requests, key: [client.ip] }
- { id: all, count: requests }
- { id: pair, count: requests, key: [client.ip, method] }",
        100,
        &c,
    );
    for _ in 0..3 {
        rec(&s, &client(1).with_str(Field::Method, "GET"));
    }
    rec(&s, &client(2).with_str(Field::Method, "get")); // same series as GET
    rec(&s, &client(2).with_str(Field::Method, "POST"));
    assert_eq!(s.get("per", &client(1)), Ok(3));
    assert_eq!(s.get("per", &client(2)), Ok(2));
    assert_eq!(s.get("all", &MapView::new()), Ok(5));
    assert_eq!(
        s.get("pair", &client(2).with_str(Field::Method, "GeT")),
        Ok(1)
    );
    // per: 2 keys, all: 1, pair: 3.
    assert_eq!(s.key_count(), 6);
    let snap = s.snapshot();
    assert!(snap.contains(&MetricSnapshot {
        id: "pair".into(),
        key: vec!["10.0.0.1".into(), "get".into()],
        value: 3,
    }));
    assert!(snap.contains(&MetricSnapshot {
        id: "all".into(),
        key: vec![],
        value: 5,
    }));
    assert_eq!(snap.len(), 6);
}

#[test]
fn window_rotation() {
    let c = TestClock::new();
    // 60 s window: 1 s buckets; 61 kept (60 complete + the current one).
    let s = store_with("- { id: w, count: requests, window: 60s }", 10, &c);
    let v = MapView::new();
    rec(&s, &v); // t = 0
    c.advance(Duration::from_secs(30));
    rec(&s, &v); // t = 30
    rec(&s, &v);
    assert_eq!(s.get("w", &v), Ok(3));
    // Partial: still inside the window.
    c.advance(Duration::from_millis(29_999)); // t = 59.999
    assert_eq!(s.get("w", &v), Ok(3));
    // At the edge the store errs on the side of counting: an event is kept
    // for at least the window and less than window + one bucket.
    c.advance(Duration::from_millis(500)); // t = 60.499
    assert_eq!(s.get("w", &v), Ok(3));
    c.advance(Duration::from_millis(501)); // t = 61.0: the t=0 bucket is gone
    assert_eq!(s.get("w", &v), Ok(2));
    rec(&s, &v); // t = 61
    assert_eq!(s.get("w", &v), Ok(3));
    // Past a full window: everything before t = 61 has expired.
    c.advance(Duration::from_secs(60)); // t = 121
    assert_eq!(s.get("w", &v), Ok(1));
    c.advance(Duration::from_secs(1));
    assert_eq!(s.get("w", &v), Ok(0));
    // Far past (more than a whole ring): recording starts clean.
    c.advance(Duration::from_secs(3600));
    rec(&s, &v);
    assert_eq!(s.get("w", &v), Ok(1));
}

#[test]
fn windowed_unique() {
    let c = TestClock::new();
    let s = store_with(
        "- { id: u, count: unique(path), key: [client.ip], window: 10s }",
        10,
        &c,
    );
    for i in 0..10 {
        rec(&s, &client(1).with_str(Field::Path, &format!("/{i}")));
        c.advance(Duration::from_secs(1));
    }
    // Buckets are 10 s / 60. At t = 10 s every event is inside the window.
    assert_eq!(s.get("u", &client(1)), Ok(10));
    rec(&s, &client(1).with_str(Field::Path, "/9")); // repeat
    assert_eq!(s.get("u", &client(1)), Ok(10));
    c.advance(Duration::from_secs(5)); // t = 15: paths recorded at t >= 5 remain
    assert_eq!(s.get("u", &client(1)), Ok(5));
    assert_eq!(s.get("u", &client(2)), Ok(0));
}

#[test]
fn cumulative_never_expires() {
    let c = TestClock::new();
    let s = store_with("- { id: total, count: requests, key: [client.ip] }", 10, &c);
    rec(&s, &client(1));
    c.advance(Duration::from_hours(10 * 365 * 24));
    assert_eq!(s.reclaim(), 0);
    assert_eq!(s.key_count(), 1);
    assert_eq!(s.get("total", &client(1)), Ok(1));
}

#[test]
fn reads_do_not_admit() {
    let c = TestClock::new();
    let s = store_with("- { id: r, count: requests, key: [client.ip] }", 1, &c);
    for n in 0..50 {
        assert_eq!(s.get("r", &client(n)), Ok(0));
    }
    assert_eq!(s.key_count(), 0);
    assert_eq!(s.snapshot(), Vec::new());
    assert_eq!(
        s.get("nope", &client(1)),
        Err(MetricError::Unknown("nope".into()))
    );
}

#[test]
fn zero_increments_do_not_admit() {
    let c = TestClock::new();
    let s = store_with("- { id: e, count: errors, key: [client.ip] }", 1, &c);
    for n in 0..5 {
        s.record(Phase::Response, &client(n), &REQ).unwrap();
    }
    assert_eq!(s.key_count(), 0);
}

#[test]
fn table_full_refuses_new_keys_only() {
    let c = TestClock::new();
    let s = store_with("- { id: r, count: requests, key: [client.ip] }", 3, &c);
    for n in 1..=3 {
        rec(&s, &client(n));
    }
    assert_eq!(s.key_count(), 3);
    let err = s.record(Phase::Request, &client(4), &REQ);
    assert_eq!(err, Err(MetricError::TableFull { metric: "r".into() }));
    assert_eq!(err.unwrap_err().to_string(), "metric table full (metric r)");
    assert_eq!(s.key_count(), 3);
    assert_eq!(s.get("r", &client(4)), Ok(0));
    // Existing keys still count while full.
    rec(&s, &client(2));
    assert_eq!(s.get("r", &client(2)), Ok(2));
}

#[test]
fn max_keys_is_shared_across_metrics_and_all_metrics_still_record() {
    let c = TestClock::new();
    let s = store_with(
        "- { id: a, count: requests, key: [client.ip] }
- { id: b, count: requests }",
        2,
        &c,
    );
    rec(&s, &client(1)); // a:1, b:global
    assert_eq!(s.key_count(), 2);
    // a needs a new key: refused, but b (existing global series) still counts.
    assert!(matches!(
        s.record(Phase::Request, &client(2), &REQ),
        Err(MetricError::TableFull { .. })
    ));
    assert_eq!(s.get("b", &MapView::new()), Ok(2));
}

#[test]
fn reclaim_frees_expired_windowed_keys() {
    let c = TestClock::new();
    let s = store_with(
        "- { id: w, count: requests, key: [client.ip], window: 1s }
- { id: cum, count: requests }",
        3,
        &c,
    );
    rec(&s, &client(1));
    rec(&s, &client(2));
    assert_eq!(s.key_count(), 3);
    assert!(s.record(Phase::Request, &client(3), &REQ).is_err());
    // Not yet fully expired (window + current bucket).
    c.advance(Duration::from_millis(1_000));
    assert_eq!(s.reclaim(), 0);
    c.advance(Duration::from_millis(20));
    assert_eq!(s.reclaim(), 2);
    assert_eq!(s.key_count(), 1, "cumulative key kept");
    rec(&s, &client(3));
    assert_eq!(s.get("w", &client(3)), Ok(1));
    assert_eq!(s.get("cum", &MapView::new()), Ok(4));
}

#[test]
fn full_table_reclaims_on_demand() {
    let c = TestClock::new();
    let s = store_with(
        "- { id: w, count: requests, key: [client.ip], window: 1s }",
        1,
        &c,
    );
    rec(&s, &client(1));
    c.advance(Duration::from_secs(5));
    // No explicit reclaim: the full table triggers one.
    rec(&s, &client(2));
    assert_eq!(s.key_count(), 1);
    assert_eq!(s.get("w", &client(2)), Ok(1));
}

#[test]
fn key_unavailable() {
    let c = TestClock::new();
    let s = store_with(
        "- { id: u, count: requests, key: [client.user] }
- { id: q, count: unique(client.user) }",
        10,
        &c,
    );
    let want = MetricError::KeyUnavailable {
        metric: "u".into(),
        field: Field::ClientUser,
    };
    assert_eq!(s.get("u", &MapView::new()), Err(want.clone()));
    assert_eq!(s.record(Phase::Request, &MapView::new(), &REQ), Err(want));
    assert_eq!(s.key_count(), 0);
    let with_user = MapView::new().with_str(Field::ClientUser, "alice");
    rec(&s, &with_user);
    assert_eq!(s.get("u", &with_user), Ok(1));
    assert_eq!(s.get("q", &MapView::new()), Ok(1));
}

#[test]
fn filter_failure_propagates() {
    let c = TestClock::new();
    let p = compile(
        "- { id: f, count: requests, where: 'body.text contains \"x\"' }
- { id: plain, count: requests }",
        "[]",
    );
    let s = MetricStore::with_clock(p.metric_defs(), 10, c.clock());
    let v = MapView::new(); // body not buffered
    let reason = p.metric_defs()[0].matches(&v).unwrap_err();
    assert_eq!(
        reason,
        FailClosedReason::BodyUnavailable("body.text".into())
    );
    assert_eq!(
        s.record(Phase::Request, &v, &REQ),
        Err(MetricError::FilterFailed {
            metric: "f".into(),
            reason,
        })
    );
    // Other metrics still counted the flow.
    assert_eq!(s.get("plain", &v), Ok(1));
    // Filter true / false.
    rec(&s, &v.clone().with_body("xyz"));
    rec(&s, &v.clone().with_body("abc"));
    assert_eq!(s.get("f", &v), Ok(1));
}

#[test]
fn carry_over_keeps_identical_definitions() {
    let c = TestClock::new();
    let old = store_with(
        "- { id: same, count: requests, key: [client.ip], window: 60s }
- { id: cum, count: requests }
- { id: rewindowed, count: requests, window: 60s }
- { id: rekeyed, count: requests }
- { id: recounted, count: requests }
- { id: gone, count: requests }",
        100,
        &c,
    );
    for _ in 0..5 {
        old.record(
            Phase::Request,
            &client(1),
            &Sample {
                request_bytes: 1,
                ..REQ
            },
        )
        .unwrap();
    }
    c.advance(Duration::from_secs(10));
    let new = store_with(
        "- { id: same, count: requests, key: [client.ip], window: 60s }
- { id: cum, count: requests }
- { id: rewindowed, count: requests, window: 30s }
- { id: rekeyed, count: requests, key: [client.ip] }
- { id: recounted, count: request_bytes }
- { id: fresh, count: requests }",
        100,
        &c,
    );
    new.carry_over(&old);
    assert_eq!(new.key_count(), 2);
    let v = client(1);
    assert_eq!(new.get("same", &v), Ok(5));
    assert_eq!(new.get("cum", &v), Ok(5));
    for id in ["rewindowed", "rekeyed", "recounted", "fresh"] {
        assert_eq!(new.get(id, &v), Ok(0), "{id}");
    }
    // The carried window still expires on schedule (recorded at old t = 0,
    // which is 10 s before the new store's origin).
    c.advance(Duration::from_secs(50));
    assert_eq!(new.get("same", &v), Ok(5));
    c.advance(Duration::from_secs(2));
    assert_eq!(new.get("same", &v), Ok(0));
    assert_eq!(new.get("cum", &v), Ok(5));
    // Self carry-over is a no-op.
    new.carry_over(&new);
}

#[test]
fn unique_exact_small_and_accurate_large() {
    let c = TestClock::new();
    let s = store_with("- { id: u, count: unique(path), window: 1h }", 10, &c);
    let v = MapView::new();
    for i in 0..16 {
        rec(&s, &v.clone().with_str(Field::Path, &format!("/x/{i}")));
        rec(&s, &v.clone().with_str(Field::Path, &format!("/x/{i}")));
        assert_eq!(s.get("u", &v), Ok(i + 1));
    }
    for i in 16..10_000 {
        rec(&s, &v.clone().with_str(Field::Path, &format!("/x/{i}")));
    }
    let e = s.get("u", &v).unwrap();
    // The hash key is random per process, so this is a statistical check:
    // 5 % ≈ 3σ at 2^12 registers (the deterministic 5 % check is a unit test
    // in src/metrics.rs); allow 4σ here to keep the test from flaking.
    assert!((e - 10_000).abs() <= 650, "estimate {e}");
}

/// §6.4: values are read before the decision and recorded after it, so a
/// rule `metric.x >= 30` denies the 31st request; denied flows count too.
#[test]
fn read_before_record_denies_the_31st() {
    let c = TestClock::new();
    let p = compile(
        "- { id: x, count: requests, key: [client.ip], window: 1m }",
        "- { id: limit, when: 'metric.x >= 30', then: deny }
- { id: ok, then: allow }",
    );
    let s = MetricStore::with_clock(p.metric_defs(), 100, c.clock());
    let mut outcomes = Vec::new();
    for _ in 0..32 {
        let base = client(1);
        let x = s.get("x", &base).unwrap();
        let flow = base.clone().with_metric("x", x);
        let out = p.evaluate(Phase::Request, &flow, &EvalContext::empty());
        let denied = !out.decision.is_allow();
        s.record(Phase::Request, &base, &Sample { denied, ..REQ })
            .unwrap();
        outcomes.push((x, denied, out.terminal_rule.to_string()));
    }
    for (i, (x, denied, rule)) in outcomes.iter().enumerate() {
        let i = i64::try_from(i).unwrap();
        assert_eq!(*x, i, "request {} reads the count of earlier ones", i + 1);
        assert_eq!(*denied, i >= 30, "request {}", i + 1);
        assert_eq!(rule, if i >= 30 { "limit" } else { "ok" });
    }
    assert_eq!(s.get("x", &client(1)), Ok(32));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_records_are_exact() {
    let c = TestClock::new();
    let s = Arc::new(store_with(
        "- { id: per, count: requests, key: [client.ip], window: 1m }
- { id: all, count: request_bytes }",
        1_000,
        &c,
    ));
    let mut tasks = Vec::new();
    for t in 0..16u32 {
        let s = Arc::clone(&s);
        tasks.push(tokio::spawn(async move {
            for i in 0..10_000u32 {
                let n = u8::try_from((i + t) % 100).unwrap();
                s.record(
                    Phase::Request,
                    &client(n),
                    &Sample {
                        request_bytes: 2,
                        ..REQ
                    },
                )
                .unwrap();
                if i % 1000 == 0 {
                    tokio::task::yield_now().await;
                }
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    assert_eq!(s.key_count(), 101);
    for n in 0..100 {
        assert_eq!(s.get("per", &client(n)), Ok(1_600));
    }
    assert_eq!(s.get("all", &MapView::new()), Ok(320_000));
}

#[test]
fn concurrent_admission_never_exceeds_max_keys() {
    let c = TestClock::new();
    let s = store_with("- { id: r, count: requests, key: [client.ip] }", 50, &c);
    std::thread::scope(|scope| {
        for t in 0..8u8 {
            let s = &s;
            scope.spawn(move || {
                for n in 0..100u8 {
                    let _ = s.record(Phase::Request, &client(n.wrapping_add(t)), &REQ);
                }
            });
        }
    });
    assert_eq!(s.key_count(), 50);
    assert_eq!(s.snapshot().len(), 50);
}

// ----- property test against a naive reference ------------------------------

#[derive(Debug, Clone)]
enum Op {
    Record(u8),
    Advance(u64),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (0u8..3).prop_map(Op::Record),
        2 => (0u64..2_500).prop_map(Op::Advance),
    ]
}

proptest! {
    /// Windowed `requests` against a reference that keeps every event
    /// timestamp. Window d = 6 s, bucket w = 100 ms. Tolerance (one bucket at
    /// the window edge): the store counts every event younger than d and none
    /// older than d + w, i.e. `exact(d) <= got <= exact(d + w)`.
    #[test]
    fn windowed_requests_match_reference(ops in proptest::collection::vec(op(), 1..200)) {
        let c = TestClock::new();
        let s = store_with("- { id: w, count: requests, key: [client.port], window: 6s }", 10, &c);
        let d: u64 = 6_000_000_000;
        let w: u64 = 100_000_000;
        let mut now: u64 = 0;
        let mut events: Vec<(u64, u8)> = Vec::new();
        let port = |k: u8| MapView::new().with_int(Field::ClientPort, i64::from(k));
        for op in ops {
            match op {
                Op::Record(k) => {
                    s.record(Phase::Request, &port(k), &REQ).unwrap();
                    events.push((now, k));
                }
                Op::Advance(ms) => {
                    c.advance(Duration::from_millis(ms));
                    now += ms * 1_000_000;
                }
            }
            for k in 0..3u8 {
                let exact = |span: u64| {
                    i64::try_from(
                        events.iter().filter(|&&(t, kk)| kk == k && now - t < span).count(),
                    )
                    .unwrap()
                };
                let got = s.get("w", &port(k)).unwrap();
                prop_assert!(
                    exact(d) <= got && got <= exact(d + w),
                    "key {} at {}ns: got {}, exact(d) {}, exact(d+w) {}",
                    k, now, got, exact(d), exact(d + w)
                );
            }
        }
    }
}
