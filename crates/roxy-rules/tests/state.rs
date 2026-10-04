//! `StateStore` behaviour.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use roxy_rules::{StateFull, StateSource, StateStore};

fn clocked(max: usize, ttl: Duration) -> (StateStore, Arc<AtomicU64>) {
    let base = Instant::now();
    let offset = Arc::new(AtomicU64::new(0));
    let o = Arc::clone(&offset);
    let s = StateStore::with_clock(
        max,
        ttl,
        Arc::new(move || base + Duration::from_millis(o.load(Ordering::SeqCst))),
    );
    (s, offset)
}

#[test]
fn get_set_remove() {
    let s = StateStore::new(10, Duration::from_secs(60));
    assert!(s.is_empty());
    assert_eq!(s.get("k"), None);
    s.set("k", "v", None).unwrap();
    assert_eq!(s.get("k").as_deref(), Some("v"));
    s.set("k", "w", None).unwrap();
    assert_eq!(s.get("k").as_deref(), Some("w"));
    assert_eq!(s.len(), 1);
    s.remove("k");
    s.remove("k");
    assert_eq!(s.get("k"), None);
    assert!(s.is_empty());
}

#[test]
fn ttl_expiry() {
    let (s, t) = clocked(10, Duration::from_secs(10));
    s.set("default", "1", None).unwrap();
    s.set("short", "2", Some(Duration::from_secs(1))).unwrap();
    s.set("long", "3", Some(Duration::from_secs(100))).unwrap();
    t.store(999, Ordering::SeqCst);
    assert_eq!(s.get("short").as_deref(), Some("2"));
    t.store(1_000, Ordering::SeqCst);
    assert_eq!(s.get("short"), None);
    assert_eq!(s.len(), 2);
    t.store(10_000, Ordering::SeqCst);
    assert_eq!(s.get("default"), None);
    assert_eq!(s.get("long").as_deref(), Some("3"));
    assert_eq!(s.len(), 1);
    assert_eq!(s.purge(), 2);
    // Overwriting refreshes the ttl.
    s.set("long", "4", Some(Duration::from_secs(1))).unwrap();
    t.store(11_000, Ordering::SeqCst);
    assert_eq!(s.get("long"), None);
}

#[test]
fn full_store_overwrites_but_refuses_new_keys() {
    let (s, t) = clocked(2, Duration::from_secs(10));
    s.set("a", "1", None).unwrap();
    s.set("b", "1", None).unwrap();
    assert_eq!(s.set("c", "1", None), Err(StateFull));
    assert_eq!(StateFull.to_string(), "state store full");
    assert_eq!(s.get("c"), None);
    // Overwriting an existing key always succeeds.
    s.set("a", "2", None).unwrap();
    assert_eq!(s.get("a").as_deref(), Some("2"));
    // Removing frees a slot.
    s.remove("b");
    s.set("c", "1", None).unwrap();
    assert_eq!(s.set("d", "1", None), Err(StateFull));
    // Expired entries are purged when a new key meets a full table.
    t.store(10_000, Ordering::SeqCst);
    s.set("d", "1", None).unwrap();
    assert_eq!(s.len(), 1);
}

#[test]
fn trait_object() {
    let s: Arc<dyn StateSource> = Arc::new(StateStore::new(1, Duration::from_secs(1)));
    s.set("k", "v", None).unwrap();
    assert_eq!(s.get("k").as_deref(), Some("v"));
    assert!(s.set("k2", "v", None).is_err());
}

#[test]
fn concurrent_admission_never_exceeds_max_entries() {
    let s = StateStore::new(100, Duration::from_secs(60));
    std::thread::scope(|scope| {
        for t in 0..8 {
            let s = &s;
            scope.spawn(move || {
                for i in 0..200 {
                    let _ = s.set(&format!("k{}", i + t * 7), "v", None);
                }
            });
        }
    });
    assert_eq!(s.len(), 100);
}

#[test]
fn set_limits_on_a_live_store() {
    let (s, t) = clocked(3, Duration::from_secs(10));
    s.set("a", "1", None).unwrap();
    s.set("b", "1", Some(Duration::from_secs(1))).unwrap();
    s.set("c", "1", None).unwrap();
    // A lower cap evicts nothing: stored keys stay readable and writable.
    s.set_limits(2, Duration::from_secs(100));
    assert_eq!(s.len(), 3);
    s.set("a", "2", None).unwrap();
    assert_eq!(s.set("d", "1", None), Err(StateFull));
    // Once expiry brings the count under the cap, new keys are admitted.
    t.store(1_000, Ordering::SeqCst);
    assert_eq!(s.set("d", "1", None), Err(StateFull));
    s.remove("c");
    s.set("d", "1", None).unwrap();
    // The new default ttl applies to later writes; "a" was written after
    // the change too.
    t.store(50_000, Ordering::SeqCst);
    assert_eq!(s.get("d").as_deref(), Some("1"));
    assert_eq!(s.get("a").as_deref(), Some("2"));
    // A higher cap admits more keys straight away.
    s.set_limits(4, Duration::from_secs(100));
    s.set("e", "1", None).unwrap();
    s.set("f", "1", None).unwrap();
    assert_eq!(s.set("g", "1", None), Err(StateFull));
}
