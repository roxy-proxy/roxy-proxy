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

/// A purge is O(entries), so a full table triggers one at most every
/// 100 ms: a client cannot force a full scan per request by filling the
/// table with short-lived keys. Inside that interval a new key is refused
/// even though every stored entry has expired.
#[test]
fn full_table_purges_at_most_every_100ms() {
    let (s, t) = clocked(2, Duration::from_millis(10));
    s.set("a", "1", None).unwrap();
    s.set("b", "1", None).unwrap();
    // Everything expired: the first new key purges and is admitted.
    t.store(20, Ordering::SeqCst);
    s.set("c", "1", None).unwrap();
    s.set("d", "1", None).unwrap();
    assert_eq!(s.len(), 2);
    // Expired again, but within 100 ms of that purge: refused.
    t.store(50, Ordering::SeqCst);
    assert_eq!(s.set("e", "1", None), Err(StateFull));
    assert_eq!(s.get("e"), None);
    // Once the interval has passed, the purge runs and the key fits.
    t.store(120, Ordering::SeqCst);
    s.set("e", "1", None).unwrap();
    assert_eq!(s.len(), 1);
}

/// Overwrites, removes and purges racing on the same keys leave the slot
/// count equal to the entries in the table: a miscount in either direction
/// would admit one key too many or refuse keys with room still free.
#[test]
fn concurrent_overwrite_remove_and_purge_keep_the_count_exact() {
    const MAX: usize = 64;
    let (s, t) = clocked(MAX, Duration::from_secs(60));
    std::thread::scope(|scope| {
        for w in 0..4 {
            let (s, t) = (&s, &t);
            scope.spawn(move || {
                for i in 0..2000 {
                    let key = format!("k{}", (i + w * 5) % 24);
                    // Short-lived and long-lived writes alternate, so a purge
                    // and an overwrite often race on the same key.
                    let ttl = if i % 3 == 0 {
                        Some(Duration::from_millis(1))
                    } else {
                        None
                    };
                    let _ = s.set(&key, "v", ttl);
                    if i % 7 == 0 {
                        t.fetch_add(1, Ordering::SeqCst);
                    }
                }
            });
        }
        let (s, t) = (&s, &t);
        scope.spawn(move || {
            for i in 0..2000 {
                s.remove(&format!("k{}", i % 24));
                if i % 50 == 0 {
                    // Advance well past any default-ttl write so purges
                    // actually remove entries.
                    t.fetch_add(70_000, Ordering::SeqCst);
                }
            }
        });
        scope.spawn(move || {
            for _ in 0..500 {
                s.purge();
                std::thread::yield_now();
            }
        });
    });
    s.purge();
    let live = s.len();
    assert!(format!("{s:?}").contains(&format!("stored: {live}")), "{s:?}");
    // Exactly the free slots are admitted.
    for i in 0..MAX - live {
        s.set(&format!("fresh{i}"), "v", None).unwrap();
    }
    assert_eq!(s.set("one-too-many", "v", None), Err(StateFull));
}
