//! The bounded TTL key/value state store (docs/rules.md#state): `state["k"]`
//! in rules and the `set_state` action. Each addon's `flow.state-get` /
//! `flow.state-put` store is one of these too (docs/addons.md#state).
//!
//! Bounded by `max_entries` with **no eviction**: overwriting an existing key
//! (live or expired-but-not-yet-purged) always succeeds; a new key when the
//! table is full is refused with [`StateFull`] and the caller denies the flow.
//! Admission reserves a slot by compare-and-swap while holding the shard
//! entry for the new key, so the number of stored entries never exceeds
//! `max_entries`. Expired entries read as absent immediately and are purged
//! every 1024 `set` calls, and (at most every 100 ms) when a new key meets a
//! full table. [`StateStore::set_limits`] changes the cap and default ttl of a
//! live store; lowering the cap below the stored count evicts nothing, it
//! only refuses new keys until expiry brings the count under it.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use parking_lot::Mutex;

use crate::metrics::Clock;

const PURGE_EVERY: u64 = 1024;
const FULL_PURGE_INTERVAL: Duration = Duration::from_millis(100);

/// The proxy-facing interface to the state store.
pub trait StateSource: Send + Sync {
    fn get(&self, key: &str) -> Option<String>;
    fn set(&self, key: &str, value: &str, ttl: Option<Duration>) -> Result<(), StateFull>;
}

/// A new key could not be stored because the table is full. The caller
/// must deny the flow (fail closed).
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[error("state store full")]
pub struct StateFull;

#[derive(Debug)]
struct Slot {
    value: String,
    /// `None` = never expires (ttl overflowed `Instant`).
    expires: Option<Instant>,
}

impl Slot {
    fn live(&self, now: Instant) -> bool {
        self.expires.is_none_or(|e| now < e)
    }
}

/// A bounded TTL map. `Send + Sync`; share it behind an `Arc`.
pub struct StateStore {
    map: DashMap<String, Slot>,
    max_entries: AtomicUsize,
    /// Nanoseconds, saturating at `u64::MAX` (about 584 years).
    default_ttl_nanos: AtomicU64,
    stored: AtomicUsize,
    clock: Clock,
    sets: AtomicU64,
    last_full_purge: Mutex<Option<Instant>>,
}

impl fmt::Debug for StateStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StateStore")
            .field("stored", &self.stored.load(Ordering::Relaxed))
            .field("max_entries", &self.max_entries.load(Ordering::Relaxed))
            .field("default_ttl", &self.default_ttl())
            .finish_non_exhaustive()
    }
}

impl StateStore {
    /// A store of at most `max_entries` keys; `set` without a ttl uses
    /// `default_ttl`.
    pub fn new(max_entries: usize, default_ttl: Duration) -> Self {
        Self::with_clock(max_entries, default_ttl, Arc::new(Instant::now))
    }

    /// Like [`StateStore::new`] with an injected clock (tests).
    pub fn with_clock(max_entries: usize, default_ttl: Duration, clock: Clock) -> Self {
        Self {
            map: DashMap::new(),
            max_entries: AtomicUsize::new(max_entries),
            default_ttl_nanos: AtomicU64::new(ttl_nanos(default_ttl)),
            stored: AtomicUsize::new(0),
            clock,
            sets: AtomicU64::new(0),
            last_full_purge: Mutex::new(None),
        }
    }

    /// Replace the entry cap and the default ttl. Stored entries keep their
    /// expiry; a cap below the stored count refuses new keys until enough
    /// entries expire.
    pub fn set_limits(&self, max_entries: usize, default_ttl: Duration) {
        self.max_entries.store(max_entries, Ordering::Release);
        self.default_ttl_nanos
            .store(ttl_nanos(default_ttl), Ordering::Relaxed);
    }

    fn default_ttl(&self) -> Duration {
        Duration::from_nanos(self.default_ttl_nanos.load(Ordering::Relaxed))
    }

    /// The value of `key`; `None` if absent or expired.
    pub fn get(&self, key: &str) -> Option<String> {
        let now = (self.clock)();
        self.map
            .get(key)
            .filter(|s| s.live(now))
            .map(|s| s.value.clone())
    }

    /// Set `key` to `value` for `ttl` (default: the store's default ttl).
    /// Overwriting an existing key never fails; a new key when the store is
    /// full returns [`StateFull`] and stores nothing.
    pub fn set(&self, key: &str, value: &str, ttl: Option<Duration>) -> Result<(), StateFull> {
        let now = (self.clock)();
        let expires = now.checked_add(ttl.unwrap_or_else(|| self.default_ttl()));
        if self.sets.fetch_add(1, Ordering::Relaxed) % PURGE_EVERY == PURGE_EVERY - 1 {
            self.purge_at(now);
        }
        if let Some(mut s) = self.map.get_mut(key) {
            value.clone_into(&mut s.value);
            s.expires = expires;
            return Ok(());
        }
        let max_entries = self.max_entries.load(Ordering::Acquire);
        if self.stored.load(Ordering::Acquire) >= max_entries {
            self.purge_if_due(now);
        }
        match self.map.entry(key.to_owned()) {
            Entry::Occupied(mut e) => {
                let s = e.get_mut();
                value.clone_into(&mut s.value);
                s.expires = expires;
            }
            Entry::Vacant(v) => {
                let reserved = self
                    .stored
                    .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                        (n < max_entries).then_some(n + 1)
                    })
                    .is_ok();
                if !reserved {
                    return Err(StateFull);
                }
                v.insert(Slot {
                    value: value.to_owned(),
                    expires,
                });
            }
        }
        Ok(())
    }

    /// Delete `key` (no-op if absent).
    pub fn remove(&self, key: &str) {
        if self.map.remove(key).is_some() {
            self.stored.fetch_sub(1, Ordering::AcqRel);
        }
    }

    /// Live (unexpired) entries. O(entries).
    pub fn len(&self) -> usize {
        let now = (self.clock)();
        self.map.iter().filter(|s| s.live(now)).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drop expired entries, returning how many were removed.
    pub fn purge(&self) -> usize {
        self.purge_at((self.clock)())
    }

    fn purge_if_due(&self, now: Instant) {
        let due = {
            let mut last = self.last_full_purge.lock();
            let due = last.is_none_or(|l| now.saturating_duration_since(l) >= FULL_PURGE_INTERVAL);
            if due {
                *last = Some(now);
            }
            due
        };
        if due {
            self.purge_at(now);
        }
    }

    fn purge_at(&self, now: Instant) -> usize {
        let mut removed = 0;
        self.map.retain(|_, s| {
            let keep = s.live(now);
            removed += usize::from(!keep);
            keep
        });
        if removed > 0 {
            self.stored.fetch_sub(removed, Ordering::AcqRel);
        }
        removed
    }
}

fn ttl_nanos(ttl: Duration) -> u64 {
    u64::try_from(ttl.as_nanos()).unwrap_or(u64::MAX)
}

impl StateSource for StateStore {
    fn get(&self, key: &str) -> Option<String> {
        StateStore::get(self, key)
    }

    fn set(&self, key: &str, value: &str, ttl: Option<Duration>) -> Result<(), StateFull> {
        StateStore::set(self, key, value, ttl)
    }
}
