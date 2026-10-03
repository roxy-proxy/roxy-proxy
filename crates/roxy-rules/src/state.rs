//! The bounded TTL key/value state store (docs/rules.md#state): `state["k"]`
//! in rules, the `set_state` action and the addon `state.get/set` calls.
//!
//! Bounded by `max_entries` with **no eviction**: overwriting an existing key
//! (live or expired-but-not-yet-purged) always succeeds; a new key when the
//! table is full is refused with [`StateFull`] and the caller denies the flow.
//! Admission reserves a slot by compare-and-swap while holding the shard
//! entry for the new key, so the number of stored entries never exceeds
//! `max_entries`. Expired entries read as absent immediately and are purged
//! every 1024 `set` calls, and (at most every 100 ms) when a new key meets a
//! full table.

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
    max_entries: usize,
    default_ttl: Duration,
    stored: AtomicUsize,
    clock: Clock,
    sets: AtomicU64,
    last_full_purge: Mutex<Option<Instant>>,
}

impl fmt::Debug for StateStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StateStore")
            .field("stored", &self.stored.load(Ordering::Relaxed))
            .field("max_entries", &self.max_entries)
            .field("default_ttl", &self.default_ttl)
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
            max_entries,
            default_ttl,
            stored: AtomicUsize::new(0),
            clock,
            sets: AtomicU64::new(0),
            last_full_purge: Mutex::new(None),
        }
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
        let expires = now.checked_add(ttl.unwrap_or(self.default_ttl));
        if self.sets.fetch_add(1, Ordering::Relaxed) % PURGE_EVERY == PURGE_EVERY - 1 {
            self.purge_at(now);
        }
        if let Some(mut s) = self.map.get_mut(key) {
            value.clone_into(&mut s.value);
            s.expires = expires;
            return Ok(());
        }
        if self.stored.load(Ordering::Acquire) >= self.max_entries {
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
                        (n < self.max_entries).then_some(n + 1)
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

impl StateSource for StateStore {
    fn get(&self, key: &str) -> Option<String> {
        StateStore::get(self, key)
    }

    fn set(&self, key: &str, value: &str, ttl: Option<Duration>) -> Result<(), StateFull> {
        StateStore::set(self, key, value, ttl)
    }
}
