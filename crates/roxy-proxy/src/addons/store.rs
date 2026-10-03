//! Process-wide addon state that outlives a reload: the quarantine set
//! (§11.3 `terminate`) and each addon's keyed store (§11.3 `state`).

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use super::StateLimits;

/// Principals an addon quarantined. The quarantine gate denies their
/// requests with rule `_quarantined` until the entry expires. Entries are
/// cleared only by their TTL (or a restart): an addon cannot lift one, and
/// a reload does not.
#[derive(Debug, Default)]
pub(crate) struct Quarantine {
    entries: Mutex<HashMap<String, (Instant, String)>>,
}

/// Longest quarantine an addon may set, and the one it gets without a TTL.
pub(crate) const MAX_QUARANTINE: Duration = Duration::from_hours(24);
/// Most quarantined principals at once. Past this, `terminate` reports
/// that it did not take effect.
const MAX_QUARANTINED: usize = 100_000;

impl Quarantine {
    /// Quarantines `principal` for `ttl` (capped at a day). Returns whether
    /// it took effect.
    pub(crate) fn add(&self, principal: &str, ttl: Option<Duration>, reason: &str) -> bool {
        let ttl = ttl.unwrap_or(MAX_QUARANTINE).min(MAX_QUARANTINE);
        let now = Instant::now();
        let mut g = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if g.len() >= MAX_QUARANTINED && !g.contains_key(principal) {
            g.retain(|_, (until, _)| *until > now);
            if g.len() >= MAX_QUARANTINED {
                return false;
            }
        }
        let until = now + ttl;
        let e = g
            .entry(principal.to_owned())
            .or_insert((until, reason.to_owned()));
        if e.0 < until {
            *e = (until, reason.to_owned());
        }
        true
    }

    /// The reason `principal` is quarantined, if it is.
    pub(crate) fn check(&self, principal: &str) -> Option<String> {
        let now = Instant::now();
        let mut g = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        match g.get(principal) {
            Some((until, reason)) if *until > now => Some(reason.clone()),
            Some(_) => {
                g.remove(principal);
                None
            }
            None => None,
        }
    }
}

/// One addon's keyed store: JSON values with a TTL, an entry cap and a
/// value cap. Nothing is evicted early: a write when full fails.
#[derive(Debug, Default)]
struct Store {
    entries: HashMap<String, (String, Instant)>,
}

/// Every addon's store, by addon name.
#[derive(Debug, Default)]
pub(crate) struct LayerStates {
    stores: Mutex<HashMap<String, Store>>,
}

impl LayerStates {
    pub(crate) fn get(&self, layer: &str, key: &str) -> Option<String> {
        let now = Instant::now();
        let mut g = self.stores.lock().unwrap_or_else(PoisonError::into_inner);
        let store = g.get_mut(layer)?;
        match store.entries.get(key) {
            Some((v, until)) if *until > now => Some(v.clone()),
            Some(_) => {
                store.entries.remove(key);
                None
            }
            None => None,
        }
    }

    /// Writes `value` (already checked to be JSON). `Err` is the refusal
    /// the addon sees.
    pub(crate) fn put(
        &self,
        layer: &str,
        limits: &StateLimits,
        key: &str,
        value: String,
        ttl: Option<Duration>,
    ) -> Result<(), String> {
        if value.len() > limits.max_value_bytes {
            return Err(format!(
                "value is {} bytes; the limit is {}",
                value.len(),
                limits.max_value_bytes
            ));
        }
        let now = Instant::now();
        let until = now + ttl.unwrap_or(limits.default_ttl);
        let mut g = self.stores.lock().unwrap_or_else(PoisonError::into_inner);
        let store = g.entry(layer.to_owned()).or_default();
        if !store.entries.contains_key(key) && store.entries.len() >= limits.max_entries {
            store.entries.retain(|_, (_, u)| *u > now);
            if store.entries.len() >= limits.max_entries {
                return Err("state store full".to_owned());
            }
        }
        store.entries.insert(key.to_owned(), (value, until));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quarantine_expires_and_extends() {
        let q = Quarantine::default();
        assert!(q.check("ip:1").is_none());
        assert!(q.add("ip:1", Some(Duration::from_millis(30)), "bad"));
        assert_eq!(q.check("ip:1").as_deref(), Some("bad"));
        // A shorter TTL does not shorten it.
        assert!(q.add("ip:1", Some(Duration::from_millis(1)), "again"));
        std::thread::sleep(Duration::from_millis(40));
        assert!(q.check("ip:1").is_none());
    }

    #[test]
    fn state_caps_without_eviction() {
        let s = LayerStates::default();
        let limits = StateLimits {
            max_entries: 2,
            max_value_bytes: 4,
            default_ttl: Duration::from_secs(60),
        };
        assert!(s.put("a", &limits, "k1", "1".into(), None).is_ok());
        assert!(s.put("a", &limits, "k2", "2".into(), None).is_ok());
        assert!(s.put("a", &limits, "k3", "3".into(), None).is_err());
        // Overwriting an existing key is fine; other layers are separate.
        assert!(s.put("a", &limits, "k1", "11".into(), None).is_ok());
        assert!(s.put("b", &limits, "k3", "3".into(), None).is_ok());
        assert!(s.put("a", &limits, "k1", "12345".into(), None).is_err());
        assert_eq!(s.get("a", "k1").as_deref(), Some("11"));
        assert_eq!(s.get("b", "k1"), None);
        // Expired entries make room.
        assert!(
            s.put("c", &limits, "x", "1".into(), Some(Duration::ZERO))
                .is_ok()
        );
        assert_eq!(s.get("c", "x"), None);
    }
}
