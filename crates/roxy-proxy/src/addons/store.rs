//! Process-wide addon state that outlives a reload: each addon's keyed
//! store.

use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use roxy_rules::StateStore;

use super::StateLimits;

/// Every addon's store, by addon name. Each is a [`StateStore`]: sharded,
/// bounded by the addon's `max_entries` with no early eviction (a write of
/// a new key when full fails), and purged when full at most every 100 ms,
/// so one addon's full store cannot stall another's. The outer lock is
/// only written when an addon writes for the first time.
#[derive(Debug, Default)]
pub(crate) struct LayerStates {
    stores: RwLock<HashMap<String, Arc<StateStore>>>,
}

impl LayerStates {
    pub(crate) fn get(&self, layer: &str, key: &str) -> Option<String> {
        self.existing(layer)?.get(key)
    }

    /// Writes `value` (already checked to be JSON). `Err` is the refusal
    /// the addon sees.
    pub(crate) fn put(
        &self,
        layer: &str,
        limits: &StateLimits,
        key: &str,
        value: &str,
        ttl: Option<Duration>,
    ) -> Result<(), String> {
        if value.len() > limits.max_value_bytes {
            return Err(format!(
                "value is {} bytes; the limit is {}",
                value.len(),
                limits.max_value_bytes
            ));
        }
        let store = match self.existing(layer) {
            Some(s) => s,
            None => self
                .stores
                .write()
                .unwrap_or_else(PoisonError::into_inner)
                .entry(layer.to_owned())
                .or_insert_with(|| {
                    Arc::new(StateStore::new(limits.max_entries, limits.default_ttl))
                })
                .clone(),
        };
        store.set(key, value, ttl).map_err(|e| e.to_string())
    }

    /// Applies each addon's entry cap and default ttl to its live store
    /// on reload. Stored entries stay; a lower cap only refuses new keys.
    pub(crate) fn configure<'a>(
        &self,
        addons: impl IntoIterator<Item = (&'a str, &'a StateLimits)>,
    ) {
        let g = self.stores.read().unwrap_or_else(PoisonError::into_inner);
        for (layer, limits) in addons {
            if let Some(s) = g.get(layer) {
                s.set_limits(limits.max_entries, limits.default_ttl);
            }
        }
    }

    fn existing(&self, layer: &str) -> Option<Arc<StateStore>> {
        self.stores
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(layer)
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_caps_without_eviction() {
        let s = LayerStates::default();
        let limits = StateLimits {
            max_entries: 2,
            max_value_bytes: 4,
            default_ttl: Duration::from_secs(60),
        };
        assert!(s.put("a", &limits, "k1", "1", None).is_ok());
        assert!(s.put("a", &limits, "k2", "2", None).is_ok());
        assert!(s.put("a", &limits, "k3", "3", None).is_err());
        // Overwriting an existing key is fine; other layers are separate.
        assert!(s.put("a", &limits, "k1", "11", None).is_ok());
        assert!(s.put("b", &limits, "k3", "3", None).is_ok());
        assert!(s.put("a", &limits, "k1", "12345", None).is_err());
        assert_eq!(s.get("a", "k1").as_deref(), Some("11"));
        assert_eq!(s.get("b", "k1"), None);
        // Expired entries make room.
        assert!(s.put("c", &limits, "x", "1", Some(Duration::ZERO)).is_ok());
        assert_eq!(s.get("c", "x"), None);
    }

    #[test]
    fn reload_changes_limits_and_keeps_entries() {
        let s = LayerStates::default();
        let mut limits = StateLimits {
            max_entries: 2,
            max_value_bytes: 4,
            default_ttl: Duration::from_secs(60),
        };
        assert!(s.put("a", &limits, "k1", "1", None).is_ok());
        assert!(s.put("a", &limits, "k2", "2", None).is_ok());
        assert!(s.put("a", &limits, "k3", "3", None).is_err());
        // A raised cap admits more keys; the stored ones survive.
        limits.max_entries = 3;
        s.configure([("a", &limits), ("unused", &limits)]);
        assert!(s.put("a", &limits, "k3", "3", None).is_ok());
        assert!(s.put("a", &limits, "k4", "4", None).is_err());
        // A lowered cap evicts nothing.
        limits.max_entries = 1;
        s.configure([("a", &limits)]);
        assert_eq!(s.get("a", "k1").as_deref(), Some("1"));
        assert_eq!(s.get("a", "k3").as_deref(), Some("3"));
        assert!(s.put("a", &limits, "k2", "22", None).is_ok());
        assert!(s.put("a", &limits, "k4", "4", None).is_err());
        // A new default ttl applies to later writes.
        limits.default_ttl = Duration::ZERO;
        s.configure([("a", &limits)]);
        assert!(s.put("a", &limits, "k1", "11", None).is_ok());
        assert_eq!(s.get("a", "k1"), None);
        assert_eq!(s.get("a", "k2").as_deref(), Some("22"));
    }
}
