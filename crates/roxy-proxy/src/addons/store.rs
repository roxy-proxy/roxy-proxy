//! Process-wide addon state that outlives a reload: each addon's keyed
//! store (docs/addons.md#state).

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use super::StateLimits;

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
