//! The live secret map: the values behind `${secret:name}` and the
//! redactor built from them.
//!
//! The map lives beside the policy snapshot rather than inside it, so a
//! secrets-only update swaps the map and the redactor without recompiling
//! rules, rebuilding addons or flushing upstream pools. An exchange loads
//! one generation ([`Secrets`]) and resolves every name and redacts every
//! logged string from it, so a swap landing mid-evaluation cannot mix two
//! generations' values. The values are never written anywhere; `Debug`
//! prints only a count.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use arc_swap::ArcSwap;

use crate::flowlog::Redactor;

/// One generation of the secret map: the values and the redactor that
/// scrubs them (and the generation before). Immutable once published.
pub(crate) struct Secrets {
    values: HashMap<String, String>,
    /// The redacted header names, as the policy sets them; secret values
    /// are added on top when the redactor is rebuilt.
    headers: Redactor,
    redactor: Arc<Redactor>,
}

impl Secrets {
    /// The value of secret `name` in this generation.
    pub(crate) fn get(&self, name: &str) -> Option<String> {
        self.values.get(name).cloned()
    }

    /// The redactor for this generation: the redacted header names plus
    /// these secret values and those the swap before replaced.
    pub(crate) fn redactor(&self) -> &Redactor {
        &self.redactor
    }
}

/// Secret values by name, swappable at runtime, plus the redactor that
/// scrubs them from logged text.
pub struct SecretStore {
    state: ArcSwap<Secrets>,
    /// Serialises writers (a swap racing a reload), so neither loses the
    /// other's values; readers never take it.
    write: Mutex<()>,
}

impl std::fmt::Debug for SecretStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretStore")
            .field("secrets", &self.state.load().values.len())
            .finish_non_exhaustive()
    }
}

/// The redactor for `values`, scrubbing `previous` too: an exchange that
/// started before the swap may still be carrying one of the values it
/// replaced, and logs it only when it ends. Older generations are not kept,
/// so the redactor's work stays bounded across rotations.
fn redactor(
    headers: &Redactor,
    values: &HashMap<String, String>,
    previous: &HashMap<String, String>,
) -> Arc<Redactor> {
    let mut r = headers.clone();
    for v in values.values().chain(previous.values()) {
        r.add_secret(v.clone());
    }
    Arc::new(r)
}

impl SecretStore {
    /// A store holding `values`, redacted along with `headers`'s header
    /// names.
    pub(crate) fn new(values: HashMap<String, String>, headers: Redactor) -> Self {
        let redactor = redactor(&headers, &values, &HashMap::new());
        Self {
            state: ArcSwap::from_pointee(Secrets {
                values,
                headers,
                redactor,
            }),
            write: Mutex::new(()),
        }
    }

    /// The current generation. An exchange holds the one it loaded for
    /// as long as it lives.
    pub(crate) fn load(&self) -> Arc<Secrets> {
        self.state.load_full()
    }

    /// The value of secret `name`, as of now.
    pub(crate) fn get(&self, name: &str) -> Option<String> {
        self.state.load().get(name)
    }

    /// The current redactor: the redacted header names plus the current
    /// secret values and those the last swap replaced.
    pub(crate) fn redactor(&self) -> Arc<Redactor> {
        self.state.load().redactor.clone()
    }

    /// Replaces every value, keeping the redacted header names.
    pub(crate) fn swap(&self, values: HashMap<String, String>) {
        let _w = self.write.lock().unwrap_or_else(PoisonError::into_inner);
        let old = self.state.load();
        let redactor = redactor(&old.headers, &values, &old.values);
        self.state.store(Arc::new(Secrets {
            values,
            headers: old.headers.clone(),
            redactor,
        }));
    }

    /// Replaces every value and the redacted header names together (a
    /// policy reload).
    pub(crate) fn replace(&self, values: HashMap<String, String>, headers: Redactor) {
        let _w = self.write.lock().unwrap_or_else(PoisonError::into_inner);
        let old = self.state.load();
        let redactor = redactor(&headers, &values, &old.values);
        self.state.store(Arc::new(Secrets {
            values,
            headers,
            redactor,
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn swap_reads_new_values_and_redacts_the_replaced_ones() {
        let store = SecretStore::new(map(&[("k", "old-value")]), Redactor::new());
        assert_eq!(store.get("k").as_deref(), Some("old-value"));

        store.swap(map(&[("k", "new-value")]));
        assert_eq!(store.get("k").as_deref(), Some("new-value"));
        let r = store.redactor();
        assert_eq!(r.redact_str("x old-value y"), "x [REDACTED] y");
        assert_eq!(r.redact_str("x new-value y"), "x [REDACTED] y");

        // Two swaps on: the first generation is no longer in flight.
        store.swap(map(&[]));
        assert_eq!(store.get("k"), None);
        let r = store.redactor();
        assert_eq!(r.redact_str("new-value"), "[REDACTED]");
        assert_eq!(r.redact_str("old-value"), "old-value");
    }

    /// A loaded generation is untouched by later swaps, so a reader
    /// resolving several names from it sees one consistent map.
    #[test]
    fn a_loaded_generation_outlives_a_swap() {
        let store = SecretStore::new(map(&[("akid", "AKID1"), ("sk", "SK1")]), Redactor::new());
        let generation = store.load();
        assert_eq!(generation.get("akid").as_deref(), Some("AKID1"));
        store.swap(map(&[("akid", "AKID2"), ("sk", "SK2")]));
        store.swap(map(&[("akid", "AKID3"), ("sk", "SK3")]));
        assert_eq!(generation.get("sk").as_deref(), Some("SK1"));
        assert_eq!(generation.redactor().redact_str("SK1"), "[REDACTED]");
        assert_eq!(store.get("sk").as_deref(), Some("SK3"));
        assert_eq!(store.redactor().redact_str("SK1"), "SK1");
    }

    #[test]
    fn swap_keeps_the_header_names_and_replace_sets_them() {
        let mut headers = Redactor::new();
        headers.add_header("x-custom");
        let store = SecretStore::new(map(&[]), headers);
        store.swap(map(&[("k", "v")]));
        assert!(store.redactor().is_redacted_header("X-Custom"));

        store.replace(map(&[]), Redactor::new());
        assert!(!store.redactor().is_redacted_header("x-custom"));
        assert_eq!(store.redactor().redact_str("v"), "[REDACTED]");
    }
}
