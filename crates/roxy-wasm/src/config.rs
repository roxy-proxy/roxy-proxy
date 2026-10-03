//! Per-layer configuration: capabilities and budgets (DESIGN.md §11.2,
//! §11.3, §11.5).

use std::fmt;
use std::time::Duration;

/// A host service a layer may be granted (DESIGN.md §11.3).
///
/// Every capability's import is always linked, so one binary loads under
/// any set of grants; calling an import whose capability was not granted
/// traps and fails the exchange closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    /// `endpoints.call`: named outbound calls.
    Endpoints,
    /// `flow.state-get` / `flow.state-put`: the layer's keyed store.
    State,
    /// `flow.record`: structured events in the flow log.
    Record,
    /// `flow.terminate`: close the connection or quarantine the principal.
    Terminate,
    /// `flow.metric-get`: read-only metrics.
    Metrics,
    /// `flow.log`: roxy's operational log.
    Log,
}

impl Capability {
    /// Every capability.
    pub const ALL: [Capability; 6] = [
        Capability::Endpoints,
        Capability::State,
        Capability::Record,
        Capability::Terminate,
        Capability::Metrics,
        Capability::Log,
    ];

    /// The name used in config (`capabilities: [state, record]`).
    pub fn name(self) -> &'static str {
        match self {
            Capability::Endpoints => "endpoints",
            Capability::State => "state",
            Capability::Record => "record",
            Capability::Terminate => "terminate",
            Capability::Metrics => "metrics",
            Capability::Log => "log",
        }
    }

    /// Parses a config name.
    pub fn from_name(name: &str) -> Option<Capability> {
        Capability::ALL.into_iter().find(|c| c.name() == name)
    }

    fn bit(self) -> u8 {
        1 << (self as u8)
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A set of granted capabilities. The default grants nothing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Capabilities(u8);

impl Capabilities {
    /// No capabilities.
    pub const NONE: Capabilities = Capabilities(0);

    /// Every capability.
    pub fn all() -> Self {
        Capability::ALL.into_iter().collect()
    }

    /// Whether `cap` is granted.
    pub fn contains(self, cap: Capability) -> bool {
        self.0 & cap.bit() != 0
    }

    /// Grants `cap`.
    pub fn insert(&mut self, cap: Capability) {
        self.0 |= cap.bit();
    }

    /// The set with `cap` granted.
    #[must_use]
    pub fn with(mut self, cap: Capability) -> Self {
        self.insert(cap);
        self
    }
}

impl FromIterator<Capability> for Capabilities {
    fn from_iter<I: IntoIterator<Item = Capability>>(iter: I) -> Self {
        let mut caps = Capabilities::NONE;
        for c in iter {
            caps.insert(c);
        }
        caps
    }
}

const MIB: u64 = 1024 * 1024;

/// Budgets for one layer (DESIGN.md §11.2, §11.5). Exceeding any of them
/// fails the exchange closed with [`crate::LayerError::BudgetExceeded`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerLimits {
    /// Linear memory per instance, summed over the instance's memories.
    pub max_memory: u64,
    /// Bytes a layer may hold per direction: what it has read from a body
    /// stream minus what it has passed on in that direction (DESIGN.md
    /// §11.5).
    pub max_buffered_body_bytes: u64,
    /// Wall time the guest may run between host calls (epoch
    /// interruption).
    pub step_cpu: Duration,
    /// Wall clock per exchange, from the start of [`crate::Layer::handle`]
    /// until the guest's handler returns, including waiting for an
    /// instance, endpoint calls and streaming both bodies.
    pub max_exchange_time: Duration,
    /// Fuel (roughly, wasm instructions) the guest may use between host
    /// calls.
    pub fuel_per_step: u64,
    /// Replace an instance after it has served this many exchanges.
    pub recycle_after_exchanges: u64,
    /// Replace an instance after an exchange that left its linear memory
    /// above this size.
    pub recycle_above_memory: u64,
    /// Instances of this layer alive at once, which is also the number of
    /// exchanges it runs concurrently (each exchange holds an instance
    /// until it ends). An exchange that finds none free waits, within its
    /// `max_exchange_time`.
    pub max_instances: usize,
}

impl Default for LayerLimits {
    fn default() -> Self {
        Self {
            max_memory: 64 * MIB,
            max_buffered_body_bytes: MIB,
            step_cpu: Duration::from_millis(50),
            max_exchange_time: Duration::from_secs(60),
            fuel_per_step: 100_000_000,
            recycle_after_exchanges: 10_000,
            recycle_above_memory: 48 * MIB,
            max_instances: 64,
        }
    }
}

/// Everything roxy-wasm needs to run one configured layer.
#[derive(Debug, Clone)]
pub struct LayerConfig {
    /// The layer's name (`addons[].name`), used in errors and logs.
    pub name: String,
    /// Granted capabilities.
    pub capabilities: Capabilities,
    /// Budgets.
    pub limits: LayerLimits,
    /// The layer's `config:` value as a JSON document, returned by
    /// `flow.config`. Opaque to roxy.
    pub config_json: String,
}

impl LayerConfig {
    /// A layer with no capabilities, default limits and `null` config.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            capabilities: Capabilities::NONE,
            limits: LayerLimits::default(),
            config_json: "null".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_names_round_trip() {
        for c in Capability::ALL {
            assert_eq!(Capability::from_name(c.name()), Some(c));
        }
        assert_eq!(Capability::from_name("secrets"), None);
    }

    #[test]
    fn capability_set() {
        let caps = Capabilities::NONE.with(Capability::State);
        assert!(caps.contains(Capability::State));
        assert!(!caps.contains(Capability::Record));
        let all = Capabilities::all();
        assert!(Capability::ALL.into_iter().all(|c| all.contains(c)));
        assert!(!Capabilities::default().contains(Capability::Log));
    }
}
