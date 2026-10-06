//! Loading `addons:` into ready-to-run layers.
//!
//! WASM components are compiled once per config load and cached across
//! reloads while their file and settings are unchanged, so an unrelated
//! reload keeps their warm instance pools. New layers apply to new
//! exchanges; in-flight exchanges finish on the stack they started with.
//! The cache follows the running policy: a reload whose swap fails leaves
//! it as it was.

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use anyhow::{Context, anyhow};
use roxy_proxy::addons::{
    AddonImpl, AddonSpec, EndpointPath, EndpointSpec, ServiceSpec, StateLimits,
};
use roxy_proxy::addr::PrivateAddrs;
use roxy_rules::Condition;
use roxy_wasm::{
    Capabilities, Capability as WasmCap, Layer, LayerConfig, LayerLimits, WasmRuntime,
};

use crate::config::EndpointPath as ConfigPath;
use crate::config::{Addon, AddonKind, AddonMode, Capability, Config};

/// Endpoint timeout when none is configured.
const DEFAULT_ENDPOINT_TIMEOUT: Duration = Duration::from_secs(30);
/// A service layer's connections to its endpoint when not configured.
const DEFAULT_SERVICE_CONNECTIONS: u64 = 4;
/// Streams on one service connection when not configured.
const DEFAULT_SERVICE_STREAMS: u64 = 100;

fn service(a: &Addon) -> anyhow::Result<ServiceSpec> {
    let endpoint = a
        .endpoint
        .clone()
        .ok_or_else(|| anyhow!("addon {}: no `endpoint`", a.name))?;
    Ok(ServiceSpec {
        endpoint,
        first_byte_timeout: a
            .limits
            .first_byte_timeout
            .unwrap_or(LayerLimits::default().first_byte_timeout),
        max_connections: usize_of(
            a.limits
                .max_connections
                .unwrap_or(DEFAULT_SERVICE_CONNECTIONS),
        ),
        max_streams: usize_of(a.limits.max_streams.unwrap_or(DEFAULT_SERVICE_STREAMS)),
    })
}

/// Compiles and caches addon layers.
#[derive(Default)]
pub struct AddonLoader {
    runtime: OnceLock<WasmRuntime>,
    cache: Mutex<HashMap<String, (u64, Layer)>>,
}

impl std::fmt::Debug for AddonLoader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AddonLoader").finish_non_exhaustive()
    }
}

fn capabilities(caps: &[Capability]) -> Capabilities {
    caps.iter()
        .map(|c| match c {
            Capability::Endpoints => WasmCap::Endpoints,
            Capability::State => WasmCap::State,
            Capability::Record => WasmCap::Record,
            Capability::Metrics => WasmCap::Metrics,
            Capability::Log => WasmCap::Log,
        })
        .collect()
}

/// Where an instance is recycled when the config does not say: three
/// quarters of its memory cap, so lowering `max_memory` alone keeps
/// recycling reachable.
pub fn default_recycle_above_memory(max_memory: u64) -> u64 {
    max_memory / 4 * 3
}

fn usize_of(n: u64) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
}

fn layer_config(a: &Addon) -> anyhow::Result<LayerConfig> {
    let d = LayerLimits::default();
    let l = &a.limits;
    let max_memory = l.max_memory.map_or(d.max_memory, |b| b.as_u64());
    let limits = LayerLimits {
        max_memory,
        first_byte_timeout: l.first_byte_timeout.unwrap_or(d.first_byte_timeout),
        recycle_after_exchanges: l
            .recycle_after_exchanges
            .unwrap_or(d.recycle_after_exchanges),
        recycle_above_memory: l
            .recycle_above_memory
            .map_or(default_recycle_above_memory(max_memory), |b| b.as_u64()),
        max_instances: l.max_instances.map_or(d.max_instances, usize_of),
    };
    if limits != d {
        tracing::info!(
            addon = a.name,
            ?limits,
            "addon limits differ from the defaults"
        );
    }
    let config_json = serde_json::to_string(&a.config)
        .with_context(|| format!("addon {}: `config` is not representable as JSON", a.name))?;
    Ok(LayerConfig {
        name: a.name.clone(),
        capabilities: capabilities(&a.capabilities),
        limits,
        config_json,
    })
}

fn endpoints(a: &Addon) -> anyhow::Result<HashMap<String, EndpointSpec>> {
    a.endpoints
        .iter()
        .map(|(name, e)| {
            let url = e
                .url
                .parse()
                .with_context(|| format!("addon {}: endpoint {name}: url", a.name))?;
            let headers = e
                .headers
                .iter()
                .map(|(h, v)| {
                    let h = http::HeaderName::from_bytes(h.as_bytes()).with_context(|| {
                        format!("addon {}: endpoint {name}: header {h}", a.name)
                    })?;
                    Ok((h, v.clone()))
                })
                .collect::<anyhow::Result<_>>()?;
            Ok((
                name.clone(),
                EndpointSpec {
                    url,
                    path: match e.path {
                        ConfigPath::Fixed => EndpointPath::Fixed,
                        ConfigPath::Prefix => EndpointPath::Prefix,
                    },
                    headers,
                    timeout: e.timeout.unwrap_or(DEFAULT_ENDPOINT_TIMEOUT),
                    retries: e.retries,
                    private: PrivateAddrs::from_private_ok(e.private_ok),
                },
            ))
        })
        .collect()
}

fn state_limits(a: &Addon) -> StateLimits {
    let d = StateLimits::default();
    StateLimits {
        max_entries: a.state.max_entries.map_or(d.max_entries, usize_of),
        max_value_bytes: a
            .state
            .max_value_bytes
            .map_or(d.max_value_bytes, |b| usize_of(b.as_u64())),
        default_ttl: a.state.default_ttl.unwrap_or(d.default_ttl),
    }
}

/// The addons of one config, compiled but not yet the loader's: the
/// layers it keeps across reloads change only once the policy swap they
/// belong to has succeeded.
pub struct PreparedAddons {
    specs: Vec<Arc<AddonSpec>>,
    layers: HashMap<String, (u64, Layer)>,
}

impl PreparedAddons {
    /// The specs for the policy update.
    pub fn specs(&self) -> Vec<Arc<AddonSpec>> {
        self.specs.clone()
    }
}

impl AddonLoader {
    /// Compiles every addon in `config`, reusing cached layers whose file
    /// and settings are unchanged. Any failure fails the whole load
    /// (startup error, or the reload keeps the running policy). The cache
    /// is untouched until [`AddonLoader::install`].
    pub async fn prepare(
        &self,
        config: &Config,
        conditions: Vec<Option<Condition>>,
    ) -> anyhow::Result<PreparedAddons> {
        let mut specs = Vec::with_capacity(config.addons.len());
        let mut layers = HashMap::new();
        for (a, when) in config.addons.iter().zip(conditions) {
            let kind = if a.kind == AddonKind::Service {
                AddonImpl::Service(service(a)?)
            } else {
                let (key, layer) = self.wasm(a).await?;
                layers.insert(a.name.clone(), (key, layer.clone()));
                AddonImpl::Wasm(layer)
            };
            specs.push(Arc::new(AddonSpec {
                name: a.name.clone(),
                mode: match a.mode {
                    AddonMode::Enforce => roxy_proxy::addons::AddonMode::Enforce,
                    AddonMode::Observe => roxy_proxy::addons::AddonMode::Observe,
                },
                kind,
                endpoints: endpoints(a)?,
                state: state_limits(a),
                audit_endpoint: a.audit_endpoint.clone(),
                when,
                sample: a.sample,
            }));
        }
        Ok(PreparedAddons { specs, layers })
    }

    /// Makes `prepared`'s layers the ones later reloads reuse, dropping
    /// every other cached layer (its pool drains as in-flight exchanges
    /// finish).
    pub fn install(&self, prepared: PreparedAddons) {
        *self.cache.lock().unwrap_or_else(PoisonError::into_inner) = prepared.layers;
    }

    /// [`AddonLoader::prepare`] and [`AddonLoader::install`] in one step,
    /// for startup, where there is no running policy to keep.
    pub async fn load(
        &self,
        config: &Config,
        conditions: Vec<Option<Condition>>,
    ) -> anyhow::Result<Vec<Arc<AddonSpec>>> {
        let prepared = self.prepare(config, conditions).await?;
        let specs = prepared.specs();
        self.install(prepared);
        Ok(specs)
    }

    /// Compiles (or reuses) a WASM addon's layer, with its cache key.
    async fn wasm(&self, a: &Addon) -> anyhow::Result<(u64, Layer)> {
        let path = a
            .path
            .as_ref()
            .ok_or_else(|| anyhow!("addon {}: no `path`", a.name))?;
        let bytes = std::fs::read(path)
            .with_context(|| format!("addon {}: reading {}", a.name, path.display()))?;
        let lc = layer_config(a)?;
        let key = {
            let mut h = DefaultHasher::new();
            bytes.hash(&mut h);
            format!("{lc:?}").hash(&mut h);
            h.finish()
        };
        let cached = self
            .cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&a.name)
            .filter(|(k, _)| *k == key)
            .map(|(_, l)| l.clone());
        if let Some(layer) = cached {
            return Ok((key, layer));
        }
        let rt = if let Some(rt) = self.runtime.get() {
            rt.clone()
        } else {
            let rt = WasmRuntime::new().map_err(|e| anyhow!("{e}"))?;
            self.runtime.get_or_init(|| rt).clone()
        };
        let layer = Layer::load(&rt, bytes, lc)
            .await
            .map_err(|e| anyhow!("{e}"))?;
        tracing::info!(addon = a.name, "addon loaded");
        Ok((key, layer))
    }
}

/// Every WASM addon file the config names (for the reload watcher).
pub fn files(config: &Config) -> Vec<std::path::PathBuf> {
    config
        .addons
        .iter()
        .filter(|a| a.kind == AddonKind::Wasm)
        .filter_map(|a| a.path.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(addons: &str) -> (Config, Vec<Option<Condition>>) {
        let wasm = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../roxy-wasm/tests/fixtures/test_layer.wasm");
        let config = Config::from_yaml(&format!(
            "version: 1\nlisteners: [{{ name: p, bind: 127.0.0.1:3128 }}]\naddons:\n{}",
            addons.replace("WASM", wasm.to_str().unwrap())
        ))
        .unwrap();
        let conditions = config.validate().unwrap().addon_conditions;
        (config, conditions)
    }

    fn cached(loader: &AddonLoader) -> Vec<(String, u64)> {
        let mut v: Vec<_> = loader
            .cache
            .lock()
            .unwrap()
            .iter()
            .map(|(n, (k, _))| (n.clone(), *k))
            .collect();
        v.sort();
        v
    }

    /// Preparing a config compiles its layers but changes nothing until
    /// `install`: a reload whose policy swap fails leaves the cache, and so
    /// the layers the next reload reuses, as they were.
    #[tokio::test]
    async fn prepare_leaves_the_cache_until_install() {
        let loader = AddonLoader::default();
        let (c, when) = config("  - { name: a, path: WASM }\n");
        loader.load(&c, when).await.unwrap();
        let before = cached(&loader);
        assert_eq!(before.len(), 1);

        let (c, when) = config(
            "  - { name: a, path: WASM, config: { changed: true } }\n  - { name: b, path: WASM }\n",
        );
        let prepared = loader.prepare(&c, when).await.unwrap();
        assert_eq!(prepared.specs().len(), 2);
        assert_eq!(cached(&loader), before, "a failed swap keeps the cache");

        loader.install(prepared);
        let after = cached(&loader);
        assert_eq!(after.len(), 2);
        assert_ne!(after[0], before[0], "`a` has a new key for its new config");
    }

    /// Lowering `max_memory` alone lowers where instances are recycled too;
    /// an explicit threshold is taken as given.
    #[test]
    fn recycle_threshold_follows_max_memory_unless_set() {
        let (c, _) = config(
            "  - { name: a, path: WASM, limits: { max_memory: 16mb } }\n  \
             - { name: b, path: WASM, limits: { max_memory: 16mb, recycle_above_memory: 1mb } }\n  \
             - { name: c, path: WASM }\n",
        );
        let recycle = |i: usize| {
            layer_config(&c.addons[i])
                .unwrap()
                .limits
                .recycle_above_memory
        };
        assert_eq!(recycle(0), 12 << 20);
        assert_eq!(recycle(1), 1 << 20);
        assert_eq!(recycle(2), LayerLimits::default().recycle_above_memory);
    }

    #[test]
    fn files_names_only_wasm_paths() {
        let (c, _) = config(
            "  - { name: a, path: WASM }\n  \
             - { name: s, kind: service, endpoint: e, endpoints: { e: { url: \"http://s/\" } } }\n",
        );
        assert_eq!(files(&c), [c.addons[0].path.clone().unwrap()]);
    }
}
