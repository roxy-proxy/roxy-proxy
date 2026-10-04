//! Loading `addons:` into ready-to-run layers.
//!
//! WASM components are compiled once per config load and cached across
//! reloads while their file and settings are unchanged, so an unrelated
//! reload keeps their warm instance pools. New layers apply to new
//! exchanges; in-flight exchanges finish on the stack they started with.

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use anyhow::{Context, anyhow};
use roxy_proxy::addons::{AddonImpl, AddonSpec, EndpointSpec, ServiceSpec, StateLimits};
use roxy_wasm::{
    Capabilities, Capability as WasmCap, Layer, LayerConfig, LayerLimits, WasmRuntime,
};

use crate::config::{Addon, AddonKind, AddonMode, Capability, Config};

/// Endpoint timeout when none is configured.
const DEFAULT_ENDPOINT_TIMEOUT: Duration = Duration::from_secs(30);
/// A service layer's `first_byte_timeout` when none is configured.
const DEFAULT_FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(30);
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
            .unwrap_or(DEFAULT_FIRST_BYTE_TIMEOUT),
        max_exchange_time: a
            .limits
            .max_exchange_time
            .unwrap_or(LayerLimits::default().max_exchange_time),
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
        .filter_map(|c| match c {
            Capability::Endpoints => Some(WasmCap::Endpoints),
            Capability::State => Some(WasmCap::State),
            Capability::Record => Some(WasmCap::Record),
            Capability::Metrics => Some(WasmCap::Metrics),
            Capability::Log => Some(WasmCap::Log),
            // Refused by validation.
            Capability::Secrets => None,
        })
        .collect()
}

fn usize_of(n: u64) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
}

fn layer_config(config: &Config, a: &Addon) -> anyhow::Result<LayerConfig> {
    let d = LayerLimits::default();
    let l = &a.limits;
    let limits = LayerLimits {
        max_memory: l.max_memory.map_or(d.max_memory, |b| b.as_u64()),
        max_buffered_body_bytes: l
            .max_buffered_body_bytes
            .map_or(config.limits.max_inspect_body_bytes.as_u64(), |b| {
                b.as_u64()
            }),
        step_cpu: l.step_cpu.unwrap_or(d.step_cpu),
        max_exchange_time: l.max_exchange_time.unwrap_or(d.max_exchange_time),
        fuel_per_step: l.fuel_per_step.unwrap_or(d.fuel_per_step),
        recycle_after_exchanges: l
            .recycle_after_exchanges
            .unwrap_or(d.recycle_after_exchanges),
        recycle_above_memory: l
            .recycle_above_memory
            .map_or(d.recycle_above_memory, |b| b.as_u64()),
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
                    headers,
                    timeout: e.timeout.unwrap_or(DEFAULT_ENDPOINT_TIMEOUT),
                    retries: e.retries,
                    private_ok: e.private_ok,
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

impl AddonLoader {
    /// Loads every addon in `config`. Any failure fails the whole load
    /// (startup error, or the reload keeps the running policy).
    pub async fn load(&self, config: &Config) -> anyhow::Result<Vec<Arc<AddonSpec>>> {
        let mut out = Vec::with_capacity(config.addons.len());
        let mut keep = Vec::new();
        let conditions = config.compile_addon_conditions().map_err(|d| {
            let msgs: Vec<String> = d.iter().map(ToString::to_string).collect();
            anyhow!("{}", msgs.join("; "))
        })?;
        for (a, when) in config.addons.iter().zip(conditions) {
            let kind = if a.kind == AddonKind::Service {
                AddonImpl::Service(service(a)?)
            } else {
                AddonImpl::Wasm(self.wasm(config, a, &mut keep).await?)
            };
            out.push(Arc::new(AddonSpec {
                name: a.name.clone(),
                observe: a.mode == AddonMode::Observe,
                kind,
                endpoints: endpoints(a)?,
                state: state_limits(a),
                audit_endpoint: a.audit_endpoint.clone(),
                when,
                sample: a.sample,
            }));
        }
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        cache.clear();
        for (name, key, layer) in keep {
            cache.insert(name, (key, layer));
        }
        Ok(out)
    }

    /// Compiles (or reuses) a WASM addon's layer.
    async fn wasm(
        &self,
        config: &Config,
        a: &Addon,
        keep: &mut Vec<(String, u64, Layer)>,
    ) -> anyhow::Result<Layer> {
        let path = a
            .path
            .as_ref()
            .ok_or_else(|| anyhow!("addon {}: no `path`", a.name))?;
        let bytes = std::fs::read(path)
            .with_context(|| format!("addon {}: reading {}", a.name, path.display()))?;
        let lc = layer_config(config, a)?;
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
        let layer = if let Some(l) = cached {
            l
        } else {
            let rt = if let Some(rt) = self.runtime.get() {
                rt.clone()
            } else {
                let rt = WasmRuntime::new().map_err(|e| anyhow!("{e}"))?;
                self.runtime.get_or_init(|| rt).clone()
            };
            let layer = Layer::load(&rt, bytes, lc)
                .await
                .map_err(|e| anyhow!("{e}"))?;
            tracing::info!(addon = a.name, tunnel = layer.has_tunnel(), "addon loaded");
            layer
        };
        keep.push((a.name.clone(), key, layer.clone()));
        Ok(layer)
    }

    /// [`AddonLoader::load`] from a blocking thread (config reload).
    pub fn load_blocking(&self, config: &Config) -> anyhow::Result<Vec<Arc<AddonSpec>>> {
        if config.addons.is_empty() {
            return Ok(Vec::new());
        }
        tokio::runtime::Handle::current().block_on(self.load(config))
    }
}
