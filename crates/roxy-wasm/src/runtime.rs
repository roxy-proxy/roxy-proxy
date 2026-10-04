//! The engine, loaded layers, their instance pools and the exchange
//! driver.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};
use tokio::time::{Instant, timeout_at};
use wasmtime::component::{Component, InstancePre, Linker, Resource};
use wasmtime::{Config, Engine, Store, StoreContextMut};
use wasmtime_wasi_http::WasiHttpView;
use wasmtime_wasi_http::p2::bindings::http::types::Scheme as WasiScheme;

use crate::bindings::exports::roxy::addon::init;
use crate::bindings::exports::wasi::http::incoming_handler;
use crate::bindings::roxy::addon::{chain, endpoints, flow};
use crate::config::LayerConfig;
use crate::error::{Budget, LayerError, LoadError};
use crate::exchange::{CancelGuard, Dir, ExchangeShared, FromGuest, IntoGuest};
use crate::host::{LayerHost, LayerRequest, LayerResponse};
use crate::state::{ExchangeCtx, LayerShared, StoreState};

/// Epoch tick: a running guest yields to the async runtime once per tick,
/// so a busy layer cannot hog a worker thread, and cancelling its exchange
/// takes effect within a tick.
const EPOCH_TICK: Duration = Duration::from_millis(1);

struct Ticker {
    stop: Arc<AtomicBool>,
}

impl Drop for Ticker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// The wasm engine shared by every layer: compilation settings and the
/// epoch ticker that makes guests yield. Cheap to clone.
#[derive(Clone)]
pub struct WasmRuntime {
    engine: Engine,
    _ticker: Arc<Ticker>,
}

impl std::fmt::Debug for WasmRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmRuntime").finish_non_exhaustive()
    }
}

impl WasmRuntime {
    /// Creates the engine and starts its epoch ticker thread (stopped when
    /// the last clone is dropped).
    pub fn new() -> Result<Self, LoadError> {
        let mut config = Config::new();
        config.wasm_component_model(true).epoch_interruption(true);
        let engine = Engine::new(&config).map_err(|e| LoadError::Engine(e.to_string()))?;

        let stop = Arc::new(AtomicBool::new(false));
        let ticker_engine = engine.clone();
        let ticker_stop = stop.clone();
        thread::Builder::new()
            .name("roxy-wasm-epoch".to_owned())
            .spawn(move || {
                while !ticker_stop.load(Ordering::Relaxed) {
                    thread::sleep(EPOCH_TICK);
                    ticker_engine.increment_epoch();
                }
            })
            .map_err(|e| LoadError::Engine(format!("epoch ticker: {e}")))?;
        Ok(Self {
            engine,
            _ticker: Arc::new(Ticker { stop }),
        })
    }

    fn linker(&self) -> Result<Linker<StoreState>, String> {
        type Me = wasmtime::component::HasSelf<StoreState>;
        let mut linker = Linker::new(&self.engine);
        // All of WASI 0.2 except the outbound HTTP client, inert (see
        // `StoreState::new`), so stock toolchain output links.
        wasmtime_wasi::p2::add_to_linker_async(&mut linker).map_err(|e| e.to_string())?;
        let options = wasmtime_wasi_http::p2::bindings::LinkOptions::default();
        wasmtime_wasi_http::p2::bindings::http::types::add_to_linker::<
            _,
            wasmtime_wasi_http::WasiHttp,
        >(&mut linker, &options.into(), StoreState::http)
        .map_err(|e| e.to_string())?;
        // Every roxy:addon import is linked whatever the grants; a call
        // without its capability traps.
        chain::add_to_linker::<_, Me>(&mut linker, |s| s).map_err(|e| e.to_string())?;
        endpoints::add_to_linker::<_, Me>(&mut linker, |s| s).map_err(|e| e.to_string())?;
        flow::add_to_linker::<_, Me>(&mut linker, |s| s).map_err(|e| e.to_string())?;
        Ok(linker)
    }
}

/// One live instance of a layer.
struct Instance {
    store: Store<StoreState>,
    handler: incoming_handler::Guest,
    exchanges: u64,
}

struct LayerInner {
    runtime: WasmRuntime,
    shared: Arc<LayerShared>,
    pre: InstancePre<StoreState>,
    handler: incoming_handler::GuestIndices,
    init: init::GuestIndices,
    idle: Mutex<Vec<Instance>>,
    slots: Arc<Semaphore>,
}

impl LayerInner {
    /// The idle instances. Only `Vec` push and pop happen under the lock,
    /// so a poisoned lock still holds a consistent pool.
    fn idle(&self) -> MutexGuard<'_, Vec<Instance>> {
        self.idle.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A compiled layer with its instance pool. Cheap to clone; clones share
/// the pool.
#[derive(Clone)]
pub struct Layer {
    inner: Arc<LayerInner>,
}

impl std::fmt::Debug for Layer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Layer")
            .field("name", &self.inner.shared.config.name)
            .finish_non_exhaustive()
    }
}

/// Maps a guest failure to the error it reports. A failure already
/// recorded for the exchange (a limit or host failure that made the guest
/// trap) takes precedence.
fn classify(err: &wasmtime::Error) -> LayerError {
    match err.downcast_ref::<LayerError>() {
        Some(e) => e.clone(),
        None => LayerError::Trap(format!("{err:#}")),
    }
}

/// Runs once per epoch tick while the guest runs: yields to the async
/// runtime. Not a limit: a guest may compute for as long as it likes.
#[allow(clippy::unnecessary_wraps)] // the callback's signature
fn epoch_yield(_: StoreContextMut<'_, StoreState>) -> wasmtime::Result<wasmtime::UpdateDeadline> {
    Ok(wasmtime::UpdateDeadline::Yield(1))
}

impl Layer {
    /// Compiles `wasm` (a component) and starts one instance, running its
    /// `init`, so a bad layer fails the config load rather than the first
    /// exchange. Compilation runs on the blocking thread pool.
    pub async fn load(
        runtime: &WasmRuntime,
        wasm: Vec<u8>,
        config: LayerConfig,
    ) -> Result<Layer, LoadError> {
        let layer = config.name.clone();
        let limits = &config.limits;
        if limits.max_instances == 0 {
            return Err(LoadError::Limits {
                layer,
                message: "max_instances must be at least 1".to_owned(),
            });
        }
        if limits.first_byte_timeout.is_zero() {
            return Err(LoadError::Limits {
                layer,
                message: "first_byte_timeout must be positive".to_owned(),
            });
        }

        let engine = runtime.engine.clone();
        let component = tokio::task::spawn_blocking(move || Component::new(&engine, &wasm))
            .await
            .map_err(|e| LoadError::Compile {
                layer: layer.clone(),
                message: e.to_string(),
            })?
            .map_err(|e| LoadError::Compile {
                layer: layer.clone(),
                message: format!("{e:#}"),
            })?;

        let linker = runtime.linker().map_err(LoadError::Engine)?;
        let pre = linker
            .instantiate_pre(&component)
            .map_err(|e| LoadError::Link {
                layer: layer.clone(),
                message: format!("{e:#}"),
            })?;
        let missing = |e: wasmtime::Error| LoadError::MissingExport {
            layer: layer.clone(),
            message: format!("{e:#}"),
        };
        let handler = incoming_handler::GuestIndices::new(&pre).map_err(missing)?;
        let init = init::GuestIndices::new(&pre).map_err(missing)?;

        let max_instances = config.limits.max_instances;
        let inner = Arc::new(LayerInner {
            runtime: runtime.clone(),
            shared: Arc::new(LayerShared { config }),
            pre,
            handler,
            init,
            idle: Mutex::new(Vec::new()),
            slots: Arc::new(Semaphore::new(max_instances)),
        });
        let layer = Layer { inner };
        let deadline = Instant::now() + layer.inner.shared.config.limits.first_byte_timeout;
        let first = layer
            .instantiate(deadline)
            .await
            .map_err(|source| LoadError::Start {
                layer: layer.name().to_owned(),
                source,
            })?;
        layer.inner.idle().push(first);
        Ok(layer)
    }

    /// The layer's name.
    pub fn name(&self) -> &str {
        &self.inner.shared.config.name
    }

    /// Instances currently idle in the pool.
    pub fn idle_instances(&self) -> usize {
        self.inner.idle().len()
    }

    async fn instantiate(&self, deadline: Instant) -> Result<Instance, LayerError> {
        let inner = &self.inner;
        let mut store = Store::new(&inner.runtime.engine, StoreState::new(inner.shared.clone()));
        store.limiter(|s| &mut s.limiter);
        store.epoch_deadline_callback(epoch_yield);
        store.set_epoch_deadline(1);

        let start =
            async {
                let instance = inner.pre.instantiate_async(&mut store).await.map_err(|e| {
                    match classify(&e) {
                        LayerError::Trap(msg) => LayerError::Instantiate(msg),
                        other => other,
                    }
                })?;
                let handler = inner
                    .handler
                    .load(&mut store, &instance)
                    .map_err(|e| LayerError::Instantiate(format!("{e:#}")))?;
                let init = inner
                    .init
                    .load(&mut store, &instance)
                    .map_err(|e| LayerError::Instantiate(format!("{e:#}")))?;
                init.call_init(&mut store)
                    .await
                    .map_err(|e| classify(&e))?
                    .map_err(LayerError::Init)?;
                Ok::<_, LayerError>(handler)
            };
        let handler = timeout_at(deadline, start)
            .await
            .map_err(|_| LayerError::BudgetExceeded(Budget::FirstByte))??;
        Ok(Instance {
            store,
            handler,
            exchanges: 0,
        })
    }

    /// Takes an idle instance or starts a new one, once a slot is free.
    /// Waiting for a slot has no deadline; starting an instance must finish
    /// within `first_byte_timeout`, and counts towards it. Returns when the
    /// head clock started.
    async fn checkout(&self) -> Result<(Instance, OwnedSemaphorePermit, Instant), LayerError> {
        let permit = self
            .inner
            .slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| LayerError::Cancelled)?;
        let started = Instant::now();
        let idle = self.inner.idle().pop();
        let instance = if let Some(i) = idle {
            i
        } else {
            let limit = self.inner.shared.config.limits.first_byte_timeout;
            self.instantiate(started + limit).await?
        };
        Ok((instance, permit, started))
    }

    /// Returns a healthy instance to the pool, unless it is due for
    /// recycling.
    fn checkin(&self, mut instance: Instance) {
        instance.store.data_mut().exchange = None;
        instance.exchanges += 1;
        let limits = &self.inner.shared.config.limits;
        let memory = instance.store.data().limiter.total_memory;
        if instance.exchanges >= limits.recycle_after_exchanges
            || memory > limits.recycle_above_memory
        {
            tracing::debug!(
                layer = self.name(),
                exchanges = instance.exchanges,
                memory,
                "recycling layer instance"
            );
            return;
        }
        self.inner.idle().push(instance);
    }

    /// Runs one exchange through the layer.
    ///
    /// `req` must have an absolute URI. Returns the layer's response once
    /// its head is set; the body streams from the guest, which keeps
    /// running until its handler returns. If the layer fails after the
    /// head (trap, budget, host failure), the body ends with
    /// [`roxy_http::BodyError::Stopped`] and the [`crate::LayerOutcome`]
    /// in the response's extensions reports why. Any `Err` here must be
    /// turned into a deny (invariant 3).
    ///
    /// Dropping the future, or the response body before it ends, cancels
    /// the exchange and discards the instance.
    pub async fn handle(
        &self,
        host: Arc<dyn LayerHost>,
        req: LayerRequest,
    ) -> Result<LayerResponse, LayerError> {
        let limits = &self.inner.shared.config.limits;

        let scheme = req
            .uri()
            .scheme()
            .cloned()
            .ok_or_else(|| LayerError::InvalidRequest("request URI has no scheme".into()))?;
        let authority = req
            .uri()
            .authority()
            .map(ToString::to_string)
            .ok_or_else(|| LayerError::InvalidRequest("request URI has no authority".into()))?;
        let wasi_scheme = match scheme.as_str() {
            "http" => WasiScheme::Http,
            "https" => WasiScheme::Https,
            other => WasiScheme::Other(other.to_owned()),
        };

        let (mut instance, permit, started) = self.checkout().await?;
        let shared = ExchangeShared::new();
        let (tx, rx) = oneshot::channel();
        let (req_res, out_res) = {
            let data = instance.store.data_mut();
            data.exchange = Some(ExchangeCtx {
                host,
                shared: shared.clone(),
                next_called: false,
                scheme,
                authority,
            });
            let req = req.map(|b| IntoGuest::new(b, Dir::Request));
            let mut http = data.http();
            let req_res = http
                .new_incoming_request(wasi_scheme, req)
                .map_err(|e| LayerError::InvalidRequest(format!("{e:#}")))?;
            let out_res = http
                .new_response_outparam(tx)
                .map_err(|e| LayerError::Instantiate(format!("{e:#}")))?;
            (req_res, out_res)
        };

        let run = ExchangeRun {
            layer: self.clone(),
            shared: shared.clone(),
            instance: Some(instance),
            _permit: permit,
        };
        let driver = tokio::spawn(run.drive(req_res, out_res));
        let cancel = Arc::new(CancelGuard {
            abort: driver.abort_handle(),
            shared: shared.clone(),
        });

        let settled = shared.wait_settled();
        let head_clock =
            shared.head_clock(limits.first_byte_timeout.saturating_sub(started.elapsed()));
        tokio::select! {
            biased;
            resp = rx => match resp {
                Ok(Ok(resp)) => {
                    let outcome = shared.outcome();
                    let mut resp = resp.map(|b| FromGuest::response(b, shared.clone(), cancel));
                    resp.extensions_mut().insert(outcome);
                    Ok(resp)
                }
                Ok(Err(code)) => {
                    let err = LayerError::ErrorResponse(format!("{code:?}"));
                    shared.fail(err.clone());
                    Err(err)
                }
                // The outparam was dropped: the handler returned without a
                // response, or the instance was torn down.
                Err(_) => Err(shared
                    .wait_settled()
                    .await
                    .err()
                    .unwrap_or(LayerError::NoResponse)),
            },
            outcome = settled => Err(outcome.err().unwrap_or(LayerError::NoResponse)),
            () = head_clock => {
                let err = LayerError::BudgetExceeded(Budget::FirstByte);
                // The driver sees the failure and tears the instance down.
                shared.fail(err.clone());
                Err(err)
            }
        }
    }
}

/// An exchange in progress. Dropping it before it finished (the task was
/// aborted) records [`LayerError::Cancelled`] *before* the instance is
/// dropped, so no guest body can end cleanly.
struct ExchangeRun {
    layer: Layer,
    shared: Arc<ExchangeShared>,
    instance: Option<Instance>,
    _permit: OwnedSemaphorePermit,
}

impl Drop for ExchangeRun {
    fn drop(&mut self) {
        if self.instance.is_some() {
            self.shared.fail(LayerError::Cancelled);
            self.shared.settle();
            self.instance = None;
        }
    }
}

impl ExchangeRun {
    /// Settles the exchange: a failure (recorded first) discards the
    /// instance; success returns it to the pool.
    fn finish(&mut self, result: Result<(), LayerError>) {
        let mut instance = self.instance.take().expect("instance present");
        let result = result.and_then(|()| {
            // Anything the guest still holds when its handler returns was
            // never finished (an unfinished body would otherwise end
            // cleanly when the store is reused or dropped).
            if instance.store.data().table.is_empty() {
                Ok(())
            } else {
                Err(LayerError::InvalidResponse(
                    "handler returned while still holding resources (an unfinished body?)"
                        .to_owned(),
                ))
            }
        });
        if let Err(e) = result {
            tracing::debug!(layer = self.layer.name(), error = %e, "layer exchange failed");
            self.shared.fail(e);
        }
        let failed = self.shared.failure().is_some();
        self.shared.settle();
        if failed {
            drop(instance);
        } else {
            instance.store.data_mut().exchange = None;
            self.layer.checkin(instance);
        }
    }

    async fn drive(
        mut self,
        req: Resource<wasmtime_wasi_http::p2::types::HostIncomingRequest>,
        out: Resource<wasmtime_wasi_http::p2::types::HostResponseOutparam>,
    ) {
        let failure = self.shared.wait_failure();
        let instance = self.instance.as_mut().expect("instance present");
        let call = instance.handler.call_handle(&mut instance.store, req, out);
        let result = tokio::select! {
            biased;
            err = failure => Err(err),
            r = call => r.map_err(|e| classify(&e)),
        };
        self.finish(result);
    }
}
