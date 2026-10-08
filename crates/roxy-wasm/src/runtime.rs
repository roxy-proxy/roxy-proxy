//! The engine, loaded layers, their instance pools and the exchange
//! driver.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};
use tokio::time::{Instant, timeout, timeout_at};
use wasmtime::component::{Component, InstancePre, Linker, Resource};
use wasmtime::{Config, Engine, Store, StoreContextMut};
use wasmtime_wasi::p2::DynInputStream;

use crate::bindings::exports::roxy::addon::{handler, init};
use crate::bindings::roxy::addon::types::RequestHead;
use crate::bindings::roxy::addon::{chain, endpoints, flow, types};
use crate::config::{LayerConfig, LayerLimits};
use crate::error::{Budget, LayerError, LoadError};
use crate::exchange::{CancelGuard, ExchangeShared, FromGuest};
use crate::head;
use crate::host::{LayerHost, LayerRequest, LayerResponse};
use crate::state::{ExchangeCtx, LayerShared, StoreState};
use crate::streams::Streams;

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
        // All of WASI 0.2 (no HTTP), inert (see `StoreState::new`), so
        // stock toolchain output links.
        wasmtime_wasi::p2::add_to_linker_async(&mut linker).map_err(|e| e.to_string())?;
        // Every roxy:addon import is linked whatever the grants; a call
        // without its capability traps.
        types::add_to_linker::<_, Me>(&mut linker, StoreState::called)
            .map_err(|e| e.to_string())?;
        chain::add_to_linker::<_, Me>(&mut linker, StoreState::called)
            .map_err(|e| e.to_string())?;
        endpoints::add_to_linker::<_, Me>(&mut linker, StoreState::called)
            .map_err(|e| e.to_string())?;
        flow::add_to_linker::<_, Me>(&mut linker, StoreState::called).map_err(|e| e.to_string())?;
        Ok(linker)
    }
}

/// One live instance of a layer.
struct Instance {
    store: Store<StoreState>,
    handler: handler::Guest,
    exchanges: u64,
}

struct LayerInner {
    runtime: WasmRuntime,
    shared: Arc<LayerShared>,
    pre: InstancePre<StoreState>,
    handler: handler::GuestIndices,
    init: init::GuestIndices,
    idle: Mutex<Vec<Instance>>,
    slots: Arc<Semaphore>,
    /// Calls from the guest into the host (every import, resource drops
    /// included), across every instance: what the interface shape costs.
    host_calls: Arc<AtomicU64>,
}

impl LayerInner {
    /// The idle instances. Only `Vec` push and pop happen under the lock,
    /// so a poisoned lock still holds a consistent pool.
    fn idle(&self) -> MutexGuard<'_, Vec<Instance>> {
        self.idle.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// How long an exchange may wait for a free instance when all
/// `max_instances` are busy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotWait {
    /// Until one is free: the exchange is slow, never refused.
    Unbounded,
    /// At most this long; past it the exchange fails with
    /// [`LayerError::NoInstance`].
    Within(Duration),
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
    if let Some(e) = err.downcast_ref::<LayerError>() {
        return e.clone();
    }
    LayerError::Trap(format!("{err:#}"))
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
        let handler = handler::GuestIndices::new(&pre).map_err(missing)?;
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
            host_calls: Arc::new(AtomicU64::new(0)),
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

    /// The layer's limits.
    pub fn limits(&self) -> &LayerLimits {
        &self.inner.shared.config.limits
    }

    /// Instances currently idle in the pool.
    pub fn idle_instances(&self) -> usize {
        self.inner.idle().len()
    }

    /// Calls the layer's guests have made into the host so far: every
    /// import, resource drops included. The cost of the interface shape.
    pub fn host_calls(&self) -> u64 {
        self.inner.host_calls.load(Ordering::Relaxed)
    }

    async fn instantiate(&self, deadline: Instant) -> Result<Instance, LayerError> {
        let inner = &self.inner;
        let mut store = Store::new(
            &inner.runtime.engine,
            StoreState::new(inner.shared.clone(), inner.host_calls.clone()),
        );
        store.limiter(|s| &mut s.limiter);
        store.epoch_deadline_callback(epoch_yield);
        store.set_epoch_deadline(1);

        let start =
            async {
                let instance = inner.pre.instantiate_async(&mut store).await.map_err(|e| {
                    match classify(&e) {
                        LayerError::Trap(msg) => LayerError::Instantiate(msg),
                        other @ (LayerError::BudgetExceeded(_)
                        | LayerError::CapabilityDenied { .. }
                        | LayerError::NextCalledTwice
                        | LayerError::OutsideExchange(_)
                        | LayerError::InvalidRequest(_)
                        | LayerError::NoResponse
                        | LayerError::InvalidResponse(_)
                        | LayerError::Host(_)
                        | LayerError::Init(_)
                        | LayerError::Instantiate(_)
                        | LayerError::NoInstance
                        | LayerError::Cancelled
                        | LayerError::Unsubscribed(_)) => other,
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
    /// Waiting for a slot is bounded only by `wait`; starting an instance
    /// must finish within `first_byte_timeout`, and counts towards it.
    /// Returns when the head clock started.
    async fn checkout(
        &self,
        wait: SlotWait,
    ) -> Result<(Instance, OwnedSemaphorePermit, Instant), LayerError> {
        let acquire = self.inner.slots.clone().acquire_owned();
        let permit = match wait {
            SlotWait::Unbounded => acquire.await,
            SlotWait::Within(d) => timeout(d, acquire)
                .await
                .map_err(|_| LayerError::NoInstance)?,
        }
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
        self.handle_waiting(host, req, SlotWait::Unbounded).await
    }

    /// [`Self::handle`], waiting at most `wait` for a free instance when
    /// all `max_instances` are busy; past that the exchange fails with
    /// [`LayerError::NoInstance`] before the layer has seen it.
    pub async fn handle_waiting(
        &self,
        host: Arc<dyn LayerHost>,
        req: LayerRequest,
        wait: SlotWait,
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
            .cloned()
            .ok_or_else(|| LayerError::InvalidRequest("request URI has no authority".into()))?;

        let (mut instance, permit, started) = self.checkout(wait).await?;
        let shared = ExchangeShared::new(host.clone());
        let (tx, mut rx) = oneshot::channel();
        let (parts, body) = req.into_parts();
        let head = head::request_into_guest(&parts);
        let body_res = {
            let data = instance.store.data_mut();
            let mut streams = Streams::default();
            let body_res = streams
                .input(&mut data.table, body)
                .map_err(|e| LayerError::Instantiate(format!("{e:#}")))?;
            data.exchange = Some(ExchangeCtx {
                host,
                shared: shared.clone(),
                next_called: false,
                scheme,
                authority,
                answer: Some(tx),
                streams,
            });
            body_res
        };

        let run = ExchangeRun {
            layer: self.clone(),
            shared: shared.clone(),
            instance: Some(instance),
            _permit: permit,
        };
        let driver = tokio::spawn(run.drive(head, body_res));
        let cancel = Arc::new(CancelGuard {
            abort: driver.abort_handle(),
            shared: shared.clone(),
        });

        let settled = shared.wait_settled();
        let head_clock =
            shared.head_clock(limits.first_byte_timeout.saturating_sub(started.elapsed()));
        // The answer is polled first, but the guest can answer and return
        // between that poll and the next branch's, so a settle or an
        // expired clock winning does not mean no answer came: each reads
        // the channel before deciding.
        let answer = tokio::select! {
            biased;
            answer = &mut rx => answer,
            outcome = settled => match outcome {
                Err(e) => return Err(e),
                // The handler returned cleanly, so whatever it answered is
                // in the channel (or the sender went with the exchange).
                Ok(()) => rx.await,
            },
            () = head_clock => {
                if let Ok(answer) = rx.try_recv() {
                    Ok(answer)
                } else {
                    let err = LayerError::BudgetExceeded(Budget::FirstByte);
                    // The driver sees the failure and tears the instance down.
                    shared.fail(err.clone());
                    return Err(err);
                }
            }
        };
        match answer {
            Ok(resp) => {
                let outcome = shared.outcome();
                let mut resp = resp.map(|b| FromGuest::response(b, shared.clone(), cancel));
                resp.extensions_mut().insert(outcome);
                Ok(resp)
            }
            // The sender was dropped: the handler returned without
            // answering, or the instance was torn down.
            Err(_) => Err(shared
                .wait_settled()
                .await
                .err()
                .unwrap_or(LayerError::NoResponse)),
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

    async fn drive(mut self, head: RequestHead, body: Resource<DynInputStream>) {
        let failure = self.shared.wait_failure();
        let instance = self.instance.as_mut().expect("instance present");
        let call = instance
            .handler
            .call_handle(&mut instance.store, &head, body);
        let result = tokio::select! {
            biased;
            err = failure => Err(err),
            r = call => r.map_err(|e| classify(&e)),
        };
        self.finish(result);
    }
}
