//! The data in each instance's `Store`: the WASI context, the memory
//! limiter, and the implementations of the `roxy:addon` imports.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use http::uri::{Authority, Scheme};
use roxy_http::Body;
use tokio::sync::oneshot;
use wasmtime::component::{Resource, ResourceTable};
use wasmtime_wasi::p2::{DynInputStream, DynOutputStream, DynPollable};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};

use crate::bindings::roxy::addon::{chain, endpoints, flow, types};
use crate::config::{Capability, LayerConfig};
use crate::error::{Budget, LayerError};
use crate::exchange::{ExchangeShared, FromGuest};
use crate::head::{self, HeadError};
use crate::host::{EndpointError, LayerHost, LogLevel, TagError};
use crate::streams::{Answer, PendingResponse, Produced, Streams};

/// Most resources (streams, pollables, pending responses) a guest may hold
/// at once. Each costs host memory outside the guest's `max_memory`.
const MAX_RESOURCES: usize = 4096;
/// Most elements a guest table may grow to.
const MAX_TABLE_ELEMENTS: usize = 100_000;
/// Longest `flow.log` message, and longest `flow.record` document (kind and
/// JSON together), in bytes.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;
/// Most bytes in a whole body the guest hands the host in one piece
/// (`body.bytes`); a larger body is streamed. Held host-side until read,
/// outside the guest's `max_memory`.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// The layer, as every instance of it sees it.
#[derive(Debug)]
pub(crate) struct LayerShared {
    pub(crate) config: LayerConfig,
}

/// The exchange an instance is running.
pub(crate) struct ExchangeCtx {
    pub(crate) host: Arc<dyn LayerHost>,
    pub(crate) shared: Arc<ExchangeShared>,
    pub(crate) next_called: bool,
    /// The exchange's scheme and authority, the defaults for a request the
    /// guest passes to `next` without them.
    pub(crate) scheme: Scheme,
    pub(crate) authority: Authority,
    /// Takes the guest's answer (`respond`); `None` once it has answered.
    pub(crate) answer: Option<oneshot::Sender<http::Response<Body>>>,
    /// The streams handed to the guest so far.
    pub(crate) streams: Streams,
}

/// Linear-memory accounting for one instance (`max_memory`).
#[derive(Debug)]
pub(crate) struct Limiter {
    max_memory: u64,
    /// Bytes of linear memory across the instance's memories.
    pub(crate) total_memory: u64,
}

impl wasmtime::ResourceLimiter for Limiter {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        let grow = desired.saturating_sub(current) as u64;
        let total = self.total_memory.saturating_add(grow);
        if total > self.max_memory {
            return Err(wasmtime::Error::new(LayerError::BudgetExceeded(
                Budget::Memory,
            )));
        }
        self.total_memory = total;
        Ok(true)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if desired > MAX_TABLE_ELEMENTS {
            return Err(wasmtime::Error::new(LayerError::BudgetExceeded(
                Budget::Memory,
            )));
        }
        Ok(true)
    }
}

pub(crate) struct StoreState {
    wasi: WasiCtx,
    pub(crate) table: ResourceTable,
    pub(crate) layer: Arc<LayerShared>,
    pub(crate) limiter: Limiter,
    pub(crate) exchange: Option<ExchangeCtx>,
    /// Counted once per import call, in the getter every binding goes
    /// through to reach this state.
    host_calls: Arc<AtomicU64>,
}

impl StoreState {
    pub(crate) fn new(layer: Arc<LayerShared>, host_calls: Arc<AtomicU64>) -> Self {
        // No preopens, no environment, no arguments, stdio closed, every
        // socket address denied and name lookup off: the WASI imports a
        // stock toolchain links are present but reach nothing.
        let wasi = WasiCtx::builder()
            .allow_tcp(false)
            .allow_udp(false)
            .allow_ip_name_lookup(false)
            .build();
        let mut table = ResourceTable::new();
        table.set_max_capacity(MAX_RESOURCES);
        let max_memory = layer.config.limits.max_memory;
        Self {
            wasi,
            table,
            layer,
            limiter: Limiter {
                max_memory,
                total_memory: 0,
            },
            exchange: None,
            host_calls,
        }
    }

    /// The getter the `roxy:addon` bindings reach the state through: one
    /// call per import.
    pub(crate) fn called(&mut self) -> &mut Self {
        self.host_calls.fetch_add(1, Ordering::Relaxed);
        self
    }

    fn require(&self, cap: Capability, import: &'static str) -> wasmtime::Result<()> {
        if self.layer.config.capabilities.contains(cap) {
            Ok(())
        } else {
            Err(wasmtime::Error::new(LayerError::CapabilityDenied {
                capability: cap,
                import,
            }))
        }
    }

    fn exchange(&self, import: &'static str) -> wasmtime::Result<&ExchangeCtx> {
        self.exchange
            .as_ref()
            .ok_or_else(|| wasmtime::Error::new(LayerError::OutsideExchange(import)))
    }

    fn exchange_mut(&mut self, import: &'static str) -> wasmtime::Result<&mut ExchangeCtx> {
        self.exchange
            .as_mut()
            .ok_or_else(|| wasmtime::Error::new(LayerError::OutsideExchange(import)))
    }

    fn host(&self, import: &'static str) -> wasmtime::Result<Arc<dyn LayerHost>> {
        Ok(self.exchange(import)?.host.clone())
    }

    /// Runs a host-service future, turning a [`crate::HostError`] into a
    /// trap that fails the exchange.
    fn host_failed(&self, err: crate::host::HostError) -> wasmtime::Error {
        self.fail(LayerError::Host(err))
    }

    /// A trap that fails the exchange, if one is running, with `err`.
    fn fail(&self, err: LayerError) -> wasmtime::Error {
        if let Some(ex) = &self.exchange {
            ex.shared.fail(err.clone());
        }
        wasmtime::Error::new(err)
    }

    /// Refuses a `flow.log` or `flow.record` payload over
    /// [`MAX_MESSAGE_BYTES`], so a guest cannot grow the host's memory (or
    /// its log) a payload at a time.
    fn check_message(&self, len: usize) -> wasmtime::Result<()> {
        if len > MAX_MESSAGE_BYTES {
            return Err(self.fail(LayerError::BudgetExceeded(Budget::Message)));
        }
        Ok(())
    }

    /// The body the guest handed over, as the proxy's; for `stream`, also
    /// the `output-stream` the guest writes it through.
    fn body_from_guest(
        &mut self,
        body: types::Body,
        produced: Produced,
    ) -> Result<(Body, Option<Resource<DynOutputStream>>), LayerError> {
        let Self {
            table, exchange, ..
        } = self;
        let ex = exchange.as_mut().expect("in an exchange");
        match body {
            types::Body::Empty => Ok((Body::empty(), None)),
            types::Body::Bytes(b) => {
                if b.len() > MAX_BODY_BYTES {
                    return Err(LayerError::BudgetExceeded(Budget::Body));
                }
                Ok((Body::from_bytes(b), None))
            }
            types::Body::Passthrough(stream) => {
                let moved = ex.streams.take_input(&stream);
                // The guest's handle is spent either way.
                table
                    .delete(stream)
                    .map_err(|e| invalid(produced, e.to_string()))?;
                moved.map(|b| (b, None)).ok_or_else(|| {
                    invalid(
                        produced,
                        "passthrough of a stream this exchange did not hand out".to_owned(),
                    )
                })
            }
            types::Body::Stream => {
                let (out, body) = ex
                    .streams
                    .output(table, produced, ex.shared.clone())
                    .map_err(|e| invalid(produced, e.to_string()))?;
                Ok((body, Some(out)))
            }
        }
    }

    /// Spends a body the guest handed to a call that did not take it: a
    /// `passthrough` handle is the host's from the call on, so it leaves the
    /// table and its body is dropped.
    fn discard_body(&mut self, body: types::Body) {
        if let types::Body::Passthrough(stream) = body {
            if let Some(ex) = self.exchange.as_mut() {
                drop(ex.streams.take_input(&stream));
            }
            let _ = self.table.delete(stream);
        }
    }

    /// A resolved `next` or endpoint call, as the guest takes it: the head
    /// and a stream for the body.
    fn answer_into_guest(
        &mut self,
        answer: Answer,
    ) -> wasmtime::Result<Result<(types::ResponseHead, Resource<DynInputStream>), types::Error>>
    {
        let resp = match answer {
            Ok(resp) => resp,
            Err(e) => return Ok(Err(e)),
        };
        let (parts, body) = resp.into_parts();
        let head = head::response_into_guest(&parts);
        let Self {
            table, exchange, ..
        } = self;
        let ex = exchange
            .as_mut()
            .ok_or_else(|| wasmtime::Error::new(LayerError::OutsideExchange("pending-response")))?;
        let stream = ex.streams.input(table, body)?;
        Ok(Ok((head, stream)))
    }
}

/// An unusable guest head or body, named for the message it was part of.
fn invalid(produced: Produced, msg: String) -> LayerError {
    match produced {
        Produced::Response => LayerError::InvalidResponse(msg),
        Produced::Next | Produced::Endpoint => LayerError::InvalidRequest(msg),
    }
}

fn head_error(err: HeadError, produced: Produced) -> LayerError {
    match err {
        HeadError::TooLarge => LayerError::BudgetExceeded(Budget::Fields),
        HeadError::Invalid(msg) | HeadError::InvalidPath(msg) => invalid(produced, msg),
    }
}

fn internal(msg: &str) -> types::Error {
    types::Error::Internal(Some(msg.to_owned()))
}

impl WasiView for StoreState {
    /// The getter the WASI bindings reach the state through: one call per
    /// import.
    fn ctx(&mut self) -> WasiCtxView<'_> {
        self.host_calls.fetch_add(1, Ordering::Relaxed);
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

/// Pauses the exchange's head clock while `next` runs below the layer,
/// until it returns or the guest abandons it.
struct Below(Arc<ExchangeShared>);

impl Below {
    fn enter(shared: Arc<ExchangeShared>) -> Self {
        shared.set_below(true);
        Self(shared)
    }
}

impl Drop for Below {
    fn drop(&mut self) {
        self.0.set_below(false);
    }
}

type Call = Result<(Resource<PendingResponse>, Option<Resource<DynOutputStream>>), types::Error>;

// Every import is bound `async` (one bindgen default); some need no await.
#[allow(clippy::unused_async_trait_impl)]
impl types::Host for StoreState {
    async fn finish(&mut self, body: Resource<DynOutputStream>) -> wasmtime::Result<()> {
        let taken = self
            .exchange_mut("types.finish")?
            .streams
            .take_output(&body);
        self.table.delete(body)?;
        let sender = match taken {
            Some((Some(sender), _)) => sender,
            Some((None, produced)) => {
                return Err(self.fail(invalid(produced, "finish of a finished body".to_owned())));
            }
            None => {
                return Err(self.fail(LayerError::InvalidRequest(
                    "finish of a stream this exchange did not hand out".to_owned(),
                )));
            }
        };
        // The end queues behind the frames already written. Waiting for
        // room here would wait on the reader, which may be this very guest
        // (reading the response), and deadlock; finishing a body nobody
        // reads any more is harmless.
        tokio::spawn(async move {
            let _ = sender.finish().await;
        });
        Ok(())
    }
}

// Every import is bound `async` (one bindgen default); some need no await.
#[allow(clippy::unused_async_trait_impl)]
impl types::HostPendingResponse for StoreState {
    async fn subscribe(
        &mut self,
        this: Resource<PendingResponse>,
    ) -> wasmtime::Result<Resource<DynPollable>> {
        wasmtime_wasi::p2::subscribe(&mut self.table, this)
    }

    async fn get(
        &mut self,
        this: Resource<PendingResponse>,
    ) -> wasmtime::Result<
        Option<Result<(types::ResponseHead, Resource<DynInputStream>), types::Error>>,
    > {
        let answer = match self.table.get_mut(&this)?.poll_take() {
            Ok(None) => return Ok(None),
            Ok(Some(answer)) => answer,
            Err(()) => return Err(wasmtime::format_err!("pending-response already taken")),
        };
        self.answer_into_guest(answer).map(Some)
    }

    async fn wait(
        &mut self,
        this: Resource<PendingResponse>,
    ) -> wasmtime::Result<Result<(types::ResponseHead, Resource<DynInputStream>), types::Error>>
    {
        let pending = self.table.delete(this)?;
        let answer = pending
            .wait()
            .await
            .map_err(|()| wasmtime::format_err!("pending-response already taken"))?;
        self.answer_into_guest(answer)
    }

    async fn drop(&mut self, this: Resource<PendingResponse>) -> wasmtime::Result<()> {
        self.table.delete(this)?;
        Ok(())
    }
}

// Every import is bound `async` (one bindgen default); some need no await.
#[allow(clippy::unused_async_trait_impl)]
impl chain::Host for StoreState {
    async fn next(
        &mut self,
        head: types::RequestHead,
        body: types::Body,
    ) -> wasmtime::Result<Call> {
        let (host, shared, parsed) = {
            let ex = self.exchange_mut("chain.next")?;
            if ex.next_called {
                return Err(wasmtime::Error::new(LayerError::NextCalledTwice));
            }
            ex.next_called = true;
            let parsed = head::request_from_guest(head, Some((&ex.scheme, &ex.authority)));
            (ex.host.clone(), ex.shared.clone(), parsed)
        };
        let (method, uri, headers) =
            parsed.map_err(|e| self.fail(head_error(e, Produced::Next)))?;
        let (body, out) = self
            .body_from_guest(body, Produced::Next)
            .map_err(|e| self.fail(e))?;
        let mut request = http::Request::new(FromGuest::next_request(body, shared.clone()));
        *request.method_mut() = method;
        *request.uri_mut() = uri;
        *request.headers_mut() = headers;

        let fut = wasmtime_wasi::runtime::spawn(async move {
            let below = Below::enter(shared.clone());
            let resp = host.next(request).await;
            drop(below);
            if shared.check_next().is_err() {
                return Err(internal("next failed"));
            }
            match resp {
                Ok(resp) => Ok(resp),
                Err(e) => {
                    shared.fail(LayerError::Host(e));
                    Err(internal("next failed"))
                }
            }
        });
        let pending = self.table.push(PendingResponse::new(fut))?;
        Ok(Ok((pending, out)))
    }

    async fn respond(
        &mut self,
        head: types::ResponseHead,
        body: types::Body,
    ) -> wasmtime::Result<Option<Resource<DynOutputStream>>> {
        let answer = self.exchange_mut("chain.respond")?.answer.take();
        let Some(answer) = answer else {
            return Err(self.fail(LayerError::InvalidResponse(
                "respond called twice".to_owned(),
            )));
        };
        let (status, headers) = head::response_from_guest(head)
            .map_err(|e| self.fail(head_error(e, Produced::Response)))?;
        let produced_here = matches!(body, types::Body::Bytes(_) | types::Body::Stream);
        let (body, out) = self
            .body_from_guest(body, Produced::Response)
            .map_err(|e| self.fail(e))?;
        // A body the guest produces has its end held until the handler
        // returns, so it cannot promise a length: framed by length, a whole
        // body would reach the client complete before a trap after it could
        // cut it. A body passed through keeps the length its origin gave.
        let body = if produced_here {
            Body::wrap_native(body, u64::MAX, None)
        } else {
            body
        };
        let mut resp = http::Response::new(body);
        *resp.status_mut() = status;
        *resp.headers_mut() = headers;
        // The receiver is gone only once the exchange has failed or been
        // cancelled; an answer to a failed exchange is discarded.
        let _ = answer.send(resp);
        Ok(out)
    }
}

// Every import is bound `async` (one bindgen default); some need no await.
#[allow(clippy::unused_async_trait_impl)]
impl endpoints::Host for StoreState {
    async fn call(
        &mut self,
        name: String,
        head: types::RequestHead,
        body: types::Body,
    ) -> wasmtime::Result<Call> {
        self.require(Capability::Endpoints, "endpoints.call")?;
        let ex = self.exchange("endpoints.call")?;
        let host = ex.host.clone();
        let shared = ex.shared.clone();

        let (method, uri, headers) = match head::request_from_guest(head, None) {
            Ok(parsed) => parsed,
            Err(HeadError::InvalidPath(_)) => {
                self.discard_body(body);
                return Ok(Err(types::Error::RequestUriInvalid));
            }
            Err(e) => return Err(self.fail(head_error(e, Produced::Endpoint))),
        };
        let (body, out) = self
            .body_from_guest(body, Produced::Endpoint)
            .map_err(|e| self.fail(e))?;
        let mut request = http::Request::new(FromGuest::endpoint_request(body, shared));
        *request.method_mut() = method;
        *request.uri_mut() = uri;
        *request.headers_mut() = headers;

        let fut = wasmtime_wasi::runtime::spawn(async move {
            match host.endpoint_call(&name, request).await {
                Ok(resp) => Ok(resp),
                Err(EndpointError::NotFound) => Err(types::Error::DestinationNotFound),
                Err(EndpointError::Denied) => Err(types::Error::DestinationDenied),
                Err(EndpointError::PathRefused(_)) => Err(types::Error::RequestUriInvalid),
                Err(EndpointError::Timeout) => Err(types::Error::Timeout),
                Err(e @ EndpointError::Failed(_)) => Err(internal(&e.to_string())),
            }
        });
        let pending = self.table.push(PendingResponse::new(fut))?;
        Ok(Ok((pending, out)))
    }
}

// Every import is bound `async` (one bindgen default); some need no await.
#[allow(clippy::unused_async_trait_impl)]
impl flow::Host for StoreState {
    async fn current(&mut self) -> wasmtime::Result<flow::FlowInfo> {
        let info = self.exchange("flow.current")?.host.flow_info();
        Ok(flow::FlowInfo {
            flow_id: info.flow_id,
            conn_id: info.conn_id,
            principal: flow::Principal {
                client_ip: info.principal.client_ip.to_string(),
                listener: info.principal.listener,
                tls_sni: info.principal.tls_sni,
            },
            tags: info.tags,
        })
    }

    async fn add_tag(&mut self, tag: String) -> wasmtime::Result<()> {
        self.exchange("flow.add-tag")?
            .host
            .add_tag(tag)
            .map_err(|e| match e {
                TagError::Full => self.fail(LayerError::BudgetExceeded(Budget::Tags)),
                TagError::Host(e) => self.host_failed(e),
            })
    }

    async fn config(&mut self) -> wasmtime::Result<String> {
        Ok(self.layer.config.config_json.clone())
    }

    async fn log(&mut self, level: flow::LogLevel, msg: String) -> wasmtime::Result<()> {
        self.require(Capability::Log, "flow.log")?;
        self.check_message(msg.len())?;
        let level = match level {
            flow::LogLevel::Trace => LogLevel::Trace,
            flow::LogLevel::Debug => LogLevel::Debug,
            flow::LogLevel::Info => LogLevel::Info,
            flow::LogLevel::Warn => LogLevel::Warn,
            flow::LogLevel::Error => LogLevel::Error,
        };
        if let Some(ex) = &self.exchange {
            ex.host.log(level, &msg);
            return Ok(());
        }
        // During `init` there is no flow; log directly.
        let layer = &self.layer.config.name;
        match level {
            LogLevel::Trace => tracing::trace!(layer, "{msg}"),
            LogLevel::Debug => tracing::debug!(layer, "{msg}"),
            LogLevel::Info => tracing::info!(layer, "{msg}"),
            LogLevel::Warn => tracing::warn!(layer, "{msg}"),
            LogLevel::Error => tracing::error!(layer, "{msg}"),
        }
        Ok(())
    }

    async fn record(&mut self, kind: String, json: String) -> wasmtime::Result<()> {
        self.require(Capability::Record, "flow.record")?;
        self.check_message(kind.len().saturating_add(json.len()))?;
        let host = self.host("flow.record")?;
        host.record(kind, json)
            .await
            .map_err(|e| self.host_failed(e))
    }

    async fn state_get(&mut self, key: String) -> wasmtime::Result<Option<String>> {
        self.require(Capability::State, "flow.state-get")?;
        let host = self.host("flow.state-get")?;
        host.state_get(key).await.map_err(|e| self.host_failed(e))
    }

    async fn state_put(
        &mut self,
        key: String,
        json: String,
        ttl_ms: Option<u64>,
    ) -> wasmtime::Result<Result<(), String>> {
        self.require(Capability::State, "flow.state-put")?;
        let host = self.host("flow.state-put")?;
        host.state_put(key, json, ttl_ms)
            .await
            .map_err(|e| self.host_failed(e))
    }

    async fn metric_get(&mut self, id: String, key: Vec<String>) -> wasmtime::Result<Option<i64>> {
        self.require(Capability::Metrics, "flow.metric-get")?;
        let host = self.host("flow.metric-get")?;
        host.metric_get(id, key)
            .await
            .map_err(|e| self.host_failed(e))
    }
}
