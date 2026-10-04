//! The data in each instance's `Store`: WASI contexts, the memory limiter,
//! and the implementations of the `roxy:addon` imports.

use std::sync::Arc;

use http::uri::{PathAndQuery, Scheme};
use http::{HeaderMap, Uri};
use http_body_util::BodyExt;
use wasmtime::component::{Resource, ResourceTable};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};
use wasmtime_wasi_http::p2::bindings::http::types::{
    ErrorCode, Method as WasiMethod, Scheme as WasiScheme,
};
use wasmtime_wasi_http::p2::body::HyperIncomingBody;
use wasmtime_wasi_http::p2::types::{HostFutureIncomingResponse, HostOutgoingRequest};
use wasmtime_wasi_http::{
    Error as WasiError, WasiBody, WasiHttpCtx, WasiHttpCtxView, WasiHttpHooks, WasiHttpView,
};

use crate::bindings::roxy::addon::{chain, endpoints, flow};
use crate::config::{Capability, LayerConfig};
use crate::error::{Budget, LayerError};
use crate::exchange::{Dir, ExchangeShared, FromGuest, IntoGuest};
use crate::host::{EndpointError, LayerHost, LogLevel};

/// Most resources (requests, bodies, streams, fields) a guest may hold at
/// once. Each costs host memory outside the guest's `max_memory`.
const MAX_RESOURCES: usize = 4096;
/// Most elements a guest table may grow to.
const MAX_TABLE_ELEMENTS: usize = 100_000;

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
    /// guest builds without them.
    pub(crate) scheme: Scheme,
    pub(crate) authority: String,
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

/// `wasi:http/outgoing-handler` is never linked into a layer, so this is
/// never called; it exists because the hooks trait requires it.
struct NoOutgoing;

impl WasiHttpHooks for NoOutgoing {
    fn send_request(
        &mut self,
        _request: http::Request<WasiBody>,
        _options: Option<wasmtime_wasi_http::RequestOptions>,
        _fut: Box<dyn Future<Output = Result<(), WasiError>> + Send>,
    ) -> Box<
        dyn Future<
                Output = Result<
                    (
                        http::Response<WasiBody>,
                        Box<dyn Future<Output = Result<(), WasiError>> + Send>,
                    ),
                    WasiError,
                >,
            > + Send,
    > {
        Box::new(async { Err(WasiError::HttpRequestDenied) })
    }
}

pub(crate) struct StoreState {
    wasi: WasiCtx,
    http: WasiHttpCtx,
    pub(crate) table: ResourceTable,
    hooks: NoOutgoing,
    pub(crate) layer: Arc<LayerShared>,
    pub(crate) limiter: Limiter,
    pub(crate) exchange: Option<ExchangeCtx>,
}

impl StoreState {
    pub(crate) fn new(layer: Arc<LayerShared>) -> Self {
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
            http: WasiHttpCtx::new(),
            table,
            hooks: NoOutgoing,
            layer,
            limiter: Limiter {
                max_memory,
                total_memory: 0,
            },
            exchange: None,
        }
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

    fn host(&self, import: &'static str) -> wasmtime::Result<Arc<dyn LayerHost>> {
        Ok(self.exchange(import)?.host.clone())
    }

    /// Runs a host-service future, turning a [`crate::HostError`] into a
    /// trap that fails the exchange.
    fn host_failed(&self, err: crate::host::HostError) -> wasmtime::Error {
        let err = LayerError::Host(err);
        if let Some(ex) = &self.exchange {
            ex.shared.fail(err.clone());
        }
        wasmtime::Error::new(err)
    }
}

impl WasiView for StoreState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

impl WasiHttpView for StoreState {
    fn http(&mut self) -> WasiHttpCtxView<'_> {
        WasiHttpCtxView {
            ctx: &mut self.http,
            table: &mut self.table,
            hooks: &mut self.hooks,
        }
    }
}

fn method(m: WasiMethod) -> Result<http::Method, String> {
    m.try_into().map_err(|e| format!("invalid method: {e}"))
}

fn scheme(s: WasiScheme) -> Result<Scheme, String> {
    match s {
        WasiScheme::Http => Ok(Scheme::HTTP),
        WasiScheme::Https => Ok(Scheme::HTTPS),
        WasiScheme::Other(o) => Err(format!("unsupported scheme {o:?}")),
    }
}

/// Takes the head and body of a guest-built request.
fn take_request(
    req: HostOutgoingRequest,
) -> Result<(http::request::Builder, Option<WasiBody>, RequestTarget), String> {
    let method = method(req.method)?;
    let target = RequestTarget {
        scheme: req.scheme.map(scheme).transpose()?,
        authority: req.authority,
        path_with_query: req.path_with_query,
    };
    let headers: HeaderMap = req.headers.into();
    let mut builder = http::Request::builder().method(method);
    if let Some(h) = builder.headers_mut() {
        *h = headers;
    }
    Ok((builder, req.body, target))
}

struct RequestTarget {
    scheme: Option<Scheme>,
    authority: Option<String>,
    path_with_query: Option<String>,
}

impl RequestTarget {
    fn path(&self) -> Result<PathAndQuery, String> {
        match self.path_with_query.as_deref() {
            None | Some("") => Ok(PathAndQuery::from_static("/")),
            Some(p) => p
                .parse::<PathAndQuery>()
                .map_err(|e| format!("invalid path {p:?}: {e}")),
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

fn response_into_guest(
    resp: http::Response<roxy_http::Body>,
) -> (
    http::Response<HyperIncomingBody>,
    wasmtime_wasi::runtime::AbortOnDropJoinHandle<()>,
) {
    let resp = resp.map(|b| IntoGuest::new(b, Dir::Response).boxed_unsync());
    (resp, wasmtime_wasi::runtime::spawn(async {}))
}

// Every import is bound `async` (one bindgen default); some need no await.
#[allow(clippy::unused_async_trait_impl)]
impl chain::Host for StoreState {
    async fn next(
        &mut self,
        req: Resource<HostOutgoingRequest>,
    ) -> wasmtime::Result<Result<Resource<HostFutureIncomingResponse>, ErrorCode>> {
        let ex = self
            .exchange
            .as_mut()
            .ok_or_else(|| wasmtime::Error::new(LayerError::OutsideExchange("chain.next")))?;
        if ex.next_called {
            return Err(wasmtime::Error::new(LayerError::NextCalledTwice));
        }
        ex.next_called = true;
        let host = ex.host.clone();
        let shared = ex.shared.clone();
        let default_scheme = ex.scheme.clone();
        let default_authority = ex.authority.clone();

        let req = self.table.delete(req)?;
        let built = take_request(req).and_then(|(builder, body, target)| {
            let uri = Uri::builder()
                .scheme(target.scheme.clone().unwrap_or(default_scheme))
                .authority(target.authority.clone().unwrap_or(default_authority))
                .path_and_query(target.path()?)
                .build()
                .map_err(|e| format!("invalid URI: {e}"))?;
            let body = match body {
                Some(b) => FromGuest::next_request(b, shared.clone()),
                None => roxy_http::Body::empty(),
            };
            builder
                .uri(uri)
                .body(body)
                .map_err(|e| format!("invalid request: {e}"))
        });
        let request = match built {
            Ok(r) => r,
            Err(msg) => {
                let err = LayerError::InvalidRequest(msg);
                shared.fail(err.clone());
                return Err(wasmtime::Error::new(err));
            }
        };

        let fut = wasmtime_wasi::runtime::spawn(async move {
            let below = Below::enter(shared.clone());
            let resp = host.next(request).await;
            drop(below);
            if shared.check_next().is_err() {
                return Err(WasiError::InternalError(Some("next failed".to_owned())));
            }
            match resp {
                Ok(resp) => Ok(response_into_guest(resp)),
                Err(e) => {
                    shared.fail(LayerError::Host(e));
                    Err(WasiError::InternalError(Some("next failed".to_owned())))
                }
            }
        });
        Ok(Ok(self
            .table
            .push(HostFutureIncomingResponse::Pending(fut))?))
    }
}

// Every import is bound `async` (one bindgen default); some need no await.
#[allow(clippy::unused_async_trait_impl)]
impl endpoints::Host for StoreState {
    async fn call(
        &mut self,
        name: String,
        req: Resource<HostOutgoingRequest>,
    ) -> wasmtime::Result<Result<Resource<HostFutureIncomingResponse>, ErrorCode>> {
        self.require(Capability::Endpoints, "endpoints.call")?;
        let ex = self.exchange("endpoints.call")?;
        let host = ex.host.clone();
        let shared = ex.shared.clone();

        let req = self.table.delete(req)?;
        let built = take_request(req).and_then(|(builder, body, target)| {
            let body = match body {
                Some(b) => FromGuest::endpoint_request(b, shared.clone()),
                None => roxy_http::Body::empty(),
            };
            builder
                .uri(Uri::from(target.path()?))
                .body(body)
                .map_err(|e| format!("invalid request: {e}"))
        });
        let Ok(request) = built else {
            return Ok(Err(ErrorCode::HttpRequestUriInvalid));
        };

        let fut = wasmtime_wasi::runtime::spawn(async move {
            match host.endpoint_call(&name, request).await {
                Ok(resp) => Ok(response_into_guest(resp)),
                Err(EndpointError::NotFound) => Err(WasiError::DestinationNotFound),
                Err(EndpointError::Denied) => Err(WasiError::DestinationIpProhibited),
                Err(EndpointError::Timeout) => Err(WasiError::ConnectionTimeout),
                Err(e) => Err(WasiError::InternalError(Some(e.to_string()))),
            }
        });
        Ok(Ok(self
            .table
            .push(HostFutureIncomingResponse::Pending(fut))?))
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
                client_user: info.principal.client_user,
                listener: info.principal.listener,
                tls_sni: info.principal.tls_sni,
            },
            tags: info.tags,
        })
    }

    async fn add_tag(&mut self, tag: String) -> wasmtime::Result<()> {
        self.exchange("flow.add-tag")?.host.add_tag(tag);
        Ok(())
    }

    async fn config(&mut self) -> wasmtime::Result<String> {
        Ok(self.layer.config.config_json.clone())
    }

    async fn log(&mut self, level: flow::LogLevel, msg: String) -> wasmtime::Result<()> {
        self.require(Capability::Log, "flow.log")?;
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

    async fn record(&mut self, kind: String, json: String, audit: bool) -> wasmtime::Result<()> {
        self.require(Capability::Record, "flow.record")?;
        let host = self.host("flow.record")?;
        host.record(kind, json, audit)
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
