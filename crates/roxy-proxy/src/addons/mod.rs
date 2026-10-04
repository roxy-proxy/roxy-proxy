//! The addon layer stack (docs/addons.md#layer-stack).
//!
//! ```text
//!   front ─▶ addon 0 ─▶ … ─▶ addon n-1 ─▶ core (rules ↓ / ↑, address floor, connector)
//! ```
//!
//! The front (h1 codec or h2 stream) drives the client's request body into
//! the first layer. Each layer's `next` enters the layer below; the last
//! one's `next` runs the ordinary exchange core on whatever the layer passed
//! on, after re-validating it exactly as strictly as a client request
//! (invariant 1). On the way back the rules see the upstream's response
//! before any layer does. Any layer failure fails the exchange closed
//! (invariant 3): a deny before the response head, a cut body after it.

mod endpoint;
mod host;
pub mod service;
pub(crate) mod store;
mod tee;

pub use service::{ServiceError, ServiceSpec};

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::Bytes;
use http::HeaderName;
use http_body::{Body as HttpBody, Frame, SizeHint};
use roxy_http::layer::{from_layer_request, to_layer_request, to_layer_response};
use roxy_http::upstream::from_upstream_response;
use roxy_http::ws::WsKey;
use roxy_http::{Body, BodyError, CanonicalRequest, Headers, coding};
use roxy_wasm::{HostError, LayerError, LayerOutcome, LayerRequest, LayerResponse};
use ulid::Ulid;

use crate::body::{Collected, collect_prefix};
use crate::exchange::{Front, Outcome, refusal_response};
use crate::flowlog::{DecisionKind, FlowEvent, FlowSink, TlsInfo};
use crate::listener::ClientConn;
use crate::pipeline::{BodyIo, CollectFuture, FlowCx, Refusal, RefusalKind};
use crate::server::{Shared, Snapshot};
use crate::view::FlowFacts;

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// One configured addon, ready to run (docs/addons.md#configuration).
pub struct AddonSpec {
    /// `addons[].name`.
    pub name: String,
    /// `mode: observe`: gets copies of both streams, cannot change or delay
    /// traffic, failures are logged only.
    pub observe: bool,
    /// What runs the layer.
    pub kind: AddonImpl,
    /// Named endpoints, by name.
    pub endpoints: HashMap<String, EndpointSpec>,
    /// The addon's keyed store.
    pub state: StateLimits,
    /// Endpoint that also receives `record(.., audit: true)` events.
    pub audit_endpoint: Option<String>,
}

/// What runs a layer.
#[derive(Clone)]
pub enum AddonImpl {
    /// A compiled WASM component and its instance pool (docs/addons.md#instances).
    Wasm(roxy_wasm::Layer),
    /// An external service the exchange streams through (docs/addons.md#service-layers).
    Service(ServiceSpec),
}

impl AddonSpec {
    /// The WASM layer, if this addon is one.
    pub(crate) fn wasm(&self) -> Option<&roxy_wasm::Layer> {
        match &self.kind {
            AddonImpl::Wasm(l) => Some(l),
            AddonImpl::Service(_) => None,
        }
    }
}

/// Why a layer failed.
#[derive(Debug, Clone)]
pub(crate) enum StackError {
    Layer(LayerError),
    Service(ServiceError),
}

impl From<LayerError> for StackError {
    fn from(e: LayerError) -> Self {
        StackError::Layer(e)
    }
}

impl std::fmt::Display for StackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StackError::Layer(e) => e.fmt(f),
            StackError::Service(e) => e.fmt(f),
        }
    }
}

impl std::fmt::Debug for AddonSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AddonSpec")
            .field("name", &self.name)
            .field("observe", &self.observe)
            .finish_non_exhaustive()
    }
}

/// A named endpoint (docs/addons.md#endpoints).
#[derive(Debug, Clone)]
pub struct EndpointSpec {
    /// Base URL; the request's path and query are appended.
    pub url: http::Uri,
    /// Headers roxy attaches; values may contain `${secret:name}`.
    pub headers: Vec<(HeaderName, String)>,
    /// Per attempt, until the response head.
    pub timeout: Duration,
    /// Extra attempts after a connection failure or a 502/503/504.
    pub retries: u32,
    /// Allow private addresses.
    pub private_ok: bool,
}

/// An addon's keyed store limits (docs/addons.md#state).
#[derive(Debug, Clone)]
pub struct StateLimits {
    pub max_entries: usize,
    pub max_value_bytes: usize,
    pub default_ttl: Duration,
}

impl Default for StateLimits {
    fn default() -> Self {
        Self {
            max_entries: 100_000,
            max_value_bytes: 64 * 1024,
            default_ttl: Duration::from_hours(6),
        }
    }
}

/// One exchange's trip through the stack, shared by every layer's host.
pub(crate) struct StackFlow {
    pub(crate) shared: Arc<Shared>,
    pub(crate) snap: Arc<Snapshot>,
    pub(crate) flow: Ulid,
    pub(crate) client: ClientConn,
    pub(crate) tls: Option<TlsInfo>,
    /// The client's request facts (for `metric-get`).
    pub(crate) facts: FlowFacts,
    /// The client asked to upgrade (WebSocket); carried to the core, since
    /// a layer cannot express hop-by-hop fields.
    upgrade_req: Option<String>,
    tags: Mutex<Vec<String>>,
    /// The core's flow context, once the last layer called `next`.
    inner: Mutex<Option<FlowCx>>,
    /// The first layer failure (it decides the outcome and attribution).
    failure: Mutex<Option<(String, StackError)>>,
    /// The enforce-mode failure has been logged.
    reported: AtomicBool,
    /// A layer asked to close the client connection.
    pub(crate) close: AtomicBool,
    /// The upgraded upstream connection, when the core relayed a `101`.
    upgrade: Mutex<Option<(hyper::upgrade::OnUpgrade, WsKey)>>,
    /// One more than the deepest layer entered.
    depth: AtomicUsize,
}

impl StackFlow {
    fn new(cx: &FlowCx, req: &CanonicalRequest) -> Self {
        Self {
            shared: cx.shared.clone(),
            snap: cx.snap.clone(),
            flow: cx.flow,
            client: cx.facts.client.clone(),
            tls: cx.facts.tls.clone(),
            facts: cx.facts.clone(),
            upgrade_req: req.meta.upgrade.clone(),
            tags: Mutex::new(Vec::new()),
            inner: Mutex::new(None),
            failure: Mutex::new(None),
            reported: AtomicBool::new(false),
            close: AtomicBool::new(false),
            upgrade: Mutex::new(None),
            depth: AtomicUsize::new(0),
        }
    }

    pub(crate) fn tags(&self) -> Vec<String> {
        self.tags
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn add_tag(&self, tag: String) {
        let mut t = self.tags.lock().unwrap_or_else(PoisonError::into_inner);
        if !t.contains(&tag) {
            t.push(tag);
        }
    }

    fn fail(&self, layer: &str, err: impl Into<StackError>) {
        let mut f = self.failure.lock().unwrap_or_else(PoisonError::into_inner);
        if f.is_none() {
            *f = Some((layer.to_owned(), err.into()));
        }
    }

    fn failure(&self) -> Option<(String, StackError)> {
        self.failure
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn take_upgrade(&self) -> Option<(hyper::upgrade::OnUpgrade, WsKey)> {
        self.upgrade
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    fn inner_watch(&self) -> Option<Arc<crate::watch::Watch>> {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .and_then(|c| c.watch.clone())
    }

    /// Folds the stack's outcome into the client-side flow record, just
    /// before its `request` event: what the rules decided about the request
    /// that left, the layers, their tags; or, if no request left, that a
    /// layer answered.
    pub(crate) fn merge_into(&self, cx: &mut FlowCx) {
        cx.record.addons = self.snap.addons.iter().map(|a| a.name.clone()).collect();
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        match inner {
            Some(mut icx) => {
                if cx.watch.is_none() {
                    icx.absorb_watch();
                }
                let r = &mut cx.record;
                for rule in icx.record.rules {
                    if !r.rules.contains(&rule) {
                        r.rules.push(rule);
                    }
                }
                for t in icx.record.tags {
                    if !r.tags.contains(&t) {
                        r.tags.push(t);
                    }
                }
                r.mutations.extend(icx.record.mutations);
                if r.decision.is_none() {
                    r.decision = icx.record.decision;
                    r.terminal_rule = icx.record.terminal_rule;
                    r.reason = icx.record.reason;
                    r.stage = icx.record.stage;
                }
                r.request_bytes = icx.record.request_bytes;
                r.ttfb_ms = icx.record.ttfb_ms;
            }
            None => {
                // Nothing left: the deepest layer reached answered itself.
                if cx.record.decision.is_none() {
                    let depth = self.depth.load(Ordering::Relaxed).max(1);
                    let layer = &self.snap.addons[depth - 1].name;
                    cx.record.decision = Some(DecisionKind::Deny);
                    cx.record.terminal_rule = Some(format!("layer:{layer}"));
                }
            }
        }
        for t in self.tags() {
            if !cx.record.tags.contains(&t) {
                cx.record.tags.push(t);
            }
        }
    }
}

/// A stable code for a layer failure, for the flow log.
fn error_kind(e: &StackError) -> String {
    let e = match e {
        StackError::Layer(e) => e,
        StackError::Service(e) => return e.kind().to_owned(),
    };
    match e {
        LayerError::Trap(_) => "trap".into(),
        LayerError::BudgetExceeded(b) => format!("budget:{b}"),
        LayerError::CapabilityDenied { capability, .. } => format!("capability:{capability}"),
        LayerError::NextCalledTwice => "next_twice".into(),
        LayerError::OutsideExchange(_) => "outside_exchange".into(),
        LayerError::InvalidRequest(_) => "invalid_request".into(),
        LayerError::NoResponse => "no_response".into(),
        LayerError::ErrorResponse(_) => "error_response".into(),
        LayerError::InvalidResponse(_) => "invalid_response".into(),
        LayerError::Host(_) => "host".into(),
        LayerError::Init(_) => "init".into(),
        LayerError::Instantiate(_) => "instantiate".into(),
        LayerError::Cancelled => "cancelled".into(),
        _ => "other".into(),
    }
}

pub(crate) fn emit_layer_error(st: &StackFlow, layer: &str, e: &LayerError, observe: bool) {
    emit_stack_error(st, layer, &StackError::Layer(e.clone()), observe);
}

/// Logs a layer failure: once per exchange in enforce mode (the first
/// failure decides the outcome), every time in observe mode.
pub(crate) fn emit_stack_error(st: &StackFlow, layer: &str, e: &StackError, observe: bool) {
    if matches!(e, StackError::Layer(LayerError::Cancelled)) {
        // The client went away; nothing failed.
        return;
    }
    if !observe && st.reported.swap(true, Ordering::Relaxed) {
        return;
    }
    tracing::info!(flow = %st.flow, layer, error = %e, observe, "layer failed");
    st.shared.sink.emit(&FlowEvent::LayerError {
        ts: chrono::Utc::now(),
        flow: st.flow.to_string(),
        conn: st.client.id.to_string(),
        layer: layer.to_owned(),
        mode: if observe { "observe" } else { "enforce" }.to_owned(),
        kind: error_kind(e),
        message: st.snap.redactor.redact_str(&e.to_string()).into_owned(),
    });
}

/// 503 `layer:<name>`, `layer_error`; closes.
fn layer_refusal(layer: &str) -> Refusal {
    Refusal {
        kind: RefusalKind::Deny,
        status: 503,
        message: "request blocked: an addon failed".to_owned(),
        rule: Some(format!("layer:{layer}")),
        close: true,
        reason: Some("layer_error".to_owned()),
    }
}

/// Runs the exchange through the addon stack.
pub(crate) async fn run<F: Front>(
    front: &mut F,
    cx: &mut FlowCx,
    mut req: CanonicalRequest,
) -> Outcome {
    if cx.snap.flags.decode_for_addons {
        let limit = cx.snap.limits.max_request_body_bytes;
        decode_for_layers(&mut req.headers, &mut req.body, limit);
    }
    let st = Arc::new(StackFlow::new(cx, &req));
    cx.stack = Some(st.clone());
    let driven = front
        .drive(enter(st.clone(), 0, to_layer_request(req)))
        .await;
    let resp = match driven {
        Err(e) => return Outcome::Close(e),
        Ok(Err(_)) => {
            let (layer, err) = st.failure().unwrap_or_else(|| {
                (
                    st.snap.addons[0].name.clone(),
                    LayerError::NoResponse.into(),
                )
            });
            emit_stack_error(&st, &layer, &err, false);
            return Outcome::Refuse(layer_refusal(&layer));
        }
        Ok(Ok(r)) => r,
    };
    // A failure after the head cuts the body (the codec then breaks the
    // connection); log which layer failed once it is known.
    if let Some(outcome) = resp.extensions().get::<LayerOutcome>().cloned() {
        let st2 = st.clone();
        tokio::spawn(async move {
            if let Err(e) = outcome.wait().await {
                let (layer, err) = st2
                    .failure()
                    .unwrap_or_else(|| (st2.snap.addons[0].name.clone(), e.into()));
                emit_stack_error(&st2, &layer, &err, false);
            }
        });
    }
    let mut res = from_upstream_response(resp, &cx.snap.limits);
    res.body = gated(std::mem::take(&mut res.body), cx.shared.sink.clone());
    if st.close.load(Ordering::Relaxed) {
        res.meta.close = true;
    }
    if let Some(w) = st.inner_watch() {
        cx.watch = Some(w);
    }
    if res.status == http::StatusCode::SWITCHING_PROTOCOLS {
        if let Some((on, key)) = st.take_upgrade() {
            // A layer cannot express `upgrade: websocket` (hop-by-hop); the
            // core relayed a real upgrade, so restore it.
            res.meta.upgrade = Some("websocket".to_owned());
            return Outcome::Upgrade { res, on, key };
        }
        let layer = st.snap.addons[0].name.clone();
        let err = LayerError::InvalidResponse("101 without an upgraded upstream".into());
        emit_layer_error(&st, &layer, &err, false);
        return Outcome::Refuse(layer_refusal(&layer));
    }
    Outcome::Respond(res)
}

/// Runs layer `index` on `req`.
pub(crate) fn enter(
    st: Arc<StackFlow>,
    index: usize,
    req: LayerRequest,
) -> BoxFuture<Result<LayerResponse, HostError>> {
    Box::pin(async move {
        st.depth.fetch_max(index + 1, Ordering::Relaxed);
        let addon = st.snap.addons[index].clone();
        if addon.observe {
            return tee::observe(st, index, req).await;
        }
        let layer = match &addon.kind {
            AddonImpl::Wasm(l) => l,
            AddonImpl::Service(svc) => return service::handle(st, index, svc, req).await,
        };
        let h = Arc::new(host::StackHost {
            st: st.clone(),
            index,
            observer: None,
        });
        match layer.handle(h, req).await {
            Ok(r) => Ok(r),
            Err(e) => {
                st.fail(&addon.name, e);
                Err(HostError::new(format!("layer {} failed", addon.name)))
            }
        }
    })
}

/// What layer `index`'s `next` reaches: the next layer, or the core.
pub(crate) fn below(
    st: Arc<StackFlow>,
    index: usize,
    req: LayerRequest,
) -> BoxFuture<Result<LayerResponse, HostError>> {
    if index + 1 < st.snap.addons.len() {
        enter(st, index + 1, req)
    } else {
        Box::pin(core(st, index, req))
    }
}

/// The client-side view the core needs when the "client" is the last
/// layer: its body is a stream from the guest, with no codec to service.
struct Detached;

impl BodyIo for Detached {
    fn collect<'a>(
        &'a mut self,
        body: &'a mut Body,
        cap: u64,
    ) -> CollectFuture<'a, Result<Collected, roxy_http::ParseError>> {
        Box::pin(async move { Ok(collect_prefix(body, cap).await) })
    }
}

impl Front for Detached {
    #[allow(clippy::manual_async_fn)] // the trait spells out the `Send` bound
    fn drive<Fut>(
        &mut self,
        fut: Fut,
    ) -> impl Future<Output = Result<Fut::Output, roxy_http::ParseError>> + Send
    where
        Fut: Future + Send,
        Fut::Output: Send,
    {
        async move { Ok(fut.await) }
    }
}

/// The exchange core on what the last layer (`index`) passed on.
async fn core(
    st: Arc<StackFlow>,
    index: usize,
    req: LayerRequest,
) -> Result<LayerResponse, HostError> {
    let snap = st.snap.clone();
    let layer = snap.addons[index].name.clone();
    let mut creq = match from_layer_request(req, &snap.limits, &snap.flags) {
        Ok(r) => r,
        Err(e) => {
            st.fail(&layer, LayerError::InvalidRequest(e.to_string()));
            return Err(HostError::new(format!("invalid request: {e}")));
        }
    };
    creq.meta.upgrade.clone_from(&st.upgrade_req);
    let mut icx = FlowCx::new(
        st.shared.clone(),
        snap.clone(),
        st.client.clone(),
        st.tls.clone(),
        &creq,
    );
    icx.flow = st.flow;
    let outcome = crate::exchange::core(&mut Detached, &mut icx, creq).await;
    let resp = match outcome {
        Outcome::Respond(mut res) => {
            // A range of an encoded body is not decodable on its own.
            if snap.flags.decode_for_addons
                && res.status != http::StatusCode::PARTIAL_CONTENT
                && !res.headers.contains("content-range")
            {
                let limit = snap.limits.max_response_body_bytes;
                decode_for_layers(&mut res.headers, &mut res.body, limit);
            }
            Ok(to_layer_response(res))
        }
        Outcome::Refuse(refusal) => {
            if refusal.close {
                st.close.store(true, Ordering::Relaxed);
            }
            if refusal.kind == RefusalKind::UpstreamError && icx.watch.is_some() {
                icx.record_final_sample(true);
            }
            Ok(to_layer_response(refusal_response(&mut icx, &refusal)))
        }
        Outcome::Close(e) => {
            st.fail(
                &layer,
                LayerError::InvalidRequest(format!("request body: {e}")),
            );
            Err(HostError::new(format!("request body failed: {e}")))
        }
        Outcome::Upgrade { res, on, key } => {
            *st.upgrade.lock().unwrap_or_else(PoisonError::into_inner) = Some((on, key));
            Ok(to_layer_response(res))
        }
    };
    *st.inner.lock().unwrap_or_else(PoisonError::into_inner) = Some(icx);
    resp
}

/// Decodes a body by its `content-encoding` for the layers
/// (docs/addons.md#content-codings), and drops the header. A coding roxy
/// cannot decode is left as it is, header and all, for a layer to judge.
fn decode_for_layers(headers: &mut Headers, body: &mut Body, limit: u64) {
    let Ok(codings) = coding::content_codings(headers) else {
        return;
    };
    if codings.is_empty() {
        return;
    }
    headers.remove("content-encoding");
    *body = coding::decode_body(std::mem::take(body), &codings, limit);
}

/// A layer's response body to the client, sent only while the flow log
/// keeps up (audit backpressure, docs/flow-log.md#writing).
struct Gated {
    inner: Body,
    sink: Arc<dyn FlowSink>,
}

impl HttpBody for Gated {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        ready!(self.sink.poll_ready(cx));
        Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

fn gated(body: Body, sink: Arc<dyn FlowSink>) -> Body {
    let known = body.known_length();
    Body::wrap_native(Gated { inner: body, sink }, u64::MAX, known)
}

/// Inserts the stack's `tunnel` layers (outermost first) between the client
/// and the WebSocket relay (docs/addons.md#layer-stack): each gets the raw byte streams of the
/// upgraded connection. The rules' relay stays the hop next to the
/// upstream, so byte budgets still see what leaves. `leftover` (bytes that
/// arrived with the upgrade request) goes through the layers too, and the
/// returned leftover is then empty. Without a `tunnel` layer, returns its
/// inputs.
type ReadSide = Box<dyn tokio::io::AsyncRead + Send + Unpin>;
type WriteSide = Box<dyn tokio::io::AsyncWrite + Send + Unpin>;

pub(crate) fn chain_tunnels(
    st: &Arc<StackFlow>,
    client: crate::io::BoxIo,
    leftover: Vec<u8>,
) -> (crate::io::BoxIo, Vec<u8>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let tunnels: Vec<usize> = st
        .snap
        .addons
        .iter()
        .enumerate()
        .filter(|(_, a)| !a.observe && a.wasm().is_some_and(roxy_wasm::Layer::has_tunnel))
        .map(|(i, _)| i)
        .collect();
    if tunnels.is_empty() {
        return (client, leftover);
    }
    let (cr, mut cw) = tokio::io::split(client);
    let mut side_r: ReadSide = Box::new(std::io::Cursor::new(leftover).chain(cr));
    // The outermost layer writes to the client through a pipe too: when it
    // drops its writer, the copy ends and shuts the client's side down, so
    // the client sees the close. Dropping a half of the client would not.
    let (to_client, mut from_layers) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        if tokio::io::copy(&mut from_layers, &mut cw).await.is_ok() {
            let _ = cw.shutdown().await;
        }
    });
    let mut side_w: WriteSide = Box::new(to_client);
    for index in tunnels {
        // One pipe per direction, each end held whole: when a side drops
        // its writer, the reader on the far end sees EOF. Halves of one
        // split duplex would not, as the other half keeps it open (#36).
        let (up_w, up_r) = tokio::io::duplex(64 * 1024);
        let (down_w, down_r) = tokio::io::duplex(64 * 1024);
        let addon = st.snap.addons[index].clone();
        let Some(layer) = addon.wasm().cloned() else {
            continue;
        };
        let host = Arc::new(host::StackHost {
            st: st.clone(),
            index,
            observer: None,
        });
        let from_client = std::mem::replace(&mut side_r, Box::new(tokio::io::empty()));
        let to_client = std::mem::replace(&mut side_w, Box::new(tokio::io::sink()));
        let st2 = st.clone();
        tokio::spawn(async move {
            if let Err(e) = layer
                .tunnel(host, from_client, up_w, down_r, to_client)
                .await
            {
                emit_layer_error(&st2, &addon.name, &e, false);
            }
        });
        side_r = Box::new(up_r);
        side_w = Box::new(down_w);
    }
    (Box::new(tokio::io::join(side_r, side_w)), Vec::new())
}
