//! The addon layer stack.
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

mod decode;
mod endpoint;
mod host;
mod select;
pub mod service;
pub(crate) mod store;
mod tee;
mod ws;

pub use service::{ServiceError, ServiceSpec};
pub(crate) use ws::{SplicedClient, splice_client, ws_without_extensions};

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderName, StatusCode};
use http_body::{Body as HttpBody, Frame, SizeHint};
use roxy_http::layer::{from_layer_request, to_layer_request, to_layer_response};
use roxy_http::upstream::from_upstream_response;
use roxy_http::{Body, BodyError, BodySender, CanonicalRequest, RequestMeta};
use roxy_wasm::{HostError, LayerError, LayerOutcome, LayerRequest, LayerResponse};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::addr::PrivateAddrs;
use crate::body::{Collected, collect_prefix};
use crate::exchange::{Front, Outcome, bad_upgrade_refusal, refusal_response};
use crate::flowlog::{DecisionKind, FlowEvent, FlowSink};
use crate::pipeline::{BodyIo, CollectFuture, Decider, FlowCx, FlowMeta, Refusal, RefusalKind};
use crate::view::FlowFacts;

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// How an addon runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddonMode {
    /// In the path; failures fail the flow closed.
    Enforce,
    /// Gets copies of both streams, cannot change or delay traffic,
    /// failures are logged only.
    Observe,
}

impl AddonMode {
    /// `enforce` or `observe`, as the flow log and the service protocol
    /// write it.
    pub fn as_str(self) -> &'static str {
        match self {
            AddonMode::Enforce => "enforce",
            AddonMode::Observe => "observe",
        }
    }
}

/// One configured addon, ready to run.
pub struct AddonSpec {
    /// `addons[].name`.
    pub name: String,
    /// `mode`.
    pub mode: AddonMode,
    /// What runs the layer.
    pub kind: AddonImpl,
    /// Named endpoints, by name.
    pub endpoints: HashMap<String, EndpointSpec>,
    /// The addon's keyed store.
    pub state: StateLimits,
    /// Endpoint that also receives `record(.., audit: true)` events.
    pub audit_endpoint: Option<String>,
    /// `when`: the layer runs only on requests this matches, as they reach
    /// it; the others go straight to the layer below.
    pub when: Option<roxy_rules::Condition>,
    /// `sample` (observe mode only): the share of matching exchanges the
    /// layer gets a copy of.
    pub sample: Option<f64>,
}

/// What runs a layer.
#[derive(Clone)]
pub enum AddonImpl {
    /// A compiled WASM component and its instance pool.
    Wasm(roxy_wasm::Layer),
    /// An external service the exchange streams through.
    Service(ServiceSpec),
}

/// Why a layer failed.
#[derive(Debug, Clone)]
pub(crate) enum StackError {
    Layer(LayerError),
    Service(ServiceError),
    /// The layer's `when` reached an unavailable input. `code` is the
    /// rules' fail-closed code.
    Condition {
        code: &'static str,
        reason: String,
    },
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
            StackError::Condition { reason, .. } => {
                write!(f, "`when` could not be evaluated: {reason}")
            }
        }
    }
}

impl std::fmt::Debug for AddonSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AddonSpec")
            .field("name", &self.name)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

/// A named endpoint.
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
    /// Whether the endpoint may be on a private address.
    pub private: PrivateAddrs,
}

/// An addon's keyed store limits.
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

/// How far one layer of an exchange got with `next`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum NextState {
    /// The exchange never reached this layer.
    Unentered,
    /// Entered; `next` not called.
    Entered,
    /// `next` called; no response yet.
    Pending,
    /// `next` returned the response from below.
    Resolved,
    /// `next` failed.
    Failed,
    /// The layer dropped `next` before it returned.
    Abandoned,
}

impl NextState {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Entered,
            2 => Self::Pending,
            3 => Self::Resolved,
            4 => Self::Failed,
            5 => Self::Abandoned,
            _ => Self::Unentered,
        }
    }
}

/// One layer's part in an exchange.
#[derive(Default)]
struct LayerSlot {
    next: AtomicU8,
    /// The layer ran on this exchange: its `when` and `sample` let it.
    ran: AtomicBool,
    /// The layer's own outcome, once its handler returned a response: a
    /// failure after the head shows here first.
    outcome: Mutex<Option<LayerOutcome>>,
}

impl LayerSlot {
    fn state(&self) -> NextState {
        NextState::from_u8(self.next.load(Ordering::SeqCst))
    }

    fn set(&self, s: NextState) {
        self.next.store(s as u8, Ordering::SeqCst);
    }
}

/// Marks a layer's `next` pending, and settles it when `next` returns or
/// is dropped unfinished.
struct NextGuard {
    st: Arc<StackFlow>,
    index: usize,
    settled: bool,
}

impl NextGuard {
    fn new(st: Arc<StackFlow>, index: usize) -> Self {
        st.layers[index].set(NextState::Pending);
        Self {
            st,
            index,
            settled: false,
        }
    }

    fn settle(mut self, ok: bool) {
        self.settled = true;
        let s = if ok {
            NextState::Resolved
        } else {
            NextState::Failed
        };
        self.st.layers[self.index].set(s);
    }
}

impl Drop for NextGuard {
    fn drop(&mut self) {
        if !self.settled {
            self.st.layers[self.index].set(NextState::Abandoned);
        }
    }
}

/// The flow's one [`FlowCx`], lent to the core for as long as it runs. It
/// goes back to the stack however the core ends, dropped mid-flight
/// included, so nothing the core recorded is lost.
struct Lease {
    st: Arc<StackFlow>,
    cx: Option<FlowCx>,
    /// The core ran to its outcome.
    done: bool,
}

impl Lease {
    fn cx(&mut self) -> &mut FlowCx {
        self.cx.as_mut().expect("leased until dropped")
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        let Some(mut cx) = self.cx.take() else {
            return;
        };
        if !self.done && cx.record.decision.is_some() {
            // The rules had decided and the request was on its way.
            cx.record
                .reason
                .get_or_insert_with(|| "upstream_aborted".to_owned());
        }
        *self.st.cx.lock().unwrap_or_else(PoisonError::into_inner) = Some(cx);
        self.st.returned.notify_one();
    }
}

/// One exchange's trip through the stack, shared by every layer's host.
/// It holds the flow's [`FlowCx`] while the layers run, lends it to the
/// core, and hands it back to the front afterwards.
pub(crate) struct StackFlow {
    /// What identifies the flow, shared with its [`FlowCx`].
    pub(crate) meta: Arc<FlowMeta>,
    /// The flow's facts as of the latest request to leave the stack (the
    /// client's until then), for `metric-get`: the same keys the core's
    /// samples use.
    facts: Mutex<FlowFacts>,
    /// The client's request as the fronts described it, which what a
    /// layer passes on inherits: a layer cannot express the protocol
    /// version, the target form or an upgrade.
    client_meta: RequestMeta,
    tags: Mutex<Vec<String>>,
    /// The flow context, while it is not with the front or the core.
    cx: Mutex<Option<FlowCx>>,
    /// The core gave the flow context back.
    returned: Notify,
    /// The response left without the core's: stop the core.
    abandon: CancellationToken,
    layers: Box<[LayerSlot]>,
    /// The first layer failure (it decides the outcome and attribution).
    failure: Mutex<Option<(String, StackError)>>,
    /// The request body failed in the core, as a client's would (framing,
    /// a cut): no layer's doing, so no layer is blamed for it.
    client_fault: Mutex<Option<roxy_http::DriveError>>,
    /// The enforce-mode failure has been logged.
    reported: AtomicBool,
    /// A layer asked to close the client connection.
    pub(crate) close: AtomicBool,
    /// The first layer to run has decoded the request for the layers.
    request_decoded: AtomicBool,
    /// What the core relayed, when it answered a `101`: taken by the
    /// stack's outcome.
    relay: Mutex<Option<ws::Relay>>,
    /// An upgraded exchange's client side, for the front to splice in
    /// once it has sent the `101`.
    ws: Mutex<Option<ws::WsPlumbing>>,
}

impl std::ops::Deref for StackFlow {
    type Target = FlowMeta;

    fn deref(&self) -> &FlowMeta {
        &self.meta
    }
}

impl StackFlow {
    fn new(cx: &FlowCx, req: &CanonicalRequest) -> Self {
        Self {
            meta: cx.meta.clone(),
            facts: Mutex::new(cx.facts.clone()),
            client_meta: req.meta.clone(),
            tags: Mutex::new(Vec::new()),
            cx: Mutex::new(None),
            returned: Notify::new(),
            abandon: CancellationToken::new(),
            layers: cx
                .snap
                .addons
                .iter()
                .map(|_| LayerSlot::default())
                .collect(),
            failure: Mutex::new(None),
            client_fault: Mutex::new(None),
            reported: AtomicBool::new(false),
            close: AtomicBool::new(false),
            request_decoded: AtomicBool::new(false),
            relay: Mutex::new(None),
            ws: Mutex::new(None),
        }
    }

    /// The facts `metric-get` reads.
    pub(crate) fn facts(&self) -> FlowFacts {
        self.facts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn set_facts(&self, facts: &FlowFacts) {
        facts.clone_into(&mut self.facts.lock().unwrap_or_else(PoisonError::into_inner));
    }

    /// Parks the flow context for the core to borrow.
    fn park(&self, cx: FlowCx) {
        *self.cx.lock().unwrap_or_else(PoisonError::into_inner) = Some(cx);
    }

    /// Lends the flow context to the core. `None` if it is already lent
    /// (the core runs at most once per exchange).
    fn lease(self: &Arc<Self>) -> Option<Lease> {
        let cx = self
            .cx
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()?;
        Some(Lease {
            st: self.clone(),
            cx: Some(cx),
            done: false,
        })
    }

    /// Takes the flow context back once the stack has answered. A core
    /// still running was abandoned by the layer that answered: it is
    /// stopped, and its record comes back with it.
    async fn reclaim(&self) -> FlowCx {
        loop {
            if let Some(cx) = self
                .cx
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
            {
                return cx;
            }
            self.abandon.cancel();
            self.returned.notified().await;
        }
    }

    pub(crate) fn tags(&self) -> Vec<String> {
        self.tags
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Some layer ran on the flow (its `when` and `sample` let it).
    fn any_ran(&self) -> bool {
        self.layers.iter().any(|l| l.ran.load(Ordering::SeqCst))
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

    fn take_client_fault(&self) -> Option<roxy_http::DriveError> {
        lock(&self.client_fault).take()
    }

    /// The layer failure behind a body cut after the head: the innermost
    /// layer whose own outcome failed (an outer layer that reads a cut body
    /// fails in turn), else the first recorded failure.
    fn post_head_failure(&self) -> Option<(String, StackError)> {
        self.layers
            .iter()
            .enumerate()
            .rev()
            .find_map(|(i, l)| {
                let failure = l
                    .outcome
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .as_ref()
                    .and_then(LayerOutcome::failure)?;
                Some((self.snap.addons[i].name.clone(), failure.into()))
            })
            .or_else(|| self.failure())
    }

    /// The client asked to upgrade (a WebSocket).
    fn is_upgrade(&self) -> bool {
        self.client_meta.upgrade.is_some()
    }

    fn take_ws(&self) -> Option<ws::WsPlumbing> {
        lock(&self.ws).take()
    }

    /// The layer that answered: the outermost one whose `next` did not
    /// return the response from below (never called, still pending,
    /// failed or dropped). `None` when every layer entered passed on what
    /// came from below, so the response is the core's.
    fn answered_by(&self) -> Option<usize> {
        self.layers.iter().position(|l| {
            matches!(
                l.state(),
                NextState::Entered | NextState::Pending | NextState::Failed | NextState::Abandoned
            )
        })
    }

    /// Folds the stack into the flow record just before its `request`
    /// event: the layers and the tags they added.
    pub(crate) fn fold_into(&self, cx: &mut FlowCx) {
        cx.record.addons = self
            .snap
            .addons
            .iter()
            .zip(&self.layers)
            .filter(|(_, l)| l.ran.load(Ordering::SeqCst))
            .map(|(a, _)| a.name.clone())
            .collect();
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
        StackError::Condition { code, .. } => return format!("when:{code}"),
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
    }
}

pub(crate) fn emit_layer_error(st: &StackFlow, layer: &str, e: &LayerError, mode: AddonMode) {
    emit_stack_error(st, layer, &StackError::Layer(e.clone()), mode);
}

/// Logs a layer failure: once per exchange in enforce mode (the first
/// failure decides the outcome), every time in observe mode.
pub(crate) fn emit_stack_error(st: &StackFlow, layer: &str, e: &StackError, mode: AddonMode) {
    if matches!(e, StackError::Layer(LayerError::Cancelled)) {
        // The client went away; nothing failed.
        return;
    }
    if mode == AddonMode::Enforce && st.reported.swap(true, Ordering::Relaxed) {
        return;
    }
    tracing::info!(flow = %st.flow, layer, error = %e, mode = mode.as_str(), "layer failed");
    st.shared.sink.emit(&FlowEvent::LayerError {
        ts: chrono::Utc::now(),
        flow: st.flow.to_string(),
        conn: st.client.id.to_string(),
        layer: layer.to_owned(),
        mode: mode.as_str().to_owned(),
        kind: error_kind(e),
        message: st.snap.redactor.redact_str(&e.to_string()).into_owned(),
    });
}

/// 503 `layer:<name>`, `layer_error`; closes.
fn layer_refusal(layer: &str) -> Refusal {
    Refusal {
        kind: RefusalKind::Deny,
        status: StatusCode::SERVICE_UNAVAILABLE,
        message: "request blocked: an addon failed".to_owned(),
        rule: Some(Decider::Layer(layer.to_owned())),
        close: true,
        reason: Some("layer_error".to_owned()),
    }
}

/// Runs the exchange through the addon stack. The flow context is parked
/// in the stack while the layers run, lent to the core if a request
/// reaches it, and comes back with the outcome.
pub(crate) async fn run<F: Front>(
    front: &mut F,
    cx: FlowCx,
    mut req: CanonicalRequest,
) -> (FlowCx, Outcome) {
    let st = Arc::new(StackFlow::new(&cx, &req));
    // A WebSocket is a long-lived exchange: once upgraded, the client's
    // bytes are the request body and the upstream's the response body.
    let client_tx = if st.is_upgrade() {
        // The swap below would hide a body from `validate_upgrade_request`.
        if req.body.known_length() != Some(0) {
            let refusal = bad_upgrade_refusal(roxy_http::Reason::WsBadHandshake);
            return (cx, Outcome::Refuse(refusal));
        }
        let (tx, body) = Body::channel(u64::MAX, None);
        req.body = body;
        Some(tx)
    } else {
        None
    };
    st.park(cx);
    let driven = front
        .drive(enter(st.clone(), 0, to_layer_request(req)))
        .await;
    let mut cx = st.reclaim().await;
    cx.stack = Some(st.clone());
    let outcome = stack_outcome(&st, &mut cx, driven, client_tx);
    (cx, outcome)
}

/// What the stack's answer means for the client. `client_tx` feeds the
/// client's bytes into the stack after a `101`.
fn stack_outcome(
    st: &Arc<StackFlow>,
    cx: &mut FlowCx,
    driven: Result<Result<LayerResponse, HostError>, roxy_http::DriveError>,
    client_tx: Option<BodySender>,
) -> Outcome {
    let resp = match driven {
        Err(e) => return Outcome::Close(e),
        // A layer's failure explains the exchange first; a request body
        // that failed in the core with no layer at fault closes the
        // connection as it would without a stack.
        Ok(Err(_)) => {
            let (layer, err) = match (st.failure(), st.take_client_fault()) {
                (Some(f), _) => f,
                (None, Some(e)) => return Outcome::Close(e),
                (None, None) => (
                    st.snap.addons[0].name.clone(),
                    LayerError::NoResponse.into(),
                ),
            };
            emit_stack_error(st, &layer, &err, AddonMode::Enforce);
            return Outcome::Refuse(layer_refusal(&layer));
        }
        Ok(Ok(r)) => r,
    };
    if let Some(i) = st.answered_by() {
        cx.record.decision = Some(DecisionKind::Answered);
        cx.record.terminal_rule = Some(Decider::Layer(st.snap.addons[i].name.clone()));
    }
    // A failure after the head cuts the body (the codec then breaks the
    // connection); log which layer failed once it is known.
    if let Some(outcome) = resp.extensions().get::<LayerOutcome>().cloned() {
        let st2 = st.clone();
        tokio::spawn(async move {
            if let Err(e) = outcome.wait().await {
                let (layer, err) = st2
                    .post_head_failure()
                    .unwrap_or_else(|| (st2.snap.addons[0].name.clone(), e.into()));
                emit_stack_error(&st2, &layer, &err, AddonMode::Enforce);
            }
        });
    }
    let mut resp = resp;
    // A `101`'s body is the upgraded stream for the client, not an HTTP
    // body: keep it out of the response model.
    let upgraded_body = (resp.status() == http::StatusCode::SWITCHING_PROTOCOLS)
        .then(|| std::mem::take(resp.body_mut()));
    let mut res = from_upstream_response(resp, &cx.snap.limits);
    res.body = gated(std::mem::take(&mut res.body), cx.shared.sink.clone());
    if st.close.load(Ordering::Relaxed) {
        res.meta.close = true;
    }
    if res.status == http::StatusCode::SWITCHING_PROTOCOLS {
        if let (Some(relay), Some(client_tx)) = (lock(&st.relay).take(), client_tx) {
            // A layer cannot express `upgrade: websocket` (hop-by-hop); the
            // core relayed a real upgrade, so restore it.
            res.meta.upgrade = Some("websocket".to_owned());
            let to_client = upgraded_body.unwrap_or_default();
            *lock(&st.ws) = Some(ws::WsPlumbing::new(client_tx, to_client, relay.bottom));
            return Outcome::Upgrade {
                res,
                upstream: relay.upstream,
                key: relay.key,
            };
        }
        let layer = st.snap.addons[0].name.clone();
        let err = LayerError::InvalidResponse("101 without an upgrade to relay".into());
        emit_layer_error(st, &layer, &err, AddonMode::Enforce);
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
        let addon = st.snap.addons[index].clone();
        let req = match select::selects(&st, index, &addon, req) {
            Ok((true, req)) => req,
            // Skipped: as if the layer passed both directions on unchanged.
            Ok((false, req)) => return below(st, index, req).await,
            Err(e) => {
                st.fail(&addon.name, e);
                return Err(HostError::new(format!("layer {} failed", addon.name)));
            }
        };
        st.layers[index].ran.store(true, Ordering::SeqCst);
        st.layers[index].set(NextState::Entered);
        let mut req = req;
        // Layers see bodies decoded; a flow no layer runs on is left as
        // the client sent it.
        if st.snap.http.decode_for_addons && !st.request_decoded.swap(true, Ordering::SeqCst) {
            decode::request(&mut req, st.snap.limits.max_request_body_bytes);
        }
        if addon.mode == AddonMode::Observe {
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
            Ok(r) => {
                *st.layers[index]
                    .outcome
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner) =
                    r.extensions().get::<LayerOutcome>().cloned();
                Ok(r)
            }
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
    let guard = NextGuard::new(st.clone(), index);
    let fut = if index + 1 < st.snap.addons.len() {
        enter(st, index + 1, req)
    } else {
        Box::pin(core(st, index, req))
    };
    Box::pin(async move {
        let r = fut.await;
        guard.settle(r.is_ok());
        r
    })
}

/// The client-side view the core needs when the "client" is the last
/// layer: its body is a stream from the guest, with no codec to service.
struct Detached;

impl BodyIo for Detached {
    fn collect<'a>(
        &'a mut self,
        body: &'a mut Body,
        cap: u64,
    ) -> CollectFuture<'a, Result<Collected, roxy_http::DriveError>> {
        Box::pin(async move { Ok(collect_prefix(body, cap).await) })
    }
}

impl Front for Detached {
    #[allow(clippy::manual_async_fn)] // the trait spells out the `Send` bound
    fn drive<Fut>(
        &mut self,
        fut: Fut,
    ) -> impl Future<Output = Result<Fut::Output, roxy_http::DriveError>> + Send
    where
        Fut: Future + Send,
        Fut::Output: Send,
    {
        async move { Ok(fut.await) }
    }
}

/// The exchange core on what the last layer (`index`) passed on, with the
/// flow's own [`FlowCx`]: what the rules judge is the request that left
/// the stack.
async fn core(
    st: Arc<StackFlow>,
    index: usize,
    req: LayerRequest,
) -> Result<LayerResponse, HostError> {
    let snap = st.snap.clone();
    let layer = snap.addons[index].name.clone();
    let (req, stream) = ws::split_upgrade_stream(&st, req);
    let creq = match from_layer_request(req, st.client_meta.clone(), &snap.limits, &snap.flags) {
        Ok(r) => r,
        Err(e) => {
            st.fail(&layer, LayerError::InvalidRequest(e.to_string()));
            return Err(HostError::new(format!("invalid request: {e}")));
        }
    };
    let Some(mut lease) = st.lease() else {
        st.fail(&layer, LayerError::NextCalledTwice);
        return Err(HostError::new("the flow already reached the core"));
    };
    let cx = lease.cx();
    cx.layer_ran = st.any_ran();
    cx.facts.request = Some(crate::pipeline::request_facts(&creq));
    st.set_facts(&cx.facts);
    let mut front = Detached;
    let outcome = tokio::select! {
        biased;
        () = st.abandon.cancelled() => None,
        o = crate::exchange::core(&mut front, cx, creq) => Some(o),
    };
    let Some(outcome) = outcome else {
        // The lease records the abandonment as it goes back.
        return Err(HostError::new(
            "the layer answered without the upstream's response",
        ));
    };
    lease.done = true;
    let cx = lease.cx();
    st.set_facts(&cx.facts);
    match outcome {
        Outcome::Respond(mut res) => {
            // A flow no layer ran on gets the response as the origin sent
            // it.
            if snap.http.decode_for_addons && st.any_ran() {
                decode::response(&mut res, snap.limits.max_response_body_bytes);
            }
            Ok(to_layer_response(res))
        }
        Outcome::Refuse(refusal) => {
            if refusal.close {
                st.close.store(true, Ordering::Relaxed);
            }
            if cx.watch.is_some() {
                cx.record_refusal_sample(&refusal);
            }
            Ok(to_layer_response(refusal_response(cx, &refusal)))
        }
        Outcome::Close(e) => {
            let msg = format!("request body failed: {e}");
            *lock(&st.client_fault) = Some(e);
            Err(HostError::new(msg))
        }
        Outcome::Upgrade {
            mut res,
            upstream,
            key,
        } => {
            let relay = ws::Relay::new(upstream, key, stream.unwrap_or_default(), &mut res);
            *lock(&st.relay) = Some(relay);
            Ok(to_layer_response(res))
        }
    }
}

/// A layer's response body to the client, sent only while the flow log
/// keeps up (audit backpressure).
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

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A flow through `kit`'s current snapshot, for tests that drive the
/// stack's parts directly: a `GET http://up.test/` from a client on the
/// proxy port.
#[cfg(test)]
pub(crate) fn test_flow(kit: &crate::testkit::Kit) -> (Arc<StackFlow>, FlowCx) {
    use crate::listener::{ClientConn, ListenerInfo, ListenerMode};
    use ulid::Ulid;
    let shared = kit.server.shared().clone();
    let snap = shared.snapshot();
    let req = http::Request::get("http://up.test/")
        .body(Body::empty())
        .unwrap();
    let meta = RequestMeta::new(roxy_http::Version::H1_1, roxy_http::TargetForm::Absolute);
    let creq = from_layer_request(req, meta, &snap.limits, &snap.flags).unwrap();
    let client = ClientConn {
        id: Ulid::generate(),
        listener: Arc::new(ListenerInfo {
            name: "main".to_owned(),
            mode: ListenerMode::Explicit,
            auth_required: false,
        }),
        peer: "192.0.2.7:40000".parse().unwrap(),
        user: None,
        original_dst: None,
    };
    let cx = FlowCx::new(shared, snap, client, None, &creq);
    let st = Arc::new(StackFlow::new(&cx, &creq));
    (st, cx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{AddonDef, Kit};

    /// A request body that failed in the core closes the connection as a
    /// client's fault, unless a layer's own failure explains the exchange.
    #[tokio::test]
    async fn a_body_failure_in_the_core_is_the_clients_unless_a_layer_failed() {
        let kit = Kit::builder()
            .addon(AddonDef::test_layer("a"))
            .start()
            .await;
        let (st, mut cx) = test_flow(&kit);
        let fault = || roxy_http::ParseError::new(roxy_http::Reason::BadChunkSize, "zz");
        let failed = || Ok(Err(HostError::new("request body failed")));

        *lock(&st.client_fault) = Some(fault().into());
        let out = stack_outcome(&st, &mut cx, failed(), None);
        assert!(
            matches!(&out, Outcome::Close(roxy_http::DriveError::Client(e)) if e.reason == roxy_http::Reason::BadChunkSize),
            "closes as a parse error"
        );
        assert!(st.failure().is_none(), "no layer is blamed");

        *lock(&st.client_fault) = Some(fault().into());
        st.fail("a", LayerError::Trap("boom".into()));
        let out = stack_outcome(&st, &mut cx, failed(), None);
        assert!(
            matches!(&out, Outcome::Refuse(r) if r.rule == Some(Decider::Layer("a".into()))),
            "the layer's failure comes first"
        );
    }
}
