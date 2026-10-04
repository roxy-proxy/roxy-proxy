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

mod endpoint;
mod host;
pub mod service;
pub(crate) mod store;
mod tee;

pub use service::{ServiceError, ServiceSpec};

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
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
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use ulid::Ulid;

use crate::body::{Collected, collect_prefix};
use crate::exchange::{Front, Outcome, refusal_response};
use crate::flowlog::{DecisionKind, FlowEvent, FlowSink, TlsInfo};
use crate::listener::ClientConn;
use crate::pipeline::{BodyIo, CollectFuture, FlowCx, Refusal, RefusalKind};
use crate::server::{Shared, Snapshot};
use crate::view::{FlowFacts, ProxyView};

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// One configured addon, ready to run.
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
            .field("observe", &self.observe)
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
    /// Allow private addresses.
    pub private_ok: bool,
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
    pub(crate) shared: Arc<Shared>,
    pub(crate) snap: Arc<Snapshot>,
    pub(crate) flow: Ulid,
    pub(crate) client: ClientConn,
    pub(crate) tls: Option<TlsInfo>,
    /// The flow's facts as of the latest request to leave the stack (the
    /// client's until then), for `metric-get`: the same keys the core's
    /// samples use.
    facts: Mutex<FlowFacts>,
    /// The client asked to upgrade (WebSocket); carried to the core, since
    /// a layer cannot express hop-by-hop fields.
    upgrade_req: Option<String>,
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
    /// The enforce-mode failure has been logged.
    reported: AtomicBool,
    /// A layer asked to close the client connection.
    pub(crate) close: AtomicBool,
    /// The upgraded upstream connection, when the core relayed a `101`.
    upgrade: Mutex<Option<(hyper::upgrade::Upgraded, WsKey)>>,
    /// The first layer to run has decoded the request for the layers.
    request_decoded: AtomicBool,
}

impl StackFlow {
    fn new(cx: &FlowCx, req: &CanonicalRequest) -> Self {
        Self {
            shared: cx.shared.clone(),
            snap: cx.snap.clone(),
            flow: cx.flow,
            client: cx.facts.client.clone(),
            tls: cx.facts.tls.clone(),
            facts: Mutex::new(cx.facts.clone()),
            upgrade_req: req.meta.upgrade.clone(),
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
            reported: AtomicBool::new(false),
            close: AtomicBool::new(false),
            upgrade: Mutex::new(None),
            request_decoded: AtomicBool::new(false),
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

    /// A `tunnel` layer ran on the upgrade request, so it will join the
    /// WebSocket.
    fn tunnel_ran(&self) -> bool {
        tunnel_layers(&self.snap.addons)
            .into_iter()
            .any(|i| self.layers[i].ran.load(Ordering::SeqCst))
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

    fn take_upgrade(&self) -> Option<(hyper::upgrade::Upgraded, WsKey)> {
        self.upgrade
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
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

/// Runs the exchange through the addon stack. The flow context is parked
/// in the stack while the layers run, lent to the core if a request
/// reaches it, and comes back with the outcome.
pub(crate) async fn run<F: Front>(
    front: &mut F,
    cx: FlowCx,
    req: CanonicalRequest,
) -> (FlowCx, Outcome) {
    let st = Arc::new(StackFlow::new(&cx, &req));
    st.park(cx);
    let driven = front
        .drive(enter(st.clone(), 0, to_layer_request(req)))
        .await;
    let mut cx = st.reclaim().await;
    cx.stack = Some(st.clone());
    let outcome = stack_outcome(&st, &mut cx, driven);
    (cx, outcome)
}

/// What the stack's answer means for the client.
fn stack_outcome(
    st: &Arc<StackFlow>,
    cx: &mut FlowCx,
    driven: Result<Result<LayerResponse, HostError>, roxy_http::ParseError>,
) -> Outcome {
    let resp = match driven {
        Err(e) => return Outcome::Close(e),
        Ok(Err(_)) => {
            let (layer, err) = st.failure().unwrap_or_else(|| {
                (
                    st.snap.addons[0].name.clone(),
                    LayerError::NoResponse.into(),
                )
            });
            emit_stack_error(st, &layer, &err, false);
            return Outcome::Refuse(layer_refusal(&layer));
        }
        Ok(Ok(r)) => r,
    };
    if let Some(i) = st.answered_by() {
        cx.record.decision = Some(DecisionKind::Answered);
        cx.record.terminal_rule = Some(format!("layer:{}", st.snap.addons[i].name));
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
                emit_stack_error(&st2, &layer, &err, false);
            }
        });
    }
    let mut res = from_upstream_response(resp, &cx.snap.limits);
    res.body = gated(std::mem::take(&mut res.body), cx.shared.sink.clone());
    if st.close.load(Ordering::Relaxed) {
        res.meta.close = true;
    }
    if res.status == http::StatusCode::SWITCHING_PROTOCOLS {
        if let Some((upstream, key)) = st.take_upgrade() {
            // A layer cannot express `upgrade: websocket` (hop-by-hop); the
            // core relayed a real upgrade, so restore it.
            res.meta.upgrade = Some("websocket".to_owned());
            return Outcome::Upgrade { res, upstream, key };
        }
        let layer = st.snap.addons[0].name.clone();
        let err = LayerError::InvalidResponse("101 without an upgraded upstream".into());
        emit_layer_error(st, &layer, &err, false);
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
        let req = match selects(&st, index, &addon, req) {
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
        if st.snap.flags.decode_for_addons && !st.request_decoded.swap(true, Ordering::SeqCst) {
            decode_layer_request(&mut req, st.snap.limits.max_request_body_bytes);
        }
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

/// Whether layer `index` runs on `req`: its `when` matches the request
/// as it reaches the layer, and `sample` picks the exchange. The request
/// comes back for the layer, or for the layer below when it is skipped.
///
/// A `when` sees the request re-validated as the core would, so a layer
/// above that passed on something invalid fails here, attributed to it.
fn selects(
    st: &StackFlow,
    index: usize,
    addon: &AddonSpec,
    req: LayerRequest,
) -> Result<(bool, LayerRequest), StackError> {
    let Some(when) = &addon.when else {
        return Ok((sampled(st.flow, index, addon.sample), req));
    };
    let snap = &st.snap;
    let mut creq = match from_layer_request(req, &snap.limits, &snap.flags) {
        Ok(r) => r,
        Err(e) => {
            // Layer 0 gets the client's request, already canonical.
            let above = &snap.addons[index.saturating_sub(1)].name;
            st.fail(above, LayerError::InvalidRequest(e.to_string()));
            return Err(LayerError::InvalidRequest(e.to_string()).into());
        }
    };
    creq.meta.upgrade.clone_from(&st.upgrade_req);
    let mut facts = st.facts();
    facts.request = Some(crate::pipeline::request_facts(&creq));
    let view = ProxyView::new(
        &facts,
        &*st.shared.metrics,
        &*st.shared.state,
        &snap.address_lists,
    );
    let matched = when.matches(&view, &st.tags());
    let metric_err = view.take_metric_error();
    drop(view);
    match matched {
        Ok(m) => Ok((
            m && sampled(st.flow, index, addon.sample),
            to_layer_request(creq),
        )),
        Err(reason) => {
            let err = StackError::Condition {
                code: crate::pipeline::fail_closed_code(&reason, metric_err.as_ref()),
                reason: reason.to_string(),
            };
            if !addon.observe {
                return Err(err);
            }
            // An observer cannot affect traffic, so neither can its `when`.
            emit_stack_error(st, &addon.name, &err, true);
            Ok((false, to_layer_request(creq)))
        }
    }
}

/// Whether `sample` picks this exchange for layer `index`. The draw comes
/// from the flow id's random bits, so it is reproducible from the log, and
/// is mixed with the index so two sampled layers draw independently.
fn sampled(flow: Ulid, index: usize, sample: Option<f64>) -> bool {
    let Some(p) = sample else {
        return true;
    };
    // splitmix64's finaliser: every input bit reaches the top 32.
    let low = u64::try_from(flow.random() & u128::from(u64::MAX)).unwrap_or(0);
    let mut z = low ^ (index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^= z >> 31;
    let draw = u32::try_from(z >> 32).unwrap_or(u32::MAX);
    f64::from(draw) < p * 4_294_967_296.0
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
    let mut creq = match from_layer_request(req, &snap.limits, &snap.flags) {
        Ok(r) => r,
        Err(e) => {
            st.fail(&layer, LayerError::InvalidRequest(e.to_string()));
            return Err(HostError::new(format!("invalid request: {e}")));
        }
    };
    creq.meta.upgrade.clone_from(&st.upgrade_req);
    let Some(mut lease) = st.lease() else {
        st.fail(&layer, LayerError::NextCalledTwice);
        return Err(HostError::new("the flow already reached the core"));
    };
    let cx = lease.cx();
    cx.tunnel_ran = st.tunnel_ran();
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
            // A range of an encoded body is not decodable on its own. A
            // flow no layer ran on gets the response as the origin sent it.
            if snap.flags.decode_for_addons
                && st.any_ran()
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
            if refusal.kind == RefusalKind::UpstreamError && cx.watch.is_some() {
                cx.record_final_sample(true);
            }
            Ok(to_layer_response(refusal_response(cx, &refusal)))
        }
        Outcome::Close(e) => {
            st.fail(
                &layer,
                LayerError::InvalidRequest(format!("request body: {e}")),
            );
            Err(HostError::new(format!("request body failed: {e}")))
        }
        Outcome::Upgrade { res, upstream, key } => {
            *st.upgrade.lock().unwrap_or_else(PoisonError::into_inner) = Some((upstream, key));
            Ok(to_layer_response(res))
        }
    }
}

/// [`decode_for_layers`] on a request on its way into a layer.
fn decode_layer_request(req: &mut LayerRequest, limit: u64) {
    let mut headers = Headers::from_header_map_lenient(req.headers());
    let mut body = std::mem::take(req.body_mut());
    decode_for_layers(&mut headers, &mut body, limit);
    if !headers.contains("content-encoding") {
        req.headers_mut().remove(http::header::CONTENT_ENCODING);
    }
    *req.body_mut() = body;
}

/// Decodes a body by its `content-encoding` for the layers,
/// and drops the header. A coding roxy
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

/// The indexes of the stack's `tunnel` layers, outermost first.
fn tunnel_layers(addons: &[Arc<AddonSpec>]) -> Vec<usize> {
    addons
        .iter()
        .enumerate()
        .filter(|(_, a)| !a.observe && a.wasm().is_some_and(roxy_wasm::Layer::has_tunnel))
        .map(|(i, _)| i)
        .collect()
}

/// Whether a WebSocket must be relayed with no extension negotiated, so
/// every message stays readable: message rules check them, or a `tunnel`
/// layer that ran on the upgrade request gets them decoded.
pub(crate) fn ws_without_extensions(snap: &Snapshot, tunnel_ran: bool) -> bool {
    snap.policy.reads_ws() || (snap.flags.decode_for_addons && tunnel_ran)
}

/// Inserts the stack's `tunnel` layers (outermost first) between the client
/// and the WebSocket relay: each gets the raw byte streams of the
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
    // Only the layers that ran on the upgrade request: a `when` that
    // skipped a layer skips its tunnel too.
    let tunnels: Vec<usize> = tunnel_layers(&st.snap.addons)
        .into_iter()
        .filter(|&i| st.layers[i].ran.load(Ordering::SeqCst))
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

#[cfg(test)]
mod tests {
    use super::sampled;
    use ulid::Ulid;

    #[test]
    fn sampling_is_deterministic_and_proportional() {
        let flows: Vec<Ulid> = (0..10_000).map(|_| Ulid::generate()).collect();
        assert!(flows.iter().all(|&f| sampled(f, 0, None)));
        assert!(flows.iter().all(|&f| sampled(f, 3, Some(1.0))));
        for p in [0.01, 0.25, 0.9] {
            let hits = flows.iter().filter(|&&f| sampled(f, 0, Some(p))).count();
            #[allow(clippy::cast_precision_loss)]
            let share = hits as f64 / flows.len() as f64;
            assert!((share - p).abs() < 0.03, "p {p}: {share}");
        }
        let f = flows[0];
        assert_eq!(sampled(f, 1, Some(0.5)), sampled(f, 1, Some(0.5)));
        // Two layers draw independently.
        let both = flows
            .iter()
            .filter(|&&f| sampled(f, 0, Some(0.5)) && sampled(f, 1, Some(0.5)))
            .count();
        assert!((2000..3000).contains(&both), "{both}");
    }
}
