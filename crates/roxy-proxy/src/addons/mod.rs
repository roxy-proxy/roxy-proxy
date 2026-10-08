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

mod attribution;
mod decode;
mod endpoint;
mod host;
mod select;
pub mod service;
pub(crate) mod store;
mod subscribe;
mod tee;
mod ws;

pub use service::{ServiceError, ServiceSpec};
pub use subscribe::{Part, Subscription};
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
use roxy_wasm::{HostError, LayerError, LayerRequest, LayerResponse, TagError};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use self::attribution::{Attribution, Driven, Fault, Side, attributed};
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
    /// `when`: the layer runs only on requests this matches, as they reach
    /// it; the others go straight to the layer below.
    pub when: Option<roxy_rules::Condition>,
    /// `sample` (observe mode only): the share of matching exchanges the
    /// layer gets a copy of.
    pub sample: Option<f64>,
    /// Which parts of the exchange the layer sees; the rest bypass it.
    pub subscribe: Subscription,
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

/// How an endpoint call's URL takes the layer's path and query. A `..`
/// segment is refused in either mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EndpointPath {
    /// The configured URL is the whole target; the layer's path and query
    /// are ignored.
    #[default]
    Fixed,
    /// The layer's path and query are normalised and appended under the
    /// configured path.
    Prefix,
}

/// A named endpoint.
#[derive(Debug, Clone)]
pub struct EndpointSpec {
    /// Base URL: the whole target, or the prefix the request's path goes
    /// under, as `path` says.
    pub url: http::Uri,
    /// What the request's path and query contribute to the URL.
    pub path: EndpointPath,
    /// Headers roxy attaches; values may contain `${secret:name}`.
    pub headers: Vec<(HeaderName, String)>,
    /// Until the response head.
    pub timeout: Duration,
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

/// Most tags a flow holds, and most bytes of them together. Tags are
/// labels for `when` and the flow log; the host keeps them outside any
/// layer's `max_memory`, so a guest cannot grow them without end.
const MAX_TAGS: usize = 64;
const MAX_TAG_BYTES: usize = 4096;

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
    /// Bodies bypassing the layer (enforce mode, head-only subscription).
    bypass: Mutex<subscribe::Bypass>,
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
        self.st.loan.give_back(cx);
    }
}

/// The flow's [`FlowCx`], parked in the stack while the layers run and lent
/// to the core (once) while it runs. However the core ends, the context
/// comes back here, so nothing it recorded is lost.
struct Loan {
    cx: Mutex<Option<FlowCx>>,
    /// The core gave the flow context back.
    returned: Notify,
    /// The response left without the core's: stop the core.
    abandon: CancellationToken,
}

impl Loan {
    fn new() -> Self {
        Self {
            cx: Mutex::new(None),
            returned: Notify::new(),
            abandon: CancellationToken::new(),
        }
    }

    fn park(&self, cx: FlowCx) {
        *lock(&self.cx) = Some(cx);
    }

    /// Takes the context to lend it. `None` if it is already lent.
    fn take(&self) -> Option<FlowCx> {
        lock(&self.cx).take()
    }

    fn give_back(&self, cx: FlowCx) {
        *lock(&self.cx) = Some(cx);
        self.returned.notify_one();
    }

    /// Takes the context back once the stack has answered. A core still
    /// running was abandoned by the layer that answered: it is stopped, and
    /// its record comes back with it.
    async fn reclaim(&self) -> FlowCx {
        loop {
            if let Some(cx) = self.take() {
                return cx;
            }
            self.abandon.cancel();
            self.returned.notified().await;
        }
    }
}

/// The relayed WebSocket on its way from the core to the front.
enum Upgrade {
    None,
    /// The core answered a `101`: the relay waits for the stack's answer.
    Relayed(ws::Relay),
    /// The stack's answer was the `101`: the client side waits for the
    /// front to splice it in once it has sent the `101`.
    Plumbed(ws::WsPlumbing),
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
    loan: Loan,
    layers: Box<[LayerSlot]>,
    /// Who is to blame for the exchange failing, if it does.
    pub(crate) attribution: Attribution,
    /// A layer asked to close the client connection.
    pub(crate) close: AtomicBool,
    /// The first layer to run has decoded the request for the layers.
    request_decoded: AtomicBool,
    upgrade: Mutex<Upgrade>,
    /// Permits for the exchange's endpoint calls in flight.
    endpoint_calls: tokio::sync::Semaphore,
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
            loan: Loan::new(),
            layers: cx
                .snap
                .addons
                .iter()
                .map(|_| LayerSlot::default())
                .collect(),
            attribution: Attribution::new(cx.meta.clone()),
            close: AtomicBool::new(false),
            request_decoded: AtomicBool::new(false),
            upgrade: Mutex::new(Upgrade::None),
            endpoint_calls: tokio::sync::Semaphore::new(endpoint::MAX_ENDPOINT_CALLS_IN_FLIGHT),
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

    /// Lends the flow context to the core. `None` if it is already lent
    /// (the core runs at most once per exchange).
    fn lease(self: &Arc<Self>) -> Option<Lease> {
        Some(Lease {
            st: self.clone(),
            cx: Some(self.loan.take()?),
            done: false,
        })
    }

    pub(crate) fn tags(&self) -> Vec<String> {
        self.tags
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The layers that ran, with their subscriptions.
    fn ran(&self) -> impl Iterator<Item = Subscription> + '_ {
        self.layers
            .iter()
            .zip(self.snap.addons.iter())
            .filter(|(l, _)| l.ran.load(Ordering::SeqCst))
            .map(|(_, a)| a.subscribe)
    }

    /// A layer that ran is subscribed to the body in `dir`.
    fn body_subscribed(&self, dir: crate::watch::Dir) -> bool {
        self.ran().any(|s| s.part(dir) == Part::Full)
    }

    /// A layer that ran reads at least one body.
    fn reads_bytes(&self) -> bool {
        self.ran().any(Subscription::reads_bytes)
    }

    /// Adds a tag, unless the flow already has it or is at
    /// [`MAX_TAGS`] / [`MAX_TAG_BYTES`].
    pub(crate) fn add_tag(&self, tag: String) -> Result<(), TagError> {
        let mut t = self.tags.lock().unwrap_or_else(PoisonError::into_inner);
        if t.contains(&tag) {
            return Ok(());
        }
        let bytes: usize = t.iter().map(String::len).sum();
        if t.len() >= MAX_TAGS || bytes.saturating_add(tag.len()) > MAX_TAG_BYTES {
            return Err(TagError::Full);
        }
        t.push(tag);
        Ok(())
    }

    /// Layer `layer` failed the exchange.
    pub(crate) fn fail(&self, layer: &str, err: impl Into<StackError>) {
        self.attribution.record(Fault::Layer {
            name: layer.to_owned(),
            err: err.into(),
        });
    }

    /// The flow log's code for the fault that cut the exchange's response
    /// body after its head was out, if one is recorded.
    pub(crate) fn fault_reason(&self) -> Option<String> {
        self.attribution.fault().map(|f| f.reason().to_owned())
    }

    /// The layer blamed for the exchange failing, if one is.
    #[cfg(test)]
    fn blamed_layer(&self) -> Option<String> {
        match self.attribution.fault()? {
            Fault::Layer { name, .. } => Some(name),
            Fault::Client(_) | Fault::UpstreamBody | Fault::Budget => None,
        }
    }

    /// The client asked for a WebSocket, the one upgrade the core relays.
    /// The rules below the stack decide whether it is relayed.
    fn is_upgrade(&self) -> bool {
        crate::exchange::wants_websocket(&self.client_meta)
    }

    /// The core relayed an upgrade; the stack's answer decides its fate.
    fn relayed(&self, relay: ws::Relay) {
        *lock(&self.upgrade) = Upgrade::Relayed(relay);
    }

    fn take_relay(&self) -> Option<ws::Relay> {
        let mut u = lock(&self.upgrade);
        match std::mem::replace(&mut *u, Upgrade::None) {
            Upgrade::Relayed(relay) => Some(relay),
            other @ (Upgrade::None | Upgrade::Plumbed(_)) => {
                *u = other;
                None
            }
        }
    }

    /// The stack answered the `101`: the client side waits for the front.
    fn plumbed(&self, plumbing: ws::WsPlumbing) {
        *lock(&self.upgrade) = Upgrade::Plumbed(plumbing);
    }

    fn take_ws(&self) -> Option<ws::WsPlumbing> {
        let mut u = lock(&self.upgrade);
        match std::mem::replace(&mut *u, Upgrade::None) {
            Upgrade::Plumbed(plumbing) => Some(plumbing),
            other @ (Upgrade::None | Upgrade::Relayed(_)) => {
                *u = other;
                None
            }
        }
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

    /// Layer `i` ran in enforce mode: what left it is its own. An observer
    /// runs beside the exchange and passes nothing on, so it is never the
    /// one to blame for what reached the layers below.
    fn enforced(&self, i: usize) -> bool {
        self.layers[i].ran.load(Ordering::SeqCst) && self.snap.addons[i].mode == AddonMode::Enforce
    }

    /// The nearest enforcing layer above `below` that ran: the one that
    /// passed on what reached `below` (a skipped layer or an observer
    /// passes it on untouched). `None` when the request reaching `below`
    /// is the client's.
    fn passed_on_by(&self, below: usize) -> Option<usize> {
        (0..below).rev().find(|&i| self.enforced(i))
    }

    /// The layer a failure no layer recorded is put down to: the one that
    /// answered, else the outermost enforcing layer that ran, since what
    /// the client got came from it.
    fn blamed(&self) -> String {
        let i = self
            .answered_by()
            .or_else(|| (0..self.layers.len()).find(|&i| self.enforced(i)))
            .unwrap_or(0);
        self.snap.addons[i].name.clone()
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
        LayerError::InvalidResponse(_) => "invalid_response".into(),
        LayerError::Host(_) => "host".into(),
        LayerError::Init(_) => "init".into(),
        LayerError::Instantiate(_) => "instantiate".into(),
        LayerError::NoInstance => "no_instance".into(),
        LayerError::Cancelled => "cancelled".into(),
        LayerError::Unsubscribed(dir) => format!("unsubscribed:{dir}"),
    }
}

pub(crate) fn emit_layer_error(st: &FlowMeta, layer: &str, e: &LayerError, mode: AddonMode) {
    emit_stack_error(st, layer, &StackError::Layer(e.clone()), mode);
}

/// Logs a layer failure. In enforce mode only the exchange's
/// [`Attribution`] calls this, once; an observer's failures are logged
/// every time.
pub(crate) fn emit_stack_error(st: &FlowMeta, layer: &str, e: &StackError, mode: AddonMode) {
    if matches!(e, StackError::Layer(LayerError::Cancelled)) {
        // The client went away; nothing failed.
        return;
    }
    // Redacted once, for both sinks: a guest's panic message or an
    // `InvalidRequest` detail can quote whatever the guest was given.
    let message = st
        .secrets()
        .redactor()
        .redact_str(&e.to_string())
        .into_owned();
    tracing::info!(flow = %st.flow, layer, error = %message, mode = mode.as_str(), "layer failed");
    st.shared.sink.emit(&FlowEvent::LayerError {
        ts: chrono::Utc::now(),
        flow: st.flow.to_string(),
        conn: st.client.id.to_string(),
        layer: layer.to_owned(),
        mode: mode.as_str().to_owned(),
        kind: error_kind(e),
        message,
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
    req.body = attributed(&st, Side::Client, std::mem::take(&mut req.body));
    st.loan.park(cx);
    let driven = front
        .drive(Driven::new(
            st.clone(),
            enter(st.clone(), 0, to_layer_request(req)),
        ))
        .await;
    let mut cx = st.loan.reclaim().await;
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
        Ok(Err(_)) => return refuse(st),
        Ok(Ok(r)) => r,
    };
    // A layer's answer is a final response; the one `1xx` with a meaning
    // here is the `101` of a relayed upgrade, judged below.
    if resp.status().is_informational() && resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        let err = LayerError::InvalidResponse(format!("{} is not a final response", resp.status()));
        st.fail(&st.blamed(), err);
        return refuse(st);
    }
    if let Some(i) = st.answered_by() {
        cx.record.decision = Some(DecisionKind::Answered);
        cx.record.terminal_rule = Some(Decider::Layer(st.snap.addons[i].name.clone()));
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
    let relay = st.take_relay();
    if res.status == http::StatusCode::SWITCHING_PROTOCOLS {
        if let (Some(relay), Some(client_tx)) = (relay, client_tx) {
            // A layer cannot express `upgrade: websocket` (hop-by-hop); the
            // core relayed a real upgrade, so restore it.
            res.meta.upgrade = Some("websocket".to_owned());
            let to_client = upgraded_body.unwrap_or_default();
            st.plumbed(ws::WsPlumbing::new(
                client_tx,
                to_client,
                relay.bottom,
                cx.shared.sink.clone(),
            ));
            // A failure from here on cuts the body (the codec then breaks
            // the connection) and is logged as it is recorded.
            st.attribution.head_out();
            return Outcome::Upgrade {
                res,
                upstream: relay.upstream,
                key: relay.key,
            };
        }
        let err = LayerError::InvalidResponse("101 without an upgrade to relay".into());
        st.fail(&st.blamed(), err);
        return refuse(st);
    }
    if let Some(relay) = relay {
        // The upstream switched protocols but the stack answered otherwise:
        // no body can carry the relay, so close it and fail closed.
        tokio::spawn(crate::exchange::close_upstream_ws(relay.upstream));
        let err = LayerError::InvalidResponse(format!("{} over a relayed upgrade", res.status));
        st.fail(&st.blamed(), err);
        return refuse(st);
    }
    st.attribution.head_out();
    Outcome::Respond(res)
}

/// The exchange's refusal before the response head, from the fault
/// recorded: a layer's failure is logged and refused as its own; a request
/// body that failed on its way in closes the connection as it would
/// without a stack; the others are the refusals the core would give.
fn refuse(st: &Arc<StackFlow>) -> Outcome {
    let fault = st.attribution.fault().unwrap_or_else(|| {
        // Every path that fails a layer records it, so this is a layer
        // that returned an error without saying why.
        let name = st.blamed();
        st.fail(&name, LayerError::NoResponse);
        Fault::Layer {
            name,
            err: LayerError::NoResponse.into(),
        }
    });
    match &fault {
        Fault::Layer { name, .. } => {
            st.attribution.log();
            Outcome::Refuse(layer_refusal(name))
        }
        Fault::Client(e) => Outcome::Close(e.clone().into()),
        Fault::UpstreamBody => {
            Outcome::Refuse(Refusal::upstream(StatusCode::BAD_GATEWAY, fault.reason()))
        }
        Fault::Budget => Outcome::Refuse(Refusal::fail_closed(fault.reason())),
    }
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
        // Layers see bodies decoded, from the first layer subscribed to the
        // body; a body no layer reads is left as the client sent it.
        if st.snap.http.decode_for_addons
            && addon.subscribe.request == Part::Full
            && !st.request_decoded.swap(true, Ordering::SeqCst)
        {
            decode::request(&st, &mut req, st.snap.limits.max_request_body_bytes);
        }
        if addon.mode == AddonMode::Observe {
            return tee::observe(st, index, req).await;
        }
        let req = subscribe::detach_request(&st, index, req);
        let res = match &addon.kind {
            AddonImpl::Wasm(layer) => {
                let h = Arc::new(host::StackHost {
                    st: st.clone(),
                    index,
                    observer: None,
                });
                match layer.handle(h, req).await {
                    Ok(r) => Ok(r),
                    // Recorded as it happened, through the host; an error
                    // from before the exchange had a host (no instance,
                    // say) is not.
                    Err(e) => {
                        st.fail(&addon.name, e);
                        Err(HostError::new(format!("layer {} failed", addon.name)))
                    }
                }
            }
            AddonImpl::Service(svc) => service::handle(st.clone(), index, svc, req).await,
        };
        subscribe::release_request(&st, index);
        res.map(|r| subscribe::reattach_response(&st, index, r))
    })
}

/// What layer `index`'s `next` reaches: the next layer, or the core.
pub(crate) fn below(
    st: Arc<StackFlow>,
    index: usize,
    req: LayerRequest,
) -> BoxFuture<Result<LayerResponse, HostError>> {
    let guard = NextGuard::new(st.clone(), index);
    let req = subscribe::reattach_request(&st, index, req);
    let fut = if index + 1 < st.snap.addons.len() {
        enter(st.clone(), index + 1, req)
    } else {
        Box::pin(core(st.clone(), index, req))
    };
    Box::pin(async move {
        let r = fut.await;
        guard.settle(r.is_ok());
        // A skipped layer, or an observer, passes the response on whole;
        // an enforce layer subscribed to the head gets only that.
        let enforcing = st.layers[index].ran.load(Ordering::SeqCst)
            && st.snap.addons[index].mode == AddonMode::Enforce;
        match r {
            Ok(res) if enforcing => Ok(subscribe::detach_response(&st, index, res)),
            other => other,
        }
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
        meter: &'a mut (dyn FnMut(u64) -> bool + Send),
    ) -> CollectFuture<'a, Result<Collected, roxy_http::DriveError>> {
        Box::pin(async move { Ok(collect_prefix(body, cap, meter).await) })
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
    let layer = snap.addons[st.passed_on_by(index + 1).unwrap_or(index)]
        .name
        .clone();
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
    cx.layer_reads_bytes = st.reads_bytes();
    cx.facts.request = Some(crate::pipeline::request_facts(&creq));
    st.set_facts(&cx.facts);
    let mut front = Detached;
    let outcome = tokio::select! {
        biased;
        () = st.loan.abandon.cancelled() => None,
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
            res.body = attributed(&st, Side::Upstream, std::mem::take(&mut res.body));
            // A response body no layer reads goes up as the origin sent it.
            if snap.http.decode_for_addons && st.body_subscribed(crate::watch::Dir::Response) {
                decode::response(&st, &mut res, snap.limits.max_response_body_bytes);
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
        // The body that failed was recorded where it entered the stack
        // (the client's) or by the layer that produced it.
        Outcome::Close(e) => Err(HostError::new(format!("request body failed: {e}"))),
        Outcome::Upgrade {
            mut res,
            upstream,
            key,
        } => {
            st.relayed(ws::Relay::new(
                upstream,
                key,
                stream.unwrap_or_default(),
                &mut res,
            ));
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
    use crate::listener::{ClientConn, ListenerInfo};
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
            mode: crate::listener::ListenerMode::HttpProxy,
        }),
        peer: "192.0.2.7:40000".parse().unwrap(),
        original_dst: None,
    };
    let cx = FlowCx::new(shared, snap, client, None, &creq);
    let st = Arc::new(StackFlow::new(&cx, &creq));
    (st, cx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flowlog::REDACTED;
    use crate::testkit::{AddonDef, Kit};

    /// A `tracing` writer into a shared buffer.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
        type Writer = Self;

        fn make_writer(&'a self) -> Self {
            self.clone()
        }
    }

    /// A layer error is redacted once for both sinks, so a secret a guest
    /// quotes in its message reaches neither the operational log nor the
    /// flow log.
    #[tokio::test]
    async fn a_layer_error_is_redacted_in_the_operational_log_too() {
        let secret = "sk-live-123";
        let kit = Kit::builder()
            .secret("k", secret)
            .addon(AddonDef::test_layer("a"))
            .start()
            .await;
        let (st, _cx) = test_flow(&kit);
        let e = LayerError::InvalidRequest(format!("header x-token: {secret}"));
        let captured = Captured::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(captured.clone())
            .with_max_level(tracing::Level::INFO)
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            emit_layer_error(&st.meta, "a", &e, AddonMode::Enforce);
        });
        let logged = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        assert!(logged.contains("layer failed"), "{logged}");
        assert!(!logged.contains(secret), "{logged}");
        assert!(logged.contains(REDACTED), "{logged}");
        let errs = kit.events("layer_error", 1).await;
        assert_eq!(
            errs[0]["message"],
            format!("layer passed an invalid request to `next`: header x-token: {REDACTED}")
        );
    }

    /// A metric source's detail can quote the series key, which a rule may
    /// build from request data.
    #[tokio::test]
    async fn a_metric_error_is_redacted_in_the_operational_log_too() {
        use crate::flowlog::Stage;
        use crate::sources::MetricSourceError;
        let secret = "sk-live-123";
        let kit = Kit::builder()
            .secret("k", secret)
            .addon(AddonDef::test_layer("a"))
            .start()
            .await;
        let (_st, cx) = test_flow(&kit);
        let e = MetricSourceError::KeyUnavailable(format!("key token={secret}"));
        let captured = Captured::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(captured.clone())
            .with_max_level(tracing::Level::WARN)
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            cx.metric_error(Stage::Head, &e);
        });
        let logged = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        assert!(logged.contains("metric recording failed"), "{logged}");
        assert!(!logged.contains(secret), "{logged}");
        assert!(logged.contains(REDACTED), "{logged}");
        let errs = kit.events("policy_input_unavailable", 1).await;
        assert_eq!(
            errs[0]["reason"],
            format!("{}: metric key unavailable: key token={REDACTED}", e.code())
        );
    }

    /// The first fault recorded stands, whoever records next: a client
    /// body that failed on its way in closes the connection as a client's
    /// would, and the layer that then fails on the cut body is not blamed;
    /// a layer that failed first is, and the body its failure cut is not
    /// the client's.
    #[tokio::test]
    async fn the_first_fault_recorded_stands() {
        let kit = Kit::builder()
            .addon(AddonDef::test_layer("a"))
            .start()
            .await;
        let fault = || roxy_http::ParseError::new(roxy_http::Reason::BadChunkSize, "zz");
        let failed = || Ok(Err(HostError::new("request body failed")));

        let (st, mut cx) = test_flow(&kit);
        st.attribution.record(Fault::Client(fault()));
        st.fail("a", LayerError::Trap("boom".into()));
        let out = stack_outcome(&st, &mut cx, failed(), None);
        assert!(
            matches!(&out, Outcome::Close(roxy_http::DriveError::Client(e)) if e.reason == roxy_http::Reason::BadChunkSize),
            "closes as a parse error"
        );
        assert!(st.blamed_layer().is_none(), "no layer is blamed");

        let (st, mut cx) = test_flow(&kit);
        st.fail("a", LayerError::Trap("boom".into()));
        st.attribution.record(Fault::Client(fault()));
        let out = stack_outcome(&st, &mut cx, failed(), None);
        assert!(
            matches!(&out, Outcome::Refuse(r) if r.rule == Some(Decider::Layer("a".into()))),
            "the layer's failure stands"
        );
        let errs = kit.events("layer_error", 1).await;
        assert_eq!(errs[0]["kind"], "trap", "{errs:#?}");
    }

    /// A layer's fault is logged once, when the exchange can carry it no
    /// other way: with the refusal before the head, or as recorded once
    /// the head is out (whether it was recorded before or after the head
    /// went). A cancelled exchange is nobody's failure and is not logged.
    #[tokio::test]
    async fn a_layer_fault_is_logged_once_and_only_once_the_head_cannot_carry_it() {
        let kit = Kit::builder()
            .addon(AddonDef::test_layer("a"))
            .start()
            .await;
        let logged = |kit: &Kit| {
            kit.sink
                .events()
                .into_iter()
                .filter(|e| e["event"] == "layer_error")
                .count()
        };

        // Recorded before the head, logged as it goes out, once.
        let (st, _) = test_flow(&kit);
        st.fail("a", LayerError::Trap("early".into()));
        assert_eq!(logged(&kit), 0, "nothing carries it yet");
        st.attribution.head_out();
        st.attribution.log();
        st.fail("a", LayerError::Trap("late".into()));
        assert_eq!(logged(&kit), 1);

        // Recorded after the head: logged at once.
        let (st, _) = test_flow(&kit);
        st.attribution.head_out();
        st.fail("a", LayerError::NoResponse);
        assert_eq!(logged(&kit), 2);
        assert_eq!(kit.sink.events().last().unwrap()["kind"], "no_response");

        // A client that went away: nothing to log, and it shadows what
        // the layers make of their bodies ending.
        let (st, _) = test_flow(&kit);
        st.attribution.head_out();
        st.fail("a", LayerError::Cancelled);
        st.fail("a", LayerError::Trap("on the cut".into()));
        assert_eq!(logged(&kit), 2);
    }

    /// A failure is put down to a layer that ran, never to one its `when`
    /// skipped: the request a skipped layer passes on is its caller's, and
    /// the response it passes back is from below.
    #[tokio::test]
    async fn blame_skips_layers_that_did_not_run() {
        let skipped = r#"path == "/never""#;
        let kit = Kit::builder()
            .addon(AddonDef::test_layer("a"))
            .addon(AddonDef::test_layer("b").when(skipped))
            .addon(AddonDef::test_layer("c").when(skipped))
            .start()
            .await;
        let invalid = || {
            http::Request::get("ftp://up.test/")
                .body(Body::empty())
                .unwrap()
        };
        let ran = |st: &StackFlow, i: usize| {
            st.layers[i].ran.store(true, Ordering::SeqCst);
            st.layers[i].set(NextState::Resolved);
        };
        let blamed = |st: &StackFlow| st.blamed_layer().expect("a failure");

        // What reaches `c`'s `when` was passed on by `a`, through `b`.
        let (st, _) = test_flow(&kit);
        ran(&st, 0);
        assert!(select::selects(&st, 2, &st.snap.addons[2], invalid()).is_err());
        assert_eq!(blamed(&st), "a");

        // Likewise what reaches the core below a skipped last layer.
        let (st, _) = test_flow(&kit);
        ran(&st, 0);
        assert!(core(st.clone(), 2, invalid()).await.is_err());
        assert_eq!(blamed(&st), "a");

        // A failure no layer recorded goes to the outermost that ran.
        let (st, mut cx) = test_flow(&kit);
        ran(&st, 1);
        let out = stack_outcome(&st, &mut cx, Ok(Err(HostError::new("x"))), None);
        assert!(
            matches!(&out, Outcome::Refuse(r) if r.rule == Some(Decider::Layer("b".into()))),
            "blames b"
        );
    }

    /// An observer that ran passed nothing on: what reaches the layers
    /// below it came from the nearest enforcing layer above, which is the
    /// one blamed when it does not validate.
    #[tokio::test]
    async fn blame_skips_observers() {
        let kit = Kit::builder()
            .addon(AddonDef::test_layer("a"))
            .addon(AddonDef::test_layer("o").observe())
            .addon(AddonDef::test_layer("c").when(r#"path == "/x""#))
            .start()
            .await;
        let invalid = || {
            http::Request::get("ftp://up.test/")
                .body(Body::empty())
                .unwrap()
        };
        let ran = |st: &StackFlow, i: usize| {
            st.layers[i].ran.store(true, Ordering::SeqCst);
            st.layers[i].set(NextState::Resolved);
        };
        let blamed = |st: &StackFlow| st.blamed_layer().expect("a failure");

        let (st, _) = test_flow(&kit);
        ran(&st, 0);
        ran(&st, 1);
        assert!(select::selects(&st, 2, &st.snap.addons[2], invalid()).is_err());
        assert_eq!(blamed(&st), "a");

        let (st, _) = test_flow(&kit);
        ran(&st, 0);
        ran(&st, 1);
        assert!(core(st.clone(), 2, invalid()).await.is_err());
        assert_eq!(blamed(&st), "a");

        // A failure no layer recorded goes past an observer too.
        let (st, mut cx) = test_flow(&kit);
        ran(&st, 1);
        ran(&st, 2);
        let out = stack_outcome(&st, &mut cx, Ok(Err(HostError::new("x"))), None);
        assert!(
            matches!(&out, Outcome::Refuse(r) if r.rule == Some(Decider::Layer("c".into()))),
            "blames c"
        );
    }

    /// A `1xx` other than a relayed `101` is not a response a client can
    /// be given: the stack refuses it as the answering layer's invalid
    /// response.
    #[tokio::test]
    async fn an_interim_response_from_a_layer_is_refused() {
        let kit = Kit::builder()
            .addon(AddonDef::test_layer("a"))
            .start()
            .await;
        let (st, mut cx) = test_flow(&kit);
        st.layers[0].ran.store(true, Ordering::SeqCst);
        st.layers[0].set(NextState::Resolved);
        let resp = http::Response::builder()
            .status(StatusCode::CONTINUE)
            .body(Body::empty())
            .unwrap();
        let out = stack_outcome(&st, &mut cx, Ok(Ok(resp)), None);
        assert!(
            matches!(&out, Outcome::Refuse(r) if r.rule == Some(Decider::Layer("a".into()))),
            "refused as a's"
        );
        let errs = kit.events("layer_error", 1).await;
        assert_eq!(errs[0]["kind"], "invalid_response", "{errs:#?}");
        assert_eq!(errs[0]["layer"], "a");
    }
}
