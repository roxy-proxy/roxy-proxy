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
mod lanes;
mod reclaim;
mod select;
pub mod service;
mod subscribe;
mod tee;
mod ws;

pub(crate) use reclaim::Reclaim;
pub use service::{ServiceError, ServiceSpec};
pub use subscribe::{Part, Subscription};
pub(crate) use ws::{SplicedClient, splice_client, ws_without_extensions};

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use http::{HeaderName, StatusCode};
use roxy_http::layer::{from_layer_request, to_layer_request, to_layer_response};
use roxy_http::upstream::from_upstream_response;
use roxy_http::{Body, BodySender, CanonicalRequest, RequestMeta};
use roxy_wasm::{HostError, LayerError, LayerRequest, LayerResponse, TagError};
use tokio_util::sync::CancellationToken;

use self::attribution::{Attribution, Driven, Fault, Side, attributed};
use crate::addr::PrivateAddrs;
use crate::body::{Collected, collect_prefix};
use crate::exchange::{Front, Outcome, bad_upgrade_refusal, refusal_response};
use crate::flowlog::{DecisionKind, FlowEvent};
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
    /// The host services the layer may call.
    pub capabilities: roxy_wasm::Capabilities,
    /// `config`: the document the layer reads, whatever its kind.
    pub config: serde_json::Value,
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

/// Most tags a flow may hold when a layer adds one, and most bytes of
/// them together; the rules' tags count towards it, though a rule's own
/// `tag` is never refused. The host keeps the tags outside any layer's
/// `max_memory`, so a guest cannot grow them without end.
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
    /// `next` returned the response from upstream.
    Resolved,
    /// `next` ended without one: the layer dropped it, or the exchange was
    /// torn down under it.
    Abandoned,
}

impl NextState {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Entered,
            2 => Self::Pending,
            3 => Self::Resolved,
            4 => Self::Abandoned,
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
    /// An enforce layer that is still running: it may yet forward.
    live: AtomicBool,
    /// The response from upstream is still streaming into the layer.
    response_open: AtomicBool,
    /// Bodies bypassing the layer (enforce mode, head-only subscription).
    bypass: Mutex<subscribe::Bypass>,
    /// The layer failed: any forward of its still running is given up.
    cancel: CancellationToken,
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
/// What a service is told when its exchange is torn down: the client is
/// gone, or the exchange ended for another reason (refused, quarantined,
/// the relay over).
pub(crate) const CLIENT_GONE: &str = "the client went away";
pub(crate) const ENDED: &str = "the exchange ended";

struct NextGuard {
    st: Arc<StackFlow>,
    index: usize,
    settled: bool,
}

impl NextGuard {
    fn new(st: Arc<StackFlow>, index: usize) -> Self {
        st.set_next(index, NextState::Pending);
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
            NextState::Abandoned
        };
        self.st.set_next(self.index, s);
    }
}

impl Drop for NextGuard {
    fn drop(&mut self) {
        if !self.settled {
            self.st.set_next(self.index, NextState::Abandoned);
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
    /// The client's request is a `HEAD`: it gets no response body, whatever
    /// a layer answers.
    client_head: bool,
    loan: reclaim::Loan,
    layers: Box<[LayerSlot]>,
    /// Who is to blame for the exchange failing, if it does.
    pub(crate) attribution: Attribution,
    /// A layer asked to close the client connection.
    pub(crate) close: AtomicBool,
    /// The first layer to run has decoded the request for the layers.
    request_decoded: AtomicBool,
    upgrade: Mutex<Upgrade>,
    /// Permits for the exchange's endpoint calls in flight.
    endpoint_calls: Arc<tokio::sync::Semaphore>,
    /// Whose response reached the client, decided as it did: a layer's
    /// own, or (`Some(None)`) the core's.
    decided: std::sync::OnceLock<Option<usize>>,
    /// The request reached the core: the connector is its consumer from
    /// then on.
    core_entered: AtomicBool,
    /// The client's response is complete.
    response_done: AtomicBool,
    /// Why the exchange was torn down, for whatever the stack still ran
    /// (a service's stream is reset with it).
    torn_down_why: std::sync::OnceLock<&'static str>,
    /// The client's request lane is snipped: the response is complete and
    /// nothing upstream will consume the rest.
    snip: CancellationToken,
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
            client_head: req.method == roxy_http::Method::Head,
            loan: reclaim::Loan::new(),
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
            endpoint_calls: Arc::new(tokio::sync::Semaphore::new(
                endpoint::MAX_ENDPOINT_CALLS_IN_FLIGHT,
            )),
            decided: std::sync::OnceLock::new(),
            core_entered: AtomicBool::new(false),
            response_done: AtomicBool::new(false),
            torn_down_why: std::sync::OnceLock::new(),
            snip: CancellationToken::new(),
        }
    }

    /// Stops whatever the stack still has running: a core forwarding a
    /// request, the pumps feeding layers, bodies parked for a forward that
    /// will not come. For an exchange the front has given up on, or
    /// refused; never for one a layer merely answered. `why` is what a
    /// service still on the exchange is told.
    pub(crate) fn tear_down(&self, why: &'static str) {
        let _ = self.torn_down_why.set(why);
        self.loan.torn_down.cancel();
        self.snip.cancel();
        for index in 0..self.layers.len() {
            subscribe::release(self, index);
        }
        self.loan.changed();
    }

    /// Cancelled when the exchange is torn down.
    pub(crate) fn torn_down(&self) -> CancellationToken {
        self.loan.torn_down.clone()
    }

    /// Why the exchange ended, once it has been torn down.
    pub(crate) fn torn_down_why(&self) -> &'static str {
        self.torn_down_why.get().copied().unwrap_or(ENDED)
    }

    /// Takes the flow context back for the record: once the core has
    /// returned it, nothing in the stack can still forward, and no response
    /// from upstream is still streaming into a layer. A layer's answer
    /// reaching the client says nothing about the request it forwarded, or
    /// may yet forward, which runs to its end first.
    async fn reclaim(&self) -> FlowCx {
        let cx = self
            .loan
            .wait_until(|loan| {
                if self.can_forward() || self.response_open() {
                    return None;
                }
                loan.take()
            })
            .await;
        self.loan.taken();
        cx
    }

    /// A request may still reach the core: a forward is on its way or
    /// running, or a layer is still alive without having forwarded. Not
    /// once the exchange is torn down: the core takes nothing then.
    fn can_forward(&self) -> bool {
        if self.loan.torn_down.is_cancelled() {
            return false;
        }
        self.layers.iter().any(|l| match l.state() {
            NextState::Pending => true,
            NextState::Entered => l.live.load(Ordering::SeqCst),
            NextState::Unentered | NextState::Resolved | NextState::Abandoned => false,
        })
    }

    /// The response from upstream has started into layer `index`, or has
    /// ended there (complete, cut or dropped).
    pub(super) fn response_streaming(&self, index: usize, open: bool) {
        self.layers[index]
            .response_open
            .store(open, Ordering::SeqCst);
        if !open {
            self.lanes_changed();
        }
    }

    /// A response from upstream is still streaming into some layer.
    fn response_open(&self) -> bool {
        !self.loan.torn_down.is_cancelled()
            && self
                .layers
                .iter()
                .any(|l| l.response_open.load(Ordering::SeqCst))
    }

    /// Layer `index` is forwarding: a forward of its has been accepted,
    /// whether or not the call that carries it has run.
    pub(crate) fn forward_requested(&self, index: usize) -> bool {
        self.layers[index].state() == NextState::Pending
    }

    /// Layer `index` failed after answering: any forward of its still
    /// running is given up, and it forwards nothing more.
    pub(crate) fn layer_failed(&self, index: usize) {
        self.layers[index].cancel.cancel();
        self.layer_done(index);
    }

    fn set_next(&self, index: usize, state: NextState) {
        self.layers[index].set(state);
        self.lanes_changed();
    }

    /// Layer `index` is done: its handler returned, or its stream ended.
    /// It forwards nothing more.
    pub(crate) fn layer_done(&self, index: usize) {
        self.layers[index].live.store(false, Ordering::SeqCst);
        self.lanes_changed();
    }

    /// The response the client got is complete.
    fn response_complete(&self) {
        self.response_done.store(true, Ordering::SeqCst);
        self.lanes_changed();
    }

    /// Something that decides the exchange's end moved: whoever waits on
    /// the context is woken, and the request lane is snipped once the
    /// response is complete and nothing upstream will consume the rest of
    /// it: the core never entered, and nothing can still forward. The
    /// client's lane is dropped, parked bypassed bodies included, so the
    /// front drains or closes rather than waits on a reader that will not
    /// come.
    fn lanes_changed(&self) {
        self.loan.changed();
        if self.response_done.load(Ordering::SeqCst)
            && !self.core_entered.load(Ordering::SeqCst)
            && !self.can_forward()
            && !self.snip.is_cancelled()
        {
            self.snip.cancel();
            for index in 0..self.layers.len() {
                subscribe::release_request(self, index);
            }
        }
    }

    /// Layer `index` is forwarding: its request is on its way to the next
    /// layer. Marked here, before the call that carries it runs, so a
    /// response completing meanwhile neither snips the lane nor lets the
    /// record go.
    pub(crate) fn forwarding(&self, index: usize) {
        self.set_next(index, NextState::Pending);
    }

    /// Layer `index`'s forward was given up before it reached the next
    /// layer.
    pub(crate) fn forward_dropped(&self, index: usize) {
        self.set_next(index, NextState::Abandoned);
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
    fn lease(self: &Arc<Self>) -> Option<reclaim::Lease> {
        Some(reclaim::Lease {
            st: self.clone(),
            cx: Some(self.loan.take()?),
            done: false,
        })
    }

    /// The flow's tags: the layers' and the rules' alike.
    pub(crate) fn tags(&self) -> Vec<String> {
        self.meta.tags()
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
    fn body_subscribed(&self, dir: crate::in_flight::Dir) -> bool {
        self.ran().any(|s| s.part(dir) == Part::Full)
    }

    /// A layer that ran reads at least one body.
    fn reads_bytes(&self) -> bool {
        self.ran().any(Subscription::reads_bytes)
    }

    /// Adds a tag, unless the flow already has it or is at
    /// [`MAX_TAGS`] / [`MAX_TAG_BYTES`].
    pub(crate) fn add_tag(&self, tag: String) -> Result<(), TagError> {
        let mut t = self.meta.tags_mut();
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
    fn blamed_layer(&self) -> Option<String> {
        match self.attribution.fault()? {
            Fault::Layer { name, .. } => Some(name),
            Fault::Client(_) | Fault::UpstreamBody | Fault::Budget => None,
        }
    }

    /// The index of the layer blamed for the exchange failing, if one is.
    fn failed_layer(&self) -> Option<usize> {
        let name = self.blamed_layer()?;
        self.snap.addons.iter().position(|a| a.name == name)
    }

    /// The client asked for a WebSocket, the one upgrade the core relays.
    /// The rules below the stack decide whether it is relayed.
    fn is_upgrade(&self) -> bool {
        crate::exchange::wants_websocket(&self.client_meta)
    }

    /// The core relayed an upgrade; the stack's answer decides its fate. An
    /// answer already given carries no relay: the upstream side is closed.
    fn relayed(&self, relay: ws::Relay) {
        if self.decided.get().is_some() {
            tokio::spawn(crate::exchange::close_upstream_ws(relay.upstream));
            return;
        }
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
                NextState::Entered | NextState::Pending | NextState::Abandoned
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

    /// Folds the stack's answer into the record as the front reclaims the
    /// flow: a layer's own response is `answered`, by that layer, unless
    /// the rules refused the request it forwarded meanwhile. A refusal is
    /// the verdict whatever the client was given.
    fn fold_answer(&self, cx: &mut FlowCx) {
        if cx.record.decision == Some(DecisionKind::Deny) {
            return;
        }
        if let Some(Some(i)) = self.decided.get() {
            cx.record.decision = Some(DecisionKind::Answered);
            cx.record.terminal_rule = Some(Decider::Layer(self.snap.addons[*i].name.clone()));
        }
    }

    /// Folds the stack into the flow record just before its `request`
    /// event: the layers that ran.
    pub(crate) fn fold_into(&self, cx: &mut FlowCx) {
        cx.record.addons = self
            .snap
            .addons
            .iter()
            .zip(&self.layers)
            .filter(|(_, l)| l.ran.load(Ordering::SeqCst))
            .map(|(a, _)| a.name.clone())
            .collect();
    }
}

/// A stable code for a layer failure, for the flow log.
fn error_kind(e: &StackError) -> String {
    match e {
        StackError::Layer(e) => layer_error_kind(e),
        StackError::Service(e) => e.kind(),
        StackError::Condition { code, .. } => format!("when:{code}"),
    }
}

/// A stable code for a [`LayerError`], whichever kind of layer it failed.
pub(crate) fn layer_error_kind(e: &LayerError) -> String {
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
    let call = match e {
        StackError::Service(ServiceError::Layer { call, .. }) => Some(*call),
        StackError::Layer(_) | StackError::Service(_) | StackError::Condition { .. } => None,
    };
    tracing::info!(flow = %st.flow, layer, error = %message, mode = mode.as_str(), call, "layer failed");
    st.shared.sink.emit(&FlowEvent::LayerError {
        ts: chrono::Utc::now(),
        flow: st.flow.to_string(),
        conn: st.client.id.to_string(),
        layer: layer.to_owned(),
        mode: mode.as_str().to_owned(),
        kind: error_kind(e),
        message,
        call,
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
/// reaches it, and comes back to the front through the [`Reclaim`].
pub(crate) async fn run<F: Front>(
    front: &mut F,
    cx: FlowCx,
    mut req: CanonicalRequest,
) -> (Reclaim, Outcome) {
    let st = Arc::new(StackFlow::new(&cx, &req));
    // A WebSocket is a long-lived exchange: once upgraded, the client's
    // bytes are the request body and the upstream's the response body.
    let client_tx = if st.is_upgrade() {
        // The swap below would hide a body from `validate_upgrade_request`.
        if req.body.known_length() != Some(0) {
            let refusal = bad_upgrade_refusal(roxy_http::Reason::WsBadHandshake);
            return (Reclaim::now(cx), Outcome::Refuse(refusal));
        }
        let (tx, body) = Body::channel(u64::MAX, None);
        req.body = body;
        Some(tx)
    } else {
        None
    };
    req.body = lanes::snipped(
        &st,
        attributed(&st, Side::Client, std::mem::take(&mut req.body)),
    );
    st.loan.park(cx);
    let driven = front
        .drive(Driven::new(
            st.clone(),
            enter(st.clone(), 0, to_layer_request(req)),
        ))
        .await;
    let outcome = stack_outcome(&st, driven, client_tx);
    if !matches!(outcome, Outcome::Respond(_) | Outcome::Upgrade { .. }) {
        st.tear_down(ENDED);
    }
    (Reclaim::stack(st), outcome)
}

/// What the stack's answer means for the client. `client_tx` feeds the
/// client's bytes into the stack after a `101`.
fn stack_outcome(
    st: &Arc<StackFlow>,
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
    // Decided now: a layer that answered while its forward was below is
    // the one that answered, whatever the core returns to it later. A
    // layer that failed answered nothing: the refusal its failure earned
    // did, and the record already says so.
    let answered = st.answered_by().filter(|&i| st.failed_layer() != Some(i));
    let _ = st.decided.set(answered);
    let mut resp = resp;
    // A `101`'s body is the upgraded stream for the client, not an HTTP
    // body: keep it out of the response model.
    let upgraded_body = (resp.status() == http::StatusCode::SWITCHING_PROTOCOLS)
        .then(|| std::mem::take(resp.body_mut()));
    let mut res = from_upstream_response(resp, &st.snap.limits);
    // A body the front never writes (a bodiless status, a HEAD) ends
    // nothing: the response is complete with its head.
    if res.status_forbids_body() || st.client_head {
        st.response_complete();
    }
    res.body = lanes::completing(
        st,
        lanes::gated(std::mem::take(&mut res.body), st.shared.sink.clone()),
    );
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
                st.shared.sink.clone(),
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
    match refusal_for_fault(st) {
        Ok(refusal) => Outcome::Refuse(refusal),
        Err(e) => Outcome::Close(e.into()),
    }
}

/// The refusal the fault recorded earns, or the client's own parse error
/// when the fault is the client's.
fn refusal_for_fault(st: &Arc<StackFlow>) -> Result<Refusal, roxy_http::ParseError> {
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
            Ok(layer_refusal(name))
        }
        Fault::Client(e) => Err(e.clone()),
        Fault::UpstreamBody => Ok(Refusal::upstream(StatusCode::BAD_GATEWAY, fault.reason())),
        Fault::Budget => Ok(Refusal::fail_closed(fault.reason())),
    }
}

/// The refusal a failure below a layer earns, as a response on that
/// layer's lane, recorded on the flow as the refusal the front would have
/// written. `None` when the fault is the client's (the exchange is
/// closing, and no layer answers it), or the record has already left the
/// stack.
async fn seeded_refusal(st: &Arc<StackFlow>) -> Option<LayerResponse> {
    let refusal = refusal_for_fault(st).ok()?;
    if refusal.close {
        st.close.store(true, Ordering::Relaxed);
    }
    // The core has let go of the context by now: whatever failed below
    // has returned, and with it the lease.
    let mut cx = st.loan.returned().await?;
    if cx.in_flight.is_some() {
        cx.record_refusal_sample(&refusal);
    }
    let res = refusal_response(&mut cx, &refusal);
    st.loan.give_back(cx);
    Some(to_layer_response(res))
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
        st.set_next(index, NextState::Entered);
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
        // Live until something says otherwise: the layer's own done signal
        // once it has one, or this future being dropped before then.
        st.layers[index].live.store(true, Ordering::SeqCst);
        let mut live = Live {
            st: st.clone(),
            index,
            armed: true,
        };
        let res = match &addon.kind {
            AddonImpl::Wasm(layer) => {
                let h = Arc::new(host::StackHost {
                    st: st.clone(),
                    index,
                    observer: None,
                    call: None,
                });
                match layer.handle(h, req).await {
                    Ok(mut r) => {
                        // The guest runs on after answering, and may still
                        // forward, until its handler returns: kept running
                        // whether or not the front writes its body, and
                        // cancelled with the exchange.
                        let running = r.extensions_mut().remove::<roxy_wasm::Running>();
                        match r.extensions().get::<roxy_wasm::LayerOutcome>().cloned() {
                            Some(outcome) => {
                                let st = st.clone();
                                tokio::spawn(async move {
                                    let torn_down = st.torn_down();
                                    let failed = tokio::select! {
                                        biased;
                                        r = outcome.wait() => r.is_err(),
                                        () = torn_down.cancelled() => true,
                                    };
                                    drop(running);
                                    if failed {
                                        st.layer_failed(index);
                                    } else {
                                        st.layer_done(index);
                                    }
                                });
                            }
                            None => st.layer_done(index),
                        }
                        Ok(r)
                    }
                    // Recorded as it happened, through the host; an error
                    // from before the exchange had a host (no instance,
                    // say) is not.
                    Err(e) => {
                        st.fail(&addon.name, e);
                        Err(HostError::new(format!("layer {} failed", addon.name)))
                    }
                }
            }
            // A service's stream ending marks it done.
            AddonImpl::Service(svc) => service::handle(st.clone(), index, svc, req).await,
        };
        if res.is_err() {
            // A failed layer forwards nothing more, any forward of its
            // still running is given up, and the bodies parked for it are
            // dropped: no answer of its will take them, and a response
            // still open at it would hold the record.
            st.layers[index].cancel.cancel();
            subscribe::release(&st, index);
        }
        live.handed_over(res.is_ok());
        res.map(|r| subscribe::reattach_response(&st, index, r))
    })
}

/// Marks layer `index` done if the layer's future is dropped before the
/// layer has a done signal of its own: the exchange ended while its stream
/// was opening, say.
struct Live {
    st: Arc<StackFlow>,
    index: usize,
    armed: bool,
}

impl Live {
    /// The layer answered, and its kind signals its end from here: a WASM
    /// layer when its handler returns, a service when its stream ends. A
    /// layer that failed is done now.
    fn handed_over(&mut self, answered: bool) {
        self.armed = false;
        if !answered {
            self.st.layer_done(self.index);
        }
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        if self.armed {
            self.st.layer_done(self.index);
        }
    }
}

/// What layer `index`'s `next` reaches: the next layer, or the core. What
/// comes back is a response, whoever produced it: the upstream's, the
/// rules' refusal, or the refusal a failure below earns, seeded here so
/// the layers above see it as they would any response. Only the client's
/// own failure comes back as an error: nothing answers a client whose
/// request broke.
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
        let cancelled = st.layers[index].cancel.clone();
        let r = tokio::select! {
            biased;
            // The layer failed: nothing reads what its forward returns.
            () = cancelled.cancelled() => Err(HostError::new("the layer failed")),
            r = fut => match r {
                Ok(r) => Ok(r),
                Err(e) => match seeded_refusal(&st).await {
                    Some(res) => Ok(res),
                    None => Err(e),
                },
            },
        };
        // A skipped layer, or an observer, passes the response on whole;
        // an enforce layer subscribed to the head gets only that.
        let enforcing = st.layers[index].ran.load(Ordering::SeqCst)
            && st.snap.addons[index].mode == AddonMode::Enforce;
        let r = match r {
            // A `101`'s body is the relayed socket, open for its life: not
            // a response the record waits for.
            Ok(res) if enforcing && res.status() != StatusCode::SWITCHING_PROTOCOLS => {
                Ok(subscribe::detach_response(
                    &st,
                    index,
                    res.map(|body| lanes::draining(&st, index, body)),
                ))
            }
            Ok(res) if enforcing => Ok(subscribe::detach_response(&st, index, res)),
            other => other,
        };
        // The response is open at the layer before the forward is marked
        // resolved: whoever waits on the record never sees the forward
        // done and no response streaming in between.
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
        meter: &'a mut (dyn FnMut(u64) -> bool + Send),
        idle: Option<Duration>,
    ) -> CollectFuture<'a, Result<Collected, roxy_http::DriveError>> {
        Box::pin(async move { Ok(collect_prefix(body, cap, meter, idle).await) })
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
    st.core_entered.store(true, Ordering::SeqCst);
    let cx = lease.cx();
    cx.layer_reads_bytes = st.reads_bytes();
    cx.facts.request = Some(crate::pipeline::request_facts(&creq));
    st.set_facts(&cx.facts);
    let mut front = Detached;
    let outcome = tokio::select! {
        biased;
        () = st.loan.torn_down.cancelled() => None,
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
            if snap.http.decode_for_addons && st.body_subscribed(crate::in_flight::Dir::Response) {
                decode::response(&st, &mut res, snap.limits.max_response_body_bytes);
            }
            Ok(to_layer_response(res))
        }
        Outcome::Refuse(refusal) => {
            if refusal.close {
                st.close.store(true, Ordering::Relaxed);
            }
            if cx.in_flight.is_some() {
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

pub(super) fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
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
            forwarded_for: None,
        }),
        peer: "192.0.2.7:40000".parse().unwrap(),
        original_dst: None,
    };
    let cx = FlowCx::new(shared, snap, client, None, &creq).unwrap();
    let st = Arc::new(StackFlow::new(&cx, &creq));
    (st, cx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flowlog::REDACTED;
    use crate::testkit::{AddonDef, Kit, capture_logs};

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
        let logged = capture_logs(tracing::Level::INFO, || {
            emit_layer_error(&st.meta, "a", &e, AddonMode::Enforce);
        });
        assert!(logged.contains("layer failed"), "{logged}");
        assert!(!logged.contains(secret), "{logged}");
        assert!(logged.contains(REDACTED), "{logged}");
        let errs = kit.events("layer_error", 1).await;
        assert_eq!(
            errs[0]["message"],
            format!("layer passed an invalid request: header x-token: {REDACTED}")
        );
    }

    /// A front that lets go of the context before taking it (its task
    /// aborted with the connection) tears the stack down with it; one that
    /// took it leaves the stack to end as it will.
    #[tokio::test]
    async fn a_reclaim_dropped_untaken_tears_the_stack_down() {
        let kit = Kit::builder()
            .addon(AddonDef::test_layer("a"))
            .start()
            .await;
        let (st, cx) = test_flow(&kit);
        st.loan.park(cx);
        let taken = Reclaim::stack(st.clone()).take().await;
        assert!(!st.torn_down().is_cancelled());
        drop(taken);

        let (st, cx) = test_flow(&kit);
        st.loan.park(cx);
        drop(Reclaim::stack(st.clone()));
        assert!(st.torn_down().is_cancelled());
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
        let logged = capture_logs(tracing::Level::WARN, || {
            cx.metric_error(Stage::Head, &e);
        });
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

        let (st, _cx) = test_flow(&kit);
        st.attribution.record(Fault::Client(fault()));
        st.fail("a", LayerError::Trap("boom".into()));
        let out = stack_outcome(&st, failed(), None);
        assert!(
            matches!(&out, Outcome::Close(roxy_http::DriveError::Client(e)) if e.reason == roxy_http::Reason::BadChunkSize),
            "closes as a parse error"
        );
        assert!(st.blamed_layer().is_none(), "no layer is blamed");

        let (st, _cx) = test_flow(&kit);
        st.fail("a", LayerError::Trap("boom".into()));
        st.attribution.record(Fault::Client(fault()));
        let out = stack_outcome(&st, failed(), None);
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
        let (st, _cx) = test_flow(&kit);
        ran(&st, 1);
        let out = stack_outcome(&st, Ok(Err(HostError::new("x"))), None);
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
        let (st, _cx) = test_flow(&kit);
        ran(&st, 1);
        ran(&st, 2);
        let out = stack_outcome(&st, Ok(Err(HostError::new("x"))), None);
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
        let (st, _cx) = test_flow(&kit);
        st.layers[0].ran.store(true, Ordering::SeqCst);
        st.layers[0].set(NextState::Resolved);
        let resp = http::Response::builder()
            .status(StatusCode::CONTINUE)
            .body(Body::empty())
            .unwrap();
        let out = stack_outcome(&st, Ok(Ok(resp)), None);
        assert!(
            matches!(&out, Outcome::Refuse(r) if r.rule == Some(Decider::Layer("a".into()))),
            "refused as a's"
        );
        let errs = kit.events("layer_error", 1).await;
        assert_eq!(errs[0]["kind"], "invalid_response", "{errs:#?}");
        assert_eq!(errs[0]["layer"], "a");
    }
}
