//! The addon layer stack.
//!
//! ```text
//!   client edge ──req[0]──▶ addon 0 ──req[1]──▶ … ──req[n]──▶ core edge (rules ↓ / ↑, address floor, connector)
//!               ◀──res[0]──         ◀──res[1]──   …  ◀──res[n]──
//! ```
//!
//! An exchange is a chain of stages joined by lanes (`chain`). The client
//! edge puts the client's request on the first request lane and waits for
//! the head on the first response lane. Each layer runs on what reaches it
//! on its request lane; what it forwards goes on the lane upstream of it,
//! and what it answers goes on the response lane downstream. The core edge
//! runs the ordinary exchange core on whatever the last layer passed on,
//! after re-validating it exactly as strictly as a client request
//! (invariant 1). On the way back the rules see the upstream's response
//! before any layer does. Any layer failure fails the exchange closed
//! (invariant 3): a deny before the response head, a cut body after it.

mod attribution;
mod chain;
mod client_edge;
mod core_edge;
mod decode;
mod endpoint;
mod host;
mod layer;
mod reclaim;
mod select;
pub mod service;
mod subscribe;
mod tee;
mod ws;

pub(crate) use client_edge::run;
pub(crate) use reclaim::Reclaim;
pub use service::{ServiceError, ServiceSpec};
pub use subscribe::{Part, Subscription};
pub(crate) use ws::{SplicedClient, splice_client, ws_without_extensions};

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use http::HeaderName;
use roxy_http::{CanonicalRequest, RequestMeta};
use roxy_wasm::{LayerError, TagError};
use tokio_util::sync::CancellationToken;

use self::attribution::{Attribution, Fault};
use self::chain::{Chain, Dir, LaneId};
use crate::addr::PrivateAddrs;
use crate::flowlog::{DecisionKind, FlowEvent};
use crate::pipeline::{Decider, FlowCx, FlowMeta};
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

/// One layer's part in an exchange.
#[derive(Default)]
struct LayerSlot {
    /// The layer ran on this exchange: its `when` and `sample` let it.
    ran: AtomicBool,
    /// The layer's ends of the hop upstream of it, until it forwards.
    forward: Mutex<Option<layer::Forward>>,
}

/// What a service is told when its exchange is torn down: the client is
/// gone, or the exchange ended for another reason (refused, quarantined,
/// the relay over).
pub(crate) const CLIENT_GONE: &str = "the client went away";
pub(crate) const ENDED: &str = "the exchange ended";

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
    /// The lanes of the exchange, and the rules that move them.
    chain: OnceLock<Arc<Chain>>,
    /// Who is to blame for the exchange failing, if it does.
    pub(crate) attribution: Attribution,
    /// A layer asked to close the client connection.
    pub(crate) close: AtomicBool,
    /// The first layer to run has decoded the request for the layers.
    request_decoded: AtomicBool,
    upgrade: Mutex<Upgrade>,
    /// Permits for the exchange's endpoint calls in flight.
    endpoint_calls: Arc<tokio::sync::Semaphore>,
    /// Whose response reached the client, decided as the front took it: a
    /// layer's own, or (`Some(None)`) the core's.
    decided: OnceLock<Option<usize>>,
    /// The front is splicing the client into a relayed WebSocket: the
    /// record goes with the relay, which ends the exchange.
    upgraded: CancellationToken,
    /// The client edge reads the response body itself (one the client is
    /// not sent), so the lane ends as the layer ends it.
    draining: AtomicBool,
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
            chain: OnceLock::new(),
            attribution: Attribution::new(cx.meta.clone()),
            close: AtomicBool::new(false),
            request_decoded: AtomicBool::new(false),
            upgrade: Mutex::new(Upgrade::None),
            endpoint_calls: Arc::new(tokio::sync::Semaphore::new(
                endpoint::MAX_ENDPOINT_CALLS_IN_FLIGHT,
            )),
            decided: OnceLock::new(),
            upgraded: CancellationToken::new(),
            draining: AtomicBool::new(false),
        }
    }

    fn chain(&self) -> &Arc<Chain> {
        self.chain.get().expect("the chain is built with the flow")
    }

    /// Stops whatever the stack still has running: the client edge lets
    /// go of the response and cuts the request, and every stage upstream
    /// is torn down in turn. For an exchange the front has given up on, or
    /// refused; never for one a layer merely answered. `why` is what a
    /// service still on the exchange is told.
    pub(crate) fn tear_down(&self, why: &'static str) {
        self.chain().tear_down(why);
    }

    /// Cancelled when the exchange is torn down.
    #[cfg(test)]
    pub(crate) fn torn_down(&self) -> CancellationToken {
        self.chain().torn_down()
    }

    /// Layer `index` is torn down, or being torn down.
    pub(crate) fn layer_torn(&self, index: usize) -> bool {
        self.chain().layer_torn(index)
    }

    /// Why layer `index` was torn down, once it has been.
    pub(crate) fn layer_torn_down_why(&self, index: usize) -> &'static str {
        self.chain().layer_torn_down_why(index)
    }

    /// The response has been written: a body the client edge did not read
    /// to its end, and is not reading, is one it will not read.
    pub(crate) fn response_written(&self) {
        if self.draining.load(Ordering::SeqCst) {
            return;
        }
        let res = LaneId {
            hop: 0,
            dir: Dir::Res,
        };
        self.chain().release(res, ENDED);
    }

    /// Layer `index` failed with `err`: recorded, then torn down.
    pub(crate) fn layer_failed(&self, index: usize, err: impl Into<StackError>) {
        self.chain().fail_layer(index, err.into());
    }

    /// Takes the flow context back for the record: once the exchange is
    /// over, nothing in the stack can still forward or answer, and the
    /// core has returned the context with whatever it recorded. A relayed
    /// WebSocket is the exception: the front runs the relay on the
    /// context, and the exchange ends with it.
    async fn reclaim(&self) -> FlowCx {
        tokio::select! {
            () = self.chain().until_over() => {}
            () = self.upgraded.cancelled() => {}
        }
        let cx = self.loan.wait_until(reclaim::Loan::take).await;
        self.loan.taken();
        cx
    }

    /// Layer `index`'s forward is outstanding: its head is on the request
    /// lane upstream of the layer, and nothing has answered it there yet.
    pub(crate) fn forward_requested(&self, index: usize) -> bool {
        let chain = self.chain();
        let hop = index + 1;
        chain.has_head(LaneId { hop, dir: Dir::Req })
            && !chain.has_head(LaneId { hop, dir: Dir::Res })
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
    /// answer already on its way to the client carries no relay: the
    /// upstream side is closed.
    fn relayed(&self, relay: ws::Relay) {
        let answered = LaneId {
            hop: 0,
            dir: Dir::Res,
        };
        if self.chain().has_head(answered) {
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
        self.upgraded.cancel();
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

    /// The front refused the upgrade the stack relayed: the exchange is
    /// over, and the socket the layers were to carry is dropped unspliced.
    pub(crate) fn abandon_upgrade(&self) {
        self.tear_down(ENDED);
        drop(self.take_ws());
    }

    /// The layer whose own answer reached the client, if a layer's did.
    fn answered_by(&self) -> Option<usize> {
        self.chain().answered_by()
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
        // A lane a layer cut of its own accord: the reason, unless one
        // stands.
        if let Some(abort) = self.chain().abort_reason() {
            cx.record.reason.get_or_insert_with(|| abort.to_owned());
        }
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

pub(super) fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A flow through `kit`'s current snapshot, for tests that drive the
/// stack's parts directly: a `GET http://up.test/` from a client on the
/// proxy port.
/// The chain's ends, held so the lanes stay open for as long as a test
/// wants them.
#[cfg(test)]
pub(crate) struct Ends {
    #[allow(dead_code)]
    pub(crate) edge: chain::EdgeIo,
    pub(crate) layers: Vec<chain::LayerIo>,
    pub(crate) core: chain::CoreIo,
}

#[cfg(test)]
pub(crate) fn test_flow(kit: &crate::testkit::Kit) -> (Arc<StackFlow>, FlowCx, Ends) {
    use crate::listener::{ClientConn, ListenerInfo};
    use ulid::Ulid;
    let shared = kit.server.shared().clone();
    let snap = shared.snapshot();
    let req = http::Request::get("http://up.test/")
        .body(roxy_http::Body::empty())
        .unwrap();
    let meta = RequestMeta::new(roxy_http::Version::H1_1, roxy_http::TargetForm::Absolute);
    let creq = roxy_http::layer::from_layer_request(req, meta, &snap.limits, &snap.flags).unwrap();
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
    let (chain, edge, layers, core) = client_edge::test_chain(&st);
    assert!(st.chain.set(chain).is_ok());
    (st, cx, Ends { edge, layers, core })
}

#[cfg(test)]
mod tests {
    use super::chain::{Head, Headless};
    use super::client_edge::stack_outcome;
    use super::*;
    use crate::exchange::Outcome;
    use crate::flowlog::REDACTED;
    use crate::testkit::{AddonDef, Kit, capture_logs};
    use roxy_http::Body;
    use roxy_wasm::LayerError;

    fn cut(why: &str) -> client_edge::Arrival {
        Err(Headless::Cut(why.to_owned()))
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
        let (st, _cx, _ends) = test_flow(&kit);
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
        let (st, cx, ends) = test_flow(&kit);
        st.loan.park(cx);
        // The lanes let go of unused: the exchange is over, not torn down.
        drop(ends);
        let taken = Reclaim::stack(st.clone()).take().await;
        assert!(!st.torn_down().is_cancelled());
        drop(taken);

        let (st, cx, _ends) = test_flow(&kit);
        st.loan.park(cx);
        drop(Reclaim::stack(st.clone()));
        assert!(st.torn_down().is_cancelled());
    }

    /// Which layer answered is read as its head lands on its lane: a
    /// response from upstream landing after that does not turn the answer
    /// into a response passed on.
    #[tokio::test]
    async fn the_answering_layer_is_read_when_it_answers() {
        let kit = Kit::builder()
            .addon(AddonDef::test_layer("a"))
            .start()
            .await;
        let answer = |status: u16| {
            http::Response::builder()
                .status(status)
                .body(())
                .unwrap()
                .into_parts()
                .0
        };
        let (st, _cx, mut ends) = test_flow(&kit);
        let a = ends.layers.pop().unwrap();
        a.stage.enforcing();
        a.res_out.whole(Head::Response(answer(403)), Body::empty());
        ends.core
            .res_out
            .whole(Head::Response(answer(200)), Body::empty());
        assert_eq!(st.answered_by(), Some(0));

        let (st, _cx, mut ends) = test_flow(&kit);
        let a = ends.layers.pop().unwrap();
        a.stage.enforcing();
        ends.core
            .res_out
            .whole(Head::Response(answer(200)), Body::empty());
        a.res_out.whole(Head::Response(answer(200)), Body::empty());
        assert_eq!(
            st.answered_by(),
            None,
            "the response from upstream, passed on"
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
        let (_st, cx, _ends) = test_flow(&kit);
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
        let failed = || Ok(cut("request body failed"));

        let (st, _cx, _ends) = test_flow(&kit);
        st.attribution.record(Fault::Client(fault()));
        st.fail("a", LayerError::Trap("boom".into()));
        let out = stack_outcome(&st, failed(), None);
        assert!(
            matches!(&out, Outcome::Close(roxy_http::DriveError::Client(e)) if e.reason == roxy_http::Reason::BadChunkSize),
            "closes as a parse error"
        );
        assert!(st.blamed_layer().is_none(), "no layer is blamed");

        let (st, _cx, _ends) = test_flow(&kit);
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
        let (st, _, _ends) = test_flow(&kit);
        st.fail("a", LayerError::Trap("early".into()));
        assert_eq!(logged(&kit), 0, "nothing carries it yet");
        st.attribution.head_out();
        st.attribution.log();
        st.fail("a", LayerError::Trap("late".into()));
        assert_eq!(logged(&kit), 1);

        // Recorded after the head: logged at once.
        let (st, _, _ends) = test_flow(&kit);
        st.attribution.head_out();
        st.fail("a", LayerError::NoResponse);
        assert_eq!(logged(&kit), 2);
        assert_eq!(kit.sink.events().last().unwrap()["kind"], "no_response");

        // A client that went away: nothing to log, and it shadows what
        // the layers make of their bodies ending.
        let (st, _, _ends) = test_flow(&kit);
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
        let ran = |st: &StackFlow, i: usize| st.layers[i].ran.store(true, Ordering::SeqCst);
        let blamed = |st: &StackFlow| st.blamed_layer().expect("a failure");

        // What reaches `c`'s `when` was passed on by `a`, through `b`.
        let (st, _, _ends) = test_flow(&kit);
        ran(&st, 0);
        assert!(select::selects(&st, 2, &st.snap.addons[2], invalid()).is_err());
        assert_eq!(blamed(&st), "a");

        // Likewise what reaches the core below a skipped last layer.
        let (st, _, _ends) = test_flow(&kit);
        ran(&st, 0);
        assert!(core_edge::admit(&st, invalid()).is_none());
        assert_eq!(blamed(&st), "a");

        // A failure no layer recorded goes to the outermost that ran.
        let (st, _cx, _ends) = test_flow(&kit);
        ran(&st, 1);
        let out = stack_outcome(&st, Ok(cut("x")), None);
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
        let ran = |st: &StackFlow, i: usize| st.layers[i].ran.store(true, Ordering::SeqCst);
        let blamed = |st: &StackFlow| st.blamed_layer().expect("a failure");

        let (st, _, _ends) = test_flow(&kit);
        ran(&st, 0);
        ran(&st, 1);
        assert!(select::selects(&st, 2, &st.snap.addons[2], invalid()).is_err());
        assert_eq!(blamed(&st), "a");

        let (st, _, _ends) = test_flow(&kit);
        ran(&st, 0);
        ran(&st, 1);
        assert!(core_edge::admit(&st, invalid()).is_none());
        assert_eq!(blamed(&st), "a");

        // A failure no layer recorded goes past an observer too.
        let (st, _cx, _ends) = test_flow(&kit);
        ran(&st, 1);
        ran(&st, 2);
        let out = stack_outcome(&st, Ok(cut("x")), None);
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
        let (st, _cx, _ends) = test_flow(&kit);
        st.layers[0].ran.store(true, Ordering::SeqCst);
        let (parts, body) = http::Response::builder()
            .status(http::StatusCode::CONTINUE)
            .body(Body::empty())
            .unwrap()
            .into_parts();
        let out = stack_outcome(&st, Ok(Ok((Head::Response(parts), body))), None);
        assert!(
            matches!(&out, Outcome::Refuse(r) if r.rule == Some(Decider::Layer("a".into()))),
            "refused as a's"
        );
        let errs = kit.events("layer_error", 1).await;
        assert_eq!(errs[0]["kind"], "invalid_response", "{errs:#?}");
        assert_eq!(errs[0]["layer"], "a");
    }
}
