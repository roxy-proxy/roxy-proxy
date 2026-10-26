//! The exchange core's fixed steps.
//!
//! On the way out, [`request_steps`] buffers the request body (only when a
//! rule reads `body.text`) and then makes the admission decision with its
//! effects. On the way back, [`response_steps`] buffers the response body
//! (only for `response.body.text`) and then checks the in-flight rules at the
//! response head ([`crate::in_flight`]). The upstream exchange between the two
//! is in [`crate::exchange`]. Extension happens above all of this, in the
//! addon stack ([`crate::addons`]), not here.
//!
//! # Fail closed by construction
//!
//! No step can forward anything itself: each returns a [`Verdict`] (or
//! [`ResponseVerdict`]), and the only variant that leads toward the upstream
//! is [`Verdict::Continue`]. Every error a step meets (body failure,
//! unavailable policy input, invalid mutation, denied redirect target,
//! state store full, unsupported effect) is mapped to [`Verdict::Deny`] or
//! [`Verdict::Close`]. The steps and their caller (`exchange::core`) match
//! verdicts exhaustively with no wildcard arm, so a new variant cannot
//! silently fall through to forwarding.

use std::borrow::Cow;
use std::fmt::{self, Write as _};
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use aws_sigv4::http_request::SignableBody;
use bytes::Bytes;
use http::StatusCode;
use roxy_http::h1::ServerConn;
use roxy_http::url::{normalize_path, normalize_query};
use roxy_http::{
    Authority, Body, BodyError, CanonicalRequest, CanonicalResponse, DriveError, Headers, Method,
    ParseError, Query, Reason, Scheme, status_forbids_body,
};
use roxy_rules::{
    AllowOpts, AwsSigV4, CaptureTarget, DEFAULT_DENY_MESSAGE, Decision, Deny, DenyStatus, Effect,
    EvalContext, FAIL_CLOSED_STATUS, FailClosedReason, LogLevel, Outcome, RuleId,
};
use ulid::Ulid;

use crate::body::{Collected, collect_prefix};
use crate::budget::{self, BufferLease, Exhausted};
use crate::capture::Tap;
use crate::exchange::{WriteFailure, emit_response_error};
use crate::flowlog::{
    ClientInfo, DecisionKind, DstInfo, FlowEvent, PeerInfo, RequestInfo, ResponseInfo, Stage,
    Timing, TlsInfo,
};
use crate::in_flight::InFlight;
use crate::io::ClientIo;
use crate::listener::ClientConn;
use crate::quarantine::QuarantineCause;
use crate::secrets::Secrets;
use crate::server::{Shared, Snapshot};
use crate::sign;
use crate::sources::{MetricSourceError, Sample};
use crate::view::{
    FlowFacts, Inspected, ProxyView, RequestFacts, ResponseFacts, host_str, host_text,
};

/// The boxed future of [`BodyIo::collect`].
pub(crate) type CollectFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Rule id used for denies by the upstream address floor.
pub(crate) const ADDRESS_POLICY_RULE: &str = "_address_policy";

/// Rule id used for denies after the policy's `valid_until`.
pub(crate) const EXPIRED_RULE: &str = "_expired";

/// Flow-log `reason` of an `_expired` deny.
pub(crate) const EXPIRED_REASON: &str = "policy_expired";

/// Rule id used for refusals while the process is quarantined.
pub(crate) const QUARANTINED_RULE: &str = "_quarantined";

/// Flow-log `reason` of a `_quarantined` refusal.
pub(crate) const QUARANTINED_REASON: &str = "quarantined";

/// Rule id used for the refusal of a request `sign` cannot hash.
pub(crate) const SIGN_RULE: &str = "_sign";

/// Flow-log `reason` of a `_sign` refusal: the body is over
/// `limits.max_sign_body_bytes`.
pub(crate) const SIGN_BODY_TOO_LARGE: &str = "sign_body_too_large";

/// Flow-log `reason` of a `_sign` refusal: a request header holds a value
/// the signature cannot cover.
pub(crate) const SIGN_HEADER_INVALID: &str = "sign_header_invalid";

/// Flow-log `mutations` entry of a request a `sign` rule matched but that
/// went out under its own presigned query, roxy's signature withheld.
pub(crate) const SIGN_PRESIGNED: &str = "sign:presigned";

/// Whether a local answer is a policy decision or a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefusalKind {
    /// A rule (or a built-in policy) denied the flow.
    Deny,
    /// The upstream could not be reached or broke.
    UpstreamError,
}

/// What decided a flow: a rule (or one of the reserved `_…` ids roxy uses
/// for its own decisions), or an addon layer. Rendered as the flow log's
/// `terminal_rule`, `x-roxy-rule` and the deny body's `rule`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Decider {
    Rule(RuleId),
    Layer(String),
}

impl Decider {
    /// The rendered form: the rule id, or `layer:<name>`.
    pub(crate) fn name(&self) -> Cow<'_, str> {
        match self {
            Decider::Rule(id) => Cow::Borrowed(id.as_str()),
            Decider::Layer(name) => Cow::Owned(format!("layer:{name}")),
        }
    }
}

impl fmt::Display for Decider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name())
    }
}

/// A deny status as an HTTP status code.
pub(crate) fn status_code(s: DenyStatus) -> StatusCode {
    StatusCode::from_u16(s.get()).expect("4xx and 5xx are valid status codes")
}

/// Rule ids as the flow log writes them.
pub(crate) fn rule_names(rules: &[RuleId]) -> Vec<String> {
    rules.iter().map(ToString::to_string).collect()
}

/// A response roxy writes itself instead of forwarding.
#[derive(Debug, Clone)]
pub(crate) struct Refusal {
    pub kind: RefusalKind,
    pub status: StatusCode,
    pub message: String,
    /// For `x-roxy-rule` and the JSON body (denies only).
    pub rule: Option<Decider>,
    /// Close the client connection after the response.
    pub close: bool,
    /// Stable reason code for the flow log. Never sent to the client: the
    /// body says no more than the rule id, so a probing client cannot tell
    /// an unresolvable name from a closed port or a full table.
    pub reason: Option<String>,
}

impl Refusal {
    pub(crate) fn deny(status: StatusCode, message: &str, rule: RuleId, close: bool) -> Self {
        Self {
            kind: RefusalKind::Deny,
            status,
            message: message.to_owned(),
            rule: Some(Decider::Rule(rule)),
            close,
            reason: None,
        }
    }

    /// 503 `_fail_closed`; `reason` goes to the flow log.
    pub(crate) fn fail_closed(reason: &str) -> Self {
        Self {
            reason: Some(reason.to_owned()),
            ..Self::deny(
                status_code(FAIL_CLOSED_STATUS),
                DEFAULT_DENY_MESSAGE,
                RuleId::new(RuleId::FAIL_CLOSED),
                true,
            )
        }
    }

    /// 403 `_expired`: the policy's lease has run out.
    pub(crate) fn expired() -> Self {
        Self {
            reason: Some(EXPIRED_REASON.to_owned()),
            ..Self::deny(
                status_code(roxy_rules::DEFAULT_DENY_STATUS),
                DEFAULT_DENY_MESSAGE,
                RuleId::new(EXPIRED_RULE),
                false,
            )
        }
    }

    /// 403 `_quarantined`, closing the connection: the process is
    /// quarantined.
    pub(crate) fn quarantined() -> Self {
        Self {
            reason: Some(QUARANTINED_REASON.to_owned()),
            ..Self::deny(
                status_code(roxy_rules::DEFAULT_DENY_STATUS),
                DEFAULT_DENY_MESSAGE,
                RuleId::new(QUARANTINED_RULE),
                true,
            )
        }
    }

    /// 413 `_sign`: the body to sign is over `limits.max_sign_body_bytes`.
    /// The connection closes, since the body was not read to its end.
    pub(crate) fn sign_body_too_large() -> Self {
        Self {
            reason: Some(SIGN_BODY_TOO_LARGE.to_owned()),
            ..Self::deny(
                StatusCode::PAYLOAD_TOO_LARGE,
                DEFAULT_DENY_MESSAGE,
                RuleId::new(SIGN_RULE),
                true,
            )
        }
    }

    /// 400 `_sign`: a request header cannot be signed, so the request is
    /// not forwarded. The connection closes: its body may be unread.
    pub(crate) fn sign_header_invalid() -> Self {
        Self {
            reason: Some(SIGN_HEADER_INVALID.to_owned()),
            ..Self::deny(
                StatusCode::BAD_REQUEST,
                DEFAULT_DENY_MESSAGE,
                RuleId::new(SIGN_RULE),
                true,
            )
        }
    }

    /// 403 `_address_policy`.
    pub(crate) fn address_policy(reason: &str) -> Self {
        Self {
            reason: Some(reason.to_owned()),
            ..Self::deny(
                StatusCode::FORBIDDEN,
                DEFAULT_DENY_MESSAGE,
                RuleId::new(ADDRESS_POLICY_RULE),
                true,
            )
        }
    }

    /// 502/504 for an upstream failure. It says nothing about the client,
    /// so the connection stays open. `reason` goes to the flow log.
    pub(crate) fn upstream(status: StatusCode, reason: &str) -> Self {
        Self {
            kind: RefusalKind::UpstreamError,
            status,
            message: DEFAULT_DENY_MESSAGE.to_owned(),
            rule: None,
            close: false,
            reason: Some(reason.to_owned()),
        }
    }

    /// The deny response.
    pub(crate) fn response(&self, flow: &Ulid) -> CanonicalResponse {
        let mut body = serde_json::json!({
            "error": self.message,
            "flow": flow.to_string(),
        });
        if let Some(rule) = &self.rule {
            body["rule"] = serde_json::Value::String(rule.to_string());
        }
        let mut res = CanonicalResponse::new(self.status);
        let _ = res.headers.insert("content-type", "application/json");
        let _ = res.headers.insert("cache-control", "no-store");
        if let Some(rule) = &self.rule
            && res
                .headers
                .insert("x-roxy-rule", &rule.to_string())
                .is_err()
        {
            // A rule id that is not a valid header value is still in the body.
            tracing::debug!("rule id is not a valid header value");
        }
        res.body = Body::from_bytes(Bytes::from(body.to_string()));
        res.meta.close = self.close;
        res
    }
}

/// Outcome of the request steps. Consumed exhaustively by the exchange
/// driver: only `Continue` reaches the upstream.
#[allow(clippy::large_enum_variant)] // moved once per step, never stored
pub(crate) enum Verdict {
    /// Proceed with this (possibly mutated) request.
    Continue(CanonicalRequest),
    /// Answer locally (deny or fail-closed).
    Deny(Refusal),
    /// The client side ended the exchange (body framing, timeout, cap, a
    /// failed `100 Continue`): close.
    Close(DriveError),
}

/// Outcome of the response steps.
#[allow(clippy::large_enum_variant)]
pub(crate) enum ResponseVerdict {
    /// Send this (possibly mutated) response.
    Continue(CanonicalResponse),
    /// Replace it with a local answer.
    Deny(Refusal),
    /// The client side ended the exchange while the response was being
    /// inspected.
    Close(DriveError),
}

/// Body access a step needs from the client connection: buffering while
/// the codec keeps pumping the client's request body.
pub(crate) trait BodyIo: Send {
    /// [`collect_prefix`], with `meter` asked after each frame whether the
    /// bytes held so far may be kept and `idle` bounding the wait for each
    /// frame.
    fn collect<'a>(
        &'a mut self,
        body: &'a mut Body,
        cap: u64,
        meter: &'a mut (dyn FnMut(u64) -> bool + Send),
        idle: Option<Duration>,
    ) -> CollectFuture<'a, Result<Collected, DriveError>>;
}

impl BodyIo for ServerConn<ClientIo> {
    fn collect<'a>(
        &'a mut self,
        body: &'a mut Body,
        cap: u64,
        meter: &'a mut (dyn FnMut(u64) -> bool + Send),
        idle: Option<Duration>,
    ) -> CollectFuture<'a, Result<Collected, DriveError>> {
        Box::pin(self.drive(collect_prefix(body, cap, meter, idle)))
    }
}

/// The request side: inspect the body if a rule needs it, then the admission
/// decision and its effects, then the signature over the result if a
/// `sign` effect asked for one.
pub(crate) async fn request_steps(
    cx: &mut FlowCx,
    req: CanonicalRequest,
    io: &mut dyn BodyIo,
) -> Verdict {
    let req = match inspect_request_body(cx, req, io).await {
        Verdict::Continue(req) => req,
        Verdict::Deny(d) => return Verdict::Deny(d),
        Verdict::Close(e) => return Verdict::Close(e),
    };
    match request_rules(cx, req) {
        Verdict::Continue(mut req) => {
            // Settled with the effects, and before the signature, which
            // covers the request as it leaves. The in-flight rules and the
            // log see the request without the dropped fields.
            if crate::redact::request(cx, &mut req) {
                settle_request_facts(cx, &req);
            }
            sign_request(cx, req, io).await
        }
        Verdict::Deny(d) => Verdict::Deny(d),
        Verdict::Close(e) => Verdict::Close(e),
    }
}

/// The response side: inspect the body if a rule needs it, then the
/// in-flight rules at the response head.
pub(crate) async fn response_steps(
    cx: &mut FlowCx,
    res: CanonicalResponse,
    io: &mut dyn BodyIo,
) -> ResponseVerdict {
    match inspect_response_body(cx, res, io).await {
        ResponseVerdict::Continue(res) => response_rules(cx, res),
        ResponseVerdict::Deny(d) => ResponseVerdict::Deny(d),
        ResponseVerdict::Close(e) => ResponseVerdict::Close(e),
    }
}

// ---------------------------------------------------------------------------
// Per-flow context
// ---------------------------------------------------------------------------

/// One value for each direction of an exchange.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct PerDir<T> {
    pub request: T,
    pub response: T,
}

/// What the flow log needs about a flow.
#[derive(Debug, Default)]
pub(crate) struct FlowRecord {
    pub rules: Vec<RuleId>,
    pub mutations: Vec<String>,
    pub terminal_rule: Option<Decider>,
    pub reason: Option<String>,
    pub decision: Option<DecisionKind>,
    pub request_bytes: u64,
    pub response_bytes: u64,
    /// SHA-256 (hex) of each body, once it completed.
    pub request_sha256: Option<String>,
    pub response_sha256: Option<String>,
    pub response_status: Option<u16>,
    pub response_headers_bytes: u64,
    pub ttfb_ms: Option<u64>,
    /// How long opening the upstream connection took; `None` when a pooled
    /// connection was reused (or nothing was dialled).
    pub upstream_connect_ms: Option<u64>,
    /// Where the terminal decision was made.
    pub stage: Option<Stage>,
    /// The addons the exchange went through.
    pub addons: Vec<String>,
}

/// What identifies a flow and the world it runs in. Shared by everything
/// that logs or evaluates for the flow: the flow context, the in-flight
/// checker and the addon stack.
pub(crate) struct FlowMeta {
    pub shared: Arc<Shared>,
    pub snap: Arc<Snapshot>,
    pub flow: Ulid,
    pub client: ClientConn,
    /// `client.ip`: the canonical TCP peer address, or the client
    /// `forwarded_for` resolved from `X-Forwarded-For`. The one client
    /// identity of the exchange.
    pub client_ip: IpAddr,
    pub tls: Option<TlsInfo>,
    /// The secret generation this exchange resolves from and redacts
    /// with: loaded on first use (the admission evaluation) and kept for the
    /// exchange's life, however many swaps happen meanwhile.
    secrets: OnceLock<Arc<Secrets>>,
    /// The flow's tags: the one set the rules' `tag` actions and the
    /// layers' `add-tag` write to, and `tag[..]`, the layers' `when`,
    /// `flow.current` and the flow log read. Shared rather than copied
    /// about so that a tag reaches every reader after the writer, whether
    /// the writer was a rule or a layer.
    tags: Mutex<Vec<String>>,
}

impl FlowMeta {
    pub(crate) fn conn_id(&self) -> String {
        self.client.id.to_string()
    }

    /// The flow's tags so far.
    pub(crate) fn tags(&self) -> Vec<String> {
        self.tags_mut().clone()
    }

    /// The flow's tags, to read or add to. Hold the guard for no longer
    /// than one evaluation: a layer's `add-tag` waits on it.
    pub(crate) fn tags_mut(&self) -> MutexGuard<'_, Vec<String>> {
        self.tags.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn client_info(&self) -> ClientInfo {
        client_info_as(&self.client, self.client_ip)
    }

    pub(crate) fn secrets(&self) -> &Arc<Secrets> {
        self.secrets.get_or_init(|| self.snap.secrets.load())
    }

    pub(crate) fn input_unavailable(
        &self,
        stage: Stage,
        code: &str,
        reason: &FailClosedReason,
        metric_err: Option<&MetricSourceError>,
    ) {
        let ts = chrono::Utc::now();
        if let Some(e @ MetricSourceError::TableFull(_)) = metric_err {
            self.shared.sink.emit(&FlowEvent::MetricTableFull {
                ts,
                flow: self.flow.to_string(),
                conn: self.conn_id(),
                stage,
                detail: e.to_string(),
            });
        }
        let reason = self
            .secrets()
            .redactor()
            .redact_str(&reason.to_string())
            .into_owned();
        tracing::warn!(flow = %self.flow, stage = stage.as_str(), code, %reason, "policy input unavailable; failing closed");
        self.shared.sink.emit(&FlowEvent::PolicyInputUnavailable {
            ts,
            flow: self.flow.to_string(),
            conn: self.conn_id(),
            stage,
            reason: format!("{code}: {reason}"),
        });
    }

    pub(crate) fn metric_error(&self, stage: Stage, e: &MetricSourceError) {
        let detail = self
            .secrets()
            .redactor()
            .redact_str(&e.to_string())
            .into_owned();
        tracing::warn!(flow = %self.flow, stage = stage.as_str(), error = %detail, "metric recording failed; failing closed");
        let ts = chrono::Utc::now();
        if matches!(e, MetricSourceError::TableFull(_)) {
            self.shared.sink.emit(&FlowEvent::MetricTableFull {
                ts,
                flow: self.flow.to_string(),
                conn: self.conn_id(),
                stage,
                detail,
            });
        } else {
            self.shared.sink.emit(&FlowEvent::PolicyInputUnavailable {
                ts,
                flow: self.flow.to_string(),
                conn: self.conn_id(),
                stage,
                reason: format!("{}: {detail}", e.code()),
            });
        }
    }

    pub(crate) fn rule_log(&self, stage: Stage, level: LogLevel, message: &str) {
        let message = self.secrets().redactor().redact_str(message).into_owned();
        match level {
            LogLevel::Trace => tracing::trace!(flow = %self.flow, %message, "rule log"),
            LogLevel::Debug => tracing::debug!(flow = %self.flow, %message, "rule log"),
            LogLevel::Info => tracing::info!(flow = %self.flow, %message, "rule log"),
            LogLevel::Warn => tracing::warn!(flow = %self.flow, %message, "rule log"),
            LogLevel::Error => tracing::error!(flow = %self.flow, %message, "rule log"),
        }
        self.shared.sink.emit(&FlowEvent::Log {
            ts: chrono::Utc::now(),
            flow: self.flow.to_string(),
            conn: self.conn_id(),
            stage,
            level: level.as_str().to_owned(),
            message,
        });
    }
}

/// Per-flow state shared by the steps. Derefs to its [`FlowMeta`].
pub(crate) struct FlowCx {
    pub meta: Arc<FlowMeta>,
    pub facts: FlowFacts,
    pub opts: AllowOpts,
    pub record: FlowRecord,
    pub completion: crate::exchange::Completion,
    pub started: Instant,
    /// The in-flight rules of this exchange, once it is forwarded.
    pub in_flight: Option<Arc<InFlight>>,
    /// Capture this exchange's request / response: set by a
    /// `capture` effect at admission, or for every exchange with
    /// `log.capture.all`.
    pub capture: PerDir<bool>,
    /// Hash this exchange's request / response body for the flow
    /// record's `body_sha256`: set by a `digest` effect at admission.
    pub digest: PerDir<bool>,
    /// Capture taps not yet handed to a body adapter (the WebSocket relay
    /// takes them after the `101`).
    pub taps: PerDir<Option<Tap>>,
    /// `Host` to send upstream after a `redirect` without `rewrite_host`.
    pub host_override: Option<String>,
    /// A `sign` effect of the admission decision, applied once every other
    /// request change has settled.
    pub sign: Option<AwsSigV4>,
    /// The secret values `set_header` effects put into the forwarded
    /// request: what an upstream could echo that the client never held.
    pub injected: Vec<String>,
    /// Request body bytes forwarded so far (and their digest once the
    /// body completed), once the request is on its way.
    pub request_tally: Option<Arc<crate::body::Tally>>,
    pub request_delivery: Option<crate::body::Delivery>,
    /// Child work retained through final exchange accounting.
    pub tasks: tokio_util::task::TaskTracker,
    /// The addon stack this exchange went through (set once the stack has
    /// handed the flow back), folded into the record when it is logged.
    pub stack: Option<Arc<crate::addons::StackFlow>>,
    /// An addon layer that ran on this request reads a body: on an upgrade,
    /// it is in the WebSocket's byte path.
    pub layer_reads_bytes: bool,
    /// Where the core hands its response, and what it decoded it from.
    pub response_leg: crate::recode::Leg,
    /// The exchange's share of the buffer budget, held until it ends: the
    /// buffered body text stays with the facts for as long as the flow.
    pub buffers: Vec<BufferLease>,
    /// The `request` event went out. Dropping an unlogged flow logs it as
    /// `aborted`, so an exchange cut off by its connection ending or the
    /// server stopping is never missing from the log.
    logged: bool,
}

impl std::ops::Deref for FlowCx {
    type Target = FlowMeta;

    fn deref(&self) -> &FlowMeta {
        &self.meta
    }
}

impl Drop for FlowCx {
    fn drop(&mut self) {
        drop(self.request_delivery.take());
        if !self.logged {
            self.record
                .reason
                .get_or_insert_with(|| "aborted".to_owned());
            self.emit_request_event();
        }
    }
}

pub(crate) fn request_facts(req: &CanonicalRequest) -> RequestFacts {
    RequestFacts {
        method: req.method.clone(),
        scheme: req.scheme,
        host: req.authority.host.clone(),
        port: req.authority.port,
        path: req.path.as_str().to_owned(),
        query: req.query.clone(),
        headers: req.headers.clone(),
        upgrade: req.meta.upgrade.clone(),
        body_size: req.body.known_length(),
        body: Inspected::NotBuffered,
        head_bytes: req.meta.head_bytes,
    }
}

/// The TCP peer as a client identity. An IPv4-mapped address (how an IPv4
/// client reaches a dual-stack `[::]` listener) is the IPv4 address, and
/// that is the only equivalence, as in a rule's `==` and `in`: a rule may
/// `allow` on `client.ip`, so an IPv4-compatible or translated form is not
/// the address it embeds.
fn peer_ip(c: &ClientConn) -> IpAddr {
    c.peer.ip().to_canonical()
}

/// `client` for an event with no exchange (a refused connection, a
/// CONNECT, a head that did not parse): nothing has named a client but the
/// TCP peer.
pub(crate) fn client_info(c: &ClientConn) -> ClientInfo {
    client_info_as(c, peer_ip(c))
}

fn client_info_as(c: &ClientConn, ip: IpAddr) -> ClientInfo {
    ClientInfo {
        ip,
        peer: PeerInfo {
            ip: c.peer.ip(),
            port: c.peer.port(),
        },
    }
}

pub(crate) fn ms(d: std::time::Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// Query for the log: keys kept, values redacted.
fn redact_query(q: &Query) -> String {
    q.as_str()
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, _)) => format!("{k}={}", crate::flowlog::REDACTED),
            None => p.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("&")
}

impl FlowCx {
    pub(crate) fn new(
        shared: Arc<Shared>,
        snap: Arc<Snapshot>,
        client: ClientConn,
        tls: Option<TlsInfo>,
        req: &CanonicalRequest,
    ) -> Result<Self, ParseError> {
        // Identity first: the rules, metric keys and the flow log all key
        // on it, so an exchange whose client cannot be named never starts.
        let client_ip = match client.listener.forwarded_for {
            Some(f) => crate::forwarded::client_ip(&req.headers, f.trusted_hops)?,
            None => peer_ip(&client),
        };
        let facts = FlowFacts {
            client: client.clone(),
            client_ip,
            tls: tls.clone(),
            client_request: Some(request_facts(req)),
            request: Some(request_facts(req)),
            response: None,
            request_body_bytes: None,
            response_body_bytes: None,
            ws: None,
        };
        Ok(Self {
            meta: Arc::new(FlowMeta {
                shared,
                snap,
                flow: Ulid::generate(),
                client,
                client_ip,
                tls,
                secrets: OnceLock::new(),
                tags: Mutex::new(Vec::new()),
            }),
            facts,
            opts: AllowOpts::default(),
            record: FlowRecord::default(),
            completion: crate::exchange::Completion::default(),
            started: Instant::now(),
            in_flight: None,
            capture: PerDir::default(),
            digest: PerDir::default(),
            taps: PerDir::default(),
            host_override: None,
            sign: None,
            injected: Vec::new(),
            request_tally: None,
            request_delivery: None,
            tasks: {
                let tasks = tokio_util::task::TaskTracker::new();
                tasks.close();
                tasks
            },
            stack: None,
            layer_reads_bytes: false,
            response_leg: crate::recode::Leg::Direct,
            buffers: Vec::new(),
            logged: false,
        })
    }

    fn note_outcome(&mut self, out: &Outcome) {
        for r in &out.matched {
            if !self.record.rules.contains(r) {
                self.record.rules.push(r.clone());
            }
        }
        let mut tags = self.meta.tags_mut();
        for t in &out.tags {
            if !tags.contains(t) {
                tags.push(t.clone());
            }
        }
        drop(tags);
        if !out.terminal_rule.as_str().starts_with('_')
            && !self.record.rules.contains(&out.terminal_rule)
        {
            self.record.rules.push(out.terminal_rule.clone());
        }
    }

    /// The refusal every exchange gets, whatever its request, while the
    /// process is quarantined or the policy's lease has run out. Recorded
    /// as the admission decision. Every site that admits a request checks
    /// it, so a request a layer held is refused if either began while it
    /// was held. The quarantine comes first: it outlives any policy.
    pub(crate) fn blanket_refusal(&mut self) -> Option<Refusal> {
        let refusal = self
            .quarantined()
            .or_else(|| self.shared.expired().then(Refusal::expired))?;
        self.refused_at_admission();
        Some(refusal)
    }

    /// The quarantine refusal for an exchange that has been through the addon
    /// stack. An admission decision the rules made stands, sample and stage
    /// included; a stack that answered without `next` left none, and the
    /// refusal is then the exchange's decision, as above the stack.
    pub(crate) fn late_quarantine_refusal(&mut self) -> Option<Refusal> {
        let refusal = self.quarantined()?;
        if self.record.stage.is_none() {
            self.refused_at_admission();
        }
        Some(refusal)
    }

    fn quarantined(&self) -> Option<Refusal> {
        self.shared.quarantined().then(Refusal::quarantined)
    }

    /// Records a refusal made in place of the admission decision.
    fn refused_at_admission(&mut self) {
        self.record.stage = Some(Stage::Head);
        if let Err(e) = self.record_admission_sample(true) {
            self.meta.metric_error(Stage::Head, &e);
        }
    }

    /// A matched `quarantine` action puts the process into quarantine,
    /// whatever else the admission decision was.
    fn trip_quarantine_if_matched(&self, out: &Outcome) {
        if let Some(rule) = &out.quarantine {
            self.shared.trip_quarantine(QuarantineCause::Rule {
                rule: rule.to_string(),
                flow: self.flow.to_string(),
            });
        }
    }

    /// The admission decision. Returns the outcome plus a refusal when it
    /// denies or an input was unavailable.
    fn evaluate_admission(&mut self) -> (Outcome, Option<Refusal>) {
        let snap = self.snap.clone();
        let shared = self.shared.clone();
        let generation = self.meta.secrets().clone();
        let secrets = |name: &str| generation.get(name);
        let tags = self.meta.tags();
        let ctx = EvalContext {
            secrets: &secrets,
            initial_tags: &tags,
        };
        let view = ProxyView::new(
            &self.facts,
            &*shared.metrics,
            &*shared.state,
            &snap.address_lists,
        );
        let out = snap.policy.evaluate_admission(&view, &ctx);
        let metric_err = view.take_metric_error();
        drop(view);
        self.note_outcome(&out);
        self.record.stage = Some(Stage::Head);
        let mut refusal = None;
        if let Some(reason) = &out.fail_closed_reason {
            let code = fail_closed_code(reason, metric_err.as_ref());
            self.meta
                .input_unavailable(Stage::Head, code, reason, metric_err.as_ref());
            refusal = Some(Refusal::fail_closed(code));
        } else {
            match &out.decision {
                Decision::Deny(Deny {
                    status,
                    message,
                    close,
                }) => {
                    refusal = Some(Refusal::deny(
                        status_code(*status),
                        message,
                        out.terminal_rule.clone(),
                        *close,
                    ));
                }
                Decision::Allow(_) => {}
            }
        }
        (out, refusal)
    }

    /// Records the exchange's admission metric sample, once the admission
    /// step's outcome is settled (`denied`).
    fn record_admission_sample(&self, denied: bool) -> Result<(), MetricSourceError> {
        let view = ProxyView::new(
            &self.facts,
            &*self.shared.metrics,
            &*self.shared.state,
            &self.snap.address_lists,
        );
        let sample = Sample {
            admission: true,
            denied,
            ..Sample::default()
        };
        self.shared.metrics.record(&view, &sample)
    }

    /// Emits the flow's `request` event.
    pub(crate) fn emit_request_event(&mut self) {
        self.logged = true;
        if let Some(st) = self.stack.take() {
            st.fold_into(self);
        } else if let Some(reason) = self.completion.reason(None) {
            self.record.reason.get_or_insert(reason);
        }
        self.absorb_in_flight();
        if let Some(t) = &self.request_tally {
            self.record.request_bytes = t.bytes();
            self.record.request_sha256 = t.sha256_hex();
        }
        let redactor = self.meta.secrets().redactor();
        let r = self.facts.client_request.as_ref();
        let record = &self.record;
        let req = RequestInfo {
            method: r
                .map(|r| Cow::Borrowed(r.method.as_str()))
                .unwrap_or_default(),
            host: r.map(|r| host_str(&r.host)).unwrap_or_default(),
            port: r.map_or(0, |r| r.port),
            path: r.map(|r| redactor.redact_str(&r.path)).unwrap_or_default(),
            query: r
                .and_then(|r| r.query.as_ref())
                .map(|q| Cow::Owned(redactor.redact_str(&redact_query(q)).into_owned())),
            headers_bytes: r.map_or(0, |r| r.head_bytes as u64),
            body_bytes: record.request_bytes,
            body_sha256: record.request_sha256.as_deref().map(Cow::Borrowed),
            content_type: r
                .and_then(|r| r.headers.get("content-type"))
                .map(|v| redactor.redact_header("content-type", v)),
        };
        let res = record.response_status.map(|status| ResponseInfo {
            status,
            headers_bytes: record.response_headers_bytes,
            body_bytes: record.response_bytes,
            body_sha256: record.response_sha256.as_deref().map(Cow::Borrowed),
        });
        let (mut flow_id, mut conn_id) = ([0; ulid::ULID_LEN], [0; ulid::ULID_LEN]);
        self.shared.sink.emit(&FlowEvent::Request {
            ts: chrono::Utc::now(),
            flow: Cow::Borrowed(self.flow.array_to_str(&mut flow_id)),
            conn: Cow::Borrowed(self.meta.client.id.array_to_str(&mut conn_id)),
            listener: Cow::Borrowed(&self.meta.client.listener.name),
            client: self.meta.client_info(),
            tls: self.meta.tls.as_ref().map(Cow::Borrowed),
            req,
            res,
            decision: record.decision.unwrap_or(DecisionKind::Deny),
            rules: Cow::Borrowed(&record.rules),
            tags: Cow::Owned(self.meta.tags()),
            mutations: Cow::Borrowed(&record.mutations),
            addons: Cow::Borrowed(&record.addons),
            timing: Timing {
                total_ms: ms(self.started.elapsed()),
                upstream_connect_ms: record.upstream_connect_ms,
                upstream_ttfb_ms: record.ttfb_ms,
            },
            terminal_rule: record.terminal_rule.as_ref().map(Decider::name),
            reason: record.reason.as_deref().map(Cow::Borrowed),
            stage: record.stage,
        });
    }

    /// An in-flight rule stopped the exchange.
    fn stopped(&self) -> bool {
        self.in_flight
            .as_ref()
            .is_some_and(|w| w.stopped().is_some())
    }

    /// Records the final metric sample of an exchange whose response was
    /// sent (or failed to reach the client, which is not an upstream
    /// error): `denied` if an in-flight rule stopped it. Bytes were recorded
    /// as they streamed.
    pub(crate) fn record_final_sample(&self) {
        self.final_sample(self.stopped(), false);
    }

    /// Records the final metric sample of an exchange refused after the
    /// forwarding decision: `denied` for a deny (an in-flight stop, the
    /// address floor, an invalid upgrade), `error` for an upstream failure.
    pub(crate) fn record_refusal_sample(&self, refusal: &Refusal) {
        let denied = refusal.kind == RefusalKind::Deny || self.stopped();
        self.final_sample(denied, refusal.kind == RefusalKind::UpstreamError);
    }

    fn final_sample(&self, denied: bool, error: bool) {
        let sample = Sample {
            denied,
            error,
            ..Sample::default()
        };
        if sample == Sample::default() {
            return;
        }
        let view = ProxyView::new(
            &self.facts,
            &*self.shared.metrics,
            &*self.shared.state,
            &self.snap.address_lists,
        );
        if let Err(e) = self.shared.metrics.record(&view, &sample) {
            // The response has already been sent; the next flow that needs
            // the missing key fails closed at its decision.
            drop(view);
            let stage = self.record.stage.unwrap_or(Stage::ResponseBody);
            self.meta.metric_error(stage, &e);
        }
    }

    /// Folds the in-flight checker's outcome (in-flight rules that matched,
    /// response mutations, a stop) into the flow record. Call once the
    /// exchange is over, before logging it.
    pub(crate) fn absorb_in_flight(&mut self) {
        let Some(w) = self.in_flight.clone() else {
            return;
        };
        let summary = w.summary();
        for r in summary.rules {
            if !self.record.rules.contains(&r) {
                self.record.rules.push(r);
            }
        }
        self.record.mutations.extend(summary.mutations);
        if let Some(stop) = summary.stop {
            self.record.decision = Some(DecisionKind::Deny);
            self.record.terminal_rule.clone_from(&stop.refusal.rule);
            if stop.refusal.reason.is_some() {
                self.record.reason.clone_from(&stop.refusal.reason);
            }
            self.record.stage = Some(stop.stage);
        }
    }
}

/// Emits a `connect` event for a CONNECT accepted for inspection. No
/// connect-time rules exist, so the event carries none and its decision
/// is always `allow`.
pub(crate) fn emit_connect_event(shared: &Shared, client: &ClientConn, authority: &Authority) {
    if !shared.connection_events {
        return;
    }
    shared.sink.emit(&FlowEvent::Connect {
        ts: chrono::Utc::now(),
        conn: client.id.to_string(),
        listener: client.listener.name.clone(),
        client: client_info(client),
        dst: DstInfo {
            host: host_text(&authority.host),
            port: authority.port,
            ip: None,
        },
        tls: None,
        decision: DecisionKind::Allow,
        rules: Vec::new(),
    });
}

pub(crate) fn fail_closed_code(
    reason: &FailClosedReason,
    metric: Option<&MetricSourceError>,
) -> &'static str {
    match reason {
        FailClosedReason::MetricUnavailable(_) => {
            metric.map_or("metric_unavailable", MetricSourceError::code)
        }
        FailClosedReason::AddressListUnavailable(_) => "address_list_unavailable",
        FailClosedReason::SecretMissing(_) => "secret_missing",
        FailClosedReason::SecretInvalid(_) => "secret_invalid",
        FailClosedReason::BodyTooLargeToInspect(_) => "body_too_large_to_inspect",
        FailClosedReason::BodyUnavailable(_) => "body_unavailable",
        FailClosedReason::UnsupportedContentEncoding { .. } => "unsupported_content_encoding",
        FailClosedReason::BodyDecodeFailed { .. } => "body_decode_failed",
        FailClosedReason::MissingValue(_) => "missing_value",
        FailClosedReason::WrongType { .. } => "wrong_type",
    }
}

/// Maps a failed body to the parse error that closes the connection.
pub(crate) fn body_failure(e: &BodyError) -> ParseError {
    match e {
        BodyError::Invalid(pe) => pe.clone(),
        BodyError::TooLarge { .. } => ParseError::new(Reason::BodyTooLarge, e.to_string()),
        BodyError::Timeout => ParseError::new(Reason::BodyTimeout, e.to_string()),
        BodyError::LengthMismatch
        | BodyError::Incomplete
        | BodyError::Closed
        | BodyError::Abandoned
        | BodyError::Upstream(_)
        | BodyError::Stopped
        | BodyError::Undecodable(_)
        | BodyError::BudgetExhausted => ParseError::new(Reason::UnexpectedEof, e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Request steps
// ---------------------------------------------------------------------------

/// Bounded buffering in front of body-inspecting rules.
async fn inspect_request_body(
    cx: &mut FlowCx,
    mut req: CanonicalRequest,
    io: &mut dyn BodyIo,
) -> Verdict {
    if !cx.snap.policy.needs_request_body() {
        return Verdict::Continue(req);
    }
    if known_empty(&req.body) {
        if let Some(f) = cx.facts.request.as_mut() {
            f.body_size = Some(0);
            f.body = Inspected::empty();
        }
        return Verdict::Continue(req);
    }
    let cap = cx.snap.limits.max_inspect_body_bytes;
    let Some(mut lease) = reserve_decoded_inspection(cx, &req.headers, &req.body, cap) else {
        return Verdict::Deny(Refusal::fail_closed(budget::EXHAUSTED));
    };
    let shared = cx.shared.clone();
    let mut meter = |held: u64| shared.grow_buffer(&mut lease, held);
    let inspected = match io.collect(&mut req.body, cap, &mut meter, None).await {
        Err(e) => return Verdict::Close(e),
        Ok(Collected::Failed(e)) => return Verdict::Close(body_failure(&e).into()),
        Ok(Collected::Complete { data, held }) => {
            if let Some(f) = cx.facts.request.as_mut() {
                f.body_size = Some(data.len() as u64);
            }
            let inspected = match Inspected::decode(&req.headers, &data, cap, &cx.shared) {
                Ok(i) => i,
                Err(Exhausted) => return Verdict::Deny(Refusal::fail_closed(budget::EXHAUSTED)),
            };
            lease.shrink_to(buffered_bytes(held, &inspected));
            inspected
        }
        Ok(Collected::TooLarge { held }) => {
            lease.shrink_to(held);
            Inspected::TooLarge
        }
        Ok(Collected::BudgetExhausted) => {
            return Verdict::Deny(Refusal::fail_closed(budget::EXHAUSTED));
        }
    };
    cx.buffers.push(lease);
    if let Some(f) = cx.facts.request.as_mut() {
        f.body = inspected;
    }
    Verdict::Continue(req)
}

/// A body that carries no bytes needs no inspection buffer; the rules see
/// it as empty text.
pub(crate) fn known_empty(body: &Body) -> bool {
    body.known_length() == Some(0) || http_body::Body::is_end_stream(body)
}

/// Reserves the budget a body held as sent can need: its declared length
/// when the framing gives one, else the whole cap.
fn reserve_inspection(cx: &FlowCx, body: &Body, cap: u64) -> Option<BufferLease> {
    let bytes = body.known_length().map_or(cap, |n| n.min(cap));
    cx.shared.reserve_buffer(bytes)
}

/// Reserves the budget a body inspected by the rules can need. The facts
/// hold the body decoded by its `content-encoding`, which can be any size
/// up to the cap whatever length the framing declares, so an encoded body
/// reserves the whole cap.
fn reserve_decoded_inspection(
    cx: &FlowCx,
    headers: &Headers,
    body: &Body,
    cap: u64,
) -> Option<BufferLease> {
    let encoded = roxy_http::coding::content_codings(headers).is_ok_and(|c| !c.is_empty());
    if encoded {
        cx.shared.reserve_buffer(cap)
    } else {
        reserve_inspection(cx, body, cap)
    }
}

/// What a completely buffered body holds for the rest of the exchange: the
/// bytes as sent with their trailers (they go on to be forwarded) and, if
/// `content-encoding` was decoded, the text the facts carry, which can be
/// larger.
fn buffered_bytes(held: u64, inspected: &Inspected) -> u64 {
    let text = if let Inspected::Text(t) = inspected {
        t.len() as u64
    } else {
        0
    };
    held.max(text)
}

/// The admission decision and its effects.
fn request_rules(cx: &mut FlowCx, mut req: CanonicalRequest) -> Verdict {
    // A layer above may have quarantined the process, or held the request
    // past the lease; nothing of such an exchange is forwarded.
    if let Some(refusal) = cx.blanket_refusal() {
        return Verdict::Deny(refusal);
    }
    let (out, mut refusal) = cx.evaluate_admission();
    cx.trip_quarantine_if_matched(&out);
    // Request changes apply to an allowed request only (a refused outcome
    // carries none). `log` and `set_state` apply whatever the outcome, in
    // rule order, once the request changes are settled, so a failing change
    // never leaves only some of them behind.
    let (changes, side_effects): (Vec<Effect>, Vec<Effect>) = out
        .effects
        .into_iter()
        .partition(|e| !matches!(e, Effect::Log { .. } | Effect::SetState { .. }));
    if refusal.is_none() {
        if let Decision::Allow(opts) = &out.decision {
            cx.opts = *opts;
        }
        refusal = changes
            .into_iter()
            .try_for_each(|e| apply_request_effect(cx, &mut req, e))
            .err();
    }
    for effect in side_effects {
        if let Err(r) = apply_request_effect(cx, &mut req, effect) {
            refusal.get_or_insert(r);
        }
    }
    // The admission sample counts the outcome as it finally stands.
    if let Err(e) = cx.record_admission_sample(refusal.is_some())
        && refusal.is_none()
    {
        cx.meta.metric_error(Stage::Head, &e);
        refusal = Some(Refusal::fail_closed(e.code()));
    }
    cx.record.terminal_rule = match &refusal {
        Some(r) => r.rule.clone(),
        None => Some(Decider::Rule(out.terminal_rule.clone())),
    };
    if let Some(r) = refusal {
        return Verdict::Deny(r);
    }
    settle_request_facts(cx, &req);
    Verdict::Continue(req)
}

/// The in-flight rules and the log see the request as it will be
/// forwarded; what was learnt about the body stays.
fn settle_request_facts(cx: &mut FlowCx, req: &CanonicalRequest) {
    let body = cx
        .facts
        .request
        .as_ref()
        .map(|r| (r.body.clone(), r.body_size));
    let mut facts = request_facts(req);
    if let Some((inspected, size)) = body {
        facts.body = inspected;
        facts.body_size = size;
    }
    cx.facts.request = Some(facts);
}

/// The `sign` effect, over the request as every other effect left it. A
/// presigned request (`X-Amz-Signature` in its query) authenticates by its
/// query and goes out without roxy's signature, the client's signature
/// headers stripped. The payload hash needs the whole body, so it is
/// buffered under `limits.max_sign_body_bytes`; a body over that is
/// refused with 413 rather than forwarded with a signature AWS would
/// reject. `unsigned_payload` streams the body instead.
async fn sign_request(cx: &mut FlowCx, mut req: CanonicalRequest, io: &mut dyn BodyIo) -> Verdict {
    let Some(spec) = cx.sign.take() else {
        return Verdict::Continue(req);
    };
    if sign::is_presigned(req.query.as_ref()) {
        sign::strip_client_signature(&mut req);
        cx.record.mutations.push(SIGN_PRESIGNED.to_owned());
        settle_request_facts(cx, &req);
        return Verdict::Continue(req);
    }
    let buffered;
    let body = if spec.unsigned_payload {
        SignableBody::UnsignedPayload
    } else if known_empty(&req.body) {
        SignableBody::Bytes(&[])
    } else if let Some(b) = req.body.as_bytes() {
        // Already buffered (inspected for the rules); its lease is held.
        buffered = b.clone();
        SignableBody::Bytes(&buffered)
    } else {
        // A declared length is reserved up front; a chunked body grows its
        // reservation as it is read, since the cap is far above the usual
        // body and reserving it whole would starve other exchanges.
        let cap = cx.snap.limits.max_sign_body_bytes;
        let declared = req.body.known_length().map_or(0, |n| n.min(cap));
        let Some(mut lease) = cx.shared.reserve_buffer(declared) else {
            return Verdict::Deny(Refusal::fail_closed(budget::EXHAUSTED));
        };
        let shared = cx.shared.clone();
        let mut meter = |held: u64| shared.grow_buffer(&mut lease, held);
        buffered = match io.collect(&mut req.body, cap, &mut meter, None).await {
            Err(e) => return Verdict::Close(e),
            Ok(Collected::Failed(e)) => return Verdict::Close(body_failure(&e).into()),
            Ok(Collected::TooLarge { .. }) => return Verdict::Deny(Refusal::sign_body_too_large()),
            Ok(Collected::BudgetExhausted) => {
                return Verdict::Deny(Refusal::fail_closed(budget::EXHAUSTED));
            }
            Ok(Collected::Complete { data, held }) => {
                lease.shrink_to(held);
                data
            }
        };
        cx.buffers.push(lease);
        if let Some(f) = cx.facts.request.as_mut() {
            f.body_size = Some(buffered.len() as u64);
        }
        SignableBody::Bytes(&buffered)
    };
    let host = cx
        .host_override
        .clone()
        .unwrap_or_else(|| req.authority.to_host_header(req.scheme));
    match sign::sign_request(&mut req, &host, body, &spec, SystemTime::now()) {
        Ok(()) => {}
        Err(e @ sign::SignError::UnsignableHeader(_)) => {
            tracing::info!(flow = %cx.flow, error = %e, "request cannot be signed; denying");
            return Verdict::Deny(Refusal::sign_header_invalid());
        }
        Err(e) => return Verdict::Deny(invalid("sign", &e)),
    }
    cx.record.mutations.push("sign:aws_sigv4".to_owned());
    settle_request_facts(cx, &req);
    Verdict::Continue(req)
}

fn invalid(what: &str, e: &dyn std::fmt::Display) -> Refusal {
    tracing::warn!(effect = what, error = %e, "rule effect produced an invalid request; denying");
    Refusal::fail_closed("effect_invalid")
}

/// Sets or removes `key` in a query, rebuilding it through the URL
/// normaliser. Other pairs keep their raw form and order.
fn edit_query(
    q: Option<&Query>,
    key: &str,
    value: Option<&str>,
) -> Result<Option<Query>, ParseError> {
    fn enc(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                out.push(char::from(b));
            } else {
                let _ = write!(out, "%{b:02X}");
            }
        }
        out
    }
    let mut parts: Vec<String> = Vec::new();
    let mut replaced = false;
    if let Some(q) = q {
        for seg in q.as_str().split('&').filter(|s| !s.is_empty()) {
            let raw_key = seg.split_once('=').map_or(seg, |(k, _)| k);
            let decoded = Query::try_from(raw_key)
                .ok()
                .and_then(|k| k.pairs().next().map(|(k, _)| k.into_owned()));
            if decoded.as_deref() == Some(key) {
                if let Some(v) = value
                    && !replaced
                {
                    parts.push(format!("{}={}", enc(key), enc(v)));
                    replaced = true;
                }
                continue;
            }
            parts.push(seg.to_owned());
        }
    }
    if let Some(v) = value
        && !replaced
    {
        parts.push(format!("{}={}", enc(key), enc(v)));
    }
    if parts.is_empty() {
        return Ok(None);
    }
    normalize_query(parts.join("&").as_bytes()).map(Some)
}

fn rules_scheme(s: roxy_rules::Scheme) -> Scheme {
    match s {
        roxy_rules::Scheme::Http => Scheme::Http,
        roxy_rules::Scheme::Https => Scheme::Https,
    }
}

/// Applies one effect of the admission decision. Any failure denies the
/// flow.
fn apply_request_effect(
    cx: &mut FlowCx,
    req: &mut CanonicalRequest,
    effect: Effect,
) -> Result<(), Refusal> {
    let kind = effect.kind();
    match effect {
        Effect::SetHeader { name, value } => {
            req.headers
                .insert(&name, value.as_str())
                .map_err(|e| invalid(kind, &e))?;
            cx.injected.extend_from_slice(value.secrets());
            cx.record.mutations.push(format!("set_header:{name}"));
        }
        Effect::RemoveHeader(name) => {
            req.headers.remove(&name);
            cx.record.mutations.push(format!("remove_header:{name}"));
        }
        Effect::RewritePath { regex, to } => {
            let path = req.path.as_str().to_owned();
            if regex.is_match(&path) {
                let new = regex.replace(&path, to.as_str());
                req.path = normalize_path(new.as_bytes()).map_err(|e| invalid(kind, &e))?;
                cx.record.mutations.push("rewrite_path".into());
            }
        }
        Effect::SetQuery { key, value } => {
            req.query = edit_query(req.query.as_ref(), &key, Some(&value))
                .map_err(|e| invalid(kind, &e))?;
            cx.record.mutations.push(format!("set_query:{key}"));
        }
        Effect::RemoveQuery(key) => {
            req.query =
                edit_query(req.query.as_ref(), &key, None).map_err(|e| invalid(kind, &e))?;
            cx.record.mutations.push(format!("remove_query:{key}"));
        }
        Effect::Redirect {
            host,
            port,
            scheme,
            rewrite_host,
        } => {
            if rewrite_host {
                cx.host_override = None;
            } else if cx.host_override.is_none() {
                cx.host_override = Some(req.authority.to_host_header(req.scheme));
            }
            req.authority = Authority::new(host, port.get());
            if let Some(s) = scheme {
                req.scheme = rules_scheme(s);
            }
            // The address floor and deny lists check the new target's
            // addresses when the upstream connects.
            cx.record
                .mutations
                .push(format!("redirect:{}://{}", req.scheme, req.authority));
        }
        Effect::Log { level, message } => cx.meta.rule_log(Stage::Head, level, &message),
        Effect::SetState { key, value, ttl } => {
            cx.shared
                .state
                .set(&key, &value, ttl)
                .map_err(|_| Refusal::fail_closed("state_unavailable"))?;
        }
        Effect::Capture(target) => {
            // `roxy run` refuses `capture` without a capture log; deny
            // defensively if one is somehow missing.
            if cx.shared.capture.is_none() {
                return Err(Refusal::fail_closed("capture_unavailable"));
            }
            cx.capture.request |= matches!(target, CaptureTarget::Request | CaptureTarget::Both);
            cx.capture.response |= matches!(target, CaptureTarget::Response | CaptureTarget::Both);
        }
        Effect::Digest(target) => {
            cx.digest.request |= matches!(target, CaptureTarget::Request | CaptureTarget::Both);
            cx.digest.response |= matches!(target, CaptureTarget::Response | CaptureTarget::Both);
        }
        Effect::Sign(spec) => {
            // Two rules signing one request is a policy mistake (which
            // identity did the author mean?), so it is an error rather
            // than last-wins.
            if cx.sign.replace(spec).is_some() {
                return Err(Refusal::fail_closed("sign_conflict"));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Response steps
// ---------------------------------------------------------------------------

/// Bounded buffering of the response body for `response.body.text`.
async fn inspect_response_body(
    cx: &mut FlowCx,
    mut res: CanonicalResponse,
    io: &mut dyn BodyIo,
) -> ResponseVerdict {
    cx.facts.response = Some(ResponseFacts {
        status: res.status,
        headers: res.headers.clone(),
        body_size: res.body.known_length(),
        body: Inspected::NotBuffered,
    });
    if !cx.snap.policy.needs_response_body() {
        return ResponseVerdict::Continue(res);
    }
    if response_known_empty(cx, &res) {
        if let Some(f) = cx.facts.response.as_mut() {
            f.body_size = Some(0);
            f.body = Inspected::empty();
        }
        return ResponseVerdict::Continue(res);
    }
    let cap = cx.snap.limits.max_inspect_body_bytes;
    let Some(mut lease) = reserve_decoded_inspection(cx, &res.headers, &res.body, cap) else {
        return ResponseVerdict::Deny(Refusal::fail_closed(budget::EXHAUSTED));
    };
    let shared = cx.shared.clone();
    let mut meter = |held: u64| shared.grow_buffer(&mut lease, held);
    let idle = Some(cx.snap.limits.response_body_idle_timeout);
    let inspected = match io.collect(&mut res.body, cap, &mut meter, idle).await {
        Err(e) => return ResponseVerdict::Close(e),
        // The same stall the transport would cut mid-body, caught before the
        // head went out: the client gets an answer instead of a cut.
        Ok(Collected::Failed(BodyError::Timeout)) => {
            let e = WriteFailure::UpstreamStalled;
            tracing::info!(flow = %cx.flow, error = %e, "upstream response body stalled");
            emit_response_error(cx, "response_body_timeout", &e);
            return ResponseVerdict::Deny(Refusal::upstream(
                StatusCode::GATEWAY_TIMEOUT,
                "response_body_timeout",
            ));
        }
        Ok(Collected::Failed(e)) => {
            tracing::info!(flow = %cx.flow, error = %e, "upstream response body failed");
            return ResponseVerdict::Deny(Refusal::upstream(
                StatusCode::BAD_GATEWAY,
                "upstream_body_failed",
            ));
        }
        Ok(Collected::Complete { data, held }) => {
            if let Some(f) = cx.facts.response.as_mut() {
                f.body_size = Some(data.len() as u64);
            }
            let inspected = match Inspected::decode(&res.headers, &data, cap, &cx.shared) {
                Ok(i) => i,
                Err(Exhausted) => {
                    return ResponseVerdict::Deny(Refusal::fail_closed(budget::EXHAUSTED));
                }
            };
            lease.shrink_to(buffered_bytes(held, &inspected));
            inspected
        }
        Ok(Collected::TooLarge { held }) => {
            lease.shrink_to(held);
            Inspected::TooLarge
        }
        Ok(Collected::BudgetExhausted) => {
            return ResponseVerdict::Deny(Refusal::fail_closed(budget::EXHAUSTED));
        }
    };
    cx.buffers.push(lease);
    if let Some(f) = cx.facts.response.as_mut() {
        f.body = inspected;
    }
    ResponseVerdict::Continue(res)
}

/// A response with no body by its status, its framing, or because the
/// request was a `HEAD`.
pub(crate) fn response_known_empty(cx: &FlowCx, res: &CanonicalResponse) -> bool {
    status_forbids_body(res.status)
        || cx
            .facts
            .request
            .as_ref()
            .is_some_and(|r| r.method == Method::Head)
        || known_empty(&res.body)
}

/// The in-flight rules at the response head: they may stop the
/// exchange (answered with an error response, since nothing has been sent
/// yet) or change the response head.
fn response_rules(cx: &mut FlowCx, mut res: CanonicalResponse) -> ResponseVerdict {
    // Every forwarded exchange has an in-flight checker and response facts;
    // never continue without them.
    let (Some(in_flight), Some(facts)) = (cx.in_flight.clone(), cx.facts.response.clone()) else {
        return ResponseVerdict::Deny(Refusal::fail_closed("in_flight_missing"));
    };
    match in_flight.on_response_head(facts, &mut res) {
        Ok(()) => ResponseVerdict::Continue(res),
        Err(stop) => ResponseVerdict::Deny(stop.refusal),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_editing() {
        let q = Query::try_from("a=1&b=2&a=3").unwrap();
        let out = edit_query(Some(&q), "a", Some("x y")).unwrap().unwrap();
        assert_eq!(out.as_str(), "a=x%20y&b=2");
        let out = edit_query(Some(&q), "a", None).unwrap().unwrap();
        assert_eq!(out.as_str(), "b=2");
        assert!(edit_query(None, "a", None).unwrap().is_none());
        let out = edit_query(None, "k", Some("v")).unwrap().unwrap();
        assert_eq!(out.as_str(), "k=v");
        let q = Query::try_from("x=1").unwrap();
        assert_eq!(redact_query(&q), "x=[REDACTED]");
    }

    #[test]
    fn refusal_body_shape() {
        let flow = Ulid::generate();
        let r = Refusal::deny(
            StatusCode::FORBIDDEN,
            "blocked by roxy",
            RuleId::new(RuleId::DEFAULT),
            true,
        );
        let res = r.response(&flow);
        assert_eq!(res.status, StatusCode::FORBIDDEN);
        assert_eq!(res.headers.get("x-roxy-rule"), Some("_default"));
        let r = Refusal::fail_closed("body_too_large_to_inspect");
        assert_eq!(r.status, 503);
        assert_eq!(
            r.rule,
            Some(Decider::Rule(RuleId::new(RuleId::FAIL_CLOSED)))
        );
    }

    /// An event with no exchange names the peer as its client: an
    /// IPv4-mapped peer as the IPv4 address, with `client.peer` in the
    /// socket's form. Only that equivalence applies: an IPv4-compatible peer
    /// (`::a.b.c.d`) is not the IPv4 address it embeds, so an `allow` on
    /// that address cannot be reached by presenting it.
    #[test]
    fn the_no_exchange_client_is_the_mapped_peer_as_ipv4() {
        let mut client = crate::testkit::client_conn(crate::listener::ListenerMode::HttpProxy);
        client.peer = "[::ffff:10.0.0.1]:40000".parse().unwrap();
        let info = client_info(&client);
        assert_eq!(info.ip, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(info.peer.ip, "::ffff:10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(info.peer.port, 40000);

        client.peer = "[::10.0.0.1]:40000".parse().unwrap();
        let info = client_info(&client);
        assert_eq!(info.ip, "::10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(info.ip, info.peer.ip);
    }
}
