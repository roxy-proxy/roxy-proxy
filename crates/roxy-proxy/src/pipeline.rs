//! The exchange core's fixed steps.
//!
//! On the way out, [`request_steps`] buffers the request body (only when a
//! rule reads `body.text`) and then makes the head decision with its
//! effects. On the way back, [`response_steps`] buffers the response body
//! (only for `response.body.text`) and then checks the watching rules at the
//! response head ([`crate::watch`]). The upstream exchange between the two
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

use std::fmt::{self, Write as _};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::{Instant, SystemTime};

use aws_sigv4::http_request::SignableBody;
use bytes::Bytes;
use http::StatusCode;
use roxy_http::h1::ServerConn;
use roxy_http::url::{normalize_path, normalize_query};
use roxy_http::{
    Authority, Body, BodyError, CanonicalRequest, CanonicalResponse, DriveError, Method,
    ParseError, Query, Reason, Scheme, status_forbids_body,
};
use roxy_rules::{
    AllowOpts, AwsSigV4, CaptureTarget, DEFAULT_DENY_MESSAGE, Decision, Deny, DenyStatus, Effect,
    EvalContext, FAIL_CLOSED_STATUS, FailClosedReason, LogLevel, Outcome, RuleId,
};
use ulid::Ulid;

use crate::body::{Collected, collect_prefix};
use crate::budget::{self, BufferLease};
use crate::capture::Tap;
use crate::flowlog::{
    ClientInfo, DecisionKind, DstInfo, FlowEvent, RequestInfo, ResponseInfo, Stage, Timing, TlsInfo,
};
use crate::io::ClientIo;
use crate::listener::ClientConn;
use crate::secrets::Secrets;
use crate::server::{Shared, Snapshot};
use crate::sign;
use crate::sources::{MetricSourceError, Sample};
use crate::view::{FlowFacts, Inspected, ProxyView, RequestFacts, ResponseFacts, host_text};
use crate::watch::Watch;

/// The boxed future of [`BodyIo::collect`].
pub(crate) type CollectFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Rule id used for denies by the upstream address floor.
pub(crate) const ADDRESS_POLICY_RULE: &str = "_address_policy";

/// Rule id used for denies after the policy's `valid_until`.
pub(crate) const EXPIRED_RULE: &str = "_expired";

/// Flow-log `reason` of an `_expired` deny.
pub(crate) const EXPIRED_REASON: &str = "policy_expired";

/// Rule id used for the refusal of a request `sign` cannot hash.
pub(crate) const SIGN_RULE: &str = "_sign";

/// Flow-log `reason` of a `_sign` refusal: the body is over
/// `limits.max_sign_body_bytes`.
pub(crate) const SIGN_BODY_TOO_LARGE: &str = "sign_body_too_large";

/// Flow-log `reason` of a `_sign` refusal: a request header holds a value
/// the signature cannot cover.
pub(crate) const SIGN_HEADER_INVALID: &str = "sign_header_invalid";

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

impl fmt::Display for Decider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Decider::Rule(id) => write!(f, "{id}"),
            Decider::Layer(name) => write!(f, "layer:{name}"),
        }
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
    fn collect<'a>(
        &'a mut self,
        body: &'a mut Body,
        cap: u64,
    ) -> CollectFuture<'a, Result<Collected, DriveError>>;
}

impl BodyIo for ServerConn<ClientIo> {
    fn collect<'a>(
        &'a mut self,
        body: &'a mut Body,
        cap: u64,
    ) -> CollectFuture<'a, Result<Collected, DriveError>> {
        Box::pin(self.drive(collect_prefix(body, cap)))
    }
}

/// The request side: inspect the body if a rule needs it, then the head
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
        Verdict::Continue(req) => sign_request(cx, req, io).await,
        Verdict::Deny(d) => Verdict::Deny(d),
        Verdict::Close(e) => Verdict::Close(e),
    }
}

/// The response side: inspect the body if a rule needs it, then the
/// watching rules at the response head.
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
    pub tags: Vec<String>,
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
    /// Where the terminal decision was made.
    pub stage: Option<Stage>,
    /// The addons the exchange went through.
    pub addons: Vec<String>,
}

/// What identifies a flow and the world it runs in. Shared, read-only,
/// by everything that logs or evaluates for the flow: the flow context
/// and the watcher.
pub(crate) struct FlowMeta {
    pub shared: Arc<Shared>,
    pub snap: Arc<Snapshot>,
    pub flow: Ulid,
    pub client: ClientConn,
    pub tls: Option<TlsInfo>,
    /// The secret generation this exchange resolves from and redacts
    /// with: loaded on first use (the head evaluation) and kept for the
    /// exchange's life, however many swaps happen meanwhile.
    secrets: OnceLock<Arc<Secrets>>,
}

impl FlowMeta {
    pub(crate) fn conn_id(&self) -> String {
        self.client.id.to_string()
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
        tracing::warn!(flow = %self.flow, stage = stage.as_str(), code, %reason, "policy input unavailable; failing closed");
        self.shared.sink.emit(&FlowEvent::PolicyInputUnavailable {
            ts,
            flow: self.flow.to_string(),
            conn: self.conn_id(),
            stage,
            reason: format!(
                "{code}: {}",
                self.secrets().redactor().redact_str(&reason.to_string())
            ),
        });
    }

    pub(crate) fn metric_error(&self, stage: Stage, e: &MetricSourceError) {
        tracing::warn!(flow = %self.flow, stage = stage.as_str(), error = %e, "metric recording failed; failing closed");
        let ts = chrono::Utc::now();
        if matches!(e, MetricSourceError::TableFull(_)) {
            self.shared.sink.emit(&FlowEvent::MetricTableFull {
                ts,
                flow: self.flow.to_string(),
                conn: self.conn_id(),
                stage,
                detail: e.to_string(),
            });
        } else {
            self.shared.sink.emit(&FlowEvent::PolicyInputUnavailable {
                ts,
                flow: self.flow.to_string(),
                conn: self.conn_id(),
                stage,
                reason: format!("{}: {e}", e.code()),
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
    pub started: Instant,
    /// The watching rules of this exchange, once it is forwarded.
    pub watch: Option<Arc<Watch>>,
    /// Capture this exchange's request / response: set by a
    /// `capture` effect at the head, or for every exchange with
    /// `log.capture.all`.
    pub capture: PerDir<bool>,
    /// Capture taps not yet handed to a body adapter (the WebSocket relay
    /// takes them after the `101`).
    pub taps: PerDir<Option<Tap>>,
    /// `Host` to send upstream after a `redirect` without `rewrite_host`.
    pub host_override: Option<String>,
    /// A `sign` effect of the head decision, applied once every other
    /// request change has settled.
    pub sign: Option<AwsSigV4>,
    /// Request body bytes forwarded so far (and their digest once the
    /// body completed), once the request is on its way.
    pub request_tally: Option<Arc<crate::body::Tally>>,
    /// The addon stack this exchange went through (set once the stack has
    /// handed the flow back), folded into the record when it is logged.
    pub stack: Option<Arc<crate::addons::StackFlow>>,
    /// An addon layer ran on this request: on an upgrade, it is in the
    /// WebSocket's byte path.
    pub layer_ran: bool,
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

pub(crate) fn client_info(c: &ClientConn) -> ClientInfo {
    ClientInfo {
        ip: c.peer.ip(),
        port: c.peer.port(),
    }
}

fn ms(d: std::time::Duration) -> u64 {
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
    ) -> Self {
        let facts = FlowFacts {
            client: client.clone(),
            tls: tls.clone(),
            client_request: Some(request_facts(req)),
            request: Some(request_facts(req)),
            response: None,
            request_body_bytes: None,
            response_body_bytes: None,
            ws: None,
        };
        Self {
            meta: Arc::new(FlowMeta {
                shared,
                snap,
                flow: Ulid::generate(),
                client,
                tls,
                secrets: OnceLock::new(),
            }),
            facts,
            opts: AllowOpts::default(),
            record: FlowRecord::default(),
            started: Instant::now(),
            watch: None,
            capture: PerDir::default(),
            taps: PerDir::default(),
            host_override: None,
            sign: None,
            request_tally: None,
            stack: None,
            layer_ran: false,
            buffers: Vec::new(),
            logged: false,
        }
    }

    fn note_outcome(&mut self, out: &Outcome) {
        for r in &out.matched {
            if !self.record.rules.contains(r) {
                self.record.rules.push(r.clone());
            }
        }
        for t in &out.tags {
            if !self.record.tags.contains(t) {
                self.record.tags.push(t.clone());
            }
        }
        if !out.terminal_rule.as_str().starts_with('_')
            && !self.record.rules.contains(&out.terminal_rule)
        {
            self.record.rules.push(out.terminal_rule.clone());
        }
    }

    /// The deny every exchange gets once the policy's lease has run out,
    /// recorded as the head decision. Nothing of the policy (the addons
    /// included) runs for it.
    pub(crate) fn expiry_refusal(&mut self) -> Option<Refusal> {
        if !self.shared.expired() {
            return None;
        }
        self.record.stage = Some(Stage::Head);
        if let Err(e) = self.record_head_sample(true) {
            self.meta.metric_error(Stage::Head, &e);
        }
        Some(Refusal::expired())
    }

    /// The head decision. Returns the outcome plus a refusal when it
    /// denies or an input was unavailable.
    fn evaluate_head(&mut self) -> (Outcome, Option<Refusal>) {
        let snap = self.snap.clone();
        let shared = self.shared.clone();
        let generation = self.meta.secrets().clone();
        let secrets = |name: &str| generation.get(name);
        let tags = self.record.tags.clone();
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
        let out = snap.policy.evaluate_head(&view, &ctx);
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

    /// Records the exchange's head metric sample, once the head step's
    /// outcome is settled (`denied`).
    fn record_head_sample(&self, denied: bool) -> Result<(), MetricSourceError> {
        let view = ProxyView::new(
            &self.facts,
            &*self.shared.metrics,
            &*self.shared.state,
            &self.snap.address_lists,
        );
        let sample = Sample {
            head: true,
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
        }
        self.absorb_watch();
        if let Some(t) = &self.request_tally {
            self.record.request_bytes = t.bytes();
            self.record.request_sha256 = t.sha256_hex();
        }
        let redactor = self.meta.secrets().redactor();
        let r = self.facts.client_request.as_ref();
        let req = RequestInfo {
            method: r.map(|r| r.method.as_str().to_owned()).unwrap_or_default(),
            host: r.map(|r| host_text(&r.host)).unwrap_or_default(),
            port: r.map_or(0, |r| r.port),
            path: r
                .map(|r| redactor.redact_str(&r.path).into_owned())
                .unwrap_or_default(),
            query: r
                .and_then(|r| r.query.as_ref())
                .map(|q| redactor.redact_str(&redact_query(q)).into_owned()),
            headers_bytes: r.map_or(0, |r| r.head_bytes as u64),
            body_bytes: self.record.request_bytes,
            body_sha256: self.record.request_sha256.clone(),
            content_type: r
                .and_then(|r| r.headers.get("content-type"))
                .map(|v| redactor.redact_header("content-type", v).into_owned()),
        };
        let res = self.record.response_status.map(|status| ResponseInfo {
            status,
            headers_bytes: self.record.response_headers_bytes,
            body_bytes: self.record.response_bytes,
            body_sha256: self.record.response_sha256.clone(),
        });
        self.shared.sink.emit(&FlowEvent::Request {
            ts: chrono::Utc::now(),
            flow: self.flow.to_string(),
            conn: self.conn_id(),
            listener: self.meta.client.listener.name.clone(),
            client: client_info(&self.meta.client),
            tls: self.meta.tls.clone(),
            req,
            res,
            decision: self.record.decision.unwrap_or(DecisionKind::Deny),
            rules: rule_names(&self.record.rules),
            tags: self.record.tags.clone(),
            mutations: self.record.mutations.clone(),
            addons: self.record.addons.clone(),
            timing: Timing {
                total_ms: ms(self.started.elapsed()),
                upstream_connect_ms: None,
                upstream_ttfb_ms: self.record.ttfb_ms,
            },
            terminal_rule: self.record.terminal_rule.as_ref().map(ToString::to_string),
            reason: self.record.reason.clone(),
            stage: self.record.stage,
        });
    }

    /// A watching rule stopped the exchange.
    fn stopped(&self) -> bool {
        self.watch.as_ref().is_some_and(|w| w.stopped().is_some())
    }

    /// Records the final metric sample of an exchange whose response was
    /// sent (or failed to reach the client, which is not an upstream
    /// error): `denied` if a watching rule stopped it. Bytes were recorded
    /// as they streamed.
    pub(crate) fn record_final_sample(&self) {
        self.final_sample(self.stopped(), false);
    }

    /// Records the final metric sample of an exchange refused after the
    /// forwarding decision: `denied` for a deny (a watching stop, the
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

    /// Folds the watcher's outcome (watching rules that matched, tags,
    /// response mutations, a stop) into the flow record. Call once the
    /// exchange is over, before logging it.
    pub(crate) fn absorb_watch(&mut self) {
        let Some(w) = self.watch.clone() else {
            return;
        };
        let summary = w.summary();
        for r in summary.rules {
            if !self.record.rules.contains(&r) {
                self.record.rules.push(r);
            }
        }
        for t in summary.tags {
            if !self.record.tags.contains(&t) {
                self.record.tags.push(t);
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

/// Emits a `connect` event for a CONNECT (refused, or accepted for
/// inspection). No connect-time rules exist, so the event carries none.
pub(crate) fn emit_connect_event(
    shared: &Shared,
    client: &ClientConn,
    authority: &Authority,
    denied: bool,
) {
    if !denied && !shared.connection_events {
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
        decision: if denied {
            DecisionKind::Deny
        } else {
            DecisionKind::Allow
        },
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
        | BodyError::Undecodable(_) => ParseError::new(Reason::UnexpectedEof, e.to_string()),
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
    let Some(mut lease) = reserve_inspection(cx, &req.body, cap) else {
        return Verdict::Deny(Refusal::fail_closed(budget::EXHAUSTED));
    };
    let inspected = match io.collect(&mut req.body, cap).await {
        Err(e) => return Verdict::Close(e),
        Ok(Collected::Failed(e)) => return Verdict::Close(body_failure(&e).into()),
        Ok(Collected::Complete(b)) => {
            if let Some(f) = cx.facts.request.as_mut() {
                f.body_size = Some(b.len() as u64);
            }
            let inspected = Inspected::decode(&req.headers, &b, cap);
            lease.shrink_to(buffered_bytes(&b, &inspected));
            inspected
        }
        Ok(Collected::TooLarge) => Inspected::TooLarge,
    };
    cx.buffers.push(lease);
    if let Some(f) = cx.facts.request.as_mut() {
        f.body = inspected;
    }
    Verdict::Continue(req)
}

/// A body that carries no bytes needs no inspection buffer; the rules see
/// it as empty text.
fn known_empty(body: &Body) -> bool {
    body.known_length() == Some(0) || http_body::Body::is_end_stream(body)
}

/// Reserves the budget an inspected body can need: its declared length
/// when the framing gives one, else the whole cap.
fn reserve_inspection(cx: &FlowCx, body: &Body, cap: u64) -> Option<BufferLease> {
    let bytes = body.known_length().map_or(cap, |n| n.min(cap));
    cx.shared.reserve_buffer(bytes)
}

/// What a completely buffered body holds for the rest of the exchange: the
/// bytes as sent (they go on to be forwarded) and, if `content-encoding`
/// was decoded, the text the facts carry, which can be larger.
fn buffered_bytes(sent: &Bytes, inspected: &Inspected) -> u64 {
    let text = if let Inspected::Text(t) = inspected {
        t.len()
    } else {
        0
    };
    sent.len().max(text) as u64
}

/// The head decision and its effects.
fn request_rules(cx: &mut FlowCx, mut req: CanonicalRequest) -> Verdict {
    let (out, mut refusal) = cx.evaluate_head();
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
    // The head sample counts the outcome as it finally stands.
    if let Err(e) = cx.record_head_sample(refusal.is_some())
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

/// The watching rules and the log see the request as it will be
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
/// presigned request (`X-Amz-Signature` in its query) authenticates
/// itself and goes untouched. The payload hash needs the whole body, so it
/// is buffered under `limits.max_sign_body_bytes`; a body over that is
/// refused with 413 rather than forwarded with a signature AWS would
/// reject. `unsigned_payload` streams the body instead.
async fn sign_request(cx: &mut FlowCx, mut req: CanonicalRequest, io: &mut dyn BodyIo) -> Verdict {
    let Some(spec) = cx.sign.take() else {
        return Verdict::Continue(req);
    };
    if sign::is_presigned(req.query.as_ref()) {
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
        let cap = cx.snap.limits.max_sign_body_bytes;
        let Some(mut lease) = reserve_inspection(cx, &req.body, cap) else {
            return Verdict::Deny(Refusal::fail_closed(budget::EXHAUSTED));
        };
        buffered = match io.collect(&mut req.body, cap).await {
            Err(e) => return Verdict::Close(e),
            Ok(Collected::Failed(e)) => return Verdict::Close(body_failure(&e).into()),
            Ok(Collected::TooLarge) => return Verdict::Deny(Refusal::sign_body_too_large()),
            Ok(Collected::Complete(b)) => b,
        };
        lease.shrink_to(buffered.len() as u64);
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

/// Applies one effect of the head decision. Any failure denies the
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
    let Some(mut lease) = reserve_inspection(cx, &res.body, cap) else {
        return ResponseVerdict::Deny(Refusal::fail_closed(budget::EXHAUSTED));
    };
    let inspected = match io.collect(&mut res.body, cap).await {
        Err(e) => return ResponseVerdict::Close(e),
        Ok(Collected::Failed(e)) => {
            tracing::info!(flow = %cx.flow, error = %e, "upstream response body failed");
            return ResponseVerdict::Deny(Refusal::upstream(
                StatusCode::BAD_GATEWAY,
                "upstream_body_failed",
            ));
        }
        Ok(Collected::Complete(b)) => {
            if let Some(f) = cx.facts.response.as_mut() {
                f.body_size = Some(b.len() as u64);
            }
            let inspected = Inspected::decode(&res.headers, &b, cap);
            lease.shrink_to(buffered_bytes(&b, &inspected));
            inspected
        }
        Ok(Collected::TooLarge) => Inspected::TooLarge,
    };
    cx.buffers.push(lease);
    if let Some(f) = cx.facts.response.as_mut() {
        f.body = inspected;
    }
    ResponseVerdict::Continue(res)
}

/// A response with no body by its status, its framing, or because the
/// request was a `HEAD`.
fn response_known_empty(cx: &FlowCx, res: &CanonicalResponse) -> bool {
    status_forbids_body(res.status)
        || cx
            .facts
            .request
            .as_ref()
            .is_some_and(|r| r.method == Method::Head)
        || known_empty(&res.body)
}

/// The watching rules at the response head: they may stop the
/// exchange (answered with an error response, since nothing has been sent
/// yet) or change the response head.
fn response_rules(cx: &mut FlowCx, mut res: CanonicalResponse) -> ResponseVerdict {
    // Every forwarded exchange has a watcher and response facts;
    // never continue without them.
    let (Some(watch), Some(facts)) = (cx.watch.clone(), cx.facts.response.clone()) else {
        return ResponseVerdict::Deny(Refusal::fail_closed("watch_missing"));
    };
    match watch.on_response_head(facts, &mut res) {
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
}
