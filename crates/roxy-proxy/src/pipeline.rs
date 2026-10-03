//! The flow pipeline as stream stages (`DESIGN.md` §3).
//!
//! A request passes through the [`RequestStage`]s in order, each receiving
//! the request head plus its (still streaming) body and returning a
//! [`Verdict`]. The upstream connector is the terminal stage (in
//! [`crate::exchange`]); its response passes through the
//! [`ResponseStage`]s. Built-in stages: the connect gate (plain-HTTP
//! requests on the proxy port), the bounded body buffer (only when a rule
//! reads `body.text`), and the rule chain with its effects. Addons will be
//! more stages.
//!
//! # Fail closed by construction
//!
//! Stages cannot forward anything themselves: they return a [`Verdict`],
//! and the only variant that leads toward the upstream is
//! [`Verdict::Continue`]. Every error a stage meets (body failure,
//! unavailable policy input, invalid mutation, denied redirect target,
//! state store full, unsupported effect) is mapped to [`Verdict::Deny`] or
//! [`Verdict::Close`]. The driver ([`run_request_stages`] and
//! `exchange::run`) matches the verdict exhaustively with no wildcard arm, so
//! a new variant cannot silently fall through to forwarding.

use std::fmt::Write as _;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http::StatusCode;
use roxy_http::h1::ServerConn;
use roxy_http::url::{normalize_path, normalize_query, parse_host};
use roxy_http::{
    Authority, Body, BodyError, CanonicalRequest, CanonicalResponse, ParseError, Query, Reason,
    Scheme,
};
use roxy_rules::{
    AllowOpts, Decision, Effect, EvalContext, FAIL_CLOSED_MESSAGE, FAIL_CLOSED_STATUS,
    FailClosedReason, LogLevel, Outcome, Phase,
};
use ulid::Ulid;

use crate::body::{Collected, body_text, collect_prefix};
use crate::flowlog::{
    ClientInfo, DecisionKind, DstInfo, FlowEvent, RequestInfo, ResponseInfo, Timing, TlsInfo,
};
use crate::io::ConnIo;
use crate::listener::ClientConn;
use crate::server::{Shared, Snapshot};
use crate::sources::{MetricSourceError, Sample};
use crate::view::{
    DstFacts, FlowFacts, Inspected, ProxyView, RequestFacts, ResponseFacts, host_text,
};

/// Boxed future returned by stages.
pub(crate) type StageFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Rule id used for denies by the upstream address floor.
pub(crate) const ADDRESS_POLICY_RULE: &str = "_address_policy";
/// Rule id for fail-closed denies.
pub(crate) const FAIL_CLOSED_RULE: &str = "_fail_closed";

/// Whether a local answer is a policy decision or a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefusalKind {
    /// A rule (or a built-in policy) denied the flow.
    Deny,
    /// The upstream could not be reached or broke.
    UpstreamError,
}

/// A response roxy writes itself instead of forwarding.
#[derive(Debug, Clone)]
pub(crate) struct Refusal {
    pub kind: RefusalKind,
    pub status: u16,
    pub message: String,
    /// Rule id for `x-roxy-rule` and the JSON body (denies only).
    pub rule: Option<String>,
    /// Close the client connection after the response.
    pub close: bool,
    /// Stable reason code for the flow log (and the body of upstream errors).
    pub reason: Option<String>,
}

impl Refusal {
    pub(crate) fn deny(status: u16, message: &str, rule: &str, close: bool) -> Self {
        Self {
            kind: RefusalKind::Deny,
            status,
            message: message.to_owned(),
            rule: Some(rule.to_owned()),
            close,
            reason: None,
        }
    }

    /// 503 `_fail_closed` with `reason`.
    pub(crate) fn fail_closed(reason: &str) -> Self {
        Self {
            reason: Some(reason.to_owned()),
            ..Self::deny(
                FAIL_CLOSED_STATUS,
                FAIL_CLOSED_MESSAGE,
                FAIL_CLOSED_RULE,
                true,
            )
        }
    }

    /// 403 `_address_policy`.
    pub(crate) fn address_policy(reason: &str) -> Self {
        Self {
            reason: Some(reason.to_owned()),
            ..Self::deny(
                403,
                roxy_rules::DEFAULT_DENY_MESSAGE,
                ADDRESS_POLICY_RULE,
                true,
            )
        }
    }

    /// 502/504 for an upstream failure; always closes.
    pub(crate) fn upstream(status: u16, reason: &str, message: &str) -> Self {
        Self {
            kind: RefusalKind::UpstreamError,
            status,
            message: message.to_owned(),
            rule: None,
            close: true,
            reason: Some(reason.to_owned()),
        }
    }

    /// The §5.7 response.
    pub(crate) fn response(&self, flow: &Ulid) -> CanonicalResponse {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::FORBIDDEN);
        let body = match (&self.rule, self.kind) {
            (Some(rule), RefusalKind::Deny) => serde_json::json!({
                "error": self.message,
                "rule": rule,
                "flow": flow.to_string(),
            }),
            _ => serde_json::json!({
                "error": self.message,
                "reason": self.reason,
                "flow": flow.to_string(),
            }),
        };
        let mut res = CanonicalResponse::new(status);
        let _ = res.headers.insert("content-type", "application/json");
        let _ = res.headers.insert("cache-control", "no-store");
        if let Some(rule) = &self.rule
            && res.headers.insert("x-roxy-rule", rule).is_err()
        {
            // A rule id that is not a valid header value is still in the body.
            tracing::debug!("rule id is not a valid header value");
        }
        res.body = Body::from_bytes(Bytes::from(body.to_string()));
        res
    }
}

/// Outcome of the request stages. Consumed exhaustively by the exchange
/// driver: only `Continue` reaches the upstream.
#[allow(clippy::large_enum_variant)] // moved once per stage, never stored
pub(crate) enum Verdict {
    /// Proceed with this (possibly mutated) request.
    Continue(CanonicalRequest),
    /// Answer locally (deny or fail-closed).
    Deny(Refusal),
    /// The client side broke (body framing, timeout, cap): close.
    Close(ParseError),
}

/// Outcome of the response stages.
#[allow(clippy::large_enum_variant)]
pub(crate) enum ResponseVerdict {
    /// Send this (possibly mutated) response.
    Continue(CanonicalResponse),
    /// Replace it with a local answer.
    Deny(Refusal),
    /// The client side broke while the response was being inspected.
    Close(ParseError),
}

/// Body access a stage needs from the client connection: buffering while
/// the codec keeps pumping the client's request body.
pub(crate) trait BodyIo: Send {
    fn collect<'a>(
        &'a mut self,
        body: &'a mut Body,
        cap: u64,
    ) -> StageFuture<'a, Result<Collected, ParseError>>;
}

impl BodyIo for ServerConn<ConnIo> {
    fn collect<'a>(
        &'a mut self,
        body: &'a mut Body,
        cap: u64,
    ) -> StageFuture<'a, Result<Collected, ParseError>> {
        Box::pin(self.drive(collect_prefix(body, cap)))
    }
}

/// A stage on the request path.
pub(crate) trait RequestStage: Send + Sync {
    fn name(&self) -> &'static str;
    fn on_request<'a>(
        &'a self,
        cx: &'a mut FlowCx,
        req: CanonicalRequest,
        io: &'a mut dyn BodyIo,
    ) -> StageFuture<'a, Verdict>;
}

/// A stage on the response path.
pub(crate) trait ResponseStage: Send + Sync {
    fn name(&self) -> &'static str;
    fn on_response<'a>(
        &'a self,
        cx: &'a mut FlowCx,
        res: CanonicalResponse,
        io: &'a mut dyn BodyIo,
    ) -> StageFuture<'a, ResponseVerdict>;
}

/// The ordered stages.
pub(crate) struct Pipeline {
    pub request: Vec<Box<dyn RequestStage>>,
    pub response: Vec<Box<dyn ResponseStage>>,
}

impl Pipeline {
    /// The built-in pipeline.
    pub(crate) fn builtin() -> Self {
        Self {
            request: vec![
                Box::new(ConnectGate),
                Box::new(InspectRequestBody),
                Box::new(RequestRules),
            ],
            response: vec![Box::new(InspectResponseBody), Box::new(ResponseRules)],
        }
    }
}

/// Runs the request stages in order.
pub(crate) async fn run_request_stages(
    p: &Pipeline,
    cx: &mut FlowCx,
    mut req: CanonicalRequest,
    io: &mut dyn BodyIo,
) -> Verdict {
    for stage in &p.request {
        match stage.on_request(cx, req, io).await {
            Verdict::Continue(r) => req = r,
            Verdict::Deny(d) => {
                tracing::debug!(stage = stage.name(), "request denied");
                return Verdict::Deny(d);
            }
            Verdict::Close(e) => return Verdict::Close(e),
        }
    }
    Verdict::Continue(req)
}

/// Runs the response stages in order.
pub(crate) async fn run_response_stages(
    p: &Pipeline,
    cx: &mut FlowCx,
    mut res: CanonicalResponse,
    io: &mut dyn BodyIo,
) -> ResponseVerdict {
    for stage in &p.response {
        match stage.on_response(cx, res, io).await {
            ResponseVerdict::Continue(r) => res = r,
            ResponseVerdict::Deny(d) => {
                tracing::debug!(stage = stage.name(), "response denied");
                return ResponseVerdict::Deny(d);
            }
            ResponseVerdict::Close(e) => return ResponseVerdict::Close(e),
        }
    }
    ResponseVerdict::Continue(res)
}

// ---------------------------------------------------------------------------
// Per-flow context
// ---------------------------------------------------------------------------

/// What the flow log needs about a flow.
#[derive(Debug, Default)]
pub(crate) struct FlowRecord {
    pub rules: Vec<String>,
    pub tags: Vec<String>,
    pub mutations: Vec<String>,
    pub terminal_rule: Option<String>,
    pub reason: Option<String>,
    pub decision: Option<DecisionKind>,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub response_status: Option<u16>,
    pub response_headers_bytes: u64,
    pub ttfb_ms: Option<u64>,
    /// Request bytes already reported in the request-phase sample.
    pub sampled_request_bytes: Option<u64>,
}

/// Per-flow state shared by the stages.
pub(crate) struct FlowCx {
    pub shared: Arc<Shared>,
    pub snap: Arc<Snapshot>,
    pub flow: Ulid,
    pub facts: FlowFacts,
    pub opts: AllowOpts,
    pub record: FlowRecord,
    pub started: Instant,
    /// Plain-HTTP request on the proxy port (not inside a tunnel).
    pub on_proxy_port: bool,
    /// `Host` to send upstream after a `redirect` without `rewrite_host`.
    pub host_override: Option<String>,
}

pub(crate) fn request_facts(req: &CanonicalRequest) -> RequestFacts {
    RequestFacts {
        method: req.method.as_str().to_owned(),
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
        user: c.user.clone(),
    }
}

fn ms(d: std::time::Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// Query for the log: keys kept, values redacted (§10.1).
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
        on_proxy_port: bool,
    ) -> Self {
        Self {
            shared,
            snap,
            flow: Ulid::generate(),
            facts: FlowFacts {
                client,
                tls,
                dst: None,
                request: Some(request_facts(req)),
                response: None,
            },
            opts: AllowOpts::default(),
            record: FlowRecord::default(),
            started: Instant::now(),
            on_proxy_port,
            host_override: None,
        }
    }

    pub(crate) fn conn_id(&self) -> String {
        self.facts.client.id.to_string()
    }

    fn note_outcome(&mut self, out: &Outcome) {
        for r in &out.matched {
            let r = r.to_string();
            if !self.record.rules.contains(&r) {
                self.record.rules.push(r);
            }
        }
        for t in &out.tags {
            if !self.record.tags.contains(t) {
                self.record.tags.push(t.clone());
            }
        }
        if !out.terminal_rule.to_string().starts_with('_')
            && !self.record.rules.contains(&out.terminal_rule.to_string())
        {
            self.record.rules.push(out.terminal_rule.to_string());
        }
    }

    /// Evaluates `phase` and records the metric sample. Returns the outcome
    /// plus a refusal when the decision (or recording) must deny.
    fn evaluate(&mut self, phase: Phase, sample_bytes: (u64, u64)) -> (Outcome, Option<Refusal>) {
        let snap = self.snap.clone();
        let shared = self.shared.clone();
        let secrets = |name: &str| snap.secrets.get(name).cloned();
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
        let out = snap.policy.evaluate(phase, &view, &ctx);
        let metric_err = view.take_metric_error();
        let sample = Sample {
            request_bytes: sample_bytes.0,
            response_bytes: sample_bytes.1,
            denied: !out.decision.is_allow(),
            error: false,
        };
        let record_err = shared.metrics.record(phase, &view, &sample).err();
        drop(view);
        self.note_outcome(&out);
        let mut refusal = None;
        if let Some(reason) = &out.fail_closed_reason {
            let code = fail_closed_code(reason, metric_err.as_ref());
            self.emit_input_unavailable(phase, code, reason, metric_err.as_ref());
            refusal = Some(Refusal::fail_closed(code));
        } else {
            match &out.decision {
                Decision::Deny {
                    status,
                    message,
                    close,
                } => {
                    refusal = Some(Refusal::deny(
                        *status,
                        message,
                        out.terminal_rule.as_str(),
                        *close,
                    ));
                }
                Decision::Passthrough => {
                    refusal = Some(Refusal::fail_closed("passthrough_unsupported"));
                }
                Decision::Allow(_) => {}
            }
        }
        if refusal.is_none()
            && let Some(e) = record_err
        {
            self.emit_metric_error(phase, &e);
            refusal = Some(Refusal::fail_closed(e.code()));
        }
        // The flow's terminal rule is the request decision, unless another
        // phase refused it.
        if let Some(r) = &refusal {
            self.record.terminal_rule.clone_from(&r.rule);
        } else if phase == Phase::Request {
            self.record.terminal_rule = Some(out.terminal_rule.to_string());
        }
        (out, refusal)
    }

    fn emit_input_unavailable(
        &self,
        phase: Phase,
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
                phase: phase.as_str().to_owned(),
                detail: e.to_string(),
            });
        }
        tracing::warn!(flow = %self.flow, phase = phase.as_str(), code, %reason, "policy input unavailable; failing closed");
        self.shared.sink.emit(&FlowEvent::PolicyInputUnavailable {
            ts,
            flow: self.flow.to_string(),
            conn: self.conn_id(),
            phase: phase.as_str().to_owned(),
            reason: format!(
                "{code}: {}",
                self.snap.redactor.redact_str(&reason.to_string())
            ),
        });
    }

    fn emit_metric_error(&self, phase: Phase, e: &MetricSourceError) {
        tracing::warn!(flow = %self.flow, phase = phase.as_str(), error = %e, "metric recording failed; failing closed");
        let ts = chrono::Utc::now();
        if matches!(e, MetricSourceError::TableFull(_)) {
            self.shared.sink.emit(&FlowEvent::MetricTableFull {
                ts,
                flow: self.flow.to_string(),
                conn: self.conn_id(),
                phase: phase.as_str().to_owned(),
                detail: e.to_string(),
            });
        } else {
            self.shared.sink.emit(&FlowEvent::PolicyInputUnavailable {
                ts,
                flow: self.flow.to_string(),
                conn: self.conn_id(),
                phase: phase.as_str().to_owned(),
                reason: format!("{}: {e}", e.code()),
            });
        }
    }

    fn emit_rule_log(&self, phase: Phase, level: LogLevel, message: &str) {
        let message = self.snap.redactor.redact_str(message).into_owned();
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
            phase: phase.as_str().to_owned(),
            level: level.as_str().to_owned(),
            message,
        });
    }

    /// Runs the connect phase for `authority` (CONNECT, plain-HTTP requests
    /// on the proxy port, and `redirect` targets).
    pub(crate) fn connect_phase(&mut self, authority: &Authority) -> Option<Refusal> {
        let kept_request = self.facts.request.take();
        let kept_response = self.facts.response.take();
        self.facts.dst = Some(DstFacts {
            host: authority.host.clone(),
            port: authority.port,
        });
        let (_out, refusal) = self.evaluate(Phase::Connect, (0, 0));
        self.facts.dst = None;
        self.facts.request = kept_request;
        self.facts.response = kept_response;
        refusal
    }

    /// Emits the flow's `request` event.
    pub(crate) fn emit_request_event(&self) {
        let r = self.facts.request.as_ref();
        let req = RequestInfo {
            method: r.map(|r| r.method.clone()).unwrap_or_default(),
            host: r.map(|r| host_text(&r.host)).unwrap_or_default(),
            port: r.map_or(0, |r| r.port),
            path: r
                .map(|r| self.snap.redactor.redact_str(&r.path).into_owned())
                .unwrap_or_default(),
            query: r
                .and_then(|r| r.query.as_ref())
                .map(|q| self.snap.redactor.redact_str(&redact_query(q)).into_owned()),
            headers_bytes: r.map_or(0, |r| r.head_bytes as u64),
            body_bytes: self.record.request_bytes,
            content_type: r.and_then(|r| r.headers.get("content-type")).map(|v| {
                self.snap
                    .redactor
                    .redact_header("content-type", v)
                    .into_owned()
            }),
        };
        let res = self.record.response_status.map(|status| ResponseInfo {
            status,
            headers_bytes: self.record.response_headers_bytes,
            body_bytes: self.record.response_bytes,
        });
        self.shared.sink.emit(&FlowEvent::Request {
            ts: chrono::Utc::now(),
            flow: self.flow.to_string(),
            conn: self.conn_id(),
            listener: self.facts.client.listener.name.clone(),
            client: client_info(&self.facts.client),
            tls: self.facts.tls.clone(),
            req,
            res,
            decision: self.record.decision.unwrap_or(DecisionKind::Deny),
            rules: self.record.rules.clone(),
            tags: self.record.tags.clone(),
            mutations: self.record.mutations.clone(),
            addons: Vec::new(),
            timing: Timing {
                total_ms: ms(self.started.elapsed()),
                upstream_connect_ms: None,
                upstream_ttfb_ms: self.record.ttfb_ms,
            },
            terminal_rule: self.record.terminal_rule.clone(),
            reason: self.record.reason.clone(),
        });
    }

    /// Emits a `connect` event for a connect-phase decision.
    pub(crate) fn emit_connect_event(&self, authority: &Authority, denied: bool) {
        if !denied && !self.shared.connection_events {
            return;
        }
        self.shared.sink.emit(&FlowEvent::Connect {
            ts: chrono::Utc::now(),
            conn: self.conn_id(),
            listener: self.facts.client.listener.name.clone(),
            client: client_info(&self.facts.client),
            dst: DstInfo {
                host: host_text(&authority.host),
                port: authority.port,
                ip: None,
            },
            tls: self.facts.tls.clone(),
            decision: if denied {
                DecisionKind::Deny
            } else {
                DecisionKind::Allow
            },
            rules: self.record.rules.clone(),
        });
    }

    /// Records the response-phase metric sample once the body has streamed.
    pub(crate) fn record_final_sample(&self, error: bool) {
        let request_bytes = match self.record.sampled_request_bytes {
            Some(_) => 0,
            None => self.record.request_bytes,
        };
        let sample = Sample {
            request_bytes,
            response_bytes: self.record.response_bytes,
            denied: matches!(self.record.decision, Some(DecisionKind::Deny)),
            error,
        };
        let view = ProxyView::new(
            &self.facts,
            &*self.shared.metrics,
            &*self.shared.state,
            &self.snap.address_lists,
        );
        if let Err(e) = self.shared.metrics.record(Phase::Response, &view, &sample) {
            // The response has already been sent; the next flow that needs
            // the missing key fails closed at its decision.
            drop(view);
            self.emit_metric_error(Phase::Response, &e);
        }
    }
}

fn fail_closed_code(reason: &FailClosedReason, metric: Option<&MetricSourceError>) -> &'static str {
    match reason {
        FailClosedReason::MetricUnavailable(_) => {
            metric.map_or("metric_unavailable", MetricSourceError::code)
        }
        FailClosedReason::AddressListUnavailable(_) => "address_list_unavailable",
        FailClosedReason::SecretMissing(_) => "secret_missing",
        FailClosedReason::SecretInvalid(_) => "secret_invalid",
        FailClosedReason::BodyTooLargeToInspect(_) => "body_too_large_to_inspect",
        FailClosedReason::BodyUnavailable(_) => "body_unavailable",
        FailClosedReason::BodySizeUnknown(_) => "body_size_unknown",
    }
}

/// Maps a failed body to the parse error that closes the connection.
pub(crate) fn body_failure(e: &BodyError) -> ParseError {
    match e {
        BodyError::Invalid(pe) => pe.clone(),
        BodyError::TooLarge { .. } => ParseError::new(Reason::BodyTooLarge, e.to_string()),
        BodyError::Timeout => ParseError::new(Reason::BodyTimeout, e.to_string()),
        _ => ParseError::new(Reason::UnexpectedEof, e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Built-in request stages
// ---------------------------------------------------------------------------

/// Plain-HTTP requests on the proxy port never had a CONNECT, so the
/// connect-phase rules run here against the request's authority, giving
/// `dst.*` rules the same reach for `http://` as for `https://`.
struct ConnectGate;

impl RequestStage for ConnectGate {
    fn name(&self) -> &'static str {
        "connect_gate"
    }

    fn on_request<'a>(
        &'a self,
        cx: &'a mut FlowCx,
        req: CanonicalRequest,
        _io: &'a mut dyn BodyIo,
    ) -> StageFuture<'a, Verdict> {
        Box::pin(async move {
            if !cx.on_proxy_port {
                return Verdict::Continue(req);
            }
            match cx.connect_phase(&req.authority) {
                None => Verdict::Continue(req),
                Some(r) => Verdict::Deny(r),
            }
        })
    }
}

/// Bounded buffering in front of body-inspecting rules (§6.2).
struct InspectRequestBody;

impl RequestStage for InspectRequestBody {
    fn name(&self) -> &'static str {
        "inspect_request_body"
    }

    fn on_request<'a>(
        &'a self,
        cx: &'a mut FlowCx,
        mut req: CanonicalRequest,
        io: &'a mut dyn BodyIo,
    ) -> StageFuture<'a, Verdict> {
        Box::pin(async move {
            if !cx.snap.policy.needs_request_body() {
                return Verdict::Continue(req);
            }
            let cap = cx.snap.limits.max_inspect_body_bytes;
            let inspected = match io.collect(&mut req.body, cap).await {
                Err(e) => return Verdict::Close(e),
                Ok(Collected::Failed(e)) => return Verdict::Close(body_failure(&e)),
                Ok(Collected::Complete(b)) => {
                    if let Some(f) = cx.facts.request.as_mut() {
                        f.body_size = Some(b.len() as u64);
                    }
                    Inspected::Text(body_text(&b))
                }
                Ok(Collected::TooLarge) => Inspected::TooLarge,
            };
            if let Some(f) = cx.facts.request.as_mut() {
                f.body = inspected;
            }
            Verdict::Continue(req)
        })
    }
}

/// The request rule chain and its effects.
struct RequestRules;

impl RequestStage for RequestRules {
    fn name(&self) -> &'static str {
        "request_rules"
    }

    fn on_request<'a>(
        &'a self,
        cx: &'a mut FlowCx,
        mut req: CanonicalRequest,
        _io: &'a mut dyn BodyIo,
    ) -> StageFuture<'a, Verdict> {
        Box::pin(async move {
            let declared = cx.facts.request.as_ref().and_then(|r| r.body_size);
            cx.record.sampled_request_bytes = declared;
            let (out, refusal) = cx.evaluate(Phase::Request, (declared.unwrap_or(0), 0));
            if let Some(r) = refusal {
                return Verdict::Deny(r);
            }
            if let Decision::Allow(opts) = out.decision {
                cx.opts = opts;
            }
            for effect in out.effects {
                if let Err(r) = apply_request_effect(cx, &mut req, effect) {
                    return Verdict::Deny(r);
                }
            }
            // Later stages, the response phase and the log see the request
            // as it will be forwarded.
            let body = cx
                .facts
                .request
                .as_ref()
                .map(|r| (r.body.clone(), r.body_size));
            let mut facts = request_facts(&req);
            if let Some((inspected, size)) = body {
                facts.body = inspected;
                facts.body_size = size;
            }
            cx.facts.request = Some(facts);
            Verdict::Continue(req)
        })
    }
}

fn invalid(what: &str, e: &dyn std::fmt::Display) -> Refusal {
    tracing::warn!(effect = what, error = %e, "rule effect produced an invalid request; denying");
    Refusal::fail_closed("effect_invalid")
}

/// Sets or removes `key` in a query, rebuilding it through the §5.4
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

/// Applies one request-phase effect (§6.3). Any failure denies the flow.
fn apply_request_effect(
    cx: &mut FlowCx,
    req: &mut CanonicalRequest,
    effect: Effect,
) -> Result<(), Refusal> {
    let kind = effect.kind();
    match effect {
        Effect::SetHeader { name, value } => {
            req.headers
                .insert(&name, &value)
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
            let new_host = parse_host(host.as_bytes()).map_err(|e| invalid(kind, &e))?;
            if rewrite_host {
                cx.host_override = None;
            } else if cx.host_override.is_none() {
                cx.host_override = Some(req.authority.to_host_header(req.scheme));
            }
            req.authority = Authority::new(new_host, port);
            if let Some(s) = scheme {
                req.scheme = rules_scheme(s);
            }
            cx.record
                .mutations
                .push(format!("redirect:{}://{}", req.scheme, req.authority));
            // §6.3: the new target goes through the connect phase again.
            if let Some(r) = cx.connect_phase(&req.authority) {
                return Err(r);
            }
        }
        Effect::Log { level, message } => cx.emit_rule_log(Phase::Request, level, &message),
        Effect::SetState { key, value, ttl } => {
            cx.shared
                .state
                .set(&key, &value, ttl)
                .map_err(|_| Refusal::fail_closed("state_unavailable"))?;
        }
        // Capture and addon calls are not in this build; `roxy run`
        // refuses policies that use them. Deny defensively.
        Effect::Capture(_) | Effect::CallAddon(_) => {
            return Err(Refusal::fail_closed("unsupported_effect"));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Built-in response stages
// ---------------------------------------------------------------------------

/// Bounded buffering of the response body for `response.body.text`.
struct InspectResponseBody;

impl ResponseStage for InspectResponseBody {
    fn name(&self) -> &'static str {
        "inspect_response_body"
    }

    fn on_response<'a>(
        &'a self,
        cx: &'a mut FlowCx,
        mut res: CanonicalResponse,
        io: &'a mut dyn BodyIo,
    ) -> StageFuture<'a, ResponseVerdict> {
        Box::pin(async move {
            cx.facts.response = Some(ResponseFacts {
                status: res.status.as_u16(),
                headers: res.headers.clone(),
                body_size: res.body.known_length(),
                body: Inspected::NotBuffered,
            });
            if !cx.snap.policy.needs_response_body() {
                return ResponseVerdict::Continue(res);
            }
            let cap = cx.snap.limits.max_inspect_body_bytes;
            let inspected = match io.collect(&mut res.body, cap).await {
                Err(e) => return ResponseVerdict::Close(e),
                Ok(Collected::Failed(e)) => {
                    return ResponseVerdict::Deny(Refusal::upstream(
                        502,
                        "upstream_body_failed",
                        &format!("upstream response body failed: {e}"),
                    ));
                }
                Ok(Collected::Complete(b)) => {
                    if let Some(f) = cx.facts.response.as_mut() {
                        f.body_size = Some(b.len() as u64);
                    }
                    Inspected::Text(body_text(&b))
                }
                Ok(Collected::TooLarge) => Inspected::TooLarge,
            };
            if let Some(f) = cx.facts.response.as_mut() {
                f.body = inspected;
            }
            ResponseVerdict::Continue(res)
        })
    }
}

/// The response rule chain and its effects.
struct ResponseRules;

impl ResponseStage for ResponseRules {
    fn name(&self) -> &'static str {
        "response_rules"
    }

    fn on_response<'a>(
        &'a self,
        cx: &'a mut FlowCx,
        mut res: CanonicalResponse,
        _io: &'a mut dyn BodyIo,
    ) -> StageFuture<'a, ResponseVerdict> {
        Box::pin(async move {
            // The response sample is recorded once the body has streamed
            // (`FlowCx::record_final_sample`); evaluation here only reads.
            let (out, refusal) = cx.evaluate_response();
            if let Some(r) = refusal {
                return ResponseVerdict::Deny(r);
            }
            for effect in out.effects {
                let kind = effect.kind();
                match effect {
                    Effect::SetHeader { name, value } => {
                        if let Err(e) = res.headers.insert(&name, &value) {
                            return ResponseVerdict::Deny(invalid(kind, &e));
                        }
                        cx.record
                            .mutations
                            .push(format!("response.set_header:{name}"));
                    }
                    Effect::RemoveHeader(name) => {
                        res.headers.remove(&name);
                        cx.record
                            .mutations
                            .push(format!("response.remove_header:{name}"));
                    }
                    Effect::Log { level, message } => {
                        cx.emit_rule_log(Phase::Response, level, &message);
                    }
                    Effect::SetState { key, value, ttl } => {
                        if cx.shared.state.set(&key, &value, ttl).is_err() {
                            return ResponseVerdict::Deny(Refusal::fail_closed(
                                "state_unavailable",
                            ));
                        }
                    }
                    Effect::RewritePath { .. }
                    | Effect::SetQuery { .. }
                    | Effect::RemoveQuery(_)
                    | Effect::Redirect { .. }
                    | Effect::Capture(_)
                    | Effect::CallAddon(_) => {
                        return ResponseVerdict::Deny(Refusal::fail_closed("unsupported_effect"));
                    }
                }
            }
            ResponseVerdict::Continue(res)
        })
    }
}

impl FlowCx {
    /// Response-phase evaluation without recording a sample (recorded after
    /// the body streamed, with real byte counts).
    fn evaluate_response(&mut self) -> (Outcome, Option<Refusal>) {
        let snap = self.snap.clone();
        let shared = self.shared.clone();
        let secrets = |name: &str| snap.secrets.get(name).cloned();
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
        let out = snap.policy.evaluate(Phase::Response, &view, &ctx);
        let metric_err = view.take_metric_error();
        drop(view);
        self.note_outcome(&out);
        let refusal = if let Some(reason) = &out.fail_closed_reason {
            let code = fail_closed_code(reason, metric_err.as_ref());
            self.emit_input_unavailable(Phase::Response, code, reason, metric_err.as_ref());
            Some(Refusal::fail_closed(code))
        } else {
            match &out.decision {
                Decision::Deny {
                    status,
                    message,
                    close,
                } => Some(Refusal::deny(
                    *status,
                    message,
                    out.terminal_rule.as_str(),
                    *close,
                )),
                Decision::Passthrough => Some(Refusal::fail_closed("passthrough_unsupported")),
                Decision::Allow(_) => None,
            }
        };
        if let Some(r) = &refusal {
            self.record.terminal_rule.clone_from(&r.rule);
        }
        (out, refusal)
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
        let r = Refusal::deny(403, "blocked by roxy", "_default", true);
        let res = r.response(&flow);
        assert_eq!(res.status, StatusCode::FORBIDDEN);
        assert_eq!(res.headers.get("x-roxy-rule"), Some("_default"));
        let r = Refusal::fail_closed("body_too_large_to_inspect");
        assert_eq!(r.status, 503);
        assert_eq!(r.rule.as_deref(), Some("_fail_closed"));
    }
}
