//! The exchange core's fixed steps (docs/architecture.md#exchange).
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
    AllowOpts, CaptureTarget, Decision, Effect, EvalContext, FAIL_CLOSED_MESSAGE,
    FAIL_CLOSED_STATUS, FailClosedReason, LogLevel, Outcome,
};
use ulid::Ulid;

use crate::body::{Collected, body_text, collect_prefix};
use crate::capture::Tap;
use crate::flowlog::{
    ClientInfo, DecisionKind, DstInfo, FlowEvent, RequestInfo, ResponseInfo, Stage, Timing, TlsInfo,
};
use crate::io::ConnIo;
use crate::listener::ClientConn;
use crate::server::{Shared, Snapshot};
use crate::sources::{MetricSourceError, Sample};
use crate::view::{FlowFacts, Inspected, ProxyView, RequestFacts, ResponseFacts, host_text};
use crate::watch::Watch;

/// The boxed future of [`BodyIo::collect`].
pub(crate) type CollectFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

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

    /// The deny response (docs/http.md#deny-responses).
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

/// Outcome of the request steps. Consumed exhaustively by the exchange
/// driver: only `Continue` reaches the upstream.
#[allow(clippy::large_enum_variant)] // moved once per step, never stored
pub(crate) enum Verdict {
    /// Proceed with this (possibly mutated) request.
    Continue(CanonicalRequest),
    /// Answer locally (deny or fail-closed).
    Deny(Refusal),
    /// The client side broke (body framing, timeout, cap): close.
    Close(ParseError),
}

/// Outcome of the response steps.
#[allow(clippy::large_enum_variant)]
pub(crate) enum ResponseVerdict {
    /// Send this (possibly mutated) response.
    Continue(CanonicalResponse),
    /// Replace it with a local answer.
    Deny(Refusal),
    /// The client side broke while the response was being inspected.
    Close(ParseError),
}

/// Body access a step needs from the client connection: buffering while
/// the codec keeps pumping the client's request body.
pub(crate) trait BodyIo: Send {
    fn collect<'a>(
        &'a mut self,
        body: &'a mut Body,
        cap: u64,
    ) -> CollectFuture<'a, Result<Collected, ParseError>>;
}

impl BodyIo for ServerConn<ConnIo> {
    fn collect<'a>(
        &'a mut self,
        body: &'a mut Body,
        cap: u64,
    ) -> CollectFuture<'a, Result<Collected, ParseError>> {
        Box::pin(self.drive(collect_prefix(body, cap)))
    }
}

/// The request side: inspect the body if a rule needs it, then the head
/// decision and its effects.
pub(crate) async fn request_steps(
    cx: &mut FlowCx,
    req: CanonicalRequest,
    io: &mut dyn BodyIo,
) -> Verdict {
    match inspect_request_body(cx, req, io).await {
        Verdict::Continue(req) => request_rules(cx, req),
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
    /// Where the terminal decision was made.
    pub stage: Option<Stage>,
    /// The addons the exchange went through (docs/addons.md#layer-stack).
    pub addons: Vec<String>,
}

/// Per-flow state shared by the steps.
pub(crate) struct FlowCx {
    pub shared: Arc<Shared>,
    pub snap: Arc<Snapshot>,
    pub flow: Ulid,
    pub facts: FlowFacts,
    pub opts: AllowOpts,
    pub record: FlowRecord,
    pub started: Instant,
    /// The watching rules of this exchange, once it is forwarded.
    pub watch: Option<Arc<Watch>>,
    /// Capture this exchange's request / response (docs/flow-log.md#capture): set by a
    /// `capture` effect at the head, or for every exchange with
    /// `log.capture.all`.
    pub capture: (bool, bool),
    /// Capture taps not yet handed to a body adapter (the WebSocket relay
    /// takes them after the `101`).
    pub taps: (Option<Tap>, Option<Tap>),
    /// `Host` to send upstream after a `redirect` without `rewrite_host`.
    pub host_override: Option<String>,
    /// The addon stack this exchange went through, folded into the record
    /// when it is logged.
    pub stack: Option<Arc<crate::addons::StackFlow>>,
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

/// Query for the log: keys kept, values redacted (docs/flow-log.md#redaction).
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
        Self {
            shared,
            snap,
            flow: Ulid::generate(),
            facts: FlowFacts {
                client,
                tls,
                request: Some(request_facts(req)),
                response: None,
                request_body_bytes: None,
                response_body_bytes: None,
            },
            opts: AllowOpts::default(),
            record: FlowRecord::default(),
            started: Instant::now(),
            watch: None,
            capture: (false, false),
            taps: (None, None),
            host_override: None,
            stack: None,
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

    /// The event helpers for this flow.
    pub(crate) fn events(&self) -> Events<'_> {
        Events {
            shared: &self.shared,
            snap: &self.snap,
            flow: self.flow,
            conn: self.conn_id(),
        }
    }

    /// The head decision (docs/rules.md#evaluation), and the exchange's head metric sample.
    /// Returns the outcome plus a refusal when the decision (or recording)
    /// must deny.
    fn evaluate_head(&mut self) -> (Outcome, Option<Refusal>) {
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
        let out = snap.policy.evaluate_head(&view, &ctx);
        let metric_err = view.take_metric_error();
        let sample = Sample {
            head: true,
            denied: !out.decision.is_allow(),
            ..Sample::default()
        };
        let record_err = shared.metrics.record(&view, &sample).err();
        drop(view);
        self.note_outcome(&out);
        self.record.stage = Some(Stage::Head);
        let mut refusal = None;
        if let Some(reason) = &out.fail_closed_reason {
            let code = fail_closed_code(reason, metric_err.as_ref());
            self.events()
                .input_unavailable(Stage::Head, code, reason, metric_err.as_ref());
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
            self.events().metric_error(Stage::Head, &e);
            refusal = Some(Refusal::fail_closed(e.code()));
        }
        self.record.terminal_rule = match &refusal {
            Some(r) => r.rule.clone(),
            None => Some(out.terminal_rule.to_string()),
        };
        (out, refusal)
    }

    /// Emits the flow's `request` event.
    pub(crate) fn emit_request_event(&mut self) {
        if let Some(st) = self.stack.take() {
            st.merge_into(self);
        }
        self.absorb_watch();
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
            addons: self.record.addons.clone(),
            timing: Timing {
                total_ms: ms(self.started.elapsed()),
                upstream_connect_ms: None,
                upstream_ttfb_ms: self.record.ttfb_ms,
            },
            terminal_rule: self.record.terminal_rule.clone(),
            reason: self.record.reason.clone(),
            stage: self.record.stage,
        });
    }

    /// Emits a `connect` event for a CONNECT (refused, or accepted for
    /// inspection).
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

    /// Records the exchange's final metric sample (errors, and `denied` if
    /// a watching rule stopped it). Bytes were recorded as they streamed.
    pub(crate) fn record_final_sample(&self, error: bool) {
        let stopped = self.watch.as_ref().is_some_and(|w| w.stopped().is_some());
        let sample = Sample {
            denied: stopped,
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
            self.events().metric_error(stage, &e);
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

/// Event helpers shared by the head decision and the watcher.
pub(crate) struct Events<'a> {
    pub shared: &'a Shared,
    pub snap: &'a Snapshot,
    pub flow: Ulid,
    pub conn: String,
}

impl Events<'_> {
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
                conn: self.conn.clone(),
                stage,
                detail: e.to_string(),
            });
        }
        tracing::warn!(flow = %self.flow, stage = stage.as_str(), code, %reason, "policy input unavailable; failing closed");
        self.shared.sink.emit(&FlowEvent::PolicyInputUnavailable {
            ts,
            flow: self.flow.to_string(),
            conn: self.conn.clone(),
            stage,
            reason: format!(
                "{code}: {}",
                self.snap.redactor.redact_str(&reason.to_string())
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
                conn: self.conn.clone(),
                stage,
                detail: e.to_string(),
            });
        } else {
            self.shared.sink.emit(&FlowEvent::PolicyInputUnavailable {
                ts,
                flow: self.flow.to_string(),
                conn: self.conn.clone(),
                stage,
                reason: format!("{}: {e}", e.code()),
            });
        }
    }

    pub(crate) fn rule_log(&self, stage: Stage, level: LogLevel, message: &str) {
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
            conn: self.conn.clone(),
            stage,
            level: level.as_str().to_owned(),
            message,
        });
    }
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
        FailClosedReason::MissingValue(_) => "missing_value",
        FailClosedReason::Unsupported(_) => "unsupported_effect",
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
// Request steps
// ---------------------------------------------------------------------------

/// Bounded buffering in front of body-inspecting rules (docs/rules.md#body-access).
async fn inspect_request_body(
    cx: &mut FlowCx,
    mut req: CanonicalRequest,
    io: &mut dyn BodyIo,
) -> Verdict {
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
}

/// The head decision (docs/rules.md#evaluation) and its effects.
fn request_rules(cx: &mut FlowCx, mut req: CanonicalRequest) -> Verdict {
    let (out, refusal) = cx.evaluate_head();
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
    // The watching rules and the log see the request as it
    // will be forwarded.
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
}

fn invalid(what: &str, e: &dyn std::fmt::Display) -> Refusal {
    tracing::warn!(effect = what, error = %e, "rule effect produced an invalid request; denying");
    Refusal::fail_closed("effect_invalid")
}

/// Sets or removes `key` in a query, rebuilding it through the docs/http.md#url-normalisation
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

/// Applies one effect of the head decision (docs/rules.md#actions). Any failure denies the
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
            // docs/rules.md#actions: the address floor and deny lists check the new target's
            // addresses when the upstream connects.
            cx.record
                .mutations
                .push(format!("redirect:{}://{}", req.scheme, req.authority));
        }
        Effect::Log { level, message } => cx.events().rule_log(Stage::Head, level, &message),
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
            let (req, res) = &mut cx.capture;
            *req |= matches!(target, CaptureTarget::Request | CaptureTarget::Both);
            *res |= matches!(target, CaptureTarget::Response | CaptureTarget::Both);
        }
        // Addon calls are not in this build; `roxy run` refuses policies
        // that use them. Deny defensively.
        Effect::CallAddon(_) => {
            return Err(Refusal::fail_closed("unsupported_effect"));
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
}

/// The watching rules at the response head (docs/rules.md#evaluation): they may stop the
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
        let r = Refusal::deny(403, "blocked by roxy", "_default", true);
        let res = r.response(&flow);
        assert_eq!(res.status, StatusCode::FORBIDDEN);
        assert_eq!(res.headers.get("x-roxy-rule"), Some("_default"));
        let r = Refusal::fail_closed("body_too_large_to_inspect");
        assert_eq!(r.status, 503);
        assert_eq!(r.rule.as_deref(), Some("_fail_closed"));
    }
}
