//! The per-exchange watcher (`DESIGN.md` §6.1): after the forwarding
//! decision, watching rules are re-checked as values become known or
//! change, and byte metrics grow as bytes stream (§6.4).
//!
//! # Where it runs
//!
//! - **Request body chunks.** [`watched`] wraps the request body on its way
//!   upstream. Each data frame is counted, added to `request_bytes` metrics
//!   and checked against the watching rules **before** it is yielded, so a
//!   chunk that makes a deny match is never forwarded.
//! - **Response head.** [`Watch::on_response_head`] runs before the head is
//!   written to the client: a stop is answered with roxy's error response,
//!   and header effects of matching rules change the response.
//! - **Response body chunks.** The same adapter on the response body; a stop
//!   ends the body with [`BodyError::Stopped`], so the h1 front end breaks
//!   the connection without a terminating chunk and the h2 front end
//!   resets the stream.
//! - **WebSocket relay.** [`Watch::on_ws_chunk`] before each write.
//!
//! # Fail closed
//!
//! A stop is sticky: once [`Watch::stopped`] is `Some`, every later chunk in
//! either direction is refused and [`Watch::cancelled`] resolves, so the
//! exchange driver abandons a pending upstream request. Any error in
//! watching evaluation (an unavailable metric, a missing value under an
//! operator that cannot answer for it, a failed metric record, a state store
//! that refuses a write, an effect that cannot run) stops the exchange; no
//! error lets it continue.
//!
//! # Cost
//!
//! Whether a chunk needs anything is decided once per exchange from the
//! policy's masks. When no rule watches a direction and no metric counts
//! its bytes, a chunk costs two atomic loads (the stop flag and the flow
//! log's readiness) and no lock.
//!
//! # Audit backpressure
//!
//! The body adapter also waits for the flow log ([`FlowSink::poll_ready`],
//! §10.1) before moving each chunk, so a log that cannot keep up slows the
//! traffic instead of dropping records.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body::{Frame, SizeHint};
use roxy_http::{Body, BodyError, CanonicalResponse};
use roxy_rules::{Decision, Effect, EvalContext, Reads, WatchState};
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};
use ulid::Ulid;

use crate::capture::Tap;
use crate::flowlog::{FlowSink, Stage};
use crate::pipeline::{Events, FlowCx, Refusal, fail_closed_code};
use crate::server::{Shared, Snapshot};
use crate::sources::Sample;
use crate::view::{FlowFacts, ProxyView, ResponseFacts};

/// Why and where a watching rule stopped the exchange.
#[derive(Debug, Clone)]
pub(crate) struct Stopped {
    pub refusal: Refusal,
    pub stage: Stage,
}

/// What the flow log needs from the watcher at the end of an exchange.
#[derive(Debug, Default)]
pub(crate) struct Summary {
    pub rules: Vec<String>,
    pub tags: Vec<String>,
    pub mutations: Vec<String>,
    pub stop: Option<Stopped>,
}

/// Direction of a body or WebSocket chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dir {
    /// Client to upstream.
    Request,
    /// Upstream to client.
    Response,
}

/// The watching state of one exchange. Shared (`Arc`) between the request
/// body adapter (polled by the upstream connection), the response path and
/// the exchange driver.
pub(crate) struct Watch {
    stop: CancellationToken,
    /// Request chunks need evaluation or metric recording.
    request_chunks: bool,
    /// Response chunks need evaluation or metric recording.
    response_chunks: bool,
    inner: Mutex<Inner>,
}

struct Inner {
    shared: Arc<Shared>,
    snap: Arc<Snapshot>,
    flow: Ulid,
    conn: String,
    facts: FlowFacts,
    st: WatchState,
    /// Watched fields known so far.
    known: Reads,
    stopped: Option<Stopped>,
    rules: Vec<String>,
    mutations: Vec<String>,
}

impl std::fmt::Debug for Watch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Watch")
            .field("stopped", &self.stop.is_cancelled())
            .finish_non_exhaustive()
    }
}

impl Watch {
    /// The watcher for an exchange about to be forwarded: `body.bytes` is
    /// known (0) from now on.
    pub(crate) fn new(cx: &FlowCx) -> Arc<Self> {
        let policy = &cx.snap.policy;
        let bm = policy.byte_metrics();
        let request_chunks = policy.watches(Reads::BODY_BYTES | Reads::METRIC_REQUEST_BYTES)
            || bm.intersects(Reads::METRIC_REQUEST_BYTES);
        let response_chunks = policy
            .watches(Reads::RESPONSE_BODY_BYTES | Reads::METRIC_RESPONSE_BYTES)
            || bm.intersects(Reads::METRIC_RESPONSE_BYTES);
        let mut facts = cx.facts.clone();
        facts.request_body_bytes = Some(0);
        Arc::new(Self {
            stop: CancellationToken::new(),
            request_chunks,
            response_chunks,
            inner: Mutex::new(Inner {
                shared: cx.shared.clone(),
                snap: cx.snap.clone(),
                flow: cx.flow,
                conn: cx.conn_id(),
                facts,
                st: policy.watch_state(&cx.record.tags),
                known: Reads::BODY_BYTES,
                stopped: None,
                rules: Vec::new(),
                mutations: Vec::new(),
            }),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The stop, if a watching rule (or an error) stopped the exchange.
    pub(crate) fn stopped(&self) -> Option<Stopped> {
        if !self.stop.is_cancelled() {
            return None;
        }
        self.lock().stopped.clone()
    }

    /// The flow sink, for audit backpressure (§10.1).
    pub(crate) fn sink(&self) -> Arc<dyn FlowSink> {
        self.lock().shared.sink.clone()
    }

    /// Resolves once the exchange is stopped.
    pub(crate) fn cancelled(&self) -> WaitForCancellationFutureOwned {
        self.stop.clone().cancelled_owned()
    }

    /// Rules, tags and response mutations of the watching rules, and the
    /// stop. Mutations are drained (call once).
    pub(crate) fn summary(&self) -> Summary {
        let mut g = self.lock();
        Summary {
            rules: g.rules.clone(),
            tags: g.st.tags.clone(),
            mutations: std::mem::take(&mut g.mutations),
            stop: g.stopped.clone(),
        }
    }

    /// Makes a stop recorded in `g` visible (`cancelled`, the flag) and
    /// returns it.
    fn publish(&self, g: &Inner) -> Result<(), Stopped> {
        match &g.stopped {
            Some(s) => {
                self.stop.cancel();
                Err(s.clone())
            }
            None => Ok(()),
        }
    }

    /// The response head arrived (§6.1): rules reading response values are
    /// checked before the head is written. `Err` means answer with the
    /// stop's refusal instead; header effects are applied to `res`.
    pub(crate) fn on_response_head(
        &self,
        facts: ResponseFacts,
        res: &mut CanonicalResponse,
    ) -> Result<(), Stopped> {
        let mut g = self.lock();
        if let Some(s) = &g.stopped {
            return Err(s.clone());
        }
        g.facts.response = Some(facts);
        g.facts.response_body_bytes = Some(0);
        let changed = Reads::RESPONSE_HEAD | Reads::RESPONSE_BODY_BYTES | Reads::RESPONSE_BODY_TEXT;
        g.known |= changed;
        let effects = g.evaluate(changed, Stage::ResponseHead);
        for e in effects {
            if g.stopped.is_some() {
                break;
            }
            let applied = match e {
                Effect::SetHeader { name, value } => res
                    .headers
                    .insert(&name, &value)
                    .map(|()| format!("response.set_header:{name}"))
                    .map_err(|e| e.to_string()),
                Effect::RemoveHeader(name) => {
                    res.headers.remove(&name);
                    Ok(format!("response.remove_header:{name}"))
                }
                // `evaluate` returns header effects only; never continue
                // on anything else.
                other => Err(format!("unexpected effect {}", other.kind())),
            };
            match applied {
                Ok(m) => g.mutations.push(m),
                Err(err) => {
                    tracing::warn!(flow = %g.flow, error = %err, "response header effect invalid; stopping");
                    g.stop_with(Refusal::fail_closed("effect_invalid"), Stage::ResponseHead);
                }
            }
        }
        self.publish(&g)
    }

    /// One body chunk of `n` bytes is about to be forwarded. `Err` means it
    /// must not be: the exchange is stopped.
    pub(crate) fn on_body_chunk(&self, dir: Dir, n: u64) -> Result<(), Stopped> {
        let needed = match dir {
            Dir::Request => self.request_chunks,
            Dir::Response => self.response_chunks,
        };
        if !needed {
            return self.check();
        }
        let mut g = self.lock();
        if let Some(s) = &g.stopped {
            return Err(s.clone());
        }
        let (field, stage) = match dir {
            Dir::Request => (&mut g.facts.request_body_bytes, Stage::RequestBody),
            Dir::Response => (&mut g.facts.response_body_bytes, Stage::ResponseBody),
        };
        *field = Some(field.unwrap_or(0).saturating_add(n));
        let changed = match dir {
            Dir::Request => Reads::BODY_BYTES,
            Dir::Response => Reads::RESPONSE_BODY_BYTES,
        };
        g.bytes(dir, n, changed, stage);
        self.publish(&g)
    }

    /// One WebSocket relay chunk of `n` bytes is about to be written. Only
    /// byte metrics change (`ws.*` message rules are not in this build).
    pub(crate) fn on_ws_chunk(&self, dir: Dir, n: u64) -> Result<(), Stopped> {
        let needed = match dir {
            Dir::Request => self.request_chunks,
            Dir::Response => self.response_chunks,
        };
        if !needed {
            return self.check();
        }
        let mut g = self.lock();
        if let Some(s) = &g.stopped {
            return Err(s.clone());
        }
        g.bytes(dir, n, Reads::NONE, Stage::Websocket);
        self.publish(&g)
    }

    fn check(&self) -> Result<(), Stopped> {
        match self.stopped() {
            Some(s) => Err(s),
            None => Ok(()),
        }
    }
}

impl Inner {
    fn events(&self) -> Events<'_> {
        Events {
            shared: &self.shared,
            snap: &self.snap,
            flow: self.flow,
            conn: self.conn.clone(),
        }
    }

    fn stop_with(&mut self, refusal: Refusal, stage: Stage) {
        if self.stopped.is_none() {
            self.stopped = Some(Stopped { refusal, stage });
        }
    }

    /// Records `n` bytes in byte metrics (if any count this direction),
    /// then re-checks the rules watching `changed` (plus the metric bit).
    fn bytes(&mut self, dir: Dir, n: u64, mut changed: Reads, stage: Stage) {
        let (bit, sample) = match dir {
            Dir::Request => (
                Reads::METRIC_REQUEST_BYTES,
                Sample {
                    request_bytes: n,
                    ..Sample::default()
                },
            ),
            Dir::Response => (
                Reads::METRIC_RESPONSE_BYTES,
                Sample {
                    response_bytes: n,
                    ..Sample::default()
                },
            ),
        };
        if n > 0 && self.snap.policy.byte_metrics().intersects(bit) {
            let view = ProxyView::new(
                &self.facts,
                &*self.shared.metrics,
                &*self.shared.state,
                &self.snap.address_lists,
            );
            let r = self.shared.metrics.record(&view, &sample);
            drop(view);
            if let Err(e) = r {
                self.events().metric_error(stage, &e);
                self.stop_with(Refusal::fail_closed(e.code()), stage);
                return;
            }
            changed |= bit;
        }
        // A body chunk carries no header effects (the compiler rejects them
        // in rules that can fire after the response head was sent).
        let effects = self.evaluate(changed, stage);
        if !effects.is_empty() && self.stopped.is_none() {
            self.stop_with(Refusal::fail_closed("unsupported_effect"), stage);
        }
    }

    /// Re-checks the watching rules after `changed`. Applies `log`, `tag`
    /// and `set_state` effects, records a stop, and returns the header
    /// effects for the caller to apply to the response.
    fn evaluate(&mut self, changed: Reads, stage: Stage) -> Vec<Effect> {
        let snap = self.snap.clone();
        if !snap.policy.watches(changed) {
            return Vec::new();
        }
        let shared = self.shared.clone();
        let secrets = |name: &str| snap.secrets.get(name).cloned();
        let ctx = EvalContext {
            secrets: &secrets,
            initial_tags: &[],
        };
        let view = ProxyView::new(
            &self.facts,
            &*shared.metrics,
            &*shared.state,
            &snap.address_lists,
        );
        let out = snap
            .policy
            .evaluate_watching(changed, self.known, &mut self.st, &view, &ctx);
        let metric_err = view.take_metric_error();
        drop(view);
        let Some(o) = out else {
            return Vec::new();
        };
        for r in &o.matched {
            let r = r.to_string();
            if !self.rules.contains(&r) {
                self.rules.push(r);
            }
        }
        let mut headers = Vec::new();
        for e in o.effects {
            match e {
                Effect::Log { level, message } => self.events().rule_log(stage, level, &message),
                Effect::SetState { key, value, ttl } => {
                    if shared.state.set(&key, &value, ttl).is_err() {
                        self.stop_with(Refusal::fail_closed("state_unavailable"), stage);
                    }
                }
                e @ (Effect::SetHeader { .. } | Effect::RemoveHeader(_)) => headers.push(e),
                Effect::RewritePath { .. }
                | Effect::SetQuery { .. }
                | Effect::RemoveQuery(_)
                | Effect::Redirect { .. }
                | Effect::Capture(_)
                | Effect::CallAddon(_) => {
                    self.stop_with(Refusal::fail_closed("unsupported_effect"), stage);
                }
            }
        }
        if let Some(decision) = o.stop {
            let refusal = if let Some(reason) = &o.fail_closed_reason {
                let code = fail_closed_code(reason, metric_err.as_ref());
                self.events()
                    .input_unavailable(stage, code, reason, metric_err.as_ref());
                Refusal::fail_closed(code)
            } else {
                match decision {
                    Decision::Deny {
                        status,
                        message,
                        close,
                    } => {
                        let rule = o
                            .terminal_rule
                            .as_ref()
                            .map_or_else(|| "_fail_closed".to_owned(), ToString::to_string);
                        tracing::info!(flow = %self.flow, rule, stage = stage.as_str(), "watching rule stopped the exchange");
                        Refusal::deny(status, &message, &rule, close)
                    }
                    Decision::Allow(_) | Decision::Passthrough => {
                        Refusal::fail_closed("unsupported_effect")
                    }
                }
            };
            // A stop's own refusal takes precedence over an effect failure
            // in the same evaluation only if nothing stopped earlier.
            self.stop_with(refusal, stage);
            return Vec::new();
        }
        headers
    }
}

/// Wraps a body so each data frame passes [`Watch::on_body_chunk`] before
/// it is yielded. Framing (known length) is preserved; a stop ends the body
/// with [`BodyError::Stopped`] and the frame that caused it is dropped.
pub(crate) fn watched(body: Body, watch: Arc<Watch>, dir: Dir, tap: Option<Tap>) -> Body {
    let known = body.known_length();
    let cancelled = Box::pin(watch.cancelled());
    let sink = watch.sink();
    Body::wrap_native(
        Watched {
            inner: body,
            watch,
            dir,
            cancelled,
            sink,
            tap,
            done: false,
        },
        u64::MAX,
        known,
    )
}

struct Watched {
    inner: Body,
    watch: Arc<Watch>,
    dir: Dir,
    cancelled: Pin<Box<WaitForCancellationFutureOwned>>,
    /// Audit backpressure (§10.1): no chunk moves while the flow log is
    /// behind.
    sink: Arc<dyn FlowSink>,
    /// Capture (§10.2): records each chunk as it is forwarded.
    tap: Option<Tap>,
    done: bool,
}

impl Watched {
    /// Ends the body with [`BodyError::Stopped`]; the capture tap (if any)
    /// records an aborted end.
    fn stop(&mut self) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        self.done = true;
        self.tap = None;
        Poll::Ready(Some(Err(BodyError::Stopped)))
    }
}

impl http_body::Body for Watched {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        if self.done {
            return Poll::Ready(None);
        }
        if self.watch.stop.is_cancelled() {
            return self.stop();
        }
        let capture_behind = self
            .tap
            .as_ref()
            .is_some_and(|t| t.log().poll_ready(cx).is_pending());
        if self.sink.poll_ready(cx).is_pending() || capture_behind {
            if self.cancelled.as_mut().poll(cx).is_ready() {
                return self.stop();
            }
            return Poll::Pending;
        }
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Pending => {
                // Wake up if the exchange is stopped while waiting.
                if self.cancelled.as_mut().poll(cx).is_ready() {
                    return self.stop();
                }
                Poll::Pending
            }
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(d) = frame.data_ref()
                    && !d.is_empty()
                {
                    if self.watch.on_body_chunk(self.dir, d.len() as u64).is_err() {
                        return self.stop();
                    }
                    if let Some(t) = self.tap.as_mut() {
                        t.data(d);
                    }
                }
                // The consumer may not poll again once the body says it
                // has ended, so record the end now.
                if self.inner.is_end_stream()
                    && let Some(mut t) = self.tap.take()
                {
                    t.end(false);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(None) => {
                if let Some(mut t) = self.tap.take() {
                    t.end(false);
                }
                Poll::Ready(None)
            }
            // A failed body: the tap records an aborted end when dropped.
            other @ Poll::Ready(Some(Err(_))) => {
                self.tap = None;
                other
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
