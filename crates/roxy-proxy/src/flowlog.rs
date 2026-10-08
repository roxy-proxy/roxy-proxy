//! Structured flow log.
//!
//! Every stage of the pipeline emits [`FlowEvent`]s to a [`FlowSink`]. Events
//! serialise to one JSON object per line, tagged by an `event` field. Sinks
//! never panic and never block the data path on I/O: the log's own sink,
//! [`BufferedSink`], queues lines for a writer thread and, while the queue
//! is full or the writer is failing, holds traffic back through
//! [`FlowSink::poll_ready`] rather than dropping an event.
//!
//! Strings that may contain secrets must pass through a [`Redactor`] before
//! they are put into an event.

use std::borrow::Cow;
use std::collections::HashSet;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};

use roxy_log::{LogWriter, RotateOptions, RotatingFile, Stream, WriterOptions};
use roxy_rules::RuleId;

use chrono::{DateTime, SecondsFormat, Utc};
use serde::ser::SerializeSeq;
use serde::{Serialize, Serializer};

/// Replacement text for redacted values.
pub const REDACTED: &str = "[REDACTED]";

/// Header names whose values are never logged. `log.redact_headers`
/// extends this set.
pub const DEFAULT_REDACTED_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
];

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// One flow-log record. Serialised as `{"ts":..., "event":"<variant>", ...}`.
///
/// `Request` is emitted once per exchange and borrows its strings from the
/// flow, so building it allocates nothing; the other variants are rare and
/// own theirs.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
// Events are built and emitted immediately, never stored in bulk, so the
// size of the `Request` variant does not matter.
#[allow(clippy::large_enum_variant)]
pub enum FlowEvent<'a> {
    /// The configuration was loaded at startup.
    ConfigLoaded {
        #[serde(serialize_with = "ser_ts")]
        ts: DateTime<Utc>,
        path: PathBuf,
        listeners: Vec<String>,
        rules: usize,
        metrics: usize,
        addons: usize,
    },
    /// A new configuration was compiled and swapped in.
    ConfigReloaded {
        #[serde(serialize_with = "ser_ts")]
        ts: DateTime<Utc>,
        path: PathBuf,
        rules: usize,
    },
    /// A reload was attempted and rejected; the old policy stays in force.
    ConfigReloadFailed {
        #[serde(serialize_with = "ser_ts")]
        ts: DateTime<Utc>,
        path: PathBuf,
        diagnostics: Vec<String>,
    },
    /// A CONNECT on the proxy port, accepted for inspection. There are no
    /// connect-time rules: every decision is made on the requests inside
    /// the tunnel, and a tunnel closed at its first bytes is a
    /// `parse_error`. Only emitted when `log.flow.connection_events` is
    /// enabled.
    Connect {
        #[serde(serialize_with = "ser_ts")]
        ts: DateTime<Utc>,
        conn: String,
        listener: String,
        client: ClientInfo,
        dst: DstInfo,
        tls: Option<TlsInfo>,
        decision: DecisionKind,
        rules: Vec<String>,
    },
    /// One request/response exchange. Every flow produces at least one.
    Request {
        #[serde(serialize_with = "ser_ts")]
        ts: DateTime<Utc>,
        flow: Cow<'a, str>,
        conn: Cow<'a, str>,
        listener: Cow<'a, str>,
        client: ClientInfo,
        tls: Option<Cow<'a, TlsInfo>>,
        req: RequestInfo<'a>,
        res: Option<ResponseInfo<'a>>,
        decision: DecisionKind,
        #[serde(serialize_with = "ser_rule_ids")]
        rules: Cow<'a, [RuleId]>,
        tags: Cow<'a, [String]>,
        mutations: Cow<'a, [String]>,
        addons: Cow<'a, [String]>,
        timing: Timing,
        /// The rule that decided (`_default`, `_fail_closed`,
        /// `_address_policy`, … for built-in decisions).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        terminal_rule: Option<Cow<'a, str>>,
        /// Stable reason code for a deny or failure (`body_too_large_to_inspect`,
        /// `effect_invalid`, `timeout`, …).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<Cow<'a, str>>,
        /// Where the terminal decision was made: `head` for the forwarding
        /// decision, or the stage at which a watching rule stopped the
        /// exchange. Absent when no decision was reached.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stage: Option<Stage>,
    },
    /// The response failed after the request was allowed (e.g. body limit hit
    /// mid-stream).
    ResponseError {
        #[serde(serialize_with = "ser_ts")]
        ts: DateTime<Utc>,
        flow: String,
        conn: String,
        reason: String,
        message: String,
    },
    /// A WebSocket upgrade was relayed.
    WsOpen {
        #[serde(serialize_with = "ser_ts")]
        ts: DateTime<Utc>,
        flow: String,
        conn: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host: Option<String>,
    },
    /// A relayed WebSocket closed.
    WsClose {
        #[serde(serialize_with = "ser_ts")]
        ts: DateTime<Utc>,
        flow: String,
        conn: String,
        bytes_c2s: u64,
        bytes_s2c: u64,
        /// The close code roxy sent both sides when it ended the WebSocket.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        close_code: Option<u16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        close_reason: Option<String>,
    },
    /// A checked WebSocket message: denied, or sampled with
    /// `log.flow.ws_message_every`.
    WsMessage {
        #[serde(serialize_with = "ser_ts")]
        ts: DateTime<Utc>,
        flow: String,
        conn: String,
        direction: String,
        opcode: u8,
        size: u64,
        decision: DecisionKind,
        rules: Vec<String>,
    },
    /// The client sent something roxy refused to parse. `reason` is a
    /// stable code suitable for alerting.
    ParseError {
        #[serde(serialize_with = "ser_ts")]
        ts: DateTime<Utc>,
        conn: String,
        flow: Option<String>,
        listener: String,
        client: ClientInfo,
        reason: String,
        detail: Option<String>,
    },
    /// Connecting to or talking to the upstream failed.
    UpstreamError {
        #[serde(serialize_with = "ser_ts")]
        ts: DateTime<Utc>,
        flow: String,
        conn: String,
        host: String,
        port: u16,
        reason: String,
        message: String,
    },
    /// An addon layer failed (invariant 3): a trap, an exceeded
    /// budget, a missing capability, an invalid request or response. In
    /// enforce mode the flow was denied (or its body cut); in observe mode
    /// nothing else happened.
    LayerError {
        #[serde(serialize_with = "ser_ts")]
        ts: DateTime<Utc>,
        flow: String,
        conn: String,
        layer: String,
        /// `enforce` or `observe`.
        mode: String,
        /// `trap`, `budget:<limit>`, `capability:<name>`, `invalid_request`,
        /// ...
        kind: String,
        message: String,
    },
    /// A structured event an addon recorded (`flow.record`).
    LayerRecord {
        #[serde(serialize_with = "ser_ts")]
        ts: DateTime<Utc>,
        flow: String,
        conn: String,
        layer: String,
        kind: String,
        /// The addon's JSON, with secrets redacted.
        data: serde_json::Value,
    },
    /// An addon called a named endpoint.
    EndpointCall {
        #[serde(serialize_with = "ser_ts")]
        ts: DateTime<Utc>,
        flow: String,
        conn: String,
        layer: String,
        endpoint: String,
        method: String,
        path: String,
        status: Option<u16>,
        attempts: u32,
        duration_ms: u64,
        error: Option<String>,
    },
    /// An observe-mode addon's copy of a stream was cut (the real traffic
    /// was not delayed).
    ObserverLagged {
        #[serde(serialize_with = "ser_ts")]
        ts: DateTime<Utc>,
        flow: String,
        layer: String,
        /// `request` or `response`.
        direction: String,
        /// `observer_behind` (the copy outgrew `max_observer_lag_bytes`),
        /// `buffer_budget_exhausted` (the budget could not cover a copy) or
        /// `no_instance` (no instance came free within `first_byte_timeout`).
        reason: String,
    },
    /// The upstream address policy refused every connection for the flow:
    /// a resolved address is private or on a deny list.
    UpstreamDenied {
        #[serde(serialize_with = "ser_ts")]
        ts: DateTime<Utc>,
        flow: String,
        conn: String,
        host: String,
        port: u16,
        resolved_ip: Option<IpAddr>,
        /// `private_range:<class>`, `deny_cidrs` or `list:<name>`.
        reason: String,
        list: Option<String>,
        matched_cidr: Option<String>,
    },
    /// A new connection was accepted and immediately closed.
    ConnectionRefused {
        #[serde(serialize_with = "ser_ts")]
        ts: DateTime<Utc>,
        listener: String,
        client: ClientInfo,
        /// `max_connections` or `max_connections_per_client`.
        reason: String,
    },
    /// A policy input (metric, address list, secret, body) was unavailable
    /// and the flow failed closed.
    PolicyInputUnavailable {
        #[serde(serialize_with = "ser_ts")]
        ts: DateTime<Utc>,
        flow: String,
        conn: String,
        stage: Stage,
        reason: String,
    },
    /// The policy's `valid_until` passed and no reload has replaced it:
    /// every exchange is denied with `_expired`. Once per snapshot.
    PolicyExpired {
        #[serde(serialize_with = "ser_ts")]
        ts: DateTime<Utc>,
        #[serde(serialize_with = "ser_ts")]
        valid_until: DateTime<Utc>,
    },
    /// A metric key could not be created because the table is full.
    MetricTableFull {
        #[serde(serialize_with = "ser_ts")]
        ts: DateTime<Utc>,
        flow: String,
        conn: String,
        stage: Stage,
        detail: String,
    },
    /// A request asked for an Upgrade the matching rule did not grant; it
    /// was forwarded as a plain request.
    UpgradeStripped {
        #[serde(serialize_with = "ser_ts")]
        ts: DateTime<Utc>,
        flow: String,
        conn: String,
        upgrade: String,
    },
    /// A rule's `log` action.
    Log {
        #[serde(serialize_with = "ser_ts")]
        ts: DateTime<Utc>,
        flow: String,
        conn: String,
        stage: Stage,
        level: String,
        message: String,
    },
}

/// The client side of a connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClientInfo {
    pub ip: IpAddr,
    pub port: u16,
}

/// A CONNECT destination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DstInfo {
    pub host: String,
    pub port: u16,
    pub ip: Option<IpAddr>,
}

/// The client-facing TLS session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsInfo {
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub version: Option<String>,
}

/// Request summary (never the body).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RequestInfo<'a> {
    pub method: Cow<'a, str>,
    pub host: Cow<'a, str>,
    pub port: u16,
    pub path: Cow<'a, str>,
    pub query: Option<Cow<'a, str>>,
    pub headers_bytes: u64,
    pub body_bytes: u64,
    /// Lower-case hex SHA-256 of the body as forwarded; absent when the
    /// exchange ended before the body did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_sha256: Option<Cow<'a, str>>,
    pub content_type: Option<Cow<'a, str>>,
}

/// Response summary (never the body).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResponseInfo<'a> {
    pub status: u16,
    pub headers_bytes: u64,
    pub body_bytes: u64,
    /// Lower-case hex SHA-256 of the body as sent; absent when the
    /// exchange ended before the body did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_sha256: Option<Cow<'a, str>>,
}

/// Timings in milliseconds; `None` where the stage did not happen.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Timing {
    pub total_ms: u64,
    pub upstream_connect_ms: Option<u64>,
    pub upstream_ttfb_ms: Option<u64>,
}

/// Where in an exchange a decision was made: the forwarding
/// decision at the request head, or the point at which a watching rule
/// stopped the exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// The forwarding decision at the request head.
    Head,
    /// While the request body streamed upstream.
    RequestBody,
    /// When the response head arrived, before it was sent to the client.
    ResponseHead,
    /// While the response body streamed to the client.
    ResponseBody,
    /// While a WebSocket relay was open.
    Websocket,
}

impl Stage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Head => "head",
            Self::RequestBody => "request_body",
            Self::ResponseHead => "response_head",
            Self::ResponseBody => "response_body",
            Self::Websocket => "websocket",
        }
    }
}

/// Final decision recorded in the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionKind {
    Allow,
    Deny,
    /// An addon layer answered: its request never reached the upstream,
    /// or it abandoned the forwarded request.
    Answered,
}

impl FlowEvent<'_> {
    /// Serialise to a single JSON line, including the trailing `\n`.
    pub fn to_json_line(&self) -> serde_json::Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.write_json_line(&mut buf)?;
        Ok(buf)
    }

    /// Appends the JSON line, trailing `\n` included, to `buf`.
    pub fn write_json_line(&self, buf: &mut Vec<u8>) -> serde_json::Result<()> {
        serde_json::to_writer(&mut *buf, self)?;
        buf.push(b'\n');
        Ok(())
    }
}

/// Timestamps are RFC 3339 UTC with millisecond precision, e.g.
/// `2026-10-03T10:12:00.123Z`.
#[allow(clippy::trivially_copy_pass_by_ref)] // signature required by serde
fn ser_ts<S: Serializer>(ts: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&ts.to_rfc3339_opts(SecondsFormat::Millis, true))
}

/// Rule ids as a list of their names.
fn ser_rule_ids<S: Serializer>(rules: &[RuleId], s: S) -> Result<S::Ok, S::Error> {
    let mut seq = s.serialize_seq(Some(rules.len()))?;
    for r in rules {
        seq.serialize_element(r.as_str())?;
    }
    seq.end()
}

// ---------------------------------------------------------------------------
// Sinks
// ---------------------------------------------------------------------------

/// Destination for flow events. `emit` must not panic and must not block on
/// I/O. A sink that writes somewhere slow buffers and exerts backpressure
/// through [`FlowSink::poll_ready`] instead of dropping events.
pub trait FlowSink: Send + Sync {
    fn emit(&self, event: &FlowEvent<'_>);

    /// `Pending` while the sink is behind (or failing); traffic producers
    /// wait on it before doing more work, so the backlog cannot grow
    /// without bound and audit records are never dropped. Default: always
    /// ready.
    fn poll_ready(&self, _cx: &mut Context<'_>) -> Poll<()> {
        Poll::Ready(())
    }

    /// Blocks until every event emitted so far is written (bounded by the
    /// sink's own timeout). Default: nothing to flush.
    fn flush(&self) {}

    /// Reopens file destinations after external rotation (`SIGHUP`).
    /// Default: nothing to reopen.
    fn reopen(&self) {}
}

/// Waits until `sink` accepts more work ([`FlowSink::poll_ready`]).
pub async fn sink_ready(sink: &dyn FlowSink) {
    std::future::poll_fn(|cx| sink.poll_ready(cx)).await;
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic while holding the lock cannot leave a half-written line that
    // matters more than losing the log entirely; keep going.
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn serialise_failed(error: &serde_json::Error) {
    tracing::warn!(%error, "flow log: failed to serialise event");
}

/// JSON lines through a [`LogWriter`]: one writer thread, batched writes,
/// backpressure.
#[derive(Debug)]
pub struct BufferedSink {
    writer: LogWriter,
}

impl BufferedSink {
    /// Starts the writer thread for `dest`.
    pub fn spawn<D: roxy_log::Destination>(
        name: &'static str,
        dest: D,
        opts: WriterOptions,
    ) -> io::Result<Self> {
        Ok(Self {
            writer: LogWriter::spawn(name, dest, opts)?,
        })
    }

    /// Whether the log is currently holding traffic back.
    pub fn is_holding(&self) -> bool {
        self.writer.is_holding()
    }

    /// Bytes emitted but not yet written.
    pub fn pending(&self) -> usize {
        self.writer.pending()
    }
}

impl FlowSink for BufferedSink {
    fn emit(&self, event: &FlowEvent<'_>) {
        if let Err(error) = self.writer.append_with(|buf| event.write_json_line(buf)) {
            serialise_failed(&error);
        }
    }

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<()> {
        self.writer.poll_ready(cx)
    }

    fn flush(&self) {
        self.writer.flush();
    }

    fn reopen(&self) {
        self.writer.reopen();
    }
}

/// Writes JSON lines to the process's stdout, buffered.
#[derive(Debug)]
pub struct StdoutSink(BufferedSink);

impl StdoutSink {
    pub fn new() -> io::Result<Self> {
        Self::with_options(WriterOptions::default())
    }

    pub fn with_options(opts: WriterOptions) -> io::Result<Self> {
        BufferedSink::spawn("stdout", Stream(io::stdout()), opts).map(Self)
    }
}

impl FlowSink for StdoutSink {
    fn emit(&self, event: &FlowEvent<'_>) {
        self.0.emit(event);
    }

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<()> {
        self.0.poll_ready(cx)
    }

    fn flush(&self) {
        self.0.flush();
    }
}

/// Appends JSON lines to a file, buffered, with optional size-based
/// rotation.
#[derive(Debug)]
pub struct FileSink {
    path: PathBuf,
    inner: BufferedSink,
}

impl FileSink {
    /// Open `path` for appending, creating it if needed.
    pub fn open(path: &Path) -> io::Result<Self> {
        Self::open_with(path, WriterOptions::default(), RotateOptions::default())
    }

    /// [`FileSink::open`] with explicit writer tuning and rotation.
    pub fn open_with(path: &Path, opts: WriterOptions, rotate: RotateOptions) -> io::Result<Self> {
        let dest = RotatingFile::open(path, rotate)?;
        Ok(Self {
            path: path.to_path_buf(),
            inner: BufferedSink::spawn("file", dest, opts)?,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl FlowSink for FileSink {
    fn emit(&self, event: &FlowEvent<'_>) {
        self.inner.emit(event);
    }

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<()> {
        self.inner.poll_ready(cx)
    }

    fn flush(&self) {
        self.inner.flush();
    }

    fn reopen(&self) {
        self.inner.reopen();
    }
}

/// Fans each event out to several sinks.
#[derive(Default)]
pub struct MultiSink {
    sinks: Vec<Box<dyn FlowSink>>,
}

impl MultiSink {
    pub fn new(sinks: Vec<Box<dyn FlowSink>>) -> Self {
        Self { sinks }
    }

    pub fn push(&mut self, sink: Box<dyn FlowSink>) {
        self.sinks.push(sink);
    }

    pub fn len(&self) -> usize {
        self.sinks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sinks.is_empty()
    }
}

impl FlowSink for MultiSink {
    fn emit(&self, event: &FlowEvent<'_>) {
        for sink in &self.sinks {
            sink.emit(event);
        }
    }

    /// Ready only when every sink is.
    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<()> {
        let mut ready = true;
        for sink in &self.sinks {
            ready &= sink.poll_ready(cx).is_ready();
        }
        if ready {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    fn flush(&self) {
        for sink in &self.sinks {
            sink.flush();
        }
    }

    fn reopen(&self) {
        for sink in &self.sinks {
            sink.reopen();
        }
    }
}

/// Keeps events in memory as JSON values. Intended for tests.
#[derive(Debug, Default)]
pub struct MemorySink {
    events: Mutex<Vec<serde_json::Value>>,
    emitted: tokio::sync::Notify,
}

impl MemorySink {
    pub fn new() -> Self {
        Self::default()
    }

    /// A copy of every event emitted so far.
    pub fn events(&self) -> Vec<serde_json::Value> {
        lock(&self.events).clone()
    }

    /// Waits until at least `n` events of `kind` (the `event` field) were
    /// emitted, and returns all of that kind. Panics after `timeout`,
    /// listing what was logged.
    pub async fn wait_for(
        &self,
        kind: &str,
        n: usize,
        timeout: std::time::Duration,
    ) -> Vec<serde_json::Value> {
        let of_kind = || -> Vec<serde_json::Value> {
            lock(&self.events)
                .iter()
                .filter(|e| e["event"] == kind)
                .cloned()
                .collect()
        };
        let wait = async {
            loop {
                let emitted = self.emitted.notified();
                let found = of_kind();
                if found.len() >= n {
                    return found;
                }
                emitted.await;
            }
        };
        tokio::time::timeout(timeout, wait)
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "wanted {n} `{kind}` events within {timeout:?}; logged: {:#?}",
                    self.events()
                )
            })
    }
}

impl FlowSink for MemorySink {
    fn emit(&self, event: &FlowEvent<'_>) {
        match serde_json::to_value(event) {
            Ok(v) => {
                lock(&self.events).push(v);
                self.emitted.notify_waiters();
            }
            Err(error) => serialise_failed(&error),
        }
    }
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

/// Scrubs secret values and sensitive headers from logged strings.
#[derive(Debug, Clone)]
pub struct Redactor {
    secrets: Vec<String>,
    headers: HashSet<String>,
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new()
    }
}

impl Redactor {
    /// A redactor with no secrets and the default redacted headers.
    pub fn new() -> Self {
        Self {
            secrets: Vec::new(),
            headers: DEFAULT_REDACTED_HEADERS
                .iter()
                .map(|h| (*h).to_owned())
                .collect(),
        }
    }

    /// Register a secret value. Empty strings are ignored.
    pub fn add_secret(&mut self, secret: impl Into<String>) {
        let secret = secret.into();
        if !secret.is_empty() && !self.secrets.contains(&secret) {
            self.secrets.push(secret);
        }
    }

    /// Add a header name (case-insensitive) whose values are never logged.
    pub fn add_header(&mut self, name: &str) {
        self.headers.insert(name.to_ascii_lowercase());
    }

    /// Whether values of header `name` are redacted.
    pub fn is_redacted_header(&self, name: &str) -> bool {
        self.headers.contains(&name.to_ascii_lowercase())
    }

    /// Replace every occurrence of a registered secret in `s` with
    /// [`REDACTED`]. Overlapping occurrences are merged into one marker.
    pub fn redact_str<'a>(&self, s: &'a str) -> Cow<'a, str> {
        let mut ranges: Vec<(usize, usize)> = Vec::new();
        for secret in &self.secrets {
            // Find every start position, including overlapping ones.
            let mut from = 0;
            while let Some(i) = s[from..].find(secret.as_str()) {
                let start = from + i;
                ranges.push((start, start + secret.len()));
                // Advance by one char so overlapping matches are found.
                from = start + s[start..].chars().next().map_or(1, char::len_utf8);
            }
        }
        if ranges.is_empty() {
            return Cow::Borrowed(s);
        }
        ranges.sort_unstable();
        let mut out = String::with_capacity(s.len());
        let mut pos = 0;
        let mut iter = ranges.into_iter().peekable();
        while let Some((start, mut end)) = iter.next() {
            while let Some(&(next_start, next_end)) = iter.peek() {
                if next_start > end {
                    break;
                }
                end = end.max(next_end);
                iter.next();
            }
            out.push_str(&s[pos..start]);
            out.push_str(REDACTED);
            pos = end;
        }
        out.push_str(&s[pos..]);
        Cow::Owned(out)
    }

    /// The loggable form of a header value: [`REDACTED`] for redacted header
    /// names, otherwise the value with secrets scrubbed.
    pub fn redact_header<'a>(&self, name: &str, value: &'a str) -> Cow<'a, str> {
        if self.is_redacted_header(name) {
            Cow::Borrowed(REDACTED)
        } else {
            self.redact_str(value)
        }
    }

    /// Every string in `v`, object keys included, with secrets scrubbed.
    pub fn redact_json(&self, v: serde_json::Value) -> serde_json::Value {
        use serde_json::Value;
        match v {
            Value::String(s) => Value::String(self.redact_str(&s).into_owned()),
            Value::Array(a) => Value::Array(a.into_iter().map(|x| self.redact_json(x)).collect()),
            Value::Object(o) => Value::Object(
                o.into_iter()
                    .map(|(k, x)| (self.redact_str(&k).into_owned(), self.redact_json(x)))
                    .collect(),
            ),
            other @ (Value::Null | Value::Bool(_) | Value::Number(_)) => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::Waker;

    /// Writes JSON lines to any [`Write`]r, flushing after every line, and
    /// drops an event whose write fails. For tests and tools; an audit log is a
    /// [`BufferedSink`].
    pub(crate) struct WriterSink<W: Write + Send> {
        name: &'static str,
        writer: Mutex<W>,
    }

    impl<W: Write + Send> WriterSink<W> {
        /// `name` identifies the sink in warnings.
        pub(crate) fn new(name: &'static str, writer: W) -> Self {
            Self {
                name,
                writer: Mutex::new(writer),
            }
        }

        /// Consume the sink and return the writer.
        pub(crate) fn into_inner(self) -> W {
            self.writer
                .into_inner()
                .unwrap_or_else(PoisonError::into_inner)
        }
    }

    impl<W: Write + Send> FlowSink for WriterSink<W> {
        fn emit(&self, event: &FlowEvent<'_>) {
            let line = match event.to_json_line() {
                Ok(line) => line,
                Err(error) => return serialise_failed(&error),
            };
            let mut w = lock(&self.writer);
            if let Err(error) = w.write_all(&line).and_then(|()| w.flush()) {
                tracing::warn!(sink = self.name, %error, "flow log: write failed; event dropped");
            }
        }
    }
    use std::sync::Arc;

    fn ts() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-03T10:12:00.123456Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn sample_request() -> FlowEvent<'static> {
        FlowEvent::Request {
            ts: ts(),
            flow: "01J9FLOW".into(),
            conn: "01J9CONN".into(),
            listener: "proxy".into(),
            client: ClientInfo {
                ip: "10.0.0.7".parse().unwrap(),
                port: 51234,
            },
            tls: Some(Cow::Owned(TlsInfo {
                sni: Some("api.github.com".into()),
                alpn: Some("h2".into()),
                version: Some("1.3".into()),
            })),
            req: RequestInfo {
                method: "POST".into(),
                host: "api.github.com".into(),
                port: 443,
                path: "/repos/x/y/issues".into(),
                query: None,
                headers_bytes: 812,
                body_bytes: 1032,
                body_sha256: Some(
                    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08".into(),
                ),
                content_type: Some("application/json".into()),
            },
            res: Some(ResponseInfo {
                status: 201,
                headers_bytes: 1420,
                body_bytes: 5120,
                body_sha256: None,
            }),
            decision: DecisionKind::Allow,
            rules: vec![RuleId::new("openai-key"), RuleId::new("github-writes")].into(),
            tags: vec!["billing".into()].into(),
            mutations: vec!["set_header:authorization".into()].into(),
            addons: vec!["pii-scan".into()].into(),
            timing: Timing {
                total_ms: 412,
                upstream_connect_ms: Some(38),
                upstream_ttfb_ms: Some(350),
            },
            terminal_rule: Some("github-writes".into()),
            reason: None,
            stage: Some(Stage::Head),
        }
    }

    #[test]
    fn request_event_shape() {
        let v = serde_json::to_value(sample_request()).unwrap();
        assert_eq!(v["event"], "request");
        assert_eq!(v["ts"], "2026-10-03T10:12:00.123Z");
        assert_eq!(v["client"]["ip"], "10.0.0.7");
        assert_eq!(v["tls"]["sni"], "api.github.com");
        assert_eq!(v["req"]["query"], serde_json::Value::Null);
        assert_eq!(
            v["req"]["body_sha256"],
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
        assert_eq!(v["res"]["status"], 201);
        assert!(v["res"].get("body_sha256").is_none(), "{v:#}");
        assert_eq!(v["decision"], "allow");
        assert_eq!(v["timing"]["upstream_ttfb_ms"], 350);
        assert_eq!(v["terminal_rule"], "github-writes");
        assert_eq!(v["stage"], "head");
        assert!(v.get("reason").is_none());
    }

    #[test]
    fn json_line_is_single_line() {
        let line = sample_request().to_json_line().unwrap();
        assert_eq!(line.last(), Some(&b'\n'));
        assert_eq!(String::from_utf8(line).unwrap().matches('\n').count(), 1);
    }

    #[test]
    fn config_loaded_event() {
        let ev = FlowEvent::ConfigLoaded {
            ts: ts(),
            path: "/etc/roxy/roxy.yaml".into(),
            listeners: vec!["proxy".into()],
            rules: 3,
            metrics: 0,
            addons: 0,
        };
        let v = serde_json::to_value(ev).unwrap();
        assert_eq!(v["event"], "config_loaded");
        assert_eq!(v["rules"], 3);
    }

    #[test]
    fn file_sink_appends_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("flow.jsonl");
        std::fs::write(&path, "{\"existing\":true}\n").unwrap();
        let sink = FileSink::open(&path).unwrap();
        sink.emit(&sample_request());
        sink.emit(&sample_request());
        // Writes are asynchronous (one writer thread); flush first.
        sink.flush();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.ends_with('\n'));
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 3);
        for line in &lines[1..] {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(v["event"], "request");
        }
    }

    struct FailingWriter;
    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("disk on fire"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("disk on fire"))
        }
    }

    #[test]
    fn write_failure_does_not_panic() {
        let sink = WriterSink::new("test", FailingWriter);
        sink.emit(&sample_request());
        sink.emit(&sample_request());
    }

    #[test]
    fn writer_sink_flushes_each_line() {
        let sink = WriterSink::new("test", Vec::new());
        sink.emit(&sample_request());
        let out = sink.into_inner();
        assert_eq!(String::from_utf8(out).unwrap().matches('\n').count(), 1);
    }

    #[test]
    fn multi_sink_fans_out() {
        struct Shared(Arc<MemorySink>);
        impl FlowSink for Shared {
            fn emit(&self, event: &FlowEvent<'_>) {
                self.0.emit(event);
            }
        }
        let a = Arc::new(MemorySink::new());
        let b = Arc::new(MemorySink::new());
        let multi = MultiSink::new(vec![
            Box::new(Shared(a.clone())),
            Box::new(Shared(b.clone())),
            Box::new(WriterSink::new("failing", FailingWriter)),
        ]);
        assert_eq!(multi.len(), 3);
        multi.emit(&sample_request());
        assert_eq!(a.events().len(), 1);
        assert_eq!(b.events().len(), 1);
        assert_eq!(a.events()[0]["event"], "request");
    }

    /// The fan-out is ready only when every sink is, and asks every sink on
    /// each poll so each one registers the waker: a sink that becomes ready
    /// later can wake the producer whichever sink held it.
    #[test]
    fn multi_sink_is_ready_only_when_every_sink_is() {
        struct Gated {
            ready: Arc<AtomicBool>,
            polls: Arc<AtomicUsize>,
        }
        impl FlowSink for Gated {
            fn emit(&self, _: &FlowEvent<'_>) {}
            fn poll_ready(&self, _: &mut Context<'_>) -> Poll<()> {
                self.polls.fetch_add(1, Ordering::SeqCst);
                if self.ready.load(Ordering::SeqCst) {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            }
        }
        let gated = |ready: bool| {
            let flag = Arc::new(AtomicBool::new(ready));
            let polls = Arc::new(AtomicUsize::new(0));
            let sink = Gated {
                ready: flag.clone(),
                polls: polls.clone(),
            };
            (Box::new(sink) as Box<dyn FlowSink>, flag, polls)
        };
        let (a, _, a_polls) = gated(true);
        let (b, b_ready, b_polls) = gated(false);
        let (c, _, c_polls) = gated(true);
        let multi = MultiSink::new(vec![a, b, c]);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(multi.poll_ready(&mut cx).is_pending());
        for polls in [&a_polls, &b_polls, &c_polls] {
            assert_eq!(polls.load(Ordering::SeqCst), 1);
        }
        b_ready.store(true, Ordering::SeqCst);
        assert!(multi.poll_ready(&mut cx).is_ready());
    }

    #[test]
    fn redact_str_replaces_secrets() {
        let mut r = Redactor::new();
        r.add_secret("sk-live-123");
        r.add_secret("");
        assert!(matches!(r.redact_str("nothing here"), Cow::Borrowed(_)));
        assert_eq!(
            r.redact_str("Bearer sk-live-123 and sk-live-123!"),
            "Bearer [REDACTED] and [REDACTED]!"
        );
    }

    #[test]
    fn redact_str_handles_overlaps() {
        let mut r = Redactor::new();
        r.add_secret("abcd");
        r.add_secret("cdef");
        r.add_secret("aa");
        assert_eq!(r.redact_str("xabcdefx"), "x[REDACTED]x");
        assert_eq!(r.redact_str("aaa"), "[REDACTED]");
        assert_eq!(r.redact_str("é-abcd-é"), "é-[REDACTED]-é");
    }

    #[test]
    fn redact_json_scrubs_keys_as_well_as_values() {
        let mut r = Redactor::new();
        r.add_secret("hunter2");
        let v = serde_json::json!({"token hunter2": ["hunter2", {"hunter2": 1}]});
        let out = r.redact_json(v).to_string();
        assert!(!out.contains("hunter2"), "{out}");
    }

    #[test]
    fn redact_header_defaults_and_extensions() {
        let mut r = Redactor::new();
        for h in DEFAULT_REDACTED_HEADERS {
            assert_eq!(r.redact_header(h, "v"), REDACTED);
        }
        assert_eq!(r.redact_header("Authorization", "Bearer x"), REDACTED);
        assert_eq!(r.redact_header("x-custom", "visible"), "visible");
        r.add_header("X-Custom");
        assert_eq!(r.redact_header("x-custom", "visible"), REDACTED);
        r.add_secret("tok");
        assert_eq!(r.redact_header("x-other", "a tok b"), "a [REDACTED] b");
    }
}
