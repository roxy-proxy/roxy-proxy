//! Structured flow log (docs/flow-log.md).
//!
//! Every stage of the pipeline emits [`FlowEvent`]s to a [`FlowSink`]. Events
//! serialise to one JSON object per line, tagged by an `event` field. Sinks
//! never panic and never propagate write failures into the data path: a
//! failed write is reported as a `tracing` warning and the event is dropped.
//!
//! Strings that may contain secrets must pass through a [`Redactor`] before
//! they are put into an event.

use std::borrow::Cow;
use std::collections::HashSet;
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};

use roxy_log::{LogWriter, RotateOptions, RotatingFile, Stream, WriterOptions};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Serialize, Serializer};

/// Replacement text for redacted values.
pub const REDACTED: &str = "[REDACTED]";

/// Header names whose values are never logged (docs/flow-log.md#redaction). `log.redact_headers`
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
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
// Events are built and emitted immediately, never stored in bulk, so the
// size of the `Request` variant does not matter.
#[allow(clippy::large_enum_variant)]
pub enum FlowEvent {
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
    /// A CONNECT (explicit mode). There are no connect-time rules (docs/http.md#connect):
    /// a CONNECT is accepted for inspection unless proxy auth or the SNI
    /// check refuses it. Only emitted when `log.flow.connection_events` is
    /// enabled or the connect was refused.
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
        flow: String,
        conn: String,
        listener: String,
        client: ClientInfo,
        tls: Option<TlsInfo>,
        req: RequestInfo,
        res: Option<ResponseInfo>,
        decision: DecisionKind,
        rules: Vec<String>,
        tags: Vec<String>,
        mutations: Vec<String>,
        addons: Vec<String>,
        timing: Timing,
        /// The rule that decided (`_default`, `_fail_closed`,
        /// `_address_policy`, … for built-in decisions).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        terminal_rule: Option<String>,
        /// Stable reason code for a deny or failure (`body_too_large_to_inspect`,
        /// `effect_invalid`, `upstream_timeout`, …).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        /// Where the terminal decision was made: `head` for the forwarding
        /// decision, or the stage at which a watching rule stopped the
        /// exchange (docs/rules.md#evaluation). Absent when no decision was reached.
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
    /// A WebSocket upgrade was relayed (docs/websockets.md#relay).
    WsOpen {
        #[serde(serialize_with = "ser_ts")]
        ts: DateTime<Utc>,
        flow: String,
        conn: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host: Option<String>,
    },
    /// A relayed WebSocket closed (docs/websockets.md#relay).
    WsClose {
        #[serde(serialize_with = "ser_ts")]
        ts: DateTime<Utc>,
        flow: String,
        conn: String,
        bytes_c2s: u64,
        bytes_s2c: u64,
        /// The close code roxy sent both sides when it ended the WebSocket
        /// (docs/websockets.md#message-rules).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        close_code: Option<u16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        close_reason: Option<String>,
    },
    /// A checked WebSocket message: denied, or sampled with
    /// `log.flow.ws_message_every` (docs/websockets.md#message-rules).
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
    /// The client sent something roxy refused to parse (docs/http.md#rejection-rules). `reason` is a
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
    /// Connecting to or talking to the upstream failed (docs/upstream.md#errors).
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
    /// An addon layer failed (docs/addons.md#invariants, invariant 3): a trap, an exceeded
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
    /// A structured event an addon recorded (`flow.record`, docs/addons.md#record).
    LayerRecord {
        #[serde(serialize_with = "ser_ts")]
        ts: DateTime<Utc>,
        flow: String,
        conn: String,
        layer: String,
        kind: String,
        /// The addon's JSON, with secrets redacted.
        data: serde_json::Value,
        /// Also sent to the addon's `audit_endpoint`.
        audit: bool,
    },
    /// An addon called a named endpoint (docs/addons.md#endpoints).
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
    /// An observe-mode addon fell behind; its copy of the stream was cut
    /// (the real traffic was not delayed).
    ObserverLagged {
        #[serde(serialize_with = "ser_ts")]
        ts: DateTime<Utc>,
        flow: String,
        layer: String,
        /// `request` or `response`.
        direction: String,
    },
    /// The upstream address policy refused every connection for the flow
    /// (docs/upstream.md#address-floor): a resolved address is private or on a deny list.
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
    /// A new connection was accepted and immediately closed (docs/limits.md#connections).
    ConnectionRefused {
        #[serde(serialize_with = "ser_ts")]
        ts: DateTime<Utc>,
        listener: String,
        client: ClientInfo,
        /// `max_connections` or `max_connections_per_client`.
        reason: String,
    },
    /// A policy input (metric, address list, secret, body) was unavailable
    /// and the flow failed closed (docs/rules.md#evaluation).
    PolicyInputUnavailable {
        #[serde(serialize_with = "ser_ts")]
        ts: DateTime<Utc>,
        flow: String,
        conn: String,
        stage: Stage,
        reason: String,
    },
    /// A metric key could not be created because the table is full (docs/rules.md#metrics).
    MetricTableFull {
        #[serde(serialize_with = "ser_ts")]
        ts: DateTime<Utc>,
        flow: String,
        conn: String,
        stage: Stage,
        detail: String,
    },
    /// A request asked for an Upgrade the matching rule did not grant; it
    /// was forwarded as a plain request (docs/websockets.md).
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
    /// Bytes relayed uninspected (transparent mode only; deferred).
    Passthrough {
        #[serde(serialize_with = "ser_ts")]
        ts: DateTime<Utc>,
        conn: String,
        listener: String,
        client: ClientInfo,
        dst: DstInfo,
        rules: Vec<String>,
    },
}

/// The client side of a connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClientInfo {
    pub ip: IpAddr,
    pub port: u16,
    pub user: Option<String>,
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
pub struct RequestInfo {
    pub method: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub query: Option<String>,
    pub headers_bytes: u64,
    pub body_bytes: u64,
    pub content_type: Option<String>,
}

/// Response summary (never the body).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResponseInfo {
    pub status: u16,
    pub headers_bytes: u64,
    pub body_bytes: u64,
}

/// Timings in milliseconds; `None` where the stage did not happen.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Timing {
    pub total_ms: u64,
    pub upstream_connect_ms: Option<u64>,
    pub upstream_ttfb_ms: Option<u64>,
}

/// Where in an exchange a decision was made (docs/rules.md#evaluation): the forwarding
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
    Passthrough,
}

impl FlowEvent {
    /// Serialise to a single JSON line, including the trailing `\n`.
    pub fn to_json_line(&self) -> serde_json::Result<Vec<u8>> {
        let mut buf = serde_json::to_vec(self)?;
        buf.push(b'\n');
        Ok(buf)
    }
}

/// Timestamps are RFC 3339 UTC with millisecond precision, e.g.
/// `2026-10-03T10:12:00.123Z`.
#[allow(clippy::trivially_copy_pass_by_ref)] // signature required by serde
fn ser_ts<S: Serializer>(ts: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&ts.to_rfc3339_opts(SecondsFormat::Millis, true))
}

// ---------------------------------------------------------------------------
// Sinks
// ---------------------------------------------------------------------------

/// Destination for flow events. `emit` must not panic and must not block on
/// I/O. A sink that writes somewhere slow buffers and exerts backpressure
/// through [`FlowSink::poll_ready`] instead of dropping events (docs/flow-log.md#writing).
pub trait FlowSink: Send + Sync {
    fn emit(&self, event: &FlowEvent);

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

fn encode(event: &FlowEvent) -> Option<Vec<u8>> {
    match event.to_json_line() {
        Ok(line) => Some(line),
        Err(error) => {
            tracing::warn!(%error, "flow log: failed to serialise event");
            None
        }
    }
}

/// Writes JSON lines to any [`Write`]r, flushing after every line.
pub struct WriterSink<W: Write + Send> {
    name: &'static str,
    writer: Mutex<W>,
}

impl<W: Write + Send> WriterSink<W> {
    /// `name` identifies the sink in warnings.
    pub fn new(name: &'static str, writer: W) -> Self {
        Self {
            name,
            writer: Mutex::new(writer),
        }
    }

    /// Consume the sink and return the writer.
    pub fn into_inner(self) -> W {
        self.writer
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

impl<W: Write + Send> FlowSink for WriterSink<W> {
    fn emit(&self, event: &FlowEvent) {
        let Some(line) = encode(event) else { return };
        let mut w = lock(&self.writer);
        if let Err(error) = w.write_all(&line).and_then(|()| w.flush()) {
            tracing::warn!(sink = self.name, %error, "flow log: write failed; event dropped");
        }
    }
}

/// JSON lines through a [`LogWriter`]: one writer thread, batched writes,
/// backpressure (docs/flow-log.md#writing).
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
    fn emit(&self, event: &FlowEvent) {
        if let Some(line) = encode(event) {
            self.writer.append(&line);
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

/// Writes JSON lines to the process's stdout, buffered (docs/flow-log.md).
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
    fn emit(&self, event: &FlowEvent) {
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
/// rotation (docs/flow-log.md#writing).
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
    fn emit(&self, event: &FlowEvent) {
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
    fn emit(&self, event: &FlowEvent) {
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
    fn emit(&self, event: &FlowEvent) {
        match serde_json::to_value(event) {
            Ok(v) => {
                lock(&self.events).push(v);
                self.emitted.notify_waiters();
            }
            Err(error) => tracing::warn!(%error, "flow log: failed to serialise event"),
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn ts() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-03T10:12:00.123456Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn sample_request() -> FlowEvent {
        FlowEvent::Request {
            ts: ts(),
            flow: "01J9FLOW".into(),
            conn: "01J9CONN".into(),
            listener: "proxy".into(),
            client: ClientInfo {
                ip: "10.0.0.7".parse().unwrap(),
                port: 51234,
                user: None,
            },
            tls: Some(TlsInfo {
                sni: Some("api.github.com".into()),
                alpn: Some("h2".into()),
                version: Some("1.3".into()),
            }),
            req: RequestInfo {
                method: "POST".into(),
                host: "api.github.com".into(),
                port: 443,
                path: "/repos/x/y/issues".into(),
                query: None,
                headers_bytes: 812,
                body_bytes: 1032,
                content_type: Some("application/json".into()),
            },
            res: Some(ResponseInfo {
                status: 201,
                headers_bytes: 1420,
                body_bytes: 5120,
            }),
            decision: DecisionKind::Allow,
            rules: vec!["openai-key".into(), "github-writes".into()],
            tags: vec!["billing".into()],
            mutations: vec!["set_header:authorization".into()],
            addons: vec!["pii-scan".into()],
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
        assert_eq!(v["client"]["user"], serde_json::Value::Null);
        assert_eq!(v["tls"]["sni"], "api.github.com");
        assert_eq!(v["req"]["query"], serde_json::Value::Null);
        assert_eq!(v["res"]["status"], 201);
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
            fn emit(&self, event: &FlowEvent) {
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
