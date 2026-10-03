//! Body capture and traffic teeing (docs/flow-log.md#capture).
//!
//! Captured traffic is one append-only stream, `<capture_dir>/capture.rxc`,
//! written through a [`LogWriter`] (one writer thread, batching, rotation,
//! and the same backpressure as the flow log: capture is never dropped; a
//! slow disk slows traffic).
//!
//! # Format
//!
//! A sequence of records. Each record is one JSON header line, then exactly
//! `len` payload bytes, then `\n`:
//!
//! ```text
//! {"flow":"01J9…","dir":"request","kind":"head","seq":0,"len":187}
//! {"method":"POST","url":"https://api.example.com/v1/x","headers":[["content-type","application/json"]]}
//! {"flow":"01J9…","dir":"request","kind":"data","seq":1,"len":5}
//! hello
//! {"flow":"01J9…","dir":"request","kind":"end","seq":2,"len":0,"bytes":5}
//! ```
//!
//! - `flow` joins the records to the flow log's events.
//! - `dir` is `request` (client → upstream) or `response` (upstream →
//!   client). The WebSocket relay uses the same names for its two
//!   directions.
//! - `kind`:
//!   - `head`: the canonical head as JSON, after rule effects, i.e. as
//!     forwarded;
//!   - `data`: body bytes, exactly as forwarded (or relayed);
//!   - `truncated`: `limits.max_capture_body_bytes` was reached; nothing
//!     more of this direction is captured. The record carries the cap.
//!   - `end`: the direction ended. It carries the total `bytes` forwarded,
//!     and `aborted: true` if it did not complete (stopped by a rule, the
//!     client or upstream went away, an error).
//! - `seq` counts records per flow and direction.
//!
//! What is captured is what was forwarded: data records are written by the
//! same body adapters that forward each chunk, after the watching rules
//! allowed it and before it is handed on.
//!
//! Injected secret values are redacted in captured *head* values (the
//! agent never saw them). Bodies are captured as they are, unredacted.

use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::task::{Context, Poll};

use roxy_http::{CanonicalRequest, CanonicalResponse, Headers};
use roxy_log::{LogWriter, RotateOptions, RotatingFile, WriterOptions};

use crate::flowlog::Redactor;

/// The capture file's name inside `capture_dir`.
pub const CAPTURE_FILE: &str = "capture.rxc";

/// The capture destination, shared by every exchange.
#[derive(Debug)]
pub struct CaptureLog {
    writer: LogWriter,
    path: PathBuf,
    max_body: u64,
    all: bool,
}

/// How [`CaptureLog::open`] is set up.
#[derive(Debug, Clone, Copy)]
pub struct CaptureOptions {
    /// Per body (per direction) cap: `limits.max_capture_body_bytes`.
    pub max_body_bytes: u64,
    /// Capture every forwarded exchange, not only those a rule selects.
    pub all: bool,
    pub writer: WriterOptions,
    pub rotate: RotateOptions,
}

impl CaptureLog {
    /// Opens `<dir>/capture.rxc` for appending, creating `dir` if needed.
    pub fn open(dir: &Path, opts: CaptureOptions) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join(CAPTURE_FILE);
        let dest = RotatingFile::open(&path, opts.rotate)?;
        Ok(Self {
            writer: LogWriter::spawn("capture", dest, opts.writer)?,
            path,
            max_body: opts.max_body_bytes,
            all: opts.all,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether every forwarded exchange is captured.
    pub fn captures_all(&self) -> bool {
        self.all
    }

    /// Backpressure: `Pending` while the capture writer is behind.
    pub fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<()> {
        self.writer.poll_ready(cx)
    }

    /// Blocks until everything captured so far is written.
    pub fn flush(&self) -> bool {
        self.writer.flush()
    }

    /// Reopens the file after external rotation.
    pub fn reopen(&self) {
        self.writer.reopen();
    }

    /// Appends one record: header line, payload, `\n`, as one unit.
    fn record(&self, flow: &str, dir: Dir, kind: &str, seq: u64, extra: &str, payload: &[u8]) {
        let mut buf = Vec::with_capacity(payload.len() + 128);
        let mut head = String::with_capacity(128);
        let _ = writeln!(
            head,
            "{{\"flow\":\"{flow}\",\"dir\":\"{}\",\"kind\":\"{kind}\",\"seq\":{seq},\"len\":{}{extra}}}",
            dir.as_str(),
            payload.len()
        );
        buf.extend_from_slice(head.as_bytes());
        buf.extend_from_slice(payload);
        buf.push(b'\n');
        self.writer.append(&buf);
    }
}

/// A captured direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dir {
    Request,
    Response,
}

impl Dir {
    fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
        }
    }
}

/// One direction of one captured exchange. Owned by the single producer
/// of that direction (a body adapter or a relay pump). Dropping it before
/// [`Tap::end`] records an aborted end, so an exchange cut short is
/// explicit in the capture.
#[derive(Debug)]
pub(crate) struct Tap {
    log: Arc<CaptureLog>,
    flow: String,
    dir: Dir,
    seq: u64,
    /// Body bytes forwarded (captured or not, past the cap).
    bytes: u64,
    truncated: bool,
    ended: bool,
}

impl Tap {
    pub(crate) fn new(log: Arc<CaptureLog>, flow: &str, dir: Dir) -> Self {
        Self {
            log,
            flow: flow.to_owned(),
            dir,
            seq: 0,
            bytes: 0,
            truncated: false,
            ended: false,
        }
    }

    pub(crate) fn log(&self) -> &Arc<CaptureLog> {
        &self.log
    }

    fn next_seq(&mut self) -> u64 {
        let s = self.seq;
        self.seq += 1;
        s
    }

    /// The canonical request head, as forwarded.
    pub(crate) fn request_head(&mut self, req: &CanonicalRequest, redactor: &Redactor) {
        let mut url = format!(
            "{}://{}{}",
            req.scheme,
            req.authority.to_host_header(req.scheme),
            req.path.as_str()
        );
        if let Some(q) = &req.query {
            url.push('?');
            url.push_str(q.as_str());
        }
        let v = serde_json::json!({
            "method": req.method.as_str(),
            "url": url,
            "headers": header_pairs(&req.headers, redactor),
        });
        self.head(&v);
    }

    /// The canonical response head, as sent to the client.
    pub(crate) fn response_head(&mut self, res: &CanonicalResponse, redactor: &Redactor) {
        let v = serde_json::json!({
            "status": res.status.as_u16(),
            "headers": header_pairs(&res.headers, redactor),
        });
        self.head(&v);
    }

    fn head(&mut self, v: &serde_json::Value) {
        let seq = self.next_seq();
        self.log.record(
            &self.flow,
            self.dir,
            "head",
            seq,
            "",
            v.to_string().as_bytes(),
        );
    }

    /// Body bytes about to be forwarded. Past the cap, records one
    /// `truncated` record and nothing more.
    pub(crate) fn data(&mut self, d: &[u8]) {
        self.bytes += d.len() as u64;
        if self.truncated || d.is_empty() {
            return;
        }
        let captured = self.bytes - d.len() as u64;
        let room = self.log.max_body.saturating_sub(captured);
        let take = usize::try_from(room).unwrap_or(usize::MAX).min(d.len());
        if take > 0 {
            let seq = self.next_seq();
            self.log
                .record(&self.flow, self.dir, "data", seq, "", &d[..take]);
        }
        if take < d.len() {
            self.truncated = true;
            let seq = self.next_seq();
            let extra = format!(",\"cap\":{}", self.log.max_body);
            self.log
                .record(&self.flow, self.dir, "truncated", seq, &extra, &[]);
        }
    }

    /// The direction ended; `aborted` if it did not complete.
    pub(crate) fn end(&mut self, aborted: bool) {
        if self.ended {
            return;
        }
        self.ended = true;
        let seq = self.next_seq();
        let mut extra = format!(",\"bytes\":{}", self.bytes);
        if aborted {
            extra.push_str(",\"aborted\":true");
        }
        self.log
            .record(&self.flow, self.dir, "end", seq, &extra, &[]);
    }
}

impl Drop for Tap {
    fn drop(&mut self) {
        self.end(true);
    }
}

fn header_pairs(h: &Headers, redactor: &Redactor) -> Vec<[String; 2]> {
    h.iter()
        .map(|(n, v)| {
            let v = String::from_utf8_lossy(v.as_bytes());
            [n.as_str().to_owned(), redactor.redact_str(&v).into_owned()]
        })
        .collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Parses a capture file into `(header, payload)` records.
    pub(crate) fn parse(bytes: &[u8]) -> Vec<(serde_json::Value, Vec<u8>)> {
        let mut out = Vec::new();
        let mut rest = bytes;
        while !rest.is_empty() {
            let nl = rest.iter().position(|&b| b == b'\n').expect("header line");
            let head: serde_json::Value = serde_json::from_slice(&rest[..nl]).unwrap();
            let len = usize::try_from(head["len"].as_u64().unwrap()).unwrap();
            let payload = rest[nl + 1..nl + 1 + len].to_vec();
            assert_eq!(rest[nl + 1 + len], b'\n', "record terminator");
            rest = &rest[nl + 2 + len..];
            out.push((head, payload));
        }
        out
    }

    fn log(dir: &Path, max_body: u64) -> Arc<CaptureLog> {
        Arc::new(
            CaptureLog::open(
                dir,
                CaptureOptions {
                    max_body_bytes: max_body,
                    all: false,
                    writer: WriterOptions::default(),
                    rotate: RotateOptions::default(),
                },
            )
            .unwrap(),
        )
    }

    #[test]
    fn records_round_trip_and_truncate() {
        let dir = tempfile::tempdir().unwrap();
        let log = log(dir.path(), 8);
        let mut t = Tap::new(log.clone(), "F1", Dir::Request);
        t.data(b"hello");
        t.data(b"\nworld"); // crosses the 8-byte cap
        t.data(b"more");
        t.end(false);
        let mut r = Tap::new(log.clone(), "F1", Dir::Response);
        r.data(b"partial");
        drop(r); // never ended: aborted
        assert!(log.flush());
        let recs = parse(&std::fs::read(log.path()).unwrap());
        let kinds: Vec<(&str, &str)> = recs
            .iter()
            .map(|(h, _)| (h["dir"].as_str().unwrap(), h["kind"].as_str().unwrap()))
            .collect();
        assert_eq!(
            kinds,
            [
                ("request", "data"),
                ("request", "data"),
                ("request", "truncated"),
                ("request", "end"),
                ("response", "data"),
                ("response", "end"),
            ]
        );
        assert_eq!(recs[0].1, b"hello");
        assert_eq!(recs[1].1, b"\nwo", "a payload may contain newlines");
        assert_eq!(recs[2].0["cap"], 8);
        assert_eq!(recs[3].0["bytes"], 15, "total forwarded, past the cap too");
        assert!(recs[3].0.get("aborted").is_none());
        assert_eq!(recs[5].0["aborted"], true);
        let seqs: Vec<u64> = recs[..4]
            .iter()
            .map(|(h, _)| h["seq"].as_u64().unwrap())
            .collect();
        assert_eq!(seqs, [0, 1, 2, 3]);
    }
}
