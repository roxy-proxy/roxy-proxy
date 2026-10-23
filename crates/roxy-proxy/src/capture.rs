//! Body capture and traffic teeing.
//!
//! Captured traffic is one append-only stream, `<capture_dir>/capture.rxc`
//! or `<capture_dir>/capture.jsonl` by [`CaptureFormat`], written through a [`LogWriter`] (one writer thread, batching, rotation,
//! and the same backpressure as the flow log: capture is never dropped; a
//! slow disk slows traffic).
//!
//! # Format
//!
//! In `rxc`, a sequence of records. Each record is one JSON header line, then exactly
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
//! In `jsonl`, the same records one JSON object per line, with no `len`:
//! a head nested under `head`, data base64 under `data`, and a data
//! record at most [`JSONL_DATA_MAX`] bytes, so a larger chunk spans
//! several records.
//!
//! What is captured is what was forwarded: data records are written by the
//! same body adapters that forward each chunk, after the in-flight rules
//! allowed it and before it is handed on.
//!
//! Every string in a captured *head* passes through the exchange's
//! redactor, so an injected secret value (which the agent never saw) is
//! scrubbed wherever it appears. Bodies are captured as they are,
//! unredacted.

use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::task::{Context, Poll};

use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use roxy_http::{CanonicalRequest, CanonicalResponse, Headers};
use roxy_log::{LogWriter, RotateOptions, RotatingFile, WriterOptions};

use crate::secrets::Secrets;

/// The capture file's name inside `capture_dir`, in the default format.
pub const CAPTURE_FILE: &str = "capture.rxc";

/// How capture records are laid out on disk: `log.capture.format`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureFormat {
    /// A JSON header line, then `len` raw payload bytes, then `\n`.
    #[default]
    Rxc,
    /// One JSON object per line, the payload inline: a head nested under
    /// `head`, body bytes base64 under `data`. Line-oriented shippers split
    /// on `\n`, which raw payload bytes would corrupt.
    Jsonl,
}

/// The most body bytes one `jsonl` data record carries: 64 KiB once base64
/// encoded. Forwarded chunks have no useful bound of their own (a
/// WebSocket message can be 16 MiB), and a shipper's line limit needs one.
pub const JSONL_DATA_MAX: usize = 48 << 10;

impl CaptureFormat {
    /// The capture file's name inside `capture_dir`. Rotations append
    /// `.<UTC>-<seq>`, so the name tells a reader the format.
    pub fn file_name(self) -> &'static str {
        match self {
            Self::Rxc => CAPTURE_FILE,
            Self::Jsonl => "capture.jsonl",
        }
    }

    /// The most body bytes one data record carries.
    fn data_max(self) -> usize {
        match self {
            Self::Rxc => usize::MAX,
            Self::Jsonl => JSONL_DATA_MAX,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rxc => "rxc",
            Self::Jsonl => "jsonl",
        }
    }
}

/// The capture destination, shared by every exchange.
#[derive(Debug)]
pub struct CaptureLog {
    writer: LogWriter,
    path: PathBuf,
    format: CaptureFormat,
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
    pub format: CaptureFormat,
    pub writer: WriterOptions,
    pub rotate: RotateOptions,
}

impl CaptureLog {
    /// Opens the format's file in `dir` for appending, creating `dir` if
    /// needed.
    pub fn open(dir: &Path, opts: CaptureOptions) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join(opts.format.file_name());
        let dest = RotatingFile::open(&path, opts.rotate)?;
        Ok(Self {
            writer: LogWriter::spawn("capture", dest, opts.writer)?,
            path,
            format: opts.format,
            max_body: opts.max_body_bytes,
            all: opts.all,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn format(&self) -> CaptureFormat {
        self.format
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

    /// Appends one record as one unit: in `rxc` the header line, the
    /// payload and `\n`; in `jsonl` one line with the payload inline.
    fn record(&self, flow: &str, dir: Dir, kind: &str, seq: u64, extra: &str, payload: Payload) {
        let mut line = String::with_capacity(128);
        let _ = write!(
            line,
            "{{\"flow\":\"{flow}\",\"dir\":\"{}\",\"kind\":\"{kind}\",\"seq\":{seq}",
            dir.as_str()
        );
        let buf = match self.format {
            CaptureFormat::Rxc => {
                let bytes = match &payload {
                    Payload::None => Vec::new(),
                    Payload::Head(v) => v.to_string().into_bytes(),
                    Payload::Data(d) => d.to_vec(),
                };
                let _ = writeln!(line, ",\"len\":{}{extra}}}", bytes.len());
                let mut buf = Vec::with_capacity(line.len() + bytes.len() + 1);
                buf.extend_from_slice(line.as_bytes());
                buf.extend_from_slice(&bytes);
                buf.push(b'\n');
                buf
            }
            CaptureFormat::Jsonl => {
                line.push_str(extra);
                match payload {
                    Payload::None => {}
                    Payload::Head(v) => {
                        let _ = write!(line, ",\"head\":{v}");
                    }
                    Payload::Data(d) => {
                        line.push_str(",\"data\":\"");
                        BASE64_STANDARD.encode_string(d, &mut line);
                        line.push('"');
                    }
                }
                line.push_str("}\n");
                line.into_bytes()
            }
        };
        self.writer.append(&buf);
    }
}

/// What a record carries besides its header fields.
#[derive(Clone, Copy)]
enum Payload<'a> {
    None,
    Head(&'a serde_json::Value),
    Data(&'a [u8]),
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
/// explicit in the capture. A tap that recorded nothing (the exchange was
/// refused before its head left) ends silently: there is no record to
/// close.
#[derive(Debug)]
pub(crate) struct Tap {
    log: Arc<CaptureLog>,
    /// The exchange's secret generation: every head string is redacted
    /// from it, in [`Tap::head`] and nowhere else.
    secrets: Arc<Secrets>,
    flow: String,
    dir: Dir,
    seq: u64,
    /// Body bytes forwarded (captured or not, past the cap).
    bytes: u64,
    truncated: bool,
    ended: bool,
}

impl Tap {
    pub(crate) fn new(log: Arc<CaptureLog>, secrets: Arc<Secrets>, flow: &str, dir: Dir) -> Self {
        Self {
            log,
            secrets,
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
    pub(crate) fn request_head(&mut self, req: &CanonicalRequest) {
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
            "headers": header_pairs(&req.headers),
        });
        self.head(v);
    }

    /// The canonical response head, as sent to the client.
    pub(crate) fn response_head(&mut self, res: &CanonicalResponse) {
        let v = serde_json::json!({
            "status": res.status.as_u16(),
            "headers": header_pairs(&res.headers),
        });
        self.head(v);
    }

    /// Writes a head record. The one place a head is redacted: whatever a
    /// head builder puts in `v` is scrubbed here.
    fn head(&mut self, v: serde_json::Value) {
        let v = self.secrets.redactor().redact_json(v);
        let seq = self.next_seq();
        self.log
            .record(&self.flow, self.dir, "head", seq, "", Payload::Head(&v));
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
        for part in d[..take].chunks(self.log.format.data_max()) {
            let seq = self.next_seq();
            self.log
                .record(&self.flow, self.dir, "data", seq, "", Payload::Data(part));
        }
        if take < d.len() {
            self.truncated = true;
            let seq = self.next_seq();
            let extra = format!(",\"cap\":{}", self.log.max_body);
            self.log.record(
                &self.flow,
                self.dir,
                "truncated",
                seq,
                &extra,
                Payload::None,
            );
        }
    }

    /// The direction ended; `aborted` if it did not complete.
    pub(crate) fn end(&mut self, aborted: bool) {
        if self.ended || self.seq == 0 {
            return;
        }
        self.ended = true;
        let seq = self.next_seq();
        let mut extra = format!(",\"bytes\":{}", self.bytes);
        if aborted {
            extra.push_str(",\"aborted\":true");
        }
        self.log
            .record(&self.flow, self.dir, "end", seq, &extra, Payload::None);
    }
}

impl Drop for Tap {
    fn drop(&mut self) {
        self.end(true);
    }
}

fn header_pairs(h: &Headers) -> Vec<[String; 2]> {
    h.iter()
        .map(|(n, v)| {
            [
                n.as_str().to_owned(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            ]
        })
        .collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::HashMap;

    use roxy_http::url::{parse_authority, parse_origin_form};
    use roxy_http::{Body, HttpFlags, Limits, Method, RequestMeta, Scheme, TargetForm, Version};

    use super::*;
    use crate::flowlog::{REDACTED, Redactor};
    use crate::secrets::SecretStore;

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

    /// Parses a `jsonl` capture file into the same `(header, payload)`
    /// records as [`parse`]: the payload taken out of the line (a head
    /// re-serialised, data base64-decoded) and `len` added, so the two
    /// formats compare equal record for record.
    pub(crate) fn parse_jsonl(bytes: &[u8]) -> Vec<(serde_json::Value, Vec<u8>)> {
        let text = std::str::from_utf8(bytes).expect("jsonl is UTF-8");
        assert!(text.is_empty() || text.ends_with('\n'), "last line ends");
        text.lines()
            .map(|line| {
                let mut v: serde_json::Value = serde_json::from_str(line).unwrap();
                let obj = v.as_object_mut().unwrap();
                assert!(obj.get("len").is_none(), "{line}");
                let payload = match (obj.remove("head"), obj.remove("data")) {
                    (Some(head), None) => head.to_string().into_bytes(),
                    (None, Some(data)) => BASE64_STANDARD.decode(data.as_str().unwrap()).unwrap(),
                    (None, None) => Vec::new(),
                    (Some(_), Some(_)) => panic!("head and data: {line}"),
                };
                obj.insert("len".into(), payload.len().into());
                (v, payload)
            })
            .collect()
    }

    /// Parses a capture file written in `format`.
    pub(crate) fn parse_as(
        format: CaptureFormat,
        bytes: &[u8],
    ) -> Vec<(serde_json::Value, Vec<u8>)> {
        match format {
            CaptureFormat::Rxc => parse(bytes),
            CaptureFormat::Jsonl => parse_jsonl(bytes),
        }
    }

    /// A secret generation holding `values`.
    fn secrets(values: &[&str]) -> Arc<Secrets> {
        let values = values
            .iter()
            .enumerate()
            .map(|(i, v)| (format!("s{i}"), (*v).to_owned()))
            .collect::<HashMap<_, _>>();
        SecretStore::new(values, Redactor::new()).load()
    }

    fn log(dir: &Path, max_body: u64) -> Arc<CaptureLog> {
        log_as(dir, max_body, CaptureFormat::Rxc)
    }

    fn log_as(dir: &Path, max_body: u64, format: CaptureFormat) -> Arc<CaptureLog> {
        Arc::new(
            CaptureLog::open(
                dir,
                CaptureOptions {
                    max_body_bytes: max_body,
                    all: false,
                    format,
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
        let mut t = Tap::new(log.clone(), secrets(&[]), "F1", Dir::Request);
        t.data(b"hello");
        t.data(b"\nworld"); // crosses the 8-byte cap
        t.data(b"more");
        t.end(false);
        let mut r = Tap::new(log.clone(), secrets(&[]), "F1", Dir::Response);
        r.data(b"partial");
        drop(r); // never ended: aborted
        drop(Tap::new(log.clone(), secrets(&[]), "F2", Dir::Request)); // nothing recorded: nothing to end
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

    /// A secret value is scrubbed from a captured head wherever it sits:
    /// the URL's path and query, and header names and values alike.
    #[test]
    fn heads_are_redacted_with_the_exchanges_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let log = log(dir.path(), 8);
        let secret = "sk-live-123";
        let (path, query) =
            parse_origin_form(format!("/v1/{secret}/x?k={secret}&plain=1").as_bytes()).unwrap();
        let secret_name = format!("x-{secret}");
        let raw: Vec<(&[u8], &[u8])> = vec![
            (b"x-token", secret.as_bytes()),
            (secret_name.as_bytes(), b"v"),
        ];
        let headers =
            Headers::try_from_raw(raw, &Limits::default(), &HttpFlags::default()).unwrap();
        let req = CanonicalRequest {
            method: Method::parse(b"GET").unwrap(),
            scheme: Scheme::Https,
            authority: parse_authority(b"api.example.com", 443).unwrap(),
            path,
            query,
            headers,
            body: Body::empty(),
            meta: RequestMeta::new(Version::H1_1, TargetForm::Origin),
        };
        let mut res = CanonicalResponse::new(http::StatusCode::OK);
        res.headers.append("x-echo", secret).unwrap();

        let mut up = Tap::new(log.clone(), secrets(&[secret]), "F1", Dir::Request);
        up.request_head(&req);
        let mut down = Tap::new(log.clone(), secrets(&[secret]), "F1", Dir::Response);
        down.response_head(&res);
        assert!(log.flush());

        let records = parse(&std::fs::read(log.path()).unwrap());
        assert_eq!(records.len(), 2);
        for (_, payload) in &records {
            let text = std::str::from_utf8(payload).unwrap();
            assert!(!text.contains(secret), "{text}");
        }
        let head: serde_json::Value = serde_json::from_slice(&records[0].1).unwrap();
        assert_eq!(
            head["url"],
            format!("https://api.example.com/v1/{REDACTED}/x?k={REDACTED}&plain=1")
        );
        assert_eq!(
            head["headers"],
            serde_json::json!([["x-token", REDACTED], [format!("x-{REDACTED}"), "v"]])
        );
        let head: serde_json::Value = serde_json::from_slice(&records[1].1).unwrap();
        assert_eq!(head["headers"], serde_json::json!([["x-echo", REDACTED]]));
    }

    /// One exchange's worth of records through a log in `format`: a
    /// redacted head, data with a newline and a non-UTF-8 byte, a
    /// truncation, and an aborted direction.
    fn sample(format: CaptureFormat) -> (Arc<CaptureLog>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let log = log_as(dir.path(), 8, format);
        let mut res = CanonicalResponse::new(http::StatusCode::OK);
        res.headers.append("x-echo", "sk-1").unwrap();
        let mut t = Tap::new(log.clone(), secrets(&["sk-1"]), "F1", Dir::Response);
        t.response_head(&res);
        t.data(b"a\nb\xff");
        t.data(b"cdefgh");
        t.end(false);
        let mut r = Tap::new(log.clone(), secrets(&[]), "F1", Dir::Request);
        r.data(b"x");
        drop(r);
        assert!(log.flush());
        (log, dir)
    }

    /// The `jsonl` shape, pinned line for line.
    #[test]
    fn jsonl_records_are_one_line_each() {
        let (log, _dir) = sample(CaptureFormat::Jsonl);
        assert!(
            log.path().ends_with("capture.jsonl"),
            "{}",
            log.path().display()
        );
        let text = String::from_utf8(std::fs::read(log.path()).unwrap()).unwrap();
        let expected = [
            format!(
                r#"{{"flow":"F1","dir":"response","kind":"head","seq":0,"head":{{"headers":[["x-echo","{REDACTED}"]],"status":200}}}}"#
            ),
            r#"{"flow":"F1","dir":"response","kind":"data","seq":1,"data":"YQpi/w=="}"#.to_owned(),
            r#"{"flow":"F1","dir":"response","kind":"data","seq":2,"data":"Y2RlZg=="}"#.to_owned(),
            r#"{"flow":"F1","dir":"response","kind":"truncated","seq":3,"cap":8}"#.to_owned(),
            r#"{"flow":"F1","dir":"response","kind":"end","seq":4,"bytes":10}"#.to_owned(),
            r#"{"flow":"F1","dir":"request","kind":"data","seq":0,"data":"eA=="}"#.to_owned(),
            r#"{"flow":"F1","dir":"request","kind":"end","seq":1,"bytes":1,"aborted":true}"#
                .to_owned(),
        ];
        assert_eq!(text.lines().collect::<Vec<_>>(), expected);
        assert!(text.ends_with('\n'));
    }

    /// The same records written in either format read back the same.
    #[test]
    fn formats_carry_the_same_records() {
        let (rxc, _a) = sample(CaptureFormat::Rxc);
        let (jsonl, _b) = sample(CaptureFormat::Jsonl);
        assert!(rxc.path().ends_with(CAPTURE_FILE));
        let rxc = parse(&std::fs::read(rxc.path()).unwrap());
        let jsonl = parse_jsonl(&std::fs::read(jsonl.path()).unwrap());
        assert_eq!(rxc.len(), 7);
        assert_eq!(rxc, jsonl);
    }

    /// A chunk larger than [`JSONL_DATA_MAX`] spans several `jsonl` data
    /// records, so a line never outgrows the documented bound; `rxc` keeps
    /// it as one.
    #[test]
    fn a_large_chunk_is_split_across_jsonl_lines() {
        let chunk: Vec<u8> = (0..=255u8).cycle().take(JSONL_DATA_MAX * 2 + 1).collect();
        for (format, records) in [(CaptureFormat::Rxc, 1), (CaptureFormat::Jsonl, 3)] {
            let dir = tempfile::tempdir().unwrap();
            let log = log_as(dir.path(), u64::MAX, format);
            let mut t = Tap::new(log.clone(), secrets(&[]), "F1", Dir::Request);
            t.data(&chunk);
            t.end(false);
            assert!(log.flush());
            let bytes = std::fs::read(log.path()).unwrap();
            let recs = parse_as(format, &bytes);
            let data: Vec<_> = recs.iter().filter(|(h, _)| h["kind"] == "data").collect();
            assert_eq!(data.len(), records, "{format:?}");
            let body: Vec<u8> = data.iter().flat_map(|(_, p)| p.iter().copied()).collect();
            assert_eq!(body, chunk);
            if format == CaptureFormat::Jsonl {
                let longest = bytes.split(|&b| b == b'\n').map(<[u8]>::len).max().unwrap();
                assert!(longest < (64 << 10) + 128, "{longest}");
            }
        }
    }
}
