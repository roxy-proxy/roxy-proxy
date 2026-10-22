//! Differential check of the HTTP/1.1 server codec (`roxy-http`
//! `h1::ServerConn`) against hyper's HTTP/1 server.
//!
//! Input: one config byte (parser flags and role, see `roxy_fuzz::flags` /
//! `roxy_fuzz::role`), then the raw bytes of a client connection. A probe
//! request legal for the role is appended to every input, so whether a codec
//! reads on after the input's last request (keep-alive, and where it took
//! that request to end) shows as whether it parses the probe.
//!
//! hyper is the lenient reference and roxy is meant to be strictly stricter,
//! so the property is one-sided, request by request down the connection:
//! - roxy accepts a request hyper rejects: a roxy bug;
//! - both accept: version, method, request target (hyper's URI through roxy's
//!   `url` normalisation), the header list without the fields roxy consumes
//!   (hop-by-hop, framing, `Host`, `Expect`; names lower-case, values
//!   OWS-trimmed, sorted by name), the body bytes and the trailers agree,
//!   and both read on to the next request or neither does;
//! - hyper accepts and roxy rejects, or closes an HTTP/1.0 connection hyper
//!   keeps alive: fine. The reason codes are counted and printed now and
//!   then, never asserted on.
#![no_main]

use std::cell::RefCell;
use std::convert::Infallible;
use std::fmt::Write as _;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http::header::{CONNECTION, HOST};
use http::request::Parts;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use http_body_util::{BodyExt, Collected, Empty};
use hyper::rt::ReadBufCursor;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use libfuzzer_sys::fuzz_target;
use roxy_http::h1::{Incoming, Role, ServerConn};
use roxy_http::url::{
    parse_absolute_form, parse_authority, parse_authority_opt, parse_origin_form,
};
use roxy_http::{
    Authority, Buffered, CanonicalRequest, CanonicalResponse, DriveError, Path, Query, Reason,
    Scheme, Version, is_reserved,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

thread_local! {
    /// Nothing in either codec waits on the wire, so one `block_on` runs an
    /// input to completion and the runtime is reused.
    static RUNTIME: tokio::runtime::Runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("tokio runtime");
}

/// The client's end of the connection: it has sent `input` and half-closed;
/// whatever the server writes back is discarded.
struct Wire(Bytes);

impl Wire {
    fn take(&mut self, room: usize) -> Bytes {
        let n = self.0.len().min(room);
        self.0.split_to(n)
    }
}

impl AsyncRead for Wire {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let chunk = self.take(buf.remaining());
        buf.put_slice(&chunk);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Wire {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl hyper::rt::Read for Wire {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        mut buf: ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        let chunk = self.take(buf.remaining());
        buf.put_slice(&chunk);
        Poll::Ready(Ok(()))
    }
}

impl hyper::rt::Write for Wire {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// A request legal for the role, appended to every input (see the module
/// doc).
fn probe(role: &Role) -> &'static [u8] {
    match role {
        Role::ProxyPort => b"GET http://example.com/probe HTTP/1.1\r\nHost: example.com\r\n\r\n",
        Role::Origin | Role::Tunnel { .. } => b"GET /probe HTTP/1.1\r\nHost: example.com\r\n\r\n",
    }
}

/// Header fields sorted by name (stably: repeated fields keep their order),
/// values as the ISO-8859-1 text of their bytes so a mismatch reads well.
type Fields = Vec<(String, String)>;

/// A request as either codec reports it, in the form the two are compared
/// in.
#[derive(Debug, PartialEq, Eq)]
struct Msg {
    /// Checked independently so the HTTP/1.0 close allowance cannot hide a
    /// version misparse in roxy.
    version: http::Version,
    method: String,
    /// `scheme://host:port/path?query`; `host:port` for CONNECT.
    target: String,
    headers: Fields,
    trailers: Fields,
    body: Vec<u8>,
}

/// What one codec made of the connection: the requests it accepted, then
/// why it stopped reading.
struct Side<E> {
    msgs: Vec<Msg>,
    end: E,
}

enum RoxyEnd {
    /// EOF between requests.
    Eof,
    /// Closed after a request: `Connection: close`, or HTTP/1.0.
    Closed(Version),
    /// A CONNECT, which hands the connection over to the tunnel.
    Connect,
    Rejected(Reason),
}

enum HyperEnd {
    /// EOF, a close decision, or a CONNECT answered.
    Done,
    Rejected(hyper::Error),
    /// The body of the request after the last accepted one.
    BodyRejected(hyper::Error),
}

fn trim_ows(mut s: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = s {
        s = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = s {
        s = rest;
    }
    s
}

/// The `Connection` options, lower-case: the fields they name are
/// hop-by-hop.
fn nominated(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(CONNECTION)
        .iter()
        .flat_map(|v| v.as_bytes().split(|&b| b == b','))
        .map(|t| String::from_utf8_lossy(trim_ows(t)).to_ascii_lowercase())
        .collect()
}

/// Every field of `iter` in the compared form. roxy's lists go through
/// this as they are, so a reserved name roxy kept shows up as a mismatch.
fn fields<'a>(iter: impl Iterator<Item = (&'a HeaderName, &'a HeaderValue)>) -> Fields {
    let mut out: Fields = iter
        .map(|(n, v)| {
            let text = trim_ows(v.as_bytes())
                .iter()
                .map(|&b| char::from(b))
                .collect();
            (n.as_str().to_owned(), text)
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// hyper's header list as roxy would keep it: without the reserved names
/// (hop-by-hop, framing, `host`, `expect`) and the fields `Connection`
/// nominates.
fn end_to_end(headers: &HeaderMap) -> Fields {
    let nominated = nominated(headers);
    fields(
        headers.iter().filter(|(n, _)| {
            !is_reserved(n.as_str()) && !nominated.iter().any(|t| t == n.as_str())
        }),
    )
}

fn url(scheme: Scheme, authority: &Authority, path: &Path, query: Option<&Query>) -> String {
    match query {
        Some(q) => format!("{scheme}://{authority}{path}?{q}"),
        None => format!("{scheme}://{authority}{path}"),
    }
}

/// The one `Host` field, normalised with `default_port`, or why there is no
/// such thing.
fn host(parts: &Parts, default_port: u16) -> Result<Option<Authority>, String> {
    let hosts: Vec<&HeaderValue> = parts.headers.get_all(HOST).iter().collect();
    match hosts[..] {
        [] => Ok(None),
        [h] => parse_authority(trim_ows(h.as_bytes()), default_port)
            .map(Some)
            .map_err(|e| format!("<host: {}>", e.reason)),
        _ => Err(format!("<{} host fields>", hosts.len())),
    }
}

/// `authority` once `Host`, if sent, is seen to name it. roxy requires that
/// of an absolute-form or CONNECT target, so a mismatch here means roxy let
/// one through.
fn named_by_host(
    parts: &Parts,
    authority: Authority,
    default_port: u16,
) -> Result<Authority, String> {
    match host(parts, default_port)? {
        Some(h) if h != authority => Err(format!("<host {h} does not name {authority}>")),
        _ => Ok(authority),
    }
}

/// hyper's URI through roxy's URL normalisation, printed as
/// `CanonicalRequest::url` prints roxy's. For origin-form the authority is
/// the one `Host` names, with the role's scheme, as roxy's is. A target
/// roxy's normaliser refuses prints as its reason code: roxy did not accept
/// that request either, so it is never compared.
fn hyper_target(parts: &Parts, role: &Role) -> String {
    let uri = &parts.uri;
    if parts.method == http::Method::CONNECT {
        let raw = uri.authority().map_or("", |a| a.as_str());
        return parse_authority_opt(raw.as_bytes(), None)
            .map_err(|e| format!("<{}>", e.reason))
            .and_then(|a| named_by_host(parts, a.clone(), a.port))
            .map_or_else(|e| e, |a| a.to_string());
    }
    let pq = uri.path_and_query().map_or("", |p| p.as_str());
    if let (Some(scheme), Some(authority)) = (uri.scheme_str(), uri.authority()) {
        return match parse_absolute_form(format!("{scheme}://{authority}{pq}").as_bytes()) {
            Ok((s, a, p, q)) => named_by_host(parts, a, s.default_port())
                .map_or_else(|e| e, |a| url(s, &a, &p, q.as_ref())),
            Err(e) => format!("<{}>", e.reason),
        };
    }
    let scheme = match role {
        Role::Tunnel { scheme, .. } => *scheme,
        Role::ProxyPort | Role::Origin => Scheme::Http,
    };
    let authority = match host(parts, scheme.default_port()) {
        Ok(Some(a)) => a,
        Ok(None) => return "<no host field>".to_owned(),
        Err(e) => return e,
    };
    match parse_origin_form(pq.as_bytes()) {
        Ok((p, q)) => url(scheme, &authority, &p, q.as_ref()),
        Err(e) => format!("<{}>", e.reason),
    }
}

fn roxy_version(version: Version) -> http::Version {
    match version {
        Version::H1_0 => http::Version::HTTP_10,
        Version::H1_1 => http::Version::HTTP_11,
        Version::H2 => http::Version::HTTP_2,
    }
}

fn roxy_msg(req: &CanonicalRequest, body: Buffered) -> Msg {
    Msg {
        version: roxy_version(req.meta.version),
        method: req.method.as_str().to_owned(),
        target: req.url(),
        headers: fields(req.headers.iter()),
        trailers: body
            .trailers
            .as_ref()
            .map_or_else(Vec::new, |t| fields(t.iter())),
        body: body.data.to_vec(),
    }
}

/// Trailers are compared whole: roxy keeps every trailer field or refuses
/// the request, so there is nothing to drop from hyper's.
fn hyper_msg(parts: &Parts, body: Collected<Bytes>, role: &Role) -> Msg {
    Msg {
        version: parts.version,
        method: parts.method.as_str().to_owned(),
        target: hyper_target(parts, role),
        headers: end_to_end(&parts.headers),
        trailers: body.trailers().map_or_else(Vec::new, |t| fields(t.iter())),
        body: body.to_bytes().to_vec(),
    }
}

/// Serves the connection with roxy: every request's body is read to the
/// end and answered `200`, as the proxy would.
fn roxy_side(cfg: u8, role: &Role, wire: Bytes) -> Side<RoxyEnd> {
    let limits = Arc::new(roxy_fuzz::tight_limits());
    let flags = Arc::new(roxy_fuzz::flags(cfg));
    let mut conn = ServerConn::new(Wire(wire), role.clone(), limits, flags);
    let mut msgs = Vec::new();
    let end = RUNTIME.with(|rt| {
        rt.block_on(async {
            loop {
                let mut req = match conn.next_request().await {
                    Ok(None) => return RoxyEnd::Eof,
                    Err(e) => return RoxyEnd::Rejected(e.reason),
                    Ok(Some(Incoming::Connect {
                        authority,
                        headers,
                        meta,
                    })) => {
                        msgs.push(Msg {
                            version: roxy_version(meta.version),
                            method: "CONNECT".to_owned(),
                            target: authority.to_string(),
                            headers: fields(headers.iter()),
                            trailers: Vec::new(),
                            body: Vec::new(),
                        });
                        return RoxyEnd::Connect;
                    }
                    Ok(Some(Incoming::Request(req) | Incoming::OriginFormOnProxyPort(req))) => req,
                };
                let body = std::mem::take(&mut req.body);
                let body = match conn.drive(body.collect_up_to(u64::MAX)).await {
                    Ok(Ok(body)) => body,
                    Err(DriveError::Client(e)) => return RoxyEnd::Rejected(e.reason),
                    Ok(Err(e)) => panic!("body failed without a client fault: {e}"),
                    Err(DriveError::Write(e)) => panic!("write to the in-memory wire failed: {e}"),
                };
                msgs.push(roxy_msg(&req, body));
                conn.respond(CanonicalResponse::new(StatusCode::OK))
                    .await
                    .unwrap_or_else(|e| panic!("write to the in-memory wire failed: {e}"));
                if conn.is_closed() {
                    return RoxyEnd::Closed(req.meta.version);
                }
            }
        })
    });
    Side { msgs, end }
}

/// Serves the connection with hyper, the same way. `half_close` keeps hyper
/// from treating the client's half-close as a reason to drop a request it
/// has read but not yet answered; no header timeout, so no timer is needed.
fn hyper_side(role: &Role, wire: Bytes) -> Side<HyperEnd> {
    let msgs = Rc::new(RefCell::new(Vec::new()));
    let body_error = Rc::new(RefCell::new(None));
    let role = Rc::new(role.clone());
    let service = service_fn({
        let (msgs, body_error) = (msgs.clone(), body_error.clone());
        move |req: Request<hyper::body::Incoming>| {
            let (msgs, body_error, role) = (msgs.clone(), body_error.clone(), role.clone());
            async move {
                let (parts, body) = req.into_parts();
                match body.collect().await {
                    Ok(body) => msgs.borrow_mut().push(hyper_msg(&parts, body, &role)),
                    Err(e) => *body_error.borrow_mut() = Some(e),
                }
                Ok::<_, Infallible>(Response::new(Empty::<Bytes>::new()))
            }
        }
    });
    let conn = http1::Builder::new()
        .half_close(true)
        .header_read_timeout(None::<Duration>)
        .serve_connection(Wire(wire), service);
    let result = RUNTIME.with(|rt| rt.block_on(conn));
    let end = match (result, body_error.borrow_mut().take()) {
        (_, Some(e)) => HyperEnd::BodyRejected(e),
        (Ok(()), None) => HyperEnd::Done,
        (Err(e), None) => HyperEnd::Rejected(e),
    };
    let msgs = std::mem::take(&mut *msgs.borrow_mut());
    Side { msgs, end }
}

/// Why roxy refused what hyper accepted, by reason code, then roxy closing
/// a connection hyper kept alive (HTTP/1.0 with `Connection: keep-alive`).
static ROXY_ONLY: [AtomicU64; Reason::ALL.len() + 1] =
    [const { AtomicU64::new(0) }; Reason::ALL.len() + 1];
const CLOSED: usize = Reason::ALL.len();
static EXECS: AtomicU64 = AtomicU64::new(0);
/// Executions between reports: a few per minute at the target's speed, so
/// the 60-second CI run shows the counters too.
const REPORT_EVERY: u64 = 1 << 16;

fn count(slot: usize) {
    ROXY_ONLY[slot].fetch_add(1, Ordering::Relaxed);
}

fn slot(reason: Reason) -> usize {
    Reason::ALL
        .iter()
        .position(|&r| r == reason)
        .expect("every reason is in Reason::ALL")
}

/// Prints the counters once every `REPORT_EVERY` executions.
fn report() {
    if EXECS.fetch_add(1, Ordering::Relaxed) % REPORT_EVERY != REPORT_EVERY - 1 {
        return;
    }
    let mut line = String::from("h1_hyper: hyper accepted, roxy did not:");
    for (i, n) in ROXY_ONLY.iter().enumerate() {
        let n = n.load(Ordering::Relaxed);
        if n > 0 {
            let what = match i {
                CLOSED => "closed",
                _ => Reason::ALL[i].as_str(),
            };
            let _ = write!(line, " {what}={n}");
        }
    }
    eprintln!("{line}");
}

fn compare(roxy: &Side<RoxyEnd>, hyper: &Side<HyperEnd>, wire: &[u8]) {
    let shown = || String::from_utf8_lossy(wire);
    for (i, r) in roxy.msgs.iter().enumerate() {
        let Some(h) = hyper.msgs.get(i) else {
            match &hyper.end {
                HyperEnd::Rejected(e) | HyperEnd::BodyRejected(e) => {
                    panic!(
                        "roxy accepted request #{i}, hyper rejected it ({e}):\n{r:#?}\n{}",
                        shown()
                    );
                }
                HyperEnd::Done => panic!(
                    "hyper stopped reading before request #{i} and roxy read on:\n{r:#?}\n{}",
                    shown()
                ),
            }
        };
        assert_eq!(
            r,
            h,
            "request #{i} differs (roxy left, hyper right):\n{}",
            shown()
        );
    }
    if hyper.msgs.len() > roxy.msgs.len() {
        match roxy.end {
            RoxyEnd::Rejected(reason) => count(slot(reason)),
            RoxyEnd::Closed(Version::H1_0) => count(CLOSED),
            RoxyEnd::Closed(_) | RoxyEnd::Eof | RoxyEnd::Connect => panic!(
                "roxy ended the connection where hyper parsed request #{}:\n{}",
                roxy.msgs.len(),
                shown()
            ),
        }
    } else if let (RoxyEnd::Rejected(reason), HyperEnd::Done) = (&roxy.end, &hyper.end) {
        // Same requests, so the same bytes consumed, and the probe means some
        // remain: hyper's `Done` is a close decision roxy did not take.
        panic!(
            "hyper stopped reading before request #{} and roxy read on ({} on what followed):\n{}",
            roxy.msgs.len(),
            reason.as_str(),
            shown()
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&cfg, input)) = data.split_first() else {
        return;
    };
    let role = roxy_fuzz::role(cfg);
    let probe = probe(&role);
    let mut wire = BytesMut::with_capacity(input.len() + probe.len());
    wire.extend_from_slice(input);
    wire.extend_from_slice(probe);
    let wire = wire.freeze();
    let roxy = roxy_side(cfg, &role, wire.clone());
    let hyper = hyper_side(&role, wire.clone());
    compare(&roxy, &hyper, &wire);
    report();
});
