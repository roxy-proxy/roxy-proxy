//! Requests, responses and headers, and the plumbing that moves them to and
//! from the host.

use std::fmt;

use crate::bindings::roxy::addon::{chain, endpoints};
use crate::bindings::wasi::http::types::{
    ErrorCode, Fields, FutureIncomingResponse, IncomingRequest, IncomingResponse,
    Method as WMethod, OutgoingBody, OutgoingRequest, OutgoingResponse, ResponseOutparam, Scheme,
};
use crate::bindings::wasi::io::poll::poll;
use crate::body::{Body, Parent};
use crate::pump::{RequestPump, Wait};

/// Header names the SDK never forwards: hop-by-hop fields the host's WASI
/// HTTP implementation refuses, and `content-length`, which roxy derives
/// from the body (a transformed body changes length).
const DROPPED_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
    "host",
    "http2-settings",
    "te",
    "content-length",
];

/// Ordered header fields. Names are compared case-insensitively and stored
/// lower-case; repeated fields stay separate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers(Vec<(String, Vec<u8>)>);

impl Headers {
    /// No headers.
    pub fn new() -> Self {
        Self::default()
    }

    /// The first value of `name`, if any.
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        let name = name.to_ascii_lowercase();
        self.0
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_slice())
    }

    /// The first value of `name` as a string, if it is valid UTF-8.
    pub fn get_str(&self, name: &str) -> Option<&str> {
        self.get(name).and_then(|v| std::str::from_utf8(v).ok())
    }

    /// Every value of `name`.
    pub fn get_all(&self, name: &str) -> impl Iterator<Item = &[u8]> {
        let name = name.to_ascii_lowercase();
        self.0
            .iter()
            .filter(move |(n, _)| *n == name)
            .map(|(_, v)| v.as_slice())
    }

    /// Replaces every value of `name` with `value`.
    pub fn set(&mut self, name: &str, value: impl Into<Vec<u8>>) {
        self.remove(name);
        self.append(name, value);
    }

    /// Adds a value for `name`.
    pub fn append(&mut self, name: &str, value: impl Into<Vec<u8>>) {
        self.0.push((name.to_ascii_lowercase(), value.into()));
    }

    /// Removes every value of `name`.
    pub fn remove(&mut self, name: &str) {
        let name = name.to_ascii_lowercase();
        self.0.retain(|(n, _)| *n != name);
    }

    /// Iterates `(name, value)` pairs in order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.0.iter().map(|(n, v)| (n.as_str(), v.as_slice()))
    }

    fn from_fields(fields: &Fields) -> Self {
        Self(fields.entries())
    }

    fn to_fields(&self) -> Fields {
        let entries: Vec<(String, Vec<u8>)> = self
            .0
            .iter()
            .filter(|(n, _)| !DROPPED_HEADERS.contains(&n.as_str()))
            .cloned()
            .collect();
        Fields::from_list(&entries).expect("header fields rejected by the host")
    }
}

/// A request. `scheme` and `authority` left `None` in a request passed to
/// [`Next::run`] default to the exchange's own.
#[derive(Debug)]
pub struct Request {
    /// Method, e.g. `"POST"`.
    pub method: String,
    /// `"http"` or `"https"`.
    pub scheme: Option<String>,
    /// `host:port`.
    pub authority: Option<String>,
    /// Path and query, e.g. `"/v1/messages?beta=true"`.
    pub path_with_query: String,
    /// Header fields.
    pub headers: Headers,
    /// Body.
    pub body: Body,
}

impl Request {
    /// A request with no headers and an empty body.
    pub fn new(method: &str, path_with_query: &str) -> Self {
        Self {
            method: method.to_owned(),
            scheme: None,
            authority: None,
            path_with_query: path_with_query.to_owned(),
            headers: Headers::new(),
            body: Body::empty(),
        }
    }

    /// The path without the query.
    pub fn path(&self) -> &str {
        self.path_with_query
            .split_once('?')
            .map_or(self.path_with_query.as_str(), |(p, _)| p)
    }

    /// Sets the body.
    #[must_use]
    pub fn with_body(mut self, body: impl Into<Body>) -> Self {
        self.body = body.into();
        self
    }

    /// Sets a header.
    #[must_use]
    pub fn with_header(mut self, name: &str, value: impl Into<Vec<u8>>) -> Self {
        self.headers.set(name, value);
        self
    }

    /// Replaces the body with `f(body)` (for example
    /// `req.map_body(|b| b.transform(redact))`).
    #[must_use]
    pub fn map_body(mut self, f: impl FnOnce(Body) -> Body) -> Self {
        self.body = f(std::mem::take(&mut self.body));
        self
    }

    pub(crate) fn from_incoming(req: IncomingRequest) -> Self {
        let method = method_name(&req.method());
        let scheme = req.scheme().map(|s| scheme_name(&s));
        let authority = req.authority();
        let path_with_query = req.path_with_query().unwrap_or_else(|| "/".to_owned());
        let headers = Headers::from_fields(&req.headers());
        let body = match req.consume() {
            Ok(body) => Body::incoming(body, Parent::Request(req), None),
            Err(()) => Body::empty(),
        };
        Self {
            method,
            scheme,
            authority,
            path_with_query,
            headers,
            body,
        }
    }

    /// Builds the outgoing head, returning it with the body still to write.
    fn into_outgoing(self) -> (OutgoingRequest, Body) {
        let out = OutgoingRequest::new(self.headers.to_fields());
        out.set_method(&method_value(&self.method))
            .expect("method rejected by the host");
        if let Some(s) = &self.scheme {
            out.set_scheme(Some(&scheme_value(s)))
                .expect("scheme rejected by the host");
        }
        if let Some(a) = &self.authority {
            out.set_authority(Some(a))
                .expect("authority rejected by the host");
        }
        out.set_path_with_query(Some(&self.path_with_query))
            .expect("path rejected by the host");
        (out, self.body)
    }
}

/// A response.
#[derive(Debug)]
pub struct Response {
    /// Status code.
    pub status: u16,
    /// Header fields.
    pub headers: Headers,
    /// Body.
    pub body: Body,
}

impl Response {
    /// A response with no headers and an empty body.
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: Headers::new(),
            body: Body::empty(),
        }
    }

    /// A `text/plain` response.
    pub fn text(status: u16, text: impl Into<String>) -> Self {
        Self::new(status)
            .with_header("content-type", "text/plain; charset=utf-8")
            .with_body(text.into())
    }

    /// An `application/json` response; `json` must already be JSON.
    pub fn json(status: u16, json: impl Into<String>) -> Self {
        Self::new(status)
            .with_header("content-type", "application/json")
            .with_body(json.into())
    }

    /// Sets the body.
    #[must_use]
    pub fn with_body(mut self, body: impl Into<Body>) -> Self {
        self.body = body.into();
        self
    }

    /// Sets a header.
    #[must_use]
    pub fn with_header(mut self, name: &str, value: impl Into<Vec<u8>>) -> Self {
        self.headers.set(name, value);
        self
    }

    /// Replaces the body with `f(body)`.
    #[must_use]
    pub fn map_body(mut self, f: impl FnOnce(Body) -> Body) -> Self {
        self.body = f(std::mem::take(&mut self.body));
        self
    }

    fn from_incoming(resp: IncomingResponse, pump: RequestPump) -> Self {
        let status = resp.status();
        let headers = Headers::from_fields(&resp.headers());
        let body = if let Ok(body) = resp.consume() {
            Body::incoming(body, Parent::Response(resp), Some(pump))
        } else {
            let mut pump = pump;
            pump.drain();
            Body::empty()
        };
        Self {
            status,
            headers,
            body,
        }
    }
}

/// Why a call through [`Next`] or [`crate::endpoints`] failed.
#[derive(Debug, Clone)]
pub struct Error(pub ErrorCode);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl std::error::Error for Error {}

/// The layers below this one. Consumed by [`Next::run`], so a layer can
/// pass at most one request down per exchange (the host enforces the same).
#[derive(Debug)]
pub struct Next {
    _private: (),
}

impl Next {
    pub(crate) fn new() -> Self {
        Self { _private: () }
    }

    /// Passes `req` down and returns the response. Panics (failing the
    /// exchange closed) if the host refuses the request.
    pub fn run(self, req: Request) -> Response {
        self.try_run(req).expect("next failed")
    }

    /// Passes `req` down and returns the response, or the error the host
    /// reported.
    ///
    /// The request body is written before the response is read, chunk by
    /// chunk, as the layer below consumes it.
    pub fn try_run(self, req: Request) -> Result<Response, Error> {
        send(req, chain::next)
    }
}

/// Sends a request through `call` (`chain::next` or an endpoint) and
/// returns the response once its head arrives. The request body is written
/// while waiting, and the rest of it while the response body is read.
pub(crate) fn send(
    req: Request,
    call: impl FnOnce(OutgoingRequest) -> Result<FutureIncomingResponse, ErrorCode>,
) -> Result<Response, Error> {
    let (out, body) = req.into_outgoing();
    let out_body = out.body().expect("request body already taken");
    let future = call(out).map_err(Error)?;
    let mut pump = RequestPump::new(out_body, body);
    let resp = loop {
        if let Some(result) = future.get() {
            break result.expect("response taken once").map_err(Error)?;
        }
        match pump.step() {
            Wait::Done => future.subscribe().block(),
            Wait::On(writable) => {
                let head = future.subscribe();
                poll(&[&head, &writable]);
            }
        }
    };
    drop(future);
    Ok(Response::from_incoming(resp, pump))
}

/// Calls the endpoint configured under `name` (capability `endpoints`).
/// Only the request's method, headers and body are used, plus its path if
/// the endpoint is configured `path: prefix`: roxy picks the destination
/// and attaches the credentials.
pub fn call_endpoint(name: &str, req: Request) -> Result<Response, Error> {
    send(req, |out| endpoints::call(name, out))
}

/// Writes `body` to `out` and finishes it (the response to the client).
fn write_body(out: OutgoingBody, body: Body) {
    let mut pump = RequestPump::new(out, body);
    pump.drain();
}

/// Sends `resp` to the client through `out`.
pub(crate) fn respond(out: ResponseOutparam, resp: Response) {
    let outgoing = OutgoingResponse::new(resp.headers.to_fields());
    outgoing
        .set_status_code(resp.status)
        .expect("status rejected by the host");
    let body = outgoing.body().expect("response body already taken");
    ResponseOutparam::set(out, Ok(outgoing));
    write_body(body, resp.body);
}

fn method_name(m: &WMethod) -> String {
    match m {
        WMethod::Get => "GET",
        WMethod::Head => "HEAD",
        WMethod::Post => "POST",
        WMethod::Put => "PUT",
        WMethod::Delete => "DELETE",
        WMethod::Connect => "CONNECT",
        WMethod::Options => "OPTIONS",
        WMethod::Trace => "TRACE",
        WMethod::Patch => "PATCH",
        WMethod::Other(o) => o,
    }
    .to_owned()
}

fn method_value(m: &str) -> WMethod {
    match m {
        "GET" => WMethod::Get,
        "HEAD" => WMethod::Head,
        "POST" => WMethod::Post,
        "PUT" => WMethod::Put,
        "DELETE" => WMethod::Delete,
        "CONNECT" => WMethod::Connect,
        "OPTIONS" => WMethod::Options,
        "TRACE" => WMethod::Trace,
        "PATCH" => WMethod::Patch,
        other => WMethod::Other(other.to_owned()),
    }
}

fn scheme_name(s: &Scheme) -> String {
    match s {
        Scheme::Http => "http".to_owned(),
        Scheme::Https => "https".to_owned(),
        Scheme::Other(o) => o.clone(),
    }
}

fn scheme_value(s: &str) -> Scheme {
    match s {
        "http" => Scheme::Http,
        "https" => Scheme::Https,
        other => Scheme::Other(other.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_are_case_insensitive_and_ordered() {
        let mut h = Headers::new();
        h.append("Set-Cookie", "a=1");
        h.append("set-cookie", "b=2");
        h.set("X-Test", "one");
        assert_eq!(h.get("set-COOKIE"), Some(&b"a=1"[..]));
        assert_eq!(h.get_all("set-cookie").count(), 2);
        assert_eq!(h.get_str("x-test"), Some("one"));
        h.set("x-test", "two");
        assert_eq!(h.get_all("x-test").collect::<Vec<_>>(), vec![&b"two"[..]]);
        h.remove("SET-cookie");
        assert_eq!(h.iter().count(), 1);
    }

    #[test]
    fn request_path() {
        let r = Request::new("GET", "/v1/messages?beta=true");
        assert_eq!(r.path(), "/v1/messages");
        assert_eq!(Request::new("GET", "/x").path(), "/x");
    }

    #[test]
    fn methods_round_trip() {
        for m in ["GET", "POST", "PATCH", "PURGE"] {
            assert_eq!(method_name(&method_value(m)), m);
        }
    }
}
