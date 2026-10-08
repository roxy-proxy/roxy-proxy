//! Requests, responses and headers, and the plumbing that moves them to and
//! from the host.

use std::fmt;

use crate::bindings::roxy::addon::types::{self, PendingResponse, RequestHead, ResponseHead};
use crate::bindings::roxy::addon::{chain, endpoints};
use crate::bindings::wasi::io::poll::poll;
use crate::bindings::wasi::io::streams::{InputStream, OutputStream};
use crate::body::Body;
use crate::pump::{RequestPump, Wait};

/// Header names the SDK never forwards from a list the layer built: the
/// hop-by-hop, framing and routing fields roxy owns (`content-length` comes
/// from the body, which a transform may change in length; `host` from the
/// authority), which the host refuses. A head from roxy carries none of
/// them.
pub(crate) const DROPPED_HEADERS: &[&str] = &[
    "connection",
    "content-length",
    "expect",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Ordered header fields. Names are compared case-insensitively and stored
/// lower-case; repeated fields stay separate.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Headers {
    list: Vec<(String, Vec<u8>)>,
}

impl Headers {
    /// No headers.
    pub fn new() -> Self {
        Self::default()
    }

    /// The first value of `name`, if any.
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        let name = name.to_ascii_lowercase();
        self.list
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
        self.list
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
        self.list.push((name.to_ascii_lowercase(), value.into()));
    }

    /// Removes every value of `name`.
    pub fn remove(&mut self, name: &str) {
        let name = name.to_ascii_lowercase();
        self.list.retain(|(n, _)| *n != name);
    }

    /// Iterates `(name, value)` pairs in order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.list.iter().map(|(n, v)| (n.as_str(), v.as_slice()))
    }

    /// The head of a message from the host, whose names are lower-case.
    fn from_wire(list: Vec<(String, Vec<u8>)>) -> Self {
        Self { list }
    }

    /// The list for a message to the host, less the fields the host owns.
    fn into_wire(self) -> Vec<(String, Vec<u8>)> {
        let mut list = self.list;
        list.retain(|(n, _)| !DROPPED_HEADERS.contains(&n.as_str()));
        list
    }
}

impl fmt::Debug for Headers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(&self.list).finish()
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

    pub(crate) fn from_wire(head: RequestHead, body: InputStream) -> Self {
        Self {
            method: head.method,
            scheme: head.scheme,
            authority: head.authority,
            path_with_query: head.path_with_query,
            headers: Headers::from_wire(head.headers),
            body: Body::incoming(body, None),
        }
    }

    /// The head and body as the host takes them, and the body left to pump
    /// if the host did not take it whole.
    fn into_wire(self) -> (RequestHead, types::Body, Option<Body>) {
        let head = RequestHead {
            method: self.method,
            scheme: self.scheme,
            authority: self.authority,
            path_with_query: self.path_with_query,
            headers: self.headers.into_wire(),
        };
        let (body, rest) = self.body.into_wire();
        (head, body, rest)
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

    /// A response from the host, with the pump for the rest of its
    /// request's body.
    fn from_wire((head, body): (ResponseHead, InputStream), pump: RequestPump) -> Self {
        Self {
            status: head.status,
            headers: Headers::from_wire(head.headers),
            body: Body::incoming(body, Some(pump)),
        }
    }

    fn into_wire(self) -> (ResponseHead, types::Body, Option<Body>) {
        let head = ResponseHead {
            status: self.status,
            headers: self.headers.into_wire(),
        };
        let (body, rest) = self.body.into_wire();
        (head, body, rest)
    }
}

/// Why a call through [`Next`] or [`call_endpoint`] failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// No endpoint of that name is configured for this layer.
    DestinationNotFound,
    /// The endpoint's address is denied by roxy's address floor or deny
    /// lists.
    DestinationDenied,
    /// The request's path cannot go under the endpoint's URL.
    RequestUriInvalid,
    /// The endpoint did not answer within its timeout.
    Timeout,
    /// Anything else, with a message when the host has one.
    Internal(Option<String>),
}

impl From<types::Error> for Error {
    fn from(e: types::Error) -> Self {
        match e {
            types::Error::DestinationNotFound => Error::DestinationNotFound,
            types::Error::DestinationDenied => Error::DestinationDenied,
            types::Error::RequestUriInvalid => Error::RequestUriInvalid,
            types::Error::Timeout => Error::Timeout,
            types::Error::Internal(msg) => Error::Internal(msg),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::DestinationNotFound => f.write_str("destination not found"),
            Error::DestinationDenied => f.write_str("destination denied"),
            Error::RequestUriInvalid => f.write_str("request URI invalid"),
            Error::Timeout => f.write_str("timed out"),
            Error::Internal(Some(msg)) => write!(f, "internal error: {msg}"),
            Error::Internal(None) => f.write_str("internal error"),
        }
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

/// The result of `chain.next` or `endpoints.call`: the response to come,
/// and the stream to write the body to when the host did not take it whole.
type Call = Result<(PendingResponse, Option<OutputStream>), types::Error>;

/// Sends a request through `call` (`chain::next` or an endpoint) and
/// returns the response once its head arrives. The request body is written
/// while waiting, and the rest of it while the response body is read.
pub(crate) fn send(
    req: Request,
    call: impl FnOnce(&RequestHead, types::Body) -> Call,
) -> Result<Response, Error> {
    let (head, body, rest) = req.into_wire();
    let (pending, out) = call(&head, body)?;
    let mut pump = RequestPump::new(out, rest.unwrap_or_default());
    let answer = loop {
        match pump.step() {
            // Nothing left to write: one call takes the response.
            Wait::Done => break PendingResponse::wait(pending)?,
            Wait::On(writable) => {
                let ready = pending.subscribe();
                poll(&[&ready, &writable]);
                drop(ready);
                if let Some(result) = pending.get() {
                    break result?;
                }
            }
        }
    };
    Ok(Response::from_wire(answer, pump))
}

/// Calls the endpoint configured under `name` (capability `endpoints`).
/// Only the request's method, headers and body are used, plus its path if
/// the endpoint is configured `path: prefix`: roxy picks the destination
/// and attaches the credentials.
pub fn call_endpoint(name: &str, req: Request) -> Result<Response, Error> {
    send(req, |head, body| endpoints::call(name, head, body))
}

/// Answers the client with `resp`, writing its body to the end.
pub(crate) fn respond(response: Response) {
    let (head, body, rest) = response.into_wire();
    let out = chain::respond(&head, body);
    if let Some(rest) = rest {
        RequestPump::new(out, rest).drain();
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
    fn fields_the_host_owns_are_not_sent() {
        let mut h = Headers::new();
        h.set("Content-Length", "5");
        h.set("Host", "x");
        h.set("x-keep", "1");
        assert_eq!(h.into_wire(), vec![("x-keep".to_owned(), b"1".to_vec())]);
    }

    #[test]
    fn request_path() {
        let r = Request::new("GET", "/v1/messages?beta=true");
        assert_eq!(r.path(), "/v1/messages");
        assert_eq!(Request::new("GET", "/x").path(), "/x");
    }
}
