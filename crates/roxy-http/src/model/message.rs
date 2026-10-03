//! Canonical request and response.

use std::time::SystemTime;

use http::{HeaderValue, StatusCode};

use super::authority::{Authority, Scheme};
use super::body::Body;
use super::headers::Headers;
use super::method::Method;
use crate::url::{Path, Query};

/// Client-side protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Version {
    /// HTTP/1.0 (only with `http.allow_http10`).
    H1_0,
    /// HTTP/1.1
    H1_1,
    /// HTTP/2
    H2,
}

impl Version {
    /// Whether this is an HTTP/1.x version.
    pub fn is_h1(self) -> bool {
        matches!(self, Version::H1_0 | Version::H1_1)
    }
}

/// The request-target form the client used (docs/http.md#explicit-proxy, RFC 9112 §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetForm {
    /// `/path?query` (tunnel) — also reported for origin-form on the proxy
    /// port, which the proxy must reject unless the host is `roxy.internal`.
    Origin,
    /// `http://host/path` (proxy port).
    Absolute,
    /// `host:port` (CONNECT).
    Authority,
    /// h2 pseudo-headers.
    H2,
}

/// Request metadata that is not part of the forwarded message.
#[derive(Debug, Clone)]
pub struct RequestMeta {
    /// Client protocol version.
    pub version: Version,
    /// When the head was fully received.
    pub received_at: SystemTime,
    /// Size of the request head on the wire (h1) or the header list (h2).
    pub head_bytes: usize,
    /// The request-target form used.
    pub target_form: TargetForm,
    /// The client sent `Expect: 100-continue` (and a body may follow). The
    /// `expect` header itself is consumed; roxy answers `100` itself.
    pub expect_continue: bool,
    /// Lower-cased `Upgrade` value when `Connection` nominated `upgrade`
    /// (h1 only). The header itself is hop-by-hop and stripped; it is only
    /// re-emitted upstream through [`crate::ws`].
    pub upgrade: Option<String>,
    /// `Proxy-Authorization` value (hop-by-hop, never forwarded), for the
    /// proxy's own authentication.
    pub proxy_authorization: Option<HeaderValue>,
    /// The client asked to close the connection after this exchange.
    pub close: bool,
}

impl RequestMeta {
    /// Metadata with defaults for the given version and target form.
    pub fn new(version: Version, target_form: TargetForm) -> Self {
        Self {
            version,
            received_at: SystemTime::now(),
            head_bytes: 0,
            target_form,
            expect_continue: false,
            upgrade: None,
            proxy_authorization: None,
            close: false,
        }
    }
}

/// A validated, normalised, version-agnostic request (docs/http.md#canonical-request).
#[derive(Debug)]
pub struct CanonicalRequest {
    /// Method.
    pub method: Method,
    /// Scheme of the target.
    pub scheme: Scheme,
    /// Target authority (port always explicit).
    pub authority: Authority,
    /// Normalised path.
    pub path: Path,
    /// Validated query, if non-empty.
    pub query: Option<Query>,
    /// End-to-end headers (no hop-by-hop, no `host`, no `content-length`).
    pub headers: Headers,
    /// Body; `body.known_length()` decides upstream framing.
    pub body: Body,
    /// Metadata.
    pub meta: RequestMeta,
}

impl CanonicalRequest {
    /// `path[?query]` as forwarded.
    pub fn path_and_query(&self) -> String {
        match &self.query {
            Some(q) => format!("{}?{}", self.path, q),
            None => self.path.to_string(),
        }
    }

    /// `scheme://authority/path?query` with the port always explicit.
    pub fn url(&self) -> String {
        format!(
            "{}://{}{}",
            self.scheme,
            self.authority,
            self.path_and_query()
        )
    }
}

/// Response metadata.
#[derive(Debug, Clone, Default)]
pub struct ResponseMeta {
    /// `content-length` declared by the upstream, if valid. Used for `HEAD`
    /// responses, whose body is empty but whose length describes the `GET`
    /// representation.
    pub declared_length: Option<u64>,
    /// Lower-cased `Upgrade` value of a `101` response when `Connection`
    /// nominated `upgrade`.
    pub upgrade: Option<String>,
    /// Close the client connection after this response
    /// ([`crate::h1::ServerConn::respond`] writes `connection: close`, then
    /// half-closes with a lingering close). Set by roxy for responses it
    /// generates (e.g. denials); never derived from the upstream's
    /// `Connection` field, because the upstream connection is managed
    /// independently of the client's keep-alive.
    pub close: bool,
}

/// A response to be sent to the client (docs/http.md#responses).
#[derive(Debug)]
pub struct CanonicalResponse {
    /// Status code; the reason phrase is regenerated from it.
    pub status: StatusCode,
    /// End-to-end headers.
    pub headers: Headers,
    /// Body.
    pub body: Body,
    /// Metadata.
    pub meta: ResponseMeta,
}

impl CanonicalResponse {
    /// A response with the given status, no headers and an empty body.
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            headers: Headers::new(),
            body: Body::empty(),
            meta: ResponseMeta::default(),
        }
    }

    /// Whether this status never carries a body (1xx, 204, 304).
    pub fn status_forbids_body(&self) -> bool {
        status_forbids_body(self.status)
    }
}

/// 1xx, 204 and 304 never carry a body (RFC 9112 §6.3).
pub fn status_forbids_body(s: StatusCode) -> bool {
    s.is_informational() || s == StatusCode::NO_CONTENT || s == StatusCode::NOT_MODIFIED
}
