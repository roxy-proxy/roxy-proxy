//! Canonical model ↔ hyper client types (`DESIGN.md` §5.5, §5.6).
//!
//! hyper serialises what these functions produce. The guarantees:
//! - `host` is the first header and equals the canonical authority (default
//!   port omitted);
//! - no hop-by-hop header can be present (canonical [`Headers`] cannot hold
//!   them);
//! - `content-length` is set exactly when the body length is known; otherwise
//!   hyper sends clean `chunked` (no extensions, no trailers, since roxy's
//!   bodies only yield trailers when `http.allow_trailers` let them in);
//! - never both.

use std::fmt;

use http::header::{CONNECTION, CONTENT_LENGTH, HOST, UPGRADE};
use http::{HeaderMap, HeaderValue, Uri};

use crate::model::{
    Body, CanonicalRequest, CanonicalResponse, Headers, Limits, ParseError, Reason, ResponseMeta,
    connection_tokens,
};

/// How the request URI is written into the `http::Request`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UriForm {
    /// `scheme://authority/path?query`. Use with `hyper_util`'s pooled
    /// client (which routes on the URI and rewrites to origin-form for
    /// HTTP/1.1) and with hyper's HTTP/2 client (which derives `:scheme` and
    /// `:authority` from it).
    Absolute,
    /// `/path?query`. Use with hyper's low-level HTTP/1.1
    /// `client::conn::http1::SendRequest`, which writes the URI verbatim.
    Origin,
}

/// Builds the upstream request.
///
/// The `host` header is always included (first). Over HTTP/2 it equals
/// `:authority`, which RFC 9113 §8.3.1 permits; callers may drop it there.
pub fn to_upstream_request(
    req: CanonicalRequest,
    form: UriForm,
) -> Result<http::Request<Body>, ParseError> {
    let host = req.authority.to_host_header(req.scheme);
    let uri_str = match form {
        UriForm::Absolute => format!("{}://{}{}", req.scheme, host, req.path_and_query()),
        UriForm::Origin => req.path_and_query(),
    };
    let uri = Uri::try_from(uri_str)
        .map_err(|e| ParseError::new(Reason::BadRequestTarget, format!("uri: {e}")))?;
    let mut headers = HeaderMap::with_capacity(req.headers.len() + 2);
    let host_value = HeaderValue::from_str(&host)
        .map_err(|_| ParseError::new(Reason::BadAuthority, "host header"))?;
    headers.insert(HOST, host_value);
    for (n, v) in &req.headers {
        headers.append(n.clone(), v.clone());
    }
    match req.body.known_length() {
        // A bodiless method with an empty body: no framing header at all.
        Some(0) if !req.method.allows_body(false) => {}
        Some(n) => {
            headers.insert(CONTENT_LENGTH, HeaderValue::from(n));
        }
        None => {}
    }
    let mut out = http::Request::new(req.body);
    *out.method_mut() = req.method.to_http();
    *out.uri_mut() = uri;
    *out.version_mut() = http::Version::HTTP_11;
    *out.headers_mut() = headers;
    Ok(out)
}

/// Builds the upstream request for an allowed WebSocket upgrade: as
/// [`to_upstream_request`] plus `connection: upgrade` and
/// `upgrade: websocket`. Validates the request first.
pub fn to_upstream_upgrade_request(
    req: CanonicalRequest,
    form: UriForm,
) -> Result<http::Request<Body>, ParseError> {
    crate::ws::validate_upgrade_request(&req)?;
    let mut out = to_upstream_request(req, form)?;
    out.headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("upgrade"));
    out.headers_mut()
        .insert(UPGRADE, HeaderValue::from_static("websocket"));
    Ok(out)
}

fn single_content_length(map: &HeaderMap) -> Option<u64> {
    let mut it = map.get_all(CONTENT_LENGTH).iter();
    let v = it.next()?;
    if it.next().is_some() {
        return None;
    }
    let v = v.to_str().ok()?.trim();
    if v.is_empty() || v.len() > 19 || !v.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    v.parse().ok()
}

/// Adapts an upstream response. Hop-by-hop headers (and those nominated by
/// `connection`) are stripped; `content-length` / `transfer-encoding` are
/// regenerated on the client side; the body is streamed through with
/// `limits.max_response_body_bytes` applied as frames flow (no buffering).
pub fn from_upstream_response<B>(res: http::Response<B>, limits: &Limits) -> CanonicalResponse
where
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: fmt::Display,
{
    let (parts, body) = res.into_parts();
    let headers = Headers::from_header_map_lenient(&parts.headers);
    let conn = connection_tokens(
        parts
            .headers
            .get_all(CONNECTION)
            .iter()
            .map(HeaderValue::as_bytes),
    )
    .unwrap_or_default();
    let upgrade = (parts.status == http::StatusCode::SWITCHING_PROTOCOLS
        && conn.iter().any(|t| t == "upgrade"))
    .then(|| {
        parts
            .headers
            .get(UPGRADE)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim().to_ascii_lowercase())
    })
    .flatten();
    let meta = ResponseMeta {
        declared_length: single_content_length(&parts.headers),
        upgrade,
        close: conn.iter().any(|t| t == "close"),
    };
    CanonicalResponse {
        status: parts.status,
        headers,
        body: Body::wrap(body, limits.max_response_body_bytes),
        meta,
    }
}
