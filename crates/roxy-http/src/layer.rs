//! Addon layer messages ↔ canonical model.
//!
//! A layer receives the canonical request as an `http::Request` with an
//! absolute URI, and passes on whatever it likes. What it passes on is
//! re-validated here exactly as strictly as a client's request (invariant
//! 1: the rules then judge it as if the agent had sent it), and held to the
//! same limits. The client's [`RequestMeta`] travels with it: a layer
//! cannot express the protocol version, the target form, the upgrade or
//! the time the head arrived, and those stay the client's.

use crate::chars::trim_ows;
use crate::model::{
    Body, CanonicalRequest, CanonicalResponse, Headers, HttpFlags, Limits, Method, ParseError,
    Reason, RequestMeta, Scheme, parse_content_length, plan_body, reject,
};
use crate::url;

/// Fields a layer may not set on a request it passes on: hop-by-hop and
/// framing fields roxy owns. `host` and `content-length` are checked
/// separately.
const REFUSED: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authorization",
    "proxy-authenticate",
    "transfer-encoding",
    "upgrade",
    "te",
    "trailer",
    "expect",
];

/// The canonical request as a layer sees it: `scheme://authority/path?query`,
/// end-to-end headers, the body. No `host` or framing fields; the body's
/// known length is carried by the body.
pub fn to_layer_request(req: CanonicalRequest) -> http::Request<Body> {
    let uri = format!(
        "{}://{}{}",
        req.scheme,
        req.authority.to_host_header(req.scheme),
        req.path_and_query()
    );
    let mut out = http::Request::new(req.body);
    *out.method_mut() = req.method.to_http();
    // A canonical request always forms a valid absolute URI.
    *out.uri_mut() = uri.parse().unwrap_or_default();
    *out.headers_mut() = req.headers.to_header_map();
    out
}

/// A canonical response as a layer sees it.
pub fn to_layer_response(res: CanonicalResponse) -> http::Response<Body> {
    let mut out = http::Response::new(res.body);
    *out.status_mut() = res.status;
    *out.headers_mut() = res.headers.to_header_map();
    out
}

/// Re-validates a request a layer passes on, as the client's request
/// `meta` describes.
///
/// The URI must be absolute (`http` or `https`, with an authority). A
/// `host` field, if present, must match the authority and is dropped. A
/// `content-length` must be valid and is checked against the body as it
/// flows. Hop-by-hop and framing fields are refused, as is any field or
/// value a client could not send. The body is capped at
/// `limits.max_request_body_bytes`.
pub fn from_layer_request(
    req: http::Request<Body>,
    meta: RequestMeta,
    limits: &Limits,
    flags: &HttpFlags,
) -> Result<CanonicalRequest, ParseError> {
    let (parts, body) = req.into_parts();
    // A tunnel is opened by the client at the proxy port, never by a layer:
    // forwarded as a request it would ask the upstream to open one.
    if parts.method == http::Method::CONNECT {
        return reject(Reason::InvalidMethod, "a layer cannot pass on CONNECT");
    }
    let method = Method::from_http(&parts.method)?;
    let scheme = match parts.uri.scheme_str() {
        Some("http") => Scheme::Http,
        Some("https") => Scheme::Https,
        Some(other) => return reject(Reason::BadRequestTarget, format!("scheme {other}")),
        None => return reject(Reason::BadRequestTarget, "relative request URI"),
    };
    let Some(auth) = parts.uri.authority() else {
        return reject(Reason::BadAuthority, "request URI has no authority");
    };
    let authority = url::parse_authority(auth.as_str().as_bytes(), scheme.default_port())?;
    let pq = parts.uri.path_and_query().map_or("/", |p| p.as_str());
    if pq.len() > limits.max_url_bytes {
        return reject(Reason::UrlTooLong, "request target too long");
    }
    let (path, query) = url::parse_origin_form(pq.as_bytes())?;

    let head_bytes = parts.headers.iter().fold(0usize, |acc, (n, v)| {
        acc.saturating_add(n.as_str().len())
            .saturating_add(v.len())
            .saturating_add(4)
    });
    if head_bytes > limits.max_header_bytes {
        return reject(Reason::HeadTooLarge, format!("head is {head_bytes} bytes"));
    }
    let mut content_length: Option<u64> = None;
    let mut host_seen = false;
    let mut rest: Vec<(&[u8], &[u8])> = Vec::new();
    for (name, value) in &parts.headers {
        let n = name.as_str();
        let v = trim_ows(value.as_bytes());
        if REFUSED.contains(&n) {
            return reject(Reason::ReservedHeader, format!("{n} set by a layer"));
        }
        match n {
            "host" => {
                if host_seen {
                    return reject(Reason::MultipleHost, "multiple host fields");
                }
                host_seen = true;
                if url::parse_authority(v, scheme.default_port())? != authority {
                    return reject(Reason::HostMismatch, "host does not match the URI");
                }
            }
            "content-length" => {
                if content_length.is_some() {
                    return reject(Reason::DuplicateContentLength, "multiple content-length");
                }
                content_length = Some(parse_content_length(v)?);
            }
            _ => rest.push((name.as_str().as_bytes(), value.as_bytes())),
        }
    }
    let headers = Headers::try_from_raw(rest.iter().copied(), limits, flags)?;

    let plan = plan_body(
        &method,
        content_length.or(body.known_length()),
        http_body::Body::is_end_stream(&body),
        limits,
        flags,
    )?;
    let body = Body::wrap_native(body, plan.cap, plan.known);

    Ok(CanonicalRequest {
        method,
        scheme,
        authority,
        path,
        query,
        headers,
        body,
        meta,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{TargetForm, Version};

    fn req(uri: &str, headers: &[(&str, &str)], body: &'static str) -> http::Request<Body> {
        let mut b = http::Request::builder().method("POST").uri(uri);
        for (n, v) in headers {
            b = b.header(*n, *v);
        }
        b.body(Body::from_bytes(body)).unwrap()
    }

    fn client_meta() -> RequestMeta {
        let mut meta = RequestMeta::new(Version::H2, TargetForm::Absolute);
        meta.head_bytes = 321;
        meta.upgrade = Some("websocket".to_owned());
        meta
    }

    fn check(r: http::Request<Body>) -> Result<CanonicalRequest, ParseError> {
        from_layer_request(r, client_meta(), &Limits::default(), &HttpFlags::default())
    }

    #[test]
    fn accepts_a_plain_request_and_keeps_the_clients_meta() {
        let c = check(req(
            "https://api.example.com/v1/x?a=1",
            &[
                ("content-type", "application/json"),
                ("host", "api.example.com:443"),
            ],
            "{}",
        ))
        .unwrap();
        assert_eq!(c.scheme, Scheme::Https);
        assert_eq!(c.authority.port, 443);
        assert_eq!(c.path_and_query(), "/v1/x?a=1");
        assert_eq!(c.headers.len(), 1);
        assert_eq!(c.body.known_length(), Some(2));
        assert_eq!(c.meta.version, Version::H2);
        assert_eq!(c.meta.head_bytes, 321);
        assert_eq!(c.meta.upgrade.as_deref(), Some("websocket"));
    }

    #[test]
    fn round_trips_through_to_layer_request() {
        let c = check(req("http://example.com:8080/a%20b", &[("x-a", "1")], "")).unwrap();
        let back = check(to_layer_request(c)).unwrap();
        assert_eq!(back.url(), "http://example.com:8080/a%20b");
    }

    #[test]
    fn refuses_what_a_client_could_not_send() {
        for (uri, headers, reason) in [
            ("/relative", vec![], Reason::BadRequestTarget),
            ("ftp://example.com/", vec![], Reason::BadRequestTarget),
            (
                "https://example.com/",
                vec![("transfer-encoding", "chunked")],
                Reason::ReservedHeader,
            ),
            (
                "https://example.com/",
                vec![("connection", "close")],
                Reason::ReservedHeader,
            ),
            (
                "https://example.com/",
                vec![("host", "other.example")],
                Reason::HostMismatch,
            ),
            (
                "https://example.com/",
                vec![("host", "example.com"), ("host", "example.com")],
                Reason::MultipleHost,
            ),
            (
                "https://example.com/",
                vec![("content-length", "1"), ("content-length", "1")],
                Reason::DuplicateContentLength,
            ),
            (
                "https://example.com/",
                vec![("content-length", "-1")],
                Reason::BadContentLength,
            ),
            (
                "https://example.com/",
                vec![("proxy-authorization", "Basic x")],
                Reason::ReservedHeader,
            ),
            (
                "https://example.com/../../etc",
                vec![],
                Reason::PathClimbsAboveRoot,
            ),
        ] {
            let e = check(req(uri, &headers, "")).unwrap_err();
            assert_eq!(e.reason, reason, "{uri} {headers:?}: {e}");
        }
        let get = http::Request::builder()
            .method("GET")
            .uri("https://example.com/")
            .header("content-length", "3")
            .body(Body::from_bytes("abc"))
            .unwrap();
        assert_eq!(check(get).unwrap_err().reason, Reason::BodyOnBodiless);
        let connect = http::Request::builder()
            .method("CONNECT")
            .uri("https://example.com:443/")
            .body(Body::empty())
            .unwrap();
        assert_eq!(check(connect).unwrap_err().reason, Reason::InvalidMethod);
    }
}
