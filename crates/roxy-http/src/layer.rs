//! Addon layer messages ↔ canonical model.
//!
//! A layer receives the canonical request as an `http::Request` with an
//! absolute URI, and passes on whatever it likes. What it passes on is
//! re-validated here exactly as strictly as a client's request (invariant
//! 1: the rules then judge it as if the agent had sent it), and held to the
//! same limits. The client's [`RequestMeta`] travels with it: a layer
//! cannot express the protocol version, the target form, the upgrade or
//! the time the head arrived, and those stay the client's.

use crate::model::{
    Body, BodyHint, CanonicalRequest, CanonicalResponse, HttpFlags, Limits, Method, ParseError,
    Reason, RequestFields, RequestMeta, Scheme, check_host, is_reserved, reject,
};
use crate::url;

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
    *out.uri_mut() = uri
        .parse()
        .expect("a canonical request serialises to a valid absolute URI");
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
    // `host` and `content-length` are reserved too, but a layer states them
    // as part of the request rather than owning them: they are checked
    // against the URI and the body, then dropped.
    if let Some(n) = parts
        .headers
        .keys()
        .map(http::HeaderName::as_str)
        .find(|n| is_reserved(n) && !matches!(*n, "host" | "content-length"))
    {
        return reject(Reason::ReservedHeader, format!("{n} set by a layer"));
    }
    let raw: Vec<(&[u8], &[u8])> = parts
        .headers
        .iter()
        .map(|(n, v)| (n.as_str().as_bytes(), v.as_bytes()))
        .collect();
    let hint = BodyHint::Stream {
        ended: http_body::Body::is_end_stream(&body),
        known_length: body.known_length(),
    };
    let fields = RequestFields::from_raw(&raw, &method, meta.version, hint, limits, flags)?;
    if let Some(h) = fields.host {
        check_host(h, &authority, scheme.default_port(), "the URI")?;
    }
    let headers = fields.headers;
    let body = Body::wrap_native(body, fields.body.cap, fields.body.known);

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
    use proptest::prelude::*;

    use super::*;
    use crate::chars::is_pchar_literal;
    use crate::model::{TargetForm, Version, is_reserved};

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

    /// Every byte the normaliser leaves literal in a path or query must
    /// also be accepted by `http::Uri`, or `to_layer_request` panics.
    #[test]
    fn round_trips_every_literal_byte() {
        let path_literals: String = (0x21u8..0x7f)
            .filter(|&b| b != b'/' && is_pchar_literal(b))
            .map(char::from)
            .collect();
        let query_literals: String = (0x21u8..0x7f)
            .filter(|&b| matches!(b, b'/' | b'?' | b'[' | b']') || is_pchar_literal(b))
            .map(char::from)
            .collect();
        let uri = format!("https://example.com/{path_literals}/%2F%7B?{query_literals}&%2F");
        let c = check(req(&uri, &[], "")).unwrap();
        assert_eq!(c.path_and_query(), &uri["https://example.com".len()..]);
        let back = check(to_layer_request(c)).unwrap();
        assert_eq!(back.url(), uri.replace("example.com", "example.com:443"));
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
                "https://example.com/",
                vec![("expect", "100-continue")],
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

    fn header_strategy() -> impl Strategy<Value = Vec<(String, String)>> {
        let name = prop_oneof![
            "[a-z][a-z0-9-]{0,8}",
            Just("host".to_owned()),
            Just("content-length".to_owned()),
            Just("connection".to_owned()),
            Just("transfer-encoding".to_owned()),
            Just("te".to_owned()),
            Just("proxy-authorization".to_owned()),
            Just("upgrade".to_owned()),
        ];
        let value = prop_oneof![
            "[ -~]{0,12}",
            Just("example.com".to_owned()),
            Just("example.com:8443".to_owned()),
            Just("EXAMPLE.com:443".to_owned()),
            Just("0".to_owned()),
            Just("5".to_owned()),
        ];
        proptest::collection::vec((name, value), 0..6)
    }

    proptest! {
        /// A request a layer passes on is canonical when accepted: the
        /// authority is the URI's (with the scheme's default port filled
        /// in), the path is already normalised, and no hop-by-hop or
        /// framing field survives.
        #[test]
        fn accepted_layer_requests_are_canonical(
            method in prop_oneof![Just("GET"), Just("POST"), Just("HEAD"), Just("DELETE"), Just("CONNECT"), Just("PATCH")],
            scheme in prop_oneof![Just("http"), Just("https"), Just("ftp")],
            authority in prop_oneof![
                Just("example.com"),
                Just("EXAMPLE.com:443"),
                Just("example.com:8443"),
                Just("example.com."),
                Just("[::1]:8080"),
                Just("a..b"),
                Just("x:0"),
            ],
            path in "(/[a-zA-Z0-9._~%!$&'()*+,;=:@-]{0,6}){0,4}(\\?[a-z=&%]{0,8})?",
            headers in header_strategy(),
            body in "[a-z]{0,8}",
        ) {
            let mut b = http::Request::builder()
                .method(method)
                .uri(format!("{scheme}://{authority}{path}"));
            for (n, v) in &headers {
                b = b.header(n.as_str(), v.as_str());
            }
            let Ok(req) = b.body(Body::from_bytes(body)) else {
                return Ok(());
            };
            let Ok(c) = check(req) else {
                return Ok(());
            };
            let want = url::parse_authority(authority.as_bytes(), c.scheme.default_port()).unwrap();
            prop_assert_eq!(&c.authority, &want);
            prop_assert_eq!(
                url::normalize_path(c.path.as_str().as_bytes()).unwrap(),
                c.path.clone()
            );
            for (name, _) in &c.headers {
                prop_assert!(!is_reserved(name.as_str()), "reserved field {} kept", name);
            }
        }
    }
}
