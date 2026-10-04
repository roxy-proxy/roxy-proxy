//! HTTP/2 request parts ↔ canonical model.
//!
//! Pure functions over `http` types; the `h2` connection itself is wired by
//! `roxy-proxy`. The `h2` crate already enforces pseudo-header presence,
//! ordering and uniqueness, lower-case names, and `content-length` vs DATA;
//! these functions apply roxy's semantic rules on top.
//!
//! Note: `http::Uri` silently drops a `#fragment` from `:path`, so h2
//! fragments cannot be rejected here; matching and forwarding still agree
//! because both use the fragment-less path.

use http::header::{CONTENT_LENGTH, DATE};
use http::{HeaderValue, Version as HttpVersion};

use crate::chars::trim_ows;
use crate::model::{
    Authority, Body, CanonicalRequest, CanonicalResponse, Headers, HttpFlags, Limits, Method,
    ParseError, Reason, RequestMeta, Scheme, TargetForm, Version, is_reserved, reject,
    status_forbids_body,
};
use crate::url;

/// Connection-specific fields that make an h2 request malformed (RFC 9113
/// §8.2.2).
const CONNECTION_SPECIFIC: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
];

/// Trailer fields never accepted even with `http.allow_trailers` (mirrors
/// the h1 chunked decoder; RFC 9110 §6.5.1). `content-*` and reserved
/// fields are refused too.
const FORBIDDEN_TRAILERS: &[&str] = &[
    "authorization",
    "cookie",
    "set-cookie",
    "content-type",
    "content-encoding",
    "content-range",
    "expect",
    "range",
    "max-forwards",
    "cache-control",
];

/// Per-field overhead counted by HPACK's header list size (RFC 9113 §6.5.2).
const FIELD_OVERHEAD: usize = 32;

/// Builds a canonical request from h2 request parts.
///
/// `body` is the stream's body (adapted by the caller); it is wrapped here so
/// that `limits.max_request_body_bytes` and the declared `content-length` are
/// enforced as frames flow, and so that GET/HEAD/... carry no data unless
/// `http.allow_body_on_get`.
#[allow(clippy::too_many_lines, clippy::needless_pass_by_value)] // signature takes ownership by contract
pub fn from_h2_parts(
    parts: http::request::Parts,
    body: Body,
    expected_authority: &Authority,
    limits: &Limits,
    flags: &HttpFlags,
) -> Result<CanonicalRequest, ParseError> {
    if parts.version != HttpVersion::HTTP_2 {
        return reject(Reason::UnsupportedVersion, "not an HTTP/2 request");
    }
    if parts.method == http::Method::CONNECT {
        return reject(
            Reason::H2UnsupportedMethod,
            "h2 CONNECT / extended CONNECT is not supported",
        );
    }
    let method = Method::from_http(&parts.method)?;

    // Pseudo-headers (as mapped into the URI by the h2 crate).
    match parts.uri.scheme_str() {
        None => return reject(Reason::H2BadPseudoHeader, "missing :scheme"),
        Some("https") => {}
        Some(other) => return reject(Reason::H2BadScheme, format!(":scheme {other}")),
    }
    let Some(auth) = parts.uri.authority() else {
        return reject(Reason::H2BadPseudoHeader, "missing :authority");
    };
    let authority = url::parse_authority(auth.as_str().as_bytes(), Scheme::Https.default_port())?;
    if authority != *expected_authority {
        return reject(
            Reason::AuthorityMismatch,
            format!(":authority {authority} != {expected_authority}"),
        );
    }
    let Some(pq) = parts.uri.path_and_query() else {
        return reject(Reason::H2BadPseudoHeader, "missing :path");
    };
    let pq = pq.as_str();
    if pq == "*" {
        return reject(Reason::BadRequestTarget, "asterisk-form is not supported");
    }
    if pq.is_empty() {
        return reject(Reason::H2BadPseudoHeader, "empty :path");
    }
    let (path, query) = url::parse_origin_form(pq.as_bytes())?;

    // Regular headers.
    let list_size: usize = parts
        .headers
        .iter()
        .map(|(n, v)| n.as_str().len() + v.len() + FIELD_OVERHEAD)
        .sum();
    if list_size > limits.h2_max_header_list_bytes {
        return reject(
            Reason::HeadTooLarge,
            format!("header list is {list_size} bytes"),
        );
    }
    if parts.headers.len() > limits.max_headers {
        return reject(Reason::TooManyHeaders, "too many header fields");
    }
    let mut meta = RequestMeta::new(Version::H2, TargetForm::H2);
    meta.head_bytes = list_size;
    let mut content_length: Option<u64> = None;
    let mut host_seen = false;
    let mut expect = false;
    let mut cookies: Vec<&[u8]> = Vec::new();
    let mut rest: Vec<(&[u8], &[u8])> = Vec::new();
    for (name, value) in &parts.headers {
        let n = name.as_str();
        let v = trim_ows(value.as_bytes());
        if CONNECTION_SPECIFIC.contains(&n) {
            return reject(Reason::H2ConnectionHeader, format!("{n} in an h2 request"));
        }
        match n {
            "te" => {
                if !v.eq_ignore_ascii_case(b"trailers") {
                    return reject(Reason::H2BadTe, "te other than trailers");
                }
            }
            "host" => {
                if host_seen {
                    return reject(Reason::MultipleHost, "multiple host fields");
                }
                host_seen = true;
                let h = url::parse_authority(v, Scheme::Https.default_port())?;
                if h != authority {
                    return reject(Reason::HostMismatch, "host does not match :authority");
                }
            }
            "content-length" => {
                if content_length.is_some() {
                    return reject(Reason::DuplicateContentLength, "multiple content-length");
                }
                if v.is_empty() || v.len() > 19 || !v.iter().all(u8::is_ascii_digit) {
                    return reject(Reason::BadContentLength, "invalid content-length");
                }
                content_length = Some(
                    v.iter()
                        .fold(0u64, |acc, &d| acc * 10 + u64::from(d - b'0')),
                );
            }
            "expect" => {
                if expect || !v.eq_ignore_ascii_case(b"100-continue") {
                    return reject(Reason::BadExpect, "unsupported expectation");
                }
                expect = true;
            }
            "proxy-authorization" => {
                meta.proxy_authorization = HeaderValue::from_bytes(v).ok();
            }
            "cookie" => cookies.push(v),
            _ => rest.push((name.as_str().as_bytes(), value.as_bytes())),
        }
    }
    // RFC 9113 §8.2.3: split cookie fields are re-joined for HTTP/1.1
    // upstreams.
    let joined_cookie = cookies.join(&b"; "[..]);
    if !cookies.is_empty() {
        rest.push((b"cookie", &joined_cookie));
    }
    let headers = Headers::try_from_raw(rest.iter().copied(), limits, flags)?;

    let bodiless = !method.allows_body(flags.allow_body_on_get);
    if bodiless && content_length.is_some_and(|n| n > 0) {
        return reject(Reason::BodyOnBodiless, format!("body on {method} request"));
    }
    if let Some(n) = content_length
        && n > limits.max_request_body_bytes
    {
        return reject(Reason::BodyTooLarge, format!("content-length {n}"));
    }
    let cap = if bodiless {
        0
    } else {
        limits.max_request_body_bytes
    };
    // END_STREAM on the HEADERS frame: the body is known to be empty (the
    // `h2` crate already refused a non-zero `content-length` with it).
    let known = if bodiless || http_body::Body::is_end_stream(&body) {
        Some(0)
    } else {
        content_length
    };
    let body = Body::wrap_with_length(body, cap, known);
    meta.expect_continue = expect && known != Some(0);

    Ok(CanonicalRequest {
        method,
        scheme: Scheme::Https,
        authority,
        path,
        query,
        headers,
        body,
        meta,
    })
}

/// Validates an h2 request trailer section. Only call this when
/// `http.allow_trailers` is set (otherwise any trailer section is a
/// rejection). Applies the same field rules as the h1 chunked decoder:
/// framing, routing, authentication and content metadata are refused, and
/// values go through the header validator.
pub fn validate_h2_trailers(
    trailers: &http::HeaderMap,
    limits: &Limits,
    flags: &HttpFlags,
) -> Result<http::HeaderMap, ParseError> {
    if trailers.len() > limits.max_headers {
        return reject(Reason::TooManyHeaders, "too many trailer fields");
    }
    for name in trailers.keys() {
        let n = name.as_str();
        if is_reserved(n)
            || CONNECTION_SPECIFIC.contains(&n)
            || FORBIDDEN_TRAILERS.contains(&n)
            || n.starts_with("content-")
        {
            return reject(Reason::Trailers, format!("{n} not allowed in trailers"));
        }
    }
    let raw: Vec<(&[u8], &[u8])> = trailers
        .iter()
        .map(|(n, v)| (n.as_str().as_bytes(), v.as_bytes()))
        .collect();
    let checked = Headers::try_from_raw(raw.iter().copied(), limits, flags)?;
    let mut out = http::HeaderMap::new();
    for (n, v) in &checked {
        out.append(n.clone(), v.clone());
    }
    Ok(out)
}

/// Response head for an h2 stream (the caller streams `res.body` as DATA
/// frames). `content-length` is set when the length is known and the status
/// permits a body; for HEAD requests the upstream's declared length is used.
/// `date` is added if absent. No connection-specific headers are emitted
/// (canonical headers never contain them).
pub fn to_h2_response(res: &CanonicalResponse, request_method: &Method) -> http::response::Builder {
    let mut b = http::Response::builder()
        .status(res.status)
        .version(HttpVersion::HTTP_2);
    if !res.headers.contains("date")
        && let Ok(v) = HeaderValue::from_str(&httpdate::fmt_http_date(std::time::SystemTime::now()))
    {
        b = b.header(DATE, v);
    }
    for (n, v) in &res.headers {
        b = b.header(n, v);
    }
    if !status_forbids_body(res.status) {
        let len = if *request_method == Method::Head {
            res.meta.declared_length.or(res.body.known_length())
        } else {
            res.body.known_length()
        };
        if let Some(n) = len {
            b = b.header(CONTENT_LENGTH, n);
        }
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::StatusCode;

    fn auth() -> Authority {
        url::parse_authority(b"api.example.com", 443).unwrap()
    }

    fn req(uri: &str, headers: &[(&str, &str)]) -> http::request::Parts {
        let mut b = http::Request::builder()
            .method("GET")
            .uri(uri)
            .version(HttpVersion::HTTP_2);
        for (n, v) in headers {
            b = b.header(*n, *v);
        }
        b.body(()).unwrap().into_parts().0
    }

    fn map(parts: http::request::Parts) -> Result<CanonicalRequest, Reason> {
        from_h2_parts(
            parts,
            Body::empty(),
            &auth(),
            &Limits::default(),
            &HttpFlags::default(),
        )
        .map_err(|e| e.reason)
    }

    #[test]
    fn happy_path() {
        let r = map(req(
            "https://API.example.com/v1/../v2/x?q=%2f",
            &[
                ("accept", "*/*"),
                ("te", "trailers"),
                ("host", "api.example.com:443"),
                ("cookie", "a=1"),
                ("cookie", "b=2"),
                ("proxy-authorization", "Basic eA=="),
            ],
        ))
        .unwrap();
        assert_eq!(r.url(), "https://api.example.com:443/v2/x?q=%2F");
        assert_eq!(r.meta.version, Version::H2);
        assert_eq!(r.headers.get("cookie"), Some("a=1; b=2"));
        assert!(!r.headers.contains("te"));
        assert!(!r.headers.contains("host"));
        assert!(!r.headers.contains("proxy-authorization"));
        assert_eq!(r.meta.proxy_authorization.unwrap(), "Basic eA==");
        assert_eq!(r.body.known_length(), Some(0));
    }

    #[test]
    fn connection_specific_headers_rejected() {
        for h in [
            "connection",
            "keep-alive",
            "proxy-connection",
            "transfer-encoding",
            "upgrade",
        ] {
            assert_eq!(
                map(req("https://api.example.com/", &[(h, "x")])).unwrap_err(),
                Reason::H2ConnectionHeader,
                "{h}"
            );
        }
    }

    #[test]
    fn te_only_trailers() {
        assert_eq!(
            map(req("https://api.example.com/", &[("te", "gzip")])).unwrap_err(),
            Reason::H2BadTe
        );
        assert_eq!(
            map(req("https://api.example.com/", &[("te", "trailers, gzip")])).unwrap_err(),
            Reason::H2BadTe
        );
        assert!(map(req("https://api.example.com/", &[("te", "Trailers")])).is_ok());
    }

    #[test]
    fn authority_rules() {
        assert_eq!(
            map(req("https://evil.example.com/", &[])).unwrap_err(),
            Reason::AuthorityMismatch
        );
        assert_eq!(
            map(req("https://api.example.com:8443/", &[])).unwrap_err(),
            Reason::AuthorityMismatch
        );
        assert!(map(req("https://api.example.com:443/", &[])).is_ok());
        assert_eq!(
            map(req("https://u@api.example.com/", &[])).unwrap_err(),
            Reason::BadAuthority
        );
        assert_eq!(
            map(req("/only-path", &[])).unwrap_err(),
            Reason::H2BadPseudoHeader
        );
        assert_eq!(
            map(req(
                "https://api.example.com/",
                &[("host", "evil.example.com")]
            ))
            .unwrap_err(),
            Reason::HostMismatch
        );
        assert_eq!(
            map(req(
                "https://api.example.com/",
                &[("host", "api.example.com"), ("host", "api.example.com")]
            ))
            .unwrap_err(),
            Reason::MultipleHost
        );
    }

    #[test]
    fn scheme_must_be_https() {
        assert_eq!(
            map(req("http://api.example.com/", &[])).unwrap_err(),
            Reason::H2BadScheme
        );
    }

    #[test]
    fn path_goes_through_normaliser() {
        assert_eq!(
            map(req("https://api.example.com/%2e%2e/x", &[])).unwrap_err(),
            Reason::PathClimbsAboveRoot
        );
        assert_eq!(
            map(req("https://api.example.com/a/../../x", &[])).unwrap_err(),
            Reason::PathClimbsAboveRoot
        );
        assert_eq!(
            map(req("https://api.example.com/a%zz", &[])).unwrap_err(),
            Reason::BadPercentEncoding
        );
        assert_eq!(
            map(req("https://api.example.com/caf\u{e9}", &[])).unwrap_err(),
            Reason::NonAscii
        );
        let r = map(req("https://api.example.com/%7e", &[])).unwrap();
        assert_eq!(r.path.as_str(), "/~");
    }

    #[test]
    fn version_and_method() {
        let mut p = req("https://api.example.com/", &[]);
        p.version = HttpVersion::HTTP_11;
        assert_eq!(map(p).unwrap_err(), Reason::UnsupportedVersion);
        let mut p = req("https://api.example.com/", &[]);
        p.method = http::Method::CONNECT;
        assert_eq!(map(p).unwrap_err(), Reason::H2UnsupportedMethod);
    }

    #[test]
    fn framing_and_values() {
        assert_eq!(
            map(req("https://api.example.com/", &[("content-length", "5")])).unwrap_err(),
            Reason::BodyOnBodiless
        );
        assert_eq!(
            map(req(
                "https://api.example.com/",
                &[("expect", "102-processing")]
            ))
            .unwrap_err(),
            Reason::BadExpect
        );
        let mut p = req("https://api.example.com/", &[]);
        p.headers
            .append("content-length", HeaderValue::from_static("1"));
        p.headers
            .append("content-length", HeaderValue::from_static("1"));
        p.method = http::Method::POST;
        assert_eq!(map(p).unwrap_err(), Reason::DuplicateContentLength);
        let mut p = req("https://api.example.com/", &[("content-length", "+1")]);
        p.method = http::Method::POST;
        assert_eq!(map(p).unwrap_err(), Reason::BadContentLength);
        let mut p = req("https://api.example.com/", &[]);
        p.headers
            .append("x-obs", HeaderValue::from_bytes(b"caf\xe9").unwrap());
        assert_eq!(map(p).unwrap_err(), Reason::NonAscii);
    }

    #[test]
    fn header_list_cap() {
        let limits = Limits {
            h2_max_header_list_bytes: 100,
            ..Limits::default()
        };
        let big = "x".repeat(100);
        let p = req("https://api.example.com/", &[("x-big", &big)]);
        assert_eq!(
            from_h2_parts(p, Body::empty(), &auth(), &limits, &HttpFlags::default())
                .unwrap_err()
                .reason,
            Reason::HeadTooLarge
        );
    }

    #[tokio::test]
    async fn body_cap_and_length_enforced() {
        let limits = Limits {
            max_request_body_bytes: 4,
            ..Limits::default()
        };
        let mut p = req("https://api.example.com/", &[]);
        p.method = http::Method::POST;
        let r = from_h2_parts(
            p,
            Body::from_bytes("hello"),
            &auth(),
            &limits,
            &HttpFlags::default(),
        )
        .unwrap();
        assert!(r.body.collect_up_to(100).await.is_err());

        // A GET whose stream carries data anyway.
        let r = from_h2_parts(
            req("https://api.example.com/", &[]),
            Body::from_bytes("x"),
            &auth(),
            &Limits::default(),
            &HttpFlags::default(),
        )
        .unwrap();
        assert!(r.body.collect_up_to(100).await.is_err());

        let mut p = req("https://api.example.com/", &[("content-length", "3")]);
        p.method = http::Method::POST;
        let r = from_h2_parts(
            p,
            Body::from_bytes("hello"),
            &auth(),
            &Limits::default(),
            &HttpFlags::default(),
        )
        .unwrap();
        assert_eq!(r.body.known_length(), Some(3));
        assert!(r.body.collect_up_to(100).await.is_err());
    }

    #[test]
    fn trailers_validated() {
        let mut t = http::HeaderMap::new();
        t.insert("grpc-status", HeaderValue::from_static("0"));
        let ok = validate_h2_trailers(&t, &Limits::default(), &HttpFlags::default()).unwrap();
        assert_eq!(ok.get("grpc-status").unwrap(), "0");
        for bad in [
            "authorization",
            "content-length",
            "content-md5",
            "host",
            "connection",
        ] {
            let mut t = http::HeaderMap::new();
            t.insert(
                http::HeaderName::from_static(bad),
                HeaderValue::from_static("x"),
            );
            assert_eq!(
                validate_h2_trailers(&t, &Limits::default(), &HttpFlags::default())
                    .unwrap_err()
                    .reason,
                Reason::Trailers,
                "{bad}"
            );
        }
    }

    #[test]
    fn response_head() {
        let mut res = CanonicalResponse::new(StatusCode::OK);
        res.headers.append("set-cookie", "a").unwrap();
        res.headers.append("set-cookie", "b").unwrap();
        res.body = Body::from_bytes("hello");
        let r = to_h2_response(&res, &Method::Get).body(()).unwrap();
        assert_eq!(r.version(), HttpVersion::HTTP_2);
        assert_eq!(r.headers().get("content-length").unwrap(), "5");
        assert_eq!(r.headers().get_all("set-cookie").iter().count(), 2);
        assert!(r.headers().contains_key("date"));

        let mut res = CanonicalResponse::new(StatusCode::OK);
        res.meta.declared_length = Some(99);
        let r = to_h2_response(&res, &Method::Head).body(()).unwrap();
        assert_eq!(r.headers().get("content-length").unwrap(), "99");

        let res = CanonicalResponse::new(StatusCode::NOT_MODIFIED);
        let r = to_h2_response(&res, &Method::Get).body(()).unwrap();
        assert!(!r.headers().contains_key("content-length"));
    }
}
