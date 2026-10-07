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
    Authority, Body, BodyHint, CanonicalRequest, CanonicalResponse, Headers, HttpFlags, Limits,
    Method, ParseError, Reason, RequestFields, RequestMeta, Scheme, TargetForm, Version,
    check_host, check_trailer_fields, reject, status_forbids_body,
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

/// Per-field overhead counted by HPACK's header list size (RFC 9113 §6.5.2).
const FIELD_OVERHEAD: usize = 32;

/// The target from the pseudo-headers (as mapped into the URI by the h2
/// crate): `:scheme` must be `https`, `:authority` must be the expected one
/// and `:path` goes through the URL normaliser under the h1 length cap.
fn target_from_uri(
    uri: &http::Uri,
    expected_authority: &Authority,
    limits: &Limits,
) -> Result<(Authority, url::Path, Option<url::Query>), ParseError> {
    match uri.scheme_str() {
        None => return reject(Reason::H2BadPseudoHeader, "missing :scheme"),
        Some("https") => {}
        Some(other) => return reject(Reason::H2BadScheme, format!(":scheme {other}")),
    }
    let Some(auth) = uri.authority() else {
        return reject(Reason::H2BadPseudoHeader, "missing :authority");
    };
    let authority = url::parse_authority(auth.as_str().as_bytes(), Scheme::Https.default_port())?;
    if authority != *expected_authority {
        return reject(
            Reason::AuthorityMismatch,
            format!(":authority {authority} != {expected_authority}"),
        );
    }
    let Some(pq) = uri.path_and_query() else {
        return reject(Reason::H2BadPseudoHeader, "missing :path");
    };
    let pq = pq.as_str();
    if pq == "*" {
        return reject(Reason::BadRequestTarget, "asterisk-form is not supported");
    }
    if pq.is_empty() {
        return reject(Reason::H2BadPseudoHeader, "empty :path");
    }
    if pq.len() > limits.max_url_bytes {
        return reject(Reason::UrlTooLong, format!(":path is {} bytes", pq.len()));
    }
    let (path, query) = url::parse_origin_form(pq.as_bytes())?;
    Ok((authority, path, query))
}

/// The HPACK header list size (RFC 9113 §6.5.2), checked against
/// `limits.h2_max_header_list_bytes`, with the field count checked against
/// `limits.max_headers`.
fn header_list_size(headers: &http::HeaderMap, limits: &Limits) -> Result<usize, ParseError> {
    let list_size = headers.iter().fold(0usize, |acc, (n, v)| {
        acc.saturating_add(n.as_str().len())
            .saturating_add(v.len())
            .saturating_add(FIELD_OVERHEAD)
    });
    if list_size > limits.h2_max_header_list_bytes {
        return reject(
            Reason::HeadTooLarge,
            format!("header list is {list_size} bytes"),
        );
    }
    if headers.len() > limits.max_headers {
        return reject(Reason::TooManyHeaders, "too many header fields");
    }
    Ok(list_size)
}

/// Builds a canonical request from h2 request parts.
///
/// `body` is the stream's body (adapted by the caller); it is wrapped here so
/// that `limits.max_request_body_bytes` and the declared `content-length` are
/// enforced as frames flow, and so that GET/HEAD/... carry no data unless
/// `http.allow_body_on_get`.
#[allow(clippy::needless_pass_by_value)] // signature takes ownership by contract
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

    let (authority, path, query) = target_from_uri(&parts.uri, expected_authority, limits)?;

    let list_size = header_list_size(&parts.headers, limits)?;
    let mut cookies: Vec<&[u8]> = Vec::new();
    let mut rest: Vec<(&[u8], &[u8])> = Vec::new();
    for (name, value) in &parts.headers {
        let n = name.as_str();
        if CONNECTION_SPECIFIC.contains(&n) {
            return reject(Reason::H2ConnectionHeader, format!("{n} in an h2 request"));
        }
        match n {
            "te" => {
                if !trim_ows(value.as_bytes()).eq_ignore_ascii_case(b"trailers") {
                    return reject(Reason::H2BadTe, "te other than trailers");
                }
            }
            "cookie" => cookies.push(trim_ows(value.as_bytes())),
            _ => rest.push((n.as_bytes(), value.as_bytes())),
        }
    }
    // RFC 9113 §8.2.3: split cookie fields are re-joined for HTTP/1.1
    // upstreams.
    let joined_cookie = cookies.join(&b"; "[..]);
    if !cookies.is_empty() {
        rest.push((b"cookie", &joined_cookie));
    }
    // END_STREAM on the HEADERS frame: the body is known to be empty.
    let hint = BodyHint::Stream {
        ended: http_body::Body::is_end_stream(&body),
        known_length: None,
    };
    let fields = RequestFields::from_raw(&rest, &method, Version::H2, hint, limits, flags)?;
    if let Some(h) = fields.host {
        check_host(h, &authority, Scheme::Https.default_port(), ":authority")?;
    }
    let headers = fields.headers;
    let body = Body::wrap_with_length(body, fields.body.cap, fields.body.known);
    let mut meta = RequestMeta::new(Version::H2, TargetForm::H2);
    meta.head_bytes = list_size;
    meta.expect_continue = fields.expect_continue;

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

/// Validates an h2 request trailer section. Any trailer section is a
/// rejection unless `http.allow_request_trailers`; with it, the same field
/// rules as the h1 chunked decoder apply: framing, routing, authentication
/// and content metadata are refused, and values go through the header
/// validator.
pub fn validate_h2_trailers(
    trailers: &http::HeaderMap,
    limits: &Limits,
    flags: &HttpFlags,
) -> Result<http::HeaderMap, ParseError> {
    if !flags.allow_request_trailers {
        return reject(Reason::Trailers, "trailer section present");
    }
    check_trailer_fields(trailers, limits)?;
    let raw: Vec<(&[u8], &[u8])> = trailers
        .iter()
        .map(|(n, v)| (n.as_str().as_bytes(), v.as_bytes()))
        .collect();
    let checked = Headers::try_from_raw(raw, limits, flags)?;
    Ok(checked.to_header_map())
}

/// Response head for an h2 stream (the caller streams `res.body` as DATA
/// frames). `content-length` is set when the length is known and the status
/// permits a body. A HEAD response's body is always empty, so only the
/// length the upstream declared is forwarded. `date` is added if absent. No connection-specific headers are emitted
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
            res.meta.declared_length
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
    use crate::BodyError;
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
    fn path_length_cap() {
        let limits = Limits {
            max_url_bytes: 16,
            ..Limits::default()
        };
        let long = format!("https://api.example.com/{}", "a".repeat(16));
        assert_eq!(
            from_h2_parts(
                req(&long, &[]),
                Body::empty(),
                &auth(),
                &limits,
                &HttpFlags::default()
            )
            .unwrap_err()
            .reason,
            Reason::UrlTooLong
        );
        let fits = format!("https://api.example.com/{}", "a".repeat(15));
        assert!(
            from_h2_parts(
                req(&fits, &[]),
                Body::empty(),
                &auth(),
                &limits,
                &HttpFlags::default()
            )
            .is_ok()
        );
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

    /// Without a content-length the body's length is unknown: it is held
    /// to the cap, not to any declared length, and the client's `expect`
    /// still earns a 100. A bodiless method is capped at zero, so the first
    /// data frame on its stream is the error, whatever the stream says.
    #[tokio::test]
    async fn an_unknown_length_is_capped_and_a_bodiless_method_takes_no_data() {
        let limits = Limits {
            max_request_body_bytes: 4,
            ..Limits::default()
        };
        let post = |body: &'static str| {
            let mut p = req("https://api.example.com/", &[("expect", "100-continue")]);
            p.method = http::Method::POST;
            from_h2_parts(
                p,
                Body::from_bytes(body),
                &auth(),
                &limits,
                &HttpFlags::default(),
            )
            .unwrap()
        };
        let r = post("hell");
        assert_eq!(r.body.known_length(), None);
        assert!(r.meta.expect_continue);
        assert_eq!(r.body.collect_up_to(100).await.unwrap().data, "hell");
        let r = post("hello");
        assert_eq!(
            r.body.collect_up_to(100).await.unwrap_err(),
            BodyError::TooLarge { limit: 4 }
        );

        let r = from_h2_parts(
            req("https://api.example.com/", &[("expect", "100-continue")]),
            Body::from_bytes("x"),
            &auth(),
            &Limits::default(),
            &HttpFlags::default(),
        )
        .unwrap();
        assert_eq!(r.body.known_length(), Some(0));
        assert!(!r.meta.expect_continue);
        assert_eq!(
            r.body.collect_up_to(100).await.unwrap_err(),
            BodyError::TooLarge { limit: 0 }
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
    fn trailers_refused_unless_allowed() {
        let mut t = http::HeaderMap::new();
        t.insert("grpc-status", HeaderValue::from_static("0"));
        assert_eq!(
            validate_h2_trailers(&t, &Limits::default(), &HttpFlags::default())
                .unwrap_err()
                .reason,
            Reason::Trailers
        );
    }

    #[test]
    fn trailers_validated() {
        let flags = HttpFlags {
            allow_request_trailers: true,
            ..HttpFlags::default()
        };
        let mut t = http::HeaderMap::new();
        t.insert("grpc-status", HeaderValue::from_static("0"));
        let ok = validate_h2_trailers(&t, &Limits::default(), &flags).unwrap();
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
                validate_h2_trailers(&t, &Limits::default(), &flags)
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

        // A HEAD response's empty body says nothing about the length.
        let mut res = CanonicalResponse::new(StatusCode::OK);
        res.body = Body::empty();
        assert_eq!(res.body.known_length(), Some(0));
        let r = to_h2_response(&res, &Method::Head).body(()).unwrap();
        assert!(!r.headers().contains_key("content-length"));

        let res = CanonicalResponse::new(StatusCode::NOT_MODIFIED);
        let r = to_h2_response(&res, &Method::Get).body(()).unwrap();
        assert!(!r.headers().contains_key("content-length"));
    }
}
