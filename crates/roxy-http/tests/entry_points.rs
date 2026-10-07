//! The three request entry points (the h1 head parser, the h2 mapping and
//! the layer re-validation) judge a field list by one set of rules: an
//! input one of them refuses, the others refuse for the same reason.

use roxy_http::h1::{Role, parse_head};
use roxy_http::h2map::from_h2_parts;
use roxy_http::layer::from_layer_request;
use roxy_http::url::parse_authority;
use roxy_http::{Body, HttpFlags, Limits, Reason, RequestMeta, Scheme, TargetForm, Version};

const AUTHORITY: &str = "api.example.com";

type Field = (&'static str, &'static [u8]);

/// A body that has not ended and declares no length, like an h2 stream
/// whose `HEADERS` frame had no `END_STREAM`.
fn open_body() -> Body {
    let (tx, body) = Body::channel(u64::MAX, None);
    std::mem::forget(tx);
    body
}

fn h1(method: &str, fields: &[Field], limits: &Limits) -> Result<(), Reason> {
    let mut head = format!("{method} / HTTP/1.1\r\n").into_bytes();
    if !fields.iter().any(|(n, _)| n.eq_ignore_ascii_case("host")) {
        head.extend_from_slice(format!("Host: {AUTHORITY}\r\n").as_bytes());
    }
    for (n, v) in fields {
        head.extend_from_slice(n.as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(v);
        head.extend_from_slice(b"\r\n");
    }
    head.extend_from_slice(b"\r\n");
    let role = Role::Tunnel {
        authority: parse_authority(AUTHORITY.as_bytes(), 443).unwrap(),
        scheme: Scheme::Https,
    };
    parse_head(&head, &role, limits, &HttpFlags::default())
        .map(|_| ())
        .map_err(|e| e.reason)
}

fn h2(method: &str, fields: &[Field], body: Body, limits: &Limits) -> Result<(), Reason> {
    let mut b = http::Request::builder()
        .method(method)
        .uri(format!("https://{AUTHORITY}/"))
        .version(http::Version::HTTP_2);
    for (n, v) in fields {
        b = b.header(*n, *v);
    }
    let (parts, ()) = b.body(()).unwrap().into_parts();
    let expected = parse_authority(AUTHORITY.as_bytes(), 443).unwrap();
    from_h2_parts(parts, body, &expected, limits, &HttpFlags::default())
        .map(|_| ())
        .map_err(|e| e.reason)
}

fn layer(method: &str, fields: &[Field], body: Body, limits: &Limits) -> Result<(), Reason> {
    let mut b = http::Request::builder()
        .method(method)
        .uri(format!("https://{AUTHORITY}/"));
    for (n, v) in fields {
        b = b.header(*n, *v);
    }
    let req = b.body(body).unwrap();
    let meta = RequestMeta::new(Version::H1_1, TargetForm::Absolute);
    from_layer_request(req, meta, limits, &HttpFlags::default())
        .map(|_| ())
        .map_err(|e| e.reason)
}

/// Contradictory or over-limit field lists every entry point can carry,
/// and the one reason each gives.
#[test]
fn every_entry_point_gives_the_same_reason() {
    let small = Limits {
        max_request_body_bytes: 10,
        max_headers: 3,
        ..Limits::default()
    };
    let rows: &[(&str, &[Field], Reason)] = &[
        (
            "POST",
            &[("content-length", b"1"), ("content-length", b"1")],
            Reason::DuplicateContentLength,
        ),
        (
            "POST",
            &[("content-length", b"+1")],
            Reason::BadContentLength,
        ),
        ("GET", &[("content-length", b"5")], Reason::BodyOnBodiless),
        ("POST", &[("content-length", b"11")], Reason::BodyTooLarge),
        (
            "POST",
            &[
                ("host", AUTHORITY.as_bytes()),
                ("host", AUTHORITY.as_bytes()),
            ],
            Reason::MultipleHost,
        ),
        ("POST", &[("host", b"other.example")], Reason::HostMismatch),
        ("POST", &[("host", b"ex ample.com")], Reason::BadAuthority),
        ("POST", &[("x-obs", b"caf\xe9")], Reason::NonAscii),
        (
            "POST",
            &[("x-a", b"1"), ("x-b", b"2"), ("x-c", b"3"), ("x-d", b"4")],
            Reason::TooManyHeaders,
        ),
    ];
    for (method, fields, reason) in rows {
        assert_eq!(h1(method, fields, &small), Err(*reason), "h1 {fields:?}");
        assert_eq!(
            h2(method, fields, open_body(), &small),
            Err(*reason),
            "h2 {fields:?}"
        );
        assert_eq!(
            layer(method, fields, open_body(), &small),
            Err(*reason),
            "layer {fields:?}"
        );
    }
}

/// A declared length on a stream that ended with the head is refused by
/// both stream entry points; over h1 the same claim fails as a truncated
/// body once the connection closes, which is exercised by the corpus.
#[test]
fn a_length_on_an_ended_stream_is_a_contradiction() {
    let l = Limits::default();
    let fields: &[Field] = &[("content-length", b"5")];
    assert_eq!(
        h2("POST", fields, Body::empty(), &l),
        Err(Reason::BadContentLength)
    );
    assert_eq!(
        layer("POST", fields, Body::empty(), &l),
        Err(Reason::BadContentLength)
    );
    assert_eq!(h2("POST", fields, open_body(), &l), Ok(()));
    assert_eq!(layer("POST", fields, open_body(), &l), Ok(()));
}

/// Fields a transport refuses before the shared rules see them: h2 as
/// connection-specific (RFC 9113 §8.2.2), a layer as reserved. Over h1
/// they reach the shared rules and are judged there.
#[test]
fn transport_gates_name_their_own_reason() {
    let l = Limits::default();
    let rows: &[(&[Field], Reason, Reason, Reason)] = &[
        (
            &[("content-length", b"5"), ("transfer-encoding", b"chunked")],
            Reason::ClAndTe,
            Reason::H2ConnectionHeader,
            Reason::ReservedHeader,
        ),
        (
            &[("transfer-encoding", b"gzip")],
            Reason::BadTransferEncoding,
            Reason::H2ConnectionHeader,
            Reason::ReservedHeader,
        ),
        (
            &[("connection", b"(bad)")],
            Reason::BadConnectionHeader,
            Reason::H2ConnectionHeader,
            Reason::ReservedHeader,
        ),
        (
            &[("expect", b"102-processing")],
            Reason::BadExpect,
            Reason::BadExpect,
            Reason::ReservedHeader,
        ),
        (
            &[("expect", b"100-continue"), ("expect", b"100-continue")],
            Reason::BadExpect,
            Reason::BadExpect,
            Reason::ReservedHeader,
        ),
    ];
    for (fields, on_h1, on_h2, on_layer) in rows {
        assert_eq!(h1("POST", fields, &l), Err(*on_h1), "h1 {fields:?}");
        assert_eq!(
            h2("POST", fields, open_body(), &l),
            Err(*on_h2),
            "h2 {fields:?}"
        );
        assert_eq!(
            layer("POST", fields, open_body(), &l),
            Err(*on_layer),
            "layer {fields:?}"
        );
    }
}
