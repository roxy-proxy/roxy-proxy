//! The h2 → canonical request mapping (`roxy-http::h2map::from_h2_parts`),
//! with arbitrary pseudo-headers and header lists.
//!
//! Invariants:
//! - nothing panics;
//! - an accepted request is canonical: its authority is the tunnel's, its
//!   path is already normalised (normalising it again changes nothing), and
//!   its headers hold no reserved (hop-by-hop / framing / routing) field.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use roxy_http::h2map::from_h2_parts;
use roxy_http::model::is_reserved;
use roxy_http::url::{normalize_path, parse_authority};
use roxy_http::{Body, Limits};

#[derive(Debug, Arbitrary)]
struct Input<'a> {
    cfg: u8,
    method: &'a str,
    scheme: u8,
    /// `None`: the tunnel's own authority, so the mapping goes deeper.
    authority: Option<&'a str>,
    path: &'a str,
    headers: Vec<(&'a [u8], &'a [u8])>,
}

fuzz_target!(|input: Input<'_>| {
    let expected = parse_authority(b"example.com", 443).expect("valid authority");
    let scheme = match input.scheme % 4 {
        0 => "http",
        1 => "ftp",
        _ => "https",
    };
    let authority = input.authority.unwrap_or("example.com");
    let uri = format!("{scheme}://{authority}{}", input.path);
    let Ok(mut req) = http::Request::builder()
        .version(http::Version::HTTP_2)
        .method(input.method)
        .uri(uri)
        .body(())
    else {
        return;
    };
    for (name, value) in &input.headers {
        if let (Ok(n), Ok(v)) = (
            http::HeaderName::from_bytes(name),
            http::HeaderValue::from_bytes(value),
        ) {
            req.headers_mut().append(n, v);
        }
    }
    let (parts, ()) = req.into_parts();
    let flags = roxy_fuzz::flags(input.cfg);
    let limits = Limits {
        max_headers: 32,
        h2_max_header_list_bytes: 4096,
        ..Limits::default()
    };
    let Ok(canon) = from_h2_parts(parts, Body::empty(), &expected, &limits, &flags) else {
        return;
    };
    assert_eq!(canon.authority, expected);
    assert_eq!(
        normalize_path(canon.path.as_str().as_bytes()).unwrap(),
        canon.path
    );
    for (name, _) in &canon.headers {
        assert!(!is_reserved(name.as_str()), "reserved field {name} kept");
    }
});
