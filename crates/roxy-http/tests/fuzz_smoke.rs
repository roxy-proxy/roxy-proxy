//! Stable-toolchain smoke version of the `fuzz/` targets: the same
//! invariants, driven by proptest over an HTTP-flavoured byte alphabet.

use bytes::BytesMut;
use proptest::prelude::*;
use roxy_http::h1::{ChunkedDecoder, Decoded, HeadScan, Role, parse_head, scan_head};
use roxy_http::url::{
    normalize_path, normalize_query, parse_absolute_form, parse_authority, parse_origin_form,
};
use roxy_http::{HttpFlags, Limits, Scheme};

const TOKENS: &[&str] = &[
    "GET ",
    "POST ",
    "CONNECT ",
    "http://",
    "https://",
    "example.com",
    ":443",
    "/",
    "/a",
    "%2e",
    "%2F",
    "%",
    "..",
    ".",
    "?",
    "#",
    "&",
    "=",
    "[",
    "]",
    "@",
    " ",
    "\t",
    "\r\n",
    "\r",
    "\n",
    "HTTP/1.1",
    "HTTP/1.0",
    "Host: ",
    "host: example.com",
    "Content-Length: ",
    "Transfer-Encoding: ",
    "chunked",
    "Connection: close",
    "Expect: 100-continue",
    "0",
    "5",
    "f",
    "x",
    ";",
    ":",
    "\0",
    "\u{e9}",
    "\r\n\r\n",
];

fn http_bytes() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(
        prop_oneof![
            4 => proptest::sample::select(TOKENS).prop_map(|t| t.as_bytes().to_vec()),
            1 => proptest::collection::vec(any::<u8>(), 1..4),
        ],
        0..40,
    )
    .prop_map(|parts| parts.concat())
}

fn decode_chunked(input: &[u8], piece: usize, flags: &HttpFlags) -> Result<Vec<u8>, String> {
    let limits = Limits {
        max_request_body_bytes: 1 << 20,
        max_header_bytes: 256,
        ..Limits::default()
    };
    let mut d = ChunkedDecoder::new(&limits, flags);
    let mut buf = BytesMut::new();
    let mut out = Vec::new();
    let mut fed = 0;
    loop {
        match d
            .decode(&mut buf)
            .map_err(|e| e.reason.as_str().to_owned())?
        {
            Decoded::Data(b) => out.extend_from_slice(&b),
            Decoded::Trailers(_) => {}
            Decoded::Done => return Ok(out),
            Decoded::NeedMore => {
                if fed == input.len() {
                    return Err("eof".into());
                }
                let end = (fed + piece).min(input.len());
                buf.extend_from_slice(&input[fed..end]);
                fed = end;
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3000))]

    #[test]
    fn head_parser_never_panics(input in http_bytes(), cfg in any::<u8>()) {
        let flags = HttpFlags {
            allow_http10: cfg & 1 != 0,
            allow_trailers: cfg & 2 != 0,
            allow_chunk_extensions: cfg & 4 != 0,
            allow_obs_text: cfg & 8 != 0,
            allow_body_on_get: cfg & 16 != 0,
            allow_plain_in_connect: false,
            strip_accept_encoding: false,
            decode_for_addons: true,
        };
        let limits = Limits { max_header_bytes: 512, max_url_bytes: 128, max_headers: 8, ..Limits::default() };
        let role = if cfg & 32 != 0 {
            Role::ProxyPort
        } else {
            Role::Tunnel { authority: parse_authority(b"example.com", 443).unwrap(), scheme: Scheme::Https }
        };
        let split = usize::from(cfg) % (input.len() + 1);
        let whole = scan_head(&input, 0, &limits).map_err(|e| e.reason);
        if let Ok(HeadScan::Partial(from)) = scan_head(&input[..split], 0, &limits) {
            let resumed = scan_head(&input, from, &limits).map_err(|e| e.reason);
            if let (Ok(HeadScan::Complete(a)), Ok(HeadScan::Complete(b))) = (&whole, &resumed) {
                prop_assert_eq!(a, b);
            }
        }
        if let Ok(HeadScan::Complete(n)) = whole {
            let _ = parse_head(&input[..n], &role, &limits, &flags);
        }
        let _ = parse_head(&input, &role, &limits, &flags);
    }

    #[test]
    fn chunked_split_independent(input in http_bytes(), cfg in any::<u8>()) {
        let flags = HttpFlags {
            allow_trailers: cfg & 1 != 0,
            allow_chunk_extensions: cfg & 2 != 0,
            ..HttpFlags::default()
        };
        let a = decode_chunked(&input, input.len().max(1), &flags);
        let b = decode_chunked(&input, usize::from(cfg >> 2) % 7 + 1, &flags);
        prop_assert_eq!(a.is_ok(), b.is_ok(), "{:?} vs {:?}", a, b);
        if let (Ok(x), Ok(y)) = (&a, &b) {
            prop_assert_eq!(x, y);
            prop_assert!(x.len() <= input.len());
        }
    }

    #[test]
    fn url_round_trips(input in http_bytes()) {
        if let Ok(p) = normalize_path(&input) {
            prop_assert_eq!(normalize_path(p.as_str().as_bytes()).unwrap(), p);
        }
        if let Ok(q) = normalize_query(&input) {
            prop_assert_eq!(normalize_query(q.as_str().as_bytes()).unwrap(), q);
        }
        if let Ok((p, q)) = parse_origin_form(&input) {
            let again = match &q { Some(q) => format!("{p}?{q}"), None => p.to_string() };
            prop_assert_eq!(parse_origin_form(again.as_bytes()).unwrap(), (p, q));
        }
        if let Ok((scheme, auth, p, q)) = parse_absolute_form(&input) {
            let again = format!("{scheme}://{auth}{p}{}", q.as_ref().map(|q| format!("?{q}")).unwrap_or_default());
            prop_assert_eq!(parse_absolute_form(again.as_bytes()).unwrap(), (scheme, auth, p, q));
        }
        if let Ok(a) = parse_authority(&input, 443) {
            prop_assert_eq!(parse_authority(a.to_string().as_bytes(), 443).unwrap(), a);
        }
    }
}
