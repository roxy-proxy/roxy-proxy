//! Stable-toolchain smoke version of the `fuzz/` targets: the same
//! invariants, driven by proptest over an HTTP-flavoured byte alphabet (and,
//! for the WebSocket decoder, frame-shaped bytes).

use bytes::BytesMut;
use proptest::prelude::*;
use roxy_http::coding::{self, Coding, DecodeError};
use roxy_http::h1::{ChunkedDecoder, Decoded, HeadScan, Role, parse_head, scan_head};
use roxy_http::url::{
    normalize_path, normalize_query, parse_absolute_form, parse_authority, parse_origin_form,
};
use roxy_http::ws::frame::{Decoder, FrameError, Message, Opcode, Peer, encode};
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
        let role = match (cfg >> 5) & 3 {
            0 | 1 => Role::ProxyPort,
            2 => Role::Direct { port: 80 },
            _ => Role::Tunnel { authority: parse_authority(b"example.com", 443).unwrap(), scheme: Scheme::Https },
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

const CODINGS: [Coding; 4] = [Coding::Gzip, Coding::Deflate, Coding::Br, Coding::Zstd];

fn compress(c: Coding, b: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    match c {
        Coding::Gzip => {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            e.write_all(b).unwrap();
            e.finish().unwrap()
        }
        Coding::Deflate => {
            let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
            e.write_all(b).unwrap();
            e.finish().unwrap()
        }
        Coding::Br => {
            let mut out = Vec::new();
            let params = brotli::enc::BrotliEncoderParams::default();
            brotli::BrotliCompress(&mut &b[..], &mut out, &params).unwrap();
            out
        }
        Coding::Zstd => {
            ruzstd::encoding::compress_to_vec(b, ruzstd::encoding::CompressionLevel::Fastest)
        }
    }
}

fn decode_pieces(c: Coding, input: &[u8], piece: usize) -> Result<Vec<u8>, DecodeError> {
    let mut d = coding::Decoder::new(&[c], 1 << 20);
    let mut out = Vec::new();
    let mut buf = vec![0u8; piece];
    for p in input.chunks(piece) {
        d.feed(p);
        loop {
            let n = d.read(&mut buf)?;
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
    }
    d.finish();
    loop {
        let n = d.read(&mut buf)?;
        if n == 0 {
            return Ok(out);
        }
        out.extend_from_slice(&buf[..n]);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// The `content_coding` fuzz target's invariant on mutated valid
    /// streams: the result does not depend on how input is fed or output
    /// read, and a stream that decodes is the text that was encoded.
    #[test]
    fn content_coding_split_independent(
        text in http_bytes(),
        c in 0..4usize,
        flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 0..3),
        piece in 1..50usize,
    ) {
        let c = CODINGS[c];
        let mut enc = compress(c, &text);
        for (at, x) in &flips {
            let i = at % enc.len();
            enc[i] ^= x;
        }
        let whole = coding::decode(&[c], &enc, 1 << 20);
        let pieces = decode_pieces(c, &enc, piece);
        prop_assert_eq!(whole.is_ok(), pieces.is_ok(), "{:?} vs {:?}", whole, pieces);
        if let (Ok(a), Ok(b)) = (&whole, &pieces) {
            prop_assert_eq!(a, b);
            if flips.iter().all(|(_, x)| *x == 0) {
                prop_assert_eq!(a, &text);
            }
        }
    }
}

/// Frame-shaped bytes for the `ws_frame` target: frames with random
/// headers (any FIN, opcode and mask bit, some RSV bits), short payloads,
/// and an optional junk tail.
fn ws_bytes() -> impl Strategy<Value = Vec<u8>> {
    let frame = (
        any::<u8>(),
        any::<bool>(),
        proptest::collection::vec(any::<u8>(), 0..200),
    );
    (
        proptest::collection::vec(frame, 0..8),
        proptest::collection::vec(any::<u8>(), 0..4),
    )
        .prop_map(|(frames, tail)| {
            let mut out = Vec::new();
            for (head, masked, payload) in frames {
                let opcode = [0u8, 1, 2, 8, 9, 10, 3][usize::from(head % 7)];
                let rsv = if head & 0xe0 == 0xe0 { 0x40 } else { 0 };
                let mask = masked.then_some([head, 0x5a, 0x01, 0xff]);
                let mut f = Vec::new();
                encode(Opcode::Binary, &payload, mask, &mut f);
                f[0] = (head & 0x80) | rsv | opcode;
                out.extend(f);
            }
            out.extend(tail);
            out
        })
}

fn decode_ws(
    from: Peer,
    max: u64,
    input: &[u8],
    piece: usize,
) -> (Vec<Message>, Option<FrameError>) {
    let mut d = Decoder::new(from, max);
    let mut out = Vec::new();
    for mut chunk in input.chunks(piece) {
        loop {
            match d.decode(&mut chunk) {
                Ok(Some(m)) => out.push(m),
                Ok(None) => break,
                Err(e) => return (out, Some(e)),
            }
        }
    }
    (out, None)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3000))]

    #[test]
    fn ws_frames_split_independent_and_re_encodable(input in ws_bytes(), cfg in any::<u8>()) {
        let from = if cfg & 1 == 0 { Peer::Client } else { Peer::Server };
        let max = [16, 125, 4096, 1 << 20][usize::from((cfg >> 4) & 3)];
        let whole = decode_ws(from, max, &input, input.len().max(1));
        let pieces = decode_ws(from, max, &input, usize::from((cfg >> 1) & 7) + 1);
        prop_assert_eq!(&whole, &pieces);
        let mask = (from == Peer::Client).then_some([0xa5, 0x01, 0x7f, 0xc3]);
        let mut again = Vec::new();
        for m in &whole.0 {
            encode(m.opcode, m.payload(), mask, &mut again);
        }
        let (round, err) = decode_ws(from, max, &again, again.len().max(1));
        prop_assert_eq!(err, None);
        prop_assert_eq!(round, whole.0);
    }
}
