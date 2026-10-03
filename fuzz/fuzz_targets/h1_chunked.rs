//! The chunked transfer-coding decoder (`roxy-http` `h1::ChunkedDecoder`).
//!
//! Input: one config byte (trailers / extensions flags and a piece size),
//! then the raw body bytes.
//!
//! Invariants:
//! - decoding never panics;
//! - the result does not depend on how the bytes are split into reads:
//!   all at once and in small pieces give the same data or both fail;
//! - the decoded data is never longer than the encoded input.
#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use roxy_http::h1::{ChunkedDecoder, Decoded};
use roxy_http::{HttpFlags, Limits};

fn decode(input: &[u8], piece: usize, flags: &HttpFlags) -> Result<Vec<u8>, String> {
    let limits = Limits {
        max_request_body_bytes: 1 << 20,
        max_header_bytes: 1024,
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

fuzz_target!(|data: &[u8]| {
    let Some((&cfg, input)) = data.split_first() else {
        return;
    };
    let flags = HttpFlags {
        allow_trailers: cfg & 1 != 0,
        allow_chunk_extensions: cfg & 2 != 0,
        ..HttpFlags::default()
    };
    let whole = decode(input, input.len().max(1), &flags);
    let pieces = decode(input, usize::from(cfg >> 2) % 7 + 1, &flags);
    assert_eq!(whole.is_ok(), pieces.is_ok(), "{whole:?} vs {pieces:?}");
    if let (Ok(a), Ok(b)) = (&whole, &pieces) {
        assert_eq!(a, b, "split-dependent decode");
        assert!(a.len() <= input.len());
    }
});
