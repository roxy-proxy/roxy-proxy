//! Fuzzes the chunked decoder: never panics, never emits more bytes than it
//! was given, and decoding is independent of how the input is split.
#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use roxy_http::h1::{ChunkedDecoder, Decoded};
use roxy_http::{HttpFlags, Limits};

fn run(input: &[u8], piece: usize, flags: &HttpFlags) -> Result<Vec<u8>, String> {
    let limits = Limits {
        max_request_body_bytes: 1 << 20,
        max_header_bytes: 4096,
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
    let piece = usize::from(cfg >> 2) + 1;
    let a = run(input, input.len().max(1), &flags);
    let b = run(input, piece, &flags);
    if let Ok(out) = &a {
        assert!(out.len() <= input.len());
    }
    // Byte-at-a-time and one-shot decoding agree on success.
    if let (Ok(x), Ok(y)) = (&a, &b) {
        assert_eq!(x, y);
    }
    assert_eq!(a.is_ok(), b.is_ok());
});
