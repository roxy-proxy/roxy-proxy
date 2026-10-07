//! The content-coding decoders (`roxy-http` `coding::Decoder`).
//!
//! Input: one config byte, then the encoded body. Bits 0–1 pick a coding
//! (gzip, deflate, br, zstd); with bit 2 set, bits 3–4 pick a second coding
//! applied on top. Bits 5–7 set the piece size.
//!
//! Invariants:
//! - decoding never panics;
//! - the result does not depend on how the input is fed or how the output
//!   is read: all at once and in small pieces give the same data or both
//!   fail;
//! - the limit holds: a body that decodes to `n` bytes is refused under a
//!   limit of `n - 1`, and never yields more than its limit.
#![no_main]

use libfuzzer_sys::fuzz_target;
use roxy_http::coding::{self, Coding, DecodeError, Decoder};

const CODINGS: [Coding; 4] = [Coding::Gzip, Coding::Deflate, Coding::Br, Coding::Zstd];

/// Room for any honest small input; a bomb stops here.
const LIMIT: u64 = 4 << 20;

fn decode(
    codings: &[Coding],
    input: &[u8],
    piece: usize,
    limit: u64,
) -> Result<Vec<u8>, DecodeError> {
    let mut d = Decoder::new(codings, limit, coding::unmetered());
    let mut out = Vec::new();
    let mut buf = vec![0u8; piece];
    let mut drain = |d: &mut Decoder, out: &mut Vec<u8>| -> Result<(), DecodeError> {
        loop {
            let n = d.read(&mut buf)?;
            assert!(n <= piece);
            if n == 0 {
                return Ok(());
            }
            out.extend_from_slice(&buf[..n]);
            assert!(out.len() as u64 <= limit, "read past the limit");
        }
    };
    for p in input.chunks(piece) {
        d.feed(p);
        drain(&mut d, &mut out)?;
    }
    d.finish();
    drain(&mut d, &mut out)?;
    Ok(out)
}

fuzz_target!(|data: &[u8]| {
    let Some((&cfg, input)) = data.split_first() else {
        return;
    };
    let mut codings = vec![CODINGS[usize::from(cfg & 3)]];
    if cfg & 4 != 0 {
        codings.push(CODINGS[usize::from((cfg >> 3) & 3)]);
    }
    let piece = usize::from(cfg >> 5) * 37 + 1;
    let whole = decode(&codings, input, 1 << 16, LIMIT);
    let pieces = decode(&codings, input, piece, LIMIT);
    match (&whole, &pieces) {
        (Ok(a), Ok(b)) => assert_eq!(a, b, "split-dependent decode"),
        (Err(_), Err(_)) => {}
        _ => panic!("split-dependent result: {whole:?} vs {pieces:?}"),
    }
    if let Ok(a) = &whole
        && !a.is_empty()
    {
        let limit = a.len() as u64 - 1;
        assert_eq!(
            decode(&codings, input, piece, limit),
            Err(DecodeError::TooLarge { limit })
        );
    }
});
