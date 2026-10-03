//! The WebSocket frame decoder (`roxy-http` `ws::frame::Decoder`).
//!
//! Input: one config byte (bit 0: client or server frames; bits 1-3: a
//! piece size; bits 4-5: the message size limit), then the raw frames.
//!
//! Invariants:
//! - decoding never panics;
//! - the result does not depend on how the bytes are split into reads:
//!   all at once and in small pieces give the same messages and the same
//!   error;
//! - no data message is over the limit and no control message over 125
//!   bytes;
//! - re-encoding is a fixed point: the decoded messages, encoded as roxy
//!   relays them, decode to the same messages without error.
#![no_main]

use libfuzzer_sys::fuzz_target;
use roxy_http::ws::frame::{Decoder, FrameError, Message, Opcode, Peer, encode};

const LIMITS: [u64; 4] = [16, 125, 4096, 1 << 20];

fn decode(from: Peer, max: u64, input: &[u8], piece: usize) -> (Vec<Message>, Option<FrameError>) {
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

fuzz_target!(|data: &[u8]| {
    let Some((&cfg, input)) = data.split_first() else {
        return;
    };
    let from = if cfg & 1 == 0 { Peer::Client } else { Peer::Server };
    let piece = usize::from((cfg >> 1) & 7) + 1;
    let max = LIMITS[usize::from((cfg >> 4) & 3)];
    let whole = decode(from, max, input, input.len().max(1));
    let pieces = decode(from, max, input, piece);
    assert_eq!(whole, pieces, "split-dependent decode");
    for m in &whole.0 {
        match m.opcode {
            Opcode::Text | Opcode::Binary => assert!(m.len() as u64 <= max),
            Opcode::Close | Opcode::Ping | Opcode::Pong => assert!(m.len() <= 125),
        }
    }
    let mask = (from == Peer::Client).then_some([0xa5, 0x01, 0x7f, 0xc3]);
    let mut again = Vec::new();
    for m in &whole.0 {
        encode(m.opcode, m.payload(), mask, &mut again);
    }
    let (round, err) = decode(from, max, &again, again.len().max(1));
    assert_eq!(err, None, "re-encoded messages failed to decode");
    assert_eq!(round, whole.0, "re-encoding is not a fixed point");
});
