//! The DNS listener's codec (`roxy-dns`).
//!
//! Invariants:
//! - `parse` never panics;
//! - every message roxy builds (an answer to an accepted query, or an error
//!   reply) fits in 512 bytes, carries the query's id, and is a response:
//!   `parse` drops it, so roxy never answers its own answers;
//! - an accepted query's name is non-empty, lower-case, and made of
//!   letters, digits, `-`, `_` and `.` only, and its answer echoes the
//!   question bytes exactly as sent.
#![no_main]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use libfuzzer_sys::fuzz_target;
use roxy_dns::{MAX_UDP_PAYLOAD, Parsed, answer, error, parse};

const ADDRS: [IpAddr; 2] = [
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
    IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
];

fuzz_target!(|data: &[u8]| {
    let (reply, id) = match parse(data) {
        Parsed::Drop => return,
        Parsed::Query(q) => {
            assert!(!q.name.is_empty());
            assert!(q.name.bytes().all(|b| b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(b, b'-' | b'_' | b'.')));
            let reply = answer(&q, &ADDRS, 60);
            let question = q.question();
            assert_eq!(&reply[12..12 + question.len()], question);
            assert_eq!(&data[12..12 + question.len()], question);
            (reply, q.id)
        }
        Parsed::Error { id, opcode, rd, rcode } => (error(id, opcode, rd, rcode), id),
    };
    assert!(reply.len() <= MAX_UDP_PAYLOAD);
    assert_eq!(reply[..2], id.to_be_bytes());
    assert_eq!(parse(&reply), Parsed::Drop);
});
