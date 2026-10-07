//! ClientHello sniffing (`roxy-tls::sniff`).
//!
//! Invariants:
//! - `sniff` never panics;
//! - reading more never changes a verdict: over the prefixes of an input
//!   the results are `NeedMore` until some length, then one constant answer
//!   (`NotTls`, or the same `Tls(info)`) for every longer prefix. So a
//!   hello is never accepted or rejected early and then re-judged, and
//!   bytes after the hello never affect it;
//! - an accepted SNI is printable ASCII of bounded length, as sent: the
//!   sniffer does no host canonicalisation (that is `parse_host`'s).
#![no_main]

use libfuzzer_sys::fuzz_target;
use roxy_tls::{MAX_HELLO_BYTES, Sniff, sniff};

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_HELLO_BYTES + 64)];
    let mut verdict: Option<(usize, Sniff)> = None;
    // Every prefix up to 512 bytes, then a stride (each `sniff` is linear,
    // so checking every prefix of a 16 KiB hello would be quadratic).
    let lens = (0..=data.len().min(512))
        .chain((512..=data.len()).step_by(61))
        .chain([data.len()]);
    for len in lens {
        let got = sniff(&data[..len]);
        match (&verdict, got) {
            (None, Sniff::NeedMore) => {}
            (None, other) => verdict = Some((len, other)),
            (Some((at, first)), other) => {
                assert_eq!(
                    first, &other,
                    "verdict at {len} bytes differs from the one reached at {at}"
                );
            }
        }
    }
    if let Some((_, Sniff::Tls(info))) = &verdict
        && let Some(sni) = &info.sni
    {
        assert!(!sni.is_empty() && sni.len() <= 253, "{sni:?}");
        assert!(sni.bytes().all(|b| (0x21..=0x7e).contains(&b)), "{sni:?}");
    }
});
