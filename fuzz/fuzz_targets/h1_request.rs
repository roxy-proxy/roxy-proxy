//! The strict HTTP/1.1 request-head parser (`roxy-http` `h1`).
//!
//! Input: one config byte (parser flags and role, see `roxy_fuzz::flags` /
//! `roxy_fuzz::role`), then the raw bytes.
//!
//! Invariants:
//! - `scan_head` / `parse_head` never panic;
//! - scanning is resumable: a scan resumed from a partial scan's offset
//!   finds the same end of head as one scan over everything;
//! - the canonical form is a fixed point: a parsed head, serialised again
//!   (`roxy_fuzz::serialise`), parses to a head that serialises to the very
//!   same bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use roxy_http::h1::{HeadScan, parse_head, scan_head};

fuzz_target!(|data: &[u8]| {
    let Some((&cfg, input)) = data.split_first() else {
        return;
    };
    let flags = roxy_fuzz::flags(cfg);
    let role = roxy_fuzz::role(cfg);
    let limits = roxy_fuzz::tight_limits();

    let whole = scan_head(input, 0, &limits).map_err(|e| e.reason);
    let split = usize::from(cfg) * input.len() / 256;
    if let Ok(HeadScan::Partial(from)) = scan_head(&input[..split], 0, &limits) {
        let resumed = scan_head(input, from, &limits).map_err(|e| e.reason);
        if let (Ok(HeadScan::Complete(a)), Ok(HeadScan::Complete(b))) = (&whole, &resumed) {
            assert_eq!(a, b, "resumed scan disagrees");
        }
    }
    // The whole input as a head (usually rejected: not CRLF CRLF terminated).
    let _ = parse_head(input, &role, &limits, &flags);

    let Ok(HeadScan::Complete(n)) = whole else {
        return;
    };
    let Ok(head) = parse_head(&input[..n], &role, &limits, &flags) else {
        return;
    };
    let roomy = roxy_fuzz::roomy_limits();
    let once = roxy_fuzz::serialise(&head);
    let again = parse_head(&once, &role, &roomy, &flags).unwrap_or_else(|e| {
        panic!(
            "canonical head rejected ({:?}: {}):\n{}",
            e.reason,
            e.detail,
            String::from_utf8_lossy(&once)
        )
    });
    let twice = roxy_fuzz::serialise(&again);
    assert_eq!(
        String::from_utf8_lossy(&once),
        String::from_utf8_lossy(&twice),
        "canonical form is not a fixed point"
    );
});
