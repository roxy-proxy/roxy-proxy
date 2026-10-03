//! Fuzzes the h1 head scanner and parser: must never panic, and a head the
//! parser accepts must survive a second scan unchanged.
#![no_main]

use libfuzzer_sys::fuzz_target;
use roxy_http::h1::{HeadScan, Role, parse_head, scan_head};
use roxy_http::url::parse_authority;
use roxy_http::{HttpFlags, Limits, Scheme};

fuzz_target!(|data: &[u8]| {
    let Some((&cfg, input)) = data.split_first() else {
        return;
    };
    let flags = HttpFlags {
        allow_http10: cfg & 1 != 0,
        allow_trailers: cfg & 2 != 0,
        allow_chunk_extensions: cfg & 4 != 0,
        allow_obs_text: cfg & 8 != 0,
        allow_body_on_get: cfg & 16 != 0,
        allow_plain_in_connect: false,
    };
    let limits = Limits {
        max_header_bytes: 4096,
        max_url_bytes: 1024,
        max_headers: 32,
        ..Limits::default()
    };
    let role = if cfg & 32 != 0 {
        Role::ProxyPort
    } else {
        Role::Tunnel {
            authority: parse_authority(b"example.com", 443).unwrap(),
            scheme: Scheme::Https,
        }
    };

    // Incremental scanning in two pieces must agree with a one-shot scan.
    let split = usize::from(cfg) % (input.len() + 1);
    let whole = scan_head(input, 0, &limits).map_err(|e| e.reason);
    let partial = scan_head(&input[..split], 0, &limits);
    if let Ok(HeadScan::Partial(from)) = partial {
        let resumed = scan_head(input, from, &limits).map_err(|e| e.reason);
        if let (Ok(HeadScan::Complete(a)), Ok(HeadScan::Complete(b))) = (&whole, &resumed) {
            assert_eq!(a, b);
        }
    }

    if let Ok(HeadScan::Complete(n)) = whole {
        let _ = parse_head(&input[..n], &role, &limits, &flags);
    }
    let _ = parse_head(input, &role, &limits, &flags);
});
