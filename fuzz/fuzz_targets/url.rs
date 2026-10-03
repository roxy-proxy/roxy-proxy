//! URL, path and query normalisation (`roxy-http::url`).
//!
//! Invariants:
//! - nothing panics;
//! - normalisation is idempotent: a normalised path / query / origin-form /
//!   absolute-form / authority, written out and parsed again, is unchanged;
//! - a normalised path starts with `/` and has no `.` or `..` segment
//!   (decoded or not), so it can never climb above the root.
#![no_main]

use libfuzzer_sys::fuzz_target;
use roxy_http::url::{
    normalize_path, normalize_query, parse_absolute_form, parse_authority, parse_origin_form,
};

fn assert_no_dot_segments(path: &str) {
    assert!(path.starts_with('/'), "path {path:?} does not start with /");
    for seg in path.split('/') {
        let lower = seg.to_ascii_lowercase();
        let decoded = lower.replace("%2e", ".");
        assert!(
            decoded != "." && decoded != "..",
            "path {path:?} keeps a dot segment {seg:?}"
        );
    }
}

fuzz_target!(|input: &[u8]| {
    if let Ok(p) = normalize_path(input) {
        assert_no_dot_segments(p.as_str());
        assert_eq!(normalize_path(p.as_str().as_bytes()).unwrap(), p);
    }
    if let Ok(q) = normalize_query(input) {
        assert_eq!(normalize_query(q.as_str().as_bytes()).unwrap(), q);
    }
    if let Ok((p, q)) = parse_origin_form(input) {
        assert_no_dot_segments(p.as_str());
        let again = match &q {
            Some(q) => format!("{p}?{q}"),
            None => p.to_string(),
        };
        assert_eq!(parse_origin_form(again.as_bytes()).unwrap(), (p, q));
    }
    if let Ok((scheme, auth, p, q)) = parse_absolute_form(input) {
        assert_no_dot_segments(p.as_str());
        let again = format!(
            "{scheme}://{auth}{p}{}",
            q.as_ref().map(|q| format!("?{q}")).unwrap_or_default()
        );
        assert_eq!(
            parse_absolute_form(again.as_bytes()).unwrap(),
            (scheme, auth, p, q)
        );
    }
    for default_port in [80, 443] {
        if let Ok(a) = parse_authority(input, default_port) {
            assert_eq!(
                parse_authority(a.to_string().as_bytes(), default_port).unwrap(),
                a
            );
        }
    }
});
