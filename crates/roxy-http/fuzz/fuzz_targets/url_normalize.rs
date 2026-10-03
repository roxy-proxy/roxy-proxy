//! Fuzzes the URL normaliser: never panics, and normalisation is
//! idempotent for paths, queries and absolute-form targets.
#![no_main]

use libfuzzer_sys::fuzz_target;
use roxy_http::url::{
    normalize_path, normalize_query, parse_absolute_form, parse_authority, parse_origin_form,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = normalize_path(data) {
        assert!(p.as_str().starts_with('/'));
        assert_eq!(normalize_path(p.as_str().as_bytes()).unwrap(), p);
        for seg in p.as_str().split('/') {
            assert!(seg != "." && seg != "..");
        }
    }
    if let Ok(q) = normalize_query(data) {
        assert_eq!(normalize_query(q.as_str().as_bytes()).unwrap(), q);
        for _ in q.pairs() {}
    }
    if let Ok((p, q)) = parse_origin_form(data) {
        let again = match &q {
            Some(q) => format!("{p}?{q}"),
            None => p.to_string(),
        };
        assert_eq!(parse_origin_form(again.as_bytes()).unwrap(), (p, q));
    }
    if let Ok((scheme, auth, p, q)) = parse_absolute_form(data) {
        let again = format!(
            "{}://{}{}{}",
            scheme,
            auth,
            p,
            q.as_ref().map(|q| format!("?{q}")).unwrap_or_default()
        );
        assert_eq!(
            parse_absolute_form(again.as_bytes()).unwrap(),
            (scheme, auth, p, q)
        );
    }
    if let Ok(a) = parse_authority(data, 443) {
        assert_eq!(parse_authority(a.to_string().as_bytes(), 443).unwrap(), a);
    }
});
