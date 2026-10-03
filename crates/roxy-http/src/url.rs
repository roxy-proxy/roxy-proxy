//! URL normalisation (`DESIGN.md` §5.4).
//!
//! The output of these functions is used both for rule matching and for what
//! is forwarded, so the upstream sees exactly what the rules matched.

use std::borrow::Cow;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::chars::{hex_upper, hex_val, is_pchar_literal, is_unreserved};
use crate::model::{Authority, Host, ParseError, Reason, Scheme, reject};

/// Longest DNS name accepted (RFC 1035).
const MAX_DNS_NAME: usize = 253;
/// Longest DNS label accepted (RFC 1035).
const MAX_DNS_LABEL: usize = 63;

/// A normalised request path. Only produced by [`normalize_path`] (or the
/// equivalent `TryFrom`), so holding one means it is canonical: starts with
/// `/`, contains only `pchar` / `/`, upper-case percent-encodings of
/// non-unreserved bytes only, and no dot segments.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Path(String);

impl Path {
    /// The canonical path.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The root path `/`.
    pub fn root() -> Path {
        Path("/".to_owned())
    }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<&str> for Path {
    type Error = ParseError;
    /// Normalises `s` (so the result may differ from the input).
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        normalize_path(s.as_bytes())
    }
}

/// A validated query string (without the leading `?`). The raw form is what
/// is forwarded; [`Query::pairs`] is for matching only.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Query(String);

impl Query {
    /// The canonical raw query (percent-encodings upper-cased, otherwise
    /// untouched).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Decoded `(key, value)` pairs for rule matching. Pairs are split on `&`,
    /// key and value on the first `=`; `+` decodes to space and
    /// percent-encodings are decoded (invalid UTF-8 is replaced with U+FFFD).
    /// Empty pairs are skipped; a pair without `=` has an empty value.
    pub fn pairs(&self) -> impl Iterator<Item = (Cow<'_, str>, Cow<'_, str>)> {
        self.0.split('&').filter(|p| !p.is_empty()).map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (decode_form(k), decode_form(v))
        })
    }

    /// First decoded value for `key`.
    pub fn get(&self, key: &str) -> Option<String> {
        self.pairs()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.into_owned())
    }
}

impl fmt::Display for Query {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<&str> for Query {
    type Error = ParseError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        normalize_query(s.as_bytes())
    }
}

fn decode_form(s: &str) -> Cow<'_, str> {
    if !s.bytes().any(|b| b == b'%' || b == b'+') {
        return Cow::Borrowed(s);
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' => {
                // Encodings were validated at construction.
                match (
                    bytes.get(i + 1).copied().and_then(hex_val),
                    bytes.get(i + 2).copied().and_then(hex_val),
                ) {
                    (Some(hi), Some(lo)) => {
                        out.push(hi << 4 | lo);
                        i += 2;
                    }
                    _ => out.push(b'%'),
                }
            }
            other => out.push(other),
        }
        i += 1;
    }
    Cow::Owned(String::from_utf8_lossy(&out).into_owned())
}

/// Validates percent-encodings and literal characters, decoding encoded
/// unreserved bytes when `decode_unreserved`, upper-casing the rest.
fn canonicalize_encodings(
    raw: &[u8],
    allowed: impl Fn(u8) -> bool,
    invalid: Reason,
    decode_unreserved: bool,
) -> Result<String, ParseError> {
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        let byte = raw[i];
        if byte == b'%' {
            let (Some(hi), Some(lo)) = (
                raw.get(i + 1).copied().and_then(hex_val),
                raw.get(i + 2).copied().and_then(hex_val),
            ) else {
                return reject(
                    Reason::BadPercentEncoding,
                    format!("bad percent-encoding at offset {i}"),
                );
            };
            let val = hi << 4 | lo;
            if decode_unreserved && is_unreserved(val) {
                out.push(char::from(val));
            } else {
                out.push('%');
                out.push(char::from(hex_upper(hi)));
                out.push(char::from(hex_upper(lo)));
            }
            i += 3;
            continue;
        }
        if byte == b'#' {
            return reject(Reason::FragmentInTarget, "fragment in request target");
        }
        if byte >= 0x80 {
            return reject(Reason::NonAscii, format!("non-ASCII byte at offset {i}"));
        }
        if !allowed(byte) {
            return reject(
                invalid,
                format!("byte 0x{byte:02x} not allowed at offset {i}"),
            );
        }
        out.push(char::from(byte));
        i += 1;
    }
    Ok(out)
}

/// Normalises a request path per §5.4 steps 1-5.
pub fn normalize_path(raw: &[u8]) -> Result<Path, ParseError> {
    if raw.is_empty() {
        return Ok(Path::root());
    }
    if raw[0] != b'/' {
        if raw.contains(&b'#') {
            return reject(Reason::FragmentInTarget, "fragment in request target");
        }
        return reject(Reason::InvalidPath, "path does not start with '/'");
    }
    let decoded = canonicalize_encodings(
        raw,
        |b| b == b'/' || is_pchar_literal(b),
        Reason::InvalidPath,
        true,
    )?;
    remove_dot_segments(&decoded).map(Path)
}

/// RFC 3986 §5.2.4 on an absolute path, rejecting climbs above the root.
fn remove_dot_segments(path: &str) -> Result<String, ParseError> {
    debug_assert!(path.starts_with('/'));
    let segments: Vec<&str> = path[1..].split('/').collect();
    let last = segments.len() - 1;
    let mut out: Vec<&str> = Vec::with_capacity(segments.len());
    for (i, seg) in segments.iter().enumerate() {
        match *seg {
            "." => {}
            ".." => {
                if out.pop().is_none() {
                    return reject(
                        Reason::PathClimbsAboveRoot,
                        "dot segments climb above the root",
                    );
                }
            }
            s => {
                out.push(s);
                continue;
            }
        }
        if i == last {
            // A trailing dot segment leaves a trailing slash.
            out.push("");
        }
    }
    let mut s = String::with_capacity(path.len());
    s.push('/');
    s.push_str(&out.join("/"));
    Ok(s)
}

/// Validates a query (without the leading `?`) per §5.4 step 6.
///
/// Allowed literals are `pchar`, `/`, `?`, plus `[` and `]`: Python
/// `requests` (and others) send brackets unencoded in queries, and rejecting
/// them would trip well-behaved clients (§2). They are forwarded untouched.
pub fn normalize_query(raw: &[u8]) -> Result<Query, ParseError> {
    canonicalize_encodings(
        raw,
        |b| matches!(b, b'/' | b'?' | b'[' | b']') || is_pchar_literal(b),
        Reason::InvalidQuery,
        false,
    )
    .map(Query)
}

/// Splits `path[?query]` and normalises both. An empty query (`/a?`) is
/// dropped.
pub fn parse_origin_form(raw: &[u8]) -> Result<(Path, Option<Query>), ParseError> {
    if raw.contains(&b'#') {
        return reject(Reason::FragmentInTarget, "fragment in request target");
    }
    if raw.first() != Some(&b'/') {
        return reject(Reason::BadRequestTarget, "origin-form must start with '/'");
    }
    let (p, q) = match raw.iter().position(|&b| b == b'?') {
        Some(i) => (&raw[..i], Some(&raw[i + 1..])),
        None => (raw, None),
    };
    let path = normalize_path(p)?;
    let query = match q {
        Some(q) if !q.is_empty() => Some(normalize_query(q)?),
        _ => None,
    };
    Ok((path, query))
}

/// Parses an absolute-form target `scheme://authority[/path][?query]`.
pub fn parse_absolute_form(
    raw: &[u8],
) -> Result<(Scheme, Authority, Path, Option<Query>), ParseError> {
    if raw.contains(&b'#') {
        return reject(Reason::FragmentInTarget, "fragment in request target");
    }
    let (scheme, rest) = if let Some(r) = strip_prefix_ci(raw, b"http://") {
        (Scheme::Http, r)
    } else if let Some(r) = strip_prefix_ci(raw, b"https://") {
        (Scheme::Https, r)
    } else {
        return reject(
            Reason::BadRequestTarget,
            "absolute-form target must be http:// or https://",
        );
    };
    let auth_end = rest
        .iter()
        .position(|&b| b == b'/' || b == b'?')
        .unwrap_or(rest.len());
    let authority = parse_authority(&rest[..auth_end], scheme.default_port())?;
    let tail = &rest[auth_end..];
    let (path, query) = if tail.first() == Some(&b'?') {
        let q = &tail[1..];
        (
            Path::root(),
            if q.is_empty() {
                None
            } else {
                Some(normalize_query(q)?)
            },
        )
    } else if tail.is_empty() {
        (Path::root(), None)
    } else {
        parse_origin_form(tail)?
    };
    Ok((scheme, authority, path, query))
}

fn strip_prefix_ci<'a>(s: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    (s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix))
        .then(|| &s[prefix.len()..])
}

/// Parses `host[:port]` (§5.4 step 8). `default_port` is used when the port
/// is omitted; pass `None` to require an explicit port (CONNECT targets).
pub fn parse_authority_opt(raw: &[u8], default_port: Option<u16>) -> Result<Authority, ParseError> {
    if raw.is_empty() {
        return reject(Reason::BadAuthority, "empty authority");
    }
    if raw.iter().any(|&b| b >= 0x80) {
        return reject(Reason::NonAscii, "non-ASCII authority");
    }
    if raw.contains(&b'@') {
        return reject(Reason::BadAuthority, "userinfo in authority");
    }
    let (host_raw, port_raw) = if raw[0] == b'[' {
        let Some(close) = raw.iter().position(|&b| b == b']') else {
            return reject(Reason::BadAuthority, "unterminated IPv6 literal");
        };
        let after = &raw[close + 1..];
        let port = match after {
            [] => None,
            [b':', p @ ..] => Some(p),
            _ => return reject(Reason::BadAuthority, "garbage after IPv6 literal"),
        };
        (&raw[..=close], port)
    } else {
        match raw.iter().position(|&b| b == b':') {
            Some(i) => (&raw[..i], Some(&raw[i + 1..])),
            None => (raw, None),
        }
    };
    let host = parse_host(host_raw)?;
    let port = match (port_raw, default_port) {
        (Some(p), _) => parse_port(p)?,
        (None, Some(d)) => d,
        (None, None) => return reject(Reason::BadAuthority, "port required"),
    };
    Ok(Authority::new(host, port))
}

/// Parses `host[:port]`, defaulting the port.
pub fn parse_authority(raw: &[u8], default_port: u16) -> Result<Authority, ParseError> {
    parse_authority_opt(raw, Some(default_port))
}

fn parse_port(p: &[u8]) -> Result<u16, ParseError> {
    if p.is_empty() || p.len() > 5 || !p.iter().all(u8::is_ascii_digit) {
        return reject(Reason::BadAuthority, "invalid port");
    }
    let v: u32 = p.iter().fold(0, |acc, &d| acc * 10 + u32::from(d - b'0'));
    match u16::try_from(v) {
        Ok(port) if port != 0 => Ok(port),
        _ => reject(Reason::BadAuthority, "port out of range"),
    }
}

/// Parses a host: bracketed IPv6, strict dotted-quad IPv4, or a DNS name of
/// LDH(+underscore) labels which is lower-cased with one trailing dot removed.
///
/// Raw Unicode is rejected (IDNA labels must already be A-labels). A name
/// whose last label is numeric or `0x`-hex is treated as an IPv4 attempt
/// (WHATWG semantics; `127.1`, `0x7f000001` resolve to loopback with
/// `inet_aton`) and rejected unless it is a strict dotted quad.
pub fn parse_host(raw: &[u8]) -> Result<Host, ParseError> {
    if raw.iter().any(|&b| b >= 0x80) {
        return reject(Reason::NonAscii, "non-ASCII host (A-labels required)");
    }
    if let [b'[', inner @ .., b']'] = raw {
        let s = std::str::from_utf8(inner).unwrap_or("");
        return s
            .parse::<Ipv6Addr>()
            .map(Host::Ipv6)
            .map_err(|_| ParseError::new(Reason::BadAuthority, "invalid IPv6 literal"));
    }
    let raw = raw.strip_suffix(b".").unwrap_or(raw);
    if raw.is_empty() || raw.len() > MAX_DNS_NAME {
        return reject(Reason::BadAuthority, "empty or over-long host");
    }
    let lower = raw.to_ascii_lowercase();
    // Only ASCII by the check above.
    let s = String::from_utf8_lossy(&lower).into_owned();
    let last = s.rsplit('.').next().unwrap_or("");
    let looks_numeric = !last.is_empty()
        && (last.bytes().all(|b| b.is_ascii_digit())
            || last
                .strip_prefix("0x")
                .is_some_and(|h| h.bytes().all(|b| b.is_ascii_hexdigit())));
    if looks_numeric {
        return s
            .parse::<Ipv4Addr>()
            .map(Host::Ipv4)
            .map_err(|_| ParseError::new(Reason::BadAuthority, "non-canonical IPv4 literal"));
    }
    for label in s.split('.') {
        let ok = !label.is_empty()
            && label.len() <= MAX_DNS_LABEL
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
        if !ok {
            return reject(Reason::BadAuthority, format!("invalid DNS label {label:?}"));
        }
    }
    Ok(Host::Dns(s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn np(s: &str) -> Result<String, Reason> {
        normalize_path(s.as_bytes())
            .map(|p| p.0)
            .map_err(|e| e.reason)
    }

    #[test]
    fn path_basics() {
        assert_eq!(np("").unwrap(), "/");
        assert_eq!(np("/").unwrap(), "/");
        assert_eq!(np("/a/b/../c/./d").unwrap(), "/a/c/d");
        assert_eq!(np("/a/.").unwrap(), "/a/");
        assert_eq!(np("/a/..").unwrap(), "/");
        assert_eq!(np("/a/b/..").unwrap(), "/a/");
        assert_eq!(np("/a//../b").unwrap(), "/a/b");
        assert_eq!(np("//x").unwrap(), "//x");
        assert_eq!(np("/%7euser").unwrap(), "/~user");
        assert_eq!(np("/%41%62%2d").unwrap(), "/Ab-");
        assert_eq!(np("/a%2fb").unwrap(), "/a%2Fb");
        assert_eq!(np("/a%2Fb").unwrap(), "/a%2Fb");
        assert_eq!(np("/%e2%82%ac").unwrap(), "/%E2%82%AC");
        assert_eq!(np("/a:b@c;d=e,f!$&'()*+").unwrap(), "/a:b@c;d=e,f!$&'()*+");
    }

    #[test]
    fn path_rejections() {
        assert_eq!(np("/.."), Err(Reason::PathClimbsAboveRoot));
        assert_eq!(np("/a/../../b"), Err(Reason::PathClimbsAboveRoot));
        assert_eq!(np("/%2e%2e/etc"), Err(Reason::PathClimbsAboveRoot));
        assert_eq!(np("/%2E%2E/etc"), Err(Reason::PathClimbsAboveRoot));
        assert_eq!(np("/.%2e/"), Err(Reason::PathClimbsAboveRoot));
        assert_eq!(np("/a/%2e%2e/%2e%2e"), Err(Reason::PathClimbsAboveRoot));
        assert_eq!(np("/%"), Err(Reason::BadPercentEncoding));
        assert_eq!(np("/%4"), Err(Reason::BadPercentEncoding));
        assert_eq!(np("/%zz"), Err(Reason::BadPercentEncoding));
        assert_eq!(np("/%%41"), Err(Reason::BadPercentEncoding));
        assert_eq!(np("a"), Err(Reason::InvalidPath));
        assert_eq!(np("/a b"), Err(Reason::InvalidPath));
        assert_eq!(np("/a\\b"), Err(Reason::InvalidPath));
        assert_eq!(np("/a\"b"), Err(Reason::InvalidPath));
        assert_eq!(np("/a[b]"), Err(Reason::InvalidPath));
        assert_eq!(np("/a\x00"), Err(Reason::InvalidPath));
        assert_eq!(np("/a#b"), Err(Reason::FragmentInTarget));
        assert_eq!(np("/caf\u{e9}"), Err(Reason::NonAscii));
    }

    #[test]
    fn query_rules() {
        let q = normalize_query(b"a=%2f&b=%7e&c=x+y&d").unwrap();
        assert_eq!(q.as_str(), "a=%2F&b=%7E&c=x+y&d");
        let pairs: Vec<_> = q
            .pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("a".into(), "/".into()),
                ("b".into(), "~".into()),
                ("c".into(), "x y".into()),
                ("d".into(), String::new())
            ]
        );
        assert_eq!(q.get("c").as_deref(), Some("x y"));
        assert_eq!(normalize_query(b"a[]=1").unwrap().as_str(), "a[]=1");
        assert_eq!(normalize_query(b"a=?/").unwrap().as_str(), "a=?/");
        for (bad, r) in [
            (&b"a=%g0"[..], Reason::BadPercentEncoding),
            (b"a b", Reason::InvalidQuery),
            (b"a=\"", Reason::InvalidQuery),
            (b"a#b", Reason::FragmentInTarget),
            (b"a=\xff", Reason::NonAscii),
        ] {
            assert_eq!(normalize_query(bad).unwrap_err().reason, r);
        }
    }

    #[test]
    fn authority_rules() {
        let a = parse_authority(b"EXAMPLE.com.", 443).unwrap();
        assert_eq!(a.to_string(), "example.com:443");
        assert_eq!(
            parse_authority(b"example.com:8443", 443).unwrap().port,
            8443
        );
        assert_eq!(
            parse_authority(b"[::1]:80", 443).unwrap().to_string(),
            "[::1]:80"
        );
        assert_eq!(
            parse_authority(b"10.0.0.1", 80).unwrap().host,
            Host::Ipv4(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert_eq!(
            parse_authority(b"xn--bcher-kva.example", 443)
                .unwrap()
                .host
                .dns_name(),
            Some("xn--bcher-kva.example")
        );
        assert_eq!(
            parse_authority(b"my_host.internal", 443)
                .unwrap()
                .host
                .dns_name(),
            Some("my_host.internal")
        );
        for (bad, r) in [
            (&b""[..], Reason::BadAuthority),
            (b"user@example.com", Reason::BadAuthority),
            (b"example.com:", Reason::BadAuthority),
            (b"example.com:0", Reason::BadAuthority),
            (b"example.com:65536", Reason::BadAuthority),
            (b"example.com:+80", Reason::BadAuthority),
            (b"example.com:80:80", Reason::BadAuthority),
            (b"b\xc3\xbccher.example", Reason::NonAscii),
            (b"127.1", Reason::BadAuthority),
            (b"0x7f000001", Reason::BadAuthority),
            (b"2130706433", Reason::BadAuthority),
            (b"010.0.0.1", Reason::BadAuthority),
            (b"[fe80::1%25eth0]", Reason::BadAuthority),
            (b"[::1", Reason::BadAuthority),
            (b"[::1]x", Reason::BadAuthority),
            (b"-a.example", Reason::BadAuthority),
            (b"a..example", Reason::BadAuthority),
            (b"a b.example", Reason::BadAuthority),
            (b".", Reason::BadAuthority),
        ] {
            assert_eq!(
                parse_authority(bad, 443).unwrap_err().reason,
                r,
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
        assert_eq!(
            parse_authority_opt(b"example.com", None)
                .unwrap_err()
                .reason,
            Reason::BadAuthority
        );
    }

    #[test]
    fn absolute_form() {
        let (s, a, p, q) = parse_absolute_form(b"HTTP://Example.COM/a/../b?x=%2f").unwrap();
        assert_eq!(s, Scheme::Http);
        assert_eq!(a.to_string(), "example.com:80");
        assert_eq!(p.as_str(), "/b");
        assert_eq!(q.unwrap().as_str(), "x=%2F");
        let (s, a, p, q) = parse_absolute_form(b"https://h:8443").unwrap();
        assert_eq!((s, a.port, p.as_str(), q), (Scheme::Https, 8443, "/", None));
        let (_, _, p, q) = parse_absolute_form(b"http://h?a=1").unwrap();
        assert_eq!((p.as_str(), q.unwrap().as_str()), ("/", "a=1"));
        let (_, _, _, q) = parse_absolute_form(b"http://h/?").unwrap();
        assert_eq!(q, None);
        for (bad, r) in [
            (&b"ftp://h/"[..], Reason::BadRequestTarget),
            (b"http://h/#f", Reason::FragmentInTarget),
            (b"http:///a", Reason::BadAuthority),
            (b"http://u:p@h/", Reason::BadAuthority),
            (b"http://h/../a", Reason::PathClimbsAboveRoot),
        ] {
            assert_eq!(parse_absolute_form(bad).unwrap_err().reason, r);
        }
    }

    fn path_strategy() -> impl Strategy<Value = String> {
        let seg = prop_oneof![
            Just(".".to_owned()),
            Just("..".to_owned()),
            Just("%2e".to_owned()),
            Just("%2E%2e".to_owned()),
            Just(String::new()),
            "[a-zA-Z0-9._~!$&'()*+,;=:@-]{1,6}",
            "(%[0-9a-fA-F]{2}){1,3}",
        ];
        proptest::collection::vec(seg, 0..8).prop_map(|segs| format!("/{}", segs.join("/")))
    }

    proptest! {
        #[test]
        fn normalisation_is_idempotent(raw in path_strategy()) {
            if let Ok(p) = normalize_path(raw.as_bytes()) {
                let again = normalize_path(p.as_str().as_bytes()).unwrap();
                prop_assert_eq!(&again, &p);
                prop_assert!(p.as_str().starts_with('/'));
                // No dot segments survive.
                for seg in p.as_str().split('/') {
                    prop_assert!(seg != "." && seg != "..");
                }
                // No encoded unreserved bytes and no lower-case hex survive.
                let b = p.as_str().as_bytes();
                for (i, _) in b.iter().enumerate().filter(|(_, c)| **c == b'%') {
                    let v = hex_val(b[i + 1]).unwrap() << 4 | hex_val(b[i + 2]).unwrap();
                    prop_assert!(!is_unreserved(v));
                    prop_assert!(!b[i + 1].is_ascii_lowercase() && !b[i + 2].is_ascii_lowercase());
                }
            }
        }

        #[test]
        fn arbitrary_bytes_never_panic_and_stay_idempotent(raw in proptest::collection::vec(any::<u8>(), 0..64)) {
            let mut v = vec![b'/'];
            v.extend(raw);
            if let Ok(p) = normalize_path(&v) {
                prop_assert_eq!(normalize_path(p.as_str().as_bytes()).unwrap(), p);
            }
            if let Ok(q) = normalize_query(&v) {
                prop_assert_eq!(normalize_query(q.as_str().as_bytes()).unwrap(), q);
            }
        }

        #[test]
        fn encoded_dotdot_climbs_are_caught(prefix in 0usize..3, enc in prop_oneof![Just("%2e%2e"), Just("%2E%2E"), Just(".%2e"), Just("%2e."), Just("..")]) {
            let mut s = String::new();
            for i in 0..prefix { s.push_str("/s"); s.push_str(&i.to_string()); }
            for _ in 0..=prefix { s.push('/'); s.push_str(enc); }
            prop_assert_eq!(np(&s), Err(Reason::PathClimbsAboveRoot));
        }

        #[test]
        fn encoded_slash_preserved(a in "[a-z]{1,5}", b in "[a-z]{1,5}", lower in any::<bool>()) {
            let enc = if lower { "%2f" } else { "%2F" };
            let p = np(&format!("/{a}{enc}{b}")).unwrap();
            prop_assert_eq!(p, format!("/{a}%2F{b}"));
        }

        #[test]
        fn unreserved_decoded(c in proptest::char::range('!', '~')) {
            let b = u8::try_from(u32::from(c)).unwrap();
            let s = format!("/x%{b:02x}y");
            let r = np(&s);
            if is_unreserved(b) {
                if b == b'.' {
                    // "/x.y" — not a dot segment.
                    prop_assert_eq!(r.unwrap(), "/x.y");
                } else {
                    prop_assert_eq!(r.unwrap(), format!("/x{c}y"));
                }
            } else {
                prop_assert_eq!(r.unwrap(), format!("/x%{b:02X}y"));
            }
        }
    }
}
