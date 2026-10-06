//! A pure, allocation-light `ClientHello` sniffer.
//!
//! [`sniff`] inspects the start of a byte stream and reports whether it is a
//! TLS `ClientHello`, and if so its SNI and ALPN. It does no I/O; the caller
//! reads into a buffer (at most [`MAX_HELLO_BYTES`] + 5 bytes are ever needed)
//! and calls it again on [`Sniff::NeedMore`].
//!
//! Strictness: the whole handshake message must be present and well-formed
//! before it is parsed, so a hello is never partially interpreted. A hello
//! split across several TLS records is reported as `NotTls` (no real client
//! does this). A malformed or hostile `server_name` (non-ASCII, control
//! characters, NUL, trailing dot, duplicate entries) also yields `NotTls`
//! rather than silently becoming "no SNI".

/// Hard cap on the TLS record and handshake length we are willing to parse.
pub const MAX_HELLO_BYTES: usize = 16 * 1024;

const RECORD_HEADER: usize = 5;
const HANDSHAKE_HEADER: usize = 4;
const CONTENT_TYPE_HANDSHAKE: u8 = 22;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const EXT_SERVER_NAME: u16 = 0;
const EXT_ALPN: u16 = 16;
const MAX_HOST: usize = 253;

/// Result of [`sniff`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sniff {
    /// The bytes so far are a plausible `ClientHello` prefix; read more.
    NeedMore,
    /// Not a (well-formed, acceptable) TLS `ClientHello`.
    NotTls,
    /// A complete, well-formed `ClientHello`.
    Tls(ClientHelloInfo),
}

/// What was extracted from a `ClientHello`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHelloInfo {
    /// `server_name` host name, lower-cased.
    pub sni: Option<String>,
    /// ALPN protocol names offered, in order.
    pub alpn: Vec<String>,
}

/// Parse the start of a TLS stream. Never panics, for any input.
#[must_use]
pub fn sniff(buf: &[u8]) -> Sniff {
    // Early rejection of the fixed header bytes, so plaintext is recognised
    // after one byte rather than after a full record header.
    if buf.first().is_some_and(|&t| t != CONTENT_TYPE_HANDSHAKE)
        || buf.get(1).is_some_and(|&major| major != 3)
        || buf.get(2).is_some_and(|minor| !(1..=4).contains(minor))
    {
        return Sniff::NotTls;
    }
    let Some(header) = buf.get(..RECORD_HEADER) else {
        return Sniff::NeedMore;
    };
    let record_payload = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if record_payload == 0 || record_payload > MAX_HELLO_BYTES {
        return Sniff::NotTls;
    }
    // Handshake header is available as soon as 4 payload bytes are.
    let Some(hs) = buf.get(RECORD_HEADER..RECORD_HEADER + HANDSHAKE_HEADER) else {
        // Still validate the handshake type byte if we have it.
        if buf
            .get(RECORD_HEADER)
            .is_some_and(|&t| t != HANDSHAKE_CLIENT_HELLO)
        {
            return Sniff::NotTls;
        }
        return Sniff::NeedMore;
    };
    if hs[0] != HANDSHAKE_CLIENT_HELLO {
        return Sniff::NotTls;
    }
    let hs_len = (usize::from(hs[1]) << 16) | (usize::from(hs[2]) << 8) | usize::from(hs[3]);
    if hs_len > MAX_HELLO_BYTES || hs_len + HANDSHAKE_HEADER > record_payload {
        // Oversized, or the hello spans multiple records (unsupported).
        return Sniff::NotTls;
    }
    let start = RECORD_HEADER + HANDSHAKE_HEADER;
    let Some(body) = buf.get(start..start + hs_len) else {
        return Sniff::NeedMore;
    };
    match parse_body(body) {
        Some((sni, alpn)) => Sniff::Tls(ClientHelloInfo { sni, alpn }),
        None => Sniff::NotTls,
    }
}

/// Bounds-checked big-endian cursor.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, tail) = self.0.split_at_checked(n)?;
        self.0 = tail;
        Some(head)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    /// A `u8`-length-prefixed vector.
    fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = usize::from(self.u8()?);
        self.take(n)
    }
    /// A `u16`-length-prefixed vector.
    fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = usize::from(self.u16()?);
        self.take(n)
    }
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

type Parsed = (Option<String>, Vec<String>);

fn parse_body(body: &[u8]) -> Option<Parsed> {
    let mut r = Reader(body);
    let legacy_version = r.u16()?;
    if !(0x0301..=0x0304).contains(&legacy_version) {
        return None;
    }
    r.take(32)?; // random
    r.vec8()?; // session id (max 32 per spec; length is bounded by u8 anyway)
    let suites = r.vec16()?;
    if suites.len() < 2 || suites.len() % 2 != 0 {
        return None;
    }
    if r.vec8()?.is_empty() {
        return None; // compression methods: at least one
    }
    let mut sni = None;
    let mut alpn = Vec::new();
    if r.is_empty() {
        return Some((sni, alpn)); // no extensions at all
    }
    let exts = r.vec16()?;
    if !r.is_empty() {
        return None; // trailing garbage after extensions
    }
    let mut r = Reader(exts);
    let (mut seen_sni, mut seen_alpn) = (false, false);
    while !r.is_empty() {
        let ty = r.u16()?;
        let data = r.vec16()?;
        match ty {
            EXT_SERVER_NAME => {
                if std::mem::replace(&mut seen_sni, true) {
                    return None;
                }
                sni = parse_server_name(data)?;
            }
            EXT_ALPN => {
                if std::mem::replace(&mut seen_alpn, true) {
                    return None;
                }
                alpn = parse_alpn(data)?;
            }
            _ => {}
        }
    }
    Some((sni, alpn))
}

/// `Some(Some(host))`, `Some(None)` for a list with no `host_name` entry,
/// `None` if malformed.
#[allow(clippy::option_option)]
fn parse_server_name(data: &[u8]) -> Option<Option<String>> {
    let mut outer = Reader(data);
    let list = outer.vec16()?;
    if !outer.is_empty() {
        return None;
    }
    let mut r = Reader(list);
    let mut host = None;
    while !r.is_empty() {
        let name_type = r.u8()?;
        let name = r.vec16()?;
        if name_type == 0 {
            if host.is_some() {
                return None; // at most one host_name (RFC 6066)
            }
            host = Some(validate_host(name)?);
        }
    }
    Some(host)
}

fn validate_host(name: &[u8]) -> Option<String> {
    if name.is_empty() || name.len() > MAX_HOST {
        return None;
    }
    // Printable ASCII only: rules out NUL, whitespace, controls and non-ASCII.
    if !name.iter().all(|b| (0x21..=0x7e).contains(b)) {
        return None;
    }
    if name.ends_with(b".") {
        return None;
    }
    let s = std::str::from_utf8(name).ok()?;
    Some(s.to_ascii_lowercase())
}

fn parse_alpn(data: &[u8]) -> Option<Vec<String>> {
    let mut outer = Reader(data);
    let list = outer.vec16()?;
    if !outer.is_empty() {
        return None;
    }
    let mut r = Reader(list);
    let mut out = Vec::new();
    while !r.is_empty() {
        let proto = r.vec8()?;
        if proto.is_empty() || !proto.iter().all(|b| (0x21..=0x7e).contains(b)) {
            return None;
        }
        out.push(String::from_utf8(proto.to_vec()).ok()?);
    }
    if out.is_empty() {
        return None;
    }
    Some(out)
}

/// Does `buf` start like an HTTP/1.x request: an uppercase token followed by
/// a space, within the first 16 bytes? Used to detect plaintext inside a
/// CONNECT tunnel.
#[must_use]
pub fn looks_like_http(buf: &[u8]) -> bool {
    let window = &buf[..buf.len().min(16)];
    match window.iter().position(|b| !b.is_ascii_uppercase()) {
        Some(i) => i > 0 && window[i] == b' ',
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rustls::{ClientConfig, ClientConnection, RootCertStore};
    use std::sync::Arc;

    fn hello(sni: &str, alpn: &[&str], tls13_only: bool) -> Vec<u8> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let versions: &[&rustls::SupportedProtocolVersion] = if tls13_only {
            &[&rustls::version::TLS13]
        } else {
            rustls::ALL_VERSIONS
        };
        let mut cfg = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .unwrap()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        cfg.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
        let name = crate::server_name(&roxy_http::url::parse_host(sni.as_bytes()).unwrap());
        let mut conn = ClientConnection::new(Arc::new(cfg), name).unwrap();
        let mut out = Vec::new();
        while conn.wants_write() {
            conn.write_tls(&mut out).unwrap();
        }
        out
    }

    #[test]
    fn extracts_sni_and_alpn() {
        let cases: [(&str, &[&str], bool); 4] = [
            ("example.com", &["h2", "http/1.1"], false),
            ("Sub.Example.ORG", &["http/1.1"], true),
            ("a.b.c.d.example.net", &[], false),
            ("x.test", &["h2", "http/1.1", "acme-tls/1"], true),
        ];
        for (sni, alpn, t13) in cases {
            let buf = hello(sni, alpn, t13);
            let Sniff::Tls(info) = sniff(&buf) else {
                panic!("not tls: {sni}");
            };
            assert_eq!(info.sni.as_deref(), Some(sni.to_ascii_lowercase().as_str()));
            assert_eq!(info.alpn, alpn);
        }
    }

    #[test]
    fn ip_target_has_no_sni() {
        let buf = hello("127.0.0.1", &["h2"], false);
        let Sniff::Tls(info) = sniff(&buf) else {
            panic!()
        };
        assert_eq!(info.sni, None);
        assert_eq!(info.alpn, ["h2"]);
    }

    #[test]
    fn trailing_bytes_are_ignored() {
        let mut buf = hello("example.com", &["h2"], false);
        let whole = sniff(&buf);
        assert!(matches!(whole, Sniff::Tls(_)));
        buf.extend_from_slice(b"extra application bytes");
        assert_eq!(sniff(&buf), whole);
    }

    #[test]
    fn need_more_on_every_prefix() {
        for buf in [
            hello("example.com", &["h2", "http/1.1"], false),
            hello("example.com", &[], true),
        ] {
            assert!(matches!(sniff(&buf), Sniff::Tls(_)));
            for n in 0..buf.len() {
                assert_eq!(sniff(&buf[..n]), Sniff::NeedMore, "prefix {n}");
            }
        }
    }

    #[test]
    fn not_tls_cases() {
        assert_eq!(sniff(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"), Sniff::NotTls);
        assert_eq!(sniff(b"G"), Sniff::NotTls);
        assert_eq!(sniff(b"CONNECT a:443 HTTP/1.1\r\n"), Sniff::NotTls);
        assert_eq!(sniff(&[0u8; 64]), Sniff::NotTls);
        assert_eq!(sniff(&[0xff; 64]), Sniff::NotTls);
        // Other record types: change_alert, application_data, heartbeat.
        for ty in [20u8, 21, 23, 24] {
            let mut buf = hello("example.com", &[], false);
            buf[0] = ty;
            assert_eq!(sniff(&buf), Sniff::NotTls, "type {ty}");
        }
        // Not a ClientHello handshake type (ServerHello).
        let mut buf = hello("example.com", &[], false);
        buf[5] = 2;
        assert_eq!(sniff(&buf), Sniff::NotTls);
        // Bad versions.
        for (a, b) in [(2u8, 0u8), (3, 0), (3, 5), (4, 1)] {
            let mut buf = hello("example.com", &[], false);
            buf[1] = a;
            buf[2] = b;
            assert_eq!(sniff(&buf), Sniff::NotTls, "version {a}.{b}");
        }
    }

    #[test]
    fn oversized_lengths_are_not_tls() {
        let base = hello("example.com", &[], false);
        // Record length over 16 KiB.
        let mut buf = base.clone();
        buf[3..5].copy_from_slice(&0x4001u16.to_be_bytes());
        assert_eq!(sniff(&buf), Sniff::NotTls);
        buf[3..5].copy_from_slice(&0xffffu16.to_be_bytes());
        assert_eq!(sniff(&buf), Sniff::NotTls);
        // Zero record length.
        buf[3..5].copy_from_slice(&0u16.to_be_bytes());
        assert_eq!(sniff(&buf), Sniff::NotTls);
        // Handshake length over 16 KiB (header only is enough to decide).
        let mut buf = base.clone();
        buf[6] = 0x01;
        assert_eq!(sniff(&buf[..9]), Sniff::NotTls);
        // Handshake longer than its record.
        let mut buf = base;
        buf[8] = buf[8].wrapping_add(10);
        assert_eq!(sniff(&buf), Sniff::NotTls);
    }

    /// Replace the SNI bytes of a real hello in place.
    fn with_sni_bytes(replacement: &[u8]) -> Vec<u8> {
        let mut buf = hello("aaaaaaaaaaa", &[], false);
        let pos = buf.windows(11).position(|w| w == b"aaaaaaaaaaa").unwrap();
        buf[pos..pos + replacement.len()].copy_from_slice(replacement);
        buf
    }

    #[test]
    fn hostile_sni_is_rejected() {
        assert!(matches!(
            sniff(&with_sni_bytes(b"bbbbbbbbbbb")),
            Sniff::Tls(_)
        ));
        for bad in [
            &b"a\0aaaaaaaaa"[..],
            b"aaaaaaaaaa.",
            b"aaaa aaaaaa",
            b"aaaa\xc3\xa9aaaaa",
            b"aaaa\naaaaaa",
        ] {
            assert_eq!(sniff(&with_sni_bytes(bad)), Sniff::NotTls, "{bad:?}");
        }
    }

    #[test]
    fn http_detection() {
        for yes in [
            &b"GET / HTTP/1.1\r\n"[..],
            b"CONNECT a:1 HTTP/1.1",
            b"POST /",
            b"PROPFIND /",
            b"X ",
        ] {
            assert!(looks_like_http(yes), "{yes:?}");
        }
        for no in [
            &b""[..],
            b"get / HTTP/1.1",
            b" GET",
            b"GET",
            b"\x16\x03\x01\x02\x00",
            b"ABCDEFGHIJKLMNOPQ ",
            b"GET\t/",
        ] {
            assert!(!looks_like_http(no), "{no:?}");
        }
        assert!(!looks_like_http(&hello("example.com", &[], false)));
    }

    proptest! {
        #[test]
        fn never_panics_on_random_bytes(buf in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let _ = sniff(&buf);
            let _ = looks_like_http(&buf);
        }

        #[test]
        fn never_panics_on_tls_shaped_bytes(
            tail in proptest::collection::vec(any::<u8>(), 0..2048),
            len in 0u16..20_000,
        ) {
            let mut buf = vec![22, 3, 1];
            buf.extend_from_slice(&len.to_be_bytes());
            buf.push(1);
            buf.extend_from_slice(&tail);
            let _ = sniff(&buf);
        }

        #[test]
        fn never_panics_on_mutated_hellos(
            t13 in any::<bool>(),
            cut in 0usize..1024,
            flips in proptest::collection::vec((0usize..1024, any::<u8>()), 0..8),
        ) {
            let mut buf = hello("example.com", &["h2", "http/1.1"], t13);
            for (i, v) in flips {
                if let Some(b) = buf.get_mut(i) {
                    *b = v;
                }
            }
            buf.truncate(cut);
            let _ = sniff(&buf);
        }

        #[test]
        fn real_hello_prefixes_never_complete(cut in 0usize..1024) {
            let buf = hello("example.com", &["h2"], false);
            if cut < buf.len() {
                prop_assert_eq!(sniff(&buf[..cut]), Sniff::NeedMore);
            }
        }
    }
}
