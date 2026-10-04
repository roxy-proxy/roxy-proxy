//! Validated, ordered header fields.

use http::{HeaderMap, HeaderName, HeaderValue};

use super::error::{ParseError, Reason, reject};
use super::limits::{HttpFlags, Limits};
use crate::chars::{is_field_value_byte, is_token, split_list, trim_ows};

/// Header names that never appear in a canonical [`Headers`] set: the
/// hop-by-hop fields plus the framing / routing fields roxy
/// regenerates itself (`content-length` from the body, `host` from the
/// authority).
pub const RESERVED: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authorization",
    "proxy-authenticate",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "host",
];

/// Whether `name` (lower-case) is reserved.
pub fn is_reserved(name: &str) -> bool {
    RESERVED.contains(&name)
}

/// Ordered, validated header fields.
///
/// Invariants: (a) every name is a lower-case `token`; (b) every value is
/// visible ASCII, SP and HTAB with no leading/trailing whitespace (obs-text
/// only where explicitly allowed: `http.allow_obs_text`, or upstream
/// responses which hyper already validated); (c) no [`RESERVED`] name is
/// present. Iteration is in insertion order and repeated fields (e.g.
/// `set-cookie`) stay separate entries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers {
    entries: Vec<(HeaderName, HeaderValue)>,
}

fn validate_name(name: &[u8]) -> Result<HeaderName, ParseError> {
    if !is_token(name) {
        if name.iter().any(|&b| b >= 0x80) {
            return reject(Reason::NonAscii, "non-ASCII header name");
        }
        return reject(
            Reason::InvalidHeaderName,
            format!("invalid header name {:?}", String::from_utf8_lossy(name)),
        );
    }
    HeaderName::from_bytes(&name.to_ascii_lowercase())
        .map_err(|_| ParseError::new(Reason::InvalidHeaderName, "invalid header name"))
}

pub(crate) fn validate_value(
    value: &[u8],
    allow_obs_text: bool,
) -> Result<HeaderValue, ParseError> {
    let v = trim_ows(value);
    if let Some(&b) = v.iter().find(|&&b| !is_field_value_byte(b, allow_obs_text)) {
        if b >= 0x80 {
            return reject(Reason::NonAscii, "non-ASCII header value");
        }
        return reject(
            Reason::InvalidHeaderValue,
            format!("byte 0x{b:02x} in header value"),
        );
    }
    HeaderValue::from_bytes(v)
        .map_err(|_| ParseError::new(Reason::InvalidHeaderValue, "invalid header value"))
}

/// Parses client `Connection` values into lower-case tokens; any element
/// that is not a token rejects the request.
pub(crate) fn connection_tokens<'a>(
    values: impl IntoIterator<Item = &'a [u8]>,
) -> Result<Vec<String>, ParseError> {
    values
        .into_iter()
        .flat_map(split_list)
        .map(|t| {
            if is_token(t) {
                Ok(String::from_utf8_lossy(t).to_ascii_lowercase())
            } else {
                reject(
                    Reason::BadConnectionHeader,
                    "connection option is not a token",
                )
            }
        })
        .collect()
}

/// Parses upstream `Connection` values into lower-case tokens, skipping
/// elements that are not tokens. Upstreams are trusted but not held to the
/// client's strictness, and one sloppy element must not switch off the
/// stripping of the fields the valid ones nominate.
fn connection_tokens_lenient<'a>(values: impl IntoIterator<Item = &'a [u8]>) -> Vec<String> {
    values
        .into_iter()
        .flat_map(split_list)
        .filter(|t| is_token(t))
        .map(|t| String::from_utf8_lossy(t).to_ascii_lowercase())
        .collect()
}

impl Headers {
    /// Empty header set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a canonical set from raw `(name, value)` pairs (e.g. from the h1
    /// tokenizer). Validates names and values, enforces `limits.max_headers`,
    /// and silently drops [`RESERVED`] fields and every field nominated by
    /// `Connection`. Callers that need the hop-by-hop information (framing,
    /// `Connection: close`, `Upgrade`) must extract it from the raw pairs
    /// first.
    pub fn try_from_raw<'a, I>(
        raw: I,
        limits: &Limits,
        flags: &HttpFlags,
    ) -> Result<Self, ParseError>
    where
        I: IntoIterator<Item = (&'a [u8], &'a [u8])>,
        I::IntoIter: Clone,
    {
        let iter = raw.into_iter();
        let nominated = connection_tokens(
            iter.clone()
                .filter(|(n, _)| n.eq_ignore_ascii_case(b"connection"))
                .map(|(_, v)| v),
        )?;
        let mut entries = Vec::new();
        for (count, (name, value)) in iter.enumerate() {
            if count >= limits.max_headers {
                return reject(Reason::TooManyHeaders, "too many header fields");
            }
            let name = validate_name(name)?;
            let value = validate_value(value, flags.allow_obs_text)?;
            if is_reserved(name.as_str()) || nominated.iter().any(|t| t == name.as_str()) {
                continue;
            }
            entries.push((name, value));
        }
        Ok(Self { entries })
    }

    /// Builds a set from an already-validated `http::HeaderMap` (upstream
    /// responses: hyper guarantees `HeaderValue` validity, obs-text allowed).
    /// Reserved and `Connection`-nominated fields are dropped. Iteration
    /// order follows `HeaderMap` (grouped by name).
    pub fn from_header_map_lenient(map: &HeaderMap) -> Self {
        Self::from_header_map_lenient_with_connection(map).0
    }

    /// As [`Headers::from_header_map_lenient`], also returning the
    /// lower-case options the `Connection` fields nominated (elements that
    /// are not tokens are ignored), for callers that act on them, such as
    /// `101` detection.
    pub fn from_header_map_lenient_with_connection(map: &HeaderMap) -> (Self, Vec<String>) {
        let nominated = connection_tokens_lenient(
            map.get_all(http::header::CONNECTION)
                .iter()
                .map(HeaderValue::as_bytes),
        );
        let entries = map
            .iter()
            .filter(|(n, _)| !is_reserved(n.as_str()) && !nominated.iter().any(|t| t == n.as_str()))
            .map(|(n, v)| (n.clone(), v.clone()))
            .collect();
        (Self { entries }, nominated)
    }

    /// First value of `name` as a string (`None` if absent or if the value
    /// contains obs-text; use [`Headers::get_raw`] for bytes).
    ///
    /// Absent and unreadable look the same here. A caller that must not
    /// treat an unreadable value as "not set" (anything that decides how a
    /// body is read, say) uses [`Headers::get_raw`].
    pub fn get(&self, name: &str) -> Option<&str> {
        self.get_raw(name).and_then(|v| v.to_str().ok())
    }

    /// First value of `name`.
    pub fn get_raw(&self, name: &str) -> Option<&HeaderValue> {
        self.entries
            .iter()
            .find(|(n, _)| n.as_str().eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    }

    /// All values of `name` that are valid strings, in order. Values with
    /// obs-text are skipped, not reported: a caller that needs to know
    /// about them uses [`Headers::get_all_raw`].
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.get_all_raw(name).filter_map(|v| v.to_str().ok())
    }

    /// All values of `name`, in order.
    pub fn get_all_raw<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a HeaderValue> + 'a {
        self.entries
            .iter()
            .filter(move |(n, _)| n.as_str().eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    }

    /// Whether `name` is present.
    pub fn contains(&self, name: &str) -> bool {
        self.get_raw(name).is_some()
    }

    fn checked(name: &str, value: &str) -> Result<(HeaderName, HeaderValue), ParseError> {
        let n = validate_name(name.as_bytes())?;
        if is_reserved(n.as_str()) {
            return reject(
                Reason::ReservedHeader,
                format!("{} is managed by roxy", n.as_str()),
            );
        }
        let v = validate_value(value.as_bytes(), false)?;
        Ok((n, v))
    }

    /// Sets `name` to `value`, replacing any existing values (position of the
    /// first existing occurrence is kept). Validates strictly: lower-cases the
    /// name, rejects reserved names, CR/LF/NUL/controls and non-ASCII.
    pub fn insert(&mut self, name: &str, value: &str) -> Result<(), ParseError> {
        let (n, v) = Self::checked(name, value)?;
        if let Some(pos) = self.entries.iter().position(|(e, _)| *e == n) {
            self.entries[pos].1 = v;
            let mut i = pos + 1;
            while i < self.entries.len() {
                if self.entries[i].0 == n {
                    self.entries.remove(i);
                } else {
                    i += 1;
                }
            }
        } else {
            self.entries.push((n, v));
        }
        Ok(())
    }

    /// Appends a value, keeping existing ones. Same validation as
    /// [`Headers::insert`].
    pub fn append(&mut self, name: &str, value: &str) -> Result<(), ParseError> {
        let (n, v) = Self::checked(name, value)?;
        self.entries.push((n, v));
        Ok(())
    }

    /// Removes every value of `name`; returns how many were removed.
    pub fn remove(&mut self, name: &str) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|(n, _)| !n.as_str().eq_ignore_ascii_case(name));
        before - self.entries.len()
    }

    /// Fields in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&HeaderName, &HeaderValue)> {
        self.entries.iter().map(|(n, v)| (n, v))
    }

    /// Number of fields.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no fields.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Approximate h1 wire size (`name: value\r\n` per field).
    pub fn wire_len(&self) -> usize {
        self.entries
            .iter()
            .map(|(n, v)| n.as_str().len() + v.len() + 4)
            .sum()
    }

    /// Copies into an `http::HeaderMap` (repeated names appended in order).
    pub fn to_header_map(&self) -> HeaderMap {
        let mut m = HeaderMap::with_capacity(self.entries.len());
        for (n, v) in &self.entries {
            m.append(n.clone(), v.clone());
        }
        m
    }
}

impl<'a> IntoIterator for &'a Headers {
    type Item = (&'a HeaderName, &'a HeaderValue);
    type IntoIter = std::iter::Map<
        std::slice::Iter<'a, (HeaderName, HeaderValue)>,
        fn(&'a (HeaderName, HeaderValue)) -> (&'a HeaderName, &'a HeaderValue),
    >;
    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter().map(|(n, v)| (n, v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(pairs: &[(&'static str, &'static str)]) -> Vec<(&'static [u8], &'static [u8])> {
        pairs
            .iter()
            .map(|(n, v)| (n.as_bytes(), v.as_bytes()))
            .collect()
    }

    #[test]
    fn from_raw_strips_hop_by_hop_and_nominated() {
        let h = Headers::try_from_raw(
            raw(&[
                ("Accept", " */* "),
                ("Connection", "keep-alive, X-Secret"),
                ("x-secret", "1"),
                ("Keep-Alive", "timeout=5"),
                ("TE", "trailers"),
                ("Set-Cookie", "a=1"),
                ("set-cookie", "b=2"),
                ("Proxy-Authorization", "Basic x"),
            ]),
            &Limits::default(),
            &HttpFlags::default(),
        )
        .unwrap();
        let names: Vec<_> = h.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["accept", "set-cookie", "set-cookie"]);
        assert_eq!(h.get("ACCEPT"), Some("*/*"));
        assert_eq!(h.get_all("set-cookie").collect::<Vec<_>>(), ["a=1", "b=2"]);
    }

    #[test]
    fn value_rules() {
        let l = Limits::default();
        let f = HttpFlags::default();
        for (v, r) in [
            (&b"a\x00b"[..], Reason::InvalidHeaderValue),
            (b"a\rb", Reason::InvalidHeaderValue),
            (b"a\nb", Reason::InvalidHeaderValue),
            (b"a\x7fb", Reason::InvalidHeaderValue),
            (b"caf\xc3\xa9", Reason::NonAscii),
        ] {
            let e = Headers::try_from_raw([(&b"x"[..], v)], &l, &f).unwrap_err();
            assert_eq!(e.reason, r);
        }
        let obs = HttpFlags {
            allow_obs_text: true,
            ..HttpFlags::default()
        };
        let h = Headers::try_from_raw([(&b"x"[..], &b"caf\xc3\xa9"[..])], &l, &obs).unwrap();
        assert_eq!(h.get_raw("x").unwrap().as_bytes(), b"caf\xc3\xa9");
        assert_eq!(h.get("x"), None);
        let e = Headers::try_from_raw([(&b"a b"[..], &b"1"[..])], &l, &f).unwrap_err();
        assert_eq!(e.reason, Reason::InvalidHeaderName);
        let e = Headers::try_from_raw([(&b"\xc3\xa9"[..], &b"1"[..])], &l, &f).unwrap_err();
        assert_eq!(e.reason, Reason::NonAscii);
    }

    #[test]
    fn count_limit() {
        let l = Limits {
            max_headers: 2,
            ..Limits::default()
        };
        let r = raw(&[("a", "1"), ("b", "2"), ("c", "3")]);
        assert_eq!(
            Headers::try_from_raw(r, &l, &HttpFlags::default())
                .unwrap_err()
                .reason,
            Reason::TooManyHeaders
        );
    }

    #[test]
    fn insert_validates() {
        let mut h = Headers::new();
        h.append("X-A", "1").unwrap();
        h.append("x-b", "2").unwrap();
        h.append("x-a", "3").unwrap();
        h.insert("x-a", "4").unwrap();
        assert_eq!(
            h.iter()
                .map(|(n, v)| format!("{}={}", n, v.to_str().unwrap()))
                .collect::<Vec<_>>(),
            ["x-a=4", "x-b=2"]
        );
        assert_eq!(
            h.insert("x", "a\r\nevil: 1").unwrap_err().reason,
            Reason::InvalidHeaderValue
        );
        assert_eq!(
            h.insert("Connection", "close").unwrap_err().reason,
            Reason::ReservedHeader
        );
        assert_eq!(
            h.insert("content-length", "1").unwrap_err().reason,
            Reason::ReservedHeader
        );
        assert_eq!(
            h.insert("bad name", "1").unwrap_err().reason,
            Reason::InvalidHeaderName
        );
        assert_eq!(h.remove("X-A"), 1);
        assert_eq!(h.len(), 1);
        assert_eq!(h.to_header_map().get("x-b").unwrap(), "2");
    }

    #[test]
    fn lenient_map() {
        let mut m = HeaderMap::new();
        m.append("connection", HeaderValue::from_static("x-hop"));
        m.append("x-hop", HeaderValue::from_static("1"));
        m.append("transfer-encoding", HeaderValue::from_static("chunked"));
        m.append("set-cookie", HeaderValue::from_static("a"));
        m.append("set-cookie", HeaderValue::from_static("b"));
        let h = Headers::from_header_map_lenient(&m);
        assert_eq!(h.len(), 2);
        assert_eq!(h.get_all("set-cookie").count(), 2);
    }

    #[test]
    fn lenient_map_keeps_valid_connection_tokens_beside_a_malformed_one() {
        let mut m = HeaderMap::new();
        m.append(
            "connection",
            HeaderValue::from_static("x-hop, Upgrade, (bad)"),
        );
        m.append("x-hop", HeaderValue::from_static("1"));
        m.append("x-keep", HeaderValue::from_static("1"));
        let (h, nominated) = Headers::from_header_map_lenient_with_connection(&m);
        assert_eq!(nominated, ["x-hop", "upgrade"]);
        assert!(!h.contains("x-hop"));
        assert!(h.contains("x-keep"));
    }
}
