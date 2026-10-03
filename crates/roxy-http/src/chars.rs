//! Byte classes from RFC 9110 / RFC 3986.

/// `tchar` (RFC 9110 §5.6.2).
pub(crate) const fn is_tchar(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
    ) || b.is_ascii_alphanumeric()
}

/// A non-empty `token`.
pub(crate) fn is_token(s: &[u8]) -> bool {
    !s.is_empty() && s.iter().all(|&b| is_tchar(b))
}

/// `unreserved` (RFC 3986 §2.3).
pub(crate) const fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// `sub-delims` (RFC 3986 §2.2).
pub(crate) const fn is_sub_delim(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
    )
}

/// `pchar` minus `pct-encoded` (RFC 3986 §3.3).
pub(crate) const fn is_pchar_literal(b: u8) -> bool {
    is_unreserved(b) || is_sub_delim(b) || matches!(b, b':' | b'@')
}

/// Field-value byte under roxy's rule: visible ASCII, SP, HTAB, and obs-text
/// only when allowed.
pub(crate) const fn is_field_value_byte(b: u8, allow_obs_text: bool) -> bool {
    matches!(b, b'\t' | b' '..=b'~') || (allow_obs_text && b >= 0x80)
}

/// Value of an ASCII hex digit.
pub(crate) const fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Upper-case hex digit for a nibble.
pub(crate) const fn hex_upper(n: u8) -> u8 {
    b"0123456789ABCDEF"[(n & 0x0f) as usize]
}

/// Strips leading and trailing SP / HTAB.
pub(crate) fn trim_ows(mut s: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = s {
        s = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = s {
        s = rest;
    }
    s
}

/// Splits a comma-separated list, trimming OWS and skipping empty elements
/// (RFC 9110 §5.6.1 requires recipients to ignore them).
pub(crate) fn split_list(s: &[u8]) -> impl Iterator<Item = &[u8]> {
    s.split(|&b| b == b',')
        .map(trim_ows)
        .filter(|e| !e.is_empty())
}
