//! The client behind trusted proxies.
//!
//! A listener with `forwarded_for` sits behind `trusted_hops` proxies, each
//! appending the address it accepted the connection from to
//! `X-Forwarded-For`, so the client is that many entries from the right of
//! the combined list. Everything to the left is client-supplied and is
//! never read.

use std::net::IpAddr;
use std::num::NonZeroUsize;

use roxy_http::{Headers, ParseError, Reason};

use crate::addr::canonical;

/// Longest combined `X-Forwarded-For` roxy accepts. A chain of trusted
/// proxies is short; anything longer is a client padding the header.
const MAX_BYTES: usize = 4096;

/// The client's address: the entry `hops` from the right of
/// `X-Forwarded-For`, all lines joined in order. Every entry from there to
/// the right must be a bare IPv4 or IPv6 address (no port, brackets, zone
/// or `unknown`): a proxy that wrote anything else, or too few entries, is
/// not the configured one, so the request is refused rather than
/// attributed to anyone.
pub(crate) fn client_ip(headers: &Headers, hops: NonZeroUsize) -> Result<IpAddr, ParseError> {
    let values: Vec<_> = headers.get_all_text("x-forwarded-for").collect();
    // The combined list: the lines, with a separator between each pair.
    let bytes = values.iter().map(|v| v.len()).sum::<usize>() + values.len().saturating_sub(1);
    if bytes > MAX_BYTES {
        return Err(invalid(format!(
            "x-forwarded-for is {bytes} bytes, over {MAX_BYTES}"
        )));
    }
    let trusted = values
        .iter()
        .rev()
        .flat_map(|v| v.rsplit(','))
        .take(hops.get())
        .map(|e| {
            e.trim_matches([' ', '\t']).parse::<IpAddr>().map_err(|_| {
                invalid(format!(
                    "x-forwarded-for entry {e:?} is not a bare IP address"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    match trusted.last() {
        Some(&ip) if trusted.len() == hops.get() => Ok(canonical(ip)),
        _ => Err(invalid(format!(
            "x-forwarded-for has {} entries, fewer than the {hops} trusted hops",
            trusted.len()
        ))),
    }
}

fn invalid(detail: String) -> ParseError {
    ParseError::new(Reason::ForwardedForInvalid, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(lines: &[&str]) -> Headers {
        let mut h = Headers::new();
        for l in lines {
            h.append("x-forwarded-for", l).unwrap();
        }
        h
    }

    fn resolve(lines: &[&str], hops: usize) -> Result<IpAddr, ParseError> {
        client_ip(&headers(lines), NonZeroUsize::new(hops).unwrap())
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// The client is counted from the right, so whatever it put in the
    /// header itself sits to the left of the trusted entries and is never
    /// read.
    #[test]
    fn the_client_is_the_nth_entry_from_the_right() {
        assert_eq!(resolve(&["203.0.113.9"], 1).unwrap(), ip("203.0.113.9"));
        assert_eq!(
            resolve(&["1.1.1.1, 203.0.113.9"], 1).unwrap(),
            ip("203.0.113.9")
        );
        assert_eq!(
            resolve(&["1.1.1.1, 203.0.113.9, 10.0.0.1"], 2).unwrap(),
            ip("203.0.113.9")
        );
        assert_eq!(
            resolve(&["1.1.1.1,\t203.0.113.9 ,10.0.0.1"], 2).unwrap(),
            ip("203.0.113.9")
        );
    }

    /// Several `X-Forwarded-For` lines are one list in the order sent.
    #[test]
    fn lines_join_in_order() {
        let lines = ["1.1.1.1, 203.0.113.9", "10.0.0.1"];
        assert_eq!(resolve(&lines, 1).unwrap(), ip("10.0.0.1"));
        assert_eq!(resolve(&lines, 2).unwrap(), ip("203.0.113.9"));
        assert_eq!(resolve(&lines, 3).unwrap(), ip("1.1.1.1"));
    }

    #[test]
    fn ipv6_is_bare_and_mapped_v4_is_v4() {
        assert_eq!(resolve(&["2001:db8::1"], 1).unwrap(), ip("2001:db8::1"));
        assert_eq!(
            resolve(&["::ffff:203.0.113.9"], 1).unwrap(),
            ip("203.0.113.9")
        );
    }

    /// Fewer entries than trusted hops means a proxy is missing or
    /// bypassed: nobody is attributed, the request is refused.
    #[test]
    fn too_few_entries_are_refused() {
        for (lines, hops) in [
            (&[][..], 1),
            (&[""][..], 1),
            (&["203.0.113.9"][..], 2),
            (&["203.0.113.9", "10.0.0.1"][..], 3),
        ] {
            let e = resolve(lines, hops).unwrap_err();
            assert_eq!(e.reason, Reason::ForwardedForInvalid, "{lines:?} {hops}");
        }
    }

    /// Every trusted entry must be a bare address; the left-hand ones are
    /// not looked at.
    #[test]
    fn a_trusted_entry_that_is_not_a_bare_address_is_refused() {
        for bad in [
            "203.0.113.9:1234",
            "[2001:db8::1]",
            "[2001:db8::1]:443",
            "unknown",
            "_hidden",
            "203.0.113.9 extra",
            "01.2.3.4",
            "fe80::1%eth0",
            "203.0.113.9,",
            "",
        ] {
            let e = resolve(&[bad], 1).unwrap_err();
            assert_eq!(e.reason, Reason::ForwardedForInvalid, "{bad:?}");
            let e = resolve(&[&format!("{bad}, 10.0.0.1")], 2).unwrap_err();
            assert_eq!(e.reason, Reason::ForwardedForInvalid, "{bad:?} as hop 2");
        }
        assert_eq!(
            resolve(&["garbage, unknown, 203.0.113.9"], 1).unwrap(),
            ip("203.0.113.9")
        );
    }

    #[test]
    fn a_header_over_the_cap_is_refused() {
        let padding = "1.1.1.1, ".repeat(MAX_BYTES / 8);
        let e = resolve(&[&format!("{padding}203.0.113.9")], 1).unwrap_err();
        assert_eq!(e.reason, Reason::ForwardedForInvalid);
        let padding = "1.1.1.1, ".repeat(MAX_BYTES / 16);
        assert_eq!(
            resolve(&[&format!("{padding}203.0.113.9")], 1).unwrap(),
            ip("203.0.113.9")
        );
    }
}
