//! The request-head rules every entry point applies to its field list once
//! the transport has taken what is its own: the h1 codec after tokenising,
//! the h2 mapping after the pseudo-headers and connection-specific fields,
//! the layer re-validation after the URI and the fields a layer may not set.
//! One implementation, so a request is judged the same way whichever path
//! carried it.

use super::authority::Authority;
use super::error::{ParseError, Reason, reject};
use super::headers::{Headers, connection_tokens, requested_upgrade};
use super::limits::{HttpFlags, Limits};
use super::message::Version;
use super::method::Method;
use crate::chars::trim_ows;
use crate::url;

/// Parses a `Content-Length` value: 1 to 19 ASCII digits, nothing else.
pub(crate) fn parse_content_length(v: &[u8]) -> Result<u64, ParseError> {
    if v.is_empty() || v.len() > 19 || !v.iter().all(u8::is_ascii_digit) {
        return reject(
            Reason::BadContentLength,
            format!("content-length {:?}", String::from_utf8_lossy(v)),
        );
    }
    // 19 digits always fit in a u64, so this cannot fail.
    str::from_utf8(v)
        .ok()
        .and_then(|s| s.parse().ok())
        .map_or_else(
            || reject(Reason::BadContentLength, "content-length out of range"),
            Ok,
        )
}

/// What the transport knows about the body beyond the field list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BodyHint {
    /// HTTP/1.x: the body follows the head on the connection and the fields
    /// alone frame it; none means no body (RFC 9112 §6.3).
    Framed,
    /// A stream of frames (h2 DATA, a layer's body).
    Stream {
        /// The stream ended with the head: the body is empty.
        ended: bool,
        /// A length the stream itself declares (a layer's body), used when
        /// no field does.
        known_length: Option<u64>,
    },
}

/// The body as the head declares it, with the body policy applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BodyPlan {
    /// Bytes the body may carry before it is cut (`0` for a bodiless
    /// method, so stray data is an error rather than a body).
    pub cap: u64,
    /// The length the body is known to have, if any.
    pub known: Option<u64>,
    /// `Transfer-Encoding: chunked` (HTTP/1.1 only).
    pub chunked: bool,
}

/// The semantic content of a request's field list: the single `Host` to
/// resolve against the transport's target, the body plan, the hop-by-hop
/// facts roxy acts on, and the canonical headers.
#[derive(Debug)]
pub(crate) struct RequestFields<'a> {
    /// The single `Host` value, if any.
    pub host: Option<&'a [u8]>,
    /// Body framing and policy.
    pub body: BodyPlan,
    /// `Expect: 100-continue` on a request that may carry a body.
    pub expect_continue: bool,
    /// Lower-case `Connection` options.
    pub connection: Vec<String>,
    /// The protocols `Upgrade` asks for, when `Connection` nominates it.
    pub upgrade: Option<String>,
    /// Canonical headers: validated, reserved and nominated fields dropped.
    pub headers: Headers,
}

/// Values of every field named `name`, OWS-trimmed, in order.
fn all<'a>(raw: &[(&'a [u8], &'a [u8])], name: &str) -> Vec<&'a [u8]> {
    raw.iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case(name.as_bytes()))
        .map(|(_, v)| trim_ows(v))
        .collect()
}

/// Body framing from `Content-Length` / `Transfer-Encoding` and the
/// transport's hint, with the body policy applied: one `Content-Length` or
/// exactly `chunked`, never both; a declared length that agrees with a
/// stream that has ended; no body on a bodiless method; a declared length
/// within the cap.
fn plan_body(
    raw: &[(&[u8], &[u8])],
    method: &Method,
    version: Version,
    hint: BodyHint,
    limits: &Limits,
    flags: &HttpFlags,
) -> Result<BodyPlan, ParseError> {
    let cls = all(raw, "content-length");
    let tes = all(raw, "transfer-encoding");
    if !cls.is_empty() && !tes.is_empty() {
        return reject(Reason::ClAndTe, "both content-length and transfer-encoding");
    }
    if cls.len() > 1 {
        return reject(
            Reason::DuplicateContentLength,
            "multiple content-length fields",
        );
    }
    let declared = cls.first().map(|cl| parse_content_length(cl)).transpose()?;
    let chunked = match tes.as_slice() {
        [] => false,
        [te] if te.eq_ignore_ascii_case(b"chunked") => {
            if version == Version::H1_0 {
                return reject(
                    Reason::BadTransferEncoding,
                    "chunked in an HTTP/1.0 request",
                );
            }
            true
        }
        _ => {
            return reject(
                Reason::BadTransferEncoding,
                format!(
                    "transfer-encoding {:?}",
                    tes.iter()
                        .map(|t| String::from_utf8_lossy(t))
                        .collect::<Vec<_>>()
                ),
            );
        }
    };
    let (ended, length) = match hint {
        BodyHint::Framed => (false, declared),
        BodyHint::Stream {
            ended,
            known_length,
        } => (ended, declared.or(known_length)),
    };
    let bodiless = !method.allows_body(flags.allow_body_on_get);
    if bodiless && (chunked || length.is_some_and(|n| n > 0)) {
        return reject(Reason::BodyOnBodiless, format!("body on {method} request"));
    }
    if let Some(n) = length
        && n > limits.max_request_body_bytes
    {
        return reject(Reason::BodyTooLarge, format!("content-length {n}"));
    }
    if ended && length.is_some_and(|n| n > 0) {
        return reject(
            Reason::BadContentLength,
            "content-length on a body that has already ended",
        );
    }
    Ok(BodyPlan {
        cap: if bodiless {
            0
        } else {
            limits.max_request_body_bytes
        },
        known: if chunked {
            None
        } else if bodiless || ended || hint == BodyHint::Framed {
            Some(length.unwrap_or(0))
        } else {
            length
        },
        chunked,
    })
}

impl<'a> RequestFields<'a> {
    /// Applies the field rules to `raw` (names in any case, values with or
    /// without OWS): framing and body policy, `Expect`, one `Host`,
    /// `Connection` and `Upgrade`, then the header validator over the lot.
    pub(crate) fn from_raw(
        raw: &[(&'a [u8], &'a [u8])],
        method: &Method,
        version: Version,
        hint: BodyHint,
        limits: &Limits,
        flags: &HttpFlags,
    ) -> Result<Self, ParseError> {
        let body = plan_body(raw, method, version, hint, limits, flags)?;
        let expects = all(raw, "expect");
        if !expects.is_empty()
            && (expects.len() > 1 || !expects[0].eq_ignore_ascii_case(b"100-continue"))
        {
            return reject(Reason::BadExpect, "unsupported expectation");
        }
        // HTTP/1.0 has no `100 Continue`; an empty body earns none.
        let expect_continue =
            !expects.is_empty() && version != Version::H1_0 && body.known != Some(0);
        let connection = connection_tokens(all(raw, "connection"))?;
        let upgrade = requested_upgrade(&connection, all(raw, "upgrade"));
        let hosts = all(raw, "host");
        if hosts.len() > 1 {
            return reject(Reason::MultipleHost, "multiple host fields");
        }
        let headers = Headers::try_from_raw(raw.iter().copied(), limits, flags)?;
        Ok(Self {
            host: hosts.first().copied(),
            body,
            expect_continue,
            connection,
            upgrade,
            headers,
        })
    }
}

/// `host` must name `authority` (with `default_port` implied).
pub(crate) fn check_host(
    host: &[u8],
    authority: &Authority,
    default_port: u16,
    what: &str,
) -> Result<(), ParseError> {
    let ha = url::parse_authority(host, default_port)?;
    if ha != *authority {
        return reject(Reason::HostMismatch, format!("host does not match {what}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_length_syntax() {
        assert_eq!(parse_content_length(b"0").unwrap(), 0);
        assert_eq!(
            parse_content_length(b"9999999999999999999").unwrap(),
            9_999_999_999_999_999_999
        );
        for bad in [&b""[..], b"+1", b"-1", b" 1", b"1 ", b"0x1", b"1,1"] {
            assert_eq!(
                parse_content_length(bad).unwrap_err().reason,
                Reason::BadContentLength,
                "{bad:?}"
            );
        }
        assert_eq!(
            parse_content_length(b"10000000000000000000")
                .unwrap_err()
                .reason,
            Reason::BadContentLength
        );
    }

    fn plan(
        method: &Method,
        content_length: Option<&str>,
        hint: BodyHint,
        limits: &Limits,
        flags: &HttpFlags,
    ) -> Result<BodyPlan, Reason> {
        let raw: Vec<(&[u8], &[u8])> = content_length
            .map(|cl| (&b"content-length"[..], cl.as_bytes()))
            .into_iter()
            .collect();
        plan_body(&raw, method, Version::H1_1, hint, limits, flags).map_err(|e| e.reason)
    }

    const OPEN: BodyHint = BodyHint::Stream {
        ended: false,
        known_length: None,
    };
    const ENDED: BodyHint = BodyHint::Stream {
        ended: true,
        known_length: None,
    };

    #[test]
    fn body_policy() {
        let l = Limits {
            max_request_body_bytes: 10,
            ..Limits::default()
        };
        let f = HttpFlags::default();
        assert_eq!(
            plan(&Method::Get, Some("1"), OPEN, &l, &f).unwrap_err(),
            Reason::BodyOnBodiless
        );
        assert_eq!(
            plan(&Method::Post, Some("11"), OPEN, &l, &f).unwrap_err(),
            Reason::BodyTooLarge
        );
        assert_eq!(
            plan(&Method::Get, Some("0"), OPEN, &l, &f).unwrap(),
            BodyPlan {
                cap: 0,
                known: Some(0),
                chunked: false,
            }
        );
        assert_eq!(
            plan(&Method::Post, None, OPEN, &l, &f).unwrap(),
            BodyPlan {
                cap: 10,
                known: None,
                chunked: false,
            }
        );
        assert_eq!(
            plan(&Method::Post, None, ENDED, &l, &f).unwrap().known,
            Some(0)
        );
        let lax = HttpFlags {
            allow_body_on_get: true,
            ..HttpFlags::default()
        };
        assert_eq!(
            plan(&Method::Get, Some("3"), OPEN, &l, &lax).unwrap().known,
            Some(3)
        );
    }

    /// A declared length on a stream that has already ended is a
    /// contradiction, not an empty body: a layer's `content-length: 5` with
    /// no body must not go upstream as a bodiless request.
    #[test]
    fn a_declared_length_on_an_ended_stream_is_rejected() {
        let l = Limits::default();
        let f = HttpFlags::default();
        assert_eq!(
            plan(&Method::Post, Some("5"), ENDED, &l, &f).unwrap_err(),
            Reason::BadContentLength
        );
        let known = BodyHint::Stream {
            ended: true,
            known_length: Some(5),
        };
        assert_eq!(
            plan(&Method::Post, None, known, &l, &f).unwrap_err(),
            Reason::BadContentLength
        );
        assert_eq!(
            plan(&Method::Post, Some("0"), ENDED, &l, &f).unwrap().known,
            Some(0)
        );
    }

    /// Without framing fields an HTTP/1.x request has no body, where a
    /// stream's length is simply unknown.
    #[test]
    fn framed_without_fields_is_empty() {
        let l = Limits::default();
        let f = HttpFlags::default();
        assert_eq!(
            plan(&Method::Post, None, BodyHint::Framed, &l, &f)
                .unwrap()
                .known,
            Some(0)
        );
        assert_eq!(plan(&Method::Post, None, OPEN, &l, &f).unwrap().known, None);
    }
}
