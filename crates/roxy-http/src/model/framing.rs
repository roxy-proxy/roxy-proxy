//! Request body framing rules shared by the HTTP/1.1 and HTTP/2 fronts.

use super::error::{ParseError, Reason, reject};
use super::limits::{HttpFlags, Limits};
use super::method::Method;

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

/// How a request body arriving as a stream of frames (h2 DATA, a layer's
/// body) is to be wrapped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BodyPlan {
    /// Bytes the stream may carry before it is cut (`0` for a bodiless
    /// method, so stray data is an error rather than a body).
    pub cap: u64,
    /// The length the body is known to have, if any.
    pub known: Option<u64>,
}

/// Applies the body policy to a declared `content-length` and whether the
/// stream already ended with the head: a bodiless method may not declare a
/// body, a declared length is held to `limits.max_request_body_bytes`, and
/// the body of a bodiless method or an ended stream is known to be empty.
pub(crate) fn plan_body(
    method: &Method,
    content_length: Option<u64>,
    end_stream: bool,
    limits: &Limits,
    flags: &HttpFlags,
) -> Result<BodyPlan, ParseError> {
    let bodiless = !method.allows_body(flags.allow_body_on_get);
    if bodiless && content_length.is_some_and(|n| n > 0) {
        return reject(Reason::BodyOnBodiless, format!("body on {method} request"));
    }
    if let Some(n) = content_length
        && n > limits.max_request_body_bytes
    {
        return reject(Reason::BodyTooLarge, format!("content-length {n}"));
    }
    Ok(BodyPlan {
        cap: if bodiless {
            0
        } else {
            limits.max_request_body_bytes
        },
        known: if bodiless || end_stream {
            Some(0)
        } else {
            content_length
        },
    })
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

    #[test]
    fn body_policy() {
        let l = Limits {
            max_request_body_bytes: 10,
            ..Limits::default()
        };
        let f = HttpFlags::default();
        assert_eq!(
            plan_body(&Method::Get, Some(1), false, &l, &f)
                .unwrap_err()
                .reason,
            Reason::BodyOnBodiless
        );
        assert_eq!(
            plan_body(&Method::Post, Some(11), false, &l, &f)
                .unwrap_err()
                .reason,
            Reason::BodyTooLarge
        );
        assert_eq!(
            plan_body(&Method::Get, Some(0), false, &l, &f).unwrap(),
            BodyPlan {
                cap: 0,
                known: Some(0)
            }
        );
        assert_eq!(
            plan_body(&Method::Post, Some(5), true, &l, &f).unwrap(),
            BodyPlan {
                cap: 10,
                known: Some(0)
            }
        );
        assert_eq!(
            plan_body(&Method::Post, None, false, &l, &f).unwrap(),
            BodyPlan {
                cap: 10,
                known: None
            }
        );
        let lax = HttpFlags {
            allow_body_on_get: true,
            ..HttpFlags::default()
        };
        assert_eq!(
            plan_body(&Method::Get, Some(3), false, &l, &lax)
                .unwrap()
                .known,
            Some(3)
        );
    }
}
