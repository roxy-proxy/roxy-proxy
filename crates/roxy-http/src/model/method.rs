//! Request methods.

use std::fmt;

use super::error::{ParseError, Reason, reject};
use crate::chars::is_tchar;

/// Longest method token accepted. No registered method is close to this.
const MAX_METHOD_LEN: usize = 32;

/// A validated request method. Methods are case-sensitive (RFC 9110 §9.1),
/// so `get` is an [`Method::Extension`], not [`Method::Get`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Method {
    /// `GET`
    Get,
    /// `HEAD`
    Head,
    /// `POST`
    Post,
    /// `PUT`
    Put,
    /// `DELETE`
    Delete,
    /// `CONNECT`
    Connect,
    /// `OPTIONS`
    Options,
    /// `TRACE`
    Trace,
    /// `PATCH`
    Patch,
    /// Any other valid `token`.
    Extension(String),
}

impl Method {
    /// Parses and validates a method token.
    pub fn parse(raw: &[u8]) -> Result<Method, ParseError> {
        if raw.is_empty() || raw.len() > MAX_METHOD_LEN || !raw.iter().all(|&b| is_tchar(b)) {
            return reject(
                Reason::InvalidMethod,
                format!("method {:?}", String::from_utf8_lossy(raw)),
            );
        }
        Ok(match raw {
            b"GET" => Method::Get,
            b"HEAD" => Method::Head,
            b"POST" => Method::Post,
            b"PUT" => Method::Put,
            b"DELETE" => Method::Delete,
            b"CONNECT" => Method::Connect,
            b"OPTIONS" => Method::Options,
            b"TRACE" => Method::Trace,
            b"PATCH" => Method::Patch,
            // tchar is ASCII, so this cannot fail.
            other => Method::Extension(String::from_utf8_lossy(other).into_owned()),
        })
    }

    /// The method token.
    pub fn as_str(&self) -> &str {
        match self {
            Method::Get => "GET",
            Method::Head => "HEAD",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
            Method::Connect => "CONNECT",
            Method::Options => "OPTIONS",
            Method::Trace => "TRACE",
            Method::Patch => "PATCH",
            Method::Extension(s) => s,
        }
    }

    /// Safe methods per RFC 9110 §9.2.1.
    pub fn is_safe(&self) -> bool {
        matches!(
            self,
            Method::Get | Method::Head | Method::Options | Method::Trace
        )
    }

    /// Whether a request body is permitted. POST/PUT/PATCH and extension
    /// methods always; GET/HEAD/DELETE/OPTIONS/TRACE only when
    /// `allow_body_on_get`. CONNECT never carries a body.
    pub fn allows_body(&self, allow_body_on_get: bool) -> bool {
        match self {
            Method::Post | Method::Put | Method::Patch | Method::Extension(_) => true,
            Method::Connect => false,
            Method::Get | Method::Head | Method::Delete | Method::Options | Method::Trace => {
                allow_body_on_get
            }
        }
    }

    /// Converts to an [`http::Method`].
    pub fn to_http(&self) -> http::Method {
        match self {
            Method::Get => http::Method::GET,
            Method::Head => http::Method::HEAD,
            Method::Post => http::Method::POST,
            Method::Put => http::Method::PUT,
            Method::Delete => http::Method::DELETE,
            Method::Connect => http::Method::CONNECT,
            Method::Options => http::Method::OPTIONS,
            Method::Trace => http::Method::TRACE,
            Method::Patch => http::Method::PATCH,
            // Validated as a token, which http::Method accepts.
            Method::Extension(s) => {
                http::Method::from_bytes(s.as_bytes()).unwrap_or(http::Method::GET)
            }
        }
    }

    /// Converts from an [`http::Method`], re-validating the token.
    pub fn from_http(m: &http::Method) -> Result<Method, ParseError> {
        Method::parse(m.as_str().as_bytes())
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_known_and_extension() {
        assert_eq!(Method::parse(b"GET").unwrap(), Method::Get);
        assert_eq!(
            Method::parse(b"PROPFIND").unwrap(),
            Method::Extension("PROPFIND".into())
        );
        assert_eq!(
            Method::parse(b"get").unwrap(),
            Method::Extension("get".into())
        );
        for bad in [
            &b""[..],
            b"GE T",
            b"G\x00T",
            b"G\xc3\xa9T",
            b"GET(",
            b"[GET]",
        ] {
            assert_eq!(
                Method::parse(bad).unwrap_err().reason,
                Reason::InvalidMethod
            );
        }
        assert_eq!(
            Method::parse(&[b'A'; 33]).unwrap_err().reason,
            Reason::InvalidMethod
        );
    }

    #[test]
    fn body_rules() {
        assert!(Method::Post.allows_body(false));
        assert!(Method::Extension("X".into()).allows_body(false));
        assert!(!Method::Get.allows_body(false));
        assert!(Method::Get.allows_body(true));
        assert!(!Method::Connect.allows_body(true));
        assert!(Method::Get.is_safe());
        assert!(!Method::Post.is_safe());
    }

    #[test]
    fn http_round_trip() {
        for m in ["GET", "PATCH", "PROPFIND"] {
            let ours = Method::parse(m.as_bytes()).unwrap();
            assert_eq!(ours.to_http().as_str(), m);
            assert_eq!(Method::from_http(&ours.to_http()).unwrap(), ours);
        }
    }
}
