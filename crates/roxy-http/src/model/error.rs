//! Error types: parse rejections with stable reason codes, body errors and
//! connection write errors.

use std::fmt;

use http::StatusCode;

/// Stable rejection reason. Every rejection rule maps to
/// exactly one variant; [`Reason::as_str`] is the stable snake-case code used
/// in `parse_error` flow events and alerting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    // ----- request line -----
    /// Method is not a valid `token`.
    InvalidMethod,
    /// Request line is not `method SP target SP version`.
    BadRequestLine,
    /// Request target is syntactically invalid (asterisk-form, CONNECT target
    /// that is not authority-form, empty, ...).
    BadRequestTarget,
    /// Request-target form does not match the context: absolute-form inside a
    /// tunnel, CONNECT off the proxy port, origin-form CONNECT, ...
    TargetFormMismatch,
    /// Version is not `HTTP/1.1` (or `HTTP/1.0` when allowed).
    UnsupportedVersion,
    // ----- line structure -----
    /// CR not followed by LF anywhere in the head (or chunk framing).
    BareCr,
    /// LF not preceded by CR anywhere in the head (or chunk framing).
    BareLf,
    /// Byte `>= 0x80` in the request line, a header name, or (unless
    /// `http.allow_obs_text`) a header value; or raw Unicode in a host.
    NonAscii,
    // ----- limits -----
    /// Head larger than `limits.max_header_bytes`.
    HeadTooLarge,
    /// Request target longer than `limits.max_url_bytes`.
    UrlTooLong,
    /// More than `limits.max_headers` header fields.
    TooManyHeaders,
    /// Body larger than `limits.max_request_body_bytes`.
    BodyTooLarge,
    // ----- header fields -----
    /// Header name is not a `token` (or is empty, or there is no colon).
    InvalidHeaderName,
    /// Whitespace between the header name and the colon.
    WhitespaceBeforeColon,
    /// Obsolete line folding (header line starting with SP/HTAB).
    ObsFold,
    /// Header value contains NUL, DEL or another control character.
    InvalidHeaderValue,
    /// Attempt to insert a hop-by-hop or framing header (`connection`,
    /// `content-length`, `host`, ...) into a canonical header set.
    ReservedHeader,
    /// `Connection` header value is not a comma-separated list of tokens.
    BadConnectionHeader,
    // ----- host / authority -----
    /// No `Host` header where one is required.
    MissingHost,
    /// More than one `Host` header.
    MultipleHost,
    /// More than one `Proxy-Authorization` header.
    MultipleProxyAuthorization,
    /// `Host` does not equal the absolute-form authority, the tunnel
    /// authority, or (h2) `:authority`.
    HostMismatch,
    /// Authority (host or port) is malformed.
    BadAuthority,
    /// h2 `:authority` does not equal the SNI / tunnel authority.
    AuthorityMismatch,
    // ----- framing -----
    /// More than one `Content-Length` field (even with equal values).
    DuplicateContentLength,
    /// `Content-Length` is not 1-19 ASCII digits.
    BadContentLength,
    /// `Transfer-Encoding` is anything other than a single `chunked`.
    BadTransferEncoding,
    /// Both `Content-Length` and `Transfer-Encoding` present.
    ClAndTe,
    /// Non-zero (or chunked) body on GET/HEAD/DELETE/OPTIONS/CONNECT/TRACE.
    BodyOnBodiless,
    /// `Expect` other than `100-continue` (answer `417`).
    BadExpect,
    /// Chunk size is not 1-16 hex digits.
    BadChunkSize,
    /// Chunk extension present while `http.allow_chunk_extensions` is false.
    ChunkExtension,
    /// Trailer section present while `http.allow_trailers` is false, or a
    /// forbidden field inside allowed trailers.
    Trailers,
    /// Missing CRLF after chunk data.
    BadChunkFraming,
    // ----- URL -----
    /// Path contains a character outside `pchar` / `/`, or does not start
    /// with `/`.
    InvalidPath,
    /// Query contains a character outside the allowed set.
    InvalidQuery,
    /// Dot segments climb above the root.
    PathClimbsAboveRoot,
    /// `%` not followed by two hex digits.
    BadPercentEncoding,
    /// `#` in the request target.
    FragmentInTarget,
    // ----- timing / transport -----
    /// Head not received within `limits.header_timeout`.
    HeaderTimeout,
    /// No body progress within `limits.body_idle_timeout`.
    BodyTimeout,
    /// Peer closed the connection mid-head or mid-body.
    UnexpectedEof,
    /// Transport read error.
    Io,
    // ----- HTTP/2 -----
    /// Connection-specific header in an h2 request (RFC 9113 §8.2.2).
    H2ConnectionHeader,
    /// `te` with a value other than `trailers`.
    H2BadTe,
    /// Missing or malformed pseudo-header.
    H2BadPseudoHeader,
    /// `:scheme` is not `https`.
    H2BadScheme,
    /// h2 CONNECT (including RFC 8441 extended CONNECT) is unsupported.
    H2UnsupportedMethod,
    // ----- WebSocket -----
    /// WebSocket upgrade request or `101` response is invalid.
    WsBadHandshake,
    // ----- API misuse -----
    /// Connection API used out of order (caller bug, not a client fault).
    InvalidState,
}

impl Reason {
    /// Every reason, for exhaustive tests and documentation.
    pub const ALL: &'static [Reason] = &[
        Reason::InvalidMethod,
        Reason::BadRequestLine,
        Reason::BadRequestTarget,
        Reason::TargetFormMismatch,
        Reason::UnsupportedVersion,
        Reason::BareCr,
        Reason::BareLf,
        Reason::NonAscii,
        Reason::HeadTooLarge,
        Reason::UrlTooLong,
        Reason::TooManyHeaders,
        Reason::BodyTooLarge,
        Reason::InvalidHeaderName,
        Reason::WhitespaceBeforeColon,
        Reason::ObsFold,
        Reason::InvalidHeaderValue,
        Reason::ReservedHeader,
        Reason::BadConnectionHeader,
        Reason::MissingHost,
        Reason::MultipleHost,
        Reason::MultipleProxyAuthorization,
        Reason::HostMismatch,
        Reason::BadAuthority,
        Reason::AuthorityMismatch,
        Reason::DuplicateContentLength,
        Reason::BadContentLength,
        Reason::BadTransferEncoding,
        Reason::ClAndTe,
        Reason::BodyOnBodiless,
        Reason::BadExpect,
        Reason::BadChunkSize,
        Reason::ChunkExtension,
        Reason::Trailers,
        Reason::BadChunkFraming,
        Reason::InvalidPath,
        Reason::InvalidQuery,
        Reason::PathClimbsAboveRoot,
        Reason::BadPercentEncoding,
        Reason::FragmentInTarget,
        Reason::HeaderTimeout,
        Reason::BodyTimeout,
        Reason::UnexpectedEof,
        Reason::Io,
        Reason::H2ConnectionHeader,
        Reason::H2BadTe,
        Reason::H2BadPseudoHeader,
        Reason::H2BadScheme,
        Reason::H2UnsupportedMethod,
        Reason::WsBadHandshake,
        Reason::InvalidState,
    ];

    /// Stable snake-case code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Reason::InvalidMethod => "invalid_method",
            Reason::BadRequestLine => "bad_request_line",
            Reason::BadRequestTarget => "bad_request_target",
            Reason::TargetFormMismatch => "target_form_mismatch",
            Reason::UnsupportedVersion => "unsupported_version",
            Reason::BareCr => "bare_cr",
            Reason::BareLf => "bare_lf",
            Reason::NonAscii => "non_ascii",
            Reason::HeadTooLarge => "head_too_large",
            Reason::UrlTooLong => "url_too_long",
            Reason::TooManyHeaders => "too_many_headers",
            Reason::BodyTooLarge => "body_too_large",
            Reason::InvalidHeaderName => "invalid_header_name",
            Reason::WhitespaceBeforeColon => "whitespace_before_colon",
            Reason::ObsFold => "obs_fold",
            Reason::InvalidHeaderValue => "invalid_header_value",
            Reason::ReservedHeader => "reserved_header",
            Reason::BadConnectionHeader => "bad_connection_header",
            Reason::MissingHost => "missing_host",
            Reason::MultipleHost => "multiple_host",
            Reason::MultipleProxyAuthorization => "multiple_proxy_authorization",
            Reason::HostMismatch => "host_mismatch",
            Reason::BadAuthority => "bad_authority",
            Reason::AuthorityMismatch => "authority_mismatch",
            Reason::DuplicateContentLength => "duplicate_content_length",
            Reason::BadContentLength => "bad_content_length",
            Reason::BadTransferEncoding => "bad_transfer_encoding",
            Reason::ClAndTe => "cl_and_te",
            Reason::BodyOnBodiless => "body_on_bodiless_method",
            Reason::BadExpect => "bad_expect",
            Reason::BadChunkSize => "bad_chunk_size",
            Reason::ChunkExtension => "chunk_extension",
            Reason::Trailers => "trailers",
            Reason::BadChunkFraming => "bad_chunk_framing",
            Reason::InvalidPath => "invalid_path",
            Reason::InvalidQuery => "invalid_query",
            Reason::PathClimbsAboveRoot => "path_climbs_above_root",
            Reason::BadPercentEncoding => "bad_percent_encoding",
            Reason::FragmentInTarget => "fragment_in_target",
            Reason::HeaderTimeout => "header_timeout",
            Reason::BodyTimeout => "body_timeout",
            Reason::UnexpectedEof => "unexpected_eof",
            Reason::Io => "io_error",
            Reason::H2ConnectionHeader => "h2_connection_header",
            Reason::H2BadTe => "h2_bad_te",
            Reason::H2BadPseudoHeader => "h2_bad_pseudo_header",
            Reason::H2BadScheme => "h2_bad_scheme",
            Reason::H2UnsupportedMethod => "h2_unsupported_method",
            Reason::WsBadHandshake => "ws_bad_handshake",
            Reason::InvalidState => "invalid_state",
        }
    }

    /// Looks a reason up by its stable code.
    pub fn from_code(code: &str) -> Option<Reason> {
        Reason::ALL.iter().copied().find(|r| r.as_str() == code)
    }

    /// The status roxy should answer with before closing, if it answers at
    /// all.
    pub fn suggested_status(self) -> StatusCode {
        match self {
            Reason::HeadTooLarge | Reason::TooManyHeaders => {
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
            }
            Reason::UrlTooLong => StatusCode::URI_TOO_LONG,
            Reason::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Reason::BadExpect => StatusCode::EXPECTATION_FAILED,
            Reason::UnsupportedVersion => StatusCode::HTTP_VERSION_NOT_SUPPORTED,
            Reason::HeaderTimeout | Reason::BodyTimeout => StatusCode::REQUEST_TIMEOUT,
            Reason::InvalidState => StatusCode::INTERNAL_SERVER_ERROR,
            Reason::InvalidMethod
            | Reason::BadRequestLine
            | Reason::BadRequestTarget
            | Reason::TargetFormMismatch
            | Reason::BareCr
            | Reason::BareLf
            | Reason::NonAscii
            | Reason::InvalidHeaderName
            | Reason::WhitespaceBeforeColon
            | Reason::ObsFold
            | Reason::InvalidHeaderValue
            | Reason::ReservedHeader
            | Reason::BadConnectionHeader
            | Reason::MissingHost
            | Reason::MultipleHost
            | Reason::MultipleProxyAuthorization
            | Reason::HostMismatch
            | Reason::BadAuthority
            | Reason::AuthorityMismatch
            | Reason::DuplicateContentLength
            | Reason::BadContentLength
            | Reason::BadTransferEncoding
            | Reason::ClAndTe
            | Reason::BodyOnBodiless
            | Reason::BadChunkSize
            | Reason::ChunkExtension
            | Reason::Trailers
            | Reason::BadChunkFraming
            | Reason::InvalidPath
            | Reason::InvalidQuery
            | Reason::PathClimbsAboveRoot
            | Reason::BadPercentEncoding
            | Reason::FragmentInTarget
            | Reason::UnexpectedEof
            | Reason::Io
            | Reason::H2ConnectionHeader
            | Reason::H2BadTe
            | Reason::H2BadPseudoHeader
            | Reason::H2BadScheme
            | Reason::H2UnsupportedMethod
            | Reason::WsBadHandshake => StatusCode::BAD_REQUEST,
        }
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A rejection of client input. The connection must be closed after one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{reason}: {detail}")]
pub struct ParseError {
    /// Stable reason code.
    pub reason: Reason,
    /// Human-readable detail for logs. Never sent to the client.
    pub detail: String,
}

impl ParseError {
    /// Creates a parse error.
    pub fn new(reason: Reason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }
}

/// Shorthand for `Err(ParseError::new(..))`.
pub(crate) fn reject<T>(reason: Reason, detail: impl Into<String>) -> Result<T, ParseError> {
    Err(ParseError::new(reason, detail))
}

/// Error carried by a [`crate::Body`] stream.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BodyError {
    /// More bytes than the configured cap.
    #[error("body exceeds the {limit} byte cap")]
    TooLarge {
        /// The cap that was exceeded.
        limit: u64,
    },
    /// The body does not match its declared length.
    #[error("body length does not match the declared length")]
    LengthMismatch,
    /// The producer went away before the body was complete. A truncated body
    /// is never presented as complete.
    #[error("body ended before it was complete")]
    Incomplete,
    /// The consumer dropped the body.
    #[error("body receiver dropped")]
    Closed,
    /// No progress within the idle timeout.
    #[error("body idle timeout")]
    Timeout,
    /// The client sent an invalid body (bad chunk framing, ...).
    #[error("invalid request body: {0}")]
    Invalid(ParseError),
    /// The upstream body stream failed.
    #[error("upstream body error: {0}")]
    Upstream(String),
    /// The exchange was stopped by policy (a watching rule matched, or its
    /// evaluation failed closed). The body is cut where it stood.
    #[error("stopped by policy")]
    Stopped,
    /// The body could not be decoded by its `content-encoding`
    /// ([`crate::coding::decode_body`]).
    #[error("body could not be decoded: {0}")]
    Undecodable(String),
}

/// Error while writing to (or driving) a client connection. After any of
/// these the connection must be dropped.
#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    /// Transport error or timeout while writing.
    #[error("write failed: {0}")]
    Io(#[from] std::io::Error),
    /// The response body failed mid-stream; the response was truncated and the
    /// connection must be closed so the client cannot mistake it for complete.
    #[error("response body failed: {0}")]
    Body(BodyError),
    /// The request body (being read concurrently) was invalid.
    #[error("request body rejected: {0}")]
    Request(ParseError),
    /// The API was used out of order.
    #[error("invalid connection state: {0}")]
    State(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn suggested_status_per_reason() {
        for (r, status) in [
            (Reason::HeadTooLarge, 431),
            (Reason::TooManyHeaders, 431),
            (Reason::UrlTooLong, 414),
            (Reason::BodyTooLarge, 413),
            (Reason::BadExpect, 417),
            (Reason::UnsupportedVersion, 505),
            (Reason::HeaderTimeout, 408),
            (Reason::BodyTimeout, 408),
            (Reason::InvalidState, 500),
            (Reason::BareCr, 400),
            (Reason::MultipleHost, 400),
            (Reason::H2BadScheme, 400),
        ] {
            assert_eq!(r.suggested_status().as_u16(), status, "{r}");
        }
    }

    #[test]
    fn codes_unique_and_round_trip() {
        let mut seen = HashSet::new();
        for r in Reason::ALL {
            assert!(seen.insert(r.as_str()), "duplicate code {r}");
            assert_eq!(Reason::from_code(r.as_str()), Some(*r));
            assert!(
                r.as_str()
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'_' || b.is_ascii_digit())
            );
        }
    }
}
