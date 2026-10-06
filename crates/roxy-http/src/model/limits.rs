//! Resource limits (`limits.*`) and HTTP strictness flags (`http.*`).

use std::time::Duration;

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const GIB: u64 = 1024 * MIB;

/// Mirrors the `limits.*` config block with the same
/// defaults. The binary builds this from config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Total request head size (request line + headers + final CRLF).
    pub max_header_bytes: usize,
    /// Request-target length.
    pub max_url_bytes: usize,
    /// Number of header fields.
    pub max_headers: usize,
    /// Request body cap, enforced while streaming.
    pub max_request_body_bytes: u64,
    /// Response body cap, enforced while streaming.
    pub max_response_body_bytes: u64,
    /// Cap for bodies buffered for inspection (`Body::collect_up_to`).
    pub max_inspect_body_bytes: u64,
    /// Cap for a request body buffered to hash it for `sign: aws_sigv4`;
    /// a larger body is refused with 413.
    pub max_sign_body_bytes: u64,
    /// Cap for a reassembled WebSocket message when rules read messages
    /// (`ws::frame::Decoder`).
    pub max_ws_message_bytes: u64,
    /// How far behind the real body an observe-mode addon's copy may fall,
    /// in buffered bytes per direction, before the copy is cut.
    pub max_observer_lag_bytes: u64,
    /// Process-wide budget for the buffers the three caps above bound:
    /// an exchange reserves each cap in full before it fills that buffer.
    pub max_buffered_bytes: u64,
    /// Deadline for receiving a complete request head once it has started
    /// (and for the first request on a connection, from accept).
    pub header_timeout: Duration,
    /// Maximum time without progress from the client: reading its request
    /// body, or writing the response to it.
    pub body_idle_timeout: Duration,
    /// Maximum wait for the upstream's next response-body frame.
    pub response_body_idle_timeout: Duration,
    /// Upstream response-head timeout (enforced by the caller).
    pub response_header_timeout: Duration,
    /// Keep-alive idle time between requests on a client connection.
    pub idle_timeout: Duration,
    /// h2 concurrent stream limit (enforced by the h2 connection wiring).
    pub h2_max_concurrent_streams: u32,
    /// h2 header list size cap per stream (also checked in `h2map`).
    pub h2_max_header_list_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_header_bytes: 64 * 1024,
            max_url_bytes: 8 * 1024,
            max_headers: 100,
            max_request_body_bytes: GIB,
            max_response_body_bytes: GIB,
            max_inspect_body_bytes: MIB,
            max_sign_body_bytes: 100 * MIB,
            max_ws_message_bytes: 16 * MIB,
            max_observer_lag_bytes: 16 * MIB,
            max_buffered_bytes: GIB,
            header_timeout: Duration::from_secs(10),
            body_idle_timeout: Duration::from_secs(30),
            response_body_idle_timeout: Duration::from_secs(300),
            response_header_timeout: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(300),
            h2_max_concurrent_streams: 100,
            h2_max_header_list_bytes: 64 * 1024,
        }
    }
}

/// The `http.*` strictness flags the codec reads. Every one defaults to
/// the strict setting (off).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct HttpFlags {
    /// Accept `HTTP/1.0` request lines.
    pub allow_http10: bool,
    /// Accept chunked trailer sections. They are forwarded to an HTTP/2
    /// upstream; a request that carries them to an HTTP/1.1 upstream is
    /// refused, since HTTP/1.1 cannot carry them without naming them up
    /// front.
    pub allow_trailers: bool,
    /// Accept (and discard) chunk extensions.
    pub allow_chunk_extensions: bool,
    /// Accept obs-text (bytes `0x80..=0xFF`) in header values.
    pub allow_obs_text: bool,
    /// Accept a body on GET/HEAD/DELETE/OPTIONS/TRACE.
    pub allow_body_on_get: bool,
}
