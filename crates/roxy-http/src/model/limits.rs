//! Resource limits (`limits.*`) and HTTP strictness flags (`http.*`).

use std::time::Duration;

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const GIB: u64 = 1024 * MIB;

/// Mirrors the `limits.*` config block (docs/limits.md#limits) with the same
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
    /// Cap for a reassembled WebSocket message when rules read messages
    /// (`ws::frame::Decoder`).
    pub max_ws_message_bytes: u64,
    /// Deadline for receiving a complete request head once it has started
    /// (and for the first request on a connection, from accept).
    pub header_timeout: Duration,
    /// Maximum time without request-body progress (read or backpressure) and
    /// without response-write progress.
    pub body_idle_timeout: Duration,
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
            max_ws_message_bytes: 16 * MIB,
            header_timeout: Duration::from_secs(10),
            body_idle_timeout: Duration::from_secs(30),
            response_header_timeout: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(300),
            h2_max_concurrent_streams: 100,
            h2_max_header_list_bytes: 64 * 1024,
        }
    }
}

/// Mirrors the `http.*` config block. Every strictness flag defaults to the
/// strict setting; `decode_for_addons` defaults to true.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct HttpFlags {
    /// Accept `HTTP/1.0` request lines.
    pub allow_http10: bool,
    /// Accept chunked trailer sections (forwarded as trailers).
    pub allow_trailers: bool,
    /// Accept (and discard) chunk extensions.
    pub allow_chunk_extensions: bool,
    /// Accept obs-text (bytes `0x80..=0xFF`) in header values.
    pub allow_obs_text: bool,
    /// Accept a body on GET/HEAD/DELETE/OPTIONS/TRACE.
    pub allow_body_on_get: bool,
    /// Accept plaintext HTTP inside a CONNECT tunnel (used by the proxy's
    /// tunnel classifier, not by this crate).
    pub allow_plain_in_connect: bool,
    /// Remove `accept-encoding` from requests, so origins answer
    /// uncompressed (used by the proxy, not by this crate).
    pub strip_accept_encoding: bool,
    /// Decode bodies at the edge of the addon stack (used by the proxy, not
    /// by this crate). Default true.
    pub decode_for_addons: bool,
}

impl Default for HttpFlags {
    fn default() -> Self {
        Self {
            allow_http10: false,
            allow_trailers: false,
            allow_chunk_extensions: false,
            allow_obs_text: false,
            allow_body_on_get: false,
            allow_plain_in_connect: false,
            strip_accept_encoding: false,
            decode_for_addons: true,
        }
    }
}
