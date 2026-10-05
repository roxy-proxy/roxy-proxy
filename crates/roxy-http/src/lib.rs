//! Canonical HTTP model and strict codecs for roxy.
//!
//! Responsibilities: the canonical request/response
//! model, the strict HTTP/1.1 server-side codec, the HTTP/2 ↔ canonical
//! mapping, URL normalisation, body framing with size caps, hyper interop for
//! the upstream side, and the WebSocket handshake check and frame codec.
//!
//! This crate performs no network I/O of its own (it works over any
//! `AsyncRead + AsyncWrite`) and carries no policy; it is fully unit- and
//! fuzz-testable.
//!
//! Modules:
//! - [`model`]: `CanonicalRequest`, `CanonicalResponse`, `Headers`, `Body`,
//!   `Limits`, `HttpFlags`, `ParseError` / `Reason`.
//! - [`url`]: the URL normaliser.
//! - [`coding`]: bounded content-coding decoders.
//! - [`h1`]: client-facing HTTP/1.1 server codec (`ServerConn`).
//! - [`h2map`]: h2 request parts ↔ canonical model.
//! - [`upstream`]: canonical ↔ hyper client types.
//! - [`ws`]: WebSocket upgrade handshake validation and the frame codec.

// Casts go through `From` / `TryFrom`, so a narrowing one cannot slip in.
#![warn(clippy::as_conversions)]

mod chars;
pub mod coding;
pub mod h1;
pub mod h2map;
pub mod layer;
pub mod model;
pub mod upstream;
pub mod url;
pub mod ws;

pub use model::*;

/// A length as `u64`. `usize` is at most 64 bits on every target roxy
/// builds for; it saturates otherwise.
pub(crate) fn len_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}
