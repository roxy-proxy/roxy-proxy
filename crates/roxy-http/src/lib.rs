//! Canonical HTTP model and strict codecs for roxy.
//!
//! Responsibilities (see `DESIGN.md` §3 and §5): the canonical request/response
//! model, the strict HTTP/1.1 server-side codec, the HTTP/2 ↔ canonical
//! mapping, URL normalisation, body framing with size caps, hyper interop for
//! the upstream side, and the WebSocket handshake check.
//!
//! This crate performs no network I/O of its own (it works over any
//! `AsyncRead + AsyncWrite`) and carries no policy; it is fully unit- and
//! fuzz-testable.
//!
//! Modules:
//! - [`model`]: `CanonicalRequest`, `CanonicalResponse`, `Headers`, `Body`,
//!   `Limits`, `HttpFlags`, `ParseError` / `Reason`.
//! - [`url`]: §5.4 normaliser.
//! - [`h1`]: client-facing HTTP/1.1 server codec (`ServerConn`).
//! - [`h2map`]: h2 request parts ↔ canonical model.
//! - [`upstream`]: canonical ↔ hyper client types.
//! - [`ws`]: WebSocket upgrade handshake validation (relay tier).

mod chars;
pub mod h1;
pub mod model;
pub mod url;

pub use model::*;
