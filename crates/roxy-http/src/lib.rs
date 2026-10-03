//! Canonical HTTP model and strict codecs for roxy.
//!
//! Responsibilities (see `DESIGN.md` §3 and §5): the canonical request/response
//! model, the strict HTTP/1.1 codec, the HTTP/2 ↔ canonical mapping, URL
//! normalisation, body framing with size caps, and the WebSocket frame codec.
//!
//! This crate performs no network I/O and carries no policy; it is fully
//! unit- and fuzz-testable. It is filled in during milestone M1.
