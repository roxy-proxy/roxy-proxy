//! Conformance harness for the roxy node protocol, with an in-memory
//! reference server. The protocol is specified in
//! `docs/pages/reference/node-protocol.md`; the body schemas it names live in
//! `spec/node-protocol/v1/` and are embedded here by [`schema`].

pub mod ca;
pub mod harness;
pub mod protocol;
pub mod reference;
pub mod schema;

mod client;

/// Path prefix shared by every endpoint.
pub const PREFIX: &str = "/roxy/v1";
/// Header carrying the node's state on a lease fetch.
pub const NODE_STATE_HEADER: &str = "roxy-node-state";
/// Headers on a `304` that extend the lease the node already holds.
pub const LEASE_VALID_FOR_HEADER: &str = "roxy-lease-valid-for";
pub const LEASE_REFRESH_AFTER_HEADER: &str = "roxy-lease-refresh-after";
/// The feature a harness node deliberately lacks, so a `require-feature`
/// hook can make the server answer `426`.
pub const UNSUPPORTED_FEATURE: &str = "conformance:unsupported";

/// `sha256:<hex>` of `bytes`, the form the spec fixes for `config_hash`.
pub fn sha256_tag(bytes: &[u8]) -> String {
    use sha2::Digest;
    use std::fmt::Write as _;
    let digest = sha2::Sha256::digest(bytes);
    let mut out = String::with_capacity(7 + 64);
    out.push_str("sha256:");
    for b in digest {
        let _ = write!(out, "{b:02x}");
    }
    out
}
