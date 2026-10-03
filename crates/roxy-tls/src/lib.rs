//! TLS for roxy (`DESIGN.md` §9).
//!
//! * [`Ca`]: the certificate authority (generation, persistence, strict reload).
//! * [`LeafMinter`]: on-demand leaf certificates signed by the CA, cached.
//! * [`server_config_for`] / [`client_config`]: rustls configurations for the
//!   client-facing and upstream sides. Only the `ring` provider is used.
//! * [`sniff()`]: a pure `ClientHello` parser (SNI and ALPN).

mod ca;
mod config;
mod leaf;
mod sniff;

pub use ca::{CA_CERT_FILE, CA_KEY_FILE, Ca, CaError};
pub use config::{
    MinTlsVersion, TlsError, UpstreamTlsOptions, client_config, install_crypto_provider,
    server_config_for, server_name_for_host,
};
pub use leaf::{LeafError, LeafMinter};
pub use sniff::{ClientHelloInfo, MAX_HELLO_BYTES, Sniff, looks_like_http, sniff};

/// Re-exported so callers need not depend on rustls-pki-types directly.
pub use rustls_pki_types::ServerName;
