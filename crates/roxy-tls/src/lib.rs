//! TLS for roxy (`DESIGN.md` §9).
//!
//! M0 provides the certificate authority: generation, persistence and
//! strict reloading ([`Ca`]). Leaf minting and its cache, the rustls
//! client/server config builders and the `ClientHello` sniffer arrive in M1 and
//! build on [`Ca::issuer`].

mod ca;

pub use ca::{CA_CERT_FILE, CA_KEY_FILE, Ca, CaError};
