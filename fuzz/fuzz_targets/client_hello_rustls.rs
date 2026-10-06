//! Differential check of the `ClientHello` sniffer (`roxy-tls::sniff`)
//! against rustls.
//!
//! Invariant: when `sniff` accepts the input as `Tls(info)` and a rustls
//! server gets as far as choosing a certificate for the same bytes, the SNI
//! rustls acts on is the host roxy keys on: `info.sni` as a canonical
//! `Host::Dns`, or no name when it is an IP literal (rustls ignores those).
//! rustls rejecting the hello is fine; the two only have to agree on
//! handshakes that complete. A name `parse_host` rejects is never handed to
//! rustls by roxy, so the property makes no claim about it.
#![no_main]

use std::sync::{Arc, Mutex};

use libfuzzer_sys::fuzz_target;
use roxy_http::Host;
use roxy_http::url::parse_host;
use roxy_tls::{ClientHelloInfo, MAX_HELLO_BYTES, Sniff, sniff};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ServerConfig, ServerConnection};

/// Records the SNI rustls hands to its certificate resolver.
#[derive(Debug, Default)]
struct RecordSni(Mutex<Option<Option<String>>>);

impl ResolvesServerCert for RecordSni {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        *self.0.lock().unwrap() = Some(hello.server_name().map(str::to_owned));
        None
    }
}

/// What a rustls server makes of `bytes`: `None` if it rejects them before
/// choosing a certificate, else the SNI it acts on.
fn rustls_sni(bytes: &[u8]) -> Option<Option<String>> {
    let recorder = Arc::new(RecordSni::default());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(recorder.clone());
    let mut conn = ServerConnection::new(Arc::new(cfg)).unwrap();
    let mut cursor = bytes;
    while !cursor.is_empty() {
        if matches!(conn.read_tls(&mut cursor), Ok(0) | Err(_))
            || conn.process_new_packets().is_err()
        {
            break;
        }
    }
    recorder.0.lock().unwrap().clone()
}

/// The SNI rustls must act on for a hello the sniffer accepted, or `None`
/// when roxy rejects the sniffed name itself.
fn expected_rustls_sni(info: &ClientHelloInfo) -> Option<Option<String>> {
    let Some(sni) = &info.sni else {
        return Some(None);
    };
    match parse_host(sni.as_bytes()) {
        Ok(Host::Dns(name)) => Some(Some(name)),
        Ok(Host::Ipv4(_) | Host::Ipv6(_)) => Some(None),
        Err(_) => None,
    }
}

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_HELLO_BYTES + 64)];
    if let Sniff::Tls(info) = sniff(data)
        && let Some(expected) = expected_rustls_sni(&info)
        && let Some(got) = rustls_sni(data)
    {
        assert_eq!(got, expected, "sniffed {info:?}");
    }
});
