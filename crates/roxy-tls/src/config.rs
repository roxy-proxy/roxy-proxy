//! rustls configurations for both sides of the proxy (ring provider only).
//!
//! # Per-connection SNI default
//!
//! rustls hands a `ResolvesServerCert` only the `ClientHello`, so a shared
//! config cannot know the CONNECT host when the client omits SNI. Rather than
//! smuggling a hint through a shared `Mutex`, [`server_config_for`] builds a
//! tiny per-connection `ServerConfig`: a handful of `Arc` clones and one small
//! allocation (no crypto, no key parsing; the provider and the leaf cache are
//! shared), with session storage and tickets disabled so nothing heavyweight is
//! allocated per connection. Resumption is therefore off, which is the right
//! trade-off for an inspecting proxy whose clients are short-lived agents.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use roxy_http::Host;
use rustls::crypto::CryptoProvider;
use rustls::server::{ClientHello, NoServerSessionStorage, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, RootCertStore, ServerConfig, SupportedProtocolVersion};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, DnsName, ServerName};

use crate::leaf::{LeafError, LeafMinter};

/// Errors building TLS configurations.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// Could not read a root certificate file.
    #[error("{}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// A root certificate file is malformed.
    #[error("invalid PEM in {}: {reason}", path.display())]
    InvalidPem { path: PathBuf, reason: String },
    /// A root certificate file contains no certificates.
    #[error("no certificates found in {}", .0.display())]
    NoCertificates(PathBuf),
    /// A certificate in a root file was rejected as a trust anchor.
    #[error("unusable root certificate in {}: {reason}", path.display())]
    InvalidRoot { path: PathBuf, reason: String },
    /// A leaf could not be minted.
    #[error(transparent)]
    Leaf(#[from] LeafError),
    /// rustls rejected the configuration.
    #[error("rustls: {0}")]
    Rustls(#[from] rustls::Error),
}

/// Minimum TLS version for upstream connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MinTlsVersion {
    /// Allow TLS 1.2 and 1.3 (default).
    #[default]
    Tls12,
    /// Allow TLS 1.3 only.
    Tls13,
}

impl MinTlsVersion {
    fn versions(self) -> &'static [&'static SupportedProtocolVersion] {
        match self {
            Self::Tls12 => rustls::ALL_VERSIONS,
            Self::Tls13 => TLS13_ONLY,
        }
    }
}

/// Options for the upstream (roxy to origin) TLS client.
///
/// Verification is always strict; there is deliberately no insecure mode.
#[derive(Debug, Clone, Default)]
pub struct UpstreamTlsOptions {
    /// PEM files with additional trusted roots (on top of `webpki-roots`).
    pub extra_roots_pem: Vec<PathBuf>,
    /// Minimum protocol version.
    pub min_version: MinTlsVersion,
}

static TLS13_ONLY: &[&SupportedProtocolVersion] = &[&rustls::version::TLS13];

fn provider() -> Arc<CryptoProvider> {
    static PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    Arc::clone(PROVIDER.get_or_init(|| Arc::new(rustls::crypto::ring::default_provider())))
}

/// Install the ring provider as the process-wide default. Idempotent; safe to
/// call from many threads and when another default is already installed.
pub fn install_crypto_provider() {
    if CryptoProvider::get_default().is_none() {
        // Losing a race to another installer is fine.
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}

/// The rustls [`ServerName`] for a canonical host.
///
/// Every name `roxy_http::url::parse_host` accepts is a valid DNS name to
/// rustls (its label rules are the stricter of the two), so this cannot fail.
pub fn server_name(host: &Host) -> ServerName<'static> {
    match host {
        Host::Dns(name) => ServerName::DnsName(
            DnsName::try_from(name.clone()).expect("a canonical host is a valid DNS name"),
        ),
        Host::Ipv4(ip) => ServerName::IpAddress((*ip).into()),
        Host::Ipv6(ip) => ServerName::IpAddress((*ip).into()),
    }
}

#[derive(Debug)]
struct Resolver {
    minter: Arc<LeafMinter>,
    default_host: Host,
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let host = match hello.server_name() {
            // An SNI that is present but invalid fails the handshake rather
            // than silently falling back.
            Some(sni) => roxy_http::url::parse_host(sni.as_bytes()).ok()?,
            None => self.default_host.clone(),
        };
        self.minter.certified_key(&host).ok()
    }
}

/// Build the client-facing config for one accepted connection.
///
/// The certificate is chosen by SNI, or `default_host` (normally the CONNECT
/// host) when the client sends no SNI. ALPN is `h2, http/1.1` if `enable_h2`
/// else `http/1.1`; TLS 1.2 and 1.3; no client authentication.
///
/// Cheap enough to call per connection (see the module docs). Minting on a
/// cache miss happens inside the handshake; warm the cache first with
/// `LeafMinter::certified_key` on the blocking pool for the default name.
pub fn server_config_for(
    minter: Arc<LeafMinter>,
    default_host: Host,
    enable_h2: bool,
) -> Arc<ServerConfig> {
    let resolver = Arc::new(Resolver {
        minter,
        default_host,
    });
    let mut cfg = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(rustls::ALL_VERSIONS)
        .expect("ring provider supports TLS 1.2 and 1.3")
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    cfg.alpn_protocols = if enable_h2 {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };
    cfg.session_storage = Arc::new(NoServerSessionStorage {});
    cfg.send_tls13_tickets = 0;
    Arc::new(cfg)
}

/// Build the upstream TLS client config: `webpki-roots` plus `extra_roots_pem`,
/// strict verification, SNI on, ALPN `h2, http/1.1`.
pub fn client_config(opts: &UpstreamTlsOptions) -> Result<Arc<ClientConfig>, TlsError> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for path in &opts.extra_roots_pem {
        add_pem_roots(&mut roots, path)?;
    }
    let mut cfg = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(opts.min_version.versions())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    cfg.enable_sni = true;
    Ok(Arc::new(cfg))
}

fn add_pem_roots(roots: &mut RootCertStore, path: &Path) -> Result<(), TlsError> {
    let pem = std::fs::read(path).map_err(|source| TlsError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut n = 0usize;
    for cert in CertificateDer::pem_slice_iter(&pem) {
        let cert = cert.map_err(|e| TlsError::InvalidPem {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })?;
        roots.add(cert).map_err(|e| TlsError::InvalidRoot {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })?;
        n += 1;
    }
    if n == 0 {
        return Err(TlsError::NoCertificates(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::Ca;
    use rustls::{ClientConnection, ServerConnection};

    fn minter() -> (Arc<Ca>, Arc<LeafMinter>) {
        let dir = tempfile::tempdir().unwrap();
        let ca = Arc::new(Ca::generate(dir.path()).unwrap());
        let m = Arc::new(LeafMinter::new(Arc::clone(&ca), 16).unwrap());
        (ca, m)
    }

    fn write_ca(ca: &Ca) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("ca.pem");
        std::fs::write(&p, ca.cert_pem()).unwrap();
        (dir, p)
    }

    /// Client trusting only the roxy CA (no webpki bundle).
    fn ca_only_client(ca: &Ca, sni: bool, min: MinTlsVersion) -> Arc<ClientConfig> {
        let (_dir, path) = write_ca(ca);
        let mut roots = RootCertStore::empty();
        add_pem_roots(&mut roots, &path).unwrap();
        let mut cfg = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(min.versions())
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        cfg.enable_sni = sni;
        Arc::new(cfg)
    }

    fn pump(
        from: &mut dyn FnMut(&mut Vec<u8>),
        to: &mut dyn FnMut(&[u8]) -> Result<(), rustls::Error>,
    ) -> Result<bool, rustls::Error> {
        let mut buf = Vec::new();
        from(&mut buf);
        if buf.is_empty() {
            return Ok(false);
        }
        to(&buf)?;
        Ok(true)
    }

    /// Drive an in-memory handshake to completion.
    fn handshake(
        client: &mut ClientConnection,
        server: &mut ServerConnection,
    ) -> Result<(), rustls::Error> {
        while client.is_handshaking() || server.is_handshaking() {
            let a = pump(
                &mut |b| {
                    while client.wants_write() {
                        client.write_tls(b).unwrap();
                    }
                },
                &mut |mut rd| {
                    while !rd.is_empty() {
                        server.read_tls(&mut rd).unwrap();
                        server.process_new_packets()?;
                    }
                    Ok(())
                },
            )?;
            let b = pump(
                &mut |b| {
                    while server.wants_write() {
                        server.write_tls(b).unwrap();
                    }
                },
                &mut |mut rd| {
                    while !rd.is_empty() {
                        client.read_tls(&mut rd).unwrap();
                        client.process_new_packets()?;
                    }
                    Ok(())
                },
            )?;
            assert!(a || b, "handshake stalled");
        }
        Ok(())
    }

    fn host(s: &str) -> Host {
        roxy_http::url::parse_host(s.as_bytes()).unwrap()
    }

    fn name(s: &str) -> ServerName<'static> {
        server_name(&host(s))
    }

    #[test]
    fn full_handshake_and_alpn() {
        install_crypto_provider();
        install_crypto_provider();
        let (ca, m) = minter();
        let client = ca_only_client(&ca, true, MinTlsVersion::Tls12);
        for (h2, want) in [(true, &b"h2"[..]), (false, &b"http/1.1"[..])] {
            let scfg = server_config_for(Arc::clone(&m), host("fallback.test"), h2);
            let mut c = ClientConnection::new(Arc::clone(&client), name("example.com")).unwrap();
            let mut s = ServerConnection::new(scfg).unwrap();
            handshake(&mut c, &mut s).unwrap();
            assert_eq!(c.alpn_protocol(), Some(want));
            assert_eq!(s.alpn_protocol(), Some(want));
            assert_eq!(s.server_name(), Some("example.com"));
        }
    }

    #[test]
    fn sniless_uses_default_name() {
        let (ca, m) = minter();
        // Client sends no SNI but expects example.com.
        let client = ca_only_client(&ca, false, MinTlsVersion::Tls12);
        let mut c = ClientConnection::new(Arc::clone(&client), name("example.com")).unwrap();
        let mut s =
            ServerConnection::new(server_config_for(Arc::clone(&m), host("example.com"), true))
                .unwrap();
        handshake(&mut c, &mut s).unwrap();
        assert_eq!(s.server_name(), None);

        // Wrong default: the client must reject the certificate.
        let mut c = ClientConnection::new(client, name("example.com")).unwrap();
        let mut s =
            ServerConnection::new(server_config_for(Arc::clone(&m), host("wrong.test"), true))
                .unwrap();
        assert!(handshake(&mut c, &mut s).is_err());

        // IP target: no SNI is sent at all, IP SAN is used.
        let client = ca_only_client(&ca, true, MinTlsVersion::Tls13);
        let mut c = ClientConnection::new(client, name("127.0.0.1")).unwrap();
        let mut s = ServerConnection::new(server_config_for(m, host("127.0.0.1"), false)).unwrap();
        handshake(&mut c, &mut s).unwrap();
        assert_eq!(s.server_name(), None);
    }

    #[test]
    fn untrusted_without_ca() {
        let (_ca, m) = minter();
        let client = client_config(&UpstreamTlsOptions::default()).unwrap();
        let mut c = ClientConnection::new(client, name("example.com")).unwrap();
        let mut s = ServerConnection::new(server_config_for(m, host("example.com"), true)).unwrap();
        assert!(handshake(&mut c, &mut s).is_err());
    }

    #[test]
    fn client_config_rejects_bad_pem() {
        let dir = tempfile::tempdir().unwrap();
        let opts = |p: PathBuf| UpstreamTlsOptions {
            extra_roots_pem: vec![p],
            min_version: MinTlsVersion::Tls12,
        };
        let bad = dir.path().join("bad.pem");
        std::fs::write(
            &bad,
            "-----BEGIN CERTIFICATE-----\n!!!notbase64!!!\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        assert!(client_config(&opts(bad)).is_err());
        let empty = dir.path().join("empty.pem");
        std::fs::write(&empty, "just text\n").unwrap();
        assert!(matches!(
            client_config(&opts(empty)),
            Err(TlsError::NoCertificates(_))
        ));
        let junk_der = dir.path().join("junk.pem");
        std::fs::write(
            &junk_der,
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        assert!(client_config(&opts(junk_der)).is_err());
        assert!(matches!(
            client_config(&opts(dir.path().join("missing.pem"))),
            Err(TlsError::Io { .. })
        ));
    }

    #[test]
    fn min_version_respected() {
        let (ca, m) = minter();
        let (_t, pem) = write_ca(&ca);
        // Server restricted to TLS 1.2.
        let mut scfg = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Resolver {
                minter: m,
                default_host: host("example.com"),
            }));
        scfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let scfg = Arc::new(scfg);

        let mk = |min| {
            client_config(&UpstreamTlsOptions {
                extra_roots_pem: vec![pem.clone()],
                min_version: min,
            })
            .unwrap()
        };
        let mut c = ClientConnection::new(mk(MinTlsVersion::Tls12), name("example.com")).unwrap();
        let mut s = ServerConnection::new(Arc::clone(&scfg)).unwrap();
        handshake(&mut c, &mut s).unwrap();
        assert_eq!(c.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_2));

        let mut c = ClientConnection::new(mk(MinTlsVersion::Tls13), name("example.com")).unwrap();
        let mut s = ServerConnection::new(scfg).unwrap();
        assert!(handshake(&mut c, &mut s).is_err());
    }

    #[test]
    fn provided_sub_ca_chains_to_root() {
        use crate::ca::tests::{ca_named, make_ca, write_provided};
        let dir = tempfile::tempdir().unwrap();
        let (root_pem, root_key) = make_ca(&ca_named("Org Root"), None);
        let root = rcgen::Issuer::from_ca_cert_pem(&root_pem, root_key).unwrap();
        let (mid_pem, mid_key) = make_ca(&ca_named("Org Mid"), Some(&root));
        let mid = rcgen::Issuer::from_ca_cert_pem(&mid_pem, mid_key).unwrap();
        let (sub_pem, sub_key) = make_ca(&ca_named("roxy sub-CA"), Some(&mid));
        let root_file = dir.path().join("root.pem");
        std::fs::write(&root_file, &root_pem).unwrap();
        let client = || {
            client_config(&UpstreamTlsOptions {
                extra_roots_pem: vec![root_file.clone()],
                min_version: MinTlsVersion::Tls12,
            })
            .unwrap()
        };
        let handshake_with = |bundle: &str| {
            let (cert, key) = write_provided(dir.path(), bundle, &sub_key);
            let ca = Arc::new(Ca::load_provided(&cert, &key).unwrap());
            let m = Arc::new(LeafMinter::new(ca, 4).unwrap());
            let mut c = ClientConnection::new(client(), name("example.com")).unwrap();
            let mut s =
                ServerConnection::new(server_config_for(m, host("example.com"), true)).unwrap();
            handshake(&mut c, &mut s).map(|()| c.peer_certificates().unwrap().len())
        };

        // A client trusting only the root builds the chain from what roxy sends.
        assert_eq!(handshake_with(&(sub_pem.clone() + &mid_pem)).unwrap(), 3);
        // Without the intermediate it cannot.
        assert!(handshake_with(&sub_pem).is_err());
    }

    /// A canonical host maps onto rustls's name type without re-parsing.
    #[test]
    fn server_name_of_canonical_host() {
        assert!(matches!(
            server_name(&host("Example.COM.")),
            ServerName::DnsName(d) if d.as_ref() == "example.com"
        ));
        assert!(matches!(
            server_name(&host("a_b.example")),
            ServerName::DnsName(d) if d.as_ref() == "a_b.example"
        ));
        assert!(matches!(
            server_name(&host("[::1]")),
            ServerName::IpAddress(_)
        ));
    }
}
