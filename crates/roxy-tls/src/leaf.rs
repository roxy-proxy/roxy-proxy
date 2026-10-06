//! On-demand leaf certificate minting with a bounded LRU cache.
//!
//! One ECDSA P-256 keypair is generated per [`LeafMinter`] and shared by every
//! leaf (as mitmproxy does): the CA key is what protects clients, and sharing
//! the leaf key makes minting a pure signing operation.
//!
//! Minting is synchronous (roughly 1 ms, dominated by the CA signature). The
//! cache lock is *not* held while minting, so concurrent misses for the same
//! name may mint twice; the last insert wins. Async callers should warm the
//! cache with `tokio::task::spawn_blocking(move || minter.certified_key(&n))`
//! before starting the handshake, so the `ResolvesServerCert` callback (which
//! runs inline in the handshake future) normally hits the cache.

use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use lru::LruCache;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SanType,
};
use rustls::crypto::ring::sign::any_ecdsa_type;
use rustls::sign::{CertifiedKey, SigningKey};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use time::{Duration, OffsetDateTime};

use crate::ca::Ca;

/// Leaf validity, cut short to the CA's `notAfter` when that comes first.
pub(crate) const LEAF_VALIDITY: Duration = Duration::days(7);
/// `notBefore` backdating for clock skew.
const LEAF_BACKDATE: Duration = Duration::hours(1);
/// Cached entries are dropped (and re-minted) within this long of expiry.
const EVICT_BEFORE_EXPIRY: Duration = Duration::hours(1);
/// Maximum DNS name length (RFC 1035 presentation form).
const MAX_DNS_NAME: usize = 253;

/// Errors from minting leaf certificates.
#[derive(Debug, thiserror::Error)]
pub enum LeafError {
    /// Not a valid DNS name or IP address.
    #[error("invalid server name {0:?}")]
    InvalidName(String),
    /// Longer than 253 bytes.
    #[error("server name too long ({0} bytes, max 253)")]
    NameTooLong(usize),
    /// Wildcard names are never minted.
    #[error("wildcard server names are not allowed: {0:?}")]
    Wildcard(String),
    /// Certificate generation failed.
    #[error("leaf certificate generation failed: {0}")]
    Generate(#[from] rcgen::Error),
    /// The shared leaf key could not be loaded into rustls.
    #[error("leaf key unusable: {0}")]
    Key(String),
    /// The system random number generator failed.
    #[error("system random number generator failed")]
    Rng,
    /// The CA certificate has expired; no leaf it signs is valid.
    #[error("CA certificate expired at {0}")]
    CaExpired(OffsetDateTime),
}

struct Entry {
    key: Arc<CertifiedKey>,
    not_after: OffsetDateTime,
}

type Cache = LruCache<ServerName<'static>, Entry>;

/// Mints and caches leaf certificates signed by the roxy CA.
pub struct LeafMinter {
    ca: Arc<Ca>,
    leaf_key: KeyPair,
    signing_key: Arc<dyn SigningKey>,
    cache: Mutex<Cache>,
    /// Seconds added to the wall clock; only non-zero in tests.
    clock_skew_secs: AtomicI64,
}

impl std::fmt::Debug for LeafMinter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeafMinter").finish_non_exhaustive()
    }
}

impl LeafMinter {
    /// Create a minter with a fresh shared leaf key and a cache of
    /// `cache_size` names (minimum 1).
    pub fn new(ca: Arc<Ca>, cache_size: usize) -> Result<Self, LeafError> {
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let signing_key = any_ecdsa_type(&der).map_err(|e| LeafError::Key(e.to_string()))?;
        let cap = NonZeroUsize::new(cache_size).unwrap_or(NonZeroUsize::MIN);
        Ok(Self {
            ca,
            leaf_key,
            signing_key,
            cache: Mutex::new(LruCache::new(cap)),
            clock_skew_secs: AtomicI64::new(0),
        })
    }

    /// The CA this minter signs with.
    pub fn ca(&self) -> &Arc<Ca> {
        &self.ca
    }

    /// Number of cached leaves.
    pub fn cached(&self) -> usize {
        self.lock().len()
    }

    /// Get (minting if needed) the certified key for `name`.
    ///
    /// The chain is `[leaf, CA, intermediates...]`. Names are validated and canonicalised
    /// (lower-cased); invalid names, names over 253 bytes and wildcards are
    /// rejected. This blocks for ~1 ms on a cache miss; see the module docs.
    pub fn certified_key(&self, name: &ServerName<'_>) -> Result<Arc<CertifiedKey>, LeafError> {
        let name = canonical_name(name)?;
        let now = self.now();
        {
            let mut cache = self.lock();
            if let Some(entry) = cache.get(&name) {
                if entry.not_after - now > EVICT_BEFORE_EXPIRY {
                    return Ok(Arc::clone(&entry.key));
                }
                cache.pop(&name);
            }
        }
        let (key, not_after) = self.mint(&name, now)?;
        let key = Arc::new(key);
        self.lock().put(
            name,
            Entry {
                key: Arc::clone(&key),
                not_after,
            },
        );
        Ok(key)
    }

    fn mint(
        &self,
        name: &ServerName<'static>,
        now: OffsetDateTime,
    ) -> Result<(CertifiedKey, OffsetDateTime), LeafError> {
        let (san, cn) = match name {
            ServerName::DnsName(dns) => {
                let s = dns.as_ref().to_owned();
                (SanType::DnsName(s.clone().try_into()?), s)
            }
            ServerName::IpAddress(ip) => {
                let ip = IpAddr::from(*ip);
                (SanType::IpAddress(ip), ip.to_string())
            }
            _ => return Err(LeafError::InvalidName(format!("{name:?}"))),
        };
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        params.distinguished_name = dn;
        params.subject_alt_names = vec![san];
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.serial_number = Some(crate::ca::random_serial().map_err(|_| LeafError::Rng)?);
        // A leaf that outlives its CA is rejected by every client.
        let not_after = (now + LEAF_VALIDITY).min(self.ca.not_after());
        if not_after <= now {
            return Err(LeafError::CaExpired(self.ca.not_after()));
        }
        params.not_before = now - LEAF_BACKDATE;
        params.not_after = not_after;
        let cert = params.signed_by(&self.leaf_key, self.ca.issuer())?;
        let chain: Vec<CertificateDer<'static>> = [cert.der(), self.ca.certificate()]
            .into_iter()
            .chain(self.ca.chain())
            .cloned()
            .collect();
        Ok((
            CertifiedKey::new(chain, Arc::clone(&self.signing_key)),
            not_after,
        ))
    }

    fn lock(&self) -> MutexGuard<'_, Cache> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc() + Duration::seconds(self.clock_skew_secs.load(Ordering::Relaxed))
    }

    #[cfg(test)]
    fn advance_clock(&self, by: Duration) {
        self.clock_skew_secs
            .fetch_add(by.whole_seconds(), Ordering::Relaxed);
    }
}

/// Parse a host string (DNS name, IPv4, IPv6 with or without brackets) into a
/// canonical [`ServerName`]: lower-case, no trailing dot, no wildcard, at most
/// 253 bytes.
pub(crate) fn parse_host(host: &str) -> Result<ServerName<'static>, LeafError> {
    let trimmed = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }
    if host.len() > MAX_DNS_NAME {
        return Err(LeafError::NameTooLong(host.len()));
    }
    if host.contains('*') {
        return Err(LeafError::Wildcard(host.to_owned()));
    }
    if host.ends_with('.') || !host.is_ascii() {
        return Err(LeafError::InvalidName(host.to_owned()));
    }
    let lower = host.to_ascii_lowercase();
    ServerName::try_from(lower).map_err(|_| LeafError::InvalidName(host.to_owned()))
}

fn canonical_name(name: &ServerName<'_>) -> Result<ServerName<'static>, LeafError> {
    match name {
        ServerName::DnsName(dns) => parse_host(dns.as_ref()),
        ServerName::IpAddress(ip) => Ok(ServerName::IpAddress(*ip)),
        _ => Err(LeafError::InvalidName(format!("{name:?}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minter(size: usize) -> LeafMinter {
        let dir = tempfile::tempdir().unwrap();
        let ca = Ca::generate(dir.path()).unwrap();
        LeafMinter::new(Arc::new(ca), size).unwrap()
    }

    fn name(s: &str) -> ServerName<'static> {
        parse_host(s).unwrap()
    }

    #[test]
    fn cert_properties() {
        let m = minter(8);
        let ck = m.certified_key(&name("Example.COM")).unwrap();
        assert_eq!(ck.cert.len(), 2);
        assert_eq!(ck.cert[1], *m.ca().certificate());
        let (_, x509) = x509_parser::parse_x509_certificate(ck.cert[0].as_ref()).unwrap();
        assert!(x509.subject().to_string().contains("CN=example.com"));
        assert!(
            !x509
                .basic_constraints()
                .unwrap()
                .is_some_and(|b| b.value.ca)
        );
        let ku = x509.key_usage().unwrap().unwrap().value;
        assert!(ku.digital_signature());
        let eku = x509.extended_key_usage().unwrap().unwrap().value;
        assert!(eku.server_auth);
        let v = x509.validity();
        let secs = v.not_after.timestamp() - v.not_before.timestamp();
        assert_eq!(secs, 7 * 86_400 + 3600);
        assert!(ck.keys_match().is_ok());
    }

    #[test]
    fn cache_hit_returns_same_arc() {
        let m = minter(8);
        let a = m.certified_key(&name("example.com")).unwrap();
        let b = m.certified_key(&name("EXAMPLE.com")).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        let c = m.certified_key(&name("other.example")).unwrap();
        assert!(!Arc::ptr_eq(&a, &c));
        assert_eq!(m.cached(), 2);
    }

    #[test]
    fn lru_bound_is_respected() {
        let m = minter(2);
        for n in ["a.test", "b.test", "c.test"] {
            m.certified_key(&name(n)).unwrap();
        }
        assert_eq!(m.cached(), 2);
    }

    #[test]
    fn evicted_near_expiry() {
        let m = minter(8);
        let a = m.certified_key(&name("example.com")).unwrap();
        m.advance_clock(Duration::days(6));
        let b = m.certified_key(&name("example.com")).unwrap();
        assert!(Arc::ptr_eq(&a, &b), "still fresh after 6 days");
        m.advance_clock(Duration::hours(23) + Duration::minutes(30));
        let c = m.certified_key(&name("example.com")).unwrap();
        assert!(!Arc::ptr_eq(&a, &c), "re-minted within 1h of expiry");
        assert_eq!(m.cached(), 1);
    }

    #[test]
    fn rejects_bad_names() {
        let m = minter(8);
        for bad in [
            "",
            "*.example.com",
            "*",
            "exa mple.com",
            "example.com.",
            "-bad-.com",
            "a..b",
            "münchen.de",
            "nul\0.com",
        ] {
            assert!(parse_host(bad).is_err(), "{bad:?} should be rejected");
        }
        assert!(matches!(
            parse_host(&format!("{}.com", "a".repeat(250))),
            Err(LeafError::NameTooLong(_))
        ));
        assert!(matches!(
            parse_host("*.example.com"),
            Err(LeafError::Wildcard(_))
        ));
        assert_eq!(m.cached(), 0);
    }

    /// A CA with less than `LEAF_VALIDITY` left bounds its leaves, and once
    /// it has expired nothing is minted.
    #[test]
    fn leaf_validity_is_clamped_to_the_ca() {
        use crate::ca::tests::{ca_named, make_ca, write_provided};
        let dir = tempfile::tempdir().unwrap();
        let mut params = ca_named("short");
        params.not_after = OffsetDateTime::now_utc() + Duration::days(2);
        let (pem, key) = make_ca(&params, None);
        let (cert, key) = write_provided(dir.path(), &pem, &key);
        let ca = Ca::load_provided(&cert, &key).unwrap();
        let ca_not_after = ca.not_after().unix_timestamp();
        let m = LeafMinter::new(Arc::new(ca), 8).unwrap();

        let ck = m.certified_key(&name("example.com")).unwrap();
        let (_, x509) = x509_parser::parse_x509_certificate(ck.cert[0].as_ref()).unwrap();
        assert_eq!(x509.validity().not_after.timestamp(), ca_not_after);

        m.advance_clock(Duration::days(3));
        assert!(matches!(
            m.certified_key(&name("example.com")),
            Err(LeafError::CaExpired(_))
        ));
    }

    #[test]
    fn ip_san_works() {
        let m = minter(8);
        for host in ["127.0.0.1", "[::1]", "2001:db8::1"] {
            let n = name(host);
            assert!(matches!(n, ServerName::IpAddress(_)));
            let ck = m.certified_key(&n).unwrap();
            let (_, x509) = x509_parser::parse_x509_certificate(ck.cert[0].as_ref()).unwrap();
            let san = x509.subject_alternative_name().unwrap().unwrap();
            assert!(matches!(
                san.value.general_names[0],
                x509_parser::extensions::GeneralName::IPAddress(_)
            ));
        }
    }
}
