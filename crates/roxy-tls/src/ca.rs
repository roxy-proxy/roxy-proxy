//! roxy's certificate authority.
//!
//! The CA is an ECDSA P-256 key and a self-signed certificate
//! (`CA:TRUE, pathlen:0`, key usage `keyCertSign, cRLSign`, 10-year validity)
//! stored as two PEM files in `tls.ca_dir`. Once generated it is only ever
//! reloaded: a missing or corrupt half of the pair is a hard error, never a
//! silent regeneration, because regenerating would invalidate the trust that
//! clients have already been given.
//!
//! An operator can instead provide their own CA as a certificate file and a
//! key file anywhere on disk ([`Ca::load_provided`]).
//! A provided CA is never generated or replaced, and the certificate file may
//! carry intermediates after the CA, which are sent in every handshake.

use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SerialNumber,
};
use ring::rand::{SecureRandom, SystemRandom};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// File name of the CA certificate (PEM) inside the CA directory.
pub const CA_CERT_FILE: &str = "roxy-ca.pem";
/// File name of the CA private key (PKCS#8 PEM, mode 0600) inside the CA directory.
pub const CA_KEY_FILE: &str = "roxy-ca.key";

/// CA validity: 10 years.
const CA_VALIDITY_DAYS: i64 = 3650;
/// Backdate `notBefore` slightly so clients with a skewed clock accept the CA.
const CA_BACKDATE_HOURS: i64 = 1;
const CA_COMMON_NAME: &str = "roxy CA";
const CA_ORGANIZATION: &str = "roxy";

/// Errors from loading or generating the CA.
#[derive(Debug, thiserror::Error)]
pub enum CaError {
    /// Neither CA file exists (only returned by [`Ca::load`]).
    #[error("no CA found in {}", .0.display())]
    NotFound(PathBuf),
    /// At least one CA file already exists (returned by [`Ca::generate`]).
    #[error("a CA already exists in {}", .0.display())]
    AlreadyExists(PathBuf),
    /// Exactly one of the two CA files exists.
    #[error(
        "incomplete CA in {}: {} exists but {} is missing; refusing to regenerate \
         (that would invalidate trust already given to this CA). Restore the missing \
         file or remove both to start over",
        dir.display(), present.display(), missing.display()
    )]
    Incomplete {
        dir: PathBuf,
        present: PathBuf,
        missing: PathBuf,
    },
    /// Filesystem error.
    #[error("{}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// The certificate is outside its validity period.
    #[error("CA certificate {} is not valid now (valid {not_before} to {not_after})", path.display())]
    NotCurrent {
        path: PathBuf,
        not_before: String,
        not_after: String,
    },
    /// The certificate file is not a usable CA certificate.
    #[error("invalid CA certificate {}: {reason}", path.display())]
    InvalidCert { path: PathBuf, reason: String },
    /// The key file is not a usable PKCS#8 private key.
    #[error("invalid CA key {}: {reason}", path.display())]
    InvalidKey { path: PathBuf, reason: String },
    /// Key and certificate both parse but do not belong together.
    #[error("CA key {} does not match certificate {}", key.display(), cert.display())]
    KeyMismatch { cert: PathBuf, key: PathBuf },
    /// Certificate generation or signing failed.
    #[error("CA generation failed: {0}")]
    Generate(#[from] rcgen::Error),
    /// The system random number generator failed.
    #[error("system random number generator failed")]
    Rng,
}

/// roxy's certificate authority: certificate, private key and an rcgen
/// [`Issuer`] ready to sign leaf certificates.
pub struct Ca {
    cert_path: PathBuf,
    cert_der: CertificateDer<'static>,
    /// Certificates sent after the CA in handshakes (intermediates).
    chain: Vec<CertificateDer<'static>>,
    key_der: PrivateKeyDer<'static>,
    issuer: Issuer<'static, KeyPair>,
}

impl fmt::Debug for Ca {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ca")
            .field("cert_path", &self.cert_path)
            .field("cert_der_len", &self.cert_der.len())
            .field("chain_len", &self.chain.len())
            .finish_non_exhaustive()
    }
}

impl Ca {
    /// Load the CA from `dir`, generating it first if neither file exists.
    ///
    /// If exactly one file exists, or either is unparsable, this is an error;
    /// the CA is never silently regenerated.
    pub fn load_or_generate(dir: &Path) -> Result<Self, CaError> {
        match Self::load(dir) {
            Err(CaError::NotFound(_)) => Self::generate(dir),
            other => other,
        }
    }

    /// Load an existing CA from `dir`.
    ///
    /// Returns [`CaError::NotFound`] if neither file exists and
    /// [`CaError::Incomplete`] if only one does.
    pub fn load(dir: &Path) -> Result<Self, CaError> {
        let cert_path = dir.join(CA_CERT_FILE);
        let key_path = dir.join(CA_KEY_FILE);
        match (exists(&cert_path)?, exists(&key_path)?) {
            (false, false) => return Err(CaError::NotFound(dir.to_path_buf())),
            (true, false) => {
                return Err(CaError::Incomplete {
                    dir: dir.to_path_buf(),
                    present: cert_path,
                    missing: key_path,
                });
            }
            (false, true) => {
                return Err(CaError::Incomplete {
                    dir: dir.to_path_buf(),
                    present: key_path,
                    missing: cert_path,
                });
            }
            (true, true) => {}
        }

        Self::load_files(cert_path, &key_path)
    }

    /// Load a CA the operator provided: `cert_path` holds the CA certificate
    /// (PEM), optionally followed by its intermediates in order up to (not
    /// including) the root; `key_path` holds the CA's PKCS#8 PEM key.
    ///
    /// Nothing is ever generated: a missing file is [`CaError::Io`].
    pub fn load_provided(cert_path: &Path, key_path: &Path) -> Result<Self, CaError> {
        Self::load_files(cert_path.to_path_buf(), key_path)
    }

    fn load_files(cert_path: PathBuf, key_path: &Path) -> Result<Self, CaError> {
        let cert_pem = read(&cert_path)?;
        let key_pem = read(key_path)?;

        let invalid_cert = |reason: String| CaError::InvalidCert {
            path: cert_path.clone(),
            reason,
        };
        let mut certs = CertificateDer::pem_slice_iter(&cert_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| invalid_cert(e.to_string()))?
            .into_iter();
        let cert_der = certs
            .next()
            .ok_or_else(|| invalid_cert("no PEM certificate found".into()))?;
        let chain: Vec<_> = certs.collect();

        let key_der =
            PrivatePkcs8KeyDer::from_pem_slice(&key_pem).map_err(|e| CaError::InvalidKey {
                path: key_path.to_path_buf(),
                reason: format!(
                    "expected a PKCS#8 PEM private key (\"BEGIN PRIVATE KEY\"; convert with \
                     `openssl pkcs8 -topk8 -nocrypt`): {e}"
                ),
            })?;
        let key_der = PrivateKeyDer::Pkcs8(key_der);
        let key_pair = KeyPair::try_from(&key_der).map_err(|e| CaError::InvalidKey {
            path: key_path.to_path_buf(),
            reason: e.to_string(),
        })?;

        check_ca_cert(&cert_der, &chain, &cert_path, key_path, &key_pair)?;

        let issuer = Issuer::from_ca_cert_der(&cert_der, key_pair)
            .map_err(|e| invalid_cert(e.to_string()))?;

        Ok(Self {
            cert_path,
            cert_der,
            chain,
            key_der,
            issuer,
        })
    }

    /// Generate a new CA in `dir` (created with mode 0700 if absent).
    ///
    /// Fails with [`CaError::AlreadyExists`] if either CA file is present.
    pub fn generate(dir: &Path) -> Result<Self, CaError> {
        let cert_path = dir.join(CA_CERT_FILE);
        let key_path = dir.join(CA_KEY_FILE);
        if exists(&cert_path)? || exists(&key_path)? {
            return Err(CaError::AlreadyExists(dir.to_path_buf()));
        }
        create_dir(dir)?;

        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let params = ca_params()?;
        let cert = params.self_signed(&key_pair)?;

        let key_pem = key_pair.serialize_pem();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        let cert_der = cert.der().clone();

        // Key first: if we crash between the two writes, the next start sees an
        // incomplete pair and refuses to run rather than minting a new CA.
        write_new(&key_path, key_pem.as_bytes(), 0o600)?;
        write_new(&cert_path, cert.pem().as_bytes(), 0o644)?;

        Ok(Self {
            cert_path,
            cert_der,
            chain: Vec::new(),
            key_der,
            issuer: Issuer::new(params, key_pair),
        })
    }

    /// Remove any existing CA files in `dir` and generate a fresh CA.
    ///
    /// This invalidates every client that trusts the old CA; it is only for
    /// explicit operator action (`roxy ca init --force`).
    pub fn generate_force(dir: &Path) -> Result<Self, CaError> {
        for name in [CA_CERT_FILE, CA_KEY_FILE] {
            let path = dir.join(name);
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(source) => return Err(CaError::Io { path, source }),
            }
        }
        Self::generate(dir)
    }

    /// Path of the CA certificate file.
    pub fn cert_path(&self) -> &Path {
        &self.cert_path
    }

    /// The CA certificate, PEM-encoded.
    pub fn cert_pem(&self) -> String {
        pem::encode_config(
            &pem::Pem::new("CERTIFICATE", self.cert_der.to_vec()),
            pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
        )
    }

    /// The CA certificate, DER-encoded.
    pub fn cert_der(&self) -> Vec<u8> {
        self.cert_der.to_vec()
    }

    /// The CA certificate as a rustls certificate, e.g. for building chains.
    pub fn certificate(&self) -> &CertificateDer<'static> {
        &self.cert_der
    }

    /// Intermediates sent after the CA certificate in every handshake. Empty
    /// unless a provided CA's certificate file carries them.
    pub fn chain(&self) -> &[CertificateDer<'static>] {
        &self.chain
    }

    /// The CA private key. Never serve or log this.
    pub fn key_der(&self) -> &PrivateKeyDer<'static> {
        &self.key_der
    }

    /// The rcgen issuer for signing leaf certificates
    /// (`leaf_params.signed_by(&leaf_key, ca.issuer())`).
    pub fn issuer(&self) -> &Issuer<'static, KeyPair> {
        &self.issuer
    }
}

fn ca_params() -> Result<CertificateParams, CaError> {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, CA_COMMON_NAME);
    dn.push(DnType::OrganizationName, CA_ORGANIZATION);
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.serial_number = Some(random_serial()?);
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::hours(CA_BACKDATE_HOURS);
    params.not_after = now + time::Duration::days(CA_VALIDITY_DAYS);
    Ok(params)
}

/// A random, positive, 128-bit serial number.
pub(crate) fn random_serial() -> Result<SerialNumber, CaError> {
    let mut bytes = [0u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| CaError::Rng)?;
    // Clear the sign bit and set the next one so the DER INTEGER is positive
    // and always 16 bytes long.
    bytes[0] = (bytes[0] & 0x7f) | 0x40;
    Ok(SerialNumber::from_slice(&bytes))
}

/// Verify that `cert_der` is a currently valid CA certificate that may sign
/// certificates, whose public key belongs to `key`, and that `chain` (if any)
/// runs upwards from it in order.
fn check_ca_cert(
    cert_der: &CertificateDer<'_>,
    chain: &[CertificateDer<'_>],
    cert_path: &Path,
    key_path: &Path,
    key: &KeyPair,
) -> Result<(), CaError> {
    let invalid = |reason: String| CaError::InvalidCert {
        path: cert_path.to_path_buf(),
        reason,
    };
    let x509 = parse_cert(cert_der).map_err(invalid)?;
    let is_ca = x509
        .basic_constraints()
        .map_err(|e| invalid(e.to_string()))?
        .is_some_and(|bc| bc.value.ca);
    if !is_ca {
        return Err(invalid(
            "certificate is not a CA (basicConstraints CA:FALSE or absent)".into(),
        ));
    }
    // Clients reject leaves from a CA whose key usage forbids signing them,
    // so refuse to start rather than fail every handshake.
    let may_sign = x509
        .key_usage()
        .map_err(|e| invalid(e.to_string()))?
        .is_none_or(|ku| ku.value.key_cert_sign());
    if !may_sign {
        return Err(invalid("key usage does not include keyCertSign".into()));
    }
    let validity = x509.validity();
    if !validity.is_valid() {
        return Err(CaError::NotCurrent {
            path: cert_path.to_path_buf(),
            not_before: validity.not_before.to_string(),
            not_after: validity.not_after.to_string(),
        });
    }
    if x509.public_key().subject_public_key.data.as_ref() != key.public_key_raw() {
        return Err(CaError::KeyMismatch {
            cert: cert_path.to_path_buf(),
            key: key_path.to_path_buf(),
        });
    }
    // Each certificate must be issued by the next: a misordered or unrelated
    // bundle would be served as a chain no client can build.
    let mut below = x509;
    for (i, der) in chain.iter().enumerate() {
        let above = parse_cert(der).map_err(invalid)?;
        if below.issuer() != above.subject() {
            return Err(invalid(format!(
                "certificate {} (subject {}) is not the issuer of the one before it (issuer {})",
                i + 2,
                above.subject(),
                below.issuer()
            )));
        }
        below = above;
    }
    Ok(())
}

fn parse_cert(der: &[u8]) -> Result<x509_parser::certificate::X509Certificate<'_>, String> {
    let (rest, x509) = x509_parser::parse_x509_certificate(der).map_err(|e| e.to_string())?;
    if rest.is_empty() {
        Ok(x509)
    } else {
        Err("trailing data after certificate".into())
    }
}

fn exists(path: &Path) -> Result<bool, CaError> {
    path.try_exists().map_err(|source| CaError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn read(path: &Path) -> Result<Vec<u8>, CaError> {
    fs::read(path).map_err(|source| CaError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn create_dir(dir: &Path) -> Result<(), CaError> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir).map_err(|source| CaError::Io {
        path: dir.to_path_buf(),
        source,
    })
}

/// Create `path` exclusively (never overwrite) with the given unix mode.
fn write_new(path: &Path, contents: &[u8], #[allow(unused)] mode: u32) -> Result<(), CaError> {
    let io_err = |source| CaError::Io {
        path: path.to_path_buf(),
        source,
    };
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    let mut file = opts.open(path).map_err(io_err)?;
    file.write_all(contents).map_err(io_err)?;
    file.sync_all().map_err(io_err)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn generate_then_reload_yields_same_cert() {
        let tmp = tmp();
        let dir = tmp.path().join("ca");
        let generated = Ca::generate(&dir).unwrap();
        let loaded = Ca::load(&dir).unwrap();
        assert_eq!(generated.cert_der(), loaded.cert_der());
        assert_eq!(generated.cert_pem(), loaded.cert_pem());
        assert_eq!(
            generated.cert_pem(),
            fs::read_to_string(dir.join(CA_CERT_FILE)).unwrap()
        );
        let again = Ca::load_or_generate(&dir).unwrap();
        assert_eq!(generated.cert_der(), again.cert_der());
    }

    #[test]
    fn load_or_generate_creates_when_absent() {
        let tmp = tmp();
        let dir = tmp.path().join("nested").join("ca");
        let ca = Ca::load_or_generate(&dir).unwrap();
        assert!(dir.join(CA_CERT_FILE).exists());
        assert!(dir.join(CA_KEY_FILE).exists());
        assert!(ca.cert_pem().starts_with("-----BEGIN CERTIFICATE-----\n"));
    }

    #[test]
    fn generated_cert_has_ca_properties() {
        let tmp = tmp();
        let ca = Ca::generate(tmp.path()).unwrap();
        let der = ca.cert_der();
        let (_, x509) = x509_parser::parse_x509_certificate(&der).unwrap();
        let bc = x509.basic_constraints().unwrap().unwrap().value;
        assert!(bc.ca);
        assert_eq!(bc.path_len_constraint, Some(0));
        let ku = x509.key_usage().unwrap().unwrap().value;
        assert!(ku.key_cert_sign());
        assert!(ku.crl_sign());
        assert!(!ku.digital_signature());
        let subject = x509.subject().to_string();
        assert!(subject.contains("CN=roxy CA"), "{subject}");
        assert!(subject.contains("O=roxy"), "{subject}");
        let validity = x509.validity();
        let days = (validity.not_after.timestamp() - validity.not_before.timestamp()) / 86_400;
        assert!((3650..=3651).contains(&days), "{days}");
        assert_eq!(
            x509.signature_algorithm.algorithm,
            x509_parser::oid_registry::OID_SIG_ECDSA_WITH_SHA256
        );
    }

    #[test]
    fn serials_are_random() {
        let a = Ca::generate(tmp().path()).unwrap();
        let b = Ca::generate(tmp().path()).unwrap();
        let serial = |ca: &Ca| {
            let der = ca.cert_der();
            let (_, x509) = x509_parser::parse_x509_certificate(&der).unwrap();
            x509.raw_serial().to_vec()
        };
        assert_ne!(serial(&a), serial(&b));
        assert_eq!(serial(&a).len(), 16);
    }

    #[test]
    fn issuer_can_sign_a_leaf() {
        let tmp = tmp();
        Ca::generate(tmp.path()).unwrap();
        let ca = Ca::load(tmp.path()).unwrap();
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let params = CertificateParams::new(vec!["example.com".to_string()]).unwrap();
        let leaf = params.signed_by(&leaf_key, ca.issuer()).unwrap();
        let (_, x509) = x509_parser::parse_x509_certificate(leaf.der()).unwrap();
        assert!(x509.issuer().to_string().contains("CN=roxy CA"));
    }

    #[test]
    fn generate_refuses_to_overwrite() {
        let tmp = tmp();
        Ca::generate(tmp.path()).unwrap();
        assert!(matches!(
            Ca::generate(tmp.path()),
            Err(CaError::AlreadyExists(_))
        ));
        let old = Ca::load(tmp.path()).unwrap();
        let new = Ca::generate_force(tmp.path()).unwrap();
        assert_ne!(old.cert_der(), new.cert_der());
    }

    #[test]
    fn load_missing_is_not_found() {
        assert!(matches!(Ca::load(tmp().path()), Err(CaError::NotFound(_))));
    }

    #[test]
    fn missing_one_file_is_an_error() {
        for missing in [CA_CERT_FILE, CA_KEY_FILE] {
            let tmp = tmp();
            Ca::generate(tmp.path()).unwrap();
            fs::remove_file(tmp.path().join(missing)).unwrap();
            assert!(matches!(
                Ca::load(tmp.path()),
                Err(CaError::Incomplete { .. })
            ));
            assert!(matches!(
                Ca::load_or_generate(tmp.path()),
                Err(CaError::Incomplete { .. })
            ));
            // Nothing was regenerated.
            assert!(!tmp.path().join(missing).exists());
        }
    }

    #[test]
    fn corrupt_key_is_an_error() {
        let tmp = tmp();
        Ca::generate(tmp.path()).unwrap();
        let key_path = tmp.path().join(CA_KEY_FILE);
        let pem = fs::read_to_string(&key_path).unwrap();
        // Flip a character inside the base64 body.
        let mut lines: Vec<String> = pem.lines().map(str::to_owned).collect();
        let body = &mut lines[1];
        let flipped = if body.starts_with('A') { "B" } else { "A" };
        body.replace_range(0..1, flipped);
        fs::write(&key_path, lines.join("\n")).unwrap();
        let err = Ca::load_or_generate(tmp.path()).unwrap_err();
        assert!(
            matches!(
                err,
                CaError::InvalidKey { .. } | CaError::KeyMismatch { .. }
            ),
            "{err}"
        );

        fs::write(&key_path, "not a key").unwrap();
        assert!(matches!(
            Ca::load(tmp.path()),
            Err(CaError::InvalidKey { .. })
        ));
    }

    #[test]
    fn mismatched_pair_is_an_error() {
        let a = tmp();
        let b = tmp();
        Ca::generate(a.path()).unwrap();
        Ca::generate(b.path()).unwrap();
        fs::copy(b.path().join(CA_KEY_FILE), a.path().join(CA_KEY_FILE)).unwrap();
        assert!(matches!(
            Ca::load(a.path()),
            Err(CaError::KeyMismatch { .. })
        ));
    }

    #[test]
    fn corrupt_cert_is_an_error() {
        let tmp = tmp();
        Ca::generate(tmp.path()).unwrap();
        fs::write(tmp.path().join(CA_CERT_FILE), "garbage").unwrap();
        assert!(matches!(
            Ca::load(tmp.path()),
            Err(CaError::InvalidCert { .. })
        ));
    }

    /// A CA's PEM certificate and PKCS#8 PEM key, built from `params`,
    /// self-signed or signed by `parent`.
    pub(crate) fn make_ca(
        params: &CertificateParams,
        parent: Option<&Issuer<'_, KeyPair>>,
    ) -> (String, KeyPair) {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = match parent {
            Some(p) => params.signed_by(&key, p).unwrap(),
            None => params.self_signed(&key).unwrap(),
        };
        (cert.pem(), key)
    }

    pub(crate) fn ca_named(cn: &str) -> CertificateParams {
        let mut params = ca_params().unwrap();
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, cn);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
    }

    /// Writes `cert` and `key` to `ca.crt` / `ca.key` in `dir`.
    pub(crate) fn write_provided(dir: &Path, cert: &str, key: &KeyPair) -> (PathBuf, PathBuf) {
        let (c, k) = (dir.join("ca.crt"), dir.join("ca.key"));
        fs::write(&c, cert).unwrap();
        fs::write(&k, key.serialize_pem()).unwrap();
        (c, k)
    }

    #[test]
    fn provided_ca_loads_with_its_chain() {
        let tmp = tmp();
        let (root_pem, root_key) = make_ca(&ca_named("Org Root"), None);
        let root = Issuer::from_ca_cert_pem(&root_pem, root_key).unwrap();
        let (mid_pem, mid_key) = make_ca(&ca_named("Org Mid"), Some(&root));
        let mid = Issuer::from_ca_cert_pem(&mid_pem, mid_key).unwrap();
        let (sub_pem, sub_key) = make_ca(&ca_named("roxy sub-CA"), Some(&mid));

        let (cert, key) = write_provided(tmp.path(), &(sub_pem.clone() + &mid_pem), &sub_key);
        let ca = Ca::load_provided(&cert, &key).unwrap();
        assert_eq!(ca.cert_pem(), sub_pem);
        assert_eq!(ca.cert_path(), cert);
        assert_eq!(ca.chain().len(), 1);
        assert_eq!(
            ca.chain()[0].as_ref(),
            CertificateDer::from_pem_slice(mid_pem.as_bytes())
                .unwrap()
                .as_ref()
        );
        // Nothing is written next to a provided CA.
        assert_eq!(fs::read_dir(tmp.path()).unwrap().count(), 2);

        // Without intermediates the chain is empty.
        let (cert, key) = write_provided(tmp.path(), &sub_pem, &sub_key);
        assert_eq!(Ca::load_provided(&cert, &key).unwrap().chain(), &[]);
    }

    #[test]
    fn provided_ca_is_never_generated() {
        let tmp = tmp();
        let err =
            Ca::load_provided(&tmp.path().join("ca.crt"), &tmp.path().join("ca.key")).unwrap_err();
        assert!(matches!(err, CaError::Io { .. }), "{err}");
        assert_eq!(fs::read_dir(tmp.path()).unwrap().count(), 0);
    }

    #[test]
    fn provided_chain_out_of_order_is_an_error() {
        let tmp = tmp();
        let (root_pem, root_key) = make_ca(&ca_named("Org Root"), None);
        let root = Issuer::from_ca_cert_pem(&root_pem, root_key).unwrap();
        let (mid_pem, mid_key) = make_ca(&ca_named("Org Mid"), Some(&root));
        let mid = Issuer::from_ca_cert_pem(&mid_pem, mid_key).unwrap();
        let (sub_pem, sub_key) = make_ca(&ca_named("roxy sub-CA"), Some(&mid));
        let (other_pem, _) = make_ca(&ca_named("Unrelated"), None);

        for bundle in [
            sub_pem.clone() + &root_pem + &mid_pem,
            sub_pem.clone() + &other_pem,
        ] {
            let (cert, key) = write_provided(tmp.path(), &bundle, &sub_key);
            let err = Ca::load_provided(&cert, &key).unwrap_err();
            assert!(
                matches!(&err, CaError::InvalidCert { reason, .. } if reason.contains("issuer")),
                "{err}"
            );
        }
    }

    #[test]
    fn provided_cert_must_be_a_current_signing_ca() {
        let tmp = tmp();

        let mut leaf = ca_named("not a CA");
        leaf.is_ca = IsCa::NoCa;
        let (pem, key) = make_ca(&leaf, None);
        let (cert, key_path) = write_provided(tmp.path(), &pem, &key);
        let err = Ca::load_provided(&cert, &key_path).unwrap_err();
        assert!(
            matches!(&err, CaError::InvalidCert { reason, .. } if reason.contains("not a CA")),
            "{err}"
        );

        let mut no_sign = ca_named("no keyCertSign");
        no_sign.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let (pem, key) = make_ca(&no_sign, None);
        let (cert, key_path) = write_provided(tmp.path(), &pem, &key);
        let err = Ca::load_provided(&cert, &key_path).unwrap_err();
        assert!(
            matches!(&err, CaError::InvalidCert { reason, .. } if reason.contains("keyCertSign")),
            "{err}"
        );

        let now = time::OffsetDateTime::now_utc();
        for (from, to) in [
            (
                now - time::Duration::days(20),
                now - time::Duration::days(10),
            ),
            (
                now + time::Duration::days(10),
                now + time::Duration::days(20),
            ),
        ] {
            let mut params = ca_named("not current");
            params.not_before = from;
            params.not_after = to;
            let (pem, key) = make_ca(&params, None);
            let (cert, key_path) = write_provided(tmp.path(), &pem, &key);
            let err = Ca::load_provided(&cert, &key_path).unwrap_err();
            assert!(matches!(err, CaError::NotCurrent { .. }), "{err}");
        }
    }

    #[test]
    fn provided_key_must_be_pkcs8_and_match() {
        let tmp = tmp();
        let (pem, key) = make_ca(&ca_named("roxy"), None);
        let (cert, key_path) = write_provided(tmp.path(), &pem, &key);

        // A SEC1 ("EC PRIVATE KEY") key is refused with a pointer to convert it.
        fs::write(
            &key_path,
            "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n",
        )
        .unwrap();
        let err = Ca::load_provided(&cert, &key_path).unwrap_err();
        assert!(
            matches!(&err, CaError::InvalidKey { reason, .. } if reason.contains("openssl pkcs8")),
            "{err}"
        );

        let (_, other) = make_ca(&ca_named("other"), None);
        fs::write(&key_path, other.serialize_pem()).unwrap();
        assert!(matches!(
            Ca::load_provided(&cert, &key_path),
            Err(CaError::KeyMismatch { .. })
        ));

        fs::write(&cert, "no certificate here\n").unwrap();
        assert!(matches!(
            Ca::load_provided(&cert, &key_path),
            Err(CaError::InvalidCert { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn file_and_dir_modes() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tmp();
        let dir = tmp.path().join("ca");
        Ca::generate(&dir).unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join(CA_KEY_FILE)), 0o600);
    }
}
