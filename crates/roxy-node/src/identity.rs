//! The node's key pair and certificate: generation, the CSR, and what the
//! node reads back out of the certificate it was issued.

use chrono::{DateTime, Utc};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject as _;

/// Scheme of the SAN URI that carries the node id.
pub const NODE_ID_URI_PREFIX: &str = "urn:roxy:node:";

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("generating the node key: {0}")]
    Generate(#[from] rcgen::Error),
    #[error("the certificate chain has no certificate")]
    EmptyChain,
    #[error("the node certificate does not parse: {0}")]
    InvalidCert(String),
    #[error("the node key does not parse: {0}")]
    InvalidKey(String),
    #[error("the node certificate carries no `{NODE_ID_URI_PREFIX}` URI SAN")]
    NoNodeId,
}

/// A fresh P-256 key pair, PKCS#8 PEM.
pub fn generate_key() -> Result<KeyPair, IdentityError> {
    Ok(KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?)
}

/// Loads a PKCS#8 PEM key written by [`generate_key`].
pub fn load_key(pem: &str) -> Result<KeyPair, IdentityError> {
    KeyPair::from_pem(pem).map_err(|e| IdentityError::InvalidKey(e.to_string()))
}

/// A CSR for `key`. The server sets the subject and the node-id SAN; the
/// CSR names only the key.
pub fn csr_pem(key: &KeyPair) -> Result<String, IdentityError> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "roxy node");
    params.distinguished_name = dn;
    Ok(params.serialize_request(key)?.pem()?)
}

/// What the node reads out of its certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertInfo {
    pub node_id: String,
    pub not_after: DateTime<Utc>,
}

/// Parses the first certificate of a PEM chain.
pub fn cert_info(chain_pem: &str) -> Result<CertInfo, IdentityError> {
    let leaf = CertificateDer::pem_slice_iter(chain_pem.as_bytes())
        .next()
        .ok_or(IdentityError::EmptyChain)?
        .map_err(|e| IdentityError::InvalidCert(e.to_string()))?;
    let (_, x509) = x509_parser::parse_x509_certificate(&leaf)
        .map_err(|e| IdentityError::InvalidCert(e.to_string()))?;
    let not_after = DateTime::from_timestamp(x509.validity().not_after.timestamp(), 0)
        .ok_or_else(|| IdentityError::InvalidCert("not_after out of range".into()))?;
    let san = x509
        .subject_alternative_name()
        .map_err(|e| IdentityError::InvalidCert(e.to_string()))?;
    let node_id = san
        .into_iter()
        .flat_map(|ext| ext.value.general_names.iter())
        .find_map(|name| match name {
            x509_parser::extensions::GeneralName::URI(uri) => {
                uri.strip_prefix(NODE_ID_URI_PREFIX).map(str::to_owned)
            }
            _ => None,
        })
        .ok_or(IdentityError::NoNodeId)?;
    Ok(CertInfo { node_id, not_after })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csr_round_trips_and_the_issued_cert_yields_the_node_id() {
        let key = generate_key().unwrap();
        let csr = csr_pem(&key).unwrap();
        assert!(csr.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
        let issued = crate::testkit::TestCa::new().issue(&csr, "node-42", 3600);
        let info = cert_info(&issued).unwrap();
        assert_eq!(info.node_id, "node-42");
        let left = info.not_after - Utc::now();
        assert!(left.num_seconds() > 3500 && left.num_seconds() <= 3600);

        let reloaded = load_key(&key.serialize_pem()).unwrap();
        assert_eq!(reloaded.public_key_pem(), key.public_key_pem());
    }

    #[test]
    fn a_certificate_without_the_node_id_san_is_refused() {
        let key = generate_key().unwrap();
        let ca = crate::testkit::TestCa::new();
        let pem = ca.issue_without_node_id(&csr_pem(&key).unwrap());
        assert!(matches!(cert_info(&pem), Err(IdentityError::NoNodeId)));
        assert!(matches!(cert_info(""), Err(IdentityError::EmptyChain)));
    }
}
