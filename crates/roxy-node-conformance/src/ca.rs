//! Certificates: the node CA a control plane signs with, CSR issuance, and
//! the SAN URI that carries the node id.

use anyhow::{Context, anyhow};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, CertifiedIssuer,
    DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use time::{Duration, OffsetDateTime};
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

/// Prefix of the URI SAN that names the node.
pub const NODE_URN_PREFIX: &str = "urn:roxy:node:";

/// A CA that issues node certificates from CSRs.
pub struct NodeCa {
    issuer: CertifiedIssuer<'static, KeyPair>,
}

/// An issued certificate: the PEM chain and its expiry.
pub struct Issued {
    pub chain_pem: String,
    pub not_after: OffsetDateTime,
}

impl NodeCa {
    pub fn new(common_name: &str) -> anyhow::Result<Self> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.distinguished_name = dn(common_name);
        params.not_before = OffsetDateTime::now_utc() - Duration::minutes(5);
        params.not_after = OffsetDateTime::now_utc() + Duration::days(3650);
        Ok(Self {
            issuer: CertifiedIssuer::self_signed(params, key)?,
        })
    }

    pub fn cert_pem(&self) -> String {
        self.issuer.pem()
    }

    pub fn cert_der(&self) -> Vec<u8> {
        self.issuer.der().to_vec()
    }

    /// Sign a node certificate for `node_id` from a CSR. The CSR's subject
    /// and requested extensions are ignored: only the key is taken, and the
    /// signature over it is what proves the node holds the private key.
    pub fn issue_node(
        &self,
        csr_pem: &str,
        node_id: &str,
        lifetime: Duration,
    ) -> anyhow::Result<Issued> {
        let mut csr = CertificateSigningRequestParams::from_pem(csr_pem)
            .map_err(|e| anyhow!("invalid csr: {e}"))?;
        let not_after = OffsetDateTime::now_utc() + lifetime;
        let uri = format!("{NODE_URN_PREFIX}{node_id}")
            .try_into()
            .map_err(|e| anyhow!("node id is not IA5: {e}"))?;
        csr.params.subject_alt_names = vec![SanType::URI(uri)];
        csr.params.distinguished_name = dn(node_id);
        csr.params.is_ca = IsCa::ExplicitNoCa;
        csr.params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        csr.params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        csr.params.not_before = OffsetDateTime::now_utc() - Duration::minutes(5);
        csr.params.not_after = not_after;
        csr.params.serial_number = Some(random_serial().into());
        let cert = csr.signed_by(&self.issuer)?;
        Ok(Issued {
            chain_pem: cert.pem(),
            not_after,
        })
    }

    /// A server certificate for the control plane's own listener, signed by
    /// this CA so one bundle verifies both directions.
    pub fn issue_server(&self, names: &[&str]) -> anyhow::Result<(String, KeyPair)> {
        let key = KeyPair::generate()?;
        let mut params =
            CertificateParams::new(names.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())?;
        params.distinguished_name = dn("roxy-node-conformance");
        params.not_before = OffsetDateTime::now_utc() - Duration::minutes(5);
        params.not_after = OffsetDateTime::now_utc() + Duration::days(30);
        params.serial_number = Some(random_serial().into());
        let cert = params.signed_by(&key, &self.issuer)?;
        Ok((cert.pem(), key))
    }
}

fn dn(cn: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    dn
}

fn random_serial() -> Vec<u8> {
    use ring::rand::SecureRandom;
    let mut serial = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut serial)
        .expect("system random");
    // A positive INTEGER: clear the sign bit.
    serial[0] &= 0x7f;
    serial.to_vec()
}

/// Generate a node key pair and the CSR a node sends. The CSR carries no
/// names: the server sets the SAN.
pub fn node_csr() -> anyhow::Result<(KeyPair, String)> {
    let key = KeyPair::generate()?;
    let params = CertificateParams::default();
    let csr = params.serialize_request(&key)?;
    Ok((key, csr.pem()?))
}

/// What a node certificate says about the node: its id from the URI SAN,
/// the number of SANs it carries, its expiry and its `SubjectPublicKeyInfo`.
pub struct NodeCertInfo {
    pub node_id: Option<String>,
    pub san_count: usize,
    pub not_after: OffsetDateTime,
    pub spki_der: Vec<u8>,
}

pub fn inspect_node_cert(der: &[u8]) -> anyhow::Result<NodeCertInfo> {
    let (_, cert) = X509Certificate::from_der(der).context("parse certificate")?;
    let mut node_id = None;
    let mut san_count = 0;
    if let Some(ext) = cert.subject_alternative_name().context("read SAN")? {
        for name in &ext.value.general_names {
            san_count += 1;
            if let GeneralName::URI(uri) = name
                && let Some(id) = uri.strip_prefix(NODE_URN_PREFIX)
            {
                node_id = Some(id.to_owned());
            }
        }
    }
    let not_after = OffsetDateTime::from_unix_timestamp(cert.validity().not_after.timestamp())
        .context("not_after out of range")?;
    Ok(NodeCertInfo {
        node_id,
        san_count,
        not_after,
        spki_der: cert.public_key().raw.to_vec(),
    })
}

/// The node id a certificate names, or `None` if it has no node URI SAN.
pub fn node_id_from_cert(der: &[u8]) -> Option<String> {
    inspect_node_cert(der).ok().and_then(|info| info.node_id)
}

/// The first PEM `CERTIFICATE` block of `pem`, as DER.
pub fn first_cert_der(pem: &str) -> anyhow::Result<Vec<u8>> {
    let block = pem::parse_many(pem)
        .map_err(|e| anyhow!("parse pem: {e}"))?
        .into_iter()
        .find(|b| b.tag() == "CERTIFICATE")
        .ok_or_else(|| anyhow!("no CERTIFICATE block"))?;
    Ok(block.contents().to_vec())
}
