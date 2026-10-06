//! HTTP clients for the harness: anonymous (enrolment) and with a node
//! identity (everything else).

use std::time::Duration;

use anyhow::Context;

pub(crate) fn build(
    ca_bundle_pem: Option<&str>,
    identity: Option<(&str, &str)>,
) -> anyhow::Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .use_rustls_tls()
        .no_proxy()
        .timeout(Duration::from_secs(15))
        .user_agent("roxy-node-conformance/0.1");
    if let Some(bundle) = ca_bundle_pem {
        b = b.tls_built_in_root_certs(false);
        for cert in reqwest::Certificate::from_pem_bundle(bundle.as_bytes()).context("ca bundle")? {
            b = b.add_root_certificate(cert);
        }
    }
    if let Some((chain_pem, key_pem)) = identity {
        let mut pem = chain_pem.as_bytes().to_vec();
        pem.push(b'\n');
        pem.extend_from_slice(key_pem.as_bytes());
        b = b.identity(reqwest::Identity::from_pem(&pem).context("node identity")?);
    }
    b.build().context("build client")
}
