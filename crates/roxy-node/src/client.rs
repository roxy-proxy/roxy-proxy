//! The HTTP client for `/roxy/v1/`: a bearer token for enrolment, the node
//! certificate (mTLS) for everything after. Each call classifies the
//! response into what the node does about it; the caller never sees a raw
//! status.

use std::io::Write as _;
use std::time::Duration;

use reqwest::header::{CONTENT_ENCODING, CONTENT_TYPE};
use reqwest::{Identity, StatusCode, Url};

use crate::protocol::{
    CertificateRequest, CertificateResponse, ErrorBody, FlowAck, Lease, NodeState, PREFIX,
    PROTOCOL_VERSION,
};

/// Per-request timeout. Lease and certificate calls are small; a flow
/// batch is at most `batch_max_bytes`.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Largest response body the client reads before giving up on it.
const MAX_BODY: usize = 16 << 20;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("control plane URL: {0}")]
    Url(String),
    #[error("control plane CA bundle: {0}")]
    Ca(String),
    #[error("node certificate or key: {0}")]
    Identity(String),
    #[error("building the HTTP client: {0}")]
    Build(String),
}

/// A failure the node retries with backoff: 5xx, a timeout, a connection
/// error, or a body that does not parse.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Transient(String);

impl Transient {
    fn status(status: StatusCode, body: &[u8]) -> Self {
        let text = String::from_utf8_lossy(&body[..body.len().min(200)]);
        Self(format!("{status}: {}", text.trim()))
    }
}

/// What a lease fetch came back with.
#[derive(Debug)]
pub enum LeaseFetch {
    /// 200: the lease the server would have this node run.
    Lease(Box<Lease>),
    /// 410: the node is revoked. Definite and terminal.
    Revoked,
    /// 426: the server will not serve this protocol or roxy version;
    /// `missing` names what it wants.
    Unsupported(ErrorBody),
    /// 401: the certificate is not recognised.
    Unauthorized,
    /// 5xx, timeout, connection error, unreadable body.
    Failed(Transient),
}

/// What a flow upload came back with.
#[derive(Debug)]
pub enum ShipOutcome {
    Acked(FlowAck),
    /// 507: this node's flow quota is exhausted under the current lease.
    QuotaExhausted,
    /// 410: the node is revoked.
    Revoked,
    /// Anything else, including a 413 for a batch within the stated size.
    Failed(Transient),
}

/// How an enrolment or renewal failed.
#[derive(Debug, thiserror::Error)]
pub enum CertificateError {
    /// A 4xx: the token is spent or invalid, or the certificate is not
    /// recognised. Retrying cannot help.
    #[error("rejected: {0}")]
    Rejected(String),
    #[error("{0}")]
    Failed(Transient),
}

/// What the node says about itself.
#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub roxy_version: String,
}

/// Verification material for the control plane connection.
#[derive(Debug, Clone, Default)]
pub struct Trust {
    /// PEM CA bundle to verify the control plane with; `None` = the
    /// system roots.
    pub ca_pem: Option<String>,
}

/// A client for one control plane.
#[derive(Debug, Clone)]
pub struct ControlPlane {
    base: Url,
    http: reqwest::Client,
    info: NodeInfo,
}

fn builder(trust: &Trust, info: &NodeInfo) -> Result<reqwest::ClientBuilder, ClientError> {
    let mut b = reqwest::Client::builder()
        .use_rustls_tls()
        .https_only(true)
        .timeout(REQUEST_TIMEOUT)
        .user_agent(format!("roxy/{}", info.roxy_version))
        .no_proxy();
    if let Some(pem) = &trust.ca_pem {
        b = b.tls_built_in_root_certs(false);
        let certs = reqwest::Certificate::from_pem_bundle(pem.as_bytes())
            .map_err(|e| ClientError::Ca(e.to_string()))?;
        if certs.is_empty() {
            return Err(ClientError::Ca("no certificates in the bundle".into()));
        }
        for c in certs {
            b = b.add_root_certificate(c);
        }
    }
    Ok(b)
}

fn parse_base(url: &str) -> Result<Url, ClientError> {
    let base = Url::parse(url).map_err(|e| ClientError::Url(e.to_string()))?;
    if base.scheme() != "https" {
        return Err(ClientError::Url(format!(
            "{url}: the control plane must be an https:// URL"
        )));
    }
    Ok(base)
}

impl ControlPlane {
    /// A client with no identity, for enrolment.
    pub fn unauthenticated(url: &str, trust: &Trust, info: NodeInfo) -> Result<Self, ClientError> {
        Ok(Self {
            base: parse_base(url)?,
            http: builder(trust, &info)?
                .build()
                .map_err(|e| ClientError::Build(e.to_string()))?,
            info,
        })
    }

    /// A client presenting the node certificate.
    pub fn with_identity(
        url: &str,
        trust: &Trust,
        info: NodeInfo,
        cert_pem: &str,
        key_pem: &str,
    ) -> Result<Self, ClientError> {
        let mut pem = cert_pem.as_bytes().to_vec();
        pem.push(b'\n');
        pem.extend_from_slice(key_pem.as_bytes());
        let identity =
            Identity::from_pem(&pem).map_err(|e| ClientError::Identity(e.to_string()))?;
        Ok(Self {
            base: parse_base(url)?,
            http: builder(trust, &info)?
                .identity(identity)
                .build()
                .map_err(|e| ClientError::Build(e.to_string()))?,
            info,
        })
    }

    pub fn info(&self) -> &NodeInfo {
        &self.info
    }

    fn endpoint(&self, name: &str) -> Url {
        let mut url = self.base.clone();
        let path = format!("{}{PREFIX}/{name}", url.path().trim_end_matches('/'));
        url.set_path(&path);
        url
    }

    fn certificate_request(&self, csr_pem: String) -> Vec<u8> {
        serde_json::to_vec(&CertificateRequest {
            csr: csr_pem,
            roxy_version: self.info.roxy_version.clone(),
            protocol_version: PROTOCOL_VERSION,
        })
        .unwrap_or_default()
    }

    /// `POST /enrol` with the bootstrap token.
    pub async fn enrol(
        &self,
        token: &str,
        csr_pem: String,
    ) -> Result<CertificateResponse, CertificateError> {
        let req = self
            .http
            .post(self.endpoint("enrol"))
            .bearer_auth(token.trim())
            .header(CONTENT_TYPE, "application/json")
            .body(self.certificate_request(csr_pem));
        self.certificate_call(req).await
    }

    /// `POST /renew` under the current certificate.
    pub async fn renew(&self, csr_pem: String) -> Result<CertificateResponse, CertificateError> {
        let req = self
            .http
            .post(self.endpoint("renew"))
            .header(CONTENT_TYPE, "application/json")
            .body(self.certificate_request(csr_pem));
        self.certificate_call(req).await
    }

    async fn certificate_call(
        &self,
        req: reqwest::RequestBuilder,
    ) -> Result<CertificateResponse, CertificateError> {
        let (status, body) = send(req).await.map_err(CertificateError::Failed)?;
        if status.is_success() {
            return serde_json::from_slice(&body).map_err(|e| {
                CertificateError::Failed(Transient(format!("certificate response: {e}")))
            });
        }
        if status.is_client_error() {
            let text = String::from_utf8_lossy(&body[..body.len().min(200)]);
            return Err(CertificateError::Rejected(format!(
                "{status}: {}",
                text.trim()
            )));
        }
        Err(CertificateError::Failed(Transient::status(status, &body)))
    }

    /// `POST /lease`, reporting `state`.
    pub async fn fetch_lease(&self, state: &NodeState) -> LeaseFetch {
        let req = self
            .http
            .post(self.endpoint("lease"))
            .header(CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(state).unwrap_or_default());
        let (status, body) = match send(req).await {
            Ok(r) => r,
            Err(e) => return LeaseFetch::Failed(e),
        };
        match status {
            StatusCode::OK => match serde_json::from_slice::<Lease>(&body) {
                Ok(lease) => LeaseFetch::Lease(Box::new(lease)),
                Err(e) => LeaseFetch::Failed(Transient(format!("lease body: {e}"))),
            },
            StatusCode::GONE => LeaseFetch::Revoked,
            StatusCode::UPGRADE_REQUIRED => LeaseFetch::Unsupported(error_body(&body)),
            StatusCode::UNAUTHORIZED => LeaseFetch::Unauthorized,
            other => LeaseFetch::Failed(Transient::status(other, &body)),
        }
    }

    /// `POST /flows` with a gzip-encoded batch body.
    pub async fn ship_flows(&self, batch_json: &[u8]) -> ShipOutcome {
        let mut gz = flate2::write::GzEncoder::new(
            Vec::with_capacity(batch_json.len() / 4),
            flate2::Compression::fast(),
        );
        let body = match gz.write_all(batch_json).and_then(|()| gz.finish()) {
            Ok(b) => b,
            Err(e) => return ShipOutcome::Failed(Transient(format!("gzip: {e}"))),
        };
        let req = self
            .http
            .post(self.endpoint("flows"))
            .header(CONTENT_TYPE, "application/json")
            .header(CONTENT_ENCODING, "gzip")
            .body(body);
        let (status, body) = match send(req).await {
            Ok(r) => r,
            Err(e) => return ShipOutcome::Failed(e),
        };
        match status {
            StatusCode::OK => match serde_json::from_slice::<FlowAck>(&body) {
                Ok(ack) => ShipOutcome::Acked(ack),
                Err(e) => ShipOutcome::Failed(Transient(format!("flow ack body: {e}"))),
            },
            StatusCode::INSUFFICIENT_STORAGE => ShipOutcome::QuotaExhausted,
            StatusCode::GONE => ShipOutcome::Revoked,
            other => ShipOutcome::Failed(Transient::status(other, &body)),
        }
    }
}

/// The error body of a non-2xx response, or a stand-in built from the
/// raw text when it is not one.
fn error_body(body: &[u8]) -> ErrorBody {
    serde_json::from_slice(body).unwrap_or_else(|_| ErrorBody {
        error: "unknown".into(),
        message: String::from_utf8_lossy(&body[..body.len().min(200)])
            .trim()
            .to_owned(),
        missing: Vec::new(),
    })
}

async fn send(req: reqwest::RequestBuilder) -> Result<(StatusCode, Vec<u8>), Transient> {
    let res = req.send().await.map_err(|e| Transient(describe(e)))?;
    let status = res.status();
    if res.content_length().is_some_and(|n| n > MAX_BODY as u64) {
        return Err(Transient(format!("{status}: response body too large")));
    }
    let body = res
        .bytes()
        .await
        .map_err(|e| Transient(format!("{status}: reading the body: {}", describe(e))))?;
    if body.len() > MAX_BODY {
        return Err(Transient(format!("{status}: response body too large")));
    }
    Ok((status, body.to_vec()))
}

/// A reqwest error without the URL, which may carry a query string.
fn describe(e: reqwest::Error) -> String {
    let e = e.without_url();
    let mut text = e.to_string();
    let mut source = std::error::Error::source(&e);
    while let Some(s) = source {
        text.push_str(": ");
        text.push_str(&s.to_string());
        source = s.source();
    }
    text
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::protocol::{FlowSettings, OnHighWater, PolicyState};
    use crate::testkit::{MockServer, Reply};

    fn info() -> NodeInfo {
        NodeInfo {
            roxy_version: "0.1.0-test".into(),
        }
    }

    fn state() -> NodeState {
        NodeState {
            lease_id: Some("L1".into()),
            roxy_version: "0.1.0-test".into(),
            protocol_version: PROTOCOL_VERSION,
            uptime_seconds: 42,
            policy_state: PolicyState::Loaded,
            spooled_bytes: 7,
        }
    }

    pub(crate) fn lease(id: &str) -> Lease {
        Lease {
            lease_id: id.into(),
            valid_for_seconds: 600,
            refresh_after_seconds: 60,
            config: "version: 1\nrules: []\n".to_owned(),
            secrets: std::collections::BTreeMap::default(),
            state_epoch: "e1".into(),
            flow: FlowSettings {
                ship: true,
                batch_max_bytes: 1 << 20,
                flush_interval_seconds: 5,
                spool_high_water_bytes: 8 << 20,
                on_high_water: OnHighWater::Spool,
            },
            interception_ca: None,
        }
    }

    async fn enrolled(mock: &MockServer) -> (ControlPlane, String) {
        let trust = Trust {
            ca_pem: Some(mock.ca.pem.clone()),
        };
        let anon = ControlPlane::unauthenticated(&mock.url(), &trust, info()).unwrap();
        let key = crate::identity::generate_key().unwrap();
        let csr = crate::identity::csr_pem(&key).unwrap();
        mock.push("/roxy/v1/enrol", Reply::issue("node-1"));
        let res = anon.enrol("tok", csr).await.unwrap();
        assert_eq!(res.node_id, "node-1");
        let cp = ControlPlane::with_identity(
            &mock.url(),
            &trust,
            info(),
            &res.certificate_chain,
            &key.serialize_pem(),
        )
        .unwrap();
        (cp, res.certificate_chain)
    }

    #[tokio::test]
    async fn enrol_sends_the_token_and_the_csr_and_the_cert_authenticates_after() {
        let mock = MockServer::start().await;
        let (cp, _) = enrolled(&mock).await;
        let enrol = &mock.requests_to("/roxy/v1/enrol")[0];
        assert_eq!(enrol.header("authorization"), Some("Bearer tok"));
        assert_eq!(enrol.client, None, "no client certificate yet");
        let body = enrol.json();
        assert!(body["csr"].as_str().unwrap().contains("CERTIFICATE REQUEST"));
        assert_eq!(body["protocol_version"], 1);
        assert_eq!(body["roxy_version"], "0.1.0-test");
        assert!(body.get("features").is_none());
        assert_eq!(enrol.header("user-agent"), Some("roxy/0.1.0-test"));

        mock.push("/roxy/v1/lease", Reply::json(200, &lease("L2")));
        assert!(matches!(
            cp.fetch_lease(&state()).await,
            LeaseFetch::Lease(l) if l.lease_id == "L2"
        ));
        let fetch = &mock.requests_to("/roxy/v1/lease")[0];
        assert_eq!(fetch.method, http::Method::POST);
        assert_eq!(fetch.client.as_deref(), Some("node-1"), "mTLS identity");
        let reported = fetch.json();
        assert_eq!(reported["lease_id"], "L1");
        assert_eq!(reported["protocol_version"], 1);
        assert_eq!(reported["policy_state"], "loaded");
        assert_eq!(reported["spooled_bytes"], 7);
        assert_eq!(reported["uptime_seconds"], 42);
        assert!(reported.get("features").is_none());
        assert!(reported.get("config_hash").is_none());
    }

    #[tokio::test]
    async fn enrol_distinguishes_a_spent_token_from_an_outage() {
        let mock = MockServer::start().await;
        let trust = Trust {
            ca_pem: Some(mock.ca.pem.clone()),
        };
        let anon = ControlPlane::unauthenticated(&mock.url(), &trust, info()).unwrap();
        let key = crate::identity::generate_key().unwrap();
        let csr = crate::identity::csr_pem(&key).unwrap();
        mock.push("/roxy/v1/enrol", Reply::status(401));
        assert!(matches!(
            anon.enrol("spent", csr.clone()).await,
            Err(CertificateError::Rejected(m)) if m.starts_with("401")
        ));
        mock.push("/roxy/v1/enrol", Reply::status(503));
        assert!(matches!(
            anon.enrol("tok", csr.clone()).await,
            Err(CertificateError::Failed(_))
        ));
        mock.push("/roxy/v1/enrol", Reply::Hangup);
        assert!(matches!(
            anon.enrol("tok", csr).await,
            Err(CertificateError::Failed(_))
        ));
    }

    #[tokio::test]
    async fn every_lease_status_maps_to_its_own_outcome() {
        let mock = MockServer::start().await;
        let (cp, _) = enrolled(&mock).await;
        let path = "/roxy/v1/lease";
        mock.push(path, Reply::status(410));
        assert!(matches!(cp.fetch_lease(&state()).await, LeaseFetch::Revoked));
        mock.push(
            path,
            Reply::json(
                426,
                &ErrorBody {
                    error: "unsupported".into(),
                    message: "roxy 0.1.0-test is below the floor".into(),
                    missing: vec!["roxy_version:0.2.0".into()],
                },
            ),
        );
        assert!(matches!(
            cp.fetch_lease(&state()).await,
            LeaseFetch::Unsupported(e) if e.missing == ["roxy_version:0.2.0"] && e.error == "unsupported"
        ));
        mock.push(
            path,
            Reply::Status {
                status: 426,
                headers: vec![],
                body: b"nope".to_vec(),
            },
        );
        assert!(matches!(
            cp.fetch_lease(&state()).await,
            LeaseFetch::Unsupported(e) if e.message == "nope"
        ));
        mock.push(path, Reply::status(401));
        assert!(matches!(
            cp.fetch_lease(&state()).await,
            LeaseFetch::Unauthorized
        ));
        mock.push(path, Reply::status(500));
        assert!(matches!(cp.fetch_lease(&state()).await, LeaseFetch::Failed(_)));
        mock.push(path, Reply::Hangup);
        assert!(matches!(cp.fetch_lease(&state()).await, LeaseFetch::Failed(_)));
        mock.push(
            path,
            Reply::Status {
                status: 200,
                headers: vec![],
                body: b"not json".to_vec(),
            },
        );
        assert!(matches!(
            cp.fetch_lease(&state()).await,
            LeaseFetch::Failed(e) if e.to_string().contains("lease body")
        ));
    }

    #[tokio::test]
    async fn an_unknown_server_certificate_is_a_transient_failure() {
        let mock = MockServer::start().await;
        let other = crate::testkit::TestCa::new();
        let trust = Trust {
            ca_pem: Some(other.pem),
        };
        let anon = ControlPlane::unauthenticated(&mock.url(), &trust, info()).unwrap();
        let key = crate::identity::generate_key().unwrap();
        let csr = crate::identity::csr_pem(&key).unwrap();
        mock.push("/roxy/v1/enrol", Reply::issue("node-1"));
        assert!(matches!(
            anon.enrol("tok", csr).await,
            Err(CertificateError::Failed(_))
        ));
        assert!(mock.requests_to("/roxy/v1/enrol").is_empty());
    }

    #[tokio::test]
    async fn flow_upload_is_gzipped_and_each_status_maps() {
        let mock = MockServer::start().await;
        let (cp, _) = enrolled(&mock).await;
        let path = "/roxy/v1/flows";
        let body = crate::protocol::encode_flow_batch(
            "node-1",
            "L1",
            5,
            [r#"{"seq":5}"#, r#"{"seq":6}"#],
        );
        mock.push(path, Reply::json(200, &FlowAck { acked_through: 6 }));
        assert!(matches!(
            cp.ship_flows(&body).await,
            ShipOutcome::Acked(FlowAck { acked_through: 6 })
        ));
        let sent = &mock.requests_to(path)[0];
        assert_eq!(sent.header("content-encoding"), Some("gzip"));
        assert_eq!(sent.client.as_deref(), Some("node-1"));
        let parsed = sent.json();
        assert_eq!(parsed["seq_first"], 5);
        assert_eq!(parsed["events"][1]["seq"], 6);

        mock.push(path, Reply::status(413));
        assert!(
            matches!(cp.ship_flows(&body).await, ShipOutcome::Failed(_)),
            "413 within the stated batch size is a server error"
        );
        mock.push(path, Reply::status(507));
        assert!(matches!(
            cp.ship_flows(&body).await,
            ShipOutcome::QuotaExhausted
        ));
        mock.push(path, Reply::status(410));
        assert!(matches!(cp.ship_flows(&body).await, ShipOutcome::Revoked));
        mock.push(path, Reply::status(502));
        assert!(matches!(cp.ship_flows(&body).await, ShipOutcome::Failed(_)));
    }

    #[test]
    fn the_control_plane_must_be_https_and_the_prefix_follows_the_base_path() {
        let trust = Trust::default();
        assert!(matches!(
            ControlPlane::unauthenticated("http://cp.example", &trust, info()),
            Err(ClientError::Url(_))
        ));
        let cp = ControlPlane::unauthenticated("https://cp.example/base/", &trust, info()).unwrap();
        assert_eq!(
            cp.endpoint("lease").as_str(),
            "https://cp.example/base/roxy/v1/lease"
        );
        let cp = ControlPlane::unauthenticated("https://cp.example", &trust, info()).unwrap();
        assert_eq!(
            cp.endpoint("enrol").as_str(),
            "https://cp.example/roxy/v1/enrol"
        );
        assert!(matches!(
            ControlPlane::unauthenticated(
                "https://cp.example",
                &Trust {
                    ca_pem: Some("garbage".into()),
                },
                info()
            ),
            Err(ClientError::Ca(_))
        ));
    }
}
