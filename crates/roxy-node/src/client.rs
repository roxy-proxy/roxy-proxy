//! The HTTP client for `/roxy/v1/`: the bootstrap token for enrolment, the
//! node token for everything after, each as `Authorization: Bearer` inside
//! the server's TLS. Each call classifies the response into what the node
//! does about it; the caller never sees a raw status.

use std::io::Write as _;
use std::time::Duration;

use chrono::{DateTime, Utc};
use reqwest::header::{CONTENT_ENCODING, CONTENT_TYPE};
use reqwest::{StatusCode, Url};

use crate::protocol::{
    EnrolRequest, EnrolResponse, ErrorBody, FlowAck, Lease, NodeState, PREFIX, PROTOCOL_VERSION,
};
use crate::token::NodeToken;

/// Per-request timeout. Lease and token calls are small; a flow batch is
/// at most `batch_max_bytes`.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Largest response body the client reads before giving up on it. The
/// read stops at the cap, so a response without `Content-Length` cannot
/// make the node buffer without bound.
const MAX_BODY: usize = 16 << 20;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("control plane URL: {0}")]
    Url(String),
    #[error("control plane CA bundle: {0}")]
    Ca(String),
    #[error("building the HTTP client: {0}")]
    Build(String),
}

/// A failure the node retries with backoff: 5xx, a timeout, a connection
/// error, or a body that does not parse.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Transient(String);

impl Transient {
    fn status(status: StatusCode, body: &[u8], secrets: &[&str]) -> Self {
        Self(format!("{status}: {}", excerpt(body, secrets)))
    }
}

/// Up to 200 characters of a response body with every credential the
/// request carried replaced, so an error that quotes a body echoing the
/// token cannot put it in the log. Replaced before the cut, so a prefix
/// of a token cannot survive it either.
fn excerpt(body: &[u8], secrets: &[&str]) -> String {
    let text = redact(&String::from_utf8_lossy(body), secrets);
    let cut = text.char_indices().nth(200).map_or(text.len(), |(i, _)| i);
    text[..cut].trim().to_owned()
}

/// Longest first, so a token that is a prefix of another cannot leave the
/// longer one's tail behind. Tokens are token68 text, which JSON never
/// escapes, so a plain substring match finds an echoed one.
fn redact(text: &str, secrets: &[&str]) -> String {
    let mut secrets: Vec<&str> = secrets.iter().copied().filter(|s| !s.is_empty()).collect();
    secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
    let mut out = text.to_owned();
    for secret in secrets {
        out = out.replace(secret, "[redacted]");
    }
    out
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
    /// 401: the node token is not recognised.
    Unauthorized,
    /// 400 or another 4xx: the server refused the request itself. Retrying
    /// cannot help; handled as a 401 is, logged distinctly.
    Rejected(Transient),
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
    /// 400 or another 4xx: the server refused the batch itself. Retried
    /// like a failure (the batch is unshipped audit), logged distinctly.
    Rejected(Transient),
    /// Anything else, including a 413 for a batch within the stated size.
    Failed(Transient),
}

/// How an enrolment or renewal failed.
#[derive(Debug, thiserror::Error)]
pub enum EnrolError {
    /// 410: the node is revoked. Definite and terminal.
    #[error("revoked")]
    Revoked,
    /// 426: the server will not serve this protocol or roxy version;
    /// `missing` names what it wants.
    #[error("unsupported: missing {}", .0.missing.join(","))]
    Unsupported(ErrorBody),
    /// 401: the token was not recognised. Retried: the token a replica
    /// is shown may be newer than the one it knows of.
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    /// 400 or another 4xx: the server refused the request itself. Retrying
    /// cannot help.
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

/// A client for one control plane. Clones share the connection pool, so
/// swapping the token on renewal does not reconnect.
#[derive(Clone)]
pub struct ControlPlane {
    base: Url,
    http: reqwest::Client,
    info: NodeInfo,
    /// The active node token, last, and the one it replaced while that is
    /// unexpired, each with its `not_after`; empty before enrolment. The
    /// server still accepts the previous token and may echo it, so it is
    /// redacted too. Nothing older is held: a server only echoes the token
    /// the request carried, and the set must not grow with renewals.
    tokens: Vec<(String, DateTime<Utc>)>,
}

/// Never prints the token.
impl std::fmt::Debug for ControlPlane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlPlane")
            .field("base", &self.base.as_str())
            .field("info", &self.info)
            .field("has_token", &!self.tokens.is_empty())
            .finish_non_exhaustive()
    }
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
    /// A client with no node token, for enrolment.
    pub fn new(url: &str, trust: &Trust, info: NodeInfo) -> Result<Self, ClientError> {
        Ok(Self {
            base: parse_base(url)?,
            http: builder(trust, &info)?
                .build()
                .map_err(|e| ClientError::Build(e.to_string()))?,
            info,
            tokens: Vec::new(),
        })
    }

    /// The same client presenting `token`, good until `not_after`, as the
    /// node token. The token it replaces is kept for redaction while it is
    /// unexpired at `now`; anything older is let go.
    #[must_use]
    pub fn with_token(&self, token: &str, not_after: DateTime<Utc>, now: DateTime<Utc>) -> Self {
        let mut next = self.clone();
        let previous = self.tokens.last().filter(|(_, expiry)| *expiry > now);
        next.tokens = previous
            .cloned()
            .into_iter()
            .chain(std::iter::once((token.to_owned(), not_after)))
            .collect();
        next
    }

    /// The credentials to redact from anything a response says: every
    /// token the server may still recognise.
    fn secrets(&self) -> Vec<&str> {
        self.tokens.iter().map(|(t, _)| t.as_str()).collect()
    }

    fn endpoint(&self, name: &str) -> Url {
        let mut url = self.base.clone();
        let path = format!("{}{PREFIX}/{name}", url.path().trim_end_matches('/'));
        url.set_path(&path);
        url
    }

    /// A request under the node token.
    fn authenticated(&self, name: &str) -> reqwest::RequestBuilder {
        let req = self.http.post(self.endpoint(name));
        match self.tokens.last() {
            Some((token, _)) => req.bearer_auth(token),
            None => req,
        }
    }

    fn enrol_request(&self) -> Vec<u8> {
        serde_json::to_vec(&EnrolRequest {
            roxy_version: self.info.roxy_version.clone(),
            protocol_version: PROTOCOL_VERSION,
        })
        .unwrap_or_default()
    }

    /// `POST /enrol` with the bootstrap token.
    pub async fn enrol(&self, token: &str) -> Result<EnrolResponse, EnrolError> {
        let token = token.trim();
        let req = self
            .http
            .post(self.endpoint("enrol"))
            .bearer_auth(token)
            .header(CONTENT_TYPE, "application/json")
            .body(self.enrol_request());
        Self::enrol_call(req, &[token]).await
    }

    /// `POST /renew` under the current node token.
    pub async fn renew(&self) -> Result<EnrolResponse, EnrolError> {
        let req = self
            .authenticated("renew")
            .header(CONTENT_TYPE, "application/json")
            .body(self.enrol_request());
        Self::enrol_call(req, &self.secrets()).await
    }

    async fn enrol_call(
        req: reqwest::RequestBuilder,
        secrets: &[&str],
    ) -> Result<EnrolResponse, EnrolError> {
        let (status, body) = send(req).await.map_err(EnrolError::Failed)?;
        if status.is_success() {
            let res: EnrolResponse = serde_json::from_slice(&body)
                .map_err(|e| EnrolError::Failed(Transient(format!("enrol response: {e}"))))?;
            // A token the header cannot carry is the server's bug, not a
            // reason to give up on it.
            NodeToken::from_response(&res)
                .map_err(|e| EnrolError::Failed(Transient(format!("enrol response: {e}"))))?;
            return Ok(res);
        }
        match status {
            StatusCode::GONE => Err(EnrolError::Revoked),
            StatusCode::UPGRADE_REQUIRED => {
                Err(EnrolError::Unsupported(error_body(&body, secrets)))
            }
            StatusCode::UNAUTHORIZED => Err(EnrolError::Unauthorized(format!(
                "{status}: {}",
                excerpt(&body, secrets)
            ))),
            s if s.is_client_error() => Err(EnrolError::Rejected(format!(
                "{status}: {}",
                excerpt(&body, secrets)
            ))),
            _ => Err(EnrolError::Failed(Transient::status(
                status, &body, secrets,
            ))),
        }
    }

    /// `POST /lease`, reporting `state`.
    pub async fn fetch_lease(&self, state: &NodeState) -> LeaseFetch {
        let req = self
            .authenticated("lease")
            .header(CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(state).unwrap_or_default());
        let (status, body) = match send(req).await {
            Ok(r) => r,
            Err(e) => return LeaseFetch::Failed(e),
        };
        let secrets = self.secrets();
        match status {
            StatusCode::OK => match serde_json::from_slice::<Lease>(&body) {
                Ok(lease) => LeaseFetch::Lease(Box::new(lease)),
                Err(e) => LeaseFetch::Failed(Transient(format!("lease body: {e}"))),
            },
            StatusCode::GONE => LeaseFetch::Revoked,
            StatusCode::UPGRADE_REQUIRED => LeaseFetch::Unsupported(error_body(&body, &secrets)),
            StatusCode::UNAUTHORIZED => LeaseFetch::Unauthorized,
            s if s.is_client_error() => LeaseFetch::Rejected(Transient::status(s, &body, &secrets)),
            other => LeaseFetch::Failed(Transient::status(other, &body, &secrets)),
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
            .authenticated("flows")
            .header(CONTENT_TYPE, "application/json")
            .header(CONTENT_ENCODING, "gzip")
            .body(body);
        let (status, body) = match send(req).await {
            Ok(r) => r,
            Err(e) => return ShipOutcome::Failed(e),
        };
        let secrets = self.secrets();
        match status {
            StatusCode::OK => match serde_json::from_slice::<FlowAck>(&body) {
                Ok(ack) => ShipOutcome::Acked(ack),
                Err(e) => ShipOutcome::Failed(Transient(format!("flow ack body: {e}"))),
            },
            StatusCode::INSUFFICIENT_STORAGE => ShipOutcome::QuotaExhausted,
            StatusCode::GONE => ShipOutcome::Revoked,
            // A 413 within the stated size and a 401 are the server's
            // problem, not the batch's.
            s if s.is_client_error()
                && s != StatusCode::PAYLOAD_TOO_LARGE
                && s != StatusCode::UNAUTHORIZED =>
            {
                ShipOutcome::Rejected(Transient::status(s, &body, &secrets))
            }
            other => ShipOutcome::Failed(Transient::status(other, &body, &secrets)),
        }
    }
}

/// The error body of a non-2xx response, or a stand-in built from the
/// raw text when it is not one. Its strings are logged, so `secrets` are
/// replaced in them as in any other excerpt.
fn error_body(body: &[u8], secrets: &[&str]) -> ErrorBody {
    let parsed: ErrorBody = serde_json::from_slice(body).unwrap_or_else(|_| ErrorBody {
        error: "unknown".into(),
        message: excerpt(body, secrets),
        missing: Vec::new(),
    });
    ErrorBody {
        error: redact(&parsed.error, secrets),
        message: redact(&parsed.message, secrets),
        missing: parsed.missing.iter().map(|m| redact(m, secrets)).collect(),
    }
}

async fn send(req: reqwest::RequestBuilder) -> Result<(StatusCode, Vec<u8>), Transient> {
    let mut res = req.send().await.map_err(|e| Transient(describe(e)))?;
    let status = res.status();
    let too_large = || Transient(format!("{status}: response body too large"));
    if res.content_length().is_some_and(|n| n > MAX_BODY as u64) {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = res
        .chunk()
        .await
        .map_err(|e| Transient(format!("{status}: reading the body: {}", describe(e))))?
    {
        if body.len() + chunk.len() > MAX_BODY {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok((status, body))
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
            seq_unreserved: false,
            quarantine: None,
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
            quarantine: None,
            interception_ca: None,
        }
    }

    fn anon(mock: &MockServer) -> ControlPlane {
        let trust = Trust {
            ca_pem: Some(mock.trust_pem.clone()),
        };
        ControlPlane::new(&mock.url(), &trust, info()).unwrap()
    }

    async fn enrolled(mock: &MockServer) -> (ControlPlane, EnrolResponse) {
        let anon = anon(mock);
        mock.push("/roxy/v1/enrol", Reply::issue("node-1"));
        let res = anon.enrol("tok").await.unwrap();
        assert_eq!(res.node_id, "node-1");
        (anon.with_token(&res.token, res.not_after, Utc::now()), res)
    }

    fn in_an_hour() -> DateTime<Utc> {
        Utc::now() + chrono::Duration::hours(1)
    }

    /// The redaction set is the active token and its predecessor while
    /// that is unexpired on the caller's clock, never more; the active one
    /// stays whether or not it has expired, and a token that is a prefix
    /// of another is still wholly redacted.
    #[test]
    fn held_tokens_are_the_active_one_and_its_predecessor_redacted_longest_first() {
        let cp = ControlPlane::new("https://cp.example", &Trust::default(), info()).unwrap();
        assert_eq!(cp.secrets(), Vec::<&str>::new());
        let now = Utc::now();
        let yesterday = now - chrono::Duration::days(1);
        let cp = cp.with_token("old", yesterday, now);
        assert_eq!(
            cp.secrets(),
            ["old"],
            "the active token stays, expired or not"
        );
        let cp = cp.with_token("ab", in_an_hour(), now);
        assert_eq!(cp.secrets(), ["ab"], "a renewal lets the expired one go");
        let cp = cp.with_token("abcd", in_an_hour(), now);
        assert_eq!(cp.secrets(), ["ab", "abcd"]);
        assert_eq!(
            cp.with_token("wxyz", in_an_hour(), now + chrono::Duration::hours(2))
                .secrets(),
            ["wxyz"],
            "expiry is judged on the clock passed in, not the system's"
        );
        assert_eq!(
            redact("abcd and ab and abcdef", &cp.secrets()),
            "[redacted] and [redacted] and [redacted]ef"
        );
        assert_eq!(excerpt(b"  abcd\n", &cp.secrets()), "[redacted]");
        let cp = cp.with_token("wxyz", in_an_hour(), now);
        assert_eq!(
            cp.secrets(),
            ["abcd", "wxyz"],
            "a renewal lets go of the token before the one it replaces"
        );
    }

    #[tokio::test]
    async fn enrol_sends_the_bootstrap_token_and_the_node_token_authenticates_after() {
        let mock = MockServer::start().await;
        let (cp, res) = enrolled(&mock).await;
        let enrol = &mock.requests_to("/roxy/v1/enrol")[0];
        assert_eq!(enrol.header("authorization"), Some("Bearer tok"));
        assert_eq!(enrol.client, None, "the bootstrap token names no node");
        let body = enrol.json();
        assert_eq!(body["protocol_version"], 1);
        assert_eq!(body["roxy_version"], "0.1.0-test");
        assert_eq!(enrol.header("user-agent"), Some("roxy/0.1.0-test"));
        assert_eq!(mock.tokens_for("node-1"), std::slice::from_ref(&res.token));

        mock.push("/roxy/v1/lease", Reply::json(200, &lease("L2")));
        assert!(matches!(
            cp.fetch_lease(&state()).await,
            LeaseFetch::Lease(l) if l.lease_id == "L2"
        ));
        let fetch = &mock.requests_to("/roxy/v1/lease")[0];
        assert_eq!(fetch.method, http::Method::POST);
        assert_eq!(
            fetch.header("authorization"),
            Some(format!("Bearer {}", res.token).as_str())
        );
        assert_eq!(fetch.client.as_deref(), Some("node-1"));
        let reported = fetch.json();
        assert_eq!(reported["lease_id"], "L1");
        assert_eq!(reported["protocol_version"], 1);
        assert_eq!(reported["policy_state"], "loaded");
        assert_eq!(reported["spooled_bytes"], 7);
        assert_eq!(reported["seq_unreserved"], false);
        assert_eq!(reported["uptime_seconds"], 42);
        assert!(reported.get("features").is_none());
        assert!(reported.get("config_hash").is_none());

        let text = format!("{cp:?}");
        assert!(!text.contains(&res.token), "{text}");
        assert!(text.contains("has_token: true"));
    }

    /// The mock answers 401 itself to a token it never issued, so a client
    /// test cannot pass by scripting around authentication.
    #[tokio::test]
    async fn a_token_the_server_did_not_issue_is_unauthorized() {
        let mock = MockServer::start().await;
        let (cp, _) = enrolled(&mock).await;
        mock.fallback("/roxy/v1/lease", Reply::json(200, &lease("L2")));
        let forged = cp.with_token("not-issued", in_an_hour(), Utc::now());
        assert!(matches!(
            forged.fetch_lease(&state()).await,
            LeaseFetch::Unauthorized
        ));
        assert!(matches!(
            anon(&mock).fetch_lease(&state()).await,
            LeaseFetch::Unauthorized
        ));
        assert!(matches!(
            cp.fetch_lease(&state()).await,
            LeaseFetch::Lease(_)
        ));
        assert_eq!(mock.requests_to("/roxy/v1/lease")[0].client, None);
    }

    #[tokio::test]
    async fn enrol_distinguishes_a_rejected_token_from_an_outage() {
        let mock = MockServer::start().await;
        let anon = anon(&mock);
        mock.push("/roxy/v1/enrol", Reply::status(401));
        assert!(matches!(
            anon.enrol("rejected").await,
            Err(EnrolError::Unauthorized(m)) if m.starts_with("401")
        ));
        mock.push("/roxy/v1/enrol", Reply::status(400));
        assert!(matches!(
            anon.enrol("tok").await,
            Err(EnrolError::Rejected(m)) if m.starts_with("400")
        ));
        mock.push("/roxy/v1/enrol", Reply::status(503));
        assert!(matches!(
            anon.enrol("tok").await,
            Err(EnrolError::Failed(_))
        ));
        mock.push("/roxy/v1/enrol", Reply::Hangup);
        assert!(matches!(
            anon.enrol("tok").await,
            Err(EnrolError::Failed(_))
        ));
    }

    /// A token the header cannot carry, or a body without one, is a
    /// server fault: retried, never stored.
    #[tokio::test]
    async fn a_malformed_enrol_response_is_a_transient_failure() {
        let mock = MockServer::start().await;
        let anon = anon(&mock);
        for body in [
            r#"{"node_id":"n1","token":"has space","not_after":"2026-11-05T10:12:00Z","renew_after_seconds":1}"#,
            r#"{"node_id":"n1","token":"","not_after":"2026-11-05T10:12:00Z","renew_after_seconds":1}"#,
            r#"{"node_id":"n1","not_after":"2026-11-05T10:12:00Z","renew_after_seconds":1}"#,
        ] {
            mock.push(
                "/roxy/v1/enrol",
                Reply::Status {
                    status: 200,
                    headers: vec![],
                    body: body.as_bytes().to_vec(),
                },
            );
            assert!(
                matches!(
                    anon.enrol("tok").await,
                    Err(EnrolError::Failed(e)) if e.to_string().starts_with("enrol response")
                ),
                "{body}"
            );
        }
    }

    /// A server that echoes the credential it was shown, in a body or an
    /// error message, does not get it into the node's diagnostics.
    #[tokio::test]
    async fn response_diagnostics_never_quote_a_token() {
        let mock = MockServer::start().await;
        let anon = anon(&mock);
        let boot = "boot-7f3a9c";
        mock.push(
            "/roxy/v1/enrol",
            Reply::Status {
                status: 401,
                headers: vec![],
                body: format!(
                    "{{\"error\":\"invalid_token\",\"message\":\"{boot} is not a token\"}}"
                )
                .into_bytes(),
            },
        );
        let err = anon.enrol(boot).await.unwrap_err().to_string();
        assert!(!err.contains(boot), "{err}");
        assert!(err.contains("[redacted] is not a token"), "{err}");

        let (cp, res) = enrolled(&mock).await;
        let token = res.token.as_str();
        let echo = |status: u16, text: &str| Reply::Status {
            status,
            headers: vec![],
            body: text.replace("TOKEN", token).into_bytes(),
        };
        mock.push("/roxy/v1/lease", echo(400, "no lease for TOKEN"));
        let LeaseFetch::Rejected(e) = cp.fetch_lease(&state()).await else {
            panic!("400 is a rejection");
        };
        assert!(!e.to_string().contains(token), "{e}");
        mock.push(
            "/roxy/v1/lease",
            echo(
                426,
                r#"{"error":"unsupported","message":"TOKEN too old","missing":["roxy_version:TOKEN"]}"#,
            ),
        );
        let LeaseFetch::Unsupported(e) = cp.fetch_lease(&state()).await else {
            panic!("426 is unsupported");
        };
        assert!(!format!("{e:?}").contains(token), "{e:?}");
        assert_eq!(e.message, "[redacted] too old");
        mock.push("/roxy/v1/lease", echo(503, "TOKEN"));
        let LeaseFetch::Failed(e) = cp.fetch_lease(&state()).await else {
            panic!("503 is a failure");
        };
        assert!(!e.to_string().contains(token), "{e}");
        // A body long enough to be cut still loses the whole token.
        let padded = format!("{}TOKEN{}", "x".repeat(190), "y".repeat(300));
        mock.push("/roxy/v1/renew", echo(400, &padded));
        let err = cp.renew().await.unwrap_err().to_string();
        assert!(!err.contains(&token[..8]), "{err}");
        mock.push("/roxy/v1/flows", echo(400, "batch for TOKEN"));
        let ShipOutcome::Rejected(e) = cp.ship_flows(b"{}").await else {
            panic!("400 is a rejection");
        };
        assert!(!e.to_string().contains(token), "{e}");
    }

    #[tokio::test]
    async fn every_lease_status_maps_to_its_own_outcome() {
        let mock = MockServer::start().await;
        let (cp, _) = enrolled(&mock).await;
        let path = "/roxy/v1/lease";
        mock.push(path, Reply::status(410));
        assert!(matches!(
            cp.fetch_lease(&state()).await,
            LeaseFetch::Revoked
        ));
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
        mock.push(path, Reply::status(400));
        assert!(matches!(
            cp.fetch_lease(&state()).await,
            LeaseFetch::Rejected(e) if e.to_string().starts_with("400")
        ));
        mock.push(path, Reply::status(500));
        assert!(matches!(
            cp.fetch_lease(&state()).await,
            LeaseFetch::Failed(_)
        ));
        mock.push(path, Reply::Hangup);
        assert!(matches!(
            cp.fetch_lease(&state()).await,
            LeaseFetch::Failed(_)
        ));
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
        let other = MockServer::start().await;
        let trust = Trust {
            ca_pem: Some(other.trust_pem.clone()),
        };
        let anon = ControlPlane::new(&mock.url(), &trust, info()).unwrap();
        mock.push("/roxy/v1/enrol", Reply::issue("node-1"));
        assert!(matches!(
            anon.enrol("tok").await,
            Err(EnrolError::Failed(_))
        ));
        assert!(mock.requests_to("/roxy/v1/enrol").is_empty());
    }

    /// Renewal is the enrol body under the current node token, and the
    /// fresh token it answers is what the client presents once switched.
    #[tokio::test]
    async fn renew_sends_the_enrol_body_under_the_node_token_and_returns_a_fresh_one() {
        let mock = MockServer::start().await;
        let (cp, first) = enrolled(&mock).await;
        mock.push("/roxy/v1/renew", Reply::issue("node-1"));
        let second = cp.renew().await.unwrap();
        let renew = &mock.requests_to("/roxy/v1/renew")[0];
        assert_eq!(
            renew.header("authorization"),
            Some(format!("Bearer {}", first.token).as_str())
        );
        assert_eq!(renew.json()["protocol_version"], 1);
        assert_eq!(renew.json()["roxy_version"], "0.1.0-test");
        assert_eq!(second.node_id, "node-1");
        assert_ne!(second.token, first.token);
        mock.fallback("/roxy/v1/lease", Reply::json(200, &lease("L2")));
        cp.with_token(&second.token, second.not_after, Utc::now())
            .fetch_lease(&state())
            .await;
        assert_eq!(
            mock.requests_to("/roxy/v1/lease")[0].header("authorization"),
            Some(format!("Bearer {}", second.token).as_str())
        );
    }

    #[tokio::test]
    async fn renew_distinguishes_the_terminal_statuses() {
        let mock = MockServer::start().await;
        let (cp, _) = enrolled(&mock).await;
        let path = "/roxy/v1/renew";
        mock.push(path, Reply::status(410));
        assert!(matches!(cp.renew().await, Err(EnrolError::Revoked)));
        mock.push(
            path,
            Reply::json(
                426,
                &ErrorBody {
                    error: "unsupported".into(),
                    message: "too old".into(),
                    missing: vec!["roxy_version:0.2.0".into()],
                },
            ),
        );
        assert!(matches!(
            cp.renew().await,
            Err(EnrolError::Unsupported(e)) if e.missing == ["roxy_version:0.2.0"]
        ));
        mock.push(path, Reply::status(401));
        assert!(matches!(
            cp.renew().await,
            Err(EnrolError::Unauthorized(m)) if m.starts_with("401")
        ));
        mock.push(path, Reply::status(400));
        assert!(matches!(
            cp.renew().await,
            Err(EnrolError::Rejected(m)) if m.starts_with("400")
        ));
        mock.push(path, Reply::status(503));
        assert!(matches!(cp.renew().await, Err(EnrolError::Failed(_))));
    }

    #[tokio::test]
    async fn flow_upload_is_gzipped_and_each_status_maps() {
        let mock = MockServer::start().await;
        let (cp, _) = enrolled(&mock).await;
        let path = "/roxy/v1/flows";
        let body =
            crate::protocol::encode_flow_batch("node-1", "L1", 5, [r#"{"seq":5}"#, r#"{"seq":6}"#]);
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
        mock.push(
            path,
            Reply::Status {
                status: 400,
                headers: vec![],
                body: br#"{"error":"bad_request","message":"lease_id was never issued"}"#.to_vec(),
            },
        );
        assert!(matches!(
            cp.ship_flows(&body).await,
            ShipOutcome::Rejected(e) if e.to_string().contains("lease_id was never issued")
        ));
        mock.push(path, Reply::status(401));
        assert!(
            matches!(cp.ship_flows(&body).await, ShipOutcome::Failed(_)),
            "401 is the token's standing, not the batch's"
        );
    }

    /// Every body the client sends, and the bodies it parses, match the
    /// published contract's component schemas.
    #[tokio::test]
    async fn bodies_match_the_openapi_contract() {
        let mock = MockServer::start().await;
        let (cp, res) = enrolled(&mock).await;
        let enrol = mock.requests_to("/roxy/v1/enrol")[0].json();
        roxy_node_spec::validate("EnrolRequest", &enrol).unwrap();
        roxy_node_spec::validate("EnrolResponse", &serde_json::to_value(&res).unwrap()).unwrap();

        mock.push("/roxy/v1/lease", Reply::json(200, &lease("L2")));
        cp.fetch_lease(&state()).await;
        let node_state = mock.requests_to("/roxy/v1/lease")[0].json();
        roxy_node_spec::validate("NodeState", &node_state).unwrap();
        let fresh = NodeState {
            lease_id: None,
            ..state()
        };
        roxy_node_spec::validate("NodeState", &serde_json::to_value(&fresh).unwrap()).unwrap();

        roxy_node_spec::validate("Lease", &serde_json::to_value(lease("L")).unwrap()).unwrap();

        mock.push(
            "/roxy/v1/flows",
            Reply::json(200, &FlowAck { acked_through: 1 }),
        );
        let batch = crate::protocol::encode_flow_batch(
            "node-1",
            "L2",
            0,
            [
                r#"{"seq":0,"ts":"2026-10-06T10:12:00.123Z","event":"request"}"#,
                r#"{"seq":1,"ts":"2026-10-06T10:12:00.410Z","event":"log"}"#,
            ],
        );
        cp.ship_flows(&batch).await;
        let sent = mock.requests_to("/roxy/v1/flows")[0].json();
        roxy_node_spec::validate("FlowBatch", &sent).unwrap();
    }

    #[test]
    fn the_control_plane_must_be_https_and_the_prefix_follows_the_base_path() {
        let trust = Trust::default();
        assert!(matches!(
            ControlPlane::new("http://cp.example", &trust, info()),
            Err(ClientError::Url(_))
        ));
        let cp = ControlPlane::new("https://cp.example/base/", &trust, info()).unwrap();
        assert_eq!(
            cp.endpoint("lease").as_str(),
            "https://cp.example/base/roxy/v1/lease"
        );
        let cp = ControlPlane::new("https://cp.example", &trust, info()).unwrap();
        assert_eq!(
            cp.endpoint("enrol").as_str(),
            "https://cp.example/roxy/v1/enrol"
        );
        assert!(matches!(
            ControlPlane::new(
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
