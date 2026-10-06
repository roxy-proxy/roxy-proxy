//! Test scaffolding: a CA that issues node certificates from CSRs, and a
//! scripted control plane over mTLS that records what it was sent.

#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DnType, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::identity::NODE_ID_URI_PREFIX;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A CA for the control plane's server certificate and the node
/// certificates it issues.
pub(crate) struct TestCa {
    pub pem: String,
    der: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
}

impl TestCa {
    pub(crate) fn new() -> Self {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::DigitalSignature];
        params
            .distinguished_name
            .push(DnType::CommonName, "roxy test control plane CA");
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        Self {
            pem: cert.pem(),
            der: cert.der().clone(),
            issuer: Issuer::new(params, key),
        }
    }

    /// Signs `csr_pem` as a node certificate for `node_id`, valid for
    /// `lifetime_secs`.
    pub(crate) fn issue(&self, csr_pem: &str, node_id: &str, lifetime_secs: i64) -> String {
        let mut csr = CertificateSigningRequestParams::from_pem(csr_pem).unwrap();
        let uri = format!("{NODE_ID_URI_PREFIX}{node_id}");
        csr.params.subject_alt_names = vec![SanType::URI(uri.as_str().try_into().unwrap())];
        csr.params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(1);
        csr.params.not_after =
            time::OffsetDateTime::now_utc() + time::Duration::seconds(lifetime_secs);
        csr.signed_by(&self.issuer).unwrap().pem()
    }

    pub(crate) fn issue_without_node_id(&self, csr_pem: &str) -> String {
        let csr = CertificateSigningRequestParams::from_pem(csr_pem).unwrap();
        csr.signed_by(&self.issuer).unwrap().pem()
    }

    /// A server config for `127.0.0.1` that asks for, but does not
    /// require, a client certificate chaining to this CA.
    fn server_config(&self) -> Arc<rustls::ServerConfig> {
        let mut params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        params
            .subject_alt_names
            .push(SanType::IpAddress("127.0.0.1".parse().unwrap()));
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &self.issuer).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.der.clone()).unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .allow_unauthenticated()
            .build()
            .unwrap();
        let config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap();
        Arc::new(config)
    }
}

/// One scripted answer.
#[derive(Debug, Clone)]
pub(crate) enum Reply {
    /// A fixed response.
    Status {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    /// Sign the CSR in the request as `node_id`, valid `lifetime_secs`.
    Issue {
        node_id: String,
        lifetime_secs: i64,
        renew_after_seconds: u64,
    },
    /// Close the connection without answering.
    Hangup,
    /// Answer after `delay` (the client times out first when it is long).
    Delayed(Duration, Box<Reply>),
}

impl Reply {
    pub(crate) fn status(status: u16) -> Self {
        Self::Status {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub(crate) fn json(status: u16, value: &impl serde::Serialize) -> Self {
        Self::Status {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            body: serde_json::to_vec(value).unwrap(),
        }
    }

    pub(crate) fn with_header(mut self, name: &str, value: &str) -> Self {
        if let Self::Status { headers, .. } = &mut self {
            headers.push((name.to_owned(), value.to_owned()));
        }
        self
    }

    pub(crate) fn issue(node_id: &str) -> Self {
        Self::Issue {
            node_id: node_id.to_owned(),
            lifetime_secs: 3600,
            renew_after_seconds: 1800,
        }
    }
}

/// A request the mock received.
#[derive(Debug, Clone)]
pub(crate) struct Recorded {
    pub method: Method,
    pub path: String,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    /// The node id from the client certificate, when one was presented.
    pub client: Option<String>,
}

impl Recorded {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    pub(crate) fn json(&self) -> serde_json::Value {
        let body = if self.header("content-encoding") == Some("gzip") {
            use std::io::Read as _;
            let mut out = Vec::new();
            flate2::read::GzDecoder::new(self.body.as_slice())
                .read_to_end(&mut out)
                .unwrap();
            out
        } else {
            self.body.clone()
        };
        serde_json::from_slice(&body).unwrap()
    }
}

#[derive(Default)]
struct Script {
    /// Queued replies by path (`/roxy/v1/lease`, ...).
    queued: HashMap<String, VecDeque<Reply>>,
    /// The reply for a path whose queue is empty.
    fallback: HashMap<String, Reply>,
    received: Vec<Recorded>,
}

/// The scripted control plane.
pub(crate) struct MockServer {
    pub ca: Arc<TestCa>,
    pub addr: SocketAddr,
    script: Arc<Mutex<Script>>,
    received: Arc<tokio::sync::Notify>,
    stop: tokio::sync::watch::Sender<bool>,
}

impl MockServer {
    pub(crate) async fn start() -> Self {
        let ca = Arc::new(TestCa::new());
        let acceptor = TlsAcceptor::from(ca.server_config());
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let script: Arc<Mutex<Script>> = Arc::default();
        let received = Arc::new(tokio::sync::Notify::new());
        let (stop, mut stopped) = tokio::sync::watch::channel(false);
        let (s, n, issuer) = (script.clone(), received.clone(), ca.clone());
        tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    r = tcp.accept() => r,
                    _ = stopped.changed() => return,
                };
                let Ok((stream, _)) = accepted else { continue };
                let (acceptor, s, n, issuer) =
                    (acceptor.clone(), s.clone(), n.clone(), issuer.clone());
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let client = tls
                        .get_ref()
                        .1
                        .peer_certificates()
                        .and_then(|certs| certs.first())
                        .and_then(|c| {
                            let (_, x509) = x509_parser::parse_x509_certificate(c).ok()?;
                            let san = x509.subject_alternative_name().ok()??;
                            san.value.general_names.iter().find_map(|g| match g {
                                x509_parser::extensions::GeneralName::URI(u) => {
                                    u.strip_prefix(NODE_ID_URI_PREFIX).map(str::to_owned)
                                }
                                _ => None,
                            })
                        });
                    let service = service_fn(move |req: Request<Incoming>| {
                        let (s, n, client, issuer) =
                            (s.clone(), n.clone(), client.clone(), issuer.clone());
                        async move { handle(req, client, &s, &n, &issuer).await }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                });
            }
        });
        Self {
            ca,
            addr,
            script,
            received,
            stop,
        }
    }

    pub(crate) fn url(&self) -> String {
        format!("https://{}", self.addr)
    }

    /// Queues `reply` for the next request to `path`.
    pub(crate) fn push(&self, path: &str, reply: Reply) {
        lock(&self.script)
            .queued
            .entry(path.to_owned())
            .or_default()
            .push_back(reply);
    }

    /// The reply for `path` once its queue is empty.
    pub(crate) fn fallback(&self, path: &str, reply: Reply) {
        lock(&self.script).fallback.insert(path.to_owned(), reply);
    }

    pub(crate) fn received(&self) -> Vec<Recorded> {
        lock(&self.script).received.clone()
    }

    pub(crate) fn requests_to(&self, path: &str) -> Vec<Recorded> {
        self.received()
            .into_iter()
            .filter(|r| r.path == path)
            .collect()
    }

    /// Waits until `path` has been requested at least `n` times.
    pub(crate) async fn wait_for(&self, path: &str, n: usize) -> Vec<Recorded> {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let notified = self.received.notified();
                let got = self.requests_to(path);
                if got.len() >= n {
                    return got;
                }
                notified.await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "waited for {n} request(s) to {path}; got {:?}",
                self.received()
                    .iter()
                    .map(|r| r.path.clone())
                    .collect::<Vec<_>>()
            )
        })
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}

/// `Err` makes hyper drop the connection, which is how `Reply::Hangup`
/// gives the client a connection error.
async fn handle(
    req: Request<Incoming>,
    client: Option<String>,
    script: &Mutex<Script>,
    notify: &tokio::sync::Notify,
    issuer: &TestCa,
) -> Result<Response<Full<Bytes>>, Hangup> {
    let (parts, body) = req.into_parts();
    let body = body.collect().await.map(|b| b.to_bytes().to_vec()).unwrap_or_default();
    let path = parts.uri.path().to_owned();
    let recorded = Recorded {
        method: parts.method,
        path: path.clone(),
        headers: parts.headers,
        body,
        client,
    };
    let reply = {
        let mut s = lock(script);
        let reply = s
            .queued
            .get_mut(&path)
            .and_then(VecDeque::pop_front)
            .or_else(|| s.fallback.get(&path).cloned())
            .unwrap_or(Reply::status(404));
        s.received.push(recorded.clone());
        reply
    };
    notify.notify_waiters();
    render(reply, &recorded, issuer).await
}

#[derive(Debug)]
struct Hangup;

impl std::fmt::Display for Hangup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("scripted hangup")
    }
}

impl std::error::Error for Hangup {}

async fn render(
    reply: Reply,
    req: &Recorded,
    issuer: &TestCa,
) -> Result<Response<Full<Bytes>>, Hangup> {
    Ok(match reply {
        Reply::Status {
            status,
            headers,
            body,
        } => {
            let mut res = Response::new(Full::new(Bytes::from(body)));
            *res.status_mut() = StatusCode::from_u16(status).unwrap();
            for (k, v) in headers {
                res.headers_mut().insert(
                    http::HeaderName::try_from(k).unwrap(),
                    http::HeaderValue::try_from(v).unwrap(),
                );
            }
            res
        }
        Reply::Issue {
            node_id,
            lifetime_secs,
            renew_after_seconds,
        } => {
            let body: crate::protocol::CertificateRequest = serde_json::from_slice(&req.body)
                .unwrap_or_else(|e| panic!("bad certificate request body: {e}"));
            let chain = issuer.issue(&body.csr, &node_id, lifetime_secs);
            let res = crate::protocol::CertificateResponse {
                node_id,
                certificate_chain: chain,
                not_after: chrono::Utc::now() + chrono::Duration::seconds(lifetime_secs),
                renew_after_seconds,
            };
            let mut out = Response::new(Full::new(Bytes::from(serde_json::to_vec(&res).unwrap())));
            out.headers_mut().insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/json"),
            );
            out
        }
        Reply::Hangup => return Err(Hangup),
        Reply::Delayed(d, inner) => {
            tokio::time::sleep(d).await;
            return Box::pin(render(*inner, req, issuer)).await;
        }
    })
}
