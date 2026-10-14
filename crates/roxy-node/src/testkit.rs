//! Test scaffolding: a scripted control plane over TLS that issues node
//! tokens, authenticates every later request by them, and records what it
//! was sent.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rcgen::{CertificateParams, KeyPair, SanType};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A self-signed server certificate for `127.0.0.1`, which is also what
/// the node pins as the control plane's root.
fn server_config() -> (String, Arc<rustls::ServerConfig>) {
    let mut params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    params
        .subject_alt_names
        .push(SanType::IpAddress("127.0.0.1".parse().unwrap()));
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
    (cert.pem(), Arc::new(config))
}

/// One scripted answer.
#[derive(Debug, Clone)]
pub enum Reply {
    /// A fixed response.
    Status {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    /// Issue a fresh node token for `node_id`, valid `lifetime_secs`.
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
    pub fn status(status: u16) -> Self {
        Self::Status {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn json(status: u16, value: &impl serde::Serialize) -> Self {
        Self::Status {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            body: serde_json::to_vec(value).unwrap(),
        }
    }

    pub fn issue(node_id: &str) -> Self {
        Self::Issue {
            node_id: node_id.to_owned(),
            lifetime_secs: 3600,
            renew_after_seconds: 1800,
        }
    }
}

/// A request the mock received.
#[derive(Debug, Clone)]
pub struct Recorded {
    pub method: Method,
    pub path: String,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    /// The node id of the unexpired node token presented, when one was.
    pub client: Option<String>,
}

impl Recorded {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// A lease fetch's body, parsed.
    pub fn node_state(&self) -> crate::protocol::NodeState {
        serde_json::from_slice(&self.body).unwrap()
    }

    pub fn json(&self) -> serde_json::Value {
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

/// A node token the mock issued.
#[derive(Debug, Clone)]
struct Issued {
    node_id: String,
    not_after: DateTime<Utc>,
}

#[derive(Default)]
struct Script {
    /// Queued replies by path (`/roxy/v1/lease`, ...).
    queued: HashMap<String, VecDeque<Reply>>,
    /// The reply for a path whose queue is empty.
    fallback: HashMap<String, Reply>,
    received: Vec<Recorded>,
    /// Every token issued, in order, each accepted until its own expiry.
    issued: Vec<(String, Issued)>,
}

/// The scripted control plane.
pub struct MockServer {
    /// The PEM the node verifies the server with.
    pub trust_pem: String,
    pub addr: SocketAddr,
    script: Arc<Mutex<Script>>,
    received: Arc<tokio::sync::Notify>,
    stop: tokio::sync::watch::Sender<bool>,
}

impl MockServer {
    pub async fn start() -> Self {
        let (trust_pem, config) = server_config();
        let acceptor = TlsAcceptor::from(config);
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let script: Arc<Mutex<Script>> = Arc::default();
        let received = Arc::new(tokio::sync::Notify::new());
        let (stop, mut stopped) = tokio::sync::watch::channel(false);
        let (s, n) = (script.clone(), received.clone());
        tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    r = tcp.accept() => r,
                    _ = stopped.changed() => return,
                };
                let Ok((stream, _)) = accepted else { continue };
                let (acceptor, s, n) = (acceptor.clone(), s.clone(), n.clone());
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let service = service_fn(move |req: Request<Incoming>| {
                        let (s, n) = (s.clone(), n.clone());
                        async move { handle(req, &s, &n).await }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                });
            }
        });
        Self {
            trust_pem,
            addr,
            script,
            received,
            stop,
        }
    }

    pub fn url(&self) -> String {
        format!("https://{}", self.addr)
    }

    /// Queues `reply` for the next request to `path`.
    pub fn push(&self, path: &str, reply: Reply) {
        lock(&self.script)
            .queued
            .entry(path.to_owned())
            .or_default()
            .push_back(reply);
    }

    /// The reply for `path` once its queue is empty.
    pub fn fallback(&self, path: &str, reply: Reply) {
        lock(&self.script).fallback.insert(path.to_owned(), reply);
    }

    pub fn received(&self) -> Vec<Recorded> {
        lock(&self.script).received.clone()
    }

    pub fn requests_to(&self, path: &str) -> Vec<Recorded> {
        self.received()
            .into_iter()
            .filter(|r| r.path == path)
            .collect()
    }

    /// The tokens issued to `node_id`, oldest first.
    pub fn tokens_for(&self, node_id: &str) -> Vec<String> {
        lock(&self.script)
            .issued
            .iter()
            .filter(|(_, i)| i.node_id == node_id)
            .map(|(t, _)| t.clone())
            .collect()
    }

    /// Waits until `path` has been requested at least `n` times.
    pub async fn wait_for(&self, path: &str, n: usize) -> Vec<Recorded> {
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

/// The node id named by the request's bearer token, when it is one the
/// mock issued and it has not expired.
fn authenticate(script: &Script, headers: &HeaderMap) -> Option<String> {
    let bearer = headers
        .get(http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")?;
    script
        .issued
        .iter()
        .find(|(t, i)| t == bearer && i.not_after > Utc::now())
        .map(|(_, i)| i.node_id.clone())
}

fn random_token() -> String {
    let mut bytes = [0u8; 24];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes)
        .expect("system randomness");
    let mut out = String::with_capacity(4 + 48);
    out.push_str("nt1-");
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// `Err` makes hyper drop the connection, which is how `Reply::Hangup`
/// gives the client a connection error. Every operation but enrolment is
/// answered `401` for a token the mock did not issue, whatever the script
/// says, so a test cannot pass by scripting around authentication.
async fn handle(
    req: Request<Incoming>,
    script: &Mutex<Script>,
    notify: &tokio::sync::Notify,
) -> Result<Response<Full<Bytes>>, Hangup> {
    let (parts, body) = req.into_parts();
    let body = body
        .collect()
        .await
        .map(|b| b.to_bytes().to_vec())
        .unwrap_or_default();
    let path = parts.uri.path().to_owned();
    let reply = {
        let mut s = lock(script);
        let client = authenticate(&s, &parts.headers);
        s.received.push(Recorded {
            method: parts.method,
            path: path.clone(),
            headers: parts.headers,
            body,
            client: client.clone(),
        });
        if client.is_none() && path != "/roxy/v1/enrol" {
            Reply::Status {
                status: 401,
                headers: vec![("content-type".into(), "application/json".into())],
                body: br#"{"error":"unrecognised","message":"node token not recognised"}"#.to_vec(),
            }
        } else {
            s.queued
                .get_mut(&path)
                .and_then(VecDeque::pop_front)
                .or_else(|| s.fallback.get(&path).cloned())
                .unwrap_or(Reply::status(404))
        }
    };
    notify.notify_waiters();
    render(reply, script).await
}

#[derive(Debug)]
struct Hangup;

impl std::fmt::Display for Hangup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("scripted hangup")
    }
}

impl std::error::Error for Hangup {}

async fn render(reply: Reply, script: &Mutex<Script>) -> Result<Response<Full<Bytes>>, Hangup> {
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
            let token = random_token();
            let not_after = Utc::now() + chrono::Duration::seconds(lifetime_secs);
            lock(script).issued.push((
                token.clone(),
                Issued {
                    node_id: node_id.clone(),
                    not_after,
                },
            ));
            let res = crate::protocol::EnrolResponse {
                node_id,
                token,
                not_after,
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
            return Box::pin(render(*inner, script)).await;
        }
    })
}
