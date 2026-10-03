//! Integration-test harness: a roxy server started in-process from a YAML
//! config, a local upstream (HTTPS with h2/h1, plain HTTP, and a WebSocket
//! echo server) whose TLS certificate comes from a test CA generated here
//! with rcgen, and clients (reqwest through the proxy, raw TCP, raw
//! CONNECT + TLS).

#![allow(dead_code)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt as _, StreamExt as _};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use roxy::run::{Running, StartOptions};
use roxy_proxy::MemorySink;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub const SECRET: &str = "s3cr3t-token-value-0123456789";

pub fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The upstream's test CA and server configs.
pub struct TestCa {
    pub pem: String,
    server: Arc<rustls::ServerConfig>,
    ws_server: Arc<rustls::ServerConfig>,
}

pub fn test_ca() -> TestCa {
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "roxy test upstream CA");
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);

    let mut leaf = CertificateParams::new(vec![
        "upstream.test".to_owned(),
        "alias.test".to_owned(),
        "ws.test".to_owned(),
        "blocked.test".to_owned(),
    ])
    .unwrap();
    leaf.subject_alt_names
        .push(SanType::IpAddress("127.0.0.1".parse().unwrap()));
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf.distinguished_name
        .push(DnType::CommonName, "upstream.test");
    let leaf_key = KeyPair::generate().unwrap();
    let leaf_cert = leaf.signed_by(&leaf_key, &issuer).unwrap();

    let chain = vec![leaf_cert.der().clone(), ca_cert.der().clone()];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    let build = |alpn: Vec<Vec<u8>>| {
        let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain.clone(), key.clone_key())
            .unwrap();
        cfg.alpn_protocols = alpn;
        Arc::new(cfg)
    };
    TestCa {
        pem: ca_cert.pem(),
        server: build(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
        ws_server: build(vec![b"http/1.1".to_vec()]),
    }
}

/// What the upstream saw.
#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    pub path_and_query: String,
    pub host: Option<String>,
    pub headers: Vec<(String, String)>,
    pub version: http::Version,
    pub body_len: u64,
}

impl Seen {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Default)]
pub struct UpState {
    pub seen: Mutex<Vec<Seen>>,
    /// Signalled when `/stream-probe` receives its first body bytes.
    pub probe: Notify,
}

type BoxBody = http_body_util::combinators::BoxBody<Bytes, Infallible>;

fn full(status: StatusCode, body: impl Into<Bytes>) -> Response<BoxBody> {
    let mut r = Response::new(Full::new(body.into()).boxed());
    *r.status_mut() = status;
    r
}

async fn handle(req: Request<Incoming>, st: Arc<UpState>) -> Result<Response<BoxBody>, Infallible> {
    let (parts, mut body) = req.into_parts();
    let path = parts.uri.path().to_owned();
    let pq = parts
        .uri
        .path_and_query()
        .map(ToString::to_string)
        .unwrap_or_default();
    if path == "/slow-headers" {
        tokio::time::sleep(Duration::from_secs(4)).await;
    }
    let mut n: u64 = 0;
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut body_ok = true;
    while let Some(frame) = body.frame().await {
        let Ok(f) = frame else {
            body_ok = false;
            break;
        };
        if let Some(d) = f.data_ref() {
            if n == 0 && path == "/stream-probe" {
                st.probe.notify_one();
            }
            n += d.len() as u64;
            for b in d {
                hash = (hash ^ u64::from(*b)).wrapping_mul(0x100_0000_01b3);
            }
        }
    }
    let headers: Vec<(String, String)> = parts
        .headers
        .iter()
        .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap_or("").to_owned()))
        .collect();
    let host = parts
        .headers
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .or_else(|| parts.uri.authority().map(ToString::to_string));
    st.seen.lock().unwrap().push(Seen {
        method: parts.method.to_string(),
        path_and_query: pq.clone(),
        host: host.clone(),
        headers: headers.clone(),
        version: parts.version,
        body_len: n,
    });
    if !body_ok {
        return Ok(full(StatusCode::BAD_REQUEST, "body error"));
    }
    Ok(match path.as_str() {
        "/status/500" => full(StatusCode::INTERNAL_SERVER_ERROR, "upstream exploded"),
        "/big" => {
            let size: usize = parts
                .uri
                .query()
                .and_then(|q| q.strip_prefix("n="))
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
            full(StatusCode::OK, vec![b'x'; size])
        }
        _ => {
            let hm: serde_json::Map<String, Value> = headers
                .iter()
                .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                .collect();
            let v = serde_json::json!({
                "method": parts.method.as_str(),
                "path": pq,
                "host": host,
                "headers": hm,
                "body_len": n,
                "body_hash": format!("{hash:016x}"),
                "version": format!("{:?}", parts.version),
            });
            let mut r = full(StatusCode::OK, v.to_string());
            r.headers_mut().insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/json"),
            );
            r
        }
    })
}

/// FNV-1a as computed by the upstream.
pub fn fnv(data: &[u8]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in data {
        hash = (hash ^ u64::from(*b)).wrapping_mul(0x100_0000_01b3);
    }
    format!("{hash:016x}")
}

pub struct Upstream {
    pub https: SocketAddr,
    pub http: SocketAddr,
    pub ws: SocketAddr,
    /// A port nothing listens on.
    pub down: u16,
    pub state: Arc<UpState>,
}

impl Upstream {
    pub fn seen(&self) -> Vec<Seen> {
        self.state.seen.lock().unwrap().clone()
    }
}

async fn serve_http<IO>(io: IO, st: Arc<UpState>)
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let svc = service_fn(move |req| handle(req, st.clone()));
    let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(io), svc)
        .await;
}

pub async fn start_upstream(ca: &TestCa) -> Upstream {
    let st = Arc::new(UpState::default());
    let https = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ws = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let down = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let up = Upstream {
        https: https.local_addr().unwrap(),
        http: http.local_addr().unwrap(),
        ws: ws.local_addr().unwrap(),
        down,
        state: st.clone(),
    };
    let acceptor = TlsAcceptor::from(ca.server.clone());
    let s = st.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = https.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let s = s.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(tcp).await {
                    serve_http(tls, s).await;
                }
            });
        }
    });
    let s = st.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = http.accept().await else {
                return;
            };
            tokio::spawn(serve_http(tcp, s.clone()));
        }
    });
    let acceptor = TlsAcceptor::from(ca.ws_server.clone());
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = ws.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let Ok(mut ws) = tokio_tungstenite::accept_async(tls).await else {
                    return;
                };
                while let Some(Ok(msg)) = ws.next().await {
                    if msg.is_close() {
                        let _ = ws.close(None).await;
                        break;
                    }
                    if (msg.is_text() || msg.is_binary()) && ws.send(msg).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    up
}

/// Options for [`Harness::start_with`].
#[derive(Default)]
pub struct Opts<'a> {
    /// The `rules:` list (YAML, indented by two spaces per item).
    pub rules: &'a str,
    /// Extra lines under `limits:`.
    pub limits: &'a str,
    /// Extra lines under `http:`.
    pub http: &'a str,
    /// `listeners[0].auth` users file content.
    pub users: Option<String>,
    /// Top-level YAML appended before `rules:` (e.g. `metrics:`).
    pub extra: &'a str,
    /// A metric store to plug in.
    pub metrics: Option<Arc<dyn roxy_proxy::MetricSource>>,
}

pub struct Harness {
    pub dir: tempfile::TempDir,
    pub config_path: PathBuf,
    pub running: Option<Running>,
    pub sink: Arc<MemorySink>,
    pub proxy: SocketAddr,
    pub ca_server: Option<SocketAddr>,
    pub roxy_ca_pem: String,
    pub upstream: Upstream,
    pub test_ca: TestCa,
}

fn indent(s: &str, n: usize) -> String {
    let pad = " ".repeat(n);
    let mut out = String::new();
    for l in s.lines() {
        out.push_str(&pad);
        out.push_str(l);
        out.push('\n');
    }
    out
}

impl Harness {
    pub async fn start(rules: &str) -> Self {
        Self::start_with(Opts {
            rules,
            ..Opts::default()
        })
        .await
    }

    /// Placeholders in rules: `{HTTPS}`, `{HTTP}`, `{WS}`, `{DOWN}` ports.
    pub fn render(&self, opts: &Opts<'_>) -> String {
        Self::render_config(self.dir.path(), &self.upstream, opts)
    }

    fn render_config(dir: &Path, up: &Upstream, opts: &Opts<'_>) -> String {
        let rules = opts
            .rules
            .replace("{HTTPS}", &up.https.port().to_string())
            .replace("{HTTP}", &up.http.port().to_string())
            .replace("{WS}", &up.ws.port().to_string())
            .replace("{DOWN}", &up.down.to_string());
        let auth = if opts.users.is_some() {
            format!(
                "    auth:\n      basic: {{ users_file: {} }}\n",
                dir.join("users").display()
            )
        } else {
            String::new()
        };
        format!(
            r#"version: 1
listeners:
  - name: proxy
    bind: 127.0.0.1:0
{auth}ca_server:
  bind: 127.0.0.1:0
tls:
  ca_dir: {dir}/ca
  upstream:
    verify: strict+extra_roots
    extra_roots: [{dir}/upstream-ca.pem]
http:
  allow_plain_in_connect: false
{http}limits:
  header_timeout: 5s
  response_header_timeout: 2s
  max_inspect_body_bytes: 1kb
{limits}upstream:
  connect_timeout: 2s
  dns:
    resolver: ["127.0.0.1:9"]
    static_hosts:
      upstream.test: 127.0.0.1
      alias.test: 127.0.0.1
      ws.test: 127.0.0.1
      blocked.test: 127.0.0.1
      down.test: 127.0.0.1
secrets:
  token: {{ file: {dir}/token }}
log:
  flow:
    connection_events: true
{extra}rules:
{rules}"#,
            dir = dir.display(),
            http = indent(opts.http, 2),
            limits = indent(opts.limits, 2),
            extra = opts.extra,
            rules = if rules.trim().is_empty() {
                "  []\n".to_owned()
            } else {
                rules
            },
        )
        .replace("rules:\n  []\n", "rules: []\n")
    }

    pub async fn start_with(opts: Opts<'_>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let test_ca = test_ca();
        std::fs::write(dir.path().join("upstream-ca.pem"), &test_ca.pem).unwrap();
        std::fs::write(dir.path().join("token"), SECRET).unwrap();
        if let Some(users) = &opts.users {
            std::fs::write(dir.path().join("users"), users).unwrap();
        }
        let upstream = start_upstream(&test_ca).await;
        let config_path = dir.path().join("roxy.yaml");
        std::fs::write(
            &config_path,
            Self::render_config(dir.path(), &upstream, &opts),
        )
        .unwrap();
        let sink = Arc::new(MemorySink::new());
        let running = roxy::run::start(
            &config_path,
            StartOptions {
                sink: Some(sink.clone()),
                metrics: opts.metrics.clone(),
                watch: true,
                ..StartOptions::default()
            },
        )
        .await
        .unwrap_or_else(|e| panic!("roxy failed to start: {e:#}"));
        let proxy = running.server.local_addr("proxy").unwrap();
        let ca_server = running.server.ca_server_addr();
        let roxy_ca_pem = std::fs::read_to_string(dir.path().join("ca/roxy-ca.pem")).unwrap();
        Self {
            dir,
            config_path,
            running: Some(running),
            sink,
            proxy,
            ca_server,
            roxy_ca_pem,
            upstream,
            test_ca,
        }
    }

    pub fn https_url(&self, path: &str) -> String {
        format!("https://upstream.test:{}{path}", self.upstream.https.port())
    }

    pub fn http_url(&self, path: &str) -> String {
        format!("http://upstream.test:{}{path}", self.upstream.http.port())
    }

    pub fn client_builder(&self) -> reqwest::ClientBuilder {
        self.client_builder_with(reqwest::Proxy::all(format!("http://{}", self.proxy)).unwrap())
    }

    pub fn client_builder_with(&self, proxy: reqwest::Proxy) -> reqwest::ClientBuilder {
        reqwest::Client::builder()
            .no_proxy()
            .proxy(proxy)
            .add_root_certificate(
                reqwest::Certificate::from_pem(self.roxy_ca_pem.as_bytes()).unwrap(),
            )
            .timeout(Duration::from_secs(30))
    }

    pub fn client(&self) -> reqwest::Client {
        self.client_builder().build().unwrap()
    }

    pub fn events(&self, kind: &str) -> Vec<Value> {
        self.sink
            .events()
            .into_iter()
            .filter(|e| e["event"] == kind)
            .collect()
    }

    /// Waits until at least `n` events of `kind` exist.
    pub async fn wait_events(&self, kind: &str, n: usize) -> Vec<Value> {
        for _ in 0..200 {
            let ev = self.events(kind);
            if ev.len() >= n {
                return ev;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!(
            "timed out waiting for {n} `{kind}` event(s); have: {:#?}",
            self.sink.events()
        );
    }

    /// Opens a CONNECT tunnel; returns the stream after `200`.
    pub async fn connect_tunnel(&self, authority: &str) -> TcpStream {
        let mut s = TcpStream::connect(self.proxy).await.unwrap();
        s.write_all(
            format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
        let head = read_head(&mut s).await;
        assert!(head.starts_with("HTTP/1.1 200"), "CONNECT failed: {head}");
        s
    }

    /// CONNECT + TLS (trusting roxy's CA) with the given SNI.
    pub async fn tls_tunnel(
        &self,
        authority: &str,
        sni: &str,
    ) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let s = self.connect_tunnel(authority).await;
        let mut roots = rustls::RootCertStore::empty();
        for c in rustls_pemfile_certs(&self.roxy_ca_pem) {
            roots.add(c).unwrap();
        }
        let mut cfg = rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        TlsConnector::from(Arc::new(cfg))
            .connect(ServerName::try_from(sni.to_owned()).unwrap(), s)
            .await
    }

    pub async fn stop(mut self) {
        if let Some(r) = self.running.take() {
            r.shutdown(Duration::from_secs(2)).await;
        }
    }
}

fn rustls_pemfile_certs(pem: &str) -> Vec<CertificateDer<'static>> {
    use rustls::pki_types::pem::PemObject;
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .map(Result::unwrap)
        .collect()
}

/// Reads a response head byte by byte (so nothing after it is consumed).
pub async fn read_head<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> String {
    let mut buf = Vec::new();
    loop {
        let mut b = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(10), r.read(&mut b))
            .await
            .expect("timed out reading a response head")
            .unwrap_or(0);
        if n == 0 {
            break;
        }
        buf.push(b[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// Reads one response (head + content-length body).
pub async fn read_response<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> (String, Vec<u8>) {
    let head = read_head(r).await;
    let len = head
        .to_ascii_lowercase()
        .lines()
        .find_map(|l| {
            l.strip_prefix("content-length: ")
                .map(|v| v.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    tokio::time::timeout(Duration::from_secs(10), r.read_exact(&mut body))
        .await
        .expect("timed out reading a body")
        .unwrap();
    (head, body)
}

/// Reads until EOF (or 10 s). Returns what was read and whether EOF was seen.
pub async fn read_to_eof<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match tokio::time::timeout(Duration::from_secs(10), r.read(&mut buf)).await {
            Ok(Ok(0) | Err(_)) => return (out, true),
            Ok(Ok(n)) => out.extend_from_slice(&buf[..n]),
            Err(_) => return (out, false),
        }
    }
}

/// Sends raw bytes to the proxy and reads until EOF.
pub async fn raw(proxy: SocketAddr, bytes: &[u8]) -> (String, bool) {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(bytes).await.unwrap();
    let (out, eof) = read_to_eof(&mut s).await;
    (String::from_utf8_lossy(&out).into_owned(), eof)
}
