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
    /// The body ended cleanly (not cut or failed).
    pub body_ok: bool,
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
    /// Upgrade request headers the WebSocket server saw, one list per
    /// connection.
    pub ws_upgrades: Mutex<Vec<Vec<(String, String)>>>,
    /// Data messages the WebSocket server received.
    pub ws_received: Mutex<Vec<Vec<u8>>>,
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
        body_ok,
    });
    if !body_ok {
        return Ok(full(StatusCode::BAD_REQUEST, "body error"));
    }
    Ok(match path.as_str() {
        "/status/500" => full(StatusCode::INTERNAL_SERVER_ERROR, "upstream exploded"),
        // Answers without echoing anything back (endpoint tests).
        p if p.starts_with("/no-echo") => full(StatusCode::OK, "scored"),
        // `n` chunks, `ms` apart: a long-lived streamed response.
        "/drip" => {
            let q = parts.uri.query().unwrap_or("");
            let arg = |k: &str| {
                q.split('&')
                    .find_map(|kv| kv.strip_prefix(k)?.strip_prefix('='))
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0)
            };
            let (n, ms) = (arg("n"), arg("ms"));
            let chunks = futures_util::stream::unfold(0, move |i| async move {
                if i == n {
                    return None;
                }
                tokio::time::sleep(Duration::from_millis(ms)).await;
                let frame = hyper::body::Frame::data(Bytes::from(format!("chunk{i};")));
                Some((Ok::<_, Infallible>(frame), i + 1))
            });
            Response::new(BoxBody::new(http_body_util::StreamBody::new(chunks)))
        }
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

    pub fn ws_upgrades(&self) -> Vec<Vec<(String, String)>> {
        self.state.ws_upgrades.lock().unwrap().clone()
    }

    pub fn ws_received(&self) -> Vec<Vec<u8>> {
        self.state.ws_received.lock().unwrap().clone()
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
    let s = st.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = ws.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let s = s.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                #[allow(clippy::result_large_err)] // tungstenite's callback type
                let record = |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
                              res| {
                    let headers = req
                        .headers()
                        .iter()
                        .map(|(n, v)| (n.as_str().to_owned(), v.to_str().unwrap_or("").to_owned()))
                        .collect();
                    s.ws_upgrades.lock().unwrap().push(headers);
                    Ok(res)
                };
                let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(tls, record).await else {
                    return;
                };
                while let Some(Ok(msg)) = ws.next().await {
                    if msg.is_close() {
                        let _ = ws.close(None).await;
                        break;
                    }
                    if msg.is_text() || msg.is_binary() {
                        s.ws_received
                            .lock()
                            .unwrap()
                            .push(msg.clone().into_data().to_vec());
                        if ws.send(msg).await.is_err() {
                            break;
                        }
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
    /// Extra lines under `limits:`. A `response_header_timeout` here
    /// replaces the harness default (2s).
    pub limits: &'a str,
    /// Extra lines under `http:`.
    pub http: &'a str,
    /// `listeners[0].auth` users file content.
    pub users: Option<String>,
    /// Top-level YAML appended before `rules:` (e.g. `metrics:`).
    pub extra: &'a str,
    /// More `listeners:` items (YAML, indented by two spaces per item);
    /// the rule placeholders work here too.
    pub listeners: &'a str,
    /// Extra lines under `upstream:` (e.g. `deny_lists: [x]`).
    pub upstream: &'a str,
    /// Extra lines under `log.flow:`.
    pub flow_log: &'a str,
    /// A metric store to plug in.
    pub metrics: Option<Arc<dyn roxy_proxy::MetricSource>>,
    /// Hold the flow sink "behind" (not ready) while the gate is closed.
    pub log_gate: Option<Arc<LogGate>>,
    /// Lines under `log.capture:`; when set, `capture_dir` is
    /// `<tempdir>/capture`.
    pub capture: Option<&'a str>,
    /// Use this `capture_dir` instead of `<tempdir>/capture`.
    pub capture_dir: Option<&'a Path>,
}

/// Makes the test flow sink report backpressure on demand.
#[derive(Default)]
pub struct LogGate {
    closed: std::sync::atomic::AtomicBool,
    waiters: std::sync::Mutex<Vec<std::task::Waker>>,
}

impl LogGate {
    pub fn set_closed(&self, closed: bool) {
        self.closed
            .store(closed, std::sync::atomic::Ordering::SeqCst);
        if !closed {
            for w in std::mem::take(&mut *self.waiters.lock().unwrap()) {
                w.wake();
            }
        }
    }
}

/// A [`MemorySink`] whose readiness follows a [`LogGate`].
struct GatedSink {
    inner: Arc<MemorySink>,
    gate: Option<Arc<LogGate>>,
}

impl roxy_proxy::FlowSink for GatedSink {
    fn emit(&self, event: &roxy_proxy::FlowEvent) {
        self.inner.emit(event);
    }

    fn poll_ready(&self, cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        let Some(g) = &self.gate else {
            return std::task::Poll::Ready(());
        };
        let mut waiters = g.waiters.lock().unwrap();
        if g.closed.load(std::sync::atomic::Ordering::SeqCst) {
            waiters.push(cx.waker().clone());
            std::task::Poll::Pending
        } else {
            std::task::Poll::Ready(())
        }
    }
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
        let ports = |s: &str| {
            s.replace("{HTTPS}", &up.https.port().to_string())
                .replace("{HTTP}", &up.http.port().to_string())
                .replace("{WS}", &up.ws.port().to_string())
                .replace("{DOWN}", &up.down.to_string())
        };
        let rules = ports(opts.rules);
        let listeners = ports(opts.listeners);
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
{auth}{listeners}ca_server:
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
{response_header_timeout}  max_inspect_body_bytes: 1kb
{limits}upstream:
  connect_timeout: 2s
{upstream}  dns:
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
{flow_log}{capture}{extra}rules:
{rules}"#,
            dir = dir.display(),
            http = indent(opts.http, 2),
            limits = indent(opts.limits, 2),
            response_header_timeout = if opts.limits.contains("response_header_timeout") {
                ""
            } else {
                "  response_header_timeout: 2s\n"
            },
            upstream = indent(opts.upstream, 2),
            flow_log = indent(opts.flow_log, 4),
            extra = opts.extra,
            capture = opts.capture.map_or_else(String::new, |c| format!(
                "  capture:\n{}capture_dir: {}\n",
                indent(if c.trim().is_empty() { "all: false" } else { c }, 4),
                opts.capture_dir.map_or_else(
                    || format!("{}/capture", dir.display()),
                    |d| d.display().to_string()
                )
            )),
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
        let gated = Arc::new(GatedSink {
            inner: sink.clone(),
            gate: opts.log_gate.clone(),
        });
        let running = roxy::run::start(
            &config_path,
            StartOptions {
                sink: Some(gated),
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

    /// Every capture record so far, `(header, payload)`, after flushing
    /// the capture log.
    pub fn captured(&self) -> Vec<(Value, Vec<u8>)> {
        let log = self
            .running
            .as_ref()
            .unwrap()
            .server
            .handle()
            .capture()
            .expect("capture enabled");
        assert!(log.flush());
        parse_capture(&std::fs::read(log.path()).unwrap())
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
        self.tls_tunnel_alpn(authority, sni, &[b"http/1.1"]).await
    }

    /// CONNECT + TLS offering `alpn`.
    pub async fn tls_tunnel_alpn(
        &self,
        authority: &str,
        sni: &str,
        alpn: &[&[u8]],
    ) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let s = self.connect_tunnel(authority).await;
        self.tls_over(s, sni, alpn).await
    }

    /// TLS for `sni` (ALPN `http/1.1`) straight to `addr`, trusting roxy's
    /// CA: a client of a direct listener.
    pub async fn tls_direct(
        &self,
        addr: SocketAddr,
        sni: &str,
    ) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let s = TcpStream::connect(addr).await?;
        self.tls_over(s, sni, &[b"http/1.1"]).await
    }

    async fn tls_over(
        &self,
        s: TcpStream,
        sni: &str,
        alpn: &[&[u8]],
    ) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let mut roots = rustls::RootCertStore::empty();
        for c in rustls_pemfile_certs(&self.roxy_ca_pem) {
            roots.add(c).unwrap();
        }
        let mut cfg = rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        TlsConnector::from(Arc::new(cfg))
            .connect(ServerName::try_from(sni.to_owned()).unwrap(), s)
            .await
    }

    /// A raw `h2` client over CONNECT + TLS (ALPN `h2`) to the HTTPS
    /// upstream. The connection task is returned so tests can watch it end.
    pub async fn h2_client(
        &self,
    ) -> (
        h2::client::SendRequest<Bytes>,
        tokio::task::JoinHandle<Result<(), h2::Error>>,
    ) {
        let authority = format!("upstream.test:{}", self.upstream.https.port());
        let tls = self
            .tls_tunnel_alpn(&authority, "upstream.test", &[b"h2"])
            .await
            .unwrap();
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
        let (send, conn) = h2::client::handshake(tls).await.unwrap();
        (send, tokio::spawn(conn))
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

/// Sends one h2 request (no body) and returns the response head and body,
/// or the stream / connection error.
pub async fn h2_get(
    send: &h2::client::SendRequest<Bytes>,
    uri: &str,
    headers: &[(&str, &str)],
) -> Result<(http::response::Parts, Bytes), h2::Error> {
    let mut b = http::Request::builder().method("GET").uri(uri);
    for (n, v) in headers {
        b = b.header(*n, *v);
    }
    let req = b.body(()).unwrap();
    let mut ready = send.clone().ready().await?;
    let (resp, _) = ready.send_request(req, true)?;
    let resp = tokio::time::timeout(Duration::from_secs(10), resp)
        .await
        .expect("timed out waiting for an h2 response")?;
    let (parts, mut body) = resp.into_parts();
    let mut out = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        let _ = body.flow_control().release_capacity(chunk.len());
        out.extend_from_slice(&chunk);
    }
    Ok((parts, Bytes::from(out)))
}

/// A minimal HPACK encoder: every field as a literal without indexing, no
/// Huffman (so tests can send what the `h2` client refuses to).
fn hpack_literal(out: &mut Vec<u8>, name: &str, value: &str) {
    fn len(out: &mut Vec<u8>, n: usize) {
        assert!(n < 127, "the test HPACK encoder only does short strings");
        out.push(u8::try_from(n).unwrap());
    }
    out.push(0x00);
    len(out, name.len());
    out.extend_from_slice(name.as_bytes());
    len(out, value.len());
    out.extend_from_slice(value.as_bytes());
}

fn h2_frame(out: &mut Vec<u8>, kind: u8, flags: u8, stream: u32, payload: &[u8]) {
    let n = u32::try_from(payload.len()).unwrap();
    out.extend_from_slice(&n.to_be_bytes()[1..]);
    out.push(kind);
    out.push(flags);
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(payload);
}

/// h2 frame type codes used by the tests.
pub const H2_HEADERS: u8 = 0x1;
pub const H2_RST_STREAM: u8 = 0x3;
pub const H2_SETTINGS: u8 = 0x4;
pub const H2_GOAWAY: u8 = 0x7;

/// Opens an h2 tunnel and sends stream 1 with exactly `fields`
/// (pseudo-headers included, in order) and `END_STREAM`, frame by frame.
/// Returns the frames `(type, flags, stream id, payload)` received until
/// stream 1 is reset or answered, or the connection ends.
pub async fn h2_raw_request(h: &Harness, fields: &[(&str, &str)]) -> Vec<(u8, u8, u32, Vec<u8>)> {
    let authority = format!("upstream.test:{}", h.upstream.https.port());
    let mut tls = h
        .tls_tunnel_alpn(&authority, "upstream.test", &[b"h2"])
        .await
        .unwrap();
    let mut out = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    h2_frame(&mut out, H2_SETTINGS, 0, 0, &[]);
    let mut block = Vec::new();
    for (n, v) in fields {
        hpack_literal(&mut block, n, v);
    }
    // END_HEADERS | END_STREAM
    h2_frame(&mut out, H2_HEADERS, 0x4 | 0x1, 1, &block);
    tls.write_all(&out).await.unwrap();
    let mut frames = Vec::new();
    loop {
        let mut head = [0u8; 9];
        let read = tokio::time::timeout(Duration::from_secs(10), tls.read_exact(&mut head)).await;
        let Ok(Ok(_)) = read else { break };
        let len = (usize::from(head[0]) << 16) | (usize::from(head[1]) << 8) | usize::from(head[2]);
        let mut payload = vec![0u8; len];
        if tls.read_exact(&mut payload).await.is_err() {
            break;
        }
        let (kind, flags) = (head[3], head[4]);
        let stream = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
        if kind == H2_SETTINGS && flags & 0x1 == 0 {
            let mut ack = Vec::new();
            h2_frame(&mut ack, H2_SETTINGS, 0x1, 0, &[]);
            tls.write_all(&ack).await.unwrap();
        }
        let done =
            (stream == 1 && (kind == H2_RST_STREAM || kind == H2_HEADERS)) || kind == H2_GOAWAY;
        frames.push((kind, flags, stream, payload));
        if done {
            break;
        }
    }
    frames
}

/// Parses a capture stream (`capture.rxc`) into `(header, payload)` records.
pub fn parse_capture(bytes: &[u8]) -> Vec<(Value, Vec<u8>)> {
    let mut out = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let nl = rest.iter().position(|&b| b == b'\n').expect("header line");
        let head: Value = serde_json::from_slice(&rest[..nl]).unwrap();
        let len = usize::try_from(head["len"].as_u64().unwrap()).unwrap();
        let payload = rest[nl + 1..nl + 1 + len].to_vec();
        assert_eq!(rest[nl + 1 + len], b'\n', "record terminator");
        rest = &rest[nl + 2 + len..];
        out.push((head, payload));
    }
    out
}

/// The records of one flow and direction, in order.
pub fn capture_of<'a>(
    recs: &'a [(Value, Vec<u8>)],
    flow: &str,
    dir: &str,
) -> Vec<&'a (Value, Vec<u8>)> {
    recs.iter()
        .filter(|(h, _)| h["flow"] == flow && h["dir"] == dir)
        .collect()
}

/// Concatenated `data` payloads.
pub fn capture_body(recs: &[&(Value, Vec<u8>)]) -> Vec<u8> {
    recs.iter()
        .filter(|(h, _)| h["kind"] == "data")
        .flat_map(|(_, p)| p.iter().copied())
        .collect()
}
