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
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub(crate) const SECRET: &str = "s3cr3t-token-value-0123456789";

pub(crate) fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The upstream's test CA and server configs.
pub(crate) struct TestCa {
    pub pem: String,
    server: Arc<rustls::ServerConfig>,
    ws_server: Arc<rustls::ServerConfig>,
}

pub(crate) fn test_ca() -> TestCa {
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

impl TestCa {
    /// A server config for a leaf of this CA (`upstream.test` and others,
    /// and 127.0.0.1), offering only HTTP/1.1, as a WebSocket server needs.
    pub(crate) fn ws_server(&self) -> Arc<rustls::ServerConfig> {
        self.ws_server.clone()
    }
}

/// What the upstream saw.
#[derive(Debug, Clone)]
pub(crate) struct Seen {
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
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Default)]
pub(crate) struct UpState {
    pub seen: Mutex<Vec<Seen>>,
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
    let mut n: u64 = 0;
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut body_ok = true;
    while let Some(frame) = body.frame().await {
        let Ok(f) = frame else {
            body_ok = false;
            break;
        };
        if let Some(d) = f.data_ref() {
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
    if path == "/big" {
        let size: usize = parts
            .uri
            .query()
            .and_then(|q| q.strip_prefix("n="))
            .and_then(|n| n.parse().ok())
            .unwrap_or(0);
        return Ok(full(StatusCode::OK, vec![b'x'; size]));
    }
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
    Ok(r)
}

/// FNV-1a as computed by the upstream.
pub(crate) fn fnv(data: &[u8]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in data {
        hash = (hash ^ u64::from(*b)).wrapping_mul(0x100_0000_01b3);
    }
    format!("{hash:016x}")
}

pub(crate) struct Upstream {
    pub https: SocketAddr,
    pub http: SocketAddr,
    pub ws: SocketAddr,
    /// A port nothing listens on.
    pub down: u16,
    pub state: Arc<UpState>,
}

impl Upstream {
    pub(crate) fn seen(&self) -> Vec<Seen> {
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

/// A loopback listener with fixed, generous socket buffers. Left to the
/// kernel's autotuning, a slow reader under CPU contention can shrink the
/// receive window below the loopback MSS, after which the sender holds its
/// queued data indefinitely: an upload through roxy then stalls with every
/// byte already written to the socket, which no proxy-side timer can see.
fn listen() -> TcpListener {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(4 << 20).unwrap();
    socket.set_send_buffer_size(4 << 20).unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    socket.listen(128).unwrap()
}

pub(crate) fn start_upstream(ca: &TestCa) -> Upstream {
    let st = Arc::new(UpState::default());
    let https = listen();
    let http = listen();
    let ws = listen();
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
pub(crate) struct Opts<'a> {
    /// The `rules:` list (YAML, indented by two spaces per item).
    pub rules: &'a str,
    /// Extra lines under `limits:`. A `response_header_timeout` here
    /// replaces the harness default (2s).
    pub limits: &'a str,
    /// Extra lines under `http:`.
    pub http: &'a str,
    /// Extra lines under `tls:` (e.g. `require_sni_match: false`).
    pub tls: &'a str,
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
pub(crate) struct LogGate {
    closed: std::sync::atomic::AtomicBool,
    waiters: std::sync::Mutex<Vec<std::task::Waker>>,
}

impl LogGate {
    pub(crate) fn set_closed(&self, closed: bool) {
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

pub(crate) struct Harness {
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
    pub(crate) async fn start(rules: &str) -> Self {
        Self::start_with(Opts {
            rules,
            ..Opts::default()
        })
        .await
    }

    /// Placeholders in rules: `{HTTPS}`, `{HTTP}`, `{WS}`, `{DOWN}` ports.
    pub(crate) fn render(&self, opts: &Opts<'_>) -> String {
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
        format!(
            r#"version: 1
listeners:
  - name: proxy
    bind: 127.0.0.1:0
{listeners}ca_server:
  bind: 127.0.0.1:0
tls:
  ca_dir: {dir}/ca
{tls}  upstream:
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
            tls = indent(opts.tls, 2),
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

    pub(crate) async fn start_with(opts: Opts<'_>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let test_ca = test_ca();
        std::fs::write(dir.path().join("upstream-ca.pem"), &test_ca.pem).unwrap();
        std::fs::write(dir.path().join("token"), SECRET).unwrap();
        let upstream = start_upstream(&test_ca);
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
    pub(crate) fn captured(&self) -> Vec<(Value, Vec<u8>)> {
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

    pub(crate) fn https_url(&self, path: &str) -> String {
        format!("https://upstream.test:{}{path}", self.upstream.https.port())
    }

    pub(crate) fn http_url(&self, path: &str) -> String {
        format!("http://upstream.test:{}{path}", self.upstream.http.port())
    }

    pub(crate) fn client_builder(&self) -> reqwest::ClientBuilder {
        self.client_builder_with(reqwest::Proxy::all(format!("http://{}", self.proxy)).unwrap())
    }

    pub(crate) fn client_builder_with(&self, proxy: reqwest::Proxy) -> reqwest::ClientBuilder {
        reqwest::Client::builder()
            .no_proxy()
            .proxy(proxy)
            .add_root_certificate(
                reqwest::Certificate::from_pem(self.roxy_ca_pem.as_bytes()).unwrap(),
            )
            .timeout(Duration::from_secs(30))
    }

    pub(crate) fn client(&self) -> reqwest::Client {
        self.client_builder().build().unwrap()
    }

    pub(crate) fn events(&self, kind: &str) -> Vec<Value> {
        self.sink
            .events()
            .into_iter()
            .filter(|e| e["event"] == kind)
            .collect()
    }

    /// Waits until at least `n` events of `kind` were emitted; returns them.
    pub(crate) async fn wait_events(&self, kind: &str, n: usize) -> Vec<Value> {
        self.sink.wait_for(kind, n, Duration::from_secs(10)).await
    }

    /// Opens a CONNECT tunnel; returns the stream after `200`.
    pub(crate) async fn connect_tunnel(&self, authority: &str) -> TcpStream {
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
    pub(crate) async fn tls_tunnel(
        &self,
        authority: &str,
        sni: &str,
    ) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        self.tls_tunnel_alpn(authority, sni, &[b"http/1.1"]).await
    }

    /// CONNECT + TLS offering `alpn`.
    pub(crate) async fn tls_tunnel_alpn(
        &self,
        authority: &str,
        sni: &str,
        alpn: &[&[u8]],
    ) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let s = self.connect_tunnel(authority).await;
        self.tls_over(s, sni, alpn).await
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

    pub(crate) async fn stop(mut self) {
        if let Some(r) = self.running.take() {
            r.shutdown(Duration::from_secs(2)).await;
        }
    }
}

pub(crate) fn rustls_pemfile_certs(pem: &str) -> Vec<CertificateDer<'static>> {
    use rustls::pki_types::pem::PemObject;
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .map(Result::unwrap)
        .collect()
}

/// Reads a response head byte by byte (so nothing after it is consumed).
pub(crate) async fn read_head<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> String {
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
pub(crate) async fn read_response<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> (String, Vec<u8>) {
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
pub(crate) async fn read_to_eof<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> (Vec<u8>, bool) {
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
pub(crate) async fn raw(proxy: SocketAddr, bytes: &[u8]) -> (String, bool) {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(bytes).await.unwrap();
    let (out, eof) = read_to_eof(&mut s).await;
    (String::from_utf8_lossy(&out).into_owned(), eof)
}

/// Parses a capture stream (`capture.rxc`) into `(header, payload)` records.
pub(crate) fn parse_capture(bytes: &[u8]) -> Vec<(Value, Vec<u8>)> {
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
pub(crate) fn capture_of<'a>(
    recs: &'a [(Value, Vec<u8>)],
    flow: &str,
    dir: &str,
) -> Vec<&'a (Value, Vec<u8>)> {
    recs.iter()
        .filter(|(h, _)| h["flow"] == flow && h["dir"] == dir)
        .collect()
}

/// Concatenated `data` payloads.
pub(crate) fn capture_body(recs: &[&(Value, Vec<u8>)]) -> Vec<u8> {
    recs.iter()
        .filter(|(h, _)| h["kind"] == "data")
        .flat_map(|(_, p)| p.iter().copied())
        .collect()
}
