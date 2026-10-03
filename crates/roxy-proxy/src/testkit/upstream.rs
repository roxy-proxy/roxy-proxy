//! The scripted upstream behind the connector's test dial.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use roxy_tls::LeafMinter;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::Notify;

use super::{DOWN_IP, PRIVATE_IP, UP_IP};
use crate::io::BoxIo;

/// One request as the upstream received it.
#[derive(Debug, Clone)]
pub(crate) struct Seen {
    /// The address roxy dialled.
    pub addr: SocketAddr,
    pub method: String,
    pub path: String,
    pub headers: http::HeaderMap,
    pub version: http::Version,
    /// Body bytes received so far.
    pub body: Vec<u8>,
    /// `Some(true)` once the body ended cleanly, `Some(false)` if it was
    /// cut, `None` while it is still arriving.
    pub complete: Option<bool>,
}

/// Every request the upstream received, in arrival order.
pub(crate) struct Upstream {
    minter: Arc<LeafMinter>,
    seen: Mutex<Vec<Arc<Mutex<Seen>>>>,
    changed: Notify,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Upstream {
    pub(crate) fn new(minter: Arc<LeafMinter>) -> Arc<Self> {
        Arc::new(Self {
            minter,
            seen: Mutex::new(Vec::new()),
            changed: Notify::new(),
        })
    }

    /// A snapshot of what arrived so far.
    pub(crate) fn seen(&self) -> Vec<Seen> {
        lock(&self.seen).iter().map(|s| lock(s).clone()).collect()
    }

    /// Waits until `n` requests arrived and each body finished or was cut.
    pub(crate) async fn wait_seen(&self, n: usize) -> Vec<Seen> {
        let wait = async {
            loop {
                let changed = self.changed.notified();
                let seen = self.seen();
                if seen.len() >= n && seen.iter().all(|s| s.complete.is_some()) {
                    return seen;
                }
                changed.await;
            }
        };
        tokio::time::timeout(Duration::from_secs(10), wait)
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "upstream: wanted {n} finished requests, have {:#?}",
                    self.seen()
                )
            })
    }

    /// The connector's dial: an in-memory connection served by this
    /// upstream (TLS on port 443).
    pub(crate) fn dial(self: &Arc<Self>, addr: SocketAddr) -> std::io::Result<BoxIo> {
        let ip = addr.ip().to_string();
        if ip == DOWN_IP {
            return Err(std::io::ErrorKind::ConnectionRefused.into());
        }
        assert!(
            ip == UP_IP || ip == PRIVATE_IP,
            "dial to an unexpected address {addr}"
        );
        let (ours, theirs) = tokio::io::duplex(64 * 1024);
        let me = self.clone();
        tokio::spawn(async move { me.serve(addr, ours).await });
        Ok(Box::new(theirs))
    }

    async fn serve(self: Arc<Self>, addr: SocketAddr, io: tokio::io::DuplexStream) {
        if addr.port() == 443 {
            let name = roxy_tls::server_name_for_host("up.test").unwrap();
            let cfg = roxy_tls::server_config_for(self.minter.clone(), name, true);
            let Ok(tls) = tokio_rustls::TlsAcceptor::from(cfg).accept(io).await else {
                return;
            };
            let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
            self.serve_http(addr, tls, h2).await;
        } else {
            self.serve_http(addr, io, false).await;
        }
    }

    async fn serve_http<IO>(self: Arc<Self>, addr: SocketAddr, io: IO, h2: bool)
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let me = self.clone();
        let svc = service_fn(move |req| {
            let me = me.clone();
            async move { Ok::<_, Infallible>(me.answer(addr, req).await) }
        });
        let io = TokioIo::new(io);
        if h2 {
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(io, svc)
                .await;
        } else {
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, svc)
                .with_upgrades()
                .await;
        }
    }

    /// Answers by path:
    ///
    /// * `/early`: `200 early` at once, without reading the body;
    /// * `/status/<n>`: reads the body, answers `<n>`;
    /// * `/echo`: reads the body, answers with the same bytes, with
    ///   `content-encoding` set to the request's `x-echo-encoding` and the
    ///   status to its `x-echo-status` (default `200`);
    /// * a WebSocket upgrade: `101`, then echoes bytes;
    /// * anything else: reads the body, answers `200` with JSON
    ///   `{method, path, host, body_len, via}`.
    async fn answer(
        self: Arc<Self>,
        addr: SocketAddr,
        mut req: http::Request<Incoming>,
    ) -> http::Response<Full<Bytes>> {
        let path = req
            .uri()
            .path_and_query()
            .map_or("/", |p| p.as_str())
            .to_owned();
        let entry = Arc::new(Mutex::new(Seen {
            addr,
            method: req.method().to_string(),
            path: path.clone(),
            headers: req.headers().clone(),
            version: req.version(),
            body: Vec::new(),
            complete: None,
        }));
        lock(&self.seen).push(entry.clone());
        self.changed.notify_waiters();

        if let Some(key) = req.headers().get("sec-websocket-key").cloned() {
            lock(&entry).complete = Some(true);
            self.changed.notify_waiters();
            return upgrade_and_echo(&mut req, &key);
        }

        let host = req
            .headers()
            .get("host")
            .map(|h| String::from_utf8_lossy(h.as_bytes()).into_owned())
            .or_else(|| req.uri().authority().map(ToString::to_string));
        let via = req
            .headers()
            .get("x-via")
            .map(|h| String::from_utf8_lossy(h.as_bytes()).into_owned());
        let method = req.method().to_string();
        let echo_encoding = req.headers().get("x-echo-encoding").cloned();
        let echo_status = req.headers().get("x-echo-status").cloned();
        let body = req.into_body();
        let mine = entry.clone();
        let me = self.clone();
        let read = async move {
            let mut body = body;
            loop {
                match body.frame().await {
                    Some(Ok(f)) => {
                        if let Some(d) = f.data_ref() {
                            lock(&entry).body.extend_from_slice(d);
                            me.changed.notify_waiters();
                        }
                    }
                    Some(Err(_)) => {
                        lock(&entry).complete = Some(false);
                        me.changed.notify_waiters();
                        return None;
                    }
                    None => {
                        let mut e = lock(&entry);
                        e.complete = Some(true);
                        let n = e.body.len();
                        drop(e);
                        me.changed.notify_waiters();
                        return Some(n);
                    }
                }
            }
        };

        if path == "/early" {
            tokio::spawn(read);
            return http::Response::new(Full::new(Bytes::from_static(b"early")));
        }
        let Some(body_len) = read.await else {
            return http::Response::builder()
                .status(400)
                .body(Full::default())
                .unwrap();
        };
        if path == "/echo" {
            let body = lock(&mine).body.clone();
            return echo(echo_status.as_ref(), echo_encoding, body);
        }
        if let Some(code) = path.strip_prefix("/status/") {
            return http::Response::builder()
                .status(code.parse::<u16>().unwrap())
                .body(Full::default())
                .unwrap();
        }
        let json = serde_json::json!({
            "method": method,
            "path": path,
            "host": host,
            "body_len": body_len,
            "via": via,
        });
        http::Response::builder()
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(json.to_string())))
            .unwrap()
    }
}

/// The `/echo` answer: `body`, with the requested status and coding.
fn echo(
    status: Option<&http::HeaderValue>,
    encoding: Option<http::HeaderValue>,
    body: Vec<u8>,
) -> http::Response<Full<Bytes>> {
    let mut res = http::Response::builder();
    if let Some(s) = status {
        res = res.status(s.to_str().unwrap().parse::<u16>().unwrap());
    }
    if let Some(v) = encoding {
        res = res.header("content-encoding", v);
    }
    res.body(Full::new(Bytes::from(body))).unwrap()
}

/// Answers a WebSocket upgrade with `101` and echoes the upgraded bytes.
fn upgrade_and_echo(
    req: &mut http::Request<Incoming>,
    key: &http::HeaderValue,
) -> http::Response<Full<Bytes>> {
    let on = hyper::upgrade::on(req);
    tokio::spawn(async move {
        if let Ok(up) = on.await {
            let mut up = TokioIo::new(up);
            let mut buf = vec![0u8; 16 * 1024];
            while let Ok(n) = up.read(&mut buf).await {
                if n == 0 || up.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        }
    });
    let accept = roxy_http::ws::compute_accept(&String::from_utf8_lossy(key.as_bytes()));
    http::Response::builder()
        .status(101)
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-accept", accept)
        .body(Full::default())
        .unwrap()
}
