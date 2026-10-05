//! The scripted upstream behind the connector's test dial.

pub(crate) mod service;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt as _, StreamExt as _};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use roxy_tls::LeafMinter;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::Notify;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::Role;

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

/// The response body type the upstream answers with.
type Body = BoxBody<Bytes, Infallible>;

/// Every request the upstream received, in arrival order.
pub(crate) struct Upstream {
    minter: Arc<LeafMinter>,
    seen: Mutex<Vec<Arc<Mutex<Seen>>>>,
    changed: Notify,
    service: Arc<service::ServiceLog>,
    /// Connections roxy dialled that are still open.
    open: AtomicUsize,
    /// Data messages the framed WebSocket echo received.
    ws_received: Mutex<Vec<Vec<u8>>>,
    /// Framed echo upgrades that have ended, from the upstream's side.
    ws_closed: AtomicUsize,
}

/// Counts one dialled connection as open until it is dropped.
struct OpenConn(Arc<Upstream>);

impl Drop for OpenConn {
    fn drop(&mut self) {
        self.0.open.fetch_sub(1, Ordering::SeqCst);
        self.0.changed.notify_waiters();
    }
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
            service: Arc::new(service::ServiceLog::default()),
            open: AtomicUsize::new(0),
            ws_received: Mutex::new(Vec::new()),
            ws_closed: AtomicUsize::new(0),
        })
    }

    /// The data messages the framed WebSocket echo (`x-echo: frames`)
    /// received so far.
    pub(crate) fn ws_received(&self) -> Vec<Vec<u8>> {
        lock(&self.ws_received).clone()
    }

    /// Waits until `n` framed echo upgrades have ended on the upstream's
    /// side: roxy closed its connection, or the close handshake finished.
    pub(crate) async fn wait_ws_closed(&self, n: usize) {
        let wait = async {
            loop {
                let changed = self.changed.notified();
                if self.ws_closed.load(Ordering::SeqCst) >= n {
                    return;
                }
                changed.await;
            }
        };
        tokio::time::timeout(Duration::from_secs(10), wait)
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "upstream: wanted {n} closed WebSockets, have {}",
                    self.ws_closed.load(Ordering::SeqCst)
                )
            });
    }

    /// How many of the connections roxy dialled are still open.
    pub(crate) fn open_connections(&self) -> usize {
        self.open.load(Ordering::SeqCst)
    }

    /// Waits until exactly `n` dialled connections are open.
    pub(crate) async fn wait_open(&self, n: usize) {
        let wait = async {
            loop {
                let changed = self.changed.notified();
                if self.open_connections() == n {
                    return;
                }
                changed.await;
            }
        };
        tokio::time::timeout(Duration::from_secs(10), wait)
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "upstream: wanted {n} open connections, have {}",
                    self.open_connections()
                )
            });
    }

    /// What the in-test service layer endpoint saw.
    pub(crate) fn service(&self) -> &service::ServiceLog {
        &self.service
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
        self.open.fetch_add(1, Ordering::SeqCst);
        let open = OpenConn(self.clone());
        let me = self.clone();
        tokio::spawn(async move {
            me.serve(addr, ours).await;
            drop(open);
        });
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
    /// * `/drip?n=<n>&ms=<ms>`: `n` chunks, `ms` apart, without reading the
    ///   body;
    /// * `/cut`: reads the body, answers `200` declaring 10 bytes of body,
    ///   sends 3 and breaks the connection;
    /// * a `roxy.layer.v3` handshake: the in-test service layer endpoint
    ///   ([`service`]);
    /// * a WebSocket upgrade: `101`, then echoes bytes; with
    ///   `x-echo: once`, echoes the first read and closes; with
    ///   `x-echo: frames`, echoes whole messages as a WebSocket server
    ///   would and answers a close; with `x-accept-extension`, accepts
    ///   `permessage-deflate`;
    /// * anything else: reads the body, answers `200` with JSON
    ///   `{method, path, host, body_len, via}`.
    async fn answer(
        self: Arc<Self>,
        addr: SocketAddr,
        mut req: http::Request<Incoming>,
    ) -> http::Response<Body> {
        let path = req
            .uri()
            .path_and_query()
            .map_or("/", |p| p.as_str())
            .to_owned();
        if service::is_handshake(&req) {
            return service::accept(&mut req, path, self.service.clone()).map(BodyExt::boxed);
        }
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

        if req.headers().contains_key("upgrade")
            && let Some(key) = req.headers().get("sec-websocket-key").cloned()
        {
            lock(&entry).complete = Some(true);
            self.changed.notify_waiters();
            let echo = req.headers().get("x-echo").cloned();
            if echo.as_ref().is_some_and(|v| v == "frames") {
                return self.upgrade_and_echo_frames(&mut req, &key);
            }
            let once = echo.is_some_and(|v| v == "once");
            return upgrade_and_echo(&mut req, &key, once);
        }
        if path.starts_with("/drip?") {
            return drip(&path);
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
        let read = self.clone().read_body(entry.clone(), req.into_body());

        if path == "/early" {
            tokio::spawn(read);
            return http::Response::new(full(b"early".as_slice()));
        }
        let Some(body_len) = read.await else {
            return http::Response::builder()
                .status(400)
                .body(full(Bytes::new()))
                .unwrap();
        };
        if path == "/echo" {
            let body = lock(&entry).body.clone();
            return echo(echo_status.as_ref(), echo_encoding, body);
        }
        if path == "/cut" {
            return http::Response::builder()
                .header("content-length", "10")
                .body(cut())
                .unwrap();
        }
        if let Some(code) = path.strip_prefix("/status/") {
            return http::Response::builder()
                .status(code.parse::<u16>().unwrap())
                .body(full(Bytes::new()))
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
            .body(full(json.to_string()))
            .unwrap()
    }

    /// Reads `body` into `entry` as it arrives; the length once it ended
    /// cleanly, `None` if it was cut.
    async fn read_body(
        self: Arc<Self>,
        entry: Arc<Mutex<Seen>>,
        mut body: Incoming,
    ) -> Option<usize> {
        loop {
            match body.frame().await {
                Some(Ok(f)) => {
                    if let Some(d) = f.data_ref() {
                        lock(&entry).body.extend_from_slice(d);
                        self.changed.notify_waiters();
                    }
                }
                Some(Err(_)) => {
                    lock(&entry).complete = Some(false);
                    self.changed.notify_waiters();
                    return None;
                }
                None => {
                    let mut e = lock(&entry);
                    e.complete = Some(true);
                    let n = e.body.len();
                    drop(e);
                    self.changed.notify_waiters();
                    return Some(n);
                }
            }
        }
    }

    /// Answers a WebSocket upgrade with `101`, then echoes each data
    /// message as one unmasked frame, recording it, and answers a close
    /// with a close.
    fn upgrade_and_echo_frames(
        self: &Arc<Self>,
        req: &mut http::Request<Incoming>,
        key: &http::HeaderValue,
    ) -> http::Response<Body> {
        let on = hyper::upgrade::on(req);
        let me = self.clone();
        tokio::spawn(async move {
            let Ok(up) = on.await else { return };
            let mut ws =
                WebSocketStream::from_raw_socket(TokioIo::new(up), Role::Server, None).await;
            while let Some(Ok(msg)) = ws.next().await {
                if msg.is_close() {
                    let _ = ws.close(None).await;
                    break;
                }
                if msg.is_text() || msg.is_binary() {
                    lock(&me.ws_received).push(msg.clone().into_data().to_vec());
                    if ws.send(msg).await.is_err() {
                        break;
                    }
                }
            }
            me.ws_closed.fetch_add(1, Ordering::SeqCst);
            me.changed.notify_waiters();
        });
        let accept = roxy_http::ws::compute_accept(&String::from_utf8_lossy(key.as_bytes()));
        http::Response::builder()
            .status(101)
            .header("connection", "upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-accept", accept)
            .body(full(Bytes::new()))
            .unwrap()
    }
}

fn full(b: impl Into<Bytes>) -> Body {
    Full::new(b.into()).boxed()
}

/// 3 bytes, then (once they have gone out with the head) the end, 7
/// short of the declared length.
fn cut() -> Body {
    let frames = futures_util::stream::unfold(true, |first| async move {
        if !first {
            tokio::time::sleep(Duration::from_millis(50)).await;
            return None;
        }
        let frame = hyper::body::Frame::data(Bytes::from_static(b"cut"));
        Some((Ok::<_, Infallible>(frame), false))
    });
    BoxBody::new(http_body_util::StreamBody::new(frames))
}

/// `n` chunks `chunk<i>;`, `ms` apart, from `/drip?n=..&ms=..`.
fn drip(path: &str) -> http::Response<Body> {
    let query = path.split_once('?').map_or("", |(_, q)| q);
    let arg = |k: &str| {
        query
            .split('&')
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
    http::Response::new(BoxBody::new(http_body_util::StreamBody::new(chunks)))
}

/// The `/echo` answer: `body`, with the requested status and coding.
fn echo(
    status: Option<&http::HeaderValue>,
    encoding: Option<http::HeaderValue>,
    body: Vec<u8>,
) -> http::Response<Body> {
    let mut res = http::Response::builder();
    if let Some(s) = status {
        res = res.status(s.to_str().unwrap().parse::<u16>().unwrap());
    }
    if let Some(v) = encoding {
        res = res.header("content-encoding", v);
    }
    res.body(full(body)).unwrap()
}

/// Answers a WebSocket upgrade with `101` and echoes the upgraded bytes,
/// closing after the first read when `once`. With `x-accept-extension`, the
/// `101` accepts `permessage-deflate` whether or not it was offered.
fn upgrade_and_echo(
    req: &mut http::Request<Incoming>,
    key: &http::HeaderValue,
    once: bool,
) -> http::Response<Body> {
    let accept_ext = req.headers().contains_key("x-accept-extension");
    let on = hyper::upgrade::on(req);
    tokio::spawn(async move {
        if let Ok(up) = on.await {
            let mut up = TokioIo::new(up);
            let mut buf = vec![0u8; 16 * 1024];
            while let Ok(n) = up.read(&mut buf).await {
                if n == 0 || up.write_all(&buf[..n]).await.is_err() || once {
                    break;
                }
            }
        }
    });
    let accept = roxy_http::ws::compute_accept(&String::from_utf8_lossy(key.as_bytes()));
    let mut res = http::Response::builder()
        .status(101)
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-accept", accept);
    if accept_ext {
        res = res.header("sec-websocket-extensions", "permessage-deflate");
    }
    res.body(full(Bytes::new())).unwrap()
}
