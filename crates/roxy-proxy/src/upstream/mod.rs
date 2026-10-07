//! The upstream connector: resolve → address floor →
//! connect → TLS, behind hyper-util's pooled client.
//!
//! # Pooling and the address floor
//!
//! The floor (private ranges, `deny_cidrs`, `upstream.deny_lists`) runs
//! inside the connector on the addresses it is about to dial, after DNS and
//! immediately before `connect`, so the address checked is the address
//! dialled and DNS rebinding between check and connect is impossible. The
//! exchange also runs it as a preflight before any request bytes move.
//!
//! A pooled connection is keyed by scheme + authority only and is reused
//! without re-resolving. The pool lives in [`Upstream`], which lives in the
//! policy snapshot and is rebuilt on every reload, so a reload that changes
//! the address policy or any address list starts with an empty pool: a
//! pooled connection to a newly denied address is never reused (and the
//! preflight would refuse the flow first anyway). Flows with `private_ok`
//! use a separate pool, so a connection opened for a `private_ok` flow is
//! never reused by a flow without it.

mod dns;

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::Uri;
use http_body::{Body as _, Frame, SizeHint};
use hyper::body::Incoming;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use roxy_http::{Authority, Body, Host, Scheme};
use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::io::BoxIo;

pub(crate) use dns::Dns;
pub use dns::DnsSettings;

use crate::addr::{AddressDenied, AddressPolicy, PrivateAddrs};

/// `upstream.*` settings that may change on reload. The resolver is not
/// one: `upstream.dns` is read once, at start ([`crate::RuntimeConfig::dns`]).
#[derive(Debug, Clone)]
pub struct UpstreamSettings {
    pub address_policy: AddressPolicy,
    pub connect_timeout: Duration,
    /// Idle pooled connections are closed after this long.
    pub pool_idle_timeout: Duration,
    /// HTTP/2 connections the pool may hold to one origin ([`PooledClient`]).
    pub max_h2_connections_per_origin: usize,
    /// Replaces the TCP dial (after DNS and the address floor, before TLS),
    /// so tests can hand the connector an in-memory upstream.
    #[cfg(test)]
    pub(crate) dial: Option<TestDial>,
}

/// What a [`TestDial`] returns.
#[cfg(test)]
pub(crate) type TestDialFuture = Pin<Box<dyn Future<Output = std::io::Result<BoxIo>> + Send>>;

/// A substitute for `TcpStream::connect` in tests.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct TestDial(pub(crate) Arc<dyn Fn(SocketAddr) -> TestDialFuture + Send + Sync>);

#[cfg(test)]
impl std::fmt::Debug for TestDial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TestDial")
    }
}

impl Default for UpstreamSettings {
    fn default() -> Self {
        Self {
            address_policy: AddressPolicy::default(),
            connect_timeout: Duration::from_secs(10),
            pool_idle_timeout: Duration::from_secs(90),
            max_h2_connections_per_origin: 4,
            #[cfg(test)]
            dial: None,
        }
    }
}

/// A failure to reach the upstream, with a stable reason code.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ConnectError {
    #[error("DNS resolution failed: {0}")]
    Dns(String),
    #[error("address {} denied by the upstream address policy ({})", .0.ip, .0.reason)]
    Denied(AddressDenied),
    #[error("connect failed: {0}")]
    Connect(String),
    #[error("TLS handshake failed: {0}")]
    Tls(String),
    #[error("timed out: {0}")]
    Timeout(&'static str),
    #[error("invalid upstream target: {0}")]
    Target(String),
}

impl ConnectError {
    /// Stable flow-log reason code.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Dns(_) => "dns_failed",
            Self::Denied(_) => "address_denied",
            Self::Connect(_) => "connect_failed",
            Self::Target(_) => "invalid_target",
            Self::Tls(_) => "tls_failed",
            Self::Timeout(_) => "timeout",
        }
    }
}

/// Plain TCP or TLS to the upstream.
pub(crate) enum MaybeTls {
    Plain(BoxIo),
    Tls(Box<tokio_rustls::client::TlsStream<BoxIo>>),
}

impl AsyncRead for MaybeTls {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeTls {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// How the connection a response arrived on was opened. hyper puts it on
/// every response's extensions; the first exchange over the connection is
/// the one that paid for the dial.
#[derive(Debug, Clone)]
pub(crate) struct ConnectInfo {
    dial: Duration,
    fresh: Arc<AtomicBool>,
}

impl ConnectInfo {
    /// The time the dial took (DNS, TCP and TLS), the first time asked;
    /// `None` after that, the connection being reused.
    pub(crate) fn take_dial(&self) -> Option<Duration> {
        self.fresh
            .swap(false, Ordering::AcqRel)
            .then_some(self.dial)
    }
}

/// The connection type handed to hyper.
pub(crate) struct UpstreamIo {
    io: TokioIo<MaybeTls>,
    h2: bool,
    info: ConnectInfo,
    /// Counted in [`H1Open`] for as long as hyper holds the connection.
    _h1: Option<H1Guard>,
}

/// Open HTTP/1.1 connections per pool key (`scheme://authority`).
///
/// hyper polls a request body only once the connection carrying it is up,
/// and does not say which connection that is. While no HTTP/1.1 connection
/// to the body's key is open, the body is on an HTTP/2 one; while one is,
/// it may be the carrier. Entries leave the map when their count hits
/// zero, so the map is bounded by open connections.
#[derive(Default)]
struct H1Open(Mutex<HashMap<String, usize>>);

impl H1Open {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, usize>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn open(self: &Arc<Self>, key: String) -> H1Guard {
        *self.lock().entry(key.clone()).or_default() += 1;
        H1Guard {
            open: self.clone(),
            key,
        }
    }

    fn any(&self, key: &str) -> bool {
        self.lock().contains_key(key)
    }
}

struct H1Guard {
    open: Arc<H1Open>,
    key: String,
}

impl Drop for H1Guard {
    fn drop(&mut self) {
        let mut map = self.open.lock();
        if let Some(n) = map.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                map.remove(&self.key);
            }
        }
    }
}

/// hyper-util's pool key for a URI, as the connector is asked for it.
fn pool_key(scheme: &str, authority: &str) -> String {
    format!("{scheme}://{authority}")
}

impl hyper::rt::Read for UpstreamIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl hyper::rt::Write for UpstreamIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

impl Connection for UpstreamIo {
    fn connected(&self) -> Connected {
        let c = Connected::new().extra(self.info.clone());
        if self.h2 { c.negotiated_h2() } else { c }
    }
}

struct ConnectorInner {
    dns: Arc<Dns>,
    policy: AddressPolicy,
    connect_timeout: Duration,
    private: PrivateAddrs,
    h1_open: Arc<H1Open>,
    #[cfg(test)]
    dial: Option<TestDial>,
}

/// `Service<Uri>` performing resolve → floor → connect → TLS.
#[derive(Clone)]
pub(crate) struct Connector {
    inner: Arc<ConnectorInner>,
    /// What TLS offers, ALPN included: `h2` and `http/1.1`, or `http/1.1`
    /// only for the HTTP/1.1 pool.
    tls: Arc<ClientConfig>,
}

fn host_of(uri: &Uri) -> Result<Host, ConnectError> {
    let raw = uri
        .host()
        .ok_or_else(|| ConnectError::Target("URI without host".into()))?;
    roxy_http::url::parse_host(raw.as_bytes()).map_err(|e| ConnectError::Target(e.to_string()))
}

impl ConnectorInner {
    /// Opens the byte stream to an address that already passed the floor.
    async fn dial(&self, addr: SocketAddr) -> std::io::Result<BoxIo> {
        #[cfg(test)]
        if let Some(d) = &self.dial {
            return (d.0)(addr).await;
        }
        let tcp = TcpStream::connect(addr).await?;
        let _ = tcp.set_nodelay(true);
        Ok(Box::new(tcp))
    }

    async fn resolve_checked(&self, host: &Host) -> Result<Vec<IpAddr>, ConnectError> {
        let ips = self.dns.resolve(host).await?;
        self.policy
            .check_all(&ips, self.private)
            .map_err(ConnectError::Denied)?;
        Ok(ips)
    }

    /// Dials the addresses in turn, within one `connect_timeout` for all
    /// of them: each gets an equal share of what is left, so an address
    /// that drops packets does not spend the whole budget before the next
    /// is tried.
    async fn dial_any(&self, ips: &[IpAddr], port: u16) -> Result<BoxIo, ConnectError> {
        let deadline = tokio::time::Instant::now() + self.connect_timeout;
        let mut last = ConnectError::Connect("no addresses".into());
        for (i, ip) in ips.iter().enumerate() {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            let share = left / u32::try_from(ips.len() - i).unwrap_or(u32::MAX);
            match tokio::time::timeout(share, self.dial(SocketAddr::new(*ip, port))).await {
                Ok(Ok(s)) => return Ok(s),
                Ok(Err(e)) => last = ConnectError::Connect(format!("{ip}:{port}: {e}")),
                Err(_) => last = ConnectError::Timeout("upstream connect"),
            }
        }
        Err(last)
    }

    async fn connect(
        &self,
        scheme: Scheme,
        host: &Host,
        port: u16,
        tls: &Arc<ClientConfig>,
    ) -> Result<MaybeTls, ConnectError> {
        let ips = interleave_families(self.resolve_checked(host).await?);
        let tcp = self.dial_any(&ips, port).await?;
        match scheme {
            Scheme::Http => Ok(MaybeTls::Plain(tcp)),
            Scheme::Https => {
                let name = roxy_tls::server_name(host);
                let tls = tokio::time::timeout(
                    self.connect_timeout,
                    TlsConnector::from(tls.clone()).connect(name, tcp),
                )
                .await
                .map_err(|_| ConnectError::Timeout("upstream TLS handshake"))?
                .map_err(|e| ConnectError::Tls(e.to_string()))?;
                Ok(MaybeTls::Tls(Box::new(tls)))
            }
        }
    }
}

/// The addresses with their families alternating, starting with the
/// resolver's first, so one unreachable family costs at most every other
/// attempt.
fn interleave_families(ips: Vec<IpAddr>) -> Vec<IpAddr> {
    let Some(first) = ips.first().copied() else {
        return ips;
    };
    let (same, other): (Vec<_>, Vec<_>) = ips
        .into_iter()
        .partition(|ip| ip.is_ipv4() == first.is_ipv4());
    let mut same = same.into_iter();
    let mut other = other.into_iter();
    let mut out = Vec::new();
    loop {
        match (same.next(), other.next()) {
            (None, None) => return out,
            (a, b) => out.extend(a.into_iter().chain(b)),
        }
    }
}

impl tower_service::Service<Uri> for Connector {
    type Response = UpstreamIo;
    type Error = ConnectError;
    type Future = Pin<Box<dyn Future<Output = Result<UpstreamIo, ConnectError>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    // Entry point for every pooled upstream connection. Anything else that
    // dials out (addon endpoint calls) must also
    // pass the address floor (`Upstream::preflight` or this connector), so
    // that `upstream.deny_lists` and the private-range floor apply to it
    // too: nothing opts out of a deny list.
    fn call(&mut self, uri: Uri) -> Self::Future {
        let inner = self.inner.clone();
        let tls = self.tls.clone();
        Box::pin(async move {
            let scheme = match uri.scheme_str() {
                Some("https") => Scheme::Https,
                Some("http") => Scheme::Http,
                other => return Err(ConnectError::Target(format!("scheme {other:?}"))),
            };
            let host = host_of(&uri)?;
            let port = uri.port_u16().unwrap_or(scheme.default_port());
            let dialled = Instant::now();
            let io = inner.connect(scheme, &host, port, &tls).await?;
            let info = ConnectInfo {
                dial: dialled.elapsed(),
                fresh: Arc::new(AtomicBool::new(true)),
            };
            let h2 = match &io {
                MaybeTls::Tls(t) => t.get_ref().1.alpn_protocol() == Some(b"h2".as_slice()),
                MaybeTls::Plain(_) => false,
            };
            let key = pool_key(
                uri.scheme_str().unwrap_or_default(),
                uri.authority().map_or("", http::uri::Authority::as_str),
            );
            Ok(UpstreamIo {
                io: TokioIo::new(io),
                h2,
                info,
                _h1: (!h2).then(|| inner.h1_open.open(key)),
            })
        })
    }
}

/// One hyper client with its pool.
type HttpClient = Client<Connector, Body>;

/// hyper-util's client error.
pub(crate) type ClientError = hyper_util::client::legacy::Error;

/// Receive windows and frame size offered to HTTP/2 origins. The stream
/// window is hyper's default, stated so it is a choice; the connection
/// window fits four streams at full window, so bulk downloads multiplexed
/// on one connection do not throttle each other; a 1 MiB frame lets an
/// origin that fills frames to the offered size send a body as a few
/// frames rather than sixty-four 16 KiB ones (each is a trip through the
/// relay). The windows are fixed rather than adaptive: they are the bound
/// on what roxy buffers for a stalled client, and a LAN origin would spend
/// several round trips probing its way up from the default 64 KiB.
const H2_STREAM_WINDOW: u32 = 2 << 20;
const H2_CONNECTION_WINDOW: u32 = 8 << 20;
const H2_MAX_FRAME_SIZE: u32 = 1 << 20;

/// Attempts after the first for a request that never reached the origin.
const MAX_RETRIES: u32 = 2;

/// The pooled client for one protocol choice: several hyper clients over
/// one connector. hyper-util carries every request for a
/// `scheme://authority` on one HTTP/2 connection per client, driven by one
/// task, so a client per shard lets a busy origin spread over as many
/// connections (and runtime workers) as there are shards, up to
/// `upstream.max_h2_connections_per_origin`. See [`pick`] for the choice.
#[derive(Clone)]
pub(crate) struct PooledClient {
    shards: Arc<[Shard]>,
}

struct Shard {
    client: HttpClient,
    /// Exchanges on this shard: sent, and the response body not yet ended.
    in_flight: AtomicUsize,
}

/// Counts an exchange against its shard from the request going out until
/// the response body ends or is dropped, or the request fails.
struct InFlight {
    shards: Arc<[Shard]>,
    index: usize,
}

impl InFlight {
    fn start(shards: Arc<[Shard]>, index: usize) -> Self {
        shards[index].in_flight.fetch_add(1, Ordering::Relaxed);
        Self { shards, index }
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.shards[self.index]
            .in_flight
            .fetch_sub(1, Ordering::Relaxed);
    }
}

/// A pooled response body, counted against its shard until it ends (so a
/// client's next request, sent once it has the whole response, finds the
/// shard free) or is dropped.
pub(crate) struct UpstreamBody {
    inner: Incoming,
    in_flight: Option<InFlight>,
}

impl UpstreamBody {
    /// A body from a connection outside the pool (an upgrade's).
    pub(crate) fn untracked(inner: Incoming) -> Self {
        Self {
            inner,
            in_flight: None,
        }
    }
}

impl std::fmt::Debug for UpstreamBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}

impl http_body::Body for UpstreamBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let r = Pin::new(&mut self.inner).poll_frame(cx);
        if matches!(r, Poll::Ready(None | Some(Err(_)))) {
            self.in_flight = None;
        }
        r
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// What a bodiless request needs to be sent again.
struct Head {
    method: http::Method,
    uri: Uri,
    version: http::Version,
    headers: http::HeaderMap,
}

impl Head {
    fn of(req: &http::Request<Body>) -> Self {
        Self {
            method: req.method().clone(),
            uri: req.uri().clone(),
            version: req.version(),
            headers: req.headers().clone(),
        }
    }

    fn request(&self) -> http::Request<Body> {
        let mut req = http::Request::new(Body::empty());
        *req.method_mut() = self.method.clone();
        *req.uri_mut() = self.uri.clone();
        *req.version_mut() = self.version;
        *req.headers_mut() = self.headers.clone();
        req
    }
}

impl PooledClient {
    fn new(shards: usize, mut client: impl FnMut() -> HttpClient) -> Self {
        let shards = (0..shards.max(1))
            .map(|_| Shard {
                client: client(),
                in_flight: AtomicUsize::new(0),
            })
            .collect();
        Self { shards }
    }

    /// Sends `req`, again on another connection when the one it was on
    /// went away before the origin saw it: an HTTP/2 connection the origin
    /// closes with `GOAWAY` fails every stream above its last stream id,
    /// which the origin never processed (RFC 9113 §6.8), and hyper drops
    /// the requests queued on a connection that closed first. Only a
    /// request without a body is sent again: hyper consumes the body as it
    /// streams and nothing holds a copy.
    pub(crate) fn request(&self, req: http::Request<Body>) -> ResponseFuture {
        let shards = self.shards.clone();
        Box::pin(async move {
            let mut req = req;
            let head = req.body().is_end_stream().then(|| Head::of(&req));
            let mut retries = 0;
            loop {
                let index = pick(&shards);
                let in_flight = InFlight::start(shards.clone(), index);
                match shards[index].client.request(req).await {
                    Ok(res) => {
                        return Ok(res.map(|inner| UpstreamBody {
                            inner,
                            in_flight: Some(in_flight),
                        }));
                    }
                    Err(e) => match &head {
                        Some(head) if retries < MAX_RETRIES && never_reached_origin(&e) => {
                            retries += 1;
                            req = head.request();
                        }
                        _ => return Err(e),
                    },
                }
            }
        })
    }
}

/// A [`PooledClient::request`] in progress.
pub(crate) type ResponseFuture =
    Pin<Box<dyn Future<Output = Result<http::Response<UpstreamBody>, ClientError>> + Send>>;

/// The shard for a request: the one with the fewest exchanges in flight,
/// the lowest index among equals. Requests one after another all land on
/// the first shard, so a lightly used origin keeps a single connection;
/// requests in flight at the same time take distinct shards up to the
/// limit, and spread evenly beyond it.
fn pick(shards: &[Shard]) -> usize {
    shards
        .iter()
        .enumerate()
        .min_by_key(|(_, s)| s.in_flight.load(Ordering::Relaxed))
        .map(|(i, _)| i)
        .expect("at least one shard")
}

/// Whether `err` says the origin never saw the request: the stream was
/// above the last one a remote `GOAWAY` named, or hyper never sent it.
fn never_reached_origin(err: &ClientError) -> bool {
    let mut src: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = src {
        if let Some(h2) = e.downcast_ref::<h2::Error>() {
            return h2.is_go_away() && h2.is_remote();
        }
        if let Some(h) = e.downcast_ref::<hyper::Error>() {
            // hyper has no predicate for a request its dispatcher dropped
            // unsent; the message is its stable description of that case.
            if h.is_canceled() || h.to_string() == "dispatch task is gone" {
                return true;
            }
        }
        src = e.source();
    }
    false
}

/// Which protocols a pooled client may negotiate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Protocols {
    /// `h2` or `http/1.1`, by ALPN.
    Any,
    /// HTTP/1.1 only: the connection target and `Host` may differ (a
    /// `redirect` that keeps `Host`); over h2, `:authority` and `host` must
    /// agree.
    Http1Only,
}

/// The pooled clients that share one address-floor setting (`private_ok`
/// or not), so a connection opened for a `private_ok` flow is never reused
/// by a flow without it.
struct Pools {
    inner: Arc<ConnectorInner>,
    /// ALPN `h2` or `http/1.1`, as the upstream chooses.
    any: PooledClient,
    /// ALPN `http/1.1` only. One shard: HTTP/1.1 opens a connection per
    /// concurrent request anyway.
    http1: PooledClient,
    http1_tls: Arc<ClientConfig>,
}

/// Everything needed to talk to upstreams under one policy snapshot.
pub(crate) struct Upstream {
    strict: Pools,
    private: Pools,
}

impl std::fmt::Debug for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Upstream").finish_non_exhaustive()
    }
}

impl Upstream {
    /// Pools and connectors for one snapshot. `dns` is the server's: its
    /// cache outlives the snapshot.
    pub(crate) fn new(s: &UpstreamSettings, dns: &Arc<Dns>, tls: &Arc<ClientConfig>) -> Self {
        let mut http1 = (**tls).clone();
        http1.alpn_protocols = vec![b"http/1.1".to_vec()];
        let http1_tls = Arc::new(http1);
        let pools = |private| {
            let inner = Arc::new(ConnectorInner {
                dns: dns.clone(),
                policy: s.address_policy.clone(),
                connect_timeout: s.connect_timeout,
                private,
                h1_open: Arc::default(),
                #[cfg(test)]
                dial: s.dial.clone(),
            });
            let client = |tls: &Arc<ClientConfig>| {
                Client::builder(TokioExecutor::new())
                    .pool_timer(TokioTimer::new())
                    .pool_idle_timeout(s.pool_idle_timeout)
                    .http2_initial_stream_window_size(H2_STREAM_WINDOW)
                    .http2_initial_connection_window_size(H2_CONNECTION_WINDOW)
                    .http2_max_frame_size(H2_MAX_FRAME_SIZE)
                    .build(Connector {
                        inner: inner.clone(),
                        tls: tls.clone(),
                    })
            };
            Pools {
                any: PooledClient::new(s.max_h2_connections_per_origin, || client(tls)),
                http1: PooledClient::new(1, || client(&http1_tls)),
                http1_tls: http1_tls.clone(),
                inner,
            }
        };
        Self {
            strict: pools(PrivateAddrs::Deny),
            private: pools(PrivateAddrs::Allow),
        }
    }

    fn pools(&self, private: PrivateAddrs) -> &Pools {
        match private {
            PrivateAddrs::Allow => &self.private,
            PrivateAddrs::Deny => &self.strict,
        }
    }

    /// The pooled client for a flow.
    pub(crate) fn client(&self, private: PrivateAddrs, protocols: Protocols) -> &PooledClient {
        let pools = self.pools(private);
        match protocols {
            Protocols::Any => &pools.any,
            Protocols::Http1Only => &pools.http1,
        }
    }

    /// Whether a request body going through the pooled client for
    /// `protocols` to `scheme://authority` may be on an HTTP/1.1 connection
    /// right now ([`H1Open`]). Over HTTP/1.1 hyper drops the body's
    /// trailers, so a body asks this when one arrives.
    pub(crate) fn may_be_h1(
        &self,
        private: PrivateAddrs,
        protocols: Protocols,
        scheme: &str,
        authority: &str,
    ) -> bool {
        match protocols {
            Protocols::Http1Only => true,
            Protocols::Any => self
                .pools(private)
                .inner
                .h1_open
                .any(&pool_key(scheme, authority)),
        }
    }

    /// Resolve and apply the address floor before any request bytes move, so
    /// a denied destination is refused before `100 Continue` and before the
    /// body streams. The connector checks again for the address it actually
    /// connects to.
    pub(crate) async fn preflight(
        &self,
        authority: &Authority,
        private: PrivateAddrs,
    ) -> Result<(), ConnectError> {
        self.pools(private)
            .inner
            .resolve_checked(&authority.host)
            .await
            .map(|_| ())
    }

    /// A fresh, non-pooled HTTP/1.1 connection (WebSocket relay).
    pub(crate) async fn connect_h1(
        &self,
        scheme: Scheme,
        authority: &Authority,
        private: PrivateAddrs,
    ) -> Result<MaybeTls, ConnectError> {
        let pools = self.pools(private);
        pools
            .inner
            .connect(scheme, &authority.host, authority.port, &pools.http1_tls)
            .await
    }
}

/// Classifies a hyper-util client error by walking its source chain:
/// `Some` for a failure to establish the connection, `None` when the
/// exchange itself broke (`protocol_error`).
pub(crate) fn classify(err: &ClientError) -> Option<ConnectError> {
    let mut src: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = src {
        if let Some(c) = e.downcast_ref::<ConnectError>() {
            return Some(c.clone());
        }
        src = e.source();
    }
    err.is_connect()
        .then(|| ConnectError::Connect(describe(err)))
}

/// Stable reason for a non-connect client error (the exchange itself broke).
pub(crate) fn describe(err: &ClientError) -> String {
    let mut out = err.to_string();
    let mut src = std::error::Error::source(err);
    while let Some(e) = src {
        out.push_str(": ");
        out.push_str(&e.to_string());
        src = e.source();
    }
    out
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;
    use crate::addrlist::AddressList;

    /// Answers `200` to every HTTP/1.1 request on `s`, keeping it open.
    async fn answer_ok<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(mut s: S) {
        let mut buf = vec![0u8; 4096];
        let mut seen = Vec::new();
        while let Ok(k) = s.read(&mut buf).await {
            if k == 0 {
                return;
            }
            seen.extend_from_slice(&buf[..k]);
            while let Some(i) = seen.windows(4).position(|w| w == b"\r\n\r\n") {
                seen.drain(..i + 4);
                if s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
    }

    /// A keep-alive HTTP/1.1 server answering `200` to everything; counts
    /// accepted connections.
    async fn tiny_server() -> (u16, Arc<AtomicUsize>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let n = accepted.clone();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                n.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(answer_ok(s));
            }
        });
        (port, accepted)
    }

    /// A resolver answering `hosts` and nothing else: real DNS is never
    /// consulted.
    fn static_dns(hosts: &[(&str, &[&str])]) -> Arc<Dns> {
        let mut s = DnsSettings {
            servers: Some(vec!["127.0.0.1:9".parse().unwrap()]),
            ..DnsSettings::default()
        };
        for (name, ips) in hosts {
            s.static_hosts.insert(
                (*name).to_owned(),
                ips.iter().map(|ip| ip.parse().unwrap()).collect(),
            );
        }
        Arc::new(Dns::new(&s).unwrap())
    }

    /// Settings whose dial records each address and hands it to `connect`,
    /// with a resolver for `hosts`.
    fn dialing(
        hosts: &[(&str, &[&str])],
        connect: impl Fn(SocketAddr) -> TestDialFuture + Send + Sync + 'static,
    ) -> (UpstreamSettings, Arc<Dns>, Arc<Mutex<Vec<SocketAddr>>>) {
        let mut s = UpstreamSettings::default();
        let dns = static_dns(hosts);
        let dialled = Arc::new(Mutex::new(Vec::new()));
        let seen = dialled.clone();
        s.dial = Some(TestDial(Arc::new(move |addr| {
            seen.lock().unwrap().push(addr);
            connect(addr)
        })));
        (s, dns, dialled)
    }

    fn tls() -> Arc<ClientConfig> {
        roxy_tls::install_crypto_provider();
        roxy_tls::client_config(&roxy_tls::UpstreamTlsOptions::default()).unwrap()
    }

    /// An HTTP/2 origin, as raw frames, that answers its first stream
    /// `200` and meets any later one with `GOAWAY` naming the first as the
    /// last it processed (what nginx does at `keepalive_requests`).
    async fn first_stream_only<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(mut s: S) {
        const SETTINGS: u8 = 0x4;
        const HEADERS: u8 = 0x1;
        const GOAWAY: u8 = 0x7;
        fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
            let mut out = u32::try_from(payload.len()).unwrap().to_be_bytes()[1..].to_vec();
            out.extend([kind, flags]);
            out.extend(stream.to_be_bytes());
            out.extend(payload);
            out
        }
        let mut preface = [0u8; 24];
        if s.read_exact(&mut preface).await.is_err() {
            return;
        }
        if s.write_all(&frame(SETTINGS, 0, 0, &[])).await.is_err() {
            return;
        }
        loop {
            let mut head = [0u8; 9];
            if s.read_exact(&mut head).await.is_err() {
                return;
            }
            let len =
                (usize::from(head[0]) << 16) | (usize::from(head[1]) << 8) | usize::from(head[2]);
            let mut payload = vec![0u8; len];
            if s.read_exact(&mut payload).await.is_err() {
                return;
            }
            let stream = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
            let reply = match (head[3], stream) {
                (SETTINGS, _) if head[4] & 0x1 == 0 => frame(SETTINGS, 0x1, 0, &[]),
                // `:status: 200` is static table entry 8; END_HEADERS | END_STREAM.
                (HEADERS, 1) => frame(HEADERS, 0x4 | 0x1, 1, &[0x88]),
                // last stream id 1, NO_ERROR
                (HEADERS, _) => frame(GOAWAY, 0, 0, &[0, 0, 0, 1, 0, 0, 0, 0]),
                _ => continue,
            };
            if s.write_all(&reply).await.is_err() {
                return;
            }
        }
    }

    /// An `Upstream` whose dial reaches a fresh [`first_stream_only`]
    /// origin over TLS with ALPN `h2`, and the addresses it dialled.
    fn goaway_origin() -> (Upstream, Arc<Mutex<Vec<SocketAddr>>>) {
        roxy_tls::install_crypto_provider();
        let dir = tempfile::tempdir().unwrap();
        let ca = Arc::new(roxy_tls::Ca::generate(dir.path()).unwrap());
        let minter = Arc::new(roxy_tls::LeafMinter::new(ca, 8).unwrap());
        let host = roxy_http::url::parse_host(b"go.test").unwrap();
        let server = roxy_tls::server_config_for(minter, host, true);
        let client = roxy_tls::client_config(&roxy_tls::UpstreamTlsOptions {
            extra_roots_pem: vec![dir.path().join(roxy_tls::CA_CERT_FILE)],
            ..roxy_tls::UpstreamTlsOptions::default()
        })
        .unwrap();
        let (s, dns, dialled) = dialing(&[("go.test", &["93.184.216.34"])], move |_| {
            let (ours, theirs) = tokio::io::duplex(64 * 1024);
            let acceptor = tokio_rustls::TlsAcceptor::from(server.clone());
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(ours).await {
                    first_stream_only(tls).await;
                }
            });
            Box::pin(async move { Ok(Box::new(theirs) as BoxIo) })
        });
        (Upstream::new(&s, &dns, &client), dialled)
    }

    fn goaway_get() -> http::Request<Body> {
        http::Request::get("https://go.test/")
            .body(Body::empty())
            .unwrap()
    }

    /// A stream above a remote `GOAWAY`'s last stream id was never
    /// processed, so a bodiless request on it goes again on a fresh
    /// connection and the client sees the answer, not a `502`.
    #[tokio::test]
    async fn a_request_the_origin_never_saw_is_sent_again_after_goaway() {
        let (up, dialled) = goaway_origin();
        let client = up.client(PrivateAddrs::Deny, Protocols::Any);
        for i in 0..2 {
            let res = client.request(goaway_get()).await.unwrap();
            assert_eq!(res.status(), 200, "request {i}");
        }
        assert_eq!(
            dialled.lock().unwrap().len(),
            2,
            "the second request reconnected"
        );
    }

    /// A request with a body is not sent again: hyper has streamed the
    /// body and nothing holds a copy. Its error names the `GOAWAY` and is
    /// not a connect failure, so the exchange answers `protocol_error`.
    #[tokio::test]
    async fn a_request_with_a_body_is_not_sent_again_after_goaway() {
        let (up, dialled) = goaway_origin();
        let client = up.client(PrivateAddrs::Deny, Protocols::Any);
        assert_eq!(client.request(goaway_get()).await.unwrap().status(), 200);
        let req = http::Request::post("https://go.test/")
            .body(Body::from_bytes(bytes::Bytes::from_static(b"x")))
            .unwrap();
        let err = client.request(req).await.unwrap_err();
        assert!(never_reached_origin(&err), "{}", describe(&err));
        assert!(classify(&err).is_none(), "{}", describe(&err));
        assert_eq!(
            dialled.lock().unwrap().len(),
            1,
            "no retry: {}",
            describe(&err)
        );
    }

    /// A name with several addresses that drop packets fails within one
    /// `connect_timeout`, not one per address; the families are tried
    /// alternately, the resolver's first family first.
    #[tokio::test]
    async fn unroutable_addresses_share_one_connect_timeout() {
        let ips = ["93.184.216.1", "93.184.216.2", "2606:4700::1"];
        let (mut s, dns, dialled) =
            dialing(&[("many.test", &ips)], |_| Box::pin(std::future::pending()));
        s.connect_timeout = Duration::from_millis(300);
        let up = Upstream::new(&s, &dns, &tls());
        let authority = Authority::new(Host::Dns("many.test".into()), 80);
        let started = std::time::Instant::now();
        let Err(err) = up
            .connect_h1(Scheme::Http, &authority, PrivateAddrs::Deny)
            .await
        else {
            panic!("nothing answers");
        };
        assert!(matches!(err, ConnectError::Timeout(_)), "{err:?}");
        assert!(
            started.elapsed() < Duration::from_millis(600),
            "{:?}",
            started.elapsed()
        );
        let order: Vec<String> = dialled
            .lock()
            .unwrap()
            .iter()
            .map(|a| a.ip().to_string())
            .collect();
        assert_eq!(order, ["93.184.216.1", "2606:4700::1", "93.184.216.2"]);
    }

    /// IPv6 targets, as a literal `Host` and from `static_hosts`, pass the
    /// floor and are dialled as given.
    #[tokio::test]
    async fn ipv6_targets_are_dialled() {
        let ip = "2606:4700::1111";
        let (s, dns, dialled) = dialing(&[("v6.test", &[ip])], |_| {
            let (ours, theirs) = tokio::io::duplex(16 * 1024);
            tokio::spawn(answer_ok(ours));
            Box::pin(async move { Ok(Box::new(theirs) as BoxIo) })
        });
        let up = Upstream::new(&s, &dns, &tls());
        for host in [format!("[{ip}]"), "v6.test".to_owned()] {
            let req = http::Request::get(format!("http://{host}:8080/"))
                .body(Body::empty())
                .unwrap();
            let res = up
                .client(PrivateAddrs::Deny, Protocols::Any)
                .request(req)
                .await
                .unwrap();
            assert_eq!(res.status(), 200, "{host}");
        }
        let expected: SocketAddr = format!("[{ip}]:8080").parse().unwrap();
        assert_eq!(*dialled.lock().unwrap(), [expected, expected]);
    }

    fn settings(lists: Vec<Arc<AddressList>>) -> UpstreamSettings {
        let mut s = UpstreamSettings::default();
        s.address_policy.deny_lists = lists;
        s
    }

    fn get(port: u16) -> http::Request<Body> {
        http::Request::get(format!("http://listed.test:{port}/"))
            .body(Body::empty())
            .unwrap()
    }

    /// The deny list is enforced by the connector itself (not only the
    /// preflight), and a rebuilt `Upstream` (what a reload does) does not
    /// reuse the old pool's connection to a newly listed address.
    #[tokio::test]
    async fn connector_enforces_deny_lists_and_reload_drops_the_pool() {
        roxy_tls::install_crypto_provider();
        let tls = roxy_tls::client_config(&roxy_tls::UpstreamTlsOptions::default()).unwrap();
        let (port, accepted) = tiny_server().await;

        let dns = static_dns(&[("listed.test", &["127.0.0.1"])]);
        let before = Upstream::new(&settings(Vec::new()), &dns, &tls);
        for _ in 0..2 {
            let res = before
                .client(PrivateAddrs::Allow, Protocols::Any)
                .request(get(port))
                .await
                .unwrap();
            assert_eq!(res.status(), 200);
        }
        assert_eq!(accepted.load(Ordering::SeqCst), 1, "second request pooled");

        let list = Arc::new(AddressList::parse("blocked", "127.0.0.1\n").unwrap());
        let after = Upstream::new(&settings(vec![list]), &dns, &tls);
        let authority = Authority::new(Host::Dns("listed.test".into()), port);
        let Err(ConnectError::Denied(d)) = after.preflight(&authority, PrivateAddrs::Allow).await
        else {
            panic!("preflight must deny");
        };
        assert_eq!(d.list.as_deref(), Some("blocked"));
        // Straight through the pooled client, bypassing the preflight.
        let err = after
            .client(PrivateAddrs::Allow, Protocols::Any)
            .request(get(port))
            .await
            .unwrap_err();
        let Some(ConnectError::Denied(d)) = classify(&err) else {
            panic!("connector must deny: {err:?}");
        };
        assert_eq!(d.reason, "list:blocked");
        assert_eq!(d.matched_cidr, Some("127.0.0.1/32".parse().unwrap()));
        assert_eq!(d.ip, "127.0.0.1".parse::<IpAddr>().unwrap());
        // And the WebSocket path.
        assert!(matches!(
            after
                .connect_h1(Scheme::Http, &authority, PrivateAddrs::Allow)
                .await,
            Err(ConnectError::Denied(_))
        ));
        assert_eq!(accepted.load(Ordering::SeqCst), 1, "nothing was dialled");
    }
}
