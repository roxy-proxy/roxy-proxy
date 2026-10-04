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

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use http::Uri;
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

use crate::addr::{AddressDenied, AddressPolicy};

/// `upstream.*` settings that may change on reload.
#[derive(Debug, Clone)]
pub struct UpstreamSettings {
    pub dns: DnsSettings,
    pub address_policy: AddressPolicy,
    pub connect_timeout: Duration,
    /// Idle pooled connections are closed after this long.
    pub pool_idle_timeout: Duration,
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
            dns: DnsSettings::default(),
            address_policy: AddressPolicy::default(),
            connect_timeout: Duration::from_secs(10),
            pool_idle_timeout: Duration::from_secs(90),
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
            Self::Connect(_) | Self::Target(_) => "connect_failed",
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

/// The connection type handed to hyper.
pub(crate) struct UpstreamIo {
    io: TokioIo<MaybeTls>,
    h2: bool,
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
        let c = Connected::new();
        if self.h2 { c.negotiated_h2() } else { c }
    }
}

struct ConnectorInner {
    dns: Arc<Dns>,
    policy: AddressPolicy,
    connect_timeout: Duration,
    private_ok: bool,
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

/// The host as a TLS server name (IPv6 without brackets).
fn tls_name(host: &Host) -> String {
    match host {
        Host::Dns(n) => n.clone(),
        Host::Ipv4(ip) => ip.to_string(),
        Host::Ipv6(ip) => ip.to_string(),
    }
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
            .check_all(&ips, self.private_ok)
            .map_err(ConnectError::Denied)?;
        Ok(ips)
    }

    async fn connect(
        &self,
        scheme: Scheme,
        host: &Host,
        port: u16,
        tls: &Arc<ClientConfig>,
    ) -> Result<MaybeTls, ConnectError> {
        let ips = self.resolve_checked(host).await?;
        let mut last = ConnectError::Connect("no addresses".into());
        let mut tcp = None;
        for ip in ips {
            match tokio::time::timeout(self.connect_timeout, self.dial(SocketAddr::new(ip, port)))
                .await
            {
                Ok(Ok(s)) => {
                    tcp = Some(s);
                    break;
                }
                Ok(Err(e)) => last = ConnectError::Connect(format!("{ip}:{port}: {e}")),
                Err(_) => last = ConnectError::Timeout("upstream connect"),
            }
        }
        let tcp = tcp.ok_or(last)?;
        match scheme {
            Scheme::Http => Ok(MaybeTls::Plain(tcp)),
            Scheme::Https => {
                let name = roxy_tls::server_name_for_host(&tls_name(host))
                    .map_err(|e| ConnectError::Tls(e.to_string()))?;
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
            let io = inner.connect(scheme, &host, port, &tls).await?;
            let h2 = match &io {
                MaybeTls::Tls(t) => t.get_ref().1.alpn_protocol() == Some(b"h2".as_slice()),
                MaybeTls::Plain(_) => false,
            };
            Ok(UpstreamIo {
                io: TokioIo::new(io),
                h2,
            })
        })
    }
}

/// The pooled HTTP client type.
pub(crate) type HttpClient = Client<Connector, Body>;

/// The pooled clients that share one address-floor setting (`private_ok`
/// or not), so a connection opened for a `private_ok` flow is never reused
/// by a flow without it.
struct Pools {
    inner: Arc<ConnectorInner>,
    /// ALPN `h2` or `http/1.1`, as the upstream chooses.
    any: HttpClient,
    /// ALPN `http/1.1` only.
    http1: HttpClient,
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
    pub(crate) fn new(s: &UpstreamSettings, tls: &Arc<ClientConfig>) -> Result<Self, String> {
        let dns = Arc::new(Dns::new(&s.dns)?);
        let mut http1 = (**tls).clone();
        http1.alpn_protocols = vec![b"http/1.1".to_vec()];
        let http1_tls = Arc::new(http1);
        let pools = |private_ok| {
            let inner = Arc::new(ConnectorInner {
                dns: dns.clone(),
                policy: s.address_policy.clone(),
                connect_timeout: s.connect_timeout,
                private_ok,
                #[cfg(test)]
                dial: s.dial.clone(),
            });
            let client = |tls: &Arc<ClientConfig>| {
                Client::builder(TokioExecutor::new())
                    .pool_timer(TokioTimer::new())
                    .pool_idle_timeout(s.pool_idle_timeout)
                    .build(Connector {
                        inner: inner.clone(),
                        tls: tls.clone(),
                    })
            };
            Pools {
                any: client(tls),
                http1: client(&http1_tls),
                http1_tls: http1_tls.clone(),
                inner,
            }
        };
        Ok(Self {
            strict: pools(false),
            private: pools(true),
        })
    }

    fn pools(&self, private_ok: bool) -> &Pools {
        if private_ok {
            &self.private
        } else {
            &self.strict
        }
    }

    /// The pooled client for a flow. `http1_only` keeps the exchange on
    /// HTTP/1.1, where the connection target and `Host` may differ (a
    /// `redirect` that keeps `Host`); over h2, `:authority` and `host` must
    /// agree.
    pub(crate) fn client(&self, private_ok: bool, http1_only: bool) -> &HttpClient {
        let pools = self.pools(private_ok);
        if http1_only { &pools.http1 } else { &pools.any }
    }

    /// Resolve and apply the address floor before any request bytes move, so
    /// a denied destination is refused before `100 Continue` and before the
    /// body streams. The connector checks again for the address it actually
    /// connects to.
    pub(crate) async fn preflight(
        &self,
        authority: &Authority,
        private_ok: bool,
    ) -> Result<(), ConnectError> {
        self.pools(private_ok)
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
        private_ok: bool,
    ) -> Result<MaybeTls, ConnectError> {
        let pools = self.pools(private_ok);
        pools
            .inner
            .connect(scheme, &authority.host, authority.port, &pools.http1_tls)
            .await
    }
}

/// Classifies a hyper-util client error by walking its source chain:
/// `Some` for a failure to establish the connection, `None` when the
/// exchange itself broke (`protocol_error`).
pub(crate) fn classify(err: &hyper_util::client::legacy::Error) -> Option<ConnectError> {
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
pub(crate) fn describe(err: &hyper_util::client::legacy::Error) -> String {
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;
    use crate::addrlist::AddressList;

    /// A keep-alive HTTP/1.1 server answering `200` to everything; counts
    /// accepted connections.
    async fn tiny_server() -> (u16, Arc<AtomicUsize>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let n = accepted.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                n.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
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
                });
            }
        });
        (port, accepted)
    }

    fn settings(lists: Vec<Arc<AddressList>>) -> UpstreamSettings {
        let mut s = UpstreamSettings::default();
        s.dns.servers = Some(vec!["127.0.0.1:9".parse().unwrap()]);
        s.dns
            .static_hosts
            .insert("listed.test".into(), vec!["127.0.0.1".parse().unwrap()]);
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

        let before = Upstream::new(&settings(Vec::new()), &tls).unwrap();
        for _ in 0..2 {
            let res = before.client(true, false).request(get(port)).await.unwrap();
            assert_eq!(res.status(), 200);
        }
        assert_eq!(accepted.load(Ordering::SeqCst), 1, "second request pooled");

        let list = Arc::new(AddressList::parse("blocked", "127.0.0.1\n").unwrap());
        let after = Upstream::new(&settings(vec![list]), &tls).unwrap();
        let authority = Authority::new(Host::Dns("listed.test".into()), port);
        let Err(ConnectError::Denied(d)) = after.preflight(&authority, true).await else {
            panic!("preflight must deny");
        };
        assert_eq!(d.list.as_deref(), Some("blocked"));
        // Straight through the pooled client, bypassing the preflight.
        let err = after
            .client(true, false)
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
            after.connect_h1(Scheme::Http, &authority, true).await,
            Err(ConnectError::Denied(_))
        ));
        assert_eq!(accepted.load(Ordering::SeqCst), 1, "nothing was dialled");
    }
}
