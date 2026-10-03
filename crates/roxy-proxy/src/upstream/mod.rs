//! The upstream connector (`DESIGN.md` §7): resolve → address floor →
//! connect → TLS, behind hyper-util's pooled client.
//!
//! # Pooling and the address floor
//!
//! The floor runs inside the connector, i.e. for every new connection. A
//! pooled connection is keyed by scheme + authority only and is reused
//! without re-resolving; a connection to an address that becomes denied by a
//! later config is therefore reused until the pool is rebuilt. The pool is
//! rebuilt on every reload ([`Upstream`] lives in the policy snapshot), so
//! this window ends at the next reload. Flows with `private_ok` use a
//! separate pool, so a connection opened for a `private_ok` flow is never
//! reused by a flow without it.

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
}

impl Default for UpstreamSettings {
    fn default() -> Self {
        Self {
            dns: DnsSettings::default(),
            address_policy: AddressPolicy::default(),
            connect_timeout: Duration::from_secs(10),
            pool_idle_timeout: Duration::from_secs(90),
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
    /// Stable flow-log reason code (§7).
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
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
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
    tls: Arc<ClientConfig>,
    private_ok: bool,
}

/// `Service<Uri>` performing resolve → floor → connect → TLS.
#[derive(Clone)]
pub(crate) struct Connector {
    inner: Arc<ConnectorInner>,
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
            match tokio::time::timeout(
                self.connect_timeout,
                TcpStream::connect(SocketAddr::new(ip, port)),
            )
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
        let _ = tcp.set_nodelay(true);
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

    fn call(&mut self, uri: Uri) -> Self::Future {
        let inner = self.inner.clone();
        Box::pin(async move {
            let scheme = match uri.scheme_str() {
                Some("https") => Scheme::Https,
                Some("http") => Scheme::Http,
                other => return Err(ConnectError::Target(format!("scheme {other:?}"))),
            };
            let host = host_of(&uri)?;
            let port = uri.port_u16().unwrap_or(scheme.default_port());
            let tls = inner.tls.clone();
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

/// Everything needed to talk to upstreams under one policy snapshot.
pub(crate) struct Upstream {
    strict: HttpClient,
    private: HttpClient,
    strict_conn: Connector,
    private_conn: Connector,
    /// ALPN `http/1.1` only, for WebSocket upgrades.
    h1_tls: Arc<ClientConfig>,
}

impl std::fmt::Debug for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Upstream").finish_non_exhaustive()
    }
}

impl Upstream {
    pub(crate) fn new(s: &UpstreamSettings, tls: &Arc<ClientConfig>) -> Result<Self, String> {
        let dns = Arc::new(Dns::new(&s.dns)?);
        let mk = |private_ok| Connector {
            inner: Arc::new(ConnectorInner {
                dns: dns.clone(),
                policy: s.address_policy.clone(),
                connect_timeout: s.connect_timeout,
                tls: tls.clone(),
                private_ok,
            }),
        };
        let strict_conn = mk(false);
        let private_conn = mk(true);
        let build = |c: &Connector| {
            Client::builder(TokioExecutor::new())
                .pool_timer(TokioTimer::new())
                .pool_idle_timeout(s.pool_idle_timeout)
                .build(c.clone())
        };
        let mut h1 = (**tls).clone();
        h1.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            strict: build(&strict_conn),
            private: build(&private_conn),
            strict_conn,
            private_conn,
            h1_tls: Arc::new(h1),
        })
    }

    fn connector(&self, private_ok: bool) -> &Connector {
        if private_ok {
            &self.private_conn
        } else {
            &self.strict_conn
        }
    }

    /// The pooled client for a flow.
    pub(crate) fn client(&self, private_ok: bool) -> &HttpClient {
        if private_ok {
            &self.private
        } else {
            &self.strict
        }
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
        self.connector(private_ok)
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
        self.connector(private_ok)
            .inner
            .connect(scheme, &authority.host, authority.port, &self.h1_tls)
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
