//! Listeners and client connections.
//!
//! A [`Listener`] accepts a TCP stream and describes it as a
//! [`ClientConn`]; the server then hands both to the pipeline for the
//! listener's [`ListenerMode`]. Transparent mode (issue #15) would be one
//! more implementation.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use ulid::Ulid;

/// Listener mode (`listener.mode` in rules).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerMode {
    /// `HTTP_PROXY` mode: absolute-form requests and CONNECT.
    Explicit,
    /// Clients connect as if to the origin (DNS steering): the target comes
    /// from the TLS SNI or the `Host` header.
    Direct {
        /// The port clients believe they are connecting to, which becomes
        /// the target's port.
        port: u16,
    },
}

impl ListenerMode {
    /// The rule-visible name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Explicit => "explicit",
            Self::Direct { .. } => "direct",
        }
    }
}

/// Static description of a listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerInfo {
    /// `listener.name`.
    pub name: String,
    /// `listener.mode`.
    pub mode: ListenerMode,
}

/// One accepted client connection.
#[derive(Debug, Clone)]
pub struct ClientConn {
    /// Connection id (flow-log `conn`).
    pub id: Ulid,
    /// The listener that accepted it.
    pub listener: Arc<ListenerInfo>,
    /// Client address.
    pub peer: SocketAddr,
    /// Original destination (transparent mode only; always `None` today).
    pub original_dst: Option<SocketAddr>,
}

/// Future returned by [`Listener::accept`].
pub type AcceptFuture<'a> =
    Pin<Box<dyn Future<Output = io::Result<(TcpStream, ClientConn)>> + Send + 'a>>;

/// A source of client connections.
pub trait Listener: Send + Sync {
    /// The listener's description.
    fn info(&self) -> &Arc<ListenerInfo>;
    /// The bound address.
    fn local_addr(&self) -> io::Result<SocketAddr>;
    /// Accepts the next connection.
    fn accept(&self) -> AcceptFuture<'_>;
}

/// A plain TCP listener: explicit or direct, by its [`ListenerMode`].
#[derive(Debug)]
pub struct TcpProxyListener {
    info: Arc<ListenerInfo>,
    tcp: TcpListener,
}

impl TcpProxyListener {
    /// Binds an explicit-proxy listener on `addr`.
    pub async fn bind(name: &str, addr: SocketAddr) -> io::Result<Self> {
        let tcp = TcpListener::bind(addr).await?;
        Ok(Self {
            info: Arc::new(ListenerInfo {
                name: name.to_owned(),
                mode: ListenerMode::Explicit,
            }),
            tcp,
        })
    }

    /// Binds a direct listener on `addr`. `target_port` defaults to the
    /// bound port.
    pub async fn bind_direct(
        name: &str,
        addr: SocketAddr,
        target_port: Option<u16>,
    ) -> io::Result<Self> {
        let tcp = TcpListener::bind(addr).await?;
        let port = match target_port {
            Some(p) => p,
            None => tcp.local_addr()?.port(),
        };
        Ok(Self {
            info: Arc::new(ListenerInfo {
                name: name.to_owned(),
                mode: ListenerMode::Direct { port },
            }),
            tcp,
        })
    }
}

impl Listener for TcpProxyListener {
    fn info(&self) -> &Arc<ListenerInfo> {
        &self.info
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.tcp.local_addr()
    }

    fn accept(&self) -> AcceptFuture<'_> {
        Box::pin(async move {
            let (stream, peer) = self.tcp.accept().await?;
            let _ = stream.set_nodelay(true);
            Ok((
                stream,
                ClientConn {
                    id: Ulid::generate(),
                    listener: self.info.clone(),
                    peer,
                    original_dst: None,
                },
            ))
        })
    }
}
