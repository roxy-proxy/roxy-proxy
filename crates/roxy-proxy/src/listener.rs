//! Listeners and client connections (`DESIGN.md` §4).
//!
//! [`Listener`] is the hook transparent mode (§4.2) will implement: it
//! accepts a TCP stream and describes it as a [`ClientConn`]; the server
//! then hands both to the pipeline for the listener's [`ListenerMode`].
//! Only [`ExplicitListener`] exists in this build.

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
}

impl ListenerMode {
    /// The rule-visible name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Explicit => "explicit",
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
    /// Whether `Proxy-Authorization` is required (users come from the
    /// policy snapshot, keyed by listener name).
    pub auth_required: bool,
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
    /// Proxy-auth user (`client.user`), once authenticated. On the proxy
    /// port each request authenticates on its own; inside a CONNECT tunnel
    /// the CONNECT's user applies.
    pub user: Option<String>,
    /// Original destination (transparent mode only; always `None` here).
    pub original_dst: Option<SocketAddr>,
}

impl ClientConn {
    /// A copy with `user` set.
    #[must_use]
    pub fn with_user(&self, user: Option<String>) -> Self {
        Self {
            user,
            ..self.clone()
        }
    }
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

/// The explicit-proxy listener.
#[derive(Debug)]
pub struct ExplicitListener {
    info: Arc<ListenerInfo>,
    tcp: TcpListener,
}

impl ExplicitListener {
    /// Binds `addr`.
    pub async fn bind(name: &str, addr: SocketAddr, auth_required: bool) -> io::Result<Self> {
        let tcp = TcpListener::bind(addr).await?;
        Ok(Self {
            info: Arc::new(ListenerInfo {
                name: name.to_owned(),
                mode: ListenerMode::Explicit,
                auth_required,
            }),
            tcp,
        })
    }
}

impl Listener for ExplicitListener {
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
                    user: None,
                    original_dst: None,
                },
            ))
        })
    }
}
