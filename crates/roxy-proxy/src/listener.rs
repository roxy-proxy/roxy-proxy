//! Listeners and client connections.
//!
//! A [`Listener`] accepts a TCP stream and describes it as a
//! [`ClientConn`]; the server then hands both to the connection handler
//! for the listener's [`ListenerMode`].

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use ulid::Ulid;

/// What a listener's clients speak to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerMode {
    /// An HTTP proxy: absolute-form requests and CONNECT.
    HttpProxy,
    /// Plain HTTP/1.1 spoken to roxy as if it were the server: origin-form
    /// requests, each to the host its `Host` names.
    Http,
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

/// A plain TCP listener, in either mode.
#[derive(Debug)]
pub struct TcpProxyListener {
    info: Arc<ListenerInfo>,
    tcp: TcpListener,
}

impl TcpProxyListener {
    /// Binds a listener on `addr`.
    pub async fn bind(name: &str, mode: ListenerMode, addr: SocketAddr) -> io::Result<Self> {
        let tcp = TcpListener::bind(addr).await?;
        Ok(Self {
            info: Arc::new(ListenerInfo {
                name: name.to_owned(),
                mode,
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
