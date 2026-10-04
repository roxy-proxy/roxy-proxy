//! The server: listeners, connection caps, the policy snapshot, reload and
//! graceful shutdown.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use arc_swap::ArcSwap;
use roxy_http::{HttpFlags, Limits, ParseError};
use roxy_rules::Policy;
use roxy_tls::{Ca, LeafMinter};
use rustls::ClientConfig;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::addr::canonical;
use crate::addrlist::AddressLists;
use crate::auth::UserDb;
use crate::config::{PolicyUpdate, RuntimeConfig};
use crate::flowlog::{FlowEvent, FlowSink, Redactor};
use crate::listener::{ClientConn, ExplicitListener, Listener, ListenerMode};
use crate::pipeline::client_info;
use crate::sources::{MetricSource, StateSource};
use crate::upstream::Upstream;

/// Everything that a reload swaps, as one unit. Each exchange clones the
/// `Arc` at its start and finishes under that snapshot.
pub(crate) struct Snapshot {
    pub policy: Policy,
    pub secrets: HashMap<String, String>,
    pub redactor: Redactor,
    pub users: HashMap<String, Arc<UserDb>>,
    pub limits: Arc<Limits>,
    pub flags: Arc<HttpFlags>,
    /// Rebuilt on every reload, which also flushes the upstream pools.
    pub upstream: Arc<Upstream>,
    /// Address lists for `ip in @name` (and, resolved into the upstream's
    /// address policy, `upstream.deny_lists`).
    pub address_lists: Arc<AddressLists>,
    /// The addon stack, outermost first.
    pub addons: Arc<[Arc<crate::addons::AddonSpec>]>,
}

/// Per-client and global connection counting.
struct ConnCaps {
    max: usize,
    max_per_client: usize,
    state: Mutex<(usize, HashMap<IpAddr, usize>)>,
}

/// Releases a connection slot on drop.
pub(crate) struct ConnSlot {
    caps: Arc<ConnCaps>,
    ip: IpAddr,
}

impl Drop for ConnSlot {
    fn drop(&mut self) {
        let mut g = self
            .caps
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        g.0 = g.0.saturating_sub(1);
        if let Some(n) = g.1.get_mut(&self.ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                g.1.remove(&self.ip);
            }
        }
    }
}

impl ConnCaps {
    fn acquire(self: &Arc<Self>, ip: IpAddr) -> Result<ConnSlot, &'static str> {
        let ip = canonical(ip);
        let mut g = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if g.0 >= self.max {
            return Err("max_connections");
        }
        let per = g.1.get(&ip).copied().unwrap_or(0);
        if per >= self.max_per_client {
            return Err("max_connections_per_client");
        }
        g.0 += 1;
        *g.1.entry(ip).or_insert(0) += 1;
        Ok(ConnSlot {
            caps: self.clone(),
            ip,
        })
    }
}

/// State shared by every connection task.
pub(crate) struct Shared {
    snapshot: ArcSwap<Snapshot>,
    pub sink: Arc<dyn FlowSink>,
    pub capture: Option<Arc<crate::capture::CaptureLog>>,
    pub metrics: Arc<dyn MetricSource>,
    pub state: Arc<dyn StateSource>,
    pub ca: Arc<Ca>,
    pub minter: Arc<LeafMinter>,
    upstream_tls: Arc<ClientConfig>,
    pub require_sni_match: bool,
    /// Offer ALPN `h2` in terminated tunnels.
    pub enable_h2: bool,
    pub connection_events: bool,
    /// `log.flow.ws_message_every`: log every Nth checked WebSocket message
    /// (0: only denied ones).
    pub ws_message_every: u64,
    /// Each addon's keyed store, by addon name; survives reloads.
    pub layer_state: crate::addons::store::LayerStates,
    caps: Arc<ConnCaps>,
    /// Stop accepting; idle connections end.
    pub stop: CancellationToken,
    /// Grace period over: drop everything.
    kill: CancellationToken,
    tasks: TaskTracker,
}

impl Shared {
    /// The current snapshot.
    pub(crate) fn snapshot(&self) -> Arc<Snapshot> {
        self.snapshot.load_full()
    }

    fn build_snapshot(&self, u: PolicyUpdate) -> Result<Snapshot, String> {
        build_snapshot(u, &self.upstream_tls)
    }

    pub(crate) fn emit_parse_error(&self, c: &ClientConn, flow: Option<String>, e: &ParseError) {
        self.emit_parse_reason(c, flow, e.reason.as_str(), Some(&e.detail));
    }

    pub(crate) fn emit_parse_reason(
        &self,
        c: &ClientConn,
        flow: Option<String>,
        reason: &str,
        detail: Option<&str>,
    ) {
        tracing::debug!(conn = %c.id, reason, detail, "client protocol error");
        let redactor = self.snapshot().redactor.clone();
        self.sink.emit(&FlowEvent::ParseError {
            ts: chrono::Utc::now(),
            conn: c.id.to_string(),
            flow,
            listener: c.listener.name.clone(),
            client: client_info(c),
            reason: reason.to_owned(),
            detail: detail.map(|d| redactor.redact_str(d).into_owned()),
        });
    }

    /// Spawns a connection task holding `slot` until it ends. The task is
    /// dropped (closing its sockets) if shutdown's grace period runs out.
    /// A panic inside it is contained by tokio and closes only that
    /// connection.
    pub(crate) fn spawn_conn<F>(&self, slot: ConnSlot, fut: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let kill = self.kill.clone();
        self.tasks.spawn(async move {
            let _slot = slot;
            tokio::select! {
                () = fut => {}
                () = kill.cancelled() => {}
            }
        });
    }
}

fn build_snapshot(u: PolicyUpdate, tls: &Arc<ClientConfig>) -> Result<Snapshot, String> {
    let mut settings = u.upstream;
    for name in &u.deny_lists {
        // Fail closed: a deny list that is not loaded refuses the snapshot
        // (startup error, or the reload fails and the old lists stay).
        let list = u
            .address_lists
            .get(name)
            .ok_or_else(|| format!("upstream.deny_lists: address list {name:?} is not loaded"))?;
        settings.address_policy.deny_lists.push(list.clone());
    }
    let upstream = Upstream::new(&settings, tls)?;
    Ok(Snapshot {
        policy: u.policy,
        secrets: u.secrets,
        redactor: u.redactor,
        users: u.users,
        limits: Arc::new(u.limits),
        flags: Arc::new(u.flags),
        upstream: Arc::new(upstream),
        address_lists: u.address_lists,
        addons: u.addons.into(),
    })
}

/// Errors starting the server.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct StartError(String);

/// A running roxy proxy.
pub struct Server {
    shared: Arc<Shared>,
    listeners: Vec<(String, SocketAddr)>,
    ca_addr: Option<SocketAddr>,
}

/// A cloneable handle for reloads (e.g. from a file watcher).
#[derive(Clone)]
pub struct ServerHandle {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for ServerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerHandle").finish_non_exhaustive()
    }
}

impl ServerHandle {
    /// Swaps in a new policy snapshot (policy, secrets, users, limits,
    /// upstream settings) atomically. On error the old snapshot stays.
    /// In-flight exchanges finish under the snapshot they started with.
    pub fn reload(&self, update: PolicyUpdate) -> Result<(), String> {
        let snap = self.shared.build_snapshot(update)?;
        self.shared
            .layer_state
            .configure(snap.addons.iter().map(|a| (a.name.as_str(), &a.state)));
        self.shared.snapshot.store(Arc::new(snap));
        Ok(())
    }

    /// The flow sink.
    pub fn sink(&self) -> Arc<dyn FlowSink> {
        self.shared.sink.clone()
    }

    /// The capture log, if capture is enabled.
    pub fn capture(&self) -> Option<Arc<crate::capture::CaptureLog>> {
        self.shared.capture.clone()
    }
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("listeners", &self.listeners)
            .field("ca_server", &self.ca_addr)
            .finish_non_exhaustive()
    }
}

impl Server {
    /// The state every connection task shares (the test harness serves
    /// connections on it directly).
    #[cfg(test)]
    pub(crate) fn shared(&self) -> &Arc<Shared> {
        &self.shared
    }

    /// Binds every listener (and the CA server) and starts serving.
    pub async fn start(cfg: RuntimeConfig) -> Result<Server, StartError> {
        roxy_tls::install_crypto_provider();
        let upstream_tls = roxy_tls::client_config(&cfg.upstream_tls)
            .map_err(|e| StartError(format!("upstream TLS configuration: {e}")))?;
        let snap = build_snapshot(cfg.policy, &upstream_tls).map_err(StartError)?;
        let shared = Arc::new(Shared {
            snapshot: ArcSwap::from_pointee(snap),
            sink: cfg.sink,
            capture: cfg.capture,
            metrics: cfg.metrics,
            state: cfg.state,
            ca: cfg.ca,
            minter: cfg.minter,
            upstream_tls,
            require_sni_match: cfg.require_sni_match,
            enable_h2: cfg.enable_h2,
            connection_events: cfg.connection_events,
            ws_message_every: cfg.ws_message_every,
            layer_state: crate::addons::store::LayerStates::default(),
            caps: Arc::new(ConnCaps {
                max: cfg.max_connections.max(1),
                max_per_client: cfg.max_connections_per_client.max(1),
                state: Mutex::new((0, HashMap::new())),
            }),
            stop: CancellationToken::new(),
            kill: CancellationToken::new(),
            tasks: TaskTracker::new(),
        });
        let mut bound: Vec<Arc<dyn Listener>> = Vec::new();
        let mut addrs = Vec::new();
        for spec in &cfg.listeners {
            let l = ExplicitListener::bind(&spec.name, spec.bind, spec.auth_required)
                .await
                .map_err(|e| {
                    StartError(format!(
                        "binding listener {:?} on {}: {e}",
                        spec.name, spec.bind
                    ))
                })?;
            let addr = l
                .local_addr()
                .map_err(|e| StartError(format!("listener {:?}: {e}", spec.name)))?;
            addrs.push((spec.name.clone(), addr));
            bound.push(Arc::new(l));
        }
        let ca_addr = match cfg.ca_server {
            Some(bind) => {
                let tcp = TcpListener::bind(bind)
                    .await
                    .map_err(|e| StartError(format!("binding ca_server on {bind}: {e}")))?;
                let addr = tcp
                    .local_addr()
                    .map_err(|e| StartError(format!("ca_server: {e}")))?;
                let s = shared.clone();
                shared.tasks.spawn(crate::ca_server::serve(tcp, s));
                Some(addr)
            }
            None => None,
        };
        for l in bound {
            let s = shared.clone();
            shared.tasks.spawn(accept_loop(l, s));
        }
        for (name, addr) in &addrs {
            tracing::info!(listener = %name, %addr, "listening");
        }
        Ok(Server {
            shared,
            listeners: addrs,
            ca_addr,
        })
    }

    /// Bound listener addresses by name, in config order.
    pub fn local_addrs(&self) -> &[(String, SocketAddr)] {
        &self.listeners
    }

    /// The bound address of listener `name`.
    pub fn local_addr(&self, name: &str) -> Option<SocketAddr> {
        self.listeners
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, a)| *a)
    }

    /// The bound CA server address.
    pub fn ca_server_addr(&self) -> Option<SocketAddr> {
        self.ca_addr
    }

    /// A cloneable reload handle.
    pub fn handle(&self) -> ServerHandle {
        ServerHandle {
            shared: self.shared.clone(),
        }
    }

    /// See [`ServerHandle::reload`].
    pub fn reload(&self, update: PolicyUpdate) -> Result<(), String> {
        self.handle().reload(update)
    }

    /// Graceful shutdown: stop accepting, let in-flight exchanges finish for
    /// up to `grace`, then drop whatever is left.
    pub async fn shutdown(self, grace: Duration) {
        self.shared.stop.cancel();
        self.shared.tasks.close();
        if tokio::time::timeout(grace, self.shared.tasks.wait())
            .await
            .is_err()
        {
            tracing::warn!("shutdown grace period over; closing remaining connections");
            self.shared.kill.cancel();
            self.shared.tasks.wait().await;
        }
    }
}

async fn accept_loop(listener: Arc<dyn Listener>, shared: Arc<Shared>) {
    loop {
        let accepted = tokio::select! {
            r = listener.accept() => r,
            () = shared.stop.cancelled() => return,
        };
        let (stream, client) = match accepted {
            Ok(x) => x,
            Err(e) => {
                // EMFILE and friends: back off instead of spinning.
                tracing::warn!(error = %e, "accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        match shared.caps.acquire(client.peer.ip()) {
            Ok(slot) => {
                let s = shared.clone();
                match client.listener.mode {
                    ListenerMode::Explicit => {
                        shared.spawn_conn(
                            slot,
                            crate::conn::serve_explicit(Box::new(stream), client, s),
                        );
                    }
                }
            }
            Err(reason) => {
                drop(stream);
                tracing::info!(peer = %client.peer, reason, "connection refused");
                shared.sink.emit(&FlowEvent::ConnectionRefused {
                    ts: chrono::Utc::now(),
                    listener: client.listener.name.clone(),
                    client: client_info(&client),
                    reason: reason.to_owned(),
                });
            }
        }
    }
}

/// Acquires a slot for a CA-server connection.
pub(crate) fn ca_slot(shared: &Shared, ip: IpAddr) -> Option<ConnSlot> {
    shared.caps.acquire(ip).ok()
}
