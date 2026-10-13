//! The server: listeners, connection caps, the policy snapshot, reload and
//! graceful shutdown.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use arc_swap::{ArcSwap, ArcSwapOption};
use chrono::{DateTime, Utc};
use roxy_http::{HttpFlags, Limits, ParseError};
use roxy_rules::Policy;
use roxy_tls::{Ca, LeafMinter};
use rustls::ClientConfig;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::addr::canonical;
use crate::addrlist::AddressLists;
use crate::budget::{BufferBudget, BufferLease};
use crate::config::{HttpBehaviour, PolicyUpdate, RuntimeConfig};
use crate::flowlog::{FlowEvent, FlowSink, Redactor};
use crate::listener::{ClientConn, Listener, ListenerMode, TcpProxyListener};
use crate::pipeline::client_info;
use crate::quarantine::{QuarantineCause, QuarantineRecord, QuarantineState, TripCounter};
use crate::secrets::SecretStore;
use crate::sources::{MetricSource, StateSource};
use crate::upstream::{Dns, Upstream};

/// Everything that a reload swaps, as one unit. Each exchange clones the
/// `Arc` at its start and finishes under that snapshot, except for the
/// lease: [`Shared::expired`] reads the current snapshot's, so a reload
/// or an extension reaches exchanges already open.
pub(crate) struct Snapshot {
    pub policy: Policy,
    /// The lease's end; `None` = no expiry. Read live by [`Shared::expired`]
    /// and moved by [`ServerHandle::extend_valid_until`] without a rebuild.
    valid_until: ArcSwapOption<DateTime<Utc>>,
    /// Set when the snapshot was first seen expired, so `policy_expired`
    /// is logged once per expiry; cleared when the expiry moves later.
    expired_logged: AtomicBool,
    /// A stand-in from startup, not a policy anyone applied: `/readyz`
    /// says `no_policy` until a reload replaces it. See
    /// [`RuntimeConfig::placeholder_policy`].
    pub placeholder: bool,
    /// The server's one secret store, shared by every snapshot; its values
    /// and redactor change under a running exchange.
    pub secrets: Arc<SecretStore>,
    pub limits: Arc<Limits>,
    pub flags: Arc<HttpFlags>,
    pub http: Arc<HttpBehaviour>,
    /// Rebuilt on every reload, which also flushes the upstream pools; the
    /// resolver inside is the server's and keeps its cache.
    pub upstream: Arc<Upstream>,
    /// Address lists for `ip in @name` (and, resolved into the upstream's
    /// address policy, `upstream.deny_lists`).
    pub address_lists: Arc<AddressLists>,
    /// The addon stack, outermost first.
    pub addons: Arc<[Arc<crate::addons::AddonSpec>]>,
    /// Service layers' connection pools. A reload starts empty ones, so
    /// new exchanges dial under the new policy, and retires
    /// the old ones, whose connections close as their exchanges end.
    pub services: crate::addons::service::Pools,
}

/// What `/readyz` reports: whether an applied policy is in force. An
/// empty policy is a legitimate deny-all that serves and logs its
/// denials, so it counts as loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PolicyState {
    /// A policy has been applied and its lease has not run out.
    Loaded,
    /// No policy has been applied yet (the startup placeholder).
    Missing,
    /// The policy's lease has run out. Denies everything until a reload
    /// brings a later lease.
    Expired,
    /// The process is quarantined. Denies everything, whatever the
    /// policy, until the quarantine is released.
    Quarantined,
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
    secrets: Arc<SecretStore>,
    pub sink: Arc<dyn FlowSink>,
    pub capture: Option<Arc<crate::capture::CaptureLog>>,
    pub metrics: Arc<dyn MetricSource>,
    pub state: Arc<dyn StateSource>,
    pub ca: Arc<Ca>,
    pub minter: Arc<LeafMinter>,
    upstream_tls: Arc<ClientConfig>,
    dns: Arc<Dns>,
    pub connection_events: bool,
    /// `log.flow.ws_message_every`: log every Nth checked WebSocket message
    /// (0: only denied ones).
    pub ws_message_every: u64,
    /// Each addon's keyed store, by addon name; survives reloads.
    pub layer_state: crate::addons::store::LayerStates,
    /// The process-wide quarantine; outlives this server.
    pub quarantine: Arc<QuarantineState>,
    /// Each listener's parse-error threshold counter, by listener name.
    parse_error_trips: HashMap<String, TripCounter>,
    /// Bytes reserved for per-exchange buffers, against the current
    /// snapshot's `max_buffered_bytes`.
    buffers: Arc<BufferBudget>,
    caps: Arc<ConnCaps>,
    ca_caps: Arc<ConnCaps>,
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

    /// Whether the lease has run out. The lease is the deployment's, not
    /// an exchange's: the current snapshot's `valid_until` is what counts,
    /// checked against the wall clock on every exchange and WebSocket
    /// message, since it is an absolute instant and only a reload or an
    /// extension brings it back. The first check that finds the lease
    /// expired logs `policy_expired`.
    pub(crate) fn expired(&self) -> bool {
        let snap = self.snapshot();
        let Some(until) = snap.valid_until.load().as_deref().copied() else {
            return false;
        };
        let now = Utc::now();
        if now < until {
            return false;
        }
        if !snap.expired_logged.swap(true, Ordering::AcqRel) {
            tracing::warn!(valid_until = %until.to_rfc3339(), "policy expired; denying every exchange until a reload");
            self.sink.emit(&FlowEvent::PolicyExpired {
                ts: now,
                valid_until: until,
            });
        }
        true
    }

    /// The current policy's state, for `/readyz`. A quarantine comes first:
    /// it refuses everything whatever the policy says.
    pub(crate) fn policy_state(&self) -> PolicyState {
        let snap = self.snapshot();
        if self.quarantined() {
            PolicyState::Quarantined
        } else if snap.placeholder {
            PolicyState::Missing
        } else if self.expired() {
            PolicyState::Expired
        } else {
            PolicyState::Loaded
        }
    }

    /// Whether the process is quarantined. Read on every exchange and
    /// WebSocket message, like the lease.
    pub(crate) fn quarantined(&self) -> bool {
        self.quarantine.is_active()
    }

    /// Puts the process into quarantine for `cause`, unless it already is.
    /// Logs the trip, and cuts the connections open at this moment after
    /// [`CUT_GRACE`]; the exchange that tripped it has that long to write
    /// its refusal.
    pub(crate) fn trip_quarantine(&self, cause: QuarantineCause) {
        let trip = self.quarantine.trip(cause);
        if !trip.tripped {
            return;
        }
        let record = &trip.record;
        match &trip.persisted {
            Ok(()) => tracing::error!(
                id = %record.id,
                cause = ?record.cause,
                "quarantined; refusing every exchange until released"
            ),
            Err(e) => tracing::error!(
                id = %record.id,
                cause = ?record.cause,
                error = %e,
                "quarantined, but the marker could not be written: the quarantine will not survive a restart"
            ),
        }
        self.emit_quarantined(record, false);
    }

    /// Logs a quarantine read back from the state dir, once per process.
    fn announce_restored_quarantine(&self) {
        if let Some(record) = self.quarantine.active()
            && self.quarantine.take_announce()
        {
            tracing::error!(
                id = %record.id,
                since = %record.since.to_rfc3339(),
                cause = ?record.cause,
                "starting quarantined; refusing every exchange until released"
            );
            self.emit_quarantined(&record, true);
        }
    }

    fn emit_quarantined(&self, record: &QuarantineRecord, restored: bool) {
        self.sink.emit(&FlowEvent::Quarantined {
            ts: Utc::now(),
            id: record.id.clone(),
            since: record.since,
            cause: record.cause.clone(),
            restored,
        });
    }

    /// Counts a parse error towards the listener's threshold, tripping
    /// the quarantine when it is reached.
    fn note_parse_error(&self, c: &ClientConn, reason: &str) {
        if !crate::quarantine::counts_as_probe(reason) {
            return;
        }
        let Some(counter) = self.parse_error_trips.get(&c.listener.name) else {
            return;
        };
        if counter.note(std::time::Instant::now()) {
            let t = counter.threshold();
            self.trip_quarantine(QuarantineCause::Threshold {
                listener: c.listener.name.clone(),
                counter: crate::quarantine::PARSE_ERRORS.to_owned(),
                count: t.count,
                window_seconds: t.window.as_secs(),
            });
        }
    }

    fn build_snapshot(&self, u: PolicyUpdate) -> Result<Snapshot, String> {
        build_snapshot(u, &self.dns, &self.upstream_tls, &self.secrets)
    }

    /// Reserves `bytes` of the buffer budget, or `None` when that would
    /// take the process past `limits.max_buffered_bytes` as it stands now
    /// (a reload applies to the next reservation, not to those held).
    pub(crate) fn reserve_buffer(&self, bytes: u64) -> Option<BufferLease> {
        let cap = self.snapshot().limits.max_buffered_bytes;
        self.buffers.reserve(cap, bytes)
    }

    /// Grows `lease` to `bytes` within the budget; `false` leaves it as it
    /// was.
    pub(crate) fn grow_buffer(&self, lease: &mut BufferLease, bytes: u64) -> bool {
        let cap = self.snapshot().limits.max_buffered_bytes;
        lease.grow_to(cap, bytes)
    }

    /// A content decoder's meter: a lease that grows to the windows the
    /// decoder charges and lives as long as the decoder does. Refuses
    /// everything when the budget is already over its cap.
    pub(crate) fn window_meter(self: &Arc<Self>) -> roxy_http::coding::Meter<'static> {
        let Some(mut lease) = self.reserve_buffer(0) else {
            return Box::new(|_| false);
        };
        let shared = self.clone();
        Box::new(move |held| shared.grow_buffer(&mut lease, held))
    }

    /// Bytes of the buffer budget reserved right now.
    #[cfg(test)]
    pub(crate) fn buffered(&self) -> u64 {
        self.buffers.used()
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
        // Redacted once, for both sinks: a detail string can quote what the
        // client sent.
        let redactor = self.secrets.redactor();
        let detail = detail.map(|d| redactor.redact_str(d).into_owned());
        tracing::debug!(conn = %c.id, reason, detail, "client protocol error");
        self.sink.emit(&FlowEvent::ParseError {
            ts: chrono::Utc::now(),
            conn: c.id.to_string(),
            flow,
            listener: c.listener.name.clone(),
            client: client_info(c),
            reason: reason.to_owned(),
            detail,
        });
        self.note_parse_error(c, reason);
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
        let cut = self.quarantine.cut_token();
        self.tasks.spawn(async move {
            let _slot = slot;
            tokio::select! {
                () = fut => {}
                () = kill.cancelled() => {}
                () = cut_after_grace(cut, kill.clone()) => {}
            }
        });
    }
}

/// One parse-error counter per listener with a `quarantine_on`.
fn trip_counters(listeners: &[crate::config::ListenerSpec]) -> HashMap<String, TripCounter> {
    listeners
        .iter()
        .filter_map(|l| {
            l.quarantine_on
                .map(|t| (l.name.clone(), TripCounter::new(t)))
        })
        .collect()
}

/// How long a connection open when the quarantine trips has to finish on
/// its own. Long enough for the exchange that tripped it to write its
/// refusal; short enough that a stream in flight carries little more.
pub(crate) const CUT_GRACE: Duration = Duration::from_secs(1);

/// Resolves [`CUT_GRACE`] after a quarantine trip, or at the kill switch.
async fn cut_after_grace(cut: CancellationToken, kill: CancellationToken) {
    cut.cancelled().await;
    tokio::select! {
        () = tokio::time::sleep(CUT_GRACE) => {}
        () = kill.cancelled() => {}
    }
}

/// Builds a snapshot from the reloadable part of the config. Everything
/// read once at start ([`RuntimeConfig`]) reaches it only as the server's
/// built state: the resolver, the upstream TLS config, the secret store.
fn build_snapshot(
    u: PolicyUpdate,
    dns: &Arc<Dns>,
    tls: &Arc<ClientConfig>,
    secrets: &Arc<SecretStore>,
) -> Result<Snapshot, String> {
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
    let upstream = Upstream::new(&settings, dns, tls);
    Ok(Snapshot {
        policy: u.policy,
        valid_until: ArcSwapOption::from_pointee(u.valid_until),
        expired_logged: AtomicBool::new(false),
        placeholder: false,
        secrets: secrets.clone(),
        limits: Arc::new(u.limits),
        flags: Arc::new(u.flags),
        http: Arc::new(u.http),
        upstream: Arc::new(upstream),
        address_lists: u.address_lists,
        addons: u.addons.into(),
        services: crate::addons::service::Pools::default(),
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

/// A snapshot built by [`ServerHandle::prepare`] and not yet serving.
/// Dropping it without [`ServerHandle::commit`] leaves the server as it
/// was.
pub struct PreparedReload {
    snapshot: Snapshot,
    secrets: HashMap<String, String>,
    redactor: Redactor,
}

impl std::fmt::Debug for PreparedReload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedReload").finish_non_exhaustive()
    }
}

impl ServerHandle {
    /// Builds the snapshot for `update` (policy, secrets, limits, upstream
    /// settings) without installing it. Everything in a reload that can
    /// fail happens here, so a caller with other state to swap alongside
    /// the policy can do so between this and [`Self::commit`].
    pub fn prepare(&self, mut update: PolicyUpdate) -> Result<PreparedReload, String> {
        let secrets = std::mem::take(&mut update.secrets);
        let redactor = std::mem::take(&mut update.redactor);
        let snapshot = self.shared.build_snapshot(update)?;
        Ok(PreparedReload {
            snapshot,
            secrets,
            redactor,
        })
    }

    /// Swaps in a prepared snapshot atomically. In-flight exchanges finish
    /// under the snapshot they started with. The secret store is replaced
    /// first, so the redactor covers every value before a rule can inject
    /// it.
    pub fn commit(&self, prepared: PreparedReload) {
        let snap = prepared.snapshot;
        self.shared
            .secrets
            .replace(prepared.secrets, prepared.redactor);
        self.shared
            .layer_state
            .configure(snap.addons.iter().map(|a| (a.name.as_str(), &a.state)));
        let old = self.shared.snapshot.swap(Arc::new(snap));
        old.services.retire();
    }

    /// [`Self::prepare`] then [`Self::commit`]. On error the old snapshot
    /// stays.
    pub fn reload(&self, update: PolicyUpdate) -> Result<(), String> {
        let prepared = self.prepare(update)?;
        self.commit(prepared);
        Ok(())
    }

    /// Moves the current policy's `valid_until` to `until` without a
    /// rebuild: the snapshot, its upstream pools and the addon stack stay
    /// as they are. An extension past an expiry already logged lets the
    /// next expiry log `policy_expired` again.
    pub fn extend_valid_until(&self, until: DateTime<Utc>) {
        let snap = self.shared.snapshot();
        let old = snap.valid_until.swap(Some(Arc::new(until)));
        if old.is_none_or(|old| *old < until) {
            snap.expired_logged.store(false, Ordering::Release);
        }
    }

    /// Replaces the secret map without touching the policy: the rules,
    /// addons and upstream pools stay as they are and no event is logged.
    /// `secrets` is the whole map, by the names the config declares under
    /// `secrets:`; a name the policy references but the map lacks fails
    /// each flow that needs it closed (`secret_missing`). The next request
    /// to evaluate sees the new values; an exchange already under way keeps
    /// the value it injected, and the redactor scrubs both until the swap
    /// after this one.
    pub fn swap_secrets(&self, secrets: HashMap<String, String>) {
        tracing::info!(secrets = secrets.len(), "secrets swapped");
        self.shared.secrets.swap(secrets);
    }

    /// The quarantine in force, if any.
    pub fn quarantine(&self) -> Option<Arc<QuarantineRecord>> {
        self.shared.quarantine.active()
    }

    /// Releases the quarantine if `id` names the incident in force, and
    /// logs the release. `Ok(false)`: `id` is not the active incident, so
    /// nothing changed. `Err`: the marker could not be removed, and the
    /// process stays quarantined.
    pub fn release_quarantine(&self, id: &str) -> std::io::Result<bool> {
        let released = self.shared.quarantine.release(id)?;
        if released {
            tracing::warn!(id, "quarantine released");
            self.shared.sink.emit(&FlowEvent::QuarantineReleased {
                ts: Utc::now(),
                id: id.to_owned(),
            });
        }
        Ok(released)
    }

    /// Identifies the current snapshot: two calls return the same value
    /// only if no reload swapped it between them. For tests of the paths
    /// that must not rebuild.
    pub fn snapshot_id(&self) -> usize {
        Arc::as_ptr(&self.shared.snapshot()) as usize
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
        let dns =
            Arc::new(Dns::new(&cfg.dns).map_err(|e| StartError(format!("upstream.dns: {e}")))?);
        let mut policy = cfg.policy;
        let secrets = Arc::new(SecretStore::new(
            std::mem::take(&mut policy.secrets),
            std::mem::take(&mut policy.redactor),
        ));
        let mut snap = build_snapshot(policy, &dns, &upstream_tls, &secrets).map_err(StartError)?;
        snap.placeholder = cfg.placeholder_policy;
        let parse_error_trips = trip_counters(&cfg.listeners);
        let shared = Arc::new(Shared {
            snapshot: ArcSwap::from_pointee(snap),
            secrets,
            sink: cfg.sink,
            capture: cfg.capture,
            metrics: cfg.metrics,
            state: cfg.state,
            ca: cfg.ca,
            minter: cfg.minter,
            upstream_tls,
            dns,
            connection_events: cfg.connection_events,
            ws_message_every: cfg.ws_message_every,
            layer_state: crate::addons::store::LayerStates::default(),
            quarantine: cfg.quarantine,
            parse_error_trips,
            buffers: Arc::new(BufferBudget::default()),
            caps: Arc::new(ConnCaps {
                max: cfg.max_connections.max(1),
                max_per_client: cfg.max_connections_per_client.max(1),
                state: Mutex::new((0, HashMap::new())),
            }),
            // Counted apart from the proxy's connections, so a client filling
            // `max_connections` cannot starve `/healthz` into a restart. No
            // per-client cap: behind a load balancer every client is one IP.
            ca_caps: Arc::new(ConnCaps {
                max: cfg.max_connections.max(1),
                max_per_client: cfg.max_connections.max(1),
                state: Mutex::new((0, HashMap::new())),
            }),
            stop: CancellationToken::new(),
            kill: CancellationToken::new(),
            tasks: TaskTracker::new(),
        });
        let mut bound: Vec<Arc<dyn Listener>> = Vec::new();
        let mut addrs = Vec::new();
        for spec in &cfg.listeners {
            let l = TcpProxyListener::bind(&spec.name, spec.mode, spec.bind)
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
        shared.announce_restored_quarantine();
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
            r = async {
                // Audit backpressure: while the flow log is behind, new
                // connections wait in the kernel's backlog, so the events
                // they would emit (a refusal, a parse error) are never
                // buffered without bound.
                crate::flowlog::sink_ready(&*shared.sink).await;
                listener.accept().await
            } => r,
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
                let stream = Box::new(stream);
                match client.listener.mode {
                    ListenerMode::HttpProxy => {
                        shared.spawn_conn(slot, crate::conn::serve_http_proxy(stream, client, s));
                    }
                    ListenerMode::Http => {
                        shared.spawn_conn(slot, crate::conn::serve_http(stream, client, s));
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

/// Acquires a proxy connection slot outside the accept loop (the testkit).
#[cfg(test)]
pub(crate) fn conn_slot(shared: &Shared, ip: IpAddr) -> Option<ConnSlot> {
    shared.caps.acquire(ip).ok()
}

/// Acquires a slot from the `ca_server` listener's own cap.
pub(crate) fn ca_conn_slot(shared: &Shared, ip: IpAddr) -> Result<ConnSlot, &'static str> {
    shared.ca_caps.acquire(ip)
}

#[cfg(test)]
mod tests {
    use crate::flowlog::REDACTED;
    use crate::listener::ListenerMode;
    use crate::testkit::{Kit, capture_logs, client_conn};

    /// A parse-error detail is redacted once for both sinks, so a secret
    /// it quotes reaches neither the operational log nor the flow log.
    #[tokio::test]
    async fn a_parse_error_detail_is_redacted_in_the_operational_log_too() {
        let secret = "sk-live-123";
        let kit = Kit::builder().secret("k", secret).start().await;
        let shared = kit.server.shared();
        let client = client_conn(ListenerMode::HttpProxy);
        let detail = format!("sni {secret}");
        let logged = capture_logs(tracing::Level::DEBUG, || {
            shared.emit_parse_reason(&client, None, "bad_sni", Some(&detail));
        });
        assert!(logged.contains("client protocol error"), "{logged}");
        assert!(!logged.contains(secret), "{logged}");
        assert!(logged.contains(REDACTED), "{logged}");
        let ev = kit.events("parse_error", 1).await;
        assert_eq!(ev[0]["detail"], format!("sni {REDACTED}"));
    }
}
