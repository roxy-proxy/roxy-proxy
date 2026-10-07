//! `roxy run --control-plane`: node mode. The listeners open at once on a
//! bootstrap config that denies everything; a [`roxy_node::node::Node`]
//! enrols, fetches the lease and hands it to [`NodeHandler`], which turns
//! the rendered config and the secret map into the running policy. Flow
//! events go to the local `log.flow` destination and into the node's spool.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{Context as _, anyhow, bail};
use chrono::{DateTime, Utc};
use roxy_node::client::{NodeInfo, Trust};
use roxy_node::node::{Change, HandlerFuture, LeaseHandler, Node, NodeConfig, NodeError};
use roxy_node::protocol::{Lease, PolicyState, sha256_hex};
use roxy_node::spool::Spool;
use roxy_node::state::StateDir;
use roxy_proxy::{FlowEvent, FlowSink, PolicyUpdate, RuntimeConfig, Server};
use roxy_rules::Policy;
use roxy_tls::{CA_CERT_FILE, CA_KEY_FILE, Ca, CaError, LeafMinter};

use crate::addons::AddonLoader;
use crate::config::{Config, SecretSource};
use crate::run::{
    build_capture, build_sink, keep_restart_only, listener_specs, load_ca,
    policy_update_with_secrets,
};
use crate::secrets::Secrets;
use crate::stores::{BuiltinState, ReloadableMetrics};

/// In-flight exchanges get this long when the first lease replaces the
/// bootstrap listeners.
const RESTART_GRACE: Duration = Duration::from_secs(5);

/// How long shutdown waits for spooled flow events to reach the control
/// plane.
const DRAIN_GRACE: Duration = Duration::from_secs(10);

/// What the node runs before its first lease: the listeners it opens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bootstrap {
    pub proxy_bind: SocketAddr,
    /// `None` = no `ca_server` until the lease says so.
    pub ca_server_bind: Option<SocketAddr>,
}

impl Default for Bootstrap {
    fn default() -> Self {
        Self {
            proxy_bind: "0.0.0.0:3128".parse().expect("literal"),
            ca_server_bind: Some("0.0.0.0:3130".parse().expect("literal")),
        }
    }
}

/// `roxy run --control-plane ...`.
#[derive(Clone)]
pub struct NodeOptions {
    pub control_plane: String,
    pub enrol_token_file: Option<PathBuf>,
    pub state_dir: PathBuf,
    /// PEM bundle to verify the control plane with; `None` = system roots.
    pub control_plane_ca: Option<PathBuf>,
    /// `--interception-ca-cert` / `--interception-ca-key`: a CA pair to
    /// import into the state dir.
    pub interception_ca: Option<(PathBuf, PathBuf)>,
    pub replace_interception_ca: bool,
    pub bootstrap: Bootstrap,
    /// Flow sink override (default: the rendered config's `log.flow`).
    pub local_sink: Option<Arc<dyn FlowSink>>,
    /// Multiplies every protocol wait. 1.0 in production.
    #[doc(hidden)]
    pub time_scale: f64,
}

impl std::fmt::Debug for NodeOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeOptions")
            .field("control_plane", &self.control_plane)
            .field("state_dir", &self.state_dir)
            .finish_non_exhaustive()
    }
}

impl NodeOptions {
    pub fn new(control_plane: &str, state_dir: &Path) -> Self {
        Self {
            control_plane: control_plane.to_owned(),
            enrol_token_file: None,
            state_dir: state_dir.to_path_buf(),
            control_plane_ca: None,
            interception_ca: None,
            replace_interception_ca: false,
            bootstrap: Bootstrap::default(),
            local_sink: None,
            time_scale: 1.0,
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The local flow sink plus the node's spool. Ready only when both are:
/// the spool in `hold` mode at its high water holds traffic exactly as a
/// slow local writer does.
struct ShipSink {
    local: Arc<dyn FlowSink>,
    spool: Arc<Spool>,
}

impl FlowSink for ShipSink {
    fn emit(&self, event: &FlowEvent) {
        self.local.emit(event);
        if let Ok(line) = event.to_json_line() {
            self.spool.push(&line);
        }
    }

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<()> {
        let local = self.local.poll_ready(cx).is_ready();
        let spool = self.spool.poll_ready(cx).is_ready();
        if local && spool {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    fn flush(&self) {
        self.local.flush();
    }

    fn reopen(&self) {
        self.local.reopen();
    }
}

/// The policy the node runs.
struct RunningPolicy {
    config: Config,
    /// `config` compiled, for the metric store.
    policy: Policy,
    secrets: HashMap<String, String>,
    valid_until: Option<DateTime<Utc>>,
    /// A lease has been applied: the bootstrap listeners are gone.
    leased: bool,
    revoked: bool,
}

/// Applies leases to the server.
pub struct NodeHandler {
    state_dir: StateDir,
    spool: OnceLock<Arc<Spool>>,
    local_sink: Option<Arc<dyn FlowSink>>,
    addons: Arc<AddonLoader>,
    metrics: Arc<ReloadableMetrics>,
    state: Mutex<Arc<BuiltinState>>,
    server: tokio::sync::Mutex<Option<Server>>,
    running: tokio::sync::Mutex<RunningPolicy>,
    /// For `policy_state` without taking the async lock.
    state_summary: Mutex<(bool, bool, Option<DateTime<Utc>>)>,
}

impl std::fmt::Debug for NodeHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeHandler")
            .field("state_dir", &self.state_dir.path())
            .finish_non_exhaustive()
    }
}

/// Parses a lease's rendered config. The state dir is authoritative for
/// the interception CA, so `tls.ca_dir` always points into it and a
/// provided CA in the document is ignored.
fn parse_lease_config(text: &str, state_dir: &StateDir) -> Result<Config, String> {
    let mut config = Config::from_yaml(text)
        .map_err(|e| format!("config: {}", crate::config::describe_parse_error(text, &e)))?;
    if config.tls.ca_cert.is_some() || config.tls.ca_key.is_some() {
        tracing::warn!(
            "lease config sets tls.ca_cert/tls.ca_key; node mode uses the CA in the state dir"
        );
        config.tls.ca_cert = None;
        config.tls.ca_key = None;
    }
    if config.tls.ca_dir != state_dir.ca_dir() {
        if config.tls.ca_dir != crate::config::Tls::default().ca_dir {
            tracing::warn!(
                ca_dir = %config.tls.ca_dir.display(),
                "lease config sets tls.ca_dir; node mode uses the CA in the state dir"
            );
        }
        config.tls.ca_dir = state_dir.ca_dir();
    }
    Ok(config)
}

/// The full secret map: `env`/`file` entries resolved here, the rest from
/// the lease. A declared name with no value anywhere refuses the lease.
fn resolve_secrets(config: &Config, lease: &Lease) -> Result<HashMap<String, String>, String> {
    let from_lease = &lease.secrets;
    let mut sourced = BTreeMap::new();
    for (name, source) in &config.secrets {
        match source {
            SecretSource::Env(_) | SecretSource::File(_) => {
                sourced.insert(name.clone(), source.clone());
            }
            SecretSource::Lease => {}
        }
    }
    let resolved = Secrets::resolve(&sourced).map_err(|e| e.to_string())?;
    let mut map = HashMap::new();
    let mut missing = Vec::new();
    for name in config.secrets.keys() {
        if let Some(v) = resolved.get(name) {
            map.insert(name.clone(), v.expose().to_owned());
        } else if let Some(v) = from_lease.get(name) {
            map.insert(name.clone(), v.clone());
        } else {
            missing.push(name.as_str());
        }
    }
    if !missing.is_empty() {
        return Err(format!("lease secrets missing for: {}", missing.join(", ")));
    }
    Ok(map)
}

impl NodeHandler {
    fn spool(&self) -> &Arc<Spool> {
        self.spool
            .get()
            .expect("spool set before the server starts")
    }

    fn summarise(&self, run: &RunningPolicy) {
        *lock(&self.state_summary) = (run.leased, run.revoked, run.valid_until);
    }

    /// Everything a snapshot swap or a server start needs, from a config
    /// and its secret map.
    async fn build_update(
        &self,
        config: &Config,
        secrets: HashMap<String, String>,
        valid_until: Option<DateTime<Utc>>,
        restart: bool,
    ) -> Result<(Policy, PolicyUpdate, Option<crate::addons::PreparedAddons>), String> {
        let compiled = config.validate().map_err(|diags| {
            diags
                .iter()
                .map(|d| format!("config:{d}"))
                .collect::<Vec<_>>()
                .join("\n")
        })?;
        let policy = compiled.policy.clone();
        let mut update = policy_update_with_secrets(config, compiled.policy, secrets)
            .map_err(|e| format!("{e:#}"))?;
        update.valid_until = valid_until;
        let prepared = if restart {
            update.addons = self
                .addons
                .load(config, compiled.addon_conditions)
                .await
                .map_err(|e| format!("{e:#}"))?;
            None
        } else {
            let prepared = self
                .addons
                .prepare(config, compiled.addon_conditions)
                .await
                .map_err(|e| format!("{e:#}"))?;
            update.addons = prepared.specs();
            Some(prepared)
        };
        Ok((policy, update, prepared))
    }

    /// Starts a server for `config` with `update` as its policy;
    /// `placeholder` marks the bootstrap policy, which `/readyz` reports as
    /// no policy at all.
    async fn start_server(
        &self,
        config: &Config,
        update: PolicyUpdate,
        placeholder: bool,
    ) -> anyhow::Result<Server> {
        let ca = Arc::new(load_ca(config)?);
        let minter = Arc::new(LeafMinter::new(ca.clone(), config.tls.leaf_cache_size)?);
        let local = match &self.local_sink {
            Some(s) => s.clone(),
            None => build_sink(config)?,
        };
        let sink: Arc<dyn FlowSink> = Arc::new(ShipSink {
            local,
            spool: self.spool().clone(),
        });
        sink.emit(&FlowEvent::ConfigLoaded {
            ts: Utc::now(),
            path: PathBuf::from("<lease>"),
            listeners: config.listeners.iter().map(|l| l.name.clone()).collect(),
            rules: config.rules.len(),
            metrics: config.metrics.len(),
            addons: config.addons.len(),
        });
        let state = Arc::new(BuiltinState::new(config.limits.max_state_entries));
        *lock(&self.state) = state.clone();
        let rt = RuntimeConfig {
            listeners: listener_specs(config),
            ca_server: config.ca_server.as_ref().map(|c| c.bind),
            ca,
            minter,
            upstream_tls: config.into(),
            max_connections: config.limits.max_connections,
            max_connections_per_client: config.limits.max_connections_per_client,
            connection_events: config.log.flow.connection_events,
            ws_message_every: config.log.flow.ws_message_every,
            sink,
            capture: build_capture(config)?,
            metrics: self.metrics.clone(),
            state,
            policy: update,
            placeholder_policy: placeholder,
        };
        Ok(Server::start(rt).await?)
    }

    /// Swaps `update` into the running server, rebuilding the metric
    /// store around the swap as a file reload does, or from empty when the
    /// lease's `state_epoch` changed.
    async fn swap(
        &self,
        config: &Config,
        policy: &Policy,
        update: PolicyUpdate,
        prepared: Option<crate::addons::PreparedAddons>,
        clear_state: bool,
    ) -> Result<(), String> {
        let server = self.server.lock().await;
        let handle = server
            .as_ref()
            .ok_or_else(|| "server is not running".to_owned())?
            .handle();
        let limits = config.limits.metric_limits();
        let ready = handle.prepare(update)?;
        if clear_state {
            lock(&self.state).clear();
            self.metrics.reset(policy, limits);
            handle.commit(ready);
        } else {
            let early = self.metrics.keeps_every_metric(policy);
            if early {
                self.metrics.install(policy, limits);
            }
            handle.commit(ready);
            if !early {
                self.metrics.install(policy, limits);
            }
        }
        if let Some(p) = prepared {
            self.addons.install(p);
        }
        Ok(())
    }

    async fn apply_lease(
        &self,
        lease: &Lease,
        fetched_at: DateTime<Utc>,
        change: Change,
    ) -> Result<(), String> {
        let valid_for = i64::try_from(lease.valid_for_seconds).unwrap_or(i64::MAX);
        let valid_until = fetched_at
            .checked_add_signed(chrono::Duration::seconds(valid_for))
            .ok_or_else(|| "valid_for_seconds out of range".to_owned())?;
        let mut run = self.running.lock().await;
        if run.revoked {
            return Err("node is revoked".into());
        }
        if run.leased && !change.config {
            return self.renew_lease(&mut run, lease, valid_until, change).await;
        }
        let mut config = parse_lease_config(&lease.config, &self.state_dir)?;
        // The first lease replaces the bootstrap listeners outright; after
        // that, restart-only settings keep their running values, as on a
        // file reload.
        let restart = if run.leased {
            for field in keep_restart_only(&run.config, &mut config) {
                tracing::warn!(
                    field,
                    "lease changes a setting that takes effect at startup; the running value is kept until a restart"
                );
            }
            false
        } else {
            let mut probe = config.clone();
            !keep_restart_only(&run.config, &mut probe).is_empty()
        };
        let secrets = resolve_secrets(&config, lease)?;
        let (policy, update, prepared) = self
            .build_update(&config, secrets.clone(), Some(valid_until), restart)
            .await?;
        if restart {
            let old = self.server.lock().await.take();
            if let Some(old) = old {
                old.shutdown(RESTART_GRACE).await;
            }
            if change.state_epoch {
                self.metrics.reset(&policy, config.limits.metric_limits());
            } else {
                self.metrics.install(&policy, config.limits.metric_limits());
            }
            match self.start_server(&config, update, false).await {
                Ok(server) => *self.server.lock().await = Some(server),
                Err(e) => {
                    let e = format!("starting the listeners for the lease: {e:#}");
                    tracing::error!(lease_id = %lease.lease_id, error = %e, "lease refused");
                    self.reopen_bootstrap(&run).await;
                    return Err(e);
                }
            }
        } else {
            self.swap(&config, &policy, update, prepared, change.state_epoch)
                .await?;
        }
        tracing::info!(
            lease_id = %lease.lease_id,
            valid_until = %valid_until.to_rfc3339(),
            rules = config.rules.len(),
            restarted = restart,
            "lease applied"
        );
        *run = RunningPolicy {
            config,
            policy,
            secrets,
            valid_until: Some(valid_until),
            leased: true,
            revoked: false,
        };
        self.summarise(&run);
        Ok(())
    }

    /// A lease whose config is the one running: the lease moves forward
    /// on the live snapshot, the secret map is swapped if it changed and a
    /// new epoch clears state and metrics. Nothing is rebuilt, so the
    /// upstream pools and addon stack carry on.
    async fn renew_lease(
        &self,
        run: &mut RunningPolicy,
        lease: &Lease,
        valid_until: DateTime<Utc>,
        change: Change,
    ) -> Result<(), String> {
        let secrets = change
            .secrets
            .then(|| resolve_secrets(&run.config, lease))
            .transpose()?;
        let server = self.server.lock().await;
        let handle = server
            .as_ref()
            .ok_or_else(|| "server is not running".to_owned())?
            .handle();
        if change.state_epoch {
            lock(&self.state).clear();
            self.metrics
                .reset(&run.policy, run.config.limits.metric_limits());
        }
        if let Some(secrets) = secrets {
            handle.swap_secrets(secrets.clone());
            run.secrets = secrets;
        }
        handle.extend_valid_until(valid_until);
        drop(server);
        tracing::debug!(
            lease_id = %lease.lease_id,
            valid_until = %valid_until.to_rfc3339(),
            secrets = change.secrets,
            state_epoch = change.state_epoch,
            "lease renewed"
        );
        run.valid_until = Some(valid_until);
        self.summarise(run);
        Ok(())
    }

    /// Puts the bootstrap listeners back when the first lease's server
    /// failed to start after they were shut down, so `/healthz` stays up
    /// and `/readyz` keeps reporting `no_policy` until a lease applies.
    async fn reopen_bootstrap(&self, run: &RunningPolicy) {
        let limits = run.config.limits.metric_limits();
        let result = async {
            let update =
                policy_update_with_secrets(&run.config, run.policy.clone(), HashMap::new())?;
            self.metrics.install(&run.policy, limits);
            self.start_server(&run.config, update, true).await
        }
        .await;
        match result {
            Ok(server) => *self.server.lock().await = Some(server),
            Err(e) => tracing::error!(
                error = format!("{e:#}"),
                "could not reopen the bootstrap listeners; nothing listens until a restart"
            ),
        }
    }

    /// Denies everything at once. `valid_until` moves into the past and
    /// the secret map is emptied on the running server; neither needs a
    /// rebuild, so neither can fail. Expiry is checked before the addons
    /// and rules, so nothing of the policy runs again and `/readyz`
    /// reports the policy expired, until a restart.
    async fn revoke_lease(&self) {
        let mut run = self.running.lock().await;
        let expired = Utc::now() - chrono::Duration::seconds(1);
        if let Some(server) = self.server.lock().await.as_ref() {
            let handle = server.handle();
            handle.extend_valid_until(expired);
            handle.swap_secrets(HashMap::new());
        }
        run.revoked = true;
        run.secrets.clear();
        run.valid_until = Some(expired);
        self.summarise(&run);
    }

    /// For tests: the running server's addresses.
    pub async fn local_addrs(&self) -> Vec<(String, SocketAddr)> {
        self.server
            .lock()
            .await
            .as_ref()
            .map(|s| s.local_addrs().to_vec())
            .unwrap_or_default()
    }

    pub async fn ca_server_addr(&self) -> Option<SocketAddr> {
        self.server
            .lock()
            .await
            .as_ref()
            .and_then(Server::ca_server_addr)
    }

    /// The running server's handle, if any.
    pub async fn handle(&self) -> Option<roxy_proxy::ServerHandle> {
        self.server.lock().await.as_ref().map(Server::handle)
    }
}

impl LeaseHandler for NodeHandler {
    fn apply<'a>(
        &'a self,
        lease: &'a Lease,
        fetched_at: DateTime<Utc>,
        change: Change,
    ) -> HandlerFuture<'a, Result<(), String>> {
        Box::pin(self.apply_lease(lease, fetched_at, change))
    }

    fn revoke(&self) -> HandlerFuture<'_, ()> {
        Box::pin(self.revoke_lease())
    }

    fn policy_state(&self) -> PolicyState {
        let (leased, revoked, valid_until) = *lock(&self.state_summary);
        if revoked || valid_until.is_some_and(|u| u <= Utc::now()) {
            PolicyState::Expired
        } else if leased {
            PolicyState::Loaded
        } else {
            PolicyState::None
        }
    }
}

/// `sha256:` fingerprint of a CA certificate.
fn fingerprint(ca: &Ca) -> String {
    sha256_hex(&ca.cert_der())
}

/// Puts the interception CA in place before the server starts. The state
/// dir is authoritative: a pair given on the command line is imported only
/// when the state dir holds none, or replaces it only when asked to.
fn prepare_interception_ca(
    state_dir: &StateDir,
    provided: Option<(&Path, &Path)>,
    replace: bool,
) -> anyhow::Result<()> {
    let dir = state_dir.ca_dir();
    let stored = match Ca::load(&dir) {
        Ok(ca) => Some(ca),
        Err(CaError::NotFound(_)) => None,
        Err(e) => return Err(e).context("interception CA in the state dir"),
    };
    let Some((cert, key)) = provided else {
        return Ok(());
    };
    let given =
        Ca::load_provided(cert, key).context("--interception-ca-cert/--interception-ca-key")?;
    match stored {
        None => import_ca(&dir, cert, key),
        Some(stored) if stored.cert_der() == given.cert_der() => Ok(()),
        Some(stored) if replace => {
            tracing::warn!(
                stored = %fingerprint(&stored),
                replacement = %fingerprint(&given),
                "replacing the interception CA; workloads trusting the old one break"
            );
            for name in [CA_CERT_FILE, CA_KEY_FILE] {
                std::fs::remove_file(dir.join(name))
                    .with_context(|| format!("removing {}", dir.join(name).display()))?;
            }
            import_ca(&dir, cert, key)
        }
        Some(stored) => bail!(
            "the state dir already holds an interception CA ({}) and the flags name a different one ({}); \
             workloads trust the stored CA. Remove {} and {} from {} or pass --replace-interception-ca",
            fingerprint(&stored),
            fingerprint(&given),
            CA_CERT_FILE,
            CA_KEY_FILE,
            dir.display()
        ),
    }
}

/// Copies a validated CA pair into `dir` (key 0600).
fn import_ca(dir: &Path, cert: &Path, key: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let write = |name: &str, from: &Path, mode: u32| -> anyhow::Result<()> {
        use std::io::Write as _;
        let bytes = std::fs::read(from).with_context(|| format!("reading {}", from.display()))?;
        let to = dir.join(name);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(mode);
        }
        #[cfg(not(unix))]
        let _ = mode;
        let mut f = opts
            .open(&to)
            .with_context(|| format!("writing {}", to.display()))?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        Ok(())
    };
    write(CA_KEY_FILE, key, 0o600)?;
    write(CA_CERT_FILE, cert, 0o644)?;
    Ca::load(dir).context("imported interception CA")?;
    tracing::info!(dir = %dir.display(), "imported the interception CA into the state dir");
    Ok(())
}

fn bootstrap_config(bootstrap: &Bootstrap, state_dir: &StateDir) -> anyhow::Result<Config> {
    let ca_server = bootstrap
        .ca_server_bind
        .map(|b| format!("ca_server: {{ bind: \"{b}\" }}\n"))
        .unwrap_or_default();
    let yaml = format!(
        "version: 1\nlisteners: [{{ name: proxy, bind: \"{}\" }}]\n{ca_server}tls: {{ ca_dir: {:?} }}\nrules: []\n",
        bootstrap.proxy_bind,
        state_dir.ca_dir().display().to_string(),
    );
    Config::from_yaml(&yaml).context("bootstrap config")
}

/// A node: the server behind its handler, and the node task.
pub struct NodeRunning {
    pub handler: Arc<NodeHandler>,
    pub node: Arc<Node>,
    task: tokio::task::JoinHandle<Result<(), NodeError>>,
}

impl std::fmt::Debug for NodeRunning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeRunning").finish_non_exhaustive()
    }
}

impl NodeRunning {
    /// Reopens file log destinations (`SIGHUP`).
    pub async fn reopen_logs(&self) {
        if let Some(h) = self.handler.handle().await {
            h.sink().reopen();
            if let Some(c) = h.capture() {
                c.reopen();
            }
        }
    }

    /// Stops the node task, shuts the server down (in-flight exchanges get
    /// `grace`, and their flow events are spooled) and then drains the
    /// spool within [`DRAIN_GRACE`].
    pub async fn shutdown(self, grace: Duration) {
        self.task.abort();
        let _ = self.task.await;
        let server = self.handler.server.lock().await.take();
        if let Some(server) = server {
            let sink = server.handle().sink();
            let capture = server.handle().capture();
            server.shutdown(grace).await;
            self.node.drain(DRAIN_GRACE).await;
            let _ = tokio::task::spawn_blocking(move || {
                sink.flush();
                if let Some(c) = capture {
                    c.flush();
                }
            })
            .await;
        }
    }
}

/// Starts node mode: the bootstrap listeners first, then the node task,
/// which enrols (or loads the identity) and fetches leases.
pub async fn start(opts: NodeOptions) -> anyhow::Result<NodeRunning> {
    roxy_tls::install_crypto_provider();
    let state_dir = StateDir::open(&opts.state_dir)?;
    prepare_interception_ca(
        &state_dir,
        opts.interception_ca
            .as_ref()
            .map(|(c, k)| (c.as_path(), k.as_path())),
        opts.replace_interception_ca,
    )?;
    let trust: Trust = roxy_node::node::read_trust(opts.control_plane_ca.as_deref())?;
    let config = bootstrap_config(&opts.bootstrap, &state_dir)?;
    let compiled = config
        .validate()
        .map_err(|d| anyhow!("bootstrap config: {d:?}"))?;
    let handler = Arc::new(NodeHandler {
        state_dir: state_dir.clone(),
        spool: OnceLock::new(),
        local_sink: opts.local_sink,
        addons: Arc::new(AddonLoader::default()),
        metrics: Arc::new(ReloadableMetrics::new(
            &compiled.policy,
            config.limits.metric_limits(),
        )),
        state: Mutex::new(Arc::new(BuiltinState::new(config.limits.max_state_entries))),
        server: tokio::sync::Mutex::new(None),
        running: tokio::sync::Mutex::new(RunningPolicy {
            config: config.clone(),
            policy: compiled.policy.clone(),
            secrets: HashMap::new(),
            valid_until: None,
            leased: false,
            revoked: false,
        }),
        state_summary: Mutex::new((false, false, None)),
    });
    let node = Node::new(
        NodeConfig {
            control_plane: opts.control_plane,
            trust,
            state_dir: opts.state_dir,
            enrol_token_file: opts.enrol_token_file,
            info: NodeInfo {
                roxy_version: env!("CARGO_PKG_VERSION").to_owned(),
            },
            time_scale: opts.time_scale,
        },
        handler.clone(),
    )?;
    let _ = handler.spool.set(node.spool().clone());
    let update = policy_update_with_secrets(&config, compiled.policy, HashMap::new())?;
    let server = handler.start_server(&config, update, true).await?;
    *handler.server.lock().await = Some(server);
    tracing::info!(
        state_dir = %state_dir.path().display(),
        "node mode: listeners open and denying everything until the first lease"
    );
    let n = node.clone();
    let task = tokio::spawn(async move {
        let result = n.run().await;
        if let Err(e) = &result {
            tracing::error!(error = %e, "node cannot proceed; denying everything until a restart");
        }
        result
    });
    Ok(NodeRunning {
        handler,
        node,
        task,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxy_node::protocol::{FlowSettings, OnHighWater};
    use roxy_proxy::MemorySink;

    fn generated(dir: &Path) -> (PathBuf, PathBuf, String) {
        let ca = Ca::generate(dir).unwrap();
        (
            dir.join(CA_CERT_FILE),
            dir.join(CA_KEY_FILE),
            fingerprint(&ca),
        )
    }

    /// Importing a CA pair once makes the state dir authoritative: a later
    /// start without the flags keeps it, flags naming another pair refuse
    /// to start, and `--replace-interception-ca` swaps it.
    #[test]
    fn the_state_dir_is_authoritative_for_the_interception_ca() {
        let dir = tempfile::tempdir().unwrap();
        let state = StateDir::open(&dir.path().join("state")).unwrap();
        let (cert_a, key_a, fp_a) = generated(&dir.path().join("a"));
        let (cert_b, key_b, fp_b) = generated(&dir.path().join("b"));

        prepare_interception_ca(&state, Some((&cert_a, &key_a)), false).unwrap();
        let stored = Ca::load(&state.ca_dir()).unwrap();
        assert_eq!(fingerprint(&stored), fp_a);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(state.ca_dir().join(CA_KEY_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        // Without flags the stored pair stays; with the same pair too.
        prepare_interception_ca(&state, None, false).unwrap();
        prepare_interception_ca(&state, Some((&cert_a, &key_a)), false).unwrap();
        assert_eq!(fingerprint(&Ca::load(&state.ca_dir()).unwrap()), fp_a);

        let err = prepare_interception_ca(&state, Some((&cert_b, &key_b)), false)
            .unwrap_err()
            .to_string();
        assert!(err.contains(&fp_a) && err.contains(&fp_b), "{err}");
        assert!(err.contains("--replace-interception-ca"), "{err}");
        assert_eq!(fingerprint(&Ca::load(&state.ca_dir()).unwrap()), fp_a);

        prepare_interception_ca(&state, Some((&cert_b, &key_b)), true).unwrap();
        assert_eq!(fingerprint(&Ca::load(&state.ca_dir()).unwrap()), fp_b);

        // A corrupt stored pair is fatal, flags or not.
        std::fs::write(state.ca_dir().join(CA_KEY_FILE), "garbage").unwrap();
        assert!(prepare_interception_ca(&state, None, false).is_err());
        assert!(prepare_interception_ca(&state, Some((&cert_b, &key_b)), true).is_err());
    }

    /// The lease's `tls` cannot point the node at another CA.
    #[test]
    fn lease_configs_use_the_state_dir_ca() {
        let dir = tempfile::tempdir().unwrap();
        let state = StateDir::open(dir.path()).unwrap();
        let c = parse_lease_config("version: 1\n", &state).unwrap();
        assert_eq!(c.tls.ca_dir, state.ca_dir());
        let c = parse_lease_config(
            "version: 1\ntls: { ca_dir: /elsewhere, ca_cert: /x.pem, ca_key: /x.key }\n",
            &state,
        )
        .unwrap();
        assert_eq!(c.tls.ca_dir, state.ca_dir());
        assert_eq!((c.tls.ca_cert, c.tls.ca_key), (None, None));
        assert!(parse_lease_config("version: 1\nrules: 3\n", &state).is_err());
    }

    /// Every declared secret must have a value, from a source or the lease.
    #[test]
    fn declared_secrets_without_a_value_refuse_the_lease() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("t"), "from-file\n").unwrap();
        let config = Config::from_yaml(&format!(
            "version: 1\nsecrets:\n  a: {{ file: {} }}\n",
            dir.path().join("t").display()
        ))
        .unwrap();
        let mut lease = roxy_node::protocol::Lease {
            lease_id: "L".into(),
            valid_for_seconds: 1,
            refresh_after_seconds: 1,
            config: String::new(),
            secrets: BTreeMap::new(),
            state_epoch: "e".into(),
            flow: FlowSettings {
                ship: false,
                batch_max_bytes: 1,
                flush_interval_seconds: 1,
                spool_high_water_bytes: 1,
                on_high_water: OnHighWater::Spool,
            },
            interception_ca: None,
        };
        let map = resolve_secrets(&config, &lease).unwrap();
        assert_eq!(map["a"], "from-file");

        let config = Config::from_yaml(&format!(
            "version: 1\nsecrets:\n  a: {{ file: {} }}\n  b: {{ env: ROXY_NODE_TEST_UNSET }}\n",
            dir.path().join("t").display()
        ))
        .unwrap();
        lease.secrets.insert("b".into(), "ignored".into());
        let err = resolve_secrets(&config, &lease).unwrap_err();
        assert!(err.contains("ROXY_NODE_TEST_UNSET"), "{err}");

        let config = Config::from_yaml(
            "version: 1\nsecrets:\n  from_lease: { lease: true }\n  other: { lease: true }\n",
        )
        .unwrap();
        lease.secrets.clear();
        lease.secrets.insert("from_lease".into(), "v1".into());
        let err = resolve_secrets(&config, &lease).unwrap_err();
        assert!(
            err.contains("other") && !err.contains("from_lease"),
            "{err}"
        );
        lease.secrets.insert("other".into(), "v2".into());
        let map = resolve_secrets(&config, &lease).unwrap();
        assert_eq!(
            (map["from_lease"].as_str(), map["other"].as_str()),
            ("v1", "v2")
        );
    }

    /// The node sink holds traffic exactly when the spool does: `hold`
    /// mode at the high water, released by an ack.
    #[test]
    fn the_ship_sink_applies_the_spools_backpressure() {
        let spool = Arc::new(Spool::new(0, Box::new(|_| Ok(()))));
        spool.configure(FlowSettings {
            ship: true,
            batch_max_bytes: 1 << 20,
            flush_interval_seconds: 1,
            spool_high_water_bytes: 200,
            on_high_water: OnHighWater::Hold,
        });
        let local = Arc::new(MemorySink::new());
        let sink = ShipSink {
            local: local.clone(),
            spool: spool.clone(),
        };
        let ready = |s: &ShipSink| {
            let mut cx = Context::from_waker(std::task::Waker::noop());
            s.poll_ready(&mut cx).is_ready()
        };
        let event = FlowEvent::ConfigReloaded {
            ts: Utc::now(),
            path: PathBuf::from("/etc/roxy/roxy.yaml"),
            rules: 3,
        };
        assert!(ready(&sink));
        while spool.pending_bytes() < 200 {
            sink.emit(&event);
        }
        assert!(!ready(&sink), "held at the high water");
        assert_eq!(
            local.events().len(),
            spool.pending_events(),
            "the local log gets every event"
        );
        let batch = spool.batch(1 << 20).unwrap();
        assert_eq!(batch.seq_first, 0);
        assert!(batch.lines[0].starts_with(b"{\"seq\":0,\"event\":\"config_reloaded\""));
        spool.ack(batch.seq_last);
        assert!(ready(&sink));
    }
}
