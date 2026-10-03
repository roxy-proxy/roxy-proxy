//! `roxy run` wiring: config → [`RuntimeConfig`] / [`PolicyUpdate`],
//! startup refusals for features this build lacks, the reload path (file
//! watcher and `SIGHUP`), and [`start`] for the binary and the integration
//! tests.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::{Context as _, anyhow};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher as _};
use roxy_proxy::{
    FileSink, FlowEvent, FlowSink, ListenerSpec, MetricSource, PolicyUpdate, Redactor,
    RuntimeConfig, Server, ServerHandle, StateSource, StdoutSink, UserDb,
};
use roxy_rules::ast::{Expr as Ast, Lit, Node, Operand};
use roxy_tls::{Ca, CaError, LeafMinter};

use crate::config::{Action, Config};
use crate::secrets::Secrets;

/// Debounce for config file events.
const RELOAD_DEBOUNCE: Duration = Duration::from_millis(200);

/// Which optional stores the running build provides.
#[derive(Debug, Clone, Copy, Default)]
pub struct Capabilities {
    /// A real [`MetricSource`] is plugged in.
    pub metric_store: bool,
    /// A real [`StateSource`] is plugged in.
    pub state_store: bool,
}

fn node_uses_list(n: &Node) -> bool {
    fn operand(o: &Operand) -> bool {
        match o {
            Operand::Lit(l) => lit(&l.lit),
            Operand::Field(_) => false,
        }
    }
    fn lit(l: &Lit) -> bool {
        match l {
            Lit::AddressList(_) => true,
            Lit::List(items) => items.iter().any(|i| lit(&i.lit)),
            _ => false,
        }
    }
    match &n.expr {
        Ast::Or(a, b) | Ast::And(a, b) => node_uses_list(a) || node_uses_list(b),
        Ast::Not(a) => node_uses_list(a),
        Ast::Cmp { lhs, rhs, .. } => operand(lhs) || operand(rhs),
        Ast::Pred(o) => operand(o),
    }
}

fn expr_uses_list(e: Option<&crate::config::Expr>) -> bool {
    e.and_then(|e| roxy_rules::parse(e.as_str()).ok())
        .is_some_and(|n| node_uses_list(&n))
}

/// Features the config uses that this build cannot run. `roxy check`
/// accepts them; `roxy run` refuses to start (and a reload is rejected)
/// rather than run with every affected flow failing closed.
pub fn unsupported(config: &Config, caps: Capabilities) -> Vec<String> {
    let mut out = Vec::new();
    if !config.metrics.is_empty() && !caps.metric_store {
        out.push(format!(
            "this build has no metric store yet ({} metric(s) defined under `metrics`)",
            config.metrics.len()
        ));
    }
    let list_refs = config.rules.iter().any(|r| expr_uses_list(r.when.as_ref()))
        || config
            .metrics
            .iter()
            .any(|m| expr_uses_list(m.where_.as_ref()));
    if list_refs || !config.upstream.deny_lists.is_empty() {
        out.push(
            "address lists not in this build (`@list` references or `upstream.deny_lists`)".into(),
        );
    }
    let actions = || config.rules.iter().flat_map(|r| r.then.0.iter());
    if actions().any(|a| matches!(a, Action::Capture(_))) {
        out.push("the `capture` action is not in this build".into());
    }
    if actions().any(|a| matches!(a, Action::Call(_))) {
        out.push("the `call` action (addons) is not in this build".into());
    }
    if !caps.state_store && actions().any(|a| matches!(a, Action::SetState(_))) {
        out.push("`set_state` needs a state store, which is not in this build".into());
    }
    if !config.addons.is_empty() {
        out.push("WASM addons are not in this build (`addons`)".into());
    }
    out
}

/// Loads and validates a config; diagnostics as `path:diagnostic` lines.
pub fn load_checked(path: &Path) -> Result<Config, Vec<String>> {
    let config = Config::load(path).map_err(|e| vec![format!("{e:#}")])?;
    config.validate().map_err(|diags| {
        diags
            .iter()
            .map(|d| format!("{}:{d}", path.display()))
            .collect::<Vec<_>>()
    })?;
    Ok(config)
}

/// Everything a reload may change, resolved (secrets, users files).
pub fn policy_update(config: &Config) -> anyhow::Result<PolicyUpdate> {
    let policy = config.compile_policy().map_err(|diags| {
        anyhow!(
            "policy failed to compile: {}",
            diags
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        )
    })?;
    let secrets = Secrets::resolve(&config.secrets)?;
    let mut redactor = Redactor::new();
    for value in secrets.values() {
        redactor.add_secret(value.expose());
    }
    for header in &config.log.redact_headers {
        redactor.add_header(header);
    }
    let mut users = HashMap::new();
    for l in &config.listeners {
        if let Some(auth) = &l.auth {
            let db = UserDb::load(&auth.basic.users_file).map_err(|e| anyhow!(e))?;
            users.insert(l.name.clone(), Arc::new(db));
        }
    }
    let secret_map = config
        .secrets
        .keys()
        .filter_map(|k| secrets.get(k).map(|v| (k.clone(), v.expose().to_owned())))
        .collect();
    Ok(PolicyUpdate {
        policy,
        secrets: secret_map,
        redactor,
        users,
        limits: config.into(),
        flags: config.into(),
        upstream: config.into(),
    })
}

/// Loads the CA from `tls.ca_dir`, generating it on first start.
pub fn load_ca(config: &Config) -> anyhow::Result<Ca> {
    let dir = &config.tls.ca_dir;
    match Ca::load(dir) {
        Ok(ca) => Ok(ca),
        Err(CaError::NotFound(_)) => {
            let ca = Ca::generate(dir)?;
            tracing::info!(dir = %dir.display(), "generated new roxy CA");
            Ok(ca)
        }
        Err(e) => Err(e.into()),
    }
}

/// The flow sink configured by `log.flow`.
pub fn build_sink(config: &Config) -> anyhow::Result<Arc<dyn FlowSink>> {
    Ok(match &config.log.flow.path {
        Some(path) => Arc::new(
            FileSink::open(path).with_context(|| format!("opening flow log {}", path.display()))?,
        ),
        None => Arc::new(StdoutSink::new()),
    })
}

/// Optional overrides for [`start`].
#[derive(Default)]
pub struct StartOptions {
    /// Flow sink (default: from `log.flow`).
    pub sink: Option<Arc<dyn FlowSink>>,
    /// Metric store (default: none; policies with metrics are refused).
    pub metrics: Option<Arc<dyn MetricSource>>,
    /// State store (default: none; `set_state` is refused).
    pub state: Option<Arc<dyn StateSource>>,
    /// Watch the config file for changes.
    pub watch: bool,
}

/// Reloads the config from disk into a running server (§6.5).
pub struct Reloader {
    path: PathBuf,
    handle: ServerHandle,
    caps: Capabilities,
    last: Mutex<Config>,
    /// The built-in metric store, rebuilt (with carry-over) on each reload.
    /// `None` when the caller supplied its own `MetricSource`.
    metrics: Option<Arc<crate::stores::ReloadableMetrics>>,
}

impl std::fmt::Debug for Reloader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reloader")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

fn restart_required(old: &Config, new: &Config) -> Vec<&'static str> {
    let mut out = Vec::new();
    let d = |a: &dyn std::fmt::Debug, b: &dyn std::fmt::Debug| format!("{a:?}") != format!("{b:?}");
    if d(
        &old.listeners
            .iter()
            .map(|l| (&l.name, l.bind, l.auth.is_some()))
            .collect::<Vec<_>>(),
        &new.listeners
            .iter()
            .map(|l| (&l.name, l.bind, l.auth.is_some()))
            .collect::<Vec<_>>(),
    ) {
        out.push("listeners");
    }
    if d(&old.ca_server, &new.ca_server) {
        out.push("ca_server");
    }
    if d(&old.tls, &new.tls) {
        out.push("tls");
    }
    if old.http.enable_h2 != new.http.enable_h2 {
        out.push("http.enable_h2");
    }
    if old.limits.max_connections != new.limits.max_connections
        || old.limits.max_connections_per_client != new.limits.max_connections_per_client
    {
        out.push("limits.max_connections*");
    }
    if d(&old.log.flow, &new.log.flow) {
        out.push("log.flow");
    }
    out
}

impl Reloader {
    /// Loads, validates, compiles and swaps. On any failure the running
    /// snapshot stays and `config_reload_failed` is emitted. Blocking (file
    /// reads, bcrypt-free but synchronous); call from a blocking context.
    pub fn reload(&self) -> bool {
        let sink = self.handle.sink();
        let attempt = || -> Result<(Config, PolicyUpdate), Vec<String>> {
            let config = load_checked(&self.path)?;
            let bad = unsupported(&config, self.caps);
            if !bad.is_empty() {
                return Err(bad);
            }
            let update = policy_update(&config).map_err(|e| vec![format!("{e:#}")])?;
            Ok((config, update))
        };
        let result = attempt().and_then(|(config, update)| {
            let next_metrics = self
                .metrics
                .as_ref()
                .map(|m| m.prepare(&update.policy, config.limits.max_metric_keys));
            self.handle.reload(update).map_err(|e| vec![e])?;
            if let (Some(m), Some(next)) = (&self.metrics, next_metrics) {
                m.install(next);
            }
            Ok(config)
        });
        match result {
            Ok(config) => {
                let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
                for field in restart_required(&last, &config) {
                    tracing::warn!(
                        field,
                        "config change requires a restart; ignored until then"
                    );
                }
                tracing::info!(path = %self.path.display(), rules = config.rules.len(), "config reloaded");
                sink.emit(&FlowEvent::ConfigReloaded {
                    ts: chrono::Utc::now(),
                    path: self.path.clone(),
                    rules: config.rules.len(),
                });
                *last = config;
                true
            }
            Err(diagnostics) => {
                tracing::warn!(path = %self.path.display(), ?diagnostics, "config reload failed; keeping the running policy");
                sink.emit(&FlowEvent::ConfigReloadFailed {
                    ts: chrono::Utc::now(),
                    path: self.path.clone(),
                    diagnostics,
                });
                false
            }
        }
    }

    /// [`Reloader::reload`] on the blocking pool.
    pub async fn reload_async(self: &Arc<Self>) -> bool {
        let r = self.clone();
        tokio::task::spawn_blocking(move || r.reload())
            .await
            .unwrap_or(false)
    }
}

/// Watches the config file's directory (editors replace files rather than
/// writing them in place) and reloads after a short debounce.
fn spawn_watcher(path: &Path, reloader: Arc<Reloader>) -> anyhow::Result<RecommendedWatcher> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(16);
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("config path has no file name"))?
        .to_owned();
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(ev) = res
            && !matches!(ev.kind, EventKind::Access(_))
            && ev
                .paths
                .iter()
                .any(|p| p.file_name() == Some(file_name.as_os_str()))
        {
            let _ = tx.try_send(());
        }
    })
    .context("starting the config file watcher")?;
    watcher
        .watch(&dir, RecursiveMode::NonRecursive)
        .with_context(|| format!("watching {}", dir.display()))?;
    tokio::spawn(async move {
        while rx.recv().await.is_some() {
            tokio::time::sleep(RELOAD_DEBOUNCE).await;
            while rx.try_recv().is_ok() {}
            reloader.reload_async().await;
        }
    });
    Ok(watcher)
}

/// A started server plus its reload machinery.
pub struct Running {
    pub server: Server,
    pub reloader: Arc<Reloader>,
    watcher: Option<RecommendedWatcher>,
}

impl std::fmt::Debug for Running {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Running")
            .field("server", &self.server)
            .finish_non_exhaustive()
    }
}

impl Running {
    /// Graceful shutdown (§12): stop accepting, drain for up to `grace`.
    pub async fn shutdown(self, grace: Duration) {
        drop(self.watcher);
        self.server.shutdown(grace).await;
    }
}

/// Loads `path`, refuses unsupported features, resolves secrets, loads the
/// CA and starts the server.
pub async fn start(path: &Path, opts: StartOptions) -> anyhow::Result<Running> {
    roxy_tls::install_crypto_provider();
    let config = load_checked(path).map_err(|d| anyhow!("invalid config:\n{}", d.join("\n")))?;
    // The built-in stores are always available; callers (tests) may still
    // inject their own.
    let caps = Capabilities {
        metric_store: true,
        state_store: true,
    };
    let bad = unsupported(&config, caps);
    if !bad.is_empty() {
        return Err(anyhow!("cannot run this config: {}", bad.join("; ")));
    }
    let update = policy_update(&config)?;
    let (metric_source, builtin_metrics): (
        Arc<dyn MetricSource>,
        Option<Arc<crate::stores::ReloadableMetrics>>,
    ) = if let Some(m) = opts.metrics {
        (m, None)
    } else {
        let b = Arc::new(crate::stores::ReloadableMetrics::new(
            &update.policy,
            config.limits.max_metric_keys,
        ));
        (b.clone(), Some(b))
    };
    let ca = Arc::new(load_ca(&config)?);
    let minter = Arc::new(LeafMinter::new(ca.clone(), config.tls.leaf_cache_size)?);
    let sink = match opts.sink {
        Some(s) => s,
        None => build_sink(&config)?,
    };
    sink.emit(&FlowEvent::ConfigLoaded {
        ts: chrono::Utc::now(),
        path: path.to_path_buf(),
        listeners: config.listeners.iter().map(|l| l.name.clone()).collect(),
        rules: config.rules.len(),
        metrics: config.metrics.len(),
        addons: config.addons.len(),
    });
    let rt = RuntimeConfig {
        listeners: config
            .listeners
            .iter()
            .map(|l| ListenerSpec {
                name: l.name.clone(),
                bind: l.bind,
                auth_required: l.auth.is_some(),
            })
            .collect(),
        ca_server: config.ca_server.as_ref().map(|c| c.bind),
        ca,
        minter,
        require_sni_match: config.tls.require_sni_match,
        enable_h2: config.http.enable_h2,
        upstream_tls: (&config).into(),
        max_connections: config.limits.max_connections,
        max_connections_per_client: config.limits.max_connections_per_client,
        connection_events: config.log.flow.connection_events,
        sink,
        metrics: metric_source,
        state: opts.state.unwrap_or_else(|| {
            Arc::new(crate::stores::BuiltinState::new(
                config.limits.max_state_entries,
            ))
        }),
        policy: update,
    };
    let server = Server::start(rt).await?;
    let reloader = Arc::new(Reloader {
        path: path.to_path_buf(),
        handle: server.handle(),
        caps,
        last: Mutex::new(config),
        metrics: builtin_metrics,
    });
    let watcher = if opts.watch {
        Some(spawn_watcher(path, reloader.clone())?)
    } else {
        None
    };
    Ok(Running {
        server,
        reloader,
        watcher,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(yaml: &str) -> Config {
        Config::from_yaml(yaml).unwrap()
    }

    #[test]
    fn plain_policies_are_supported() {
        let c = cfg("version: 1\nrules:\n  - id: a\n    when: host == \"x\"\n    then: allow\n");
        assert_eq!(
            unsupported(&c, Capabilities::default()),
            Vec::<String>::new()
        );
    }

    #[test]
    fn refusals() {
        let c = cfg("
version: 1
metrics:
  - { id: m, count: requests }
address_lists:
  - { name: bad, inline: [10.0.0.0/8] }
rules:
  - id: lists
    when: client.ip in @bad
    then: deny
  - id: effects
    then:
      - capture: request
      - call: scan
      - set_state: { key: k, value: v }
      - allow
");
        let bad = unsupported(&c, Capabilities::default()).join("\n");
        for needle in [
            "no metric store",
            "address lists",
            "`capture`",
            "`call`",
            "`set_state`",
        ] {
            assert!(bad.contains(needle), "{needle}: {bad}");
        }
        let with_stores = unsupported(
            &c,
            Capabilities {
                metric_store: true,
                state_store: true,
            },
        )
        .join("\n");
        assert!(!with_stores.contains("metric store"));
        assert!(!with_stores.contains("set_state"));
        assert!(with_stores.contains("address lists"));
    }

    #[test]
    fn deny_lists_are_refused() {
        let c = cfg(
            "version: 1\naddress_lists: [{ name: b, inline: [1.2.3.4] }]\nupstream: { deny_lists: [b] }\n",
        );
        assert_eq!(unsupported(&c, Capabilities::default()).len(), 1);
    }
}
