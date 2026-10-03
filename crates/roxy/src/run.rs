//! `roxy run` wiring: config → [`RuntimeConfig`] / [`PolicyUpdate`],
//! startup refusals for features this build lacks, the reload path (file
//! watcher and `SIGHUP`), and [`start`] for the binary and the integration
//! tests.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use anyhow::{Context as _, anyhow};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher as _};
use roxy_proxy::{
    CaptureLog, FileSink, FlowEvent, FlowSink, ListenerSpec, MetricSource, PolicyUpdate, Redactor,
    RuntimeConfig, Server, ServerHandle, StateSource, StdoutSink, UserDb,
};
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
    /// A capture log was opened at startup (`capture_dir` was set then).
    pub capture: bool,
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
    let actions = || config.rules.iter().flat_map(|r| r.then.0.iter());
    if config.uses_capture() && !caps.capture {
        out.push(
            "capture needs `capture_dir` set when roxy starts (the capture log is opened at \
             startup; restart to enable it)"
                .into(),
        );
    }
    if actions().any(|a| matches!(a, Action::Call(_))) {
        out.push("the `call` action (addons) is not in this build".into());
    }
    if !caps.state_store && actions().any(|a| matches!(a, Action::SetState(_))) {
        out.push("`set_state` needs a state store, which is not in this build".into());
    }
    if config.compile_policy().is_ok_and(|p| p.reads_ws()) {
        out.push(
            "WebSocket message rules (`ws.*`) are not in this build (issue #14); byte \
             budgets on WebSockets work through `request_bytes` / `response_bytes` metrics"
                .into(),
        );
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

/// Everything a reload may change, resolved (secrets, users files, address
/// lists). Any address list that fails to load fails the whole update.
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
    let address_lists = crate::lists::load_all(config)
        .map_err(|errs| anyhow!("address lists failed to load: {}", errs.join("; ")))?;
    for (name, list) in &address_lists {
        tracing::info!(list = %name, entries = list.len(), "address list loaded");
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
        address_lists: Arc::new(address_lists),
        deny_lists: config.upstream.deny_lists.clone(),
        // Loaded separately (async): see `AddonLoader`.
        addons: Vec::new(),
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
    let f = &config.log.flow;
    let opts = roxy_proxy::logging::WriterOptions {
        high_water: usize::try_from(f.high_water.as_u64()).unwrap_or(usize::MAX),
        ..roxy_proxy::logging::WriterOptions::default()
    };
    Ok(match &f.path {
        Some(path) => {
            let rotate = roxy_proxy::logging::RotateOptions {
                max_file_bytes: f.max_file_bytes.map(|b| b.as_u64()),
                max_files: f.max_files,
                compress: f.compress,
            };
            Arc::new(
                FileSink::open_with(path, opts, rotate)
                    .with_context(|| format!("opening flow log {}", path.display()))?,
            )
        }
        None => Arc::new(StdoutSink::with_options(opts).context("starting the flow log writer")?),
    })
}

/// The capture log under `capture_dir`, if set (docs/flow-log.md#capture).
pub fn build_capture(config: &Config) -> anyhow::Result<Option<Arc<CaptureLog>>> {
    let Some(dir) = &config.capture_dir else {
        return Ok(None);
    };
    let c = &config.log.capture;
    let opts = roxy_proxy::CaptureOptions {
        max_body_bytes: config.limits.max_capture_body_bytes.as_u64(),
        all: c.all,
        writer: roxy_proxy::logging::WriterOptions {
            high_water: usize::try_from(c.high_water.as_u64()).unwrap_or(usize::MAX),
            ..roxy_proxy::logging::WriterOptions::default()
        },
        rotate: roxy_proxy::logging::RotateOptions {
            max_file_bytes: c.max_file_bytes.map(|b| b.as_u64()),
            max_files: c.max_files,
            compress: c.compress,
        },
    };
    let log = CaptureLog::open(dir, opts)
        .with_context(|| format!("opening the capture log in {}", dir.display()))?;
    tracing::info!(path = %log.path().display(), all = c.all, "capturing traffic");
    Ok(Some(Arc::new(log)))
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

/// Reloads the config from disk into a running server (docs/rules.md#reload).
pub struct Reloader {
    path: PathBuf,
    handle: ServerHandle,
    caps: Capabilities,
    last: Mutex<Config>,
    /// The built-in metric store, rebuilt (with carry-over) on each reload.
    /// `None` when the caller supplied its own `MetricSource`.
    metrics: Option<Arc<crate::stores::ReloadableMetrics>>,
    /// The file watcher, told about the current address list files on
    /// every reload attempt.
    watch: OnceLock<Arc<Watch>>,
    /// Compiles addons, keeping unchanged ones across reloads.
    addons: Arc<crate::addons::AddonLoader>,
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
    if d(&old.capture_dir, &new.capture_dir)
        || d(&old.log.capture, &new.log.capture)
        || old.limits.max_capture_body_bytes != new.limits.max_capture_body_bytes
    {
        out.push("capture_dir / log.capture / limits.max_capture_body_bytes");
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
            let config = Config::load(&self.path).map_err(|e| vec![format!("{e:#}")])?;
            // Track the list files even if this attempt fails, so fixing (or
            // creating) a broken list file triggers the next reload.
            if let Some(w) = self.watch.get() {
                w.track(&self.path, &crate::lists::files(&config));
            }
            config.validate().map_err(|diags| {
                diags
                    .iter()
                    .map(|d| format!("{}:{d}", self.path.display()))
                    .collect::<Vec<_>>()
            })?;
            let bad = unsupported(&config, self.caps);
            if !bad.is_empty() {
                return Err(bad);
            }
            let mut update = policy_update(&config).map_err(|e| vec![format!("{e:#}")])?;
            update.addons = self
                .addons
                .load_blocking(&config)
                .map_err(|e| vec![format!("{e:#}")])?;
            Ok((config, update))
        };
        let result = attempt().and_then(|(config, update)| {
            let next_metrics = self
                .metrics
                .as_ref()
                .map(|m| m.prepare(&update.policy, config.limits.metric_limits()));
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

/// Watches the config file and every address list file. Directories are
/// watched (editors replace files rather than writing them in place) and
/// events are filtered to the tracked files.
struct Watch {
    watcher: Mutex<RecommendedWatcher>,
    /// Absolute paths of the tracked files.
    targets: Arc<Mutex<HashSet<PathBuf>>>,
    /// Directories already watched.
    dirs: Mutex<HashSet<PathBuf>>,
}

fn absolute(p: &Path) -> PathBuf {
    std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf())
}

impl Watch {
    /// Tracks exactly `config` plus `lists` from now on.
    fn track(&self, config: &Path, lists: &[PathBuf]) {
        let targets: HashSet<PathBuf> = std::iter::once(config)
            .chain(lists.iter().map(PathBuf::as_path))
            .map(absolute)
            .collect();
        {
            let mut dirs = self.dirs.lock().unwrap_or_else(PoisonError::into_inner);
            let mut watcher = self.watcher.lock().unwrap_or_else(PoisonError::into_inner);
            for t in &targets {
                let dir = t
                    .parent()
                    .map_or_else(|| PathBuf::from("/"), Path::to_path_buf);
                if dirs.contains(&dir) {
                    continue;
                }
                match watcher.watch(&dir, RecursiveMode::NonRecursive) {
                    Ok(()) => {
                        dirs.insert(dir);
                    }
                    Err(e) => {
                        tracing::warn!(dir = %dir.display(), error = %e, "cannot watch directory; changes there need SIGHUP");
                    }
                }
            }
        }
        *self.targets.lock().unwrap_or_else(PoisonError::into_inner) = targets;
    }
}

/// Starts the watcher and reloads after a short debounce when any tracked
/// file changes.
fn spawn_watcher(
    path: &Path,
    config: &Config,
    reloader: Arc<Reloader>,
) -> anyhow::Result<Arc<Watch>> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(16);
    let targets: Arc<Mutex<HashSet<PathBuf>>> = Arc::default();
    let t = targets.clone();
    let watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(ev) = res
            && !matches!(ev.kind, EventKind::Access(_))
        {
            let targets = t.lock().unwrap_or_else(PoisonError::into_inner);
            if ev.paths.iter().any(|p| targets.contains(p)) {
                let _ = tx.try_send(());
            }
        }
    })
    .context("starting the config file watcher")?;
    let watch = Arc::new(Watch {
        watcher: Mutex::new(watcher),
        targets,
        dirs: Mutex::new(HashSet::new()),
    });
    let config_dir = absolute(path)
        .parent()
        .map_or_else(|| PathBuf::from("/"), Path::to_path_buf);
    watch.track(path, &crate::lists::files(config));
    if !watch
        .dirs
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .contains(&config_dir)
    {
        return Err(anyhow!("watching {}", config_dir.display()));
    }
    let _ = reloader.watch.set(watch.clone());
    tokio::spawn(async move {
        while rx.recv().await.is_some() {
            tokio::time::sleep(RELOAD_DEBOUNCE).await;
            while rx.try_recv().is_ok() {}
            reloader.reload_async().await;
        }
    });
    Ok(watch)
}

/// A started server plus its reload machinery.
pub struct Running {
    pub server: Server,
    pub reloader: Arc<Reloader>,
    watcher: Option<Arc<Watch>>,
}

impl std::fmt::Debug for Running {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Running")
            .field("server", &self.server)
            .finish_non_exhaustive()
    }
}

impl Running {
    /// Reopens file log destinations (after external rotation; `SIGHUP`).
    pub fn reopen_logs(&self) {
        let h = self.server.handle();
        h.sink().reopen();
        if let Some(c) = h.capture() {
            c.reopen();
        }
    }

    /// Graceful shutdown (docs/limits.md): stop accepting, drain for up to `grace`.
    pub async fn shutdown(self, grace: Duration) {
        drop(self.watcher);
        let sink = self.server.handle().sink();
        let capture = self.server.handle().capture();
        self.server.shutdown(grace).await;
        // Everything logged and captured so far reaches its destination
        // before exit.
        let _ = tokio::task::spawn_blocking(move || {
            sink.flush();
            if let Some(c) = capture {
                c.flush();
            }
        })
        .await;
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
        capture: config.capture_dir.is_some(),
    };
    let bad = unsupported(&config, caps);
    if !bad.is_empty() {
        return Err(anyhow!("cannot run this config: {}", bad.join("; ")));
    }
    let mut update = policy_update(&config)?;
    let addon_loader = Arc::new(crate::addons::AddonLoader::default());
    update.addons = addon_loader.load(&config).await?;
    let (metric_source, builtin_metrics): (
        Arc<dyn MetricSource>,
        Option<Arc<crate::stores::ReloadableMetrics>>,
    ) = if let Some(m) = opts.metrics {
        (m, None)
    } else {
        let b = Arc::new(crate::stores::ReloadableMetrics::new(
            &update.policy,
            config.limits.metric_limits(),
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
        capture: build_capture(&config)?,
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
        last: Mutex::new(config.clone()),
        metrics: builtin_metrics,
        watch: OnceLock::new(),
        addons: addon_loader,
    });
    let watcher = if opts.watch {
        Some(spawn_watcher(path, &config, reloader.clone())?)
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

    /// `log.flow` rotation settings reach the file sink: emitting past
    /// `max_file_bytes` rotates, and nothing is lost.
    #[test]
    fn flow_log_rotates_from_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("flow.jsonl");
        let c = cfg(&format!(
            "version: 1\nlisteners: [{{ name: p, bind: 127.0.0.1:3128 }}]\nlog:\n  flow:\n    \
             path: {}\n    max_file_bytes: 4kb\n    max_files: 100\n",
            path.display()
        ));
        c.validate().unwrap();
        let sink = build_sink(&c).unwrap();
        for i in 0..200 {
            sink.emit(&FlowEvent::ConfigLoaded {
                ts: chrono::Utc::now(),
                path: format!("/etc/roxy/{i}.yaml").into(),
                listeners: vec!["p".into()],
                rules: i,
                metrics: 0,
                addons: 0,
            });
            if i % 20 == 0 {
                sink.flush();
            }
        }
        sink.flush();
        let files: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert!(files.len() > 2, "rotated: {files:?}");
        let lines: usize = files
            .into_iter()
            .map(|e| {
                std::fs::read_to_string(e.unwrap().path())
                    .unwrap()
                    .lines()
                    .count()
            })
            .sum();
        assert_eq!(lines, 200);
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
rules:
  - id: effects
    then:
      - capture: request
      - call: scan
      - set_state: { key: k, value: v }
      - allow
");
        let bad = unsupported(&c, Capabilities::default()).join("\n");
        for needle in ["no metric store", "capture_dir", "`call`", "`set_state`"] {
            assert!(bad.contains(needle), "{needle}: {bad}");
        }
        let with_stores = unsupported(
            &c,
            Capabilities {
                metric_store: true,
                state_store: true,
                capture: true,
            },
        )
        .join("\n");
        assert!(!with_stores.contains("metric store"));
        assert!(!with_stores.contains("set_state"));
        assert!(!with_stores.contains("capture"));
    }

    #[test]
    fn websocket_message_rules_are_refused() {
        let c = cfg(
            "version: 1\nlisteners: [{ name: p, bind: 127.0.0.1:3128 }]\nrules:\n  - id: w\n    \
             when: ws.size > 1mb\n    then: deny\n",
        );
        let bad = unsupported(&c, Capabilities::default()).join("\n");
        assert!(bad.contains("`ws.*`"), "{bad}");
        // `roxy check` still accepts it.
        c.validate().unwrap();
    }

    #[test]
    fn address_lists_are_supported() {
        let c = cfg(
            "version: 1\naddress_lists: [{ name: b, inline: [1.2.3.4] }]\nupstream: { deny_lists: [b] }\n\
             rules: [{ id: r, when: 'client.ip in @b', then: deny }]\n",
        );
        assert_eq!(
            unsupported(&c, Capabilities::default()),
            Vec::<String>::new()
        );
    }
}
