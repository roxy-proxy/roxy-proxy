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
    RuntimeConfig, Server, ServerHandle, StateSource, StdoutSink,
};
use roxy_rules::Policy;
use roxy_tls::{Ca, LeafMinter};
use tokio::task::JoinSet;

use crate::addons::{AddonLoader, PreparedAddons};
use crate::config::{Compiled, Config, Listener, ListenerMode, Startup};
use crate::secrets::Secrets;
use crate::stores::ReloadableMetrics;

/// Debounce for config file events.
const RELOAD_DEBOUNCE: Duration = Duration::from_millis(200);

/// Loads and validates a config; diagnostics as `path:diagnostic` lines.
pub fn load_checked(path: &Path) -> Result<(Config, Compiled), Vec<String>> {
    let config = Config::load(path).map_err(|e| vec![format!("{e:#}")])?;
    let compiled = validate_at(&config, path)?;
    Ok((config, compiled))
}

fn validate_at(config: &Config, path: &Path) -> Result<Compiled, Vec<String>> {
    config.validate().map_err(|diags| {
        diags
            .iter()
            .map(|d| format!("{}:{d}", path.display()))
            .collect()
    })
}

/// Everything a reload may change, resolved (secrets, address lists). Any
/// address list that fails to load fails the whole update.
pub fn policy_update(config: &Config, policy: Policy) -> anyhow::Result<PolicyUpdate> {
    let secrets = Secrets::resolve(&config.secrets)?;
    let secret_map = config
        .secrets
        .keys()
        .filter_map(|k| secrets.get(k).map(|v| (k.clone(), v.expose().to_owned())));
    policy_update_with_secrets(config, policy, secret_map)
}

/// [`policy_update`] with the secret values already resolved, for a loader
/// that supplies them itself (node mode).
pub fn policy_update_with_secrets(
    config: &Config,
    policy: Policy,
    secrets: impl IntoIterator<Item = (String, String)>,
) -> anyhow::Result<PolicyUpdate> {
    let secret_map: HashMap<String, String> = secrets.into_iter().collect();
    let mut redactor = Redactor::new();
    for header in &config.log.redact_headers {
        redactor.add_header(header);
    }
    let address_lists = crate::lists::load_all(config)
        .map_err(|errs| anyhow!("address lists failed to load: {}", errs.join("; ")))?;
    for (name, list) in &address_lists {
        tracing::info!(list = %name, entries = list.len(), "address list loaded");
    }
    Ok(PolicyUpdate {
        policy,
        valid_until: config.valid_until,
        secrets: secret_map,
        redactor,
        limits: config.into(),
        flags: config.into(),
        http: config.into(),
        upstream: config.into(),
        address_lists: Arc::new(address_lists),
        deny_lists: config.upstream.deny_lists.clone(),
        // Loaded separately (async): see `AddonLoader`.
        addons: Vec::new(),
    })
}

/// Loads the CA on disk: the provided one (`tls.ca_cert` / `tls.ca_key`),
/// else the one in `tls.ca_dir`; `None` when that directory holds none yet.
/// Both `roxy check` and startup load through here, so a CA `check` passes
/// is one startup accepts, with the same [`Ca::warnings`] for each to
/// report. Errors name the field.
pub fn load_existing_ca(startup: &Startup) -> anyhow::Result<Option<Ca>> {
    if let Some((cert, key)) = startup.provided_ca().context("tls.ca_cert")? {
        return Ca::load_provided(cert, key)
            .map(Some)
            .context("tls.ca_cert");
    }
    match Ca::load(&startup.ca_dir) {
        Err(roxy_tls::CaError::NotFound(_)) => Ok(None),
        loaded => loaded.map(Some).context("tls.ca_dir"),
    }
}

/// The CA startup runs with: [`load_existing_ca`], or a new one generated
/// in `tls.ca_dir` on first start. Its warnings go to the log.
pub fn load_ca(startup: &Startup) -> anyhow::Result<Ca> {
    let ca = if let Some(ca) = load_existing_ca(startup)? {
        ca
    } else {
        let ca = Ca::generate(&startup.ca_dir)?;
        tracing::info!(dir = %startup.ca_dir.display(), "generated new roxy CA");
        ca
    };
    for warning in ca.warnings() {
        tracing::warn!("{warning}");
    }
    Ok(ca)
}

/// The flow sink configured by `log.flow`.
pub fn build_sink(startup: &Startup) -> anyhow::Result<Arc<dyn FlowSink>> {
    let f = &startup.flow;
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

/// The capture log under `capture_dir`, if set.
pub fn build_capture(startup: &Startup) -> anyhow::Result<Option<Arc<CaptureLog>>> {
    let Some(dir) = &startup.capture_dir else {
        return Ok(None);
    };
    let c = &startup.capture;
    let opts = roxy_proxy::CaptureOptions {
        max_body_bytes: startup.max_capture_body_bytes.as_u64(),
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

/// Reloads the config from disk into a running server.
pub struct Reloader {
    path: PathBuf,
    handle: ServerHandle,
    /// The running config. Held for the whole of a reload, so reloads
    /// (watcher and `SIGHUP`) never interleave.
    last: tokio::sync::Mutex<Config>,
    /// The built-in metric store, rebuilt (with carry-over) on each reload.
    /// `None` when the caller supplied its own `MetricSource`.
    metrics: Option<Arc<ReloadableMetrics>>,
    /// The file watcher, told about the current list and addon files on
    /// every reload attempt.
    watch: OnceLock<Arc<Watch>>,
    /// Compiles addons, keeping unchanged ones across reloads.
    addons: Arc<AddonLoader>,
}

impl std::fmt::Debug for Reloader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reloader")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

fn listener_specs(listeners: &[Listener]) -> anyhow::Result<Vec<ListenerSpec>> {
    listeners
        .iter()
        .map(|l| {
            let mode = match l.mode {
                ListenerMode::HttpProxy => roxy_proxy::ListenerMode::HttpProxy,
                ListenerMode::Http => roxy_proxy::ListenerMode::Http,
                ListenerMode::Transparent => {
                    anyhow::bail!("listener {:?}: there are no transparent listeners", l.name)
                }
            };
            Ok(ListenerSpec {
                name: l.name.clone(),
                mode,
                bind: l.bind,
            })
        })
        .collect()
}

/// What startup opens before the server starts: the resources the config
/// names rather than the settings it holds.
pub struct Opened {
    pub ca: Arc<Ca>,
    pub sink: Arc<dyn FlowSink>,
    pub metrics: Arc<dyn MetricSource>,
    pub state: Arc<dyn StateSource>,
}

/// The server's fixed configuration: the restart-only settings, read from
/// `startup` and nowhere else, plus what startup opened. `policy` is the
/// reloadable part.
pub fn runtime_config(
    startup: &Startup,
    opened: Opened,
    policy: PolicyUpdate,
    placeholder_policy: bool,
) -> anyhow::Result<RuntimeConfig> {
    let minter = Arc::new(LeafMinter::new(opened.ca.clone(), startup.leaf_cache_size)?);
    Ok(RuntimeConfig {
        placeholder_policy,
        listeners: listener_specs(&startup.listeners)?,
        ca_server: startup.ca_server.as_ref().map(|c| c.bind),
        ca: opened.ca,
        minter,
        upstream_tls: startup.into(),
        dns: startup.into(),
        max_connections: startup.max_connections,
        max_connections_per_client: startup.per_client_cap(),
        connection_events: startup.flow.connection_events,
        ws_message_every: startup.flow.ws_message_every,
        sink: opened.sink,
        capture: build_capture(startup)?,
        metrics: opened.metrics,
        state: opened.state,
        policy,
    })
}

/// Puts the running restart-only values into `config` and validates the
/// result. A failure is then reported against the config as validated: when
/// the file changed a restart-only setting, the diagnostics say which, so
/// a file that adds `capture` together with `capture_dir` is told that
/// `capture_dir` needs a restart rather than that it is missing.
fn validate_reload(
    running: &Config,
    config: &mut Config,
    path: &Path,
) -> Result<(Compiled, Vec<&'static str>), Vec<String>> {
    let restart = config.keep_startup(&running.startup());
    let compiled = validate_at(config, path).map_err(|mut diagnostics| {
        if !restart.is_empty() {
            diagnostics.push(format!(
                "{}: validated with the running value of {}; changing it needs a restart",
                path.display(),
                restart.join(", ")
            ));
        }
        diagnostics
    })?;
    Ok((compiled, restart))
}

/// What a reload has ready before anything is swapped.
struct Staged {
    config: Config,
    update: PolicyUpdate,
    addons: PreparedAddons,
    /// Restart-only settings the file changed; the running values are kept.
    restart: Vec<&'static str>,
}

impl Reloader {
    /// Loads, validates, compiles and swaps. On any failure the running
    /// snapshot stays and `config_reload_failed` is emitted.
    pub async fn reload(self: &Arc<Self>) -> bool {
        let sink = self.handle.sink();
        let mut last = self.last.lock().await;
        let result = self.stage(&last).await.and_then(|s| self.swap(s));
        match result {
            Ok((config, restart)) => {
                for field in restart {
                    tracing::warn!(
                        field,
                        "config change requires a restart; the running value is kept until then"
                    );
                }
                tracing::info!(path = %self.path.display(), rules = config.rules.len(), "config reloaded");
                sink.emit(&FlowEvent::ConfigReloaded {
                    ts: chrono::Utc::now(),
                    path: self.path.clone(),
                    rules: config.rules.len(),
                });
                if let Some(w) = self.watch.get() {
                    w.track(&self.path, &watched_files(&config));
                }
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

    /// Everything before the swap: the file reads and compilation on the
    /// blocking pool, then the addons.
    async fn stage(self: &Arc<Self>, running: &Config) -> Result<Staged, Vec<String>> {
        let r = self.clone();
        let running = running.clone();
        let (config, compiled, restart) = tokio::task::spawn_blocking(move || r.load(&running))
            .await
            .map_err(|e| vec![format!("reload: {e}")])??;
        let mut update =
            policy_update(&config, compiled.policy).map_err(|e| vec![format!("{e:#}")])?;
        let addons = self
            .addons
            .prepare(&config, compiled.addon_conditions)
            .await
            .map_err(|e| vec![format!("{e:#}")])?;
        update.addons = addons.specs();
        Ok(Staged {
            config,
            update,
            addons,
            restart,
        })
    }

    fn load(&self, running: &Config) -> Result<(Config, Compiled, Vec<&'static str>), Vec<String>> {
        let mut config = Config::load(&self.path).map_err(|e| vec![format!("{e:#}")])?;
        // Track the new file's files even if this attempt fails, so fixing
        // (or creating) a broken one triggers the next reload, and the
        // running policy's, which stay in use until an attempt succeeds.
        if let Some(w) = self.watch.get() {
            let mut files = watched_files(running);
            files.extend(watched_files(&config));
            w.track(&self.path, &files);
        }
        let (compiled, restart) = validate_reload(running, &mut config, &self.path)?;
        Ok((config, compiled, restart))
    }

    /// The swap. The snapshot is built first, since that is the last step
    /// that can fail; from there everything is applied. The metric store
    /// is rebuilt around the policy swap: before it when the new policy
    /// keeps every running metric, so no flow on either side meets a
    /// metric its store does not know; otherwise right after, where only
    /// flows still finishing under the old policy can. The addon cache
    /// follows the swap.
    fn swap(&self, staged: Staged) -> Result<(Config, Vec<&'static str>), Vec<String>> {
        let Staged {
            config,
            update,
            addons,
            restart,
        } = staged;
        let limits = config.limits.metric_limits();
        let policy = update.policy.clone();
        let prepared = self.handle.prepare(update).map_err(|e| vec![e])?;
        let early = self
            .metrics
            .as_ref()
            .filter(|m| m.keeps_every_metric(&policy));
        if let Some(m) = early {
            m.install(&policy, limits);
        }
        self.handle.commit(prepared);
        if early.is_none()
            && let Some(m) = &self.metrics
        {
            m.install(&policy, limits);
        }
        self.addons.install(addons);
        Ok((config, restart))
    }
}

/// Every file the config names that a reload reads: address lists and
/// WASM addons.
fn watched_files(config: &Config) -> Vec<PathBuf> {
    let mut files = crate::lists::files(config);
    files.extend(crate::addons::files(config));
    files
}

/// Watches the config file, the address-list files and the addon files.
/// Directories are watched (editors replace files rather than writing
/// them in place) and events are filtered to the tracked files.
struct Watch {
    watcher: Mutex<RecommendedWatcher>,
    targets: Arc<Mutex<Targets>>,
    /// Directories already watched.
    dirs: Mutex<HashSet<PathBuf>>,
}

/// The tracked files by absolute path, each with the path it currently
/// resolves to through symlinks.
#[derive(Default)]
struct Targets {
    files: HashMap<PathBuf, Option<PathBuf>>,
}

impl Targets {
    fn new(files: impl IntoIterator<Item = PathBuf>) -> Self {
        Self {
            files: files
                .into_iter()
                .map(|f| (absolute(&f), resolve(&f)))
                .collect(),
        }
    }

    /// Whether an event for `paths` touches a tracked file: by its own
    /// path, by the path it resolves to, or by changing what it resolves
    /// to (a symlink swapped underneath it, as Kubernetes does for a
    /// mounted `ConfigMap`).
    fn hit(&mut self, paths: &[PathBuf]) -> bool {
        let mut hit = false;
        for (file, resolved) in &mut self.files {
            let now = resolve(file);
            if now != *resolved || paths.iter().any(|p| p == file || Some(p) == now.as_ref()) {
                *resolved = now;
                hit = true;
            }
        }
        hit
    }

    /// The directories whose events matter: each file's, and the one its
    /// resolved path is in.
    fn dirs(&self) -> HashSet<PathBuf> {
        self.files
            .iter()
            .flat_map(|(f, r)| std::iter::once(f).chain(r.as_ref()))
            .map(|p| {
                p.parent()
                    .map_or_else(|| PathBuf::from("/"), Path::to_path_buf)
            })
            .collect()
    }
}

fn absolute(p: &Path) -> PathBuf {
    std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf())
}

/// Where `p` is right now, symlinks followed; `None` while it is missing.
fn resolve(p: &Path) -> Option<PathBuf> {
    std::fs::canonicalize(p).ok()
}

impl Watch {
    /// Tracks exactly `config` plus `files` from now on.
    fn track(&self, config: &Path, files: &[PathBuf]) {
        let targets =
            Targets::new(std::iter::once(config.to_path_buf()).chain(files.iter().cloned()));
        {
            let mut dirs = self.dirs.lock().unwrap_or_else(PoisonError::into_inner);
            let mut watcher = self.watcher.lock().unwrap_or_else(PoisonError::into_inner);
            for dir in targets.dirs() {
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
    let targets: Arc<Mutex<Targets>> = Arc::default();
    let t = targets.clone();
    let watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(ev) = res
            && !matches!(ev.kind, EventKind::Access(_))
            && t.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .hit(&ev.paths)
        {
            let _ = tx.try_send(());
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
    watch.track(path, &watched_files(config));
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
            reloader.reload().await;
        }
    });
    Ok(watch)
}

/// A started server plus its reload machinery.
pub struct Running {
    pub server: Server,
    pub reloader: Arc<Reloader>,
    watcher: Option<Arc<Watch>>,
    /// Reloads started by [`Running::reload_in_background`], every one of
    /// which shutdown abandons.
    reloads: Mutex<JoinSet<bool>>,
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

    /// Starts a reload (`SIGHUP`) without waiting for it. Reloads serialise
    /// on the [`Reloader`], so one started during another queues behind it;
    /// shutdown abandons every one still queued or running.
    pub fn reload_in_background(&self) {
        let mut reloads = self.reloads.lock().unwrap_or_else(PoisonError::into_inner);
        while reloads.try_join_next().is_some() {}
        let reloader = self.reloader.clone();
        reloads.spawn(async move { reloader.reload().await });
    }

    /// Graceful shutdown: abandon any reload in progress, stop accepting,
    /// drain for up to `grace`.
    pub async fn shutdown(self, grace: Duration) {
        drop(self.watcher);
        let mut reloads = self
            .reloads
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner);
        while reloads.try_join_next().is_some() {}
        if !reloads.is_empty() {
            tracing::warn!("shutting down during a config reload; the reload is abandoned");
            reloads.shutdown().await;
        }
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

/// Loads and validates `path`, resolves secrets, loads the CA and starts
/// the server.
pub async fn start(path: &Path, opts: StartOptions) -> anyhow::Result<Running> {
    roxy_tls::install_crypto_provider();
    let (config, compiled) =
        load_checked(path).map_err(|d| anyhow!("invalid config:\n{}", d.join("\n")))?;
    let mut update = policy_update(&config, compiled.policy)?;
    let addon_loader = Arc::new(AddonLoader::default());
    update.addons = addon_loader
        .load(&config, compiled.addon_conditions)
        .await?;
    let (metric_source, builtin_metrics): (Arc<dyn MetricSource>, Option<Arc<ReloadableMetrics>>) =
        if let Some(m) = opts.metrics {
            (m, None)
        } else {
            let b = Arc::new(ReloadableMetrics::new(
                &update.policy,
                config.limits.metric_limits(),
            ));
            (b.clone(), Some(b))
        };
    let startup = config.startup();
    let ca = Arc::new(load_ca(&startup)?);
    let sink = match opts.sink {
        Some(s) => s,
        None => build_sink(&startup)?,
    };
    sink.emit(&FlowEvent::ConfigLoaded {
        ts: chrono::Utc::now(),
        path: path.to_path_buf(),
        listeners: config.listeners.iter().map(|l| l.name.clone()).collect(),
        rules: config.rules.len(),
        metrics: config.metrics.len(),
        addons: config.addons.len(),
    });
    let state = opts
        .state
        .unwrap_or_else(|| Arc::new(crate::stores::BuiltinState::new(startup.max_state_entries)));
    let opened = Opened {
        ca,
        sink,
        metrics: metric_source,
        state,
    };
    let server = Server::start(runtime_config(&startup, opened, update, false)?).await?;
    let reloader = Arc::new(Reloader {
        path: path.to_path_buf(),
        handle: server.handle(),
        last: tokio::sync::Mutex::new(config.clone()),
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
        reloads: Mutex::new(JoinSet::new()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(yaml: &str) -> Config {
        Config::from_yaml(yaml).unwrap()
    }

    /// `run` uses a provided CA as is: a missing file is fatal, never a
    /// reason to fall back to `ca_dir`.
    #[test]
    fn load_ca_uses_the_provided_ca() {
        let dir = tempfile::tempdir().unwrap();
        let generated = Ca::generate(&dir.path().join("gen")).unwrap();
        let unused = dir.path().join("unused");
        let c = cfg(&format!(
            "version: 1\nlisteners: [{{ name: p, bind: 127.0.0.1:3128 }}]\n\
             tls: {{ ca_dir: {unused:?}, ca_cert: {:?}, ca_key: {:?} }}\n",
            generated.cert_path(),
            dir.path().join("gen").join(roxy_tls::CA_KEY_FILE),
        ));
        let c = c.startup();
        assert_eq!(load_ca(&c).unwrap().cert_der(), generated.cert_der());

        std::fs::remove_dir_all(dir.path().join("gen")).unwrap();
        assert!(load_ca(&c).is_err());
        assert!(!unused.exists());
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
        let sink = build_sink(&c.startup()).unwrap();
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

    /// A tracked path is hit by an event on it, on the file it resolves
    /// to, or on nothing it names at all when what it resolves to has
    /// changed: a ConfigMap-style swap renames `..data`, never the file.
    #[test]
    fn watch_targets_follow_symlink_swaps() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for (generation, text) in [("..v1", "a"), ("..v2", "b")] {
            std::fs::create_dir(root.join(generation)).unwrap();
            std::fs::write(root.join(generation).join("roxy.yaml"), text).unwrap();
        }
        std::os::unix::fs::symlink("..v1", root.join("..data")).unwrap();
        std::os::unix::fs::symlink("..data/roxy.yaml", root.join("roxy.yaml")).unwrap();
        let config = root.join("roxy.yaml");
        let mut t = Targets::new([config.clone()]);
        let v1 = root.canonicalize().unwrap().join("..v1").join("roxy.yaml");
        assert_eq!(t.files[&config], Some(v1.clone()));
        assert!(t.dirs().contains(v1.parent().unwrap()));

        assert!(!t.hit(&[root.join("other.yaml")]));
        assert!(t.hit(std::slice::from_ref(&config)), "the path itself");
        assert!(t.hit(&[v1]), "the file it resolves to");

        // The swap: a new generation, `..data` repointed, `roxy.yaml` untouched.
        std::fs::remove_file(root.join("..data")).unwrap();
        std::os::unix::fs::symlink("..v2", root.join("..data")).unwrap();
        assert!(t.hit(&[root.join("..data")]), "resolves elsewhere now");
        assert!(!t.hit(&[root.join("..data")]), "and is then up to date");

        // A missing file is tracked too, and its appearance is a hit.
        let list = root.join("list.txt");
        let mut t = Targets::new([list.clone()]);
        assert_eq!(t.files[&list], None);
        std::fs::write(&list, "10.0.0.0/8\n").unwrap();
        assert!(t.hit(&[root.join("unrelated")]));
    }

    /// The diagnostics for a reload that fails validation name the
    /// restart-only settings it changed, since the running values, not the
    /// file's, were validated.
    #[test]
    fn a_reload_that_needs_a_restart_says_so_when_validation_fails() {
        let base = "version: 1\nlisteners: [{ name: p, bind: 127.0.0.1:3128 }]\n";
        let running = cfg(base);
        let mut new = cfg(&format!(
            "{base}capture_dir: /tmp/c\nrules: [{{ id: c, then: [{{ capture: both }}, allow] }}]\n"
        ));
        let err = validate_reload(&running, &mut new, Path::new("roxy.yaml")).unwrap_err();
        assert!(
            err.iter().any(|d| d.contains("needs `capture_dir`")),
            "{err:?}"
        );
        assert!(
            err.iter()
                .any(|d| d.contains("capture_dir") && d.contains("needs a restart")),
            "{err:?}"
        );

        let mut new = cfg(&format!(
            "{base}rules: [{{ id: c, then: [{{ capture: both }}, allow] }}]\n"
        ));
        let err = validate_reload(&running, &mut new, Path::new("roxy.yaml")).unwrap_err();
        assert!(!err.iter().any(|d| d.contains("restart")), "{err:?}");
    }

    /// A reload that fails while building the snapshot leaves the metric
    /// store as it was: the running series under the running limits, even
    /// when the new policy keeps every metric and the store would otherwise
    /// have been rebuilt ahead of the swap.
    #[tokio::test(flavor = "multi_thread")]
    async fn failed_snapshot_build_leaves_the_metric_store_alone() {
        use roxy_proxy::{MemorySink, Sample};
        use roxy_rules::{Field, MapView};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("roxy.yaml");
        std::fs::write(
            &path,
            format!(
                "version: 1\nlisteners: [{{ name: p, bind: 127.0.0.1:0 }}]\n\
                 tls: {{ ca_dir: {:?} }}\n\
                 metrics: [{{ id: by_path, count: requests, key: [path], window: 1h }}]\n",
                dir.path().join("ca")
            ),
        )
        .unwrap();
        let running = start(
            &path,
            StartOptions {
                sink: Some(Arc::new(MemorySink::new())),
                ..StartOptions::default()
            },
        )
        .await
        .unwrap();
        let reloader = running.reloader.clone();
        let m = reloader.metrics.as_ref().unwrap();
        let view = |p: &str| MapView::new().with_str(Field::Path, p);
        let sample = Sample {
            head: true,
            ..Sample::default()
        };
        for p in ["/a", "/b", "/c"] {
            m.record(&view(p), &sample).unwrap();
        }

        let config = reloader.last.lock().await.clone();
        let mut staged = reloader.stage(&config).await.unwrap();
        assert!(m.keeps_every_metric(&staged.update.policy));
        // A budget no series fits, and a deny list the snapshot cannot
        // resolve: the store must not be rebuilt for a reload that fails.
        staged.config.limits.max_metric_bytes = bytesize::ByteSize::b(1);
        staged.update.deny_lists.push("ghost".into());
        let err = reloader.swap(staged).unwrap_err();
        assert!(err[0].contains("\"ghost\" is not loaded"), "{err:?}");

        for p in ["/a", "/b", "/c"] {
            assert_eq!(m.get("by_path", &view(p)), Ok(Some(1)), "{p}");
        }
        m.record(&view("/d"), &sample)
            .expect("the running byte budget still applies");
        assert_eq!(m.key_count(), 4);
        running.shutdown(Duration::ZERO).await;
    }

    /// Starts roxy on `yaml` (written to `roxy.yaml` in `dir`) with a
    /// memory sink.
    async fn start_in(
        dir: &Path,
        yaml: &str,
        watch: bool,
    ) -> (PathBuf, Running, Arc<roxy_proxy::MemorySink>) {
        let path = dir.join("roxy.yaml");
        std::fs::write(&path, yaml).unwrap();
        let sink = Arc::new(roxy_proxy::MemorySink::new());
        let running = start(
            &path,
            StartOptions {
                sink: Some(sink.clone()),
                watch,
                ..StartOptions::default()
            },
        )
        .await
        .unwrap();
        (path, running, sink)
    }

    fn events(sink: &roxy_proxy::MemorySink, kind: &str) -> Vec<serde_json::Value> {
        sink.events()
            .into_iter()
            .filter(|e| e["event"] == kind)
            .collect()
    }

    async fn wait_events(sink: &roxy_proxy::MemorySink, kind: &str, n: usize) {
        for _ in 0..200 {
            if events(sink, kind).len() >= n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("{n} {kind} events: {:?}", events(sink, kind));
    }

    /// A reload that fails validation keeps the running policy, so its
    /// address-list files stay watched: a later change to one still
    /// triggers a reload attempt.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_reload_keeps_watching_the_running_lists() {
        let dir = tempfile::tempdir().unwrap();
        let list = dir.path().join("blocked.txt");
        std::fs::write(&list, "192.0.2.0/24\n").unwrap();
        let base = format!(
            "version: 1\nlisteners: [{{ name: p, bind: 127.0.0.1:0 }}]\ntls: {{ ca_dir: {:?} }}\n",
            dir.path().join("ca")
        );
        let with_list = format!(
            "{base}address_lists: [{{ name: blocked, file: {list:?} }}]\n\
             rules: [{{ id: b, when: client.ip in @blocked, then: deny }}]\n"
        );
        let (path, running, sink) = start_in(dir.path(), &with_list, true).await;
        let watched = || {
            let w = running.reloader.watch.get().unwrap();
            let t = w.targets.lock().unwrap_or_else(PoisonError::into_inner);
            t.files.contains_key(&absolute(&list))
        };
        assert!(watched());

        // Drops the list and is invalid: the running policy stays.
        std::fs::write(
            &path,
            format!("{base}rules: [{{ id: b, when: client.ip in @blocked, then: deny }}]\n"),
        )
        .unwrap();
        wait_events(&sink, "config_reload_failed", 1).await;
        assert!(watched(), "the running policy's list file");

        std::fs::write(&list, "192.0.2.0/24\n198.51.100.0/24\n").unwrap();
        wait_events(&sink, "config_reload_failed", 2).await;
        running.shutdown(Duration::ZERO).await;
    }

    /// Every reload started by `SIGHUP` and still pending at shutdown is
    /// abandoned, including one queued behind another.
    #[tokio::test(flavor = "multi_thread")]
    async fn shutdown_abandons_every_queued_reload() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = format!(
            "version: 1\nlisteners: [{{ name: p, bind: 127.0.0.1:0 }}]\ntls: {{ ca_dir: {:?} }}\n",
            dir.path().join("ca")
        );
        let (_, running, sink) = start_in(dir.path(), &yaml, false).await;
        let reloader = running.reloader.clone();
        // Held across shutdown, so both reloads are still queued then.
        let held = reloader.last.lock().await;
        running.reload_in_background();
        running.reload_in_background();
        tokio::time::sleep(Duration::from_millis(50)).await;
        running.shutdown(Duration::ZERO).await;
        drop(held);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            events(&sink, "config_reloaded").is_empty(),
            "a reload ran after shutdown"
        );
    }
}
