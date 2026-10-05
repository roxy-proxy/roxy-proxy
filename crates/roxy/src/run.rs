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
    CaptureLog, DnsServerSpec, FileSink, FlowEvent, FlowSink, ListenerKind, ListenerSpec,
    MetricSource, PolicyUpdate, Redactor, RuntimeConfig, Server, ServerHandle, StateSource,
    StdoutSink, UserDb,
};
use roxy_rules::Policy;
use roxy_tls::{Ca, LeafMinter};

use crate::addons::{AddonLoader, PreparedAddons};
use crate::config::{Compiled, Config, ListenerMode};
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

/// Everything a reload may change, resolved (secrets, users files, address
/// lists). Any address list that fails to load fails the whole update.
pub fn policy_update(config: &Config, policy: Policy) -> anyhow::Result<PolicyUpdate> {
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

/// Loads the provided CA (`tls.ca_cert` / `tls.ca_key`), or else the CA in
/// `tls.ca_dir`, generating it there on first start.
pub fn load_ca(config: &Config) -> anyhow::Result<Ca> {
    if let Some((cert, key)) = config.tls.provided_ca()? {
        return Ok(Ca::load_provided(cert, key)?);
    }
    let dir = &config.tls.ca_dir;
    let existed = Ca::load(dir).is_ok();
    let ca = Ca::load_or_generate(dir)?;
    if !existed {
        tracing::info!(dir = %dir.display(), "generated new roxy CA");
    }
    Ok(ca)
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

/// The capture log under `capture_dir`, if set.
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

fn listener_specs(config: &Config) -> Vec<ListenerSpec> {
    config
        .listeners
        .iter()
        .map(|l| ListenerSpec {
            name: l.name.clone(),
            bind: l.bind,
            auth_required: l.auth.is_some(),
            kind: match l.mode {
                ListenerMode::Direct => ListenerKind::Direct {
                    target_port: l.target_port,
                },
                // Validation refuses transparent listeners.
                ListenerMode::Explicit | ListenerMode::Transparent => ListenerKind::Explicit,
            },
        })
        .collect()
}

fn dns_spec(dns: &crate::config::DnsListener, log_queries: bool) -> DnsServerSpec {
    DnsServerSpec {
        bind: dns.bind,
        ipv4: dns.answer.ipv4,
        ipv6: dns.answer.ipv6,
        // Validation caps it at u32::MAX.
        ttl: u32::try_from(dns.ttl.as_secs()).unwrap_or(u32::MAX),
        log_queries,
    }
}

/// Puts the running value of every setting that takes effect only at
/// startup (listeners and their auth, the CA server, the DNS listener, TLS,
/// HTTP/2, connection caps, the state store size, the flow and capture log
/// destinations) into `new`, and names each one that differed. The reload
/// then validates and applies `new` as a whole, so a restart-only change is
/// never half-applied (for example, a listener's `auth` removed while the
/// listener still requires it).
fn keep_restart_only(running: &Config, new: &mut Config) -> Vec<&'static str> {
    let mut changed = Vec::new();
    macro_rules! keep {
        ($name:literal, $($field:ident).+) => {
            if new.$($field).+ != running.$($field).+ {
                changed.push($name);
                new.$($field).+ = running.$($field).+.clone();
            }
        };
    }
    keep!("listeners", listeners);
    keep!("ca_server", ca_server);
    keep!("dns", dns);
    keep!("tls", tls);
    keep!("http.enable_h2", http.enable_h2);
    keep!("limits.max_connections", limits.max_connections);
    keep!(
        "limits.max_connections_per_client",
        limits.max_connections_per_client
    );
    keep!("limits.max_state_entries", limits.max_state_entries);
    keep!(
        "limits.max_capture_body_bytes",
        limits.max_capture_body_bytes
    );
    keep!("log.flow", log.flow);
    keep!("log.capture", log.capture);
    keep!("capture_dir", capture_dir);
    changed
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
        // Track the files even if this attempt fails, so fixing (or
        // creating) a broken one triggers the next reload.
        if let Some(w) = self.watch.get() {
            w.track(&self.path, &watched_files(&config));
        }
        let restart = keep_restart_only(running, &mut config);
        let compiled = validate_at(&config, &self.path)?;
        Ok((config, compiled, restart))
    }

    /// The swap. The metric store is rebuilt around it: before the policy
    /// swap when the new policy keeps every running metric, so no flow on
    /// either side meets a metric its store does not know; otherwise right
    /// after, where only flows still finishing under the old policy can.
    /// The addon cache follows a successful swap.
    fn swap(&self, staged: Staged) -> Result<(Config, Vec<&'static str>), Vec<String>> {
        let Staged {
            config,
            update,
            addons,
            restart,
        } = staged;
        let limits = config.limits.metric_limits();
        let policy = update.policy.clone();
        let early = self
            .metrics
            .as_ref()
            .filter(|m| m.keeps_every_metric(&policy));
        if let Some(m) = early {
            m.install(&policy, limits);
        }
        self.handle.reload(update).map_err(|e| vec![e])?;
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

    /// Graceful shutdown: stop accepting, drain for up to `grace`.
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
        listeners: listener_specs(&config),
        ca_server: config.ca_server.as_ref().map(|c| c.bind),
        dns: config
            .dns
            .as_ref()
            .map(|d| dns_spec(d, config.log.flow.dns_events)),
        ca,
        minter,
        require_sni_match: config.tls.require_sni_match,
        enable_h2: config.http.enable_h2,
        upstream_tls: (&config).into(),
        max_connections: config.limits.max_connections,
        max_connections_per_client: config.limits.max_connections_per_client,
        connection_events: config.log.flow.connection_events,
        ws_message_every: config.log.flow.ws_message_every,
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

    /// The restart-only changes from `running` to `new`; a second pass over
    /// the result finds none, since every one was put back.
    fn restart(running: &str, new: &str) -> Vec<&'static str> {
        let running = cfg(running);
        let mut new = cfg(new);
        let changed = keep_restart_only(&running, &mut new);
        assert!(keep_restart_only(&running, &mut new).is_empty(), "kept");
        changed
    }

    #[test]
    fn listener_modes_and_dns_need_a_restart() {
        let base = "version: 1\nlisteners: [{ name: p, bind: 127.0.0.1:443 }]\n";
        let direct = "version: 1\nlisteners: [{ name: p, mode: direct, bind: 127.0.0.1:443 }]\n";
        let remapped = "version: 1\nlisteners: [{ name: p, mode: direct, bind: 127.0.0.1:443, \
                        target_port: 8443 }]\n";
        let dns =
            |ip: &str| format!("{base}dns: {{ bind: 127.0.0.1:53, answer: {{ ipv4: {ip} }} }}\n");
        assert_eq!(restart(base, direct), ["listeners"]);
        assert_eq!(restart(direct, remapped), ["listeners"]);
        assert_eq!(restart(base, &dns("10.0.0.1")), ["dns"]);
        assert_eq!(restart(&dns("10.0.0.1"), &dns("10.0.0.2")), ["dns"]);
        assert_eq!(
            restart(&dns("10.0.0.1"), &dns("10.0.0.1")),
            Vec::<&str>::new()
        );
    }

    #[test]
    fn startup_sizes_and_log_destinations_need_a_restart() {
        let base = "version: 1\n";
        assert_eq!(
            restart(base, "version: 1\nlimits: { max_state_entries: 5 }\n"),
            ["limits.max_state_entries"]
        );
        assert_eq!(
            restart(base, "version: 1\nlog: { flow: { path: /tmp/x.jsonl } }\n"),
            ["log.flow"]
        );
        assert_eq!(
            restart(base, "version: 1\ncapture_dir: /tmp/c\n"),
            ["capture_dir"]
        );
        // Reloadable limits and log settings are not restart-only.
        assert_eq!(
            restart(
                base,
                "version: 1\nlimits: { max_header_bytes: 8kb }\nlog: { redact_headers: [x-a] }\n"
            ),
            Vec::<&str>::new()
        );
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

    /// Every setting the server reads once, at start, is kept on reload;
    /// a change to any of them is named.
    #[test]
    fn startup_only_settings_need_a_restart() {
        let base = "version: 1\nlisteners: [{ name: p, bind: 127.0.0.1:443 }]\n";
        for (yaml, field) in [
            ("tls: { require_sni_match: false }", "tls"),
            ("tls: { leaf_cache_size: 5 }", "tls"),
            ("tls: { upstream: { min_version: \"1.3\" } }", "tls"),
            ("ca_server: { bind: 127.0.0.1:3130 }", "ca_server"),
            ("http: { enable_h2: false }", "http.enable_h2"),
            ("limits: { max_connections: 5 }", "limits.max_connections"),
            (
                "limits: { max_connections_per_client: 5 }",
                "limits.max_connections_per_client",
            ),
            (
                "limits: { max_capture_body_bytes: 1mb }",
                "limits.max_capture_body_bytes",
            ),
            ("log: { capture: { all: true } }", "log.capture"),
            ("log: { capture: { max_file_bytes: 1mb } }", "log.capture"),
        ] {
            assert_eq!(restart(base, &format!("{base}{yaml}\n")), [field], "{yaml}");
        }
        // The rest of `http` and `limits` reload.
        assert_eq!(
            restart(
                base,
                &format!("{base}http: {{ allow_http10: true }}\nlimits: {{ max_headers: 5 }}\n")
            ),
            Vec::<&str>::new()
        );
    }
}
