//! roxy: a TLS-inspecting HTTP firewall for containing AI agent traffic.
//!
//! See `docs/` at the repository root. This binary owns the CLI, config
//! loading and wiring; the engine lives in the library crates.

use std::io::{IsTerminal as _, Read as _, Write as _};
use std::net::{TcpStream, ToSocketAddrs as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context as _, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use roxy_proxy::{Redactor, UpstreamSettings};
use roxy_rules::Condition;
use roxy_tls::{Ca, CaError, UpstreamTlsOptions};
use tracing_subscriber::EnvFilter;

use roxy::addons::AddonLoader;
use roxy::config::{Compiled, Config};
use roxy::ruletest;

// musl's malloc takes a global lock on every call, which halves the
// throughput of the static release image.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Debug, Parser)]
#[command(
    name = "roxy",
    version,
    about = "TLS-inspecting HTTP firewall for AI agent traffic"
)]
struct Cli {
    /// Operational log format (default: pretty on a TTY, json otherwise).
    #[arg(long, global = true, value_enum)]
    log_format: Option<LogFormat>,
    /// Operational log level or filter directive. `RUST_LOG` overrides it.
    #[arg(long, global = true, default_value = "info")]
    log_level: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum LogFormat {
    Json,
    Pretty,
}

#[derive(Debug, Args)]
struct ConfigArg {
    /// Path to the roxy YAML config.
    #[arg(long, short = 'c')]
    config: PathBuf,
}

/// `roxy run`: a config file, or node mode against a control plane.
#[derive(Debug, Args)]
#[command(group(
    clap::ArgGroup::new("source")
        .required(true)
        .args(["config", "control_plane"])
))]
struct RunArgs {
    /// Path to the roxy YAML config.
    #[arg(long, short = 'c')]
    config: Option<PathBuf>,
    /// Node mode: the control plane's `https://` URL. The config and
    /// secrets come from its lease; nothing but the node certificate, key,
    /// flow counter and interception CA is kept in `--state-dir`.
    #[arg(long, requires = "state_dir", conflicts_with = "config")]
    control_plane: Option<String>,
    /// Enrolment token, read once on a start with no node certificate in
    /// the state dir.
    #[arg(long, requires = "control_plane")]
    enrol_token_file: Option<PathBuf>,
    /// Where the node keeps its certificate and key.
    #[arg(long, requires = "control_plane")]
    state_dir: Option<PathBuf>,
    /// PEM CA bundle to verify the control plane with (default: system
    /// roots).
    #[arg(long, requires = "control_plane")]
    control_plane_ca: Option<PathBuf>,
    /// Interception CA certificate to import into the state dir when it
    /// holds none.
    #[arg(long, requires_all = ["control_plane", "interception_ca_key"])]
    interception_ca_cert: Option<PathBuf>,
    /// Its PKCS#8 PEM key.
    #[arg(long, requires = "interception_ca_cert")]
    interception_ca_key: Option<PathBuf>,
    /// Replace a stored interception CA that differs from the one given.
    /// Every workload trusting the old CA breaks.
    #[arg(long, requires = "interception_ca_cert")]
    replace_interception_ca: bool,
    /// Node mode: where the proxy listens before the first lease
    /// (default 0.0.0.0:3128).
    #[arg(long, requires = "control_plane", value_name = "ADDR")]
    bootstrap_bind: Option<std::net::SocketAddr>,
    /// Node mode: where `ca_server` listens before the first lease
    /// (default 0.0.0.0:3130).
    #[arg(long, requires = "control_plane", value_name = "ADDR")]
    bootstrap_ca_server: Option<std::net::SocketAddr>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Load the config and CA and run the proxy, or run as a node of a
    /// control plane (`--control-plane`).
    Run(RunArgs),
    /// Validate a config and print diagnostics. Exits 1 if it has problems.
    Check(ConfigArg),
    /// Manage roxy's certificate authority.
    Ca {
        #[command(subcommand)]
        command: CaCommand,
    },
    /// Rule tooling.
    Rule {
        #[command(subcommand)]
        command: RuleCommand,
    },
    /// Probe `ca_server`'s `/healthz` (the process is up) or, with
    /// `--ready`, `/readyz` (a policy is in force) for
    /// container health checks, where there is no shell or curl. Exits 0
    /// on a `200` response and 1 on anything else.
    Health(HealthArgs),
}

#[derive(Debug, Args)]
struct HealthArgs {
    /// Plain `http://` URL to GET. Defaults to `/healthz`, or `/readyz`
    /// with `--ready`, on `127.0.0.1:3130`.
    #[arg(long, conflicts_with = "ready")]
    url: Option<String>,
    /// Probe readiness (`/readyz`) instead of liveness.
    #[arg(long)]
    ready: bool,
    /// Connect, write and read timeout, in seconds.
    #[arg(long, default_value_t = 3)]
    timeout: u64,
}

#[derive(Debug, Subcommand)]
enum CaCommand {
    /// Generate the CA in `tls.ca_dir`. Fails if one already exists or a
    /// provided CA (`tls.ca_cert`) is configured.
    Init {
        #[command(flatten)]
        config: ConfigArg,
        /// Replace an existing CA. Every client trusting the old CA breaks.
        #[arg(long)]
        force: bool,
    },
    /// Print the CA certificate (never the key) to stdout.
    Export {
        #[command(flatten)]
        config: ConfigArg,
        /// Output DER instead of PEM.
        #[arg(long, conflicts_with = "pem")]
        der: bool,
        /// Output PEM (the default).
        #[arg(long)]
        pem: bool,
    },
}

#[derive(Debug, Subcommand)]
enum RuleCommand {
    /// Dry-run a request against the rules. Prints matched
    /// rules, effects and the decision; exits 0 for allow, 3 for deny.
    /// Secrets are not resolved (`[secret:name]` placeholders).
    Test(Box<RuleTestArgs>),
}

#[derive(Debug, Args)]
struct RuleTestArgs {
    #[command(flatten)]
    config: ConfigArg,
    /// `client.ip`.
    #[arg(long, default_value = "127.0.0.1")]
    client_ip: std::net::IpAddr,
    /// Request header `name: value` (repeatable).
    #[arg(short = 'H', long = "header")]
    headers: Vec<String>,
    /// Request body text (`body.text`, `body.size`).
    #[arg(long)]
    body: Option<String>,
    /// The body is chunked: `body.size` (and `header["content-length"]`)
    /// are absent, as they are before a chunked body is buffered.
    #[arg(long)]
    chunked: bool,
    /// `body.bytes`: request body bytes streamed so far. Runs the watching
    /// rules that read it.
    #[arg(long)]
    body_bytes: Option<u64>,
    /// `response.status`. Runs the watching rules that read the response
    /// head (`response.status`, `response.header[..]`).
    #[arg(long)]
    response_status: Option<u16>,
    /// `response.body.bytes`: response body bytes sent so far.
    #[arg(long)]
    response_body_bytes: Option<u64>,
    /// Response header `name: value` (repeatable).
    #[arg(short = 'R', long = "response-header")]
    response_headers: Vec<String>,
    /// `ws.text`: a WebSocket text message. Any `--ws-*` flag runs the
    /// watching rules that read `ws.*`.
    #[arg(long)]
    ws_text: Option<String>,
    /// `ws.opcode`: 1 text (the default with `--ws-text`), 2 binary (the
    /// default otherwise), 8 close, 9 ping, 10 pong.
    #[arg(long)]
    ws_opcode: Option<u8>,
    /// `ws.size` of a message that is not text (default 0).
    #[arg(long)]
    ws_size: Option<u64>,
    /// `ws.direction`: `c2s` (default) or `s2c`.
    #[arg(long)]
    ws_direction: Option<String>,
    /// Metric value `id=N` for `metric.<id>` (repeatable). Metrics not given
    /// are 0 (a fresh series); `id=unavailable` makes the view report the
    /// metric unavailable, exercising the fail-closed path.
    #[arg(long = "metric")]
    metrics: Vec<String>,
    /// State entry `key=value` for `state["key"]` (repeatable).
    #[arg(long = "state")]
    state: Vec<String>,
    /// Initial tag (repeatable).
    #[arg(long = "tag")]
    tags: Vec<String>,
    /// `METHOD URL`, as two arguments or one (`'POST https://host/path'`).
    #[arg(required = true, num_args = 1..=2, value_names = ["METHOD", "URL"])]
    request: Vec<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Err(e) = init_tracing(cli.log_format, &cli.log_level) {
        eprintln!("roxy: {e:#}");
        return ExitCode::FAILURE;
    }
    match dispatch(cli.command) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("roxy: error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(command: Command) -> anyhow::Result<ExitCode> {
    match command {
        Command::Run(args) => match args.config {
            Some(path) => run(&path),
            None => run_node(args),
        },
        Command::Check(args) => Ok(check(&args.config)),
        Command::Ca {
            command: CaCommand::Init { config, force },
        } => ca_init(&config.config, force),
        Command::Ca {
            command: CaCommand::Export { config, der, .. },
        } => ca_export(&config.config, der),
        Command::Rule {
            command: RuleCommand::Test(args),
        } => rule_test(&args),
        Command::Health(args) => {
            let url = args.url.unwrap_or_else(|| {
                let path = if args.ready { "readyz" } else { "healthz" };
                format!("http://127.0.0.1:3130/{path}")
            });
            health(&url, Duration::from_secs(args.timeout.max(1)))
        }
    }
}

/// `GET url` over HTTP/1.1 with std only. Success is a `200` status line;
/// anything else (refused, timeout, other status, garbage) is unhealthy.
/// An `x-roxy-policy: expired` header is reported, not a failure: the
/// process is up and denying everything until a reload. A failing status
/// is reported with the body's first line, which is the reason word
/// `/readyz` answers with.
fn health(url: &str, timeout: Duration) -> anyhow::Result<ExitCode> {
    let rest = url
        .strip_prefix("http://")
        .with_context(|| format!("--url must be a plain http:// URL, got {url:?}"))?;
    let (authority, path) = rest.find('/').map_or((rest, "/"), |i| rest.split_at(i));
    if authority.is_empty() {
        bail!("--url has no host: {url:?}");
    }
    // `host` or `[v6]` without a port gets the HTTP default.
    let has_port = if authority.starts_with('[') {
        authority.contains("]:")
    } else {
        authority.contains(':')
    };
    let target = if has_port {
        authority.to_owned()
    } else {
        format!("{authority}:80")
    };
    let addrs: Vec<_> = target
        .to_socket_addrs()
        .with_context(|| format!("resolving {target}"))?
        .collect();
    let mut last = None;
    let mut stream = None;
    for addr in &addrs {
        match TcpStream::connect_timeout(addr, timeout) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => last = Some(e),
        }
    }
    let mut stream = match (stream, last) {
        (Some(s), _) => s,
        (None, Some(e)) => return Err(e).with_context(|| format!("connecting to {target}")),
        (None, None) => bail!("{target} resolved to no addresses"),
    };
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: roxy-health\r\n\
         Connection: close\r\n\r\n"
    )
    .context("sending the request")?;
    // Only the head matters: read until the blank line (at most 4 KiB).
    let mut head = Vec::new();
    let mut buf = [0u8; 256];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 4096 {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => head.extend_from_slice(&buf[..n]),
            Err(e) if head.is_empty() => {
                return Err(e).context("reading the response");
            }
            Err(_) => break,
        }
    }
    let status_line = String::from_utf8_lossy(&head)
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned();
    let mut parts = status_line.split(' ');
    let healthy = matches!(
        (parts.next(), parts.next()),
        (Some("HTTP/1.1" | "HTTP/1.0"), Some("200"))
    );
    if healthy {
        let expired = String::from_utf8_lossy(&head).lines().any(|l| {
            l.split_once(':').is_some_and(|(k, v)| {
                k.eq_ignore_ascii_case(roxy_proxy::POLICY_HEADER)
                    && v.trim().eq_ignore_ascii_case("expired")
            })
        });
        if expired {
            println!("ok (policy expired)");
        } else {
            println!("ok");
        }
        return Ok(ExitCode::SUCCESS);
    }
    // The server closes after one response; read the rest (bounded) for
    // the reason. A read error here only loses the reason.
    while head.len() < 4096 {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => head.extend_from_slice(&buf[..n]),
        }
    }
    let head = String::from_utf8_lossy(&head);
    let reason = head
        .split_once("\r\n\r\n")
        .and_then(|(_, body)| body.lines().next())
        .filter(|l| !l.is_empty());
    match reason {
        Some(reason) => eprintln!("roxy: unhealthy: {url}: {status_line:?}: {reason}"),
        None => eprintln!("roxy: unhealthy: {url}: {status_line:?}"),
    }
    Ok(ExitCode::FAILURE)
}

fn rule_test(args: &RuleTestArgs) -> anyhow::Result<ExitCode> {
    let (config, compiled) = load_valid(&args.config.config)?;
    let policy = compiled.policy;
    let (method, url) = match args.request.as_slice() {
        [one] => one
            .split_once(char::is_whitespace)
            .map(|(m, u)| (m.to_owned(), u.trim().to_owned()))
            .with_context(|| format!("expected `METHOD URL`, got {one:?}"))?,
        [m, u] => (m.clone(), u.clone()),
        _ => bail!("expected `METHOD URL`"),
    };
    let mut req = ruletest::TestRequest::new(&method, &url);
    req.client_ip = args.client_ip;
    req.body.clone_from(&args.body);
    req.chunked = args.chunked;
    req.body_bytes = args.body_bytes;
    req.response_status = args.response_status;
    req.response_body_bytes = args.response_body_bytes;
    req.tags.clone_from(&args.tags);
    let err = |e: String| anyhow::anyhow!(e);
    req.ws = ruletest::ws_message(
        args.ws_direction.as_deref(),
        args.ws_opcode,
        args.ws_text.as_deref(),
        args.ws_size,
    )
    .map_err(err)?;
    req.headers = args
        .headers
        .iter()
        .map(|h| ruletest::parse_header(h))
        .collect::<Result<_, _>>()
        .map_err(err)?;
    req.response_headers = args
        .response_headers
        .iter()
        .map(|h| ruletest::parse_header(h))
        .collect::<Result<_, _>>()
        .map_err(err)?;
    req.state = args
        .state
        .iter()
        .map(|s| ruletest::parse_pair(s))
        .collect::<Result<_, _>>()
        .map_err(err)?;
    req.metrics = args
        .metrics
        .iter()
        .map(|s| ruletest::parse_metric(s))
        .collect::<Result<_, String>>()
        .map_err(err)?;

    let (view, warnings) = ruletest::build_view(&config, &req).map_err(err)?;
    for w in warnings {
        eprintln!("roxy rule test: warning: {w}");
    }
    let mut run = ruletest::run(&policy, &view, &req.tags, ruletest::known(&req));
    let address = ruletest::address_check(&config, &view, &run.head);
    if matches!(address, Some(Err(_))) {
        ruletest::apply_address_denial(&mut run.head);
        run.watching = None;
    }
    // Secrets are never resolved here, so the redactor has none registered;
    // effect text still goes through it so a future change cannot leak.
    let redactor = Redactor::new();
    let note = ruletest::metric_note(&ruletest::metric_values(&config, &req));
    print!(
        "{}",
        ruletest::report(&policy, note.as_deref(), address.as_ref(), &run, &redactor)
    );
    Ok(ExitCode::from(ruletest::exit_code(&run.decision())))
}

/// `<file>:<diagnostic>` plus the indented snippet for expression errors.
fn print_diagnostic(path: &Path, d: &roxy::config::Diagnostic) {
    eprintln!("{}:{d}", path.display());
    if let Some(snippet) = &d.snippet {
        for line in snippet.lines() {
            eprintln!("    | {line}");
        }
    }
}

fn init_tracing(format: Option<LogFormat>, level: &str) -> anyhow::Result<()> {
    let filter = match std::env::var("RUST_LOG") {
        Ok(directives) if !directives.trim().is_empty() => {
            EnvFilter::try_new(&directives).context("invalid RUST_LOG")?
        }
        _ => EnvFilter::try_new(level).with_context(|| format!("invalid --log-level {level:?}"))?,
    };
    let tty = std::io::stderr().is_terminal();
    let format = format.unwrap_or(if tty {
        LogFormat::Pretty
    } else {
        LogFormat::Json
    });
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(tty);
    match format {
        LogFormat::Json => builder.json().with_current_span(false).init(),
        LogFormat::Pretty => builder.init(),
    }
    Ok(())
}

/// Load and fully validate a config, turning diagnostics into one error.
fn load_valid(path: &Path) -> anyhow::Result<(Config, Compiled)> {
    let config = Config::load(path)?;
    match config.validate() {
        Ok(compiled) => Ok((config, compiled)),
        Err(diags) => {
            let lines: Vec<String> = diags
                .iter()
                .map(|d| {
                    let mut line = format!("{}:{d}", path.display());
                    for s in d.snippet.iter().flat_map(|s| s.lines()) {
                        line.push_str("\n    | ");
                        line.push_str(s);
                    }
                    line
                })
                .collect();
            bail!("invalid config:\n{}", lines.join("\n"));
        }
    }
}

fn check(path: &Path) -> ExitCode {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{}: cannot read: {e}", path.display());
            return ExitCode::FAILURE;
        }
    };
    let config = match Config::from_yaml(&text) {
        Ok(c) => c,
        Err(e) => {
            // serde_yaml_ng prefixes errors with the YAML path when it has one
            // (`rules[0]: unknown field ...`), giving `<file>:<yaml path>: <msg>`.
            let msg = roxy::config::describe_parse_error(&text, &e);
            let has_path = msg
                .split_once(": ")
                .is_some_and(|(p, _)| !p.is_empty() && !p.contains(' '));
            let sep = if has_path { ":" } else { ": " };
            eprintln!("{}{sep}{msg}", path.display());
            return ExitCode::FAILURE;
        }
    };
    match config.validate() {
        Ok(compiled) => {
            // Load every address list fully: a bad line is reported as
            // `<file>:<line>: ...`, exactly as startup would fail.
            let lists = match roxy::lists::load_all(&config) {
                Ok(l) => l,
                Err(errs) => {
                    for e in &errs {
                        eprintln!("{e}");
                    }
                    eprintln!("{}: {} problem(s) found", path.display(), errs.len());
                    return ExitCode::FAILURE;
                }
            };
            for spec in &config.address_lists {
                if let Some(l) = lists.get(&spec.name) {
                    println!("address list {}: {} entries", spec.name, l.len());
                }
            }
            let Compiled {
                policy,
                addon_conditions,
            } = compiled;
            for w in roxy_rules::Policy::metric_warnings(&config.metrics) {
                eprintln!("{}:{}: warning: {}", path.display(), w.path, w.message);
            }
            let errs = startup_checks(&config, addon_conditions);
            if !errs.is_empty() {
                for e in &errs {
                    eprintln!("{}:{e}", path.display());
                }
                eprintln!("{}: {} problem(s) found", path.display(), errs.len());
                return ExitCode::FAILURE;
            }
            println!(
                "{}: OK ({} listener(s), {} rule(s), {} metric(s), {} secret(s), {} addon(s))",
                path.display(),
                config.listeners.len(),
                config.rules.len(),
                config.metrics.len(),
                config.secrets.len(),
                config.addons.len(),
            );
            if policy.rule_count() > 0 {
                print!("rules:\n{}", roxy::ruletest::classification(&policy));
            }
            if let Some(until) = config.valid_until {
                println!("valid until: {}", until.to_rfc3339());
                if until <= chrono::Utc::now() {
                    eprintln!(
                        "{}: warning: valid_until has passed; roxy will load this policy and deny everything until a reload moves or removes it",
                        path.display()
                    );
                }
            }
            ExitCode::SUCCESS
        }
        Err(diags) => {
            for d in &diags {
                print_diagnostic(path, d);
            }
            eprintln!("{}: {} problem(s) found", path.display(), diags.len());
            ExitCode::FAILURE
        }
    }
}

/// The rest of startup's loading that needs no socket and writes nothing:
/// compiling the addons, loading the CA (a provided one, else the one in
/// `tls.ca_dir`; a missing one there is startup's to generate, never
/// here), reading `tls.upstream.extra_roots` and building the resolver.
/// Every failure is reported as `<field>: <why>`.
fn startup_checks(config: &Config, addon_conditions: Vec<Option<Condition>>) -> Vec<String> {
    let mut errs = Vec::new();
    let addons = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow::anyhow!("starting tokio runtime: {e}"))
        .and_then(|rt| rt.block_on(AddonLoader::default().prepare(config, addon_conditions)));
    if let Err(e) = addons {
        errs.push(format!("addons: {e:#}"));
    }
    match config.tls.provided_ca() {
        Ok(Some((cert, key))) => {
            if let Err(e) = Ca::load_provided(cert, key) {
                errs.push(format!("tls.ca_cert: {e}"));
            }
        }
        Ok(None) => match Ca::load(&config.tls.ca_dir) {
            Ok(_) | Err(roxy_tls::CaError::NotFound(_)) => {}
            Err(e) => errs.push(format!("tls.ca_dir: {e}")),
        },
        Err(e) => errs.push(format!("tls.ca_cert: {e}")),
    }
    if let Err(e) = roxy_tls::client_config(&UpstreamTlsOptions::from(config)) {
        errs.push(format!("tls.upstream.extra_roots: {e}"));
    }
    if let Err(e) = UpstreamSettings::from(config).dns.check() {
        errs.push(format!("upstream.dns.resolver: {e}"));
    }
    errs
}

fn ca_init(path: &Path, force: bool) -> anyhow::Result<ExitCode> {
    // CA commands need only `tls.ca_dir`, so a structurally valid config is
    // enough; rule problems should not block CA management.
    let config = Config::load(path)?;
    if let Some((cert, _)) = config.tls.provided_ca()? {
        anyhow::bail!(
            "tls.ca_cert is set ({}): roxy uses that CA and never generates one",
            cert.display()
        );
    }
    let dir = &config.tls.ca_dir;
    let ca = if force {
        Ca::generate_force(dir)
    } else {
        Ca::generate(dir)
    }
    .map_err(|e| match e {
        CaError::AlreadyExists(_) => {
            anyhow::anyhow!("{e} (use --force to replace it; clients trusting it will break)")
        }
        other @ (CaError::NotFound(_)
        | CaError::Incomplete { .. }
        | CaError::Io { .. }
        | CaError::NotCurrent { .. }
        | CaError::InvalidCert { .. }
        | CaError::InvalidKey { .. }
        | CaError::KeyMismatch { .. }
        | CaError::Generate(_)
        | CaError::Rng) => other.into(),
    })?;
    tracing::info!(dir = %dir.display(), "generated roxy CA");
    println!("{}", ca.cert_path().display());
    Ok(ExitCode::SUCCESS)
}

fn ca_export(path: &Path, der: bool) -> anyhow::Result<ExitCode> {
    let config = Config::load(path)?;
    let ca = match config.tls.provided_ca()? {
        Some((cert, key)) => Ca::load_provided(cert, key)?,
        None => Ca::load(&config.tls.ca_dir)?,
    };
    let mut out = std::io::stdout().lock();
    if der {
        out.write_all(&ca.cert_der())?;
    } else {
        out.write_all(ca.cert_pem().as_bytes())?;
    }
    out.flush()?;
    Ok(ExitCode::SUCCESS)
}

fn run(path: &Path) -> anyhow::Result<ExitCode> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting tokio runtime")?;
    runtime.block_on(async {
        let running = roxy::run::start(
            path,
            roxy::run::StartOptions {
                watch: true,
                ..Default::default()
            },
        )
        .await?;
        let listeners: Vec<String> = running
            .server
            .local_addrs()
            .iter()
            .map(|(n, a)| format!("{n}={a}"))
            .collect();
        tracing::info!(
            listeners = listeners.join(","),
            ca_server = ?running.server.ca_server_addr(),
            "roxy running"
        );
        wait_for_shutdown(&running).await?;
        tracing::info!("roxy shutting down");
        running.shutdown(SHUTDOWN_GRACE).await;
        anyhow::Ok(())
    })?;
    Ok(ExitCode::SUCCESS)
}

/// In-flight exchanges get this long to finish at shutdown.
const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

/// `roxy run --control-plane`: node mode. The listeners open at once and
/// deny everything until the first lease. `SIGHUP` reopens the logs; there
/// is no file to reload. A node that cannot proceed (no identity and no
/// token, a token the control plane will not accept) exits non-zero, so an
/// orchestrator sees a crash loop rather than a node denying for ever.
fn run_node(args: RunArgs) -> anyhow::Result<ExitCode> {
    let control_plane = args.control_plane.expect("clap: --control-plane");
    let state_dir = args.state_dir.expect("clap: --state-dir");
    let mut bootstrap = roxy::node::Bootstrap::default();
    if let Some(bind) = args.bootstrap_bind {
        bootstrap.proxy_bind = bind;
    }
    if let Some(bind) = args.bootstrap_ca_server {
        bootstrap.ca_server_bind = Some(bind);
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting tokio runtime")?;
    runtime.block_on(async {
        let mut running = roxy::node::start(roxy::node::NodeOptions {
            enrol_token_file: args.enrol_token_file,
            control_plane_ca: args.control_plane_ca,
            interception_ca: args.interception_ca_cert.zip(args.interception_ca_key),
            replace_interception_ca: args.replace_interception_ca,
            bootstrap,
            ..roxy::node::NodeOptions::new(&control_plane, &state_dir)
        })
        .await?;
        let listeners: Vec<String> = running
            .handler
            .local_addrs()
            .await
            .iter()
            .map(|(n, a)| format!("{n}={a}"))
            .collect();
        tracing::info!(
            listeners = listeners.join(","),
            ca_server = ?running.handler.ca_server_addr().await,
            control_plane = %control_plane,
            "roxy running as a node"
        );
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut term = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
            let mut hup = signal(SignalKind::hangup()).context("installing SIGHUP handler")?;
            loop {
                tokio::select! {
                    e = running.failed() => {
                        tracing::error!(error = %e, "node cannot proceed; exiting");
                        running.shutdown(SHUTDOWN_GRACE).await;
                        return anyhow::Ok(ExitCode::FAILURE);
                    }
                    r = tokio::signal::ctrl_c() => break r.context("waiting for ctrl-c")?,
                    _ = term.recv() => break,
                    _ = hup.recv() => {
                        tracing::info!("SIGHUP: reopening logs");
                        running.reopen_logs().await;
                    }
                }
            }
        }
        #[cfg(not(unix))]
        tokio::select! {
            e = running.failed() => {
                tracing::error!(error = %e, "node cannot proceed; exiting");
                running.shutdown(SHUTDOWN_GRACE).await;
                return anyhow::Ok(ExitCode::FAILURE);
            }
            r = tokio::signal::ctrl_c() => r.context("waiting for ctrl-c")?,
        }
        tracing::info!("roxy shutting down");
        running.shutdown(SHUTDOWN_GRACE).await;
        anyhow::Ok(ExitCode::SUCCESS)
    })
}

/// Waits for ctrl-c or SIGTERM; on SIGHUP meanwhile, reopens the flow log
/// file (for external log rotation) and reloads the config. The reload runs
/// as its own task (the `Reloader` serialises overlapping ones), so a
/// shutdown signal during a long reload is seen at once; a reload still in
/// flight then is cancelled, which leaves the running policy in place.
async fn wait_for_shutdown(running: &roxy::run::Running) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
        let mut hup = signal(SignalKind::hangup()).context("installing SIGHUP handler")?;
        let mut reload: Option<tokio::task::JoinHandle<bool>> = None;
        let result = loop {
            tokio::select! {
                r = tokio::signal::ctrl_c() => break r.context("waiting for ctrl-c"),
                _ = term.recv() => break Ok(()),
                _ = hup.recv() => {
                    tracing::info!("SIGHUP: reopening logs and reloading config");
                    running.reopen_logs();
                    let reloader = running.reloader.clone();
                    reload = Some(tokio::spawn(async move { reloader.reload().await }));
                }
            }
        };
        if let Some(task) = reload
            && !task.is_finished()
        {
            tracing::warn!("shutting down during a config reload; the reload is abandoned");
            task.abort();
        }
        result
    }
    #[cfg(not(unix))]
    {
        let _ = running;
        tokio::signal::ctrl_c().await.context("waiting for ctrl-c")
    }
}
