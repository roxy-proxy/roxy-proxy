//! roxy: a TLS-inspecting HTTP firewall for containing AI agent traffic.
//!
//! See `DESIGN.md` at the repository root. This binary owns the CLI, config
//! loading and wiring; the engine lives in the library crates.

use std::io::{IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context as _, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use roxy_proxy::{FileSink, FlowEvent, FlowSink, Redactor, StdoutSink};
use roxy_tls::{Ca, CaError};
use tracing_subscriber::EnvFilter;

use roxy::config::Config;
use roxy::ruletest;
use roxy::secrets::Secrets;
use roxy_rules::Phase;

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

#[derive(Debug, Subcommand)]
enum Command {
    /// Load the config and CA and run the proxy.
    Run(ConfigArg),
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
}

#[derive(Debug, Subcommand)]
enum CaCommand {
    /// Generate the CA in `tls.ca_dir`. Fails if one already exists.
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
    /// Dry-run a request against the rules (DESIGN.md §6.6). Prints matched
    /// rules, effects and the decision; exits 0 for allow, 3 for deny.
    /// Secrets are not resolved (`[secret:name]` placeholders).
    Test(Box<RuleTestArgs>),
}

#[derive(Debug, Args)]
struct RuleTestArgs {
    #[command(flatten)]
    config: ConfigArg,
    /// Phase whose chain to evaluate.
    #[arg(long, value_enum, default_value = "request")]
    phase: PhaseArg,
    /// `client.ip`.
    #[arg(long, default_value = "127.0.0.1")]
    client_ip: std::net::IpAddr,
    /// `client.user` (proxy-auth user).
    #[arg(long)]
    user: Option<String>,
    /// Request header `name: value` (repeatable).
    #[arg(short = 'H', long = "header")]
    headers: Vec<String>,
    /// Request body text (`body.text`, `body.size`).
    #[arg(long)]
    body: Option<String>,
    /// `response.status` (response phase).
    #[arg(long)]
    status: Option<u16>,
    /// Response header `name: value` (repeatable).
    #[arg(short = 'R', long = "response-header")]
    response_headers: Vec<String>,
    /// Metric value `id=N` for `metric.<id>` (repeatable).
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum PhaseArg {
    Connect,
    Request,
    Response,
}

impl From<PhaseArg> for Phase {
    fn from(p: PhaseArg) -> Self {
        match p {
            PhaseArg::Connect => Phase::Connect,
            PhaseArg::Request => Phase::Request,
            PhaseArg::Response => Phase::Response,
        }
    }
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
        Command::Run(args) => run(&args.config),
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
    }
}

fn rule_test(args: &RuleTestArgs) -> anyhow::Result<ExitCode> {
    let config = load_valid(&args.config.config)?;
    let policy = config
        .compile_policy()
        .map_err(|_| anyhow::anyhow!("policy failed to compile"))?;
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
    req.user.clone_from(&args.user);
    req.body.clone_from(&args.body);
    req.status = args.status;
    req.tags.clone_from(&args.tags);
    let err = |e: String| anyhow::anyhow!(e);
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
        .map(|s| {
            let (k, v) = ruletest::parse_pair(s)?;
            let n = v
                .parse::<i64>()
                .map_err(|_| format!("metric {k:?}: {v:?} is not an integer"))?;
            Ok((k, n))
        })
        .collect::<Result<_, String>>()
        .map_err(err)?;

    let (view, warnings) = ruletest::build_view(&config, &req).map_err(err)?;
    for w in warnings {
        eprintln!("roxy rule test: warning: {w}");
    }
    let phase = Phase::from(args.phase);
    let out = ruletest::run(&policy, phase, &view, &req.tags);
    // Secrets are never resolved here, so the redactor has none registered;
    // effect text still goes through it so a future change cannot leak.
    let redactor = Redactor::new();
    print!("{}", ruletest::report(phase, &out, &redactor));
    Ok(ExitCode::from(ruletest::exit_code(&out.decision)))
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
fn load_valid(path: &Path) -> anyhow::Result<Config> {
    let config = Config::load(path)?;
    if let Err(diags) = config.validate() {
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
    Ok(config)
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
        Ok(()) => {
            println!(
                "{}: OK ({} listener(s), {} rule(s), {} metric(s), {} secret(s), {} addon(s))",
                path.display(),
                config.listeners.len(),
                config.rules.len(),
                config.metrics.len(),
                config.secrets.len(),
                config.addons.len(),
            );
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

fn ca_init(path: &Path, force: bool) -> anyhow::Result<ExitCode> {
    // CA commands need only `tls.ca_dir`, so a structurally valid config is
    // enough; rule problems should not block CA management.
    let config = Config::load(path)?;
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
        other => other.into(),
    })?;
    tracing::info!(dir = %dir.display(), "generated roxy CA");
    println!("{}", ca.cert_path().display());
    Ok(ExitCode::SUCCESS)
}

fn ca_export(path: &Path, der: bool) -> anyhow::Result<ExitCode> {
    let config = Config::load(path)?;
    let ca = Ca::load(&config.tls.ca_dir)?;
    let mut out = std::io::stdout().lock();
    if der {
        out.write_all(&ca.cert_der())?;
    } else {
        out.write_all(ca.cert_pem().as_bytes())?;
    }
    out.flush()?;
    Ok(ExitCode::SUCCESS)
}

fn build_sink(config: &Config) -> anyhow::Result<Box<dyn FlowSink>> {
    Ok(match &config.log.flow.path {
        Some(path) => Box::new(
            FileSink::open(path).with_context(|| format!("opening flow log {}", path.display()))?,
        ),
        None => Box::new(StdoutSink::new()),
    })
}

fn run(path: &Path) -> anyhow::Result<ExitCode> {
    let config = load_valid(path)?;
    let secrets = Secrets::resolve(&config.secrets)?;

    let mut redactor = Redactor::new();
    for value in secrets.values() {
        redactor.add_secret(value.expose());
    }
    for header in &config.log.redact_headers {
        redactor.add_header(header);
    }

    let sink = build_sink(&config)?;

    let ca_dir = &config.tls.ca_dir;
    let ca = match Ca::load(ca_dir) {
        Ok(ca) => ca,
        Err(CaError::NotFound(_)) => {
            let ca = Ca::generate(ca_dir)?;
            tracing::info!(dir = %ca_dir.display(), "generated new roxy CA");
            ca
        }
        Err(e) => return Err(e.into()),
    };

    sink.emit(&FlowEvent::ConfigLoaded {
        ts: chrono::Utc::now(),
        path: path.to_path_buf(),
        listeners: config.listeners.iter().map(|l| l.name.clone()).collect(),
        rules: config.rules.len(),
        metrics: config.metrics.len(),
        addons: config.addons.len(),
    });

    let listeners: Vec<String> = config
        .listeners
        .iter()
        .map(|l| format!("{}={}", l.name, l.bind))
        .collect();
    let ca_server = config
        .ca_server
        .as_ref()
        .map_or_else(|| "disabled".to_owned(), |c| c.bind.to_string());
    tracing::info!(
        listeners = listeners.join(","),
        ca_server,
        ca_cert = %ca.cert_path().display(),
        secrets = secrets.len(),
        "roxy starting"
    );

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting tokio runtime")?;
    runtime.block_on(async {
        // M1: bind listeners and start the pipeline here.
        tokio::signal::ctrl_c().await.context("waiting for ctrl-c")
    })?;
    tracing::info!("roxy shutting down");
    Ok(ExitCode::SUCCESS)
}
