//! `roxy policy render` and `roxy policy test`: compose policy layers onto
//! a base with `roxy-policy`, then check the result as a node would and
//! run each layer's tests against it.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context as _, bail};
use roxy_policy::{Base, Expect, Layer, Rendered, Test};
use roxy_rules::{Policy, Reads};

use crate::config::{Compiled, Config, describe_parse_error};
use crate::ruletest::{self, TestRequest};

/// The files of one render: the base and the layers, first layer outermost.
#[derive(Debug, Clone)]
pub struct Inputs {
    pub base: PathBuf,
    pub layers: Vec<PathBuf>,
}

/// Renders the stack and validates the output exactly as `roxy check`
/// parses and compiles a config. The file-backed checks (`check` also
/// loads address lists and compiles addons) are left to the node: a render
/// may run where those files do not exist.
pub fn render(inputs: &Inputs) -> anyhow::Result<(Rendered, Config, Compiled)> {
    let base_text = read(&inputs.base)?;
    // The base is a config minus the layer sections, so the config parser
    // gives the best structural errors, against the base file.
    Config::from_yaml(&base_text)
        .map_err(|e| anyhow::anyhow!(describe_parse_error(&base_text, &e)))
        .with_context(|| format!("parsing {}", inputs.base.display()))?;
    let base = Base::parse(&base_text).with_context(|| inputs.base.display().to_string())?;
    let layers = inputs
        .layers
        .iter()
        .map(|p| {
            let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or_default();
            Layer::parse(&read(p)?, stem).with_context(|| p.display().to_string())
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let rendered = roxy_policy::render(&base, &layers)?;
    let config = Config::from_yaml(&rendered.yaml)
        .map_err(|e| anyhow::anyhow!(describe_parse_error(&rendered.yaml, &e)))
        .context("the rendered config does not parse")?;
    let compiled = config.validate().map_err(|diags| {
        let lines: Vec<String> = diags.iter().map(|d| format!("  {d}")).collect();
        anyhow::anyhow!("the rendered config is invalid:\n{}", lines.join("\n"))
    })?;
    Ok((rendered, config, compiled))
}

fn read(path: &Path) -> anyhow::Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
}

/// How the layers' tests fared against the composed policy.
#[derive(Debug, Default)]
pub struct Verdict {
    /// Deny tests that did not deny, and tests that could not run: the
    /// composed policy lets through something a layer meant to stop.
    pub failures: Vec<String>,
    /// Allow tests that did not allow: a layer narrowed the policy, which
    /// layers are entitled to do.
    pub warnings: Vec<String>,
}

/// Runs `tests` against the composed policy with the dry-run machinery of
/// `roxy rule test`.
pub fn run_tests(config: &Config, policy: &Policy, tests: &[Test]) -> Verdict {
    let mut verdict = Verdict::default();
    for t in tests {
        let label = t.label();
        let mut req = TestRequest::new(&t.method, &t.url);
        req.headers.clone_from(&t.headers);
        req.body.clone_from(&t.body);
        if let Some(ip) = t.client_ip {
            req.client_ip = ip;
        }
        req.metrics = t
            .metrics
            .iter()
            .map(|(id, v)| (id.clone(), Some(*v)))
            .collect();
        req.state.clone_from(&t.state);
        req.tags.clone_from(&t.tags);
        let (view, _) = match ruletest::build_view(config, &req) {
            Ok(v) => v,
            Err(e) => {
                verdict.failures.push(format!("{label}: cannot run: {e}"));
                continue;
            }
        };
        let mut run = ruletest::run(policy, &view, &req.tags, Reads::NONE);
        if matches!(
            ruletest::address_check(config, &view, &run.head),
            Some(Err(_))
        ) {
            ruletest::apply_address_denial(&mut run.head);
            run.watching = None;
        }
        let decision = run.decision();
        let rule = run.terminal_rule();
        let decided = match t.expect {
            Expect::Allow => decision.is_allow(),
            Expect::Deny => decision.is_deny(),
        };
        let right_rule = t.rule.as_deref().is_none_or(|want| rule == want);
        if decided && right_rule {
            continue;
        }
        let want_rule = t
            .rule
            .as_deref()
            .map(|r| format!(" by {r}"))
            .unwrap_or_default();
        let message = format!(
            "{label}: expected {}{want_rule}, got {decision} (rule {rule})",
            t.expect
        );
        match t.expect {
            Expect::Deny => verdict.failures.push(message),
            Expect::Allow => verdict.warnings.push(message),
        }
    }
    verdict
}

/// Renders, runs the tests, and prints the verdict. Returns the render only
/// when no test failed.
fn render_and_test(inputs: &Inputs) -> anyhow::Result<(Rendered, Verdict)> {
    let (rendered, config, compiled) = render(inputs)?;
    let verdict = run_tests(&config, &compiled.policy, &rendered.tests);
    for w in &verdict.warnings {
        eprintln!("roxy policy: warning: {w}");
    }
    for f in &verdict.failures {
        eprintln!("roxy policy: error: {f}");
    }
    if !verdict.failures.is_empty() {
        bail!(
            "{} test(s) failed ({} ran)",
            verdict.failures.len(),
            rendered.tests.len()
        );
    }
    Ok((rendered, verdict))
}

/// `roxy policy render`: writes the rendered config to `output` (stdout
/// when `None`) once every layer's tests pass.
pub fn render_command(
    inputs: &Inputs,
    output: Option<&Path>,
    print_hash: bool,
) -> anyhow::Result<ExitCode> {
    let (rendered, _) = render_and_test(inputs)?;
    match output {
        Some(path) => {
            std::fs::write(path, &rendered.yaml)
                .with_context(|| format!("writing {}", path.display()))?;
            if print_hash {
                println!("{}", rendered.hash);
            }
        }
        None => print!("{}", rendered.yaml),
    }
    Ok(ExitCode::SUCCESS)
}

/// `roxy policy test`: renders and runs the tests without writing anything.
pub fn test_command(inputs: &Inputs) -> anyhow::Result<ExitCode> {
    let (rendered, verdict) = render_and_test(inputs)?;
    println!(
        "{} test(s) ran, {} warning(s); inputs {}",
        rendered.tests.len(),
        verdict.warnings.len(),
        rendered.hash
    );
    Ok(ExitCode::SUCCESS)
}
