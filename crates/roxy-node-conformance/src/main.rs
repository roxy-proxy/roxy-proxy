//! `roxy-node-conformance check` runs the harness against a control plane;
//! `serve` runs the reference server; `self-test` runs one against the other.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};
use roxy_node_conformance::harness::{self, AdminUrlHook, CommandHook, Hook};
use roxy_node_conformance::reference;

#[derive(Parser)]
#[command(
    name = "roxy-node-conformance",
    about = "Conformance harness for the roxy node protocol"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run every check against a server.
    Check {
        /// Control plane URL, for example `https://cp.example:8443`
        #[arg(long, env = "ROXY_CONFORMANCE_URL")]
        url: String,
        /// PEM bundle to verify the server with (default: system roots)
        #[arg(long, env = "ROXY_CONFORMANCE_CA_BUNDLE")]
        ca_bundle: Option<std::path::PathBuf>,
        /// Single-use enrolment tokens; five are needed
        #[arg(
            long = "enrol-token",
            env = "ROXY_CONFORMANCE_TOKENS",
            value_delimiter = ','
        )]
        enrol_tokens: Vec<String>,
        /// Command run as `<hook> <action> <node_id> [<argument>]`
        #[arg(long, env = "ROXY_CONFORMANCE_HOOK", conflicts_with = "admin_url")]
        hook: Option<String>,
        /// URL that takes `{"action","node_id","argument"}` by POST
        #[arg(long, env = "ROXY_CONFORMANCE_ADMIN_URL")]
        admin_url: Option<String>,
    },
    /// Run the in-memory reference server and print how to reach it.
    Serve {
        #[arg(long, default_value = "127.0.0.1:0")]
        bind: SocketAddr,
        #[arg(long, default_value = "127.0.0.1:0")]
        admin_bind: SocketAddr,
        /// How many enrolment tokens to mint
        #[arg(long, default_value_t = 5)]
        tokens: usize,
    },
    /// Run the harness against the reference server.
    SelfTest,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().cmd {
        Cmd::Check {
            url,
            ca_bundle,
            enrol_tokens,
            hook,
            admin_url,
        } => {
            let ca_bundle_pem = match ca_bundle {
                Some(p) => Some(
                    std::fs::read_to_string(&p).with_context(|| format!("read {}", p.display()))?,
                ),
                None => None,
            };
            let hook: Option<Arc<dyn Hook>> = match (hook, admin_url) {
                (Some(cmd), _) => Some(Arc::new(CommandHook(cmd))),
                (None, Some(url)) => Some(Arc::new(AdminUrlHook::new(&url)?)),
                (None, None) => None,
            };
            let report = harness::run(harness::Options {
                url,
                ca_bundle_pem,
                tokens: enrol_tokens,
                hook,
            })
            .await?;
            report.write(std::io::stdout().lock())?;
            if !report.ok() {
                std::process::exit(1);
            }
        }
        Cmd::Serve {
            bind,
            admin_bind,
            tokens,
        } => {
            let server = reference::Server::start(reference::Options {
                bind,
                admin_bind,
                tokens,
                ..Default::default()
            })
            .await?;
            let info = serde_json::json!({
                "url": server.url(),
                "admin_url": server.admin_url(),
                "ca_bundle_pem": server.ca_pem(),
                "tokens": server.tokens(),
            });
            println!("{}", serde_json::to_string_pretty(&info)?);
            tokio::select! {
                () = server.run() => {},
                _ = tokio::signal::ctrl_c() => {},
            }
        }
        Cmd::SelfTest => {
            let server = reference::Server::start(reference::Options::default()).await?;
            let report = harness::run(harness::Options {
                url: server.url().to_owned(),
                ca_bundle_pem: Some(server.ca_pem().to_owned()),
                tokens: server.tokens().to_vec(),
                hook: Some(server.hook()),
            })
            .await?;
            report.write(std::io::stdout().lock())?;
            if !report.ok() {
                std::process::exit(1);
            }
        }
    }
    Ok(())
}
