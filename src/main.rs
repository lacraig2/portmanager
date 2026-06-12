//! portmanager — resilient QUIC port forwarder with SSH auto-bootstrap.

mod cli;
mod crypto;
mod error;
mod forward;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::cli::{Cli, Command};
use crate::forward::ForwardSpec;

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose);
    crypto::init();

    match cli.command {
        Some(Command::Agent(_args)) => {
            anyhow::bail!("agent role not yet implemented");
        }
        Some(Command::Add { .. })
        | Some(Command::Drop { .. })
        | Some(Command::List { .. })
        | Some(Command::Status { .. }) => {
            anyhow::bail!("control-socket subcommands not yet implemented");
        }
        None => run_client(cli.run),
    }
}

/// Default action: parse the forward set for a host and (eventually) start a session.
fn run_client(args: cli::RunArgs) -> Result<()> {
    let host = args
        .host
        .context("no host given; usage: portmanager <host> <spec>...")?;

    let forwards = parse_specs(&args.specs)?;
    if forwards.is_empty() && args.profile.is_none() {
        anyhow::bail!("no forwards given; pass at least one spec or --profile");
    }

    info!(%host, count = forwards.len(), "parsed forward set");
    for f in &forwards {
        let ns = if f.ns.is_host() {
            String::new()
        } else {
            format!("{:?}@", f.ns)
        };
        info!(
            "  {ns}{}:{} -> {}:{}",
            f.remote_host, f.remote_port, f.local_addr, f.local_port
        );
    }

    anyhow::bail!("session start not yet implemented (parsing works)");
}

/// Parse a list of forward-spec strings, surfacing the offending spec on error.
fn parse_specs(specs: &[String]) -> Result<Vec<ForwardSpec>> {
    specs
        .iter()
        .map(|s| {
            s.parse::<ForwardSpec>()
                .with_context(|| format!("invalid forward spec {s:?}"))
        })
        .collect()
}

fn init_tracing(verbose: u8) {
    let default = match verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("portmanager={default}")));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}
