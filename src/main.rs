//! portmanager binary entry point.
//!
//! `main` is sync on purpose: the agent role daemonizes (forks) after its
//! stdio handshake, which must happen before any tokio runtime exists.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Parser;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use portmanager::cli::{self, Cli, Command};
use portmanager::forward::ForwardSpec;
use portmanager::supervisor::{Status, Supervisor};
use portmanager::{agent, client, crypto};

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose);
    crypto::init();

    match cli.command {
        Some(Command::Agent(args)) => agent::run(
            &args.listen,
            Duration::from_secs(args.grace_secs),
            args.foreground,
        ),
        Some(Command::Add { .. })
        | Some(Command::Drop { .. })
        | Some(Command::List { .. })
        | Some(Command::Status { .. }) => {
            bail!("control-socket subcommands not yet implemented");
        }
        None => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("building tokio runtime")?;
            runtime.block_on(run_client(cli.run))
        }
    }
}

/// Default action: bootstrap an agent on the host and serve the forward set
/// under the never-give-up supervisor.
async fn run_client(args: cli::RunArgs) -> Result<()> {
    let host = args
        .host
        .context("no host given; usage: portmanager <host> <spec>...")?;

    let forwards = parse_specs(&args.specs)?;
    if forwards.is_empty() {
        bail!("no forwards given; pass at least one spec (e.g. 8888 or 192.168.4.2:8080->8080)");
    }

    let supervisor = Supervisor::start(host, "0.0.0.0:0".to_string())
        .await
        .map_err(|e| {
            e.context(
                "session bootstrap failed — note the remote must allow inbound UDP \
                 (not just SSH/22) for the QUIC channel",
            )
        })?;

    for forward in forwards {
        client::bind_forward(supervisor.slot.clone(), forward)
            .await
            .context("binding forward")?;
    }

    // Mosh-style status: announce transitions until Ctrl-C.
    let mut status = supervisor.status.clone();
    info!("session up — Ctrl-C to stop");
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("shutting down");
                supervisor.shutdown().await;
                return Ok(());
            }
            changed = status.changed() => {
                if changed.is_err() {
                    bail!("supervisor exited unexpectedly");
                }
                match &*status.borrow_and_update() {
                    Status::Connected => info!("[connected]"),
                    Status::Reconnecting { attempt } => {
                        warn!("[reconnecting — attempt {attempt}]");
                    }
                    Status::Bootstrapping => warn!("[re-bootstrapping over SSH]"),
                }
            }
        }
    }
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
    // Always log to stderr: stdout is reserved for the bootstrap handshake line.
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}
