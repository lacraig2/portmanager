//! portmanager binary entry point.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Parser;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use portmanager::cli::{self, Cli, Command};
use portmanager::forward::ForwardSpec;
use portmanager::{agent, bootstrap, client, crypto, transport};

/// How long to wait for the QUIC handshake before assuming inbound UDP is blocked.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose);
    crypto::init();

    match cli.command {
        Some(Command::Agent(args)) => agent::run(&args.listen).await,
        Some(Command::Add { .. })
        | Some(Command::Drop { .. })
        | Some(Command::List { .. })
        | Some(Command::Status { .. }) => {
            bail!("control-socket subcommands not yet implemented");
        }
        None => run_client(cli.run).await,
    }
}

/// Default action: bootstrap an agent on the host and serve the forward set.
async fn run_client(args: cli::RunArgs) -> Result<()> {
    let host = args
        .host
        .context("no host given; usage: portmanager <host> <spec>...")?;

    let forwards = parse_specs(&args.specs)?;
    if forwards.is_empty() {
        bail!("no forwards given; pass at least one spec (e.g. 8888 or 192.168.4.2:8080->8080)");
    }

    info!(%host, count = forwards.len(), "bootstrapping agent over SSH");
    let session = bootstrap::bootstrap(&host, "0.0.0.0:0")
        .await
        .context("bootstrapping remote agent")?;

    let client_cfg =
        crypto::client_config(&session.client_id, session.agent_fp, &bootstrap::default_timing())?;
    let endpoint = transport::client_endpoint(client_cfg)?;

    let addr = tokio::net::lookup_host(&session.quic_target)
        .await
        .with_context(|| format!("resolving {}", session.quic_target))?
        .next()
        .with_context(|| format!("no address for {}", session.quic_target))?;

    let conn = match tokio::time::timeout(CONNECT_TIMEOUT, transport::connect(&endpoint, addr)).await
    {
        Ok(Ok(conn)) => conn,
        Ok(Err(e)) => return Err(e).context("connecting to agent"),
        Err(_) => bail!(
            "QUIC handshake to {} timed out — the remote likely blocks inbound UDP on that port. \
             portmanager needs inbound UDP (not just SSH/22) to reach the agent.",
            session.quic_target
        ),
    };
    info!(target = %session.quic_target, "connected to agent");

    for forward in forwards {
        client::bind_forward(conn.clone(), forward)
            .await
            .context("binding forward")?;
    }

    info!("session up — Ctrl-C to stop");
    tokio::select! {
        reason = conn.closed() => warn!(%reason, "agent connection closed"),
        _ = tokio::signal::ctrl_c() => info!("shutting down"),
    }
    // Dropping the session kills the SSH control process (kill_on_drop).
    drop(session);
    Ok(())
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
