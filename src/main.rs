//! portmanager binary entry point.
//!
//! `main` is sync on purpose: the agent role daemonizes (forks) after its
//! stdio handshake, which must happen before any tokio runtime exists.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Parser;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use portmanager::cli::{self, Cli, Command};
use portmanager::client::ForwardSet;
use portmanager::control::{self, Request, Response};
use portmanager::forward::ForwardSpec;
use portmanager::supervisor::{Status, Supervisor};
use portmanager::{agent, config, crypto, discovery, netns};

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
        Some(Command::NsHelper) => netns::run_helper(),
        Some(cmd) => block_on(run_control_command(cmd)),
        None => block_on(run_client(cli.run)),
    }
}

fn block_on<F: std::future::Future<Output = Result<()>>>(fut: F) -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?
        .block_on(fut)
}

/// `add`/`drop`/`list`/`status`: talk to the running session's control socket.
async fn run_control_command(cmd: Command) -> Result<()> {
    let (host, requests) = match cmd {
        Command::Add { host, specs } => {
            if specs.is_empty() {
                bail!("add: pass at least one forward spec");
            }
            // Validate locally before bothering the session.
            for s in &specs {
                s.parse::<ForwardSpec>()
                    .map_err(|e| anyhow::anyhow!("invalid forward spec {s:?}: {e}"))?;
            }
            (
                host,
                specs
                    .into_iter()
                    .map(|spec| Request::Add { spec })
                    .collect::<Vec<_>>(),
            )
        }
        Command::Drop { host, specs } => {
            if specs.is_empty() {
                bail!("drop: pass at least one forward spec or local port");
            }
            (
                host,
                specs
                    .into_iter()
                    .map(|spec| Request::Drop { spec })
                    .collect(),
            )
        }
        Command::List { host } => (host, vec![Request::List]),
        Command::Status { host } => (host, vec![Request::Status]),
        Command::Agent(_) | Command::NsHelper => unreachable!("handled in main"),
    };

    let mut failed = false;
    for req in &requests {
        match control::request(&host, req).await? {
            Response::Ok { message } => println!("{message}"),
            Response::Forwards { entries } => print_entries(&entries),
            Response::StatusIs { state, entries } => {
                println!("session: {state}");
                print_entries(&entries);
            }
            Response::Error { message } => {
                eprintln!("error: {message}");
                failed = true;
            }
        }
    }
    if failed {
        bail!("one or more control requests failed");
    }
    Ok(())
}

fn print_entries(entries: &[control::ForwardEntry]) {
    if entries.is_empty() {
        println!("(no forwards)");
        return;
    }
    for e in entries {
        println!("{:<24} {}", e.local, e.spec);
    }
}

/// Default action: bootstrap an agent on the host and serve the forward set
/// under the never-give-up supervisor, with control socket + discovery.
async fn run_client(args: cli::RunArgs) -> Result<()> {
    // Resolve host, initial forwards, rules, and the persistence target from
    // either a named profile or the per-host remembered state.
    let (host, mut forwards, rules, persist) = if let Some(name) = &args.profile {
        let config = tokio::task::spawn_blocking(config::load_config).await??;
        let profile = config
            .profiles
            .get(name)
            .with_context(|| format!("no profile {name:?} in config.toml"))?;
        let host = args.host.clone().unwrap_or_else(|| profile.host.clone());
        if host.is_empty() {
            bail!("profile {name:?} has no host and none was given on the CLI");
        }
        let mut forwards =
            parse_specs(&profile.forwards).with_context(|| format!("in profile {name:?}"))?;
        forwards.extend(parse_specs(&args.specs)?);
        (
            host,
            forwards,
            profile.autoforward.clone(),
            config::PersistTarget::Profile { name: name.clone() },
        )
    } else {
        let host = args
            .host
            .clone()
            .context("no host given; usage: portmanager <host> <spec>...")?;
        let state = {
            let host = host.clone();
            tokio::task::spawn_blocking(move || config::load_state(&host)).await??
        };
        let mut forwards = parse_specs(&args.specs)?;
        for remembered in state.parsed_forwards() {
            if !forwards
                .iter()
                .any(|f| f.local_port == remembered.local_port)
            {
                forwards.push(remembered);
            }
        }
        (
            host.clone(),
            forwards,
            state.autoforward,
            config::PersistTarget::HostState { host },
        )
    };

    // Dedup by local port (CLI specs win over profile/state entries).
    {
        let mut seen = std::collections::HashSet::new();
        forwards.retain(|f| seen.insert(f.local_port));
    }
    if forwards.is_empty() && rules.is_empty() {
        bail!(
            "no forwards given and none remembered for {host:?}; pass at least one spec \
             (e.g. 8888 or 192.168.4.2:8080->8080)"
        );
    }

    let supervisor = Supervisor::start(host.clone(), "0.0.0.0:0".to_string())
        .await
        .map_err(|e| {
            e.context(
                "session bootstrap failed — note the remote must allow inbound UDP \
                 (not just SSH/22) for the QUIC channel",
            )
        })?;

    let forward_set = Arc::new(ForwardSet::new(supervisor.slot.clone()));
    for forward in forwards {
        forward_set.add(forward).await.context("binding forward")?;
    }

    // Control socket: live add/drop/list/status.
    let control_task = tokio::spawn(control::serve(control::ControlCtx {
        host: host.clone(),
        forwards: forward_set.clone(),
        status: supervisor.status.clone(),
        persist,
    }));

    // Discovery: auto-forward rule matching (no-op without rules).
    tokio::spawn(discovery::watch(
        host.clone(),
        supervisor.slot.clone(),
        forward_set.clone(),
        rules,
    ));

    // Mosh-style status: announce transitions until Ctrl-C.
    let mut status = supervisor.status.clone();
    info!("session up — Ctrl-C to stop");
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("shutting down");
                control_task.abort();
                control::cleanup(&host);
                supervisor.shutdown().await;
                return Ok(());
            }
            changed = status.changed() => {
                if changed.is_err() {
                    control::cleanup(&host);
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
