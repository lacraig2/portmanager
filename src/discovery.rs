//! Listening-port discovery: the VSCode "port just appears" feature.
//!
//! The client opens one dedicated QUIC stream (target host [`DISCOVERY_HOST`])
//! per connection epoch and sends the list of namespaces to watch. The agent
//! then periodically scans those namespaces' TCP tables and pushes JSON
//! snapshot lines. The client diffs snapshots against its auto-forward rules
//! and remembered assignments, binding matching forwards via the shared
//! [`ForwardSet`] core.
//!
//! Scanning is setns-free: `/proc/<pid>/net/tcp{,6}` shows the *netns of that
//! PID*, so container listeners are read directly (via `procfs`).

use std::collections::BTreeSet;
use std::sync::Arc;

use anyhow::{Context, Result};
use quinn::{RecvStream, SendStream};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::{debug, info, warn};

use crate::client::{ConnSlot, ForwardSet};
use crate::config::{self, AutoForwardRule, HostState};
use crate::forward::{ForwardSpec, NsSpec};
use crate::netns;

/// Reserved stream-header host marking a discovery stream.
pub const DISCOVERY_HOST: &str = "@discovery";
/// Scan/push interval on the agent.
const SCAN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3);

/// One discovered listener.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Listener {
    /// Namespace wire form (`""` = host).
    pub ns: String,
    /// Address the socket is bound to inside that namespace.
    pub ip: String,
    pub port: u16,
}

// ---------------------------------------------------------------------------
// Agent side
// ---------------------------------------------------------------------------

/// Serve one discovery stream: read the watch list, then push snapshots until
/// the stream closes.
pub async fn serve(mut send: SendStream, recv: RecvStream) -> Result<()> {
    let mut reader = BufReader::new(recv);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .context("reading discovery watch list")?;
    let namespaces: Vec<NsSpec> = line
        .split_whitespace()
        .filter_map(|tok| {
            let wire = if tok == "host" { "" } else { tok };
            NsSpec::from_wire(wire).ok()
        })
        .collect();
    info!(count = namespaces.len(), "discovery stream up");

    loop {
        let snapshot = scan_all(&namespaces).await;
        let mut payload = serde_json::to_string(&snapshot).context("encoding snapshot")?;
        payload.push('\n');
        if send.write_all(payload.as_bytes()).await.is_err() {
            // Client gone (reconnect epoch); it will reopen the stream.
            return Ok(());
        }
        tokio::time::sleep(SCAN_INTERVAL).await;
    }
}

/// Scan every watched namespace, skipping ones that error (container down).
async fn scan_all(namespaces: &[NsSpec]) -> Vec<Listener> {
    let mut out = BTreeSet::new();
    for ns in namespaces {
        let ns = ns.clone();
        let scanned = tokio::task::spawn_blocking(move || scan_one(&ns)).await;
        match scanned {
            Ok(Ok(found)) => out.extend(found),
            Ok(Err(e)) => debug!(error = %e, "namespace scan failed"),
            Err(e) => warn!(error = %e, "scan task panicked"),
        }
    }
    out.into_iter().collect()
}

/// List LISTEN sockets in one namespace via /proc (no setns).
fn scan_one(ns: &NsSpec) -> Result<Vec<Listener>> {
    use procfs::net::TcpState;
    let wire = ns.to_wire();

    let (tcp, tcp6) = match netns::resolve_pid(ns)? {
        None => (procfs::net::tcp(), procfs::net::tcp6()),
        Some(pid) => {
            let proc = procfs::process::Process::new(pid)
                .with_context(|| format!("opening /proc/{pid}"))?;
            (proc.tcp(), proc.tcp6())
        }
    };

    let mut out = Vec::new();
    for entry in tcp.into_iter().flatten().chain(tcp6.into_iter().flatten()) {
        if entry.state == TcpState::Listen {
            out.push(Listener {
                ns: wire.clone(),
                ip: entry.local_address.ip().to_string(),
                port: entry.local_address.port(),
            });
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

/// Run discovery for the session: (re)open the discovery stream on every
/// connection epoch, match pushed listeners against the rules, and auto-bind
/// via the shared forward core with stable assignments.
pub async fn watch(
    host: String,
    mut slot: ConnSlot,
    forwards: Arc<ForwardSet>,
    rules: Vec<AutoForwardRule>,
) {
    if rules.is_empty() {
        debug!("no autoforward rules; discovery not started");
        return;
    }
    // Watch list = the union of namespaces the rules name.
    let watch_list: String = {
        let mut set = BTreeSet::new();
        for r in &rules {
            set.insert(if r.ns.is_empty() {
                "host".to_string()
            } else {
                r.ns.clone()
            });
        }
        set.into_iter().collect::<Vec<_>>().join(" ")
    };

    loop {
        // Wait for a live connection epoch.
        let conn = loop {
            if let Some(conn) = slot.borrow_and_update().clone() {
                break conn;
            }
            if slot.changed().await.is_err() {
                return; // session over
            }
        };

        match run_epoch(&host, &conn, &watch_list, &forwards, &rules).await {
            Ok(()) => debug!("discovery epoch ended"),
            Err(e) => debug!(error = %e, "discovery epoch error"),
        }

        // Connection died; wait for the slot to change before reopening.
        if slot.changed().await.is_err() {
            return;
        }
    }
}

/// One connection epoch: open the stream, process snapshots until it dies.
async fn run_epoch(
    host: &str,
    conn: &quinn::Connection,
    watch_list: &str,
    forwards: &Arc<ForwardSet>,
    rules: &[AutoForwardRule],
) -> Result<()> {
    let (mut send, recv) = conn.open_bi().await.context("opening discovery stream")?;
    crate::proto::StreamHeader {
        ns: String::new(),
        host: DISCOVERY_HOST.to_string(),
        port: 0,
    }
    .write(&mut send)
    .await
    .context("writing discovery header")?;
    send.write_all(format!("{watch_list}\n").as_bytes())
        .await
        .context("sending watch list")?;

    let mut lines = BufReader::new(recv).lines();
    while let Some(line) = lines.next_line().await.context("reading snapshot")? {
        let snapshot: Vec<Listener> = match serde_json::from_str(&line) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "bad discovery snapshot");
                continue;
            }
        };
        for l in snapshot {
            if let Err(e) = consider(host, &l, forwards, rules).await {
                debug!(error = %e, ns = %l.ns, port = l.port, "auto-forward failed");
            }
        }
    }
    Ok(())
}

/// Auto-bind one discovered listener if a rule matches and it isn't already
/// forwarded. Stable assignments: a remote port keeps its local port across
/// sessions; collisions fall back to an ephemeral port, then persist.
async fn consider(
    host: &str,
    l: &Listener,
    forwards: &Arc<ForwardSet>,
    rules: &[AutoForwardRule],
) -> Result<()> {
    let Some(rule) = rules.iter().find(|r| r.matches(&l.ns, l.port)) else {
        return Ok(());
    };
    if forwards.targets(&l.ns, l.port).await {
        return Ok(()); // already forwarded (manually or by a previous snapshot)
    }

    // Dial loopback inside the namespace for wildcard binds.
    let remote_host = match l.ip.as_str() {
        "0.0.0.0" | "::" => "127.0.0.1".to_string(),
        ip => ip.to_string(),
    };

    let key = HostState::assignment_key(&l.ns, l.port);
    let state = {
        let host = host.to_string();
        tokio::task::spawn_blocking(move || config::load_state(&host)).await??
    };
    let preferred = state
        .assignments
        .get(&key)
        .copied()
        .or(match rule.local.as_str() {
            "same" => Some(l.port),
            _ => None,
        });

    let ns = NsSpec::from_wire(&l.ns).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut spec = ForwardSpec {
        ns,
        remote_host,
        remote_port: l.port,
        local_addr: std::net::Ipv4Addr::LOCALHOST.into(),
        local_port: preferred.unwrap_or(0),
    };

    // Preferred port may collide; fall back to ephemeral.
    let local = match forwards.add(spec.clone()).await {
        Ok(local) => local,
        Err(_) if spec.local_port != 0 => {
            spec.local_port = 0;
            forwards.add(spec.clone()).await?
        }
        Err(e) => return Err(e),
    };
    info!(
        ns = %l.ns, remote = l.port, local = %local,
        "auto-forward bound (rule {:?})", rule.ports
    );

    // Remember the assignment for next time.
    let host = host.to_string();
    let port = local.port();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut state = config::load_state(&host)?;
        state.assignments.insert(key, port);
        config::save_state(&host, &state)
    })
    .await
    .context("assignment persistence task")?
    .unwrap_or_else(|e| warn!(error = %e, "assignment persistence failed"));
    Ok(())
}
