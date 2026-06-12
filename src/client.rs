//! Client-side local listeners. Each accepted TCP connection opens a QUIC bidi
//! stream to the agent, writes the target header, and splices.
//!
//! Listeners are decoupled from any single QUIC connection: they watch a shared
//! slot holding the *current* connection (`None` during an outage). The
//! listener itself stays bound across reconnects — that's the plan's "listeners
//! stay bound" invariant — while each accepted TCP conn grabs whatever
//! connection is live, waiting up to a short deadline during outages before
//! giving up (accept-then-RST policy).

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use quinn::Connection;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::forward::ForwardSpec;
use crate::proto::{self, StreamHeader};

/// How long an accepted local connection waits for a live agent connection
/// (e.g. mid-reconnect) before being dropped.
pub const ATTACH_DEADLINE: Duration = Duration::from_secs(10);

/// Shared slot holding the current agent connection (`None` while reconnecting).
pub type ConnSlot = watch::Receiver<Option<Connection>>;

/// Create a connection slot pair.
pub fn conn_slot(initial: Option<Connection>) -> (watch::Sender<Option<Connection>>, ConnSlot) {
    watch::channel(initial)
}

/// Bind the local listener for `forward` and start serving it against whatever
/// connection the slot currently holds.
///
/// Returns the actually-bound local address (useful when the spec requested
/// port 0) and the accept-loop task handle.
pub async fn bind_forward(
    slot: ConnSlot,
    forward: ForwardSpec,
) -> Result<(SocketAddr, JoinHandle<()>)> {
    let listener = TcpListener::bind((forward.local_addr, forward.local_port))
        .await
        .with_context(|| {
            format!(
                "binding local listener on {}:{}",
                forward.local_addr, forward.local_port
            )
        })?;
    let local = listener.local_addr().context("reading local listener addr")?;
    info!(
        %local,
        target = %format!("{}:{}", forward.remote_host, forward.remote_port),
        ns = %forward.ns.to_wire(),
        "forward up"
    );
    let handle = tokio::spawn(accept_loop(listener, slot, forward));
    Ok((local, handle))
}

/// Accept local connections forever, fanning each onto its own QUIC stream.
async fn accept_loop(listener: TcpListener, slot: ConnSlot, forward: ForwardSpec) {
    loop {
        match listener.accept().await {
            Ok((tcp, peer)) => {
                debug!(%peer, "local connection accepted");
                let slot = slot.clone();
                let forward = forward.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_one(slot, forward, tcp).await {
                        debug!(error = %e, "forward stream ended");
                    }
                });
            }
            Err(e) => {
                warn!(error = %e, "local accept failed");
                return;
            }
        }
    }
}

/// Open a stream for one accepted TCP connection and splice. If the session is
/// mid-reconnect, wait up to [`ATTACH_DEADLINE`] for a live connection; if a
/// stale connection fails at open, wait for a replacement within the same
/// deadline rather than failing immediately.
async fn serve_one(mut slot: ConnSlot, forward: ForwardSpec, tcp: TcpStream) -> Result<()> {
    let header = StreamHeader {
        ns: forward.ns.to_wire(),
        host: forward.remote_host.clone(),
        port: forward.remote_port,
    };

    let deadline = tokio::time::Instant::now() + ATTACH_DEADLINE;
    loop {
        // Wait (bounded) for a live connection.
        let conn = loop {
            if let Some(conn) = slot.borrow_and_update().clone() {
                break conn;
            }
            let timeout = tokio::time::sleep_until(deadline);
            tokio::select! {
                _ = timeout => anyhow::bail!("no agent connection within attach deadline"),
                changed = slot.changed() => {
                    changed.context("session ended")?;
                }
            }
        };

        // Try to open the stream; on failure the connection is stale/dying —
        // loop back and wait for the supervisor to install a fresh one.
        match conn.open_bi().await {
            Ok((mut send, recv)) => {
                header.write(&mut send).await.context("writing stream header")?;
                return proto::splice(tcp, send, recv).await.context("splicing");
            }
            Err(e) => {
                debug!(error = %e, "open_bi on stale connection; waiting for reconnect");
                let timeout = tokio::time::sleep_until(deadline);
                tokio::select! {
                    _ = timeout => anyhow::bail!("agent connection lost and not re-established in time"),
                    changed = slot.changed() => {
                        changed.context("session ended")?;
                    }
                }
            }
        }
    }
}
