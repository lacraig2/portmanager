//! Client-side local listeners. Each accepted TCP connection opens a QUIC bidi
//! stream to the agent, writes the target header, and splices.
//!
//! This is the dynamic-forward primitive: `bind_forward` brings one forward up
//! on an existing connection and returns its task handle, so the control socket
//! and auto-detect (later steps) can add/drop forwards live.

use std::net::SocketAddr;

use anyhow::{Context, Result};
use quinn::Connection;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::forward::ForwardSpec;
use crate::proto::{self, StreamHeader};

/// Bind the local listener for `forward` and start serving it on `conn`.
///
/// Returns the actually-bound local address (useful when the spec requested port
/// 0) and the accept-loop task handle.
pub async fn bind_forward(
    conn: Connection,
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
    let handle = tokio::spawn(accept_loop(listener, conn, forward));
    Ok((local, handle))
}

/// Accept local connections forever, fanning each onto its own QUIC stream.
async fn accept_loop(listener: TcpListener, conn: Connection, forward: ForwardSpec) {
    loop {
        match listener.accept().await {
            Ok((tcp, peer)) => {
                debug!(%peer, "local connection accepted");
                let conn = conn.clone();
                let forward = forward.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_one(conn, forward, tcp).await {
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

/// Open a stream for one accepted TCP connection and splice it.
async fn serve_one(conn: Connection, forward: ForwardSpec, tcp: TcpStream) -> Result<()> {
    let (mut send, recv) = conn.open_bi().await.context("opening QUIC stream")?;
    let header = StreamHeader {
        ns: forward.ns.to_wire(),
        host: forward.remote_host.clone(),
        port: forward.remote_port,
    };
    header.write(&mut send).await.context("writing stream header")?;
    proto::splice(tcp, send, recv).await.context("splicing")?;
    Ok(())
}
