//! Remote agent: accept QUIC connections, read each stream's target, dial it,
//! and splice. Runs on the remote host (launched over SSH in the full flow).
//!
//! Namespace dialing (`netns.rs`) is layered on later; for now a non-empty
//! namespace selector is rejected with a clear error.

use std::net::SocketAddr;

use anyhow::{Context, Result};
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use tokio::io::BufReader;
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::crypto::{self, Identity};
use crate::handshake::{Hello, Ready, SessionId};
use crate::proto::{self, StreamHeader};
use crate::transport;

/// Agent entry point (the `agent` subcommand, launched over SSH).
///
/// Reads the [`Hello`] from stdin, binds the QUIC listener pinned to the
/// client's fingerprint, writes [`Ready`] to stdout, then serves until closed.
pub async fn run(listen: &str) -> Result<()> {
    let mut stdin = BufReader::new(tokio::io::stdin());
    let hello = Hello::read(&mut stdin)
        .await
        .context("reading bootstrap handshake from stdin")?;

    let identity = Identity::generate()?;
    let session_id = SessionId::random()?;
    // The token authorizes SSH-less re-attach; retained for the resilience layer.
    let _token = hello.token;

    let bind: SocketAddr = listen.parse().context("parsing --listen address")?;
    let server_cfg = crypto::server_config(&identity, hello.client_fp, &crypto::Timing::default())?;
    let endpoint = transport::server_endpoint(server_cfg, bind)?;
    let local = endpoint.local_addr().context("reading bound UDP address")?;

    let ready = Ready {
        udp_port: local.port(),
        agent_fp: identity.fingerprint,
        session_id,
    };
    let mut stdout = tokio::io::stdout();
    ready
        .write(&mut stdout)
        .await
        .context("writing ready handshake to stdout")?;

    serve(endpoint).await
}

/// Accept connections on `endpoint` until it is closed, serving each one.
pub async fn serve(endpoint: Endpoint) -> Result<()> {
    info!(addr = ?endpoint.local_addr().ok(), "agent listening");
    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    if let Err(e) = handle_connection(conn).await {
                        debug!(error = %e, "connection closed");
                    }
                }
                Err(e) => warn!(error = %e, "handshake failed"),
            }
        });
    }
    Ok(())
}

/// Serve all bidi streams on one authenticated connection.
async fn handle_connection(conn: Connection) -> Result<()> {
    let peer = conn.remote_address();
    info!(%peer, "client connected");
    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(pair) => pair,
            Err(e) => {
                debug!(%peer, error = %e, "connection ended");
                return Ok(());
            }
        };
        tokio::spawn(async move {
            if let Err(e) = handle_stream(send, recv).await {
                debug!(error = %e, "stream error");
            }
        });
    }
}

/// Read the header, dial the target, and splice.
async fn handle_stream(mut send: SendStream, mut recv: RecvStream) -> Result<()> {
    let header = StreamHeader::read(&mut recv)
        .await
        .context("reading stream header")?;

    if !header.ns.is_empty() {
        // Rootless namespace dialing arrives in a later step; fail clearly.
        let _ = send.reset(quinn::VarInt::from_u32(1));
        anyhow::bail!("namespace dialing not yet supported (ns={})", header.ns);
    }

    let target = format!("{}:{}", header.host, header.port);
    debug!(%target, "dialing target");
    let tcp = match TcpStream::connect(&target).await {
        Ok(s) => s,
        Err(e) => {
            let _ = send.reset(quinn::VarInt::from_u32(2));
            return Err(e).context(format!("connecting to {target}"));
        }
    };

    proto::splice(tcp, send, recv).await.context("splicing")?;
    Ok(())
}
