//! quinn endpoint construction and connection establishment.
//!
//! Network-change driven `Endpoint::rebind()` (active migration) lives in the
//! resilience layer; this module just builds endpoints and dials.

use std::net::{Ipv4Addr, SocketAddr};

use anyhow::{Context, Result};
use quinn::{Connection, Endpoint};

/// Server name presented on `connect`. Irrelevant to auth (we pin fingerprints),
/// but must be a syntactically valid name for the TLS layer.
const PINNED_SERVER_NAME: &str = "portmanager";

/// Build a client endpoint bound to an ephemeral local UDP port, using `cfg` as
/// the default outgoing connection config.
pub fn client_endpoint(cfg: quinn::ClientConfig) -> Result<Endpoint> {
    let mut endpoint = client_endpoint_bare()?;
    endpoint.set_default_client_config(cfg);
    Ok(endpoint)
}

/// Build a client endpoint with no default config; callers pass a config per
/// connect via [`connect_with`]. Used by the supervisor, whose pinned agent
/// fingerprint (and thus config) changes across re-bootstraps.
pub fn client_endpoint_bare() -> Result<Endpoint> {
    let bind: SocketAddr = (Ipv4Addr::UNSPECIFIED, 0).into();
    Endpoint::client(bind).context("binding client UDP socket")
}

/// Dial `addr` with an explicit per-connection config.
pub async fn connect_with(
    endpoint: &Endpoint,
    cfg: quinn::ClientConfig,
    addr: SocketAddr,
) -> Result<Connection> {
    let connecting = endpoint
        .connect_with(cfg, addr, PINNED_SERVER_NAME)
        .context("initiating QUIC connection")?;
    connecting.await.context("QUIC handshake failed")
}

/// Build a server endpoint listening for QUIC connections on `bind`.
pub fn server_endpoint(cfg: quinn::ServerConfig, bind: SocketAddr) -> Result<Endpoint> {
    Endpoint::server(cfg, bind).context("binding agent QUIC listener")
}

/// Dial `addr` over the given endpoint and complete the QUIC/TLS handshake.
pub async fn connect(endpoint: &Endpoint, addr: SocketAddr) -> Result<Connection> {
    let connecting = endpoint
        .connect(addr, PINNED_SERVER_NAME)
        .context("initiating QUIC connection")?;
    connecting.await.context("QUIC handshake failed")
}
