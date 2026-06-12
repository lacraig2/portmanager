//! Network-change detection (v1: polling).
//!
//! quinn has no built-in watchdog: passive NAT-rebinds are handled by the
//! protocol, but an *interface* change (wifi -> ethernet, VPN up/down) leaves
//! the client's UDP socket bound to a dead source address and requires
//! [`quinn::Endpoint::rebind`]. We detect that by periodically asking the OS
//! routing table which source IP would be used to reach the agent: a UDP
//! `connect()` performs the route lookup without sending a single packet.
//!
//! v2 can swap the poll for netlink (`rtnetlink`) without touching callers.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::sync::watch;
use tracing::{debug, info, warn};

/// Poll interval for route checks. Cheap (one routing lookup, no packets).
pub const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Resolve which local source IP the OS would use to reach `target` right now.
/// Returns `None` when there is no route (offline, mid-roam).
pub fn source_ip_for(target: SocketAddr) -> Option<IpAddr> {
    let bind: SocketAddr = if target.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let sock = std::net::UdpSocket::bind(bind).ok()?;
    sock.connect(target).ok()?;
    sock.local_addr().ok().map(|a| a.ip())
}

/// Watch the route to the agent and `rebind()` the endpoint when the source IP
/// changes (active migration trigger). The QUIC connection itself survives the
/// rebind via path validation — that's the seamless-roaming path.
///
/// `target_rx` carries the current agent address (it changes after a
/// re-bootstrap). Runs until the channel closes.
pub async fn run(endpoint: quinn::Endpoint, mut target_rx: watch::Receiver<SocketAddr>) {
    let mut last_ip = source_ip_for(*target_rx.borrow());

    loop {
        let target = *target_rx.borrow_and_update();
        tokio::select! {
            _ = tokio::time::sleep(POLL_INTERVAL) => {}
            changed = target_rx.changed() => {
                if changed.is_err() {
                    debug!("netwatch: session ended");
                    return;
                }
                // Target moved (re-bootstrap); reset the baseline.
                last_ip = source_ip_for(*target_rx.borrow());
                continue;
            }
        }

        let now_ip = source_ip_for(target);
        match (&last_ip, &now_ip) {
            (Some(old), Some(new)) if old != new => {
                info!(%old, %new, "network path changed; migrating QUIC endpoint");
                match std::net::UdpSocket::bind(if target.is_ipv4() {
                    "0.0.0.0:0".parse::<SocketAddr>().unwrap()
                } else {
                    "[::]:0".parse::<SocketAddr>().unwrap()
                }) {
                    Ok(sock) => {
                        if let Err(e) = sock.set_nonblocking(true) {
                            warn!(error = %e, "rebind socket setup failed");
                        } else if let Err(e) = endpoint.rebind(sock) {
                            warn!(error = %e, "endpoint rebind failed");
                        } else {
                            info!("endpoint rebound; connection migrating");
                        }
                    }
                    Err(e) => warn!(error = %e, "could not bind fresh UDP socket"),
                }
                last_ip = now_ip;
            }
            (None, Some(new)) => {
                // Route came back (e.g. wifi reconnected on the same subnet).
                // Same source IP -> the existing socket still works and QUIC
                // retransmits on its own; just update the baseline.
                debug!(ip = %new, "route restored");
                last_ip = now_ip;
            }
            (Some(_), None) => {
                debug!("route lost (offline); waiting");
                last_ip = None;
            }
            _ => {}
        }
    }
}
