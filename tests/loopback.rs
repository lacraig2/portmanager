//! End-to-end loopback test: agent + client in-process over real QUIC on
//! localhost (no SSH), forwarding to a local echo server. Asserts a large
//! transfer is byte-exact through the tunnel.

use std::net::{Ipv4Addr, SocketAddr};

use portmanager::crypto::{self, Identity, Timing};
use portmanager::forward::{ForwardSpec, NsSpec};
use portmanager::{agent, client, transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A trivial echo server; returns its bound address.
async fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = sock.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn forwards_bytes_end_to_end() {
    crypto::init();

    // Two ephemeral identities, cross-pinned (stands in for the SSH fingerprint swap).
    let client_id = Identity::generate().unwrap();
    let agent_id = Identity::generate().unwrap();
    let timing = Timing::default();

    let server_cfg = crypto::server_config(&agent_id, client_id.fingerprint, &timing).unwrap();
    let client_cfg = crypto::client_config(&client_id, agent_id.fingerprint, &timing).unwrap();

    // Bring up the agent QUIC endpoint on loopback.
    let agent_ep =
        transport::server_endpoint(server_cfg, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    let agent_addr = agent_ep.local_addr().unwrap();
    tokio::spawn(agent::serve(agent_ep));

    // The remote target the agent will dial.
    let echo_addr = spawn_echo().await;

    // Client connects and binds a forward (local port 0 = ephemeral).
    let client_ep = transport::client_endpoint(client_cfg).unwrap();
    let conn = transport::connect(&client_ep, agent_addr).await.unwrap();

    let forward = ForwardSpec {
        ns: NsSpec::Host,
        remote_host: echo_addr.ip().to_string(),
        remote_port: echo_addr.port(),
        local_addr: Ipv4Addr::LOCALHOST.into(),
        local_port: 0,
    };
    let (local_addr, _task) = client::bind_forward(conn, forward).await.unwrap();

    // Drive a large payload through the local port and assert byte-exact echo.
    let payload: Vec<u8> = (0..1_500_000u32).map(|i| (i % 251) as u8).collect();
    let mut sock = TcpStream::connect(local_addr).await.unwrap();

    let writer_payload = payload.clone();
    let writer = tokio::spawn(async move {
        let (_r, mut w) = sock.split();
        w.write_all(&writer_payload).await.unwrap();
        w.shutdown().await.unwrap();
        // Keep the socket alive until the read side finishes.
        let mut r = _r;
        let mut sink = Vec::with_capacity(writer_payload.len());
        r.read_to_end(&mut sink).await.unwrap();
        sink
    });

    let echoed = writer.await.unwrap();
    assert_eq!(echoed.len(), payload.len(), "echoed length mismatch");
    assert_eq!(echoed, payload, "echoed bytes mismatch");
}

#[tokio::test]
async fn rejects_mismatched_fingerprint() {
    crypto::init();

    let client_id = Identity::generate().unwrap();
    let agent_id = Identity::generate().unwrap();
    let imposter = Identity::generate().unwrap();
    let timing = Timing::default();

    // Agent expects the real client; client will present the real client cert,
    // but pins the WRONG agent fingerprint -> handshake must fail.
    let server_cfg = crypto::server_config(&agent_id, client_id.fingerprint, &timing).unwrap();
    let client_cfg = crypto::client_config(&client_id, imposter.fingerprint, &timing).unwrap();

    let agent_ep =
        transport::server_endpoint(server_cfg, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    let agent_addr = agent_ep.local_addr().unwrap();
    tokio::spawn(agent::serve(agent_ep));

    let client_ep = transport::client_endpoint(client_cfg).unwrap();
    let result = transport::connect(&client_ep, agent_addr).await;
    assert!(result.is_err(), "connection should fail on pin mismatch");
}
