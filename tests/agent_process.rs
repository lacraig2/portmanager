//! Spawn the real `portmanager agent` binary, drive the handshake over its
//! stdin/stdout pipes (as the SSH bootstrap would), then forward through it.
//! This covers `agent::run` + the handshake codec + QUIC forwarding end-to-end
//! without needing SSH.

use std::net::{Ipv4Addr, SocketAddr};
use std::process::Stdio;

use portmanager::crypto::{self, Identity, Timing};
use portmanager::forward::{ForwardSpec, NsSpec};
use portmanager::handshake::{Hello, Ready, Token};
use portmanager::{client, transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;

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
async fn agent_binary_bootstraps_and_forwards() {
    crypto::init();

    let echo_addr = spawn_echo().await;
    let client_id = Identity::generate().unwrap();
    let token = Token::random().unwrap();

    // Launch the real agent binary with piped stdio, listening on loopback UDP.
    let mut child = Command::new(env!("CARGO_BIN_EXE_portmanager"))
        .args(["agent", "--listen", "127.0.0.1:0"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();

    let mut stdin = child.stdin.take().unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());

    Hello {
        client_fp: client_id.fingerprint,
        token,
    }
    .write(&mut stdin)
    .await
    .unwrap();

    let ready = Ready::read(&mut reader).await.unwrap();

    // Connect to the agent's QUIC listener, pinning the fingerprint it reported.
    let client_cfg =
        crypto::client_config(&client_id, ready.agent_fp, &Timing::default()).unwrap();
    let endpoint = transport::client_endpoint(client_cfg).unwrap();
    let agent_addr: SocketAddr = (Ipv4Addr::LOCALHOST, ready.udp_port).into();
    let conn = transport::connect(&endpoint, agent_addr).await.unwrap();

    let forward = ForwardSpec {
        ns: NsSpec::Host,
        remote_host: echo_addr.ip().to_string(),
        remote_port: echo_addr.port(),
        local_addr: Ipv4Addr::LOCALHOST.into(),
        local_port: 0,
    };
    let (local_addr, _task) = client::bind_forward(conn, forward).await.unwrap();

    // Round-trip a payload through the local port.
    let payload = b"the quick brown fox jumps over the lazy dog".repeat(2000);
    let mut sock = TcpStream::connect(local_addr).await.unwrap();
    sock.write_all(&payload).await.unwrap();
    sock.shutdown().await.unwrap();
    let mut echoed = Vec::new();
    sock.read_to_end(&mut echoed).await.unwrap();

    assert_eq!(echoed, payload, "payload not echoed byte-exact through agent");

    child.kill().await.unwrap();
}
