//! Exercises the namespace connect-helper machinery end-to-end: re-exec'd
//! helper process, request line, in-helper connect, SCM_RIGHTS fd hand-back,
//! tokio wrapping, and bytes through the returned stream.
//!
//! Uses `NsSpec::Host` (no nsenter) so it runs unprivileged in CI; the
//! namespace-entry prefix itself is verified manually against a rootless
//! Podman container per the plan.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener};

use portmanager::forward::NsSpec;
use portmanager::netns::HelperPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn set_helper_exe() {
    // SAFETY: called before the runtime (and its threads) exist.
    unsafe { std::env::set_var("PORTMANAGER_HELPER_EXE", env!("CARGO_BIN_EXE_portmanager")) };
}

#[test]
fn helper_dials_and_hands_back_fd() {
    set_helper_exe();

    // Sync echo server on a thread (one connection is enough).
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let mut buf = Vec::new();
        sock.read_to_end(&mut buf).unwrap();
        sock.write_all(&buf).unwrap();
    });

    rt().block_on(async move {
        let pool = HelperPool::new();
        let mut stream = pool
            .connect(&NsSpec::Host, "127.0.0.1", addr.port())
            .await
            .expect("helper connect failed");

        stream.write_all(b"through the helper fd").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut echoed = Vec::new();
        stream.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"through the helper fd");
    });
}

#[test]
fn helper_reports_connect_failure() {
    set_helper_exe();

    rt().block_on(async {
        let pool = HelperPool::new();
        // A port that's almost certainly closed; expect a clean error, not a hang.
        let err = pool
            .connect(&NsSpec::Host, "127.0.0.1", 1)
            .await
            .expect_err("connect to closed port should fail");
        let msg = err.to_string();
        assert!(
            msg.contains("connect") || msg.contains("namespace"),
            "unhelpful error: {msg}"
        );
    });
}

#[test]
fn helper_is_reused_across_connects() {
    set_helper_exe();

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for _ in 0..2 {
            let (mut sock, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4];
            sock.read_exact(&mut buf).unwrap();
            sock.write_all(&buf).unwrap();
        }
    });

    rt().block_on(async move {
        let pool = HelperPool::new();
        for _ in 0..2 {
            let mut s = pool
                .connect(&NsSpec::Host, "127.0.0.1", addr.port())
                .await
                .unwrap();
            s.write_all(b"ping").await.unwrap();
            let mut buf = [0u8; 4];
            s.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
        }
    });
}

/// Real rootless-Podman verification: requires a running container named
/// `pmtest` with a listener on its loopback:7777 (see plan's manual
/// verification). Run explicitly:
/// `podman run --rm -d --name pmtest alpine sleep 60`
/// `podman exec -d pmtest nc -l -p 7777 -s 127.0.0.1`
/// `cargo test --test netns_helper -- --ignored`
#[test]
#[ignore = "needs a running rootless podman container named pmtest"]
fn podman_namespace_entry_real() {
    set_helper_exe();

    rt().block_on(async {
        let pool = HelperPool::new();
        // 127.0.0.1 *inside the container's netns* — unreachable from the host
        // namespace, so success proves the helper entered the container.
        let mut stream = pool
            .connect(&NsSpec::Podman("pmtest".into()), "127.0.0.1", 7777)
            .await
            .expect("in-container connect failed");
        stream.write_all(b"hello from the host").await.unwrap();
        // nc -l accepted and consumed our connection; write success + clean
        // shutdown is the proof we were inside.
        stream.shutdown().await.unwrap();
    });
}

/// Rootful `netns:` targets must fail with the clear v1 error.
#[test]
fn netns_form_rejected_rootless() {
    set_helper_exe();

    rt().block_on(async {
        let pool = HelperPool::new();
        let err = pool
            .connect(&NsSpec::Netns("blue".into()), "10.0.0.1", 80)
            .await
            .expect_err("netns: should be rejected in v1");
        assert!(
            err.to_string().contains("rootful") || err.root_cause().to_string().contains("rootful"),
            "error should explain rootful unsupported: {err:#}"
        );
    });
}
