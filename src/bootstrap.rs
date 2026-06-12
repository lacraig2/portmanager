//! SSH bootstrap: detect the remote arch, deploy the agent binary, launch it,
//! and complete the [`crate::handshake`] over the SSH pipe.
//!
//! The system `ssh`/`scp` are shelled out to (via `tokio::process`) so all of
//! the user's `~/.ssh/config`, keys, agent, jump hosts and `known_hosts`
//! verification apply unchanged — that authenticated channel is our trust anchor.

use std::path::Path;
use std::process::Stdio;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use tokio::io::BufReader;
use tokio::process::{Child, Command};

use crate::crypto::{Fingerprint, Identity, Timing};
use crate::handshake::{Hello, Ready, SessionId, Token};

/// Everything the client needs to connect to (and later re-attach to) the agent.
pub struct AgentSession {
    /// `hostname:udp_port` to dial the QUIC listener.
    pub quic_target: String,
    /// Agent's pinned certificate fingerprint.
    pub agent_fp: Fingerprint,
    /// Client identity used for the QUIC connection.
    pub client_id: Identity,
    /// Logical session id (for SSH-less re-attach).
    pub session_id: SessionId,
    /// Shared re-attach secret.
    pub token: Token,
    /// The live SSH control process; dropping it tears down the agent.
    pub control: Child,
}

/// Map `uname -s -m` output to the agent's cross-compile target triple.
pub fn target_triple(uname_sm: &str) -> Result<&'static str> {
    let mut parts = uname_sm.split_whitespace();
    let os = parts.next().unwrap_or_default();
    let arch = parts.next().unwrap_or_default();
    if os != "Linux" {
        bail!("unsupported remote OS {os:?}; v1 agents are Linux-only");
    }
    match arch {
        "x86_64" | "amd64" => Ok("x86_64-unknown-linux-musl"),
        "aarch64" | "arm64" => Ok("aarch64-unknown-linux-musl"),
        other => bail!("unsupported remote arch {other:?}; v1 supports x86_64 and aarch64"),
    }
}

/// Local arch as a `uname -m`-style token, for the same-arch v1 guard.
fn local_arch_token() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        other => other,
    }
}

/// Bootstrap an agent on `host` listening on `listen` (a UDP bind spec).
pub async fn bootstrap(host: &str, listen: &str) -> Result<AgentSession> {
    let hostname = ssh_hostname(host).await?;

    let uname = ssh_capture(host, &["uname", "-sm"])
        .await
        .context("detecting remote OS/arch")?;
    let triple = target_triple(uname.trim())?;

    // v1: deploy our own binary, so the remote arch must match the local arch.
    let remote_arch = uname.split_whitespace().nth(1).unwrap_or_default();
    if remote_arch != local_arch_token() {
        bail!(
            "remote arch {remote_arch:?} differs from local {:?}; cross-arch agent \
             deploy lands with the musl build pipeline (build step 8)",
            local_arch_token()
        );
    }

    let exe = std::env::current_exe().context("locating own binary for deploy")?;
    let remote_path = deploy_agent(host, &exe, triple).await?;

    let client_id = Identity::generate()?;
    let token = Token::random()?;

    // Launch the agent over SSH with piped stdio for the handshake.
    let mut child = Command::new("ssh")
        .arg(host)
        .arg(&remote_path)
        .arg("agent")
        .arg("--listen")
        .arg(listen)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .context("launching agent over SSH")?;

    let mut stdin = child.stdin.take().context("agent stdin unavailable")?;
    let stdout = child.stdout.take().context("agent stdout unavailable")?;
    let mut reader = BufReader::new(stdout);

    Hello {
        client_fp: client_id.fingerprint,
        token: token.clone(),
    }
    .write(&mut stdin)
    .await
    .context("sending handshake")?;

    let ready = Ready::read(&mut reader)
        .await
        .context("agent did not complete handshake")?;

    // Keep the reader draining so the agent's stderr/stdout don't block it.
    tokio::spawn(async move {
        use tokio::io::AsyncBufReadExt;
        let mut line = String::new();
        while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
            line.clear();
        }
    });

    Ok(AgentSession {
        quic_target: format!("{hostname}:{}", ready.udp_port),
        agent_fp: ready.agent_fp,
        client_id,
        session_id: ready.session_id,
        token,
        control: child,
    })
}

/// Resolve the real hostname for an SSH alias via `ssh -G`.
async fn ssh_hostname(host: &str) -> Result<String> {
    let out = ssh_g(host).await?;
    for line in out.lines() {
        if let Some(rest) = line.strip_prefix("hostname ") {
            return Ok(rest.trim().to_string());
        }
    }
    // Fall back to the alias itself if `ssh -G` yielded nothing useful.
    Ok(host.to_string())
}

async fn ssh_g(host: &str) -> Result<String> {
    let output = Command::new("ssh")
        .arg("-G")
        .arg(host)
        .output()
        .await
        .context("running ssh -G")?;
    if !output.status.success() {
        bail!("ssh -G {host} failed");
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Run a command on the remote over SSH and capture stdout.
async fn ssh_capture(host: &str, args: &[&str]) -> Result<String> {
    let output = Command::new("ssh")
        .arg("-o")
        .arg("BatchMode=no")
        .arg(host)
        .args(args)
        .output()
        .await
        .context("running remote command over SSH")?;
    if !output.status.success() {
        bail!(
            "remote command {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Ensure the agent binary exists in the remote cache; scp it if missing.
/// Returns the remote path (relative to the remote home directory).
async fn deploy_agent(host: &str, exe: &Path, triple: &str) -> Result<String> {
    let bytes = tokio::fs::read(exe)
        .await
        .with_context(|| format!("reading {}", exe.display()))?;
    let hash = Sha256::digest(&bytes);
    let short = hex::encode(&hash[..6]);
    let remote_path = format!(".cache/portmanager/agent-{triple}-{short}");

    // Already deployed (the hash is in the name, so existence implies a match)?
    let exists = Command::new("ssh")
        .arg(host)
        .arg(format!("test -x {remote_path}"))
        .status()
        .await
        .context("checking remote agent cache")?
        .success();

    if exists {
        return Ok(remote_path);
    }

    // mkdir -p, scp to a temp name, then atomically move + chmod.
    let mkdir = Command::new("ssh")
        .arg(host)
        .arg("mkdir -p .cache/portmanager")
        .status()
        .await
        .context("creating remote cache dir")?;
    if !mkdir.success() {
        bail!("failed to create remote cache directory");
    }

    let tmp = format!("{remote_path}.tmp");
    let scp = Command::new("scp")
        .arg("-q")
        .arg(exe)
        .arg(format!("{host}:{tmp}"))
        .status()
        .await
        .context("scp agent binary")?;
    if !scp.success() {
        bail!("scp of agent binary failed");
    }

    let finalize = Command::new("ssh")
        .arg(host)
        .arg(format!("chmod +x {tmp} && mv {tmp} {remote_path}"))
        .status()
        .await
        .context("finalizing agent deploy")?;
    if !finalize.success() {
        bail!("failed to install agent binary on remote");
    }

    Ok(remote_path)
}

/// Default QUIC timing for bootstrapped sessions.
pub fn default_timing() -> Timing {
    Timing::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn triple_mapping() {
        assert_eq!(
            target_triple("Linux x86_64").unwrap(),
            "x86_64-unknown-linux-musl"
        );
        assert_eq!(
            target_triple("Linux aarch64").unwrap(),
            "aarch64-unknown-linux-musl"
        );
        assert_eq!(
            target_triple("Linux arm64").unwrap(),
            "aarch64-unknown-linux-musl"
        );
    }

    #[test]
    fn triple_rejects_unsupported() {
        assert!(target_triple("Darwin arm64").is_err());
        assert!(target_triple("Linux riscv64").is_err());
        assert!(target_triple("").is_err());
    }
}
