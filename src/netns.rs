//! Namespace-aware dialing (rootless, v1).
//!
//! The agent cannot `setns()` its whole multithreaded self into a container's
//! namespaces, so it spawns a tiny **per-namespace connect-helper**: our own
//! binary re-exec'd under `nsenter -t <pid> -U -n --preserve-credentials`
//! (userns join first — that's what makes rootless Podman work, same trick as
//! `podman unshare`). The helper stays resident inside the namespace; for each
//! request it dials the target with a plain blocking `connect()` and hands the
//! connected socket fd back over a Unix socketpair via **SCM_RIGHTS**. The
//! agent wraps the fd as a tokio `TcpStream` and splices it like any other
//! forward.
//!
//! Wire protocol on the socketpair (helper's stdin, fd 0):
//! - request:  `C <host> <port>\n`
//! - response: 1 status byte — `K` (fd attached via SCM_RIGHTS) or `E`
//!   followed by a newline-terminated error message.
//!
//! One helper per distinct namespace, reused across connections; a helper
//! exits when its socket closes (agent drop) and is evicted/respawned on error.
//!
//! v1 scope: rootless only. `netns:<name>` (classic rootful `ip netns`) parses
//! but is rejected here with a clear error, per the plan.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tracing::{debug, info, warn};

use crate::forward::NsSpec;

/// Timeout for one in-namespace `connect()`.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How a helper should enter its namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Entry {
    /// Join the user+net namespaces of this PID (rootless container case).
    Pid(i32),
    /// Join an explicit netns file (no userns information available).
    Path(PathBuf),
}

/// Resolve a namespace selector to an entry strategy. Container names are
/// resolved to PIDs via the runtime CLI (one-shot, at helper spawn).
fn resolve(ns: &NsSpec) -> Result<Entry> {
    match ns {
        NsSpec::Host => bail!("host namespace needs no helper"),
        NsSpec::Pid(pid) => Ok(Entry::Pid(*pid)),
        NsSpec::NsPath(p) => Ok(Entry::Path(p.clone())),
        NsSpec::Podman(name) => Ok(Entry::Pid(inspect_pid("podman", name)?)),
        NsSpec::Docker(name) => Ok(Entry::Pid(inspect_pid("docker", name)?)),
        NsSpec::Netns(name) => bail!(
            "netns:{name} is a rootful (ip-netns) namespace; rootful entry is not \
             yet supported — the v1 agent runs unprivileged (rootless only)"
        ),
    }
}

/// Path of the binary to re-exec as the in-namespace helper. Overridable for
/// tests (whose `current_exe` is the test harness, not portmanager).
fn helper_exe() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("PORTMANAGER_HELPER_EXE") {
        return Ok(PathBuf::from(p));
    }
    std::env::current_exe().context("locating own binary")
}

/// Resolve a namespace selector to the PID whose `/proc/<pid>/net/tcp` shows
/// that namespace's listeners (`None` = the agent's own/host namespace).
/// Used by discovery; nspath/netns forms carry no PID and can't be scanned.
pub fn resolve_pid(ns: &NsSpec) -> Result<Option<i32>> {
    match ns {
        NsSpec::Host => Ok(None),
        NsSpec::Pid(pid) => Ok(Some(*pid)),
        NsSpec::Podman(name) => Ok(Some(inspect_pid("podman", name)?)),
        NsSpec::Docker(name) => Ok(Some(inspect_pid("docker", name)?)),
        NsSpec::NsPath(p) => bail!("cannot scan nspath:{} (no owning PID)", p.display()),
        NsSpec::Netns(name) => bail!("cannot scan netns:{name} (rootful; unsupported in v1)"),
    }
}

/// `<runtime> inspect --format {{.State.Pid}} <name>` -> PID.
fn inspect_pid(runtime: &str, name: &str) -> Result<i32> {
    let out = Command::new(runtime)
        .args(["inspect", "--format", "{{.State.Pid}}", name])
        .output()
        .with_context(|| format!("running {runtime} inspect (is {runtime} installed?)"))?;
    if !out.status.success() {
        bail!(
            "{runtime} inspect {name} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let pid: i32 = String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .with_context(|| format!("parsing PID from {runtime} inspect"))?;
    if pid <= 0 {
        bail!("{runtime} container {name} has no live process (PID {pid})");
    }
    Ok(pid)
}

/// A resident connect-helper inside one namespace.
struct Helper {
    child: Child,
    /// Agent's end of the socketpair (helper's stdin is the other end).
    /// Blocking I/O on purpose; all use goes through `spawn_blocking`.
    sock: Mutex<UnixStream>,
}

impl Helper {
    /// Spawn a helper for `ns`. `nsenter_needed` is false only in tests, which
    /// exercise the protocol without entering a namespace.
    fn spawn(entry: Option<&Entry>) -> Result<Helper> {
        let (agent_end, helper_end) = UnixStream::pair().context("creating helper socketpair")?;

        let exe = helper_exe()?;
        let mut cmd = match entry {
            Some(Entry::Pid(pid)) => {
                let mut c = Command::new("nsenter");
                c.arg("-t")
                    .arg(pid.to_string())
                    .arg("--preserve-credentials")
                    .arg("-U")
                    .arg("-n")
                    .arg("--")
                    .arg(&exe);
                c
            }
            Some(Entry::Path(path)) => {
                let mut c = Command::new("nsenter");
                c.arg(format!("--net={}", path.display()))
                    .arg("--")
                    .arg(&exe);
                c
            }
            None => Command::new(&exe),
        };
        cmd.arg("ns-helper");

        let child = cmd
            .stdin(Stdio::from(OwnedFd::from(helper_end)))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("spawning namespace helper (is nsenter installed?)")?;

        Ok(Helper {
            child,
            sock: Mutex::new(agent_end),
        })
    }

    /// Ask the helper to dial `host:port` inside its namespace; returns the
    /// connected socket. Blocking — call via `spawn_blocking`.
    fn connect_blocking(&self, host: &str, port: u16) -> Result<std::net::TcpStream> {
        let mut sock = self.sock.lock().expect("helper socket poisoned");
        sock.write_all(format!("C {host} {port}\n").as_bytes())
            .context("sending connect request to helper")?;

        // One status byte; an fd rides along on 'K'.
        let mut status = [0u8; 1];
        let mut cmsg_buf = nix::cmsg_space!([std::os::fd::RawFd; 1]);
        let mut iov = [std::io::IoSliceMut::new(&mut status)];
        let msg = nix::sys::socket::recvmsg::<()>(
            sock.as_raw_fd(),
            &mut iov,
            Some(&mut cmsg_buf),
            nix::sys::socket::MsgFlags::empty(),
        )
        .context("receiving helper response")?;
        if msg.bytes == 0 {
            bail!("helper closed (namespace process gone?)");
        }

        let mut fd: Option<OwnedFd> = None;
        for cmsg in msg.cmsgs().context("parsing control messages")? {
            if let nix::sys::socket::ControlMessageOwned::ScmRights(fds) = cmsg {
                if let Some(&raw) = fds.first() {
                    // SAFETY: freshly received via SCM_RIGHTS; we own it.
                    fd = Some(unsafe { OwnedFd::from_raw_fd(raw) });
                }
            }
        }

        match status[0] {
            b'K' => {
                let fd = fd.context("helper said OK but sent no fd")?;
                Ok(std::net::TcpStream::from(fd))
            }
            b'E' => {
                let mut err = String::new();
                let mut reader = BufReader::new(&mut *sock);
                reader.read_line(&mut err).context("reading helper error")?;
                bail!("in-namespace connect failed: {}", err.trim());
            }
            other => bail!("helper protocol violation (status byte {other:#x})"),
        }
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        // Closing our socket end makes the helper exit; reap it.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Pool of helpers keyed by namespace wire form. Helpers are spawned on first
/// use, reused across connections, and evicted (with one retry) on error.
pub struct HelperPool {
    helpers: tokio::sync::Mutex<HashMap<String, std::sync::Arc<Helper>>>,
}

impl Default for HelperPool {
    fn default() -> Self {
        Self::new()
    }
}

impl HelperPool {
    pub fn new() -> Self {
        HelperPool {
            helpers: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Dial `host:port` inside `ns` and return a tokio TcpStream.
    pub async fn connect(
        &self,
        ns: &NsSpec,
        host: &str,
        port: u16,
    ) -> Result<tokio::net::TcpStream> {
        // One retry after evicting a dead helper.
        for attempt in 0..2 {
            let helper = self.get_or_spawn(ns).await?;
            let (h, p) = (host.to_string(), port);
            let res = tokio::task::spawn_blocking(move || helper.connect_blocking(&h, p))
                .await
                .context("helper task panicked")?;
            match res {
                Ok(std_stream) => {
                    std_stream
                        .set_nonblocking(true)
                        .context("setting socket non-blocking")?;
                    return tokio::net::TcpStream::from_std(std_stream)
                        .context("wrapping in tokio TcpStream");
                }
                Err(e) if attempt == 0 && e.to_string().contains("helper closed") => {
                    warn!(ns = %ns.to_wire(), "helper died; respawning");
                    self.helpers.lock().await.remove(&ns.to_wire());
                }
                Err(e) => return Err(e),
            }
        }
        unreachable!("retry loop returns on second attempt");
    }

    async fn get_or_spawn(&self, ns: &NsSpec) -> Result<std::sync::Arc<Helper>> {
        let key = ns.to_wire();
        let mut pool = self.helpers.lock().await;
        if let Some(h) = pool.get(&key) {
            return Ok(h.clone());
        }
        info!(ns = %key, "spawning namespace connect-helper");
        let entry = if ns.is_host() {
            None // test path: protocol without nsenter
        } else {
            let ns = ns.clone();
            Some(tokio::task::block_in_place(|| resolve(&ns)).context("resolving namespace")?)
        };
        let helper = tokio::task::block_in_place(|| Helper::spawn(entry.as_ref()))
            .context("spawning helper")?;
        let helper = std::sync::Arc::new(helper);
        pool.insert(key, helper.clone());
        Ok(helper)
    }
}

/// Entry point for the hidden `ns-helper` subcommand: serve connect requests on
/// the socketpair at fd 0 until it closes. Plain sync code, no runtime.
pub fn run_helper() -> Result<()> {
    // SAFETY: fd 0 is the socketpair end our parent gave us as stdin.
    let sock = unsafe { UnixStream::from_raw_fd(0) };
    let mut reader = BufReader::new(sock.try_clone().context("cloning helper socket")?);
    let mut writer = sock;

    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).context("reading request")?;
        if n == 0 {
            // Agent closed the socket: session over.
            return Ok(());
        }
        let mut parts = line.split_whitespace();
        let (cmd, host, port) = (parts.next(), parts.next(), parts.next());
        let (host, port) = match (cmd, host, port.and_then(|p| p.parse::<u16>().ok())) {
            (Some("C"), Some(h), Some(p)) => (h.to_string(), p),
            _ => {
                respond_err(&mut writer, "malformed request")?;
                continue;
            }
        };

        match connect_with_timeout(&host, port) {
            Ok(stream) => {
                let fds = [stream.as_raw_fd()];
                let iov = [std::io::IoSlice::new(b"K")];
                let cmsg = [nix::sys::socket::ControlMessage::ScmRights(&fds)];
                nix::sys::socket::sendmsg::<()>(
                    writer.as_raw_fd(),
                    &iov,
                    &cmsg,
                    nix::sys::socket::MsgFlags::empty(),
                    None,
                )
                .context("sending fd to agent")?;
                // `stream` drops here; the agent's copy of the fd lives on.
            }
            Err(e) => respond_err(&mut writer, &e.to_string())?,
        }
    }
}

fn respond_err(writer: &mut UnixStream, msg: &str) -> Result<()> {
    debug!(error = %msg, "helper connect failed");
    let msg = msg.replace('\n', " ");
    writer
        .write_all(format!("E{msg}\n").as_bytes())
        .context("sending error to agent")?;
    Ok(())
}

/// Resolve + connect with a bounded timeout (helper side, in-namespace).
fn connect_with_timeout(host: &str, port: u16) -> Result<std::net::TcpStream> {
    use std::net::ToSocketAddrs;
    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("resolving {host}:{port} in namespace"))?
        .collect();
    let mut last_err = anyhow::anyhow!("no addresses for {host}:{port}");
    for addr in addrs {
        match std::net::TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(s) => return Ok(s),
            Err(e) => last_err = anyhow::anyhow!("connect {addr}: {e}"),
        }
    }
    Err(last_err)
}
