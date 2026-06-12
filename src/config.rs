//! Persistent state and configuration (TOML).
//!
//! Per-host **state** lives at `<config>/state/<host>.toml` and remembers the
//! forward set you ended with, stable auto-forward port assignments, and
//! auto-forward rules. A session launched plain (`portmanager myhost`) starts
//! from this state, and live `add`/`drop` changes are written back — so the
//! mapping set is durable, not frozen at launch. (Named profiles in
//! `config.toml` layer on top of this; see the plan's task 8.)

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::forward::ForwardSpec;

/// One auto-forward rule: which discovered listeners to forward automatically.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AutoForwardRule {
    /// Namespace selector in wire form (`""` or `"host"` = agent's host ns).
    #[serde(default)]
    pub ns: String,
    /// Ports to match: `"*"`, a single port, or comma-separated list.
    #[serde(default = "default_ports")]
    pub ports: String,
    /// Local port policy: `"same"` (mirror the remote port, fall back to a
    /// free port on collision) or `"auto"` (always pick a free port).
    #[serde(default = "default_local")]
    pub local: String,
}

fn default_ports() -> String {
    "*".to_string()
}
fn default_local() -> String {
    "same".to_string()
}

impl AutoForwardRule {
    /// Does this rule match a discovered listener?
    pub fn matches(&self, ns_wire: &str, port: u16) -> bool {
        let rule_ns = if self.ns == "host" { "" } else { &self.ns };
        if rule_ns != ns_wire {
            return false;
        }
        if self.ports.trim() == "*" {
            return true;
        }
        self.ports
            .split(',')
            .filter_map(|p| p.trim().parse::<u16>().ok())
            .any(|p| p == port)
    }
}

/// Everything we remember about one host between sessions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostState {
    /// Forward specs (CLI grammar) the last session ended with.
    #[serde(default)]
    pub forwards: Vec<String>,
    /// Stable local-port assignments for auto-forwards: `"<ns>/<remote_port>"`
    /// -> local port. Keeps a discovered port on the same local port across
    /// sessions.
    #[serde(default)]
    pub assignments: BTreeMap<String, u16>,
    /// Auto-forward rules (opt-in; empty = discovery only reports, never binds).
    #[serde(default)]
    pub autoforward: Vec<AutoForwardRule>,
}

impl HostState {
    /// Parse the remembered forward specs, skipping any that no longer parse
    /// (e.g. written by a newer version).
    pub fn parsed_forwards(&self) -> Vec<ForwardSpec> {
        self.forwards
            .iter()
            .filter_map(|s| s.parse::<ForwardSpec>().ok())
            .collect()
    }

    /// The assignment key for a discovered listener.
    pub fn assignment_key(ns_wire: &str, remote_port: u16) -> String {
        format!("{ns_wire}/{remote_port}")
    }
}

/// Path of the state file for `host`.
pub fn state_path(host: &str) -> Result<PathBuf> {
    let dirs = directories::ProjectDirs::from("", "", "portmanager")
        .context("resolving config directory")?;
    Ok(dirs.config_dir().join("state").join(format!("{}.toml", sanitize(host))))
}

/// Load the state for `host` (default-empty when absent).
pub fn load_state(host: &str) -> Result<HostState> {
    let path = state_path(host)?;
    match std::fs::read_to_string(&path) {
        Ok(s) => toml::from_str(&s).with_context(|| format!("parsing {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(HostState::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Persist the state for `host` (atomic: write temp + rename).
pub fn save_state(host: &str, state: &HostState) -> Result<()> {
    let path = state_path(host)?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let body = toml::to_string_pretty(state).context("serializing state")?;
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, body).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("installing {}", path.display()))?;
    Ok(())
}

/// Make a host string filesystem-safe.
fn sanitize(host: &str) -> String {
    host.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_matching() {
        let any = AutoForwardRule {
            ns: "podman:web".into(),
            ports: "*".into(),
            local: "same".into(),
        };
        assert!(any.matches("podman:web", 5432));
        assert!(!any.matches("podman:db", 5432));
        assert!(!any.matches("", 5432));

        let listed = AutoForwardRule {
            ns: "host".into(),
            ports: "8080, 9090".into(),
            local: "same".into(),
        };
        assert!(listed.matches("", 8080));
        assert!(listed.matches("", 9090));
        assert!(!listed.matches("", 8081));
    }

    #[test]
    fn state_roundtrip_toml() {
        let mut st = HostState::default();
        st.forwards.push("podman:web@5432->5432".into());
        st.assignments.insert(HostState::assignment_key("podman:web", 5432), 5432);
        st.autoforward.push(AutoForwardRule {
            ns: "podman:web".into(),
            ports: "*".into(),
            local: "same".into(),
        });
        let s = toml::to_string_pretty(&st).unwrap();
        let back: HostState = toml::from_str(&s).unwrap();
        assert_eq!(back.forwards, st.forwards);
        assert_eq!(back.assignments, st.assignments);
        assert_eq!(back.autoforward, st.autoforward);
        assert_eq!(back.parsed_forwards().len(), 1);
    }

    #[test]
    fn sanitize_host_names() {
        assert_eq!(sanitize("user@host.example.com"), "user_host.example.com");
        assert_eq!(sanitize("my-host"), "my-host");
    }
}
