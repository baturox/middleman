//! Session modes for `middleman claude` and the small state files shared by the launcher, the
//! proxy, the status line and `middleman mode`. Everything lives in the state dir, 0600.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Claude,
    Cheap,
    Smart,
}

impl FromStr for Mode {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Mode> {
        let s = s.trim().to_ascii_lowercase();
        Ok(match s.as_str() {
            "claude" => Mode::Claude,
            "cheap" => Mode::Cheap,
            "smart" => Mode::Smart,
            _ => bail!("unknown mode `{s}` (smart | cheap | claude)"),
        })
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Mode::Claude => f.write_str("claude"),
            Mode::Cheap => f.write_str("cheap"),
            Mode::Smart => f.write_str("smart"),
        }
    }
}

impl Mode {
    /// Modes that can send whole files to a cheap model need the repo allow-check.
    pub fn needs_allow(&self) -> bool {
        *self != Mode::Claude
    }
    /// Only smart runs through the local proxy (cheap goes direct, claude is plain).
    pub fn uses_proxy(&self) -> bool {
        *self == Mode::Smart
    }
}

fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(d) = path.parent() {
        crate::ledger::ensure_private_dir(d)?;
    }
    crate::ledger::write_private(path, bytes)
}

fn read_json<T: for<'a> Deserialize<'a>>(path: &Path) -> Option<T> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

pub fn mode_path(state: &Path) -> PathBuf {
    state.join("mode")
}

/// The live mode: `middleman mode <m>` writes it, the proxy rereads it at each new turn.
pub fn write_live_mode(state: &Path, m: Mode) -> Result<()> {
    write(&mode_path(state), m.to_string().as_bytes())
}

pub fn read_live_mode(state: &Path) -> Option<Mode> {
    std::fs::read_to_string(mode_path(state)).ok()?.parse().ok()
}

/// Remembered choice per canonical repo root.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RepoPref {
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

fn prefs_path(state: &Path) -> PathBuf {
    state.join("launch-prefs.json")
}

pub fn load_pref(state: &Path, root: &Path) -> Option<RepoPref> {
    let m: BTreeMap<String, RepoPref> = read_json(&prefs_path(state))?;
    m.get(root.to_string_lossy().as_ref()).cloned()
}

pub fn store_pref(state: &Path, root: &Path, p: RepoPref) -> Result<()> {
    let mut m: BTreeMap<String, RepoPref> = read_json(&prefs_path(state)).unwrap_or_default();
    m.insert(root.to_string_lossy().to_string(), p);
    write(
        &prefs_path(state),
        serde_json::to_string_pretty(&m)?.as_bytes(),
    )
}

/// Claude's 5-hour utilization, from the proxy (response headers) or the status line.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct Usage {
    pub pct: f64,
    pub ts: i64,
}

pub fn usage_path(state: &Path) -> PathBuf {
    state.join("claude-usage.json")
}

pub fn read_usage(state: &Path) -> Option<Usage> {
    read_json(&usage_path(state))
}

/// Keep the freshest reading (callers write whenever they see a value).
pub fn write_usage(state: &Path, pct: f64, ts: i64) -> Result<()> {
    if read_usage(state).is_some_and(|u| u.ts > ts) {
        return Ok(());
    }
    write(
        &usage_path(state),
        serde_json::to_string(&Usage { pct, ts })?.as_bytes(),
    )
}

/// What the proxy last did, for the status line.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RouteNote {
    pub mode: String,
    pub route: String,
    pub model: String,
    pub ts: i64,
}

pub fn route_path(state: &Path) -> PathBuf {
    state.join("route.json")
}

pub fn write_route(state: &Path, n: &RouteNote) -> Result<()> {
    write(&route_path(state), serde_json::to_string(n)?.as_bytes())
}

pub fn read_route(state: &Path) -> Option<RouteNote> {
    read_json(&route_path(state))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_display() {
        for s in ["claude", "cheap", "smart"] {
            assert_eq!(s.parse::<Mode>().unwrap().to_string(), s);
        }
        assert!("budget:30".parse::<Mode>().is_err());
        assert!("fast".parse::<Mode>().is_err());
        assert!(!Mode::Claude.needs_allow() && Mode::Smart.needs_allow());
    }

    #[test]
    fn state_files_roundtrip() {
        let d = tempfile::tempdir().unwrap();
        let s = d.path();
        assert_eq!(read_live_mode(s), None);
        write_live_mode(s, Mode::Cheap).unwrap();
        assert_eq!(read_live_mode(s), Some(Mode::Cheap));
        let root = Path::new("/x/repo");
        assert!(load_pref(s, root).is_none());
        let p = RepoPref {
            mode: "cheap".into(),
            model: Some("a/b".into()),
        };
        store_pref(s, root, p.clone()).unwrap();
        assert_eq!(load_pref(s, root), Some(p));
        write_usage(s, 41.0, 100).unwrap();
        write_usage(s, 10.0, 50).unwrap(); // older: ignored
        assert_eq!(read_usage(s).unwrap().pct, 41.0);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(mode_path(s))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(m & 0o777, 0o600);
        }
    }
}
