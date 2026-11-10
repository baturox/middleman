//! Provider limits (balance, key spend limit, usage counters) cached on disk for the status
//! line, which must never do network I/O itself.
//!
//! - `middleman provider refresh` (and the MCP server after each delegation) fetches them and
//!   writes `<state>/provider-limits.json` (0600), plus one usage snapshot per provider to
//!   `<state>/usage-snapshots.jsonl` for `report --reconcile`.
//! - The status line reads the cache. When it is older than [`STALE_S`], it starts one
//!   detached `middleman provider refresh --quiet` (at most one at a time, via a lock file) and
//!   shows the cached value with its age.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::{BalanceKind, Config};
use crate::providers::{KeyLimits, Provider, ProviderError};

/// The status line asks for a refresh when the cache is older than this (seconds).
pub const STALE_S: i64 = 600;
/// A refresh lock older than this is from a crashed refresh (seconds).
pub const LOCK_STALE_S: u64 = 120;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProviderLimits {
    /// Short, fixed description of a failed fetch (never provider-chosen text).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// HTTP status of a failed fetch (401/403 = key rejected).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance_usd: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<KeyLimits>,
    pub fetched_at: i64,
}

impl ProviderLimits {
    /// What can still be spent: the tighter of the account balance and the key's limits.
    pub fn left_usd(&self) -> Option<f64> {
        let k = self.key.as_ref().and_then(KeyLimits::remaining_usd);
        match (self.balance_usd, k) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    pub fn key_rejected(&self) -> bool {
        matches!(self.http_status, Some(401 | 403))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LimitsCache {
    pub fetched_at: i64,
    pub providers: BTreeMap<String, ProviderLimits>,
}

pub fn cache_path(state_dir: &Path) -> PathBuf {
    state_dir.join("provider-limits.json")
}

fn lock_path(state_dir: &Path) -> PathBuf {
    state_dir.join("provider-refresh.lock")
}

pub fn snapshots_path(state_dir: &Path) -> PathBuf {
    state_dir.join("usage-snapshots.jsonl")
}

pub fn load(state_dir: &Path) -> Option<LimitsCache> {
    let t = std::fs::read(cache_path(state_dir)).ok()?;
    serde_json::from_slice(&t).ok()
}

pub fn save(state_dir: &Path, c: &LimitsCache) -> anyhow::Result<()> {
    crate::ledger::ensure_private_dir(state_dir)?;
    let t = serde_json::to_vec_pretty(c)?;
    crate::fsutil::write_atomic(&cache_path(state_dir), &t, Some(0o600))?;
    Ok(())
}

/// One reading of a provider's own spend counters, for reconciliation.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Snapshot {
    pub ts: i64,
    pub provider: String,
    /// OpenRouter key usage (all-time, USD).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_usd: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance_usd: Option<f64>,
}

pub fn snapshots(state_dir: &Path) -> Vec<Snapshot> {
    std::fs::read_to_string(snapshots_path(state_dir))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

fn append_snapshots(state_dir: &Path, c: &LimitsCache) {
    for (name, p) in &c.providers {
        let s = Snapshot {
            ts: p.fetched_at,
            provider: name.clone(),
            usage_usd: p.key.as_ref().and_then(|k| k.usage_usd),
            balance_usd: p.balance_usd,
        };
        if s.usage_usd.is_some() || s.balance_usd.is_some() {
            let _ = crate::ledger::append_jsonl(&snapshots_path(state_dir), &s);
        }
    }
}

fn describe(e: &ProviderError) -> (String, Option<u16>) {
    match e {
        ProviderError::Http { status, .. } => (
            format!(
                "HTTP {status} ({})",
                crate::providers::http_category(*status)
            ),
            Some(*status),
        ),
        ProviderError::Timeout => ("timeout".into(), None),
        ProviderError::Transport(_) => ("network error".into(), None),
        _ => ("bad response".into(), None),
    }
}

/// Fetch limits for one provider (free GET requests only).
pub async fn fetch_one(p: &Provider, now: i64) -> ProviderLimits {
    let mut out = ProviderLimits {
        fetched_at: now,
        ..Default::default()
    };
    match p.balance().await {
        Ok(b) => out.balance_usd = Some(b.usd),
        Err(e) => {
            let (msg, st) = describe(&e);
            out.error = Some(msg);
            out.http_status = st;
        }
    }
    if p.balance_kind() == BalanceKind::Openrouter {
        match p.key_limits().await {
            Ok(k) => {
                out.key = Some(k);
                // the key endpoint answered: the key works even if /credits needs more scope
                if out.http_status.is_some_and(|s| s == 403) {
                    out.error = None;
                    out.http_status = None;
                }
            }
            Err(e) => {
                let (msg, st) = describe(&e);
                out.error.get_or_insert(msg);
                if st.is_some() {
                    out.http_status = st;
                }
            }
        }
    }
    out
}

/// Fetch every enabled provider that has a balance or limits endpoint.
pub async fn fetch(cfg: &Config, now: i64) -> LimitsCache {
    let mut c = LimitsCache {
        fetched_at: now,
        ..Default::default()
    };
    for (name, pc) in &cfg.providers {
        if !pc.enabled || pc.balance == BalanceKind::None {
            continue;
        }
        let limits = match Provider::from_cfg(name, pc, 20) {
            Ok(p) => fetch_one(&p, now).await,
            Err(_) => ProviderLimits {
                error: Some("no key".into()),
                fetched_at: now,
                ..Default::default()
            },
        };
        c.providers.insert(name.clone(), limits);
    }
    c
}

/// Fetch, save the cache and the snapshots. Used by `provider refresh` and the MCP server.
pub async fn refresh(cfg: &Config) -> anyhow::Result<LimitsCache> {
    let now = crate::ledger::now_unix();
    let c = fetch(cfg, now).await;
    let state = cfg.state_dir();
    save(&state, &c)?;
    append_snapshots(&state, &c);
    crate::session::prune(&state, now);
    Ok(c)
}

/// Exclusive refresh lock: Some(guard) when we got it. A lock older than
/// [`LOCK_STALE_S`] is taken over.
pub fn try_lock(state_dir: &Path) -> Option<RefreshLock> {
    let p = lock_path(state_dir);
    for _ in 0..2 {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        match opts.open(&p) {
            Ok(_) => return Some(RefreshLock { path: p }),
            Err(_) => {
                let stale = std::fs::metadata(&p)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.elapsed().ok())
                    .is_none_or(|age| age.as_secs() > LOCK_STALE_S);
                if !stale {
                    return None;
                }
                let _ = std::fs::remove_file(&p);
            }
        }
    }
    None
}

/// Removes the lock file when dropped, unless `keep` was called (handed to a child process).
pub struct RefreshLock {
    path: PathBuf,
}

impl RefreshLock {
    /// Leave the lock for the spawned refresh process to remove.
    pub fn keep(self) {
        std::mem::forget(self);
    }
}

impl Drop for RefreshLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Release a lock left by the status line (called by `provider refresh --quiet`).
pub fn release_lock(state_dir: &Path) {
    let _ = std::fs::remove_file(lock_path(state_dir));
}

/// If the cache is missing or older than [`STALE_S`], start `spawn` (a detached refresh) once:
/// the lock is held until the refresh finishes. Returns true when a refresh was started.
pub fn maybe_refresh(
    state_dir: &Path,
    cache: Option<&LimitsCache>,
    now: i64,
    spawn: &mut dyn FnMut() -> std::io::Result<()>,
) -> bool {
    let fresh = cache.is_some_and(|c| (0..STALE_S).contains(&(now - c.fetched_at)));
    if fresh || crate::ledger::ensure_private_dir(state_dir).is_err() {
        return false;
    }
    let Some(lock) = try_lock(state_dir) else {
        return false;
    };
    match spawn() {
        Ok(()) => {
            lock.keep();
            true
        }
        Err(_) => false, // lock dropped: the next status line may try again
    }
}

/// The real spawner: `<exe> provider refresh --quiet --config <cfg>`, detached, no stdio.
pub fn spawn_refresh(cfg_path: &Path) -> std::io::Result<()> {
    use std::process::{Command, Stdio};
    let exe = std::env::current_exe()?;
    let mut cmd = Command::new(exe);
    cmd.args([
        "provider",
        "refresh",
        "--quiet",
        "--from-statusline",
        "--config",
    ])
    .arg(cfg_path)
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    cmd.spawn().map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_cache_spawns_once_and_fresh_cache_does_not() {
        let d = tempfile::tempdir().unwrap();
        let now = 10_000;
        let calls = std::cell::Cell::new(0);
        let mut spawn = || {
            calls.set(calls.get() + 1);
            Ok(())
        };
        let fresh = LimitsCache {
            fetched_at: now - 30,
            ..Default::default()
        };
        assert!(!maybe_refresh(d.path(), Some(&fresh), now, &mut spawn));
        let stale = LimitsCache {
            fetched_at: now - STALE_S - 1,
            ..Default::default()
        };
        assert!(maybe_refresh(d.path(), Some(&stale), now, &mut spawn));
        // the lock is held by the "child": no second spawn
        assert!(!maybe_refresh(d.path(), Some(&stale), now, &mut spawn));
        assert!(!maybe_refresh(d.path(), None, now, &mut spawn));
        assert_eq!(calls.get(), 1);
        // the child releases it; the next stale render spawns again
        release_lock(d.path());
        assert!(maybe_refresh(d.path(), None, now, &mut spawn));
        assert_eq!(calls.get(), 2);
        release_lock(d.path());
        // a failed spawn does not leave the lock behind
        let mut failing = || Err(std::io::Error::other("no"));
        assert!(!maybe_refresh(d.path(), None, now, &mut failing));
        assert!(try_lock(d.path()).is_some());
    }

    #[test]
    fn left_is_the_tighter_limit() {
        let p = ProviderLimits {
            balance_usd: Some(9.0),
            key: Some(KeyLimits {
                limit_remaining_usd: Some(7.42),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(p.left_usd(), Some(7.42));
        let p = ProviderLimits {
            balance_usd: Some(3.0),
            ..Default::default()
        };
        assert_eq!(p.left_usd(), Some(3.0));
        assert_eq!(ProviderLimits::default().left_usd(), None);
    }

    #[test]
    fn save_load_private() {
        let d = tempfile::tempdir().unwrap();
        let mut c = LimitsCache {
            fetched_at: 5,
            ..Default::default()
        };
        c.providers.insert(
            "or".into(),
            ProviderLimits {
                balance_usd: Some(1.5),
                fetched_at: 5,
                ..Default::default()
            },
        );
        save(d.path(), &c).unwrap();
        assert_eq!(load(d.path()), Some(c.clone()));
        append_snapshots(d.path(), &c);
        assert_eq!(snapshots(d.path())[0].balance_usd, Some(1.5));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for p in [cache_path(d.path()), snapshots_path(d.path())] {
                let m = std::fs::metadata(p).unwrap().permissions().mode();
                assert_eq!(m & 0o777, 0o600);
            }
        }
    }
}
