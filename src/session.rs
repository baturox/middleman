//! Live facts about a Claude Code session, written by the status line (which receives them on
//! stdin) and read by the MCP server for the savings maths: current context size, model id
//! and cache TTL. One small 0600 file per session under `<state>/sessions/`, so concurrent
//! sessions never overwrite each other.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::statusline::safe_id;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionInfo {
    /// input + cache_creation + cache_read tokens of the latest API response
    pub context_tokens: u64,
    pub model_id: String,
    /// "5m" | "1h" when reported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_ttl: Option<String>,
    pub updated_at: i64,
}

/// Rewrite at most this often when nothing changed (seconds).
const REFRESH_S: i64 = 60;
/// Files older than this are removed by `prune`.
pub const KEEP_S: i64 = 7 * 86_400;

pub fn dir(state_dir: &Path) -> PathBuf {
    state_dir.join("sessions")
}

fn file(state_dir: &Path, sid: &str, ext: &str) -> Option<PathBuf> {
    let sid = safe_id(sid);
    (!sid.is_empty()).then(|| dir(state_dir).join(format!("{sid}.{ext}")))
}

/// Path of a per-session file (`<sid>.<ext>`), None for an unusable id.
pub fn session_file(state_dir: &Path, sid: &str, ext: &str) -> Option<PathBuf> {
    file(state_dir, sid, ext)
}

pub fn read(state_dir: &Path, sid: &str) -> Option<SessionInfo> {
    let p = file(state_dir, sid, "json")?;
    let t = std::fs::read(p).ok()?;
    serde_json::from_slice(&t).ok()
}

/// Store `info` (stamped `now`) unless an identical report is younger than a minute.
pub fn record(state_dir: &Path, sid: &str, mut info: SessionInfo, now: i64) {
    let Some(p) = file(state_dir, sid, "json") else {
        return;
    };
    if let Some(old) = read(state_dir, sid) {
        let same = old.context_tokens == info.context_tokens
            && old.model_id == info.model_id
            && old.cache_ttl == info.cache_ttl;
        if same && (0..REFRESH_S).contains(&(now - old.updated_at)) {
            return;
        }
    }
    info.updated_at = now;
    if crate::ledger::ensure_private_dir(&dir(state_dir)).is_err() {
        return;
    }
    if let Ok(t) = serde_json::to_vec(&info) {
        let _ = crate::fsutil::write_atomic(&p, &t, Some(0o600));
    }
}

/// The session's report if it is at most `max_age_s` old.
pub fn lookup(state_dir: &Path, sid: &str, now: i64, max_age_s: i64) -> Option<SessionInfo> {
    read(state_dir, sid).filter(|i| {
        let age = now - i.updated_at;
        (-60..=max_age_s).contains(&age)
    })
}

/// Remove per-session files not touched for a week.
pub fn prune(state_dir: &Path, now: i64) {
    let Ok(rd) = std::fs::read_dir(dir(state_dir)) else {
        return;
    };
    for e in rd.flatten() {
        let old = e
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .is_some_and(|d| now - d.as_secs() as i64 > KEEP_S);
        if old {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_lookup_stale_and_private() {
        let d = tempfile::tempdir().unwrap();
        let info = SessionInfo {
            context_tokens: 123_456,
            model_id: "claude-sonnet-5-5".into(),
            cache_ttl: Some("1h".into()),
            updated_at: 0,
        };
        record(d.path(), "s-1", info.clone(), 1000);
        let got = lookup(d.path(), "s-1", 1100, 1800).unwrap();
        assert_eq!(got.context_tokens, 123_456);
        assert_eq!(got.updated_at, 1000);
        assert!(
            lookup(d.path(), "s-1", 1000 + 1801, 1800).is_none(),
            "stale"
        );
        assert!(lookup(d.path(), "other", 1100, 1800).is_none());
        // unchanged within a minute: not rewritten
        record(d.path(), "s-1", info.clone(), 1030);
        assert_eq!(read(d.path(), "s-1").unwrap().updated_at, 1000);
        // changed: rewritten
        record(
            d.path(),
            "s-1",
            SessionInfo {
                context_tokens: 1,
                ..info
            },
            1031,
        );
        assert_eq!(read(d.path(), "s-1").unwrap().updated_at, 1031);
        // hostile ids cannot escape the directory
        record(d.path(), "../../x", SessionInfo::default(), 5);
        assert!(dir(d.path()).join("x.json").exists());
        assert!(!d.path().join("x.json").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(dir(d.path()).join("s-1.json"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(m & 0o777, 0o600);
        }
    }
}
