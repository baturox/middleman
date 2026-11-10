//! Is any other provider call in flight? A balance delta (before - after) is only this call's
//! cost when no other call (another session's MCP server, another middleman process) spent
//! from the same account in between.
//!
//! Each call creates a marker file in `<state>/inflight/` and appends one byte to
//! `<state>/inflight.log`. The call was alone if no other marker existed when it started and
//! the log did not grow while it ran (a call that started and finished inside our window
//! still grew the log).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Markers older than this belong to a crashed process and are ignored.
const STALE: Duration = Duration::from_secs(15 * 60);

pub struct InFlight {
    marker: PathBuf,
    log: PathBuf,
    log_len_at_start: u64,
    others_at_start: bool,
}

fn others(dir: &Path, mine: &Path) -> bool {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return false;
    };
    let now = SystemTime::now();
    rd.flatten().any(|e| {
        let p = e.path();
        if p == mine {
            return false;
        }
        let fresh = e
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| now.duration_since(t).ok())
            .is_some_and(|age| age < STALE);
        if !fresh {
            let _ = std::fs::remove_file(&p);
        }
        fresh
    })
}

fn len(p: &Path) -> u64 {
    std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)
}

impl InFlight {
    /// Register a call. None when the state directory is unusable (then a balance delta is
    /// never trusted).
    pub fn begin(state_dir: &Path) -> Option<InFlight> {
        let dir = state_dir.join("inflight");
        crate::ledger::ensure_private_dir(&dir).ok()?;
        let marker = dir.join(uuid::Uuid::new_v4().simple().to_string());
        crate::ledger::write_private(&marker, b"").ok()?;
        let log = state_dir.join("inflight.log");
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(&log).ok()?.write_all(b".").ok()?;
        let log_len_at_start = len(&log);
        let others_at_start = others(&dir, &marker);
        Some(InFlight {
            marker,
            log,
            log_len_at_start,
            others_at_start,
        })
    }

    /// True if another call overlapped this one (so far).
    pub fn overlapped(&self) -> bool {
        let dir = self.marker.parent().unwrap_or(Path::new("."));
        self.others_at_start || len(&self.log) > self.log_len_at_start || others(dir, &self.marker)
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.marker);
    }
}

/// `overlapped` for an optional guard: no guard means "cannot tell", i.e. overlapped.
pub fn overlapped(g: &Option<InFlight>) -> bool {
    g.as_ref().is_none_or(InFlight::overlapped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_overlap_both_ways() {
        let d = tempfile::tempdir().unwrap();
        let a = InFlight::begin(d.path()).unwrap();
        assert!(!a.overlapped());
        {
            // b starts while a runs: both see the other
            let b = InFlight::begin(d.path()).unwrap();
            assert!(b.overlapped());
            assert!(a.overlapped());
        }
        // b finished inside a's window: a still knows
        assert!(a.overlapped());
        drop(a);
        let c = InFlight::begin(d.path()).unwrap();
        assert!(!c.overlapped(), "markers are removed on drop");
        assert!(overlapped(&None));
    }
}
