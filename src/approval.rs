//! One-time approval tokens for `routing.mode = "confirm"`.
//!
//! A dry run in confirm mode issues an `approval_id` bound to a fingerprint of the request
//! (`<state>/approvals/<id>.pending`). The user approves it with `middleman approve <id>` in
//! their own terminal (`<id>.approved`). A confirmed call must present an id that is approved,
//! unexpired (30 min), unused, and whose fingerprint matches the request being sent; the
//! token is consumed on use. The model cannot approve on its own unless it can run the CLI in
//! an interactive terminal, which `approve` requires.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ledger::{ensure_private_dir, now_unix};

pub const TTL_SECS: i64 = 30 * 60;

#[derive(Debug, Error, PartialEq)]
pub enum ApprovalError {
    #[error("approval_id is malformed")]
    Malformed,
    #[error("approval_id is unknown or was already used")]
    Unknown,
    #[error("approval_id has not been approved by the user (run `middleman approve <id>` in a terminal)")]
    NotApproved,
    #[error("approval_id expired; run a new dry run")]
    Expired,
    #[error("approval_id was issued for a different request")]
    Mismatch,
    #[error("approval store error: {0}")]
    Io(String),
}

#[derive(Debug, Serialize, Deserialize)]
struct Pending {
    created: i64,
    fingerprint: String,
}

pub struct Approvals {
    dir: PathBuf,
}

fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

impl Approvals {
    pub fn new(state_dir: &Path) -> Approvals {
        Approvals {
            dir: state_dir.join("approvals"),
        }
    }

    fn path(&self, id: &str, ext: &str) -> PathBuf {
        self.dir.join(format!("{id}.{ext}"))
    }

    /// New pending approval for `fingerprint`; returns its id.
    pub fn issue(&self, fingerprint: &str) -> Result<String> {
        ensure_private_dir(&self.dir)?;
        self.sweep();
        let id = uuid::Uuid::new_v4().simple().to_string();
        let p = Pending {
            created: now_unix(),
            fingerprint: fingerprint.to_string(),
        };
        crate::ledger::write_private(&self.path(&id, "pending"), &serde_json::to_vec(&p)?)?;
        Ok(id)
    }

    fn load(&self, id: &str) -> Result<Pending, ApprovalError> {
        if !valid_id(id) {
            return Err(ApprovalError::Malformed);
        }
        let text = std::fs::read_to_string(self.path(id, "pending"))
            .map_err(|_| ApprovalError::Unknown)?;
        let p: Pending = serde_json::from_str(&text).map_err(|_| ApprovalError::Unknown)?;
        if now_unix() - p.created > TTL_SECS || p.created > now_unix() + 60 {
            return Err(ApprovalError::Expired);
        }
        Ok(p)
    }

    /// User side (`middleman approve <id>`).
    pub fn approve(&self, id: &str) -> Result<()> {
        self.load(id).map_err(|e| anyhow::anyhow!("{e}"))?;
        crate::ledger::write_private(&self.path(id, "approved"), b"approved\n")
            .context("cannot write approval")?;
        Ok(())
    }

    /// Server side: validate and consume.
    pub fn consume(&self, id: &str, fingerprint: &str) -> Result<(), ApprovalError> {
        let p = self.load(id)?;
        if !self.path(id, "approved").is_file() {
            return Err(ApprovalError::NotApproved);
        }
        if p.fingerprint != fingerprint {
            return Err(ApprovalError::Mismatch);
        }
        // consume: whoever removes the pending file first wins
        std::fs::remove_file(self.path(id, "pending")).map_err(|_| ApprovalError::Unknown)?;
        let _ = std::fs::remove_file(self.path(id, "approved"));
        Ok(())
    }

    /// Drop expired tokens (best effort).
    fn sweep(&self) {
        let Ok(rd) = std::fs::read_dir(&self.dir) else {
            return;
        };
        for e in rd.flatten() {
            let p = e.path();
            let old = e
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|d| d.as_secs() as i64 > 2 * TTL_SECS);
            if old {
                let _ = std::fs::remove_file(p);
            }
        }
    }
}

/// CLI guard: approvals must come from a person at a terminal.
pub fn require_terminal() -> Result<()> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        bail!("`middleman approve` must be run by the user in an interactive terminal");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_approve_consume_once() {
        let d = tempfile::tempdir().unwrap();
        let a = Approvals::new(d.path());
        let id = a.issue("fp1").unwrap();
        assert_eq!(a.consume(&id, "fp1"), Err(ApprovalError::NotApproved));
        a.approve(&id).unwrap();
        assert_eq!(a.consume(&id, "other"), Err(ApprovalError::Mismatch));
        assert_eq!(a.consume(&id, "fp1"), Ok(()));
        assert_eq!(a.consume(&id, "fp1"), Err(ApprovalError::Unknown));
        assert_eq!(
            a.consume("../../etc/passwd", "fp1"),
            Err(ApprovalError::Malformed)
        );
        assert!(a.approve("0123456789abcdef0123456789abcdef").is_err());
    }
}
