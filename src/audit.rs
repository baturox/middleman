//! Audit log: `audit-YYYY-MM.jsonl` (0600). Records the sanitized payload exactly as sent,
//! the SHA-256 of the original payload, finding counts, decision and cost. Never originals.
//! Note: it retains the *sanitized* payload (pseudonymized text) and scrubbed provider error
//! bodies; protect the state dir accordingly (0700 dir, 0600 files).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::ledger::{append_jsonl, ensure_private_dir};

#[derive(Debug, Clone, Serialize, Default)]
pub struct AuditRecord {
    pub ts: String,
    pub request_id: String,
    pub status: String,
    pub task_kind: String,
    pub declared: String,
    pub effective: Option<String>,
    pub complexity: Option<String>,
    pub decision: Option<String>,
    pub block_reason: Option<String>,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub finding_counts: BTreeMap<String, usize>,
    pub original_sha256: String,
    pub sent: bool,
    pub dry_run: bool,
    pub sanitized_system: Option<String>,
    pub sanitized_user: Option<String>,
    pub cost_usd: f64,
    pub cost_source: Option<String>,
    pub warnings: Vec<String>,
    /// Scrubbed, truncated provider error bodies (never shown to Claude).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub provider_errors: Vec<String>,
}

pub fn sha256_hex(s: &str) -> String {
    let d = Sha256::digest(s.as_bytes());
    d.iter().map(|b| format!("{b:02x}")).collect()
}

pub struct Audit {
    dir: PathBuf,
}

impl Audit {
    pub fn new(state_dir: &Path) -> Result<Audit> {
        ensure_private_dir(state_dir)?;
        Ok(Audit {
            dir: state_dir.to_path_buf(),
        })
    }

    pub fn current_path(&self) -> PathBuf {
        let now = time::OffsetDateTime::now_utc();
        self.dir.join(format!(
            "audit-{:04}-{:02}.jsonl",
            now.year(),
            u8::from(now.month())
        ))
    }

    pub fn write(&self, rec: &AuditRecord) -> Result<()> {
        append_jsonl(&self.current_path(), rec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha_and_write() {
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let d = tempfile::tempdir().unwrap();
        let a = Audit::new(d.path()).unwrap();
        a.write(&AuditRecord::default()).unwrap();
        assert!(a.current_path().exists());
    }
}
