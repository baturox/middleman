//! Usage ledger (v2): JSONL, one line per delegation attempt (escalation steps share
//! `request_id` with an increasing `attempt`), blocked requests included with cost 0.
//! One `write` per line, O_APPEND, 0600. Old v1 lines are read tolerantly (missing fields
//! default; v1 `cost_source = "tokens"` reads as `usage`).

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::budget::Window;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct LedgerEntry {
    pub ts: String,
    pub request_id: String,
    pub attempt: u32,
    pub project: String,
    pub task_kind: String,
    pub quality: String,
    pub mode: String,
    pub chain_step: String,
    pub provider: String,
    pub model: String,
    pub trust: String,
    pub effective_sensitivity: String,
    /// ok | blocked | error | escalated | do_it_yourself
    pub status: String,
    pub block_reason_category: Option<String>,
    pub redactions: BTreeMap<String, usize>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cost_usd: f64,
    /// balance | usage | estimate
    pub cost_source: String,
    pub latency_ms: Option<u64>,
    pub write_mode: String,
    pub output_bytes: Option<u64>,
    pub claude_model: String,
    pub claude_equiv_usd: f64,
    pub claude_overhead_usd: f64,
    pub net_savings_usd: f64,
    /// passed | failed | skipped
    pub validation: String,
}

impl LedgerEntry {
    /// Unix seconds parsed from `ts` (RFC 3339); unparseable timestamps count as "now" so a
    /// corrupted line can never hide spend from the caps.
    pub fn ts_unix(&self) -> i64 {
        time::OffsetDateTime::parse(&self.ts, &time::format_description::well_known::Rfc3339)
            .map(|t| t.unix_timestamp())
            .unwrap_or_else(|_| now_unix())
    }

    /// Normalize v1 values.
    fn upgrade(mut self) -> Self {
        if self.cost_source == "tokens" {
            self.cost_source = "usage".into();
        }
        if self.status.is_empty() {
            self.status = "ok".into();
        }
        self
    }
}

pub fn now_unix() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

pub fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

pub fn rfc3339_at(unix: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}

pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Append one JSON line with a single write call on an O_APPEND, 0600 file.
pub fn append_jsonl<T: Serialize>(path: &Path, rec: &T) -> Result<()> {
    let mut line = serde_json::to_vec(rec)?;
    line.push(b'\n');
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    f.write_all(&line)?;
    Ok(())
}

pub struct Ledger {
    path: PathBuf,
}

impl Ledger {
    pub fn new(state_dir: &Path) -> Result<Ledger> {
        ensure_private_dir(state_dir)?;
        Ok(Ledger {
            path: state_dir.join("ledger.jsonl"),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(&self, e: &LedgerEntry) -> Result<()> {
        append_jsonl(&self.path, e)
    }

    /// Unparseable lines are an error: a corrupted ledger must not under-count spend.
    pub fn entries(&self) -> Result<Vec<LedgerEntry>> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(e).context("cannot read ledger"),
        };
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                serde_json::from_str::<LedgerEntry>(l)
                    .map(LedgerEntry::upgrade)
                    .context("corrupt ledger line")
            })
            .collect()
    }

    pub fn window(&self) -> Result<Window> {
        Ok(window_at(&self.entries()?, now_unix()))
    }
}

/// Daily = since 00:00 UTC of `now`; weekly = rolling 7 x 24h.
pub fn window_at(entries: &[LedgerEntry], now: i64) -> Window {
    let day_start = now - now.rem_euclid(86_400);
    let week_start = now - 7 * 86_400;
    let mut w = Window::default();
    for e in entries {
        let t = e.ts_unix();
        if t >= day_start && t <= now {
            w.day_usd += e.cost_usd;
        }
        if t > week_start && t <= now {
            w.week_usd += e.cost_usd;
        }
    }
    w
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(ts: i64, cost: f64) -> LedgerEntry {
        LedgerEntry {
            ts: rfc3339_at(ts),
            request_id: "r".into(),
            status: "ok".into(),
            cost_usd: cost,
            cost_source: "usage".into(),
            ..Default::default()
        }
    }

    #[test]
    fn window_across_midnight() {
        let midnight = 1_767_225_600; // 2026-01-01T00:00:00Z
        let entries = vec![
            e(midnight - 60, 0.30),         // 23:59 yesterday
            e(midnight + 60, 0.10),         // 00:01 today
            e(midnight - 8 * 86_400, 1.0),  // outside the week
            e(midnight - 6 * 86_400, 0.05), // inside the week
        ];
        let w = window_at(&entries, midnight + 120);
        assert!((w.day_usd - 0.10).abs() < 1e-9);
        assert!((w.week_usd - 0.45).abs() < 1e-9);
    }

    #[test]
    fn append_and_read_0600() {
        let d = tempfile::tempdir().unwrap();
        let l = Ledger::new(d.path()).unwrap();
        l.append(&e(now_unix(), 0.01)).unwrap();
        l.append(&e(now_unix(), 0.02)).unwrap();
        assert_eq!(l.entries().unwrap().len(), 2);
        assert!((l.window().unwrap().day_usd - 0.03).abs() < 1e-9);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(l.path()).unwrap().permissions().mode();
            assert_eq!(m & 0o777, 0o600);
        }
    }

    #[test]
    fn reads_v1_lines() {
        let d = tempfile::tempdir().unwrap();
        let l = Ledger::new(d.path()).unwrap();
        let v1 = r#"{"ts":"2026-11-10T14:22:40.474565Z","ts_unix":1794320560,"request_id":"x","provider":"yzlab","model":"gpt-5.6-luna","task_kind":"docstring","status":"ok","est_worst_usd":0.000193,"cost_usd":0.000116,"cost_source":"balance","input_tokens":248,"output_tokens":215}"#;
        std::fs::write(l.path(), format!("{v1}\n")).unwrap();
        append_jsonl(l.path(), &e(now_unix(), 0.5)).unwrap();
        let es = l.entries().unwrap();
        assert_eq!(es.len(), 2);
        assert_eq!(es[0].model, "gpt-5.6-luna");
        assert_eq!(es[0].output_tokens, Some(215));
        assert_eq!(es[0].attempt, 0);
        assert!(es[0].ts_unix() > 1_700_000_000);
    }
}
