//! `middleman watch`: a live, readable tail of the ledger for a second terminal.
//! Every field shown is cleaned first (model ids come from provider catalogs).

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::Duration;

use crate::fsutil::clean;
use crate::ledger::LedgerEntry;

fn hhmmss(ts: &str) -> String {
    // RFC 3339 "2026-11-10T14:22:40.47Z" -> "14:22:40Z"
    ts.split_once('T')
        .map(|(_, t)| format!("{}Z", t.chars().take(8).collect::<String>()))
        .unwrap_or_else(|| clean(ts, 20))
}

fn tok(n: Option<u64>) -> String {
    n.map(|x| x.to_string()).unwrap_or_else(|| "?".into())
}

/// One human-readable line per ledger entry.
pub fn format_line(e: &LedgerEntry) -> String {
    let status = clean(&e.status, 16);
    let blocked = matches!(status.as_str(), "blocked" | "do_it_yourself" | "error");
    let model = if e.provider.is_empty() {
        "-".to_string()
    } else {
        clean(&format!("{}/{}", e.provider, e.model), 60)
    };
    let redactions = if e.redactions.is_empty() {
        "no redactions".to_string()
    } else {
        let v: Vec<String> = e
            .redactions
            .iter()
            .map(|(k, n)| format!("{}={n}", clean(k, 20)))
            .collect();
        format!("redacted {}", v.join(" "))
    };
    let sens = if e.effective_sensitivity.is_empty() {
        "-".into()
    } else {
        clean(&e.effective_sensitivity, 4)
    };
    let mut s = format!(
        "{}  {:<8} {:<14} {:<44} {:<3} {}",
        hhmmss(&e.ts),
        if blocked {
            status.to_uppercase()
        } else {
            status.clone()
        },
        clean(&e.task_kind, 14),
        model,
        sens,
        redactions
    );
    if blocked {
        s.push_str(&format!(
            "  reason: {}",
            e.block_reason_category
                .as_deref()
                .map(|r| clean(r, 40))
                .unwrap_or_else(|| "unknown".into())
        ));
    } else {
        s.push_str(&format!(
            "  {}→{} tok  ${:.4}",
            tok(e.input_tokens),
            tok(e.output_tokens),
            e.cost_usd
        ));
    }
    s.push_str(&format!(
        "  net {}${:.4}",
        if e.net_savings_usd < 0.0 { "-" } else { "+" },
        e.net_savings_usd.abs()
    ));
    if let Some(sid) = &e.session_id {
        s.push_str(&format!(
            "  session {}",
            crate::statusline::safe_id(sid)
                .chars()
                .take(8)
                .collect::<String>()
        ));
    }
    s
}

fn emit(out: &mut dyn Write, text: &str) -> std::io::Result<()> {
    for l in text.lines().filter(|l| !l.trim().is_empty()) {
        match serde_json::from_str::<LedgerEntry>(l) {
            Ok(e) => writeln!(out, "{}", format_line(&e.upgrade()))?,
            Err(_) => writeln!(out, "(unreadable ledger line skipped)")?,
        }
    }
    out.flush()
}

/// Print the last `tail` entries, then (if `follow`) new ones as they arrive. The file may
/// not exist yet; truncation restarts from the top.
pub fn run(path: &Path, tail: usize, follow: bool, out: &mut dyn Write) -> std::io::Result<()> {
    let mut offset = 0u64;
    if let Ok(text) = std::fs::read_to_string(path) {
        let lines: Vec<&str> = text.lines().collect();
        let start = lines.len().saturating_sub(tail);
        emit(out, &lines[start..].join("\n"))?;
        offset = text.len() as u64;
    }
    if !follow {
        return Ok(());
    }
    writeln!(
        out,
        "-- watching {} (Ctrl-C to stop) --",
        crate::fsutil::pretty(path)
    )?;
    out.flush()?;
    let mut pending = String::new();
    loop {
        std::thread::sleep(Duration::from_millis(500));
        let Ok(mut f) = std::fs::File::open(path) else {
            continue;
        };
        let len = f.metadata().map(|m| m.len()).unwrap_or(0);
        if len < offset {
            offset = 0;
            pending.clear();
        }
        if len == offset {
            continue;
        }
        if f.seek(SeekFrom::Start(offset)).is_err() {
            continue;
        }
        let mut buf = Vec::new();
        if f.take(len - offset).read_to_end(&mut buf).is_err() {
            continue;
        }
        offset += buf.len() as u64;
        pending.push_str(&String::from_utf8_lossy(&buf));
        if let Some(i) = pending.rfind('\n') {
            let complete: String = pending.drain(..=i).collect();
            emit(out, &complete)?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readable_lines() {
        let mut e = LedgerEntry {
            ts: "2026-11-10T14:22:40.474Z".into(),
            status: "ok".into(),
            task_kind: "write_tests".into(),
            provider: "openrouter".into(),
            model: "deepseek/deepseek-v4.1-flash\u{1b}[2J".into(),
            effective_sensitivity: "S1".into(),
            input_tokens: Some(1240),
            output_tokens: Some(2050),
            cost_usd: 0.0028,
            net_savings_usd: 0.0216,
            session_id: Some("abcdef123456".into()),
            ..Default::default()
        };
        e.redactions.insert("dictionary".into(), 5);
        let l = format_line(&e);
        assert!(l.starts_with("14:22:40Z  ok"), "{l}");
        assert!(l.contains("openrouter/deepseek/deepseek-v4.1-flash"));
        assert!(!l.contains('\u{1b}'));
        assert!(l.contains("redacted dictionary=5"));
        assert!(l.contains("1240→2050 tok  $0.0028  net +$0.0216  session abcdef12"));
        e.status = "blocked".into();
        e.block_reason_category = Some("secret".into());
        e.net_savings_usd = -0.0166;
        let l = format_line(&e);
        assert!(
            l.contains("BLOCKED") && l.contains("reason: secret") && l.contains("net -$0.0166")
        );
    }

    #[test]
    fn no_follow_prints_tail() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("ledger.jsonl");
        let e = LedgerEntry {
            ts: "2026-11-10T01:02:03Z".into(),
            status: "ok".into(),
            ..Default::default()
        };
        let line = serde_json::to_string(&e).unwrap();
        std::fs::write(&p, format!("{line}\n{line}\ngarbage\n")).unwrap();
        let mut out = Vec::new();
        run(&p, 2, false, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert_eq!(s.lines().count(), 2);
        assert!(s.contains("unreadable"));
    }
}
