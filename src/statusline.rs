//! `middleman statusline`: one compact line for Claude Code's `statusLine` command.
//!
//! Claude Code pipes a JSON object to the command on stdin (documented at
//! <https://code.claude.com/docs/en/statusline>); we use `session_id` and
//! `workspace.current_dir` (falling back to `cwd`). The command must be fast and must never
//! fail: every error becomes part of the line, and the exit code is always 0.
//!
//! Example: `🛡 middleman ✓ openrouter · 3 delegated today (1 this session) · saved $0.21 · 1 blocked`

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::config::{Config, KeySource, KeyStatus, ProviderCfg};
use crate::fsutil::clean;
use crate::ledger::{Ledger, LedgerEntry};

/// Positive keychain lookups are cached this long, so the statusline does not hit the
/// credential store on every refresh.
const KEY_CACHE_TTL: i64 = 600;
const LEDGER_TAIL: u64 = 2 << 20;

/// `CLAUDE_CODE_SESSION_ID` from the environment (set by Claude Code for hooks and stdio
/// MCP servers), reduced to a safe token.
pub fn session_from_env() -> Option<String> {
    std::env::var("CLAUDE_CODE_SESSION_ID")
        .ok()
        .map(|s| safe_id(&s))
        .filter(|s| !s.is_empty())
}

pub fn safe_id(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(64)
        .collect()
}

#[derive(Debug, Default, PartialEq)]
pub struct Today {
    pub delegated: usize,
    pub delegated_session: usize,
    pub saved_usd: f64,
    pub blocked: usize,
}

/// Today's (UTC) totals. One delegation = one `ok` line; blocked = refused requests.
pub fn today(entries: &[LedgerEntry], now: i64, session: Option<&str>) -> Today {
    let day_start = now - now.rem_euclid(86_400);
    let mut t = Today::default();
    for e in entries {
        let ts = e.ts_unix();
        if ts < day_start || ts > now + 60 {
            continue;
        }
        t.saved_usd += e.net_savings_usd;
        match e.status.as_str() {
            "ok" => {
                t.delegated += 1;
                if session.is_some() && e.session_id.as_deref() == session {
                    t.delegated_session += 1;
                }
            }
            "blocked" | "do_it_yourself" => t.blocked += 1,
            _ => {}
        }
    }
    t
}

fn cache_path(cfg: &Config) -> PathBuf {
    cfg.state_dir().join("statusline-keys.json")
}

fn key_ok(cfg: &Config, p: &ProviderCfg, now: i64) -> Result<(), String> {
    let env_set = p
        .key_env
        .as_ref()
        .is_some_and(|e| std::env::var_os(e).is_some_and(|v| !v.is_empty()));
    if p.key_source == Some(KeySource::Keychain) && !env_set {
        let path = cache_path(cfg);
        let mut cache: BTreeMap<String, i64> = std::fs::read_to_string(&path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        if cache
            .get(&p.name)
            .is_some_and(|t| now - t < KEY_CACHE_TTL && *t <= now)
        {
            return Ok(());
        }
        let st = p.key_status();
        if st.ok() {
            cache.insert(p.name.clone(), now);
            if let Ok(t) = serde_json::to_string(&cache) {
                let _ = crate::fsutil::write_atomic(&path, t.as_bytes(), Some(0o600));
            }
            return Ok(());
        }
        return Err(no_key(p));
    }
    match p.key_status() {
        KeyStatus::Missing(_) => Err(no_key(p)),
        _ => Ok(()),
    }
}

fn no_key(p: &ProviderCfg) -> String {
    format!("no key for {0} (run: middleman provider add {0})", p.name)
}

fn money(x: f64) -> String {
    if x < 0.0 {
        format!("-${:.2}", -x)
    } else {
        format!("${x:.2}")
    }
}

/// The status line for this stdin payload. Never panics on bad input.
pub fn render(input: &str, cfg_path: &Path, now: i64) -> String {
    let v: Value = serde_json::from_str(input).unwrap_or(Value::Null);
    let session = v
        .get("session_id")
        .and_then(Value::as_str)
        .map(safe_id)
        .filter(|s| !s.is_empty());
    let cwd = v
        .pointer("/workspace/current_dir")
        .or_else(|| v.get("cwd"))
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));
    let cfg = match Config::load_with_project(cfg_path, &cwd) {
        Ok((c, _)) => c,
        Err(e) => {
            let msg = format!("{e:#}");
            let first = msg.split(':').next().unwrap_or("config error");
            return format!("🛡 middleman ✗ {} (run: middleman doctor)", clean(first, 60));
        }
    };
    let enabled: Vec<&ProviderCfg> = cfg.providers.values().filter(|p| p.enabled).collect();
    if enabled.is_empty() {
        return "🛡 middleman ✗ no provider enabled (run: middleman provider add openrouter)".into();
    }
    let mut ready = vec![];
    let mut first_err = None;
    for p in &enabled {
        match key_ok(&cfg, p, now) {
            Ok(()) => ready.push(p.name.as_str()),
            Err(e) => {
                first_err.get_or_insert(e);
            }
        }
    }
    let Some(head) = ready.first() else {
        return format!(
            "🛡 middleman ✗ {}",
            first_err.unwrap_or_else(|| "no key".into())
        );
    };
    let who = if ready.len() > 1 {
        format!("{} +{}", clean(head, 24), ready.len() - 1)
    } else {
        clean(head, 24)
    };
    let entries = Ledger::new(&cfg.state_dir())
        .map(|l| l.tail_entries(LEDGER_TAIL))
        .unwrap_or_default();
    let t = today(&entries, now, session.as_deref());
    let mut parts = vec![
        format!("🛡 middleman ✓ {who}"),
        if t.delegated_session > 0 {
            format!(
                "{} delegated today ({} this session)",
                t.delegated, t.delegated_session
            )
        } else {
            format!("{} delegated today", t.delegated)
        },
    ];
    if t.delegated > 0 || t.saved_usd != 0.0 {
        parts.push(format!("saved {}", money(t.saved_usd)));
    }
    if t.blocked > 0 {
        parts.push(format!("{} blocked", t.blocked));
    }
    parts.join(" · ")
}

/// Entry point used by `main`: read stdin (capped), render, never fail.
pub fn run(cfg_path: &Path) -> String {
    use std::io::Read;
    let mut input = String::new();
    let _ = std::io::stdin().take(1 << 20).read_to_string(&mut input);
    let now = crate::ledger::now_unix();
    std::panic::catch_unwind(|| render(&input, cfg_path, now))
        .unwrap_or_else(|_| "🛡 middleman ✗ internal error (run: middleman doctor)".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(ts: i64, status: &str, net: f64, session: Option<&str>) -> LedgerEntry {
        LedgerEntry {
            ts: crate::ledger::rfc3339_at(ts),
            status: status.into(),
            net_savings_usd: net,
            claude_equiv_usd: net.max(0.0),
            claude_overhead_usd: (-net).max(0.0),
            session_id: session.map(String::from),
            ..Default::default()
        }
    }

    #[test]
    fn counts_today_only() {
        let now = 1_767_225_600 + 3600;
        let es = vec![
            entry(now - 10, "ok", 0.1, Some("s1")),
            entry(now - 20, "ok", 0.11, None),
            entry(now - 30, "blocked", -0.01, Some("s1")),
            entry(now - 2 * 86_400, "ok", 5.0, None),
            entry(now - 40, "escalated", 0.0, None),
        ];
        let t = today(&es, now, Some("s1"));
        assert_eq!(t.delegated, 2);
        assert_eq!(t.delegated_session, 1);
        assert_eq!(t.blocked, 1);
        assert!((t.saved_usd - 0.20).abs() < 1e-9);
    }

    fn cfg(d: &Path, extra: &str) -> PathBuf {
        let p = d.join("config.toml");
        std::fs::write(
            &p,
            format!(
                "state_dir = \"{0}/state\"\n[paths]\nroots = [\"{0}\"]\n{extra}",
                d.display()
            ),
        )
        .unwrap();
        p
    }

    #[test]
    fn renders_ok_line_and_errors() {
        let d = tempfile::tempdir().unwrap();
        let p = cfg(
            d.path(),
            "[providers.lm]\npreset = \"ollama\"\n[providers.or]\npreset = \"openrouter\"\nkey_env = \"MM_TEST_UNSET_SL_1\"\n",
        );
        let now = crate::ledger::now_unix();
        let l = Ledger::new(&d.path().join("state")).unwrap();
        l.append(&entry(now - 5, "ok", 0.21, Some("abc"))).unwrap();
        l.append(&entry(now - 4, "blocked", 0.0, None)).unwrap();
        let input = format!(
            r#"{{"session_id":"abc","workspace":{{"current_dir":"{}"}}}}"#,
            d.path().display()
        );
        let line = render(&input, &p, now);
        assert_eq!(
            line,
            "🛡 middleman ✓ lm · 1 delegated today (1 this session) · saved $0.21 · 1 blocked"
        );
        // garbage stdin still renders
        assert!(render("not json", &p, now).starts_with("🛡 middleman ✓"));
        // broken config
        let bad = d.path().join("nope.toml");
        assert!(render("{}", &bad, now).starts_with("🛡 middleman ✗ cannot read config"));
        // no key
        let p2 = cfg(
            d.path(),
            "[providers.or]\npreset = \"openrouter\"\nkey_env = \"MM_TEST_UNSET_SL_2\"\n",
        );
        assert_eq!(
            render("{}", &p2, now),
            "🛡 middleman ✗ no key for or (run: middleman provider add or)"
        );
    }
}
