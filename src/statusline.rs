//! `middleman statusline`: Claude Code's `statusLine` command.
//!
//! Claude Code pipes a JSON object on stdin (<https://code.claude.com/docs/en/statusline>).
//! Fields used, every one optional: `session_id`, `transcript_path`,
//! `workspace.current_dir` / `cwd`, `model.{id, display_name}`, `effort.level`, `fast_mode`,
//! `context_window.{context_window_size, used_percentage, current_usage.{input_tokens,
//! cache_creation_input_tokens, cache_read_input_tokens}}`, `cost.total_cost_usd`,
//! `prompt_cache.{caching_observed, warm, expires_at, ttl, recache_tokens_if_cold}` and
//! `rate_limits.five_hour.used_percentage`.
//!
//! ```text
//! Opus 5.5 high │ ██░░░░░░░░ 18% 180k/1M │ ~$1.27 │ cache 47m left (1h)
//! 🛡 middleman ✓ openrouter $7.42 left · 3 jobs this session (1 blocked) · 5 today · 2 agents · saved $0.05 session · $0.21 today · $1.84 total
//! ```
//! The Claude part is a port of context-line (same thresholds, colours and env overrides).
//! The command never does network I/O and never fails: provider limits come from a cache
//! (`limits`), subagents from an incremental transcript scan (`transcript`), ledger totals
//! from an incremental aggregate. Every printed field is cleaned of control characters.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::{BalanceKind, Config, KeySource, KeyStatus, ProviderCfg};
use crate::fsutil::clean;
use crate::ledger::LedgerEntry;
use crate::limits::{self, LimitsCache};
use crate::report::Agg;
use crate::session::{self, SessionInfo};

/// Positive keychain lookups are cached this long, so the statusline does not hit the
/// credential store on every refresh.
const KEY_CACHE_TTL: i64 = 600;

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

// ------------------------------------------------------------------ options

/// Colour thresholds (context-line's defaults and env names).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Thresholds {
    pub warn_pct: f64,
    pub danger_pct: f64,
    pub warn_tokens: f64,
    pub danger_tokens: f64,
    pub cost_warn: f64,
    /// Opt-in parts (`MIDDLEMAN_SL_SHOW_COST|CACHE|HINT=1`): off by default, because on a
    /// subscription the session cost is an API-price estimate, not money spent.
    pub show_cost: bool,
    pub show_cache: bool,
    pub show_hint: bool,
}

impl Default for Thresholds {
    fn default() -> Self {
        Thresholds {
            warn_pct: 40.0,
            danger_pct: 70.0,
            warn_tokens: 150_000.0,
            danger_tokens: 300_000.0,
            cost_warn: 5.0,
            show_cost: false,
            show_cache: false,
            show_hint: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Opts {
    pub columns: usize,
    pub color: bool,
    /// 1: one line (Claude part │ middleman part); 2: Claude part, then middleman part.
    pub lines: u8,
    /// Only the middleman part (to chain after another status line script).
    pub middleman_only: bool,
    /// Also show Claude output tokens avoided today.
    pub show_tokens: bool,
    pub env: Thresholds,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            columns: 120,
            color: false,
            lines: 1,
            middleman_only: false,
            show_tokens: false,
            env: Thresholds::default(),
        }
    }
}

/// A positive number from `MIDDLEMAN_SL_<name>`, else `CONTEXT_LINE_<name>`.
fn env_num(get: &dyn Fn(&str) -> Option<String>, name: &str) -> Option<f64> {
    [
        format!("MIDDLEMAN_SL_{name}"),
        format!("CONTEXT_LINE_{name}"),
    ]
    .iter()
    .filter_map(|k| get(k))
    .filter_map(|v| v.trim().parse::<f64>().ok())
    .find(|v| v.is_finite() && *v > 0.0)
}

impl Opts {
    /// From environment variables (`get` = `std::env::var`, injectable for tests).
    pub fn from_env(get: &dyn Fn(&str) -> Option<String>) -> Opts {
        let d = Thresholds::default();
        let n = |k: &str, dv: f64| env_num(get, k).unwrap_or(dv);
        let flag =
            |k: &str| get(&format!("MIDDLEMAN_SL_SHOW_{k}")).is_some_and(|v| v.trim() == "1");
        Opts {
            columns: get("COLUMNS")
                .and_then(|c| c.trim().parse::<usize>().ok())
                .filter(|c| *c > 0)
                .unwrap_or(120),
            // (the real tty width is applied by the CLI entry point, see `tty_columns`)
            color: get("NO_COLOR").is_none_or(|v| v.is_empty()),
            lines: match get("MIDDLEMAN_SL_LINES").as_deref().map(str::trim) {
                Some("2") => 2,
                _ => 1,
            },
            middleman_only: false,
            show_tokens: get("MIDDLEMAN_SL_TOKENS").is_some_and(|v| v.trim() == "1"),
            env: Thresholds {
                warn_pct: n("WARN_PCT", d.warn_pct),
                danger_pct: n("DANGER_PCT", d.danger_pct),
                warn_tokens: n("WARN_TOKENS", d.warn_tokens),
                danger_tokens: n("DANGER_TOKENS", d.danger_tokens),
                cost_warn: n("COST_WARN", d.cost_warn),
                show_cost: flag("COST"),
                show_cache: flag("CACHE"),
                show_hint: flag("HINT"),
            },
        }
    }
}

// ------------------------------------------------------------------ styled text

#[derive(Debug, Clone, Copy, PartialEq)]
enum C {
    Green,
    Yellow,
    Red,
    Dim,
    BoldCyan,
}

impl C {
    fn code(self) -> &'static str {
        match self {
            C::Green => "32",
            C::Yellow => "33",
            C::Red => "31",
            C::Dim => "2",
            C::BoldCyan => "1;36",
        }
    }
}

/// Text with its plain and coloured renderings (width is measured on the plain one).
#[derive(Debug, Clone, Default)]
struct T {
    plain: String,
    ansi: String,
}

impl T {
    fn raw(s: &str) -> T {
        T {
            plain: s.into(),
            ansi: s.into(),
        }
    }
    fn paint(s: &str, c: C) -> T {
        T {
            plain: s.into(),
            ansi: format!("\x1b[{}m{s}\x1b[0m", c.code()),
        }
    }
    fn push(&mut self, t: T) -> &mut Self {
        self.plain.push_str(&t.plain);
        self.ansi.push_str(&t.ansi);
        self
    }
    fn s(&mut self, s: &str) -> &mut Self {
        self.push(T::raw(s))
    }
    fn p(&mut self, s: &str, c: C) -> &mut Self {
        self.push(T::paint(s, c))
    }
    fn join(parts: Vec<T>, sep: &T) -> T {
        let mut out = T::default();
        for (i, p) in parts
            .into_iter()
            .filter(|p| !p.plain.is_empty())
            .enumerate()
        {
            if i > 0 {
                out.push(sep.clone());
            }
            out.push(p);
        }
        out
    }
    /// Terminal columns: wide emoji count 2.
    fn width(&self) -> usize {
        self.plain
            .chars()
            .map(|c| if (c as u32) >= 0x1F000 { 2 } else { 1 })
            .sum()
    }
    fn out(&self, color: bool) -> String {
        if color {
            self.ansi.clone()
        } else {
            self.plain.clone()
        }
    }
}

// ------------------------------------------------------------------ Claude part (context-line)

/// A positive finite number, else 0 (wrong types count as absent).
fn count(v: Option<&Value>) -> f64 {
    v.and_then(Value::as_f64)
        .filter(|n| n.is_finite() && *n > 0.0)
        .unwrap_or(0.0)
}

fn s60(v: Option<&Value>) -> String {
    v.and_then(Value::as_str)
        .map(|s| clean(s, 60))
        .unwrap_or_default()
}

pub fn tokens(n: f64) -> String {
    if n >= 1e6 {
        let x = n / 1e6;
        let s = if n >= 1e7 {
            format!("{x:.0}")
        } else {
            format!("{x:.1}")
        };
        format!("{}M", s.trim_end_matches(".0"))
    } else if n >= 1e3 {
        format!("{}k", (n / 1e3).round())
    } else {
        format!("{}", n.round())
    }
}

pub fn model_name(m: Option<&Value>) -> String {
    let id = s60(m.and_then(|m| m.get("id")));
    let lower = id.to_ascii_lowercase();
    if let Some(rest) = lower.find("claude-").map(|i| &lower[i + 7..]) {
        let mut it = rest.split('-');
        let fam = it.next().unwrap_or("");
        let major = it.next().unwrap_or("");
        let minor = it.next().unwrap_or("");
        // 1-2 leading digits (a longer run, like a date, is not a version)
        let digits = |s: &str| {
            let d: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
            (!d.is_empty() && d.len() <= 2).then_some(d)
        };
        let fam_ok = !fam.is_empty() && fam.chars().all(|c| c.is_ascii_lowercase());
        if let (true, Some(maj)) = (fam_ok, digits(major)) {
            let name = format!("{}{}", fam[..1].to_uppercase(), &fam[1..]);
            // a minor version only when it is 1-2 digits (not a date like 20250514)
            let minor_d: String = minor.chars().take_while(|c| c.is_ascii_digit()).collect();
            return if !minor_d.is_empty() && minor_d.len() <= 2 {
                format!("{name} {maj}.{minor_d}")
            } else {
                format!("{name} {maj}")
            };
        }
    }
    let dn = s60(m.and_then(|m| m.get("display_name")));
    if !dn.is_empty() {
        dn
    } else if !id.is_empty() {
        id
    } else {
        "Claude".into()
    }
}

pub fn money(usd: f64) -> String {
    if usd >= 100.0 {
        format!("~${}", usd.round())
    } else {
        format!("~${usd:.2}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Green,
    Yellow,
    Red,
}

pub fn context_level(pct: f64, used: f64, t: &Thresholds) -> Level {
    if pct >= t.danger_pct || used >= t.danger_tokens {
        Level::Red
    } else if pct >= t.warn_pct || used >= t.warn_tokens {
        Level::Yellow
    } else {
        Level::Green
    }
}

fn lc(l: Level) -> C {
    match l {
        Level::Green => C::Green,
        Level::Yellow => C::Yellow,
        Level::Red => C::Red,
    }
}

struct Cache {
    text: String,
    short: String,
    color: C,
}

fn cache_state(pc: Option<&Value>, now: f64) -> Option<Cache> {
    let pc = pc?;
    if pc.get("caching_observed").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    let left = count(pc.get("expires_at")) - now;
    let ttl = pc.get("ttl").and_then(Value::as_str);
    if pc.get("warm").and_then(Value::as_bool) == Some(true) && left > 0.0 {
        let mins = (left / 60.0).ceil() as u64;
        let life = match ttl {
            Some(t @ ("1h" | "5m")) => format!(" ({t})"),
            _ => String::new(),
        };
        let warn = if ttl == Some("5m") { 1 } else { 5 };
        return Some(Cache {
            text: format!("cache {mins}m left{life}"),
            short: format!("cache {mins}m"),
            color: if mins <= warn { C::Yellow } else { C::Green },
        });
    }
    let redo = count(pc.get("recache_tokens_if_cold"));
    Some(Cache {
        text: if redo > 0.0 {
            format!("cache cold: next message re-caches {}", tokens(redo))
        } else {
            "cache cold".into()
        },
        short: "cache cold".into(),
        color: C::Red,
    })
}

/// Context tokens of the latest request (output tokens are not context).
pub fn context_used(v: &Value) -> f64 {
    let u = v.pointer("/context_window/current_usage");
    count(u.and_then(|u| u.get("input_tokens")))
        + count(u.and_then(|u| u.get("cache_creation_input_tokens")))
        + count(u.and_then(|u| u.get("cache_read_input_tokens")))
}

/// Claude part at detail `level` (0 full, 1 medium, 2 short).
fn claude_part(v: &Value, level: u8, t: &Thresholds, now: f64) -> T {
    let cw = v.get("context_window");
    let used = context_used(v);
    let size = count(cw.and_then(|c| c.get("context_window_size")));
    let up = cw.and_then(|c| c.get("used_percentage"));
    let pct = if up.is_none_or(Value::is_null) {
        if size > 0.0 {
            used / size * 100.0
        } else {
            0.0
        }
    } else {
        count(up)
    }
    .round()
    .min(100.0);
    let level_c = context_level(pct, used, t);

    let mut model = T::paint(&model_name(v.get("model")), C::BoldCyan);
    let effort = s60(v.pointer("/effort/level"));
    if !effort.is_empty() {
        model.p(&format!(" {effort}"), C::Dim);
    }
    if v.get("fast_mode").and_then(Value::as_bool) == Some(true) {
        model.p(" fast", C::Yellow);
    }
    let pct_t = T::paint(&format!("{pct}%"), lc(level_c));
    let amount = if size > 0.0 {
        format!("{}/{}", tokens(used), tokens(size))
    } else {
        tokens(used)
    };
    let cost = v
        .pointer("/cost/total_cost_usd")
        .and_then(Value::as_f64)
        .filter(|u| u.is_finite() && *u >= 0.0)
        .map(|u| {
            let c = if u >= t.cost_warn * 2.0 {
                C::Red
            } else if u >= t.cost_warn {
                C::Yellow
            } else {
                C::Green
            };
            T::paint(&money(u), c)
        })
        .unwrap_or_default();
    // Session cost, cache timer and the /compact hint are opt-in: on a subscription the "cost"
    // is an API-price estimate, not money spent, and the line is for limits and context.
    let cost = if t.show_cost { cost } else { T::default() };
    let cache = if t.show_cache {
        cache_state(v.get("prompt_cache"), now)
    } else {
        None
    };
    let sep = T::paint(" │ ", C::Dim);
    match level {
        2 => T::join(vec![model, pct_t, cost], &sep),
        1 => {
            let mut ctx = pct_t;
            ctx.s(" ").p(&amount, C::Dim);
            let c = cache
                .map(|c| T::paint(&c.short, c.color))
                .unwrap_or_default();
            T::join(vec![model, ctx, cost, c], &sep)
        }
        _ => {
            let filled = ((pct / 100.0) * 10.0).round().clamp(0.0, 10.0) as usize;
            let mut ctx = T::paint(&"█".repeat(filled), lc(level_c));
            ctx.p(&"░".repeat(10 - filled), C::Dim)
                .s(" ")
                .push(pct_t)
                .s(" ")
                .p(&amount, C::Dim);
            let c = cache
                .map(|c| T::paint(&c.text, c.color))
                .unwrap_or_default();
            let hint = if level_c == Level::Red && t.show_hint {
                T::paint("/compact or /clear", C::Red)
            } else {
                T::default()
            };
            T::join(vec![model, ctx, cost, c, hint], &sep)
        }
    }
}

fn claude_level_for(columns: usize) -> u8 {
    if columns < 50 {
        2
    } else if columns < 80 {
        1
    } else {
        0
    }
}

// ------------------------------------------------------------------ ledger totals

/// Incremental ledger aggregate (`<state>/statusline-ledger.json`): all-time, per UTC day and
/// per session, advanced from the last byte offset. Same `Agg::add` as `middleman report`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LedgerTotals {
    pub offset: u64,
    /// Savings baseline these totals were computed against (0 = none); a change restarts them.
    pub baseline: i64,
    pub all: Agg,
    /// UTC day number (unix / 86400) -> totals; the last 8 days are kept.
    pub days: BTreeMap<i64, Agg>,
    /// session id -> (last line ts, totals); the 64 most recent sessions are kept.
    pub sessions: BTreeMap<String, (i64, Agg)>,
}

impl LedgerTotals {
    pub fn add(&mut self, e: &LedgerEntry) {
        let ts = e.ts_unix();
        // test runs and lines before the savings baseline never count
        if !crate::report::counts(e, self.baseline) {
            return;
        }
        self.all.add(e);
        self.days.entry(ts.div_euclid(86_400)).or_default().add(e);
        if let Some(sid) = e
            .session_id
            .as_deref()
            .map(safe_id)
            .filter(|s| !s.is_empty())
        {
            let s = self.sessions.entry(sid).or_default();
            s.0 = s.0.max(ts);
            s.1.add(e);
        }
    }

    fn prune(&mut self) {
        while self.days.len() > 8 {
            let k = *self.days.keys().next().expect("non-empty");
            self.days.remove(&k);
        }
        if self.sessions.len() > 64 {
            let mut v: Vec<(String, i64)> = self
                .sessions
                .iter()
                .map(|(k, v)| (k.clone(), v.0))
                .collect();
            v.sort_by_key(|x| std::cmp::Reverse(x.1));
            for (k, _) in v.into_iter().skip(64) {
                self.sessions.remove(&k);
            }
        }
    }

    pub fn today(&self, now: i64) -> Agg {
        self.days
            .get(&now.div_euclid(86_400))
            .copied()
            .unwrap_or_default()
    }

    pub fn session(&self, sid: &str) -> Option<Agg> {
        self.sessions.get(sid).map(|s| s.1)
    }
}

/// Advance totals over `ledger` (complete lines only; a shrunk file restarts from zero).
pub fn advance_totals(ledger: &Path, t: &mut LedgerTotals) {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut f) = std::fs::File::open(ledger) else {
        return;
    };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    if len < t.offset {
        *t = LedgerTotals::default();
    }
    if len == t.offset || f.seek(SeekFrom::Start(t.offset)).is_err() {
        return;
    }
    let mut buf = Vec::new();
    if f.take(len - t.offset).read_to_end(&mut buf).is_err() {
        return;
    }
    let Some(end) = buf.iter().rposition(|&b| b == b'\n') else {
        return;
    };
    for l in String::from_utf8_lossy(&buf[..end]).lines() {
        if let Some(e) = crate::ledger::parse_line(l) {
            t.add(&e);
        }
    }
    t.offset += end as u64 + 1;
    t.prune();
}

fn totals(state: &Path) -> LedgerTotals {
    let cache = state.join("statusline-ledger.json");
    let mut t: LedgerTotals = std::fs::read(&cache)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let baseline = crate::report::read_baseline(state).unwrap_or(0);
    let mut changed = false;
    if t.baseline != baseline {
        t = LedgerTotals {
            baseline,
            ..Default::default()
        };
        changed = true;
    }
    let before = t.offset;
    advance_totals(&state.join("ledger.jsonl"), &mut t);
    if changed || t.offset != before {
        if let Ok(b) = serde_json::to_vec(&t) {
            let _ = crate::fsutil::write_atomic(&cache, &b, Some(0o600));
        }
    }
    t
}

// ------------------------------------------------------------------ middleman part

fn key_cache_path(cfg: &Config) -> PathBuf {
    cfg.state_dir().join("statusline-keys.json")
}

fn key_ok(cfg: &Config, p: &ProviderCfg, now: i64) -> Result<(), String> {
    let env_set = p
        .key_env
        .as_ref()
        .is_some_and(|e| std::env::var_os(e).is_some_and(|v| !v.is_empty()));
    if p.key_source == Some(KeySource::Keychain) && !env_set {
        let path = key_cache_path(cfg);
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
        if let KeyStatus::Missing(why) = &st {
            if crate::keystore::is_denied(why) {
                let n = clean(&p.name, 24);
                return Err(format!("key locked (run: middleman provider test {n})"));
            }
        }
        return Err(no_key(p));
    }
    match p.key_status() {
        KeyStatus::Missing(_) => Err(no_key(p)),
        _ => Ok(()),
    }
}

fn no_key(p: &ProviderCfg) -> String {
    let n = clean(&p.name, 24);
    format!("no key for {n} (run: middleman provider add {n})")
}

/// Net dollars, sign first: `$0.21`, `-$0.03`.
pub fn usd(x: f64) -> String {
    let x = if x.abs() < 0.005 { 0.0 } else { x };
    if x < 0.0 {
        format!("-${:.2}", -x)
    } else {
        format!("${x:.2}")
    }
}

fn ago(s: i64) -> String {
    if s < 3600 {
        format!("{}m ago", s / 60)
    } else if s < 86_400 {
        format!("{}h ago", s / 3600)
    } else {
        format!("{}d ago", s / 86_400)
    }
}

/// Everything the middleman part shows.
#[derive(Debug, Clone, Default)]
pub struct MmData {
    /// Err = the reason middleman cannot delegate right now.
    pub health: Option<Result<String, String>>,
    /// Remaining spend for the head provider, and the cache age (seconds).
    pub left: Option<(f64, i64)>,
    pub low_balance: Option<C2>,
    pub limits_error: Option<String>,
    pub session: Option<Agg>,
    pub today: Agg,
    pub all: Agg,
    pub agents: Option<u64>,
    /// A newer release found by the daily check (`v0.3.1`).
    pub update: Option<String>,
    /// An automatic update installed this version (`v0.3.1`), shown for a short while.
    pub updated: Option<String>,
}

/// Balance warning colour.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum C2 {
    Yellow,
    Red,
}

fn saved(x: f64) -> T {
    T::paint(&usd(x), if x < 0.0 { C::Red } else { C::Green })
}

fn jobs(n: u64) -> String {
    format!("{n} job{}", if n == 1 { "" } else { "s" })
}

fn jobs_detail(a: &Agg) -> String {
    let mut v = vec![];
    let blocked = a.blocked + a.do_it_yourself;
    if blocked > 0 {
        v.push(format!("{blocked} blocked"));
    }
    if a.escalated > 0 {
        v.push(format!("{} escalated", a.escalated));
    }
    if a.errors > 0 {
        v.push(format!("{} failed", a.errors));
    }
    if v.is_empty() {
        String::new()
    } else {
        format!(" ({})", v.join(", "))
    }
}

/// Middleman part at detail `level` (0 full .. 3 tiny).
fn mm_part(d: &MmData, level: u8, show_tokens: bool) -> T {
    let dot = T::paint(" · ", C::Dim);
    let who = match &d.health {
        Some(Ok(w)) => w.clone(),
        Some(Err(e)) => {
            let mut t = T::raw(if level == 0 {
                "🛡 middleman "
            } else {
                "🛡 "
            });
            t.p("✗", C::Red);
            match level {
                0 | 1 => {
                    t.s(" ").s(e);
                }
                2 => {
                    t.s(" ").s(&clean(e.split(" (").next().unwrap_or(e), 30));
                }
                _ => {}
            }
            return t;
        }
        None => return T::default(),
    };
    let mut head = T::raw(if level == 0 {
        "🛡 middleman "
    } else {
        "🛡 "
    });
    head.p("✓", C::Green);
    if level <= 1 {
        head.s(" ").s(&who);
    }
    let update = d
        .update
        .as_ref()
        .filter(|_| level <= 2)
        .map(|v| T::paint(&format!("↑ {v}"), C::Yellow))
        .or_else(|| {
            d.updated
                .as_ref()
                .filter(|_| level <= 2)
                .map(|v| T::paint(&format!("✓ updated to {v}"), C::Green))
        });
    if let Some((left, age)) = d.left {
        if level <= 2 {
            let col = match d.low_balance {
                Some(C2::Red) => Some(C::Red),
                Some(C2::Yellow) => Some(C::Yellow),
                None => None,
            };
            let txt = if level == 0 {
                format!("{} left", usd(left))
            } else {
                usd(left)
            };
            head.s(" ");
            match col {
                Some(c) => head.p(&txt, c),
                None => head.s(&txt),
            };
            if age >= limits::STALE_S && level <= 1 {
                head.p(&format!(" ({})", ago(age)), C::Dim);
            }
        }
    } else if let Some(e) = &d.limits_error {
        if level == 0 {
            head.p(&format!(" (limits: {e})"), C::Dim);
        }
    }
    let mut parts = vec![head];
    parts.extend(update);
    // savings only once a real (non-test) job succeeded after the baseline
    let show_savings = d.all.ok > 0;
    match level {
        0 => {
            match &d.session {
                Some(s) => {
                    parts.push(T::raw(&format!(
                        "{} this session{}",
                        jobs(s.jobs()),
                        jobs_detail(s)
                    )));
                    parts.push(T::raw(&format!("{} today", d.today.jobs())));
                }
                None => parts.push(T::raw(&format!(
                    "{} today{}",
                    jobs(d.today.jobs()),
                    jobs_detail(&d.today)
                ))),
            }
            if let Some(a) = d.agents {
                parts.push(T::raw(&format!(
                    "{a} agent{}",
                    if a == 1 { "" } else { "s" }
                )));
            }
            let mut s = T::raw("saved ");
            if let Some(sa) = &d.session {
                s.push(saved(sa.net_savings_usd))
                    .s(" session")
                    .push(dot.clone());
            }
            s.push(saved(d.today.net_savings_usd))
                .s(" today")
                .push(dot.clone())
                .push(saved(d.all.net_savings_usd))
                .s(" total");
            if show_savings {
                parts.push(s);
            }
            if show_tokens {
                parts.push(T::raw(&format!(
                    "{} Claude tok avoided today",
                    tokens(d.today.claude_output_tokens_avoided as f64)
                )));
            }
        }
        1 => {
            let (n, a) = match &d.session {
                Some(s) => (s.jobs(), *s),
                None => (d.today.jobs(), d.today),
            };
            parts.push(T::raw(&format!("{}{}", jobs(n), jobs_detail(&a))));
            if let Some(a) = d.agents {
                parts.push(T::raw(&format!(
                    "{a} agent{}",
                    if a == 1 { "" } else { "s" }
                )));
            }
            let mut s = T::raw("saved ");
            s.push(saved(d.today.net_savings_usd))
                .s(" today")
                .push(dot.clone())
                .push(saved(d.all.net_savings_usd))
                .s(" total");
            if show_savings {
                parts.push(s);
            }
        }
        2 => {
            let n = d.session.map(|s| s.jobs()).unwrap_or(d.today.jobs());
            parts.push(T::raw(&jobs(n)));
            let mut s = T::raw("saved ");
            s.push(saved(d.today.net_savings_usd)).s(" today");
            if show_savings {
                parts.push(s);
            }
        }
        _ => {
            let mut s = T::raw("saved ");
            s.push(saved(d.today.net_savings_usd));
            if !show_savings {
                return parts.remove(0);
            }
            return T::join(vec![parts.remove(0), s], &T::raw(" "));
        }
    }
    T::join(parts, &dot)
}

/// Gather the middleman data (local files only). `spawn` starts a detached limits refresh,
/// `spawn_update` the daily update check.
fn mm_data(
    v: &Value,
    cfg_path: &Path,
    now: i64,
    spawn: &mut dyn FnMut() -> std::io::Result<()>,
    spawn_update: &mut dyn FnMut() -> std::io::Result<()>,
) -> MmData {
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
            return MmData {
                health: Some(Err(format!("{} (run: middleman doctor)", clean(first, 60)))),
                ..Default::default()
            };
        }
    };
    let state = cfg.state_dir();
    let mut d = MmData::default();
    let refresh_off = std::env::var_os("MIDDLEMAN_SL_NO_REFRESH").is_some_and(|v| v == "1");

    // a newer release, from the daily check's cache (the check itself runs detached)
    let mode = cfg.update.mode();
    if crate::upgrade::checks_enabled(mode != crate::config::UpdateMode::Off, &|k| {
        std::env::var(k).ok()
    }) {
        use crate::upgrade::{self as up, Version};
        let uc = up::load_cache(&state);
        let cur = Version::current();
        d.update = up::newer_cached(uc.as_ref(), &cur).map(|v| {
            // auto mode installs patch releases itself; a bigger jump needs the user
            if mode == crate::config::UpdateMode::Auto
                && up::auto_decision(&cur, &v) == up::AutoDecision::Manual
            {
                format!("{} available (run middleman upgrade)", v.tag())
            } else {
                v.tag()
            }
        });
        if d.update.is_none() {
            d.updated = up::updated_notice(uc.as_ref(), now, &cur);
            if let (Some(_), Some(c)) = (&d.updated, &uc) {
                if c.notice_since.is_none() {
                    let mut c = c.clone();
                    c.notice_since = Some(now);
                    let _ = up::save_cache(&state, &c);
                }
            }
        }
        if !refresh_off {
            crate::upgrade::maybe_check(&state, uc.as_ref(), now, spawn_update);
        }
    }

    // live session facts for the MCP server's savings maths
    if let Some(sid) = &session {
        let used = context_used(v);
        let model_id = s60(v.pointer("/model/id"));
        if used > 0.0 || !model_id.is_empty() {
            let ttl = v
                .pointer("/prompt_cache/ttl")
                .and_then(Value::as_str)
                .filter(|t| matches!(*t, "5m" | "1h"))
                .map(String::from);
            session::record(
                &state,
                sid,
                SessionInfo {
                    context_tokens: used as u64,
                    model_id,
                    cache_ttl: ttl,
                    updated_at: now,
                },
                now,
            );
        }
        if let Some(tp) = v.get("transcript_path").and_then(Value::as_str) {
            d.agents = crate::transcript::count_agents(&state, sid, Path::new(tp));
        }
    }

    let enabled: Vec<&ProviderCfg> = cfg.providers.values().filter(|p| p.enabled).collect();
    let mut ready = vec![];
    let mut first_err = None;
    for p in &enabled {
        match key_ok(&cfg, p, now) {
            Ok(()) => ready.push(*p),
            Err(e) => {
                first_err.get_or_insert(e);
            }
        }
    }
    let t = totals(&state);
    d.today = t.today(now);
    d.all = t.all;
    d.session = session.as_deref().map(|s| t.session(s).unwrap_or_default());
    if enabled.is_empty() {
        d.health = Some(Err(
            "no provider enabled (run: middleman provider add openrouter)".into(),
        ));
        return d;
    }
    let Some(head) = ready.first() else {
        d.health = Some(Err(first_err.unwrap_or_else(|| "no key".into())));
        return d;
    };
    let cache = limits::load(&state);
    if !refresh_off && ready.iter().any(|p| p.balance != BalanceKind::None) {
        limits::maybe_refresh(&state, cache.as_ref(), now, spawn);
    }
    let name = clean(&head.name, 24);
    if let Some(l) = cache
        .as_ref()
        .and_then(|c: &LimitsCache| c.providers.get(&head.name))
    {
        if l.key_rejected() {
            d.health = Some(Err(format!(
                "{name} key rejected (run: middleman provider test {name})"
            )));
            return d;
        }
        match l.left_usd() {
            Some(left) => {
                d.left = Some((left, now - l.fetched_at));
                let r = cfg.budget.reserve_usd;
                d.low_balance = if left <= r {
                    Some(C2::Red)
                } else if left <= 2.0 * r {
                    Some(C2::Yellow)
                } else {
                    None
                };
            }
            None => d.limits_error = l.error.as_deref().map(|e| clean(e, 40)),
        }
    }
    d.health = Some(Ok(if ready.len() > 1 {
        format!("{name} +{}", ready.len() - 1)
    } else {
        name
    }));
    d
}

// ------------------------------------------------------------------ render

/// Pick the richest variant that fits `columns` (the last one otherwise).
fn fit(variants: Vec<T>, columns: usize) -> T {
    let n = variants.len();
    variants
        .into_iter()
        .enumerate()
        .find(|(i, v)| v.width() <= columns || *i + 1 == n)
        .map(|(_, v)| v)
        .unwrap_or_default()
}

/// Short model name for tight lines: "Opus 5.5" -> "Opus".
fn short_model(name: &str) -> String {
    name.split_whitespace()
        .next()
        .unwrap_or("Claude")
        .to_string()
}

/// One compact line built by priority: each item has a rank (0 = always kept). When the
/// line is too wide, whole items are dropped from the highest rank down, so numbers are never
/// cut in half. Separators: " │ " between the Claude and middleman groups, " " inside.
fn compact(v: &Value, d: &MmData, o: &Opts) -> T {
    let t = &o.env;
    let size = count(v.pointer("/context_window/context_window_size"));
    let used = context_used(v);
    let up = v.pointer("/context_window/used_percentage");
    let pct = if up.is_none_or(Value::is_null) {
        if size > 0.0 {
            used / size * 100.0
        } else {
            0.0
        }
    } else {
        count(up)
    }
    .round()
    .min(100.0);
    let ctx_c = lc(context_level(pct, used, t));
    let name = model_name(v.get("model"));
    let effort = s60(v.pointer("/effort/level"));

    // (rank, group, item); group 0 = Claude, 1 = middleman
    // kind: 0 normal; 1 = short model (only when the full name is dropped, rank 3);
    // 2 = bare context % (only when `ctx N% tokens`, rank 6, is dropped)
    let mut items: Vec<(u8, u8, T, u8)> = vec![];
    if effort.is_empty() {
        items.push((3, 0, T::paint(&name, C::BoldCyan), 0));
    } else {
        let mut me = T::paint(&name, C::BoldCyan);
        me.p(&format!(" {effort}"), C::Dim);
        items.push((7, 0, me, 3));
        items.push((3, 0, T::paint(&name, C::BoldCyan), 4));
    }
    items.push((1, 0, T::paint(&short_model(&name), C::BoldCyan), 1));
    // Context: a coloured bar with tokens/window when there is room, else just the percentage.
    let filled = ((pct / 100.0) * 10.0).round().clamp(0.0, 10.0) as usize;
    let mut ctx = T::paint(&"█".repeat(filled), ctx_c);
    ctx.p(&"░".repeat(10 - filled), C::Dim)
        .s(" ")
        .p(&format!("{pct}%"), ctx_c);
    let amount = match (used > 0.0, size > 0.0) {
        (true, true) => format!(" {}/{}", tokens(used), tokens(size)),
        (true, false) => format!(" {}", tokens(used)),
        _ => String::new(),
    };
    ctx.p(&amount, C::Dim);
    items.push((5, 0, ctx, 0));
    items.push((0, 0, T::paint(&format!("ctx {pct}%"), ctx_c), 2));
    if t.show_cost {
        if let Some(u) = v
            .pointer("/cost/total_cost_usd")
            .and_then(Value::as_f64)
            .filter(|u| u.is_finite() && *u >= 0.0)
        {
            items.push((8, 0, T::paint(&money(u), C::Dim), 0));
        }
    }

    match &d.health {
        Some(Ok(_)) => {
            items.push((0, 1, T::paint("🛡✓", C::Green), 5));
            if let Some((left, _)) = d.left {
                let c = match d.low_balance {
                    Some(C2::Red) => C::Red,
                    Some(C2::Yellow) => C::Yellow,
                    None => C::Dim,
                };
                items.push((3, 1, T::paint(&format!("{} left", usd(left)), c), 0));
            }
            // savings only once a real (non-test) job succeeded after the baseline
            if d.all.ok > 0 {
                let mut s = T::raw("saved ");
                s.push(saved(d.today.net_savings_usd));
                items.push((0, 1, s, 0));
                let mut tot = T::raw("total ");
                tot.push(saved(d.all.net_savings_usd));
                items.push((5, 1, tot, 0));
            }
            let n = d.session.map(|s| s.jobs()).unwrap_or(d.today.jobs());
            if n > 0 {
                items.push((8, 1, T::raw(&jobs(n)), 0));
            }
            if let Some(a) = d.agents.filter(|a| *a > 0) {
                items.push((
                    9,
                    1,
                    T::raw(&format!("{a} agent{}", if a == 1 { "" } else { "s" })),
                    0,
                ));
            }
            if let Some(u) = &d.update {
                items.push((7, 1, T::paint(&format!("↑{u}"), C::Yellow), 0));
            } else if let Some(u) = &d.updated {
                items.push((7, 1, T::paint(&format!("✓ updated to {u}"), C::Green), 0));
            }
        }
        Some(Err(e)) => {
            items.push((0, 1, T::paint("🛡✗", C::Red), 5));
            items.push((
                2,
                1,
                T::paint(&clean(e.split(" (").next().unwrap_or(e), 32), C::Red),
                0,
            ));
        }
        None => {}
    }

    let build = |max: u8| {
        let pick = |g: u8| {
            let parts: Vec<T> = items
                .iter()
                .filter(|(r, grp, _, kind)| {
                    *grp == g
                        && *r <= max
                        && match kind {
                            1 => max < 3,
                            2 => max < 5,
                            4 => max < 7,
                            _ => true,
                        }
                })
                .filter(|(_, _, _, kind)| *kind != 5)
                .map(|(_, _, t, _)| t.clone())
                .collect();
            let body = T::join(parts, &T::paint(" · ", C::Dim));
            // the shield leads its group without a separator
            match items
                .iter()
                .find(|(_, grp, _, kind)| *grp == g && *kind == 5)
            {
                Some((_, _, shield, _)) => T::join(vec![shield.clone(), body], &T::raw(" ")),
                None => body,
            }
        };
        T::join(vec![pick(0), pick(1)], &T::paint(" │ ", C::Dim))
    };
    let mut line = build(0);
    for max in (0..=9).rev() {
        let l = build(max);
        if l.width() <= o.columns {
            line = l;
            break;
        }
    }
    line
}

/// The status line for this stdin payload, with an injectable refresh spawner (the update
/// check does not start).
pub fn render_with(
    input: &str,
    cfg_path: &Path,
    now: i64,
    o: &Opts,
    spawn: &mut dyn FnMut() -> std::io::Result<()>,
) -> String {
    render_jobs(input, cfg_path, now, o, spawn, &mut no_update_check)
}

fn no_update_check() -> std::io::Result<()> {
    Err(std::io::Error::other("update check not started here"))
}

/// The status line, with injectable spawners for the limits refresh and the update check.
pub fn render_jobs(
    input: &str,
    cfg_path: &Path,
    now: i64,
    o: &Opts,
    spawn: &mut dyn FnMut() -> std::io::Result<()>,
    spawn_update: &mut dyn FnMut() -> std::io::Result<()>,
) -> String {
    let v: Value = serde_json::from_str(input).unwrap_or(Value::Null);
    let d = mm_data(&v, cfg_path, now, spawn, spawn_update);
    let nowf = now as f64;
    let mm = |l: u8| mm_part(&d, l, o.show_tokens);
    let badge = mode_badge(&v, cfg_path, now);
    let out = if o.middleman_only {
        fit((0..=3).map(mm).collect(), o.columns).out(o.color)
    } else if o.lines >= 2 {
        let l1 = claude_part(&v, claude_level_for(o.columns), &o.env, nowf);
        let l2 = fit((0..=3).map(mm).collect(), o.columns);
        format!("{}\n{}", l1.out(o.color), l2.out(o.color))
    } else {
        compact(&v, &d, o).out(o.color)
    };
    with_badge(out, badge, o.columns)
}

/// Writes Claude's 5-hour utilization for the proxy, and returns `🛡 smart → glm-5.3`
/// (current mode and last route) when a smart session has routed something recently.
fn mode_badge(v: &Value, cfg_path: &Path, now: i64) -> Option<String> {
    let state = Config::load(cfg_path).ok()?.state_dir();
    if let Some(p) = v
        .pointer("/rate_limits/five_hour/used_percentage")
        .and_then(Value::as_f64)
    {
        let _ = crate::modes::write_usage(&state, p, now);
    }
    let r = crate::modes::read_route(&state).filter(|r| now - r.ts < 6 * 3600)?;
    let live = crate::modes::read_live_mode(&state)
        .map(|m| m.to_string())
        .unwrap_or(r.mode);
    let to = if r.route == "claude" {
        "claude".to_string()
    } else {
        clean(r.model.rsplit('/').next().unwrap_or(""), 24)
    };
    Some(format!("🛡 {live} → {to}"))
}

/// Append the badge to the last line only when it fits: it is the first thing dropped.
fn with_badge(out: String, badge: Option<String>, columns: usize) -> String {
    let Some(b) = badge else { return out };
    let last = out.rsplit('\n').next().unwrap_or("");
    let mut w = 0;
    let mut esc = false;
    for c in last.chars() {
        if esc {
            esc = c != 'm';
        } else if c == '\u{1b}' {
            esc = true;
        } else {
            w += if (c as u32) >= 0x1F000 { 2 } else { 1 };
        }
    }
    let bw: usize = b
        .chars()
        .map(|c| if (c as u32) >= 0x1F000 { 2 } else { 1 })
        .sum();
    if w + 3 + bw <= columns {
        format!("{out} │ {b}")
    } else {
        out
    }
}

/// Width of the controlling terminal (Claude Code does not set COLUMNS for status line
/// commands, and stdout is a pipe), via TIOCGWINSZ on /dev/tty. None when there is no tty.
#[cfg(unix)]
pub fn tty_columns() -> Option<usize> {
    use std::os::fd::AsRawFd;
    let tty = std::fs::File::open("/dev/tty").ok()?;
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: TIOCGWINSZ fills a winsize struct for a valid open fd.
    let rc = unsafe { libc::ioctl(tty.as_raw_fd(), libc::TIOCGWINSZ, &mut ws) };
    (rc == 0 && ws.ws_col > 0).then_some(ws.ws_col as usize)
}

#[cfg(not(unix))]
pub fn tty_columns() -> Option<usize> {
    None
}

/// The status line for this stdin payload. Never panics on bad input.
pub fn render(input: &str, cfg_path: &Path, now: i64, o: &Opts) -> String {
    let p = cfg_path.to_path_buf();
    render_with(input, cfg_path, now, o, &mut || limits::spawn_refresh(&p))
}

/// Entry point used by `main`: read stdin (capped), render, never fail.
pub fn run(cfg_path: &Path, o: &Opts) -> String {
    use std::io::Read;
    let mut input = String::new();
    let _ = std::io::stdin().take(1 << 20).read_to_string(&mut input);
    let now = crate::ledger::now_unix();
    let p = cfg_path.to_path_buf();
    std::panic::catch_unwind(|| {
        render_jobs(
            &input,
            cfg_path,
            now,
            o,
            &mut || limits::spawn_refresh(&p),
            &mut || {
                let auto = Config::load(&p)
                    .is_ok_and(|c| c.update.mode() == crate::config::UpdateMode::Auto);
                crate::upgrade::spawn_check(&p, auto)
            },
        )
    })
    .unwrap_or_else(|_| "🛡 middleman ✗ internal error (run: middleman doctor)".into())
}

#[cfg(test)]
mod tests;
