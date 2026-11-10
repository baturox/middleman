//! `middleman usage`: local analysis of Claude Code transcripts (`~/.claude/projects/**/*.jsonl`).
//! Only token counts and metadata (model, timestamps, session id, cwd basename, sidechain flag)
//! are read into memory; message contents are never stored or printed. Assistant messages are
//! deduplicated by `message.id` (streamed blocks repeat the same usage).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::BufRead;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::expand_tilde;
use crate::ledger::LedgerEntry;

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FamilyPrice {
    /// USD per 1M tokens
    pub input: f64,
    pub output: f64,
    pub cache_read: f64,
    pub cache_write: f64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct UsageCfg {
    pub projects_dir: PathBuf,
    /// Price per model family (matched by substring of the model id).
    pub prices: BTreeMap<String, FamilyPrice>,
}

impl Default for UsageCfg {
    fn default() -> Self {
        let fp = |i: f64, o: f64, cr: f64| FamilyPrice {
            input: i,
            output: o,
            cache_read: cr,
            cache_write: 1.25 * i,
        };
        UsageCfg {
            projects_dir: PathBuf::from("~/.claude/projects"),
            prices: BTreeMap::from([
                ("opus".to_string(), fp(4.0, 20.0, 0.20)),
                ("sonnet".to_string(), fp(2.0, 10.0, 0.10)),
                ("haiku".to_string(), fp(0.10, 0.50, 0.01)),
                ("fable".to_string(), fp(8.0, 40.0, 0.20)),
            ]),
        }
    }
}

impl UsageCfg {
    pub fn family(&self, model: &str) -> Option<(&str, FamilyPrice)> {
        let l = model.to_ascii_lowercase();
        self.prices
            .iter()
            .find(|(k, _)| l.contains(k.as_str()))
            .map(|(k, v)| (k.as_str(), *v))
    }
}

/// One deduplicated assistant message (aggregates only).
#[derive(Debug, Clone, Serialize)]
pub struct Msg {
    pub ts_unix: i64,
    pub day: String,
    pub project: String,
    pub session: String,
    pub model: String,
    pub family: String,
    pub subagent: bool,
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
}

impl Msg {
    pub fn context(&self) -> u64 {
        self.input + self.cache_read + self.cache_write
    }
    pub fn cost(&self, p: &FamilyPrice) -> Costs {
        Costs {
            input: self.input as f64 * p.input / 1e6,
            output: self.output as f64 * p.output / 1e6,
            cache_read: self.cache_read as f64 * p.cache_read / 1e6,
            cache_write: self.cache_write as f64 * p.cache_write / 1e6,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct Costs {
    pub input: f64,
    pub output: f64,
    pub cache_read: f64,
    pub cache_write: f64,
}

impl Costs {
    pub fn total(&self) -> f64 {
        self.input + self.output + self.cache_read + self.cache_write
    }
    fn add(&mut self, o: &Costs) {
        self.input += o.input;
        self.output += o.output;
        self.cache_read += o.cache_read;
        self.cache_write += o.cache_write;
    }
}

#[derive(Deserialize)]
struct RawUsage {
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
    #[serde(default)]
    cache_read_input_tokens: u64,
    #[serde(default)]
    cache_creation_input_tokens: u64,
}

#[derive(Deserialize)]
struct RawMessage {
    id: Option<String>,
    model: Option<String>,
    usage: Option<RawUsage>,
}

#[derive(Deserialize)]
struct RawLine {
    #[serde(rename = "type")]
    kind: Option<String>,
    timestamp: Option<String>,
    #[serde(rename = "sessionId")]
    session_id: Option<String>,
    cwd: Option<String>,
    #[serde(rename = "isSidechain")]
    is_sidechain: Option<bool>,
    message: Option<RawMessage>,
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        match e.file_type() {
            Ok(t) if t.is_dir() => walk(&p, out),
            Ok(t) if t.is_file() && p.extension().is_some_and(|x| x == "jsonl") => out.push(p),
            _ => {}
        }
    }
}

fn parse_ts(s: &str) -> Option<i64> {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(|t| t.unix_timestamp())
}

fn parse_file(path: &Path, since: Option<i64>) -> Vec<(Option<String>, Msg)> {
    let mut out = Vec::new();
    let Ok(f) = std::fs::File::open(path) else {
        return out;
    };
    let sub_path = path.components().any(|c| c.as_os_str() == "subagents");
    for line in std::io::BufReader::new(f).lines().map_while(|l| l.ok()) {
        if !line.contains("\"assistant\"") || !line.contains("\"usage\"") {
            continue;
        }
        let Ok(r) = serde_json::from_str::<RawLine>(&line) else {
            continue;
        };
        if r.kind.as_deref() != Some("assistant") {
            continue;
        }
        let Some(m) = r.message else { continue };
        let Some(u) = m.usage else { continue };
        let model = m.model.unwrap_or_default();
        if model.starts_with('<') {
            continue; // <synthetic>
        }
        let ts = r.timestamp.as_deref().and_then(parse_ts).unwrap_or(0);
        if since.is_some_and(|s| ts < s) {
            continue;
        }
        let project = r
            .cwd
            .as_deref()
            .and_then(|c| Path::new(c).file_name())
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "(unknown)".into());
        out.push((
            m.id,
            Msg {
                ts_unix: ts,
                day: crate::ledger::rfc3339_at(ts).chars().take(10).collect(),
                project,
                session: r.session_id.unwrap_or_default(),
                model,
                family: String::new(),
                subagent: r.is_sidechain.unwrap_or(false) || sub_path,
                input: u.input_tokens,
                output: u.output_tokens,
                cache_read: u.cache_read_input_tokens,
                cache_write: u.cache_creation_input_tokens,
            },
        ));
    }
    out
}

/// Load all assistant messages since `since`, deduplicated by message id (max output wins).
pub fn load(cfg: &UsageCfg, since: Option<i64>) -> Vec<Msg> {
    let dir = expand_tilde(&cfg.projects_dir);
    let mut files = Vec::new();
    walk(&dir, &mut files);
    if let Some(s) = since {
        files.retain(|f| {
            std::fs::metadata(f)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .is_none_or(|d| d.as_secs() as i64 >= s)
        });
    }
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(16);
    let chunks: Vec<Vec<PathBuf>> = {
        let mut c = vec![Vec::new(); threads];
        for (i, f) in files.into_iter().enumerate() {
            c[i % threads].push(f);
        }
        c
    };
    let parts: Vec<Vec<(Option<String>, Msg)>> = std::thread::scope(|sc| {
        let hs: Vec<_> = chunks
            .iter()
            .map(|ch| {
                sc.spawn(move || {
                    ch.iter()
                        .flat_map(|f| parse_file(f, since))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        hs.into_iter()
            .map(|h| h.join().unwrap_or_default())
            .collect()
    });
    let mut by_id: HashMap<String, Msg> = HashMap::new();
    let mut no_id = Vec::new();
    for (id, mut m) in parts.into_iter().flatten() {
        m.family = cfg
            .family(&m.model)
            .map(|(f, _)| f.to_string())
            .unwrap_or_else(|| "other".into());
        match id {
            Some(id) => {
                let e = by_id.entry(id).or_insert_with(|| m.clone());
                if m.output > e.output {
                    *e = m;
                }
            }
            None => no_id.push(m),
        }
    }
    let mut v: Vec<Msg> = by_id.into_values().chain(no_id).collect();
    v.sort_by_key(|m| m.ts_unix);
    v
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Group {
    pub key: String,
    pub messages: usize,
    pub sessions: usize,
    pub tokens: BTreeMap<String, u64>,
    pub costs: Costs,
    pub total_usd: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionTop {
    pub session: String,
    pub project: String,
    pub day: String,
    pub messages: usize,
    pub peak_context: u64,
    pub total_usd: f64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ContextStats {
    pub turns: usize,
    pub p50: u64,
    pub p90: u64,
    pub p99: u64,
    pub max: u64,
    pub session_start_median: u64,
    pub main_turns: usize,
    /// share of all context tokens that come from turns above 200K
    pub share_tokens_above_200k: f64,
    /// cache-read + cache-write USD spent on the part of contexts above 200K
    pub usd_above_200k: f64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct MiddlemanSummary {
    pub requests: usize,
    pub ok: usize,
    pub cheap_spend_usd: f64,
    pub claude_output_tokens_avoided: u64,
    pub net_savings_usd: f64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct UsageReport {
    pub since: Option<String>,
    pub by: String,
    pub messages: usize,
    pub sessions: usize,
    pub total: Group,
    pub share: BTreeMap<String, f64>,
    pub rows: Vec<Group>,
    /// family x main/subagent
    pub agents: Vec<Group>,
    pub context: ContextStats,
    pub top_sessions: Vec<SessionTop>,
    pub middleman: MiddlemanSummary,
}

fn pct(sorted: &[u64], q: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let i = ((sorted.len() - 1) as f64 * q).round() as usize;
    sorted[i]
}

fn group(cfg: &UsageCfg, key: String, ms: &[&Msg]) -> Group {
    let mut g = Group {
        key,
        messages: ms.len(),
        ..Default::default()
    };
    let mut sessions = BTreeSet::new();
    let mut tok = [0u64; 4];
    for m in ms {
        sessions.insert(m.session.as_str());
        if let Some((_, p)) = cfg.family(&m.model) {
            g.costs.add(&m.cost(&p));
        }
        tok[0] += m.input;
        tok[1] += m.output;
        tok[2] += m.cache_read;
        tok[3] += m.cache_write;
    }
    g.sessions = sessions.len();
    for (k, v) in ["input", "output", "cache_read", "cache_write"]
        .iter()
        .zip(tok)
    {
        g.tokens.insert(k.to_string(), v);
    }
    g.total_usd = g.costs.total();
    g
}

pub fn key_of(by: &str, m: &Msg) -> String {
    match by {
        "day" => m.day.clone(),
        "project" => m.project.clone(),
        "session" => m.session.chars().take(8).collect(),
        "agent" => if m.subagent { "subagent" } else { "main" }.into(),
        _ => m.model.clone(),
    }
}

pub fn build(
    cfg: &UsageCfg,
    msgs: &[Msg],
    since: Option<i64>,
    by: &str,
    ledger: &[LedgerEntry],
) -> UsageReport {
    let all: Vec<&Msg> = msgs.iter().collect();
    let total = group(cfg, "TOTAL".into(), &all);
    let mut share = BTreeMap::new();
    let t = total.total_usd.max(1e-12);
    share.insert("input".into(), total.costs.input / t);
    share.insert("output".into(), total.costs.output / t);
    share.insert("cache_read".into(), total.costs.cache_read / t);
    share.insert("cache_write".into(), total.costs.cache_write / t);

    let mut groups: BTreeMap<String, Vec<&Msg>> = BTreeMap::new();
    let mut agents: BTreeMap<String, Vec<&Msg>> = BTreeMap::new();
    let mut sessions: BTreeMap<&str, Vec<&Msg>> = BTreeMap::new();
    for m in msgs {
        groups.entry(key_of(by, m)).or_default().push(m);
        agents
            .entry(format!(
                "{} {}",
                m.family,
                if m.subagent { "subagent" } else { "main" }
            ))
            .or_default()
            .push(m);
        sessions.entry(m.session.as_str()).or_default().push(m);
    }
    let mut rows: Vec<Group> = groups.into_iter().map(|(k, v)| group(cfg, k, &v)).collect();
    if by != "day" {
        rows.sort_by(|a, b| b.total_usd.total_cmp(&a.total_usd));
    }
    let mut agents: Vec<Group> = agents.into_iter().map(|(k, v)| group(cfg, k, &v)).collect();
    agents.sort_by(|a, b| b.total_usd.total_cmp(&a.total_usd));

    // context distribution
    let mut ctx: Vec<u64> = msgs.iter().map(|m| m.context()).collect();
    ctx.sort_unstable();
    let sum_ctx: u64 = ctx.iter().sum();
    let above: u64 = ctx.iter().filter(|&&c| c > 200_000).sum();
    let mut usd_above = 0.0;
    for m in msgs {
        let c = m.context();
        if c > 200_000 {
            if let Some((_, p)) = cfg.family(&m.model) {
                let frac = (c - 200_000) as f64 / c as f64;
                let k = m.cost(&p);
                usd_above += frac * (k.cache_read + k.cache_write + k.input);
            }
        }
    }
    // baseline = first main-thread turn of interactive sessions (>= 10 turns) of the family
    // that dominates main-thread spend; short `claude -p` runs and title calls skew it otherwise
    let mut fam_cost: BTreeMap<&str, f64> = BTreeMap::new();
    for m in msgs.iter().filter(|m| !m.subagent) {
        if let Some((_, p)) = cfg.family(&m.model) {
            *fam_cost.entry(m.family.as_str()).or_insert(0.0) += m.cost(&p).total();
        }
    }
    let main_family = fam_cost
        .iter()
        .max_by(|a, b| a.1.total_cmp(b.1))
        .map(|(k, _)| k.to_string())
        .unwrap_or_default();
    let first_ctx = |min_turns: usize| -> Vec<u64> {
        sessions
            .values()
            .filter_map(|v| {
                let main: Vec<&&Msg> = v
                    .iter()
                    .filter(|m| !m.subagent && m.family == main_family)
                    .collect();
                if main.len() < min_turns {
                    return None;
                }
                main.iter().min_by_key(|m| m.ts_unix).map(|m| m.context())
            })
            .collect()
    };
    let mut starts = first_ctx(10);
    if starts.is_empty() {
        starts = first_ctx(1);
    }
    starts.sort_unstable();
    let context = ContextStats {
        turns: ctx.len(),
        p50: pct(&ctx, 0.5),
        p90: pct(&ctx, 0.9),
        p99: pct(&ctx, 0.99),
        max: ctx.last().copied().unwrap_or(0),
        session_start_median: pct(&starts, 0.5),
        main_turns: msgs.iter().filter(|m| !m.subagent).count(),
        share_tokens_above_200k: if sum_ctx > 0 {
            above as f64 / sum_ctx as f64
        } else {
            0.0
        },
        usd_above_200k: usd_above,
    };

    let mut top: Vec<SessionTop> = sessions
        .iter()
        .map(|(s, v)| {
            let g = group(cfg, String::new(), v);
            SessionTop {
                session: s.chars().take(8).collect(),
                project: v.first().map(|m| m.project.clone()).unwrap_or_default(),
                day: v.first().map(|m| m.day.clone()).unwrap_or_default(),
                messages: v.len(),
                peak_context: v.iter().map(|m| m.context()).max().unwrap_or(0),
                total_usd: g.total_usd,
            }
        })
        .collect();
    top.sort_by(|a, b| b.total_usd.total_cmp(&a.total_usd));
    top.truncate(10);

    let lt = crate::report::build(ledger, since, crate::report::By::Day).total;
    UsageReport {
        since: since.map(crate::ledger::rfc3339_at),
        by: by.into(),
        messages: msgs.len(),
        sessions: sessions.len(),
        total,
        share,
        rows,
        agents,
        context,
        top_sessions: top,
        middleman: MiddlemanSummary {
            requests: lt.requests,
            ok: lt.ok,
            cheap_spend_usd: lt.cheap_spend_usd,
            claude_output_tokens_avoided: lt.claude_output_tokens_avoided,
            net_savings_usd: lt.net_savings_usd,
        },
    }
}

fn k(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1e6)
    } else if n >= 1_000 {
        format!("{:.0}K", n as f64 / 1e3)
    } else {
        n.to_string()
    }
}

pub fn render_text(r: &UsageReport) -> String {
    let mut s = format!(
        "Claude Code usage (since {}; {} assistant messages, {} sessions; API-equivalent prices)\n",
        r.since.as_deref().unwrap_or("all"),
        r.messages,
        r.sessions
    );
    s.push_str(&format!(
        "total ${:.2}  | input {:.0}%  output {:.0}%  cache-read {:.0}%  cache-write {:.0}%\n\n",
        r.total.total_usd,
        100.0 * r.share["input"],
        100.0 * r.share["output"],
        100.0 * r.share["cache_read"],
        100.0 * r.share["cache_write"]
    ));
    let header = |s: &mut String, first: &str| {
        s.push_str(&format!(
            "{:<34} {:>7} {:>6} {:>10} {:>9} {:>9} {:>9} {:>9}\n",
            first, "msgs", "sess", "total$", "input$", "output$", "c.read$", "c.write$"
        ))
    };
    let line = |s: &mut String, g: &Group| {
        let key: String = g.key.chars().take(34).collect();
        s.push_str(&format!(
            "{:<34} {:>7} {:>6} {:>10.2} {:>9.2} {:>9.2} {:>9.2} {:>9.2}\n",
            key,
            g.messages,
            g.sessions,
            g.total_usd,
            g.costs.input,
            g.costs.output,
            g.costs.cache_read,
            g.costs.cache_write
        ))
    };
    header(&mut s, &format!("by {}", r.by));
    for g in r.rows.iter().take(25) {
        line(&mut s, g);
    }
    if r.rows.len() > 25 {
        s.push_str(&format!("... {} more\n", r.rows.len() - 25));
    }
    s.push('\n');
    header(&mut s, "family / main vs subagent");
    for g in &r.agents {
        line(&mut s, g);
    }
    let c = &r.context;
    s.push_str(&format!(
        "\ncontext per turn: p50 {}  p90 {}  p99 {}  max {}  | session start median {}\n\
         {:.0}% of context tokens come from turns above 200K (≈ ${:.2} of input/cache spend above 200K)\n",
        k(c.p50),
        k(c.p90),
        k(c.p99),
        k(c.max),
        k(c.session_start_median),
        100.0 * c.share_tokens_above_200k,
        c.usd_above_200k
    ));
    s.push_str("\ntop sessions:\n");
    for t in &r.top_sessions {
        s.push_str(&format!(
            "  {} {:<28} {} msgs={:<5} peak_ctx={:<6} ${:.2}\n",
            t.day,
            t.project.chars().take(28).collect::<String>(),
            t.session,
            t.messages,
            k(t.peak_context),
            t.total_usd
        ));
    }
    let m = &r.middleman;
    s.push_str(&format!(
        "\nmiddleman delegations: {} requests ({} ok), cheap spend ${:.4}, Claude output avoided {} tokens, net savings ${:.4}\n",
        m.requests, m.ok, m.cheap_spend_usd, m.claude_output_tokens_avoided, m.net_savings_usd
    ));
    s
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub fn render_html(r: &UsageReport, by_day: &UsageReport) -> String {
    let max = by_day.rows.iter().map(|g| g.total_usd).fold(1e-9, f64::max);
    let n = by_day.rows.len().max(1) as f64;
    let bw = (900.0 / n).clamp(4.0, 40.0);
    let mut svg = format!(
        "<svg viewBox=\"0 0 {} 200\" role=img aria-label=\"cost per day by bucket\">",
        bw * n + 10.0
    );
    for (i, g) in by_day.rows.iter().enumerate() {
        let x = 5.0 + i as f64 * bw;
        let mut y = 180.0;
        for (cls, v) in [
            ("o", g.costs.output),
            ("cr", g.costs.cache_read),
            ("cw", g.costs.cache_write),
            ("in", g.costs.input),
        ] {
            let h = v / max * 170.0;
            y -= h;
            svg.push_str(&format!(
                "<rect class={cls} x={x:.1} y={y:.1} width={:.1} height={h:.1}><title>{} {cls} ${v:.2}</title></rect>",
                bw * 0.8,
                esc(&g.key)
            ));
        }
    }
    svg.push_str("</svg>");
    let rows = |gs: &[Group]| {
        gs.iter()
            .take(30)
            .map(|g| {
                format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{:.2}</td><td>{:.2}</td><td>{:.2}</td><td>{:.2}</td><td>{:.2}</td></tr>",
                    esc(&g.key), g.messages, g.sessions, g.total_usd, g.costs.input, g.costs.output, g.costs.cache_read, g.costs.cache_write
                )
            })
            .collect::<String>()
    };
    let top: String = r
        .top_sessions
        .iter()
        .map(|t| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{:.2}</td></tr>",
                esc(&t.day),
                esc(&t.project),
                esc(&t.session),
                t.messages,
                k(t.peak_context),
                t.total_usd
            )
        })
        .collect();
    let c = &r.context;
    format!(
        r#"<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Claude usage</title><style>
:root{{--bg:#fbfaf8;--fg:#1d1d1b;--mu:#6b6862;--card:#fff;--line:#e6e3dd;--o:#c2683f;--cr:#4a78b5;--cw:#8a63b8;--in:#9a978f}}
@media (prefers-color-scheme:dark){{:root{{--bg:#161614;--fg:#ecebe7;--mu:#9a978f;--card:#1f1f1c;--line:#34332f;--o:#e08a5f;--cr:#7aa5e0;--cw:#b08ee0;--in:#6b6862}}}}
*{{box-sizing:border-box}}body{{margin:0;padding:24px 16px;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,sans-serif}}main{{max-width:1080px;margin:0 auto}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:16px 0}}.kpi,.card{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px;overflow-x:auto}}
.kpi b{{display:block;font-size:22px}}svg{{width:100%;height:auto}}.o{{fill:var(--o)}}.cr{{fill:var(--cr)}}.cw{{fill:var(--cw)}}.in{{fill:var(--in)}}
table{{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}}th,td{{padding:5px 8px;border-bottom:1px solid var(--line);text-align:right;white-space:nowrap}}th:first-child,td:first-child{{text-align:left}}.mu{{color:var(--mu)}}h2{{font-size:16px;margin:24px 0 8px}}
</style></head><body><main><h1>Claude Code usage</h1><div class=mu>since {since} · API-equivalent prices · aggregates only, no message contents</div>
<div class=kpis><div class=kpi>Total<b>${tot:.2}</b></div><div class=kpi>Output share<b>{os:.0}%</b></div><div class=kpi>Cache-read share<b>{crs:.0}%</b></div><div class=kpi>Cache-write share<b>{cws:.0}%</b></div><div class=kpi>Context p50 / p90<b>{p50} / {p90}</b></div><div class=kpi>middleman net savings<b>${mm:.4}</b></div></div>
<h2>Cost per day</h2><div class=card><div class=mu>output · cache-read · cache-write · input</div>{svg}</div>
<h2>By {by}</h2><div class=card><table><tr><th>key</th><th>msgs</th><th>sessions</th><th>total $</th><th>input</th><th>output</th><th>cache read</th><th>cache write</th></tr>{rows}</table></div>
<h2>Model family · main vs subagent</h2><div class=card><table><tr><th>key</th><th>msgs</th><th>sessions</th><th>total $</th><th>input</th><th>output</th><th>cache read</th><th>cache write</th></tr>{agents}</table></div>
<h2>Top sessions</h2><div class=card><table><tr><th>day</th><th>project</th><th>session</th><th>msgs</th><th>peak ctx</th><th>$</th></tr>{top}</table></div>
<p class=mu>{above:.0}% of context tokens come from turns above 200K.</p></main></body></html>
"#,
        since = esc(r.since.as_deref().unwrap_or("all time")),
        tot = r.total.total_usd,
        os = 100.0 * r.share["output"],
        crs = 100.0 * r.share["cache_read"],
        cws = 100.0 * r.share["cache_write"],
        p50 = k(c.p50),
        p90 = k(c.p90),
        mm = r.middleman.net_savings_usd,
        by = esc(&r.by),
        rows = rows(&r.rows),
        agents = rows(&r.agents),
        above = 100.0 * c.share_tokens_above_200k,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_fixture(dir: &Path) {
        let proj = dir.join("-Users-x-proj");
        std::fs::create_dir_all(proj.join("s1/subagents")).unwrap();
        let line = |id: &str, model: &str, ts: &str, side: bool, out: u64, cr: u64| {
            format!(
                r#"{{"type":"assistant","timestamp":"{ts}","sessionId":"s1","cwd":"/Users/x/proj","isSidechain":{side},"message":{{"id":"{id}","model":"{model}","content":[{{"type":"text","text":"SECRET CONTENT"}}],"usage":{{"input_tokens":10,"output_tokens":{out},"cache_read_input_tokens":{cr},"cache_creation_input_tokens":1000}}}}}}"#
            )
        };
        let main = [
            line(
                "m1",
                "claude-opus-5-5",
                "2026-11-01T10:00:00Z",
                false,
                100,
                80_000,
            ),
            line(
                "m1",
                "claude-opus-5-5",
                "2026-11-01T10:00:00Z",
                false,
                100,
                80_000,
            ), // dup
            line(
                "m2",
                "claude-opus-5-5",
                "2026-11-01T10:05:00Z",
                false,
                1000,
                300_000,
            ),
            r#"{"type":"user","message":{"content":"hi"}}"#.to_string(),
            line("m3", "<synthetic>", "2026-11-01T10:06:00Z", false, 0, 0),
        ];
        std::fs::write(proj.join("s1.jsonl"), main.join("\n")).unwrap();
        let sub = [line(
            "a1",
            "claude-sonnet-5-5",
            "2026-11-01T10:02:00Z",
            true,
            500,
            20_000,
        )];
        std::fs::write(proj.join("s1/subagents/agent-a.jsonl"), sub.join("\n")).unwrap();
    }

    #[test]
    fn html_escape_covers_attribute_chars() {
        assert_eq!(esc("<s\"'&>"), "&lt;s&quot;&#39;&amp;&gt;");
    }

    #[test]
    fn parses_dedupes_prices_and_never_keeps_content() {
        let d = tempfile::tempdir().unwrap();
        write_fixture(d.path());
        let cfg = UsageCfg {
            projects_dir: d.path().to_path_buf(),
            ..Default::default()
        };
        let ms = load(&cfg, None);
        assert_eq!(ms.len(), 3, "dedup by id, synthetic skipped");
        assert_eq!(ms.iter().filter(|m| m.subagent).count(), 1);
        let r = build(&cfg, &ms, None, "model", &[]);
        // m1: 10*4 + 100*20 + 80000*0.2 + 1000*5 = 40+2000+16000+5000 = 23040 /1e6
        let opus_main = r.agents.iter().find(|g| g.key == "opus main").unwrap();
        let expect = (23_040.0 + (40.0 + 20_000.0 + 60_000.0 + 5_000.0)) / 1e6;
        assert!(
            (opus_main.total_usd - expect).abs() < 1e-9,
            "{}",
            opus_main.total_usd
        );
        assert!(r.context.share_tokens_above_200k > 0.5);
        assert_eq!(r.context.session_start_median, 81_010);
        let text = render_text(&r);
        let json = serde_json::to_string(&r).unwrap();
        let html = render_html(&r, &build(&cfg, &ms, None, "day", &[]));
        for out in [&text, &json, &html] {
            assert!(!out.contains("SECRET CONTENT"));
        }
        assert!(html.starts_with("<!doctype html>") && !html.contains("<script"));
    }
}
