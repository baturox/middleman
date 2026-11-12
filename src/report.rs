//! `middleman report`: usage + savings from the ledger (text table, JSON, or a single-file
//! HTML dashboard with no external dependencies).

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Result};
use serde::Serialize;

use crate::ledger::{now_unix, LedgerEntry};
use std::path::Path;

const BASELINE_FILE: &str = "savings-baseline";

/// Unix time of the last `middleman savings reset` (None = never reset).
pub fn read_baseline(state: &Path) -> Option<i64> {
    std::fs::read_to_string(state.join(BASELINE_FILE))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Record "now" as the savings baseline (state dir, 0600). Returns the timestamp.
pub fn write_baseline(state: &Path) -> Result<i64> {
    crate::ledger::ensure_private_dir(state)?;
    let t = now_unix();
    crate::fsutil::write_atomic(
        &state.join(BASELINE_FILE),
        format!("{t}\n").as_bytes(),
        Some(0o600),
    )?;
    Ok(t)
}

/// Does this line count toward savings totals? Test runs never do; lines before the
/// baseline (unix seconds, 0 = none) do not either.
pub fn counts(e: &LedgerEntry, baseline: i64) -> bool {
    !e.is_test() && e.ts_unix() >= baseline
}

/// Where the savings went, as exact sums of the ledger fields.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Explained {
    /// sum of `claude_equiv_usd`
    pub avoided_usd: f64,
    /// sum of `cost_usd`
    pub cheap_usd: f64,
    /// `claude_overhead_usd` on `ok` lines
    pub handoff_ok_usd: f64,
    /// `claude_overhead_usd` on every other line (blocked, refused, errors, dry runs)
    pub wasted_usd: f64,
    /// closing lines that did not produce an answer
    pub wasted_count: u64,
    /// sum of `net_savings_usd`
    pub net_usd: f64,
    /// worst single line: (ts, task_kind, model or status, net)
    pub biggest_loss: Option<(String, String, String, f64)>,
}

pub fn explain<'a>(es: impl IntoIterator<Item = &'a LedgerEntry>) -> Explained {
    let mut x = Explained::default();
    for e in es {
        x.avoided_usd += e.claude_equiv_usd;
        x.cheap_usd += e.cost_usd;
        x.net_usd += e.net_savings_usd;
        if e.status == "ok" {
            x.handoff_ok_usd += e.claude_overhead_usd;
        } else {
            x.wasted_usd += e.claude_overhead_usd;
            if e.is_closing() {
                x.wasted_count += 1;
            }
        }
        if e.net_savings_usd < 0.0
            && x.biggest_loss
                .as_ref()
                .is_none_or(|b| e.net_savings_usd < b.3)
        {
            let who = if e.model.is_empty() {
                e.status.clone()
            } else {
                e.model.clone()
            };
            x.biggest_loss = Some((e.ts.clone(), e.task_kind.clone(), who, e.net_savings_usd));
        }
    }
    x
}

fn money3(v: f64) -> String {
    if v < -0.0005 {
        format!("\u{2212}${:.3}", -v)
    } else {
        format!("${:.3}", v.abs())
    }
}

pub fn render_explained(x: &Explained) -> String {
    let mut s = String::new();
    let mut line = |label: String, v: f64| s.push_str(&format!("{label:<34} {:>9}\n", money3(v)));
    line("Claude output you didn't pay for".into(), x.avoided_usd);
    line("\u{2212} cheap-model cost".into(), x.cheap_usd);
    line(
        "\u{2212} Claude hand-off cost (ok jobs)".into(),
        x.handoff_ok_usd,
    );
    line(
        format!("\u{2212} blocked/refused attempts ({})", x.wasted_count),
        x.wasted_usd,
    );
    line("= net saved".into(), x.net_usd);
    if let Some((ts, task, who, net)) = &x.biggest_loss {
        let when: String = ts.chars().take(16).collect::<String>().replace('T', " ");
        s.push_str(&format!(
            "biggest loss: {when} {task} via {who} ({})\n",
            money3(*net)
        ));
    }
    s
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum By {
    Model,
    Provider,
    Task,
    Day,
    Project,
    Mode,
}

impl By {
    pub fn parse(s: &str) -> Option<By> {
        match s {
            "model" => Some(By::Model),
            "provider" => Some(By::Provider),
            "task" | "task_kind" => Some(By::Task),
            "day" => Some(By::Day),
            "project" => Some(By::Project),
            "mode" => Some(By::Mode),
            _ => None,
        }
    }
    fn key(&self, e: &LedgerEntry) -> String {
        let k = match self {
            By::Model => e.model.clone(),
            By::Provider => e.provider.clone(),
            By::Task => e.task_kind.clone(),
            By::Day => e.ts.chars().take(10).collect(),
            By::Mode => e.mode.clone(),
            By::Project => e.project_label.clone().unwrap_or_else(|| e.project.clone()),
        };
        if k.is_empty() {
            "(none)".into()
        } else {
            k
        }
    }
}

/// `7d`, `30d`, `24h`, `all` -> earliest unix timestamp (None = all).
pub fn parse_since(s: &str) -> Result<Option<i64>> {
    if s == "all" {
        return Ok(None);
    }
    let (num, unit) = s.split_at(s.len().saturating_sub(1));
    let n: i64 = num
        .parse()
        .map_err(|_| anyhow::anyhow!("bad --since {s:?} (7d, 30d, 24h, all)"))?;
    let secs = match unit {
        "d" => n * 86_400,
        "h" => n * 3_600,
        _ => bail!("bad --since {s:?} (7d, 30d, 24h, all)"),
    };
    Ok(Some(now_unix() - secs))
}

/// Sums over ledger lines. Money is summed over every line (attempt lines carry their cheap
/// cost, the closing line carries the Claude-side terms), so a request's escalation steps are
/// never double counted; outcomes are counted once per request, from its closing line. The
/// report, `middleman_status` and the status line all aggregate with this.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, serde::Deserialize)]
#[serde(default)]
pub struct Agg {
    /// Closing lines, i.e. requests (dry runs included).
    pub requests: u64,
    pub ok: u64,
    pub blocked: u64,
    pub do_it_yourself: u64,
    pub errors: u64,
    pub dry_runs: u64,
    /// Requests answered (or abandoned) after more than one candidate.
    pub escalated: u64,
    /// Network attempts.
    pub attempts: u64,
    pub cheap_spend_usd: f64,
    pub claude_equiv_usd: f64,
    pub claude_overhead_usd: f64,
    pub net_savings_usd: f64,
    pub claude_output_tokens_avoided: u64,
}

impl Agg {
    pub fn add(&mut self, e: &LedgerEntry) {
        if e.is_closing() {
            self.requests += 1;
            match e.status.as_str() {
                "ok" => self.ok += 1,
                "blocked" => self.blocked += 1,
                "do_it_yourself" => self.do_it_yourself += 1,
                "dry_run" => self.dry_runs += 1,
                _ => self.errors += 1,
            }
            let tried = if e.status == "ok" {
                e.attempt + 1
            } else {
                e.attempt
            };
            if tried > 1 {
                self.escalated += 1;
            }
        }
        if sent(e) {
            self.attempts += 1;
        }
        self.cheap_spend_usd += e.cost_usd;
        self.claude_equiv_usd += e.claude_equiv_usd;
        self.claude_overhead_usd += e.claude_overhead_usd;
        self.net_savings_usd += e.net_savings_usd;
        self.claude_output_tokens_avoided += e.claude_tokens_avoided();
    }

    /// Requests that reached the delegation decision (dry runs excluded).
    pub fn jobs(&self) -> u64 {
        self.requests - self.dry_runs
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Row {
    pub key: String,
    pub requests: usize,
    pub attempts: usize,
    pub ok: usize,
    pub ok_pct: f64,
    pub escalated: usize,
    pub escalation_pct: f64,
    pub blocked: usize,
    pub do_it_yourself: usize,
    pub errors: usize,
    pub dry_runs: usize,
    pub cheap_spend_usd: f64,
    pub claude_equiv_usd: f64,
    pub claude_overhead_usd: f64,
    /// NET: claude_equiv - overhead - cheap spend
    pub net_savings_usd: f64,
    /// Claude output tokens not written (ok results, Claude tokenizer estimate)
    pub claude_output_tokens_avoided: u64,
    pub avg_latency_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub since: Option<String>,
    pub by: String,
    pub total: Row,
    pub rows: Vec<Row>,
    pub top_block_reasons: Vec<(String, usize)>,
    pub claude_models: Vec<String>,
    pub explained: Explained,
}

fn sent(e: &LedgerEntry) -> bool {
    // only network attempts carry a latency; v1 lines had none but did have token usage
    e.latency_ms.is_some() || (e.status == "ok" && e.input_tokens.is_some())
}

pub fn aggregate<'a>(es: impl IntoIterator<Item = &'a LedgerEntry>) -> Agg {
    let mut a = Agg::default();
    for e in es {
        a.add(e);
    }
    a
}

fn row(key: String, es: &[&LedgerEntry]) -> Row {
    let a = aggregate(es.iter().copied());
    let mut lat = (0u64, 0u64);
    for e in es {
        if let Some(l) = e.latency_ms {
            lat.0 += l;
            lat.1 += 1;
        }
    }
    let mut r = Row {
        key,
        requests: a.requests as usize,
        attempts: a.attempts as usize,
        ok: a.ok as usize,
        escalated: a.escalated as usize,
        blocked: a.blocked as usize,
        do_it_yourself: a.do_it_yourself as usize,
        errors: a.errors as usize,
        dry_runs: a.dry_runs as usize,
        cheap_spend_usd: a.cheap_spend_usd,
        claude_equiv_usd: a.claude_equiv_usd,
        claude_overhead_usd: a.claude_overhead_usd,
        net_savings_usd: a.net_savings_usd,
        claude_output_tokens_avoided: a.claude_output_tokens_avoided,
        ..Default::default()
    };
    let jobs = a.jobs();
    if jobs > 0 {
        r.ok_pct = 100.0 * r.ok as f64 / jobs as f64;
        r.escalation_pct = 100.0 * r.escalated as f64 / jobs as f64;
    }
    if lat.1 > 0 {
        r.avg_latency_ms = Some(lat.0 as f64 / lat.1 as f64);
    }
    r
}

pub fn filter(entries: &[LedgerEntry], since: Option<i64>) -> Vec<&LedgerEntry> {
    entries
        .iter()
        .filter(|e| since.is_none_or(|s| e.ts_unix() >= s))
        .collect()
}

pub fn build(entries: &[LedgerEntry], since: Option<i64>, by: By) -> Report {
    let es = filter(entries, since);
    let mut groups: BTreeMap<String, Vec<&LedgerEntry>> = BTreeMap::new();
    let mut reasons: BTreeMap<String, usize> = BTreeMap::new();
    let mut models = BTreeSet::new();
    for e in &es {
        groups.entry(by.key(e)).or_default().push(e);
        if let Some(c) = &e.block_reason_category {
            *reasons.entry(c.clone()).or_insert(0) += 1;
        }
        if !e.claude_model.is_empty() {
            models.insert(e.claude_model.clone());
        }
    }
    let mut rows: Vec<Row> = groups.into_iter().map(|(k, v)| row(k, &v)).collect();
    if by != By::Day {
        rows.sort_by(|a, b| {
            b.net_savings_usd
                .partial_cmp(&a.net_savings_usd)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }
    let mut top: Vec<(String, usize)> = reasons.into_iter().collect();
    top.sort_by_key(|x| std::cmp::Reverse(x.1));
    top.truncate(8);
    Report {
        since: since.map(crate::ledger::rfc3339_at),
        by: format!("{by:?}").to_lowercase(),
        total: row("TOTAL".into(), &es),
        rows,
        top_block_reasons: top,
        claude_models: models.into_iter().collect(),
        explained: explain(es.iter().copied()),
    }
}

fn usd(v: f64) -> String {
    if v.abs() < 0.01 {
        format!("{v:.5}")
    } else {
        format!("{v:.3}")
    }
}

pub fn render_text(r: &Report) -> String {
    let mut s = format!(
        "middleman report (since {}, by {}; Claude prices: {})\n",
        r.since.as_deref().unwrap_or("all"),
        r.by,
        if r.claude_models.is_empty() {
            "-".into()
        } else {
            r.claude_models.join(", ")
        }
    );
    s.push_str(&format!(
        "{:<28} {:>5} {:>5} {:>5} {:>5} {:>5} {:>10} {:>10} {:>10} {:>10} {:>9} {:>8}\n",
        "key",
        "reqs",
        "ok%",
        "esc%",
        "blk",
        "diy",
        "cheap$",
        "claude$",
        "overhd$",
        "net$",
        "tok_avoid",
        "lat_ms"
    ));
    for x in r.rows.iter().chain(std::iter::once(&r.total)) {
        let key: String = x.key.chars().take(28).collect();
        s.push_str(&format!(
            "{:<28} {:>5} {:>5.0} {:>5.0} {:>5} {:>5} {:>10} {:>10} {:>10} {:>10} {:>9} {:>8}\n",
            key,
            x.requests,
            x.ok_pct,
            x.escalation_pct,
            x.blocked,
            x.do_it_yourself,
            usd(x.cheap_spend_usd),
            usd(x.claude_equiv_usd),
            usd(x.claude_overhead_usd),
            usd(x.net_savings_usd),
            x.claude_output_tokens_avoided,
            x.avg_latency_ms
                .map(|l| format!("{l:.0}"))
                .unwrap_or_else(|| "-".into()),
        ));
    }
    if !r.top_block_reasons.is_empty() {
        s.push_str("top block reasons: ");
        s.push_str(
            &r.top_block_reasons
                .iter()
                .map(|(k, n)| format!("{k}={n}"))
                .collect::<Vec<_>>()
                .join(", "),
        );
        s.push('\n');
    }
    s.push('\n');
    s.push_str(&render_explained(&r.explained));
    s.push_str(
        "net$ (saved) = Claude output avoided at API prices - Claude-side overhead (tool call, extra turn re-reading the context, tool result) - cheap spend.\n\
         Blocked calls and dry runs count their overhead too. On a Pro/Max subscription the dollars are notional: read tok_avoid as usage-limit headroom.\n",
    );
    s
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn bars_svg(rows: &[Row]) -> String {
    if rows.is_empty() {
        return "<p class=muted>No data.</p>".into();
    }
    let max = rows
        .iter()
        .flat_map(|r| {
            [
                r.cheap_spend_usd,
                r.net_savings_usd.abs(),
                r.claude_equiv_usd,
            ]
        })
        .fold(1e-9, f64::max);
    let bw = 18.0;
    let gap = 14.0;
    let h = 160.0;
    let w = rows.len() as f64 * (2.0 * bw + gap) + gap;
    let mut s = format!(
        "<svg viewBox=\"0 0 {w} {}\" role=img aria-label=\"spend vs net savings per group\" preserveAspectRatio=\"xMinYMin meet\">",
        h + 40.0
    );
    for (i, r) in rows.iter().enumerate() {
        let x = gap + i as f64 * (2.0 * bw + gap);
        let sh = (r.cheap_spend_usd / max * h).max(1.0);
        let nh = (r.net_savings_usd.max(0.0) / max * h).max(1.0);
        s.push_str(&format!(
            "<rect class=spend x={x} y={} width={bw} height={sh}><title>{}: cheap ${:.5}</title></rect>",
            h - sh,
            esc(&r.key),
            r.cheap_spend_usd
        ));
        s.push_str(&format!(
            "<rect class=save x={} y={} width={bw} height={nh}><title>{}: net ${:.5}</title></rect>",
            x + bw,
            h - nh,
            esc(&r.key),
            r.net_savings_usd
        ));
        let label: String = r
            .key
            .chars()
            .rev()
            .take(5)
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        s.push_str(&format!(
            "<text x={} y={} class=lbl>{}</text>",
            x,
            h + 16.0,
            esc(&label)
        ));
    }
    s.push_str("</svg>");
    s
}

fn table(rows: &[Row], total: Option<&Row>) -> String {
    let mut s = String::from("<table><thead><tr><th>key</th><th>reqs</th><th>ok%</th><th>esc%</th><th>blocked</th><th>cheap $</th><th>Claude-equiv $</th><th>overhead $</th><th>net $</th><th>tokens avoided</th><th>avg ms</th></tr></thead><tbody>");
    for r in rows.iter().chain(total) {
        s.push_str(&format!(
            "<tr{}><td>{}</td><td>{}</td><td>{:.0}</td><td>{:.0}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td class={}>{}</td><td>{}</td><td>{}</td></tr>",
            if r.key == "TOTAL" { " class=tot" } else { "" },
            esc(&r.key),
            r.requests,
            r.ok_pct,
            r.escalation_pct,
            r.blocked,
            usd(r.cheap_spend_usd),
            usd(r.claude_equiv_usd),
            usd(r.claude_overhead_usd),
            if r.net_savings_usd >= 0.0 { "pos" } else { "neg" },
            usd(r.net_savings_usd),
            r.claude_output_tokens_avoided,
            r.avg_latency_ms.map(|l| format!("{l:.0}")).unwrap_or_else(|| "-".into()),
        ));
    }
    s.push_str("</tbody></table>");
    s
}

pub fn render_html(entries: &[LedgerEntry], since: Option<i64>) -> String {
    let day = build(entries, since, By::Day);
    let model = build(entries, since, By::Model);
    let task = build(entries, since, By::Task);
    let t = &day.total;
    let reasons = if day.top_block_reasons.is_empty() {
        "none".to_string()
    } else {
        day.top_block_reasons
            .iter()
            .map(|(k, n)| format!("{} ({n})", esc(k)))
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        r#"<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>middleman report</title>
<style>
:root{{--bg:#fbfaf8;--fg:#1d1d1b;--muted:#6b6862;--card:#fff;--line:#e6e3dd;--spend:#c2683f;--save:#2f7d5b;--neg:#b23b3b}}
@media (prefers-color-scheme:dark){{:root{{--bg:#161614;--fg:#ecebe7;--muted:#9a978f;--card:#1f1f1c;--line:#34332f;--spend:#e08a5f;--save:#5cbf8e;--neg:#e07070}}}}
*{{box-sizing:border-box}}body{{margin:0;padding:24px 16px;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}}
main{{max-width:1080px;margin:0 auto}}h1{{font-size:22px;margin:0 0 4px}}h2{{font-size:16px;margin:28px 0 8px}}.muted{{color:var(--muted)}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:16px 0}}
.kpi{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px}}.kpi b{{display:block;font-size:22px;font-variant-numeric:tabular-nums}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px;overflow-x:auto}}
svg{{width:100%;height:auto;max-height:240px}}.spend{{fill:var(--spend)}}.save{{fill:var(--save)}}.lbl{{font-size:10px;fill:var(--muted)}}
table{{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}}th,td{{padding:6px 8px;border-bottom:1px solid var(--line);text-align:right;white-space:nowrap}}th:first-child,td:first-child{{text-align:left}}
.tot td{{font-weight:600}}.pos{{color:var(--save)}}.neg{{color:var(--neg)}}.legend span{{display:inline-block;width:10px;height:10px;margin:0 4px 0 12px;border-radius:2px}}
</style></head><body><main>
<h1>middleman report</h1><div class=muted>since {since} · Claude price basis: {models}</div>
<div class=kpis>
<div class=kpi>Net savings (API $)<b class={netc}>${net}</b></div>
<div class=kpi>Claude output tokens avoided<b>{tok}</b></div>
<div class=kpi>Cheap-model spend<b>${spend}</b></div>
<div class=kpi>Requests · ok%<b>{reqs} · {okp:.0}%</b></div>
<div class=kpi>Blocked / do-it-yourself<b>{blk} / {diy}</b></div>
</div>
<h2>Spend vs net savings per day</h2><div class=card><div class="legend muted"><span style="background:var(--spend)"></span>cheap spend<span style="background:var(--save)"></span>net savings</div>{svg}</div>
<h2>By model</h2><div class=card>{tm}</div>
<h2>By task kind</h2><div class=card>{tt}</div>
<h2>By day</h2><div class=card>{td}</div>
<p class=muted>Top block reasons: {reasons}</p>
<p class=muted>Net savings = Claude output avoided at API prices − Claude-side overhead (tool call, extra turn re-reading context, tool result) − cheap-model spend. On a Pro/Max subscription you do not pay per token: read "tokens avoided" as usage-limit headroom.</p>
</main></body></html>
"#,
        since = esc(day.since.as_deref().unwrap_or("all time")),
        models = esc(&if day.claude_models.is_empty() {
            "-".into()
        } else {
            day.claude_models.join(", ")
        }),
        netc = if t.net_savings_usd >= 0.0 {
            "pos"
        } else {
            "neg"
        },
        net = usd(t.net_savings_usd),
        tok = t.claude_output_tokens_avoided,
        spend = usd(t.cheap_spend_usd),
        reqs = t.requests,
        okp = t.ok_pct,
        blk = t.blocked,
        diy = t.do_it_yourself,
        svg = bars_svg(&day.rows),
        tm = table(&model.rows, Some(&model.total)),
        tt = table(&task.rows, Some(&task.total)),
        td = table(&day.rows, Some(&day.total)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::now_rfc3339;

    fn e(req: &str, attempt: u32, status: &str, model: &str, cost: f64, net: f64) -> LedgerEntry {
        let oh = if status == "escalated" { 0.0 } else { 0.02 };
        LedgerEntry {
            ts: now_rfc3339(),
            request_id: req.into(),
            attempt,
            status: status.into(),
            model: model.into(),
            provider: if model.is_empty() {
                String::new()
            } else {
                "p".into()
            },
            task_kind: "write_tests".into(),
            cost_usd: cost,
            net_savings_usd: net,
            claude_equiv_usd: (net + oh + cost).max(0.0),
            claude_overhead_usd: oh,
            latency_ms: if model.is_empty() { None } else { Some(1000) },
            output_tokens: Some(2000),
            block_reason_category: (status == "blocked").then(|| "secret".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn aggregates() {
        let es: Vec<LedgerEntry> = vec![
            e("a", 0, "escalated", "m1", 0.001, -0.001),
            e("a", 1, "ok", "m2", 0.002, 0.03),
            e("b", 0, "ok", "m1", 0.001, 0.02),
            e("c", 0, "blocked", "", 0.0, -0.02),
        ]
        .into_iter()
        .map(|x| x.upgrade().sanitized())
        .collect();
        let r = build(&es, None, By::Model);
        assert_eq!(r.total.requests, 3);
        assert_eq!(r.total.ok, 2);
        assert_eq!(r.total.escalated, 1);
        assert_eq!(r.total.blocked, 1);
        assert!((r.total.net_savings_usd - 0.029).abs() < 1e-9);
        assert_eq!(r.top_block_reasons, vec![("secret".to_string(), 1)]);
        let text = render_text(&r);
        assert!(text.contains("TOTAL") && text.contains("m2"));
        let html = render_html(&es, None);
        assert!(html.starts_with("<!doctype html>") && html.contains("<svg"));
        assert!(
            !html.contains("http://") && !html.contains("https://") && !html.contains("<script")
        );
        assert!(parse_since("7d").unwrap().is_some() && parse_since("all").unwrap().is_none());
        assert!(parse_since("7w").is_err());
    }
    use crate::ledger::rfc3339_at;

    #[allow(clippy::too_many_arguments)]
    fn le(
        ts: i64,
        status: &str,
        eq: f64,
        oh: f64,
        cost: f64,
        purpose: Option<&str>,
    ) -> LedgerEntry {
        LedgerEntry {
            ts: rfc3339_at(ts),
            request_id: format!("r{ts}"),
            status: status.into(),
            closing: Some(true),
            claude_equiv_usd: eq,
            claude_overhead_usd: oh,
            cost_usd: cost,
            net_savings_usd: eq - oh - cost,
            model: "m/x".into(),
            task_kind: "explain".into(),
            purpose: purpose.map(String::from),
            ..Default::default()
        }
    }

    #[test]
    fn totals_skip_tests_and_lines_before_the_baseline() {
        let es = [
            le(1000, "ok", 0.10, 0.02, 0.01, None), // before baseline
            le(2000, "ok", 0.10, 0.02, 0.01, Some("test")), // test run
            le(2000, "ok", 0.20, 0.03, 0.02, None),
        ];
        let c: Vec<_> = es.iter().filter(|x| counts(x, 1500)).collect();
        assert_eq!(c.len(), 1);
        let a = aggregate(c.iter().copied());
        assert!((a.net_savings_usd - 0.15).abs() < 1e-12);
        assert_eq!(es.iter().filter(|x| counts(x, 0)).count(), 2);
    }

    #[test]
    fn breakdown_equals_ledger_sums() {
        let es = vec![
            le(1, "ok", 0.05, 0.01, 0.004, None),
            le(2, "ok", 0.014, 0.017, 0.002, None),
            le(3, "blocked", 0.0, 0.0166, 0.0, None),
            le(4, "do_it_yourself", 0.0, 0.02, 0.0, None),
        ];
        let x = explain(&es);
        let sum = |f: fn(&LedgerEntry) -> f64| es.iter().map(f).sum::<f64>();
        assert_eq!(x.avoided_usd, sum(|e| e.claude_equiv_usd));
        assert_eq!(x.cheap_usd, sum(|e| e.cost_usd));
        assert_eq!(x.net_usd, sum(|e| e.net_savings_usd));
        assert_eq!(
            x.handoff_ok_usd + x.wasted_usd,
            sum(|e| e.claude_overhead_usd)
        );
        assert_eq!(x.wasted_count, 2);
        assert!(
            (x.avoided_usd - x.cheap_usd - x.handoff_ok_usd - x.wasted_usd - x.net_usd).abs()
                < 1e-12
        );
        let t = render_explained(&x);
        assert!(
            t.contains("blocked/refused attempts (2)") && t.contains("biggest loss"),
            "{t}"
        );
        assert!(t.contains("\u{2212}$0.020"), "{t}");
    }

    #[test]
    fn savings_reset_writes_private_baseline() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(read_baseline(d.path()), None);
        let t = write_baseline(d.path()).unwrap();
        assert_eq!(read_baseline(d.path()), Some(t));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(d.path().join(BASELINE_FILE)).unwrap();
            assert_eq!(m.permissions().mode() & 0o777, 0o600);
        }
    }
}
