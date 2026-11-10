//! `middleman tune`: quantified, first-party cost recommendations from the usage profile, plus
//! the exact `settings.json` snippet. Prints only; `--apply` merges the snippet into
//! `~/.claude/settings.json` (with a backup) and is meant to be run by the user.

use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{json, Value};

use crate::usage::{UsageCfg, UsageReport};

#[derive(Debug, Clone, Serialize)]
pub struct Recommendation {
    pub lever: String,
    pub est_saving_usd: f64,
    pub detail: String,
    pub risk: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Tune {
    pub window: String,
    pub total_usd: f64,
    pub recommendations: Vec<Recommendation>,
    pub settings_snippet: Value,
}

fn ratio(cfg: &UsageCfg, from: &str, to: &str) -> f64 {
    match (cfg.prices.get(from), cfg.prices.get(to)) {
        (Some(a), Some(b)) if a.output > 0.0 => b.output / a.output,
        _ => 1.0,
    }
}

pub fn tune(cfg: &UsageCfg, r: &UsageReport) -> Tune {
    let mut recs = Vec::new();
    let fam = |k: &str| {
        r.agents
            .iter()
            .find(|g| g.key == k)
            .map(|g| g.total_usd)
            .unwrap_or(0.0)
    };
    let opus_sub = fam("opus subagent");
    let opus_main = fam("opus main");
    let c = &r.context;

    // 1. context cap
    // compaction is not free (summary + re-read); assume ~70% of the above-200K spend is avoidable
    recs.push(Recommendation {
        lever: "Cap context at ~200K (auto-compact window) and /clear between unrelated tasks".into(),
        est_saving_usd: 0.7 * c.usd_above_200k,
        detail: format!(
            "{:.0}% of context tokens come from turns above 200K (p50 {}K, p90 {}K); ≈ ${:.2} of input/cache spend sits above 200K",
            100.0 * c.share_tokens_above_200k,
            c.p50 / 1000,
            c.p90 / 1000,
            c.usd_above_200k
        ),
        risk: "compaction loses detail of earlier turns".into(),
    });
    // 2. subagents
    let to_sonnet = opus_sub * (1.0 - ratio(cfg, "opus", "sonnet"));
    let to_haiku = opus_sub * (1.0 - ratio(cfg, "opus", "haiku"));
    recs.push(Recommendation {
        lever: "Run subagents on Sonnet 5.5 (CLAUDE_CODE_SUBAGENT_MODEL)".into(),
        est_saving_usd: to_sonnet,
        detail: format!(
            "Opus subagents cost ${opus_sub:.2}; Sonnet saves ≈ ${to_sonnet:.2}, Haiku 5.5 ≈ ${to_haiku:.2}. Keep `model: opus` in frontmatter for agents that need it"
        ),
        risk: "quality on hard subtasks".into(),
    });
    // 3. routine main sessions
    let routine = 0.25 * opus_main * (1.0 - ratio(cfg, "opus", "sonnet"));
    recs.push(Recommendation {
        lever: "Use Sonnet 5.5 for routine sessions (/model sonnet)".into(),
        est_saving_usd: routine,
        detail: format!("Opus main-thread spend ${opus_main:.2}; if 25% of sessions are routine: ≈ ${routine:.2}"),
        risk: "quality".into(),
    });
    // 4. baseline trim
    let start = c.session_start_median;
    let trim = start.saturating_sub(50_000).min(30_000);
    let cr_price = cfg.prices.get("opus").map(|p| p.cache_read).unwrap_or(0.2);
    let baseline = trim as f64 * c.main_turns as f64 * cr_price / 1e6;
    recs.push(Recommendation {
        lever: "Trim the session baseline (unused plugins/skills/MCP per project, skillListingBudgetFraction)".into(),
        est_saving_usd: baseline,
        detail: format!(
            "interactive sessions start at ~{}K tokens; trimming {}K re-read on {} main-thread turns ≈ ${baseline:.2}",
            start / 1000,
            trim / 1000,
            c.main_turns
        ),
        risk: "none (re-enable per project when needed)".into(),
    });
    // 5. delegation
    let out_cost = r.total.costs.output;
    recs.push(Recommendation {
        lever: "Third-party delegation via middleman (file mode, >= break-even only)".into(),
        est_saving_usd: 0.025 * out_cost,
        detail: format!(
            "output is {:.0}% of spend (${out_cost:.2}); delegable bulk output is assumed ~2.5% of it. Measured so far: {} requests, net ${:.4}",
            100.0 * r.share.get("output").copied().unwrap_or(0.0),
            r.middleman.requests,
            r.middleman.net_savings_usd
        ),
        risk: "data exposure to untrusted providers (sanitized)".into(),
    });
    recs.sort_by(|a, b| b.est_saving_usd.total_cmp(&a.est_saving_usd));

    let snippet = json!({
        "env": {
            "CLAUDE_CODE_SUBAGENT_MODEL": "claude-sonnet-5-5",
            "ANTHROPIC_DEFAULT_HAIKU_MODEL": "claude-haiku-5-5",
            "CLAUDE_CODE_AUTO_COMPACT_WINDOW": "200000",
            "CLAUDE_AUTOCOMPACT_PCT_OVERRIDE": "90"
        },
        "skillListingBudgetFraction": 0.005
    });
    Tune {
        window: r.since.clone().unwrap_or_else(|| "all".into()),
        total_usd: r.total.total_usd,
        recommendations: recs,
        settings_snippet: snippet,
    }
}

pub fn render_text(t: &Tune) -> String {
    let mut s = format!(
        "middleman tune (usage since {}, API-equivalent ${:.2})\n\n",
        t.window, t.total_usd
    );
    for (i, r) in t.recommendations.iter().enumerate() {
        s.push_str(&format!(
            "{}. ~${:.0} — {}\n   {}\n   risk: {}\n",
            i + 1,
            r.est_saving_usd,
            r.lever,
            r.detail,
            r.risk
        ));
    }
    s.push_str(&format!(
        "\nsettings.json snippet (merge into ~/.claude/settings.json; or run `middleman tune --apply` yourself):\n{}\n",
        serde_json::to_string_pretty(&t.settings_snippet).unwrap_or_default()
    ));
    s.push_str(
        "CLAUDE_CODE_AUTO_COMPACT_WINDOW caps the window used for auto-compaction; CLAUDE_AUTOCOMPACT_PCT_OVERRIDE=90 compacts at 90% of it (~180K).\n\
         Re-run `middleman usage --since 7d` after a week to compare before/after.\n",
    );
    s
}

/// Deep-merge `snippet` into a settings object (objects merge, scalars replace).
pub fn merge(mut base: Value, snippet: &Value) -> Value {
    if let (Some(b), Some(s)) = (base.as_object_mut(), snippet.as_object()) {
        for (k, v) in s {
            match (b.get_mut(k), v) {
                (Some(bv), Value::Object(_)) if bv.is_object() => {
                    let merged = merge(bv.take(), v);
                    *bv = merged;
                }
                _ => {
                    b.insert(k.clone(), v.clone());
                }
            }
        }
        base
    } else {
        snippet.clone()
    }
}

/// `--apply` (user-run): backup then merge into the settings file.
pub fn apply(settings: &Path, snippet: &Value) -> Result<String> {
    let cur: Value = match std::fs::read_to_string(settings) {
        Ok(t) => {
            let backup = settings.with_extension(format!("json.bak-{}", crate::ledger::now_unix()));
            std::fs::write(&backup, &t)?;
            serde_json::from_str(&t).context("settings file is not valid JSON; not modified")?
        }
        Err(_) => json!({}),
    };
    let merged = merge(cur, snippet);
    if let Some(d) = settings.parent() {
        std::fs::create_dir_all(d)?;
    }
    std::fs::write(settings, serde_json::to_string_pretty(&merged)?)?;
    Ok(format!("merged into {}", settings.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_preserves_existing() {
        let base = json!({"env": {"FOO": "1"}, "model": "opus", "hooks": {"x": []}});
        let m = merge(
            base,
            &json!({"env": {"BAR": "2"}, "skillListingBudgetFraction": 0.5}),
        );
        assert_eq!(m["env"]["FOO"], "1");
        assert_eq!(m["env"]["BAR"], "2");
        assert_eq!(m["model"], "opus");
        assert_eq!(m["skillListingBudgetFraction"], 0.5);
    }

    #[test]
    fn recommendations_are_sorted_and_quantified() {
        let r = UsageReport::default();
        let mut r = r;
        r.share.insert("output".into(), 0.2);
        let t = tune(&UsageCfg::default(), &r);
        assert_eq!(t.recommendations.len(), 5);
        assert!(t
            .recommendations
            .windows(2)
            .all(|w| w[0].est_saving_usd >= w[1].est_saving_usd));
        assert!(t.settings_snippet["env"]["CLAUDE_CODE_SUBAGENT_MODEL"].is_string());
    }
}
