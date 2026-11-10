//! Routing chains. middleman picks the model; Claude only hints (`quality`).
//! Steps: `"claude"` (terminal: do it yourself), `"auto:<tag>:<cheapest|balanced|best>"`
//! (resolved from the catalog at call time), `"<provider>/<model id>"` or `"<provider>"` (pin).

use anyhow::{bail, Result};
use serde::Serialize;

use crate::budget::{self, Prices};
use crate::catalog::{Catalog, Priced};
use crate::config::{Config, Tier};
use crate::TaskKind;

#[derive(Debug, Clone, PartialEq)]
pub enum Step {
    Claude,
    Auto {
        tag: String,
        tier: Tier,
    },
    Pinned {
        provider: String,
        model: Option<String>,
    },
}

impl Step {
    pub fn parse(s: &str) -> Result<Step> {
        let s = s.trim();
        if s == "claude" {
            return Ok(Step::Claude);
        }
        if let Some(rest) = s.strip_prefix("auto:") {
            let mut it = rest.splitn(2, ':');
            let tag = it.next().unwrap_or("").trim();
            let tier = it.next().unwrap_or("cheapest").trim();
            if tag.is_empty() {
                bail!("bad step {s:?}: auto:<tag>:<tier>");
            }
            let Some(tier) = Tier::parse(tier) else {
                bail!("bad step {s:?}: tier must be cheapest|balanced|best");
            };
            return Ok(Step::Auto {
                tag: tag.to_string(),
                tier,
            });
        }
        if s.is_empty() {
            bail!("empty chain step");
        }
        match s.split_once('/') {
            Some((p, m)) if !p.is_empty() && !m.is_empty() => Ok(Step::Pinned {
                provider: p.to_string(),
                model: Some(m.to_string()),
            }),
            Some(_) => bail!("bad step {s:?}"),
            None => Ok(Step::Pinned {
                provider: s.to_string(),
                model: None,
            }),
        }
    }
}

pub fn is_code_kind(t: TaskKind) -> bool {
    matches!(
        t,
        TaskKind::WriteTests | TaskKind::Boilerplate | TaskKind::Snippet | TaskKind::RefactorSmall
    )
}

pub fn default_chain(t: TaskKind) -> Vec<&'static str> {
    if is_code_kind(t) || t == TaskKind::Docstring {
        vec!["auto:code:cheapest", "auto:code:balanced", "claude"]
    } else {
        vec!["auto:chat:cheapest", "auto:chat:balanced", "claude"]
    }
}

pub fn chain_for(cfg: &Config, t: TaskKind) -> Vec<(String, Step)> {
    let raw: Vec<String> = match cfg.routes.get(t.as_str()) {
        Some(r) => r.chain.clone(),
        None => default_chain(t).into_iter().map(String::from).collect(),
    };
    // validated at config load; unparseable steps are skipped defensively
    raw.into_iter()
        .filter_map(|s| Step::parse(&s).ok().map(|st| (s, st)))
        .collect()
}

#[derive(Debug, Clone)]
pub struct Needs {
    pub est_in: u64,
    pub max_out: u64,
    pub quality: Tier,
    pub per_call_cap: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Candidate {
    pub step: String,
    pub provider: String,
    pub model: String,
    pub prices: Prices,
    pub worst_usd: f64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Plan {
    pub candidates: Vec<Candidate>,
    pub notes: Vec<String>,
    /// Chain ends in `claude` (or ran out): the caller is told to do it itself.
    pub terminal_claude: bool,
}

fn eligible(m: &Priced, allowed: &[String], n: &Needs) -> Option<Candidate> {
    if !allowed.contains(&m.provider) {
        return None;
    }
    let prices = m.prices?;
    if m.context.is_some_and(|c| c < n.est_in + n.max_out) {
        return None;
    }
    let worst = budget::cost(prices, n.est_in, n.max_out);
    if worst > n.per_call_cap {
        return None;
    }
    Some(Candidate {
        step: String::new(),
        provider: m.provider.clone(),
        model: m.id.clone(),
        prices,
        worst_usd: worst,
    })
}

/// Resolve the chain into an ordered candidate list. `allowed` = providers passing policy.
pub fn plan(
    cfg: &Config,
    catalog: Option<&Catalog>,
    models: &[Priced],
    allowed: &[String],
    chain: &[(String, Step)],
    n: &Needs,
) -> Plan {
    let mut p = Plan::default();
    for (label, step) in chain {
        let c = match step {
            Step::Claude => {
                p.terminal_claude = true;
                break;
            }
            Step::Auto { tag, tier } => {
                if *tier < n.quality {
                    p.notes
                        .push(format!("{label}: skipped (quality hint {:?})", n.quality));
                    continue;
                }
                let mut pool: Vec<Candidate> = models
                    .iter()
                    .filter(|m| m.tags.iter().any(|t| t == tag))
                    .filter_map(|m| eligible(m, allowed, n))
                    .filter(|c| {
                        !p.candidates
                            .iter()
                            .any(|x| x.provider == c.provider && x.model == c.model)
                    })
                    .collect();
                pool.sort_by(|a, b| {
                    a.worst_usd
                        .partial_cmp(&b.worst_usd)
                        .unwrap_or(std::cmp::Ordering::Equal)
                        .then(a.model.cmp(&b.model))
                });
                if pool.is_empty() {
                    p.notes.push(format!(
                        "{label}: no eligible model (tag, allowed provider, known price, context, per-call cap)"
                    ));
                    continue;
                }
                let idx = match tier {
                    Tier::Cheapest => 0,
                    Tier::Balanced => pool.len() / 2,
                    Tier::Best => pool.len() - 1,
                };
                pool.swap_remove(idx)
            }
            Step::Pinned { provider, model } => {
                let Some(model) = model
                    .clone()
                    .or_else(|| cfg.providers.get(provider).and_then(|pc| pc.model.clone()))
                else {
                    p.notes
                        .push(format!("{label}: provider has no default model"));
                    continue;
                };
                if !allowed.contains(provider) {
                    p.notes
                        .push(format!("{label}: provider not allowed by policy"));
                    continue;
                }
                match Catalog::lookup(cfg, catalog, provider, &model)
                    .and_then(|m| eligible(&m, allowed, n))
                {
                    Some(c) => c,
                    None => {
                        p.notes.push(format!(
                            "{label}: price unknown, context too small, or over per-call cap"
                        ));
                        continue;
                    }
                }
            }
        };
        let mut c = c;
        c.step = label.clone();
        if !p
            .candidates
            .iter()
            .any(|x| x.provider == c.provider && x.model == c.model)
        {
            p.candidates.push(c);
        }
    }
    if p.candidates.is_empty() {
        p.terminal_claude = true;
    }
    p.candidates.truncate(cfg.routing.max_attempts);
    p
}

/// Phase 1 cheap validation: non-empty, and code kinds must contain a fenced code block.
pub fn validate_output(t: TaskKind, text: &str) -> Result<(), String> {
    if text.trim().is_empty() {
        return Err("empty output".into());
    }
    if is_code_kind(t) && !text.contains("```") {
        return Err("no fenced code block in output for a code task".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_steps() {
        assert_eq!(Step::parse("claude").unwrap(), Step::Claude);
        assert_eq!(
            Step::parse("auto:code:balanced").unwrap(),
            Step::Auto {
                tag: "code".into(),
                tier: Tier::Balanced
            }
        );
        assert_eq!(
            Step::parse("openrouter/deepseek/deepseek-chat").unwrap(),
            Step::Pinned {
                provider: "openrouter".into(),
                model: Some("deepseek/deepseek-chat".into())
            }
        );
        assert!(Step::parse("auto:code:fancy").is_err());
        assert!(Step::parse("auto::cheapest").is_err());
        assert!(Step::parse("/x").is_err());
    }

    #[test]
    fn validation() {
        assert!(validate_output(TaskKind::WriteTests, "  ").is_err());
        assert!(validate_output(TaskKind::WriteTests, "def test(): pass").is_err());
        assert!(validate_output(TaskKind::WriteTests, "```python\ndef test(): pass\n```").is_ok());
        assert!(validate_output(TaskKind::Summarize, "A summary.").is_ok());
    }
}
