//! `middleman report --reconcile`: compare what the ledger says middleman spent with the
//! provider's own counters.
//!
//! - OpenRouter: `GET /key` → `usage_daily` (current UTC day) vs the ledger's cost for today,
//!   and `usage` (all-time) deltas between snapshots vs the ledger's cost in between.
//! - Balance-only gateways (`/balance`): balance drop between snapshots vs the ledger's cost.
//!
//! Snapshots come from `provider refresh`, the MCP server (after each delegation) and every
//! reconcile run. A key or account that is also used outside middleman shows up as a
//! positive discrepancy ("provider higher").

use serde::Serialize;

use crate::config::{BalanceKind, Config};
use crate::ledger::LedgerEntry;
use crate::limits::{ProviderLimits, Snapshot};

/// |provider - ledger| within this many USD (or 2%) counts as matching.
pub const TOLERANCE_USD: f64 = 0.0005;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Check {
    pub provider: String,
    /// What is compared, e.g. "today (UTC)" or "since 2026-11-10T19:00:00Z".
    pub window: String,
    pub provider_usd: f64,
    pub ledger_usd: f64,
    /// provider - ledger
    pub diff_usd: f64,
    pub matches: bool,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Reconciliation {
    pub checks: Vec<Check>,
    pub notes: Vec<String>,
}

fn ledger_cost(es: &[LedgerEntry], provider: &str, after: i64, until: i64) -> f64 {
    es.iter()
        .filter(|e| e.provider == provider)
        .filter(|e| {
            let t = e.ts_unix();
            t > after && t <= until
        })
        .map(|e| e.cost_usd)
        .sum()
}

fn check(provider: &str, window: String, provider_usd: f64, ledger_usd: f64) -> Check {
    let diff = provider_usd - ledger_usd;
    let tol = TOLERANCE_USD.max(0.02 * provider_usd.abs().max(ledger_usd.abs()));
    Check {
        provider: provider.into(),
        window,
        provider_usd,
        ledger_usd,
        diff_usd: diff,
        matches: diff.abs() <= tol,
    }
}

/// Pure comparison: `now` limits against stored snapshots and the ledger.
pub fn compare(
    provider: &str,
    now_limits: &ProviderLimits,
    snaps: &[Snapshot],
    es: &[LedgerEntry],
    since: Option<i64>,
    now: i64,
) -> Vec<Check> {
    let mut out = vec![];
    let day_start = now - now.rem_euclid(86_400);
    if let Some(daily) = now_limits.key.as_ref().and_then(|k| k.usage_daily_usd) {
        out.push(check(
            provider,
            "today (UTC)".into(),
            daily,
            ledger_cost(es, provider, day_start - 1, now),
        ));
    }
    let start = since.unwrap_or(i64::MIN);
    let base = snaps
        .iter()
        .filter(|s| s.provider == provider && s.ts >= start && s.ts < now)
        .min_by_key(|s| s.ts);
    if let Some(b) = base {
        let label = format!("since {}", crate::ledger::rfc3339_at(b.ts));
        let usage_now = now_limits.key.as_ref().and_then(|k| k.usage_usd);
        let delta = match (b.usage_usd, usage_now) {
            (Some(a), Some(z)) => Some(z - a),
            _ => match (b.balance_usd, now_limits.balance_usd) {
                (Some(a), Some(z)) => Some(a - z),
                _ => None,
            },
        };
        if let Some(d) = delta {
            out.push(check(
                provider,
                label,
                d,
                ledger_cost(es, provider, b.ts, now),
            ));
        }
    }
    out
}

/// Fetch current counters (free GETs), compare, and store a new snapshot.
pub async fn run(cfg: &Config, es: &[LedgerEntry], since: Option<i64>) -> Reconciliation {
    let now = crate::ledger::now_unix();
    let state = cfg.state_dir();
    let snaps = crate::limits::snapshots(&state);
    let mut r = Reconciliation::default();
    let mut cache = crate::limits::LimitsCache {
        fetched_at: now,
        ..Default::default()
    };
    for (name, pc) in &cfg.providers {
        if !pc.enabled {
            continue;
        }
        if pc.balance == BalanceKind::None {
            r.notes.push(format!(
                "{}: no usage or balance endpoint; nothing to reconcile against",
                crate::fsutil::clean(name, 24)
            ));
            continue;
        }
        let p = match crate::providers::Provider::from_cfg(name, pc, 20) {
            Ok(p) => p,
            Err(e) => {
                r.notes
                    .push(format!("{}: {e:#}", crate::fsutil::clean(name, 24)));
                continue;
            }
        };
        let l = crate::limits::fetch_one(&p, now).await;
        if let Some(e) = &l.error {
            r.notes
                .push(format!("{}: {e}", crate::fsutil::clean(name, 24)));
        }
        let checks = compare(name, &l, &snaps, es, since, now);
        if checks.is_empty() {
            r.notes.push(format!(
                "{}: no earlier snapshot yet; run reconcile again later (snapshot stored now)",
                crate::fsutil::clean(name, 24)
            ));
        }
        r.checks.extend(checks);
        cache.providers.insert(name.clone(), l);
    }
    for (name, p) in &cache.providers {
        let s = Snapshot {
            ts: now,
            provider: name.clone(),
            usage_usd: p.key.as_ref().and_then(|k| k.usage_usd),
            balance_usd: p.balance_usd,
        };
        if s.usage_usd.is_some() || s.balance_usd.is_some() {
            let _ = crate::ledger::append_jsonl(&crate::limits::snapshots_path(&state), &s);
        }
    }
    let _ = crate::limits::save(&state, &cache);
    r.notes
        .push("A key or account also used outside middleman shows up as 'provider higher'.".into());
    r
}

pub fn render_text(r: &Reconciliation) -> String {
    let mut s = String::from("reconcile: ledger cost vs the provider's own counters\n");
    for c in &r.checks {
        let verdict = if c.matches {
            "ok".to_string()
        } else if c.diff_usd > 0.0 {
            format!("DISCREPANCY: provider higher by ${:.6}", c.diff_usd)
        } else {
            format!("DISCREPANCY: ledger higher by ${:.6}", -c.diff_usd)
        };
        s.push_str(&format!(
            "  {:<14} {:<34} provider ${:>10.6}  ledger ${:>10.6}  {verdict}\n",
            crate::fsutil::clean(&c.provider, 14),
            c.window,
            c.provider_usd,
            c.ledger_usd
        ));
    }
    for n in &r.notes {
        s.push_str(&format!("  note: {n}\n"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::KeyLimits;

    fn e(ts: i64, provider: &str, cost: f64) -> LedgerEntry {
        LedgerEntry {
            ts: crate::ledger::rfc3339_at(ts),
            provider: provider.into(),
            cost_usd: cost,
            status: "ok".into(),
            ..Default::default()
        }
    }

    #[test]
    fn compares_daily_and_snapshot_deltas() {
        let now = 1_767_225_600 + 7200; // 02:00 UTC
        let es = vec![
            e(now - 3 * 3600, "or", 0.5), // yesterday
            e(now - 3000, "or", 0.010),   // after the snapshot
            e(now - 60, "or", 0.002),     // after the snapshot
            e(now - 60, "other", 9.0),    // another provider
        ];
        let snaps = vec![
            Snapshot {
                ts: now - 3600,
                provider: "or".into(),
                usage_usd: Some(1.0),
                balance_usd: Some(10.0),
            },
            Snapshot {
                ts: now - 4 * 86_400,
                provider: "or".into(),
                usage_usd: Some(0.1),
                ..Default::default()
            },
        ];
        let l = ProviderLimits {
            key: Some(KeyLimits {
                usage_usd: Some(1.012),
                usage_daily_usd: Some(0.012),
                ..Default::default()
            }),
            balance_usd: Some(9.988),
            ..Default::default()
        };
        let c = compare("or", &l, &snaps, &es, Some(now - 86_400), now);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].window, "today (UTC)");
        assert!(c[0].matches, "{c:?}");
        assert!((c[1].provider_usd - 0.012).abs() < 1e-12);
        assert!((c[1].ledger_usd - 0.012).abs() < 1e-12);
        assert!(c[1].matches);
        // spend outside middleman: provider higher
        let l2 = ProviderLimits {
            key: Some(KeyLimits {
                usage_usd: Some(1.5),
                usage_daily_usd: Some(0.5),
                ..Default::default()
            }),
            ..Default::default()
        };
        let c = compare("or", &l2, &snaps, &es, Some(now - 86_400), now);
        assert!(c.iter().all(|x| !x.matches && x.diff_usd > 0.0));
        assert!(render_text(&Reconciliation {
            checks: c,
            notes: vec![]
        })
        .contains("provider higher"));
        // balance-only gateway: balance drop
        let snaps = vec![Snapshot {
            ts: now - 3600,
            provider: "yz".into(),
            balance_usd: Some(5.0),
            ..Default::default()
        }];
        let es = vec![e(now - 10, "yz", 0.25)];
        let l = ProviderLimits {
            balance_usd: Some(4.75),
            ..Default::default()
        };
        let c = compare("yz", &l, &snaps, &es, None, now);
        assert_eq!(c.len(), 1);
        assert!(c[0].matches);
    }
}
