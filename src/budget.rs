//! Pre-flight worst-case estimate, per-call/daily/weekly caps, balance reserve, reconciliation.

use serde::Serialize;
use thiserror::Error;

use crate::config::BudgetCfg;

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Prices {
    pub in_per_1m: f64,
    pub out_per_1m: f64,
}

/// Conservative token estimate for code (~3 chars/token) plus message overhead.
pub fn estimate_tokens(chars: usize) -> u64 {
    (chars as u64).div_ceil(3) + 32
}

pub fn cost(p: Prices, input_tokens: u64, output_tokens: u64) -> f64 {
    input_tokens as f64 * p.in_per_1m / 1e6 + output_tokens as f64 * p.out_per_1m / 1e6
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct Window {
    pub day_usd: f64,
    pub week_usd: f64,
}

#[derive(Debug, Error, PartialEq)]
pub enum BudgetBlock {
    #[error("worst-case ${worst:.5} exceeds per-call cap ${cap:.5}")]
    PerCall { worst: f64, cap: f64 },
    #[error("worst-case ${worst:.5} exceeds remaining daily allowance ${remaining:.5}")]
    Daily { worst: f64, remaining: f64 },
    #[error("worst-case ${worst:.5} exceeds remaining weekly allowance ${remaining:.5}")]
    Weekly { worst: f64, remaining: f64 },
    #[error(
        "balance ${balance:.4} minus worst-case ${worst:.5} would go below reserve ${reserve:.2}"
    )]
    Reserve {
        balance: f64,
        worst: f64,
        reserve: f64,
    },
    #[error("provider balance unreadable; refusing to spend")]
    BalanceUnknown,
    #[error("model price unknown; refusing to spend")]
    PriceUnknown,
}

pub fn preflight(
    cfg: &BudgetCfg,
    per_call_override: Option<f64>,
    worst: f64,
    w: Window,
    balance: Option<f64>,
) -> Result<(), BudgetBlock> {
    let cap = per_call_override
        .filter(|v| v.is_finite() && *v >= 0.0)
        .map(|v| v.min(cfg.per_call_usd))
        .unwrap_or(cfg.per_call_usd);
    if worst > cap {
        return Err(BudgetBlock::PerCall { worst, cap });
    }
    let day_left = cfg.daily_usd - w.day_usd;
    if worst > day_left {
        return Err(BudgetBlock::Daily {
            worst,
            remaining: day_left.max(0.0),
        });
    }
    let week_left = cfg.weekly_usd - w.week_usd;
    if worst > week_left {
        return Err(BudgetBlock::Weekly {
            worst,
            remaining: week_left.max(0.0),
        });
    }
    let Some(balance) = balance else {
        return Err(BudgetBlock::BalanceUnknown);
    };
    if balance - worst < cfg.reserve_usd {
        return Err(BudgetBlock::Reserve {
            balance,
            worst,
            reserve: cfg.reserve_usd,
        });
    }
    Ok(())
}

/// Real cost = balance before - after when the balance moved; otherwise token-priced.
pub fn reconcile(
    before: Option<f64>,
    after: Option<f64>,
    token_cost: Option<f64>,
) -> (f64, &'static str) {
    if let (Some(b), Some(a)) = (before, after) {
        let d = b - a;
        if d > 1e-9 {
            return (d, "balance");
        }
    }
    match token_cost {
        Some(c) => (c, "tokens"),
        None => (0.0, "unknown"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> BudgetCfg {
        BudgetCfg {
            per_call_usd: 0.05,
            daily_usd: 1.0,
            weekly_usd: 4.0,
            reserve_usd: 1.0,
        }
    }

    #[test]
    fn caps() {
        let w = Window::default();
        assert!(preflight(&cfg(), None, 0.01, w, Some(5.0)).is_ok());
        assert!(matches!(
            preflight(&cfg(), None, 0.06, w, Some(5.0)),
            Err(BudgetBlock::PerCall { .. })
        ));
        assert!(matches!(
            preflight(&cfg(), Some(0.001), 0.01, w, Some(5.0)),
            Err(BudgetBlock::PerCall { .. })
        ));
        // override can only tighten
        assert!(preflight(&cfg(), Some(10.0), 0.04, w, Some(5.0)).is_ok());
        let w = Window {
            day_usd: 0.99,
            week_usd: 0.99,
        };
        assert!(matches!(
            preflight(&cfg(), None, 0.02, w, Some(5.0)),
            Err(BudgetBlock::Daily { .. })
        ));
        let w = Window {
            day_usd: 0.0,
            week_usd: 3.99,
        };
        assert!(matches!(
            preflight(&cfg(), None, 0.02, w, Some(5.0)),
            Err(BudgetBlock::Weekly { .. })
        ));
    }

    #[test]
    fn balance_unknown_and_reserve() {
        let w = Window::default();
        assert_eq!(
            preflight(&cfg(), None, 0.01, w, None),
            Err(BudgetBlock::BalanceUnknown)
        );
        assert!(matches!(
            preflight(&cfg(), None, 0.01, w, Some(1.005)),
            Err(BudgetBlock::Reserve { .. })
        ));
    }

    #[test]
    fn reconcile_prefers_balance_delta() {
        assert_eq!(reconcile(Some(5.0), Some(4.99), Some(0.001)).1, "balance");
        assert_eq!(
            reconcile(Some(5.0), Some(5.0), Some(0.001)),
            (0.001, "tokens")
        );
        assert_eq!(reconcile(None, None, None), (0.0, "unknown"));
    }
}
