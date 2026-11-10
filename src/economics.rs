//! Does a delegation actually save money? Main-model price table, the overhead formula and the
//! break-even gate (plan §7c).
//!
//! net_savings = N·P_out − (call_tokens·P_out + ctx_tokens·P_cache_read + result_tokens·P_in) − cheap_cost
//! where N is the output Claude would otherwise have written. In file mode the tool result is a
//! short summary; in inline mode the whole output comes back as input tokens (and if Claude then
//! writes it into a file itself, it pays N·P_out again — savings gone).

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::TaskKind;

/// (name, input $/1M, output $/1M, cache-read $/1M)
pub const CLAUDE_PRESETS: &[(&str, f64, f64, f64)] = &[
    ("opus-5.5", 4.0, 20.0, 0.20),
    ("sonnet-5.5", 2.0, 10.0, 0.10),
    ("fable-5.2", 8.0, 40.0, 0.20),
    // cache-read not specified in the plan; 10% of input, the usual ratio
    ("haiku-5.5", 0.10, 0.50, 0.01),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WriteMode {
    /// middleman writes the restored output to disk and returns a short summary
    File,
    /// the output is returned to Claude as text
    Inline,
}

impl WriteMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            WriteMode::File => "file",
            WriteMode::Inline => "inline",
        }
    }
}

/// Default write mode by task kind: anything whose output is code or a whole file goes to disk.
pub fn default_write_mode(t: TaskKind) -> WriteMode {
    match t {
        TaskKind::WriteTests
        | TaskKind::Boilerplate
        | TaskKind::Snippet
        | TaskKind::RefactorSmall
        | TaskKind::Docstring => WriteMode::File,
        _ => WriteMode::Inline,
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct EconomicsCfg {
    /// Main Claude model preset: opus-5.5 | sonnet-5.5 | fable-5.2 | haiku-5.5
    pub claude_model: String,
    /// Overrides for the preset (USD / 1M tokens).
    pub price_in: Option<f64>,
    pub price_out: Option<f64>,
    pub price_cache_read: Option<f64>,
    /// Never suggest/allow delegation below this expected output size.
    pub min_expected_output_tokens: u64,
    /// Session context re-read (as cache reads) by the extra turn a tool call costs.
    pub assumed_context_tokens: u64,
    /// Output tokens Claude spends emitting the tool call.
    pub call_tokens: u64,
    /// Size of a file-mode tool result (summary), in tokens.
    pub summary_tokens: u64,
    /// Block (do it yourself) when the expected net savings are negative.
    pub enforce_break_even: bool,
}

impl Default for EconomicsCfg {
    fn default() -> Self {
        EconomicsCfg {
            claude_model: "opus-5.5".into(),
            price_in: None,
            price_out: None,
            price_cache_read: None,
            min_expected_output_tokens: 800,
            assumed_context_tokens: 60_000,
            call_tokens: 200,
            summary_tokens: 150,
            enforce_break_even: true,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct ClaudePrices {
    pub in_per_1m: f64,
    pub out_per_1m: f64,
    pub cache_read_per_1m: f64,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct Savings {
    pub claude_equiv_usd: f64,
    pub claude_overhead_usd: f64,
    pub net_savings_usd: f64,
}

impl EconomicsCfg {
    pub fn prices(&self) -> Result<ClaudePrices> {
        let Some(&(_, i, o, c)) = CLAUDE_PRESETS.iter().find(|p| p.0 == self.claude_model) else {
            bail!(
                "unknown claude_model {:?} (one of {})",
                self.claude_model,
                CLAUDE_PRESETS
                    .iter()
                    .map(|p| p.0)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        };
        let p = ClaudePrices {
            in_per_1m: self.price_in.unwrap_or(i),
            out_per_1m: self.price_out.unwrap_or(o),
            cache_read_per_1m: self.price_cache_read.unwrap_or(c),
        };
        for v in [p.in_per_1m, p.out_per_1m, p.cache_read_per_1m] {
            if !v.is_finite() || v < 0.0 {
                bail!("prices must be non-negative");
            }
        }
        Ok(p)
    }

    /// Tokens of tool result Claude reads back.
    pub fn result_tokens(&self, mode: WriteMode, output_tokens: u64) -> u64 {
        match mode {
            WriteMode::File => self.summary_tokens,
            WriteMode::Inline => self.summary_tokens + output_tokens,
        }
    }

    /// What the delegation itself costs on Claude's side (tool call + extra turn + result).
    pub fn overhead_usd(&self, p: &ClaudePrices, result_tokens: u64) -> f64 {
        (self.call_tokens as f64 * p.out_per_1m
            + self.assumed_context_tokens as f64 * p.cache_read_per_1m
            + result_tokens as f64 * p.in_per_1m)
            / 1e6
    }

    pub fn equiv_usd(&self, p: &ClaudePrices, output_tokens: u64) -> f64 {
        output_tokens as f64 * p.out_per_1m / 1e6
    }

    pub fn savings(
        &self,
        p: &ClaudePrices,
        mode: WriteMode,
        output_tokens: u64,
        cheap_cost: f64,
    ) -> Savings {
        let eq = self.equiv_usd(p, output_tokens);
        let oh = self.overhead_usd(p, self.result_tokens(mode, output_tokens));
        Savings {
            claude_equiv_usd: eq,
            claude_overhead_usd: oh,
            net_savings_usd: eq - oh - cheap_cost,
        }
    }

    /// Smallest output N (tokens) for which delegating beats Claude writing it, ignoring the
    /// (tiny) cheap-model cost.
    pub fn break_even_tokens(&self, p: &ClaudePrices, mode: WriteMode) -> u64 {
        let fixed = self.call_tokens as f64 * p.out_per_1m
            + self.assumed_context_tokens as f64 * p.cache_read_per_1m
            + self.summary_tokens as f64 * p.in_per_1m;
        let per_token = match mode {
            WriteMode::File => p.out_per_1m,
            WriteMode::Inline => p.out_per_1m - p.in_per_1m,
        };
        if per_token <= 0.0 {
            return u64::MAX;
        }
        (fixed / per_token).ceil() as u64
    }

    /// Threshold used by the gate, the hook and the tool description.
    pub fn threshold_tokens(&self, p: &ClaudePrices, mode: WriteMode) -> u64 {
        self.min_expected_output_tokens
            .max(self.break_even_tokens(p, mode))
    }
}

/// Heuristic expected output size for a task, from the input size (tokens).
pub fn expected_output_tokens(t: TaskKind, input_tokens: u64) -> u64 {
    let i = input_tokens as f64;
    let n = match t {
        TaskKind::WriteTests => (1.5 * i).max(600.0),
        TaskKind::Docstring => 1.3 * i,
        TaskKind::RefactorSmall | TaskKind::Translate => i,
        TaskKind::Boilerplate => i.max(800.0),
        TaskKind::Snippet => 250.0,
        TaskKind::Summarize => (0.2 * i).min(500.0) + 100.0,
        TaskKind::Explain => 400.0,
        TaskKind::Other => 300.0,
    };
    n.round() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opus_break_even_is_about_800_tokens_in_file_mode() {
        let c = EconomicsCfg::default();
        let p = c.prices().unwrap();
        assert_eq!(p.out_per_1m, 20.0);
        // (200*20 + 60000*0.2 + 150*4) / 20 = (4000 + 12000 + 600) / 20 = 830
        assert_eq!(c.break_even_tokens(&p, WriteMode::File), 830);
        // inline: / (20 - 4) = 1038
        assert_eq!(c.break_even_tokens(&p, WriteMode::Inline), 1038);
        let s = c.savings(&p, WriteMode::File, 3000, 0.001);
        assert!((s.claude_equiv_usd - 0.06).abs() < 1e-9);
        assert!((s.claude_overhead_usd - 0.0166).abs() < 1e-9);
        assert!(s.net_savings_usd > 0.04);
        let s = c.savings(&p, WriteMode::Inline, 300, 0.0);
        assert!(s.net_savings_usd < 0.0);
    }

    #[test]
    fn presets_and_overrides() {
        let mut c = EconomicsCfg {
            claude_model: "sonnet-5.5".into(),
            ..Default::default()
        };
        assert_eq!(c.prices().unwrap().out_per_1m, 10.0);
        c.price_out = Some(12.0);
        assert_eq!(c.prices().unwrap().out_per_1m, 12.0);
        c.claude_model = "gpt".into();
        assert!(c.prices().is_err());
    }
}
