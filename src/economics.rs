//! Does a delegation actually save money? Main-model price table, the savings formula and the
//! break-even gate (plan §7c; the formula is written out in README "How savings are calculated").
//!
//! ```text
//! claude_equiv = N_claude · P_out
//! overhead     = call_tokens · P_out              (Claude emits the tool call)
//!              + context_tokens · P_cache_read    (the extra turn re-reads the session context)
//!              + result_tokens · P_cache_write    (the tool result enters the cached context)
//! net          = claude_equiv − overhead − cheap_cost
//! ```
//! `N_claude` is estimated from the *restored output text* with Claude's tokenizer ratio
//! (chars per token), never from the cheap model's token count (different tokenizer, and it
//! includes reasoning tokens). `call_tokens` and `result_tokens` come from the actual tool-call
//! arguments and tool-result text; `context_tokens` from the status line's live context size.

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

/// Cache writes cost this multiple of the input price (Anthropic prompt caching: 5-minute
/// TTL 1.25x, 1-hour TTL 2x).
pub const CACHE_WRITE_5M: f64 = 1.25;
pub const CACHE_WRITE_1H: f64 = 2.0;

/// Tokens of tool_use framing around the arguments (tool name, id, block markers).
pub const TOOL_USE_FRAMING_TOKENS: u64 = 30;

/// Preset for a Claude Code `model.id` such as `claude-opus-5-5` or `claude-sonnet-5-5[1m]`:
/// matched by family (opus | sonnet | haiku | fable), so every version of a family uses that
/// family's preset prices.
pub fn preset_for_model_id(id: &str) -> Option<&'static str> {
    let id = id.to_ascii_lowercase();
    ["opus", "sonnet", "haiku", "fable"]
        .iter()
        .find(|f| id.contains(*f))
        .and_then(|f| CLAUDE_PRESETS.iter().find(|p| p.0.starts_with(*f)))
        .map(|p| p.0)
}

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
    /// Main Claude model preset when the session's model is unknown:
    /// opus-5.5 | sonnet-5.5 | fable-5.2 | haiku-5.5
    pub claude_model: String,
    /// Price the session's actual model (from the status line's `model.id`) when known.
    pub follow_session_model: bool,
    /// Overrides for the `claude_model` preset (USD / 1M tokens).
    pub price_in: Option<f64>,
    pub price_out: Option<f64>,
    pub price_cache_read: Option<f64>,
    /// Cache-write price; default input x 1.25 (5-minute cache) or x 2 (1-hour cache).
    pub price_cache_write: Option<f64>,
    /// Never suggest/allow delegation below this expected output size.
    pub min_expected_output_tokens: u64,
    /// Session context re-read by the extra turn, used only when the status line has not
    /// reported the live context for this session (or the report is stale).
    pub assumed_context_tokens: u64,
    /// A status line report older than this is stale (seconds).
    pub context_max_age_s: i64,
    /// Tool-call size used by the break-even gate when the real arguments are unknown.
    pub call_tokens: u64,
    /// Expected size of a file-mode tool result, for the break-even gate (the ledger uses the
    /// measured size).
    pub summary_tokens: u64,
    /// Claude tokenizer calibration: characters per token for code / JSON, and for prose.
    pub chars_per_token_code: f64,
    pub chars_per_token_prose: f64,
    /// Block (do it yourself) when the expected net savings are negative.
    pub enforce_break_even: bool,
}

impl Default for EconomicsCfg {
    fn default() -> Self {
        EconomicsCfg {
            claude_model: "opus-5.5".into(),
            follow_session_model: true,
            price_in: None,
            price_out: None,
            price_cache_read: None,
            price_cache_write: None,
            min_expected_output_tokens: 800,
            assumed_context_tokens: 60_000,
            context_max_age_s: 1800,
            call_tokens: 200,
            summary_tokens: 700,
            chars_per_token_code: 3.5,
            chars_per_token_prose: 4.2,
            enforce_break_even: true,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub struct ClaudePrices {
    pub in_per_1m: f64,
    pub out_per_1m: f64,
    pub cache_read_per_1m: f64,
    pub cache_write_5m_per_1m: f64,
    pub cache_write_1h_per_1m: f64,
}

impl ClaudePrices {
    pub const ZERO: ClaudePrices = ClaudePrices {
        in_per_1m: 0.0,
        out_per_1m: 0.0,
        cache_read_per_1m: 0.0,
        cache_write_5m_per_1m: 0.0,
        cache_write_1h_per_1m: 0.0,
    };

    pub fn cache_write(&self, one_hour: bool) -> f64 {
        if one_hour {
            self.cache_write_1h_per_1m
        } else {
            self.cache_write_5m_per_1m
        }
    }
}

/// What the tool result carries back to Claude (kept small: it is itself billed as context).
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq)]
pub struct Savings {
    pub claude_equiv_usd: f64,
    pub claude_overhead_usd: f64,
    pub net_savings_usd: f64,
}

/// Measured inputs of one request.
#[derive(Debug, Clone, Copy, Default)]
pub struct Measured {
    /// Characters of the content Claude would otherwise have written (0 when no answer).
    pub claude_output_chars: u64,
    /// The content is prose (summaries, explanations) rather than code.
    pub prose: bool,
    /// Characters of the tool-call arguments (instructions, paths, inputs, as JSON).
    pub call_chars: u64,
    /// Characters of the tool result text Claude reads.
    pub result_chars: u64,
    /// Live session context re-read by the extra turn.
    pub context_tokens: u64,
    pub cache_1h: bool,
    pub cheap_cost_usd: f64,
}

/// Every term of the formula, for the ledger.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq)]
pub struct Breakdown {
    pub claude_output_tokens: u64,
    pub claude_equiv_usd: f64,
    pub call_tokens: u64,
    pub call_usd: f64,
    pub context_tokens: u64,
    pub turn_usd: f64,
    pub result_tokens: u64,
    pub result_usd: f64,
    pub claude_overhead_usd: f64,
    pub cheap_cost_usd: f64,
    pub net_savings_usd: f64,
}

impl Breakdown {
    pub fn summary(&self) -> Savings {
        Savings {
            claude_equiv_usd: self.claude_equiv_usd,
            claude_overhead_usd: self.claude_overhead_usd,
            net_savings_usd: self.net_savings_usd,
        }
    }
}

fn fin(v: f64) -> f64 {
    if v.is_finite() {
        v
    } else {
        0.0
    }
}

impl EconomicsCfg {
    /// Prices of the configured `claude_model`.
    pub fn prices(&self) -> Result<ClaudePrices> {
        self.prices_for(&self.claude_model)
    }

    /// Prices of a preset; the `price_*` overrides apply only to the configured model.
    pub fn prices_for(&self, preset: &str) -> Result<ClaudePrices> {
        let Some(&(name, i, o, c)) = CLAUDE_PRESETS.iter().find(|p| p.0 == preset) else {
            bail!(
                "unknown claude_model {:?} (one of {})",
                preset,
                CLAUDE_PRESETS
                    .iter()
                    .map(|p| p.0)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        };
        let own = name == self.claude_model;
        let pick = |ov: Option<f64>, d: f64| if own { ov.unwrap_or(d) } else { d };
        let in_ = pick(self.price_in, i);
        let p = ClaudePrices {
            in_per_1m: in_,
            out_per_1m: pick(self.price_out, o),
            cache_read_per_1m: pick(self.price_cache_read, c),
            cache_write_5m_per_1m: pick(self.price_cache_write, in_ * CACHE_WRITE_5M),
            cache_write_1h_per_1m: pick(
                self.price_cache_write
                    .map(|w| w / CACHE_WRITE_5M * CACHE_WRITE_1H),
                in_ * CACHE_WRITE_1H,
            ),
        };
        for v in [
            p.in_per_1m,
            p.out_per_1m,
            p.cache_read_per_1m,
            p.cache_write_5m_per_1m,
            p.cache_write_1h_per_1m,
        ] {
            if !v.is_finite() || v < 0.0 {
                bail!("prices must be non-negative");
            }
        }
        Ok(p)
    }

    fn ratio(&self, prose: bool) -> f64 {
        let r = if prose {
            self.chars_per_token_prose
        } else {
            self.chars_per_token_code
        };
        if r.is_finite() && r >= 0.5 {
            r
        } else {
            3.5
        }
    }

    /// Claude tokens for `chars` characters of text (code ratio also serves JSON).
    pub fn claude_tokens(&self, chars: u64, prose: bool) -> u64 {
        if chars == 0 {
            return 0;
        }
        (chars as f64 / self.ratio(prose)).ceil() as u64
    }

    /// The whole formula from measured inputs.
    pub fn breakdown(&self, p: &ClaudePrices, m: &Measured) -> Breakdown {
        let n = self.claude_tokens(m.claude_output_chars, m.prose);
        let call = self.claude_tokens(m.call_chars, false) + TOOL_USE_FRAMING_TOKENS;
        let result = self.claude_tokens(m.result_chars, false);
        let equiv = fin(n as f64 * p.out_per_1m / 1e6);
        let call_usd = fin(call as f64 * p.out_per_1m / 1e6);
        let turn_usd = fin(m.context_tokens as f64 * p.cache_read_per_1m / 1e6);
        let result_usd = fin(result as f64 * p.cache_write(m.cache_1h) / 1e6);
        let overhead = call_usd + turn_usd + result_usd;
        let cheap = fin(m.cheap_cost_usd).max(0.0);
        Breakdown {
            claude_output_tokens: n,
            claude_equiv_usd: equiv,
            call_tokens: call,
            call_usd,
            context_tokens: m.context_tokens,
            turn_usd,
            result_tokens: result,
            result_usd,
            claude_overhead_usd: overhead,
            cheap_cost_usd: cheap,
            net_savings_usd: equiv - overhead - cheap,
        }
    }

    /// Smallest Claude output N (tokens) for which delegating beats Claude writing it,
    /// ignoring the (tiny) cheap-model cost. The file-mode result size is the configured
    /// estimate; inline results also carry the N output tokens back.
    pub fn break_even_tokens_with(
        &self,
        p: &ClaudePrices,
        mode: WriteMode,
        call_tokens: u64,
        context_tokens: u64,
        cache_1h: bool,
    ) -> u64 {
        let cw = p.cache_write(cache_1h);
        let fixed = call_tokens as f64 * p.out_per_1m
            + context_tokens as f64 * p.cache_read_per_1m
            + self.summary_tokens as f64 * cw;
        let per_token = match mode {
            WriteMode::File => p.out_per_1m,
            WriteMode::Inline => p.out_per_1m - cw,
        };
        if per_token <= 0.0 || !fixed.is_finite() {
            return u64::MAX;
        }
        (fixed / per_token).ceil() as u64
    }

    /// Break-even with the configured fallbacks (no live session data).
    pub fn break_even_tokens(&self, p: &ClaudePrices, mode: WriteMode) -> u64 {
        self.break_even_tokens_with(
            p,
            mode,
            self.call_tokens,
            self.assumed_context_tokens,
            false,
        )
    }

    /// Threshold used by the hook and the tool description (configured fallbacks).
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
    fn break_even_with_defaults() {
        let c = EconomicsCfg::default();
        let p = c.prices().unwrap();
        assert_eq!(p.out_per_1m, 20.0);
        assert_eq!(p.cache_write_5m_per_1m, 5.0);
        assert_eq!(p.cache_write_1h_per_1m, 8.0);
        // (200*20 + 60000*0.2 + 700*5) / 20 = (4000 + 12000 + 3500) / 20 = 975
        assert_eq!(c.break_even_tokens(&p, WriteMode::File), 975);
        // inline: / (20 - 5) = 1300
        assert_eq!(c.break_even_tokens(&p, WriteMode::Inline), 1300);
        // a 1M-token live context makes delegation much harder to justify
        assert_eq!(
            c.break_even_tokens_with(&p, WriteMode::File, 200, 1_000_000, false),
            10_375 // (4000 + 200000 + 3500) / 20
        );
    }

    #[test]
    fn breakdown_matches_formula_by_hand() {
        let c = EconomicsCfg::default();
        let p = c.prices().unwrap();
        let m = Measured {
            claude_output_chars: 7000, // 2000 Claude tokens at 3.5 chars/token
            prose: false,
            call_chars: 350, // 100 + 30 framing
            result_chars: 2100,
            context_tokens: 50_000,
            cache_1h: false,
            cheap_cost_usd: 0.001,
        };
        let b = c.breakdown(&p, &m);
        assert_eq!(b.claude_output_tokens, 2000);
        assert_eq!(b.call_tokens, 130);
        assert_eq!(b.result_tokens, 600);
        assert!((b.claude_equiv_usd - 0.04).abs() < 1e-12);
        assert!((b.call_usd - 130.0 * 20.0 / 1e6).abs() < 1e-12);
        assert!((b.turn_usd - 0.01).abs() < 1e-12);
        assert!((b.result_usd - 600.0 * 5.0 / 1e6).abs() < 1e-12);
        let oh = b.call_usd + b.turn_usd + b.result_usd;
        assert!((b.claude_overhead_usd - oh).abs() < 1e-15);
        assert!((b.net_savings_usd - (0.04 - oh - 0.001)).abs() < 1e-15);
        // 1-hour cache: result written at 2x input
        let b1 = c.breakdown(
            &p,
            &Measured {
                cache_1h: true,
                ..m
            },
        );
        assert!((b1.result_usd - 600.0 * 8.0 / 1e6).abs() < 1e-12);
        // prose uses the prose ratio
        let bp = c.breakdown(&p, &Measured { prose: true, ..m });
        assert_eq!(bp.claude_output_tokens, (7000.0f64 / 4.2).ceil() as u64);
        // no answer: only overhead
        let bz = c.breakdown(
            &p,
            &Measured {
                claude_output_chars: 0,
                cheap_cost_usd: 0.0,
                ..m
            },
        );
        assert_eq!(bz.claude_equiv_usd, 0.0);
        assert!(bz.net_savings_usd < 0.0);
        assert!((bz.net_savings_usd + bz.claude_overhead_usd).abs() < 1e-15);
    }

    #[test]
    fn presets_overrides_and_session_models() {
        let mut c = EconomicsCfg {
            claude_model: "sonnet-5.5".into(),
            ..Default::default()
        };
        assert_eq!(c.prices().unwrap().out_per_1m, 10.0);
        c.price_out = Some(12.0);
        assert_eq!(c.prices().unwrap().out_per_1m, 12.0);
        // overrides belong to the configured model only
        assert_eq!(c.prices_for("opus-5.5").unwrap().out_per_1m, 20.0);
        c.claude_model = "gpt".into();
        assert!(c.prices().is_err());
        assert_eq!(preset_for_model_id("claude-opus-5-5"), Some("opus-5.5"));
        assert_eq!(
            preset_for_model_id("claude-sonnet-5-5[1m]"),
            Some("sonnet-5.5")
        );
        assert_eq!(preset_for_model_id("claude-haiku-5-5"), Some("haiku-5.5"));
        assert_eq!(preset_for_model_id("claude-fable-5-2"), Some("fable-5.2"));
        assert_eq!(preset_for_model_id("gpt-5"), None);
    }

    #[test]
    fn tokenizer_ratio_is_guarded() {
        let c = EconomicsCfg {
            chars_per_token_code: f64::NAN,
            ..Default::default()
        };
        assert_eq!(c.claude_tokens(35, false), 10);
        assert_eq!(c.claude_tokens(0, false), 0);
    }
}
