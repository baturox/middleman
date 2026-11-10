//! Read-only check of a real ledger: recompute every line with the current savings formula and
//! print old vs new. Never writes to the ledger (its hash is compared before and after).
//!
//! ```sh
//! MIDDLEMAN_VERIFY_LEDGER=~/.local/state/middleman/ledger.jsonl \
//!   cargo test --test live_ledger_recompute -- --ignored --nocapture
//! ```
//! Old lines lack the measured sizes, so these inputs are assumed: call = `call_tokens`
//! (200), file-mode result = `summary_tokens` (700; inline adds the output), context =
//! `MIDDLEMAN_VERIFY_CONTEXT` or `assumed_context_tokens` (60k), 5-minute cache, the line's
//! `claude_model` prices. N = `output_bytes` at the Claude ratio (the old formula used the
//! cheap model's completion tokens, reasoning included).

use middleman::economics::{EconomicsCfg, Measured, TOOL_USE_FRAMING_TOKENS};
use sha2::{Digest, Sha256};

fn prose(task: &str) -> bool {
    matches!(task, "summarize" | "explain" | "translate" | "other")
}

#[test]
#[ignore = "reads a real ledger; set MIDDLEMAN_VERIFY_LEDGER"]
fn recompute_live_ledger() {
    let Some(path) = std::env::var_os("MIDDLEMAN_VERIFY_LEDGER") else {
        eprintln!("MIDDLEMAN_VERIFY_LEDGER not set; nothing to do");
        return;
    };
    let before = Sha256::digest(std::fs::read(&path).unwrap());
    let text = std::fs::read_to_string(&path).unwrap();
    let econ = EconomicsCfg::default();
    let ctx: u64 = std::env::var("MIDDLEMAN_VERIFY_CONTEXT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(econ.assumed_context_tokens);
    let r = econ.chars_per_token_code;
    let (mut old_net, mut new_net) = (0.0, 0.0);
    println!(
        "{:<22} {:<10} {:<28} {:>6} {:>6} | {:>9} {:>9} {:>9} | {:>9} {:>9} {:>9}",
        "ts",
        "status",
        "model",
        "cheapN",
        "claudeN",
        "old_eq",
        "old_oh",
        "old_net",
        "new_eq",
        "new_oh",
        "new_net"
    );
    for l in text.lines().filter(|l| !l.trim().is_empty()) {
        let raw: serde_json::Value = serde_json::from_str(l).unwrap();
        let Some(e) = middleman::ledger::parse_line(l) else {
            continue;
        };
        let old_eq = raw["claude_equiv_usd"].as_f64().unwrap_or(0.0);
        let old_oh = raw["claude_overhead_usd"].as_f64().unwrap_or(0.0);
        let old = raw["net_savings_usd"].as_f64().unwrap_or(-e.cost_usd);
        let (eq, oh, net, n) = if e.is_closing() {
            let model = if e.claude_model.is_empty() {
                "opus-5.5"
            } else {
                &e.claude_model
            };
            let p = econ.prices_for(model).unwrap();
            let out_chars = if e.status == "ok" {
                e.output_bytes.unwrap_or(0)
            } else {
                0
            };
            let pr = prose(&e.task_kind);
            let n = econ.claude_tokens(out_chars, pr);
            let inline = e.write_mode == "inline";
            let result_tokens = econ.summary_tokens + if inline { n } else { 0 };
            let b = econ.breakdown(
                &p,
                &Measured {
                    claude_output_chars: out_chars,
                    prose: pr,
                    call_chars: ((econ.call_tokens - TOOL_USE_FRAMING_TOKENS) as f64 * r) as u64,
                    result_chars: (result_tokens as f64 * r) as u64,
                    context_tokens: ctx,
                    cache_1h: false,
                    cheap_cost_usd: e.cost_usd,
                },
            );
            (
                b.claude_equiv_usd,
                b.claude_overhead_usd,
                b.net_savings_usd,
                n,
            )
        } else {
            (0.0, 0.0, -e.cost_usd, 0)
        };
        old_net += old;
        new_net += net;
        println!(
            "{:<22} {:<10} {:<28} {:>6} {:>6} | {:>9.5} {:>9.5} {:>9.5} | {:>9.5} {:>9.5} {:>9.5}",
            e.ts.chars().take(22).collect::<String>(),
            e.status,
            e.model.chars().take(28).collect::<String>(),
            e.output_tokens.map(|t| t.to_string()).unwrap_or("-".into()),
            n,
            old_eq,
            old_oh,
            old,
            eq,
            oh,
            net
        );
    }
    println!("TOTAL net: old {old_net:.5}  new {new_net:.5}  (context {ctx} tokens)");
    let after = Sha256::digest(std::fs::read(&path).unwrap());
    assert_eq!(before, after, "the ledger must not change");
}
