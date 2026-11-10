//! OpenAI-compatible `/v1/chat/completions` wire format (non-streaming).

use serde_json::{json, Value};

use super::{Completion, ProviderError};
use crate::egress::OutboundRequest;

pub const PATH: &str = "/chat/completions";

pub fn body(r: &OutboundRequest) -> Value {
    json!({
        "model": r.model,
        "max_tokens": r.max_tokens,
        "stream": false,
        "messages": [
            {"role": "system", "content": r.system},
            {"role": "user", "content": r.user},
        ],
    })
}

/// The billed cost the gateway reports (`usage.cost`, OpenRouter usage accounting, in USD
/// credits). Values outside 0..=100 USD per request are treated as absent.
pub fn billed_cost(v: &Value) -> Option<f64> {
    let c = match v {
        Value::Number(n) => n.as_f64()?,
        Value::String(s) => s.trim().parse().ok()?,
        _ => return None,
    };
    (c.is_finite() && (0.0..=100.0).contains(&c)).then_some(c)
}

pub fn parse(v: &Value) -> Result<Completion, ProviderError> {
    let choice = v
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|c| c.first())
        .ok_or_else(|| ProviderError::BadResponse("missing choices[0]".into()))?;
    let text = choice
        .get("message")
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .to_string();
    let usage = v.get("usage");
    Ok(Completion {
        text,
        input_tokens: usage
            .and_then(|u| u.get("prompt_tokens"))
            .and_then(|x| x.as_u64()),
        output_tokens: usage
            .and_then(|u| u.get("completion_tokens"))
            .and_then(|x| x.as_u64()),
        cost_usd: usage.and_then(|u| u.get("cost")).and_then(billed_cost),
        model: v.get("model").and_then(|m| m.as_str()).map(String::from),
        stop_reason: choice
            .get("finish_reason")
            .and_then(|m| m.as_str())
            .map(String::from),
    })
}
