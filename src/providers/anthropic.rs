//! Anthropic `/v1/messages` wire format (non-streaming).

use serde_json::{json, Value};

use super::{Completion, ProviderError};
use crate::egress::OutboundRequest;

pub const PATH: &str = "/messages";

pub fn body(r: &OutboundRequest) -> Value {
    json!({
        "model": r.model,
        "max_tokens": r.max_tokens,
        "system": r.system,
        "messages": [{"role": "user", "content": r.user}],
    })
}

pub fn parse(v: &Value) -> Result<Completion, ProviderError> {
    let content = v
        .get("content")
        .and_then(|c| c.as_array())
        .ok_or_else(|| ProviderError::BadResponse("missing content[]".into()))?;
    let text: String = content
        .iter()
        .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("text"))
        .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
        .collect::<Vec<_>>()
        .join("");
    let usage = v.get("usage");
    Ok(Completion {
        text,
        input_tokens: usage
            .and_then(|u| u.get("input_tokens"))
            .and_then(|x| x.as_u64()),
        output_tokens: usage
            .and_then(|u| u.get("output_tokens"))
            .and_then(|x| x.as_u64()),
        model: v.get("model").and_then(|m| m.as_str()).map(String::from),
        stop_reason: v
            .get("stop_reason")
            .and_then(|m| m.as_str())
            .map(String::from),
    })
}
