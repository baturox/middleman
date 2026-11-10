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
        model: v.get("model").and_then(|m| m.as_str()).map(String::from),
        stop_reason: choice
            .get("finish_reason")
            .and_then(|m| m.as_str())
            .map(String::from),
    })
}
