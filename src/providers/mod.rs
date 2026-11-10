//! Provider client. Enum dispatch over the two wire formats instead of `dyn Provider`
//! (async trait objects would need an extra crate); the surface is the plan's trait:
//! `complete`, `balance`, `models`. `complete` only accepts `&Sanitized<OutboundRequest>`.

pub mod anthropic;
pub mod openai_compat;
pub mod presets;

use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use std::collections::BTreeMap;

use crate::config::{Api, BalanceKind, ProviderCfg, Secret};
use crate::egress::{OutboundRequest, Sanitized};

#[derive(Debug, Clone, Serialize)]
pub struct Completion {
    pub text: String,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub model: Option<String>,
    pub stop_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Balance {
    pub usd: f64,
    pub payg: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    pub id: String,
    pub tier: Option<String>,
    pub modality: Option<String>,
    pub status: Option<String>,
    pub context_length: Option<u64>,
    pub price_in_per_1m: Option<f64>,
    pub price_out_per_1m: Option<f64>,
}

impl ModelInfo {
    /// Text-in/text-out chat model (heuristic over the gateway's metadata).
    pub fn is_text(&self) -> bool {
        let m = self
            .modality
            .as_deref()
            .unwrap_or("text")
            .to_ascii_lowercase();
        let id = self.id.to_ascii_lowercase();
        let bad_id = [
            "embed",
            "whisper",
            "tts",
            "image",
            "dall",
            "vision-only",
            "moderation",
            "rerank",
            "audio",
            "video",
            "veo",
            "imagen",
            "flux",
            "sora",
            "transcribe",
            "speech",
        ]
        .iter()
        .any(|b| id.contains(b));
        // yapayzekalab localizes modality: "Metin" (text), "Görsel" (vision-capable chat)
        let text_like = [
            "text",
            "metin",
            "görsel",
            "gorsel",
            "vision",
            "multimodal",
            "chat",
        ]
        .iter()
        .any(|t| m.contains(t));
        let text_modality = text_like && !m.contains("->image") && !m.contains("->audio");
        text_modality && !bad_id && self.status.as_deref().is_none_or(|s| s != "disabled")
    }
}

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("HTTP {status}: {message}")]
    Http { status: u16, message: String },
    #[error("request timed out")]
    Timeout,
    #[error("transport error: {0}")]
    Transport(String),
    #[error("bad response: {0}")]
    BadResponse(String),
}

impl ProviderError {
    /// True when the request may have reached the provider and been billed.
    pub fn maybe_billed(&self) -> bool {
        matches!(self, ProviderError::Timeout | ProviderError::BadResponse(_))
            || matches!(self, ProviderError::Http { status, .. } if *status >= 500)
    }
}

pub struct Provider {
    pub name: String,
    pub api: Api,
    base_url: String,
    key: Secret,
    ua: String,
    timeout: Duration,
    client: reqwest::Client,
    headers: BTreeMap<String, String>,
    balance_kind: BalanceKind,
}

fn num(v: Option<&Value>) -> Option<f64> {
    match v? {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

impl Provider {
    pub fn from_cfg(name: &str, cfg: &ProviderCfg, timeout_s: u64) -> Result<Provider> {
        let key = cfg.resolve_key()?;
        let mut p = Self::with_key(name, cfg.api, &cfg.base_url, key, cfg.ua(), timeout_s)?;
        p.headers = cfg.headers.clone();
        p.balance_kind = cfg.balance;
        Ok(p)
    }

    pub fn with_balance(mut self, b: BalanceKind) -> Self {
        self.balance_kind = b;
        self
    }

    pub fn balance_kind(&self) -> BalanceKind {
        self.balance_kind
    }

    pub fn with_key(
        name: &str,
        api: Api,
        base_url: &str,
        key: Secret,
        ua: &str,
        timeout_s: u64,
    ) -> Result<Provider> {
        let timeout = Duration::from_secs(timeout_s.max(1));
        let client = reqwest::Client::builder()
            .user_agent(ua)
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(15))
            .build()?;
        Ok(Provider {
            name: name.to_string(),
            api,
            base_url: base_url.trim_end_matches('/').to_string(),
            key,
            ua: ua.to_string(),
            timeout,
            client,
            headers: BTreeMap::new(),
            balance_kind: BalanceKind::Yzlab,
        })
    }

    pub fn key(&self) -> &Secret {
        &self.key
    }

    pub fn user_agent(&self) -> &str {
        &self.ua
    }

    fn scrub(&self, s: &str) -> String {
        let mut s: String = s.chars().take(300).collect();
        let k = self.key.expose();
        if !k.is_empty() {
            s = s.replace(k, "***");
        }
        s
    }

    fn map_err(&self, e: reqwest::Error) -> ProviderError {
        if e.is_timeout() {
            ProviderError::Timeout
        } else {
            ProviderError::Transport(self.scrub(&e.without_url().to_string()))
        }
    }

    fn auth(&self, rb: reqwest::RequestBuilder, api: Api) -> reqwest::RequestBuilder {
        let k = self.key.expose();
        let mut rb = rb;
        for (h, v) in &self.headers {
            rb = rb.header(h.as_str(), v.as_str());
        }
        if k.is_empty() {
            return rb; // local provider without a key
        }
        let rb = rb.header("authorization", format!("Bearer {k}"));
        match api {
            Api::Anthropic => rb
                .header("x-api-key", k)
                .header("anthropic-version", "2023-06-01"),
            Api::Openai => rb,
        }
    }

    async fn read_json(&self, resp: reqwest::Response) -> Result<Value, ProviderError> {
        let status = resp.status();
        let text = resp.text().await.map_err(|e| self.map_err(e))?;
        let v: Option<Value> = serde_json::from_str(&text).ok();
        if !status.is_success() {
            let msg = v
                .as_ref()
                .and_then(|v| {
                    v.pointer("/error/message")
                        .or_else(|| v.get("message"))
                        .or_else(|| v.get("error"))
                })
                .map(|m| {
                    m.as_str()
                        .map(String::from)
                        .unwrap_or_else(|| m.to_string())
                })
                .unwrap_or_else(|| text.clone());
            return Err(ProviderError::Http {
                status: status.as_u16(),
                message: self.scrub(&msg),
            });
        }
        v.ok_or_else(|| ProviderError::BadResponse(self.scrub(&format!("non-JSON body: {text}"))))
    }

    pub async fn complete(
        &self,
        req: &Sanitized<OutboundRequest>,
    ) -> Result<Completion, ProviderError> {
        self.complete_with(self.api, req).await
    }

    /// Send with an explicit wire format (used by `probe` to test both).
    pub async fn complete_with(
        &self,
        api: Api,
        req: &Sanitized<OutboundRequest>,
    ) -> Result<Completion, ProviderError> {
        let r = req.get();
        let (path, body) = match api {
            Api::Anthropic => (anthropic::PATH, anthropic::body(r)),
            Api::Openai => (openai_compat::PATH, openai_compat::body(r)),
        };
        let rb = self
            .client
            .post(format!("{}{}", self.base_url, path))
            .timeout(self.timeout)
            .json(&body);
        let resp = self
            .auth(rb, api)
            .send()
            .await
            .map_err(|e| self.map_err(e))?;
        let v = self.read_json(resp).await?;
        match api {
            Api::Anthropic => anthropic::parse(&v),
            Api::Openai => openai_compat::parse(&v),
        }
    }

    pub async fn balance(&self) -> Result<Balance, ProviderError> {
        let path = match self.balance_kind {
            BalanceKind::Yzlab => "/balance",
            BalanceKind::Openrouter => "/credits",
            BalanceKind::None => {
                return Err(ProviderError::BadResponse(
                    "provider has no balance endpoint".into(),
                ))
            }
        };
        let rb = self.client.get(format!("{}{}", self.base_url, path));
        let resp = self
            .auth(rb, Api::Openai)
            .send()
            .await
            .map_err(|e| self.map_err(e))?;
        let v = self.read_json(resp).await?;
        match self.balance_kind {
            BalanceKind::Openrouter => {
                let total = num(v.pointer("/data/total_credits"));
                let used = num(v.pointer("/data/total_usage"));
                let usd = total.zip(used).map(|(t, u)| t - u).ok_or_else(|| {
                    ProviderError::BadResponse("missing data.total_credits".into())
                })?;
                Ok(Balance { usd, payg: None })
            }
            _ => {
                let usd = num(v.get("balance_usd"))
                    .ok_or_else(|| ProviderError::BadResponse("missing balance_usd".into()))?;
                Ok(Balance {
                    usd,
                    payg: v.get("payg_enabled").and_then(|b| b.as_bool()),
                })
            }
        }
    }

    pub async fn models(&self) -> Result<Vec<ModelInfo>, ProviderError> {
        let rb = self.client.get(format!("{}/models", self.base_url));
        let resp = self
            .auth(rb, Api::Openai)
            .send()
            .await
            .map_err(|e| self.map_err(e))?;
        let v = self.read_json(resp).await?;
        let data = v
            .get("data")
            .and_then(|d| d.as_array())
            .ok_or_else(|| ProviderError::BadResponse("missing data[]".into()))?;
        Ok(data
            .iter()
            .filter_map(|m| {
                let id = m.get("id")?.as_str()?.to_string();
                let p = m.get("pricing");
                let pin = num(p.and_then(|p| p.get("input_per_1m_usd")))
                    .or_else(|| num(p.and_then(|p| p.get("prompt"))).map(|x| x * 1e6));
                let pout = num(p.and_then(|p| p.get("output_per_1m_usd")))
                    .or_else(|| num(p.and_then(|p| p.get("completion"))).map(|x| x * 1e6));
                let s = |k: &str| m.get(k).and_then(|x| x.as_str()).map(String::from);
                Some(ModelInfo {
                    id,
                    tier: s("tier"),
                    modality: s("modality").or_else(|| {
                        m.pointer("/architecture/modality")
                            .and_then(|x| x.as_str())
                            .map(String::from)
                    }),
                    status: s("status"),
                    context_length: m.get("context_length").and_then(|x| x.as_u64()),
                    price_in_per_1m: pin,
                    price_out_per_1m: pout,
                })
            })
            .collect())
    }

    /// GET `path` with a specific User-Agent (None = no UA header). Returns the HTTP status.
    /// Used by `probe` to learn whether the gateway rejects non-browser clients.
    pub async fn status_with_ua(&self, path: &str, ua: Option<&str>) -> Result<u16, ProviderError> {
        let mut b = reqwest::Client::builder().timeout(Duration::from_secs(20));
        if let Some(ua) = ua {
            b = b.user_agent(ua);
        }
        let c = b.build().map_err(|e| self.map_err(e))?;
        let rb = c.get(format!("{}{}", self.base_url, path));
        let resp = self
            .auth(rb, Api::Openai)
            .send()
            .await
            .map_err(|e| self.map_err(e))?;
        Ok(resp.status().as_u16())
    }
}
