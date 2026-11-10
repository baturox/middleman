//! Provider onboarding: validate a key with a free call, store it, and record where it is in
//! the config (`key_source`). Used by `middleman provider ...`, `middleman login` and `init`.
//! The interactive prompts live in `main.rs`; everything here is testable without a TTY.

use std::path::Path;

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::config::{Api, BalanceKind, Config, Secret};
use crate::keystore::KeySource;

/// What a validation call found out about a key (nothing secret).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct KeyInfo {
    pub label: Option<String>,
    pub limit_usd: Option<f64>,
    pub limit_remaining_usd: Option<f64>,
    pub usage_usd: Option<f64>,
    pub is_free_tier: Option<bool>,
    pub models: Option<usize>,
}

impl KeyInfo {
    pub fn summary(&self) -> String {
        let mut v = vec![];
        if let Some(l) = &self.label {
            v.push(format!("label {l}"));
        }
        match (self.limit_usd, self.limit_remaining_usd) {
            (Some(l), Some(r)) => v.push(format!("limit ${l:.2} (${r:.2} left)")),
            (Some(l), None) => v.push(format!("limit ${l:.2}")),
            (None, _) if self.label.is_some() => v.push("no spending limit".into()),
            _ => {}
        }
        if let Some(u) = self.usage_usd {
            v.push(format!("used ${u:.2}"));
        }
        if self.is_free_tier == Some(true) {
            v.push("free tier".into());
        }
        if let Some(n) = self.models {
            v.push(format!("{n} models visible"));
        }
        if v.is_empty() {
            "key accepted".into()
        } else {
            v.join(", ")
        }
    }
}

fn num(v: Option<&Value>) -> Option<f64> {
    match v? {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn http_error(status: u16) -> anyhow::Error {
    if status == 401 || status == 403 {
        anyhow::anyhow!(
            "the provider rejected this key (HTTP {status}); check you copied the whole key and that it is active"
        )
    } else {
        anyhow::anyhow!("could not validate the key: the provider answered HTTP {status}")
    }
}

/// Check a key with a non-billable request. OpenRouter-style providers: `GET /key`
/// (label, limit, usage); everyone else: `GET /models` with the key. The api kind does not
/// matter for these GETs (both use Bearer auth).
pub async fn validate_key(
    _api: Api,
    base_url: &str,
    balance: BalanceKind,
    key: &Secret,
) -> Result<KeyInfo> {
    let base = base_url.trim_end_matches('/');
    if balance == BalanceKind::Openrouter {
        let (st, v) = crate::http::get_json(&format!("{base}/key"), Some(key)).await?;
        if !(200..300).contains(&st) {
            return Err(http_error(st));
        }
        let v = v.context("could not validate the key: the reply was not JSON")?;
        let d = v.get("data").unwrap_or(&v);
        let s = |k: &str| {
            d.get(k)
                .and_then(Value::as_str)
                .map(|x| crate::fsutil::clean(x, 60))
        };
        return Ok(KeyInfo {
            label: s("label"),
            limit_usd: num(d.get("limit")),
            limit_remaining_usd: num(d.get("limit_remaining")),
            usage_usd: num(d.get("usage")),
            is_free_tier: d.get("is_free_tier").and_then(Value::as_bool),
            models: None,
        });
    }
    let (st, v) = crate::http::get_json(&format!("{base}/models"), Some(key)).await?;
    if !(200..300).contains(&st) {
        return Err(http_error(st));
    }
    let n = v
        .as_ref()
        .and_then(|v| v.get("data"))
        .and_then(Value::as_array)
        .map(|a| a.len())
        .context("could not validate the key: the reply had no model list")?;
    Ok(KeyInfo {
        models: Some(n),
        ..Default::default()
    })
}

/// Light sanity checks on a pasted key; errors never echo it.
pub fn check_pasted(provider: &str, key: &str) -> Result<Option<String>> {
    let k = key.trim();
    if k.is_empty() {
        bail!("no key entered");
    }
    if k.chars().any(|c| c.is_whitespace() || c.is_control()) {
        bail!("the key contains spaces or control characters; paste only the key");
    }
    if k.len() < 16 {
        bail!(
            "that is too short to be an API key ({} characters)",
            k.len()
        );
    }
    if provider == "openrouter" && !k.starts_with("sk-or-") {
        return Ok(Some(
            "OpenRouter keys usually start with `sk-or-`; continuing anyway".into(),
        ));
    }
    Ok(None)
}

/// Add or update `[providers.<name>]` in the config text, keeping comments and other keys.
pub fn upsert_provider(text: &str, name: &str, key_source: Option<KeySource>) -> Result<String> {
    let mut doc: toml_edit::DocumentMut = text.parse().context("config is not valid TOML")?;
    let preset = crate::providers::presets::find(name);
    let providers = doc
        .entry("providers")
        .or_insert_with(|| {
            let mut t = toml_edit::Table::new();
            t.set_implicit(true);
            toml_edit::Item::Table(t)
        })
        .as_table_mut()
        .context("`providers` in the config is not a table")?;
    let entry = providers
        .entry(name)
        .or_insert_with(|| toml_edit::Item::Table(toml_edit::Table::new()))
        .as_table_mut()
        .with_context(|| format!("`providers.{name}` in the config is not a table"))?;
    if preset.is_some() && !entry.contains_key("preset") && !entry.contains_key("base_url") {
        entry.insert("preset", toml_edit::value(name));
    }
    match key_source {
        Some(s) => {
            entry.insert("key_source", toml_edit::value(s.as_str()));
        }
        None => {
            entry.remove("key_source");
        }
    }
    if entry.get("enabled").and_then(|v| v.as_bool()) == Some(false) {
        entry.insert("enabled", toml_edit::value(true));
    }
    Ok(doc.to_string())
}

/// Remove `[providers.<name>]` and routes that pin it are left for the user to edit.
pub fn remove_provider(text: &str, name: &str) -> Result<(String, bool)> {
    let mut doc: toml_edit::DocumentMut = text.parse().context("config is not valid TOML")?;
    let removed = doc
        .get_mut("providers")
        .and_then(|p| p.as_table_mut())
        .and_then(|t| t.remove(name))
        .is_some();
    Ok((doc.to_string(), removed))
}

/// Validate the edited config, then write it atomically (fail closed: an invalid edit is
/// never written).
pub fn write_config(path: &Path, text: &str) -> Result<()> {
    Config::from_toml(text).context("the updated config would be invalid; not written")?;
    crate::fsutil::write_atomic(path, text.as_bytes(), Some(0o600))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn validates_openrouter_key_via_get_key() {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/key"))
            .and(header("authorization", "Bearer sk-or-goodkey-1234567"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {"label": "sk-or-v1-abc...890", "limit": 10, "limit_remaining": 7.5,
                         "usage": 2.5, "is_free_tier": false}
            })))
            .mount(&s)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/key"))
            .respond_with(
                ResponseTemplate::new(401)
                    .set_body_json(serde_json::json!({"error": {"message": "No auth"}})),
            )
            .mount(&s)
            .await;
        let base = format!("{}/api/v1", s.uri());
        let ok = validate_key(
            Api::Openai,
            &base,
            BalanceKind::Openrouter,
            &Secret::new("sk-or-goodkey-1234567"),
        )
        .await
        .unwrap();
        assert_eq!(ok.label.as_deref(), Some("sk-or-v1-abc...890"));
        assert_eq!(ok.limit_remaining_usd, Some(7.5));
        assert!(ok.summary().contains("$7.50 left"), "{}", ok.summary());
        let bad = validate_key(
            Api::Openai,
            &base,
            BalanceKind::Openrouter,
            &Secret::new("sk-or-badkey-99999999"),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(bad.contains("rejected this key (HTTP 401)"), "{bad}");
        assert!(!bad.contains("sk-or-badkey"));
    }

    #[tokio::test]
    async fn validates_other_keys_via_models() {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"data": [{"id": "a"}, {"id": "b"}]})),
            )
            .mount(&s)
            .await;
        let info = validate_key(
            Api::Openai,
            &format!("{}/v1", s.uri()),
            BalanceKind::None,
            &Secret::new("k-1234567890abcdef"),
        )
        .await
        .unwrap();
        assert_eq!(info.models, Some(2));
    }

    #[test]
    fn pasted_key_checks() {
        assert!(check_pasted("openrouter", "  ").is_err());
        assert!(check_pasted("openrouter", "sk-or-v1 with space").is_err());
        assert!(check_pasted("openrouter", "short").is_err());
        assert!(check_pasted("openrouter", "sk-or-v1-0123456789abcdef")
            .unwrap()
            .is_none());
        assert!(check_pasted("openrouter", "0123456789abcdef0123")
            .unwrap()
            .is_some());
        let e = check_pasted("x", "secret value!").unwrap_err().to_string();
        assert!(!e.contains("secret value"));
    }

    #[test]
    fn upsert_keeps_comments_and_other_keys() {
        let d = tempfile::tempdir().unwrap();
        let t = format!(
            "# my config\n[paths]\nroots = [\"{}\"]\n\n[providers.openrouter]\npreset = \"openrouter\"\nmodel = \"qwen/qwen3.8-flash\" # pinned\n",
            d.path().display()
        );
        let out = upsert_provider(&t, "openrouter", Some(KeySource::Keychain)).unwrap();
        assert!(out.contains("# my config"));
        assert!(out.contains("# pinned"));
        assert!(out.contains("key_source = \"keychain\""));
        let c = Config::from_toml(&out).unwrap();
        assert_eq!(
            c.providers["openrouter"].key_source,
            Some(KeySource::Keychain)
        );
        let out = upsert_provider(&out, "deepseek", Some(KeySource::File)).unwrap();
        let c = Config::from_toml(&out).unwrap();
        assert_eq!(c.providers["deepseek"].preset.as_deref(), Some("deepseek"));
        let (out, removed) = remove_provider(&out, "deepseek").unwrap();
        assert!(removed);
        assert!(!Config::from_toml(&out)
            .unwrap()
            .providers
            .contains_key("deepseek"));
        let p = d.path().join("c.toml");
        assert!(write_config(&p, "not = [valid").is_err());
        assert!(!p.exists());
        write_config(&p, &out).unwrap();
        assert!(p.exists());
    }
}
