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

/// The provider answered, but not with 2xx. Carries only the status (never the body).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub struct HttpStatus {
    pub status: u16,
}

impl std::fmt::Display for HttpStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.status;
        if s == 401 || s == 403 {
            write!(f, "the provider rejected this key (HTTP {s}); check you copied the whole key and that it is active")
        } else {
            write!(
                f,
                "could not validate the key: the provider answered HTTP {s}"
            )
        }
    }
}

fn http_error(status: u16) -> anyhow::Error {
    anyhow::Error::new(HttpStatus { status })
}

/// The reply was not what a model API returns (wrong URL, a web page, a proxy).
#[derive(Debug, Clone, thiserror::Error)]
#[error("{0}")]
pub struct BadReply(pub &'static str);

/// What a failed check means, in plain words, and what to do about it.
#[derive(Debug, Clone, PartialEq)]
pub struct Diagnosis {
    pub title: String,
    pub advice: String,
    /// Retrying the same input may help (network trouble, rate limits), so offer it first.
    pub retry_first: bool,
}

/// What `diagnose` needs to know about the thing being checked.
pub struct CheckTarget<'a> {
    pub label: &'a str,
    pub key_url: Option<&'a str>,
    /// Local server (Ollama, LM Studio, a localhost URL): no key, may not be running.
    pub local: bool,
}

/// Map a failed key/URL check to advice. Never includes the key (errors never carry it).
pub fn diagnose(err: &anyhow::Error, t: &CheckTarget) -> Diagnosis {
    let label = t.label;
    let key_page = t
        .key_url
        .map(|u| format!(" Copy it again from {u}."))
        .unwrap_or_default();
    let d = |title: String, advice: String, retry_first: bool| Diagnosis {
        title,
        advice,
        retry_first,
    };
    if let Some(h) = err.chain().find_map(|e| e.downcast_ref::<HttpStatus>()) {
        let s = h.status;
        return match s {
            401 => d(
                format!("{label} rejected this key (HTTP 401)."),
                format!("The key is wrong, incomplete or revoked.{key_page}"),
                false,
            ),
            402 => d(
                format!("{label} says payment is required (HTTP 402)."),
                "The key works but the account has no credit. Add credit, then retry.".into(),
                true,
            ),
            403 => d(
                format!("{label} refused access (HTTP 403)."),
                "The key is valid but not allowed to do this: it may be disabled, limited to other \
                 endpoints, or blocked in your region. Check the key's settings in the dashboard."
                    .into(),
                false,
            ),
            404 => d(
                format!("{label} has no model list at this address (HTTP 404)."),
                if t.local {
                    "The server answered, but not at this path. The URL usually ends in /v1.".into()
                } else {
                    "The base URL is probably wrong (it usually ends in /v1).".into()
                },
                false,
            ),
            429 => d(
                format!("{label} is rate-limiting this key (HTTP 429)."),
                "Too many requests right now, or the free quota is used up. Wait a minute and retry."
                    .into(),
                true,
            ),
            500..=599 => d(
                format!("{label} had a server error (HTTP {s})."),
                "This is on the provider's side. Retry in a moment.".into(),
                true,
            ),
            _ => d(
                format!("{label} answered HTTP {s}."),
                "Unexpected answer. Check the URL and the key, then retry.".into(),
                true,
            ),
        };
    }
    if let Some(n) = err
        .chain()
        .find_map(|e| e.downcast_ref::<crate::http::NetError>())
    {
        use crate::http::NetKind;
        let host = &n.host;
        return match n.kind {
            NetKind::Timeout => d(
                format!("{host} did not answer in time."),
                "The network is slow or a firewall/VPN drops the connection. Retry, or check your connection."
                    .into(),
                true,
            ),
            NetKind::Dns => d(
                format!("Cannot find {host} (DNS lookup failed)."),
                "Check your internet connection and the spelling of the URL.".into(),
                true,
            ),
            NetKind::Tls => d(
                format!("The secure connection to {host} failed (TLS)."),
                "A proxy, antivirus or captive portal may be intercepting HTTPS, or the server's \
                 certificate is invalid. Try another network."
                    .into(),
                true,
            ),
            NetKind::Refused if t.local => d(
                format!("Nothing is listening at {host}."),
                format!("{label} is probably not running. Start it (e.g. `ollama serve`, or the LM Studio server tab), then retry."),
                true,
            ),
            NetKind::Refused => d(
                format!("{host} refused the connection."),
                "Check the URL and port, then retry.".into(),
                true,
            ),
            NetKind::Other => d(
                format!("Cannot reach {host}."),
                "Check your internet connection (or proxy settings), then retry.".into(),
                true,
            ),
        };
    }
    if let Some(b) = err.chain().find_map(|e| e.downcast_ref::<BadReply>()) {
        return d(
            format!("{label} answered, but not like a model API."),
            format!("{}. Check the base URL (it usually ends in /v1).", b.0),
            false,
        );
    }
    d(
        format!(
            "The check failed: {}",
            crate::fsutil::clean(&format!("{err:#}"), 200)
        ),
        "Check the URL and the key, then retry.".into(),
        true,
    )
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
        let v = v.ok_or(BadReply("the reply was not JSON"))?;
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
    let n = count_models(base, Some(key)).await?;
    Ok(KeyInfo {
        models: Some(n),
        ..Default::default()
    })
}

/// `GET {base}/models` (free) and count the entries. `key` may be None for local servers.
pub async fn count_models(base_url: &str, key: Option<&Secret>) -> Result<usize> {
    let base = base_url.trim_end_matches('/');
    let (st, v) = crate::http::get_json(&format!("{base}/models"), key).await?;
    if !(200..300).contains(&st) {
        return Err(http_error(st));
    }
    v.as_ref()
        .and_then(|v| v.get("data"))
        .and_then(Value::as_array)
        .map(|a| a.len())
        .ok_or_else(|| BadReply("the reply had no model list").into())
}

/// Check a base URL typed by the user: http(s) only, a host, no userinfo, query or fragment,
/// and https unless the host is exactly localhost, 127.0.0.1 or ::1 (the same rule the
/// config enforces). Returns it normalized (no trailing `/`).
pub fn check_base_url(input: &str) -> std::result::Result<String, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("enter a URL, e.g. https://api.example.com/v1".into());
    }
    if !s.contains("://") {
        return Err(
            "include the scheme: https://… (or http://localhost:… for a local server)".into(),
        );
    }
    let u = url::Url::parse(s).map_err(|e| format!("not a valid URL ({e})"))?;
    match u.scheme() {
        "https" | "http" => {}
        other => return Err(format!("{other}:// is not supported; use https://")),
    }
    if u.host().is_none() {
        return Err("the URL has no host".into());
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err("remove the user:password@ part; keys are stored separately".into());
    }
    if u.query().is_some() || u.fragment().is_some() {
        return Err("remove the ?query or #fragment; enter only the base URL".into());
    }
    let norm = s.trim_end_matches('/').to_string();
    if u.scheme() == "http" && !crate::config::is_local_url(&norm) {
        return Err(
            "plain http is only allowed for localhost, 127.0.0.1 or [::1]; use https:// for anything else"
                .into(),
        );
    }
    Ok(norm)
}

/// Light sanity checks on a pasted key; errors never echo it. `prefix` is the usual key
/// prefix (a mismatch is a warning, since vendors change formats).
pub fn check_pasted(label: &str, prefix: Option<&str>, key: &str) -> Result<Option<String>> {
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
    if let Some(p) = prefix {
        if !k.starts_with(p) {
            return Ok(Some(format!(
                "{label} keys usually start with `{p}`; checking it anyway"
            )));
        }
    }
    Ok(None)
}

/// One provider as `init` writes it.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ProviderEntry {
    pub name: String,
    /// Preset name; None for a custom OpenAI-compatible endpoint.
    pub preset: Option<String>,
    /// Base URL override (local servers on another port) or the custom endpoint.
    pub base_url: Option<String>,
    /// Custom endpoint on localhost: `trust = "local"`, no key.
    pub local: bool,
    pub key_source: Option<KeySource>,
    /// Default model for this provider (pinned chain steps).
    pub model: Option<String>,
}

impl ProviderEntry {
    pub fn preset(name: &str) -> ProviderEntry {
        ProviderEntry {
            name: name.into(),
            preset: Some(name.into()),
            ..Default::default()
        }
    }
}

/// Add or update `[providers.<name>]` from an entry, keeping comments and other keys. Only
/// fields the entry sets are written (an existing stored key is never dropped).
pub fn upsert_entry(text: &str, e: &ProviderEntry) -> Result<String> {
    let mut doc: toml_edit::DocumentMut = text.parse().context("config is not valid TOML")?;
    let providers = doc
        .entry("providers")
        .or_insert_with(|| {
            let mut t = toml_edit::Table::new();
            t.set_implicit(true);
            toml_edit::Item::Table(t)
        })
        .as_table_mut()
        .context("`providers` in the config is not a table")?;
    let t = providers
        .entry(&e.name)
        .or_insert_with(|| toml_edit::Item::Table(toml_edit::Table::new()))
        .as_table_mut()
        .with_context(|| format!("`providers.{}` in the config is not a table", e.name))?;
    match &e.preset {
        Some(p) => {
            t.insert("preset", toml_edit::value(p.as_str()));
        }
        None => {
            t.remove("preset");
            t.insert("api", toml_edit::value("openai"));
        }
    }
    if let Some(u) = &e.base_url {
        t.insert("base_url", toml_edit::value(u.as_str()));
    } else if e.preset.is_some() {
        t.remove("base_url");
    }
    if e.local && e.preset.is_none() {
        t.insert("trust", toml_edit::value("local"));
    }
    if let Some(s) = e.key_source {
        t.insert("key_source", toml_edit::value(s.as_str()));
    }
    if let Some(m) = &e.model {
        t.insert("model", toml_edit::value(m.as_str()));
    }
    if t.get("enabled").and_then(|v| v.as_bool()) == Some(false) {
        t.insert("enabled", toml_edit::value(true));
    }
    Ok(doc.to_string())
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
        let or = Some("sk-or-");
        assert!(check_pasted("OpenRouter", or, "  ").is_err());
        assert!(check_pasted("OpenRouter", or, "sk-or-v1 with space").is_err());
        assert!(check_pasted("OpenRouter", or, "short").is_err());
        assert!(check_pasted("OpenRouter", or, "sk-or-v1-0123456789abcdef")
            .unwrap()
            .is_none());
        let w = check_pasted("OpenRouter", or, "0123456789abcdef0123")
            .unwrap()
            .unwrap();
        assert!(w.contains("`sk-or-`"), "{w}");
        assert!(check_pasted("Mistral", None, "0123456789abcdef0123")
            .unwrap()
            .is_none());
        let e = check_pasted("x", None, "secret value!")
            .unwrap_err()
            .to_string();
        assert!(!e.contains("secret value"));
    }

    fn target(local: bool) -> CheckTarget<'static> {
        CheckTarget {
            label: "OpenRouter",
            key_url: Some("https://openrouter.ai/settings/keys"),
            local,
        }
    }

    #[test]
    fn errors_map_to_plain_advice() {
        let st = |s| diagnose(&http_error(s), &target(false));
        let a = st(401);
        assert!(a.title.contains("rejected this key (HTTP 401)"), "{a:?}");
        assert!(a.advice.contains("wrong, incomplete or revoked"));
        assert!(a.advice.contains("https://openrouter.ai/settings/keys"));
        assert!(!a.retry_first);
        assert!(st(403).title.contains("refused access (HTTP 403)"));
        assert!(!st(403).retry_first);
        assert!(st(404).advice.contains("/v1"));
        let r = st(429);
        assert!(r.title.contains("rate-limiting") && r.retry_first);
        assert!(st(402).advice.contains("credit"));
        assert!(st(503).advice.contains("provider's side"));
        use crate::http::{NetError, NetKind};
        let net = |kind, local| {
            diagnose(
                &anyhow::Error::new(NetError {
                    host: "openrouter.ai".into(),
                    kind,
                    detail: String::new(),
                })
                .context("checking"),
                &target(local),
            )
        };
        assert!(net(NetKind::Dns, false).title.contains("DNS"));
        assert!(net(NetKind::Tls, false).title.contains("TLS"));
        assert!(net(NetKind::Tls, false).advice.contains("proxy"));
        assert!(net(NetKind::Timeout, false).title.contains("in time"));
        assert!(net(NetKind::Refused, true).advice.contains("not running"));
        assert!(!net(NetKind::Refused, false).advice.contains("not running"));
        assert!(net(NetKind::Other, false).retry_first);
        let b = diagnose(
            &anyhow::Error::new(BadReply("the reply was not JSON")),
            &target(false),
        );
        assert!(b.title.contains("not like a model API"), "{b:?}");
    }

    #[test]
    fn base_url_rules() {
        assert_eq!(
            check_base_url(" https://api.example.com/v1/ ").unwrap(),
            "https://api.example.com/v1"
        );
        for ok in [
            "http://localhost:11434/v1",
            "http://127.0.0.1:1234/v1",
            "http://[::1]:8080/v1",
        ] {
            assert!(check_base_url(ok).is_ok(), "{ok}");
        }
        for (bad, why) in [
            ("", "enter a URL"),
            ("api.example.com/v1", "scheme"),
            ("ftp://example.com", "not supported"),
            ("http://example.com/v1", "only allowed for localhost"),
            ("http://localhost.evil.com/v1", "only allowed for localhost"),
            ("http://127.0.0.2/v1", "only allowed for localhost"),
            ("https://user:pw@example.com/v1", "user:password"),
            ("https://example.com/v1?x=1", "query"),
        ] {
            let e = check_base_url(bad).unwrap_err();
            assert!(e.contains(why), "{bad}: {e}");
        }
    }

    #[test]
    fn upsert_entry_writes_custom_and_local_providers() {
        let d = tempfile::tempdir().unwrap();
        let t = format!("[paths]\nroots = [\"{}\"]\n", d.path().display());
        let custom = ProviderEntry {
            name: "work".into(),
            base_url: Some("https://llm.example.com/v1".into()),
            key_source: Some(KeySource::File),
            ..Default::default()
        };
        let out = upsert_entry(&t, &custom).unwrap();
        let local = ProviderEntry {
            base_url: Some("http://localhost:11500/v1".into()),
            ..ProviderEntry::preset("ollama")
        };
        let out = upsert_entry(&out, &local).unwrap();
        let mine = ProviderEntry {
            name: "box".into(),
            base_url: Some("http://127.0.0.1:8000/v1".into()),
            local: true,
            ..Default::default()
        };
        let out = upsert_entry(&out, &mine).unwrap();
        let c = Config::from_toml(&out).unwrap();
        assert_eq!(c.providers["work"].base_url, "https://llm.example.com/v1");
        assert_eq!(c.providers["work"].key_source, Some(KeySource::File));
        assert_eq!(c.providers["ollama"].base_url, "http://localhost:11500/v1");
        assert_eq!(c.providers["box"].trust, crate::config::Trust::Local);
        // a later update without a key keeps the stored key
        let again = ProviderEntry {
            key_source: None,
            ..custom
        };
        let out = upsert_entry(&out, &again).unwrap();
        let c = Config::from_toml(&out).unwrap();
        assert_eq!(c.providers["work"].key_source, Some(KeySource::File));
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
