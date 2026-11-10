//! Model catalog discovered from each provider's `GET /models`, cached with a TTL.
//! Pricing precedence: user `[models."<provider>/<id>"]` override > provider pricing fields >
//! bundled `config/prices.toml` > (trust=local: 0). Unknown price => not eligible.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::budget::Prices;
use crate::config::{Config, Trust};
use crate::ledger::now_unix;
use crate::providers::{ModelInfo, Provider};

#[derive(Debug, Clone, Deserialize)]
struct BundledPrice {
    price_in: f64,
    price_out: f64,
}

static BUNDLED: LazyLock<BTreeMap<String, BundledPrice>> =
    LazyLock::new(|| toml::from_str(include_str!("../config/prices.toml")).unwrap_or_default());

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawModel {
    pub provider: String,
    pub info: ModelInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Catalog {
    pub fetched_at: i64,
    pub models: Vec<RawModel>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Priced {
    pub provider: String,
    pub id: String,
    pub prices: Option<Prices>,
    pub context: Option<u64>,
    pub tags: Vec<String>,
}

/// `:free` / `-free` variants are excluded unless a `[models."p/id"] enabled = true` override
/// opts in (free upstreams commonly retain or train on prompts).
pub fn is_free_tier(id: &str) -> bool {
    let l = id.to_ascii_lowercase();
    l.ends_with(":free") || l.ends_with("-free")
}

/// Capability tags from the model id (users can override per model).
pub fn tags_for(id: &str, context: Option<u64>) -> Vec<String> {
    let l = id.to_ascii_lowercase();
    let mut t = vec!["chat".to_string()];
    let code_families = [
        "code",
        "coder",
        "codestral",
        "devstral",
        "deepseek",
        "qwen",
        "gpt-4",
        "gpt-5",
        "gpt-oss",
        "claude",
        "gemini",
        "glm",
        "kimi",
        "grok",
        "mistral-large",
        "mistral-medium",
        "llama-3.3",
        "llama-4",
        "minimax",
    ];
    if code_families.iter().any(|f| l.contains(f)) {
        t.push("code".into());
    }
    if ["r1", "reasoner", "thinking", "o1", "o3", "o4", "qwq"]
        .iter()
        .any(|f| l.split(['-', '/', ':', '.', '_']).any(|p| p == *f) || l.contains("reason"))
    {
        t.push("reasoning".into());
    }
    if context.is_some_and(|c| c >= 128_000) {
        t.push("long_context".into());
    }
    t
}

impl Catalog {
    pub fn cache_path(cfg: &Config) -> PathBuf {
        cfg.cache_dir().join("models.json")
    }

    pub fn load(cfg: &Config) -> Option<Catalog> {
        let text = std::fs::read_to_string(Self::cache_path(cfg)).ok()?;
        serde_json::from_str(&text).ok()
    }

    pub fn save(&self, cfg: &Config) -> Result<()> {
        let dir = cfg.cache_dir();
        std::fs::create_dir_all(&dir)?;
        let tmp = dir.join("models.json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(tmp, Self::cache_path(cfg))?;
        Ok(())
    }

    pub fn age_secs(&self) -> i64 {
        now_unix() - self.fetched_at
    }

    pub fn is_fresh(&self, cfg: &Config) -> bool {
        self.age_secs() < (cfg.routing.catalog_ttl_hours as i64) * 3600
    }

    /// Fetch `/models` from every enabled provider. Free GETs only; no payload leaves.
    pub async fn refresh<F>(cfg: &Config, get: F) -> Catalog
    where
        F: Fn(&str) -> Result<Arc<Provider>>,
    {
        let mut c = Catalog {
            fetched_at: now_unix(),
            ..Default::default()
        };
        for (name, p) in &cfg.providers {
            if !p.enabled {
                continue;
            }
            let prov = match get(name) {
                Ok(p) => p,
                Err(e) => {
                    c.errors.push(format!("{name}: {e}"));
                    continue;
                }
            };
            match prov.models().await {
                Ok(ms) => c.models.extend(ms.into_iter().map(|info| RawModel {
                    provider: name.clone(),
                    info,
                })),
                Err(e) => c.errors.push(format!("{name}: {e}")),
            }
        }
        c
    }

    fn price_for(
        cfg: &Config,
        provider: &str,
        id: &str,
        info: Option<&ModelInfo>,
    ) -> Option<Prices> {
        let key = format!("{provider}/{id}");
        if let Some(o) = cfg.models.get(&key) {
            if let (Some(i), Some(out)) = (o.price_in, o.price_out) {
                return Some(Prices {
                    in_per_1m: i,
                    out_per_1m: out,
                });
            }
        }
        if let Some(m) = info {
            if let (Some(i), Some(o)) = (m.price_in_per_1m, m.price_out_per_1m) {
                return Some(Prices {
                    in_per_1m: i,
                    out_per_1m: o,
                });
            }
        }
        if let Some(b) = BUNDLED.get(&key) {
            return Some(Prices {
                in_per_1m: b.price_in,
                out_per_1m: b.price_out,
            });
        }
        if cfg
            .providers
            .get(provider)
            .is_some_and(|p| p.trust == Trust::Local)
        {
            return Some(Prices {
                in_per_1m: 0.0,
                out_per_1m: 0.0,
            });
        }
        None
    }

    fn priced(cfg: &Config, provider: &str, id: &str, info: Option<&ModelInfo>) -> Option<Priced> {
        let ov = cfg.models.get(&format!("{provider}/{id}"));
        match ov.and_then(|o| o.enabled) {
            Some(false) => return None,
            // free tiers typically log/train on prompts: opt-in only
            None if is_free_tier(id) => return None,
            _ => {}
        }
        let context = ov
            .and_then(|o| o.context)
            .or(info.and_then(|m| m.context_length));
        let tags = ov
            .and_then(|o| o.tags.clone())
            .unwrap_or_else(|| tags_for(id, context));
        Some(Priced {
            provider: provider.to_string(),
            id: id.to_string(),
            prices: Self::price_for(cfg, provider, id, info),
            context,
            tags,
        })
    }

    /// Text models of enabled providers with prices/tags resolved under the current config.
    pub fn resolve(&self, cfg: &Config) -> Vec<Priced> {
        self.models
            .iter()
            .filter(|m| cfg.providers.get(&m.provider).is_some_and(|p| p.enabled))
            .filter(|m| m.info.is_text())
            .filter_map(|m| Self::priced(cfg, &m.provider, &m.info.id, Some(&m.info)))
            .collect()
    }

    /// For pinned chain steps: works without a catalog entry if the config prices the model.
    pub fn lookup(
        cfg: &Config,
        catalog: Option<&Catalog>,
        provider: &str,
        id: &str,
    ) -> Option<Priced> {
        let info = catalog.and_then(|c| {
            c.models
                .iter()
                .find(|m| m.provider == provider && m.info.id == id)
                .map(|m| &m.info)
        });
        Self::priced(cfg, provider, id, info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags() {
        assert!(tags_for("deepseek/deepseek-chat", None).contains(&"code".into()));
        assert!(tags_for("deepseek-r1", None).contains(&"reasoning".into()));
        assert!(!tags_for("tiny-chat-1b", None).contains(&"code".into()));
        assert!(tags_for("x", Some(200_000)).contains(&"long_context".into()));
    }
}
