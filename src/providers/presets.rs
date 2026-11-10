//! Built-in provider presets (data only). A preset fills api/base_url/key_env/trust/balance;
//! anything set explicitly in `[providers.<name>]` wins. Adding a vendor = a few lines of TOML.
//!
//! `base_url` includes the API version prefix (OpenAI SDK convention); adapters append
//! `/chat/completions`, `/messages`, `/models`, `/balance`.
//!
//! Verification status: `verified = true` only where the base URL was checked against the
//! vendor's documentation (OpenRouter: the same docs `oauth.rs` was verified against). The
//! others are taken from vendor documentation as known at authoring time and were NOT
//! re-checked; `init` marks them "URL unverified" and `middleman doctor` confirms them.
//! Key pages and key prefixes are hints for the setup wizard only: a different prefix is a
//! warning, never an error.
//!
//! `hidden` presets still work in configs and with `--providers`, but are not offered in the
//! picker or `init --list`: aliases (`moonshot` = `kimi`, `zhipu` = `glm`, `dashscope` =
//! `qwen`), first-party `anthropic` (not a cheap model) and legacy gateways kept for
//! existing configs.

use crate::classify::Sensitivity;
use crate::config::{Api, BalanceKind, Trust};

/// Picker group, in display order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Group {
    Recommended,
    Direct,
    Local,
}

impl Group {
    pub fn title(&self) -> &'static str {
        match self {
            Group::Recommended => "Recommended",
            Group::Direct => "Direct vendors",
            Group::Local => "Local and free (nothing leaves your machine)",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Preset {
    pub name: &'static str,
    /// Display name, e.g. "Kimi (Moonshot)".
    pub label: &'static str,
    /// One line for the picker.
    pub blurb: &'static str,
    pub group: Group,
    pub api: Api,
    pub base_url: &'static str,
    pub key_env: Option<&'static str>,
    /// Where to create a key (setup hint).
    pub key_url: Option<&'static str>,
    /// Usual key prefix, e.g. `sk-or-` (setup hint; a mismatch only warns).
    pub key_prefix: Option<&'static str>,
    pub trust: Trust,
    pub balance: BalanceKind,
    pub verified: bool,
    pub hidden: bool,
}

const BASE: Preset = Preset {
    name: "",
    label: "",
    blurb: "",
    group: Group::Direct,
    api: Api::Openai,
    base_url: "",
    key_env: None,
    key_url: None,
    key_prefix: None,
    trust: Trust::Untrusted,
    balance: BalanceKind::None,
    verified: false,
    hidden: false,
};

const KIMI: Preset = Preset {
    name: "kimi",
    label: "Kimi (Moonshot)",
    blurb: "Moonshot's Kimi models, long context",
    base_url: "https://api.moonshot.ai/v1",
    key_env: Some("MOONSHOT_API_KEY"),
    key_url: Some("https://platform.moonshot.ai/console/api-keys"),
    key_prefix: Some("sk-"),
    ..BASE
};

const GLM: Preset = Preset {
    name: "glm",
    label: "GLM (Zhipu)",
    blurb: "Zhipu's GLM models",
    base_url: "https://open.bigmodel.cn/api/paas/v4",
    key_env: Some("ZHIPU_API_KEY"),
    key_url: Some("https://open.bigmodel.cn/usercenter/apikeys"),
    ..BASE
};

const QWEN: Preset = Preset {
    name: "qwen",
    label: "Qwen (DashScope)",
    blurb: "Alibaba's Qwen models, incl. Qwen Coder",
    base_url: "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
    key_env: Some("DASHSCOPE_API_KEY"),
    key_url: Some("https://modelstudio.console.alibabacloud.com/?tab=playground#/api-key"),
    key_prefix: Some("sk-"),
    ..BASE
};

/// Picker order within a group is table order.
pub const PRESETS: &[Preset] = &[
    Preset {
        name: "openrouter",
        label: "OpenRouter",
        blurb: "one key for DeepSeek, Qwen, Kimi, GLM and 300+ models",
        group: Group::Recommended,
        base_url: "https://openrouter.ai/api/v1",
        key_env: Some("OPENROUTER_API_KEY"),
        key_url: Some("https://openrouter.ai/settings/keys"),
        key_prefix: Some("sk-or-"),
        balance: BalanceKind::Openrouter,
        verified: true,
        ..BASE
    },
    Preset {
        name: "deepseek",
        label: "DeepSeek",
        blurb: "DeepSeek's own API, very cheap coding models",
        base_url: "https://api.deepseek.com/v1",
        key_env: Some("DEEPSEEK_API_KEY"),
        key_url: Some("https://platform.deepseek.com/api_keys"),
        key_prefix: Some("sk-"),
        ..BASE
    },
    KIMI,
    GLM,
    QWEN,
    Preset {
        name: "mistral",
        label: "Mistral",
        blurb: "Mistral and Codestral models",
        base_url: "https://api.mistral.ai/v1",
        key_env: Some("MISTRAL_API_KEY"),
        key_url: Some("https://console.mistral.ai/api-keys"),
        ..BASE
    },
    Preset {
        name: "groq",
        label: "Groq",
        blurb: "very fast open models",
        base_url: "https://api.groq.com/openai/v1",
        key_env: Some("GROQ_API_KEY"),
        key_url: Some("https://console.groq.com/keys"),
        key_prefix: Some("gsk_"),
        ..BASE
    },
    Preset {
        name: "together",
        label: "Together",
        blurb: "hosted open models (Llama, Qwen, DeepSeek)",
        base_url: "https://api.together.xyz/v1",
        key_env: Some("TOGETHER_API_KEY"),
        key_url: Some("https://api.together.ai/settings/api-keys"),
        ..BASE
    },
    Preset {
        name: "fireworks",
        label: "Fireworks",
        blurb: "hosted open models, fast inference",
        base_url: "https://api.fireworks.ai/inference/v1",
        key_env: Some("FIREWORKS_API_KEY"),
        key_url: Some("https://fireworks.ai/account/api-keys"),
        key_prefix: Some("fw_"),
        ..BASE
    },
    Preset {
        name: "gemini",
        label: "Gemini",
        blurb: "Google's Gemini models (OpenAI-compatible endpoint)",
        base_url: "https://generativelanguage.googleapis.com/v1beta/openai",
        key_env: Some("GEMINI_API_KEY"),
        key_url: Some("https://aistudio.google.com/apikey"),
        key_prefix: Some("AIza"),
        ..BASE
    },
    Preset {
        name: "xai",
        label: "xAI",
        blurb: "Grok models",
        base_url: "https://api.x.ai/v1",
        key_env: Some("XAI_API_KEY"),
        key_url: Some("https://console.x.ai"),
        key_prefix: Some("xai-"),
        ..BASE
    },
    Preset {
        name: "ollama",
        label: "Ollama",
        blurb: "models on this computer, no key",
        group: Group::Local,
        base_url: "http://localhost:11434/v1",
        trust: Trust::Local,
        ..BASE
    },
    Preset {
        name: "lmstudio",
        label: "LM Studio",
        blurb: "models on this computer, no key",
        group: Group::Local,
        base_url: "http://localhost:1234/v1",
        trust: Trust::Local,
        ..BASE
    },
    // ---- hidden: aliases, first-party, legacy (still valid in configs)
    Preset {
        name: "moonshot",
        hidden: true,
        ..KIMI
    },
    Preset {
        name: "zhipu",
        hidden: true,
        ..GLM
    },
    Preset {
        name: "dashscope",
        hidden: true,
        ..QWEN
    },
    Preset {
        name: "anthropic",
        label: "Anthropic",
        blurb: "first-party Claude API",
        api: Api::Anthropic,
        base_url: "https://api.anthropic.com/v1",
        key_env: Some("ANTHROPIC_API_KEY"),
        key_url: Some("https://console.anthropic.com/settings/keys"),
        key_prefix: Some("sk-ant-"),
        trust: Trust::FirstParty,
        hidden: true,
        ..BASE
    },
    Preset {
        name: "yapayzekalab",
        label: "yapayzekalab",
        blurb: "legacy gateway preset",
        base_url: "https://yapayzekalab.org/v1",
        key_env: Some("YZLAB_KEY"),
        balance: BalanceKind::Yzlab,
        verified: true,
        hidden: true,
        ..BASE
    },
];

pub fn find(name: &str) -> Option<&'static Preset> {
    PRESETS.iter().find(|p| p.name == name)
}

/// Presets offered in the picker, grouped and ordered (OpenRouter first).
pub fn visible() -> Vec<&'static Preset> {
    let mut v: Vec<&'static Preset> = PRESETS.iter().filter(|p| !p.hidden).collect();
    v.sort_by_key(|p| p.group); // stable: table order within a group
    v
}

impl Preset {
    pub fn needs_key(&self) -> bool {
        self.trust != Trust::Local
    }

    /// Host of the base URL, for display.
    pub fn host(&self) -> &'static str {
        self.base_url
            .split("//")
            .nth(1)
            .and_then(|h| h.split('/').next())
            .unwrap_or("")
    }

    /// Base URL used for the setup wizard's live checks. Tests may point a preset at a local
    /// mock server with `MIDDLEMAN_TEST_BASE_URL_<NAME>`; only exact-loopback plain-http
    /// URLs are accepted, so the override can never send a key to another host.
    pub fn check_base_url(&self) -> String {
        let var = format!("MIDDLEMAN_TEST_BASE_URL_{}", self.name.to_ascii_uppercase());
        match std::env::var(var) {
            Ok(u) if crate::config::is_local_url(&u) => u.trim_end_matches('/').to_string(),
            _ => self.base_url.to_string(),
        }
    }
}

/// Default ceiling by trust level (plan §7b).
pub fn default_max_sensitivity(t: Trust) -> Sensitivity {
    match t {
        Trust::Untrusted => Sensitivity::S1,
        Trust::Zdr => Sensitivity::S2,
        Trust::Local | Trust::FirstParty => Sensitivity::S3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_are_sane() {
        for p in PRESETS {
            assert!(!p.base_url.ends_with('/'), "{}", p.name);
            assert!(!p.label.is_empty() && !p.blurb.is_empty(), "{}", p.name);
            if p.trust == Trust::Local {
                assert!(p.base_url.starts_with("http://localhost"), "{}", p.name);
                assert!(p.key_env.is_none(), "{}", p.name);
            } else {
                assert!(p.base_url.starts_with("https://"), "{}", p.name);
                assert!(p.key_env.is_some(), "{}", p.name);
            }
            if let Some(u) = p.key_url {
                assert!(u.starts_with("https://"), "{}", p.name);
            }
        }
        let mut names: Vec<_> = PRESETS.iter().map(|p| p.name).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), PRESETS.len(), "duplicate preset names");
        assert!(find("openrouter").is_some());
        assert!(find("nope").is_none());
    }

    #[test]
    fn picker_is_grouped_openrouter_first_without_aliases_or_legacy() {
        let v = visible();
        assert_eq!(v[0].name, "openrouter");
        assert_eq!(v[0].group, Group::Recommended);
        let names: Vec<_> = v.iter().map(|p| p.name).collect();
        for gone in [
            "yapayzekalab",
            "moonshot",
            "zhipu",
            "dashscope",
            "anthropic",
        ] {
            assert!(!names.contains(&gone), "{gone} should be hidden");
            assert!(find(gone).is_some(), "{gone} must stay loadable");
        }
        for want in [
            "deepseek",
            "kimi",
            "glm",
            "qwen",
            "mistral",
            "groq",
            "together",
            "fireworks",
            "gemini",
            "xai",
            "ollama",
            "lmstudio",
        ] {
            assert!(names.contains(&want), "{want} missing");
        }
        // groups are contiguous and in order
        assert!(v.windows(2).all(|w| w[0].group <= w[1].group));
        assert_eq!(v.last().unwrap().group, Group::Local);
        // aliases share their target's endpoint
        assert_eq!(
            find("moonshot").unwrap().base_url,
            find("kimi").unwrap().base_url
        );
    }

    #[test]
    fn test_override_only_accepts_loopback() {
        let p = find("deepseek").unwrap();
        // the variable name is unique to this test, so parallel tests are unaffected
        std::env::set_var(
            "MIDDLEMAN_TEST_BASE_URL_DEEPSEEK",
            "https://evil.example/v1",
        );
        assert_eq!(p.check_base_url(), p.base_url);
        std::env::set_var("MIDDLEMAN_TEST_BASE_URL_DEEPSEEK", "http://127.0.0.1:9/v1/");
        assert_eq!(p.check_base_url(), "http://127.0.0.1:9/v1");
        std::env::remove_var("MIDDLEMAN_TEST_BASE_URL_DEEPSEEK");
        assert_eq!(p.check_base_url(), p.base_url);
    }
}
