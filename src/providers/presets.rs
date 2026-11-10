//! Built-in provider presets (data only). A preset fills api/base_url/key_env/trust/balance;
//! anything set explicitly in `[providers.<name>]` wins. Adding a vendor = a few lines of TOML.
//!
//! `base_url` includes the API version prefix (OpenAI SDK convention); adapters append
//! `/chat/completions`, `/messages`, `/models`, `/balance`.
//!
//! Verification status: `verified = true` only for yapayzekalab, whose base URL is exercised by
//! `middleman probe` / the live smoke test. The others are taken from vendor documentation as
//! known at authoring time and were NOT re-checked against live docs in this session; confirm
//! with `middleman doctor` before relying on them.

use crate::classify::Sensitivity;
use crate::config::{Api, BalanceKind, Trust};

#[derive(Debug, Clone, Copy)]
pub struct Preset {
    pub name: &'static str,
    pub api: Api,
    pub base_url: &'static str,
    pub key_env: Option<&'static str>,
    pub trust: Trust,
    pub balance: BalanceKind,
    pub verified: bool,
}

const fn p(
    name: &'static str,
    api: Api,
    base_url: &'static str,
    key_env: Option<&'static str>,
    trust: Trust,
    balance: BalanceKind,
    verified: bool,
) -> Preset {
    Preset {
        name,
        api,
        base_url,
        key_env,
        trust,
        balance,
        verified,
    }
}

use Api::{Anthropic, Openai};
use BalanceKind::{None as NoBal, Openrouter as OrBal, Yzlab};
use Trust::{FirstParty, Local, Untrusted};

pub const PRESETS: &[Preset] = &[
    p(
        "yapayzekalab",
        Openai,
        "https://yapayzekalab.org/v1",
        Some("YZLAB_KEY"),
        Untrusted,
        Yzlab,
        true,
    ),
    p(
        "openrouter",
        Openai,
        "https://openrouter.ai/api/v1",
        Some("OPENROUTER_API_KEY"),
        Untrusted,
        OrBal,
        false,
    ),
    p(
        "deepseek",
        Openai,
        "https://api.deepseek.com/v1",
        Some("DEEPSEEK_API_KEY"),
        Untrusted,
        NoBal,
        false,
    ),
    p(
        "moonshot",
        Openai,
        "https://api.moonshot.ai/v1",
        Some("MOONSHOT_API_KEY"),
        Untrusted,
        NoBal,
        false,
    ),
    p(
        "kimi",
        Openai,
        "https://api.moonshot.ai/v1",
        Some("MOONSHOT_API_KEY"),
        Untrusted,
        NoBal,
        false,
    ),
    p(
        "zhipu",
        Openai,
        "https://open.bigmodel.cn/api/paas/v4",
        Some("ZHIPU_API_KEY"),
        Untrusted,
        NoBal,
        false,
    ),
    p(
        "glm",
        Openai,
        "https://open.bigmodel.cn/api/paas/v4",
        Some("ZHIPU_API_KEY"),
        Untrusted,
        NoBal,
        false,
    ),
    p(
        "dashscope",
        Openai,
        "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
        Some("DASHSCOPE_API_KEY"),
        Untrusted,
        NoBal,
        false,
    ),
    p(
        "qwen",
        Openai,
        "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
        Some("DASHSCOPE_API_KEY"),
        Untrusted,
        NoBal,
        false,
    ),
    p(
        "groq",
        Openai,
        "https://api.groq.com/openai/v1",
        Some("GROQ_API_KEY"),
        Untrusted,
        NoBal,
        false,
    ),
    p(
        "together",
        Openai,
        "https://api.together.xyz/v1",
        Some("TOGETHER_API_KEY"),
        Untrusted,
        NoBal,
        false,
    ),
    p(
        "fireworks",
        Openai,
        "https://api.fireworks.ai/inference/v1",
        Some("FIREWORKS_API_KEY"),
        Untrusted,
        NoBal,
        false,
    ),
    p(
        "mistral",
        Openai,
        "https://api.mistral.ai/v1",
        Some("MISTRAL_API_KEY"),
        Untrusted,
        NoBal,
        false,
    ),
    p(
        "gemini",
        Openai,
        "https://generativelanguage.googleapis.com/v1beta/openai",
        Some("GEMINI_API_KEY"),
        Untrusted,
        NoBal,
        false,
    ),
    p(
        "xai",
        Openai,
        "https://api.x.ai/v1",
        Some("XAI_API_KEY"),
        Untrusted,
        NoBal,
        false,
    ),
    p(
        "ollama",
        Openai,
        "http://localhost:11434/v1",
        None,
        Local,
        NoBal,
        false,
    ),
    p(
        "lmstudio",
        Openai,
        "http://localhost:1234/v1",
        None,
        Local,
        NoBal,
        false,
    ),
    p(
        "anthropic",
        Anthropic,
        "https://api.anthropic.com/v1",
        Some("ANTHROPIC_API_KEY"),
        FirstParty,
        NoBal,
        false,
    ),
];

pub fn find(name: &str) -> Option<&'static Preset> {
    PRESETS.iter().find(|p| p.name == name)
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
            if p.trust == Trust::Local {
                assert!(p.base_url.starts_with("http://localhost"), "{}", p.name);
            } else {
                assert!(p.base_url.starts_with("https://"), "{}", p.name);
                assert!(p.key_env.is_some(), "{}", p.name);
            }
        }
        assert!(find("openrouter").is_some());
        assert!(find("nope").is_none());
    }
}
