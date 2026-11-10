#![allow(dead_code)]

use std::path::{Path, PathBuf};

use middleman::config::Config;
use serde_json::{json, Value};
use tempfile::TempDir;
use wiremock::{Request, Respond, ResponseTemplate};

pub const FAKE_KEY: &str = "mm-test-key-0123456789abcdef";

pub fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/acme")
}

pub struct Env {
    pub dir: TempDir,
    pub cfg_path: PathBuf,
}

/// Config with fixtures as root, fixture dictionary, temp state/cache, and a provider `mock`
/// at `base_url` (key in a temp key_file). `extra` is appended verbatim.
pub fn env(base_url: &str, api: &str, max_s: &str, extra: &str) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let key_file = dir.path().join("keys.env");
    let out_root = dir.path().join("out");
    std::fs::create_dir_all(&out_root).unwrap();
    let out_root = std::fs::canonicalize(out_root).unwrap();
    std::fs::write(&key_file, format!("MM_TEST_KEY_NOT_IN_ENV={FAKE_KEY}\n")).unwrap();
    let text = format!(
        r#"
state_dir = "{state}"
cache_dir = "{cache}"

[paths]
roots = ["{root}", "{out}"]

[economics]
enforce_break_even = false

[redact]
dictionary_file = "{dict}"

[budget]
per_call_usd = 0.05
daily_usd = 1.0
weekly_usd = 4.0
reserve_usd = 1.0

[providers.mock]
api = "{api}"
base_url = "{base_url}"
key_env = "MM_TEST_KEY_NOT_IN_ENV"
key_file = "{key_file}"
balance = "yzlab"
max_sensitivity = "{max_s}"
task_kinds = ["write_tests", "docstring", "snippet", "summarize", "boilerplate"]
{extra}
"#,
        state = dir.path().join("state").display(),
        cache = dir.path().join("cache").display(),
        root = fixtures().display(),
        out = out_root.display(),
        dict = fixtures().join("dictionary.txt").display(),
        key_file = key_file.display(),
    );
    let cfg_path = dir.path().join("config.toml");
    std::fs::write(&cfg_path, text).unwrap();
    Env { dir, cfg_path }
}

impl Env {
    pub fn out_root(&self) -> PathBuf {
        std::fs::canonicalize(self.dir.path().join("out")).unwrap()
    }
    pub fn config(&self) -> Config {
        Config::load(&self.cfg_path).unwrap()
    }
}

pub fn models_body(models: &[(&str, f64, f64)]) -> Value {
    json!({
        "data": models.iter().map(|(id, i, o)| json!({
            "id": id,
            "modality": "text->text",
            "context_length": 64000,
            "pricing": {"input_per_1m_usd": i, "output_per_1m_usd": o}
        })).collect::<Vec<_>>()
    })
}

/// Echo the user message back inside a code block, in the request's wire format.
pub struct Echo;

impl Respond for Echo {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&req.body).unwrap_or(json!({}));
        let user = body["messages"]
            .as_array()
            .and_then(|m| m.iter().rev().find(|x| x["role"] == "user"))
            .and_then(|m| m["content"].as_str())
            .unwrap_or("")
            .to_string();
        let text = format!("```\n{user}\n```");
        if req.url.path().ends_with("/messages") {
            ResponseTemplate::new(200).set_body_json(json!({
                "id": "msg_1", "type": "message", "model": body["model"],
                "content": [{"type": "text", "text": text}],
                "usage": {"input_tokens": 100, "output_tokens": 50},
                "stop_reason": "end_turn"
            }))
        } else {
            ResponseTemplate::new(200).set_body_json(json!({
                "id": "c1", "model": body["model"],
                "choices": [{"message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 50}
            }))
        }
    }
}
