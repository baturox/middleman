//! `middleman bench` orchestration with a fake `claude` on PATH (no real Claude, no network):
//! the fake edits the sample project, makes one brain request and one agent request through the
//! local proxy (both upstreams are a mock; the worker bills a fixed cost), and prints Claude
//! Code style JSON.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

const FAKE: &str = r#"#!/bin/sh
cat > tests/test_slug.py <<'PY'
import unittest
from textkit.slug import slugify, is_slug

class T(unittest.TestCase):
    def test_a(self): self.assertEqual(slugify("Hello World"), "hello-world")
    def test_b(self): self.assertEqual(slugify("  x  "), "x")
    def test_c(self): self.assertEqual(slugify("a!!b"), "a-b")
    def test_d(self): self.assertTrue(is_slug("a-b"))
    def test_e(self): self.assertFalse(is_slug("A b"))
PY
case "$ANTHROPIC_BASE_URL" in
  http://127.0.0.1*)
    curl -s -X POST "$ANTHROPIC_BASE_URL/v1/messages" -H 'content-type: application/json' \
      -d '{"model":"claude-opus-5-5","max_tokens":9,"messages":[{"role":"user","content":"plan"}]}' >/dev/null
    curl -s -X POST "$ANTHROPIC_BASE_URL/v1/messages" -H 'content-type: application/json' \
      -d '{"model":"'"$CLAUDE_CODE_SUBAGENT_MODEL"'","max_tokens":9,"messages":[{"role":"user","content":"write tests for slug.py"}]}' >/dev/null ;;
esac
echo '{"total_cost_usd":0.5,"num_turns":3,"result":"done"}'
"#;

struct Env {
    _d: tempfile::TempDir,
    cfg: std::path::PathBuf,
    bin: std::path::PathBuf,
    state: std::path::PathBuf,
}

fn env() -> Env {
    let d = tempfile::tempdir().unwrap();
    let bin = d.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let fake = bin.join("claude");
    std::fs::write(&fake, FAKE).unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    let cfg = d.path().join("c.toml");
    std::fs::write(
        &cfg,
        format!(
            "state_dir = \"{0}/state\"\ncache_dir = \"{0}/cache\"\n[paths]\nroots = [\"{0}\"]\n[providers.openrouter]\npreset = \"openrouter\"\n",
            d.path().display()
        ),
    )
    .unwrap();
    let state = d.path().join("state");
    Env {
        _d: d,
        cfg,
        bin,
        state,
    }
}

fn bench(e: &Env, args: &[&str], or_url: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_middleman"))
        .arg("--config")
        .arg(&e.cfg)
        .arg("bench")
        .args(args)
        .env(
            "PATH",
            format!("{}:{}", e.bin.display(), std::env::var("PATH").unwrap()),
        )
        .env("OPENROUTER_API_KEY", "sk-or-v1-fake0000")
        .env("MM_PROXY_OPENROUTER_URL", or_url)
        .env("MM_PROXY_ANTHROPIC_URL", or_url)
        .env("MIDDLEMAN_KEYSTORE", "file")
        .output()
        .unwrap()
}

#[test]
fn bench_runs_the_brain_and_workers_and_summarizes() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mock = rt.block_on(async {
        let m = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(
                {"content": [], "usage": {"input_tokens": 10, "output_tokens": 5, "cost": 0.01}}
            )))
            .mount(&m)
            .await;
        m
    });
    let e = env();
    let o = bench(&e, &["--tasks", "1", "--yes"], &mock.uri());
    let out = String::from_utf8_lossy(&o.stdout);
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(o.status.success(), "{out}\n{err}");
    assert!(out.contains("middleman") && out.contains("1/1"), "{out}");
    // one brain and one agent request, equal tokens: half of Claude's $0.50, plus the
    // worker's billed $0.01
    assert!(
        out.contains("middleman passed 1/1 for $0.26"),
        "{out}\n{err}"
    );
    assert!(err.contains("(1 Claude / 1 agent requests)"), "{err}");
    let saved: Vec<_> = std::fs::read_dir(&e.state)
        .unwrap()
        .filter_map(|f| f.ok())
        .filter(|f| f.file_name().to_string_lossy().starts_with("bench-"))
        .collect();
    assert_eq!(saved.len(), 1);
    // bench ledger lines are excluded from the user's savings
    let l = std::fs::read_to_string(e.state.join("ledger.jsonl")).unwrap();
    assert!(l.contains("\"purpose\":\"bench\""), "{l}");
}

#[test]
fn cost_guard_refuses_without_yes_when_not_interactive() {
    let e = env();
    let o = bench(&e, &["--tasks", "2"], "http://127.0.0.1:9");
    assert!(!o.status.success());
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("worst case: up to 50 Claude requests"),
        "{err}"
    );
    assert!(err.contains("--yes"), "{err}");
    assert!(!e.state.join("bench-0.json").exists());
}
