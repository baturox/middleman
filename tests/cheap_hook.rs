//! The `cheap:` direct path end to end: the real hook binary reads the UserPromptSubmit JSON
//! on stdin, runs the delegation against wiremock, blocks the prompt, writes the file and
//! logs a ledger line with zero Claude-side overhead. Other prompts are unaffected.

mod common;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use common::{models_body, FAKE_KEY};
use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Respond, ResponseTemplate};

const ANSWER: &str = "```python\nfrom src.f1 import parse_date\n\n\ndef test_parse_date():\n    assert parse_date(\"2024-01-02\").day == 2\n\n\ndef test_parse_date_rejects_garbage():\n    try:\n        parse_date(\"nope\")\n    except ValueError:\n        pass\n```";

/// Answers with a small test file that imports the module by its pseudonymized name.
struct Tests;

impl Respond for Tests {
    fn respond(&self, req: &wiremock::Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&req.body).unwrap();
        ResponseTemplate::new(200).set_body_json(json!({
            "id": "c1", "model": body["model"],
            "choices": [{"message": {"role": "assistant", "content": ANSWER}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 120, "completion_tokens": 900}
        }))
    }
}

struct Env {
    _d: tempfile::TempDir,
    home: PathBuf,
    root: PathBuf,
    cfg: PathBuf,
    state: PathBuf,
}

async fn setup() -> (MockServer, Env) {
    let s = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(models_body(&[(
            "qwen-mini",
            0.1,
            0.2,
        )])))
        .mount(&s)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(Tests)
        .mount(&s)
        .await;
    let d = tempfile::tempdir().unwrap();
    let home = d.path().canonicalize().unwrap();
    let root = home.join("proj");
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("tests")).unwrap();
    std::fs::write(
        root.join("src/date.py"),
        "from datetime import date\n\n\ndef parse_date(s):\n    y, m, d = s.split(\"-\")\n    return date(int(y), int(m), int(d))\n",
    )
    .unwrap();
    let key_file = home.join("keys.env");
    std::fs::write(&key_file, format!("MM_TEST_KEY_NOT_IN_ENV={FAKE_KEY}\n")).unwrap();
    let state = home.join("state");
    let cfg = home.join("config.toml");
    std::fs::write(
        &cfg,
        format!(
            r#"
state_dir = "{state}"
cache_dir = "{cache}"

[paths]
roots = ["{root}"]

[routing]
mode = "confirm"

[providers.mock]
api = "openai"
base_url = "{base}/v1"
key_env = "MM_TEST_KEY_NOT_IN_ENV"
key_file = "{key}"
max_sensitivity = "S2"
"#,
            state = state.display(),
            cache = home.join("cache").display(),
            root = root.display(),
            base = s.uri(),
            key = key_file.display(),
        ),
    )
    .unwrap();
    (
        s,
        Env {
            _d: d,
            home,
            root,
            cfg,
            state,
        },
    )
}

fn hook(e: &Env, prompt: &str) -> (String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_middleman"))
        .args(["route", "--hook", "--config"])
        .arg(&e.cfg)
        .env("HOME", &e.home)
        .env("NO_COLOR", "1")
        .env_remove("CLAUDE_CODE_SESSION_ID")
        .current_dir(&e.root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let input = json!({
        "session_id": "sess-1",
        "hook_event_name": "UserPromptSubmit",
        "cwd": e.root,
        "prompt": prompt,
    });
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    (
        String::from_utf8_lossy(&out.stdout).trim().to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn ledger(state: &Path) -> Vec<Value> {
    std::fs::read_to_string(state.join("ledger.jsonl"))
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

async fn posts(s: &MockServer) -> Vec<wiremock::Request> {
    s.received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.method.as_str() == "POST")
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn cheap_prompt_runs_in_the_hook_and_never_reaches_claude() {
    let (s, e) = setup().await;
    let (stdout, stderr) = hook(&e, "cheap: write tests for src/date.py");
    let v: Value = serde_json::from_str(&stdout).unwrap_or_else(|_| panic!("{stdout} {stderr}"));
    assert_eq!(v["decision"], "block", "{v}");
    let reason = v["reason"].as_str().unwrap();
    println!("--- hook transcript ---\n{reason}\n---");
    assert!(reason.contains("Claude spent 0 tokens"), "{reason}");
    assert!(reason.contains("wrote    tests/test_date.py"), "{reason}");
    assert!(
        reason.contains("ask Claude: \"review tests/test_date.py\""),
        "{reason}"
    );
    assert!(
        v.get("hookSpecificOutput").is_none(),
        "nothing is added to Claude's context"
    );

    // one provider call, pseudonymized; confirm mode did not stop the user's own command
    let sent = posts(&s).await;
    assert_eq!(sent.len(), 1);
    let body = String::from_utf8_lossy(&sent[0].body).to_string();
    assert!(
        body.contains("--- FILE src/f1.py (from line 1) ---"),
        "{body}"
    );
    assert!(!body.contains("date.py") && !body.contains(e.root.to_str().unwrap()));

    // the file, with the module name restored
    let written = std::fs::read_to_string(e.root.join("tests/test_date.py")).unwrap();
    assert!(
        written.starts_with("from src.date import parse_date"),
        "{written}"
    );

    // the ledger: closing line via the hook, zero Claude overhead, positive net saving
    let lines = ledger(&e.state);
    let close = lines
        .iter()
        .find(|l| l["closing"] == true)
        .expect("closing line");
    assert_eq!(close["via"], "hook");
    assert_eq!(close["status"], "ok");
    assert_eq!(close["claude_overhead_usd"].as_f64().unwrap(), 0.0);
    assert_eq!(close["call_tokens"].as_u64().unwrap(), 0);
    assert_eq!(close["context_tokens"].as_u64().unwrap(), 0);
    let net = close["net_savings_usd"].as_f64().unwrap();
    let equiv = close["claude_equiv_usd"].as_f64().unwrap();
    let cost = close["cost_usd"].as_f64().unwrap();
    assert!(net > 0.0 && (net - (equiv - cost)).abs() < 1e-9, "{close}");
    assert_eq!(close["session_id"], "sess-1");
}

#[tokio::test(flavor = "multi_thread")]
async fn ambiguous_or_sensitive_cheap_prompts_are_blocked_with_help_and_nothing_is_sent() {
    let (s, e) = setup().await;
    for (p, want) in [
        ("cheap: make it better", "syntax   cheap: <task>"),
        ("cheap: write tests for src/nope.py", "no file found"),
        (
            "cheap: write tests for the login flow in src/date.py",
            "looks sensitive (login)",
        ),
    ] {
        let (stdout, _) = hook(&e, p);
        let v: Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(v["decision"], "block", "{p}");
        let r = v["reason"].as_str().unwrap();
        assert!(r.contains(want), "{p}: {r}");
    }
    assert!(posts(&s).await.is_empty());
    assert!(ledger(&e.state).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn other_prompts_are_unaffected() {
    let (s, e) = setup().await;
    for p in [
        "write the whole test suite for src/date.py",
        "fix the race in the scheduler",
        "what is cheap: about?",
    ] {
        let (stdout, _) = hook(&e, p);
        if stdout.is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(&stdout).unwrap();
        assert!(v.get("decision").is_none(), "{p}: {v}");
    }
    assert!(posts(&s).await.is_empty());
    assert!(!e.root.join("tests/test_date.py").exists());
}
