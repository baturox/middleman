//! The proxy between a mock "Anthropic" (the brain) and a mock worker provider. No live calls.
//! The rule under test: the user's conversation always goes to Claude untouched; only the
//! subagent and background requests (marker models) go to the worker provider.

use std::time::Duration;

use middleman::config::{Config, Secret};
use middleman::ledger::Ledger;
use middleman::proxy::{self, ProxyCfg, MARK_FAST, MARK_SUB};
use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN: &str = "tok123";
const SSE: &str = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":100,\"output_tokens\":1}}}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":42}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";

struct H {
    anthropic: MockServer,
    worker: MockServer,
    base: String,
    state: std::path::PathBuf,
    _dir: tempfile::TempDir,
    client: reqwest::Client,
}

async fn harness() -> H {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let anthropic = MockServer::start().await;
    let worker = MockServer::start().await;
    let cfg = Config::from_toml(&format!(
        "state_dir = \"{d}/state\"\ncache_dir = \"{d}/cache\"\n[paths]\nroots = [\"{d}\"]\n",
        d = dir.path().display()
    ))
    .unwrap();
    let mut pc = ProxyCfg::from_config(
        &cfg,
        &middleman::launch::UPSTREAMS[0],
        Secret::new("sk-or-v1-secretkey"),
        TOKEN.into(),
        "z-ai/glm-5.3".into(),
        "deepseek/fast".into(),
        "p-test".into(),
    );
    pc.anthropic_url = anthropic.uri();
    pc.cheap_url = worker.uri();
    pc.cheap_prices = Some((1.0, 2.0));
    let (l, port) = proxy::bind().await.unwrap();
    tokio::spawn(proxy::serve(pc, l));
    H {
        anthropic,
        worker,
        base: format!("http://127.0.0.1:{port}"),
        state,
        _dir: dir,
        client: reqwest::Client::new(),
    }
}

fn req(model: &str, text: &str) -> Value {
    json!({"model": model, "max_tokens": 100, "stream": true,
        "system": "You are Claude Code", "messages": [{"role": "user", "content": text}]})
}

impl H {
    async fn post(&self, body: &Value) -> reqwest::Response {
        self.client
            .post(format!("{}/{TOKEN}/v1/messages", self.base))
            .header("authorization", "Bearer oauth-secret-token")
            .header(
                "anthropic-beta",
                "oauth-2025-04-20,fine-grained-tool-streaming-2025-05-14",
            )
            .header("anthropic-version", "2023-06-01")
            .json(body)
            .send()
            .await
            .unwrap()
    }
    async fn ok_both(&self) {
        for s in [&self.anthropic, &self.worker] {
            Mock::given(method("POST"))
                .and(path("/v1/messages"))
                .respond_with(ResponseTemplate::new(200).set_body_raw(SSE, "text/event-stream"))
                .mount(s)
                .await;
        }
    }
    async fn bodies(s: &MockServer) -> Vec<Value> {
        s.received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| serde_json::from_slice(&r.body).unwrap())
            .collect()
    }
    async fn ledger(&self, n: usize) -> Vec<middleman::ledger::LedgerEntry> {
        let mut entries = vec![];
        for _ in 0..40 {
            entries = Ledger::new(&self.state).unwrap().entries().unwrap();
            if entries.len() >= n {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        entries
    }
}

#[tokio::test]
async fn the_users_conversation_always_goes_to_claude_untouched() {
    let h = harness().await;
    h.ok_both().await;
    // easy or hard, with or without a prefix: the brain is always Claude
    for text in [
        "write tests for src/date.py",
        "debug why the worker hangs after a few minutes",
        "!cheap rename this variable",
    ] {
        let r = h.post(&req("claude-opus-5-5", text)).await;
        assert_eq!(r.status(), 200);
        assert_eq!(r.text().await.unwrap(), SSE);
    }
    let seen = h.anthropic.received_requests().await.unwrap();
    assert_eq!(seen.len(), 3);
    assert_eq!(
        seen[0].headers["authorization"],
        "Bearer oauth-secret-token"
    );
    assert_eq!(
        seen[0].headers["anthropic-beta"],
        "oauth-2025-04-20,fine-grained-tool-streaming-2025-05-14"
    );
    let b = H::bodies(&h.anthropic).await;
    assert_eq!(b[0]["model"], "claude-opus-5-5");
    assert_eq!(
        b[2]["messages"][0]["content"],
        "!cheap rename this variable"
    );
    assert!(h.worker.received_requests().await.unwrap().is_empty());
    let e = &h.ledger(3).await[0];
    assert_eq!(
        (e.chain_step.as_str(), e.provider.as_str()),
        ("claude", "anthropic")
    );
    assert_eq!(e.cost_usd, 0.0);
}

#[tokio::test]
async fn agents_and_background_jobs_go_to_the_worker_with_its_own_key() {
    let h = harness().await;
    h.ok_both().await;
    let r = h.post(&req(MARK_SUB, "implement the parser")).await;
    assert_eq!(r.text().await.unwrap(), SSE);
    h.post(&req(MARK_FAST, "name this conversation"))
        .await
        .text()
        .await
        .unwrap();
    let seen = &h.worker.received_requests().await.unwrap()[0];
    assert_eq!(seen.headers["authorization"], "Bearer sk-or-v1-secretkey");
    assert!(seen.headers.get("x-api-key").is_none());
    assert!(!format!("{:?}", seen.headers).contains("oauth-secret-token"));
    let b = H::bodies(&h.worker).await;
    assert_eq!(b[0]["model"], "z-ai/glm-5.3");
    assert_eq!(b[1]["model"], "deepseek/fast");
    assert!(h.anthropic.received_requests().await.unwrap().is_empty());
    let entries = h.ledger(2).await;
    let e = &entries[0];
    assert_eq!(e.via.as_deref(), Some("proxy"));
    assert_eq!(e.mode, "workers");
    assert_eq!(e.chain_step, "worker");
    assert_eq!((e.input_tokens, e.output_tokens), (Some(100), Some(42)));
    assert!((e.cost_usd - (100.0 + 84.0) / 1e6).abs() < 1e-12);
}

#[tokio::test]
async fn a_failed_worker_request_is_reported_and_never_moved_to_claude() {
    let h = harness().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(500).set_body_string("upstream down sk-or-v1-secretkey"),
        )
        .mount(&h.worker)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(SSE, "text/event-stream"))
        .mount(&h.anthropic)
        .await;
    for _ in 0..2 {
        assert_eq!(h.post(&req(MARK_SUB, "do it")).await.status(), 500);
    }
    assert!(h.anthropic.received_requests().await.unwrap().is_empty());
    let log = std::fs::read_to_string(h.state.join("proxy-errors.log")).unwrap();
    assert!(log.contains("HTTP 500") && log.contains("[key]") && !log.contains("secretkey"));
}

#[tokio::test]
async fn token_is_required() {
    let h = harness().await;
    h.ok_both().await;
    for url in [
        format!("{}/v1/messages", h.base),
        format!("{}/wrong/v1/messages", h.base),
    ] {
        let r = h
            .client
            .post(url)
            .json(&req("claude-opus-5-5", "hi"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403);
    }
    assert!(h.anthropic.received_requests().await.unwrap().is_empty());
}
