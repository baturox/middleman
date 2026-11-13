//! The smart-mode proxy between a mock "Anthropic" and a mock "OpenRouter". No live calls.

use std::time::Duration;

use middleman::config::{Config, Secret};
use middleman::ledger::Ledger;
use middleman::modes::{self, Mode};
use middleman::proxy::{self, ProxyCfg};
use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN: &str = "tok123";
const HARD: &str = "debug why the worker hangs after a few minutes";
const EASY: &str = "write tests for src/date.py";
const SSE: &str = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":100,\"output_tokens\":1}}}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":42}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";

struct H {
    anthropic: MockServer,
    openrouter: MockServer,
    base: String,
    state: std::path::PathBuf,
    _dir: tempfile::TempDir,
    client: reqwest::Client,
}

async fn harness(mode: Mode) -> H {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let anthropic = MockServer::start().await;
    let openrouter = MockServer::start().await;
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
        mode,
        "z-ai/glm-5.3".into(),
        "deepseek/fast".into(),
        "p-test".into(),
    );
    pc.anthropic_url = anthropic.uri();
    pc.cheap_url = openrouter.uri();
    pc.cheap_prices = Some((1.0, 2.0));
    let (l, port) = proxy::bind().await.unwrap();
    tokio::spawn(proxy::serve(pc, l));
    H {
        anthropic,
        openrouter,
        base: format!("http://127.0.0.1:{port}"),
        state,
        _dir: dir,
        client: reqwest::Client::new(),
    }
}

fn first(text: &str) -> Value {
    json!({"role": "user", "content": text})
}

fn req(msgs: Vec<Value>) -> Value {
    json!({"model": "claude-sonnet-4-5", "max_tokens": 100, "stream": true,
        "system": "You are Claude Code", "messages": msgs})
}

fn tool_loop(text: &str) -> Value {
    req(vec![
        first(text),
        json!({"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Read","input":{}}]}),
        json!({"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"ok"}]}),
    ])
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
        for s in [&self.anthropic, &self.openrouter] {
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
}

#[tokio::test]
async fn anthropic_gets_client_headers_and_sse_streams_through() {
    let h = harness(Mode::Smart).await;
    h.ok_both().await;
    let r = h.post(&req(vec![first(HARD)])).await;
    assert_eq!(r.status(), 200);
    assert!(r.headers()["content-type"]
        .to_str()
        .unwrap()
        .contains("event-stream"));
    assert_eq!(r.text().await.unwrap(), SSE);
    let seen = &h.anthropic.received_requests().await.unwrap()[0];
    assert_eq!(seen.headers["authorization"], "Bearer oauth-secret-token");
    assert_eq!(
        seen.headers["anthropic-beta"],
        "oauth-2025-04-20,fine-grained-tool-streaming-2025-05-14"
    );
    assert_eq!(seen.headers["anthropic-version"], "2023-06-01");
    assert_eq!(
        serde_json::from_slice::<Value>(&seen.body).unwrap()["model"],
        "claude-sonnet-4-5"
    );
    assert!(h.openrouter.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn openrouter_gets_own_auth_and_cheap_model_and_ledger_line() {
    let h = harness(Mode::Smart).await;
    h.ok_both().await;
    let r = h.post(&req(vec![first(EASY)])).await;
    assert_eq!(r.text().await.unwrap(), SSE);
    let seen = &h.openrouter.received_requests().await.unwrap()[0];
    assert_eq!(seen.headers["authorization"], "Bearer sk-or-v1-secretkey");
    assert!(seen.headers.get("x-api-key").is_none());
    assert!(!format!("{:?}", seen.headers).contains("oauth-secret-token"));
    assert_eq!(
        serde_json::from_slice::<Value>(&seen.body).unwrap()["model"],
        "z-ai/glm-5.3"
    );
    assert!(h.anthropic.received_requests().await.unwrap().is_empty());
    // ledger line (written when the stream ends)
    let mut entries = vec![];
    for _ in 0..40 {
        entries = Ledger::new(&h.state).unwrap().entries().unwrap();
        if !entries.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let e = &entries[0];
    assert_eq!(e.via.as_deref(), Some("proxy"));
    assert_eq!(e.mode, "smart");
    assert_eq!(e.chain_step, "cheap");
    assert_eq!((e.input_tokens, e.output_tokens), (Some(100), Some(42)));
    assert!((e.cost_usd - (100.0 + 84.0) / 1e6).abs() < 1e-12);
    let rn = modes::read_route(&h.state).unwrap();
    assert_eq!((rn.route.as_str(), rn.mode.as_str()), ("cheap", "smart"));
}

#[tokio::test]
async fn turn_is_sticky_across_tool_loop() {
    let h = harness(Mode::Smart).await;
    h.ok_both().await;
    h.post(&req(vec![first(EASY)])).await.text().await.unwrap();
    h.post(&tool_loop(EASY)).await.text().await.unwrap();
    assert_eq!(h.openrouter.received_requests().await.unwrap().len(), 2);
    assert!(h.anthropic.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn rate_limited_claude_retries_on_cheap() {
    let h = harness(Mode::Smart).await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(429).set_body_json(json!({"type":"error"})))
        .mount(&h.anthropic)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(SSE, "text/event-stream"))
        .mount(&h.openrouter)
        .await;
    let r = h.post(&req(vec![first(HARD)])).await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.text().await.unwrap(), SSE);
    // the rest of the turn stays cheap
    h.post(&tool_loop(HARD)).await.text().await.unwrap();
    assert_eq!(h.anthropic.received_requests().await.unwrap().len(), 1);
    assert_eq!(h.openrouter.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn two_cheap_failures_switch_the_turn_to_claude() {
    let h = harness(Mode::Smart).await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&h.openrouter)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(SSE, "text/event-stream"))
        .mount(&h.anthropic)
        .await;
    assert_eq!(h.post(&req(vec![first(EASY)])).await.status(), 500);
    let r = h.post(&tool_loop(EASY)).await;
    assert_eq!(r.status(), 200);
    assert_eq!(h.anthropic.received_requests().await.unwrap().len(), 1);
    // and it stays on Claude for the rest of the turn
    h.post(&tool_loop(EASY)).await.text().await.unwrap();
    assert_eq!(h.anthropic.received_requests().await.unwrap().len(), 2);
    assert_eq!(h.openrouter.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn prefix_forces_route_and_is_stripped() {
    let h = harness(Mode::Smart).await;
    h.ok_both().await;
    h.post(&req(vec![first(&format!("!cheap {HARD}"))]))
        .await
        .text()
        .await
        .unwrap();
    let b = &H::bodies(&h.openrouter).await[0];
    assert_eq!(b["messages"][0]["content"], HARD);
    h.post(&req(vec![first(&format!("!claude {EASY}"))]))
        .await
        .text()
        .await
        .unwrap();
    assert_eq!(
        H::bodies(&h.anthropic).await[0]["messages"][0]["content"],
        EASY
    );
}

#[tokio::test]
async fn token_is_required() {
    let h = harness(Mode::Smart).await;
    h.ok_both().await;
    for url in [
        format!("{}/v1/messages", h.base),
        format!("{}/wrong/v1/messages", h.base),
    ] {
        let r = h
            .client
            .post(url)
            .json(&req(vec![first(HARD)]))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403);
    }
    assert!(h.anthropic.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn near_limit_goes_all_cheap_and_background_models_are_mapped() {
    let h = harness(Mode::Smart).await;
    h.ok_both().await;
    modes::write_usage(&h.state, 93.0, middleman::ledger::now_unix()).unwrap();
    h.post(&req(vec![first(HARD)])).await.text().await.unwrap();
    assert_eq!(h.openrouter.received_requests().await.unwrap().len(), 1);
    let mut bg = req(vec![first("name this conversation please")]);
    bg["model"] = json!("mm-cheap-fast");
    h.post(&bg).await.text().await.unwrap();
    assert_eq!(H::bodies(&h.openrouter).await[1]["model"], "deepseek/fast");
    assert!(h.anthropic.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn router_model_asked_only_with_sanitized_text() {
    let h = harness(Mode::Smart).await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"content":[{"type":"text","text":"EASY"}],"usage":{"input_tokens":1,"output_tokens":1}}),
        ))
        .mount(&h.openrouter)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"content":[]})))
        .mount(&h.anthropic)
        .await;
    // unclear + contains an email: the sanitizer blocks the router call, so it stays on Claude
    let secret = "update the handler to email bob@acme-corp.com when it fails";
    h.post(&req(vec![first(secret)]))
        .await
        .text()
        .await
        .unwrap();
    assert!(h.openrouter.received_requests().await.unwrap().is_empty());
    assert_eq!(h.anthropic.received_requests().await.unwrap().len(), 1);
    // unclear and clean: the router says EASY, so the turn goes cheap (router call + real call)
    let clean = "update the function to handle empty input gracefully";
    h.post(&req(vec![first(clean)])).await.text().await.unwrap();
    let ob = H::bodies(&h.openrouter).await;
    assert_eq!(ob.len(), 2);
    assert_eq!(ob[0]["max_tokens"], 5);
    assert_eq!(ob[1]["model"], "z-ai/glm-5.3");
}
