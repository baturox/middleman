//! `middleman proxy`: the local Anthropic-compatible proxy behind `middleman claude`.
//!
//! Claude is the brain, middleman supplies the workers. Claude Code talks to
//! `http://127.0.0.1:PORT/<token>` (the launcher sets ANTHROPIC_BASE_URL and gives its subagent
//! and background roles marker model names). Requests with a marker model go to the worker
//! provider (auth replaced with its key, `model` set to the worker model); everything else, the
//! user's own conversation, goes to Anthropic untouched (the client's auth headers pass through
//! and are never logged or stored). Response bodies are streamed back as they arrive; a copy is
//! kept only to read the usage for the ledger. Bound to 127.0.0.1; a request without the
//! per-launch token gets 403.

use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::{combinators::BoxBody, BodyExt, Full, Limited, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};

use crate::config::{Config, Secret};
use crate::economics::ClaudePrices;
use crate::ledger::{now_rfc3339, now_unix, Ledger, LedgerEntry};

pub const ANTHROPIC_URL: &str = "https://api.anthropic.com";
/// Model names the launcher gives Claude Code for its background and subagent roles: the
/// requests that go to the worker provider.
pub const MARK_FAST: &str = "mm-cheap-fast";
pub const MARK_SUB: &str = "mm-cheap-sub";
const MAX_REQUEST: usize = 64 << 20;
const MAX_CAPTURE: usize = 16 << 20;

type Body = BoxBody<Bytes, std::io::Error>;

pub struct ProxyCfg {
    pub state_dir: PathBuf,
    pub token: String,
    pub anthropic_url: String,
    pub cheap_url: String,
    pub cheap_key: Secret,
    /// Ledger name of the cheap upstream (`openrouter`, `miav`).
    pub cheap_provider: String,
    /// Strip Claude-only features before a cheap request (false for Claude-backed upstreams).
    pub adapt: bool,
    /// Worker model for subagents.
    pub main_model: String,
    /// Worker model for background work (titles, summaries).
    pub fast_model: String,
    pub project: String,
    /// `bench` marks ledger lines so they stay out of the savings totals.
    pub purpose: Option<String>,
    pub run_id: Option<String>,
    pub claude_prices: ClaudePrices,
    /// (input, output) USD per 1M for the cheap model, used when the response has no cost.
    pub cheap_prices: Option<(f64, f64)>,
}

impl ProxyCfg {
    #[allow(clippy::too_many_arguments)]
    pub fn from_config(
        cfg: &Config,
        up: &crate::launch::Upstream,
        key: Secret,
        token: String,
        main_model: String,
        fast_model: String,
        project: String,
    ) -> ProxyCfg {
        let cat = crate::catalog::Catalog::load(cfg);
        let cheap_prices = crate::catalog::Catalog::lookup(cfg, cat.as_ref(), up.name, &main_model)
            .and_then(|p| p.prices)
            .map(|p| (p.in_per_1m, p.out_per_1m));
        ProxyCfg {
            state_dir: cfg.state_dir(),
            token,
            anthropic_url: ANTHROPIC_URL.into(),
            cheap_url: up.base_url.into(),
            cheap_key: key,
            cheap_provider: up.name.into(),
            adapt: up.adapt,
            main_model,
            fast_model,
            project,
            purpose: None,
            run_id: None,
            claude_prices: cfg.economics.prices().unwrap_or(ClaudePrices::ZERO),
            cheap_prices,
        }
    }
}

/// Upstream URLs must be HTTPS (loopback http is allowed for tests).
pub fn check_upstream(url: &str) -> Result<()> {
    let u = reqwest::Url::parse(url).with_context(|| format!("invalid URL {url}"))?;
    let loopback = u.scheme() == "http" && matches!(u.host_str(), Some("127.0.0.1" | "localhost"));
    if u.scheme() != "https" && !loopback {
        bail!("refusing non-HTTPS upstream {url}");
    }
    Ok(())
}

struct St {
    cfg: ProxyCfg,
    client: reqwest::Client,
}

pub async fn bind() -> Result<(tokio::net::TcpListener, u16)> {
    let l = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = l.local_addr()?.port();
    Ok((l, port))
}

pub async fn serve(cfg: ProxyCfg, listener: tokio::net::TcpListener) -> Result<()> {
    check_upstream(&cfg.anthropic_url)?;
    check_upstream(&cfg.cheap_url)?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .build()?;
    let st = Arc::new(St { cfg, client });
    loop {
        let (sock, _) = listener.accept().await?;
        let st = st.clone();
        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |req| {
                let st = st.clone();
                async move { Ok::<_, Infallible>(handle(st, req).await) }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(sock), svc)
                .await;
        });
    }
}

fn full(status: u16, msg: &str) -> Response<Body> {
    let b = json!({"type": "error", "error": {"type": "proxy_error", "message": msg}}).to_string();
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(b)).map_err(|e| match e {}).boxed())
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()).map_err(|e| match e {}).boxed()))
}

async fn handle(st: Arc<St>, req: Request<Incoming>) -> Response<Body> {
    match handle_inner(st, req).await {
        Ok(r) => r,
        Err(e) => full(502, &format!("middleman proxy: {e}")),
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Target {
    Anthropic,
    Worker,
}

struct Ctx {
    worker: bool,
    model: String,
    started: std::time::Instant,
}

const HOP: &[&str] = &[
    "host",
    "content-length",
    "connection",
    "transfer-encoding",
    "keep-alive",
    "upgrade",
    "proxy-connection",
    "te",
    "trailer",
    "accept-encoding",
];

async fn send(
    st: &St,
    target: Target,
    parts: &hyper::http::request::Parts,
    path_q: &str,
    body: Bytes,
) -> Result<reqwest::Response> {
    let base = match target {
        Target::Anthropic => &st.cfg.anthropic_url,
        Target::Worker => &st.cfg.cheap_url,
    };
    let mut rb = st
        .client
        .request(
            parts.method.clone(),
            format!("{}{}", base.trim_end_matches('/'), path_q),
        )
        .header("accept-encoding", "identity");
    for (k, v) in &parts.headers {
        let n = k.as_str();
        if HOP.contains(&n) {
            continue;
        }
        if target == Target::Worker && matches!(n, "authorization" | "x-api-key") {
            continue;
        }
        rb = rb.header(k, v);
    }
    if target == Target::Worker {
        let mut v = reqwest::header::HeaderValue::from_str(&format!(
            "Bearer {}",
            st.cfg.cheap_key.expose()
        ))?;
        v.set_sensitive(true);
        rb = rb.header("authorization", v);
    }
    Ok(rb.body(body).send().await.map_err(|e| e.without_url())?)
}

async fn handle_inner(st: Arc<St>, req: Request<Incoming>) -> Result<Response<Body>> {
    let (parts, body) = req.into_parts();
    let prefix = format!("/{}", st.cfg.token);
    let Some(rest) = parts.uri.path().strip_prefix(&prefix) else {
        return Ok(full(403, "forbidden"));
    };
    if !(rest.is_empty() || rest.starts_with('/')) {
        return Ok(full(403, "forbidden"));
    }
    let path_q = match parts.uri.query() {
        Some(q) => format!("{rest}?{q}"),
        None => rest.to_string(),
    };
    let bytes = Limited::new(body, MAX_REQUEST)
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("request body: {e}"))?
        .to_bytes();
    let json: Option<Value> = (parts.method == hyper::Method::POST && rest == "/v1/messages")
        .then(|| serde_json::from_slice(&bytes).ok())
        .flatten();
    let Some(mut j) = json else {
        // count_tokens and everything else: straight to Anthropic
        let r = send(&st, Target::Anthropic, &parts, &path_q, bytes).await?;
        return Ok(relay(&st, r, None));
    };

    let model = j["model"].as_str().unwrap_or("").to_string();
    let worker_model = match model.as_str() {
        MARK_FAST => st.cfg.fast_model.clone(),
        MARK_SUB => st.cfg.main_model.clone(),
        _ => {
            // the brain: the user's own conversation always goes to Claude, unchanged
            let ctx = Ctx {
                worker: false,
                model,
                started: std::time::Instant::now(),
            };
            let r = send(&st, Target::Anthropic, &parts, &path_q, bytes).await?;
            return Ok(relay(&st, r, Some(ctx)));
        }
    };
    j["model"] = json!(worker_model);
    if st.cfg.adapt {
        adapt_for_cheap(&mut j);
    }
    if std::env::var_os("MIDDLEMAN_PROXY_SHAPE").is_some() {
        log_shape(&st, &j);
    }
    let ctx = Ctx {
        worker: true,
        model: worker_model,
        started: std::time::Instant::now(),
    };
    let body = Bytes::from(serde_json::to_vec(&j)?);
    let r = send(&st, Target::Worker, &parts, &path_q, body).await?;
    if r.status().is_success() {
        return Ok(relay(&st, r, Some(ctx)));
    }
    // Keep the provider's reason (key scrubbed, capped) so failures can be diagnosed, then
    // rebuild the response for the client from the bytes we read. A failed worker request is
    // never retried on Claude: workers do not spend the Claude plan.
    let status = r.status();
    let headers = r.headers().clone();
    let body = r.bytes().await.unwrap_or_default();
    log_provider_error(&st, status.as_u16(), &body);
    let mut b = hyper::http::Response::builder().status(status);
    for (k, v) in headers.iter() {
        if !HOP.contains(&k.as_str()) {
            b = b.header(k, v);
        }
    }
    let r = reqwest::Response::from(b.body(body.to_vec())?);
    Ok(relay(&st, r, Some(ctx)))
}

/// Make a Claude Code request acceptable to a non-Claude model. Claude Code believes it talks
/// to Claude (the main model id is a Claude id), so it uses Claude-only API features that other
/// models reject with HTTP 400:
/// - top-level `thinking`, `context_management`, `output_config`, `speed` … → removed;
/// - mid-conversation `system` messages: `tool_addition` / `tool_removal` blocks are applied to
///   the top-level `tools`, text is appended to the top-level `system`, anything else (e.g.
///   `configuration_update`) is dropped, and the message itself is removed;
/// - Claude's `thinking` / `redacted_thinking` blocks in assistant turns → removed (they are
///   signed for Claude and mean nothing to another model);
/// - consecutive messages with the same role (left after removals) are merged.
pub fn adapt_for_cheap(j: &mut Value) {
    if let Some(o) = j.as_object_mut() {
        for k in [
            "thinking",
            "context_management",
            "output_config",
            "speed",
            "diagnostics",
            "thread",
            "inference_geo",
            "fallbacks",
            "betas",
        ] {
            o.remove(k);
        }
    }
    let msgs = match j["messages"].as_array() {
        Some(m) => m.clone(),
        None => return,
    };
    let mut tools: Vec<Value> = j["tools"].as_array().cloned().unwrap_or_default();
    let mut extra_system: Vec<String> = vec![];
    let mut out: Vec<Value> = vec![];
    for m in msgs {
        let role = m["role"].as_str().unwrap_or("").to_string();
        if role == "system" {
            let blocks = match &m["content"] {
                Value::String(s) => vec![json!({"type": "text", "text": s})],
                Value::Array(a) => a.clone(),
                _ => vec![],
            };
            for b in blocks {
                match b["type"].as_str().unwrap_or("") {
                    "text" => {
                        if let Some(t) = b["text"].as_str().filter(|t| !t.trim().is_empty()) {
                            extra_system.push(t.to_string());
                        }
                    }
                    "tool_addition" => {
                        let def = &b["tool"]["definition"];
                        if let Some(name) = def["name"].as_str() {
                            tools.retain(|t| t["name"].as_str() != Some(name));
                            let mut d = def.clone();
                            if let Some(o) = d.as_object_mut() {
                                o.remove("cache_control");
                            }
                            tools.push(d);
                        }
                    }
                    "tool_removal" => {
                        let name = b["tool"]["name"]
                            .as_str()
                            .or_else(|| b["tool"]["definition"]["name"].as_str())
                            .or_else(|| b["name"].as_str())
                            .map(str::to_string);
                        if let Some(n) = name {
                            tools.retain(|t| t["name"].as_str() != Some(n.as_str()));
                        }
                    }
                    _ => {}
                }
            }
            continue;
        }
        let mut m = m;
        if role == "assistant" {
            if let Some(a) = m["content"].as_array_mut() {
                a.retain(|b| !matches!(b["type"].as_str(), Some("thinking" | "redacted_thinking")));
                if a.is_empty() {
                    a.push(json!({"type": "text", "text": "(continuing)"}));
                }
            }
        }
        // merge with the previous message when the role repeats
        if let Some(prev) = out.last_mut() {
            if prev["role"].as_str() == Some(role.as_str()) {
                let as_blocks = |c: &Value| -> Vec<Value> {
                    match c {
                        Value::String(s) => vec![json!({"type": "text", "text": s})],
                        Value::Array(a) => a.clone(),
                        _ => vec![],
                    }
                };
                let mut merged = as_blocks(&prev["content"]);
                merged.extend(as_blocks(&m["content"]));
                prev["content"] = Value::Array(merged);
                continue;
            }
        }
        out.push(m);
    }
    j["messages"] = Value::Array(out);
    if !tools.is_empty() || j.get("tools").is_some() {
        j["tools"] = Value::Array(tools);
    }
    if !extra_system.is_empty() {
        let add = extra_system.join("\n\n");
        match &mut j["system"] {
            Value::String(s) => {
                s.push_str("\n\n");
                s.push_str(&add);
            }
            Value::Array(a) => a.push(json!({"type": "text", "text": add})),
            v => *v = json!(add),
        }
    }
}

/// Debug aid (MIDDLEMAN_PROXY_SHAPE=1): log the request's SHAPE only (top-level keys, message
/// roles, block types and, for non-text blocks, their field names), never any content.
fn log_shape(st: &St, j: &Value) {
    use std::io::Write;
    fn keys(v: &Value) -> Vec<String> {
        v.as_object()
            .map(|o| o.keys().cloned().collect())
            .unwrap_or_default()
    }
    let mut out = format!("top={:?}", keys(j));
    if let Some(ms) = j["messages"].as_array() {
        for (i, m) in ms.iter().enumerate() {
            let role = m["role"].as_str().unwrap_or("?");
            let blocks: Vec<String> = match &m["content"] {
                Value::String(_) => vec!["str".into()],
                Value::Array(a) => a
                    .iter()
                    .map(|b| {
                        let t = b["type"].as_str().unwrap_or("?");
                        if matches!(t, "text" | "tool_use" | "tool_result") {
                            t.to_string()
                        } else {
                            let sub: Vec<String> = keys(b)
                                .into_iter()
                                .map(|k| {
                                    let inner = &b[&k];
                                    if inner.is_array() || inner.is_object() {
                                        format!(
                                            "{k}{:?}",
                                            inner
                                                .as_array()
                                                .and_then(|x| x.first())
                                                .map(keys)
                                                .unwrap_or_else(|| keys(inner))
                                        )
                                    } else {
                                        k
                                    }
                                })
                                .collect();
                            format!("{t}{sub:?}")
                        }
                    })
                    .collect(),
                _ => vec![],
            };
            if role == "system" || blocks.iter().any(|b| b.contains('[')) {
                out.push_str(&format!(" | m{i}:{role}:{blocks:?}"));
            }
        }
    }
    let path = st.cfg.state_dir.join("proxy-shape.log");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(f, "{out}");
    }
}

/// Append a failed cheap-model response to `<state>/proxy-errors.log` (0600): status and the
/// first 2 KB of the body with the OpenRouter key scrubbed. Never the request.
fn log_provider_error(st: &St, status: u16, body: &[u8]) {
    use std::io::Write;
    let key = st.cfg.cheap_key.expose();
    let mut text: String = String::from_utf8_lossy(body).into_owned();
    if !key.is_empty() {
        text = text.replace(key, "[key]");
    }
    let text: String = crate::fsutil::clean(&text, 2048);
    let _ = crate::ledger::ensure_private_dir(&st.cfg.state_dir);
    let path = st.cfg.state_dir.join("proxy-errors.log");
    let mut o = std::fs::OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    if let Ok(mut f) = o.open(&path) {
        let _ = writeln!(f, "{} HTTP {status} {text}", now_unix());
    }
}

#[derive(Default, Debug, PartialEq)]
pub struct Usage {
    pub input: u64,
    pub output: u64,
    pub cost: Option<f64>,
}

/// Usage from a JSON response or an SSE stream (message_start + message_delta events).
pub fn parse_usage(buf: &[u8]) -> Usage {
    let mut u = Usage::default();
    let mut take = |v: &Value| {
        let us = v.get("usage").or_else(|| v.pointer("/message/usage"));
        if let Some(us) = us {
            u.input = u.input.max(us["input_tokens"].as_u64().unwrap_or(0));
            u.output = u.output.max(us["output_tokens"].as_u64().unwrap_or(0));
            if let Some(c) = us["cost"].as_f64() {
                u.cost = Some(c);
            }
        }
    };
    let text = String::from_utf8_lossy(buf);
    if text.trim_start().starts_with('{') {
        if let Ok(v) = serde_json::from_str::<Value>(&text) {
            take(&v);
        }
    } else {
        for l in text.lines() {
            if let Some(d) = l.strip_prefix("data:") {
                if let Ok(v) = serde_json::from_str::<Value>(d.trim()) {
                    take(&v);
                }
            }
        }
    }
    u
}

fn relay(st: &Arc<St>, r: reqwest::Response, ctx: Option<Ctx>) -> Response<Body> {
    let status = r.status();
    let mut b = Response::builder().status(status);
    for (k, v) in r.headers() {
        if !HOP.contains(&k.as_str()) && k != "content-encoding" {
            b = b.header(k, v);
        }
    }
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(16);
    let st = st.clone();
    tokio::spawn(async move {
        let mut s = r.bytes_stream();
        let mut buf: Vec<u8> = Vec::new();
        let mut ok = true;
        while let Some(c) = s.next().await {
            match c {
                Ok(bytes) => {
                    if buf.len() < MAX_CAPTURE {
                        buf.extend_from_slice(&bytes);
                    }
                    if tx.send(Ok(Frame::data(bytes))).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    ok = false;
                    let _ = tx
                        .send(Err(std::io::Error::other(e.without_url().to_string())))
                        .await;
                    break;
                }
            }
        }
        drop(tx);
        if let Some(ctx) = ctx {
            finish(&st, ctx, status, ok, &buf);
        }
    });
    let stream = futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx));
    b.body(BodyExt::boxed(StreamBody::new(stream)))
        .unwrap_or_else(|_| full(502, "bad upstream response"))
}

fn finish(st: &St, ctx: Ctx, status: StatusCode, stream_ok: bool, buf: &[u8]) {
    let success = status.is_success() && stream_ok;
    let u = parse_usage(buf);
    let cheap = ctx.worker;
    let (cost, source) = match (cheap, u.cost, st.cfg.cheap_prices) {
        (false, _, _) => (0.0, "estimate"),
        (true, Some(c), _) => (c, "provider"),
        (true, None, Some((i, o))) => ((u.input as f64 * i + u.output as f64 * o) / 1e6, "usage"),
        _ => (0.0, "estimate"),
    };
    let p = &st.cfg.claude_prices;
    let equiv = if cheap {
        (u.input as f64 * p.in_per_1m + u.output as f64 * p.out_per_1m) / 1e6
    } else {
        0.0
    };
    let e = LedgerEntry {
        ts: now_rfc3339(),
        request_id: uuid::Uuid::new_v4().to_string(),
        attempt: 1,
        project: st.cfg.project.clone(),
        via: Some("proxy".into()),
        task_kind: "session".into(),
        mode: "workers".into(),
        chain_step: if cheap { "worker" } else { "claude" }.into(),
        provider: if cheap {
            st.cfg.cheap_provider.clone()
        } else {
            "anthropic".into()
        },
        model: ctx.model,
        status: if success { "ok" } else { "error" }.into(),
        closing: Some(true),
        input_tokens: Some(u.input),
        output_tokens: Some(u.output),
        cost_usd: cost,
        cost_source: source.into(),
        latency_ms: Some(ctx.started.elapsed().as_millis() as u64),
        write_mode: "session".into(),
        claude_equiv_usd: if success { equiv } else { 0.0 },
        validation: "skipped".into(),
        session_id: st.cfg.run_id.clone(),
        purpose: st.cfg.purpose.clone(),
        ..Default::default()
    };
    if let Ok(l) = Ledger::new(&st.cfg.state_dir) {
        let _ = l.append(&e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_from_json_and_sse() {
        let j = br#"{"usage":{"input_tokens":10,"output_tokens":5,"cost":0.002}}"#;
        assert_eq!(
            parse_usage(j),
            Usage {
                input: 10,
                output: 5,
                cost: Some(0.002)
            }
        );
        let sse = b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":100,\"output_tokens\":1}}}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":42}}\n\n";
        assert_eq!(
            parse_usage(sse),
            Usage {
                input: 100,
                output: 42,
                cost: None
            }
        );
    }

    /// Regression from the first live bench: GLM rejected Claude-only request features with
    /// HTTP 400 ("Mid-conversation tool changes … not supported", "configuration_update").
    #[test]
    fn adapt_for_cheap_removes_claude_only_features() {
        let mut j = serde_json::json!({
            "model": "z-ai/glm-5.3",
            "system": [{"type": "text", "text": "You are Claude Code"}],
            "tools": [{"name": "Read", "input_schema": {}}, {"name": "Old", "input_schema": {}}],
            "thinking": {"type": "adaptive"},
            "context_management": {"edits": []},
            "output_config": {"effort": "medium"},
            "messages": [
                {"role": "user", "content": "fix the bug"},
                {"role": "system", "content": [
                    {"type": "text", "text": "reminder: run tests"},
                    {"type": "tool_addition", "tool": {"type": "custom",
                        "definition": {"name": "Bash", "input_schema": {}, "cache_control": {"type": "ephemeral"}}},
                        "cache_control": {"type": "ephemeral", "ttl": "1h"}},
                    {"type": "tool_removal", "tool": {"name": "Old"}},
                    {"type": "configuration_update", "effort": "high"}
                ]},
                {"role": "user", "content": [{"type": "text", "text": "go"}]},
                {"role": "assistant", "content": [
                    {"type": "thinking", "thinking": "", "signature": "sig"},
                    {"type": "tool_use", "id": "t1", "name": "Bash", "input": {}}
                ]}
            ]
        });
        adapt_for_cheap(&mut j);
        for k in ["thinking", "context_management", "output_config"] {
            assert!(j.get(k).is_none(), "{k}");
        }
        let names: Vec<&str> = j["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["Read", "Bash"]);
        assert!(j["tools"][1].get("cache_control").is_none());
        let msgs = j["messages"].as_array().unwrap();
        assert!(msgs.iter().all(|m| m["role"] != "system"));
        // the two user messages around the removed system message are merged
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0]["content"].as_array().unwrap().len(), 2);
        assert_eq!(msgs[1]["content"].as_array().unwrap().len(), 1);
        assert_eq!(msgs[1]["content"][0]["type"], "tool_use");
        assert_eq!(j["system"][1]["text"], "reminder: run tests");
    }
}
