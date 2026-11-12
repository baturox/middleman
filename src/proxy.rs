//! `middleman proxy`: the local Anthropic-compatible proxy behind `middleman claude` smart mode.
//!
//! Claude Code talks to `http://127.0.0.1:PORT/<token>` (the launcher sets ANTHROPIC_BASE_URL).
//! Every request is forwarded to Anthropic (the client's own auth headers pass through
//! untouched, and are never logged or stored) or, when the router says so, to OpenRouter (auth
//! replaced with the OpenRouter key, `model` rewritten to the cheap model). Response bodies are
//! streamed back as they arrive; a copy is kept only to read the usage for the ledger.
//! Bound to 127.0.0.1; a request without the per-launch token gets 403.

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
use crate::detect::Detector;
use crate::economics::ClaudePrices;
use crate::egress::{self, OutboundRequest};
use crate::ledger::{now_rfc3339, now_unix, Ledger, LedgerEntry};
use crate::modes::{self, Mode, RouteNote};
use crate::pseudo::Vault;
use crate::router::{self, Class, Route, Router, Step};

pub const ANTHROPIC_URL: &str = "https://api.anthropic.com";
pub const OPENROUTER_URL: &str = "https://openrouter.ai/api";
/// Model names the launcher gives Claude Code for its background and subagent roles.
pub const MARK_FAST: &str = "mm-cheap-fast";
pub const MARK_SUB: &str = "mm-cheap-sub";
/// Real Claude model used for a marker request when the live mode is `claude`.
const CLAUDE_FAST: &str = "claude-haiku-4-5";
const MAX_REQUEST: usize = 64 << 20;
const MAX_CAPTURE: usize = 16 << 20;

type Body = BoxBody<Bytes, std::io::Error>;

pub struct ProxyCfg {
    pub state_dir: PathBuf,
    pub token: String,
    pub anthropic_url: String,
    pub openrouter_url: String,
    pub openrouter_key: Secret,
    pub main_model: String,
    pub fast_model: String,
    pub mode: Mode,
    /// Ignore `middleman mode` changes (bench runs keep their own mode).
    pub fixed_mode: bool,
    pub project: String,
    /// `bench` marks ledger lines so they stay out of the savings totals.
    pub purpose: Option<String>,
    pub run_id: Option<String>,
    pub detector: Detector,
    pub claude_prices: ClaudePrices,
    /// (input, output) USD per 1M for the cheap model, used when the response has no cost.
    pub cheap_prices: Option<(f64, f64)>,
}

impl ProxyCfg {
    pub fn from_config(
        cfg: &Config,
        key: Secret,
        token: String,
        mode: Mode,
        main_model: String,
        fast_model: String,
        project: String,
    ) -> ProxyCfg {
        let dict = cfg
            .redact
            .dictionary_file
            .as_ref()
            .and_then(|p| crate::detect::Dictionary::load(p).ok());
        let cat = crate::catalog::Catalog::load(cfg);
        let cheap_prices =
            crate::catalog::Catalog::lookup(cfg, cat.as_ref(), "openrouter", &main_model)
                .and_then(|p| p.prices)
                .map(|p| (p.in_per_1m, p.out_per_1m));
        ProxyCfg {
            state_dir: cfg.state_dir(),
            token,
            anthropic_url: ANTHROPIC_URL.into(),
            openrouter_url: OPENROUTER_URL.into(),
            openrouter_key: key,
            main_model,
            fast_model,
            mode,
            fixed_mode: false,
            project,
            purpose: None,
            run_id: None,
            detector: Detector::new(vec![], cfg.public_hosts(), dict),
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
    router: Router,
    client: reqwest::Client,
}

pub async fn bind() -> Result<(tokio::net::TcpListener, u16)> {
    let l = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = l.local_addr()?.port();
    Ok((l, port))
}

pub async fn serve(cfg: ProxyCfg, listener: tokio::net::TcpListener) -> Result<()> {
    check_upstream(&cfg.anthropic_url)?;
    check_upstream(&cfg.openrouter_url)?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .build()?;
    let st = Arc::new(St {
        cfg,
        router: Router::default(),
        client,
    });
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
    OpenRouter,
}

struct Ctx {
    key: Option<String>,
    mode: String,
    route: Route,
    reason: String,
    model: String,
    /// Count outcomes in the router (not for background-model requests).
    track: bool,
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
        Target::OpenRouter => &st.cfg.openrouter_url,
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
        if target == Target::OpenRouter && matches!(n, "authorization" | "x-api-key") {
            continue;
        }
        rb = rb.header(k, v);
    }
    if target == Target::OpenRouter {
        let mut v = reqwest::header::HeaderValue::from_str(&format!(
            "Bearer {}",
            st.cfg.openrouter_key.expose()
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
        return Ok(relay(&st, r, None, Target::Anthropic));
    };

    let live = if st.cfg.fixed_mode {
        st.cfg.mode
    } else {
        modes::read_live_mode(&st.cfg.state_dir).unwrap_or(st.cfg.mode)
    };
    let model = j["model"].as_str().unwrap_or("").to_string();
    let marker = match model.as_str() {
        MARK_FAST => Some(st.cfg.fast_model.clone()),
        MARK_SUB => Some(st.cfg.main_model.clone()),
        _ => None,
    };
    let key = router::conv_key(&j);
    let new_turn = router::is_new_turn(&j);
    let force = if new_turn {
        router::take_force_prefix(&mut j)
    } else {
        None
    };
    let mut modified = force.is_some();
    let util = modes::read_usage(&st.cfg.state_dir)
        .filter(|u| now_unix() - u.ts < 5 * 3600)
        .map(|u| u.pct);

    let (route, reason, track) = if marker.is_some() {
        if live == Mode::Claude {
            j["model"] = json!(CLAUDE_FAST);
            modified = true;
            (
                Route::Claude,
                "background model (claude mode)".to_string(),
                false,
            )
        } else {
            (Route::Cheap, "background model".to_string(), false)
        }
    } else {
        let text = router::last_user_text(&j);
        match st.router.plan(&key, new_turn, live, util, force, &text) {
            Step::Route(r, why) => (r, why, true),
            Step::Ask { hash } => {
                let class = ask_router(&st, &text).await;
                let (r, why) = st.router.settle(&key, &hash, class);
                (r, why, true)
            }
        }
    };
    let mut ctx = Ctx {
        key: track.then_some(key.clone()),
        mode: live.to_string(),
        route,
        reason,
        model: model.clone(),
        track,
        started: std::time::Instant::now(),
    };
    let cheap_id = marker.clone().unwrap_or_else(|| st.cfg.main_model.clone());
    let original = if modified {
        Bytes::from(serde_json::to_vec(&j)?)
    } else {
        bytes
    };

    let cheap_body = |j: &Value| -> Result<Bytes> {
        let mut c = j.clone();
        c["model"] = json!(cheap_id);
        Ok(Bytes::from(serde_json::to_vec(&c)?))
    };

    if ctx.route == Route::Cheap {
        ctx.model = cheap_id.clone();
        let r = send(&st, Target::OpenRouter, &parts, &path_q, cheap_body(&j)?).await;
        match r {
            Ok(r) if r.status().is_success() => {
                return Ok(relay(&st, r, Some(ctx), Target::OpenRouter));
            }
            other => {
                let next = if track {
                    st.router.cheap_failed(&key, util)
                } else {
                    Route::Cheap
                };
                if next == Route::Claude && marker.is_none() {
                    ctx.route = Route::Claude;
                    ctx.reason = "cheap model failed twice".into();
                    ctx.model = model;
                    let r = send(&st, Target::Anthropic, &parts, &path_q, original).await?;
                    return Ok(relay(&st, r, Some(ctx), Target::Anthropic));
                }
                return match other {
                    Ok(r) => Ok(relay(&st, r, Some(ctx), Target::OpenRouter)),
                    Err(e) => Err(e),
                };
            }
        }
    }

    let r = send(&st, Target::Anthropic, &parts, &path_q, original).await?;
    let code = r.status().as_u16();
    if (code == 429 || code == 529) && marker.is_none() {
        // Claude is rate limited or overloaded: the same request continues on the cheap model
        st.router
            .pin_cheap(&key, &format!("Claude returned {code}"));
        ctx.route = Route::Cheap;
        ctx.reason = format!("Claude returned {code}: retried on cheap model");
        ctx.model = cheap_id.clone();
        let r2 = send(&st, Target::OpenRouter, &parts, &path_q, cheap_body(&j)?).await?;
        return Ok(relay(&st, r2, Some(ctx), Target::OpenRouter));
    }
    Ok(relay(&st, r, Some(ctx), Target::Anthropic))
}

/// Router model: HARD or EASY. Only sanitized text leaves; a blocked prompt is HARD.
async fn ask_router(st: &St, text: &str) -> Option<Class> {
    let system = "Classify the coding request. Reply with exactly one word: EASY for routine work (tests, docstrings, renames, boilerplate, formatting, explanations, small well-specified edits), HARD for anything needing design, debugging, multi-file reasoning or judgement.";
    let user: String = text.chars().take(2000).collect();
    let sealed = egress::seal(
        OutboundRequest {
            model: st.cfg.fast_model.clone(),
            system: system.into(),
            user,
            max_tokens: 5,
        },
        &Vault::new(""),
        &st.cfg.detector,
        &[&st.cfg.openrouter_key],
    )
    .ok()?;
    let r = sealed.get();
    let body = json!({"model": r.model, "max_tokens": r.max_tokens, "system": r.system,
        "messages": [{"role": "user", "content": r.user}]});
    let mut auth = reqwest::header::HeaderValue::from_str(&format!(
        "Bearer {}",
        st.cfg.openrouter_key.expose()
    ))
    .ok()?;
    auth.set_sensitive(true);
    let resp = st
        .client
        .post(format!(
            "{}/v1/messages",
            st.cfg.openrouter_url.trim_end_matches('/')
        ))
        .header("authorization", auth)
        .header("anthropic-version", "2023-06-01")
        .timeout(Duration::from_secs(15))
        .json(&body)
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let v: Value = resp.json().await.ok()?;
    let t = v["content"][0]["text"].as_str()?.to_uppercase();
    if t.contains("EASY") {
        Some(Class::Easy)
    } else if t.contains("HARD") {
        Some(Class::Hard)
    } else {
        None
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

/// A non-streamed response whose tool_use input is not a JSON object (unusable tool call).
pub fn invalid_tool_output(buf: &[u8]) -> bool {
    serde_json::from_slice::<Value>(buf)
        .ok()
        .and_then(|v| v["content"].as_array().cloned())
        .is_some_and(|c| {
            c.iter()
                .any(|b| b["type"] == "tool_use" && !b["input"].is_object())
        })
}

/// Utilization percent from Anthropic's unified rate-limit headers (fraction 0..1 or percent).
fn utilization(h: &reqwest::header::HeaderMap) -> Option<f64> {
    let v = h
        .get("anthropic-ratelimit-unified-5h-utilization")?
        .to_str()
        .ok()?
        .trim()
        .parse::<f64>()
        .ok()?;
    Some(if v <= 1.0 { v * 100.0 } else { v })
}

fn relay(st: &Arc<St>, r: reqwest::Response, ctx: Option<Ctx>, target: Target) -> Response<Body> {
    let status = r.status();
    if target == Target::Anthropic {
        if let Some(p) = utilization(r.headers()) {
            let _ = modes::write_usage(&st.cfg.state_dir, p, now_unix());
        }
    }
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
    if ctx.route == Route::Cheap && ctx.track {
        if let Some(k) = &ctx.key {
            if success && !invalid_tool_output(buf) {
                st.router.cheap_ok(k);
            } else if success {
                st.router.cheap_failed(k, None);
            }
        }
    }
    let u = parse_usage(buf);
    let _ = modes::write_route(
        &st.cfg.state_dir,
        &RouteNote {
            mode: ctx.mode.clone(),
            route: ctx.route.as_str().into(),
            model: ctx.model.clone(),
            ts: now_unix(),
        },
    );
    let cheap = ctx.route == Route::Cheap;
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
        mode: ctx.mode,
        chain_step: ctx.route.as_str().into(),
        provider: if cheap { "openrouter" } else { "anthropic" }.into(),
        model: ctx.model,
        status: if success { "ok" } else { "error" }.into(),
        closing: Some(true),
        block_reason_category: Some(ctx.reason),
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
        assert!(invalid_tool_output(
            br#"{"content":[{"type":"tool_use","input":"oops"}]}"#
        ));
        assert!(!invalid_tool_output(
            br#"{"content":[{"type":"tool_use","input":{}}]}"#
        ));
    }

    #[test]
    fn utilization_header() {
        let mut h = reqwest::header::HeaderMap::new();
        h.insert(
            "anthropic-ratelimit-unified-5h-utilization",
            "0.41".parse().unwrap(),
        );
        assert_eq!(utilization(&h), Some(41.0));
        h.insert(
            "anthropic-ratelimit-unified-5h-utilization",
            "87".parse().unwrap(),
        );
        assert_eq!(utilization(&h), Some(87.0));
    }
}
