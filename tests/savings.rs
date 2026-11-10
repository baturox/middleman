//! Savings are measured end to end: cost source, Claude-equivalent from the restored text,
//! overhead from the real call/result sizes and the live session context, and every sum
//! (per line, per request, per day, status-line totals) agrees.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};

use common::{env, models_body, Env};
use middleman::classify::Declared;
use middleman::economics::{Measured, WriteMode};
use middleman::intake::FileRef;
use middleman::ledger::LedgerEntry;
use middleman::mcp::server::Server;
use middleman::pipeline::{DelegateRequest, Pipeline, Status};
use middleman::TaskKind;
use proptest::prelude::*;
use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const ANSWER: &str = "def test_one():\n    assert add(1, 2) == 3\n";

/// Chat completion with a fixed answer; `cost` adds OpenRouter-style `usage.cost`. The
/// completion token count is deliberately huge (reasoning tokens): it must not drive N.
fn completion(cost: Option<f64>) -> Value {
    let mut usage = json!({"prompt_tokens": 400, "completion_tokens": 5000});
    if let Some(c) = cost {
        usage["cost"] = json!(c);
    }
    json!({"id": "c1", "model": "x-coder-small",
        "choices": [{"message": {"role": "assistant", "content": format!("```python\n{ANSWER}```")}, "finish_reason": "stop"}],
        "usage": usage})
}

/// `/balance` drops by 0.004 after the first read.
struct Dropping(AtomicUsize);

impl Respond for Dropping {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        let n = self.0.fetch_add(1, Ordering::SeqCst);
        let b = if n == 0 { 10.0 } else { 9.996 };
        ResponseTemplate::new(200).set_body_json(json!({"balance_usd": b}))
    }
}

async fn server(cost: Option<f64>, dropping: bool) -> MockServer {
    let s = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(models_body(&[(
            "x-coder-small",
            0.1,
            0.2,
        )])))
        .mount(&s)
        .await;
    if dropping {
        Mock::given(method("GET"))
            .and(path("/v1/balance"))
            .respond_with(Dropping(AtomicUsize::new(0)))
            .mount(&s)
            .await;
    } else {
        Mock::given(method("GET"))
            .and(path("/v1/balance"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"balance_usd": 10.0})))
            .mount(&s)
            .await;
    }
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(completion(cost)))
        .mount(&s)
        .await;
    s
}

fn mk(s: &MockServer) -> (Env, Pipeline) {
    let e = env(&format!("{}/v1", s.uri()), "openai", "S1", "");
    let p = Pipeline::new(e.config()).unwrap();
    (e, p)
}

fn req(e: &Env) -> DelegateRequest {
    let mut r = DelegateRequest::simple(
        TaskKind::WriteTests,
        "Write tests for add().",
        Declared::Internal,
    );
    r.files = vec![FileRef {
        path: "src/invoice.py".into(),
        start_line: None,
        end_line: None,
    }];
    r.write_mode = Some(WriteMode::File);
    r.output_path = Some(e.out_root().join("test_x.py").display().to_string());
    r
}

#[tokio::test]
async fn provider_cost_live_context_session_model_and_measured_sizes() {
    let s = server(Some(0.00123), false).await;
    let (e, p) = mk(&s);
    let state = e.dir.path().join("state");
    // the status line reported this session: Sonnet, 250k context, 1-hour cache
    middleman::session::record(
        &state,
        "sess-live",
        middleman::session::SessionInfo {
            context_tokens: 250_000,
            model_id: "claude-sonnet-5-5".into(),
            cache_ttl: Some("1h".into()),
            updated_at: 0,
        },
        middleman::ledger::now_unix(),
    );
    let mut r = req(&e);
    r.session_id = Some("sess-live".into());
    r.call_chars = Some(420);
    let out = p.run(r).await;
    assert_eq!(out.status, Status::Ok, "{out:?}");
    let l = p.ledger().entries().unwrap();
    assert_eq!(l.len(), 1);
    let x = &l[0];
    assert!(x.is_closing());
    assert_eq!(x.cost_source, "provider");
    assert_eq!(x.cost_usd, 0.00123);
    // tokens x catalog price kept for comparison: 400 x 0.1 + 5000 x 0.2 per 1M
    assert!((x.catalog_cost_usd.unwrap() - 0.00104).abs() < 1e-12);
    assert_eq!(x.claude_model, "sonnet-5.5");
    assert_eq!(x.price_basis, "session");
    assert_eq!(x.context_tokens, Some(250_000));
    assert_eq!(x.context_source, "session");

    // recompute the formula from first principles
    let cfg = e.config();
    let econ = &cfg.economics;
    let prices = econ.prices_for("sonnet-5.5").unwrap();
    let written = std::fs::read_to_string(e.out_root().join("test_x.py")).unwrap();
    let n_chars = written.chars().count() as u64;
    assert_eq!(
        x.claude_output_tokens,
        Some((n_chars as f64 / 3.5).ceil() as u64),
        "N from the restored file, not the 5000 cheap-model tokens"
    );
    let result_chars = middleman::mcp::server::result_chars(&out);
    let b = econ.breakdown(
        &prices,
        &Measured {
            claude_output_chars: n_chars,
            prose: false,
            call_chars: 420,
            result_chars,
            context_tokens: 250_000,
            cache_1h: true,
            cheap_cost_usd: 0.00123,
        },
    );
    assert_eq!(
        b.call_tokens,
        120 + 30,
        "420 chars / 3.5 + tool_use framing"
    );
    assert_eq!(x.call_tokens, Some(b.call_tokens));
    assert_eq!(x.result_tokens, Some(b.result_tokens));
    assert!((x.claude_equiv_usd - b.claude_equiv_usd).abs() < 1e-15);
    assert!((x.claude_overhead_usd - b.claude_overhead_usd).abs() < 1e-15);
    // turn = 250k x $0.10/1M (Sonnet cache read)
    assert!((b.turn_usd - 0.025).abs() < 1e-12);
    // result priced as a 1-hour cache write: 2 x $2/1M
    assert!((b.result_usd - b.result_tokens as f64 * 4.0 / 1e6).abs() < 1e-15);
    assert!(
        (x.net_savings_usd - (x.claude_equiv_usd - x.claude_overhead_usd - x.cost_usd)).abs()
            < 1e-15
    );
    // tiny output, huge context: delegating this lost money, and it shows
    assert!(x.net_savings_usd < 0.0);
    let s = out.savings.unwrap();
    assert!((s.net_savings_usd - x.net_savings_usd).abs() < 1e-15);
}

#[tokio::test]
async fn balance_delta_only_when_no_other_call_is_in_flight() {
    // no usage.cost: the balance drop is the cost when this call ran alone
    let s = server(None, true).await;
    let (_e, p) = mk(&s);
    let r = req(&_e);
    assert_eq!(p.run(r).await.status, Status::Ok);
    let l = p.ledger().entries().unwrap();
    assert_eq!(l[0].cost_source, "balance");
    assert!((l[0].cost_usd - 0.004).abs() < 1e-9);

    // another call is in flight (a marker from another process): fall back to tokens
    let s = server(None, true).await;
    let (e, p) = mk(&s);
    let inflight = e.dir.path().join("state/inflight");
    std::fs::create_dir_all(&inflight).unwrap();
    std::fs::write(inflight.join("other-process"), b"").unwrap();
    let mut r = req(&e);
    r.output_path = Some(e.out_root().join("test_y.py").display().to_string());
    assert_eq!(p.run(r).await.status, Status::Ok);
    let l = p.ledger().entries().unwrap();
    assert_eq!(l[0].cost_source, "usage");
    assert!((l[0].cost_usd - 0.00104).abs() < 1e-12);
}

#[tokio::test]
async fn dry_runs_from_claude_are_logged_with_their_overhead() {
    let s = server(Some(0.001), false).await;
    let (e, p) = mk(&s);
    let srv = Server::new(p);
    let mut args = json!({
        "task_kind": "write_tests",
        "instructions": "Write tests for add().",
        "declared_sensitivity": "internal",
        "files": [{"path": "src/invoice.py"}],
        "dry_run": true,
        "output_path": e.out_root().join("t.py").display().to_string(),
        "expected_output_tokens": 5000,
    });
    let r = srv
        .handle(
            "tools/call",
            json!({"name": "delegate_task", "arguments": args.clone()}),
        )
        .await
        .unwrap();
    let text_chars: u64 = r["content"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["text"].as_str().unwrap().chars().count() as u64)
        .sum();
    let l = middleman::ledger::Ledger::new(&e.dir.path().join("state"))
        .unwrap()
        .entries()
        .unwrap();
    assert_eq!(l.len(), 1, "{l:?}");
    let d = &l[0];
    assert_eq!(d.status, "dry_run");
    assert!(d.is_closing() && d.cost_usd == 0.0);
    assert!(d.claude_overhead_usd > 0.0 && d.net_savings_usd < 0.0);
    assert_eq!(d.block_reason_category, None);
    let econ = e.config().economics;
    // the measured result: what the server returned, at the code ratio
    assert_eq!(d.result_tokens, Some(econ.claude_tokens(text_chars, false)));
    let call_chars = serde_json::to_string(&args).unwrap().chars().count() as u64;
    assert_eq!(
        d.call_tokens,
        Some(econ.claude_tokens(call_chars, false) + middleman::economics::TOOL_USE_FRAMING_TOKENS)
    );
    // dry runs do not count as jobs, but their overhead counts in the net
    let a = middleman::report::aggregate(&l);
    assert_eq!((a.requests, a.dry_runs, a.jobs()), (1, 1, 0));
    // a blocked call from Claude also carries its overhead
    args["dry_run"] = json!(false);
    args["files"] = json!([{"path": "config/settings.py"}]);
    srv.handle(
        "tools/call",
        json!({"name": "delegate_task", "arguments": args}),
    )
    .await
    .unwrap();
    let l = middleman::ledger::Ledger::new(&e.dir.path().join("state"))
        .unwrap()
        .entries()
        .unwrap();
    assert_eq!(l[1].status, "blocked");
    assert!(l[1].claude_overhead_usd > 0.0);
    assert!((l[1].net_savings_usd + l[1].claude_overhead_usd).abs() < 1e-15);
}

#[tokio::test]
async fn direct_dry_runs_are_not_logged() {
    let s = server(Some(0.001), false).await;
    let (e, p) = mk(&s);
    let mut r = req(&e);
    r.dry_run = true;
    assert_eq!(p.run(r).await.status, Status::Ok);
    assert!(p.ledger().entries().unwrap().is_empty());
}

// ------------------------------------------------------------------ sums agree

fn arb_request() -> impl Strategy<Value = Vec<(String, f64, f64, f64, u32)>> {
    // (status, equiv, overhead, cost, attempts) for one request
    (
        prop_oneof![
            Just("ok"),
            Just("blocked"),
            Just("do_it_yourself"),
            Just("error"),
            Just("dry_run")
        ],
        0.0f64..0.2,
        0.0f64..0.05,
        proptest::collection::vec(0.0f64..0.01, 0..4),
    )
        .prop_map(|(st, eq, oh, costs)| {
            let mut v = vec![];
            let n = costs.len() as u32;
            for (i, c) in costs.iter().enumerate() {
                let last = i + 1 == costs.len();
                if last && st == "ok" {
                    v.push(("ok".to_string(), eq, oh, *c, i as u32));
                } else {
                    v.push((
                        if last { "failed" } else { "escalated" }.to_string(),
                        0.0,
                        0.0,
                        *c,
                        i as u32,
                    ));
                }
            }
            if st != "ok" || costs.is_empty() {
                let st = if st == "ok" { "blocked" } else { st };
                v.push((st.to_string(), 0.0, oh, 0.0, n));
            }
            v
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn ledger_sums_agree_every_way(reqs in proptest::collection::vec(arb_request(), 0..30), day_split in 0usize..30) {
        let base = 1_767_225_600i64 + 3600;
        let mut es: Vec<LedgerEntry> = vec![];
        let mut by_request = 0.0f64;
        for (i, lines) in reqs.iter().enumerate() {
            // requests before `day_split` happen yesterday
            let ts = if i < day_split { base - 86_400 + i as i64 } else { base + i as i64 };
            let mut req_eq = 0.0;
            let mut req_oh = 0.0;
            let mut req_cost = 0.0;
            for (st, eq, oh, cost, attempt) in lines {
                let closing = !matches!(st.as_str(), "escalated" | "failed");
                let line = LedgerEntry {
                    ts: middleman::ledger::rfc3339_at(ts),
                    request_id: format!("r{i}"),
                    attempt: *attempt,
                    status: st.clone(),
                    closing: Some(closing),
                    claude_equiv_usd: *eq,
                    claude_overhead_usd: *oh,
                    cost_usd: *cost,
                    net_savings_usd: 123.0, // garbage: the identity is enforced on read
                    session_id: Some(if i % 2 == 0 { "s-even" } else { "s-odd" }.into()),
                    ..Default::default()
                };
                let line = middleman::ledger::parse_line(&serde_json::to_string(&line).unwrap()).unwrap();
                req_eq += line.claude_equiv_usd;
                req_oh += line.claude_overhead_usd;
                req_cost += line.cost_usd;
                es.push(line);
            }
            by_request += req_eq - req_oh - req_cost;
        }
        let total = middleman::report::build(&es, None, middleman::report::By::Day).total;
        // per line == per request
        prop_assert!((total.net_savings_usd - by_request).abs() < 1e-9);
        prop_assert!((total.net_savings_usd - (total.claude_equiv_usd - total.claude_overhead_usd - total.cheap_spend_usd)).abs() < 1e-9);
        // one closing line per request: requests counted once, never per escalation step
        prop_assert_eq!(total.requests, reqs.len());
        // partitions (by day, by session) add up to the total
        let days = middleman::report::build(&es, None, middleman::report::By::Day);
        let sum_days: f64 = days.rows.iter().map(|r| r.net_savings_usd).sum();
        prop_assert!((sum_days - total.net_savings_usd).abs() < 1e-9);
    }
}
