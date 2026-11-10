//! Mocked integration (wiremock), both wire formats.

mod common;

use common::{env, models_body, Echo, Env, FAKE_KEY};
use middleman::classify::Declared;
use middleman::economics::WriteMode;
use middleman::intake::FileRef;
use middleman::pipeline::{DelegateRequest, Pipeline, Status};
use middleman::TaskKind;
use serde_json::json;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn server(models: &[(&str, f64, f64)], balance: f64) -> MockServer {
    let s = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(models_body(models)))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/balance"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"balance_usd": balance, "payg_enabled": false})),
        )
        .mount(&s)
        .await;
    s
}

fn mk(s: &MockServer, api: &str, max_s: &str, extra: &str) -> (Env, Pipeline) {
    let e = env(&format!("{}/v1", s.uri()), api, max_s, extra);
    let p = Pipeline::new(e.config()).unwrap();
    (e, p)
}

fn req(kind: TaskKind, file: &str) -> DelegateRequest {
    let mut r = DelegateRequest::simple(
        kind,
        "Add docstrings to every function.",
        Declared::Internal,
    );
    r.files = vec![FileRef {
        path: file.into(),
        start_line: None,
        end_line: None,
    }];
    r.write_mode = Some(WriteMode::Inline);
    r
}

async fn posts(s: &MockServer) -> Vec<wiremock::Request> {
    s.received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.method.as_str() == "POST")
        .collect()
}

const CHEAP: (&str, f64, f64) = ("x-coder-small", 0.1, 0.2);
const BIG: (&str, f64, f64) = ("x-coder-big", 1.0, 2.0);

#[tokio::test]
async fn openai_roundtrip_restores_and_sends_no_originals() {
    let s = server(&[CHEAP, BIG], 10.0).await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(Echo)
        .mount(&s)
        .await;
    let (e, p) = mk(&s, "openai", "S1", "");
    let out = p.run(req(TaskKind::Docstring, "src/invoice.py")).await;
    assert_eq!(out.status, Status::Ok, "{out:?}");
    assert_eq!(out.model.as_deref(), Some("x-coder-small"));
    let o = out.output.unwrap();
    assert!(
        o.contains("class AcmeInvoice") && o.contains("def zorblax_discount"),
        "{o}"
    );
    assert!(o.starts_with("<untrusted_output_"));
    let sent = posts(&s).await;
    assert_eq!(sent.len(), 1);
    let body = String::from_utf8_lossy(&sent[0].body).to_lowercase();
    assert!(
        !body.contains("acme") && !body.contains("zorblax"),
        "{body}"
    );
    assert!(!body.contains(FAKE_KEY));
    assert_eq!(
        sent[0]
            .headers
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap(),
        format!("Bearer {FAKE_KEY}")
    );
    assert!(out.savings.unwrap().claude_equiv_usd > out.cost_usd);
    // ledger + audit written; audit holds the sanitized payload only
    let ledger = p.ledger().entries().unwrap();
    assert_eq!(ledger.len(), 1);
    assert_eq!(ledger[0].status, "ok");
    let audit_dir = e.dir.path().join("state");
    let audit: String = std::fs::read_dir(&audit_dir)
        .unwrap()
        .filter_map(|f| f.ok())
        .filter(|f| f.file_name().to_string_lossy().starts_with("audit-"))
        .map(|f| std::fs::read_to_string(f.path()).unwrap())
        .collect();
    assert!(audit.contains("\"sent\":true"));
    assert!(!audit.to_lowercase().contains("zorblax"));
}

#[tokio::test]
async fn anthropic_wire_format() {
    let s = server(&[CHEAP], 10.0).await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(Echo)
        .mount(&s)
        .await;
    let (_e, p) = mk(&s, "anthropic", "S1", "");
    let out = p.run(req(TaskKind::Docstring, "src/invoice.py")).await;
    assert_eq!(out.status, Status::Ok, "{out:?}");
    assert!(out.output.unwrap().contains("AcmeInvoice"));
    let sent = posts(&s).await;
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].headers.get("x-api-key").unwrap().to_str().unwrap(),
        FAKE_KEY
    );
    assert!(sent[0].headers.get("anthropic-version").is_some());
    let body: serde_json::Value = serde_json::from_slice(&sent[0].body).unwrap();
    assert!(body["system"].is_string());
}

#[tokio::test]
async fn infra_pseudonymized_at_s2() {
    let s = server(&[CHEAP], 10.0).await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(Echo)
        .mount(&s)
        .await;
    let (_e, p) = mk(&s, "openai", "S2", "");
    let out = p.run(req(TaskKind::Docstring, "src/billing.py")).await;
    assert_eq!(out.status, Status::Ok, "{out:?}");
    assert_eq!(out.sensitivity.as_deref(), Some("S2"));
    let body = String::from_utf8_lossy(&posts(&s).await[0].body).to_string();
    for orig in [
        "acme-corp.io",
        "10.20.30.40",
        "janedoe",
        "jane.doe",
        "acme.internal",
        "Acme",
    ] {
        assert!(!body.contains(orig), "{orig} leaked: {body}");
    }
    assert!(body.contains("example.net") && body.contains("198.51.100."));
    let o = out.output.unwrap();
    // surrogates inside URLs are never restored (a URL is a possible exfiltration sink)
    assert!(!o.contains("https://billing.acme-corp.io"), "{o}");
    assert!(
        o.contains("https://svc") && o.contains(".example.net:8443/v2/charges"),
        "{o}"
    );
    assert!(out
        .warnings
        .iter()
        .any(|w| w.contains("left unrestored inside URLs")));
    assert!(
        o.contains("jane.doe@acme-corp.io") && o.contains("/Users/janedoe/acme-platform/reports")
    );
}

#[tokio::test]
async fn s2_payload_blocked_for_s1_provider() {
    let s = server(&[CHEAP], 10.0).await;
    let (_e, p) = mk(&s, "openai", "S1", "");
    let out = p.run(req(TaskKind::Docstring, "src/billing.py")).await;
    assert_eq!(out.status, Status::Blocked);
    assert!(out.block_reason.unwrap().contains("S2"));
    assert!(s.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn fake_api_key_means_zero_http_requests() {
    let s = server(&[CHEAP], 10.0).await;
    let (_e, p) = mk(&s, "openai", "S2", "");
    let out = p.run(req(TaskKind::Docstring, "config/settings.py")).await;
    assert_eq!(out.status, Status::Blocked);
    let reason = out.block_reason.unwrap();
    assert!(reason.contains("config/settings.py:2"), "{reason}");
    assert!(!reason.contains("AKIA"));
    assert!(s.received_requests().await.unwrap().is_empty());

    let mut r = DelegateRequest::simple(TaskKind::Snippet, "x", Declared::Public);
    r.inputs = vec![middleman::pipeline::InputText {
        label: "pasted".into(),
        text: "token = ghp_abcdefghijklmnopqrstuvwxyz0123456789".into(),
    }];
    assert_eq!(p.run(r).await.status, Status::Blocked);
    assert!(s.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn deny_glob_and_confidential_block_without_network() {
    let s = server(&[CHEAP], 10.0).await;
    let (_e, p) = mk(&s, "openai", "S2", "");
    let out = p.run(req(TaskKind::Docstring, "secrets/token.py")).await;
    assert_eq!(out.status, Status::Blocked);
    assert!(out.block_reason.unwrap().contains("deny"));
    let mut r = req(TaskKind::Docstring, "src/invoice.py");
    r.declared_sensitivity = Declared::Confidential;
    let out = p.run(r).await;
    assert_eq!(out.status, Status::Blocked);
    assert!(s.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn http_500_is_error_with_ledger_and_no_retry() {
    let s = server(&[CHEAP], 10.0).await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(json!({"error": {"message": format!("boom {FAKE_KEY}")}})),
        )
        .mount(&s)
        .await;
    let (_e, p) = mk(
        &s,
        "openai",
        "S1",
        "[routes.docstring]\nchain = [\"mock/x-coder-small\"]\n",
    );
    let out = p.run(req(TaskKind::Docstring, "src/invoice.py")).await;
    assert_eq!(out.status, Status::Error, "{out:?}");
    let js = serde_json::to_string(&out).unwrap();
    assert!(!js.contains(FAKE_KEY), "key leaked into outcome");
    // the provider body never reaches Claude; it is kept (scrubbed) in the audit log
    assert!(!js.contains("boom"), "{js}");
    assert!(js.contains("HTTP 500"));
    let audit = std::fs::read_dir(_e.dir.path().join("state"))
        .unwrap()
        .flatten()
        .find(|f| f.file_name().to_string_lossy().starts_with("audit-"))
        .map(|f| std::fs::read_to_string(f.path()).unwrap())
        .unwrap();
    assert!(
        audit.contains("boom ***") && !audit.contains(FAKE_KEY),
        "{audit}"
    );
    assert_eq!(posts(&s).await.len(), 1);
    let l = p.ledger().entries().unwrap();
    // the attempt line, then the request-level closing line carrying Claude-side overhead
    assert_eq!(l.len(), 2);
    assert_eq!(l[0].status, "failed");
    assert!(!l[0].is_closing());
    assert!(l[0].latency_ms.is_some());
    assert_eq!(l[1].status, "error");
    assert!(l[1].is_closing());
    assert_eq!(
        l[1].block_reason_category.as_deref(),
        Some("provider_error")
    );
    assert!(l[1].net_savings_usd < 0.0);
    // counted once: one request, one error
    let a = middleman::report::aggregate(&l);
    assert_eq!((a.requests, a.errors, a.attempts), (1, 1, 1));
}

#[tokio::test]
async fn timeout_is_error_and_charged_conservatively() {
    let s2 = server(&[CHEAP], 10.0).await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(3)))
        .mount(&s2)
        .await;
    let (_e, p) = mk(
        &s2,
        "openai",
        "S1",
        "[routes.docstring]\nchain = [\"mock/x-coder-small\"]\n[limits]\nrequest_timeout_s = 1\n",
    );
    let out = p.run(req(TaskKind::Docstring, "src/invoice.py")).await;
    assert_eq!(out.status, Status::Error, "{out:?}");
    assert!(out.error.unwrap().contains("timed out"));
    assert_eq!(posts(&s2).await.len(), 1);
    let l = p.ledger().entries().unwrap();
    assert_eq!(l.len(), 2);
    assert!(l[0].cost_usd > 0.0, "timeout must be charged at worst case");
    assert_eq!(l[0].cost_source, "estimate");
}

#[tokio::test]
async fn escalates_to_next_chain_step() {
    let s = server(&[CHEAP, BIG], 10.0).await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"model": "x-coder-small"})))
        .respond_with(ResponseTemplate::new(503))
        .mount(&s)
        .await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"model": "x-coder-big"})))
        .respond_with(Echo)
        .mount(&s)
        .await;
    let (_e, p) = mk(&s, "openai", "S1", "");
    let out = p.run(req(TaskKind::WriteTests, "src/invoice.py")).await;
    assert_eq!(out.status, Status::Ok, "{out:?}");
    assert_eq!(out.answered_by.as_deref(), Some("auto:code:balanced"));
    assert_eq!(out.attempts.len(), 2);
    assert_eq!(posts(&s).await.len(), 2);
    assert_eq!(p.ledger().entries().unwrap().len(), 2);
}

#[tokio::test]
async fn failed_validation_escalates_then_do_it_yourself() {
    let s = server(&[CHEAP], 10.0).await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{"message": {"content": "no code here"}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 3}
        })))
        .mount(&s)
        .await;
    let (_e, p) = mk(&s, "openai", "S1", "");
    let out = p.run(req(TaskKind::WriteTests, "src/invoice.py")).await;
    assert_eq!(out.status, Status::Blocked);
    assert!(out.block_reason.unwrap().starts_with("do_it_yourself"));
    assert!(out.attempts[0].result.contains("validation"));
}

#[tokio::test]
async fn unknown_price_means_ineligible() {
    let s = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data": [{"id": "x-coder-free"}]})),
        )
        .mount(&s)
        .await;
    let (_e, p) = mk(&s, "openai", "S1", "");
    let out = p.run(req(TaskKind::Docstring, "src/invoice.py")).await;
    assert_eq!(out.status, Status::Blocked);
    assert!(out.block_reason.unwrap().starts_with("do_it_yourself"));
    assert!(posts(&s).await.is_empty());
}

#[tokio::test]
async fn balance_unreadable_or_below_reserve_refuses() {
    let s = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(models_body(&[CHEAP])))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/balance"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&s)
        .await;
    let (_e, p) = mk(&s, "openai", "S1", "");
    let out = p.run(req(TaskKind::Docstring, "src/invoice.py")).await;
    assert_eq!(out.status, Status::Blocked);
    assert!(
        out.attempts[0].result.contains("balance unreadable"),
        "{out:?}"
    );
    assert!(posts(&s).await.is_empty());

    let s = server(&[CHEAP], 1.0001).await;
    let (_e, p) = mk(&s, "openai", "S1", "");
    let out = p.run(req(TaskKind::Docstring, "src/invoice.py")).await;
    assert_eq!(out.status, Status::Blocked);
    assert!(out.attempts[0].result.contains("reserve"));
    assert!(posts(&s).await.is_empty());
}

#[tokio::test]
async fn confirm_and_explicit_modes() {
    let s = server(&[CHEAP], 10.0).await;
    Mock::given(method("POST"))
        .respond_with(Echo)
        .mount(&s)
        .await;
    let (_e, p) = mk(&s, "openai", "S1", "[routing]\nmode = \"confirm\"\n");
    let out = p.run(req(TaskKind::Docstring, "src/invoice.py")).await;
    assert!(out.dry_run && out.needs_confirmation);
    assert!(out.sanitized_payload.is_some());
    assert_eq!(out.plan.len(), 1);
    assert!(posts(&s).await.is_empty());
    let id = out.approval_id.clone().expect("approval id issued");
    // confirmed=true alone (the model's own say-so) is not enough
    let mut r = req(TaskKind::Docstring, "src/invoice.py");
    r.confirmed = true;
    let o = p.run(r).await;
    assert!(o.dry_run && o.needs_confirmation);
    // an unapproved id is refused
    let mut r = req(TaskKind::Docstring, "src/invoice.py");
    r.confirmed = true;
    r.approval_id = Some(id.clone());
    assert_eq!(p.run(r).await.status, Status::Blocked);
    assert!(posts(&s).await.is_empty());
    // a fresh dry run, approved by the user, works exactly once
    let id = p
        .run(req(TaskKind::Docstring, "src/invoice.py"))
        .await
        .approval_id
        .unwrap();
    middleman::approval::Approvals::new(&p.config().state_dir())
        .approve(&id)
        .unwrap();
    let mut r = req(TaskKind::Docstring, "src/invoice.py");
    r.confirmed = true;
    r.approval_id = Some(id.clone());
    assert_eq!(p.run(r.clone()).await.status, Status::Ok);
    assert_eq!(posts(&s).await.len(), 1);
    assert_eq!(
        p.run(r).await.status,
        Status::Blocked,
        "token is single-use"
    );
    assert_eq!(posts(&s).await.len(), 1);

    let s = server(&[CHEAP], 10.0).await;
    Mock::given(method("POST"))
        .respond_with(Echo)
        .mount(&s)
        .await;
    let (_e, p) = mk(&s, "openai", "S1", "[routing]\nmode = \"explicit\"\n");
    let out = p.run(req(TaskKind::Docstring, "src/invoice.py")).await;
    assert_eq!(out.status, Status::Blocked);
    let mut r = req(TaskKind::Docstring, "src/invoice.py");
    r.user_requested = true;
    assert_eq!(p.run(r).await.status, Status::Ok);
}

#[tokio::test]
async fn dry_run_shows_payload_and_plan_without_sending() {
    let s = server(&[CHEAP, BIG], 10.0).await;
    let (_e, p) = mk(&s, "openai", "S1", "");
    let mut r = req(TaskKind::WriteTests, "src/invoice.py");
    r.dry_run = true;
    let out = p.run(r).await;
    assert_eq!(out.status, Status::Ok);
    let payload = out.sanitized_payload.unwrap();
    assert!(!payload.user.to_lowercase().contains("acme"));
    assert_eq!(out.plan.len(), 2);
    assert!(posts(&s).await.is_empty());
}

#[tokio::test]
async fn file_mode_writes_to_disk_and_returns_only_a_summary() {
    let s = server(&[CHEAP], 10.0).await;
    Mock::given(method("POST"))
        .respond_with(Echo)
        .mount(&s)
        .await;
    let (e, p) = mk(&s, "openai", "S1", "");
    let target = e.out_root().join("tests/test_invoice.py");
    let mut r = req(TaskKind::WriteTests, "src/invoice.py");
    r.write_mode = None; // default for write_tests = file
    r.output_path = Some(target.display().to_string());
    let out = p.run(r).await;
    assert_eq!(out.status, Status::Ok, "{out:?}");
    assert_eq!(out.write_mode, WriteMode::File);
    assert!(
        out.output.is_none(),
        "file mode must not return the content"
    );
    let w = out.written.clone().unwrap();
    assert_eq!(w.action, "created");
    let written = std::fs::read_to_string(&target).unwrap();
    assert!(
        written.contains("class AcmeInvoice"),
        "restored identifiers on disk: {written}"
    );
    assert!(!written.contains("```"), "fence stripped");
    let js = serde_json::to_string(&out).unwrap();
    assert!(
        !js.contains("class AcmeInvoice"),
        "summary must not echo the code"
    );

    // second run: existing file is staged with a patch, not overwritten
    let mut r = req(TaskKind::WriteTests, "src/invoice.py");
    r.write_mode = Some(WriteMode::File);
    r.output_path = Some(target.display().to_string());
    std::fs::write(&target, "old\n").unwrap();
    let out = p.run(r).await;
    let w = out.written.unwrap();
    assert_eq!(w.action, "staged");
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "old\n");
    assert!(std::fs::read_to_string(w.patch_path.unwrap())
        .unwrap()
        .contains("-old"));

    // ledger v2 line
    let l = p.ledger().entries().unwrap();
    let ok = &l[0];
    assert_eq!(ok.status, "ok");
    assert_eq!(ok.write_mode, "file");
    assert_eq!(ok.validation, "passed");
    assert_eq!(ok.claude_model, "opus-5.5");
    assert_eq!(ok.trust, "untrusted");
    assert_eq!(ok.chain_step, "auto:code:cheapest");
    assert_eq!(ok.redactions.get("dictionary"), Some(&5));
    assert!(ok.output_bytes.unwrap() > 100 && ok.latency_ms.is_some());
    assert!(
        (ok.net_savings_usd - (ok.claude_equiv_usd - ok.claude_overhead_usd - ok.cost_usd)).abs()
            < 1e-12
    );
}

#[tokio::test]
async fn output_path_outside_roots_is_refused_before_spending() {
    let s = server(&[CHEAP], 10.0).await;
    let (_e, p) = mk(&s, "openai", "S1", "");
    for bad in ["/etc/mm_evil.py", "../escape.py", "src/.env.local"] {
        let mut r = req(TaskKind::WriteTests, "src/invoice.py");
        r.write_mode = Some(WriteMode::File);
        r.output_path = Some(bad.into());
        let out = p.run(r).await;
        assert_eq!(out.status, Status::Blocked, "{bad}");
        assert!(out.block_reason.unwrap().contains("output_path"));
    }
    assert!(s.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn break_even_gate_and_blocked_calls_are_logged() {
    let s = server(&[CHEAP], 10.0).await;
    // common env disables the gate; enforce it here
    let e = env(&format!("{}/v1", s.uri()), "openai", "S1", "");
    let mut cfg = e.config();
    cfg.economics.enforce_break_even = true;
    let p = Pipeline::new(cfg).unwrap();
    let out = p.run(req(TaskKind::Snippet, "src/invoice.py")).await;
    assert_eq!(out.status, Status::Blocked);
    let reason = out.block_reason.unwrap();
    assert!(reason.contains("below break-even"), "{reason}");
    assert!(out.break_even_tokens.unwrap() >= 800);
    // a large caller estimate passes the gate
    let mut r = req(TaskKind::WriteTests, "src/invoice.py");
    r.expected_output_tokens = Some(1500);
    r.dry_run = true;
    assert_eq!(p.run(r).await.status, Status::Ok);
    assert!(posts(&s).await.is_empty());
    // blocked requests are in the ledger with category and cost 0; dry runs are not
    let secret = p.run(req(TaskKind::Docstring, "config/settings.py")).await;
    assert_eq!(secret.status, Status::Blocked);
    let l = p.ledger().entries().unwrap();
    assert_eq!(l.len(), 2);
    assert_eq!(
        l[0].block_reason_category.as_deref(),
        Some("below_break_even")
    );
    assert_eq!(l[0].status, "blocked");
    assert_eq!(l[1].block_reason_category.as_deref(), Some("secret"));
    assert!(l.iter().all(|x| x.cost_usd == 0.0));
}
