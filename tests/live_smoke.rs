//! Live smoke test against the configured gateway. Synthetic fixture only, $0.01 per-call cap.
//! Run explicitly: `cargo test --test live_smoke -- --ignored --nocapture`

mod common;

use middleman::classify::Declared;
use middleman::config::{default_config_path, Config};
use middleman::intake::FileRef;
use middleman::pipeline::{DelegateRequest, Pipeline, Status};
use middleman::TaskKind;

#[tokio::test]
#[ignore = "spends real money (< $0.01); run with --ignored"]
async fn live_docstring_roundtrip() {
    let path = std::env::var("MIDDLEMAN_CONFIG")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| default_config_path());
    let mut cfg = Config::load(&path).expect("user config");
    // never real code: only the synthetic fixture is readable
    let out_dir = tempfile::tempdir().unwrap();
    let out_root = std::fs::canonicalize(out_dir.path()).unwrap();
    cfg.paths.roots = vec![common::fixtures(), out_root.clone()];
    // the synthetic fixture is far below break-even; this run validates plumbing, not savings
    cfg.economics.enforce_break_even = false;
    cfg.paths.allow = vec!["src/invoice.py".into()];
    cfg.redact.dictionary_file = Some(common::fixtures().join("dictionary.txt"));
    cfg.budget.per_call_usd = cfg.budget.per_call_usd.min(0.01);
    cfg.routing.max_attempts = 1;
    cfg.validate().unwrap();
    let p = Pipeline::new(cfg).unwrap();
    let before = p.ledger().entries().unwrap().len();

    let mut r = DelegateRequest::simple(
        TaskKind::Docstring,
        "Add a one-line docstring to each class and function. Return the full file.",
        Declared::Internal,
    );
    r.files = vec![FileRef {
        path: "src/invoice.py".into(),
        start_line: None,
        end_line: None,
    }];
    r.max_output_tokens = Some(400);
    r.max_cost_usd = Some(0.01);
    r.user_requested = true;
    r.purpose = Some("test".into()); // excluded from savings totals
    r.write_mode = Some(middleman::economics::WriteMode::File);
    let target = out_root.join("invoice_documented.py");
    r.output_path = Some(target.display().to_string());
    r.confirmed = true;
    let out = p.run(r).await;
    eprintln!("{}", serde_json::to_string_pretty(&out).unwrap());
    assert_eq!(
        out.status,
        Status::Ok,
        "{:?}",
        out.block_reason.or(out.error)
    );
    assert!(out.output.is_none(), "file mode returns a summary only");
    let o = std::fs::read_to_string(&target).unwrap();
    assert!(
        o.contains("AcmeInvoice") || o.contains("zorblax_discount"),
        "identifiers not restored"
    );
    let last = p.ledger().entries().unwrap().pop().unwrap();
    eprintln!("ledger line: {}", serde_json::to_string(&last).unwrap());
    assert_eq!(last.write_mode, "file");
    assert_eq!(last.status, "ok");
    assert!(out.cost_usd < 0.01);
    assert_eq!(p.ledger().entries().unwrap().len(), before + 1);
}
