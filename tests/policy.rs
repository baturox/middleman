//! Policy + routing: table-driven, default deny, declared can't lower detected, routing tiers,
//! unknown price ineligible, pinned steps, context and per-call cap filters.

use middleman::catalog::{Catalog, RawModel};
use middleman::classify::{
    Classification, Classifier, ClassifyInput, Complexity, Declared, RuleClassifier, Sensitivity,
};
use middleman::config::{ClassifyCfg, Config, PiiMode, SecretsMode, Tier};
use middleman::detect::{Category, Finding};
use middleman::policy::{decide, Decision};
use middleman::providers::ModelInfo;
use middleman::routing::{chain_for, plan, Needs};
use middleman::TaskKind;

fn cfg(providers: &str, extra: &str) -> Config {
    let d = std::env::temp_dir();
    Config::from_toml(&format!(
        "[paths]\nroots = [\"{}\"]\n{extra}\n{providers}",
        d.display()
    ))
    .unwrap()
}

const TWO: &str = r#"
[providers.cheap]
api = "openai"
base_url = "https://a.invalid/v1"
key_env = "X_UNSET_1"
max_sensitivity = "S1"
task_kinds = ["write_tests", "docstring"]

[providers.zdr]
api = "openai"
base_url = "https://b.invalid/v1"
key_env = "X_UNSET_2"
trust = "zdr"
max_complexity = "C1"
"#;

fn class(s: Sensitivity, c: Complexity) -> Classification {
    Classification {
        declared: s,
        detected: s,
        effective: s,
        complexity: c,
        reasons: vec![],
    }
}

#[test]
fn table_driven_provider_gate() {
    let c = cfg(TWO, "");
    use Complexity::*;
    use Sensitivity::*;
    let cases: &[(TaskKind, Sensitivity, Complexity, Option<&[&str]>)] = &[
        (TaskKind::WriteTests, S0, C0, Some(&["cheap", "zdr"])),
        (TaskKind::WriteTests, S1, C1, Some(&["cheap", "zdr"])),
        (TaskKind::WriteTests, S2, C1, Some(&["zdr"])),
        (TaskKind::Summarize, S1, C0, Some(&["zdr"])),
        (TaskKind::WriteTests, S3, C0, None),
        (TaskKind::Docstring, S1, C2, None),
    ];
    for (k, s, cx, want) in cases {
        let d = decide(&c, *k, &class(*s, *cx));
        match (want, &d) {
            (Some(w), Decision::Allow { providers }) => {
                assert_eq!(providers, &w.to_vec(), "{k} {s:?}")
            }
            (None, Decision::Block { .. }) => {}
            _ => panic!("{k} {s:?} {cx:?}: got {d:?}"),
        }
    }
}

#[test]
fn default_deny_and_disabled() {
    let c = cfg("", "");
    assert!(!decide(
        &c,
        TaskKind::Snippet,
        &class(Sensitivity::S0, Complexity::C0)
    )
    .is_allow());
    let c = cfg(
        &TWO.replace("trust = \"zdr\"", "trust = \"zdr\"\nenabled = false"),
        "",
    );
    let d = decide(
        &c,
        TaskKind::Summarize,
        &class(Sensitivity::S0, Complexity::C0),
    );
    assert!(!d.is_allow(), "{d:?}");
}

#[test]
fn declared_cannot_lower_detected() {
    let rc = RuleClassifier {
        cfg: ClassifyCfg::default(),
    };
    let f = [Finding::new(Category::Email, "email", 0, 5)];
    let i = ClassifyInput {
        task_kind: TaskKind::Snippet,
        declared: Declared::Public,
        findings: &f,
        payload_chars: 10,
        secrets_mode: SecretsMode::Block,
        pii_mode: PiiMode::Block,
    };
    let r = rc.classify(&i);
    assert_eq!(r.declared, Sensitivity::S0);
    assert_eq!(r.effective, Sensitivity::S2);
    let f = [Finding::new(Category::Secret, "k", 0, 5)];
    let r = rc.classify(&ClassifyInput { findings: &f, ..i });
    assert_eq!(r.effective, Sensitivity::S3);
    // confidential always S3 even with no findings
    let r = rc.classify(&ClassifyInput {
        findings: &[],
        declared: Declared::Confidential,
        ..i
    });
    assert_eq!(r.effective, Sensitivity::S3);
    // large payload bumps complexity; write_tests large -> C2
    let r = rc.classify(&ClassifyInput {
        findings: &[],
        task_kind: TaskKind::WriteTests,
        payload_chars: 20_000,
        ..i
    });
    assert_eq!(r.complexity, Complexity::C2);
}

fn m(provider: &str, id: &str, price: Option<(f64, f64)>, ctx: Option<u64>) -> RawModel {
    RawModel {
        provider: provider.into(),
        info: ModelInfo {
            id: id.into(),
            tier: None,
            modality: Some("text->text".into()),
            status: None,
            context_length: ctx,
            price_in_per_1m: price.map(|p| p.0),
            price_out_per_1m: price.map(|p| p.1),
        },
    }
}

fn needs(q: Tier) -> Needs {
    Needs {
        est_in: 1000,
        max_out: 1000,
        quality: q,
        per_call_cap: 0.05,
    }
}

#[test]
fn routing_tiers_prices_context_and_pins() {
    let c = cfg(
        TWO,
        "[models.\"cheap/pinned-model\"]\nprice_in = 0.5\nprice_out = 0.5\n[routes.docstring]\nchain = [\"auto:code:best\", \"cheap/pinned-model\", \"claude\", \"cheap/never\"]\n",
    );
    let cat = Catalog {
        fetched_at: 0,
        models: vec![
            m("cheap", "a-coder-1", Some((0.1, 0.1)), Some(64_000)),
            m("cheap", "b-coder-2", Some((1.0, 1.0)), Some(64_000)),
            m("cheap", "c-coder-3", Some((2.0, 2.0)), Some(64_000)),
            m("cheap", "d-coder-unpriced", None, Some(64_000)),
            m("cheap", "e-coder-tinyctx", Some((0.01, 0.01)), Some(1_000)),
            m("cheap", "f-coder-expensive", Some((100.0, 100.0)), None),
            m("zdr", "z-coder", Some((0.05, 0.05)), None),
        ],
        errors: vec![],
    };
    let models = cat.resolve(&c);
    let allowed = vec!["cheap".to_string()];

    let chain = chain_for(&c, TaskKind::WriteTests);
    let p = plan(
        &c,
        Some(&cat),
        &models,
        &allowed,
        &chain,
        &needs(Tier::Cheapest),
    );
    let ids: Vec<&str> = p.candidates.iter().map(|x| x.model.as_str()).collect();
    // unpriced, tiny-context, over-cap and not-allowed-provider models never appear
    assert_eq!(ids, vec!["a-coder-1", "c-coder-3"], "{p:?}");
    assert!(p.terminal_claude);

    // quality hint skips the cheapest step
    let p = plan(
        &c,
        Some(&cat),
        &models,
        &allowed,
        &chain,
        &needs(Tier::Balanced),
    );
    assert_eq!(p.candidates[0].step, "auto:code:balanced");

    // custom chain: best, then a config-priced pin not in the catalog, stop at claude
    let chain = chain_for(&c, TaskKind::Docstring);
    let p = plan(
        &c,
        Some(&cat),
        &models,
        &allowed,
        &chain,
        &needs(Tier::Cheapest),
    );
    let ids: Vec<&str> = p.candidates.iter().map(|x| x.model.as_str()).collect();
    assert_eq!(ids, vec!["c-coder-3", "pinned-model"]);
    assert!(p.terminal_claude);

    // nothing allowed -> empty plan -> do it yourself
    let p = plan(&c, Some(&cat), &models, &[], &chain, &needs(Tier::Cheapest));
    assert!(p.candidates.is_empty() && p.terminal_claude);
}
