//! restore(apply(x)) == x, including proptest; overlapping/nested matches, case variants,
//! collisions, dictionary terms inside identifiers; egress gate accepts the result.

use middleman::detect::{finalize, Detector, Dictionary};
use middleman::egress::{seal, OutboundRequest};
use middleman::pseudo::{apply, Vault};
use proptest::prelude::*;

fn detector() -> Detector {
    let dict = Dictionary::from_terms(["Acme", "AcmeBilling", "Zorblax", "Quuxcorp"]).unwrap();
    Detector::new(
        vec!["/Users/jane/work/acme".into()],
        vec!["github.com".into()],
        Some(dict),
    )
}

fn roundtrip(det: &Detector, text: &str) -> String {
    let fs = finalize(text, det.scan(text));
    let mut v = Vault::new(text);
    let s = apply(text, &fs, &mut v, det.dictionary());
    // the egress gate must accept every pseudonymized payload
    let r = OutboundRequest {
        model: "m".into(),
        system: "s".into(),
        user: s.clone(),
        max_tokens: 1,
    };
    seal(r, &v, det, &[]).unwrap_or_else(|e| panic!("egress rejected {s:?}: {e}"));
    let (back, _) = v.restore(&s);
    assert_eq!(back, text, "sanitized: {s}");
    s
}

#[test]
fn nested_and_overlapping() {
    let det = detector();
    // dictionary term inside a host inside a URL inside an email-like context
    let s = roundtrip(
        &det,
        "see https://api.acme.io/v1 and ops@acme.io, AcmeBillingService, acmebilling, ACMEBILLING",
    );
    assert!(!s.to_lowercase().contains("acme"), "{s}");
    assert!(s.contains("Service"));
}

#[test]
fn case_variants_and_identifiers() {
    let det = detector();
    let s = roundtrip(
        &det,
        "Zorblax zorblax ZORBLAX zOrBlAx get_zorblax_id ZorblaxClient2",
    );
    assert!(!s.to_lowercase().contains("zorblax"));
    assert!(s.contains("get_") && s.contains("_id") && s.contains("Client2"));
}

#[test]
fn collisions_with_surrogate_shapes_in_input() {
    let det = detector();
    roundtrip(
        &det,
        "user1@example.com svc1.example.net 198.51.100.1 /workspace/app/x MM_SECRET_1 real@acme.io 10.9.8.7",
    );
}

#[test]
fn paths_and_ips() {
    let det = detector();
    let s = roundtrip(
        &det,
        "cd /Users/jane/work/acme/src && cat /Users/bob/.bashrc; ping fd00::1:2:3 10.1.1.1",
    );
    assert!(s.contains("/workspace/app/src") && s.contains("/home/user"));
    assert!(!s.contains("bob") && !s.contains("10.1.1.1") && !s.contains("fd00"));
}

#[test]
fn public_hosts_untouched() {
    let det = detector();
    let s = roundtrip(
        &det,
        "clone https://github.com/rust-lang/rust and mail a@example.com",
    );
    assert!(s.contains("https://github.com/rust-lang/rust") && s.contains("a@example.com"));
}

fn token() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("Acme".to_string()),
        Just("AcmeBilling".to_string()),
        Just("acme_ledger".to_string()),
        Just("ZORBLAX".to_string()),
        Just("quuxcorp".to_string()),
        Just("jane.doe@acme-corp.io".to_string()),
        Just("bob@quuxcorp.com".to_string()),
        Just("https://billing.acme-corp.io:8443/x".to_string()),
        Just("db.internal.corp".to_string()),
        Just("10.0.0.5".to_string()),
        Just("172.16.4.2".to_string()),
        Just("/Users/jane/work/acme/src/a.py".to_string()),
        Just("/home/bob".to_string()),
        Just("user1@example.com".to_string()),
        "[a-z]{1,8}".prop_map(|s| s),
        "[A-Z][a-z]{1,6}".prop_map(|s| s),
        "[0-9]{1,3}".prop_map(|s| s),
    ]
}

fn sep() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(" ".to_string()),
        Just(", ".to_string()),
        Just("\n".to_string()),
        Just("(".to_string()),
        Just(") ".to_string()),
        Just(" = \"".to_string()),
        Just("\"; ".to_string()),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]
    #[test]
    fn prop_restore_apply_is_identity(parts in prop::collection::vec((token(), sep()), 1..25)) {
        let text: String = parts.into_iter().map(|(t, s)| t + &s).collect();
        let det = detector();
        let s = roundtrip(&det, &text);
        let lower = s.to_lowercase();
        prop_assert!(!lower.contains("zorblax") && !lower.contains("quuxcorp"));
        prop_assert!(!s.contains("10.0.0.5") && !s.contains("jane.doe"));
    }
}
