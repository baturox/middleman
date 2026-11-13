//! End-to-end: drive the real `middleman init` wizard through a pseudo-terminal.
//!
//! Temp HOME, file key store (`MIDDLEMAN_KEYSTORE=file`, the OS keychain is never touched)
//! and a wiremock OpenRouter (`MIDDLEMAN_TEST_BASE_URL_OPENROUTER`, loopback only). Flow:
//! user scope → OpenRouter → paste a bad key → 401 advice → paste a good key → keep the
//! automatic model → confirm mode → decline `setup claude` → config written.
//!
//! Run with `--nocapture` to see the transcript.
#![cfg(unix)]

use std::process::Command;

use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const GOOD: &str = "sk-or-v1-good0000pty0000test0000key";
const BAD: &str = "sk-or-v1-bad00000pty0000test0000key";
const DOWN: &str = "\x1b[B";

fn mock(rt: &tokio::runtime::Runtime) -> MockServer {
    rt.block_on(async {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/key"))
            .and(header("authorization", format!("Bearer {GOOD}").as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {"label": "pty test", "limit": 10, "limit_remaining": 7.5, "usage": 2.5}
            })))
            .mount(&s)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/key"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&s)
            .await;
        let model = |id: &str, p: &str, c: &str| {
            serde_json::json!({"id": id, "context_length": 128000,
                "architecture": {"modality": "text->text"},
                "pricing": {"prompt": p, "completion": c}})
        };
        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [{"id": "llama3.3:8b"}, {"id": "qwen3-coder:14b"}]
            })))
            .mount(&s)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/models"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    model("deepseek/deepseek-v4-flash", "0.0000001", "0.0000004"),
                    model("qwen/qwen3-coder", "0.0000002", "0.0000008"),
                ]
            })))
            .mount(&s)
            .await;
        s
    })
}

/// Collects everything the wizard printed while we wait for each needle.
struct Run {
    p: rexpect::session::PtySession,
    transcript: String,
}

/// rexpect turns each byte into one `char`; map UTF-8 text to and from that form.
fn to_bytes_str(s: &str) -> String {
    s.bytes().map(|b| b as char).collect()
}
fn from_bytes_str(s: &str) -> String {
    let bytes: Vec<u8> = s.chars().map(|c| c as u32 as u8).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

impl Run {
    fn expect(&mut self, needle: &str) {
        match self.p.exp_string(&to_bytes_str(needle)) {
            Ok(before) => {
                self.transcript.push_str(&from_bytes_str(&before));
                self.transcript.push_str(needle);
            }
            Err(e) => panic!(
                "waiting for {needle:?}: {e}\n--- transcript so far ---\n{}",
                self.transcript
            ),
        }
    }
    fn send(&mut self, s: &str) {
        self.p.send(s).unwrap();
        self.p.flush().unwrap();
    }
}

fn start(home: &std::path::Path, cwd: &std::path::Path, server: &MockServer) -> Run {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_middleman"));
    cmd.arg("init")
        .current_dir(cwd)
        .env("HOME", home)
        .env("MIDDLEMAN_KEYSTORE", "file")
        .env(
            "MIDDLEMAN_TEST_BASE_URL_OPENROUTER",
            format!("{}/api/v1", server.uri()),
        )
        .env("NO_COLOR", "1")
        .env("TERM", "xterm-256color")
        .env_remove("OPENROUTER_API_KEY")
        .env_remove("MIDDLEMAN_KEYS_DIR")
        .env_remove("CLAUDE_CODE_SESSION_ID");
    let p = rexpect::session::spawn_with_options(
        cmd,
        rexpect::reader::Options::new()
            .timeout_ms(Some(20_000))
            .strip_ansi_escape_codes(true),
    )
    .unwrap();
    Run {
        p,
        transcript: String::new(),
    }
}

impl Run {
    fn finish(&mut self) {
        match self.p.exp_eof() {
            Ok(rest) => self.transcript.push_str(&from_bytes_str(&rest)),
            Err(e) => panic!("no clean exit: {e}\n{}", self.transcript),
        }
    }
}

#[test]
fn wizard_update_existing_config_adds_a_local_provider() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = mock(&rt);
    let d = tempfile::tempdir().unwrap();
    let home = d.path().canonicalize().unwrap();
    let cfg_path = home.join(".config/middleman/config.toml");
    std::fs::create_dir_all(cfg_path.parent().unwrap()).unwrap();
    std::fs::write(
        &cfg_path,
        format!(
            "# my notes\n[paths]\nroots = [\"{}\"]\n\n[routing]\nmode = \"confirm\"\n\n[providers.openrouter]\npreset = \"openrouter\"\n",
            home.display()
        ),
    )
    .unwrap();

    let mut r = start(&home, &home, &server);
    r.expect("You already have a middleman config");
    r.expect("no key yet");
    r.expect("What do you want to do?");
    r.expect("Start fresh");
    r.send(DOWN);
    r.send("\r"); // Update
    r.expect("Install for");
    r.expect("Only this project");
    r.send("\r"); // user
    r.expect("Pick a provider");
    r.expect("Custom URL");
    for _ in 0..13 {
        r.send(DOWN); // ... Ollama, the first local entry
    }
    r.send("\r");
    r.expect("Ollama server URL");
    r.send(&format!("{}/v1\r", server.uri()));
    r.expect("Ollama is running: 2 models");
    r.expect("Add another provider?");
    r.send("n");
    r.expect("When may Claude delegate?");
    r.expect("Only when I say so (explicit)");
    r.send(DOWN);
    r.send("\r"); // Automatic
    r.expect("Keep middleman up to date");
    r.expect("never check");
    r.send(DOWN);
    r.send("\r"); // update automatically
    r.expect("step 4 of 4 · Done");
    r.expect("Protect your company names");
    r.expect("Scan this project for names now?");
    r.send("n");
    r.expect("Connect to Claude Code now?");
    r.send("n");
    r.finish();
    eprintln!("--- update transcript ---\n{}", r.transcript);

    let text = std::fs::read_to_string(&cfg_path).unwrap();
    assert!(text.contains("# my notes"), "comments are kept:\n{text}");
    let c = middleman::config::Config::load(&cfg_path).unwrap();
    assert_eq!(c.routing.mode, middleman::config::RoutingMode::Auto);
    assert_eq!(c.update.mode(), middleman::config::UpdateMode::Auto);
    assert!(c.providers.contains_key("openrouter"));
    assert_eq!(
        c.providers["ollama"].base_url,
        format!("{}/v1", server.uri())
    );
    assert!(!home.join(".claude.json").exists());
}

#[test]
fn wizard_bad_key_then_good_key_writes_config() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = mock(&rt);
    let d = tempfile::tempdir().unwrap();
    let home = d.path().canonicalize().unwrap();
    let proj = home.join("my-repo");
    std::fs::create_dir_all(proj.join(".git")).unwrap();
    let mut r = start(&home, &proj, &server);

    r.expect("step 1 of 4 · Where to install");
    r.expect("Install for");
    r.expect("Only this project");
    r.send("\r"); // All my projects (user)

    r.expect("step 2 of 4 · Provider");
    r.expect("Pick a provider");
    r.expect("Custom URL");
    r.send("\r"); // OpenRouter (first, default)

    r.expect("openrouter.ai/settings/keys");
    r.expect("How do you want to connect OpenRouter?");
    r.expect("Paste an API key");
    r.send(DOWN);
    r.send("\r");

    r.expect("Paste your OpenRouter API key (hidden)");
    r.send(&format!("{BAD}\n"));
    r.expect("rejected this key (HTTP 401)");
    r.expect("wrong, incomplete or revoked");
    r.expect("What now?");
    r.expect("Skip for now");
    r.send("\r"); // default for a 401: "Paste a different key"

    r.expect("Paste your OpenRouter API key (hidden)");
    r.send(&format!("{GOOD}\n"));
    r.expect("OpenRouter works");
    r.expect("Key stored in");
    r.expect("Default model for coding jobs");
    r.expect("qwen/qwen3-coder");
    r.send("\r"); // Automatic
    r.expect("Add another provider?");
    r.send("n");

    r.expect("step 3 of 4 · Routing mode");
    r.expect("When may Claude delegate?");
    r.expect("Only when I say so (explicit)");
    r.send("\r"); // Ask me each time (confirm), the default
    r.expect("Keep middleman up to date");
    r.expect("never check");
    r.send("\r"); // notify me, the default

    r.expect("step 4 of 4 · Done");
    r.expect("Protect your company names");
    r.expect("Scan this project for names now?");
    r.send("n");
    r.expect("Connect to Claude Code now?");
    r.send("n");
    r.expect("middleman setup claude");
    r.finish();
    eprintln!("--- wizard transcript ---\n{}", r.transcript);

    // nothing secret on screen
    assert!(!r.transcript.contains(GOOD) && !r.transcript.contains(BAD));
    // config written: OpenRouter with a stored key, confirm mode, this repo readable
    let cfg_path = home.join(".config/middleman/config.toml");
    let c = middleman::config::Config::load(&cfg_path).unwrap();
    assert_eq!(c.routing.mode, middleman::config::RoutingMode::Confirm);
    assert_eq!(c.update.mode(), middleman::config::UpdateMode::Notify);
    let or = &c.providers["openrouter"];
    assert_eq!(or.key_source, Some(middleman::keystore::KeySource::File));
    assert!(or.model.is_none());
    // user scope: the readable root is whichever project the session is in, not a fixed path
    assert!(c.project_root_placeholder);
    let in_proj = middleman::config::Config::load_in(&cfg_path, &proj).unwrap();
    assert_eq!(
        in_proj.paths.roots,
        vec![std::fs::canonicalize(&proj).unwrap()]
    );
    assert!(std::fs::read_to_string(&cfg_path)
        .unwrap()
        .contains(middleman::config::PROJECT_ROOT_PLACEHOLDER));
    let text = std::fs::read_to_string(&cfg_path).unwrap();
    assert!(!text.contains(GOOD));
    assert_eq!(
        std::fs::read_to_string(home.join(".config/middleman/keys/openrouter")).unwrap(),
        GOOD
    );
    // declined `setup claude`: Claude Code's files are untouched
    assert!(!home.join(".claude.json").exists());
    assert!(!home.join(".claude").exists());
    // user scope: no project overlay
    assert!(!proj.join(".middleman.toml").exists());
}
