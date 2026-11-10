//! End-to-end CLI flow against a temporary HOME: init, provider add (key on stdin, file
//! store), list, statusline, setup claude (dry run, apply, undo), hook on a broken config,
//! remove. The OS keychain is never touched (`MIDDLEMAN_KEYSTORE=file`) and nothing goes
//! to the network (`--no-validate`).

use std::path::Path;

use assert_cmd::Command;

const KEY: &str = "sk-or-v1-0000test0000key0000value";

fn mm(home: &Path) -> Command {
    let mut c = Command::cargo_bin("middleman").unwrap();
    c.env("HOME", home)
        .env("MIDDLEMAN_KEYSTORE", "file")
        .env_remove("OPENROUTER_API_KEY")
        .env_remove("MIDDLEMAN_KEYS_DIR")
        .env_remove("CLAUDE_CODE_SESSION_ID")
        .current_dir(home);
    c
}

fn run(c: &mut Command) -> (String, String) {
    let out = c.output().unwrap();
    let so = String::from_utf8_lossy(&out.stdout).into_owned();
    let se = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(out.status.success(), "stdout:\n{so}\nstderr:\n{se}");
    assert!(!so.contains(KEY) && !se.contains(KEY), "key leaked");
    (so, se)
}

#[test]
fn onboarding_flow_in_temp_home() {
    let d = tempfile::tempdir().unwrap();
    let home = d.path();
    let cfg = home.join(".config/middleman/config.toml");
    let cfg_s = cfg.display().to_string();

    run(mm(home).args([
        "init",
        "--yes",
        "--providers",
        "openrouter",
        "--config",
        &cfg_s,
    ]));
    assert!(cfg.is_file());

    let (_, err) = run(mm(home)
        .args([
            "provider",
            "add",
            "openrouter",
            "--key-stdin",
            "--no-validate",
            "--config",
            &cfg_s,
        ])
        .write_stdin(format!("{KEY}\n")));
    assert!(err.contains("Stored the openrouter key"), "{err}");
    let key_file = home.join(".config/middleman/keys/openrouter");
    assert_eq!(std::fs::read_to_string(&key_file).unwrap(), KEY);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key_file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let text = std::fs::read_to_string(&cfg).unwrap();
    assert!(text.contains("key_source = \"file\""), "{text}");
    assert!(!text.contains(KEY));

    let (out, _) = run(mm(home).args(["provider", "list", "--config", &cfg_s]));
    assert!(out.contains("openrouter") && out.contains("✓"), "{out}");
    assert!(out.contains("keys/openrouter"), "{out}");

    let (out, _) = run(mm(home)
        .args(["statusline", "--config", &cfg_s])
        .write_stdin(r#"{"session_id":"s-1","workspace":{"current_dir":"/"}}"#));
    assert_eq!(out.trim(), "🛡 middleman ✓ openrouter · 0 delegated today");

    let (out, _) = run(mm(home).args(["setup", "claude", "--dry-run", "--config", &cfg_s]));
    assert!(out.contains("+ register the middleman MCP server"), "{out}");
    assert!(!out.contains("mcpServers") && !out.contains('{'), "{out}");
    assert!(!out.contains('\x1b'), "no escape codes when piped: {out:?}");
    assert!(out.contains("dry run: nothing was changed"));
    let (out, _) = run(mm(home).args([
        "setup",
        "claude",
        "--dry-run",
        "--details",
        "--config",
        &cfg_s,
    ]));
    assert!(out.contains("+ mcpServers.middleman"), "{out}");
    assert!(!home.join(".claude.json").exists());
    assert!(!home.join(".claude").exists());

    // without a TTY and without --yes, it refuses to apply
    let o = mm(home)
        .args(["setup", "claude", "--config", &cfg_s])
        .output()
        .unwrap();
    assert!(!o.status.success());
    assert!(!home.join(".claude.json").exists());

    let (out, _) = run(mm(home).args(["setup", "claude", "--yes", "--config", &cfg_s]));
    assert!(out.contains("updated"), "{out}");
    let cj: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(home.join(".claude.json")).unwrap()).unwrap();
    assert_eq!(cj["mcpServers"]["middleman"]["args"][2], cfg_s.as_str());
    let st = std::fs::read_to_string(home.join(".claude/settings.json")).unwrap();
    assert!(st.contains("route --hook") && st.contains("statusline"));
    let (out, _) = run(mm(home).args(["setup", "claude", "--yes", "--config", &cfg_s]));
    assert!(out.contains("nothing to change"), "{out}");

    // a broken project overlay: the hook says "do not delegate", exit 0
    let proj = home.join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join(".middleman.toml"),
        "[budget]\ndaily_usd = 999.0\n",
    )
    .unwrap();
    let (out, _) = run(mm(home)
        .args(["route", "--hook", "--config", &cfg_s])
        .write_stdin(format!(
            r#"{{"prompt":"write unit tests for x.py","cwd":"{}"}}"#,
            proj.display()
        )));
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert!(v["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap()
        .contains("do not delegate"));
    assert!(v["systemMessage"]
        .as_str()
        .unwrap()
        .contains("config invalid"));

    let (out, _) = run(mm(home).args(["setup", "claude", "--undo", "--config", &cfg_s]));
    assert!(out.contains("removed"), "{out}");
    assert!(!home.join(".claude.json").exists());
    assert!(!home.join(".claude/settings.json").exists());

    run(mm(home).args(["watch", "--no-follow", "--config", &cfg_s]));
    let (out, _) = run(mm(home).args(["completions", "zsh"]));
    assert!(out.contains("middleman"));

    run(mm(home).args([
        "provider",
        "remove",
        "openrouter",
        "--yes",
        "--config",
        &cfg_s,
    ]));
    assert!(!key_file.exists());
    assert!(!std::fs::read_to_string(&cfg)
        .unwrap()
        .contains("[providers.openrouter]"));
}

#[test]
fn missing_key_message_is_actionable() {
    let d = tempfile::tempdir().unwrap();
    let home = d.path();
    let cfg = home.join("c.toml");
    std::fs::write(
        &cfg,
        format!(
            "state_dir = \"{0}/state\"\n[paths]\nroots = [\"{0}\"]\n[providers.openrouter]\npreset = \"openrouter\"\n",
            home.display()
        ),
    )
    .unwrap();
    let o = mm(home)
        .args(["balance", "--config", &cfg.display().to_string()])
        .output()
        .unwrap();
    assert!(!o.status.success());
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("run `middleman provider add openrouter`"),
        "{err}"
    );
    let (out, _) = run(mm(home)
        .args(["statusline", "--config", &cfg.display().to_string()])
        .write_stdin("{}"));
    assert!(out.contains("✗ no key for openrouter"), "{out}");
}

/// A mock OpenRouter: `GET /api/v1/key` accepts only `GOOD`, `/api/v1/models` lists models.
fn mock_openrouter(rt: &tokio::runtime::Runtime) -> wiremock::MockServer {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    rt.block_on(async {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/key"))
            .and(header("authorization", format!("Bearer {KEY}").as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {"label": "middleman test", "limit": 10, "limit_remaining": 7.5, "usage": 2.5}
            })))
            .mount(&s)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/key"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&s)
            .await;
        s
    })
}

#[test]
fn non_interactive_init_checks_and_stores_the_key() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = mock_openrouter(&rt);
    let base = format!("{}/api/v1", server.uri());
    let d = tempfile::tempdir().unwrap();
    let home = d.path();
    let cfg = home.join(".config/middleman/config.toml");
    let cfg_s = cfg.display().to_string();

    // no TTY and no --yes: a clear error, nothing written
    let o = mm(home)
        .args(["init", "--config", &cfg_s])
        .output()
        .unwrap();
    assert!(!o.status.success());
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("--yes"), "{err}");
    assert!(!cfg.exists());

    // unknown provider without --base-url
    let o = mm(home)
        .args(["init", "--yes", "--providers", "nope", "--config", &cfg_s])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&o.stderr).contains("--base-url"));
    // a custom remote endpoint needs a key
    let o = mm(home)
        .args([
            "init",
            "--yes",
            "--providers",
            "work",
            "--base-url",
            "https://llm.example.invalid/v1",
            "--config",
            &cfg_s,
        ])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&o.stderr).contains("--key-stdin"));
    assert!(!cfg.exists());

    // a wrong key: plain-words advice, nothing written or stored
    let o = mm(home)
        .env("MIDDLEMAN_TEST_BASE_URL_OPENROUTER", &base)
        .args(["init", "--yes", "--key-stdin", "--config", &cfg_s])
        .write_stdin("sk-or-v1-this-is-the-wrong-key-0000\n")
        .output()
        .unwrap();
    assert!(!o.status.success());
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("rejected this key (HTTP 401)"), "{err}");
    assert!(err.contains("openrouter.ai/settings/keys"), "{err}");
    assert!(!err.contains("wrong-key"));
    assert!(!cfg.exists());
    assert!(!home.join(".config/middleman/keys/openrouter").exists());

    // the right key: OpenRouter is the default provider, confirm the default mode
    let (out, err) = run(mm(home)
        .env("MIDDLEMAN_TEST_BASE_URL_OPENROUTER", &base)
        .args(["init", "--yes", "--key-stdin", "--config", &cfg_s])
        .write_stdin(format!("{KEY}\n")));
    assert!(out.contains("wrote"), "{out}");
    assert!(err.contains("label middleman test"), "{err}");
    let c = middleman::config::Config::load(&cfg).unwrap();
    assert_eq!(c.routing.mode, middleman::config::RoutingMode::Confirm);
    assert_eq!(
        c.providers["openrouter"].key_source,
        Some(middleman::keystore::KeySource::File)
    );
    assert_eq!(
        std::fs::read_to_string(home.join(".config/middleman/keys/openrouter")).unwrap(),
        KEY
    );

    // --list: grouped, no legacy/alias presets, key status without the value
    let (out, _) = run(mm(home).args(["init", "--list", "--config", &cfg_s]));
    assert!(
        out.contains("Recommended") && out.contains("Direct vendors"),
        "{out}"
    );
    assert!(out.find("openrouter").unwrap() < out.find("deepseek").unwrap());
    assert!(!out.contains("yapayzekalab") && !out.contains("YZLAB"));
    assert!(out.contains("✓ key stored"), "{out}");
    assert!(out.contains("— not set"), "{out}");
    let (out2, _) = run(mm(home).args(["provider", "list", "--all", "--config", &cfg_s]));
    assert_eq!(out, out2);

    // an existing config is merged, not overwritten, when flags ask for a change
    let (out, _) = run(mm(home).args([
        "init",
        "--yes",
        "--providers",
        "deepseek",
        "--mode",
        "explicit",
        "--config",
        &cfg_s,
    ]));
    assert!(out.contains("existing config merged"), "{out}");
    let c = middleman::config::Config::load(&cfg).unwrap();
    assert!(c.providers.contains_key("openrouter") && c.providers.contains_key("deepseek"));
    assert_eq!(c.routing.mode, middleman::config::RoutingMode::Explicit);

    // --force starts fresh and keeps a backup
    run(mm(home).args(["init", "--yes", "--force", "--config", &cfg_s]));
    let backups = std::fs::read_dir(home.join(".config/middleman"))
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".bak-")
        })
        .count();
    assert_eq!(backups, 1);
    drop(server);
}
