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
    assert!(out.contains("+ mcpServers.middleman"), "{out}");
    assert!(out.contains("dry run: nothing was changed"));
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
