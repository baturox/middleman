//! `middleman statusline off|on`: removes only middleman's entry, restores a status line it
//! replaced, is remembered by `setup claude` and `--refresh`, and `on` puts it back.
//! Runs against a temp HOME only.

use std::path::Path;
use std::process::Command;

use serde_json::{json, Value};

fn mm(home: &Path, args: &[&str]) -> String {
    let o = Command::new(env!("CARGO_BIN_EXE_middleman"))
        .args(args)
        .env("HOME", home)
        .env("NO_COLOR", "1")
        .env("MIDDLEMAN_KEYSTORE", "file")
        .env("MIDDLEMAN_NO_UPDATE_CHECK", "1")
        .env_remove("MIDDLEMAN_VERBOSE")
        .current_dir(home)
        .output()
        .unwrap();
    let so = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(
        o.status.success(),
        "{args:?}\n{so}\n{}",
        String::from_utf8_lossy(&o.stderr)
    );
    so
}

fn settings(home: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(home.join(".claude/settings.json")).unwrap())
        .unwrap()
}

fn setup_home() -> (tempfile::TempDir, std::path::PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let home = d.path().canonicalize().unwrap();
    let cfg = home.join(".config/middleman/config.toml");
    std::fs::create_dir_all(cfg.parent().unwrap()).unwrap();
    std::fs::write(
        &cfg,
        format!("# mine\n[paths]\nroots = [\"{}\"]\n", home.display()),
    )
    .unwrap();
    std::fs::create_dir_all(home.join(".claude")).unwrap();
    (d, home)
}

#[test]
fn off_removes_only_ours_and_is_remembered_then_on_restores() {
    let (_d, home) = setup_home();
    mm(&home, &["setup", "claude", "--yes"]);
    let st = settings(&home);
    assert!(st["statusLine"]["command"]
        .as_str()
        .unwrap()
        .contains("statusline"));
    let hooks = st["hooks"].clone();

    let so = mm(&home, &["statusline", "off"]);
    assert!(so.contains("status line off"), "{so}");
    let st = settings(&home);
    assert!(st.get("statusLine").is_none(), "{st}");
    assert_eq!(st["hooks"], hooks, "only the status line goes");
    let cfg = std::fs::read_to_string(home.join(".config/middleman/config.toml")).unwrap();
    assert!(
        cfg.contains("# mine") && cfg.contains("enabled = false"),
        "{cfg}"
    );

    // neither a refresh nor a new setup puts it back
    mm(&home, &["setup", "claude", "--refresh", "--yes"]);
    mm(&home, &["setup", "claude", "--yes"]);
    assert!(settings(&home).get("statusLine").is_none());

    let so = mm(&home, &["statusline", "on"]);
    assert!(so.contains("status line on"), "{so}");
    assert!(settings(&home)["statusLine"]["command"]
        .as_str()
        .unwrap()
        .contains("statusline --config"));
    let cfg = std::fs::read_to_string(home.join(".config/middleman/config.toml")).unwrap();
    assert!(cfg.contains("enabled = true"), "{cfg}");
}

#[test]
fn off_restores_a_status_line_setup_replaced() {
    let (_d, home) = setup_home();
    let mine = json!({"type": "command", "command": "~/my-line.sh"});
    std::fs::write(
        home.join(".claude/settings.json"),
        json!({"statusLine": mine}).to_string(),
    )
    .unwrap();
    mm(
        &home,
        &["setup", "claude", "--yes", "--statusline", "combined"],
    );
    assert_ne!(settings(&home)["statusLine"], mine);
    mm(&home, &["statusline", "off"]);
    assert_eq!(settings(&home)["statusLine"], mine);
    // a foreign status line is left alone by `on`
    let so = mm(&home, &["statusline", "on"]);
    assert!(so.contains("left alone"), "{so}");
    assert_eq!(settings(&home)["statusLine"], mine);
}
