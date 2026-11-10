//! `middleman dict suggest` against a temporary HOME and project: read-only without --yes,
//! appends (and wires up `[redact] dictionary_file`) with --yes. No network, no keychain.

use std::path::Path;

use assert_cmd::Command;

fn mm(home: &Path, cwd: &Path) -> Command {
    let mut c = Command::cargo_bin("middleman").unwrap();
    c.env("HOME", home)
        .env("MIDDLEMAN_KEYSTORE", "file")
        .env_remove("OPENROUTER_API_KEY")
        .env("NO_COLOR", "1")
        .current_dir(cwd);
    c
}

#[test]
fn dict_suggest_is_read_only_until_confirmed() {
    let d = tempfile::tempdir().unwrap();
    let home = d.path().canonicalize().unwrap();
    let proj = home.join("zephyrine-ledger");
    std::fs::create_dir_all(proj.join("src")).unwrap();
    std::fs::write(
        proj.join("Cargo.toml"),
        "[package]\nname = \"quasar-ledger\"\nauthors = [\"Mehmet Karaca <mk@zephyrine.io>\"]\n",
    )
    .unwrap();
    std::fs::write(proj.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
    let cfg = home.join(".config/middleman/config.toml");
    let cfg_s = cfg.display().to_string();
    let out = mm(&home, &home)
        .args([
            "init",
            "--yes",
            "--providers",
            "openrouter",
            "--config",
            &cfg_s,
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let dict = home.join(".config/middleman/dictionary.txt");

    // not a terminal, no --yes: lists, writes nothing
    let out = mm(&home, &proj)
        .args(["dict", "suggest", "--config", &cfg_s, "--root"])
        .arg(&proj)
        .output()
        .unwrap();
    let so = String::from_utf8_lossy(&out.stdout).to_string();
    let se = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(out.status.success(), "{se}");
    assert!(
        so.contains("[x] quasar-ledger") && so.contains("Cargo.toml name"),
        "{so}"
    );
    assert!(
        so.contains("[x] zephyrine-ledger") && so.contains("root dir"),
        "{so}"
    );
    assert!(
        so.contains("Mehmet Karaca") && so.contains("zephyrine"),
        "{so}"
    );
    assert!(se.contains("Nothing written"), "{se}");
    assert!(!dict.exists());

    let out = mm(&home, &proj)
        .args(["dict", "suggest", "--yes", "--config", &cfg_s, "--root"])
        .arg(&proj)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = std::fs::read_to_string(&dict).unwrap();
    for t in [
        "quasar-ledger",
        "quasar_ledger",
        "zephyrine-ledger",
        "Mehmet Karaca",
        "zephyrine",
    ] {
        assert!(text.lines().any(|l| l == t), "{t}: {text}");
    }
    let c = std::fs::read_to_string(&cfg).unwrap();
    assert!(c.contains("dictionary_file"), "{c}");
    // the config still loads and the dictionary is picked up by doctor-free paths
    let out = mm(&home, &proj)
        .args(["dict", "suggest", "--config", &cfg_s, "--json", "--root"])
        .arg(&proj)
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v
        .as_array()
        .unwrap()
        .iter()
        .all(|c| c["confidence"] == "low"));
}
