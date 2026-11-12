//! `middleman claude` mode picker through a pseudo-terminal, with a fake `claude` on PATH.
//! No network: the proxy child starts but nothing calls it; nothing touches the real keychain.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

const DOWN: &str = "\x1b[B";

struct Env {
    _d: tempfile::TempDir,
    home: PathBuf,
    repo: PathBuf,
    cfg: PathBuf,
    bin: PathBuf,
}

fn env() -> Env {
    let d = tempfile::tempdir().unwrap();
    let home = d.path().join("home");
    let repo = home.join("repo");
    let bin = d.path().join("bin");
    for p in [&home, &bin] {
        std::fs::create_dir_all(p).unwrap();
    }
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    let cfg = d.path().join("c.toml");
    std::fs::write(
        &cfg,
        format!(
            "state_dir = \"{0}/state\"\ncache_dir = \"{0}/cache\"\n[paths]\nroots = [\"{0}\"]\n[providers.openrouter]\npreset = \"openrouter\"\n",
            d.path().display()
        ),
    )
    .unwrap();
    let fake = bin.join("claude");
    std::fs::write(
        &fake,
        "#!/bin/sh\necho \"FAKE_CLAUDE base=$ANTHROPIC_BASE_URL oauth=${CLAUDE_CODE_OAUTH_TOKEN-unset} haiku=$ANTHROPIC_DEFAULT_HAIKU_MODEL\"\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    Env {
        _d: d,
        home,
        repo,
        cfg,
        bin,
    }
}

impl Env {
    fn cmd(&self) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_middleman"));
        let path = format!("{}:{}", self.bin.display(), std::env::var("PATH").unwrap());
        c.arg("--config")
            .arg(&self.cfg)
            .args(["claude", "--yes"])
            .current_dir(&self.repo)
            .env("HOME", &self.home)
            .env("PATH", path)
            .env("OPENROUTER_API_KEY", "sk-or-v1-fake0000")
            .env("CLAUDE_CODE_OAUTH_TOKEN", "oauth-xyz")
            .env("MIDDLEMAN_KEYSTORE", "file")
            .env("NO_COLOR", "1")
            .env("TERM", "xterm-256color");
        c
    }
    fn pty(&self) -> rexpect::session::PtySession {
        rexpect::session::spawn_with_options(
            self.cmd(),
            rexpect::reader::Options::new()
                .timeout_ms(Some(20_000))
                .strip_ansi_escape_codes(true),
        )
        .unwrap()
    }
}

fn send(p: &mut rexpect::session::PtySession, s: &str) {
    p.send(s).unwrap();
    p.flush().unwrap();
}

#[test]
fn picker_smart_keeps_login_and_uses_proxy() {
    let e = env();
    let mut p = e.pty();
    p.exp_string("how should this session run?").unwrap();
    p.exp_string("Smart (recommended)").unwrap();
    send(&mut p, "\r");
    p.exp_string("Remember for this repo?").unwrap();
    send(&mut p, "n");
    let out = p.exp_string("haiku=mm-cheap-fast").unwrap();
    assert!(out.contains("base=http://127.0.0.1:"), "{out}");
    assert!(out.contains("oauth=oauth-xyz"), "{out}");
}

#[test]
fn picker_cheap_goes_direct_without_login_and_can_be_remembered() {
    let e = env();
    let mut p = e.pty();
    p.exp_string("Cheap only").unwrap();
    send(&mut p, DOWN);
    send(&mut p, "\r");
    p.exp_string("Remember for this repo?").unwrap();
    send(&mut p, "y");
    let out = p.exp_string("oauth=unset").unwrap();
    assert!(out.contains("base=https://openrouter.ai/api"), "{out}");
    p.exp_eof().unwrap();
    // next launch, no terminal: the remembered mode is used and nothing is asked
    let o = e.cmd().output().unwrap();
    let t = String::from_utf8_lossy(&o.stdout);
    assert!(
        t.contains("base=https://openrouter.ai/api") && t.contains("oauth=unset"),
        "{t}"
    );
    // --mode wins over the remembered choice
    let o = e.cmd().args(["--mode", "smart"]).output().unwrap();
    assert!(String::from_utf8_lossy(&o.stdout).contains("base=http://127.0.0.1:"));
}

#[test]
fn no_terminal_defaults_to_smart_and_claude_mode_is_plain() {
    let e = env();
    let o = e.cmd().output().unwrap();
    let t = String::from_utf8_lossy(&o.stdout);
    assert!(
        t.contains("base=http://127.0.0.1:") && t.contains("oauth=oauth-xyz"),
        "{t}"
    );
    let o = e.cmd().args(["--mode", "claude"]).output().unwrap();
    assert!(String::from_utf8_lossy(&o.stdout).contains("base= oauth=oauth-xyz"));
    let _ = Path::new("");
}
