//! `middleman claude` with a fake `claude` on PATH: Claude stays the brain (login kept), the
//! agent roles point at the local proxy. No network: the proxy child starts but nothing calls
//! it; nothing touches the real keychain.
#![cfg(unix)]

use std::path::PathBuf;
use std::process::Command;

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
        "#!/bin/sh\necho \"FAKE_CLAUDE base=$ANTHROPIC_BASE_URL oauth=${CLAUDE_CODE_OAUTH_TOKEN-unset} haiku=$ANTHROPIC_DEFAULT_HAIKU_MODEL sub=$CLAUDE_CODE_SUBAGENT_MODEL worker=$MIDDLEMAN_WORKER_MODEL opus=${ANTHROPIC_DEFAULT_OPUS_MODEL-unset} args=$*\"\n",
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
}

#[test]
fn launches_with_claude_as_brain_and_agents_on_the_worker() {
    let e = env();
    let o = e.cmd().output().unwrap();
    let t = String::from_utf8_lossy(&o.stdout);
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(o.status.success(), "{t}\n{err}");
    // the proxy is in front, Claude Code keeps its own login and main model
    assert!(t.contains("base=http://127.0.0.1:"), "{t}");
    assert!(
        t.contains("oauth=oauth-xyz") && t.contains("opus=unset"),
        "{t}"
    );
    // only the agent roles are pointed at the worker provider
    assert!(
        t.contains("haiku=mm-cheap-fast") && t.contains("sub=mm-cheap-sub"),
        "{t}"
    );
    assert!(t.contains("worker=z-ai/glm-5.3"), "{t}");
    // the status line is passed for this session only
    assert!(t.contains("--settings"), "{t}");
    // the brain is told its agents are free for the user's plan
    assert!(
        t.contains("--append-system-prompt") && t.contains("does not use the user's Claude plan"),
        "{t}"
    );
    assert!(err.contains("Claude is the brain"), "{err}");
}

#[test]
fn no_mode_options_remain() {
    let e = env();
    for args in [["--mode", "cheap"], ["--pick", "x"]] {
        let o = e.cmd().args(args).output().unwrap();
        assert!(!o.status.success(), "{args:?} should be rejected");
    }
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_middleman"))
        .args(["mode", "cheap"])
        .output()
        .unwrap();
    assert!(!o.status.success());
}
