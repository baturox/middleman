//! `middleman upgrade` and `setup claude --refresh` end to end, against a copy of the built
//! binary in a temp dir, a temp HOME, a fake `gh` and a wiremock "GitHub"
//! (`MIDDLEMAN_TEST_BASE_URL_GITHUB`, loopback only). Nothing touches the network, the real
//! HOME or the keychain.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Output;

use middleman::upgrade::{archive_stem, sha256_hex, TARGET};
use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TAG: &str = "v9.9.9";

struct Fx {
    _dir: tempfile::TempDir,
    home: PathBuf,
    bin: PathBuf,
    exe: PathBuf,
    /// PATH for the child: only the fake `gh`.
    path_dir: PathBuf,
    gh_log: PathBuf,
}

fn script(p: &Path, body: &str) {
    std::fs::write(p, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn built() -> PathBuf {
    assert_cmd::cargo::cargo_bin("middleman")
}

fn fixture() -> Fx {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let home = root.join("home");
    let bin = root.join("bin");
    let path_dir = root.join("path");
    for d in [&home, &bin, &path_dir] {
        std::fs::create_dir_all(d).unwrap();
    }
    let exe = bin.join("middleman");
    std::fs::copy(built(), &exe).unwrap();
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o751)).unwrap();
    let gh_log = root.join("gh-argv");
    fake_gh(&path_dir, &gh_log, 0);
    Fx {
        _dir: dir,
        home,
        bin,
        exe,
        path_dir,
        gh_log,
    }
}

fn fake_gh(dir: &Path, log: &Path, code: i32) {
    script(
        &dir.join("gh"),
        &format!(
            "[ \"$1\" = auth ] && exit 0\nfor a in \"$@\"; do echo \"$a\" >> '{}'; done\n[ {code} = 0 ] || echo 'no matching attestations' >&2\nexit {code}",
            log.display()
        ),
    );
}

/// The release's `middleman`: a script that reports `version` and logs other calls.
fn fake_binary(version: &str) -> String {
    format!(
        "#!/bin/sh\ncase \"$1\" in\n  --version) echo \"middleman {version}\" ;;\n  *) echo \"$*\" >> \"$HOME/fake-calls\"; echo \"  (new binary) $*\" ;;\nesac\n"
    )
}

fn targz(stem: &str, bin: &[u8]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_gnu();
    h.set_entry_type(tar::EntryType::Directory);
    h.set_mode(0o755);
    h.set_size(0);
    b.append_data(&mut h, format!("{stem}/"), &[][..]).unwrap();
    for (name, data) in [("README.md", &b"readme"[..]), ("middleman", bin)] {
        let mut h = tar::Header::new_gnu();
        h.set_mode(0o755);
        h.set_size(data.len() as u64);
        b.append_data(&mut h, format!("{stem}/{name}"), data)
            .unwrap();
    }
    let tar = b.into_inner().unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    std::io::Write::write_all(&mut gz, &tar).unwrap();
    gz.finish().unwrap()
}

/// Serve release `TAG` with `archive`; `sums` overrides the SHA256SUMS.txt body.
async fn github(archive: Vec<u8>, sums: Option<String>) -> MockServer {
    let s = MockServer::start().await;
    let asset = format!("{}.tar.gz", archive_stem(TAG, TARGET));
    let sums = sums.unwrap_or_else(|| {
        format!(
            "{}  {asset}\n{}  middleman-{TAG}-other.tar.gz\n",
            sha256_hex(&archive),
            "0".repeat(64)
        )
    });
    Mock::given(method("GET"))
        .and(path("/repos/baturox/middleman/releases/latest"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tag_name": TAG,
            "html_url": "https://evil.example/notes",
            "body": "## What's changed\n* faster hook\n\u{1b}]0;pwned\u{7}* title escape\n\n* fixes",
        })))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/baturox/middleman/releases/download/{TAG}/{asset}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(archive))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/baturox/middleman/releases/download/{TAG}/SHA256SUMS.txt"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_string(sums))
        .mount(&s)
        .await;
    s
}

fn release_archive(version: &str) -> Vec<u8> {
    targz(&archive_stem(TAG, TARGET), fake_binary(version).as_bytes())
}

async fn run(fx: &Fx, exe: &Path, base: &str, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut c = std::process::Command::new(exe);
    c.args(args)
        .env_clear()
        .env("HOME", &fx.home)
        .env("PATH", &fx.path_dir)
        .env("MIDDLEMAN_TEST_BASE_URL_GITHUB", base)
        .env("MIDDLEMAN_KEYSTORE", "file")
        .env("MIDDLEMAN_NO_UPDATE_CHECK", "1")
        .env("MIDDLEMAN_SL_NO_REFRESH", "1")
        .env("NO_COLOR", "1")
        .current_dir(&fx.home);
    for (k, v) in env {
        c.env(k, v);
    }
    let out = tokio::task::spawn_blocking(move || c.output().unwrap())
        .await
        .unwrap();
    eprintln!(
        "--- {args:?}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn text(o: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

fn files_in(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[tokio::test(flavor = "multi_thread")]
async fn upgrade_verifies_replaces_keeps_prev_and_refreshes_wiring() {
    let fx = fixture();
    let s = github(release_archive("9.9.9"), None).await;
    let original = std::fs::read(&fx.exe).unwrap();
    let out = run(&fx, &fx.exe, &s.uri(), &["upgrade", "--yes"], &[]).await;
    let (so, se) = text(&out);
    assert!(out.status.success(), "{so}\n{se}");
    let cur = env!("CARGO_PKG_VERSION");
    // quiet by default: the result line, then the new binary's own refresh output
    let cfg = fx.home.join(".config/middleman/config.toml");
    assert_eq!(
        so,
        format!(
            "✓ middleman {cur} → 9.9.9 (verified)\n  (new binary) setup claude --refresh --yes --config {}\n",
            cfg.display()
        )
    );
    assert_eq!(se, "", "no warnings");

    // replaced, mode kept, previous kept as .prev, nothing else left behind
    assert_eq!(
        std::fs::read_to_string(&fx.exe).unwrap(),
        fake_binary("9.9.9")
    );
    assert_eq!(
        std::fs::metadata(&fx.exe).unwrap().permissions().mode() & 0o7777,
        0o751
    );
    assert_eq!(
        std::fs::read(fx.bin.join("middleman.prev")).unwrap(),
        original
    );
    assert_eq!(files_in(&fx.bin), vec!["middleman", "middleman.prev"]);

    // gh got the archive path as one argument, no shell
    let argv = std::fs::read_to_string(&fx.gh_log).unwrap();
    let argv: Vec<&str> = argv.lines().collect();
    assert_eq!(argv.len(), 5, "{argv:?}");
    assert_eq!(&argv[..2], &["attestation", "verify"]);
    assert!(argv[2].ends_with(&format!("{}.tar.gz", archive_stem(TAG, TARGET))));
    assert_eq!(&argv[3..], &["--repo", "baturox/middleman"]);
    assert!(!Path::new(argv[2]).exists(), "temp archive removed");

    // the NEW binary was asked to refresh the wiring
    let calls = std::fs::read_to_string(fx.home.join("fake-calls")).unwrap();
    assert!(
        calls.starts_with("setup claude --refresh --yes --config "),
        "{calls}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn verbose_upgrade_shows_every_step() {
    let fx = fixture();
    let s = github(release_archive("9.9.9"), None).await;
    let out = run(
        &fx,
        &fx.exe,
        &s.uri(),
        &["upgrade", "--yes", "--verbose"],
        &[],
    )
    .await;
    let (so, se) = text(&out);
    assert!(out.status.success(), "{so}\n{se}");
    let cur = env!("CARGO_PKG_VERSION");
    assert!(so.contains(&format!("middleman v{cur} -> {TAG}")), "{so}");
    assert!(so.contains("https://github.com/baturox/middleman/releases/tag/v9.9.9"));
    assert!(
        !so.contains("evil.example"),
        "the API's html_url is not used"
    );
    assert!(
        so.contains("* faster hook") && so.contains("* title escape"),
        "{so}"
    );
    assert!(
        !so.contains('\u{1b}') && !so.contains('\u{7}') && !so.contains("pwned"),
        "{so:?}"
    );
    for want in [
        "checksum ok",
        "provenance verified",
        "the new binary runs and reports v9.9.9",
        "`middleman upgrade --rollback` restores it",
        "(new binary) setup claude --refresh --yes --verbose --config",
        &format!("✓ middleman {cur} → 9.9.9 (verified)"),
    ] {
        assert!(so.contains(want), "{want}: {so}");
    }
    assert!(!so.contains("/mcp"), "the MCP server re-executes itself");
    // MIDDLEMAN_VERBOSE=1 does the same
    let fx = fixture();
    let out = run(
        &fx,
        &fx.exe,
        &s.uri(),
        &["upgrade", "--yes"],
        &[("MIDDLEMAN_VERBOSE", "1")],
    )
    .await;
    assert!(text(&out).0.contains("checksum ok"));
}

#[tokio::test(flavor = "multi_thread")]
async fn logged_out_gh_is_quiet() {
    let fx = fixture();
    script(
        &fx.path_dir.join("gh"),
        "[ \"$1\" = auth ] && exit 1\nexit 1",
    );
    let s = github(release_archive("9.9.9"), None).await;
    let out = run(
        &fx,
        &fx.exe,
        &s.uri(),
        &["upgrade", "--yes", "--no-wiring"],
        &[],
    )
    .await;
    let (so, se) = text(&out);
    assert!(out.status.success(), "{so}\n{se}");
    assert_eq!(se, "");
    assert!(so.starts_with("✓ middleman "), "{so}");
    // required: now fatal
    let fx = fixture();
    script(
        &fx.path_dir.join("gh"),
        "[ \"$1\" = auth ] && exit 1\nexit 1",
    );
    let out = run(
        &fx,
        &fx.exe,
        &s.uri(),
        &["upgrade", "--yes", "--require-attestation"],
        &[],
    )
    .await;
    assert!(!out.status.success());
    assert!(text(&out).1.contains("gh is not logged in"));
}

#[tokio::test(flavor = "multi_thread")]
async fn tampered_or_wrong_releases_change_nothing() {
    let fx = fixture();
    let original = std::fs::read(&fx.exe).unwrap();
    let asset = format!("{}.tar.gz", archive_stem(TAG, TARGET));
    type Case<'a> = (&'a str, MockServer, Vec<(&'a str, &'a str)>, &'a str);
    let cases: Vec<Case> = vec![
        (
            "checksum mismatch",
            github(
                release_archive("9.9.9"),
                Some(format!("{}  {asset}\n", "ab".repeat(32))),
            )
            .await,
            vec![],
            "checksum mismatch",
        ),
        (
            "no checksum entry",
            github(
                release_archive("9.9.9"),
                Some(format!("{}  something-else.tar.gz\n", "ab".repeat(32))),
            )
            .await,
            vec![],
            "has no entry for",
        ),
        (
            "wrong version inside",
            github(release_archive("9.9.8"), None).await,
            vec![],
            "reports version 9.9.8, expected 9.9.9",
        ),
        (
            "attestation required and failing",
            github(release_archive("9.9.9"), None).await,
            vec![("MIDDLEMAN_REQUIRE_ATTESTATION", "1")],
            "attestation verification failed",
        ),
    ];
    for (what, s, env, want) in cases {
        if what.starts_with("attestation") {
            fake_gh(&fx.path_dir, &fx.gh_log, 1);
        }
        let out = run(&fx, &fx.exe, &s.uri(), &["upgrade", "--yes"], &env).await;
        let (so, se) = text(&out);
        assert!(!out.status.success(), "{what}: {so}");
        assert!(se.contains(want), "{what}: {se}");
        assert_eq!(std::fs::read(&fx.exe).unwrap(), original, "{what}");
        assert_eq!(files_in(&fx.bin), vec!["middleman"], "{what}");
    }
    // without the requirement a failed attestation is still fatal: gh ran and said no
    let s = github(release_archive("9.9.9"), None).await;
    let out = run(&fx, &fx.exe, &s.uri(), &["upgrade", "--yes"], &[]).await;
    let (so, se) = text(&out);
    assert!(!out.status.success(), "{so}");
    assert!(se.contains("attestation verification failed"), "{se}");
    assert_eq!(std::fs::read(&fx.exe).unwrap(), original);
    // --no-wiring
    fake_gh(&fx.path_dir, &fx.gh_log, 0);
    let out = run(
        &fx,
        &fx.exe,
        &s.uri(),
        &["upgrade", "--yes", "--no-wiring"],
        &[],
    )
    .await;
    let (so, se) = text(&out);
    assert!(out.status.success(), "{so}\n{se}");
    assert!(so.contains("Skipped the wiring refresh"));
    assert!(!fx.home.join("fake-calls").exists(), "--no-wiring");
}

#[tokio::test(flavor = "multi_thread")]
async fn check_exit_codes_and_daily_cache() {
    let fx = fixture();
    let s = github(release_archive("9.9.9"), None).await;
    let out = run(&fx, &fx.exe, &s.uri(), &["upgrade", "--check"], &[]).await;
    let (so, _) = text(&out);
    assert_eq!(out.status.code(), Some(10), "{so}");
    assert!(so.contains(&format!(
        "installed: middleman v{}",
        env!("CARGO_PKG_VERSION")
    )));
    assert!(so.contains("latest:    v9.9.9 (release notes: https://github.com/baturox/middleman/releases/tag/v9.9.9)"));
    assert!(so.contains("update available: run `middleman upgrade`"));

    // the background form: silent, writes the cache, releases the lock
    let state = fx.home.join(".local/state/middleman");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::write(state.join("update-check.lock"), "").unwrap();
    let out = run(
        &fx,
        &fx.exe,
        &s.uri(),
        &["upgrade", "--check", "--quiet", "--write-cache"],
        &[],
    )
    .await;
    assert_eq!(out.status.code(), Some(10));
    assert!(out.stdout.is_empty());
    let c: Value =
        serde_json::from_str(&std::fs::read_to_string(state.join("update-check.json")).unwrap())
            .unwrap();
    assert_eq!(c["latest_version"], "v9.9.9");
    assert!(c["checked_at"].as_i64().unwrap() > 0);
    assert!(!state.join("update-check.lock").exists());

    // an older latest release: this dev build is ahead, exit 0
    let old = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/baturox/middleman/releases/latest"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"tag_name": "v0.0.1"})))
        .mount(&old)
        .await;
    let out = run(&fx, &fx.exe, &old.uri(), &["upgrade", "--check"], &[]).await;
    let (so, _) = text(&out);
    assert_eq!(out.status.code(), Some(0));
    assert!(so.contains("up to date (this build is newer than the latest release)"));
    let out = run(&fx, &fx.exe, &old.uri(), &["upgrade", "--yes"], &[]).await;
    assert!(out.status.success());
    assert!(text(&out)
        .0
        .contains("up to date (the latest release is v0.0.1)"));
    assert_eq!(files_in(&fx.bin), vec!["middleman"]);

    // a non-loopback override is ignored (it would be the real API): prove it by checking
    // that an https override never reaches the mock
    assert!(middleman::upgrade::Endpoints::local("https://127.0.0.1:1").is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn rollback_swaps_prev_back() {
    let fx = fixture();
    let prev = fx.bin.join("middleman.prev");
    let original = std::fs::read(&fx.exe).unwrap();
    std::fs::write(&prev, fake_binary("0.2.0")).unwrap();
    std::fs::set_permissions(&prev, std::fs::Permissions::from_mode(0o755)).unwrap();
    let out = run(
        &fx,
        &fx.exe,
        "http://127.0.0.1:9",
        &["upgrade", "--rollback", "--yes"],
        &[],
    )
    .await;
    let (so, se) = text(&out);
    assert!(out.status.success(), "{so}\n{se}");
    assert!(so.starts_with("✓ Restored middleman v0.2.0"), "{so}");
    assert_eq!(
        std::fs::read_to_string(&fx.exe).unwrap(),
        fake_binary("0.2.0")
    );
    assert_eq!(std::fs::read(&prev).unwrap(), original);
    assert_eq!(files_in(&fx.bin), vec!["middleman", "middleman.prev"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn cargo_and_brew_installs_are_not_touched() {
    let fx = fixture();
    for (dir, want) in [
        (
            fx.home.join(".cargo/bin"),
            "cargo install --git https://github.com/baturox/middleman --locked --force",
        ),
        (
            fx.home.join("brew/Cellar/middleman/0.2.0/bin"),
            "brew upgrade middleman",
        ),
    ] {
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("middleman");
        std::fs::copy(built(), &exe).unwrap();
        let before = std::fs::read(&exe).unwrap();
        // the port is closed: a refusal must come before any network call
        let out = run(&fx, &exe, "http://127.0.0.1:9", &["upgrade", "--yes"], &[]).await;
        let (_, se) = text(&out);
        assert_eq!(out.status.code(), Some(1), "{se}");
        assert!(se.contains(want), "{se}");
        assert_eq!(std::fs::read(&exe).unwrap(), before);
        assert_eq!(files_in(&dir), vec!["middleman"]);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn setup_claude_refresh_migrates_0_2_0_wiring() {
    let fx = fixture();
    let home = &fx.home;
    let proj = home.join("proj");
    std::fs::create_dir_all(home.join(".claude")).unwrap();
    std::fs::create_dir_all(&proj).unwrap();
    let old = "/old/bin/middleman";
    let cfg = home.join(".config/middleman/config.toml");
    let claude_json = json!({"numStartups": 7, "mcpServers": {
        "middleman": {"type": "stdio", "command": old, "args": ["mcp", "--config", cfg], "env": {}},
        "github": {"command": "npx", "args": ["-y", "gh-mcp"]}}});
    std::fs::write(home.join(".claude.json"), claude_json.to_string()).unwrap();
    let settings = json!({
        "permissions": {"allow": ["mcp__middleman__delegate_task", "mcp__middleman__middleman_status"]},
        "hooks": {"UserPromptSubmit": [
            {"hooks": [{"type": "command", "command": "~/bin/notify.sh", "timeout": 5}]},
            {"hooks": [{"type": "command", "command": format!("{old} route --hook --config {}", cfg.display()), "timeout": 5}]}
        ]},
        "statusLine": {"type": "command", "command": format!("{old} statusline --config {}", cfg.display()), "padding": 0}
    });
    let settings_text = serde_json::to_string_pretty(&settings).unwrap();
    std::fs::write(home.join(".claude/settings.json"), &settings_text).unwrap();
    std::fs::write(
        proj.join(".mcp.json"),
        json!({"mcpServers": {"middleman": {"type": "stdio", "command": old, "args": ["mcp", "--config", cfg]}}}).to_string(),
    )
    .unwrap();
    let proj_settings =
        r#"{"statusLine": {"type": "command", "command": "node ~/.claude/line.mjs"}}"#;
    std::fs::create_dir_all(proj.join(".claude")).unwrap();
    std::fs::write(proj.join(".claude/settings.json"), proj_settings).unwrap();

    let exe = fx.exe.display().to_string();
    let refresh = |extra: &[&str]| {
        let mut c = std::process::Command::new(&fx.exe);
        c.args(["setup", "claude", "--refresh", "--yes"])
            .args(extra)
            .env("HOME", home)
            .env("NO_COLOR", "1")
            .env_remove("MIDDLEMAN_VERBOSE")
            .current_dir(&proj);
        let out = c.output().unwrap();
        let (so, se) = text(&out);
        eprintln!("{so}\n{se}");
        assert!(out.status.success(), "{so}\n{se}");
        so
    };
    // --dry-run --verbose shows the diff and changes nothing
    let so = refresh(&["--dry-run", "--verbose"]);
    assert!(so.contains("timeout 5 s -> 150 s"), "{so}");
    assert!(so.contains("MCP server: now starts"), "{so}");
    assert_eq!(
        std::fs::read_to_string(home.join(".claude/settings.json")).unwrap(),
        settings_text
    );
    // the quiet default: one line
    let so = refresh(&[]);
    assert_eq!(
        so,
        "✓ Claude Code settings updated (backup kept; undo: middleman setup claude --undo)\n"
    );

    let read = |p: PathBuf| -> Value {
        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
    };
    let cj = read(home.join(".claude.json"));
    assert_eq!(cj["numStartups"], 7);
    assert_eq!(
        cj["mcpServers"]["github"],
        claude_json["mcpServers"]["github"]
    );
    assert_eq!(cj["mcpServers"]["middleman"]["command"], exe);
    assert_eq!(
        cj["mcpServers"]["middleman"]["args"],
        json!(["mcp", "--config", cfg])
    );
    let st = read(home.join(".claude/settings.json"));
    let ups = &st["hooks"]["UserPromptSubmit"];
    assert_eq!(
        ups[0], settings["hooks"]["UserPromptSubmit"][0],
        "unrelated hook untouched"
    );
    assert_eq!(ups[1]["hooks"][0]["timeout"], 150);
    assert_eq!(
        ups[1]["hooks"][0]["command"],
        format!("{exe} route --hook --config {}", cfg.display())
    );
    assert_eq!(
        st["statusLine"]["command"],
        format!("{exe} statusline --config {}", cfg.display())
    );
    assert_eq!(st["permissions"], settings["permissions"]);
    assert_eq!(
        read(proj.join(".mcp.json"))["mcpServers"]["middleman"]["command"],
        exe
    );
    assert_eq!(
        std::fs::read_to_string(proj.join(".claude/settings.json")).unwrap(),
        proj_settings,
        "a foreign status line is not touched"
    );
    // the backup holds the 0.2.0 file byte for byte
    let backups = home.join(".local/state/middleman/backups");
    let found = walk(&backups)
        .into_iter()
        .any(|p| std::fs::read_to_string(&p).is_ok_and(|t| t == settings_text));
    assert!(found, "0.2.0 settings.json backed up");

    // second run: nothing to do (one line)
    assert_eq!(
        refresh(&[]),
        "✓ Claude Code settings are current (nothing to refresh)\n"
    );
}

#[test]
fn verbose_refresh_lists_backups() {
    let d = tempfile::tempdir().unwrap();
    let home = d.path().canonicalize().unwrap();
    std::fs::create_dir_all(home.join(".claude")).unwrap();
    std::fs::write(
        home.join(".claude/settings.json"),
        r#"{"statusLine": {"type": "command", "command": "/old/bin/middleman statusline"}}"#,
    )
    .unwrap();
    let out = std::process::Command::new(built())
        .args(["setup", "claude", "--refresh", "--yes", "--verbose"])
        .env("HOME", &home)
        .env("NO_COLOR", "1")
        .current_dir(&home)
        .output()
        .unwrap();
    let (so, se) = text(&out);
    assert!(out.status.success(), "{so}\n{se}");
    assert!(so.contains("backed up ~/.claude/settings.json"), "{so}");
    assert!(so.contains("updated ~/.claude/settings.json"), "{so}");
    assert!(
        so.ends_with(
            "✓ Claude Code settings updated (backup kept; undo: middleman setup claude --undo)\n"
        ),
        "{so}"
    );
    assert!(!so.contains("/mcp"), "{so}");
}

fn walk(d: &Path) -> Vec<PathBuf> {
    let mut out = vec![];
    for e in std::fs::read_dir(d).into_iter().flatten().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}
