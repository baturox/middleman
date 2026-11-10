//! install.sh with a fake `curl` (serves a local "release") and a fake `gh`: quiet by default,
//! silent when gh is not logged in, an error when gh reports a failed attestation.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use middleman::upgrade::{sha256_hex, RELEASE_TARGETS};

const TAG: &str = "v9.9.9";

fn script(p: &Path, body: &str) {
    std::fs::write(p, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn fake_mm(version: &str) -> String {
    format!(
        "#!/bin/sh\ncase \"$1\" in\n  --version) echo \"middleman {version}\" ;;\n  setup) echo '✓ Claude Code settings updated (backup kept; undo: middleman setup claude --undo)'; echo \"$*\" >> \"$HOME/setup-calls\" ;;\nesac\n"
    )
}

/// The target install.sh computes for this machine.
fn target() -> String {
    let os = if cfg!(target_os = "macos") {
        "apple-darwin"
    } else {
        "unknown-linux-gnu"
    };
    let arch = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    };
    let t = format!("{arch}-{os}");
    assert!(RELEASE_TARGETS.contains(&t.as_str()));
    t
}

struct Fx {
    _d: tempfile::TempDir,
    home: PathBuf,
    bin: PathBuf,
    fake: PathBuf,
}

fn fixture(gh: &str) -> Fx {
    let d = tempfile::tempdir().unwrap();
    let root = d.path().canonicalize().unwrap();
    let (home, bin, fake, srv) = (
        root.join("home"),
        root.join("bin"),
        root.join("fake"),
        root.join("srv"),
    );
    for x in [&home, &bin, &fake, &srv] {
        std::fs::create_dir_all(x).unwrap();
    }
    // the release: <stem>/middleman reporting 9.9.9
    let stem = format!("middleman-{TAG}-{}", target());
    let st = srv.join("stage").join(&stem);
    std::fs::create_dir_all(&st).unwrap();
    script(&st.join("middleman"), &fake_mm("9.9.9")[10..]);
    let tgz = srv.join(format!("{stem}.tar.gz"));
    assert!(Command::new("tar")
        .arg("-czf")
        .arg(&tgz)
        .arg("-C")
        .arg(srv.join("stage"))
        .arg(&stem)
        .status()
        .unwrap()
        .success());
    let sum = sha256_hex(&std::fs::read(&tgz).unwrap());
    std::fs::write(
        srv.join(format!("{stem}.tar.gz.sha256")),
        format!("{sum}  {stem}.tar.gz\n"),
    )
    .unwrap();
    // curl: the last argument is the URL, `-o FILE` the output
    script(
        &fake.join("curl"),
        &format!(
            "out=''; url=''\nwhile [ $# -gt 0 ]; do case \"$1\" in -o) out=$2; shift ;; http*) url=$1 ;; esac; shift; done\n\
             case \"$url\" in\n  */releases/latest) body='{{\"tag_name\": \"{TAG}\"}}'; echo \"$body\"; exit 0 ;;\nesac\n\
             f='{}'/$(basename \"$url\")\n[ -f \"$f\" ] || exit 22\nif [ -n \"$out\" ]; then cp \"$f\" \"$out\"; else cat \"$f\"; fi",
            srv.display()
        ),
    );
    script(&fake.join("gh"), gh);
    // an existing 0.2.0 install
    script(&bin.join("middleman"), &fake_mm("0.2.0")[10..]);
    Fx {
        _d: d,
        home,
        bin,
        fake,
    }
}

fn run(fx: &Fx, env: &[(&str, &str)]) -> Output {
    let installer = Path::new(env!("CARGO_MANIFEST_DIR")).join("install.sh");
    let mut c = Command::new("sh");
    c.arg(installer)
        .env_clear()
        .env("HOME", &fx.home)
        .env(
            "PATH",
            format!(
                "{}:{}:/usr/bin:/bin:/usr/sbin",
                fx.fake.display(),
                fx.bin.display()
            ),
        )
        .env("MIDDLEMAN_INSTALL_DIR", &fx.bin)
        .current_dir(&fx.home);
    for (k, v) in env {
        c.env(k, v);
    }
    let o = c.output().unwrap();
    eprintln!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    o
}

const GH_LOGGED_OUT: &str =
    "[ \"$1\" = auth ] && exit 1\necho \"$*\" >> \"$HOME/gh-calls\"; exit 0";
const GH_FAILS: &str =
    "[ \"$1\" = auth ] && exit 0\necho 'no matching attestations found' >&2; exit 1";
const GH_OK: &str = "exit 0";

#[test]
fn quiet_upgrade_without_gh_login_says_nothing_about_attestation() {
    let fx = fixture(GH_LOGGED_OUT);
    let o = run(&fx, &[]);
    assert!(o.status.success());
    assert_eq!(
        String::from_utf8_lossy(&o.stdout),
        "✓ middleman 0.2.0 → 9.9.9 (verified)\n"
    );
    assert_eq!(String::from_utf8_lossy(&o.stderr), "", "no warnings");
    assert!(!fx.home.join("gh-calls").exists(), "verify not attempted");
    assert!(std::fs::read_to_string(fx.bin.join("middleman"))
        .unwrap()
        .contains("middleman 9.9.9"));
    assert!(std::fs::read_to_string(fx.bin.join("middleman.prev"))
        .unwrap()
        .contains("middleman 0.2.0"));
}

#[test]
fn quiet_upgrade_with_wiring_is_two_lines() {
    let fx = fixture(GH_OK);
    std::fs::create_dir_all(fx.home.join(".claude")).unwrap();
    std::fs::write(
        fx.home.join(".claude/settings.json"),
        r#"{"statusLine": {"command": "middleman statusline"}}"#,
    )
    .unwrap();
    let o = run(&fx, &[]);
    assert!(o.status.success());
    assert_eq!(
        String::from_utf8_lossy(&o.stdout),
        "✓ middleman 0.2.0 → 9.9.9 (verified)\n✓ Claude Code settings updated (backup kept; undo: middleman setup claude --undo)\n"
    );
    assert_eq!(
        std::fs::read_to_string(fx.home.join("setup-calls")).unwrap(),
        "setup claude --refresh --yes\n"
    );
}

#[test]
fn failed_attestation_is_an_error_and_changes_nothing() {
    let fx = fixture(GH_FAILS);
    let o = run(&fx, &[]);
    assert!(!o.status.success());
    let se = String::from_utf8_lossy(&o.stderr);
    assert!(se.contains("attestation verification failed"), "{se}");
    assert!(se.contains("no matching attestations found"), "{se}");
    assert!(o.stdout.is_empty());
    assert!(std::fs::read_to_string(fx.bin.join("middleman"))
        .unwrap()
        .contains("middleman 0.2.0"));
    assert!(!fx.bin.join("middleman.prev").exists());
}

#[test]
fn verbose_shows_the_steps_and_checksum_stays_fail_closed() {
    let fx = fixture(GH_LOGGED_OUT);
    let o = run(&fx, &[("MIDDLEMAN_VERBOSE", "1")]);
    assert!(o.status.success());
    let so = String::from_utf8_lossy(&o.stdout);
    for want in [
        "-> downloading",
        "checksum ok",
        "build provenance not checked (gh is not logged in)",
        "middleman.prev",
        "✓ middleman 0.2.0 → 9.9.9 (verified)",
    ] {
        assert!(so.contains(want), "{want}: {so}");
    }
    // required attestation without a logged-in gh: fatal
    let fx = fixture(GH_LOGGED_OUT);
    let o = run(&fx, &[("MIDDLEMAN_REQUIRE_ATTESTATION", "1")]);
    assert!(!o.status.success());
    // a tampered checksum: fatal
    let fx = fixture(GH_OK);
    let stem = format!("middleman-{TAG}-{}", target());
    let sha = fx
        ._d
        .path()
        .canonicalize()
        .unwrap()
        .join(format!("srv/{stem}.tar.gz.sha256"));
    std::fs::write(&sha, format!("{}  {stem}.tar.gz\n", "ab".repeat(32))).unwrap();
    let o = run(&fx, &[]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("checksum missing or mismatched"));
}

#[test]
fn installer_and_signing_script_parse() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for f in ["install.sh", "scripts/make-signing-cert.sh"] {
        let st = Command::new("sh")
            .arg("-n")
            .arg(root.join(f))
            .status()
            .unwrap();
        assert!(st.success(), "sh -n {f}");
    }
}
