//! `middleman upgrade`: the command-line flow around `middleman::upgrade`.
//!
//! Order: refuse package-managed or read-only installs (before any network), find the release,
//! show it and ask, download, verify the checksum (and the attestation when `gh` exists),
//! extract the binary, check its `--version`, replace atomically (old one kept as
//! `middleman.prev`), then run the new binary's `setup claude --refresh --yes`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Context, Result};

use middleman::config::{expand_tilde, Config};
use middleman::fsutil::{clean, pretty};
use middleman::ui::Ui;
use middleman::upgrade::{self as up, Endpoints, UpdateCache, Version};

use crate::{home, interactive, theme};

pub struct UpgradeArgs {
    pub check: bool,
    pub version: Option<String>,
    pub yes: bool,
    pub no_wiring: bool,
    pub rollback: bool,
    pub require_attestation: bool,
    pub quiet: bool,
    pub write_cache: bool,
}

pub async fn run(cfg_path: &Path, a: UpgradeArgs) -> Result<ExitCode> {
    if a.rollback {
        return rollback(a.yes);
    }
    if a.check {
        return check(cfg_path, &a).await;
    }
    upgrade(cfg_path, &a).await
}

fn state_dir(cfg_path: &Path) -> PathBuf {
    Config::load(cfg_path)
        .map(|c| c.state_dir())
        .unwrap_or_else(|_| expand_tilde(Path::new("~/.local/state/middleman")))
}

/// `upgrade --check [--quiet] [--write-cache]`: exit 0 when up to date, 10 when not.
async fn check(cfg_path: &Path, a: &UpgradeArgs) -> Result<ExitCode> {
    let ep = Endpoints::from_env();
    let cur = Version::current();
    let tag = a.version.as_deref().map(up::normalize_tag).transpose()?;
    let res = up::fetch_release(&ep, tag.as_deref()).await;
    if a.write_cache {
        let state = state_dir(cfg_path);
        let now = middleman::ledger::now_unix();
        let c = match &res {
            Ok(r) => UpdateCache {
                checked_at: now,
                latest_version: Some(r.tag.clone()),
                error: None,
            },
            // keep what an earlier check found; retry tomorrow
            Err(e) => UpdateCache {
                checked_at: now,
                latest_version: up::load_cache(&state).and_then(|c| c.latest_version),
                error: Some(clean(&format!("{e:#}"), 120)),
            },
        };
        let _ = up::save_cache(&state, &c);
        up::release_lock(&state);
    }
    let r = res?;
    let newer = r.version > cur;
    if !a.quiet {
        say!("installed: middleman v{cur}");
        say!(
            "latest:    {} (release notes: {})",
            r.tag,
            Endpoints::notes_url(&r.tag)
        );
        if newer {
            say!("update available: run `middleman upgrade`");
        } else if r.version == cur {
            say!("up to date");
        } else {
            say!("up to date (this build is newer than the latest release)");
        }
    }
    Ok(if newer {
        ExitCode::from(up::EXIT_UPDATE_AVAILABLE)
    } else {
        ExitCode::SUCCESS
    })
}

/// Package-managed or read-only installs are not touched: say what to run instead.
fn refuse_unmanageable(exe: &Path) -> Option<ExitCode> {
    let cargo_home = std::env::var_os("CARGO_HOME").map(PathBuf::from);
    if let Some(m) = up::managed_by(exe, &home(), cargo_home.as_deref()) {
        note!("{} is not changed: {}", pretty(exe), m.advice());
        return Some(ExitCode::from(1));
    }
    let dir = exe.parent().unwrap_or(Path::new("."));
    if !up::dir_writable(dir) {
        note!(
            "cannot write to {}, so {} is not changed. Rerun the installer for that directory \
             (with the rights it needs):\n    {} | MIDDLEMAN_INSTALL_DIR={} sh",
            pretty(dir),
            pretty(exe),
            up::INSTALL_SH_CMD.trim_end_matches(" | sh"),
            middleman::fsutil::shell_quote(&dir.display().to_string())
        );
        return Some(ExitCode::from(1));
    }
    None
}

fn confirm(prompt: &str, yes: bool) -> Result<bool> {
    if yes {
        return Ok(true);
    }
    if !interactive() {
        bail!("re-run with --yes to go ahead without a prompt");
    }
    Ok(dialoguer::Confirm::with_theme(&theme())
        .with_prompt(prompt)
        .default(true)
        .interact()?)
}

fn require_attestation(flag: bool) -> bool {
    flag || std::env::var("MIDDLEMAN_REQUIRE_ATTESTATION").is_ok_and(|v| v.trim() == "1")
}

async fn upgrade(cfg_path: &Path, a: &UpgradeArgs) -> Result<ExitCode> {
    let ui = Ui::stdout();
    let exe = up::current_exe()?;
    if let Some(code) = refuse_unmanageable(&exe) {
        return Ok(code);
    }
    let ep = Endpoints::from_env();
    let cur = Version::current();
    let want = a.version.as_deref().map(up::normalize_tag).transpose()?;
    let r = up::fetch_release(&ep, want.as_deref()).await?;
    if r.version == cur {
        say!("middleman v{cur} is already installed; nothing to do.");
        return Ok(ExitCode::SUCCESS);
    }
    if r.version < cur && want.is_none() {
        say!(
            "middleman v{cur} is up to date (the latest release is {}).",
            r.tag
        );
        return Ok(ExitCode::SUCCESS);
    }
    let asset = up::asset_name(&r.tag, up::TARGET).with_context(|| {
        format!(
            "there is no release build for {}; build it from source: {}",
            up::TARGET,
            up::CARGO_CMD
        )
    })?;

    say!(
        "{} middleman v{cur} -> {}{}",
        ui.bold("Upgrade:"),
        r.tag,
        if r.version < cur { " (downgrade)" } else { "" }
    );
    say!("  binary:        {}", pretty(&exe));
    say!("  release notes: {}", Endpoints::notes_url(&r.tag));
    for l in up::notes_summary(&r.body, 8) {
        say!("    {}", ui.dim(&l));
    }
    say!("");
    if !confirm(&format!("Install middleman {}?", r.tag), a.yes)? {
        say!("Nothing changed.");
        return Ok(ExitCode::SUCCESS);
    }

    say!("-> downloading {asset}");
    let archive = up::download(&ep, &ep.asset_url(&r.tag, &asset), up::MAX_DOWNLOAD).await?;
    let sums = up::download(&ep, &ep.asset_url(&r.tag, "SHA256SUMS.txt"), up::MAX_META).await?;
    let sums = String::from_utf8(sums).context("SHA256SUMS.txt is not text")?;
    let hex = up::verify_sha(&archive, &sums, &asset)?;
    say!(
        "   checksum ok (sha256 {}…, from SHA256SUMS.txt)",
        &hex[..16]
    );

    let tmp = up::TempDir::new()?;
    let file = tmp.path.join(&asset);
    std::fs::write(&file, &archive)?;
    let gh = up::find_on_path("gh");
    let att = up::verify_attestation(gh.as_deref(), &file);
    match up::attestation_policy(&att, require_attestation(a.require_attestation))? {
        None => say!(
            "   provenance verified: built by {}'s release workflow",
            up::REPO
        ),
        Some(w) => note!("   warning: {w}"),
    }

    if up::TARGET.contains("windows") {
        let keep = exe.with_file_name(&asset);
        std::fs::copy(&file, &keep)?;
        say!(
            "\nThe verified archive is at {}. To finish on Windows:\n  1. close Claude Code (it runs middleman)\n  2. extract middleman.exe from the archive over {}\n  3. run `middleman setup claude --refresh`",
            pretty(&keep),
            pretty(&exe)
        );
        return Ok(ExitCode::SUCCESS);
    }

    let stem = up::archive_stem(&r.tag, up::TARGET);
    let bin = up::extract_binary(&archive, &stem, up::MAX_DOWNLOAD)?;
    let staged = up::stage(&exe, &bin)?;
    up::check_binary(&staged.path, &r.version)?;
    say!("   the new binary runs and reports v{}", r.version);
    let prev = up::install(&exe, staged)?;
    say!(
        "{}",
        ui.ok(&format!(
            "Installed middleman {} at {}",
            r.tag,
            pretty(&exe)
        ))
    );
    say!(
        "  {}",
        ui.dim(&format!(
            "the previous binary is kept as {}; `middleman upgrade --rollback` restores it",
            pretty(&prev)
        ))
    );

    if a.no_wiring {
        say!("\nSkipped the wiring refresh (--no-wiring); run `middleman setup claude --refresh` later.");
    } else {
        say!("\n-> refreshing the Claude Code wiring with the new binary");
        refresh_wiring(&exe, cfg_path);
    }
    manual_steps(&ui);
    Ok(ExitCode::SUCCESS)
}

/// Run the NEW binary's `setup claude --refresh --yes` (its output goes straight through).
fn refresh_wiring(exe: &Path, cfg_path: &Path) {
    let _ = std::io::stdout().flush();
    let st = std::process::Command::new(exe)
        .args(["setup", "claude", "--refresh", "--yes", "--config"])
        .arg(cfg_path)
        .stdin(std::process::Stdio::null())
        .status();
    if !st.is_ok_and(|s| s.success()) {
        note!("warning: the wiring refresh did not finish; run `middleman setup claude --refresh` yourself");
    }
}

fn manual_steps(ui: &Ui) {
    say!("\n{}", ui.bold("Left for you:"));
    say!(
        "  - run /mcp in Claude Code to reconnect (or restart it): the MCP server that is running\n    is still the old binary."
    );
    if up::TARGET.contains("apple-darwin") {
        say!(
            "  - macOS may ask once to let the new binary use the Keychain: choose \"Always Allow\".\n    The binary changed, so its code signature did too, and the Keychain asks again\n    before it hands a stored API key to a program it has not seen."
        );
    }
}

/// `upgrade --rollback`: swap `middleman.prev` back in.
fn rollback(yes: bool) -> Result<ExitCode> {
    let ui = Ui::stdout();
    let exe = up::current_exe()?;
    if let Some(code) = refuse_unmanageable(&exe) {
        return Ok(code);
    }
    let prev = up::prev_path(&exe);
    if !prev.is_file() {
        bail!("nothing to roll back to: {} does not exist", pretty(&prev));
    }
    let pv =
        up::binary_version(&prev).context("the previous binary does not run; not restoring it")?;
    let cur = Version::current();
    say!(
        "{} middleman v{cur} -> v{pv} (from {})",
        ui.bold("Rollback:"),
        pretty(&prev)
    );
    if !confirm(&format!("Put middleman v{pv} back?"), yes)? {
        say!("Nothing changed.");
        return Ok(ExitCode::SUCCESS);
    }
    let v = up::rollback(&exe)?;
    say!(
        "{}",
        ui.ok(&format!("Restored middleman v{v} at {}", pretty(&exe)))
    );
    say!(
        "  {}",
        ui.dim(&format!(
            "v{cur} is now {}; `middleman upgrade --rollback` again switches back",
            pretty(&prev)
        ))
    );
    manual_steps(&ui);
    Ok(ExitCode::SUCCESS)
}
