//! `middleman upgrade`: the command-line flow around `middleman::upgrade`.
//!
//! Order: refuse package-managed or read-only installs (before any network), find the release,
//! ask (unless --yes), download, verify the checksum (and the attestation when `gh` is
//! installed and logged in), extract the binary, check its `--version`, replace atomically
//! (old one kept as `middleman.prev`), then run the new binary's `setup claude --refresh --yes`.
//!
//! Quiet by default: one line for the binary, one for the wiring, and at most one about the
//! Keychain. `--verbose` (or `MIDDLEMAN_VERBOSE=1`) shows every step.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Context, Result};

use middleman::config::{expand_tilde, Config, KeySource, UpdateMode};
use middleman::fsutil::{clean, pretty};
use middleman::ui::Ui;
use middleman::upgrade::{self as up, Endpoints, Release, UpdateCache, Version};

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
    pub auto: bool,
    pub verbose: bool,
}

/// The one line printed when macOS will ask about the Keychain.
pub const KEYCHAIN_LINE: &str =
    "macOS will ask once to let middleman use its Keychain key: click Always Allow";

pub async fn run(cfg_path: &Path, a: UpgradeArgs) -> Result<ExitCode> {
    if a.rollback {
        return rollback(cfg_path, a.yes);
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

/// `upgrade --check [--quiet] [--write-cache] [--auto]`: exit 0 when up to date, 10 when not.
/// With `--auto` (the background check in `[update] mode = "auto"`) a patch release of the
/// same line is installed too, and the result goes to `update.log`.
async fn check(cfg_path: &Path, a: &UpgradeArgs) -> Result<ExitCode> {
    let ep = Endpoints::from_env();
    let cur = Version::current();
    let tag = a.version.as_deref().map(up::normalize_tag).transpose()?;
    let res = up::fetch_release(&ep, tag.as_deref()).await;
    let state = state_dir(cfg_path);
    if a.write_cache {
        let now = middleman::ledger::now_unix();
        let old = up::load_cache(&state).unwrap_or_default();
        let c = match &res {
            Ok(r) => UpdateCache {
                checked_at: now,
                latest_version: Some(r.tag.clone()),
                error: None,
                ..old
            },
            // keep what an earlier check found; retry tomorrow
            Err(e) => UpdateCache {
                checked_at: now,
                error: Some(clean(&format!("{e:#}"), 120)),
                ..old
            },
        };
        let _ = up::save_cache(&state, &c);
    }
    let out = check_inner(cfg_path, a, &ep, &cur, &state, res).await;
    if a.write_cache {
        up::release_lock(&state);
    }
    out
}

async fn check_inner(
    cfg_path: &Path,
    a: &UpgradeArgs,
    ep: &Endpoints,
    cur: &Version,
    state: &Path,
    res: Result<Release>,
) -> Result<ExitCode> {
    let r = res?;
    let newer = r.version > *cur;
    if a.auto && newer {
        let mode = Config::load(cfg_path)
            .map(|c| c.update.mode())
            .unwrap_or_default();
        if mode == UpdateMode::Auto {
            match up::auto_decision(cur, &r.version) {
                up::AutoDecision::Install => return Ok(auto_install(cfg_path, ep, &r, state).await),
                up::AutoDecision::Manual => {
                    let _ = up::log_update(
                        state,
                        &format!(
                            "{} is available but is not a patch release of v{cur}; run `middleman upgrade`",
                            r.tag
                        ),
                    );
                }
                up::AutoDecision::Current => {}
            }
        }
    }
    if !a.quiet {
        say!("installed: middleman v{cur}");
        say!(
            "latest:    {} (release notes: {})",
            r.tag,
            Endpoints::notes_url(&r.tag)
        );
        if newer {
            say!("update available: run `middleman upgrade`");
        } else if r.version == *cur {
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

/// The background install: no output, everything goes to `update.log`.
async fn auto_install(cfg_path: &Path, ep: &Endpoints, r: &Release, state: &Path) -> ExitCode {
    let cur = Version::current();
    let res = async {
        if up::TARGET.contains("windows") {
            bail!("automatic updates are not supported on Windows");
        }
        let exe = up::current_exe()?;
        if let Some(m) = up::managed_by(&exe, &home(), cargo_home().as_deref()) {
            bail!("not changed: {}", m.advice().replace('\n', " "));
        }
        if !up::dir_writable(exe.parent().unwrap_or(Path::new("."))) {
            bail!("cannot write to {}", pretty(&exe));
        }
        let done = install_release(ep, r, &exe, require_attestation(false), &mut |_| {}).await?;
        let wiring = refresh_wiring(&exe, cfg_path, Wiring::Silent);
        Ok((done, wiring))
    }
    .await;
    match res {
        Ok((done, wiring)) => {
            let _ = up::log_update(
                state,
                &format!(
                    "updated v{cur} -> {} ({}; wiring {})",
                    r.tag,
                    done.attestation,
                    if wiring {
                        "refreshed"
                    } else {
                        "refresh FAILED: run `middleman setup claude --refresh`"
                    }
                ),
            );
            let mut c = up::load_cache(state).unwrap_or_default();
            c.updated_to = Some(r.tag.clone());
            c.notice_since = None;
            let _ = up::save_cache(state, &c);
            ExitCode::SUCCESS
        }
        Err(e) => {
            let _ = up::log_update(state, &format!("update to {} failed: {e:#}", r.tag));
            ExitCode::from(1)
        }
    }
}

fn cargo_home() -> Option<PathBuf> {
    std::env::var_os("CARGO_HOME").map(PathBuf::from)
}

/// Package-managed or read-only installs are not touched: say what to run instead.
fn refuse_unmanageable(exe: &Path) -> Option<ExitCode> {
    if let Some(m) = up::managed_by(exe, &home(), cargo_home().as_deref()) {
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

/// What `install_release` did, for the summary and the verbose log.
struct Installed {
    prev: PathBuf,
    /// How the provenance check went (`provenance verified: ...` / `... not checked ...`).
    attestation: String,
}

/// Download, verify, stage, check and install `r` over `exe`. `step` gets the verbose lines.
async fn install_release(
    ep: &Endpoints,
    r: &Release,
    exe: &Path,
    require: bool,
    step: &mut dyn FnMut(String),
) -> Result<Installed> {
    let asset = up::asset_name(&r.tag, up::TARGET).with_context(|| {
        format!(
            "there is no release build for {}; build it from source: {}",
            up::TARGET,
            up::CARGO_CMD
        )
    })?;
    step(format!("-> downloading {asset}"));
    let archive = up::download(ep, &ep.asset_url(&r.tag, &asset), up::MAX_DOWNLOAD).await?;
    let sums = up::download(ep, &ep.asset_url(&r.tag, "SHA256SUMS.txt"), up::MAX_META).await?;
    let sums = String::from_utf8(sums).context("SHA256SUMS.txt is not text")?;
    let hex = up::verify_sha(&archive, &sums, &asset)?;
    step(format!(
        "   checksum ok (sha256 {}…, from SHA256SUMS.txt)",
        &hex[..16]
    ));

    let tmp = up::TempDir::new()?;
    let file = tmp.path.join(&asset);
    std::fs::write(&file, &archive)?;
    let gh = up::find_on_path("gh");
    let att = up::verify_attestation(gh.as_deref(), &file);
    let attestation = up::attestation_policy(&att, require)?;
    step(format!("   {attestation}"));

    let stem = up::archive_stem(&r.tag, up::TARGET);
    let bin = up::extract_binary(&archive, &stem, up::MAX_DOWNLOAD)?;
    let staged = up::stage(exe, &bin)?;
    up::check_binary(&staged.path, &r.version)?;
    step(format!("   the new binary runs and reports v{}", r.version));
    let prev = up::install(exe, staged)?;
    step(format!(
        "   the previous binary is kept as {}; `middleman upgrade --rollback` restores it",
        pretty(&prev)
    ));
    Ok(Installed { prev, attestation })
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
        say!(
            "{}",
            ui.ok(&format!("middleman {cur} is already installed"))
        );
        return Ok(ExitCode::SUCCESS);
    }
    if r.version < cur && want.is_none() {
        say!(
            "{}",
            ui.ok(&format!(
                "middleman {cur} is up to date (the latest release is {})",
                r.tag
            ))
        );
        return Ok(ExitCode::SUCCESS);
    }
    let down = if r.version < cur { " (downgrade)" } else { "" };
    if a.verbose {
        say!(
            "{} middleman v{cur} -> {}{down}",
            ui.bold("Upgrade:"),
            r.tag
        );
        say!("  binary:        {}", pretty(&exe));
        say!("  release notes: {}", Endpoints::notes_url(&r.tag));
        for l in up::notes_summary(&r.body, 8) {
            say!("    {}", ui.dim(&l));
        }
        say!("");
    }
    let prompt = format!(
        "Upgrade middleman {cur} → {}{down}? (notes: {})",
        r.version,
        Endpoints::notes_url(&r.tag)
    );
    if !confirm(&prompt, a.yes)? {
        say!("Nothing changed.");
        return Ok(ExitCode::SUCCESS);
    }

    if up::TARGET.contains("windows") {
        return windows_finish(&ep, &r, &exe).await;
    }

    let old_dr = up::designated_requirement(&exe);
    let verbose = a.verbose;
    let done = install_release(
        &ep,
        &r,
        &exe,
        require_attestation(a.require_attestation),
        &mut |l| {
            if verbose {
                say!("{l}");
            }
        },
    )
    .await?;
    say!(
        "{}",
        ui.ok(&format!("middleman {cur} → {} (verified)", r.version))
    );

    if a.no_wiring {
        say!("  Skipped the wiring refresh (--no-wiring); run `middleman setup claude --refresh` later.");
    } else {
        refresh_wiring(
            &exe,
            cfg_path,
            if verbose {
                Wiring::Verbose
            } else {
                Wiring::Quiet
            },
        );
    }
    if keychain_key_stored(cfg_path)
        && up::keychain_prompt_expected(
            old_dr.as_deref(),
            up::designated_requirement(&exe).as_deref(),
        )
        && up::TARGET.contains("apple-darwin")
    {
        say!("  {KEYCHAIN_LINE}");
    }
    if verbose {
        say!(
            "  {}",
            ui.dim(&format!("previous binary: {}", pretty(&done.prev)))
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// Windows cannot replace a running exe from inside: verify, then leave the archive.
async fn windows_finish(ep: &Endpoints, r: &Release, exe: &Path) -> Result<ExitCode> {
    let asset = up::asset_name(&r.tag, up::TARGET).context("no release build for Windows")?;
    let archive = up::download(ep, &ep.asset_url(&r.tag, &asset), up::MAX_DOWNLOAD).await?;
    let sums = up::download(ep, &ep.asset_url(&r.tag, "SHA256SUMS.txt"), up::MAX_META).await?;
    up::verify_sha(&archive, &String::from_utf8_lossy(&sums), &asset)?;
    let keep = exe.with_file_name(&asset);
    std::fs::write(&keep, &archive)?;
    say!(
        "The verified archive is at {}. To finish on Windows:\n  1. close Claude Code (it runs middleman)\n  2. extract middleman.exe from the archive over {}\n  3. run `middleman setup claude --refresh`, then /mcp in Claude Code",
        pretty(&keep),
        pretty(exe)
    );
    Ok(ExitCode::SUCCESS)
}

/// Does any configured provider keep its key in the OS keychain?
fn keychain_key_stored(cfg_path: &Path) -> bool {
    Config::load(cfg_path).is_ok_and(|c| {
        c.providers
            .values()
            .any(|p| p.enabled && p.key_source == Some(KeySource::Keychain))
    })
}

#[derive(Clone, Copy, PartialEq)]
enum Wiring {
    /// The new binary's one-line summary goes straight through.
    Quiet,
    /// Its full diff and backup paths go through.
    Verbose,
    /// Nothing is printed (background update).
    Silent,
}

/// Run the NEW binary's `setup claude --refresh --yes`. Returns true when it finished.
fn refresh_wiring(exe: &Path, cfg_path: &Path, how: Wiring) -> bool {
    use std::process::Stdio;
    let _ = std::io::stdout().flush();
    let mut c = std::process::Command::new(exe);
    c.args(["setup", "claude", "--refresh", "--yes"]);
    if how == Wiring::Verbose {
        c.arg("--verbose");
    }
    c.arg("--config").arg(cfg_path).stdin(Stdio::null());
    if how == Wiring::Silent {
        c.stdout(Stdio::null()).stderr(Stdio::null());
    }
    let ok = c.status().is_ok_and(|s| s.success());
    if !ok && how != Wiring::Silent {
        note!("warning: the wiring refresh did not finish; run `middleman setup claude --refresh` yourself");
    }
    ok
}

/// `upgrade --rollback`: swap `middleman.prev` back in.
fn rollback(cfg_path: &Path, yes: bool) -> Result<ExitCode> {
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
    if !confirm(
        &format!(
            "Put middleman {pv} back (now {cur}, from {})?",
            pretty(&prev)
        ),
        yes,
    )? {
        say!("Nothing changed.");
        return Ok(ExitCode::SUCCESS);
    }
    let old_dr = up::designated_requirement(&exe);
    let v = up::rollback(&exe)?;
    say!(
        "{}",
        ui.ok(&format!(
            "Restored middleman v{v} at {} (`middleman upgrade --rollback` again switches back)",
            pretty(&exe)
        ))
    );
    if up::TARGET.contains("apple-darwin")
        && keychain_key_stored(cfg_path)
        && up::keychain_prompt_expected(
            old_dr.as_deref(),
            up::designated_requirement(&exe).as_deref(),
        )
    {
        say!("  {KEYCHAIN_LINE}");
    }
    if up::TARGET.contains("windows") {
        say!("  Run /mcp in Claude Code (or restart it) to reconnect middleman.");
    }
    Ok(ExitCode::SUCCESS)
}

/// `middleman update-settings [notify|auto|off]`.
pub fn update_settings(cfg_path: &Path, mode: Option<&str>) -> Result<ExitCode> {
    let ui = Ui::stdout();
    let text = std::fs::read_to_string(cfg_path).with_context(|| {
        format!(
            "no config at {}: run `middleman init` first",
            pretty(cfg_path)
        )
    })?;
    let cur = Config::from_toml(&text)
        .map(|c| c.update.mode())
        .unwrap_or_default();
    let want = match mode {
        Some(m) => UpdateMode::parse(m).context("the mode must be notify, auto or off")?,
        None if interactive() => {
            let items = UPDATE_CHOICES.map(|(_, l)| l);
            let def = UPDATE_CHOICES
                .iter()
                .position(|(m, _)| *m == cur)
                .unwrap_or(0);
            let i = dialoguer::Select::with_theme(&theme())
                .with_prompt("Keep middleman up to date")
                .items(items)
                .default(def)
                .interact()?;
            UPDATE_CHOICES[i].0
        }
        None => {
            say!("updates: {} ({})", cur.as_str(), describe_mode(cur));
            return Ok(ExitCode::SUCCESS);
        }
    };
    if want != cur || !text.contains("mode =") {
        let new = middleman::wizard::set_update_mode(&text, want)?;
        middleman::onboard::write_config(cfg_path, &new)?;
    }
    say!(
        "{}",
        ui.ok(&format!(
            "updates: {} ({})",
            want.as_str(),
            describe_mode(want)
        ))
    );
    Ok(ExitCode::SUCCESS)
}

/// The wizard's and `update-settings`' choices, default first.
pub const UPDATE_CHOICES: [(UpdateMode, &str); 3] = [
    (UpdateMode::Notify, "notify me"),
    (UpdateMode::Auto, "update automatically"),
    (UpdateMode::Off, "never check"),
];

pub fn describe_mode(m: UpdateMode) -> &'static str {
    match m {
        UpdateMode::Notify => "a daily check; the status line shows ↑ vX when a release is out",
        UpdateMode::Auto => {
            "patch releases install in the background (checksum-verified); bigger ones are only shown"
        }
        UpdateMode::Off => "no update checks",
    }
}
