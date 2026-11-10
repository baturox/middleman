#![deny(clippy::print_stdout)]

use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};

use middleman::catalog::Catalog;
use middleman::classify::Declared;
use middleman::claude_setup::{self, SetupOptions};
use middleman::config::{
    default_config_path, expand_tilde, Api, Config, KeySource, RoutingMode, Secret,
};
use middleman::detect::{Detector, Dictionary};
use middleman::egress::{self, OutboundRequest};
use middleman::fsutil::{clean, pretty};
use middleman::intake::FileRef;
use middleman::keystore;
use middleman::mcp::server::Server;
use middleman::oauth;
use middleman::onboard;
use middleman::pipeline::{DelegateRequest, Pipeline};
use middleman::providers::presets::{self, Preset};
use middleman::providers::{ModelInfo, Provider};
use middleman::pseudo::Vault;
use middleman::setup::{self, Scope};
use middleman::TaskKind;

/// stdout is the MCP channel in `mcp` mode; CLI subcommands write through this macro.
macro_rules! say {
    ($($t:tt)*) => {{
        let _ = writeln!(std::io::stdout(), $($t)*);
    }};
}

/// Prompts, progress and warnings go to stderr so stdout stays clean for scripts.
macro_rules! note {
    ($($t:tt)*) => {{
        let _ = writeln!(std::io::stderr(), $($t)*);
    }};
}

mod cli_init;
mod cli_upgrade;

#[derive(Parser)]
#[command(
    name = "middleman",
    version,
    about = "Let cheap models do Claude Code's grunt work, without seeing your secrets",
    after_help = "Start with `middleman init`, then `middleman setup claude`."
)]
struct Cli {
    /// Config file [default: ~/.config/middleman/config.toml]
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Guided setup: where to install, provider and key (checked live), routing mode
    Init {
        /// user (all projects) | project (this repo: also writes .middleman.toml)
        #[arg(long)]
        scope: Option<String>,
        /// Comma-separated providers, e.g. openrouter,deepseek (skips the picker) [default with --yes: openrouter]
        #[arg(long)]
        providers: Option<String>,
        /// confirm (ask each time) | auto | explicit (only `cheap:` prompts) [default: confirm]
        #[arg(long)]
        mode: Option<String>,
        /// Folders middleman may read [default: current directory, or the project]
        #[arg(long)]
        root: Vec<PathBuf>,
        /// Non-interactive: use flags and defaults, ask nothing
        #[arg(long)]
        yes: bool,
        /// Non-interactive: read the provider's key from stdin, check it, store it
        #[arg(long)]
        key_stdin: bool,
        /// With --key-stdin: store the key without the free check request
        #[arg(long)]
        no_validate: bool,
        /// Base URL for a local server on another port, or a custom endpoint
        /// (with `--providers <your-name>`)
        #[arg(long)]
        base_url: Option<String>,
        /// Replace existing middleman config files (each is backed up first)
        #[arg(long)]
        force: bool,
        /// Also run `middleman setup claude --yes` at the end
        #[arg(long)]
        apply: bool,
        /// List providers by group, with key status, then exit
        #[arg(long)]
        list: bool,
    },
    /// Manage provider API keys (stored in the OS keychain, never in the config)
    Provider {
        #[command(subcommand)]
        action: ProviderCmd,
    },
    /// Log in with your browser and store the API key it creates (OpenRouter)
    Login {
        /// Provider to log in to (only openrouter supports this)
        provider: String,
        /// Do not open a browser: print the link and paste the code it shows (SSH, containers)
        #[arg(long)]
        no_browser: bool,
        /// Seconds to wait for the browser
        #[arg(long, default_value_t = 300)]
        timeout: u64,
    },
    /// Wire middleman into a client
    Setup {
        #[command(subcommand)]
        target: SetupTarget,
    },
    /// Status line for Claude Code's statusLine: model, effort, context, cost, cache, and
    /// middleman's provider, limits, jobs, subagents and net savings (reads JSON on stdin)
    Statusline {
        /// 1: everything on one line (shortened to fit); 2: Claude part, then middleman part
        /// [env: MIDDLEMAN_SL_LINES]
        #[arg(long)]
        lines: Option<u8>,
        /// Print only the middleman part, to append to another status line script
        #[arg(long)]
        middleman_only: bool,
        /// Terminal width [default: $COLUMNS, else 120]
        #[arg(long)]
        columns: Option<usize>,
    },
    /// Follow the delegation log live, one readable line per call
    Watch {
        /// Show this many past entries first
        #[arg(long, default_value_t = 10)]
        tail: usize,
        /// Print the past entries and exit
        #[arg(long)]
        no_follow: bool,
    },
    /// Usage and savings report from the delegation log
    Report {
        /// 24h | 7d | 30d | all
        #[arg(long, default_value = "30d")]
        since: String,
        /// model | provider | task | day | project
        #[arg(long, default_value = "model")]
        by: String,
        #[arg(long)]
        json: bool,
        /// Also write a single-file HTML dashboard to this path
        #[arg(long)]
        html: Option<PathBuf>,
        /// Compare the ledger's cost with the provider's own usage counters (free GETs)
        #[arg(long)]
        reconcile: bool,
    },
    /// Claude Code spend from local transcripts (~/.claude/projects), totals only
    Usage {
        /// 24h | 7d | 30d | all
        #[arg(long, default_value = "30d")]
        since: String,
        /// model | day | project | session | agent
        #[arg(long, default_value = "model")]
        by: String,
        #[arg(long)]
        json: bool,
        /// Also write a single-file HTML dashboard to this path
        #[arg(long)]
        html: Option<PathBuf>,
    },
    /// Recommended Claude Code settings, with estimated savings
    Tune {
        /// 24h | 7d | 30d | all
        #[arg(long, default_value = "30d")]
        since: String,
        #[arg(long)]
        json: bool,
        /// Merge the snippet into ~/.claude/settings.json (a backup is taken first)
        #[arg(long)]
        apply: bool,
    },
    /// Dry run: show exactly what would be sent for these files (no network)
    Check {
        files: Vec<String>,
        #[arg(long, default_value = "snippet")]
        task_kind: String,
        /// public | internal | confidential
        #[arg(long, default_value = "internal")]
        declared: String,
        #[arg(long, default_value = "Review this code.")]
        instructions: String,
    },
    /// Show whether a prompt would be delegated, and why (`--hook`: Claude Code prompt hook)
    Route {
        text: Option<String>,
        /// Run as the UserPromptSubmit hook: JSON on stdin, always exits 0
        #[arg(long)]
        hook: bool,
    },
    /// List cached models and prices, or `models refresh` to fetch them now
    Models {
        /// list | refresh
        action: Option<String>,
        /// Include non-text and unpriced models
        #[arg(long)]
        all: bool,
    },
    /// Show a provider's balance
    Balance {
        #[arg(long)]
        provider: Option<String>,
    },
    /// Show recent raw log entries and today's / 7-day spend
    Ledger {
        #[arg(long, default_value_t = 20)]
        tail: usize,
    },
    /// Probe a gateway: User-Agent handling, wire formats, cheapest model (~2 tiny calls)
    Probe {
        #[arg(long)]
        provider: Option<String>,
        #[arg(long)]
        model: Option<String>,
        /// Only free GET requests; no completions
        #[arg(long)]
        no_send: bool,
    },
    /// Health check: config, keys, keychain, providers, catalog and Claude Code wiring
    Doctor,
    /// The private dictionary of company, product and people names
    Dict {
        #[command(subcommand)]
        action: DictCmd,
    },
    /// Approve a routing.mode=confirm dry run (run this yourself, in a terminal)
    Approve {
        /// The approval_id shown by the dry run
        id: String,
    },
    /// Print shell completions (bash, zsh, fish, elvish, powershell)
    Completions { shell: clap_complete::Shell },
    /// Run the MCP stdio server (Claude Code starts this for you)
    Mcp,
    /// Upgrade to the latest release (checksum-verified), then refresh the Claude Code wiring
    Upgrade {
        /// Only check: print this version and the latest; exit code 10 when an update exists
        #[arg(long, conflicts_with = "rollback")]
        check: bool,
        /// Install this release instead of the latest, e.g. v0.3.1
        #[arg(long, value_name = "vX.Y.Z", conflicts_with = "rollback")]
        version: Option<String>,
        /// Do not ask for confirmation
        #[arg(long)]
        yes: bool,
        /// Do not run `setup claude --refresh` with the new binary afterwards
        #[arg(long)]
        no_wiring: bool,
        /// Put the previous binary (middleman.prev) back
        #[arg(long)]
        rollback: bool,
        /// Refuse to install unless `gh attestation verify` succeeds
        /// [env: MIDDLEMAN_REQUIRE_ATTESTATION=1]
        #[arg(long)]
        require_attestation: bool,
        /// With --check: print nothing (the exit code tells)
        #[arg(long)]
        quiet: bool,
        /// With --check: record the result for the status line and doctor
        #[arg(long, hide = true)]
        write_cache: bool,
    },
}

#[derive(Subcommand)]
enum ProviderCmd {
    /// Add a provider: pick it, log in or paste the key (hidden), validate, store it
    Add {
        /// Preset name, e.g. openrouter (omit to pick from a list)
        name: Option<String>,
        /// Read the key from stdin instead of prompting (for scripts; never pass it as an argument)
        #[arg(long)]
        key_stdin: bool,
        /// Log in with the browser instead of pasting a key (OpenRouter)
        #[arg(long)]
        login: bool,
        /// Store the key without the free validation request
        #[arg(long)]
        no_validate: bool,
    },
    /// List configured providers and where each key is stored (never the key)
    List {
        /// Show every available provider by group, with key status
        #[arg(long)]
        all: bool,
    },
    /// Check a provider's key with a free request
    Test { name: String },
    /// Fetch balances and key limits (free GETs) into the cache the status line shows
    Refresh {
        /// Print nothing (the status line starts it this way in the background)
        #[arg(long)]
        quiet: bool,
        /// Started by the status line: release its refresh lock when done
        #[arg(long, hide = true)]
        from_statusline: bool,
    },
    /// Replace a provider's stored key
    Rotate {
        name: String,
        #[arg(long)]
        key_stdin: bool,
        #[arg(long)]
        login: bool,
        #[arg(long)]
        no_validate: bool,
    },
    /// Remove a provider and its stored key
    Remove {
        name: String,
        /// Do not ask for confirmation
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum DictCmd {
    /// Find names in this project (locally: files, git config, git log) and add the ones you
    /// pick to the dictionary
    Suggest {
        /// Add every candidate at or above --min-confidence without asking
        #[arg(long)]
        yes: bool,
        /// low | medium | high (with --yes, or the preselection in the picker)
        #[arg(long, default_value = "medium")]
        min_confidence: String,
        /// Project to scan [default: the git root of the current directory]
        #[arg(long)]
        root: Option<PathBuf>,
        /// Print the candidates as JSON and exit (writes nothing)
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum SetupTarget {
    /// Register the MCP server, allow its tools, add the prompt hook, statusline and CLAUDE.md block
    Claude {
        /// user (~/.claude*) | project (.mcp.json, .claude/settings.json, CLAUDE.md here)
        #[arg(long, default_value = "user")]
        scope: String,
        /// Show the changes and exit
        #[arg(long)]
        dry_run: bool,
        /// Also show the exact keys and values that change
        #[arg(long)]
        details: bool,
        /// Apply without asking
        #[arg(long)]
        yes: bool,
        /// Restore the files changed by the last `setup claude`
        #[arg(long)]
        undo: bool,
        /// Only update what middleman already wrote (binary path, hook command and timeout,
        /// status line command, CLAUDE.md block), in user and project scope; adds nothing
        #[arg(long, conflicts_with = "undo")]
        refresh: bool,
        #[arg(long)]
        no_statusline: bool,
        /// auto (set it unless you have another status line) | combined (replace another
        /// status line with middleman's full two-line one) | off
        #[arg(long, default_value = "auto")]
        statusline: String,
        #[arg(long)]
        no_hook: bool,
        #[arg(long)]
        no_claude_md: bool,
        /// Do not allow-list the two middleman tools (Claude Code will ask each time)
        #[arg(long)]
        no_permissions: bool,
    },
}

fn cwd() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

fn theme() -> dialoguer::theme::ColorfulTheme {
    dialoguer::theme::ColorfulTheme::default()
}

fn load(cfg_path: &Path) -> Result<Config> {
    if !cfg_path.exists() {
        bail!(
            "no config at {}: run `middleman init` first",
            pretty(cfg_path)
        );
    }
    let (cfg, overlay) = Config::load_with_project(cfg_path, &cwd())?;
    if let Some(p) = overlay {
        tracing::info!("applied project overlay {}", p.display());
    }
    Ok(cfg)
}

fn pick_provider(cfg: &Config, name: Option<String>) -> Result<String> {
    match name {
        Some(n) if cfg.providers.contains_key(&n) => Ok(n),
        Some(n) => {
            bail!("unknown provider {n}: run `middleman provider list` to see configured ones")
        }
        None => cfg
            .providers
            .iter()
            .find(|(_, p)| p.enabled)
            .map(|(n, _)| n.clone())
            .context("no enabled providers: run `middleman provider add openrouter`"),
    }
}

fn cheapest_text(models: &[ModelInfo]) -> Vec<&ModelInfo> {
    let mut v: Vec<&ModelInfo> = models
        .iter()
        .filter(|m| m.is_text() && m.price_in_per_1m.is_some() && m.price_out_per_1m.is_some())
        .collect();
    v.sort_by(|a, b| {
        let ca = a.price_in_per_1m.unwrap_or(0.0) + 4.0 * a.price_out_per_1m.unwrap_or(0.0);
        let cb = b.price_in_per_1m.unwrap_or(0.0) + 4.0 * b.price_out_per_1m.unwrap_or(0.0);
        ca.partial_cmp(&cb).unwrap_or(std::cmp::Ordering::Equal)
    });
    v
}

fn fmt_price(p: Option<f64>) -> String {
    p.map(|x| format!("{x:.3}")).unwrap_or_else(|| "?".into())
}

async fn probe(
    cfg: &Config,
    provider: Option<String>,
    model: Option<String>,
    no_send: bool,
) -> Result<()> {
    let name = pick_provider(cfg, provider)?;
    let pc = &cfg.providers[&name];
    let p = Provider::from_cfg(&name, pc, 60)?;
    say!(
        "probe provider={name} base_url={} configured_api={:?}",
        pc.base_url,
        pc.api
    );
    say!("configured User-Agent: {}", p.user_agent());

    say!("\n[UA] GET /models status by User-Agent:");
    for (label, ua) in [
        ("configured", Some(p.user_agent().to_string())),
        (
            "non-browser 'middleman/0.1'",
            Some("middleman/0.1".to_string()),
        ),
        ("no UA header", None),
    ] {
        match p.status_with_ua("/models", ua.as_deref()).await {
            Ok(s) => say!("  {label:<30} -> HTTP {s}"),
            Err(e) => say!("  {label:<30} -> error: {}", clean(&e.to_string(), 200)),
        }
    }

    say!("\n[models]");
    let models = match p.models().await {
        Ok(m) => m,
        Err(e) => {
            say!("  GET /models failed: {}", clean(&e.to_string(), 200));
            vec![]
        }
    };
    let text = cheapest_text(&models);
    say!(
        "  {} models total, {} priced text models; cheapest:",
        models.len(),
        text.len()
    );
    for m in text.iter().take(12) {
        say!(
            "  {:<40} in ${:>7}/1M out ${:>7}/1M tier={} ctx={} modality={} tags={:?}",
            clean(&m.id, 60),
            fmt_price(m.price_in_per_1m),
            fmt_price(m.price_out_per_1m),
            clean(m.tier.as_deref().unwrap_or("?"), 20),
            m.context_length
                .map(|c| c.to_string())
                .unwrap_or_else(|| "?".into()),
            clean(m.modality.as_deref().unwrap_or("?"), 30),
            middleman::catalog::tags_for(&m.id, m.context_length),
        );
    }

    say!("\n[balance]");
    let b0 = p.balance().await;
    match &b0 {
        Ok(b) => say!("  balance_usd={:.4} payg={:?}", b.usd, b.payg),
        Err(e) => say!("  balance failed: {}", clean(&e.to_string(), 200)),
    }
    if no_send {
        return Ok(());
    }
    let Some(chosen) = model.or_else(|| {
        text.iter()
            .find(|m| !middleman::catalog::is_free_tier(&m.id))
            .map(|m| m.id.clone())
    }) else {
        say!("  no model to test; stopping (nothing sent)");
        return Ok(());
    };
    if b0.is_err() {
        say!("  balance unreadable: refusing to send (fail-closed)");
        return Ok(());
    }
    say!(
        "\n[wire formats] model={}, max_tokens=8, synthetic prompt only",
        clean(&chosen, 80)
    );
    let det = Detector::new(vec![], cfg.public_hosts(), None);
    let vault = Vault::new("");
    let mut prev = b0.as_ref().map(|b| b.usd).ok();
    for api in [Api::Openai, Api::Anthropic] {
        let req = OutboundRequest {
            model: chosen.clone(),
            system: "Reply with exactly: OK".into(),
            user: "Reply with exactly: OK".into(),
            max_tokens: 8,
        };
        let sealed = egress::seal(req, &vault, &det, &[p.key()])
            .map_err(|e| anyhow::anyhow!("probe payload failed egress gate: {e}"))?;
        let t0 = std::time::Instant::now();
        match p.complete_with(api, &sealed).await {
            Ok(c) => say!(
                "  {:?}: OK in {} ms text={:?} model={:?} usage in={:?} out={:?} stop={:?}",
                api,
                t0.elapsed().as_millis(),
                clean(&c.text, 40),
                c.model.as_deref().map(|m| clean(m, 60)),
                c.input_tokens,
                c.output_tokens,
                c.stop_reason.as_deref().map(|s| clean(s, 20))
            ),
            Err(e) => say!("  {:?}: FAILED: {}", api, clean(&e.to_string(), 200)),
        }
        let now = p.balance().await.ok().map(|b| b.usd);
        say!(
            "    balance immediately after: {:?} (delta {:?})",
            now,
            prev.zip(now).map(|(a, b)| a - b)
        );
        prev = now.or(prev);
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    let late = p.balance().await.ok().map(|b| b.usd);
    say!(
        "\n[balance latency] after +3s: {:?}; total delta since start: {:?}",
        late,
        b0.ok().map(|b| b.usd).zip(late).map(|(a, b)| a - b)
    );
    Ok(())
}

/// Hook path: never fails. A config that cannot be loaded produces a "do not delegate"
/// message instead of silently falling back to defaults. A `cheap:` prompt is run here and
/// blocked, so it never reaches Claude (see `middleman::direct`); every other prompt only
/// gets advice.
async fn route_hook(cfg_path: &Path) {
    let mut input = String::new();
    let _ = std::io::stdin().take(1 << 20).read_to_string(&mut input);
    let parsed = serde_json::from_str::<serde_json::Value>(&input).ok();
    let hook_cwd = parsed
        .as_ref()
        .and_then(|v| v.get("cwd").and_then(|c| c.as_str()).map(PathBuf::from))
        .unwrap_or_else(cwd);
    let has_prompt = parsed
        .as_ref()
        .and_then(|v| v.get("prompt"))
        .is_some_and(|p| p.is_string());
    let cfg = match Config::load_with_project(cfg_path, &hook_cwd) {
        Ok((c, _)) => c,
        Err(e) => {
            if has_prompt {
                say!(
                    "{}",
                    middleman::hook::hook_output_config_error(&format!("{e:#}"))
                );
            }
            return;
        }
    };
    let dict = cfg
        .redact
        .dictionary_file
        .as_ref()
        .and_then(|p| Dictionary::load(p).ok());
    let prompt = parsed
        .as_ref()
        .and_then(|v| v.get("prompt"))
        .and_then(|p| p.as_str())
        .unwrap_or("");
    if let Some(body) = middleman::direct::body(prompt) {
        let session = parsed
            .as_ref()
            .and_then(|v| v.get("session_id"))
            .and_then(|s| s.as_str())
            .map(String::from);
        let msg = direct_run(cfg, dict.as_ref(), body, &hook_cwd, session).await;
        say!("{}", middleman::direct::block_json(&msg));
        return;
    }
    if let Some(out) = middleman::hook::hook_output(
        &input,
        cfg.routing.mode,
        dict.as_ref(),
        Some(&cfg.economics),
    ) {
        say!("{out}");
    }
}

/// Run one `cheap:` prompt through the full pipeline. Returns the message for the user.
async fn direct_run(
    cfg: Config,
    dict: Option<&Dictionary>,
    body: &str,
    cwd: &Path,
    session: Option<String>,
) -> String {
    use middleman::direct;
    let advice = middleman::hook::advise(body, cfg.routing.mode, dict, Some(&cfg.economics));
    if !advice.sensitive_topics.is_empty() {
        return direct::refused_message(&advice.sensitive_topics);
    }
    let root = middleman::config::project_root_for(cwd).unwrap_or_else(|| cwd.to_path_buf());
    let root = std::fs::canonicalize(&root).unwrap_or(root);
    let parsed = match direct::parse(body, &root, cwd) {
        Ok(p) => p,
        Err(why) => return direct::usage_message(&why),
    };
    let pipeline = match Pipeline::new(cfg) {
        Ok(p) => p,
        Err(e) => return direct::usage_message(&format!("middleman could not start: {e:#}")),
    };
    let out = pipeline.run(parsed.request(session)).await;
    direct::outcome_message(&out, &root)
}

// ---------------------------------------------------------------- dictionary

/// Where the dictionary lives: the configured file, else `dictionary.txt` next to the config.
fn dictionary_path(cfg_path: &Path, cfg: Option<&Config>) -> PathBuf {
    cfg.and_then(|c| c.redact.dictionary_file.clone())
        .map(|p| expand_tilde(&p))
        .unwrap_or_else(|| {
            cfg_path
                .parent()
                .unwrap_or(Path::new("."))
                .join("dictionary.txt")
        })
}

/// Set `[redact] dictionary_file` in the user config when it is not set yet.
fn set_dictionary_file(cfg_path: &Path, dict: &Path) -> Result<bool> {
    let text = std::fs::read_to_string(cfg_path)?;
    let mut doc: toml_edit::DocumentMut = text.parse().context("config is not valid TOML")?;
    let redact = doc
        .entry("redact")
        .or_insert_with(|| toml_edit::Item::Table(toml_edit::Table::new()));
    let Some(t) = redact.as_table_mut() else {
        bail!("[redact] in {} is not a table", pretty(cfg_path));
    };
    if t.contains_key("dictionary_file") {
        return Ok(false);
    }
    t.insert(
        "dictionary_file",
        toml_edit::value(dict.to_string_lossy().as_ref()),
    );
    onboard::write_config(cfg_path, &doc.to_string())?;
    Ok(true)
}

/// `middleman dict suggest`, also the init wizard's "Protect your company names" step.
/// Writes only after the user picked (or with `yes`).
pub(crate) fn dict_suggest(
    cfg_path: &Path,
    root: Option<PathBuf>,
    yes: bool,
    min: middleman::suggest::Confidence,
    json: bool,
) -> Result<()> {
    use middleman::suggest;
    let ui = middleman::ui::Ui::stderr();
    let cfg = cfg_path
        .exists()
        .then(|| Config::load_with_project(cfg_path, &cwd()).map(|(c, _)| c))
        .transpose()?;
    let root = root
        .map(|r| expand_tilde(&r))
        .or_else(|| middleman::config::project_root_for(&cwd()))
        .unwrap_or_else(cwd);
    let root = std::fs::canonicalize(&root).unwrap_or(root);
    let dict = dictionary_path(cfg_path, cfg.as_ref());
    let public = cfg.as_ref().map(|c| c.public_hosts()).unwrap_or_else(|| {
        middleman::config::DEFAULT_PUBLIC_HOSTS
            .iter()
            .map(|s| s.to_string())
            .collect()
    });
    let cands = suggest::mine(&root, &suggest::existing_terms(&dict), &public);
    if json {
        say!("{}", serde_json::to_string_pretty(&cands)?);
        return Ok(());
    }
    note!(
        "\n  {}\n  {}",
        ui.bold(&format!("Names found in {}", pretty(&root))),
        ui.dim("Read locally (files, git config, git log); nothing was sent anywhere.")
    );
    if cands.is_empty() {
        note!(
            "  No new candidates; the dictionary at {} already covers them.",
            pretty(&dict)
        );
        return Ok(());
    }
    let preselect = |c: &suggest::Candidate| c.confidence >= min;
    let picked: Vec<usize> = if yes {
        (0..cands.len())
            .filter(|&i| cands[i].confidence >= min)
            .collect()
    } else if interactive() {
        let items: Vec<String> = cands.iter().map(suggest::describe).collect();
        let defaults: Vec<bool> = cands.iter().map(preselect).collect();
        note!(
            "  {}",
            ui.dim("Space toggles, Enter confirms. Low-confidence names are not preselected.")
        );
        dialoguer::MultiSelect::with_theme(&theme())
            .with_prompt("Add to the private dictionary")
            .items(&items)
            .defaults(&defaults)
            .interact()?
    } else {
        for c in &cands {
            let mark = if preselect(c) { "[x]" } else { "[ ]" };
            say!("  {mark} {}", suggest::describe(c));
        }
        note!(
            "\n  Nothing written. Run it in a terminal to pick, or pass --yes (adds {} and above).",
            min.as_str()
        );
        return Ok(());
    };
    if yes {
        for &i in &picked {
            say!("  [x] {}", suggest::describe(&cands[i]));
        }
    }
    if picked.is_empty() {
        note!("  Nothing selected; nothing written.");
        return Ok(());
    }
    if cfg.is_none() {
        bail!(
            "no config at {}: run `middleman init` first",
            pretty(cfg_path)
        );
    }
    let chosen: Vec<&suggest::Candidate> = picked.iter().map(|&i| &cands[i]).collect();
    let n = suggest::append(&dict, &chosen)?;
    note!(
        "  {}",
        ui.ok(&format!("Added {n} line(s) to {}", pretty(&dict)))
    );
    if set_dictionary_file(cfg_path, &dict)? {
        note!(
            "  {}",
            ui.ok(&format!(
                "Set [redact] dictionary_file in {}",
                pretty(cfg_path)
            ))
        );
    }
    Ok(())
}

// ---------------------------------------------------------------- keys and providers

fn read_key_stdin() -> Result<Secret> {
    let mut s = zeroize::Zeroizing::new(String::new());
    std::io::stdin()
        .take(16 * 1024)
        .read_to_string(&mut s)
        .context("cannot read the key from stdin")?;
    Ok(Secret::new(s.trim()))
}

fn read_key_hidden(preset: &Preset) -> Result<Secret> {
    let label = preset.name;
    let k = dialoguer::Password::with_theme(&theme())
        .with_prompt(format!("Paste your {label} API key (input is hidden)"))
        .interact()
        .context("no key entered")?;
    let k = zeroize::Zeroizing::new(k);
    Ok(Secret::new(k.trim()))
}

async fn browser_login(no_browser: bool, timeout: Duration) -> Result<Secret> {
    let pk = oauth::pkce()?;
    let code = if no_browser {
        let url = oauth::auth_url(None, &pk.challenge, None, "middleman");
        note!("Open this link, log in to OpenRouter and authorize middleman:\n\n  {url}\n");
        let c: String = dialoguer::Input::with_theme(&theme())
            .with_prompt("Paste the code the page shows")
            .interact_text()
            .context("no code entered")?;
        zeroize::Zeroizing::new(c.trim().to_string())
    } else {
        let cb = oauth::Callback::bind()?;
        let state = oauth::new_state()?;
        let url = oauth::auth_url(Some(&cb.url()), &pk.challenge, Some(&state), "middleman");
        note!("Opening your browser to log in to OpenRouter. If it does not open, visit:\n\n  {url}\n");
        if open::that_detached(&url).is_err() {
            note!("(could not open a browser; open the link above yourself)");
        }
        note!(
            "Waiting for the browser (up to {}s; Ctrl-C to cancel)...",
            timeout.as_secs()
        );
        tokio::task::spawn_blocking(move || cb.wait(&state, timeout))
            .await
            .context("login listener crashed")??
    };
    oauth::exchange(oauth::EXCHANGE_URL, &code, &pk.verifier).await
}

#[derive(Clone, Copy, PartialEq)]
enum KeyHow {
    Ask,
    Stdin,
    Login,
}

/// Get a key for `preset`: browser login, stdin, or a hidden prompt. Validates it unless
/// `no_validate`. Nothing is stored here.
async fn obtain_key(preset: &Preset, how: KeyHow, no_validate: bool) -> Result<Secret> {
    let can_login = preset.name == "openrouter";
    let how = match how {
        KeyHow::Login if !can_login => bail!(
            "{} has no browser login; paste the key instead (`middleman provider add {}`)",
            preset.name,
            preset.name
        ),
        KeyHow::Ask if !interactive() => bail!(
            "no terminal to ask for the key: pipe it in with `--key-stdin`, or export {}",
            preset.key_env.unwrap_or("the key variable")
        ),
        KeyHow::Ask if can_login => {
            let i = dialoguer::Select::with_theme(&theme())
                .with_prompt("How do you want to connect OpenRouter?")
                .items([
                    "Log in with my browser (recommended: creates a key for middleman)",
                    "Paste an existing API key",
                ])
                .default(0)
                .interact()?;
            if i == 0 {
                KeyHow::Login
            } else {
                KeyHow::Ask
            }
        }
        h => h,
    };
    let key = match how {
        KeyHow::Login => browser_login(false, Duration::from_secs(300)).await?,
        KeyHow::Stdin => read_key_stdin()?,
        KeyHow::Ask => read_key_hidden(preset)?,
    };
    let ui = middleman::ui::Ui::stderr();
    if how != KeyHow::Login {
        if let Some(w) = onboard::check_pasted(preset.label, preset.key_prefix, key.expose())? {
            note!("{}", ui.warn(&w));
        }
    }
    if !no_validate {
        let base = preset.check_base_url();
        let res = ui
            .spin(
                &format!("Checking the key with a free request to {}", preset.host()),
                onboard::validate_key(preset.api, &base, preset.balance, &key),
            )
            .await;
        match res {
            Ok(info) => note!(
                "{}",
                ui.ok(&format!("{} works: {}", preset.label, info.summary()))
            ),
            Err(e) => {
                let d = onboard::diagnose(
                    &e,
                    &onboard::CheckTarget {
                        label: preset.label,
                        key_url: preset.key_url,
                        local: false,
                    },
                );
                bail!("{} {}", d.title, d.advice);
            }
        }
    }
    Ok(key)
}

fn store(name: &str, key: &Secret) -> Result<KeySource> {
    let st = keystore::store_key(name, key)?;
    if let Some(w) = &st.warning {
        note!("warning: {w}");
    }
    note!("Stored the {name} key in {}.", st.location);
    Ok(st.source)
}

fn preset_or_bail(name: &str) -> Result<&'static Preset> {
    presets::find(name).with_context(|| {
        format!(
            "unknown provider {name:?}; one of: {} (see `middleman init --list`)",
            presets::visible()
                .iter()
                .map(|p| p.name)
                .collect::<Vec<_>>()
                .join(", ")
        )
    })
}

fn read_config_text(cfg_path: &Path) -> Result<String> {
    std::fs::read_to_string(cfg_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            anyhow::anyhow!(
                "no config at {}: run `middleman init` first (it sets up a provider too)",
                pretty(cfg_path)
            )
        } else {
            anyhow::anyhow!("cannot read {}: {e}", pretty(cfg_path))
        }
    })
}

async fn provider_add(
    cfg_path: &Path,
    name: Option<String>,
    how: KeyHow,
    no_validate: bool,
    must_exist: bool,
) -> Result<()> {
    let text = read_config_text(cfg_path)?;
    let preset = match name {
        Some(n) => preset_or_bail(&n)?,
        None if interactive() => cli_init::pick_preset()?,
        None => bail!("name the provider, e.g. `middleman provider add openrouter`"),
    };
    if must_exist {
        let cfg = Config::from_toml(&text)?;
        if !cfg.providers.contains_key(preset.name) {
            bail!(
                "{} is not configured: use `middleman provider add {}`",
                preset.name,
                preset.name
            );
        }
    }
    let source = if preset.key_env.is_none() {
        note!("{} runs locally and needs no key.", preset.name);
        None
    } else {
        let key = obtain_key(preset, how, no_validate).await?;
        Some(store(preset.name, &key)?)
    };
    let new = onboard::upsert_provider(&text, preset.name, source)?;
    onboard::write_config(cfg_path, &new)?;
    note!(
        "Updated {} ([providers.{}]).",
        pretty(cfg_path),
        preset.name
    );
    if let Some(env) = preset.key_env {
        if std::env::var_os(env).is_some() {
            note!("note: {env} is set in this shell and takes precedence over the stored key.");
        }
    }
    if must_exist {
        note!("If the old key is no longer needed, revoke it in the provider's dashboard.");
    } else {
        note!(
            "Done. Next: `middleman setup claude` (once), then `middleman provider test {}` any time.",
            preset.name
        );
    }
    Ok(())
}

fn provider_list(cfg_path: &Path) -> Result<()> {
    let cfg = load(cfg_path)?;
    if cfg.providers.is_empty() {
        say!("no providers configured: run `middleman provider add openrouter`");
        return Ok(());
    }
    say!("{:<14} {:<8} KEY", "PROVIDER", "ENABLED");
    for (name, p) in &cfg.providers {
        let st = p.key_status();
        say!(
            "{:<14} {:<8} {} {}",
            clean(name, 14),
            if p.enabled { "yes" } else { "no" },
            if st.ok() { "✓" } else { "✗" },
            clean(&st.describe(), 120)
        );
    }
    say!("(keys are never shown; env vars take precedence over stored keys)");
    Ok(())
}

/// `provider refresh`: fetch limits into the status line's cache.
async fn provider_refresh(cfg_path: &Path, quiet: bool, from_statusline: bool) -> Result<ExitCode> {
    let cfg = match load(cfg_path) {
        Ok(c) => c,
        Err(e) => {
            if from_statusline {
                // the status line took the lock in the default state dir only if it could
                // read the config, so there is nothing to release here
                return Ok(ExitCode::from(1));
            }
            return Err(e);
        }
    };
    let state = cfg.state_dir();
    let res = middleman::limits::refresh(&cfg).await;
    if from_statusline {
        middleman::limits::release_lock(&state);
    }
    let c = res?;
    if !quiet {
        if c.providers.is_empty() {
            say!("no enabled provider has a balance or limits endpoint");
        }
        for (name, l) in &c.providers {
            let name = clean(name, 24);
            let mut parts = vec![];
            if let Some(b) = l.balance_usd {
                parts.push(format!("balance ${b:.4}"));
            }
            if let Some(k) = &l.key {
                if let Some(x) = k.limit_usd {
                    parts.push(format!("key limit ${x:.2}"));
                }
                if let Some(x) = k.remaining_usd() {
                    parts.push(format!("key remaining ${x:.4}"));
                }
                if let Some(x) = k.usage_daily_usd {
                    parts.push(format!("used today ${x:.4}"));
                }
                if let Some(x) = k.usage_usd {
                    parts.push(format!("used all-time ${x:.4}"));
                }
            }
            if let Some(e) = &l.error {
                parts.push(format!("error: {e}"));
            }
            let mark = if l.error.is_some() && l.left_usd().is_none() {
                "✗"
            } else {
                "✓"
            };
            say!("{mark} {name}: {}", parts.join(", "));
        }
        say!("cache: {}", pretty(&middleman::limits::cache_path(&state)));
    }
    Ok(ExitCode::SUCCESS)
}

async fn provider_test(cfg_path: &Path, name: &str) -> Result<ExitCode> {
    let cfg = load(cfg_path)?;
    let p = cfg.providers.get(name).with_context(|| {
        format!("{name} is not configured: run `middleman provider add {name}`")
    })?;
    let key = p.resolve_key()?;
    if !p.needs_key() {
        let n = Provider::from_cfg(name, p, 20)?.models().await?.len();
        say!("✓ {name}: reachable, {n} models");
        return Ok(ExitCode::SUCCESS);
    }
    match onboard::validate_key(p.api, &p.base_url, p.balance, &key).await {
        Ok(info) => {
            say!(
                "✓ {name}: key from {} works ({})",
                p.key_status().describe(),
                info.summary()
            );
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            say!("✗ {name}: {e:#}. Replace it with `middleman provider rotate {name}`.");
            Ok(ExitCode::from(1))
        }
    }
}

fn provider_remove(cfg_path: &Path, name: &str, yes: bool) -> Result<()> {
    let text = read_config_text(cfg_path)?;
    if !yes {
        if !interactive() {
            bail!("re-run with --yes to remove {name} without a prompt");
        }
        let ok = dialoguer::Confirm::with_theme(&theme())
            .with_prompt(format!("Remove {name} and its stored key?"))
            .default(false)
            .interact()?;
        if !ok {
            note!("Nothing changed.");
            return Ok(());
        }
    }
    for s in [keystore::Store::keychain(), keystore::Store::file()] {
        match s.delete(name) {
            Ok(true) => note!("Deleted the key from {}.", s.describe(name)),
            Ok(false) => {}
            Err(e) if s.source() == KeySource::Keychain => {
                note!("note: could not check the keychain: {e:#}")
            }
            Err(e) => return Err(e),
        }
    }
    let (new, removed) = onboard::remove_provider(&text, name)?;
    if removed {
        onboard::write_config(cfg_path, &new).with_context(|| {
            format!(
                "routes in {} may still name {name}; edit them",
                pretty(cfg_path)
            )
        })?;
        note!("Removed [providers.{name}] from {}.", pretty(cfg_path));
    } else {
        note!("{name} was not in {}.", pretty(cfg_path));
    }
    Ok(())
}

async fn login(cfg_path: &Path, provider: &str, no_browser: bool, timeout: u64) -> Result<()> {
    if provider != "openrouter" {
        bail!("only openrouter supports browser login; use `middleman provider add {provider}`");
    }
    let preset = preset_or_bail(provider)?;
    let key = browser_login(no_browser, Duration::from_secs(timeout.max(10))).await?;
    let info =
        onboard::validate_key(preset.api, &preset.check_base_url(), preset.balance, &key).await?;
    note!("Logged in: {}", info.summary());
    let source = store(provider, &key)?;
    match std::fs::read_to_string(cfg_path) {
        Ok(text) => {
            let new = onboard::upsert_provider(&text, provider, Some(source))?;
            onboard::write_config(cfg_path, &new)?;
            note!("Updated {}.", pretty(cfg_path));
        }
        Err(_) => note!("No config yet: run `middleman init` to finish setting up."),
    }
    Ok(())
}

// ---------------------------------------------------------------- setup claude

/// `setup claude` switches; `Default` = preview, ask, wire everything.
#[derive(Default, Clone, Copy)]
struct SetupFlags {
    dry_run: bool,
    yes: bool,
    undo: bool,
    refresh: bool,
    details: bool,
    no_statusline: bool,
    statusline_combined: bool,
    no_hook: bool,
    no_claude_md: bool,
    no_permissions: bool,
}

fn styled_log_line(ui: &middleman::ui::Ui, l: &str) -> String {
    if l.starts_with("backed up") || l.starts_with("undo with") {
        format!("  {}", ui.dim(l))
    } else if l.starts_with("updated") || l.starts_with("restored") || l.starts_with("removed") {
        format!("  {}", ui.ok(l))
    } else {
        format!("  {l}")
    }
}

fn setup_claude(cfg_path: &Path, scope: &str, f: SetupFlags) -> Result<()> {
    let home = home();
    let ui = middleman::ui::Ui::stdout();
    if f.undo {
        for l in claude_setup::undo(&claude_setup::backups_root(&home))? {
            say!("{}", styled_log_line(&ui, &l));
        }
        say!("  Restart Claude Code to pick up the change.");
        return Ok(());
    }
    if f.refresh {
        return setup_refresh(cfg_path, &home, f);
    }
    let scope = Scope::parse(scope).context("--scope must be user or project")?;
    let config_path = std::path::absolute(cfg_path).unwrap_or_else(|_| cfg_path.to_path_buf());
    if !config_path.exists() {
        note!(
            "warning: no config at {} yet; run `middleman init` or the statusline will show ✗",
            pretty(&config_path)
        );
    }
    let o = SetupOptions {
        scope,
        home: home.clone(),
        project_dir: cwd(),
        exe: std::env::current_exe().context("cannot find the middleman binary")?,
        config_path,
        hook: !f.no_hook,
        statusline: !f.no_statusline,
        statusline_combined: f.statusline_combined,
        claude_md: !f.no_claude_md,
        permissions: !f.no_permissions,
    };
    let plan = claude_setup::plan(&o)?;
    say!("{}", plan.render_ui(&ui, f.details).trim_end());
    if plan.is_empty() {
        return Ok(());
    }
    if f.dry_run {
        say!(
            "\n  {}",
            ui.dim("(dry run: nothing was changed; --details shows the exact keys)")
        );
        return Ok(());
    }
    if !f.yes {
        if !interactive() {
            bail!("re-run with --yes to apply without a prompt (or --dry-run to only look)");
        }
        say!("");
        let ok = dialoguer::Confirm::with_theme(&theme())
            .with_prompt("Apply these changes?")
            .default(true)
            .interact()?;
        if !ok {
            say!("  Nothing changed.");
            return Ok(());
        }
    }
    say!("");
    for l in claude_setup::apply(&plan, &claude_setup::backups_root(&home))? {
        say!("{}", styled_log_line(&ui, &l));
    }
    say!(
        "\n  {}",
        ui.ok("Done. Restart Claude Code (or run /mcp) to load middleman.")
    );
    Ok(())
}

/// `setup claude --refresh`: bring middleman's existing entries up to this version.
fn setup_refresh(cfg_path: &Path, home: &Path, f: SetupFlags) -> Result<()> {
    let ui = middleman::ui::Ui::stdout();
    let o = claude_setup::RefreshOptions {
        home: home.to_path_buf(),
        project_dirs: claude_setup::installed_project_dirs(home, &cwd()),
        exe: std::env::current_exe().context("cannot find the middleman binary")?,
        config_path: std::path::absolute(cfg_path).unwrap_or_else(|_| cfg_path.to_path_buf()),
    };
    let plan = claude_setup::refresh_plan(&o);
    if plan.is_empty() {
        say!(
            "  {}",
            ui.ok("middleman's Claude Code wiring is current; nothing to refresh.")
        );
        for n in &plan.notes {
            say!("  {}", ui.warn(n));
        }
        return Ok(());
    }
    say!("{}", plan.render_ui(&ui, f.details).trim_end());
    if f.dry_run {
        say!("\n  {}", ui.dim("(dry run: nothing was changed)"));
        return Ok(());
    }
    if !f.yes {
        if !interactive() {
            bail!("re-run with --yes to apply without a prompt (or --dry-run to only look)");
        }
        say!("");
        let ok = dialoguer::Confirm::with_theme(&theme())
            .with_prompt("Refresh these entries?")
            .default(true)
            .interact()?;
        if !ok {
            say!("  Nothing changed.");
            return Ok(());
        }
    }
    say!("");
    for l in claude_setup::apply(&plan, &claude_setup::backups_root(home))? {
        say!("{}", styled_log_line(&ui, &l));
    }
    say!(
        "\n  {}",
        ui.ok("Refreshed. Run /mcp in Claude Code (or restart it) to reconnect middleman.")
    );
    Ok(())
}

async fn real_main() -> Result<ExitCode> {
    let cli = Cli::parse();
    let cfg_path = cli
        .config
        .map(|p| expand_tilde(&p))
        .unwrap_or_else(default_config_path);
    match cli.cmd {
        Cmd::Route { hook: true, .. } => {
            route_hook(&cfg_path).await;
            return Ok(ExitCode::SUCCESS);
        }
        Cmd::Statusline {
            lines,
            middleman_only,
            columns,
        } => {
            let mut o = middleman::statusline::Opts::from_env(&|k: &str| std::env::var(k).ok());
            if let Some(l) = lines {
                o.lines = l.clamp(1, 2);
            }
            if let Some(c) = columns.filter(|c| *c > 0) {
                o.columns = c;
            } else if std::env::var_os("COLUMNS").is_none() {
                // Claude Code doesn't pass COLUMNS: measure the terminal, leaving a small margin
                // for the status line's own indent so the last number is never cut off.
                if let Some(c) = middleman::statusline::tty_columns() {
                    o.columns = c.saturating_sub(4).max(20);
                }
            }
            o.middleman_only = middleman_only;
            say!("{}", middleman::statusline::run(&cfg_path, &o));
            return Ok(ExitCode::SUCCESS);
        }
        Cmd::Completions { shell } => {
            clap_complete::generate(
                shell,
                &mut Cli::command(),
                "middleman",
                &mut std::io::stdout(),
            );
            return Ok(ExitCode::SUCCESS);
        }
        Cmd::Route { text, hook: false } => {
            let cfg = load(&cfg_path).ok();
            let mode = cfg
                .as_ref()
                .map(|c| c.routing.mode)
                .unwrap_or(RoutingMode::Auto);
            let dict = cfg
                .as_ref()
                .and_then(|c| c.redact.dictionary_file.as_ref())
                .and_then(|p| Dictionary::load(p).ok());
            let text = text.context("usage: middleman route \"<prompt text>\"")?;
            let a = middleman::hook::advise(
                &text,
                mode,
                dict.as_ref(),
                cfg.as_ref().map(|c| &c.economics),
            );
            say!("{}", serde_json::to_string_pretty(&a)?);
            return Ok(ExitCode::SUCCESS);
        }
        Cmd::Init {
            scope,
            providers,
            mode,
            root,
            yes,
            key_stdin,
            no_validate,
            base_url,
            force,
            apply,
            list,
        } => {
            if list {
                say!("{}", cli_init::list(&cfg_path).trim_end());
                return Ok(ExitCode::SUCCESS);
            }
            let a = cli_init::InitArgs {
                scope,
                providers,
                mode,
                root,
                yes,
                force,
                apply,
                key_stdin,
                no_validate,
                base_url,
            };
            cli_init::run(cfg_path, a).await?;
            return Ok(ExitCode::SUCCESS);
        }
        Cmd::Provider { action } => {
            return match action {
                ProviderCmd::Add {
                    name,
                    key_stdin,
                    login,
                    no_validate,
                } => {
                    let how = if login {
                        KeyHow::Login
                    } else if key_stdin {
                        KeyHow::Stdin
                    } else {
                        KeyHow::Ask
                    };
                    provider_add(&cfg_path, name, how, no_validate, false).await?;
                    Ok(ExitCode::SUCCESS)
                }
                ProviderCmd::Rotate {
                    name,
                    key_stdin,
                    login,
                    no_validate,
                } => {
                    let how = if login {
                        KeyHow::Login
                    } else if key_stdin {
                        KeyHow::Stdin
                    } else {
                        KeyHow::Ask
                    };
                    provider_add(&cfg_path, Some(name), how, no_validate, true).await?;
                    Ok(ExitCode::SUCCESS)
                }
                ProviderCmd::List { all: true } => {
                    say!("{}", cli_init::list(&cfg_path).trim_end());
                    Ok(ExitCode::SUCCESS)
                }
                ProviderCmd::List { all: false } => {
                    provider_list(&cfg_path)?;
                    Ok(ExitCode::SUCCESS)
                }
                ProviderCmd::Test { name } => provider_test(&cfg_path, &name).await,
                ProviderCmd::Refresh {
                    quiet,
                    from_statusline,
                } => provider_refresh(&cfg_path, quiet, from_statusline).await,
                ProviderCmd::Remove { name, yes } => {
                    provider_remove(&cfg_path, &name, yes)?;
                    Ok(ExitCode::SUCCESS)
                }
            };
        }
        Cmd::Login {
            provider,
            no_browser,
            timeout,
        } => {
            login(&cfg_path, &provider, no_browser, timeout).await?;
            return Ok(ExitCode::SUCCESS);
        }
        Cmd::Setup {
            target:
                SetupTarget::Claude {
                    scope,
                    dry_run,
                    details,
                    yes,
                    undo,
                    refresh,
                    no_statusline,
                    statusline,
                    no_hook,
                    no_claude_md,
                    no_permissions,
                },
        } => {
            let (off, combined) = match statusline.as_str() {
                "auto" => (false, false),
                "combined" => (false, true),
                "off" => (true, false),
                other => bail!("--statusline must be auto, combined or off (got {other:?})"),
            };
            setup_claude(
                &cfg_path,
                &scope,
                SetupFlags {
                    dry_run,
                    yes,
                    undo,
                    refresh,
                    details,
                    no_statusline: no_statusline || off,
                    statusline_combined: combined,
                    no_hook,
                    no_claude_md,
                    no_permissions,
                },
            )?;
            return Ok(ExitCode::SUCCESS);
        }
        Cmd::Watch { tail, no_follow } => {
            let state = Config::load(&cfg_path)
                .map(|c| c.state_dir())
                .unwrap_or_else(|_| expand_tilde(Path::new("~/.local/state/middleman")));
            let path = state.join("ledger.jsonl");
            tokio::task::spawn_blocking(move || {
                middleman::watch::run(&path, tail, !no_follow, &mut std::io::stdout())
            })
            .await??;
            return Ok(ExitCode::SUCCESS);
        }
        Cmd::Usage {
            since,
            by,
            json,
            html,
        } => {
            let cfg = load(&cfg_path).ok();
            let ucfg = cfg.as_ref().map(|c| c.usage.clone()).unwrap_or_default();
            let ledger = cfg
                .as_ref()
                .and_then(|c| middleman::ledger::Ledger::new(&c.state_dir()).ok())
                .and_then(|l| l.entries().ok())
                .unwrap_or_default();
            let since = middleman::report::parse_since(&since)?;
            if !["model", "day", "project", "session", "agent"].contains(&by.as_str()) {
                bail!("--by must be model, day, project, session or agent");
            }
            let msgs = middleman::usage::load(&ucfg, since);
            let r = middleman::usage::build(&ucfg, &msgs, since, &by, &ledger);
            if let Some(path) = html {
                let by_day = middleman::usage::build(&ucfg, &msgs, since, "day", &ledger);
                std::fs::write(&path, middleman::usage::render_html(&r, &by_day))?;
                say!("wrote {}", path.display());
            }
            if json {
                say!("{}", serde_json::to_string_pretty(&r)?);
            } else {
                say!("{}", middleman::usage::render_text(&r));
            }
            return Ok(ExitCode::SUCCESS);
        }
        Cmd::Tune { since, json, apply } => {
            let cfg = load(&cfg_path).ok();
            let ucfg = cfg.as_ref().map(|c| c.usage.clone()).unwrap_or_default();
            let ledger = cfg
                .as_ref()
                .and_then(|c| middleman::ledger::Ledger::new(&c.state_dir()).ok())
                .and_then(|l| l.entries().ok())
                .unwrap_or_default();
            let since = middleman::report::parse_since(&since)?;
            let msgs = middleman::usage::load(&ucfg, since);
            let r = middleman::usage::build(&ucfg, &msgs, since, "agent", &ledger);
            let t = middleman::tune::tune(&ucfg, &r);
            if json {
                say!("{}", serde_json::to_string_pretty(&t)?);
            } else {
                say!("{}", middleman::tune::render_text(&t));
            }
            if apply {
                let p = expand_tilde(Path::new("~/.claude/settings.json"));
                say!("{}", middleman::tune::apply(&p, &t.settings_snippet)?);
            }
            return Ok(ExitCode::SUCCESS);
        }
        Cmd::Dict {
            action:
                DictCmd::Suggest {
                    yes,
                    min_confidence,
                    root,
                    json,
                },
        } => {
            let min = middleman::suggest::Confidence::parse(&min_confidence)
                .context("--min-confidence must be low, medium or high")?;
            dict_suggest(&cfg_path, root, yes, min, json)?;
            return Ok(ExitCode::SUCCESS);
        }
        Cmd::Upgrade {
            check,
            version,
            yes,
            no_wiring,
            rollback,
            require_attestation,
            quiet,
            write_cache,
        } => {
            let a = cli_upgrade::UpgradeArgs {
                check,
                version,
                yes,
                no_wiring,
                rollback,
                require_attestation,
                quiet,
                write_cache,
            };
            return cli_upgrade::run(&cfg_path, a).await;
        }
        Cmd::Doctor => {
            if let Ok(cfg) = Config::load(&cfg_path) {
                let env = |k: &str| std::env::var(k).ok();
                if middleman::upgrade::checks_enabled(cfg.update.check, &env) {
                    let state = cfg.state_dir();
                    let c = middleman::upgrade::load_cache(&state);
                    middleman::upgrade::maybe_check(
                        &state,
                        c.as_ref(),
                        middleman::ledger::now_unix(),
                        &mut || middleman::upgrade::spawn_check(&cfg_path),
                    );
                }
            }
            let checks = setup::doctor(&cfg_path, &cwd(), &home()).await;
            let mut ok = true;
            for c in &checks {
                say!("{} {:<32} {}", c.label(), c.name, c.detail);
                ok &= c.ok || c.optional;
            }
            return Ok(if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            });
        }
        _ => {}
    }
    let cfg = load(&cfg_path)?;
    match cli.cmd {
        Cmd::Approve { id } => {
            middleman::approval::require_terminal()?;
            eprint!("Approve delegation {id}? Type 'yes' to approve: ");
            let mut answer = String::new();
            std::io::stdin().read_line(&mut answer)?;
            if answer.trim() != "yes" {
                bail!("not approved");
            }
            middleman::approval::Approvals::new(&cfg.state_dir()).approve(&id)?;
            say!("approved {id} (single use, expires 30 min after the dry run)");
        }
        Cmd::Mcp => {
            let pipeline = Pipeline::new(cfg)?;
            Server::new(pipeline).run_stdio().await?;
        }
        Cmd::Check {
            files,
            task_kind,
            declared,
            instructions,
        } => {
            let task_kind = TaskKind::parse(&task_kind).with_context(|| {
                format!(
                    "unknown task kind {task_kind:?}; one of {}",
                    TaskKind::ALL.map(|k| k.as_str()).join(", ")
                )
            })?;
            let declared = Declared::parse(&declared)
                .context("--declared must be public, internal or confidential")?;
            let pipeline = Pipeline::new_offline(cfg)?;
            let mut req = DelegateRequest::simple(task_kind, &instructions, declared);
            req.files = files
                .into_iter()
                .map(|path| FileRef {
                    path,
                    start_line: None,
                    end_line: None,
                })
                .collect();
            req.dry_run = true;
            let out = pipeline.run(req).await;
            say!("{}", serde_json::to_string_pretty(&out)?);
            if out.sanitized_payload.is_some() {
                say!("\negress gate: passed (no vault original, credential or detectable item in the payload)");
                return Ok(ExitCode::SUCCESS);
            }
            return Ok(ExitCode::from(3));
        }
        Cmd::Models { action, all } => {
            let refresh = match action.as_deref() {
                None | Some("list") => false,
                Some("refresh") => true,
                Some(other) => bail!("unknown models action {other:?} (list or refresh)"),
            };
            let pipeline = Pipeline::new(cfg)?;
            let Some(c) = pipeline.catalog(refresh).await else {
                bail!("no model catalog yet: run `middleman models refresh`");
            };
            for e in &c.errors {
                say!("error: {}", clean(e, 300));
            }
            if all {
                for m in &c.models {
                    say!(
                        "{}/{} in={} out={} ctx={:?} modality={:?}",
                        clean(&m.provider, 30),
                        clean(&m.info.id, 80),
                        fmt_price(m.info.price_in_per_1m),
                        fmt_price(m.info.price_out_per_1m),
                        m.info.context_length,
                        m.info.modality.as_deref().map(|s| clean(s, 30))
                    );
                }
            } else {
                let mut v = c.resolve(pipeline.config());
                v.sort_by(|a, b| {
                    let k = |m: &middleman::catalog::Priced| {
                        m.prices
                            .map(|p| p.in_per_1m + 4.0 * p.out_per_1m)
                            .unwrap_or(f64::MAX)
                    };
                    k(a).partial_cmp(&k(b)).unwrap_or(std::cmp::Ordering::Equal)
                });
                for m in v {
                    say!(
                        "{:<14} {:<40} in ${:>7}/1M out ${:>7}/1M ctx={:<8} tags={}{}",
                        clean(&m.provider, 14),
                        clean(&m.id, 80),
                        fmt_price(m.prices.map(|p| p.in_per_1m)),
                        fmt_price(m.prices.map(|p| p.out_per_1m)),
                        m.context
                            .map(|c| c.to_string())
                            .unwrap_or_else(|| "?".into()),
                        clean(&m.tags.join(","), 80),
                        if m.prices.is_none() {
                            "  (price unknown: ineligible)"
                        } else {
                            ""
                        }
                    );
                }
            }
            say!(
                "catalog: {} models, age {}s, cache {}",
                c.models.len(),
                c.age_secs(),
                Catalog::cache_path(pipeline.config()).display()
            );
        }
        Cmd::Balance { provider } => {
            let name = pick_provider(&cfg, provider)?;
            let p = Provider::from_cfg(&name, &cfg.providers[&name], 60)?;
            let b = p.balance().await?;
            say!("{name}: balance_usd={:.4} payg={:?}", b.usd, b.payg);
        }
        Cmd::Ledger { tail } => {
            let l = middleman::ledger::Ledger::new(&cfg.state_dir())?;
            let e = l.entries()?;
            for x in e.iter().rev().take(tail).rev() {
                say!(
                    "{} #{} {:<14} {}/{} {} [{}] cost=${:.6} ({}) net=${:.5} tok={:?}/{:?} {}ms {}",
                    clean(&x.ts, 40),
                    x.attempt,
                    clean(&x.status, 14),
                    clean(&x.provider, 30),
                    clean(&x.model, 80),
                    clean(&x.task_kind, 20),
                    clean(&x.write_mode, 10),
                    x.cost_usd,
                    clean(&x.cost_source, 10),
                    x.net_savings_usd,
                    x.input_tokens,
                    x.output_tokens,
                    x.latency_ms.unwrap_or(0),
                    clean(x.block_reason_category.as_deref().unwrap_or(""), 40)
                );
            }
            let w = l.window()?;
            say!(
                "today ${:.6} / ${:.2}; last 7d ${:.6} / ${:.2}; ledger {}",
                w.day_usd,
                cfg.budget.daily_usd,
                w.week_usd,
                cfg.budget.weekly_usd,
                l.path().display()
            );
        }
        Cmd::Probe {
            provider,
            model,
            no_send,
        } => probe(&cfg, provider, model, no_send).await?,
        Cmd::Report {
            since,
            by,
            json,
            html,
            reconcile,
        } => {
            let since = middleman::report::parse_since(&since)?;
            let by = middleman::report::By::parse(&by)
                .context("--by must be model, provider, task, day or project")?;
            let l = middleman::ledger::Ledger::new(&cfg.state_dir())?;
            let es = l.entries()?;
            if reconcile {
                let r = middleman::reconcile::run(&cfg, &es, since).await;
                if json {
                    say!("{}", serde_json::to_string_pretty(&r)?);
                } else {
                    say!("{}", middleman::reconcile::render_text(&r).trim_end());
                }
                let bad = r.checks.iter().any(|c| !c.matches);
                return Ok(if bad {
                    ExitCode::from(4)
                } else {
                    ExitCode::SUCCESS
                });
            }
            if let Some(path) = html {
                std::fs::write(&path, middleman::report::render_html(&es, since))?;
                say!("wrote {}", path.display());
            }
            let r = middleman::report::build(&es, since, by);
            if json {
                say!("{}", serde_json::to_string_pretty(&r)?);
            } else {
                say!("{}", middleman::report::render_text(&r));
            }
        }
        Cmd::Route { .. }
        | Cmd::Init { .. }
        | Cmd::Provider { .. }
        | Cmd::Login { .. }
        | Cmd::Setup { .. }
        | Cmd::Statusline { .. }
        | Cmd::Watch { .. }
        | Cmd::Completions { .. }
        | Cmd::Doctor
        | Cmd::Upgrade { .. }
        | Cmd::Dict { .. }
        | Cmd::Usage { .. }
        | Cmd::Tune { .. } => unreachable!(),
    }
    Ok(ExitCode::SUCCESS)
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("MIDDLEMAN_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();
    match real_main().await {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "middleman: {e:#}");
            ExitCode::from(1)
        }
    }
}
