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
use middleman::setup::{self, InitOptions, Scope};
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
    /// Set up middleman: pick a provider, log in or paste a key, choose scope and routing mode
    Init {
        /// user (all projects) | project (this repo: also writes .middleman.toml)
        #[arg(long)]
        scope: Option<String>,
        /// Comma-separated presets, e.g. openrouter,deepseek (skips the picker)
        #[arg(long)]
        providers: Option<String>,
        /// auto | confirm | explicit
        #[arg(long)]
        mode: Option<String>,
        /// Allowed roots [default: current directory]
        #[arg(long)]
        root: Vec<PathBuf>,
        /// Non-interactive: accept defaults for anything not given (keys come from env vars)
        #[arg(long)]
        yes: bool,
        /// Overwrite existing middleman config files
        #[arg(long)]
        force: bool,
        /// Also run `middleman setup claude --yes` at the end
        #[arg(long)]
        apply: bool,
        /// List presets and which key env vars are set, then exit
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
    /// Print one status line for Claude Code's statusLine (reads its JSON on stdin)
    Statusline,
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
    /// Print shell completions (bash, zsh, fish, elvish, powershell)
    Completions { shell: clap_complete::Shell },
    /// Run the MCP stdio server (Claude Code starts this for you)
    Mcp,
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
    List,
    /// Check a provider's key with a free request
    Test { name: String },
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
enum SetupTarget {
    /// Register the MCP server, allow its tools, add the prompt hook, statusline and CLAUDE.md block
    Claude {
        /// user (~/.claude*) | project (.mcp.json, .claude/settings.json, CLAUDE.md here)
        #[arg(long, default_value = "user")]
        scope: String,
        /// Show the changes and exit
        #[arg(long)]
        dry_run: bool,
        /// Apply without asking
        #[arg(long)]
        yes: bool,
        /// Restore the files changed by the last `setup claude`
        #[arg(long)]
        undo: bool,
        #[arg(long)]
        no_statusline: bool,
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

/// Hook path: never fails, never blocks. A config that cannot be loaded produces a
/// "do not delegate" message instead of silently falling back to defaults.
fn route_hook(cfg_path: &Path) {
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
    if let Some(out) = middleman::hook::hook_output(
        &input,
        cfg.routing.mode,
        dict.as_ref(),
        Some(&cfg.economics),
    ) {
        say!("{out}");
    }
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
    if how != KeyHow::Login {
        if let Some(w) = onboard::check_pasted(preset.name, key.expose())? {
            note!("warning: {w}");
        }
    }
    if !no_validate {
        note!(
            "Checking the key with a free request to {}...",
            preset.base_url
        );
        let info = onboard::validate_key(preset.api, preset.base_url, preset.balance, &key).await?;
        note!("  ok: {}", info.summary());
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
            "unknown provider {name:?}; presets: {}",
            presets::PRESETS
                .iter()
                .map(|p| p.name)
                .collect::<Vec<_>>()
                .join(", ")
        )
    })
}

fn pick_preset() -> Result<&'static Preset> {
    let list: Vec<&'static Preset> = presets::PRESETS.iter().collect();
    let items: Vec<String> = list
        .iter()
        .map(|p| {
            let host = p
                .base_url
                .split("//")
                .nth(1)
                .and_then(|h| h.split('/').next())
                .unwrap_or("");
            let hint = match p.name {
                "openrouter" => "  one key for DeepSeek, Qwen, Kimi, GLM, ... (recommended)",
                "ollama" | "lmstudio" => "  local, no key",
                "anthropic" => "  first-party Claude API",
                _ => "",
            };
            format!("{:<13} {host}{hint}", p.name)
        })
        .collect();
    let default = list
        .iter()
        .position(|p| p.name == "openrouter")
        .unwrap_or(0);
    let i = dialoguer::Select::with_theme(&theme())
        .with_prompt("Pick a provider")
        .items(&items)
        .default(default)
        .interact()?;
    Ok(list[i])
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
        None if interactive() => pick_preset()?,
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
    let info = onboard::validate_key(preset.api, preset.base_url, preset.balance, &key).await?;
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

#[allow(clippy::too_many_arguments)]
fn setup_claude(
    cfg_path: &Path,
    scope: &str,
    dry_run: bool,
    yes: bool,
    undo: bool,
    statusline: bool,
    hook: bool,
    claude_md: bool,
    permissions: bool,
) -> Result<()> {
    let home = home();
    if undo {
        for l in claude_setup::undo(&claude_setup::backups_root(&home))? {
            say!("{l}");
        }
        say!("Restart Claude Code to pick up the change.");
        return Ok(());
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
        hook,
        statusline,
        claude_md,
        permissions,
    };
    let plan = claude_setup::plan(&o)?;
    say!("{}", plan.render().trim_end());
    if plan.is_empty() {
        return Ok(());
    }
    if dry_run {
        say!("(dry run: nothing was changed)");
        return Ok(());
    }
    if !yes {
        if !interactive() {
            bail!("re-run with --yes to apply without a prompt (or --dry-run to only look)");
        }
        let ok = dialoguer::Confirm::with_theme(&theme())
            .with_prompt("Apply these changes? (every file is backed up first)")
            .default(true)
            .interact()?;
        if !ok {
            say!("Nothing changed.");
            return Ok(());
        }
    }
    for l in claude_setup::apply(&plan, &claude_setup::backups_root(&home))? {
        say!("{l}");
    }
    say!("Done. Restart Claude Code (or run /mcp) to load middleman; `middleman doctor` checks everything.");
    Ok(())
}

// ---------------------------------------------------------------- init

fn parse_mode(m: &str) -> Result<RoutingMode> {
    Ok(match m {
        "auto" => RoutingMode::Auto,
        "confirm" => RoutingMode::Confirm,
        "explicit" => RoutingMode::Explicit,
        _ => bail!("mode must be auto, confirm or explicit"),
    })
}

#[allow(clippy::too_many_arguments)]
async fn init(
    cfg_path: PathBuf,
    scope: Option<String>,
    providers: Option<String>,
    mode: Option<String>,
    root: Vec<PathBuf>,
    yes: bool,
    force: bool,
    apply: bool,
) -> Result<()> {
    let ask = !yes && interactive();
    let mut key_sources = std::collections::BTreeMap::new();
    let providers: Vec<String> = match providers {
        Some(p) => p
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        None if ask => {
            let preset = pick_preset()?;
            if let Some(env) = preset.key_env {
                let has_env = std::env::var_os(env).is_some_and(|v| !v.is_empty());
                let use_env = has_env
                    && dialoguer::Confirm::with_theme(&theme())
                        .with_prompt(format!(
                            "{env} is set in this shell. Use it instead of storing a key?"
                        ))
                        .default(false)
                        .interact()?;
                if !use_env {
                    let key = obtain_key(preset, KeyHow::Ask, false).await?;
                    key_sources.insert(preset.name.to_string(), store(preset.name, &key)?);
                }
            }
            vec![preset.name.to_string()]
        }
        None => {
            let found: Vec<String> = setup::detect_keys()
                .into_iter()
                .filter(|k| k.2)
                .map(|k| k.0.to_string())
                .collect();
            if found.is_empty() {
                vec!["openrouter".into()]
            } else {
                found
            }
        }
    };
    for p in &providers {
        preset_or_bail(p)?;
    }
    let scope = match scope {
        Some(s) => Scope::parse(&s).context("--scope must be user or project")?,
        None if ask => {
            let i = dialoguer::Select::with_theme(&theme())
                .with_prompt("Where should middleman apply?")
                .items([
                    "All my projects (user scope)",
                    "Only this project (writes .middleman.toml here)",
                ])
                .default(0)
                .interact()?;
            if i == 0 {
                Scope::User
            } else {
                Scope::Project
            }
        }
        None => Scope::User,
    };
    let mode = match mode {
        Some(m) => parse_mode(&m)?,
        None if ask => {
            let i = dialoguer::Select::with_theme(&theme())
                .with_prompt("When may Claude delegate?")
                .items([
                    "auto      when it is safe and pays off (recommended)",
                    "confirm   show me the plan and ask first",
                    "explicit  only when I start a prompt with `cheap:`",
                ])
                .default(0)
                .interact()?;
            [
                RoutingMode::Auto,
                RoutingMode::Confirm,
                RoutingMode::Explicit,
            ][i]
        }
        None => RoutingMode::Auto,
    };
    let o = InitOptions {
        scope,
        providers: providers.clone(),
        mode,
        roots: if root.is_empty() { vec![cwd()] } else { root },
        config_path: cfg_path.clone(),
        project_dir: cwd(),
        force,
        key_sources: key_sources.clone(),
    };
    let existed = cfg_path.exists();
    for l in setup::init_write(&o)? {
        say!("{l}");
    }
    if existed && !force {
        // keep the user's config, but record any key we just stored
        let mut text = std::fs::read_to_string(&cfg_path)?;
        for (name, src) in &key_sources {
            text = onboard::upsert_provider(&text, name, Some(*src))?;
        }
        if !key_sources.is_empty() {
            onboard::write_config(&cfg_path, &text)?;
            say!("recorded the stored key in {}", pretty(&cfg_path));
        }
    }
    for p in &providers {
        if key_sources.contains_key(p) {
            continue;
        }
        if let Some(env) = preset_or_bail(p)?.key_env {
            if std::env::var_os(env).is_none() {
                say!("no key for {p} yet: run `middleman provider add {p}`");
            }
        }
    }
    let wire = apply
        || (ask
            && dialoguer::Confirm::with_theme(&theme())
                .with_prompt("Connect middleman to Claude Code now? (shows every change first)")
                .default(true)
                .interact()?);
    if wire {
        say!("");
        setup_claude(
            &cfg_path,
            scope.as_str(),
            false,
            apply,
            false,
            true,
            true,
            true,
            true,
        )?;
    } else {
        say!("Next: `middleman setup claude` connects it to Claude Code.");
    }
    say!("Then `middleman models refresh` fetches current prices, and `middleman doctor` checks it all.");
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
            route_hook(&cfg_path);
            return Ok(ExitCode::SUCCESS);
        }
        Cmd::Statusline => {
            say!("{}", middleman::statusline::run(&cfg_path));
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
            force,
            apply,
            list,
        } => {
            if list {
                for p in presets::PRESETS {
                    let present = p.key_env.map(|k| std::env::var_os(k).is_some());
                    say!(
                        "{:<14} {:?} {:<55} key_env={:<20} present={:?} trust={:?} verified={}",
                        p.name,
                        p.api,
                        p.base_url,
                        p.key_env.unwrap_or("-"),
                        present,
                        p.trust,
                        p.verified
                    );
                }
                return Ok(ExitCode::SUCCESS);
            }
            init(cfg_path, scope, providers, mode, root, yes, force, apply).await?;
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
                ProviderCmd::List => {
                    provider_list(&cfg_path)?;
                    Ok(ExitCode::SUCCESS)
                }
                ProviderCmd::Test { name } => provider_test(&cfg_path, &name).await,
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
                    yes,
                    undo,
                    no_statusline,
                    no_hook,
                    no_claude_md,
                    no_permissions,
                },
        } => {
            setup_claude(
                &cfg_path,
                &scope,
                dry_run,
                yes,
                undo,
                !no_statusline,
                !no_hook,
                !no_claude_md,
                !no_permissions,
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
        Cmd::Doctor => {
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
        } => {
            let since = middleman::report::parse_since(&since)?;
            let by = middleman::report::By::parse(&by)
                .context("--by must be model, provider, task, day or project")?;
            let l = middleman::ledger::Ledger::new(&cfg.state_dir())?;
            let es = l.entries()?;
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
        | Cmd::Statusline
        | Cmd::Watch { .. }
        | Cmd::Completions { .. }
        | Cmd::Doctor
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
