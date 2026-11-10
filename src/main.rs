#![deny(clippy::print_stdout)]

use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use middleman::catalog::Catalog;
use middleman::classify::Declared;
use middleman::config::{default_config_path, Api, Config, RoutingMode};
use middleman::detect::{Detector, Dictionary};
use middleman::egress::{self, OutboundRequest};
use middleman::intake::FileRef;
use middleman::mcp::server::Server;
use middleman::pipeline::{DelegateRequest, Pipeline};
use middleman::providers::{presets, ModelInfo, Provider};
use middleman::pseudo::Vault;
use middleman::setup::{self, InitOptions, Scope};
use middleman::TaskKind;

/// stdout is the MCP channel in `mcp` mode; CLI subcommands write through this macro.
macro_rules! say {
    ($($t:tt)*) => {{
        let _ = writeln!(std::io::stdout(), $($t)*);
    }};
}

#[derive(Parser)]
#[command(
    name = "middleman",
    version,
    about = "Sanitizing delegation layer for untrusted LLM providers"
)]
struct Cli {
    /// Config file (default ~/.config/middleman/config.toml)
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the MCP stdio server
    Mcp,
    /// Offline dry run: show exactly what would be sent for these files (no network)
    Check {
        files: Vec<String>,
        #[arg(long, default_value = "snippet")]
        task_kind: String,
        #[arg(long, default_value = "internal")]
        declared: String,
        #[arg(long, default_value = "Review this code.")]
        instructions: String,
    },
    /// Model catalog: `models` (list, cached) or `models refresh` (fetch /models now)
    Models {
        /// "refresh" to re-fetch every enabled provider's /models
        action: Option<String>,
        /// Include non-text / unpriced models
        #[arg(long)]
        all: bool,
    },
    /// Show provider balance
    Balance {
        #[arg(long)]
        provider: Option<String>,
    },
    /// Show recent ledger entries and window sums
    Ledger {
        #[arg(long, default_value_t = 20)]
        tail: usize,
    },
    /// Probe a gateway: UA acceptance, wire formats, cheapest model, balance latency (~2 tiny calls)
    Probe {
        #[arg(long)]
        provider: Option<String>,
        #[arg(long)]
        model: Option<String>,
        /// Only free GET endpoints; no completions
        #[arg(long)]
        no_send: bool,
    },
    /// Local prompt classifier. `--hook`: Claude Code UserPromptSubmit hook (stdin JSON, always exit 0)
    Route {
        text: Option<String>,
        #[arg(long)]
        hook: bool,
    },
    /// Write middleman config and print the Claude Code wiring (applies it only with --apply)
    Init {
        /// user (all projects) | project (this repo: .middleman.toml + project-scoped MCP)
        #[arg(long)]
        scope: Option<String>,
        /// Comma-separated presets, e.g. yapayzekalab,openrouter
        #[arg(long)]
        providers: Option<String>,
        /// auto | confirm | explicit
        #[arg(long)]
        mode: Option<String>,
        /// Allowed roots (default: current directory)
        #[arg(long)]
        root: Vec<PathBuf>,
        /// Non-interactive: accept defaults for anything not given
        #[arg(long)]
        yes: bool,
        /// Overwrite existing middleman config files
        #[arg(long)]
        force: bool,
        /// Also run `claude mcp add` and merge the hook into Claude Code settings
        #[arg(long)]
        apply: bool,
        /// List presets and which key env vars are present, then exit
        #[arg(long)]
        list: bool,
    },
    /// Claude Code usage from local transcripts (~/.claude/projects), aggregates only
    Usage {
        #[arg(long, default_value = "30d")]
        since: String,
        /// model | day | project | session | agent
        #[arg(long, default_value = "model")]
        by: String,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        html: Option<PathBuf>,
    },
    /// Quantified first-party cost recommendations + settings.json snippet (prints only)
    Tune {
        #[arg(long, default_value = "30d")]
        since: String,
        #[arg(long)]
        json: bool,
        /// Merge the snippet into ~/.claude/settings.json (backup first). Run it yourself.
        #[arg(long)]
        apply: bool,
    },
    /// Usage + savings report from the ledger
    Report {
        /// 7d | 30d | 24h | all
        #[arg(long, default_value = "30d")]
        since: String,
        /// model | provider | task | day | project
        #[arg(long, default_value = "model")]
        by: String,
        #[arg(long)]
        json: bool,
        /// Write a single-file HTML dashboard to this path
        #[arg(long)]
        html: Option<PathBuf>,
    },
    /// Green/red checklist: config, keys, reachability, balance, catalog, binary, MCP, hook
    Doctor,
}

fn cwd() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn load(cfg_path: &Path) -> Result<Config> {
    let (cfg, overlay) = Config::load_with_project(cfg_path, &cwd())?;
    if let Some(p) = overlay {
        tracing::info!("applied project overlay {}", p.display());
    }
    Ok(cfg)
}

fn pick_provider(cfg: &Config, name: Option<String>) -> Result<String> {
    match name {
        Some(n) if cfg.providers.contains_key(&n) => Ok(n),
        Some(n) => bail!("unknown provider {n}"),
        None => cfg
            .providers
            .iter()
            .find(|(_, p)| p.enabled)
            .map(|(n, _)| n.clone())
            .context("no enabled providers configured"),
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
            Err(e) => say!("  {label:<30} -> error: {e}"),
        }
    }

    say!("\n[models]");
    let models = match p.models().await {
        Ok(m) => m,
        Err(e) => {
            say!("  GET /models failed: {e}");
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
            m.id,
            fmt_price(m.price_in_per_1m),
            fmt_price(m.price_out_per_1m),
            m.tier.as_deref().unwrap_or("?"),
            m.context_length
                .map(|c| c.to_string())
                .unwrap_or_else(|| "?".into()),
            m.modality.as_deref().unwrap_or("?"),
            middleman::catalog::tags_for(&m.id, m.context_length),
        );
    }

    say!("\n[balance]");
    let b0 = p.balance().await;
    match &b0 {
        Ok(b) => say!("  balance_usd={:.4} payg={:?}", b.usd, b.payg),
        Err(e) => say!("  balance failed: {e}"),
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
    say!("\n[wire formats] model={chosen}, max_tokens=8, synthetic prompt only");
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
                c.text.chars().take(40).collect::<String>(),
                c.model,
                c.input_tokens,
                c.output_tokens,
                c.stop_reason
            ),
            Err(e) => say!("  {:?}: FAILED: {e}", api),
        }
        let now = p.balance().await.ok().map(|b| b.usd);
        say!(
            "    balance immediately after: {:?} (delta {:?})",
            now,
            prev.zip(now).map(|(a, b)| a - b)
        );
        prev = now.or(prev);
    }
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let late = p.balance().await.ok().map(|b| b.usd);
    say!(
        "\n[balance latency] after +3s: {:?}; total delta since start: {:?}",
        late,
        b0.ok().map(|b| b.usd).zip(late).map(|(a, b)| a - b)
    );
    Ok(())
}

/// Hook path: never fails, never blocks, prints nothing on any error.
fn route_hook(cfg_path: &Path) {
    let mut input = String::new();
    let _ = std::io::stdin().take(1 << 20).read_to_string(&mut input);
    let hook_cwd = serde_json::from_str::<serde_json::Value>(&input)
        .ok()
        .and_then(|v| v.get("cwd").and_then(|c| c.as_str()).map(PathBuf::from))
        .unwrap_or_else(cwd);
    let cfg = Config::load_with_project(cfg_path, &hook_cwd)
        .ok()
        .map(|(c, _)| c);
    let mode = cfg
        .as_ref()
        .map(|c| c.routing.mode)
        .unwrap_or(RoutingMode::Auto);
    let dict = cfg
        .as_ref()
        .and_then(|c| c.redact.dictionary_file.as_ref())
        .and_then(|p| Dictionary::load(p).ok());
    if let Some(out) = middleman::hook::hook_output(
        &input,
        mode,
        dict.as_ref(),
        cfg.as_ref().map(|c| &c.economics),
    ) {
        say!("{out}");
    }
}

fn ask(prompt: &str, default: &str) -> String {
    let _ = write!(std::io::stderr(), "{prompt} [{default}]: ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    let t = line.trim();
    if t.is_empty() {
        default.to_string()
    } else {
        t.to_string()
    }
}

#[allow(clippy::too_many_arguments)]
fn init(
    cfg_path: PathBuf,
    scope: Option<String>,
    providers: Option<String>,
    mode: Option<String>,
    root: Vec<PathBuf>,
    yes: bool,
    force: bool,
    apply: bool,
) -> Result<()> {
    let keys = setup::detect_keys();
    let found: Vec<&str> = keys.iter().filter(|k| k.2).map(|k| k.0).collect();
    let scope = match scope {
        Some(s) => s,
        None if yes => "user".into(),
        None => ask(
            "Install scope: user (all projects) or project (this repo)?",
            "user",
        ),
    };
    let scope = Scope::parse(&scope).context("scope must be user|project")?;
    let default_providers = if found.is_empty() {
        "yapayzekalab".to_string()
    } else {
        found.join(",")
    };
    let providers = match providers {
        Some(p) => p,
        None if yes => default_providers,
        None => {
            let _ = writeln!(
                std::io::stderr(),
                "Presets (key env var found = yes/no, values never shown):"
            );
            for (name, env, ok) in &keys {
                let _ = writeln!(
                    std::io::stderr(),
                    "  {name:<14} {env:<20} {}",
                    if *ok { "yes" } else { "no" }
                );
            }
            ask("Providers (comma-separated)", &default_providers)
        }
    };
    let mode = match mode {
        Some(m) => m,
        None if yes => "auto".into(),
        None => ask("Routing mode: auto | confirm | explicit", "auto"),
    };
    let mode = match mode.as_str() {
        "auto" => RoutingMode::Auto,
        "confirm" => RoutingMode::Confirm,
        "explicit" => RoutingMode::Explicit,
        _ => bail!("mode must be auto|confirm|explicit"),
    };
    let exe = std::env::current_exe()?;
    let o = InitOptions {
        scope,
        providers: providers
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        mode,
        roots: if root.is_empty() { vec![cwd()] } else { root },
        config_path: cfg_path,
        project_dir: cwd(),
        exe: exe.clone(),
        force,
    };
    for l in setup::init_write(&o)? {
        say!("{l}");
    }
    say!(
        "\nRegister the MCP server ({} scope):\n  {}",
        scope.as_str(),
        setup::mcp_add_command(scope, &exe, &o.config_path)
    );
    say!(
        "\nOptional UserPromptSubmit hook (merge into {}):\n{}",
        setup::settings_path(scope, &o.project_dir).display(),
        serde_json::to_string_pretty(&setup::hook_snippet(&exe, &o.config_path))?
    );
    say!("\nThen run `middleman models refresh` and `middleman doctor`.");
    if apply {
        for l in setup::init_apply(&o)? {
            say!("{l}");
        }
    } else {
        say!("(nothing was changed in Claude Code settings; re-run with --apply to do that)");
    }
    Ok(())
}

async fn real_main() -> Result<ExitCode> {
    let cli = Cli::parse();
    let cfg_path = cli.config.unwrap_or_else(default_config_path);
    match cli.cmd {
        Cmd::Route { hook: true, .. } => {
            route_hook(&cfg_path);
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
            init(cfg_path, scope, providers, mode, root, yes, force, apply)?;
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
                bail!("--by model|day|project|session|agent");
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
                let p = middleman::config::expand_tilde(Path::new("~/.claude/settings.json"));
                say!("{}", middleman::tune::apply(&p, &t.settings_snippet)?);
            }
            return Ok(ExitCode::SUCCESS);
        }
        Cmd::Doctor => {
            let checks = setup::doctor(&cfg_path, &cwd()).await;
            let mut ok = true;
            for c in &checks {
                say!(
                    "{} {:<32} {}",
                    if c.ok { "[ok]  " } else { "[FAIL]" },
                    c.name,
                    c.detail
                );
                ok &= c.ok || c.name == "hook installed" || c.name == "MCP registered";
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
            let task_kind = TaskKind::parse(&task_kind).context("unknown task kind")?;
            let declared = Declared::parse(&declared)
                .context("declared must be public|internal|confidential")?;
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
                Some(other) => bail!("unknown models action {other} (list|refresh)"),
            };
            let pipeline = Pipeline::new(cfg)?;
            let Some(c) = pipeline.catalog(refresh).await else {
                bail!("no catalog available");
            };
            for e in &c.errors {
                say!("error: {e}");
            }
            if all {
                for m in &c.models {
                    say!(
                        "{}/{} in={} out={} ctx={:?} modality={:?}",
                        m.provider,
                        m.info.id,
                        fmt_price(m.info.price_in_per_1m),
                        fmt_price(m.info.price_out_per_1m),
                        m.info.context_length,
                        m.info.modality
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
                        m.provider,
                        m.id,
                        fmt_price(m.prices.map(|p| p.in_per_1m)),
                        fmt_price(m.prices.map(|p| p.out_per_1m)),
                        m.context
                            .map(|c| c.to_string())
                            .unwrap_or_else(|| "?".into()),
                        m.tags.join(","),
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
                    x.ts,
                    x.attempt,
                    x.status,
                    x.provider,
                    x.model,
                    x.task_kind,
                    x.write_mode,
                    x.cost_usd,
                    x.cost_source,
                    x.net_savings_usd,
                    x.input_tokens,
                    x.output_tokens,
                    x.latency_ms.unwrap_or(0),
                    x.block_reason_category.as_deref().unwrap_or("")
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
                .context("--by model|provider|task|day|project")?;
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
