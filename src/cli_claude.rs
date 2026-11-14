//! `middleman claude` and the hidden `middleman proxy`.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, Result};

use middleman::config::{Config, Secret};
use middleman::launch::{self, Decision};

use crate::{cwd, interactive, load, theme};

pub struct Opts {
    pub model: Option<String>,
    pub fast_model: Option<String>,
    pub yes: bool,
    pub dry_run: bool,
    pub args: Vec<String>,
}

/// Claude Code with Claude as the brain: worker key and models, the privacy check for agent
/// requests, then the local proxy and Claude Code.
pub fn claude_cmd(cfg_path: &Path, o: Opts) -> Result<ExitCode> {
    let cfg = load(cfg_path)?;
    let claude = std::env::var_os("PATH").and_then(|p| launch::find_on_path("claude", &p));
    if claude.is_none() && !o.dry_run {
        note!("middleman: `claude` not found on PATH: install Claude Code first");
        return Ok(ExitCode::FAILURE);
    }
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let plan = match launch::prepare(
        &cfg,
        &cwd(),
        home.as_deref(),
        o.model.as_deref(),
        o.fast_model.as_deref(),
        o.yes,
        interactive(),
        o.args.clone(),
    ) {
        Ok(p) => p,
        Err(e) => {
            note!("middleman: {e}");
            return Ok(ExitCode::FAILURE);
        }
    };
    if o.dry_run {
        say!("{}", launch::dry_run_text(&plan));
        return Ok(ExitCode::SUCCESS);
    }
    match plan.decision {
        Decision::Allowed(_) => {}
        Decision::Refuse => {
            note!("middleman: {}", launch::refusal(&plan.root));
            return Ok(ExitCode::FAILURE);
        }
        Decision::Ask => {
            for l in launch::warning(&plan.root, &plan.main) {
                note!("{l}");
            }
            let pick = dialoguer::Select::with_theme(&theme())
                .items(["Allow once", "Always for this repo", "Cancel"])
                .default(2)
                .interact()?;
            match pick {
                0 => {}
                1 => launch::store_allow(&cfg.state_dir(), &plan.root)?,
                _ => return Ok(ExitCode::FAILURE),
            }
        }
    }
    note!("{}", launch::banner(&plan));
    let exe = std::env::current_exe().context("cannot find the middleman binary")?;
    let project = middleman::ledger::project_id(&cfg.state_dir(), &plan.root);
    let proxy = launch::spawn_proxy(&launch::ProxySpec {
        exe: &exe,
        cfg_path,
        main: &plan.main,
        fast: &plan.fast,
        key: &plan.key,
        provider: plan.upstream.name,
        project: &project,
        bench_run: None,
    })?;
    let cmd = launch::LaunchCmd {
        program: claude.unwrap_or_default(),
        args: session_args(
            cfg_path,
            &cfg,
            &launch::brain_note(&plan.main, plan.upstream.label),
            &plan.args,
        ),
        env: launch::proxy_env(&proxy.base_url, &plan.main),
    };
    launch::run_with_proxy(&cmd, proxy)
}

/// `--settings` for this session only: middleman's status line (unless the user turned it off
/// with `middleman statusline off`), so it shows in any repo without changing settings files.
/// Also `--append-system-prompt` with the brain note, unless the user passes their own.
fn session_args(cfg_path: &Path, cfg: &Config, note: &str, passthrough: &[String]) -> Vec<String> {
    let mut args = vec![];
    if !passthrough.iter().any(|a| a == "--append-system-prompt") {
        args.push("--append-system-prompt".to_string());
        args.push(note.to_string());
    }
    if cfg.statusline.enabled && !passthrough.iter().any(|a| a == "--settings") {
        if let Ok(exe) = std::env::current_exe() {
            let q = middleman::fsutil::shell_quote;
            let command = format!(
                "{} statusline --config {}",
                q(&exe.display().to_string()),
                q(&cfg_path.display().to_string())
            );
            let v = serde_json::json!({
                "statusLine": {"type": "command", "command": command, "padding": 0}
            });
            args.push("--settings".to_string());
            args.push(v.to_string());
        }
    }
    args.extend(passthrough.iter().cloned());
    args
}

fn loopback_override(var: &str) -> Option<String> {
    let v = std::env::var(var).ok()?;
    let u = reqwest::Url::parse(&v).ok()?;
    (u.scheme() == "http" && matches!(u.host_str(), Some("127.0.0.1" | "localhost"))).then_some(v)
}

pub async fn proxy_cmd(
    cfg_path: &Path,
    model: String,
    fast: String,
    project: String,
    bench_run: Option<String>,
    provider: String,
) -> Result<ExitCode> {
    let cfg = Config::load(cfg_path)?;
    let up = launch::upstream_named(&provider)?;
    let key = Secret::new(std::env::var("MM_PROXY_KEY").context("MM_PROXY_KEY not set")?);
    let token = std::env::var("MM_PROXY_TOKEN").context("MM_PROXY_TOKEN not set")?;
    std::env::remove_var("MM_PROXY_KEY");
    std::env::remove_var("MM_PROXY_TOKEN");
    let mut pc =
        middleman::proxy::ProxyCfg::from_config(&cfg, up, key, token, model, fast, project);
    if let Some(r) = bench_run {
        pc.purpose = Some("bench".into());
        pc.run_id = Some(r);
    }
    // test hooks: loopback only, so they can never redirect real credentials
    if let Some(u) = loopback_override("MM_PROXY_ANTHROPIC_URL") {
        pc.anthropic_url = u;
    }
    if let Some(u) = loopback_override("MM_PROXY_OPENROUTER_URL") {
        pc.cheap_url = u;
    }
    let (listener, port) = middleman::proxy::bind().await?;
    say!("{port}");
    let _ = std::io::stdout().flush();
    // exit when the launcher goes away (its end of our stdin closes)
    tokio::spawn(async {
        use tokio::io::AsyncReadExt;
        let mut b = [0u8; 64];
        let mut i = tokio::io::stdin();
        while matches!(i.read(&mut b).await, Ok(n) if n > 0) {}
        std::process::exit(0);
    });
    middleman::proxy::serve(pc, listener).await?;
    Ok(ExitCode::SUCCESS)
}
