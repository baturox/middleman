//! `middleman claude`, `middleman mode` and the hidden `middleman proxy`.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, Result};

use middleman::config::{Config, Secret};
use middleman::launch::{self, Decision};
use middleman::modes::{self, Mode, RepoPref};

use crate::{cwd, interactive, load, theme};

pub struct Opts {
    pub mode: Option<String>,
    pub pick: bool,
    pub model: Option<String>,
    pub fast_model: Option<String>,
    pub yes: bool,
    pub dry_run: bool,
    pub args: Vec<String>,
}

/// `Claude 5h: 41% used · OpenRouter: $9.95 left`, from caches only (no network).
fn header(cfg: &Config) -> String {
    let state = cfg.state_dir();
    let mut parts = Vec::new();
    if let Some(u) =
        modes::read_usage(&state).filter(|u| middleman::ledger::now_unix() - u.ts < 5 * 3600)
    {
        parts.push(format!("Claude 5h: {:.0}% used", u.pct));
    }
    if let Some(c) = middleman::limits::load(&state)
        .and_then(|c| c.providers.get("openrouter").and_then(|p| p.left_usd()))
    {
        parts.push(format!("OpenRouter: ${c:.2} left"));
    }
    let mut h = "🛡 middleman · how should this session run?".to_string();
    if !parts.is_empty() {
        h.push_str(&format!("   {}", parts.join(" · ")));
    }
    h
}

/// The 3-line picker. `None` = cancelled.
fn pick_mode(cfg: &Config, model: &str) -> Result<Option<Mode>> {
    note!("{}", header(cfg));
    let items = [
        "Smart (recommended)  a small router picks per prompt: hard -> Claude, routine -> cheap"
            .to_string(),
        format!("Cheap only          everything on {model}; your Claude plan is not used"),
        "Claude only         normal Claude Code; middleman only for `cheap:` prompts".to_string(),
    ];
    let i = dialoguer::Select::with_theme(&theme())
        .items(&items)
        .default(0)
        .interact_opt()?;
    Ok(i.map(|i| [Mode::Smart, Mode::Cheap, Mode::Claude][i]))
}

pub fn claude_cmd(cfg_path: &Path, o: Opts) -> Result<ExitCode> {
    let cfg = load(cfg_path)?;
    let state = cfg.state_dir();
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let tty = interactive();
    let pref_root = launch::project_root(&cwd(), home.as_deref()).ok();
    let pref = pref_root
        .as_ref()
        .filter(|_| !o.pick)
        .and_then(|r| modes::load_pref(&state, r));

    let mut asked = false;
    let mode = if let Some(m) = &o.mode {
        match m.parse::<Mode>() {
            Ok(m) => m,
            Err(e) => {
                note!("middleman: {e}");
                return Ok(ExitCode::FAILURE);
            }
        }
    } else if let Some(p) = &pref {
        p.mode.parse().unwrap_or(Mode::Smart)
    } else if tty {
        let (model, _) = launch::resolve_models(o.model.as_deref(), None, &cfg)
            .unwrap_or_else(|_| (launch::DEFAULT_MODEL.into(), String::new()));
        let Some(m) = pick_mode(&cfg, &model)? else {
            return Ok(ExitCode::FAILURE);
        };
        asked = true;
        m
    } else {
        Mode::Smart
    };
    let model = o
        .model
        .clone()
        .or_else(|| pref.as_ref().and_then(|p| p.model.clone()));

    let remember = |ask: bool| -> Result<()> {
        if !(ask && tty && !o.dry_run) {
            return Ok(());
        }
        let Some(root) = &pref_root else {
            return Ok(());
        };
        let yes = dialoguer::Confirm::with_theme(&theme())
            .with_prompt("Remember for this repo?")
            .default(false)
            .interact()?;
        if yes {
            modes::store_pref(
                &state,
                root,
                RepoPref {
                    mode: mode.to_string(),
                    model: o.model.clone(),
                },
            )?;
        }
        Ok(())
    };

    let Some(claude) = std::env::var_os("PATH").and_then(|p| launch::find_on_path("claude", &p))
    else {
        if o.dry_run && mode == Mode::Claude {
            say!("🛡 middleman: plain Claude Code (mode claude: no proxy, no allow check)");
            return Ok(ExitCode::SUCCESS);
        }
        if !o.dry_run {
            note!("middleman: `claude` not found on PATH: install Claude Code first");
            return Ok(ExitCode::FAILURE);
        }
        return claude_rest(
            cfg_path,
            &cfg,
            &o,
            mode,
            model,
            std::path::PathBuf::new(),
            &remember,
            asked,
        );
    };
    if mode == Mode::Claude {
        if o.dry_run {
            say!("🛡 middleman: plain Claude Code (mode claude: no proxy, no allow check)");
            return Ok(ExitCode::SUCCESS);
        }
        remember(asked)?;
        return launch::exec(&launch::LaunchCmd {
            program: claude,
            args: o.args,
            env: vec![],
            remove: vec![],
        });
    }
    claude_rest(cfg_path, &cfg, &o, mode, model, claude, &remember, asked)
}

/// Cheap and smart: key, models, privacy check, then launch.
#[allow(clippy::too_many_arguments)]
fn claude_rest(
    cfg_path: &Path,
    cfg: &Config,
    o: &Opts,
    mode: Mode,
    model: Option<String>,
    claude: std::path::PathBuf,
    remember: &dyn Fn(bool) -> Result<()>,
    asked: bool,
) -> Result<ExitCode> {
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let plan = match launch::prepare(
        cfg,
        &cwd(),
        home.as_deref(),
        model.as_deref(),
        o.fast_model.as_deref(),
        mode,
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
    remember(asked)?;
    note!("{}", launch::banner(&plan));
    if mode.uses_proxy() {
        modes::write_live_mode(&cfg.state_dir(), mode)?;
        let exe = std::env::current_exe().context("cannot find the middleman binary")?;
        let project = middleman::ledger::project_id(&cfg.state_dir(), &plan.root);
        let proxy = launch::spawn_proxy(&launch::ProxySpec {
            exe: &exe,
            cfg_path,
            mode,
            main: &plan.main,
            fast: &plan.fast,
            key: &plan.key,
            project: &project,
            bench_run: None,
        })?;
        let mut cmd = launch::command(claude, &plan);
        cmd.env = launch::proxy_env(&proxy.base_url);
        cmd.remove.clear();
        return launch::run_with_proxy(&cmd, proxy);
    }
    launch::exec(&launch::command(claude, &plan))
}

pub fn mode_cmd(cfg_path: &Path, mode: Option<String>) -> Result<ExitCode> {
    let cfg = load(cfg_path)?;
    let state = cfg.state_dir();
    let m = match mode {
        Some(m) => match m.parse::<Mode>() {
            Ok(m) => m,
            Err(e) => {
                note!("middleman: {e}");
                return Ok(ExitCode::FAILURE);
            }
        },
        None if interactive() => {
            let (model, _) = launch::resolve_models(None, None, &cfg)?;
            let Some(m) = pick_mode(&cfg, &model)? else {
                return Ok(ExitCode::FAILURE);
            };
            m
        }
        None => {
            match modes::read_live_mode(&state) {
                Some(m) => say!("{m}"),
                None => say!("smart"),
            }
            return Ok(ExitCode::SUCCESS);
        }
    };
    modes::write_live_mode(&state, m)?;
    say!("mode: {m} (a running smart session picks it up at its next turn)");
    Ok(ExitCode::SUCCESS)
}

fn loopback_override(var: &str) -> Option<String> {
    let v = std::env::var(var).ok()?;
    let u = reqwest::Url::parse(&v).ok()?;
    (u.scheme() == "http" && matches!(u.host_str(), Some("127.0.0.1" | "localhost"))).then_some(v)
}

pub async fn proxy_cmd(
    cfg_path: &Path,
    mode: String,
    model: String,
    fast: String,
    project: String,
    bench_run: Option<String>,
) -> Result<ExitCode> {
    let cfg = Config::load(cfg_path)?;
    let key = Secret::new(std::env::var("MM_PROXY_KEY").context("MM_PROXY_KEY not set")?);
    let token = std::env::var("MM_PROXY_TOKEN").context("MM_PROXY_TOKEN not set")?;
    std::env::remove_var("MM_PROXY_KEY");
    std::env::remove_var("MM_PROXY_TOKEN");
    let mut pc = middleman::proxy::ProxyCfg::from_config(
        &cfg,
        key,
        token,
        mode.parse()?,
        model,
        fast,
        project,
    );
    if let Some(r) = bench_run {
        pc.purpose = Some("bench".into());
        pc.run_id = Some(r);
        pc.fixed_mode = true;
    }
    // test hooks: loopback only, so they can never redirect real credentials
    if let Some(u) = loopback_override("MM_PROXY_ANTHROPIC_URL") {
        pc.anthropic_url = u;
    }
    if let Some(u) = loopback_override("MM_PROXY_OPENROUTER_URL") {
        pc.openrouter_url = u;
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
