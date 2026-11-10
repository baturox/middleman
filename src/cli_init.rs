//! `middleman init`: the guided setup wizard, its non-interactive twin (`--yes`) and
//! `init --list`. Logic that needs no terminal lives in `middleman::wizard` and
//! `middleman::onboard` (unit-tested there); this module is prompts and output.
//!
//! Output conventions: prompts, progress and results go to stderr (stdout stays clean for
//! scripts), styled through `middleman::ui::Ui` (plain text without a TTY or with NO_COLOR).
//! Keys are read hidden, never echoed, and only their storage location is shown.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use dialoguer::{Confirm, Input, Password, Select};

use middleman::config::{is_local_url, Config, KeySource, RoutingMode, Secret, DEFAULT_UA};
use middleman::fsutil::pretty;
use middleman::keystore;
use middleman::onboard::{self, CheckTarget, KeyInfo, ProviderEntry};
use middleman::providers::presets::{self, Group, Preset};
use middleman::providers::Provider;
use middleman::setup::{self, InitOptions, Scope};
use middleman::ui::Ui;
use middleman::wizard::{self, ExistingSummary, DEFAULT_MODE, MODES};

const TOTAL: usize = 4;

/// Write one line to stderr.
macro_rules! out {
    ($($t:tt)*) => {{
        let _ = writeln!(std::io::stderr(), $($t)*);
    }};
}

pub struct InitArgs {
    pub scope: Option<String>,
    pub providers: Option<String>,
    pub mode: Option<String>,
    pub root: Vec<PathBuf>,
    pub yes: bool,
    pub force: bool,
    pub apply: bool,
    pub key_stdin: bool,
    pub no_validate: bool,
    pub base_url: Option<String>,
}

pub async fn run(cfg_path: PathBuf, a: InitArgs) -> Result<()> {
    if a.yes || a.key_stdin {
        return non_interactive(cfg_path, a).await;
    }
    if !crate::interactive() {
        bail!(
            "`middleman init` is a guided setup and needs a terminal. For scripts add --yes \
             (defaults: user scope, openrouter, confirm mode), e.g.\n  \
             middleman init --yes --providers openrouter --mode confirm\n  \
             pass show openrouter | middleman init --yes --key-stdin"
        );
    }
    Wizard::new(cfg_path, a).run().await
}

fn parse_mode(m: &str) -> Result<RoutingMode> {
    Ok(match m {
        "auto" => RoutingMode::Auto,
        "confirm" => RoutingMode::Confirm,
        "explicit" => RoutingMode::Explicit,
        _ => bail!("--mode must be auto, confirm or explicit"),
    })
}

fn parse_scope(s: &str) -> Result<Scope> {
    Scope::parse(s).context("--scope must be user or project")
}

/// How a provider's check ended (shown on the summary screen).
#[derive(Debug, Clone)]
enum Outcome {
    /// Key checked live and stored; (check summary, storage location).
    Stored(String, String),
    /// Key from an environment variable, checked live.
    Env(String, String),
    /// Local or keyless endpoint answered with this many models.
    Reachable(usize),
    /// Added without a working check.
    Skipped(String),
}

struct Chosen {
    entry: ProviderEntry,
    label: String,
    outcome: Outcome,
}

fn label_of(e: &ProviderEntry) -> String {
    e.preset
        .as_deref()
        .and_then(presets::find)
        .map(|p| p.label.to_string())
        .unwrap_or_else(|| e.name.clone())
}

fn store_key(ui: &Ui, account: &str, key: &Secret) -> Result<(KeySource, String)> {
    let st = keystore::store_key(account, key)?;
    if let Some(w) = &st.warning {
        out!("  {}", ui.warn(w));
    }
    Ok((st.source, st.location))
}

// ---------------------------------------------------------------- the wizard

#[derive(Clone, Copy, PartialEq)]
enum Existing {
    None,
    Update,
    Fresh,
}

struct Wizard {
    ui: Ui,
    theme: dialoguer::theme::ColorfulTheme,
    cfg_path: PathBuf,
    a: InitArgs,
    home: PathBuf,
    cwd: PathBuf,
}

impl Wizard {
    fn new(cfg_path: PathBuf, a: InitArgs) -> Wizard {
        Wizard {
            ui: Ui::stderr(),
            theme: crate::theme(),
            cfg_path,
            a,
            home: crate::home(),
            cwd: crate::cwd(),
        }
    }

    /// Arrow-key choice. Afterwards only the choice's name is echoed (`✔ prompt · name`):
    /// the text before the first double space of the item.
    fn select(&self, prompt: &str, items: &[String], default: usize) -> Result<usize> {
        let shorts: Vec<String> = items
            .iter()
            .map(|i| {
                let plain = console::strip_ansi_codes(i);
                plain.trim().split("  ").next().unwrap_or("").to_string()
            })
            .collect();
        self.select_short(prompt, items, &shorts, default)
    }

    fn select_short(
        &self,
        prompt: &str,
        items: &[String],
        shorts: &[String],
        default: usize,
    ) -> Result<usize> {
        let i = Select::with_theme(&self.theme)
            .with_prompt(prompt)
            .items(items)
            .default(default)
            .report(false)
            .interact()?;
        out!(
            "{} {} {} {}",
            self.ui.green("✔"),
            self.ui.bold(prompt),
            self.ui.dim("·"),
            self.ui.accent(&shorts[i])
        );
        Ok(i)
    }

    fn confirm(&self, prompt: &str, default: bool) -> Result<bool> {
        Ok(Confirm::with_theme(&self.theme)
            .with_prompt(prompt)
            .default(default)
            .interact()?)
    }

    fn hint(&self, s: &str) {
        out!("  {}", self.ui.dim(s));
    }

    async fn run(self) -> Result<()> {
        let ui = self.ui;
        out!(
            "\n  {}  {}",
            ui.bold("🛡  Welcome to middleman."),
            ui.dim("Four short steps; nothing is sent anywhere without your OK.")
        );
        let mut existing = Existing::None;
        let mut old_mode = None;
        if self.cfg_path.exists() {
            let s = wizard::summarize_existing(&self.cfg_path);
            self.show_existing(&s);
            let mut items = vec!["Keep it as it is".to_string()];
            if s.error.is_none() {
                items.push("Update it (add or replace providers, change the mode)".into());
            }
            items.push("Start fresh (the current file is backed up first)".into());
            let i = self.select("What do you want to do?", &items, 0)?;
            match items[i].split(' ').next() {
                Some("Keep") => {
                    out!("  {}", self.ui.ok("Kept your config unchanged."));
                    return self.offer_claude(Scope::User, &self.cwd).await;
                }
                Some("Update") => {
                    existing = Existing::Update;
                    old_mode = s.mode;
                }
                _ => existing = Existing::Fresh,
            }
        }

        let (scope, project_dir, roots) = match self.step_scope()? {
            Some(x) => x,
            None => {
                out!("  Nothing was changed.");
                return Ok(());
            }
        };
        let chosen = self.step_providers().await?;
        let mode = self.step_mode(old_mode)?;

        // ---- write
        let mut log = vec![];
        let entries: Vec<ProviderEntry> = chosen.iter().map(|c| c.entry.clone()).collect();
        let o = InitOptions {
            scope,
            providers: entries.clone(),
            mode,
            roots,
            config_path: self.cfg_path.clone(),
            project_dir: project_dir.clone(),
            force: existing == Existing::Fresh,
        };
        if existing == Existing::Update {
            let text = std::fs::read_to_string(&self.cfg_path)?;
            let mut new = wizard::merge_update(&text, &entries, Some(mode))?;
            if scope == Scope::Project {
                new = wizard::add_root(&new, &project_dir)?;
            }
            onboard::write_config(&self.cfg_path, &new)?;
            log.push(format!("updated {}", pretty(&self.cfg_path)));
            if scope == Scope::Project {
                setup::write_overlay(&InitOptions { force: false, ..o }, &mut log)?;
            }
        } else {
            log = setup::init_write(&o)?;
        }
        self.finish(scope, &project_dir, &chosen, mode, &log).await
    }

    fn show_existing(&self, s: &ExistingSummary) {
        let ui = self.ui;
        out!(
            "\n  {} {}",
            ui.bold("You already have a middleman config:"),
            ui.dim(&pretty(&self.cfg_path))
        );
        if let Some(e) = &s.error {
            out!("  {}", ui.bad(&format!("it does not load: {e}")));
            return;
        }
        if s.providers.is_empty() {
            out!("{}", ui.row("Providers", &ui.dim("none")));
        }
        for (i, (name, status, ok)) in s.providers.iter().enumerate() {
            let mark = if *ok {
                ui.green("✓")
            } else {
                ui.yellow("⚠")
            };
            out!(
                "{}",
                ui.row(
                    if i == 0 { "Providers" } else { "" },
                    &format!("{mark} {name} {}", ui.dim(&format!("({status})")))
                )
            );
        }
        if let Some(m) = s.mode {
            out!("{}", ui.row("Mode", wizard::mode_label(m)));
        }
    }

    // ---------------------------------------------------------------- step 1

    /// Returns (scope, project dir, readable roots), or None when the user cancels.
    fn step_scope(&self) -> Result<Option<(Scope, PathBuf, Vec<PathBuf>)>> {
        let ui = self.ui;
        let (info, warns) = wizard::inspect_project(&self.cwd, &self.home);
        let suggested = info.git_root.clone().unwrap_or_else(|| self.cwd.clone());
        // User scope: readable root = whichever project the Claude Code session is in.
        let user_roots = |_dir: &Path| {
            if self.a.root.is_empty() {
                vec![PathBuf::from(middleman::config::PROJECT_ROOT_PLACEHOLDER)]
            } else {
                self.a.root.clone()
            }
        };
        let scope = match &self.a.scope {
            Some(s) => parse_scope(s)?,
            None => {
                out!("{}", ui.header(1, TOTAL, "Where to install"));
                self.hint(&format!(
                    "User: one config in {} for every project.",
                    pretty(self.cfg_path.parent().unwrap_or(&self.cfg_path))
                ));
                self.hint(
                    "Project: also writes .middleman.toml in the repository (it can only make rules \
                     stricter) and connects Claude Code for that project only.",
                );
                let cfg_dir = pretty(self.cfg_path.parent().unwrap_or(&self.cfg_path));
                let items = [
                    format!("{:<28} {}", "All my projects (user)", ui.dim(&cfg_dir)),
                    format!(
                        "{:<28} {}",
                        "Only this project",
                        ui.dim(&pretty(&suggested))
                    ),
                ];
                if self.select("Install for…", &items, 0)? == 0 {
                    Scope::User
                } else {
                    Scope::Project
                }
            }
        };
        if scope == Scope::User {
            return Ok(Some((
                Scope::User,
                self.cwd.clone(),
                user_roots(&suggested),
            )));
        }

        // project scope: show where, warn, confirm
        out!("");
        out!("{}", ui.row("Folder", &pretty(&self.cwd)));
        match (&info.git_root, info.repo_name()) {
            (Some(r), Some(n)) => out!(
                "{}",
                ui.row(
                    "Git repo",
                    &format!("{n} {}", ui.dim(&format!("({})", pretty(r))))
                )
            ),
            _ => out!("{}", ui.row("Git repo", &ui.dim("none"))),
        }
        for w in &warns {
            out!("  {}", ui.warn(&w.message()));
        }
        let mut dir = self.cwd.clone();
        if let Some(root) = warns.iter().find_map(|w| match w {
            wizard::ScopeWarning::Subdirectory { root } => Some(root.clone()),
            _ => None,
        }) {
            let items = [
                format!("The repository root   {}", ui.dim(&pretty(&root))),
                format!("This subfolder        {}", ui.dim(&pretty(&self.cwd))),
            ];
            if self.select("Which folder is the project?", &items, 0)? == 0 {
                dir = root;
            }
        }
        let serious = warns.iter().any(|w| w.is_serious());
        let repo = wizard::find_git_root(&dir)
            .filter(|r| r == &dir)
            .and_then(|r| r.file_name().map(|n| n.to_string_lossy().into_owned()));
        let q = format!(
            "Install middleman for this project? {}{}",
            pretty(&dir),
            repo.map(|n| format!(" (git repo: {n})"))
                .unwrap_or_default()
        );
        if !self.confirm(&q, !serious)? {
            let items = [
                "Install for all my projects (user) instead".to_string(),
                "Cancel: cd into the right folder and run `middleman init` again".to_string(),
            ];
            return Ok(match self.select("What now?", &items, 0)? {
                0 => Some((Scope::User, self.cwd.clone(), user_roots(&suggested))),
                _ => None,
            });
        }
        let roots = if self.a.root.is_empty() {
            vec![dir.clone()]
        } else {
            self.a.root.clone()
        };
        Ok(Some((Scope::Project, dir, roots)))
    }

    // ---------------------------------------------------------------- step 2

    async fn step_providers(&self) -> Result<Vec<Chosen>> {
        let ui = self.ui;
        out!("{}", ui.header(2, TOTAL, "Provider"));
        self.hint(
            "middleman sends small, cleaned-up jobs to a cheap model. Pick where that model runs.",
        );
        let mut chosen: Vec<Chosen> = vec![];
        let mut queue: Vec<String> = match &self.a.providers {
            Some(p) => p
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            None => vec![],
        };
        let from_flag = !queue.is_empty();
        loop {
            let pick = if from_flag {
                if queue.is_empty() {
                    break;
                }
                let n = queue.remove(0);
                match presets::find(&n) {
                    Some(p) => Pick::Preset(p),
                    None => bail!("unknown provider {n:?} (see `middleman init --list`)"),
                }
            } else {
                self.pick(&chosen)?
            };
            let got = match pick {
                Pick::Preset(p) if p.needs_key() => self.connect_keyed(p).await?,
                Pick::Preset(p) => self.connect_local(p).await?,
                Pick::Custom => self.connect_custom(&chosen).await?,
            };
            if let Some(c) = got {
                chosen.retain(|x| x.entry.name != c.entry.name);
                chosen.push(c);
            }
            if from_flag {
                continue;
            }
            if !self.confirm("Add another provider?", false)? {
                break;
            }
        }
        if chosen.is_empty() {
            out!(
                "  {}",
                ui.warn("No provider was added. Add one later with `middleman provider add`.")
            );
        }
        Ok(chosen)
    }

    /// The grouped provider picker (OpenRouter first and default).
    fn pick(&self, chosen: &[Chosen]) -> Result<Pick> {
        let ui = self.ui;
        let (items, picks) = picker_items(&ui, |name| chosen.iter().any(|c| c.entry.name == name));
        let shorts: Vec<String> = picks
            .iter()
            .map(|p| match p {
                Pick::Preset(p) => p.label.to_string(),
                Pick::Custom => "Custom URL".into(),
            })
            .collect();
        let i = self.select_short("Pick a provider", &items, &shorts, 0)?;
        Ok(picks[i])
    }

    async fn connect_keyed(&self, p: &'static Preset) -> Result<Option<Chosen>> {
        let ui = self.ui;
        out!("");
        out!(
            "  {}{}",
            ui.bold(p.label),
            p.key_url
                .map(|u| format!(" · get a key at {}", ui.accent(u)))
                .unwrap_or_default()
        );
        let fmt = p
            .key_prefix
            .map(|x| format!("Keys usually start with `{x}`. "))
            .unwrap_or_default();
        self.hint(&format!(
            "{fmt}It is checked with a free request, then stored in {} (never in the config) and never shown.",
            keystore::preferred_store_name()
        ));
        let base = p.check_base_url();
        let target = CheckTarget {
            label: p.label,
            key_url: p.key_url,
            local: false,
        };
        let entry = ProviderEntry::preset(p.name);

        if let Some(env) = p
            .key_env
            .filter(|e| std::env::var_os(e).is_some_and(|v| !v.is_empty()))
        {
            let items = [
                format!("Use {env} (checked now)"),
                "Store a key for middleman anyway".to_string(),
            ];
            if self.select(&format!("{env} is set in this shell"), &items, 0)? == 0 {
                let key = Secret::new(std::env::var(env).unwrap_or_default().trim());
                let res = self.check_key(p, &base, &key).await;
                match res {
                    Ok(info) => {
                        out!(
                            "  {}",
                            ui.ok(&format!("{} works: {}", p.label, info.summary()))
                        );
                        let model = self.pick_model(p, &base, &key).await;
                        return Ok(Some(Chosen {
                            entry: ProviderEntry { model, ..entry },
                            label: p.label.into(),
                            outcome: Outcome::Env(info.summary(), env.into()),
                        }));
                    }
                    Err(e) => {
                        let d = onboard::diagnose(&e, &target);
                        out!("  {}", ui.bad(&d.title));
                        out!("    {}", d.advice);
                        out!("  {}", ui.dim("Store a working key for middleman instead:"));
                    }
                }
            }
        }

        let mut use_login = false;
        if p.name == "openrouter" {
            let items = [
                format!(
                    "Log in with my browser   {}",
                    ui.dim("creates a key just for middleman (recommended)")
                ),
                format!(
                    "Paste an API key         {}",
                    ui.dim("from openrouter.ai/settings/keys")
                ),
            ];
            use_login = self.select("How do you want to connect OpenRouter?", &items, 0)? == 0;
        }
        'acquire: loop {
            let key = if use_login {
                match crate::browser_login(false, Duration::from_secs(300)).await {
                    Ok(k) => k,
                    Err(e) => {
                        out!("  {}", ui.bad(&format!("Browser login failed: {e:#}")));
                        let items = [
                            "Try the browser login again".to_string(),
                            "Paste a key instead".to_string(),
                            "Skip for now".to_string(),
                        ];
                        match self.select("What now?", &items, 1)? {
                            0 => continue 'acquire,
                            1 => {
                                use_login = false;
                                continue 'acquire;
                            }
                            _ => return Ok(Some(self.skipped(p, entry))),
                        }
                    }
                }
            } else {
                let k = Password::with_theme(&self.theme)
                    .with_prompt(format!("Paste your {} API key (hidden)", p.label))
                    .allow_empty_password(true)
                    .interact()
                    .context("no key entered")?;
                let k = zeroize::Zeroizing::new(k);
                match onboard::check_pasted(p.label, p.key_prefix, &k) {
                    Ok(None) => {}
                    Ok(Some(w)) => out!("  {}", ui.warn(&w)),
                    Err(e) => {
                        out!("  {}", ui.bad(&format!("{e}")));
                        if k.trim().is_empty()
                            && self.select(
                                "What now?",
                                &["Paste the key".to_string(), "Skip for now".to_string()],
                                0,
                            )? == 1
                        {
                            return Ok(Some(self.skipped(p, entry)));
                        }
                        continue 'acquire;
                    }
                }
                Secret::new(k.trim())
            };
            loop {
                match self.check_key(p, &base, &key).await {
                    Ok(info) => {
                        out!(
                            "  {}",
                            ui.ok(&format!("{} works: {}", p.label, info.summary()))
                        );
                        let (source, location) = store_key(&ui, p.name, &key)?;
                        out!("  {}", ui.ok(&format!("Key stored in {location}")));
                        let model = self.pick_model(p, &base, &key).await;
                        return Ok(Some(Chosen {
                            entry: ProviderEntry {
                                key_source: Some(source),
                                model,
                                ..entry
                            },
                            label: p.label.into(),
                            outcome: Outcome::Stored(info.summary(), location),
                        }));
                    }
                    Err(e) => {
                        let d = onboard::diagnose(&e, &target);
                        out!("  {}", ui.bad(&d.title));
                        out!("    {}", d.advice);
                        let other = if use_login {
                            "Log in again"
                        } else {
                            "Paste a different key"
                        };
                        let items = [
                            "Retry".to_string(),
                            other.to_string(),
                            "Skip for now".to_string(),
                        ];
                        match self.select("What now?", &items, if d.retry_first { 0 } else { 1 })? {
                            0 => continue,
                            1 => continue 'acquire,
                            _ => return Ok(Some(self.skipped(p, entry))),
                        }
                    }
                }
            }
        }
    }

    fn skipped(&self, p: &Preset, entry: ProviderEntry) -> Chosen {
        out!(
            "  {}",
            self.ui.dim(&format!(
                "Skipped. Add the key later with `middleman provider add {}`.",
                p.name
            ))
        );
        Chosen {
            entry,
            label: p.label.into(),
            outcome: Outcome::Skipped(format!(
                "no key yet: run `middleman provider add {}`",
                p.name
            )),
        }
    }

    async fn check_key(&self, p: &Preset, base: &str, key: &Secret) -> Result<KeyInfo> {
        let host = url::Url::parse(base)
            .ok()
            .and_then(|u| u.host_str().map(String::from))
            .unwrap_or_default();
        self.ui
            .spin(
                &format!("Checking the key with a free request to {host}"),
                onboard::validate_key(p.api, base, p.balance, key),
            )
            .await
    }

    /// After a working OpenRouter key: optionally pin a cheap coding model.
    async fn pick_model(&self, p: &Preset, base: &str, key: &Secret) -> Option<String> {
        if p.name != "openrouter" {
            return None;
        }
        let ui = self.ui;
        let prov = Provider::with_key(p.name, p.api, base, key.clone(), DEFAULT_UA, 20).ok()?;
        let models = match ui
            .spin("Fetching current model prices", prov.models())
            .await
        {
            Ok(m) => m,
            Err(e) => {
                out!(
                    "  {}",
                    ui.dim(&format!(
                        "(could not fetch the model list: {e}; using automatic choice)"
                    ))
                );
                return None;
            }
        };
        let picks = wizard::coding_picks(&models, 5);
        if picks.is_empty() {
            return None;
        }
        let mut items = vec![format!(
            "Automatic   {}",
            ui.dim("cheapest suitable model for each job, from live prices (recommended)")
        )];
        items.extend(
            picks
                .iter()
                .map(|m| format!("{:<40} {}", m.id, ui.dim(&wizard::fmt_prices(m)))),
        );
        let i = self
            .select("Default model for coding jobs (optional)", &items, 0)
            .ok()?;
        (i > 0).then(|| picks[i - 1].id.clone())
    }

    async fn connect_local(&self, p: &'static Preset) -> Result<Option<Chosen>> {
        let ui = self.ui;
        out!("");
        out!(
            "  {} {}",
            ui.bold(p.label),
            ui.dim("· runs on this computer, so nothing leaves it. No key needed.")
        );
        let mut url = p.base_url.to_string();
        let target = CheckTarget {
            label: p.label,
            key_url: None,
            local: true,
        };
        loop {
            url = Input::<String>::with_theme(&self.theme)
                .with_prompt(format!("{} server URL", p.label))
                .default(url.clone())
                .validate_with(|s: &String| -> std::result::Result<(), String> {
                    let u = onboard::check_base_url(s)?;
                    if !is_local_url(&u) {
                        return Err("this must be on this computer (http://localhost:…); for a \
                                    remote server pick \"Custom OpenAI-compatible URL\""
                            .into());
                    }
                    Ok(())
                })
                .interact_text()?;
            url = onboard::check_base_url(&url).map_err(anyhow::Error::msg)?;
            let res = ui
                .spin(
                    &format!("Checking {url}"),
                    onboard::count_models(&url, None),
                )
                .await;
            let entry = ProviderEntry {
                base_url: (url != p.base_url).then(|| url.clone()),
                ..ProviderEntry::preset(p.name)
            };
            match res {
                Ok(n) => {
                    out!(
                        "  {}",
                        ui.ok(&format!("{} is running: {n} models", p.label))
                    );
                    return Ok(Some(Chosen {
                        entry,
                        label: p.label.into(),
                        outcome: Outcome::Reachable(n),
                    }));
                }
                Err(e) => {
                    let d = onboard::diagnose(&e, &target);
                    out!("  {}", ui.bad(&d.title));
                    out!("    {}", d.advice);
                    let items = [
                        "Retry".to_string(),
                        "Edit the URL".to_string(),
                        "Skip for now (add it anyway; start the server later)".to_string(),
                    ];
                    match self.select("What now?", &items, 0)? {
                        0 | 1 => continue,
                        _ => {
                            return Ok(Some(Chosen {
                                entry,
                                label: p.label.into(),
                                outcome: Outcome::Skipped(format!("not reachable yet at {url}")),
                            }))
                        }
                    }
                }
            }
        }
    }

    async fn connect_custom(&self, chosen: &[Chosen]) -> Result<Option<Chosen>> {
        let ui = self.ui;
        out!("");
        out!(
            "  {} {}",
            ui.bold("Custom provider"),
            ui.dim("· any OpenAI-compatible API (vLLM, LiteLLM, a company gateway, …)")
        );
        let taken: Vec<String> = chosen.iter().map(|c| c.entry.name.clone()).collect();
        let name: String = Input::with_theme(&self.theme)
            .with_prompt("A short name for it")
            .default("my-llm".into())
            .validate_with(|s: &String| wizard::check_provider_name(s, &taken))
            .interact_text()?;
        let name = name.trim().to_string();
        let mut url = String::new();
        'url: loop {
            let mut input = Input::<String>::with_theme(&self.theme)
                .with_prompt("Base URL (usually ends in /v1)")
                .validate_with(|s: &String| onboard::check_base_url(s).map(|_| ()));
            if !url.is_empty() {
                input = input.default(url.clone());
            }
            url = onboard::check_base_url(&input.interact_text()?).map_err(anyhow::Error::msg)?;
            let local = is_local_url(&url);
            if !local {
                self.hint("Remote endpoints get the full privacy treatment (untrusted).");
            }
            let needs_key = !local || self.confirm("Does this server need an API key?", false)?;
            let target = CheckTarget {
                label: &name,
                key_url: None,
                local,
            };
            'key: loop {
                let key = if needs_key {
                    let k = Password::with_theme(&self.theme)
                        .with_prompt(format!("Paste the API key for {name} (hidden)"))
                        .interact()
                        .context("no key entered")?;
                    let k = zeroize::Zeroizing::new(k);
                    if let Err(e) = onboard::check_pasted(&name, None, &k) {
                        out!("  {}", ui.bad(&e.to_string()));
                        continue 'key;
                    }
                    Some(Secret::new(k.trim()))
                } else {
                    None
                };
                loop {
                    let res = ui
                        .spin(
                            &format!("Checking {url}/models"),
                            onboard::count_models(&url, key.as_ref()),
                        )
                        .await;
                    match res {
                        Ok(n) => {
                            out!("  {}", ui.ok(&format!("{name} answers: {n} models")));
                            let (key_source, outcome) = match &key {
                                Some(k) => {
                                    let (s, loc) = store_key(&ui, &name, k)?;
                                    out!("  {}", ui.ok(&format!("Key stored in {loc}")));
                                    (Some(s), Outcome::Stored(format!("{n} models"), loc))
                                }
                                None => (None, Outcome::Reachable(n)),
                            };
                            return Ok(Some(Chosen {
                                entry: ProviderEntry {
                                    name: name.clone(),
                                    preset: None,
                                    base_url: Some(url.clone()),
                                    local,
                                    key_source,
                                    model: None,
                                },
                                label: name.clone(),
                                outcome,
                            }));
                        }
                        Err(e) => {
                            let d = onboard::diagnose(&e, &target);
                            out!("  {}", ui.bad(&d.title));
                            out!("    {}", d.advice);
                            let mut items = vec!["Retry".to_string()];
                            if needs_key {
                                items.push("Paste a different key".into());
                            }
                            items.push("Edit the URL".into());
                            items.push("Skip for now".into());
                            let i = self.select("What now?", &items, 0)?;
                            match items[i].as_str() {
                                "Retry" => continue,
                                "Paste a different key" => continue 'key,
                                "Edit the URL" => continue 'url,
                                _ => {
                                    if key.is_none() {
                                        // keyless local endpoint: valid config, add it anyway
                                        return Ok(Some(Chosen {
                                            entry: ProviderEntry {
                                                name: name.clone(),
                                                base_url: Some(url.clone()),
                                                local,
                                                ..Default::default()
                                            },
                                            label: name.clone(),
                                            outcome: Outcome::Skipped(format!(
                                                "not reachable yet at {url}"
                                            )),
                                        }));
                                    }
                                    out!(
                                        "  {}",
                                        ui.dim("Not added: a remote provider needs a working key. Run `middleman init` again to add it.")
                                    );
                                    return Ok(None);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // ---------------------------------------------------------------- step 3

    fn step_mode(&self, current: Option<RoutingMode>) -> Result<RoutingMode> {
        if let Some(m) = &self.a.mode {
            return parse_mode(m);
        }
        let ui = self.ui;
        out!("{}", ui.header(3, TOTAL, "Routing mode"));
        self.hint(
            "When Claude Code meets a small job (tests, boilerplate, docstrings, summaries), \
             middleman can hand it to the cheap model.",
        );
        self.hint("In every mode, secrets and your private names are removed or blocked first.");
        let items: Vec<String> = MODES
            .iter()
            .map(|(_, label, desc)| format!("{label:<31} {}", ui.dim(desc)))
            .collect();
        let want = current.unwrap_or(DEFAULT_MODE);
        let default = MODES.iter().position(|m| m.0 == want).unwrap_or(0);
        let i = self.select("When may Claude delegate?", &items, default)?;
        Ok(MODES[i].0)
    }

    // ---------------------------------------------------------------- step 4

    async fn finish(
        &self,
        scope: Scope,
        project_dir: &Path,
        chosen: &[Chosen],
        mode: RoutingMode,
        log: &[String],
    ) -> Result<()> {
        let ui = self.ui;
        out!("{}", ui.header(4, TOTAL, "Done"));
        out!("{}", ui.row("Config", &pretty(&self.cfg_path)));
        for l in log {
            if let Some(rest) = l.strip_prefix("backed up ") {
                out!("{}", ui.row("Backup", &ui.dim(rest)));
            } else if l.starts_with("exists, kept") {
                out!("{}", ui.row("", &ui.dim(l)));
            }
        }
        if scope == Scope::Project {
            out!(
                "{}",
                ui.row(
                    "Project rules",
                    &pretty(&project_dir.join(middleman::config::PROJECT_FILE))
                )
            );
        }
        if let Ok(c) = Config::load(&self.cfg_path) {
            let mut roots: Vec<String> = c.paths.roots.iter().map(|r| pretty(r)).collect();
            if c.project_root_placeholder {
                roots.retain(|r| {
                    middleman::config::project_root_for(&self.cwd)
                        .map(|p| pretty(&p) != *r)
                        .unwrap_or(true)
                });
                roots.insert(
                    0,
                    "the project each Claude Code session is open in (its git root)".into(),
                );
            }
            out!(
                "{}",
                ui.row(
                    "Readable",
                    &format!(
                        "{} {}",
                        roots.join(", "),
                        ui.dim(
                            "(middleman only reads files there; never your home folder as a whole)"
                        )
                    )
                )
            );
        }
        out!("{}", ui.row("Mode", wizard::mode_label(mode)));
        for (i, c) in chosen.iter().enumerate() {
            let head = if i == 0 { "Providers" } else { "" };
            let line = match &c.outcome {
                Outcome::Stored(sum, loc) => ui.ok(&format!(
                    "{}  {} {}",
                    c.label,
                    sum,
                    ui.dim(&format!("· key in {loc}"))
                )),
                Outcome::Env(sum, env) => ui.ok(&format!(
                    "{}  {} {}",
                    c.label,
                    sum,
                    ui.dim(&format!("· key from ${env}"))
                )),
                Outcome::Reachable(n) => ui.ok(&format!("{}  reachable, {n} models", c.label)),
                Outcome::Skipped(why) => ui.warn(&format!("{}  {why}", c.label)),
            };
            out!("{}", ui.row(head, &line));
            if let Some(m) = &c.entry.model {
                out!(
                    "{}",
                    ui.row(
                        "",
                        &ui.dim(&format!("  default model for coding jobs: {m}"))
                    )
                );
            }
        }
        // providers already in the config that this run did not touch (Update)
        let kept: Vec<(String, String, bool)> = wizard::summarize_existing(&self.cfg_path)
            .providers
            .into_iter()
            .filter(|(n, _, _)| !chosen.iter().any(|c| &c.entry.name == n))
            .collect();
        for (i, (name, status, ok)) in kept.iter().enumerate() {
            let head = if i == 0 && chosen.is_empty() {
                "Providers"
            } else {
                ""
            };
            let line = format!("{name}  kept {}", ui.dim(&format!("({status})")));
            out!(
                "{}",
                ui.row(head, &if *ok { ui.ok(&line) } else { ui.warn(&line) })
            );
        }
        if chosen.is_empty() && kept.is_empty() {
            out!("{}", ui.row("Providers", &ui.dim("none yet")));
        }
        self.offer_dictionary(project_dir)?;
        self.offer_claude(scope, project_dir).await
    }

    /// "Protect your company names": offered while the dictionary is empty. Names are the
    /// one thing only the dictionary hides.
    fn offer_dictionary(&self, project_dir: &Path) -> Result<()> {
        let ui = self.ui;
        let Ok(cfg) = Config::load(&self.cfg_path) else {
            return Ok(());
        };
        let terms = cfg
            .redact
            .dictionary_file
            .as_ref()
            .map(|p| middleman::suggest::existing_terms(&middleman::config::expand_tilde(p)).len())
            .unwrap_or(0);
        if terms > 0 {
            return Ok(());
        }
        out!("\n  {}", ui.bold("Protect your company names"));
        self.hint("Company, product and people names are hidden only if they are in your private dictionary. middleman can look for them in this project (locally) and let you pick.");
        if !self.confirm("Scan this project for names now?", true)? {
            self.hint("Later: middleman dict suggest");
            return Ok(());
        }
        if let Err(e) = crate::dict_suggest(
            &self.cfg_path,
            Some(project_dir.to_path_buf()),
            false,
            middleman::suggest::Confidence::Medium,
            false,
        ) {
            out!("  {}", ui.warn(&format!("dictionary not updated: {e:#}")));
        }
        Ok(())
    }

    async fn offer_claude(&self, scope: Scope, project_dir: &Path) -> Result<()> {
        let ui = self.ui;
        out!("");
        let flag = if scope == Scope::Project {
            " --scope project"
        } else {
            ""
        };
        let go = self.confirm(
            "Connect to Claude Code now? (runs `middleman setup claude`, shows the changes first)",
            true,
        )?;
        if go {
            out!("");
            let prev = std::env::current_dir().ok();
            if scope == Scope::Project {
                let _ = std::env::set_current_dir(project_dir);
            }
            let r =
                crate::setup_claude(&self.cfg_path, scope.as_str(), crate::SetupFlags::default());
            if let Some(p) = prev {
                let _ = std::env::set_current_dir(p);
            }
            r?;
        } else {
            out!(
                "  Later, run {} to connect it to Claude Code.",
                ui.accent(&format!("middleman setup claude{flag}"))
            );
        }
        out!(
            "  {}",
            ui.dim("`middleman doctor` checks everything; `middleman provider add` adds more providers.")
        );
        Ok(())
    }
}

// ---------------------------------------------------------------- picker

#[derive(Clone, Copy)]
pub enum Pick {
    Preset(&'static Preset),
    Custom,
}

fn group_short(g: Group) -> &'static str {
    match g {
        Group::Recommended => "Recommended",
        Group::Direct => "Direct",
        Group::Local => "Local, free",
    }
}

/// Picker rows: a group column (shown on the first row of each group), the name and a dim
/// one-liner. `added(name)` marks providers already set up in this run.
pub fn picker_items(ui: &Ui, added: impl Fn(&str) -> bool) -> (Vec<String>, Vec<Pick>) {
    let mut items = vec![];
    let mut picks = vec![];
    let mut last = None;
    for p in presets::visible() {
        let g = if last != Some(p.group) {
            last = Some(p.group);
            group_short(p.group)
        } else {
            ""
        };
        let mut blurb = ui.dim(p.blurb);
        if !p.verified && p.trust != middleman::config::Trust::Local {
            blurb.push_str(&ui.yellow(" · URL unverified"));
        }
        if added(p.name) {
            blurb.push_str(&ui.green(" ✓ added"));
        }
        items.push(format!(
            "{} {:<17} {blurb}",
            ui.dim(&format!("{g:<12}")),
            p.label
        ));
        picks.push(Pick::Preset(p));
    }
    items.push(format!(
        "{} {:<17} {}",
        ui.dim(&format!("{:<12}", "Other")),
        "Custom URL",
        ui.dim("any OpenAI-compatible endpoint")
    ));
    picks.push(Pick::Custom);
    (items, picks)
}

/// The provider picker for `provider add` (presets only).
pub fn pick_preset() -> Result<&'static Preset> {
    let ui = Ui::stderr();
    let (mut items, mut picks) = picker_items(&ui, |_| false);
    items.pop();
    picks.pop();
    let i = Select::with_theme(&crate::theme())
        .with_prompt("Pick a provider")
        .items(&items)
        .default(0)
        .interact()?;
    match picks[i] {
        Pick::Preset(p) => Ok(p),
        Pick::Custom => unreachable!(),
    }
}

// ---------------------------------------------------------------- --list

/// `init --list` / `provider list --all`: grouped presets with key status (never a key).
pub fn list(cfg_path: &Path) -> String {
    let ui = Ui::stdout();
    let cfg = Config::load(cfg_path).ok();
    let mut s = String::new();
    let mut last = None;
    for p in presets::visible() {
        if last != Some(p.group) {
            last = Some(p.group);
            s.push_str(&format!("\n  {}\n", ui.bold(p.group.title())));
        }
        let status = key_status(&ui, p, cfg.as_ref());
        let unverified = if !p.verified && p.trust != middleman::config::Trust::Local {
            ui.yellow(" (URL unverified)")
        } else {
            String::new()
        };
        s.push_str(&format!(
            "    {:<11} {:<17} {}{}\n      {}\n",
            p.name,
            p.label,
            status,
            unverified,
            ui.dim(p.blurb)
        ));
    }
    s.push_str(&format!(
        "\n  {}\n    {:<11} {:<17} {}\n",
        ui.bold("Other"),
        "<name>",
        "Custom URL",
        ui.dim("any OpenAI-compatible endpoint (`middleman init`)")
    ));
    s.push_str(&format!(
        "\n  {}\n",
        ui.dim("Also accepted in configs: moonshot (= kimi), zhipu (= glm), dashscope (= qwen), anthropic.")
    ));
    s
}

fn key_status(ui: &Ui, p: &Preset, cfg: Option<&Config>) -> String {
    if !p.needs_key() {
        return ui.dim("no key needed");
    }
    if let Some(env) = p.key_env {
        if std::env::var_os(env).is_some_and(|v| !v.is_empty()) {
            return ui.ok(&format!("env var set {}", ui.dim(&format!("({env})"))));
        }
    }
    let stored = cfg
        .and_then(|c| c.providers.get(p.name))
        .map(|pc| matches!(pc.key_status(), middleman::config::KeyStatus::Stored(..)))
        .unwrap_or(false);
    if stored {
        ui.ok("key stored")
    } else {
        ui.dim("— not set")
    }
}

// ---------------------------------------------------------------- non-interactive

async fn non_interactive(cfg_path: PathBuf, a: InitArgs) -> Result<()> {
    let ui = Ui::stderr();
    let cwd = crate::cwd();
    let home = crate::home();
    let names: Vec<String> = match &a.providers {
        Some(p) => p
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        None => {
            let found: Vec<String> = setup::detect_keys()
                .into_iter()
                .filter(|k| k.2 && presets::find(k.0).is_some_and(|p| !p.hidden))
                .map(|k| k.0.to_string())
                .collect();
            if found.is_empty() {
                vec!["openrouter".into()]
            } else {
                found
            }
        }
    };
    if names.is_empty() {
        bail!("--providers is empty; e.g. --providers openrouter");
    }
    if a.base_url.is_some() && names.len() != 1 {
        bail!("--base-url applies to exactly one provider; pass a single --providers name");
    }
    let mut entries = vec![];
    for n in &names {
        let e = match (presets::find(n), &a.base_url) {
            (Some(p), Some(u)) => {
                let u = onboard::check_base_url(u).map_err(|e| anyhow::anyhow!("--base-url: {e}"))?;
                if p.trust == middleman::config::Trust::Local && !is_local_url(&u) {
                    bail!("--base-url for {n} must be on this computer (http://localhost:…); use a custom name for a remote server");
                }
                ProviderEntry {
                    base_url: (u != p.base_url).then_some(u),
                    ..ProviderEntry::preset(n)
                }
            }
            (Some(_), None) => ProviderEntry::preset(n),
            (None, Some(u)) => {
                wizard::check_provider_name(n, &[])
                    .map_err(|e| anyhow::anyhow!("provider name {n:?}: {e}"))?;
                let u = onboard::check_base_url(u).map_err(|e| anyhow::anyhow!("--base-url: {e}"))?;
                ProviderEntry {
                    name: n.clone(),
                    local: is_local_url(&u),
                    base_url: Some(u),
                    ..Default::default()
                }
            }
            (None, None) => bail!(
                "unknown provider {n:?}: run `middleman init --list`, or add --base-url for a custom OpenAI-compatible endpoint"
            ),
        };
        entries.push(e);
    }
    let needs_key = |e: &ProviderEntry| match e.preset.as_deref().and_then(presets::find) {
        Some(p) => p.needs_key(),
        None => !e.local,
    };
    let mut outcomes: Vec<(String, String, bool)> = vec![];
    if a.key_stdin {
        let keyed: Vec<usize> = (0..entries.len())
            .filter(|i| needs_key(&entries[*i]))
            .collect();
        if keyed.len() != 1 {
            bail!(
                "--key-stdin reads one key: pass exactly one provider that needs a key (got {})",
                keyed.len()
            );
        }
        let e = &mut entries[keyed[0]];
        let preset = e.preset.as_deref().and_then(presets::find);
        let label = preset
            .map(|p| p.label.to_string())
            .unwrap_or_else(|| e.name.clone());
        let key = crate::read_key_stdin()?;
        if let Some(w) =
            onboard::check_pasted(&label, preset.and_then(|p| p.key_prefix), key.expose())?
        {
            out!("  {}", ui.warn(&w));
        }
        let summary = if a.no_validate {
            "stored without a check (--no-validate)".to_string()
        } else {
            let base = match (preset, &e.base_url) {
                (_, Some(u)) => u.clone(),
                (Some(p), None) => p.check_base_url(),
                (None, None) => unreachable!("custom entries have a base_url"),
            };
            let res = match preset {
                Some(p) => onboard::validate_key(p.api, &base, p.balance, &key).await,
                None => onboard::count_models(&base, Some(&key))
                    .await
                    .map(|n| KeyInfo {
                        models: Some(n),
                        ..Default::default()
                    }),
            };
            match res {
                Ok(info) => info.summary(),
                Err(err) => {
                    let d = onboard::diagnose(
                        &err,
                        &CheckTarget {
                            label: &label,
                            key_url: preset.and_then(|p| p.key_url),
                            local: false,
                        },
                    );
                    bail!(
                        "{} {} Nothing was written (or use --no-validate).",
                        d.title,
                        d.advice
                    );
                }
            }
        };
        let (src, loc) = store_key(&ui, &e.name, &key)?;
        e.key_source = Some(src);
        outcomes.push((label, format!("{summary} · key in {loc}"), true));
    }
    for e in &entries {
        if e.preset.is_none() && !e.local && e.key_source.is_none() {
            bail!("{} needs a key: pipe it in with --key-stdin", e.name);
        }
        if e.key_source.is_none() && needs_key(e) {
            let env = e
                .preset
                .as_deref()
                .and_then(presets::find)
                .and_then(|p| p.key_env);
            let set = env.is_some_and(|v| std::env::var_os(v).is_some_and(|x| !x.is_empty()));
            outcomes.push((
                label_of(e),
                if set {
                    format!("key from ${}", env.unwrap_or_default())
                } else {
                    format!(
                        "no key yet: run `middleman provider add {}` or pipe one with --key-stdin",
                        e.name
                    )
                },
                set,
            ));
        }
    }

    let scope = match &a.scope {
        Some(s) => parse_scope(s)?,
        None => Scope::User,
    };
    if scope == Scope::Project {
        let (_, warns) = wizard::inspect_project(&cwd, &home);
        for w in &warns {
            if w.is_serious() {
                bail!("refusing project scope here: {}", w.message());
            }
            out!("  {}", ui.warn(&w.message()));
        }
    }
    let mode = match &a.mode {
        Some(m) => parse_mode(m)?,
        None => DEFAULT_MODE,
    };
    let roots = if !a.root.is_empty() {
        a.root.clone()
    } else if scope == Scope::User {
        vec![PathBuf::from(middleman::config::PROJECT_ROOT_PLACEHOLDER)]
    } else {
        vec![cwd.clone()]
    };
    let o = InitOptions {
        scope,
        providers: entries.clone(),
        mode,
        roots,
        config_path: cfg_path.clone(),
        project_dir: cwd.clone(),
        force: a.force,
    };
    let mut log = vec![];
    if cfg_path.exists() && !a.force {
        let explicit = a.providers.is_some() || a.mode.is_some() || a.key_stdin;
        if explicit {
            let text = std::fs::read_to_string(&cfg_path)?;
            let new = wizard::merge_update(&text, &entries, a.mode.as_ref().map(|_| mode))?;
            onboard::write_config(&cfg_path, &new)?;
            log.push(format!(
                "updated {} (existing config merged)",
                pretty(&cfg_path)
            ));
        } else {
            log.push(format!(
                "exists, kept: {} (pass --providers/--mode to update it, --force to start fresh)",
                pretty(&cfg_path)
            ));
        }
        if scope == Scope::Project {
            setup::write_overlay(&o, &mut log)?;
        }
    } else {
        log = setup::init_write(&o)?;
    }
    for l in &log {
        say!("{l}");
    }
    for (label, what, ok) in &outcomes {
        let line = format!("{label}: {what}");
        out!("  {}", if *ok { ui.ok(&line) } else { ui.warn(&line) });
    }
    out!("  mode: {}", wizard::mode_label(mode));
    if a.apply {
        crate::setup_claude(
            &cfg_path,
            scope.as_str(),
            crate::SetupFlags {
                yes: true,
                ..Default::default()
            },
        )?;
    } else {
        let flag = if scope == Scope::Project {
            " --scope project"
        } else {
            ""
        };
        say!("Next: `middleman setup claude{flag}` connects it to Claude Code.");
    }
    Ok(())
}
