//! Logic behind the `middleman init` wizard that needs no terminal: where to install (project
//! detection and warnings), what an existing config contains, merging updates into it,
//! backups, routing-mode wording and the cheap-model shortlist. The prompts themselves live
//! in the binary (`src/cli_init.rs`).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::config::{Config, RoutingMode};
use crate::onboard::ProviderEntry;
use crate::providers::ModelInfo;

// ---------------------------------------------------------------- scope

/// What we know about the directory `init` runs in.
#[derive(Debug, Clone, PartialEq)]
pub struct ProjectInfo {
    pub cwd: PathBuf,
    /// Nearest directory at or above `cwd` holding `.git` (a dir, or a file for worktrees).
    pub git_root: Option<PathBuf>,
}

impl ProjectInfo {
    /// The repository's name (the git root's folder name).
    pub fn repo_name(&self) -> Option<String> {
        self.git_root
            .as_ref()
            .and_then(|r| r.file_name())
            .map(|n| n.to_string_lossy().into_owned())
    }
}

/// Reasons to double-check a project-scope install.
#[derive(Debug, Clone, PartialEq)]
pub enum ScopeWarning {
    /// cwd is the home directory: "this project" would be everything.
    Home,
    /// cwd is `/`.
    FilesystemRoot,
    /// No git repository at or above cwd.
    NotGit,
    /// cwd is inside a repository but not at its top.
    Subdirectory { root: PathBuf },
}

impl ScopeWarning {
    pub fn message(&self) -> String {
        match self {
            ScopeWarning::Home => {
                "This is your home directory, not a project. Project scope here would cover \
                 everything you own; cd into a repository first, or pick user scope."
                    .into()
            }
            ScopeWarning::FilesystemRoot => {
                "This is the filesystem root (/), not a project. cd into a repository first.".into()
            }
            ScopeWarning::NotGit => "This folder is not inside a git repository.".into(),
            ScopeWarning::Subdirectory { root } => format!(
                "This is a subfolder of the repository at {}.",
                crate::fsutil::pretty(root)
            ),
        }
    }

    /// Serious enough that the confirmation should default to "no".
    pub fn is_serious(&self) -> bool {
        matches!(self, ScopeWarning::Home | ScopeWarning::FilesystemRoot)
    }
}

pub fn find_git_root(start: &Path) -> Option<PathBuf> {
    let mut d = Some(start);
    while let Some(dir) = d {
        if dir.join(".git").exists() {
            return Some(dir.to_path_buf());
        }
        d = dir.parent();
    }
    None
}

fn same_dir(a: &Path, b: &Path) -> bool {
    let c = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    c(a) == c(b)
}

/// Inspect `cwd` for a project-scope install.
pub fn inspect_project(cwd: &Path, home: &Path) -> (ProjectInfo, Vec<ScopeWarning>) {
    let git_root = find_git_root(cwd);
    let mut w = vec![];
    if cwd.parent().is_none() {
        w.push(ScopeWarning::FilesystemRoot);
    } else if same_dir(cwd, home) {
        w.push(ScopeWarning::Home);
    }
    match &git_root {
        None => w.push(ScopeWarning::NotGit),
        Some(r) if !same_dir(r, cwd) => w.push(ScopeWarning::Subdirectory { root: r.clone() }),
        Some(_) => {}
    }
    (
        ProjectInfo {
            cwd: cwd.to_path_buf(),
            git_root,
        },
        w,
    )
}

// ---------------------------------------------------------------- routing mode

/// Picker wording for the three routing modes, safest first.
pub const MODES: [(RoutingMode, &str, &str); 3] = [
    (
        RoutingMode::Confirm,
        "Ask me each time (confirm)",
        "Claude shows what would be sent; you approve it in your terminal. Recommended to start.",
    ),
    (
        RoutingMode::Auto,
        "Automatic (auto)",
        "Claude delegates safe, big-enough jobs by itself; everything is logged.",
    ),
    (
        RoutingMode::Explicit,
        "Only when I say so (explicit)",
        "Only prompts that start with `cheap:` are delegated.",
    ),
];

/// Default for a first-time user: `confirm`. Nothing leaves the machine until the user has
/// seen the exact sanitized payload and approved it in their own terminal, so a wrong guess
/// about what is safe to delegate costs nothing; switching to `auto` later is one line.
pub const DEFAULT_MODE: RoutingMode = RoutingMode::Confirm;

pub fn mode_label(m: RoutingMode) -> &'static str {
    MODES.iter().find(|x| x.0 == m).map(|x| x.1).unwrap_or("?")
}

pub fn mode_str(m: RoutingMode) -> &'static str {
    match m {
        RoutingMode::Auto => "auto",
        RoutingMode::Confirm => "confirm",
        RoutingMode::Explicit => "explicit",
    }
}

// ---------------------------------------------------------------- existing config

/// A short description of an existing config (never a key).
#[derive(Debug, Clone, Default)]
pub struct ExistingSummary {
    /// (name, where its key comes from, key found)
    pub providers: Vec<(String, String, bool)>,
    pub mode: Option<RoutingMode>,
    /// The config does not load; only Keep or Start fresh make sense.
    pub error: Option<String>,
}

pub fn summarize_existing(path: &Path) -> ExistingSummary {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            return ExistingSummary {
                error: Some(format!("cannot read it: {e}")),
                ..Default::default()
            }
        }
    };
    match Config::from_toml(&text) {
        Ok(c) => ExistingSummary {
            providers: c
                .providers
                .iter()
                .map(|(n, p)| {
                    let st = p.key_status();
                    (n.clone(), short_key_status(&st), st.ok())
                })
                .collect(),
            mode: Some(c.routing.mode),
            error: None,
        },
        Err(e) => ExistingSummary {
            error: Some(crate::fsutil::clean(&format!("{e:#}"), 200)),
            ..Default::default()
        },
    }
}

/// "key stored" / "env var set" / "no key needed" / "no key yet" (never the value).
pub fn short_key_status(st: &crate::config::KeyStatus) -> String {
    use crate::config::KeyStatus;
    match st {
        KeyStatus::Env(v) => format!("env var {v} set"),
        KeyStatus::Stored(..) => "key stored".into(),
        KeyStatus::KeyFile(_) => "key file".into(),
        KeyStatus::NotNeeded => "no key needed".into(),
        KeyStatus::Missing(_) => "no key yet".into(),
    }
}

/// Copy `path` to `<name>.bak-YYYYMMDD-HHMMSS` (0600) next to it; never overwrites a backup.
pub fn backup_file(path: &Path) -> Result<PathBuf> {
    let text = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    let fmt =
        time::format_description::parse_borrowed::<2>("[year][month][day]-[hour][minute][second]")
            .expect("static format");
    let stamp = time::OffsetDateTime::now_utc()
        .format(&fmt)
        .unwrap_or_else(|_| "backup".into());
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "config".into());
    let dir = path.parent().unwrap_or(Path::new("."));
    let mut dest = dir.join(format!("{name}.bak-{stamp}"));
    let mut i = 1;
    while dest.exists() {
        dest = dir.join(format!("{name}.bak-{stamp}-{i}"));
        i += 1;
    }
    crate::fsutil::write_atomic(&dest, &text, Some(0o600))?;
    Ok(dest)
}

/// Set `[routing] mode`, keeping everything else.
pub fn set_mode(text: &str, mode: RoutingMode) -> Result<String> {
    let mut doc: toml_edit::DocumentMut = text.parse().context("config is not valid TOML")?;
    let r = doc
        .entry("routing")
        .or_insert_with(|| toml_edit::Item::Table(toml_edit::Table::new()))
        .as_table_mut()
        .context("`routing` in the config is not a table")?;
    r.insert("mode", toml_edit::value(mode_str(mode)));
    Ok(doc.to_string())
}

/// Make sure `dir` is readable: append it to `[paths] roots` unless a root already covers it.
pub fn add_root(text: &str, dir: &Path) -> Result<String> {
    let cfg = Config::from_toml(text)?;
    if cfg.project_root_placeholder || cfg.paths.roots.iter().any(|r| dir.starts_with(r)) {
        return Ok(text.to_string());
    }
    let mut doc: toml_edit::DocumentMut = text.parse().context("config is not valid TOML")?;
    let roots = doc
        .get_mut("paths")
        .and_then(|p| p.get_mut("roots"))
        .and_then(|r| r.as_array_mut())
        .context("`paths.roots` in the config is not a list")?;
    roots.push(dir.display().to_string());
    Ok(doc.to_string())
}

/// Task kinds whose chain starts with the pinned default model.
pub const CODE_ROUTES: [&str; 5] = [
    "write_tests",
    "boilerplate",
    "snippet",
    "refactor_small",
    "docstring",
];

/// Start the code task chains with `provider`'s default model (then the automatic cheapest
/// choice, then Claude). Routes the user already wrote are left alone.
pub fn pin_model_routes(text: &str, provider: &str) -> Result<String> {
    let mut doc: toml_edit::DocumentMut = text.parse().context("config is not valid TOML")?;
    let routes = doc
        .entry("routes")
        .or_insert_with(|| toml_edit::Item::Table(toml_edit::Table::new()))
        .as_table_mut()
        .context("`routes` in the config is not a table")?;
    for k in CODE_ROUTES {
        if routes.contains_key(k) {
            continue;
        }
        let mut chain = toml_edit::Array::new();
        chain.push(provider);
        chain.push("auto:code:cheapest");
        chain.push("claude");
        let mut t = toml_edit::InlineTable::new();
        t.insert("chain", toml_edit::Value::Array(chain));
        routes.insert(k, toml_edit::value(t));
    }
    Ok(doc.to_string())
}

/// "Update": add or replace the chosen providers, optionally change the mode. Comments and
/// unrelated settings are kept; stored keys of providers not touched stay as they are.
pub fn merge_update(
    text: &str,
    entries: &[ProviderEntry],
    mode: Option<RoutingMode>,
) -> Result<String> {
    let mut t = text.to_string();
    for e in entries {
        t = crate::onboard::upsert_entry(&t, e)?;
    }
    if let Some(e) = entries.iter().find(|e| e.model.is_some()) {
        t = pin_model_routes(&t, &e.name)?;
    }
    if let Some(m) = mode {
        t = set_mode(&t, m)?;
    }
    Config::from_toml(&t).context("the updated config would be invalid")?;
    Ok(t)
}

// ---------------------------------------------------------------- providers

/// Is `name` usable as `[providers.<name>]` for a custom endpoint?
pub fn check_provider_name(name: &str, taken: &[String]) -> std::result::Result<(), String> {
    let n = name.trim();
    if n.is_empty() || n.len() > 32 {
        return Err("use 1 to 32 characters".into());
    }
    if !n
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err("use lowercase letters, digits, - or _".into());
    }
    if ["claude", "auto", "custom"].contains(&n) {
        return Err(format!("{n} is reserved"));
    }
    if crate::providers::presets::find(n).is_some() {
        return Err(format!("{n} is a built-in provider; pick another name"));
    }
    if taken.iter().any(|t| t == n) {
        return Err(format!("{n} is already used in this setup"));
    }
    Ok(())
}

/// Weighted price used for ranking (output usually dominates for code generation).
fn weight(m: &ModelInfo) -> f64 {
    m.price_in_per_1m.unwrap_or(f64::MAX) + 4.0 * m.price_out_per_1m.unwrap_or(f64::MAX)
}

/// The `n` cheapest paid, priced text models that look suitable for code and have at least a
/// 32k context (free-tier variants are skipped: they are rate-limited and may log prompts).
pub fn coding_picks(models: &[ModelInfo], n: usize) -> Vec<ModelInfo> {
    let mut v: Vec<&ModelInfo> = models
        .iter()
        .filter(|m| {
            m.is_text()
                && m.price_in_per_1m.is_some()
                && m.price_out_per_1m.is_some()
                && !crate::catalog::is_free_tier(&m.id)
                && m.context_length.is_none_or(|c| c >= 32_000)
                && crate::catalog::tags_for(&m.id, m.context_length).contains(&"code".to_string())
        })
        .collect();
    v.sort_by(|a, b| {
        weight(a)
            .partial_cmp(&weight(b))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.id.cmp(&b.id))
    });
    v.dedup_by(|a, b| a.id == b.id);
    v.into_iter().take(n).cloned().collect()
}

pub fn fmt_prices(m: &ModelInfo) -> String {
    let p = |x: Option<f64>| match x {
        Some(v) if v < 1.0 => format!("${v:.2}"),
        Some(v) => format!("${v:.1}"),
        None => "?".into(),
    };
    format!(
        "{} in · {} out per 1M tokens",
        p(m.price_in_per_1m),
        p(m.price_out_per_1m)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_warnings() {
        let d = tempfile::tempdir().unwrap();
        let home = d.path().join("home");
        let repo = home.join("code/my-repo");
        let sub = repo.join("src/deep");
        let loose = home.join("notes");
        for p in [&sub, &loose] {
            std::fs::create_dir_all(p).unwrap();
        }
        std::fs::create_dir(repo.join(".git")).unwrap();

        let (info, w) = inspect_project(&repo, &home);
        assert!(w.is_empty(), "{w:?}");
        assert_eq!(info.git_root.as_deref(), Some(repo.as_path()));
        assert_eq!(info.repo_name().as_deref(), Some("my-repo"));

        let (info, w) = inspect_project(&sub, &home);
        assert_eq!(w, vec![ScopeWarning::Subdirectory { root: repo.clone() }]);
        assert!(w[0].message().contains("subfolder"));
        assert_eq!(info.git_root.as_deref(), Some(repo.as_path()));

        let (info, w) = inspect_project(&loose, &home);
        assert_eq!(w, vec![ScopeWarning::NotGit]);
        assert!(info.repo_name().is_none());

        let (_, w) = inspect_project(&home, &home);
        assert!(w.contains(&ScopeWarning::Home) && w.contains(&ScopeWarning::NotGit));
        assert!(w.iter().any(|x| x.is_serious()));

        let (_, w) = inspect_project(Path::new("/"), &home);
        assert!(w.contains(&ScopeWarning::FilesystemRoot));

        // a worktree has a .git *file*
        let wt = home.join("wt");
        std::fs::create_dir_all(&wt).unwrap();
        std::fs::write(wt.join(".git"), "gitdir: /x\n").unwrap();
        assert!(inspect_project(&wt, &home).1.is_empty());
    }

    #[test]
    fn default_mode_is_the_safest_and_listed_first() {
        assert_eq!(DEFAULT_MODE, RoutingMode::Confirm);
        assert_eq!(MODES[0].0, DEFAULT_MODE);
        assert!(MODES[0].2.contains("Recommended to start"));
        assert!(MODES[2].2.contains("cheap:"));
        assert_eq!(mode_label(RoutingMode::Auto), "Automatic (auto)");
    }

    fn base(dir: &Path) -> String {
        format!(
            "# mine\n[paths]\nroots = [\"{}\"]\n\n[routing]\nmode = \"auto\" # keep comment\n\n[providers.openrouter]\npreset = \"openrouter\"\nkey_source = \"file\"\n",
            dir.display()
        )
    }

    #[test]
    fn update_merges_providers_and_mode() {
        let d = tempfile::tempdir().unwrap();
        let t = base(d.path());
        let entries = vec![
            ProviderEntry {
                model: Some("qwen/qwen3-coder".into()),
                ..ProviderEntry::preset("openrouter")
            },
            ProviderEntry {
                key_source: Some(crate::keystore::KeySource::Keychain),
                ..ProviderEntry::preset("deepseek")
            },
        ];
        let out = merge_update(&t, &entries, Some(RoutingMode::Confirm)).unwrap();
        assert!(out.contains("# mine"));
        let c = Config::from_toml(&out).unwrap();
        assert_eq!(c.routing.mode, RoutingMode::Confirm);
        assert_eq!(
            c.providers["openrouter"].key_source,
            Some(crate::keystore::KeySource::File),
            "an untouched stored key stays"
        );
        assert_eq!(
            c.providers["openrouter"].model.as_deref(),
            Some("qwen/qwen3-coder")
        );
        assert!(c.providers.contains_key("deepseek"));
        assert_eq!(c.routes["write_tests"].chain[0], "openrouter");
        assert!(!c.routes.contains_key("summarize"));
        // keep: no entries, no mode -> identical text
        assert_eq!(merge_update(&t, &[], None).unwrap(), t);
        // an invalid result is refused
        let bad = ProviderEntry {
            name: "x".into(),
            base_url: Some("https://a.example/v1".into()),
            ..Default::default()
        };
        assert!(merge_update(&t, &[bad], None).is_err());
    }

    #[test]
    fn project_folder_becomes_readable_once() {
        let d = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let t = base(d.path());
        let inside = d.path().join("sub");
        std::fs::create_dir(&inside).unwrap();
        assert_eq!(add_root(&t, &inside).unwrap(), t, "already covered");
        let out = add_root(&t, other.path()).unwrap();
        let c = Config::from_toml(&out).unwrap();
        assert_eq!(c.paths.roots.len(), 2);
        assert!(out.contains("# mine"));
    }

    #[test]
    fn user_routes_are_not_overwritten() {
        let d = tempfile::tempdir().unwrap();
        let t = format!(
            "{}\n[routes.write_tests]\nchain = [\"claude\"]\n",
            base(d.path())
        );
        let out = pin_model_routes(&t, "openrouter").unwrap();
        let c = Config::from_toml(&out).unwrap();
        assert_eq!(c.routes["write_tests"].chain, vec!["claude"]);
        assert_eq!(c.routes["snippet"].chain[0], "openrouter");
    }

    #[test]
    fn fresh_start_backs_up_first() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("config.toml");
        std::fs::write(&p, "old = 1\n").unwrap();
        let b1 = backup_file(&p).unwrap();
        let b2 = backup_file(&p).unwrap();
        assert_ne!(b1, b2, "never overwrites a backup");
        assert_eq!(std::fs::read_to_string(&b1).unwrap(), "old = 1\n");
        assert!(b1
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("config.toml.bak-"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(&b1).unwrap().permissions().mode();
            assert_eq!(m & 0o777, 0o600);
        }
    }

    #[test]
    fn existing_summary_never_shows_keys() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.toml");
        std::fs::write(&p, base(d.path())).unwrap();
        let s = summarize_existing(&p);
        assert!(s.error.is_none(), "{:?}", s.error);
        assert_eq!(s.mode, Some(RoutingMode::Auto));
        assert_eq!(s.providers[0].0, "openrouter");
        std::fs::write(&p, "not [valid").unwrap();
        assert!(summarize_existing(&p).error.is_some());
    }

    #[test]
    fn custom_names() {
        assert!(check_provider_name("work-llm", &[]).is_ok());
        assert!(check_provider_name("Work", &[]).is_err());
        assert!(check_provider_name("openrouter", &[]).is_err());
        assert!(check_provider_name("claude", &[]).is_err());
        assert!(check_provider_name("a/b", &[]).is_err());
        assert!(check_provider_name("mine", &["mine".into()]).is_err());
    }

    fn m(id: &str, pin: f64, pout: f64, ctx: u64) -> ModelInfo {
        ModelInfo {
            id: id.into(),
            tier: None,
            modality: Some("text->text".into()),
            status: None,
            context_length: Some(ctx),
            price_in_per_1m: Some(pin),
            price_out_per_1m: Some(pout),
        }
    }

    #[test]
    fn shortlist_is_cheap_paid_coding_models() {
        let models = vec![
            m("qwen/qwen3-coder", 0.2, 0.8, 262_000),
            m("deepseek/deepseek-v4-flash", 0.1, 0.4, 128_000),
            m("deepseek/deepseek-v4-flash:free", 0.0, 0.0, 128_000),
            m("openai/text-embedding-3", 0.01, 0.0, 8_000),
            m("some/poem-writer", 0.01, 0.01, 128_000),
            m("qwen/qwen-tiny-coder", 0.01, 0.01, 8_000),
            m("z-ai/glm-5", 0.5, 2.0, 200_000),
            m("moonshotai/kimi-k3", 0.6, 2.5, 200_000),
            m("mistralai/devstral-2", 0.1, 0.3, 128_000),
            m("x-ai/grok-code", 0.2, 1.5, 256_000),
        ];
        let p = coding_picks(&models, 5);
        let ids: Vec<_> = p.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "mistralai/devstral-2",
                "deepseek/deepseek-v4-flash",
                "qwen/qwen3-coder",
                "x-ai/grok-code",
                "z-ai/glm-5"
            ]
        );
        assert_eq!(fmt_prices(&p[0]), "$0.10 in · $0.30 out per 1M tokens");
    }
}
