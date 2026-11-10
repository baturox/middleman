//! TOML -> typed `Config`. Validation is strict: anything invalid fails closed.
//! Providers are pure config (optionally filled from a preset). A project `.middleman.toml`
//! may only tighten the user config (`ProjectOverlay` + `Config::tighten`).

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::classify::{Complexity, Sensitivity};
use crate::providers::presets;
use crate::TaskKind;

/// Deny globs that always apply, whatever the config says.
pub const BUILTIN_DENY: &[&str] = &[
    "**/.env*",
    "**/*.pem",
    "**/*.key",
    "**/*credential*",
    "**/secrets/**",
    "**/.git/**",
    "**/.ssh/**",
    "**/*.tfstate",
    "**/*.tfstate.*",
    "**/id_rsa*",
    "**/id_ed25519*",
    "**/*.p12",
    "**/*.pfx",
    "**/.npmrc",
    "**/.pypirc",
    "**/.netrc",
];

/// Well-known public hosts that carry no identifying information and are kept verbatim.
pub const DEFAULT_PUBLIC_HOSTS: &[&str] = &[
    "github.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "gitlab.com",
    "crates.io",
    "docs.rs",
    "pypi.org",
    "python.org",
    "docs.python.org",
    "npmjs.com",
    "www.npmjs.com",
    "registry.npmjs.org",
    "nodejs.org",
    "rust-lang.org",
    "doc.rust-lang.org",
    "developer.mozilla.org",
    "w3.org",
    "www.w3.org",
    "json-schema.org",
    "schema.org",
    "google.com",
    "www.google.com",
    "stackoverflow.com",
    "wikipedia.org",
    "en.wikipedia.org",
    "localhost",
];

pub const DEFAULT_UA: &str = "Mozilla/5.0 (compatible; middleman/0.1)";
pub const PROJECT_FILE: &str = ".middleman.toml";

/// An API key. Never printed, never serialized.
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: impl Into<String>) -> Self {
        Secret(s.into())
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub budget: BudgetCfg,
    pub paths: PathsCfg,
    #[serde(default)]
    pub redact: RedactCfg,
    #[serde(default)]
    pub classify: ClassifyCfg,
    #[serde(default)]
    pub routing: RoutingCfg,
    #[serde(default)]
    pub economics: crate::economics::EconomicsCfg,
    #[serde(default)]
    pub usage: crate::usage::UsageCfg,
    /// Per-task-kind routing chains, keyed by task kind (`write_tests`, ...).
    #[serde(default)]
    pub routes: BTreeMap<String, RouteCfg>,
    /// Per-model overrides keyed `"<provider>/<model id>"`.
    #[serde(default)]
    pub models: BTreeMap<String, ModelOverride>,
    #[serde(default)]
    pub providers: BTreeMap<String, ProviderCfg>,
    /// Where ledger and audit files go. Default `~/.local/state/middleman`.
    #[serde(default)]
    pub state_dir: Option<PathBuf>,
    /// Where the model catalog is cached. Default `~/.cache/middleman`.
    #[serde(default)]
    pub cache_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    pub max_input_chars: usize,
    pub max_files: usize,
    pub max_output_tokens: u32,
    pub request_timeout_s: u64,
    pub max_file_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_input_chars: 24_000,
            max_files: 6,
            max_output_tokens: 2_000,
            request_timeout_s: 120,
            max_file_bytes: 256 * 1024,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BudgetCfg {
    pub per_call_usd: f64,
    pub daily_usd: f64,
    pub weekly_usd: f64,
    pub reserve_usd: f64,
}

impl Default for BudgetCfg {
    fn default() -> Self {
        BudgetCfg {
            per_call_usd: 0.05,
            daily_usd: 1.0,
            weekly_usd: 4.0,
            reserve_usd: 1.0,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathsCfg {
    pub roots: Vec<PathBuf>,
    /// Extra deny globs (added to `BUILTIN_DENY`).
    #[serde(default)]
    pub deny: Vec<String>,
    /// Optional allow globs (matched on the root-relative path). Empty = everything under a root.
    #[serde(default)]
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SecretsMode {
    Mask,
    #[default]
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PiiMode {
    Pseudonymize,
    #[default]
    Block,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RedactCfg {
    pub secrets: SecretsMode,
    pub pii: PiiMode,
    pub dictionary_file: Option<PathBuf>,
    /// Extra hosts kept verbatim (added to `DEFAULT_PUBLIC_HOSTS`).
    pub public_hosts: Vec<String>,
}

impl Default for RedactCfg {
    fn default() -> Self {
        RedactCfg {
            secrets: SecretsMode::Block,
            pii: PiiMode::Block,
            dictionary_file: None,
            public_hosts: vec![],
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ClassifyCfg {
    /// Dictionary hits at or above this count raise sensitivity to S2.
    pub dict_hits_s2: usize,
    /// Payload size (chars) above which complexity is bumped one level.
    pub large_chars: usize,
}

impl Default for ClassifyCfg {
    fn default() -> Self {
        ClassifyCfg {
            dict_hits_s2: 12,
            large_chars: 12_000,
        }
    }
}

/// Ordered from least to most restrictive (a project overlay may only move right).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RoutingMode {
    #[default]
    Auto,
    Confirm,
    Explicit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    #[default]
    Cheapest,
    Balanced,
    Best,
}

impl Tier {
    pub fn parse(s: &str) -> Option<Tier> {
        match s {
            "cheapest" | "cheap" => Some(Tier::Cheapest),
            "balanced" => Some(Tier::Balanced),
            "best" => Some(Tier::Best),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RoutingCfg {
    pub mode: RoutingMode,
    /// Starting tier for `auto:` steps (a `quality` hint on the call can raise it).
    pub default_quality: Tier,
    /// Max provider attempts per call (escalation steps).
    pub max_attempts: usize,
    pub catalog_ttl_hours: u64,
}

impl Default for RoutingCfg {
    fn default() -> Self {
        RoutingCfg {
            mode: RoutingMode::Auto,
            default_quality: Tier::Cheapest,
            max_attempts: 3,
            catalog_ttl_hours: 24,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteCfg {
    pub chain: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ModelOverride {
    pub price_in: Option<f64>,
    pub price_out: Option<f64>,
    pub context: Option<u64>,
    pub tags: Option<Vec<String>>,
    /// Set false to exclude a model from routing.
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Api {
    Openai,
    Anthropic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Trust {
    Untrusted,
    Zdr,
    Local,
    FirstParty,
}

/// How to read the account balance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BalanceKind {
    /// `GET {base}/balance` -> `balance_usd` (yapayzekalab)
    Yzlab,
    /// `GET {base}/credits` -> `data.total_credits - data.total_usage` (OpenRouter)
    Openrouter,
    /// No balance endpoint: the reserve check is skipped, caps still apply.
    None,
}

/// As written in TOML; turned into `ProviderCfg` by applying the preset.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProviderCfg {
    preset: Option<String>,
    api: Option<Api>,
    base_url: Option<String>,
    key_env: Option<String>,
    key_file: Option<PathBuf>,
    key_var: Option<String>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    trust: Option<Trust>,
    max_sensitivity: Option<Sensitivity>,
    max_complexity: Option<Complexity>,
    task_kinds: Option<Vec<TaskKind>>,
    enabled: Option<bool>,
    user_agent: Option<String>,
    /// Default model for pinned `"<provider>"` chain steps / `probe`.
    model: Option<String>,
    balance: Option<BalanceKind>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "RawProviderCfg")]
pub struct ProviderCfg {
    pub preset: Option<String>,
    pub api: Api,
    pub base_url: String,
    pub key_env: Option<String>,
    pub key_file: Option<PathBuf>,
    pub key_var: Option<String>,
    pub headers: BTreeMap<String, String>,
    pub trust: Trust,
    pub max_sensitivity: Sensitivity,
    pub max_complexity: Complexity,
    /// None = every task kind.
    pub task_kinds: Option<Vec<TaskKind>>,
    pub enabled: bool,
    pub user_agent: Option<String>,
    pub model: Option<String>,
    pub balance: BalanceKind,
}

impl TryFrom<RawProviderCfg> for ProviderCfg {
    type Error = String;
    fn try_from(r: RawProviderCfg) -> Result<Self, Self::Error> {
        let preset = match r.preset.as_deref() {
            None | Some("custom") => None,
            Some(name) => {
                Some(presets::find(name).ok_or_else(|| format!("unknown preset {name}"))?)
            }
        };
        let api = r
            .api
            .or(preset.map(|p| p.api))
            .ok_or("provider needs `api` (or a preset)")?;
        let base_url = r
            .base_url
            .or(preset.map(|p| p.base_url.to_string()))
            .ok_or("provider needs `base_url` (or a preset)")?;
        let trust = r
            .trust
            .or(preset.map(|p| p.trust))
            .unwrap_or(Trust::Untrusted);
        Ok(ProviderCfg {
            preset: r.preset,
            api,
            base_url: base_url.trim_end_matches('/').to_string(),
            key_env: r
                .key_env
                .or(preset.and_then(|p| p.key_env.map(String::from))),
            key_file: r.key_file,
            key_var: r.key_var,
            headers: r.headers,
            trust,
            max_sensitivity: r
                .max_sensitivity
                .unwrap_or_else(|| presets::default_max_sensitivity(trust)),
            max_complexity: r.max_complexity.unwrap_or(Complexity::C1),
            task_kinds: r.task_kinds,
            enabled: r.enabled.unwrap_or(true),
            user_agent: r.user_agent,
            model: r.model,
            balance: r
                .balance
                .or(preset.map(|p| p.balance))
                .unwrap_or(BalanceKind::None),
        })
    }
}

impl ProviderCfg {
    pub fn ua(&self) -> &str {
        self.user_agent.as_deref().unwrap_or(DEFAULT_UA)
    }

    pub fn allows_task(&self, t: TaskKind) -> bool {
        self.task_kinds.as_ref().is_none_or(|v| v.contains(&t))
    }

    pub fn needs_key(&self) -> bool {
        self.trust != Trust::Local
    }

    /// Resolve the API key: env var first, then `<key_var|key_env>=value` inside `key_file`.
    /// Errors never contain the value. Local providers may have no key.
    pub fn resolve_key(&self) -> Result<Secret> {
        if let Some(env) = &self.key_env {
            if let Ok(v) = std::env::var(env) {
                let v = v.trim();
                if !v.is_empty() {
                    return Ok(Secret::new(v));
                }
            }
        }
        let var = self.key_var.as_ref().or(self.key_env.as_ref());
        match (&self.key_file, var) {
            (Some(file), Some(var)) => {
                let text = std::fs::read_to_string(file)
                    .with_context(|| format!("cannot read key_file {}", file.display()))?;
                for line in text.lines() {
                    let line = line.trim();
                    let line = line.strip_prefix("export ").unwrap_or(line);
                    if let Some((k, v)) = line.split_once('=') {
                        if k.trim() == var {
                            let v = v.trim().trim_matches(|c| c == '"' || c == '\'').trim();
                            if v.is_empty() || v.contains("BURAYA") {
                                bail!("{var} in key_file is empty or a placeholder");
                            }
                            return Ok(Secret::new(v));
                        }
                    }
                }
                bail!("{var} not present in key_file {}", file.display())
            }
            _ if !self.needs_key() => Ok(Secret::new("")),
            _ => bail!(
                "key not found: env {} unset and no key_file",
                self.key_env.as_deref().unwrap_or("<none>")
            ),
        }
    }

    /// Whether a key is resolvable, without exposing it.
    pub fn key_present(&self) -> bool {
        self.resolve_key().is_ok()
    }
}

pub fn expand_tilde(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    p.to_path_buf()
}

pub fn default_config_path() -> PathBuf {
    expand_tilde(Path::new("~/.config/middleman/config.toml"))
}

fn is_local_url(u: &str) -> bool {
    ["http://localhost", "http://127.0.0.1", "http://[::1]"]
        .iter()
        .any(|p| u.starts_with(p))
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let path = expand_tilde(path);
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("cannot read config {}", path.display()))?;
        Self::from_toml(&text)
    }

    /// Load the user config, then apply the nearest `.middleman.toml` at or above `cwd`
    /// (tighten-only). Returns the config and the overlay path if one was applied.
    pub fn load_with_project(path: &Path, cwd: &Path) -> Result<(Config, Option<PathBuf>)> {
        let mut cfg = Self::load(path)?;
        let mut dir = Some(cwd);
        while let Some(d) = dir {
            let f = d.join(PROJECT_FILE);
            if f.is_file() {
                let text = std::fs::read_to_string(&f)
                    .with_context(|| format!("cannot read {}", f.display()))?;
                let overlay: ProjectOverlay = toml::from_str(&text).with_context(|| {
                    format!("invalid project overlay {} (fail-closed)", f.display())
                })?;
                cfg.tighten(&overlay)?;
                return Ok((cfg, Some(f)));
            }
            dir = d.parent();
        }
        Ok((cfg, None))
    }

    pub fn from_toml(text: &str) -> Result<Config> {
        let mut cfg: Config = toml::from_str(text).context("invalid config TOML")?;
        cfg.normalize();
        cfg.validate()?;
        Ok(cfg)
    }

    fn normalize(&mut self) {
        for r in &mut self.paths.roots {
            *r = expand_tilde(r);
        }
        if let Some(d) = &self.redact.dictionary_file {
            self.redact.dictionary_file = Some(expand_tilde(d));
        }
        for d in [&mut self.state_dir, &mut self.cache_dir]
            .into_iter()
            .flatten()
        {
            *d = expand_tilde(d);
        }
        for p in self.providers.values_mut() {
            if let Some(k) = &p.key_file {
                p.key_file = Some(expand_tilde(k));
            }
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.paths.roots.is_empty() {
            bail!("paths.roots must list at least one directory");
        }
        for r in &self.paths.roots {
            if !r.is_absolute() {
                bail!("paths.roots entry is not absolute: {}", r.display());
            }
            if !r.is_dir() {
                bail!("paths.roots entry is not a directory: {}", r.display());
            }
        }
        for g in self.paths.deny.iter().chain(self.paths.allow.iter()) {
            globset::Glob::new(g).with_context(|| format!("bad glob {g}"))?;
        }
        if let Some(d) = &self.redact.dictionary_file {
            if !d.is_file() {
                bail!("dictionary_file missing: {} (fail-closed)", d.display());
            }
        }
        let b = &self.budget;
        for (name, v) in [
            ("per_call_usd", b.per_call_usd),
            ("daily_usd", b.daily_usd),
            ("weekly_usd", b.weekly_usd),
            ("reserve_usd", b.reserve_usd),
            (
                "economics.min_expected_output_tokens",
                self.economics.min_expected_output_tokens as f64,
            ),
        ] {
            if !v.is_finite() || v < 0.0 {
                bail!("{name} must be a finite non-negative number");
            }
        }
        let l = &self.limits;
        if l.max_input_chars == 0 || l.max_files == 0 || l.max_output_tokens == 0 {
            bail!("limits must be positive");
        }
        self.economics.prices().context("economics")?;
        if self.routing.max_attempts == 0 {
            bail!("routing.max_attempts must be >= 1");
        }
        for (name, p) in &self.providers {
            if name.contains('/') || name == "claude" || name == "auto" {
                bail!("provider name {name:?} is reserved or contains '/'");
            }
            let https = p.base_url.starts_with("https://");
            let local_http = is_local_url(&p.base_url);
            if !(https || local_http) {
                bail!("provider {name}: base_url must be https (http only for localhost)");
            }
            if local_http
                && !(p.trust == Trust::Local || p.base_url.starts_with("http://127.0.0.1"))
            {
                bail!("provider {name}: plain-http base_url requires trust = \"local\"");
            }
            if p.max_sensitivity >= Sensitivity::S3
                && !matches!(p.trust, Trust::Local | Trust::FirstParty)
            {
                bail!("provider {name}: S3 is only allowed for trust = local | first_party");
            }
            if p.needs_key() && p.key_env.is_none() && p.key_file.is_none() {
                bail!("provider {name}: set key_env or key_file (keys are never inline)");
            }
            if p.key_file.is_some() && p.key_var.is_none() && p.key_env.is_none() {
                bail!("provider {name}: key_file needs key_var or key_env");
            }
            if let Some(m) = &p.model {
                if m.trim().is_empty() || m.contains('<') {
                    bail!("provider {name}: model placeholder not filled in");
                }
            }
        }
        for (k, r) in &self.routes {
            if TaskKind::parse(k).is_none() {
                bail!("routes.{k}: unknown task kind");
            }
            if r.chain.is_empty() {
                bail!("routes.{k}: empty chain");
            }
            for s in &r.chain {
                crate::routing::Step::parse(s).with_context(|| format!("routes.{k}"))?;
            }
        }
        for (k, m) in &self.models {
            if !k.contains('/') {
                bail!("models.{k:?}: key must be \"<provider>/<model id>\"");
            }
            for v in [m.price_in, m.price_out].into_iter().flatten() {
                if !v.is_finite() || v < 0.0 {
                    bail!("models.{k:?}: prices must be non-negative");
                }
            }
        }
        Ok(())
    }

    pub fn state_dir(&self) -> PathBuf {
        self.state_dir
            .clone()
            .unwrap_or_else(|| expand_tilde(Path::new("~/.local/state/middleman")))
    }

    pub fn cache_dir(&self) -> PathBuf {
        self.cache_dir
            .clone()
            .unwrap_or_else(|| expand_tilde(Path::new("~/.cache/middleman")))
    }

    pub fn public_hosts(&self) -> Vec<String> {
        DEFAULT_PUBLIC_HOSTS
            .iter()
            .map(|s| s.to_string())
            .chain(
                self.redact
                    .public_hosts
                    .iter()
                    .map(|s| s.to_ascii_lowercase()),
            )
            .collect()
    }

    /// Apply a project overlay. Every field can only make the config stricter; an attempt to
    /// loosen is an error (fail-closed) rather than being silently ignored.
    pub fn tighten(&mut self, o: &ProjectOverlay) -> Result<()> {
        fn lower<T: PartialOrd + Copy + fmt::Debug>(
            name: &str,
            cur: &mut T,
            new: Option<T>,
        ) -> Result<()> {
            if let Some(n) = new {
                if n > *cur {
                    bail!("project overlay may only tighten: {name} {n:?} > {cur:?}");
                }
                *cur = n;
            }
            Ok(())
        }
        fn raise<T: PartialOrd + Copy + fmt::Debug>(
            name: &str,
            cur: &mut T,
            new: Option<T>,
        ) -> Result<()> {
            if let Some(n) = new {
                if n < *cur {
                    bail!("project overlay may only tighten: {name} {n:?} < {cur:?}");
                }
                *cur = n;
            }
            Ok(())
        }
        if let Some(b) = &o.budget {
            lower(
                "budget.per_call_usd",
                &mut self.budget.per_call_usd,
                b.per_call_usd,
            )?;
            lower("budget.daily_usd", &mut self.budget.daily_usd, b.daily_usd)?;
            lower(
                "budget.weekly_usd",
                &mut self.budget.weekly_usd,
                b.weekly_usd,
            )?;
            raise(
                "budget.reserve_usd",
                &mut self.budget.reserve_usd,
                b.reserve_usd,
            )?;
        }
        if let Some(l) = &o.limits {
            lower(
                "limits.max_input_chars",
                &mut self.limits.max_input_chars,
                l.max_input_chars,
            )?;
            lower("limits.max_files", &mut self.limits.max_files, l.max_files)?;
            lower(
                "limits.max_output_tokens",
                &mut self.limits.max_output_tokens,
                l.max_output_tokens,
            )?;
            lower(
                "limits.max_file_bytes",
                &mut self.limits.max_file_bytes,
                l.max_file_bytes,
            )?;
        }
        if let Some(p) = &o.paths {
            for g in &p.deny {
                globset::Glob::new(g).with_context(|| format!("bad glob {g}"))?;
            }
            self.paths.deny.extend(p.deny.iter().cloned());
        }
        if let Some(r) = &o.redact {
            raise("redact.secrets", &mut self.redact.secrets, r.secrets)?;
            raise("redact.pii", &mut self.redact.pii, r.pii)?;
        }
        if let Some(r) = &o.routing {
            raise("routing.mode", &mut self.routing.mode, r.mode)?;
        }
        for (name, po) in &o.providers {
            let Some(p) = self.providers.get_mut(name) else {
                bail!("project overlay names unknown provider {name} (it cannot add providers)");
            };
            if po.enabled == Some(true) && !p.enabled {
                bail!("project overlay may only disable providers ({name})");
            }
            if po.enabled == Some(false) {
                p.enabled = false;
            }
            lower(
                &format!("providers.{name}.max_sensitivity"),
                &mut p.max_sensitivity,
                po.max_sensitivity,
            )?;
            lower(
                &format!("providers.{name}.max_complexity"),
                &mut p.max_complexity,
                po.max_complexity,
            )?;
            if let Some(kinds) = &po.task_kinds {
                let cur: Vec<TaskKind> = p
                    .task_kinds
                    .clone()
                    .unwrap_or_else(|| TaskKind::ALL.to_vec());
                if let Some(bad) = kinds.iter().find(|k| !cur.contains(k)) {
                    bail!("project overlay may only remove task kinds ({name}: {bad})");
                }
                p.task_kinds = Some(kinds.clone());
            }
        }
        self.validate()
    }
}

/// `.middleman.toml` in a repository: tighten-only subset of the config.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ProjectOverlay {
    pub budget: Option<OverlayBudget>,
    pub limits: Option<OverlayLimits>,
    pub paths: Option<OverlayPaths>,
    pub redact: Option<OverlayRedact>,
    pub routing: Option<OverlayRouting>,
    #[serde(default)]
    pub providers: BTreeMap<String, OverlayProvider>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct OverlayBudget {
    pub per_call_usd: Option<f64>,
    pub daily_usd: Option<f64>,
    pub weekly_usd: Option<f64>,
    pub reserve_usd: Option<f64>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct OverlayLimits {
    pub max_input_chars: Option<usize>,
    pub max_files: Option<usize>,
    pub max_output_tokens: Option<u32>,
    pub max_file_bytes: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct OverlayPaths {
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct OverlayRedact {
    pub secrets: Option<SecretsMode>,
    pub pii: Option<PiiMode>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct OverlayRouting {
    pub mode: Option<RoutingMode>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct OverlayProvider {
    pub enabled: Option<bool>,
    pub max_sensitivity: Option<Sensitivity>,
    pub max_complexity: Option<Complexity>,
    pub task_kinds: Option<Vec<TaskKind>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(root: &Path) -> String {
        format!(
            r#"
[paths]
roots = ["{}"]
[providers.p]
api = "openai"
base_url = "https://example.invalid/v1"
key_env = "MM_UNSET_TEST_VAR_123"
max_sensitivity = "S1"
task_kinds = ["snippet", "docstring"]
"#,
            root.display()
        )
    }

    #[test]
    fn example_config_parses() {
        let d = tempfile::tempdir().unwrap();
        let t = include_str!("../config/middleman.example.toml")
            .replace("/abs/path/to/project", &d.path().display().to_string())
            .replace("dictionary_file = ", "# dictionary_file = ");
        let c = Config::from_toml(&t).unwrap();
        let or = &c.providers["openrouter"];
        assert_eq!(or.base_url, "https://openrouter.ai/api/v1");
        assert!(or.enabled);
        assert_eq!(or.model.as_deref(), Some("qwen/qwen3.8-flash"));
        assert!(!c.providers["deepseek"].enabled);
    }

    #[test]
    fn secret_debug_hides_value() {
        let s = Secret::new("sk-verysecretvalue");
        assert_eq!(format!("{s:?}"), "Secret(***)");
        assert_eq!(format!("{s}"), "***");
    }

    #[test]
    fn loads_and_validates() {
        let d = tempfile::tempdir().unwrap();
        let c = Config::from_toml(&base(d.path())).unwrap();
        assert_eq!(c.limits.max_files, 6);
        assert_eq!(c.providers["p"].max_complexity, Complexity::C1);
        assert_eq!(c.providers["p"].trust, Trust::Untrusted);
    }

    #[test]
    fn preset_fills_fields_and_trust_defaults() {
        let d = tempfile::tempdir().unwrap();
        let t = format!(
            "[paths]\nroots = [\"{}\"]\n[providers.or]\npreset = \"openrouter\"\n[providers.lm]\npreset = \"ollama\"\n",
            d.path().display()
        );
        let c = Config::from_toml(&t).unwrap();
        let or = &c.providers["or"];
        assert_eq!(or.base_url, "https://openrouter.ai/api/v1");
        assert_eq!(or.key_env.as_deref(), Some("OPENROUTER_API_KEY"));
        assert_eq!(or.max_sensitivity, Sensitivity::S1);
        assert_eq!(or.balance, BalanceKind::Openrouter);
        let lm = &c.providers["lm"];
        assert_eq!(lm.trust, Trust::Local);
        assert_eq!(lm.max_sensitivity, Sensitivity::S3);
        assert_eq!(lm.resolve_key().unwrap().expose(), "");
    }

    #[test]
    fn rejects_s3_untrusted_unknown_fields_plain_http() {
        let d = tempfile::tempdir().unwrap();
        let t = base(d.path()).replace("\"S1\"", "\"S3\"");
        assert!(Config::from_toml(&t).is_err());
        let t = base(d.path()) + "\nbogus = 1\n";
        assert!(Config::from_toml(&t).is_err());
        let t = base(d.path()).replace("https://example.invalid", "http://evil.example");
        assert!(Config::from_toml(&t).is_err());
        let t = base(d.path()).replace("api = \"openai\"\n", "preset = \"nope\"\n");
        assert!(Config::from_toml(&t).is_err());
    }

    #[test]
    fn missing_dictionary_fails_closed() {
        let d = tempfile::tempdir().unwrap();
        let t = base(d.path()) + "[redact]\ndictionary_file = \"/nonexistent/dict.txt\"\n";
        assert!(Config::from_toml(&t).is_err());
    }

    #[test]
    fn key_from_file() {
        let d = tempfile::tempdir().unwrap();
        let kf = d.path().join("k.env");
        std::fs::write(&kf, "OTHER=1\nexport MM_UNSET_TEST_VAR_123=\"abc123\"\n").unwrap();
        let mut c = Config::from_toml(&base(d.path())).unwrap();
        let p = c.providers.get_mut("p").unwrap();
        p.key_file = Some(kf);
        assert_eq!(p.resolve_key().unwrap().expose(), "abc123");
    }

    fn overlay(s: &str) -> ProjectOverlay {
        toml::from_str(s).unwrap()
    }

    #[test]
    fn overlay_tightens() {
        let d = tempfile::tempdir().unwrap();
        let mut c = Config::from_toml(&base(d.path())).unwrap();
        c.tighten(&overlay(
            r#"
[budget]
per_call_usd = 0.01
reserve_usd = 2.0
[paths]
deny = ["core/**"]
[routing]
mode = "confirm"
[providers.p]
max_sensitivity = "S0"
task_kinds = ["snippet"]
"#,
        ))
        .unwrap();
        assert_eq!(c.budget.per_call_usd, 0.01);
        assert_eq!(c.budget.reserve_usd, 2.0);
        assert!(c.paths.deny.contains(&"core/**".to_string()));
        assert_eq!(c.routing.mode, RoutingMode::Confirm);
        assert_eq!(c.providers["p"].max_sensitivity, Sensitivity::S0);
        assert_eq!(c.providers["p"].task_kinds, Some(vec![TaskKind::Snippet]));
        c.tighten(&overlay("[providers.p]\nenabled = false\n"))
            .unwrap();
        assert!(!c.providers["p"].enabled);
    }

    #[test]
    fn overlay_cannot_loosen() {
        let d = tempfile::tempdir().unwrap();
        let c0 = Config::from_toml(&base(d.path())).unwrap();
        for bad in [
            "[budget]\nper_call_usd = 10.0\n",
            "[budget]\nreserve_usd = 0.0\n",
            "[providers.p]\nmax_sensitivity = \"S2\"\n",
            "[providers.p]\ntask_kinds = [\"other\"]\n",
            "[providers.q]\nenabled = false\n",
            "[redact]\nsecrets = \"mask\"\n",
            "[limits]\nmax_files = 100\n",
        ] {
            let mut c = c0.clone();
            assert!(c.tighten(&overlay(bad)).is_err(), "{bad}");
        }
        let mut c = c0.clone();
        c.providers.get_mut("p").unwrap().enabled = false;
        assert!(c
            .tighten(&overlay("[providers.p]\nenabled = true\n"))
            .is_err());
        // a provider section cannot be smuggled in
        assert!(
            toml::from_str::<ProjectOverlay>("[providers.x]\nbase_url = \"https://a\"\n").is_err()
        );
    }

    #[test]
    fn load_with_project_finds_overlay_upwards() {
        let d = tempfile::tempdir().unwrap();
        let cfgp = d.path().join("config.toml");
        std::fs::write(&cfgp, base(d.path())).unwrap();
        let sub = d.path().join("a/b");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(
            d.path().join("a").join(PROJECT_FILE),
            "[budget]\ndaily_usd = 0.5\n",
        )
        .unwrap();
        let (c, f) = Config::load_with_project(&cfgp, &sub).unwrap();
        assert!(f.is_some());
        assert_eq!(c.budget.daily_usd, 0.5);
    }
}
