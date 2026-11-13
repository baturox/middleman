//! `middleman claude`: run a whole Claude Code session on cheap models (OpenRouter or miav).
//!
//! Claude Code talks to OpenRouter directly (`ANTHROPIC_BASE_URL` + token), so nothing here is
//! sanitized: a full session sends every file Claude Code reads to the chosen model. That is why
//! a repo must be allowed first (project overlay `[launch] allow = true`, or a stored per-repo
//! choice). The pieces are pure functions so they can be tested without launching anything.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::catalog::{valid_model_id, Catalog};
use crate::config::{Config, ProjectOverlay, Secret, PROJECT_FILE};
use crate::modes::Mode;

pub const DEFAULT_MODEL: &str = "z-ai/glm-5.3";
pub const DEFAULT_FAST_MODEL: &str = "deepseek/deepseek-v4.1-flash";
pub const BASE_URL: &str = "https://openrouter.ai/api";
const ALLOW_FILE: &str = "launch-allowed.json";

/// An Anthropic-compatible upstream `middleman claude` can run a session on (`[launch]
/// provider`). The key comes from `[providers.<name>]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Upstream {
    pub name: &'static str,
    pub label: &'static str,
    /// Anthropic API root (Claude Code appends `/v1/messages`).
    pub base_url: &'static str,
    pub main: &'static str,
    pub fast: &'static str,
    /// Strip Claude-only request features before sending (the upstream is not Claude).
    pub adapt: bool,
    /// Extra child environment for direct (cheap) sessions.
    pub extra_env: &'static [(&'static str, &'static str)],
}

pub const UPSTREAMS: &[Upstream] = &[
    Upstream {
        name: "openrouter",
        label: "OpenRouter",
        base_url: BASE_URL,
        main: DEFAULT_MODEL,
        fast: DEFAULT_FAST_MODEL,
        adapt: true,
        extra_env: &[],
    },
    // miav.cloud: a third-party gateway serving Claude-family models (200k context)
    Upstream {
        name: "miav",
        label: "miav",
        base_url: "https://miav.cloud/api/gateway",
        main: "claude-opus-5.5",
        fast: "gpt-6.1-sol",
        adapt: false,
        extra_env: &[("CLAUDE_CODE_AUTO_COMPACT_WINDOW", "200000")],
    },
];

/// `[launch] provider` (default openrouter).
pub fn upstream(cfg: &Config) -> Result<&'static Upstream> {
    let name = cfg.launch.provider.as_deref().unwrap_or("openrouter");
    upstream_named(name)
}

pub fn upstream_named(name: &str) -> Result<&'static Upstream> {
    UPSTREAMS.iter().find(|u| u.name == name).with_context(|| {
        let known: Vec<_> = UPSTREAMS.iter().map(|u| u.name).collect();
        format!(
            "unknown [launch] provider `{name}` (known: {})",
            known.join(", ")
        )
    })
}

/// The upstream's key from `[providers.<name>]`.
pub fn upstream_key(cfg: &Config, u: &Upstream) -> Result<Secret> {
    let hint = || {
        anyhow::anyhow!(
            "no {} key: run `middleman provider add {}`",
            u.label,
            u.name
        )
    };
    cfg.providers
        .get(u.name)
        .ok_or_else(hint)?
        .resolve_key()
        .map_err(|_| hint())
}

/// Main and fast model: flag, then `[launch]` in the user config, then the default.
pub fn resolve_models(
    cli_model: Option<&str>,
    cli_fast: Option<&str>,
    cfg: &Config,
) -> Result<(String, String)> {
    let pick = |cli: Option<&str>, conf: &Option<String>, def: &str| {
        cli.map(str::to_string)
            .or_else(|| conf.clone())
            .unwrap_or_else(|| def.to_string())
    };
    let u = upstream(cfg)?;
    let main = pick(cli_model, &cfg.launch.model, u.main);
    let fast = pick(cli_fast, &cfg.launch.fast_model, u.fast);
    for (what, id) in [("model", &main), ("fast model", &fast)] {
        if !valid_model_id(id) {
            bail!("invalid {what} id (allowed: letters, digits and . _ : / @ + -)");
        }
    }
    Ok((main, fast))
}

/// Environment for the child only. Opus/Sonnet/Fable/subagents use the main model, Haiku the fast one.
pub fn build_env(u: &Upstream, key: &str, main: &str, fast: &str) -> Vec<(String, String)> {
    let e = |k: &str, v: &str| (k.to_string(), v.to_string());
    let mut v = vec![
        e("ANTHROPIC_BASE_URL", u.base_url),
        e("ANTHROPIC_AUTH_TOKEN", key),
        e("ANTHROPIC_API_KEY", ""),
        e("ANTHROPIC_DEFAULT_OPUS_MODEL", main),
        e("ANTHROPIC_DEFAULT_SONNET_MODEL", main),
        e("ANTHROPIC_DEFAULT_FABLE_MODEL", main),
        e("CLAUDE_CODE_SUBAGENT_MODEL", main),
        e("ANTHROPIC_DEFAULT_HAIKU_MODEL", fast),
    ];
    v.extend(u.extra_env.iter().map(|(k, x)| e(k, x)));
    v
}

/// Variables removed from the child so the subscription login is not used.
pub const REMOVE_ENV: &[&str] = &["CLAUDE_CODE_OAUTH_TOKEN"];

/// Git root of `cwd` (nearest ancestor with `.git`), else `cwd`. Refuses `$HOME` and `/`.
pub fn project_root(cwd: &Path, home: Option<&Path>) -> Result<PathBuf> {
    let cwd = std::fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    let home = home.map(|h| std::fs::canonicalize(h).unwrap_or_else(|_| h.to_path_buf()));
    let too_broad = |p: &Path| p.parent().is_none() || home.as_deref() == Some(p);
    if too_broad(&cwd) {
        bail!("refusing to run in your home directory or `/`: cd into a project first");
    }
    let root = cwd
        .ancestors()
        .find(|a| a.join(".git").exists())
        .unwrap_or(&cwd)
        .to_path_buf();
    if too_broad(&root) {
        bail!("refusing to run in your home directory or `/`: cd into a project first");
    }
    Ok(root)
}

/// `[launch] allow = true` in the nearest `.middleman.toml` at or above `cwd`.
pub fn overlay_allows(cwd: &Path) -> bool {
    for d in cwd.ancestors() {
        let f = d.join(PROJECT_FILE);
        if f.is_file() {
            return std::fs::read_to_string(&f)
                .ok()
                .and_then(|t| toml::from_str::<ProjectOverlay>(&t).ok())
                .and_then(|o| o.launch)
                .is_some_and(|l| l.allow);
        }
    }
    false
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Allowed {
    roots: Vec<String>,
}

fn load_allowed(state_dir: &Path) -> Allowed {
    std::fs::read_to_string(state_dir.join(ALLOW_FILE))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

pub fn stored_allows(state_dir: &Path, root: &Path) -> bool {
    let r = root.to_string_lossy();
    load_allowed(state_dir).roots.iter().any(|x| *x == r)
}

/// Remember "Always for this repo" (file 0600, keyed by canonical root path).
pub fn store_allow(state_dir: &Path, root: &Path) -> Result<()> {
    let mut a = load_allowed(state_dir);
    let r = root.to_string_lossy().to_string();
    if !a.roots.contains(&r) {
        a.roots.push(r);
    }
    crate::ledger::ensure_private_dir(state_dir)?;
    crate::fsutil::write_atomic(
        &state_dir.join(ALLOW_FILE),
        serde_json::to_string_pretty(&a)?.as_bytes(),
        Some(0o600),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Allowed without asking (the reason is shown by `--dry-run`).
    Allowed(&'static str),
    /// Interactive terminal: ask Allow once / Always / Cancel.
    Ask,
    /// Non-interactive and not allowed.
    Refuse,
}

pub fn decide(
    root: &Path,
    overlay_allow: bool,
    state_dir: &Path,
    yes: bool,
    interactive: bool,
) -> Decision {
    if overlay_allow {
        Decision::Allowed("allowed by .middleman.toml [launch] allow")
    } else if stored_allows(state_dir, root) {
        Decision::Allowed("allowed earlier for this repo")
    } else if yes {
        Decision::Allowed("allowed once (--yes)")
    } else if interactive {
        Decision::Ask
    } else {
        Decision::Refuse
    }
}

pub fn warning(root: &Path, model: &str) -> [String; 3] {
    [
        format!(
            "This sends every file Claude Code reads in {} to {model} on OpenRouter,",
            root.display()
        ),
        "without middleman's cleaning.".to_string(),
        "Only do this for code you'd be fine publishing.".to_string(),
    ]
}

pub fn refusal(root: &Path) -> String {
    format!(
        "not allowed for {}: re-run with --yes (once), or put `allow = true` under `[launch]` in \
         .middleman.toml, or run it in a terminal to choose",
        root.display()
    )
}

pub struct Plan {
    pub mode: Mode,
    pub upstream: &'static Upstream,
    pub key: Secret,
    pub main: String,
    pub fast: String,
    pub root: PathBuf,
    pub main_price: Option<String>,
    pub fast_price: Option<String>,
    pub credit_usd: Option<f64>,
    pub decision: Decision,
    pub args: Vec<String>,
}

fn price_text(cfg: &Config, cat: Option<&Catalog>, provider: &str, id: &str) -> Option<String> {
    let p = Catalog::lookup(cfg, cat, provider, id)?.prices?;
    Some(format!(
        "(${:.2} / ${:.2} per 1M)",
        p.in_per_1m, p.out_per_1m
    ))
}

/// Everything except the prompt and the exec.
#[allow(clippy::too_many_arguments)]
pub fn prepare(
    cfg: &Config,
    cwd: &Path,
    home: Option<&Path>,
    model: Option<&str>,
    fast_model: Option<&str>,
    mode: Mode,
    yes: bool,
    interactive: bool,
    args: Vec<String>,
) -> Result<Plan> {
    let u = upstream(cfg)?;
    let key = upstream_key(cfg, u)?;
    let (main, fast) = resolve_models(model, fast_model, cfg)?;
    let root = project_root(cwd, home)?;
    let state = cfg.state_dir();
    let cat = Catalog::load(cfg);
    let credit_usd = crate::limits::load(&state)
        .and_then(|c| c.providers.get(u.name).and_then(|p| p.left_usd()));
    let decision = decide(&root, overlay_allows(cwd), &state, yes, interactive);
    Ok(Plan {
        mode,
        upstream: u,
        main_price: price_text(cfg, cat.as_ref(), u.name, &main),
        fast_price: price_text(cfg, cat.as_ref(), u.name, &fast),
        key,
        main,
        fast,
        root,
        credit_usd,
        decision,
        args,
    })
}

fn with_price(id: &str, price: &Option<String>) -> String {
    match price {
        Some(p) => format!("{id} {p}"),
        None => id.to_string(),
    }
}

/// The one line printed before launching.
pub fn banner(p: &Plan) -> String {
    let credit = p
        .credit_usd
        .map(|c| format!(" · credit ${c:.2}"))
        .unwrap_or_default();
    if p.mode == Mode::Smart {
        return format!(
            "🛡 middleman: smart mode · hard prompts on Claude, routine ones on {} · fast {}{credit}",
            p.main, p.fast
        );
    }
    format!(
        "🛡 middleman: Claude Code on {} · main {} · fast {}{credit} · your Claude plan is not used",
        p.upstream.label, p.main, p.fast
    )
}

pub const MASKED_KEY: &str = "…(hidden)";

/// `--dry-run` text: what would be set (key masked), the root and the allow status.
pub fn dry_run_text(p: &Plan) -> String {
    let mut out = vec![
        banner(p),
        format!("  mode     {}", p.mode),
        format!("  main     {}", with_price(&p.main, &p.main_price)),
        format!("  fast     {}", with_price(&p.fast, &p.fast_price)),
        format!("  root     {}", p.root.display()),
        format!(
            "  allow    {}",
            match p.decision {
                Decision::Allowed(why) => why.to_string(),
                Decision::Ask => "would ask (Allow once / Always / Cancel)".to_string(),
                Decision::Refuse => "not allowed (non-interactive)".to_string(),
            }
        ),
        "  env (child only):".to_string(),
    ];
    if p.mode == Mode::Smart {
        for (k, v) in proxy_env("http://127.0.0.1:<port>/<token>") {
            out.push(format!("    {k}={v}"));
        }
        out.push(format!(
            "    (your Claude login is kept; the local proxy sends routine turns to {})",
            p.upstream.label
        ));
    } else {
        for (k, v) in build_env(p.upstream, MASKED_KEY, &p.main, &p.fast) {
            let v = if k == "ANTHROPIC_API_KEY" {
                "\"\"".into()
            } else {
                v
            };
            out.push(format!("    {k}={v}"));
        }
        for k in REMOVE_ENV {
            out.push(format!("    unset {k}"));
        }
    }
    if !p.args.is_empty() {
        out.push(format!("  args     {}", p.args.join(" ")));
    }
    out.join("\n")
}

/// What to run; the real exec is injected so tests never start `claude`.
pub struct LaunchCmd {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub remove: Vec<String>,
}

pub fn command(program: PathBuf, p: &Plan) -> LaunchCmd {
    LaunchCmd {
        program,
        args: p.args.clone(),
        env: build_env(p.upstream, p.key.expose(), &p.main, &p.fast),
        remove: REMOVE_ENV.iter().map(|s| s.to_string()).collect(),
    }
}

/// Environment for the proxy modes: Claude Code keeps its own login and talks to the local
/// proxy; the background and subagent roles use marker names the proxy maps to cheap models.
pub fn proxy_env(base_url: &str) -> Vec<(String, String)> {
    let e = |k: &str, v: &str| (k.to_string(), v.to_string());
    vec![
        e("ANTHROPIC_BASE_URL", base_url),
        e("ANTHROPIC_DEFAULT_HAIKU_MODEL", crate::proxy::MARK_FAST),
        e("CLAUDE_CODE_SUBAGENT_MODEL", crate::proxy::MARK_SUB),
    ]
}

/// The local proxy as a child process. It exits when this handle is dropped (its stdin closes).
pub struct ProxyChild {
    child: std::process::Child,
    _stdin: Option<std::process::ChildStdin>,
    pub base_url: String,
}

impl Drop for ProxyChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub struct ProxySpec<'a> {
    pub exe: &'a Path,
    pub cfg_path: &'a Path,
    pub mode: Mode,
    pub main: &'a str,
    pub fast: &'a str,
    pub key: &'a Secret,
    pub provider: &'a str,
    pub project: &'a str,
    /// Bench run id: marks ledger lines `purpose: bench` and pins the mode.
    pub bench_run: Option<&'a str>,
}

pub fn spawn_proxy(s: &ProxySpec) -> Result<ProxyChild> {
    use std::io::BufRead;
    use std::process::Stdio;
    let token = uuid::Uuid::new_v4().simple().to_string();
    let mut cmd = std::process::Command::new(s.exe);
    cmd.arg("--config")
        .arg(s.cfg_path)
        .args(["proxy", "--mode"])
        .arg(s.mode.to_string())
        .args([
            "--model",
            s.main,
            "--fast-model",
            s.fast,
            "--project",
            s.project,
            "--provider",
            s.provider,
        ]);
    if let Some(r) = s.bench_run {
        cmd.args(["--bench-run", r]);
    }
    let mut child = cmd
        .env("MM_PROXY_TOKEN", &token)
        .env("MM_PROXY_KEY", s.key.expose())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .context("cannot start the middleman proxy")?;
    let stdin = child.stdin.take();
    let out = child.stdout.take().context("no proxy output")?;
    let mut line = String::new();
    std::io::BufReader::new(out).read_line(&mut line)?;
    let Ok(port) = line.trim().parse::<u16>() else {
        let _ = child.kill();
        bail!("the middleman proxy did not start");
    };
    Ok(ProxyChild {
        child,
        _stdin: stdin,
        base_url: format!("http://127.0.0.1:{port}/{token}"),
    })
}

/// Run the command as a child (the proxy must outlive nothing: it is stopped on return) and
/// relay its exit code.
pub fn run_with_proxy(c: &LaunchCmd, proxy: ProxyChild) -> Result<ExitCode> {
    let mut cmd = std::process::Command::new(&c.program);
    cmd.args(&c.args);
    for k in &c.remove {
        cmd.env_remove(k);
    }
    cmd.envs(c.env.iter().map(|(k, v)| (k, v)));
    let st = cmd.status().context("cannot start claude")?;
    drop(proxy);
    Ok(ExitCode::from(st.code().unwrap_or(1).clamp(0, 255) as u8))
}

/// Find `name` in a PATH-style value.
pub fn find_on_path(name: &str, path: &OsStr) -> Option<PathBuf> {
    std::env::split_paths(path)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

/// Replace this process with the command (unix), or run it and relay its exit code.
pub fn exec(c: &LaunchCmd) -> Result<ExitCode> {
    let mut cmd = std::process::Command::new(&c.program);
    cmd.args(&c.args);
    for k in &c.remove {
        cmd.env_remove(k);
    }
    cmd.envs(c.env.iter().map(|(k, v)| (k, v)));
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let e = cmd.exec();
        Err(anyhow::anyhow!("cannot start claude: {e}"))
    }
    #[cfg(not(unix))]
    {
        let st = cmd.status().context("cannot start claude")?;
        Ok(ExitCode::from(st.code().unwrap_or(1).clamp(0, 255) as u8))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    trait TapKey {
        fn tap_key(self, var: &str) -> Self;
    }
    impl TapKey for Config {
        fn tap_key(mut self, var: &str) -> Self {
            self.providers.get_mut("openrouter").unwrap().key_env = Some(var.into());
            self
        }
    }

    fn cfg(dir: &Path, extra: &str) -> Config {
        Config::from_toml(&format!(
            r#"
state_dir = "{d}/state"
cache_dir = "{d}/cache"
[paths]
roots = ["{d}"]
[providers.openrouter]
preset = "openrouter"
key_env = "MM_TEST_OR_KEY_LAUNCH"
{extra}
"#,
            d = dir.display()
        ))
        .unwrap()
    }

    #[test]
    fn env_has_all_roles() {
        let env = build_env(&UPSTREAMS[0], "k", "m/main", "f/fast");
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("ANTHROPIC_BASE_URL"), Some(BASE_URL));
        assert_eq!(get("ANTHROPIC_AUTH_TOKEN"), Some("k"));
        assert_eq!(get("ANTHROPIC_API_KEY"), Some(""));
        for r in ["OPUS", "SONNET", "FABLE"] {
            assert_eq!(get(&format!("ANTHROPIC_DEFAULT_{r}_MODEL")), Some("m/main"));
        }
        assert_eq!(get("CLAUDE_CODE_SUBAGENT_MODEL"), Some("m/main"));
        assert_eq!(get("ANTHROPIC_DEFAULT_HAIKU_MODEL"), Some("f/fast"));
        assert!(REMOVE_ENV.contains(&"CLAUDE_CODE_OAUTH_TOKEN"));
    }

    #[test]
    fn model_defaults_and_overrides() {
        let d = tempfile::tempdir().unwrap();
        let c = cfg(d.path(), "");
        assert_eq!(
            resolve_models(None, None, &c).unwrap(),
            (DEFAULT_MODEL.into(), DEFAULT_FAST_MODEL.into())
        );
        let d2 = tempfile::tempdir().unwrap();
        let mut c2 = cfg(d2.path(), "");
        c2.launch.model = Some("a/conf".into());
        c2.launch.fast_model = Some("b/conf".into());
        assert_eq!(
            resolve_models(Some("x/cli"), None, &c2).unwrap(),
            ("x/cli".into(), "b/conf".into())
        );
        assert!(resolve_models(Some("bad id</x>"), None, &c).is_err());
    }

    #[test]
    fn miav_upstream_defaults_env_and_key() {
        let d = tempfile::tempdir().unwrap();
        let c = cfg(
            d.path(),
            "[providers.miav]\npreset = \"miav\"\nkey_env = \"MM_TEST_MIAV_KEY_LAUNCH\"\n[launch]\nprovider = \"miav\"\n",
        );
        let u = upstream(&c).unwrap();
        assert_eq!(u.name, "miav");
        assert!(
            !u.adapt,
            "miav serves Claude models: send requests unchanged"
        );
        assert_eq!(
            resolve_models(None, None, &c).unwrap(),
            ("claude-opus-5.5".into(), "gpt-6.1-sol".into())
        );
        let env = build_env(u, "k", "m", "f");
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(
            get("ANTHROPIC_BASE_URL"),
            Some("https://miav.cloud/api/gateway")
        );
        assert_eq!(get("CLAUDE_CODE_AUTO_COMPACT_WINDOW"), Some("200000"));
        assert!(upstream_key(&c, u)
            .unwrap_err()
            .to_string()
            .contains("provider add miav"));
        std::env::set_var("MM_TEST_MIAV_KEY_LAUNCH", "miav-test-key");
        assert_eq!(upstream_key(&c, u).unwrap().expose(), "miav-test-key");
        std::env::remove_var("MM_TEST_MIAV_KEY_LAUNCH");
        // the default stays OpenRouter, and an unknown name is a clear error
        let d2 = tempfile::tempdir().unwrap();
        assert_eq!(upstream(&cfg(d2.path(), "")).unwrap().name, "openrouter");
        assert!(upstream_named("nope")
            .unwrap_err()
            .to_string()
            .contains("miav"));
        assert!(crate::providers::presets::find("miav").is_some());
    }

    #[test]
    fn allow_logic() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("repo");
        std::fs::create_dir_all(root.join(".git")).unwrap();
        let state = d.path().join("state");
        assert_eq!(decide(&root, false, &state, false, false), Decision::Refuse);
        assert_eq!(decide(&root, false, &state, false, true), Decision::Ask);
        assert!(matches!(
            decide(&root, true, &state, false, false),
            Decision::Allowed(_)
        ));
        assert!(matches!(
            decide(&root, false, &state, true, false),
            Decision::Allowed(_)
        ));
        store_allow(&state, &root).unwrap();
        assert!(matches!(
            decide(&root, false, &state, false, false),
            Decision::Allowed(_)
        ));
        assert_eq!(
            decide(&d.path().join("other"), false, &state, false, false),
            Decision::Refuse
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(state.join(ALLOW_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(m & 0o777, 0o600);
        }
        // overlay file
        std::fs::write(root.join(PROJECT_FILE), "[launch]\nallow = true\n").unwrap();
        assert!(overlay_allows(&root));
        std::fs::write(root.join(PROJECT_FILE), "label = \"x\"\n").unwrap();
        assert!(!overlay_allows(&root));
    }

    #[test]
    fn refuses_home_and_root_finds_git_root() {
        let d = tempfile::tempdir().unwrap();
        let home = d.path().join("home");
        let repo = home.join("repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::create_dir_all(repo.join("sub")).unwrap();
        assert!(project_root(&home, Some(&home)).is_err());
        assert!(project_root(Path::new("/"), Some(&home)).is_err());
        assert_eq!(
            project_root(&repo.join("sub"), Some(&home)).unwrap(),
            std::fs::canonicalize(&repo).unwrap()
        );
    }

    #[test]
    fn dry_run_masks_key_and_noninteractive_refuses() {
        let d = tempfile::tempdir().unwrap();
        let repo = d.path().join("repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::env::set_var("MM_TEST_OR_KEY_LAUNCH", "sk-or-v1-SECRETSECRET");
        let c = cfg(d.path(), "");
        let p = prepare(
            &c,
            &repo,
            Some(d.path()),
            None,
            None,
            Mode::Cheap,
            false,
            false,
            vec!["-p".into()],
        )
        .unwrap();
        assert_eq!(p.decision, Decision::Refuse);
        let t = dry_run_text(&p);
        assert!(t.contains("…(hidden)"));
        assert!(!t.contains("SECRETSECRET"));
        assert!(t.contains("ANTHROPIC_API_KEY=\"\""));
        assert!(t.contains("unset CLAUDE_CODE_OAUTH_TOKEN"));
        assert!(t.contains("not allowed"));
        let cmd = command(PathBuf::from("claude"), &p);
        assert!(cmd.env.iter().any(|(_, v)| v == "sk-or-v1-SECRETSECRET"));
        assert_eq!(cmd.args, vec!["-p"]);
        std::env::remove_var("MM_TEST_OR_KEY_LAUNCH");
        assert!(prepare(
            &c,
            &repo,
            Some(d.path()),
            None,
            None,
            Mode::Cheap,
            true,
            false,
            vec![]
        )
        .is_err());
    }

    #[test]
    fn smart_dry_run_keeps_login_and_hides_nothing_secret() {
        let d = tempfile::tempdir().unwrap();
        let repo = d.path().join("repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::env::set_var("MM_TEST_OR_KEY_SMART", "sk-or-v1-SECRETSECRET");
        let c = cfg(d.path(), "").tap_key("MM_TEST_OR_KEY_SMART");
        let p = prepare(
            &c,
            &repo,
            Some(d.path()),
            None,
            None,
            Mode::Smart,
            true,
            false,
            vec![],
        )
        .unwrap();
        let t = dry_run_text(&p);
        assert!(
            t.contains("mm-cheap-fast") && t.contains("mode     smart"),
            "{t}"
        );
        assert!(
            !t.contains("AUTH_TOKEN") && !t.contains("OAUTH") && !t.contains("SECRET"),
            "{t}"
        );
    }
}
