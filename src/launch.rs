//! `middleman claude`: Claude Code with Claude as the brain and middleman's provider as the
//! workers.
//!
//! Claude Code keeps its own login and talks to a local proxy (`proxy.rs`): the user's own
//! conversation goes to Claude unchanged, while the subagents and background jobs Claude starts
//! run on the worker provider (miav or OpenRouter). Those worker requests carry whatever files
//! the agents read, uncleaned, which is why a repo must be allowed first (project overlay
//! `[launch] allow = true`, or a stored per-repo choice). The pieces are pure functions so they
//! can be tested without launching anything.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::catalog::{valid_model_id, Catalog};
use crate::config::{Config, ProjectOverlay, Secret, PROJECT_FILE};

pub const DEFAULT_MODEL: &str = "z-ai/glm-5.3";
pub const DEFAULT_FAST_MODEL: &str = "deepseek/deepseek-v4.1-flash";
pub const BASE_URL: &str = "https://openrouter.ai/api";
const ALLOW_FILE: &str = "launch-allowed.json";

/// An Anthropic-compatible worker provider (`[launch] provider`). The key comes from
/// `[providers.<name>]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Upstream {
    pub name: &'static str,
    pub label: &'static str,
    /// Anthropic API root (the proxy appends `/v1/messages`).
    pub base_url: &'static str,
    /// Worker model for subagents.
    pub main: &'static str,
    /// Worker model for background jobs.
    pub fast: &'static str,
    /// Strip Claude-only request features before sending (the provider is not Claude).
    pub adapt: bool,
}

pub const UPSTREAMS: &[Upstream] = &[
    Upstream {
        name: "openrouter",
        label: "OpenRouter",
        base_url: BASE_URL,
        main: DEFAULT_MODEL,
        fast: DEFAULT_FAST_MODEL,
        adapt: true,
    },
    // miav.cloud: a third-party gateway serving Claude-family models (200k context)
    Upstream {
        name: "miav",
        label: "miav",
        base_url: "https://miav.cloud/api/gateway",
        main: "claude-opus-5.5",
        fast: "gpt-6.1-sol",
        adapt: false,
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

/// Worker models (subagents, background): flag, then `[launch]` in the user config, then the default.
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

/// Set in Claude Code's environment by `middleman claude` so the status line (a child of
/// Claude Code) can show the worker model.
pub const SESSION_WORKER_ENV: &str = "MIDDLEMAN_WORKER_MODEL";

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
            "Agents started in {} run on {model}: every file they read is sent to it,",
            root.display()
        ),
        "without middleman's cleaning (your own prompts stay on Claude).".to_string(),
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
    format!(
        "🛡 middleman: Claude is the brain · agents run on {} ({}) · background on {}{credit}",
        p.main, p.upstream.label, p.fast
    )
}

/// `--dry-run` text: what would be set, the root and the allow status. No key is shown: the
/// worker key goes only to the proxy.
pub fn dry_run_text(p: &Plan) -> String {
    let mut out = vec![
        banner(p),
        format!("  agents   {}", with_price(&p.main, &p.main_price)),
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
    for (k, v) in proxy_env("http://127.0.0.1:<port>/<token>", &p.main) {
        out.push(format!("    {k}={v}"));
    }
    out.push(format!(
        "    (your Claude login is kept; the local proxy sends agent requests to {})",
        p.upstream.label
    ));
    if !p.args.is_empty() {
        out.push(format!("  args     {}", p.args.join(" ")));
    }
    out.join("\n")
}

/// What to run; the real run is injected so tests never start `claude`.
pub struct LaunchCmd {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
}

/// Claude Code's environment: it keeps its own login and talks to the local proxy; the
/// background and subagent roles use marker names the proxy sends to the worker provider.
pub fn proxy_env(base_url: &str, worker: &str) -> Vec<(String, String)> {
    let e = |k: &str, v: &str| (k.to_string(), v.to_string());
    vec![
        e("ANTHROPIC_BASE_URL", base_url),
        e("ANTHROPIC_DEFAULT_HAIKU_MODEL", crate::proxy::MARK_FAST),
        e("CLAUDE_CODE_SUBAGENT_MODEL", crate::proxy::MARK_SUB),
        // agents that pin `model: sonnet` in their definition are workers too (the brain
        // runs on Opus or Fable)
        e("ANTHROPIC_DEFAULT_SONNET_MODEL", crate::proxy::MARK_SUB),
        e(SESSION_WORKER_ENV, worker),
    ]
}

/// Appended to Claude's system prompt so the brain knows its agents are free for the user's
/// plan, and hands them the heavy work.
pub fn brain_note(worker: &str, provider: &str) -> String {
    format!(
        "middleman: in this session your subagents (the Agent tool, including custom agents) and \
         background jobs run on a separate worker model ({worker} via {provider}) that does not \
         use the user's Claude plan; only your own turns do. To save the user's Claude limits, \
         hand self-contained work that needs a lot of reading or writing (exploring the \
         codebase, reading long files or logs, implementing a well-specified change, writing \
         tests or boilerplate, producing drafts) to a subagent with a precise brief, and keep \
         yourself to planning, decisions and reviewing results. Ask agents for short summaries, \
         not file dumps. The middleman MCP delegate_task tool is separate and rarely worth it \
         here: prefer subagents."
    )
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
    pub main: &'a str,
    pub fast: &'a str,
    pub key: &'a Secret,
    pub provider: &'a str,
    pub project: &'a str,
    /// Bench run id: marks ledger lines `purpose: bench`.
    pub bench_run: Option<&'a str>,
}

pub fn spawn_proxy(s: &ProxySpec) -> Result<ProxyChild> {
    use std::io::BufRead;
    use std::process::Stdio;
    let token = uuid::Uuid::new_v4().simple().to_string();
    let mut cmd = std::process::Command::new(s.exe);
    cmd.arg("--config").arg(s.cfg_path).arg("proxy").args([
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn env_keeps_login_and_marks_worker_roles() {
        let env = proxy_env("http://127.0.0.1:1/t", "w/model");
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("ANTHROPIC_BASE_URL"), Some("http://127.0.0.1:1/t"));
        assert_eq!(
            get("CLAUDE_CODE_SUBAGENT_MODEL"),
            Some(crate::proxy::MARK_SUB)
        );
        assert_eq!(
            get("ANTHROPIC_DEFAULT_HAIKU_MODEL"),
            Some(crate::proxy::MARK_FAST)
        );
        assert_eq!(get(SESSION_WORKER_ENV), Some("w/model"));
        assert_eq!(
            get("ANTHROPIC_DEFAULT_SONNET_MODEL"),
            Some(crate::proxy::MARK_SUB)
        );
        assert!(brain_note("w/model", "miav").contains("does not use the user's Claude plan"));
        // the main model and the login are Claude Code's own: nothing overrides them
        for k in [
            "ANTHROPIC_AUTH_TOKEN",
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_DEFAULT_OPUS_MODEL",
        ] {
            assert_eq!(get(k), None, "{k}");
        }
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
        assert_eq!(u.base_url, "https://miav.cloud/api/gateway");
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
    fn dry_run_hides_the_key_and_noninteractive_refuses() {
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
            false,
            false,
            vec!["-p".into()],
        )
        .unwrap();
        assert_eq!(p.decision, Decision::Refuse);
        assert_eq!(p.args, vec!["-p"]);
        let t = dry_run_text(&p);
        assert!(
            t.contains("Claude is the brain") && t.contains("mm-cheap-sub"),
            "{t}"
        );
        assert!(t.contains("not allowed"), "{t}");
        assert!(
            !t.contains("SECRET") && !t.contains("AUTH_TOKEN") && !t.contains("OAUTH"),
            "{t}"
        );
        std::env::remove_var("MM_TEST_OR_KEY_LAUNCH");
        assert!(prepare(&c, &repo, Some(d.path()), None, None, true, false, vec![]).is_err());
    }
}
