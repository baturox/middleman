//! `middleman bench`: run the same small tasks through each mode with headless Claude Code and
//! compare cost and pass rate. This module holds the tasks, the checks and the maths; the
//! process handling is in `run_task`, and the CLI glue prints the result.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ledger::LedgerEntry;

/// Planning figures for the cost guard (upper bounds per task, USD).
pub const CLAUDE_MAX_PER_TASK: f64 = 1.50;
pub const CHEAP_MAX_PER_TASK: f64 = 0.10;
pub const MAX_TURNS: u32 = 25;
pub const TASK_TIMEOUT: Duration = Duration::from_secs(360);
pub const ALLOWED_TOOLS: &str = "Read Edit Write Glob Grep Bash(python3:*) Agent Task";
/// Put before every task prompt so the work runs the way `middleman claude` is meant to be
/// used: Claude plans and checks, a subagent (on the worker provider) does the work.
pub const DELEGATE_PREFIX: &str = "Use a subagent (the Agent tool) to do the actual work below, then check its result yourself.\n\n";

macro_rules! fx {
    ($p:literal) => {
        ($p, include_str!(concat!("../bench/fixtures/sample/", $p)))
    };
}

/// The sample project, embedded in the binary.
pub const FIXTURE: &[(&str, &str)] = &[
    fx!("textkit/__init__.py"),
    fx!("textkit/words.py"),
    fx!("textkit/slug.py"),
    fx!("textkit/stats.py"),
    fx!("textkit/cache.py"),
    fx!("textkit/report.py"),
    fx!("textkit/__main__.py"),
    fx!("tests/__init__.py"),
    fx!("tests/test_stats.py"),
    fx!("tests/test_words.py"),
    fx!("tests/test_report.py"),
    fx!("tests/test_cache.py"),
];

pub struct Task {
    pub id: &'static str,
    pub prompt: &'static str,
    /// `python3 -m unittest <targets>` (empty: everything)
    pub unittest: &'static [&'static str],
    /// Run with `python3 -c`; must exit 0.
    pub assertion: &'static str,
    /// Files the agent must not change.
    pub protected: &'static [&'static str],
}

/// Easiest first.
pub const TASKS: &[Task] = &[
    Task {
        id: "write-tests",
        prompt: "Write unit tests for textkit/slug.py in tests/test_slug.py using unittest, covering at least 5 cases. Do not change textkit/slug.py. Run them to check they pass.",
        unittest: &["tests.test_slug"],
        assertion: "import re;t=open('tests/test_slug.py').read();assert len(re.findall(r'def test_',t))>=5;assert 'slugify' in t",
        protected: &["textkit/slug.py"],
    },
    Task {
        id: "docstrings",
        prompt: "Add a one-line docstring to every function in textkit/words.py. Do not change any behaviour.",
        unittest: &["tests.test_words", "tests.test_report"],
        assertion: "import ast;t=ast.parse(open('textkit/words.py').read());f=[n for n in ast.walk(t) if isinstance(n,ast.FunctionDef)];assert len(f)>=4 and all(ast.get_docstring(n) for n in f)",
        protected: &["tests/test_words.py"],
    },
    Task {
        id: "fix-off-by-one",
        prompt: "tests/test_stats.py fails. Find and fix the bug in textkit/stats.py. Do not edit the tests.",
        unittest: &[],
        assertion: "from textkit.stats import moving_average as m;assert m([1,2,3,4],2)==[1.5,2.5,3.5];assert m([1,2],2)==[1.5];assert m([1],2)==[]",
        protected: &["tests/test_stats.py"],
    },
    Task {
        id: "add-function",
        prompt: "Add a function longest_word(text) to textkit/words.py: it returns the longest word in text (the first one on ties) and '' when there are no words. Add tests for it to tests/test_words.py.",
        unittest: &["tests.test_words"],
        assertion: "import re;from textkit.words import longest_word as l;assert l('a bb ccc dd')=='ccc';assert l('aa bb')=='aa';assert l('')=='';assert 'longest_word' in open('tests/test_words.py').read()",
        protected: &[],
    },
    Task {
        id: "rename-across-files",
        prompt: "Rename the function format_line to render_line everywhere it is used (it is defined in textkit/report.py and also used in textkit/__main__.py). Keep behaviour the same.",
        unittest: &["tests.test_report", "tests.test_cache", "tests.test_words"],
        assertion: "import pathlib;s=''.join(p.read_text() for p in pathlib.Path('.').rglob('*.py'));assert 'format_line' not in s;from textkit.report import render_line;assert render_line('a',1).startswith('a')",
        protected: &["tests/test_report.py"],
    },
];

pub fn copy_fixture(dst: &Path) -> Result<()> {
    for (rel, text) in FIXTURE {
        let p = dst.join(rel);
        std::fs::create_dir_all(p.parent().context("bad fixture path")?)?;
        std::fs::write(&p, text)?;
    }
    Ok(())
}

/// Did the task's checks pass in `dir`? Returns a short reason when not.
pub fn check_task(dir: &Path, t: &Task) -> Result<(), String> {
    for p in t.protected {
        let orig = FIXTURE.iter().find(|(r, _)| r == p).map(|(_, c)| *c);
        if std::fs::read_to_string(dir.join(p)).ok().as_deref() != orig {
            return Err(format!("{p} was changed"));
        }
    }
    let py = |args: Vec<&str>| {
        std::process::Command::new("python3")
            .args(args)
            .current_dir(dir)
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .stdin(Stdio::null())
            .output()
    };
    let mut ut = vec!["-m", "unittest"];
    ut.extend(t.unittest.iter().copied());
    match py(ut) {
        Ok(o) if o.status.success() => {}
        _ => return Err("unittest failed".into()),
    }
    match py(vec!["-c", t.assertion]) {
        Ok(o) if o.status.success() => Ok(()),
        _ => Err("task assertion failed".into()),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskResult {
    pub mode: String,
    pub task: String,
    pub passed: bool,
    pub reason: String,
    pub secs: f64,
    pub claude_usd: f64,
    pub cheap_usd: f64,
    pub claude_turns: u64,
    pub cheap_turns: u64,
}

/// (total_cost_usd, num_turns) from `claude -p --output-format json`.
pub fn parse_claude_json(out: &str) -> (f64, u64) {
    let v: Value = serde_json::from_str(out.trim()).unwrap_or(Value::Null);
    (
        v["total_cost_usd"].as_f64().unwrap_or(0.0),
        v["num_turns"].as_u64().unwrap_or(0),
    )
}

/// Split one run into Claude and worker spend. `total` is Claude Code's own cost figure, which
/// prices every request as a Claude request; only the Claude share of the tokens (from the
/// proxy's ledger lines) is attributed to Claude, and the worker side is what the provider
/// billed. (claude_usd, worker_usd, claude_requests, worker_requests)
pub fn split_cost(total: f64, run: &[LedgerEntry]) -> (f64, f64, u64, u64) {
    let toks = |e: &LedgerEntry| e.input_tokens.unwrap_or(0) + e.output_tokens.unwrap_or(0);
    let (mut ct, mut at, mut cn, mut an, mut cheap_usd) = (0u64, 0u64, 0u64, 0u64, 0.0);
    for e in run {
        if matches!(e.chain_step.as_str(), "worker" | "cheap") {
            ct += toks(e);
            cn += 1;
            cheap_usd += e.cost_usd;
        } else {
            at += toks(e);
            an += 1;
        }
    }
    let all = ct + at;
    let claude = if all == 0 {
        0.0
    } else {
        total * at as f64 / all as f64
    };
    (claude, cheap_usd, an, cn)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModeSummary {
    pub mode: String,
    pub passed: usize,
    pub tasks: usize,
    pub total_usd: f64,
    pub per_passed_usd: Option<f64>,
    pub secs: f64,
    pub claude_turns: u64,
}

pub fn summarize(results: &[TaskResult]) -> Vec<ModeSummary> {
    let mut modes: Vec<&str> = vec![];
    for r in results {
        if !modes.contains(&r.mode.as_str()) {
            modes.push(&r.mode);
        }
    }
    modes
        .into_iter()
        .map(|m| {
            let rs: Vec<_> = results.iter().filter(|r| r.mode == m).collect();
            let passed = rs.iter().filter(|r| r.passed).count();
            let total: f64 = rs.iter().map(|r| r.claude_usd + r.cheap_usd).sum();
            ModeSummary {
                mode: m.to_string(),
                passed,
                tasks: rs.len(),
                total_usd: total,
                per_passed_usd: (passed > 0).then(|| total / passed as f64),
                secs: rs.iter().map(|r| r.secs).sum(),
                claude_turns: rs.iter().map(|r| r.claude_turns).sum(),
            }
        })
        .collect()
}

pub fn table(s: &[ModeSummary]) -> String {
    let mut out = format!(
        "{:<8} {:>7} {:>10} {:>12} {:>8} {:>13}\n",
        "mode", "passed", "total", "per passed", "time", "claude turns"
    );
    for m in s {
        out.push_str(&format!(
            "{:<8} {:>7} {:>10} {:>12} {:>7.0}s {:>13}\n",
            m.mode,
            format!("{}/{}", m.passed, m.tasks),
            format!("${:.2}", m.total_usd),
            m.per_passed_usd.map_or("-".into(), |c| format!("${c:.2}")),
            m.secs,
            m.claude_turns
        ));
    }
    out
}

/// One plain sentence per non-claude mode, compared with the claude mode when it was run.
pub fn verdict(s: &[ModeSummary]) -> String {
    let base = s.iter().find(|m| m.mode == "claude");
    let lines: Vec<String> = s
        .iter()
        .filter(|m| m.mode != "claude")
        .map(|m| match base {
            Some(b) if b.total_usd > 0.0 => format!(
                "{} passed {}/{} at {:.0}% of claude's cost (claude passed {}/{})",
                m.mode,
                m.passed,
                m.tasks,
                100.0 * m.total_usd / b.total_usd,
                b.passed,
                b.tasks
            ),
            _ => format!(
                "{} passed {}/{} for ${:.2}",
                m.mode, m.passed, m.tasks, m.total_usd
            ),
        })
        .collect();
    if lines.is_empty() {
        "no mode to compare".into()
    } else {
        lines.join("\n")
    }
}

pub struct Estimate {
    pub claude_requests: u64,
    pub max_usd: f64,
}

/// Worst case before running: every request of every task on Claude, plus the workers.
pub fn estimate(tasks: usize) -> Estimate {
    Estimate {
        claude_requests: tasks as u64 * MAX_TURNS as u64,
        max_usd: tasks as f64 * (CLAUDE_MAX_PER_TASK + CHEAP_MAX_PER_TASK),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Guard {
    Go,
    Ask,
    Refuse,
}

pub fn guard(yes: bool, interactive: bool) -> Guard {
    if yes {
        Guard::Go
    } else if interactive {
        Guard::Ask
    } else {
        Guard::Refuse
    }
}

/// Run `claude -p` headless in `dir` with `env`; (stdout, seconds). Killed after the timeout.
pub async fn run_claude(
    claude: &Path,
    dir: &Path,
    prompt: &str,
    env: &[(String, String)],
    timeout: Duration,
) -> Result<(String, f64)> {
    let t0 = Instant::now();
    let child = tokio::process::Command::new(claude)
        .args(["-p", prompt, "--output-format", "json", "--max-turns"])
        .arg(MAX_TURNS.to_string())
        .args([
            "--permission-mode",
            "acceptEdits",
            "--allowedTools",
            ALLOWED_TOOLS,
        ])
        .current_dir(dir)
        .envs(env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("cannot start claude")?;
    match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(o) => Ok((
            String::from_utf8_lossy(&o?.stdout).into_owned(),
            t0.elapsed().as_secs_f64(),
        )),
        Err(_) => bail!("timed out"),
    }
}

pub fn results_path(state: &Path, ts: i64) -> PathBuf {
    state.join(format!("bench-{ts}.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(mode: &str, passed: bool, claude: f64, cheap: f64) -> TaskResult {
        TaskResult {
            mode: mode.into(),
            task: "t".into(),
            passed,
            reason: String::new(),
            secs: 10.0,
            claude_usd: claude,
            cheap_usd: cheap,
            claude_turns: 2,
            cheap_turns: 3,
        }
    }

    #[test]
    fn fixture_has_planted_bug_and_tasks_fail_before_work() {
        let d = tempfile::tempdir().unwrap();
        copy_fixture(d.path()).unwrap();
        assert!(d.path().join("textkit/report.py").is_file());
        if std::process::Command::new("python3")
            .arg("--version")
            .output()
            .is_ok()
        {
            for t in TASKS {
                assert!(
                    check_task(d.path(), t).is_err(),
                    "{} passes untouched",
                    t.id
                );
            }
        }
    }

    #[test]
    fn protected_files_are_enforced() {
        let d = tempfile::tempdir().unwrap();
        copy_fixture(d.path()).unwrap();
        std::fs::write(d.path().join("tests/test_stats.py"), "x").unwrap();
        let t = TASKS.iter().find(|t| t.id == "fix-off-by-one").unwrap();
        assert_eq!(
            check_task(d.path(), t),
            Err("tests/test_stats.py was changed".into())
        );
    }

    #[test]
    fn summary_maths_and_verdict() {
        let rs = vec![
            r("claude", true, 1.0, 0.0),
            r("claude", true, 1.0, 0.0),
            r("middleman", true, 0.3, 0.1),
            r("middleman", false, 0.1, 0.0),
        ];
        let s = summarize(&rs);
        assert_eq!((s[0].passed, s[0].tasks), (2, 2));
        assert!((s[0].total_usd - 2.0).abs() < 1e-9);
        assert!((s[0].per_passed_usd.unwrap() - 1.0).abs() < 1e-9);
        assert_eq!((s[1].passed, s[1].tasks), (1, 2));
        assert!((s[1].total_usd - 0.5).abs() < 1e-9);
        let v = verdict(&s);
        assert!(
            v.contains("middleman passed 1/2 at 25% of claude's cost"),
            "{v}"
        );
        assert!(table(&s).contains("1/2"));
        assert_eq!(
            verdict(&summarize(&rs[2..3])),
            "middleman passed 1/1 for $0.40"
        );
    }

    #[test]
    fn cost_split_uses_ledger_shares() {
        let e = |step: &str, tok: u64, cost: f64| LedgerEntry {
            chain_step: step.into(),
            input_tokens: Some(tok),
            output_tokens: Some(0),
            cost_usd: cost,
            ..Default::default()
        };
        let run = vec![
            e("claude", 100, 0.0),
            e("worker", 300, 0.02),
            e("cheap", 100, 0.01),
        ];
        let (c, ch, ct, cht) = split_cost(2.0, &run);
        assert!((c - 0.4).abs() < 1e-9 && (ch - 0.03).abs() < 1e-9);
        assert_eq!((ct, cht), (1, 2));
        assert_eq!(split_cost(2.0, &[]), (0.0, 0.0, 0, 0));
        assert_eq!(
            parse_claude_json(r#"{"total_cost_usd":0.5,"num_turns":4}"#),
            (0.5, 4)
        );
    }

    #[test]
    fn estimate_and_guard() {
        let e = estimate(5);
        assert_eq!(e.claude_requests, 125);
        assert!((e.max_usd - 8.0).abs() < 1e-9);
        assert_eq!(guard(true, false), Guard::Go);
        assert_eq!(guard(false, true), Guard::Ask);
        assert_eq!(guard(false, false), Guard::Refuse);
    }
}
