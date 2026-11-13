//! `middleman bench`: glue around `middleman::bench`.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use anyhow::{bail, Context, Result};

use middleman::bench::{self, Guard, TaskResult, TASKS};
use middleman::launch;
use middleman::ledger::{now_unix, Ledger};
use middleman::modes::Mode;

use crate::{interactive, load, theme};

pub async fn bench_cmd(
    cfg_path: &Path,
    modes: &str,
    tasks: usize,
    keep: bool,
    yes: bool,
) -> Result<ExitCode> {
    let cfg = load(cfg_path)?;
    let modes: Vec<Mode> = modes
        .split(',')
        .map(|m| m.trim().parse())
        .collect::<Result<_>>()?;
    if modes.is_empty() {
        bail!("--modes needs at least one of smart, cheap, claude");
    }
    let n = tasks.clamp(1, TASKS.len());
    let path = std::env::var_os("PATH").unwrap_or_default();
    let claude = launch::find_on_path("claude", &path).context("`claude` not found on PATH")?;
    if launch::find_on_path("python3", &path).is_none() {
        bail!("`python3` not found on PATH (the sample project needs it)");
    }
    let up = launch::upstream(&cfg)?;
    let key = if modes.iter().any(|m| *m != Mode::Claude) {
        let (main, fast) = launch::resolve_models(None, None, &cfg)?;
        let k = launch::upstream_key(&cfg, up)?;
        Some((k, main, fast))
    } else {
        None
    };

    let e = bench::estimate(&modes, n);
    note!(
        "middleman bench: {} task(s) x {} mode(s) on a built-in sample project, in temporary folders.",
        n,
        modes.len()
    );
    note!(
        "  worst case: up to {} Claude requests and about ${:.2} in total (typically far less)",
        e.claude_requests,
        e.max_usd
    );
    if e.claude_requests == 0 {
        note!("  your Claude plan is not used ({} only)", up.label);
    }
    match bench::guard(yes, interactive()) {
        Guard::Go => {}
        Guard::Refuse => {
            bail!("re-run with --yes to spend this (or `--modes cheap` to avoid Claude)")
        }
        Guard::Ask => {
            if !dialoguer::Confirm::with_theme(&theme())
                .with_prompt("Run the bench?")
                .default(false)
                .interact()?
            {
                return Ok(ExitCode::FAILURE);
            }
        }
    }

    let state = cfg.state_dir();
    let exe = std::env::current_exe()?;
    let mut results: Vec<TaskResult> = vec![];
    for mode in &modes {
        for task in TASKS.iter().take(n) {
            let tmp = std::env::temp_dir()
                .join(format!("middleman-bench-{}", uuid::Uuid::new_v4().simple()));
            bench::copy_fixture(&tmp)?;
            let run_id = uuid::Uuid::new_v4().to_string();
            let mut env: Vec<(String, String)> = vec![];
            let mut proxy = None;
            if let Some((k, main, fast)) = key.as_ref().filter(|_| *mode != Mode::Claude) {
                let p = launch::spawn_proxy(&launch::ProxySpec {
                    exe: &exe,
                    cfg_path,
                    mode: *mode,
                    main,
                    fast,
                    key: k,
                    provider: up.name,
                    project: "bench",
                    bench_run: Some(&run_id),
                })?;
                env = launch::proxy_env(&p.base_url);
                proxy = Some(p);
            }
            let out =
                bench::run_claude(&claude, &tmp, task.prompt, &env, bench::TASK_TIMEOUT).await;
            tokio::time::sleep(std::time::Duration::from_millis(400)).await; // proxy ledger writes
            drop(proxy);
            let (stdout, secs, mut reason) = match out {
                Ok((o, s)) => (o, s, String::new()),
                Err(e) => (
                    String::new(),
                    bench::TASK_TIMEOUT.as_secs_f64(),
                    e.to_string(),
                ),
            };
            let (total, turns) = bench::parse_claude_json(&stdout);
            let run: Vec<_> = Ledger::new(&state)
                .and_then(|l| l.entries())
                .unwrap_or_default()
                .into_iter()
                .filter(|e| e.session_id.as_deref() == Some(run_id.as_str()))
                .collect();
            let (claude_usd, cheap_usd, claude_turns, cheap_turns) =
                bench::split_cost(*mode, total, turns, &run);
            let passed = match bench::check_task(&tmp, task) {
                Ok(()) => reason.is_empty(),
                Err(why) => {
                    if reason.is_empty() {
                        reason = why;
                    }
                    false
                }
            };
            note!(
                "  {:<7} {:<20} {} {:>5.0}s  ${:.3}",
                mode,
                task.id,
                if passed { "pass" } else { "FAIL" },
                secs,
                claude_usd + cheap_usd
            );
            results.push(TaskResult {
                mode: mode.to_string(),
                task: task.id.into(),
                passed,
                reason,
                secs,
                claude_usd,
                cheap_usd,
                claude_turns,
                cheap_turns,
            });
            if keep {
                note!("  kept {}", tmp.display());
            } else {
                let _ = std::fs::remove_dir_all(&tmp);
            }
        }
    }
    let summary = bench::summarize(&results);
    say!("\n{}", bench::table(&summary));
    say!("{}", bench::verdict(&summary));
    let p = bench::results_path(&state, now_unix());
    middleman::ledger::ensure_private_dir(&state)?;
    middleman::ledger::write_private(
        &p,
        serde_json::to_string_pretty(&serde_json::json!({"results": results, "summary": summary}))?
            .as_bytes(),
    )?;
    note!("saved {}", p.display());
    Ok(ExitCode::SUCCESS)
}
