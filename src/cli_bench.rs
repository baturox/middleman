//! `middleman bench`: glue around `middleman::bench`.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use anyhow::{bail, Context, Result};

use middleman::bench::{self, Guard, TaskResult, TASKS};
use middleman::launch;
use middleman::ledger::{now_unix, Ledger};

use crate::{interactive, load, theme};

pub async fn bench_cmd(cfg_path: &Path, tasks: usize, keep: bool, yes: bool) -> Result<ExitCode> {
    let cfg = load(cfg_path)?;
    let n = tasks.clamp(1, TASKS.len());
    let path = std::env::var_os("PATH").unwrap_or_default();
    let claude = launch::find_on_path("claude", &path).context("`claude` not found on PATH")?;
    if launch::find_on_path("python3", &path).is_none() {
        bail!("`python3` not found on PATH (the sample project needs it)");
    }
    let up = launch::upstream(&cfg)?;
    let (main, fast) = launch::resolve_models(None, None, &cfg)?;
    let key = launch::upstream_key(&cfg, up)?;

    let e = bench::estimate(n);
    note!(
        "middleman bench: {} task(s) on a built-in sample project, in temporary folders.",
        n
    );
    note!(
        "  Claude plans and checks; its subagents run on {main} ({})",
        up.label
    );
    note!(
        "  worst case: up to {} Claude requests and about ${:.2} in total (typically far less)",
        e.claude_requests,
        e.max_usd
    );
    match bench::guard(yes, interactive()) {
        Guard::Go => {}
        Guard::Refuse => {
            bail!("re-run with --yes to spend this")
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
    for task in TASKS.iter().take(n) {
        {
            let tmp = std::env::temp_dir()
                .join(format!("middleman-bench-{}", uuid::Uuid::new_v4().simple()));
            bench::copy_fixture(&tmp)?;
            let run_id = uuid::Uuid::new_v4().to_string();
            let proxy = launch::spawn_proxy(&launch::ProxySpec {
                exe: &exe,
                cfg_path,
                main: &main,
                fast: &fast,
                key: &key,
                provider: up.name,
                project: "bench",
                bench_run: Some(&run_id),
            })?;
            let env = launch::proxy_env(&proxy.base_url, &main);
            let prompt = format!("{}{}", bench::DELEGATE_PREFIX, task.prompt);
            let out = bench::run_claude(&claude, &tmp, &prompt, &env, bench::TASK_TIMEOUT).await;
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
            let (total, _turns) = bench::parse_claude_json(&stdout);
            let run: Vec<_> = Ledger::new(&state)
                .and_then(|l| l.entries())
                .unwrap_or_default()
                .into_iter()
                .filter(|e| e.session_id.as_deref() == Some(run_id.as_str()))
                .collect();
            let (claude_usd, cheap_usd, claude_turns, cheap_turns) = bench::split_cost(total, &run);
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
                "  {:<20} {} {:>5.0}s  ${:.3}  ({} Claude / {} agent requests)",
                task.id,
                if passed { "pass" } else { "FAIL" },
                secs,
                claude_usd + cheap_usd,
                claude_turns,
                cheap_turns
            );
            results.push(TaskResult {
                mode: "middleman".into(),
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
