use super::*;
use serde_json::json;
use std::cell::Cell;
use std::io::Write;

const NOW: i64 = 1_000_000;

fn session() -> Value {
    json!({
        "model": {"id": "claude-opus-5-5", "display_name": "Opus"},
        "effort": {"level": "medium"},
        "cost": {"total_cost_usd": 0.42},
        "context_window": {"context_window_size": 1_000_000, "used_percentage": 12,
            "current_usage": {"input_tokens": 500, "output_tokens": 90,
                "cache_creation_input_tokens": 19_500, "cache_read_input_tokens": 100_000}},
        "prompt_cache": {"caching_observed": true, "warm": true, "expires_at": NOW + 2820,
            "recache_tokens_if_cold": 120_000},
    })
}

/// The Claude part as context-line renders it for `columns`.
fn plain(v: &Value, columns: usize) -> String {
    claude_part(
        v,
        claude_level_for(columns),
        &Thresholds::default(),
        NOW as f64,
    )
    .plain
}

fn ansi(v: &Value) -> String {
    claude_part(v, 0, &Thresholds::default(), NOW as f64).ansi
}

// ---------------------------------------------------------------- Claude part (context-line port)

#[test]
fn shows_model_effort_context_cost_and_cache() {
    assert_eq!(
        plain(&session(), 120),
        "Opus 5.5 medium │ █░░░░░░░░░ 12% 120k/1M │ ~$0.42 │ cache 47m left"
    );
}

#[test]
fn survives_empty_and_null_data() {
    let v = json!({"model": {"display_name": "Sonnet"}, "context_window":
        {"current_usage": null, "used_percentage": null, "context_window_size": 200_000}});
    assert_eq!(plain(&v, 120), "Sonnet │ ░░░░░░░░░░ 0% 0/200k");
    assert_eq!(plain(&json!({}), 120), "Claude │ ░░░░░░░░░░ 0% 0");
    assert_eq!(plain(&Value::Null, 120), "Claude │ ░░░░░░░░░░ 0% 0");
    assert!(plain(&json!({"model": null}), 120).starts_with("Claude"));
}

#[test]
fn names_models_from_their_id() {
    let n = |v: Value| model_name(Some(&v));
    assert_eq!(n(json!({"id": "claude-sonnet-5-5"})), "Sonnet 5.5");
    assert_eq!(n(json!({"id": "claude-haiku-5-5[1m]"})), "Haiku 5.5");
    assert_eq!(n(json!({"id": "claude-sonnet-4-20250514"})), "Sonnet 4");
    assert_eq!(
        n(json!({"id": "custom-gateway", "display_name": "Our model"})),
        "Our model"
    );
    assert_eq!(model_name(None), "Claude");
}

#[test]
fn warns_on_tokens_even_when_the_percentage_looks_small() {
    let t = Thresholds::default();
    assert_eq!(context_level(12.0, 120_000.0, &t), Level::Green);
    assert_eq!(context_level(15.0, 150_000.0, &t), Level::Yellow);
    assert_eq!(context_level(30.0, 300_000.0, &t), Level::Red);
    assert_eq!(context_level(70.0, 140_000.0, &t), Level::Red);
}

#[test]
fn suggests_a_fix_when_context_is_heavy() {
    let mut heavy = session();
    heavy["context_window"]["used_percentage"] = json!(35);
    heavy["context_window"]["current_usage"] = json!({"input_tokens": 350_000});
    assert!(plain(&heavy, 120).contains("/compact or /clear"));
    assert!(!plain(&session(), 120).contains("/compact"));
}

#[test]
fn reports_a_cold_cache() {
    let mut cold = session();
    cold["prompt_cache"]["expires_at"] = json!(NOW - 1);
    assert!(plain(&cold, 120).contains("cache cold: next message re-caches 120k"));
    let mut off = session();
    off["prompt_cache"] = json!({"caching_observed": false});
    assert!(!plain(&off, 120).contains("cache"));
}

#[test]
fn follows_5_minute_and_1_hour_caches_in_colour() {
    let at = |ttl: &str, left: i64| {
        let mut v = session();
        v["prompt_cache"] = json!({"caching_observed": true, "warm": true, "ttl": ttl,
            "expires_at": NOW + left});
        ansi(&v)
    };
    assert!(at("5m", 290).contains("\x1b[32mcache 5m"));
    assert!(at("5m", 50).contains("\x1b[33mcache 1m"));
    assert!(at("1h", 290).contains("\x1b[33mcache 5m"));
    assert!(at("1h", 3000).contains("\x1b[32mcache 50m"));
    let mut v = session();
    v["prompt_cache"]["ttl"] = json!("1h");
    assert!(plain(&v, 120).contains("cache 47m left (1h)"));
    assert!(plain(&v, 70).ends_with("cache 47m"));
}

#[test]
fn context_colour_thresholds_follow_env_overrides() {
    let env = |k: &str| match k {
        "CONTEXT_LINE_WARN_PCT" => Some("5".to_string()),
        "MIDDLEMAN_SL_DANGER_PCT" => Some("10".to_string()),
        "CONTEXT_LINE_DANGER_PCT" => Some("90".to_string()), // MIDDLEMAN_SL_ wins
        "MIDDLEMAN_SL_COST_WARN" => Some("0.1".to_string()),
        "NO_COLOR" => Some("1".to_string()),
        "COLUMNS" => Some("77".to_string()),
        _ => None,
    };
    let o = Opts::from_env(&env);
    assert_eq!(o.env.warn_pct, 5.0);
    assert_eq!(o.env.danger_pct, 10.0);
    assert_eq!(o.columns, 77);
    assert!(!o.color);
    let t = claude_part(&session(), 0, &o.env, NOW as f64);
    // 12% >= 10: red bar and the hint; $0.42 >= 2 x 0.1: red cost
    assert!(t.ansi.contains("\x1b[31m12%"), "{}", t.ansi);
    assert!(t.ansi.contains("\x1b[31m~$0.42"));
    assert!(t.plain.contains("/compact or /clear"));
    // bad values fall back to the defaults
    let bad = |k: &str| (k == "CONTEXT_LINE_WARN_PCT").then(|| "-3".to_string());
    assert_eq!(Opts::from_env(&bad).env.warn_pct, 40.0);
    assert!(Opts::from_env(&|_| None).color);
}

#[test]
fn fits_narrow_terminals() {
    assert_eq!(
        plain(&session(), 70),
        "Opus 5.5 medium │ 12% 120k/1M │ ~$0.42 │ cache 47m"
    );
    assert_eq!(plain(&session(), 40), "Opus 5.5 medium │ 12% │ ~$0.42");
}

#[test]
fn formats_numbers() {
    assert_eq!(tokens(999.0), "999");
    assert_eq!(tokens(45_724.0), "46k");
    assert_eq!(tokens(1_500_000.0), "1.5M");
    assert_eq!(tokens(1_000_000.0), "1M");
    assert_eq!(money(0.0), "~$0.00");
    assert_eq!(money(123.4), "~$123");
    assert_eq!(usd(-0.031), "-$0.03");
    assert_eq!(usd(-0.001), "$0.00");
    assert_eq!(usd(1.845), "$1.84");
}

#[test]
fn rate_limit_shows_when_present() {
    let mut v = session();
    v["rate_limits"] = json!({"five_hour": {"used_percentage": 72.4}});
    assert!(plain(&v, 120).contains("│ 5h 72%"));
    assert!(!plain(&v, 70).contains("5h"));
}

#[test]
fn removes_terminal_escapes_and_wrong_types_cannot_inject() {
    let evil = "\x1b]0;hacked\x07\x1b[2Jx\u{202e}\u{200b}y\r\nz";
    let v = json!({"model": {"display_name": evil, "id": evil}, "effort": {"level": evil}});
    let out = plain(&v, 120);
    assert!(
        !out.chars()
            .any(|c| c.is_control() || ('\u{200b}'..='\u{202e}').contains(&c)),
        "{out:?}"
    );
    assert!(!out.contains("hacked"), "{out:?}");
    let evil = "\x1b[31mhi";
    let v = json!({
        "cost": {"total_cost_usd": evil},
        "context_window": {"used_percentage": -50, "context_window_size": evil,
            "current_usage": {"input_tokens": evil}},
        "prompt_cache": {"caching_observed": true, "warm": true, "expires_at": evil,
            "recache_tokens_if_cold": evil},
    });
    let out = claude_part(&v, 0, &Thresholds::default(), NOW as f64).plain;
    assert!(!out.contains('\x1b') && !out.contains("hi"), "{out}");
    let v = json!({"context_window": {"used_percentage": 900}});
    assert!(plain(&v, 120).contains("100%"));
}

// ---------------------------------------------------------------- full render

struct Env {
    dir: tempfile::TempDir,
    cfg: PathBuf,
}

impl Env {
    fn state(&self) -> PathBuf {
        self.dir.path().join("state")
    }
}

/// Config with an OpenRouter provider (key from a key file) and a local provider.
fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let kf = dir.path().join("keys.env");
    std::fs::write(&kf, "MM_SL_TEST_KEY_UNSET=sk-test-0123456789\n").unwrap();
    let cfg = dir.path().join("config.toml");
    std::fs::write(
        &cfg,
        format!(
            "state_dir = \"{0}/state\"\n[paths]\nroots = [\"{0}\"]\n[budget]\nreserve_usd = 1.0\n\
             [providers.openrouter]\npreset = \"openrouter\"\nkey_env = \"MM_SL_TEST_KEY_UNSET\"\nkey_file = \"{1}\"\n",
            dir.path().display(),
            kf.display()
        ),
    )
    .unwrap();
    Env { dir, cfg }
}

fn entry(
    ts: i64,
    req: &str,
    status: &str,
    eq: f64,
    oh: f64,
    cost: f64,
    sid: Option<&str>,
) -> LedgerEntry {
    LedgerEntry {
        ts: crate::ledger::rfc3339_at(ts),
        request_id: req.into(),
        status: status.into(),
        closing: Some(status != "escalated"),
        attempt: u32::from(req == "a" && status == "ok"),
        claude_equiv_usd: eq,
        claude_overhead_usd: oh,
        cost_usd: cost,
        session_id: sid.map(String::from),
        ..Default::default()
    }
}

fn seed(e: &Env, now: i64) {
    let l = crate::ledger::Ledger::new(&e.state()).unwrap();
    // yesterday: +1.63
    l.append(&entry(now - 86_400, "y", "ok", 1.7, 0.05, 0.02, None))
        .unwrap();
    // today, this session: escalated + ok (+0.08 - 0.001), blocked (-0.02)
    l.append(&entry(
        now - 50,
        "a",
        "escalated",
        0.0,
        0.0,
        0.001,
        Some("sess-1"),
    ))
    .unwrap();
    l.append(&entry(
        now - 40,
        "a",
        "ok",
        0.12,
        0.03,
        0.01,
        Some("sess-1"),
    ))
    .unwrap();
    l.append(&entry(
        now - 30,
        "b",
        "blocked",
        0.0,
        0.02,
        0.0,
        Some("sess-1"),
    ))
    .unwrap();
    // today, another session: +0.151
    l.append(&entry(now - 20, "c", "ok", 0.2, 0.04, 0.009, Some("other")))
        .unwrap();
}

fn limits_at(e: &Env, fetched_at: i64, left: f64) {
    let mut c = LimitsCache {
        fetched_at,
        ..Default::default()
    };
    c.providers.insert(
        "openrouter".into(),
        limits::ProviderLimits {
            balance_usd: Some(20.0),
            key: Some(crate::providers::KeyLimits {
                limit_remaining_usd: Some(left),
                ..Default::default()
            }),
            fetched_at,
            ..Default::default()
        },
    );
    limits::save(&e.state(), &c).unwrap();
}

fn stdin(e: &Env, transcript: Option<&Path>) -> String {
    let mut v = session();
    v["session_id"] = json!("sess-1");
    v["workspace"] = json!({"current_dir": e.dir.path()});
    v["effort"] = json!({"level": "high"});
    v["cost"] = json!({"total_cost_usd": 1.27});
    v["context_window"] = json!({"context_window_size": 1_000_000, "used_percentage": 18,
        "current_usage": {"input_tokens": 1000, "cache_creation_input_tokens": 4000,
            "cache_read_input_tokens": 175_000}});
    v["prompt_cache"]["ttl"] = json!("1h");
    if let Some(t) = transcript {
        v["transcript_path"] = json!(t);
    }
    v.to_string()
}

fn transcript(e: &Env, agents: usize) -> PathBuf {
    let p = e.dir.path().join("t.jsonl");
    let mut f = std::fs::File::create(&p).unwrap();
    for i in 0..agents {
        let l = json!({"type": "assistant", "message": {"content": [
            {"type": "tool_use", "id": format!("toolu_{i}"), "name": "Agent", "input": {}}]}});
        writeln!(f, "{l}").unwrap();
    }
    p
}

fn opts(columns: usize, lines: u8) -> Opts {
    Opts {
        columns,
        lines,
        ..Default::default()
    }
}

fn render_no_spawn(input: &str, e: &Env, now: i64, o: &Opts) -> String {
    render_with(input, &e.cfg, now, o, &mut || {
        panic!("must not spawn with a fresh cache")
    })
}

#[test]
fn full_line_at_three_widths_and_two_line_mode() {
    let e = env();
    let now = 1_767_225_600 + 3600;
    seed(&e, now);
    limits_at(&e, now - 30, 7.42);
    let t = transcript(&e, 2);
    let input = stdin(&e, Some(&t));
    let now_v = now;
    // the Claude part's cache countdown uses `now`: put expiry 47 minutes ahead
    let input = input.replace(&(NOW + 2820).to_string(), &(now_v + 2820).to_string());

    let two = render_no_spawn(&input, &e, now, &opts(200, 2));
    let mut lines = two.lines();
    assert_eq!(
        lines.next().unwrap(),
        "Opus 5.5 high │ ██░░░░░░░░ 18% 180k/1M │ ~$1.27 │ cache 47m left (1h)"
    );
    assert_eq!(
        lines.next().unwrap(),
        "🛡 middleman ✓ openrouter $7.42 left · 2 jobs this session (1 blocked, 1 escalated) · 3 today · 2 agents · saved $0.06 session · $0.21 today · $1.84 total"
    );

    let wide = render_no_spawn(&input, &e, now, &opts(200, 1));
    assert_eq!(
        wide,
        "Opus 5.5 high │ ██░░░░░░░░ 18% 180k/1M │ ~$1.27 │ cache 47m left (1h) │ 🛡 ✓ openrouter $7.42 · 2 jobs (1 blocked, 1 escalated) · 2 agents · saved $0.21 today · $1.84 total"
    );
    let mid = render_no_spawn(&input, &e, now, &opts(120, 1));
    assert!(mid.chars().count() <= 120, "{mid}");
    assert_eq!(
        mid,
        "Opus 5.5 high │ ██░░░░░░░░ 18% 180k/1M │ ~$1.27 │ cache 47m left (1h) │ 🛡 ✓ $7.42 · 2 jobs · saved $0.21 today"
    );
    let narrow = render_no_spawn(&input, &e, now, &opts(60, 1));
    assert_eq!(narrow, "Opus 5.5 high │ 18% │ ~$1.27 │ 🛡 ✓ saved $0.21");
    let only = render_no_spawn(
        &input,
        &e,
        now,
        &Opts {
            middleman_only: true,
            ..opts(100, 1)
        },
    );
    assert_eq!(
        only,
        "🛡 ✓ openrouter $7.42 · 2 jobs (1 blocked, 1 escalated) · 2 agents · saved $0.21 today · $1.84 total"
    );
    // colours: saved is green, separators dim
    let c = render_no_spawn(
        &input,
        &e,
        now,
        &Opts {
            color: true,
            ..opts(200, 2)
        },
    );
    assert!(
        c.contains("\x1b[32m✓\x1b[0m") && c.contains("\x1b[32m$1.84\x1b[0m"),
        "{c:?}"
    );
    assert!(c.contains("\x1b[2m · \x1b[0m"));

    // the live context reached the session file for the MCP server
    let s = crate::session::read(&e.state(), "sess-1").unwrap();
    assert_eq!(s.context_tokens, 180_000);
    assert_eq!(s.model_id, "claude-opus-5-5");
    assert_eq!(s.cache_ttl.as_deref(), Some("1h"));
}

#[test]
fn totals_match_the_report_exactly() {
    let e = env();
    let now = 1_767_225_600 + 3600;
    seed(&e, now);
    let t = totals(&e.state());
    let es = crate::ledger::Ledger::new(&e.state())
        .unwrap()
        .entries()
        .unwrap();
    let day = now - now.rem_euclid(86_400);
    let r_all = crate::report::build(&es, None, crate::report::By::Day).total;
    let r_day = crate::report::build(&es, Some(day), crate::report::By::Day).total;
    assert_eq!(t.all.net_savings_usd, r_all.net_savings_usd);
    assert_eq!(t.today(now).net_savings_usd, r_day.net_savings_usd);
    assert_eq!(t.all.requests as usize, r_all.requests);
    // appended lines are picked up incrementally and still match a full recount
    let l = crate::ledger::Ledger::new(&e.state()).unwrap();
    l.append(&entry(now - 5, "d", "ok", 0.5, 0.1, 0.01, Some("sess-1")))
        .unwrap();
    let t2 = totals(&e.state());
    assert!(t2.offset > t.offset);
    let mut full = LedgerTotals::default();
    for x in l.entries().unwrap() {
        full.add(&x);
    }
    assert_eq!(t2.all, full.all);
    assert_eq!(t2.session("sess-1"), full.session("sess-1"));
}

#[test]
fn absent_fields_negative_savings_and_errors() {
    let e = env();
    let now = 1_767_225_600 + 3600;
    limits_at(&e, now - 30, 7.42);
    let l = crate::ledger::Ledger::new(&e.state()).unwrap();
    l.append(&entry(now - 5, "x", "blocked", 0.0, 0.031, 0.0, None))
        .unwrap();
    // no session id, no model, nothing
    let out = render_no_spawn(
        "{}",
        &e,
        now,
        &Opts {
            middleman_only: true,
            ..opts(200, 1)
        },
    );
    assert_eq!(
        out,
        "🛡 middleman ✓ openrouter $7.42 left · 1 job today (1 blocked) · saved -$0.03 today · -$0.03 total"
    );
    assert!(render_no_spawn("not json", &e, now, &opts(200, 1)).starts_with("Claude │"));
    let red = render_no_spawn(
        "{}",
        &e,
        now,
        &Opts {
            color: true,
            middleman_only: true,
            ..opts(200, 1)
        },
    );
    assert!(red.contains("\x1b[31m-$0.03\x1b[0m"), "{red:?}");
    // a broken config still shows the Claude part
    let bad = e.dir.path().join("nope.toml");
    let out = render_with("{}", &bad, now, &opts(200, 1), &mut || Ok(()));
    assert!(
        out.starts_with("Claude │ ░░░░░░░░░░ 0% 0 │ 🛡 middleman ✗ cannot read config"),
        "{out}"
    );
    // low balance turns red
    limits_at(&e, now - 30, 0.5);
    let c = render_no_spawn(
        "{}",
        &e,
        now,
        &Opts {
            color: true,
            middleman_only: true,
            ..opts(200, 1)
        },
    );
    assert!(c.contains("\x1b[31m$0.50 left\x1b[0m"), "{c:?}");
    // a rejected key is a health failure
    let mut lc = limits::load(&e.state()).unwrap();
    lc.providers.get_mut("openrouter").unwrap().http_status = Some(401);
    limits::save(&e.state(), &lc).unwrap();
    let out = render_no_spawn(
        "{}",
        &e,
        now,
        &Opts {
            middleman_only: true,
            ..opts(200, 1)
        },
    );
    assert_eq!(
        out,
        "🛡 middleman ✗ openrouter key rejected (run: middleman provider test openrouter)"
    );
}

#[test]
fn stale_or_missing_cache_spawns_one_refresh_and_shows_age() {
    let e = env();
    let now = 1_767_225_600 + 3600;
    let spawned = Cell::new(0);
    let mut spawn = || {
        spawned.set(spawned.get() + 1);
        Ok(())
    };
    let o = Opts {
        middleman_only: true,
        ..opts(200, 1)
    };
    // no cache yet: refresh, no amount shown
    let out = render_with("{}", &e.cfg, now, &o, &mut spawn);
    assert_eq!(spawned.get(), 1);
    assert!(out.starts_with("🛡 middleman ✓ openrouter · "), "{out}");
    // a second render while the refresh runs does not spawn again
    render_with("{}", &e.cfg, now, &o, &mut spawn);
    assert_eq!(spawned.get(), 1);
    // the refresh wrote a cache 12 minutes ago and released the lock
    limits::release_lock(&e.state());
    limits_at(&e, now - 720, 7.42);
    let out = render_with("{}", &e.cfg, now, &o, &mut spawn);
    assert_eq!(spawned.get(), 2, "stale cache: refresh again");
    assert!(out.contains("$7.42 left (12m ago)"), "{out}");
    // fresh cache: no spawn
    limits::release_lock(&e.state());
    limits_at(&e, now - 10, 7.42);
    render_with("{}", &e.cfg, now, &o, &mut spawn);
    assert_eq!(spawned.get(), 2);
}

#[test]
fn malicious_provider_names_and_session_ids_are_cleaned() {
    let e = env();
    let text = std::fs::read_to_string(&e.cfg).unwrap().replace(
        "[providers.openrouter]",
        "[providers.\"or\\u001b]0;pwn\\u0007x\"]",
    );
    std::fs::write(&e.cfg, text).unwrap();
    let input =
        json!({"session_id": "../../\u{1b}[2J", "transcript_path": "/dev/null"}).to_string();
    let out = render_with(
        &input,
        &e.cfg,
        1_767_225_600,
        &Opts {
            middleman_only: true,
            ..opts(200, 1)
        },
        &mut || Ok(()),
    );
    assert!(!out.chars().any(|c| c.is_control()), "{out:?}");
    assert!(!out.contains("pwn"), "{out:?}");
}

#[test]
fn fifty_mb_transcript_is_fast_after_the_first_run() {
    let e = env();
    let now = 1_767_225_600 + 3600;
    seed(&e, now);
    limits_at(&e, now - 30, 7.42);
    let p = e.dir.path().join("big.jsonl");
    {
        let mut f = std::io::BufWriter::new(std::fs::File::create(&p).unwrap());
        let filler = "x".repeat(900);
        let mut i = 0usize;
        let mut written = 0usize;
        while written < 50 << 20 {
            let l = if i.is_multiple_of(500) {
                json!({"type": "assistant", "message": {"content": [
                    {"type": "tool_use", "id": format!("toolu_{i}"), "name": "Agent", "input": {"prompt": filler}}]}})
            } else {
                json!({"type": "user", "message": {"content": filler}})
            };
            let s = l.to_string();
            written += s.len() + 1;
            writeln!(f, "{s}").unwrap();
            i += 1;
        }
    }
    let input = stdin(&e, Some(&p));
    let o = opts(200, 2);
    let first = std::time::Instant::now();
    let out = render_no_spawn(&input, &e, now, &o);
    let first = first.elapsed();
    assert!(out.contains(" agents · "), "{out}");
    // one new line arrives; the next run reads only that
    let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
    writeln!(
        f,
        "{}",
        json!({"type": "assistant", "message": {"content": [
        {"type": "tool_use", "id": "toolu_new", "name": "Agent", "input": {}}]}})
    )
    .unwrap();
    let mut best = std::time::Duration::MAX;
    for _ in 0..3 {
        let t0 = std::time::Instant::now();
        let out2 = render_no_spawn(&input, &e, now, &o);
        best = best.min(t0.elapsed());
        assert_ne!(out, out2, "the new agent is counted");
    }
    assert!(
        best < std::time::Duration::from_millis(50),
        "second run took {best:?} (first {first:?})"
    );
}

#[test]
fn newer_release_marker_and_daily_check() {
    let e = env();
    let now = 1_767_225_600 + 3600;
    limits_at(&e, now - 30, 7.42);
    let o = Opts {
        middleman_only: true,
        ..opts(200, 1)
    };
    let checks = Cell::new(0);
    let mut no_limits = || Ok(());
    let mut check = || {
        checks.set(checks.get() + 1);
        Ok(())
    };
    // no cache yet: no marker, one background check (the lock stops a second one)
    let out = render_jobs("{}", &e.cfg, now, &o, &mut no_limits, &mut check);
    assert!(!out.contains('↑'), "{out}");
    render_jobs("{}", &e.cfg, now, &o, &mut no_limits, &mut check);
    assert_eq!(checks.get(), 1);
    // the check found a newer release
    crate::upgrade::save_cache(
        &e.state(),
        &crate::upgrade::UpdateCache {
            checked_at: now,
            latest_version: Some("v99.0.0".into()),
            error: None,
        },
    )
    .unwrap();
    crate::upgrade::release_lock(&e.state());
    let out = render_jobs("{}", &e.cfg, now, &o, &mut no_limits, &mut check);
    assert_eq!(checks.get(), 1, "checked today: no second check");
    assert_eq!(
        out,
        "🛡 middleman ✓ openrouter $7.42 left · ↑ v99.0.0 · 0 jobs today · saved $0.00 today · $0.00 total"
    );
    let c = render_no_spawn("{}", &e, now, &Opts { color: true, ..o });
    assert!(c.contains("\x1b[33m↑ v99.0.0\x1b[0m"), "{c:?}");
    // the narrowest variant drops it
    let tiny = render_no_spawn("{}", &e, now, &opts(40, 1));
    assert!(!tiny.contains('↑'), "{tiny}");
    // an older or equal cached version shows nothing
    crate::upgrade::save_cache(
        &e.state(),
        &crate::upgrade::UpdateCache {
            checked_at: now,
            latest_version: Some("v0.0.1".into()),
            error: None,
        },
    )
    .unwrap();
    assert!(!render_no_spawn("{}", &e, now, &o).contains('↑'));
    // `[update] check = false`: no marker and no check
    crate::upgrade::save_cache(
        &e.state(),
        &crate::upgrade::UpdateCache {
            checked_at: 0,
            latest_version: Some("v99.0.0".into()),
            error: None,
        },
    )
    .unwrap();
    let mut text = std::fs::read_to_string(&e.cfg).unwrap();
    text.push_str("\n[update]\ncheck = false\n");
    std::fs::write(&e.cfg, text).unwrap();
    let out = render_jobs("{}", &e.cfg, now, &o, &mut no_limits, &mut check);
    assert!(!out.contains('↑'), "{out}");
    assert_eq!(checks.get(), 1);
}
