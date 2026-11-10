//! `middleman route [--hook]`: a local, no-network prompt classifier for Claude Code's
//! UserPromptSubmit hook. It only adds context ("looks delegable" / "keep on Claude"); it
//! never blocks the prompt and the hook path always exits 0.
//!
//! Output fields (<https://code.claude.com/docs/en/hooks>): `hookSpecificOutput.additionalContext`
//! goes to Claude; the top-level `systemMessage` is a short line shown to the user, so they can
//! see middleman acting in the session.

use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;
use serde_json::{json, Value};

use crate::classify::Sensitivity;
use crate::config::RoutingMode;
use crate::detect::Dictionary;
use crate::economics::{EconomicsCfg, WriteMode};
use crate::TaskKind;

static KINDS: LazyLock<Vec<(TaskKind, Regex)>> = LazyLock::new(|| {
    let k = |t, re: &str| (t, Regex::new(&format!("(?i){re}")).expect("static regex"));
    vec![
        k(
            TaskKind::WriteTests,
            r"\b(?:write|add|generate|create)\b[^.\n]{0,30}\btests?\b|\bunit tests?\b|\btest cases?\b|\btest(?:leri(?:ni)?)? yaz|birim test",
        ),
        k(
            TaskKind::Docstring,
            r"\bdocstrings?\b|\bdoc ?comments?\b|\bjsdoc\b|\badd comments\b|yorum ekle|dok[uü]mantasyon",
        ),
        k(
            TaskKind::Summarize,
            r"\bsummari[sz]e\b|\bsummary\b|\btl;?dr\b|[öo]zetle|\b[öo]zet\b",
        ),
        k(
            TaskKind::Explain,
            r"\bexplain\b|\bwhat does\b|\ba[çc][ıi]kla",
        ),
        k(TaskKind::Translate, r"\btranslate\b|\b[çc]evir|terc[üu]me"),
        k(
            TaskKind::Boilerplate,
            r"\bboilerplate\b|\bscaffold|\bskeleton\b|iskelet|[şs]ablon",
        ),
        k(
            TaskKind::RefactorSmall,
            r"\brename\b|\bsmall refactor|k[üu][çc][üu]k refactor|yeniden adland[ıi]r",
        ),
        k(
            TaskKind::Snippet,
            r"\bsnippet\b|\bregex for\b|\bone-?liner\b|\bsmall (?:helper|function)\b|k[üu][çc][üu]k fonksiyon",
        ),
    ]
});

static SENSITIVE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(auth\w*|login|log in|sign[- ]?in|passwords?|passwd|oauth|jwt|tokens?|credentials?|secrets?|api keys?|private keys?|billing|payments?|invoices?|stripe|checkout|customers?|pii|gdpr|kvkk|ssn|personal data|infra\w*|terraform|kubernetes|k8s|deploy\w*|prod|production|migrations?|encrypt\w*|crypto\w*|[şs]ifre|parola|[öo]deme|fatura|m[üu][şs]teri|kimlik|giri[şs])\b")
        .expect("static regex")
});

#[derive(Debug, Clone, Serialize)]
pub struct Advice {
    pub kind: Option<TaskKind>,
    pub est_sensitivity: Sensitivity,
    pub sensitive_topics: Vec<String>,
    pub dict_hits: usize,
    pub explicit_request: bool,
    pub delegable: bool,
    pub expected_output_tokens: Option<u64>,
    pub break_even_tokens: u64,
    pub message: Option<String>,
    /// Short line for the user (hook `systemMessage`).
    pub user_message: Option<String>,
}

pub fn explicit_prefix(prompt: &str) -> bool {
    let t = prompt.trim_start().to_ascii_lowercase();
    t.starts_with("cheap:") || t.starts_with("/delegate")
}

static BIG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:all|every|whole|entire|full|suite|comprehensive|exhaustive|t[üu]m|b[üu]t[üu]n|hepsi)\b")
        .expect("static regex")
});
static SMALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:one|single|small|quick|tiny|a line|one-liner|tek|k[üu][çc][üu]k|h[ıi]zl[ıi])\b",
    )
    .expect("static regex")
});

/// Rough expected output size (tokens) of the task the prompt asks for.
pub fn expected_output_from_prompt(kind: TaskKind, prompt: &str) -> u64 {
    let base: f64 = match kind {
        TaskKind::WriteTests => 1500.0,
        TaskKind::Boilerplate => 1200.0,
        TaskKind::Docstring => 1000.0,
        TaskKind::Translate => 800.0,
        TaskKind::RefactorSmall => 600.0,
        TaskKind::Explain => 400.0,
        TaskKind::Summarize => 300.0,
        TaskKind::Snippet => 200.0,
        TaskKind::Other => 300.0,
    };
    let mut n = base;
    if BIG.is_match(prompt) {
        n *= 2.0;
    }
    if SMALL.is_match(prompt) {
        n *= 0.4;
    }
    // pasted material to translate / document comes back at about its own size
    if matches!(kind, TaskKind::Translate | TaskKind::Docstring) {
        n = n.max(prompt.len() as f64 / 3.5);
    }
    n.round() as u64
}

pub fn advise(
    prompt: &str,
    mode: RoutingMode,
    dict: Option<&Dictionary>,
    econ: Option<&EconomicsCfg>,
) -> Advice {
    let explicit_request = explicit_prefix(prompt);
    let kind = KINDS
        .iter()
        .find(|(_, re)| re.is_match(prompt))
        .map(|(k, _)| *k);
    let mut topics: Vec<String> = SENSITIVE
        .find_iter(prompt)
        .map(|m| m.as_str().to_lowercase())
        .collect();
    topics.sort();
    topics.dedup();
    topics.truncate(5);
    let dict_hits = dict
        .map(|d| {
            let mut v = vec![];
            d.scan(prompt, &mut v);
            v.len()
        })
        .unwrap_or(0);
    let large = prompt.len() > 12_000;
    let est = if !topics.is_empty() {
        Sensitivity::S3
    } else if dict_hits > 0 {
        Sensitivity::S1
    } else {
        Sensitivity::S0
    };
    let default_econ = EconomicsCfg::default();
    let econ = econ.unwrap_or(&default_econ);
    let threshold = econ
        .prices()
        .map(|p| econ.threshold_tokens(&p, WriteMode::File))
        .unwrap_or(econ.min_expected_output_tokens);
    let expected = kind.map(|k| expected_output_from_prompt(k, prompt));
    let worth_it = expected.is_some_and(|e| e >= threshold);
    let delegable = kind.is_some() && topics.is_empty() && !large && worth_it;
    let suggest = match mode {
        RoutingMode::Explicit => explicit_request,
        _ => true,
    };
    let message = if !topics.is_empty() {
        // always say so, in every mode: this is the "keep on Claude" guard rail
        Some(format!(
            "middleman: keep this on Claude (sensitive: {}); do not delegate it.",
            topics.join(", ")
        ))
    } else if !suggest {
        None
    } else if large {
        Some("middleman: prompt is large; not delegable as-is (split it or do it yourself).".into())
    } else if let Some(k) = kind {
        let e = expected.unwrap_or(0);
        if !worth_it {
            explicit_request.then(|| format!(
                "middleman: the user asked to delegate, but this looks small (~{e} output tokens < break-even {threshold}); doing it yourself is cheaper."
            ))
        } else {
            let mut m = format!(
                "middleman: this looks delegable (kind={k}, ~{e} output tokens >= break-even {threshold}, est. {est:?}). Use mcp__middleman__delegate_task with file paths (not pasted code), write_mode=file and an output_path, an honest declared_sensitivity; then read the returned diff (and any risk findings) before running the tests"
            );
            if explicit_request {
                m.push_str("; the user asked explicitly, so pass user_requested=true");
            }
            if mode == RoutingMode::Confirm {
                m.push_str("; routing.mode=confirm: dry_run first and ask the user");
            }
            if dict_hits > 0 {
                m.push_str(&format!(
                    "; {dict_hits} private dictionary term(s) will be pseudonymized"
                ));
            }
            m.push('.');
            Some(m)
        }
    } else if explicit_request {
        Some("middleman: the user asked to delegate; pick a task_kind and use mcp__middleman__delegate_task with user_requested=true (or do it yourself if it is small or touches sensitive code).".into())
    } else {
        None
    };
    let user_message = message.as_ref().map(|_| {
        if !topics.is_empty() {
            format!("🛡 middleman: keep on Claude (sensitive: {})", topics.join(", "))
        } else if large {
            "🛡 middleman: prompt too large to delegate; Claude handles it".into()
        } else if let (Some(k), true) = (kind, worth_it) {
            format!(
                "🛡 middleman: suggested delegating this {k} task (~{} output tokens) to a cheap model",
                expected.unwrap_or(0)
            )
        } else if kind.is_some() {
            "🛡 middleman: too small to delegate; Claude does it".into()
        } else {
            "🛡 middleman: delegation requested; Claude picks the task kind".into()
        }
    });
    Advice {
        kind,
        est_sensitivity: est,
        sensitive_topics: topics,
        dict_hits,
        explicit_request,
        delegable,
        expected_output_tokens: expected,
        break_even_tokens: threshold,
        message,
        user_message,
    }
}

/// Hook stdout for a UserPromptSubmit event, or None (print nothing).
pub fn hook_output(
    hook_input: &str,
    mode: RoutingMode,
    dict: Option<&Dictionary>,
    econ: Option<&EconomicsCfg>,
) -> Option<String> {
    let v: Value = serde_json::from_str(hook_input).ok()?;
    let prompt = v.get("prompt")?.as_str()?;
    let a = advise(prompt, mode, dict, econ);
    let msg = a.message?;
    Some(render(&msg, a.user_message.as_deref()))
}

fn render(context: &str, user: Option<&str>) -> String {
    let mut v = json!({
        "hookSpecificOutput": {
            "hookEventName": "UserPromptSubmit",
            "additionalContext": context,
        }
    });
    if let Some(u) = user {
        v["systemMessage"] = json!(u);
    }
    v.to_string()
}

/// Hook output when the config (user or project overlay) cannot be loaded: tell Claude not
/// to delegate rather than silently falling back to defaults.
pub fn hook_output_config_error(err: &str) -> String {
    let short: String = crate::fsutil::clean(err, 160);
    render(
        &format!(
            "middleman config invalid ({short}); do not delegate anything to middleman in this session. The user can run `middleman doctor`."
        ),
        Some("🛡 middleman ✗ config invalid; delegation disabled (run: middleman doctor)"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adv(p: &str, m: RoutingMode) -> Advice {
        advise(p, m, None, None)
    }

    #[test]
    fn delegable_only_above_break_even() {
        let a = adv(
            "please write unit tests for parse_date in utils.py",
            RoutingMode::Auto,
        );
        assert_eq!(a.kind, Some(TaskKind::WriteTests));
        assert!(a.delegable, "{a:?}");
        assert!(a.message.unwrap().contains("write_mode=file"));
        // a one-liner is below break-even: no suggestion
        let a = adv(
            "give me a quick snippet to reverse a string",
            RoutingMode::Auto,
        );
        assert_eq!(a.kind, Some(TaskKind::Snippet));
        assert!(!a.delegable && a.message.is_none(), "{a:?}");
        let a = adv("bu fonksiyon için birim test yaz", RoutingMode::Auto);
        assert_eq!(a.kind, Some(TaskKind::WriteTests));
        let a = adv("fix the race condition in the scheduler", RoutingMode::Auto);
        assert!(a.message.is_none());
    }

    #[test]
    fn sensitive_always_says_keep_on_claude() {
        for m in [
            RoutingMode::Auto,
            RoutingMode::Confirm,
            RoutingMode::Explicit,
        ] {
            for p in [
                "write tests for the billing payment flow",
                "why does the login page redirect twice?",
                "müşteri ödeme ekranını düzelt",
            ] {
                let a = adv(p, m);
                assert!(!a.delegable);
                let msg = a.message.unwrap_or_default();
                assert!(
                    msg.contains("keep this on Claude (sensitive:"),
                    "{m:?} {p}: {msg}"
                );
            }
        }
    }

    #[test]
    fn explicit_mode_needs_prefix() {
        let a = adv("write unit tests for x", RoutingMode::Explicit);
        assert!(a.message.is_none());
        let a = adv("cheap: write unit tests for x", RoutingMode::Explicit);
        assert!(a.message.unwrap().contains("user_requested=true"));
        let a = adv(
            "cheap: a quick snippet to add two ints",
            RoutingMode::Explicit,
        );
        assert!(a.message.unwrap().contains("break-even"));
    }

    #[test]
    fn hook_json_shape_and_garbage() {
        let o = hook_output(
            r#"{"prompt":"write the whole test suite for utils.py","hook_event_name":"UserPromptSubmit"}"#,
            RoutingMode::Auto,
            None,
            None,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&o).unwrap();
        assert_eq!(v["hookSpecificOutput"]["hookEventName"], "UserPromptSubmit");
        assert!(v["systemMessage"]
            .as_str()
            .unwrap()
            .starts_with("🛡 middleman: suggested delegating this write_tests task"));
        let o = hook_output(
            r#"{"prompt":"fix the billing export"}"#,
            RoutingMode::Auto,
            None,
            None,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&o).unwrap();
        assert_eq!(
            v["systemMessage"],
            "🛡 middleman: keep on Claude (sensitive: billing)"
        );
        let v: Value =
            serde_json::from_str(&hook_output_config_error("bad \u{1b}[31m overlay")).unwrap();
        let ctx = v["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .unwrap();
        assert!(ctx.contains("do not delegate") && !ctx.contains('\u{1b}'));
        assert!(hook_output("not json", RoutingMode::Auto, None, None).is_none());
        assert!(hook_output("{}", RoutingMode::Auto, None, None).is_none());
    }
}
