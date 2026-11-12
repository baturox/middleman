//! Per-turn routing for the smart-mode proxy: pure functions and a small in-memory state.
//!
//! A new turn is a request whose last message is a user message with text (not only
//! tool_result blocks). The route is decided there and then kept for the turn's follow-up
//! requests (tool loops), so one task never changes model midway.

use std::collections::HashMap;
use std::sync::Mutex;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::modes::Mode;

/// At or above this 5-hour utilization (percent) everything goes cheap.
pub const CUTOFF_PCT: f64 = 90.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    Claude,
    Cheap,
}

impl Route {
    pub fn as_str(&self) -> &'static str {
        match self {
            Route::Claude => "claude",
            Route::Cheap => "cheap",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Hard,
    Easy,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn sha(s: &str) -> String {
    hex(&Sha256::digest(s.as_bytes())[..12])
}

/// Text of the content (string, or text blocks), skipping injected `<system-reminder>` blocks.
/// Remove Claude Code's injected `<system-reminder>…</system-reminder>` sections (they can share
/// a text block with the user's own words), keeping everything else.
fn strip_reminders(t: &str) -> String {
    const OPEN: &str = "<system-reminder>";
    const CLOSE: &str = "</system-reminder>";
    let mut out = String::with_capacity(t.len());
    let mut rest = t;
    while let Some(i) = rest.find(OPEN) {
        out.push_str(&rest[..i]);
        match rest[i..].find(CLOSE) {
            Some(j) => rest = &rest[i + j + CLOSE.len()..],
            None => {
                rest = "";
                break;
            }
        }
    }
    out.push_str(rest);
    out.trim().to_string()
}

/// The user's own words in a message: text blocks with reminders stripped.
fn content_text(c: &Value) -> String {
    match c {
        Value::String(s) => strip_reminders(s),
        Value::Array(a) => a
            .iter()
            .filter(|b| b.get("type").and_then(Value::as_str) == Some("text"))
            .filter_map(|b| b.get("text").and_then(Value::as_str))
            .map(strip_reminders)
            .filter(|t| !t.is_empty())
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

fn has_tool_result(c: &Value) -> bool {
    c.as_array().is_some_and(|a| {
        a.iter()
            .any(|b| b.get("type").and_then(Value::as_str) == Some("tool_result"))
    })
}

fn last_message(body: &Value) -> Option<&Value> {
    body.get("messages")?.as_array()?.last()
}

pub fn is_new_turn(body: &Value) -> bool {
    last_message(body).is_some_and(|m| {
        m.get("role").and_then(Value::as_str) == Some("user")
            && !has_tool_result(&m["content"])
            && !content_text(&m["content"]).is_empty()
    })
}

pub fn last_user_text(body: &Value) -> String {
    last_message(body)
        .map(|m| content_text(&m["content"]))
        .unwrap_or_default()
}

/// Hash of the first user message plus the system prompt prefix: one key per conversation.
pub fn conv_key(body: &Value) -> String {
    let first = body["messages"]
        .as_array()
        .and_then(|a| a.iter().find(|m| m["role"] == "user"))
        .map(|m| content_text(&m["content"]))
        .unwrap_or_default();
    let sys: String = content_text(&body["system"]).chars().take(2000).collect();
    sha(&format!("{sys}\u{0}{first}"))
}

/// `!claude` / `!cheap` at the start of the latest user text forces this turn's route. The
/// prefix is removed from the body in place; returns the forced route.
pub fn take_force_prefix(body: &mut Value) -> Option<Route> {
    let last = body.get_mut("messages")?.as_array_mut()?.last_mut()?;
    fn strip(t: &str) -> Option<(Route, String)> {
        let t0 = t.trim_start();
        for (p, r) in [("!claude", Route::Claude), ("!cheap", Route::Cheap)] {
            if let Some(rest) = t0.strip_prefix(p) {
                if rest.is_empty() || rest.starts_with(char::is_whitespace) {
                    return Some((r, rest.trim_start().to_string()));
                }
            }
        }
        None
    }
    match &mut last["content"] {
        Value::String(s) => {
            let (r, rest) = strip(s)?;
            *s = rest;
            Some(r)
        }
        Value::Array(a) => a.iter_mut().find_map(|b| {
            let t = b.get("text")?.as_str()?;
            if t.trim_start().starts_with("<system-reminder>") {
                return None;
            }
            let (r, rest) = strip(t)?;
            b["text"] = Value::String(rest);
            Some(r)
        }),
        _ => None,
    }
}

const HARD: &[&str] = &[
    "architect",
    "design",
    "debug",
    "why ",
    "why?",
    "race condition",
    "a race",
    "data race",
    "leak",
    "security",
    "vulnerab",
    "review",
    "refactor",
    "migrate",
    "investigat",
    "root cause",
    "deadlock",
    "concurren",
    "performance",
    "optimi",
    "across the",
    "trade-off",
    "tradeoff",
];
const EASY: &[&str] = &[
    "write test",
    "add test",
    "unit test",
    "docstring",
    "rename",
    "boilerplate",
    "format",
    "explain",
    "typo",
    "add comment",
    "translate",
    "readme",
    "changelog",
    "lint",
];

/// Fast local classification; None = unclear (ask the router model).
pub fn classify(text: &str) -> Option<Class> {
    let t = text.to_lowercase();
    let words = t.split_whitespace().count();
    if t.chars().count() > 1200 || words < 4 {
        return Some(Class::Hard); // long or vague: stay on Claude
    }
    if HARD.iter().any(|k| t.contains(k)) {
        return Some(Class::Hard);
    }
    if t.chars().count() < 500 && EASY.iter().any(|k| t.contains(k)) {
        return Some(Class::Easy);
    }
    None
}

pub enum Step {
    Route(Route, String),
    /// Unclear: the caller asks the router model, then calls `settle`.
    Ask {
        hash: String,
    },
}

struct Turn {
    route: Route,
    reason: String,
    cheap_failures: u32,
}

#[derive(Default)]
struct Inner {
    convs: HashMap<String, Turn>,
    cache: HashMap<String, Class>,
}

#[derive(Default)]
pub struct Router {
    inner: Mutex<Inner>,
}

impl Router {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn set(g: &mut Inner, key: &str, route: Route, reason: &str) -> Step {
        g.convs.insert(
            key.to_string(),
            Turn {
                route,
                reason: reason.to_string(),
                cheap_failures: 0,
            },
        );
        Step::Route(route, reason.to_string())
    }

    /// Route for this request. `util` is Claude's 5-hour utilization in percent, if known.
    pub fn plan(
        &self,
        key: &str,
        new_turn: bool,
        mode: Mode,
        util: Option<f64>,
        force: Option<Route>,
        text: &str,
    ) -> Step {
        let mut g = self.lock();
        if !new_turn {
            if let Some(t) = g.convs.get(key) {
                return Step::Route(t.route, t.reason.clone());
            }
        }
        if let Some(r) = force {
            return Self::set(&mut g, key, r, "forced by prefix");
        }
        match mode {
            Mode::Claude => return Self::set(&mut g, key, Route::Claude, "claude mode"),
            Mode::Cheap => return Self::set(&mut g, key, Route::Cheap, "cheap mode"),
            Mode::Smart => {}
        }
        if util.is_some_and(|u| u >= CUTOFF_PCT) {
            return Self::set(&mut g, key, Route::Cheap, "Claude 5h limit at 90%");
        }
        if !new_turn {
            // unknown conversation (proxy restarted mid-task): stay on Claude
            return Self::set(&mut g, key, Route::Claude, "unknown conversation");
        }
        let hash = sha(text);
        let class = classify(text).or_else(|| g.cache.get(&hash).copied());
        match class {
            Some(Class::Hard) => Self::set(&mut g, key, Route::Claude, "hard prompt"),
            Some(Class::Easy) => Self::set(&mut g, key, Route::Cheap, "routine prompt"),
            None => Step::Ask { hash },
        }
    }

    /// Record the router model's answer (`None` = could not ask: treat as hard).
    pub fn settle(&self, key: &str, hash: &str, class: Option<Class>) -> (Route, String) {
        let mut g = self.lock();
        if let Some(c) = class {
            g.cache.insert(hash.to_string(), c);
        }
        let class = class.unwrap_or(Class::Hard);
        match Self::set(
            &mut g,
            key,
            if class == Class::Easy {
                Route::Cheap
            } else {
                Route::Claude
            },
            "router model",
        ) {
            Step::Route(r, why) => (r, why),
            Step::Ask { .. } => unreachable!(),
        }
    }

    /// Anthropic refused (429/529): this turn continues on the cheap model.
    pub fn pin_cheap(&self, key: &str, reason: &str) {
        Self::set(&mut self.lock(), key, Route::Cheap, reason);
    }

    pub fn cheap_ok(&self, key: &str) {
        if let Some(t) = self.lock().convs.get_mut(key) {
            t.cheap_failures = 0;
        }
    }

    /// A cheap request failed. After two in a row the turn goes back to Claude (unless the
    /// 5-hour limit is nearly used). Returns the route to use for the retry.
    pub fn cheap_failed(&self, key: &str, util: Option<f64>) -> Route {
        let mut g = self.lock();
        let Some(t) = g.convs.get_mut(key) else {
            return Route::Cheap;
        };
        t.cheap_failures += 1;
        if t.cheap_failures >= 2 && !util.is_some_and(|u| u >= CUTOFF_PCT) {
            t.route = Route::Claude;
            t.reason = "cheap model failed twice".into();
            t.cheap_failures = 0;
        }
        t.route
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Regression from the live smart bench: Claude Code puts its reminders and the prompt in
    /// one text block, and appends reminders to tool-result messages.
    #[test]
    fn prompt_inside_a_reminder_block_is_found_and_tool_results_are_not_new_turns() {
        let first = json!({"messages": [{"role": "user", "content": [
            {"type": "text", "text": "<system-reminder>\nCLAUDE.md says a lot of things\n</system-reminder>\nWrite unit tests for textkit/slug.py"}
        ]}]});
        assert!(is_new_turn(&first));
        assert_eq!(
            last_user_text(&first),
            "Write unit tests for textkit/slug.py"
        );
        assert_eq!(classify(&last_user_text(&first)), Some(Class::Easy));
        let tool_step = json!({"messages": [
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": [{"type": "tool_use", "id": "t", "name": "Read", "input": {}}]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "t", "content": "file"},
                {"type": "text", "text": "<system-reminder>todo list changed</system-reminder>"}
            ]}
        ]});
        assert!(!is_new_turn(&tool_step));
    }

    fn body(msgs: Value) -> Value {
        json!({"system": "You are Claude Code", "messages": msgs})
    }

    #[test]
    fn turn_detection() {
        let new = body(json!([{"role":"user","content":"write tests for foo"}]));
        assert!(is_new_turn(&new));
        let blocks = body(json!([{"role":"user","content":[{"type":"text","text":"hi there"}]}]));
        assert!(is_new_turn(&blocks));
        let tool = body(json!([
            {"role":"user","content":"x"},
            {"role":"assistant","content":[{"type":"tool_use","id":"1","name":"Read","input":{}}]},
            {"role":"user","content":[{"type":"tool_result","tool_use_id":"1","content":"ok"}]}
        ]));
        assert!(!is_new_turn(&tool));
        let reminder = body(json!([{"role":"user","content":[
            {"type":"tool_result","tool_use_id":"1","content":"ok"},
            {"type":"text","text":"<system-reminder>x</system-reminder>"}]}]));
        assert!(!is_new_turn(&reminder));
        // same conversation: same key at the first turn and in its tool loop
        let mut later = tool.clone();
        later["messages"][0]["content"] = json!("x");
        assert_eq!(conv_key(&tool), conv_key(&later));
    }

    #[test]
    fn prefix_is_stripped() {
        let mut b = body(json!([{"role":"user","content":"!cheap write tests for foo"}]));
        assert_eq!(take_force_prefix(&mut b), Some(Route::Cheap));
        assert_eq!(b["messages"][0]["content"], "write tests for foo");
        let mut b =
            body(json!([{"role":"user","content":[{"type":"text","text":"!claude  fix it"}]}]));
        assert_eq!(take_force_prefix(&mut b), Some(Route::Claude));
        assert_eq!(b["messages"][0]["content"][0]["text"], "fix it");
        let mut b = body(json!([{"role":"user","content":"!cheaper than that"}]));
        assert_eq!(take_force_prefix(&mut b), None);
    }

    #[test]
    fn heuristics_table() {
        let hard = [
            "design the architecture for the new billing service",
            "debug why the worker hangs after a few minutes",
            "there is a race condition in the cache, find it",
            "review this module for security problems",
            "refactor the parser across the whole package",
            "investigate the memory leak in the uploader",
            "fix it",
            "help",
            "optimize the slow query path in the report",
            &"please look at this and make everything better ".repeat(40),
        ];
        let easy = [
            "write tests for src/date.py",
            "add a docstring to every function in utils.py",
            "rename the variable foo to bar in config.py",
            "generate boilerplate for a new CLI subcommand",
            "format this file with the project style",
            "explain what the retry function does",
            "fix the typo in the README heading",
            "translate the error messages in strings.py to German",
        ];
        for t in hard {
            assert_eq!(classify(t), Some(Class::Hard), "{t}");
        }
        for t in easy {
            assert_eq!(classify(t), Some(Class::Easy), "{t}");
        }
        for t in [
            "update the function to handle empty input gracefully",
            "add a retry to the fetch call please",
        ] {
            assert_eq!(classify(t), None, "{t}");
        }
    }

    #[test]
    fn sticky_per_turn_and_cutoff() {
        let r = Router::default();
        let first = r.plan("k", true, Mode::Smart, None, None, "write tests for foo.py");
        assert!(matches!(first, Step::Route(Route::Cheap, _)));
        // follow-up in the tool loop keeps the route even if the text would now be hard
        let next = r.plan(
            "k",
            false,
            Mode::Smart,
            None,
            None,
            "design the architecture of everything",
        );
        assert!(matches!(next, Step::Route(Route::Cheap, _)));
        // a new turn is decided again
        let t2 = r.plan(
            "k",
            true,
            Mode::Smart,
            None,
            None,
            "debug why the worker hangs after a while",
        );
        assert!(matches!(t2, Step::Route(Route::Claude, _)));
        // 90% cutoff
        let t3 = r.plan(
            "k",
            true,
            Mode::Smart,
            Some(91.0),
            None,
            "debug why the worker hangs after a while",
        );
        assert!(matches!(t3, Step::Route(Route::Cheap, _)));
        let t4 = r.plan(
            "k",
            true,
            Mode::Smart,
            Some(89.0),
            None,
            "debug why the worker hangs after a while",
        );
        assert!(matches!(t4, Step::Route(Route::Claude, _)));
        // forced
        let t5 = r.plan(
            "k",
            true,
            Mode::Smart,
            None,
            Some(Route::Cheap),
            "debug why this fails today",
        );
        assert!(matches!(t5, Step::Route(Route::Cheap, _)));
    }

    #[test]
    fn unclear_asks_and_blocked_router_means_hard() {
        let r = Router::default();
        let t = "update the function to handle empty input gracefully";
        let Step::Ask { hash } = r.plan("k", true, Mode::Smart, None, None, t) else {
            panic!()
        };
        assert_eq!(r.settle("k", &hash, None).0, Route::Claude);
        let Step::Ask { hash } = r.plan("k2", true, Mode::Smart, None, None, t) else {
            panic!()
        };
        assert_eq!(r.settle("k2", &hash, Some(Class::Easy)).0, Route::Cheap);
        // cached now
        assert!(matches!(
            r.plan("k3", true, Mode::Smart, None, None, t),
            Step::Route(Route::Cheap, _)
        ));
    }

    #[test]
    fn two_cheap_failures_switch_to_claude() {
        let r = Router::default();
        r.plan("k", true, Mode::Cheap, None, None, "x y z w");
        assert_eq!(r.cheap_failed("k", None), Route::Cheap);
        assert_eq!(r.cheap_failed("k", None), Route::Claude);
        r.plan("j", true, Mode::Cheap, None, None, "x y z w");
        r.cheap_failed("j", Some(95.0));
        assert_eq!(r.cheap_failed("j", Some(95.0)), Route::Cheap);
    }
}
