//! The `cheap:` direct path. A prompt that starts with `cheap:` (or `/delegate`) is run by
//! the UserPromptSubmit hook itself, through the full pipeline, and blocked
//! (`decision: "block"`) so it never reaches Claude: Claude spends nothing on it.
//!
//! Syntax: `cheap: <task> <file>[:start-end] [more files] [-> output]`, for example
//! `cheap: write tests for src/date.py -> tests/test_date.py`. When the task or the files
//! cannot be read off the prompt, nothing is guessed: the prompt is blocked with the syntax.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::json;

use crate::classify::Declared;
use crate::economics::WriteMode;
use crate::intake::FileRef;
use crate::pipeline::{DelegateOutcome, DelegateRequest, Status};
use crate::TaskKind;

pub const SYNTAX: &str = "cheap: <task> <file>[:start-end] [-> output]";
pub const EXAMPLE: &str = "cheap: write tests for src/date.py -> tests/test_date.py";

/// The prompt text after the `cheap:` / `/delegate` prefix, or None.
pub fn body(prompt: &str) -> Option<&str> {
    let t = prompt.trim_start();
    for p in ["cheap:", "/delegate"] {
        if t.len() >= p.len() && t[..p.len()].eq_ignore_ascii_case(p) {
            return Some(t[p.len()..].trim());
        }
    }
    None
}

static KINDS: LazyLock<Vec<(TaskKind, Regex)>> = LazyLock::new(|| {
    let k = |t, re: &str| (t, Regex::new(&format!("(?i){re}")).expect("static regex"));
    vec![
        k(
            TaskKind::WriteTests,
            r"\b(?:unit[ -])?tests?\b|\btest(?:ler|leri|lerini|lerin)?\b|\bbirim test",
        ),
        k(
            TaskKind::Docstring,
            r"\bdocstrings?\b|\bdocs\b|\bdocument\b|\bdoc ?comments?\b|\bjsdoc\b|\byorum(?:lar)?\b|\bdok[üu]mant\w*",
        ),
        k(
            TaskKind::Summarize,
            r"\bsummari[sz]e\b|\bsummary\b|\btl;?dr\b|\b[öo]zetle\w*|\b[öo]zet\b",
        ),
        k(TaskKind::Translate, r"\btranslate\b|\b[çc]evir\w*"),
        k(
            TaskKind::Boilerplate,
            r"\bboilerplate\b|\bscaffold\w*|\biskelet\w*|\b[şs]ablon\w*",
        ),
        k(TaskKind::Explain, r"\bexplain\b|\ba[çc][ıi]kla\w*"),
    ]
});

/// `path[:start-end]` tokens; the output arrow is handled separately.
static PATH_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:^|[\s"'`(\[])((?:\.{1,2}/|/|~/)?[A-Za-z0-9_\-][A-Za-z0-9_.\-/]*(?:\.[A-Za-z0-9]{1,10}|/[A-Za-z0-9_\-]+))(?::(\d+)-(\d+))?"#)
        .expect("static regex")
});
static ARROW: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?:->|→|=>)\s*([^\s"'`]+)"#).expect("static regex"));

#[derive(Debug, Clone, PartialEq)]
pub struct Parsed {
    pub kind: TaskKind,
    /// (absolute path, start, end)
    pub files: Vec<(PathBuf, Option<usize>, Option<usize>)>,
    /// Absolute output path.
    pub output: PathBuf,
    /// The prompt body without the `-> output` part (the output path is local only).
    pub instructions: String,
}

fn resolve(tok: &str, root: &Path, cwd: &Path) -> Option<PathBuf> {
    let tok = tok.trim_end_matches(['.', ',', ';', ':', ')']);
    let p = if let Some(rest) = tok.strip_prefix("~/") {
        PathBuf::from(std::env::var_os("HOME")?).join(rest)
    } else {
        PathBuf::from(tok)
    };
    let cands = if p.is_absolute() {
        vec![p]
    } else {
        vec![cwd.join(&p), root.join(&p)]
    };
    cands
        .into_iter()
        .filter(|c| c.is_file())
        .filter_map(|c| std::fs::canonicalize(c).ok())
        .find(|c| c.starts_with(root))
}

fn stem_ext(p: &Path) -> (String, String) {
    let stem = p
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "out".into());
    let ext = p
        .extension()
        .map(|e| e.to_string_lossy().to_string())
        .unwrap_or_else(|| "txt".into());
    (stem, ext)
}

/// Where the result goes when the prompt names no `-> output`.
pub fn default_output(kind: TaskKind, first: &Path, root: &Path) -> PathBuf {
    let (stem, ext) = stem_ext(first);
    let dir = first.parent().unwrap_or(root);
    let out = root.join(".middleman/out");
    match kind {
        TaskKind::WriteTests => match ext.as_str() {
            "py" if root.join("tests").is_dir() => root.join(format!("tests/test_{stem}.py")),
            "py" => dir.join(format!("test_{stem}.py")),
            "js" | "ts" | "jsx" | "tsx" | "mjs" | "cjs" => dir.join(format!("{stem}.test.{ext}")),
            "go" => dir.join(format!("{stem}_test.go")),
            "rs" => root.join(format!("tests/{stem}.rs")),
            "rb" => root.join(format!("spec/{stem}_spec.rb")),
            "java" | "kt" => out.join(format!("{stem}Test.{ext}")),
            _ => out.join(format!("test_{stem}.{ext}")),
        },
        // the documented file itself: it exists, so it is staged with a patch, never replaced
        TaskKind::Docstring => first.to_path_buf(),
        TaskKind::Summarize => out.join(format!("{stem}.summary.md")),
        TaskKind::Explain => out.join(format!("{stem}.explain.md")),
        TaskKind::Translate => out.join(format!("{stem}.translated.{ext}")),
        _ => out.join(format!("{stem}.{kind}.{ext}")),
    }
}

/// Parse a `cheap:` prompt body against the project root. Errors are messages for the user.
pub fn parse(body: &str, root: &Path, cwd: &Path) -> Result<Parsed, String> {
    if body.is_empty() {
        return Err("nothing after `cheap:`".into());
    }
    let (text, out_tok) = match ARROW.captures(body) {
        Some(c) => {
            let m = c.get(0).unwrap();
            let rest = format!("{} {}", &body[..m.start()], &body[m.end()..]);
            (rest.trim().to_string(), Some(c[1].to_string()))
        }
        None => (body.to_string(), None),
    };
    let mut files = vec![];
    let mut kind_text = text.clone();
    for c in PATH_TOKEN.captures_iter(&text) {
        let tok = c.get(1).unwrap().as_str();
        let Some(abs) = resolve(tok, root, cwd) else {
            continue;
        };
        let range = match (c.get(2), c.get(3)) {
            (Some(a), Some(b)) => {
                let (a, b) = (a.as_str().parse().ok(), b.as_str().parse().ok());
                match (a, b) {
                    (Some(a), Some(b)) if a >= 1 && b >= a => (Some(a), Some(b)),
                    _ => {
                        return Err(format!(
                            "bad line range in {}",
                            c.get(0).unwrap().as_str().trim()
                        ))
                    }
                }
            }
            _ => (None, None),
        };
        if !files.iter().any(|(p, _, _)| *p == abs) {
            files.push((abs, range.0, range.1));
        }
        // path words must not decide the task (`tests/x.py` is not "write tests")
        kind_text = kind_text.replace(c.get(0).unwrap().as_str(), " ");
    }
    let kind = KINDS
        .iter()
        .filter_map(|(k, re)| re.find(&kind_text).map(|m| (m.start(), *k)))
        .min_by_key(|(at, _)| *at)
        .map(|(_, k)| k)
        .ok_or_else(|| {
            "no task found: say tests, docstrings, summarize, translate, boilerplate or explain"
                .to_string()
        })?;
    let output = match &out_tok {
        Some(o) => {
            let p = PathBuf::from(o);
            if p.is_absolute() {
                p
            } else {
                cwd.join(p)
            }
        }
        None => match files.first() {
            Some((f, _, _)) => default_output(kind, f, root),
            None => {
                return Err(if out_tok.is_none() && kind == TaskKind::Boilerplate {
                    "boilerplate without an input file needs an output: `-> path`".into()
                } else {
                    "no file found: name an existing file under the project root".into()
                })
            }
        },
    };
    if files.is_empty() && kind != TaskKind::Boilerplate {
        return Err("no file found: name an existing file under the project root".into());
    }
    Ok(Parsed {
        kind,
        files,
        output,
        instructions: text,
    })
}

impl Parsed {
    pub fn request(&self, session_id: Option<String>) -> DelegateRequest {
        let mut r = DelegateRequest::simple(self.kind, &self.instructions, Declared::Internal);
        r.files = self
            .files
            .iter()
            .map(|(p, s, e)| FileRef {
                path: p.to_string_lossy().into_owned(),
                start_line: *s,
                end_line: *e,
            })
            .collect();
        r.write_mode = Some(WriteMode::File);
        r.output_path = Some(self.output.to_string_lossy().into_owned());
        r.user_requested = true;
        r.via_hook = true;
        r.call_chars = Some(0);
        r.session_id = session_id;
        r
    }
}

fn rel(p: &str, root: &Path) -> String {
    Path::new(p)
        .strip_prefix(root)
        .map(|r| r.to_string_lossy().into_owned())
        .unwrap_or_else(|_| p.to_string())
}

/// The block message for an unparseable prompt.
pub fn usage_message(why: &str) -> String {
    format!(
        "🛡 middleman · cheap: not run (Claude was not asked either)\n  why      {why}\n  syntax   {SYNTAX}\n  e.g.     {EXAMPLE}\n  tasks    tests, docstrings, summarize, translate, boilerplate, explain\n  or       drop the `cheap:` prefix to ask Claude"
    )
}

/// The block message for a refused prompt (sensitive topic).
pub fn refused_message(topics: &[String]) -> String {
    format!(
        "🛡 middleman · cheap: not run\n  why      looks sensitive ({}): this stays on Claude\n  or       drop the `cheap:` prefix to ask Claude",
        topics.join(", ")
    )
}

/// The block message after a pipeline run.
pub fn outcome_message(out: &DelegateOutcome, root: &Path) -> String {
    let mut l = vec![];
    let model = match (&out.provider, &out.model) {
        (Some(p), Some(m)) => format!("{p}/{m}"),
        _ => "-".into(),
    };
    let net = out
        .savings
        .as_ref()
        .map(|s| s.net_savings_usd)
        .unwrap_or(0.0);
    match out.status {
        Status::Ok => {
            l.push("🛡 middleman · cheap: done by a cheap model; Claude spent 0 tokens".to_string());
            l.push(format!("  model    {model}"));
            let review = if let Some(w) = &out.written {
                let path = rel(&w.path, root);
                if let Some(st) = &w.staged_path {
                    l.push(format!(
                        "  staged   {} ({} lines; {path} exists or the output is risky)",
                        rel(st, root),
                        w.lines
                    ));
                    if let Some(pp) = &w.patch_path {
                        l.push(format!("  patch    {}", rel(pp, root)));
                    }
                    rel(st, root)
                } else {
                    l.push(format!("  wrote    {path} ({} lines)", w.lines));
                    path
                }
            } else {
                "the output".into()
            };
            l.push(format!(
                "  cost     ${:.5} · net saving ~${net:.4}",
                out.cost_usd
            ));
            if let Some(r) = &out.risk {
                if r.is_high() {
                    l.push("  risk     HIGH: read it before running anything".into());
                    for f in r.findings.iter().take(5) {
                        l.push(format!("           - {f}"));
                    }
                } else {
                    l.push("  risk     low".into());
                }
            }
            for w in out.warnings.iter().take(3) {
                l.push(format!("  note     {}", crate::fsutil::clean(w, 160)));
            }
            l.push(format!(
                "  next     review it yourself, or ask Claude: \"review {review}\""
            ));
        }
        Status::Blocked | Status::Error => {
            let why = out
                .block_reason
                .as_deref()
                .or(out.error.as_deref())
                .unwrap_or("unknown");
            l.push("🛡 middleman · cheap: not run".into());
            l.push(format!("  why      {}", crate::fsutil::clean(why, 300)));
            if out.cost_usd > 0.0 {
                l.push(format!("  cost     ${:.5}", out.cost_usd));
            }
            l.push("  next     fix and retry, or drop the `cheap:` prefix and ask Claude".into());
        }
    }
    l.join("\n")
}

/// UserPromptSubmit output that stops the prompt (the reason is shown to the user only).
pub fn block_json(reason: &str) -> String {
    json!({"decision": "block", "reason": reason}).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project() -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().canonicalize().unwrap();
        for f in [
            "src/date.py",
            "src/util.ts",
            "pkg/clock.go",
            "src/lib.rs",
            "README.md",
            "docs/guide.md",
            "tests/test_other.py",
        ] {
            let p = root.join(f);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, "x\n").unwrap();
        }
        (d, root)
    }

    #[test]
    fn prefix() {
        assert_eq!(body("cheap: write tests"), Some("write tests"));
        assert_eq!(body("  CHEAP:write tests"), Some("write tests"));
        assert_eq!(body("/delegate summarize x"), Some("summarize x"));
        assert_eq!(body("write tests, cheap: please"), None);
        assert_eq!(body("cheapest model?"), None);
    }

    #[test]
    fn parse_table() {
        let (_d, root) = project();
        let r = |p: &str| root.join(p);
        type Want = Option<(
            TaskKind,
            Vec<(&'static str, Option<usize>, Option<usize>)>,
            &'static str,
        )>;
        let table: Vec<(&str, Want)> = vec![
            (
                "write tests for src/date.py -> tests/test_date.py",
                Some((
                    TaskKind::WriteTests,
                    vec![("src/date.py", None, None)],
                    "tests/test_date.py",
                )),
            ),
            (
                "write tests for src/date.py",
                Some((
                    TaskKind::WriteTests,
                    vec![("src/date.py", None, None)],
                    "tests/test_date.py",
                )),
            ),
            (
                "unit tests for src/util.ts",
                Some((
                    TaskKind::WriteTests,
                    vec![("src/util.ts", None, None)],
                    "src/util.test.ts",
                )),
            ),
            (
                "tests for pkg/clock.go",
                Some((
                    TaskKind::WriteTests,
                    vec![("pkg/clock.go", None, None)],
                    "pkg/clock_test.go",
                )),
            ),
            (
                "add tests for src/lib.rs:10-40",
                Some((
                    TaskKind::WriteTests,
                    vec![("src/lib.rs", Some(10), Some(40))],
                    "tests/lib.rs",
                )),
            ),
            (
                "src/date.py için test yaz",
                Some((
                    TaskKind::WriteTests,
                    vec![("src/date.py", None, None)],
                    "tests/test_date.py",
                )),
            ),
            (
                "add docstrings to src/date.py",
                Some((
                    TaskKind::Docstring,
                    vec![("src/date.py", None, None)],
                    "src/date.py",
                )),
            ),
            (
                "document src/util.ts:1-20",
                Some((
                    TaskKind::Docstring,
                    vec![("src/util.ts", Some(1), Some(20))],
                    "src/util.ts",
                )),
            ),
            (
                "docs for src/date.py -> docs/date.md",
                Some((
                    TaskKind::Docstring,
                    vec![("src/date.py", None, None)],
                    "docs/date.md",
                )),
            ),
            (
                "summarize README.md",
                Some((
                    TaskKind::Summarize,
                    vec![("README.md", None, None)],
                    ".middleman/out/README.summary.md",
                )),
            ),
            (
                "README.md dosyasını özetle",
                Some((
                    TaskKind::Summarize,
                    vec![("README.md", None, None)],
                    ".middleman/out/README.summary.md",
                )),
            ),
            (
                "tl;dr of docs/guide.md and README.md",
                Some((
                    TaskKind::Summarize,
                    vec![("docs/guide.md", None, None), ("README.md", None, None)],
                    ".middleman/out/guide.summary.md",
                )),
            ),
            (
                "translate docs/guide.md to German",
                Some((
                    TaskKind::Translate,
                    vec![("docs/guide.md", None, None)],
                    ".middleman/out/guide.translated.md",
                )),
            ),
            (
                "docs/guide.md dosyasını Türkçeye çevir",
                Some((
                    TaskKind::Translate,
                    vec![("docs/guide.md", None, None)],
                    ".middleman/out/guide.translated.md",
                )),
            ),
            (
                "explain src/lib.rs",
                Some((
                    TaskKind::Explain,
                    vec![("src/lib.rs", None, None)],
                    ".middleman/out/lib.explain.md",
                )),
            ),
            (
                "src/lib.rs ne yapıyor, açıkla",
                Some((
                    TaskKind::Explain,
                    vec![("src/lib.rs", None, None)],
                    ".middleman/out/lib.explain.md",
                )),
            ),
            (
                "boilerplate for a CLI with 3 subcommands -> src/cli.rs",
                Some((TaskKind::Boilerplate, vec![], "src/cli.rs")),
            ),
            (
                "scaffold like src/lib.rs -> src/other.rs",
                Some((
                    TaskKind::Boilerplate,
                    vec![("src/lib.rs", None, None)],
                    "src/other.rs",
                )),
            ),
            // the test words inside a path do not make it a test task
            (
                "summarize tests/test_other.py",
                Some((
                    TaskKind::Summarize,
                    vec![("tests/test_other.py", None, None)],
                    ".middleman/out/test_other.summary.md",
                )),
            ),
            (
                "explain `./src/date.py`.",
                Some((
                    TaskKind::Explain,
                    vec![("src/date.py", None, None)],
                    ".middleman/out/date.explain.md",
                )),
            ),
            // ambiguous: no guessing
            ("write tests for src/missing.py", None),
            ("make src/date.py better", None),
            ("write tests", None),
            ("boilerplate for a CLI", None),
            ("", None),
            ("tests for src/date.py:9-3", None),
            ("tests for ../outside.py", None),
        ];
        assert!(table.len() >= 20);
        for (p, want) in table {
            let got = parse(p, &root, &root);
            match want {
                None => assert!(got.is_err(), "{p}: {got:?}"),
                Some((k, files, out)) => {
                    let g = got.unwrap_or_else(|e| panic!("{p}: {e}"));
                    assert_eq!(g.kind, k, "{p}");
                    let fs: Vec<_> = files.iter().map(|(f, a, b)| (r(f), *a, *b)).collect();
                    assert_eq!(g.files, fs, "{p}");
                    assert_eq!(g.output, r(out), "{p}");
                    assert!(!g.instructions.contains("->"), "{p}");
                }
            }
        }
    }

    #[test]
    fn request_is_user_approved_file_mode() {
        let (_d, root) = project();
        let p = parse("write tests for src/date.py", &root, &root).unwrap();
        let r = p.request(Some("s1".into()));
        assert!(r.via_hook && r.user_requested && r.call_chars == Some(0));
        assert_eq!(r.write_mode, Some(WriteMode::File));
        assert_eq!(r.declared_sensitivity, Declared::Internal);
        let m = usage_message("no file found");
        assert!(m.contains(EXAMPLE) && m.contains(SYNTAX));
        let v: serde_json::Value = serde_json::from_str(&block_json(&m)).unwrap();
        assert_eq!(v["decision"], "block");
    }
}
