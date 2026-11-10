//! `middleman setup claude`: wire middleman into Claude Code in one step.
//!
//! What it touches (user scope / project scope):
//! - MCP server `middleman`: `~/.claude.json` `mcpServers` / `<project>/.mcp.json` `mcpServers`
//! - `permissions.allow` for the two tools, the `UserPromptSubmit` hook and (optionally) the
//!   `statusLine`: `~/.claude/settings.json` / `<project>/.claude/settings.json`
//! - the CLAUDE.md block: `~/.claude/CLAUDE.md` / `<project>/CLAUDE.md`
//!
//! `plan` computes the exact edits without writing; `apply` backs up every file it touches
//! (0600, in a 0700 dir under the state dir), writes a manifest, then replaces each file
//! atomically. Unrelated keys are preserved (and their order, via serde_json's
//! `preserve_order`). `undo` restores the backups; if a file changed since (Claude Code
//! rewrites `~/.claude.json` often), it removes only middleman's entries instead.

/// Seconds Claude Code waits for the prompt hook. Ordinary prompts return in milliseconds; a
/// `cheap:` prompt runs the delegation itself (provider timeout 120 s by default).
pub const HOOK_TIMEOUT_S: u64 = 150;

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::fsutil::{pretty, shell_quote, write_atomic};
use crate::setup::{Check, Scope};

pub const TOOLS: [&str; 2] = [
    "mcp__middleman__delegate_task",
    "mcp__middleman__middleman_status",
];
pub const MD_BEGIN: &str = "<!-- middleman:begin (managed by `middleman setup claude`) -->";
pub const MD_END: &str = "<!-- middleman:end -->";

pub struct SetupOptions {
    pub scope: Scope,
    pub home: PathBuf,
    pub project_dir: PathBuf,
    pub exe: PathBuf,
    pub config_path: PathBuf,
    pub hook: bool,
    pub statusline: bool,
    /// Replace a status line that is not middleman's with middleman's full two-line one
    /// (model, context, cost, cache, then middleman); the old one is restored by `--undo`.
    pub statusline_combined: bool,
    pub claude_md: bool,
    pub permissions: bool,
}

impl SetupOptions {
    pub fn mcp_file(&self) -> PathBuf {
        match self.scope {
            Scope::User => self.home.join(".claude.json"),
            Scope::Project => self.project_dir.join(".mcp.json"),
        }
    }
    pub fn settings_file(&self) -> PathBuf {
        match self.scope {
            Scope::User => self.home.join(".claude").join("settings.json"),
            Scope::Project => self.project_dir.join(".claude").join("settings.json"),
        }
    }
    pub fn claude_md_file(&self) -> PathBuf {
        match self.scope {
            Scope::User => self.home.join(".claude").join("CLAUDE.md"),
            Scope::Project => self.project_dir.join("CLAUDE.md"),
        }
    }
    fn exe_s(&self) -> String {
        self.exe.display().to_string()
    }
    fn cfg_s(&self) -> String {
        self.config_path.display().to_string()
    }
    pub fn hook_command(&self) -> String {
        format!(
            "{} route --hook --config {}",
            shell_quote(&self.exe_s()),
            shell_quote(&self.cfg_s())
        )
    }
    pub fn statusline_command(&self) -> String {
        format!(
            "{} statusline {}--config {}",
            shell_quote(&self.exe_s()),
            if self.statusline_combined {
                "--lines 2 "
            } else {
                ""
            },
            shell_quote(&self.cfg_s())
        )
    }
    /// What to append to another status line script to add middleman's part.
    pub fn statusline_chain_command(&self) -> String {
        format!(
            "{} statusline --middleman-only --config {}",
            shell_quote(&self.exe_s()),
            shell_quote(&self.cfg_s())
        )
    }
    pub fn mcp_entry(&self) -> Value {
        json!({"type": "stdio", "command": self.exe_s(), "args": ["mcp", "--config", self.cfg_s()], "env": {}})
    }
}

/// The CLAUDE.md text (the fenced block of `docs/CLAUDE-snippet.md`).
pub fn snippet() -> &'static str {
    let doc = include_str!("../docs/CLAUDE-snippet.md");
    let start = doc.find("```markdown\n").map(|i| i + 12).unwrap_or(0);
    let end = doc[start..]
        .rfind("\n```")
        .map(|i| start + i)
        .unwrap_or(doc.len());
    &doc[start..end]
}

fn md_block() -> String {
    format!("{MD_BEGIN}\n{}\n{MD_END}\n", snippet().trim_end())
}

/// How to take one edit back when the file changed after `apply`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Revert {
    SetKey {
        path: Vec<String>,
        before: Option<Value>,
    },
    ArrayPush {
        path: Vec<String>,
        item: Value,
    },
    ArrayReplace {
        path: Vec<String>,
        before: Value,
        after: Value,
    },
    MdBlock {
        before: Option<String>,
    },
}

#[derive(Debug, Clone)]
pub struct FilePlan {
    pub path: PathBuf,
    pub existed: bool,
    pub before: String,
    pub after: String,
    /// One technical line per edit (keys and values), for `--details`.
    pub changes: Vec<String>,
    /// One plain-words line per edit, for the normal preview.
    pub summary: Vec<String>,
    pub reverts: Vec<Revert>,
    new_mode: u32,
}

#[derive(Debug, Clone, Default)]
pub struct Plan {
    pub files: Vec<FilePlan>,
    pub notes: Vec<String>,
}

impl Plan {
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Plain-words preview without styling.
    pub fn render(&self) -> String {
        self.render_ui(&crate::ui::Ui::plain(), false)
    }

    /// The preview: per file, one plain-words line per change; with `details`, the exact
    /// keys and values as well.
    pub fn render_ui(&self, ui: &crate::ui::Ui, details: bool) -> String {
        let mut s = String::new();
        if self.files.is_empty() {
            s.push_str(&format!(
                "  {}\n",
                ui.ok("Claude Code is already set up for middleman; nothing to change.")
            ));
        } else {
            s.push_str(&format!(
                "  Claude Code will be changed like this {}:\n",
                ui.dim("(every file is backed up first; `middleman setup claude --undo` reverts)")
            ));
        }
        for f in &self.files {
            s.push_str(&format!(
                "\n  {}{}\n",
                ui.bold(&pretty(&f.path)),
                if f.existed {
                    String::new()
                } else {
                    ui.dim(" (new file)")
                }
            ));
            for line in &f.summary {
                let (mark, rest) = line.split_at(line.find(' ').unwrap_or(0));
                let mark = match mark {
                    "+" => ui.green("+"),
                    "~" => ui.yellow("~"),
                    m => m.to_string(),
                };
                s.push_str(&format!("    {mark}{rest}\n"));
            }
            if details {
                for c in &f.changes {
                    for line in c.lines() {
                        s.push_str(&format!("        {}\n", ui.dim(line)));
                    }
                }
            }
        }
        for n in &self.notes {
            s.push_str(&format!("\n  {}\n", ui.warn(n)));
        }
        s
    }
}

fn compact(v: &Value) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

fn read_text(path: &Path) -> Result<(bool, String)> {
    match std::fs::read_to_string(path) {
        Ok(t) => Ok((true, t)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((false, String::new())),
        Err(e) => Err(e).with_context(|| format!("cannot read {}", path.display())),
    }
}

fn parse_json(path: &Path, text: &str) -> Result<Value> {
    if text.trim().is_empty() {
        return Ok(json!({}));
    }
    let v: Value = serde_json::from_str(text).with_context(|| {
        format!(
            "{} is not valid JSON; fix it first (nothing was changed)",
            path.display()
        )
    })?;
    if !v.is_object() {
        bail!(
            "{} is not a JSON object; nothing was changed",
            path.display()
        );
    }
    Ok(v)
}

fn to_text(v: &Value, before: &str) -> String {
    let mut s = serde_json::to_string_pretty(v).unwrap_or_default();
    if before.is_empty() || before.ends_with('\n') {
        s.push('\n');
    }
    s
}

/// The object at `path` (creating empty objects on the way). Errors if something on the
/// way is not an object, so a surprising file is never clobbered.
fn obj_at<'a>(
    root: &'a mut Value,
    path: &[String],
    file: &Path,
) -> Result<&'a mut Map<String, Value>> {
    let mut cur = root;
    for (i, k) in path.iter().enumerate() {
        let m = cur
            .as_object_mut()
            .with_context(|| not_object(file, &path[..i]))?;
        cur = m.entry(k.clone()).or_insert_with(|| json!({}));
    }
    cur.as_object_mut().with_context(|| not_object(file, path))
}

fn not_object(file: &Path, path: &[String]) -> String {
    format!(
        "{}: `{}` is not an object; nothing was changed",
        file.display(),
        if path.is_empty() {
            "<root>".into()
        } else {
            path.join(".")
        }
    )
}

fn arr_at<'a>(root: &'a mut Value, path: &[String], file: &Path) -> Result<&'a mut Vec<Value>> {
    let (last, parent) = path.split_last().expect("non-empty path");
    let m = obj_at(root, parent, file)?;
    m.entry(last.clone())
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .with_context(|| {
            format!(
                "{}: `{}` is not an array; nothing was changed",
                file.display(),
                path.join(".")
            )
        })
}

fn p(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

fn get<'a>(root: &'a Value, path: &[String]) -> Option<&'a Value> {
    path.iter().try_fold(root, |v, k| v.get(k))
}

struct JsonEdit {
    path: PathBuf,
    existed: bool,
    before: String,
    value: Value,
    changes: Vec<String>,
    summary: Vec<String>,
    reverts: Vec<Revert>,
}

impl JsonEdit {
    /// Remove a top-level-or-nested key (undo puts it back).
    fn remove(&mut self, path: Vec<String>, human: &str) -> Result<()> {
        let Some(old) = get(&self.value, &path).cloned() else {
            return Ok(());
        };
        let (last, parent) = path.split_last().expect("non-empty path");
        obj_at(&mut self.value, parent, &self.path)?.remove(last);
        self.summary.push(format!("- {human}"));
        self.changes
            .push(format!("- {} = {}", path.join("."), compact(&old)));
        self.reverts.push(Revert::SetKey {
            path,
            before: Some(old),
        });
        Ok(())
    }

    fn open(path: PathBuf) -> Result<JsonEdit> {
        let (existed, before) = read_text(&path)?;
        let value = parse_json(&path, &before)?;
        Ok(JsonEdit {
            path,
            existed,
            before,
            value,
            changes: vec![],
            summary: vec![],
            reverts: vec![],
        })
    }

    fn set(&mut self, path: Vec<String>, new: Value, human: &str) -> Result<()> {
        let old = get(&self.value, &path).cloned();
        if old.as_ref() == Some(&new) {
            return Ok(());
        }
        self.summary.push(match old {
            None => format!("+ {human}"),
            Some(_) => format!("~ {human} (replaces the old entry)"),
        });
        let (last, parent) = path.split_last().expect("non-empty path");
        obj_at(&mut self.value, parent, &self.path)?.insert(last.clone(), new.clone());
        self.changes.push(match &old {
            None => format!("+ {} = {}", path.join("."), compact(&new)),
            Some(o) => format!(
                "~ {}: {}\n  -> {}",
                path.join("."),
                compact(o),
                compact(&new)
            ),
        });
        self.reverts.push(Revert::SetKey { path, before: old });
        Ok(())
    }

    fn push_unique(&mut self, path: Vec<String>, item: Value, human: &str) -> Result<()> {
        let arr = arr_at(&mut self.value, &path, &self.path)?;
        if arr.contains(&item) {
            return Ok(());
        }
        arr.push(item.clone());
        self.summary.push(format!("+ {human}"));
        self.changes
            .push(format!("+ {} += {}", path.join("."), compact(&item)));
        self.reverts.push(Revert::ArrayPush { path, item });
        Ok(())
    }

    fn replace_item(
        &mut self,
        path: Vec<String>,
        idx: usize,
        item: Value,
        human: &str,
    ) -> Result<()> {
        let arr = arr_at(&mut self.value, &path, &self.path)?;
        let old = std::mem::replace(&mut arr[idx], item.clone());
        self.summary
            .push(format!("~ {human} (replaces the old middleman entry)"));
        self.changes.push(format!(
            "~ {}[{idx}]: {}\n  -> {}",
            path.join("."),
            compact(&old),
            compact(&item)
        ));
        self.reverts.push(Revert::ArrayReplace {
            path,
            before: old,
            after: item,
        });
        Ok(())
    }

    fn finish(self, new_mode: u32) -> Option<FilePlan> {
        if self.changes.is_empty() {
            return None;
        }
        let after = to_text(&self.value, &self.before);
        Some(FilePlan {
            path: self.path,
            existed: self.existed,
            before: self.before,
            after,
            changes: self.changes,
            summary: self.summary,
            reverts: self.reverts,
            new_mode,
        })
    }
}

impl JsonEdit {
    /// `set`, with a plain `~ {human}` summary line.
    fn update(&mut self, path: Vec<String>, new: Value, human: &str) -> Result<()> {
        let n = self.summary.len();
        self.set(path, new, human)?;
        if self.summary.len() > n {
            *self.summary.last_mut().expect("pushed") = format!("~ {human}");
        }
        Ok(())
    }
}

/// The first word of a shell command line, unquoted, and the rest verbatim. None when the
/// word is not a plain path (unquoted shell syntax, unbalanced quotes).
fn first_word(cmd: &str) -> Option<(String, &str)> {
    let s = cmd.trim_start();
    let mut word = String::new();
    let mut it = s.char_indices();
    let mut end = s.len();
    while let Some((i, c)) = it.next() {
        match c {
            c if c.is_whitespace() => {
                end = i;
                break;
            }
            '\'' => loop {
                match it.next()? {
                    (_, '\'') => break,
                    (_, ch) => word.push(ch),
                }
            },
            '"' => loop {
                match it.next()? {
                    (_, '"') => break,
                    (_, '\\') => word.push(it.next()?.1),
                    (_, ch) if "$`".contains(ch) => return None,
                    (_, ch) => word.push(ch),
                }
            },
            '\\' => word.push(it.next()?.1),
            c if c.is_ascii_alphanumeric() || "/._-+:=@%,".contains(c) => word.push(c),
            _ => return None,
        }
    }
    (!word.is_empty()).then(|| (word, &s[end..]))
}

/// A middleman binary path: absolute, file name `middleman` (or `middleman.exe`).
fn is_middleman_path(p: &str) -> bool {
    let p = Path::new(p);
    p.is_absolute()
        && p.file_name()
            .is_some_and(|n| n == "middleman" || n == "middleman.exe")
}

/// For a command middleman wrote (`<middleman> <sub> ...`): the binary path and the rest.
fn our_command<'a>(cmd: &'a str, sub: &str) -> Option<(String, &'a str)> {
    let (word, rest) = first_word(cmd)?;
    let after = rest.trim_start();
    let sub_ok = after == sub
        || after
            .strip_prefix(sub)
            .is_some_and(|r| r.starts_with(char::is_whitespace));
    (is_middleman_path(&word) && sub_ok).then_some((word, rest))
}

/// The same command pointing at `exe` (None when it already does).
fn repoint(cmd: &str, sub: &str, exe: &str) -> Option<String> {
    let (word, rest) = our_command(cmd, sub)?;
    (word != exe).then(|| format!("{}{rest}", shell_quote(exe)))
}

pub struct RefreshOptions {
    pub home: PathBuf,
    /// Projects to look at (the current dir, and every project `setup claude` wrote to).
    pub project_dirs: Vec<PathBuf>,
    pub exe: PathBuf,
    /// Used only when an existing MCP entry names no `--config`.
    pub config_path: PathBuf,
}

/// The project a file written by `setup claude --scope project` belongs to.
fn project_dir_of(file: &Path, home: &Path) -> Option<PathBuf> {
    let parent = file.parent()?;
    let dir = match file.file_name()?.to_str()? {
        ".mcp.json" => parent.to_path_buf(),
        "settings.json" if parent.file_name()? == ".claude" => parent.parent()?.to_path_buf(),
        "CLAUDE.md" if parent != home.join(".claude") => parent.to_path_buf(),
        _ => return None,
    };
    (dir != home).then_some(dir)
}

/// `cwd`, then every existing project directory named in a (not undone) backup manifest.
pub fn installed_project_dirs(home: &Path, cwd: &Path) -> Vec<PathBuf> {
    let mut dirs = vec![cwd.to_path_buf()];
    let mut manifests: Vec<PathBuf> = std::fs::read_dir(backups_root(home))
        .map(|r| {
            r.filter_map(|e| e.ok().map(|e| e.path().join("manifest.json")))
                .filter(|p| p.is_file())
                .collect()
        })
        .unwrap_or_default();
    manifests.sort();
    for m in manifests {
        let Some(man) = std::fs::read_to_string(&m)
            .ok()
            .and_then(|t| serde_json::from_str::<Manifest>(&t).ok())
        else {
            continue;
        };
        for f in man.files {
            if let Some(d) = project_dir_of(&f.path, home) {
                if d.is_dir() && !dirs.contains(&d) {
                    dirs.push(d);
                }
            }
        }
    }
    dirs
}

fn refresh_mcp(e: &mut JsonEdit, o: &RefreshOptions, notes: &mut Vec<String>) -> Result<()> {
    let path = p(&["mcpServers", "middleman"]);
    let Some(cur) = get(&e.value, &path).cloned() else {
        return Ok(());
    };
    let cmd = cur.get("command").and_then(Value::as_str).unwrap_or("");
    let args: Vec<&str> = cur
        .get("args")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if !is_middleman_path(cmd) || args.first() != Some(&"mcp") {
        notes.push(format!(
            "{}: the `middleman` MCP entry does not run a middleman binary (`{}`); left alone",
            pretty(&e.path),
            crate::fsutil::clean(cmd, 80)
        ));
        return Ok(());
    }
    let cfg = args
        .iter()
        .position(|a| *a == "--config")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.to_string())
        .unwrap_or_else(|| o.config_path.display().to_string());
    let exe = o.exe.display().to_string();
    let mut new = cur.clone();
    new["command"] = json!(exe);
    new["args"] = json!(["mcp", "--config", cfg]);
    if new == cur {
        return Ok(());
    }
    let mut what = vec![];
    if cmd != exe {
        what.push(format!("now starts {} (was {})", pretty(&o.exe), cmd));
    }
    if new["args"] != cur["args"] {
        what.push("arguments updated".into());
    }
    e.update(path, new, &format!("MCP server: {}", what.join(", ")))
}

fn refresh_settings(e: &mut JsonEdit, o: &RefreshOptions) -> Result<()> {
    let exe = o.exe.display().to_string();
    let path = p(&["hooks", "UserPromptSubmit"]);
    let groups = get(&e.value, &path)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for (i, g) in groups.iter().enumerate() {
        let Some(hooks) = g.get("hooks").and_then(Value::as_array) else {
            continue;
        };
        let mut new_g = g.clone();
        let mut what = vec![];
        for (j, h) in hooks.iter().enumerate() {
            let Some(cmd) = h.get("command").and_then(Value::as_str) else {
                continue;
            };
            if our_command(cmd, "route").is_none() || !cmd.contains("route --hook") {
                continue;
            }
            let nh = &mut new_g["hooks"][j];
            if let Some(c) = repoint(cmd, "route", &exe) {
                nh["command"] = json!(c);
                what.push(format!("command now runs {}", pretty(&o.exe)));
            }
            let t = h.get("timeout").and_then(Value::as_f64);
            if t.is_none_or(|t| t < HOOK_TIMEOUT_S as f64) {
                nh["timeout"] = json!(HOOK_TIMEOUT_S);
                what.push(format!(
                    "timeout {} -> {HOOK_TIMEOUT_S} s (a `cheap:` prompt runs inside the hook)",
                    t.map(|t| format!("{t} s"))
                        .unwrap_or_else(|| "default".into())
                ));
            }
        }
        if &new_g != g {
            let n = e.summary.len();
            e.replace_item(path.clone(), i, new_g, "")?;
            e.summary[n] = format!("~ prompt hook: {}", what.join(", "));
        }
    }
    let sl = p(&["statusLine", "command"]);
    if let Some(cmd) = get(&e.value, &sl).and_then(Value::as_str) {
        if let Some(c) = repoint(cmd, "statusline", &exe) {
            e.update(
                sl,
                json!(c),
                &format!("status line now runs {}", pretty(&o.exe)),
            )?;
        }
    }
    Ok(())
}

fn replace_md_block(text: &str, block: &str) -> Option<String> {
    let (a, b) = (text.find(MD_BEGIN)?, text.find(MD_END)?);
    if b < a {
        return None;
    }
    let mut end = b + MD_END.len();
    if text[end..].starts_with('\n') {
        end += 1;
    }
    Some(format!("{}{}{}", &text[..a], block, &text[end..]))
}

/// The managed block between the markers, as it is in `text`.
fn md_block_in(text: &str) -> Option<String> {
    let (a, b) = (text.find(MD_BEGIN)?, text.find(MD_END)?);
    (b > a).then(|| {
        let end = b + MD_END.len();
        let end = if text[end..].starts_with('\n') {
            end + 1
        } else {
            end
        };
        text[a..end].to_string()
    })
}

/// `setup claude --refresh`: bring entries that middleman wrote (and that still exist) up to
/// this version: MCP command and args, hook command and timeout, status line command, the
/// CLAUDE.md block. Never adds anything, never touches entries that are not middleman's.
/// Files that cannot be parsed are skipped with a note.
pub fn refresh_plan(o: &RefreshOptions) -> Plan {
    let mut plan = Plan::default();
    let mut seen = std::collections::HashSet::new();
    let mut fresh = |f: &Path| {
        f.is_file() && seen.insert(std::fs::canonicalize(f).unwrap_or_else(|_| f.to_path_buf()))
    };
    let projects = &o.project_dirs;
    let mcp = std::iter::once((o.home.join(".claude.json"), 0o600))
        .chain(projects.iter().map(|d| (d.join(".mcp.json"), 0o644)));
    for (f, mode) in mcp.collect::<Vec<_>>() {
        if !fresh(&f) {
            continue;
        }
        match JsonEdit::open(f.clone()) {
            Ok(mut e) => match refresh_mcp(&mut e, o, &mut plan.notes) {
                Ok(()) => plan.files.extend(e.finish(mode)),
                Err(err) => plan.notes.push(format!("skipped {}: {err:#}", pretty(&f))),
            },
            Err(err) => plan.notes.push(format!("skipped {}: {err:#}", pretty(&f))),
        }
    }
    let settings = std::iter::once(o.home.join(".claude").join("settings.json")).chain(
        projects
            .iter()
            .map(|d| d.join(".claude").join("settings.json")),
    );
    for f in settings.collect::<Vec<_>>() {
        if !fresh(&f) {
            continue;
        }
        match JsonEdit::open(f.clone()).and_then(|mut e| refresh_settings(&mut e, o).map(|_| e)) {
            Ok(e) => plan.files.extend(e.finish(0o644)),
            Err(err) => plan.notes.push(format!("skipped {}: {err:#}", pretty(&f))),
        }
    }
    let mds = std::iter::once(o.home.join(".claude").join("CLAUDE.md"))
        .chain(projects.iter().map(|d| d.join("CLAUDE.md")));
    for f in mds.collect::<Vec<_>>() {
        if !fresh(&f) {
            continue;
        }
        let Ok((_, before)) = read_text(&f) else {
            continue;
        };
        let Some(after) = replace_md_block(&before, &md_block()) else {
            continue;
        };
        if after != before {
            plan.files.push(FilePlan {
                path: f,
                existed: true,
                changes: vec!["~ middleman block between its markers".into()],
                summary: vec!["~ the middleman block updated to this version's text".into()],
                reverts: vec![Revert::MdBlock {
                    before: md_block_in(&before),
                }],
                before,
                after,
                new_mode: 0o644,
            });
        }
    }
    plan
}

/// Doctor: would `setup claude --refresh` change anything?
pub fn outdated_check(o: &RefreshOptions) -> Check {
    let plan = refresh_plan(o);
    if plan.is_empty() {
        return Check::optional(
            "Claude Code: wiring up to date",
            true,
            "matches what this version writes",
        );
    }
    let what: Vec<String> = plan
        .files
        .iter()
        .flat_map(|f| {
            f.summary
                .iter()
                .map(move |s| format!("{}: {}", pretty(&f.path), s.trim_start_matches("~ ")))
        })
        .collect();
    Check::optional(
        "Claude Code: wiring up to date",
        false,
        format!(
            "outdated ({}); run `middleman setup claude --refresh`",
            what.join("; ")
        ),
    )
}

/// The Claude Code settings files `statusline on|off` acts on: the user's, and those of the
/// projects middleman was set up in, when they carry middleman's hook or status line (the
/// user's file when none does).
pub fn statusline_targets(home: &Path, cwd: &Path) -> Vec<PathBuf> {
    let mut files = vec![home.join(".claude/settings.json")];
    for d in installed_project_dirs(home, cwd) {
        let f = d.join(".claude/settings.json");
        if !files.contains(&f) {
            files.push(f);
        }
    }
    let ours: Vec<PathBuf> = files
        .iter()
        .filter(|f| {
            std::fs::read_to_string(f).is_ok_and(|t| {
                t.contains("route --hook") || (t.contains("middleman") && t.contains("statusline"))
            })
        })
        .cloned()
        .collect();
    if ours.is_empty() {
        files.truncate(1);
        files
    } else {
        ours
    }
}

/// The non-middleman `statusLine` an earlier `setup claude` replaced in `file`, newest first.
fn saved_foreign_statusline(backups: &Path, file: &Path) -> Option<Value> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(backups)
        .ok()?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    dirs.sort();
    for d in dirs.iter().rev() {
        let Some(man) = std::fs::read_to_string(d.join("manifest.json"))
            .ok()
            .and_then(|t| serde_json::from_str::<Manifest>(&t).ok())
        else {
            continue;
        };
        for f in man.files.iter().filter(|f| f.path == file) {
            for r in &f.reverts {
                if let Revert::SetKey {
                    path,
                    before: Some(v),
                } = r
                {
                    let foreign = v
                        .get("command")
                        .and_then(Value::as_str)
                        .is_some_and(|c| !is_our_statusline(c));
                    if path.len() == 1 && path[0] == "statusLine" && foreign {
                        return Some(v.clone());
                    }
                }
            }
        }
    }
    None
}

/// `statusline off`: drop middleman's `statusLine` from `files`, putting back a status line of
/// yours that an earlier `setup claude --statusline combined` replaced.
pub fn statusline_off_plan(files: &[PathBuf], backups: &Path) -> Result<Plan> {
    let mut plan = Plan::default();
    for f in files {
        let mut e = JsonEdit::open(f.clone())?;
        let ours = e
            .value
            .pointer("/statusLine/command")
            .and_then(Value::as_str)
            .is_some_and(is_our_statusline);
        if !ours {
            continue;
        }
        match saved_foreign_statusline(backups, f) {
            Some(v) => e.set(
                p(&["statusLine"]),
                v,
                "your previous status line (restored)",
            )?,
            None => e.remove(p(&["statusLine"]), "middleman's status line")?,
        }
        plan.files.extend(e.finish(0o644));
    }
    Ok(plan)
}

/// `statusline on`: set middleman's status line in `files` (a status line of yours is left
/// alone, with a note).
pub fn statusline_on_plan(files: &[PathBuf], o: &SetupOptions) -> Result<Plan> {
    let mut plan = Plan::default();
    for f in files {
        let mut e = JsonEdit::open(f.clone())?;
        let cur = e
            .value
            .pointer("/statusLine/command")
            .and_then(Value::as_str)
            .map(String::from);
        match cur {
            Some(c) if !is_our_statusline(&c) => plan.notes.push(format!(
                "{} already has a status line (`{}`); left alone (`middleman setup claude --statusline combined` replaces it)",
                pretty(f),
                crate::fsutil::clean(&c, 60)
            )),
            Some(_) => {}
            None => e.set(
                p(&["statusLine"]),
                json!({"type": "command", "command": o.statusline_command(), "padding": 0}),
                "middleman's status line",
            )?,
        }
        plan.files.extend(e.finish(0o644));
    }
    Ok(plan)
}

fn is_our_hook(cmd: &str) -> bool {
    cmd.contains("middleman") && cmd.contains("route --hook")
}

fn is_our_statusline(cmd: &str) -> bool {
    cmd.contains("middleman") && cmd.contains("statusline")
}

/// Compute every edit without writing anything.
pub fn plan(o: &SetupOptions) -> Result<Plan> {
    let mut plan = Plan::default();

    let mut mcp = JsonEdit::open(o.mcp_file())?;
    mcp.set(
        p(&["mcpServers", "middleman"]),
        o.mcp_entry(),
        "register the middleman MCP server (Claude Code starts it when needed)",
    )?;
    plan.files.extend(mcp.finish(match o.scope {
        Scope::User => 0o600,
        Scope::Project => 0o644,
    }));
    if o.scope == Scope::Project {
        plan.notes.push(
            "Claude Code asks once before it uses servers from a project's .mcp.json; approve `middleman` then."
                .into(),
        );
    }

    let mut st = JsonEdit::open(o.settings_file())?;
    if o.permissions {
        for t in TOOLS {
            let human = format!(
                "allow the `{}` tool without asking each time",
                t.trim_start_matches("mcp__middleman__")
            );
            st.push_unique(p(&["permissions", "allow"]), json!(t), &human)?;
        }
    }
    if o.hook {
        let group = json!({"hooks": [{"type": "command", "command": o.hook_command(), "timeout": HOOK_TIMEOUT_S}]});
        let path = p(&["hooks", "UserPromptSubmit"]);
        let arr = arr_at(&mut st.value, &path, &st.path)?.clone();
        let cmds = |g: &Value| -> Vec<String> {
            g.get("hooks")
                .and_then(Value::as_array)
                .map(|h| {
                    h.iter()
                        .filter_map(|x| x.get("command").and_then(Value::as_str))
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default()
        };
        let human = "add the prompt hook: a local check (~20 ms) that tells Claude when a job \
                     can be delegated; a `cheap:` prompt is run by middleman itself and never \
                     reaches Claude";
        // same command and timeout already there: nothing to do (an older entry with the
        // 5 s timeout is replaced)
        if !arr.contains(&group) {
            match arr
                .iter()
                .position(|g| cmds(g).iter().any(|c| is_our_hook(c)))
            {
                Some(i) => st.replace_item(path, i, group, human)?,
                None => st.push_unique(path, group, human)?,
            }
        }
    }
    if o.statusline {
        let new = json!({"type": "command", "command": o.statusline_command(), "padding": 0});
        let cur = st.value.get("statusLine").cloned();
        let cur_cmd = cur
            .as_ref()
            .and_then(|c| c.get("command"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        match cur {
            Some(_) if !is_our_statusline(&cur_cmd) && !o.statusline_combined => {
                plan.notes.push(format!(
                    "statusLine is already set (`{}`); left alone. Either replace it with middleman's full line (model, effort, context, cost, cache, then middleman's part): `middleman setup claude --statusline combined`; or keep yours and append middleman's part to its output: `{}` (pipe the same stdin JSON into it).",
                    crate::fsutil::clean(&cur_cmd, 80),
                    o.statusline_chain_command()
                ))
            }
            Some(_) if !is_our_statusline(&cur_cmd) => st.set(
                p(&["statusLine"]),
                new,
                "replace your status line with middleman's combined one (model, context, cost, cache + middleman; `--undo` restores yours)",
            )?,
            _ => st.set(
                p(&["statusLine"]),
                new,
                "show the status line: model, context, cost, cache and middleman's savings",
            )?,
        }
    }
    plan.files.extend(st.finish(0o644));

    if o.claude_md {
        let path = o.claude_md_file();
        let (existed, before) = read_text(&path)?;
        let block = md_block();
        let after = match (before.find(MD_BEGIN), before.find(MD_END)) {
            (Some(a), Some(b)) if b > a => {
                let end = b + MD_END.len();
                let end = if before[end..].starts_with('\n') {
                    end + 1
                } else {
                    end
                };
                format!("{}{}{}", &before[..a], block, &before[end..])
            }
            _ if before.is_empty() => block.clone(),
            _ => format!(
                "{}{}\n{}",
                before,
                if before.ends_with('\n') { "" } else { "\n" },
                block
            ),
        };
        if after != before {
            let replaced = before.contains(MD_BEGIN);
            let mut lines = vec![format!(
                "{} middleman block ({} lines):",
                if replaced { "~ update" } else { "+ append" },
                block.lines().count()
            )];
            lines.extend(block.lines().map(|l| format!("| {l}")));
            let human = format!(
                "{} the middleman block ({} lines): tells Claude what it may delegate and how",
                if replaced { "~ update" } else { "+ add" },
                block.lines().count()
            );
            plan.files.push(FilePlan {
                path,
                existed,
                before,
                after,
                summary: vec![human],
                changes: vec![lines.join("\n")],
                reverts: vec![Revert::MdBlock { before: None }],
                new_mode: 0o644,
            });
        }
    }
    Ok(plan)
}

#[derive(Debug, Serialize, Deserialize)]
struct ManifestFile {
    path: PathBuf,
    existed: bool,
    backup: Option<String>,
    after_sha256: String,
    reverts: Vec<Revert>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Manifest {
    created: String,
    files: Vec<ManifestFile>,
}

fn sha(s: &str) -> String {
    Sha256::digest(s.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn backups_root(home: &Path) -> PathBuf {
    home.join(".local/state/middleman/backups")
}

fn write_private(path: &Path, text: &str) -> Result<()> {
    write_atomic(path, text.as_bytes(), Some(0o600))
}

/// Back up, record a manifest, then write every planned file atomically.
pub fn apply(plan: &Plan, backups: &Path) -> Result<Vec<String>> {
    let mut log = vec![];
    if plan.is_empty() {
        return Ok(log);
    }
    for f in &plan.files {
        let (_, now) = read_text(&f.path)?;
        if now != f.before {
            bail!(
                "{} changed while the plan was being made; nothing was changed. Re-run the command.",
                f.path.display()
            );
        }
    }
    let nanos = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
    let dir = backups.join(format!("{nanos:024}"));
    crate::ledger::ensure_private_dir(backups)?;
    crate::ledger::ensure_private_dir(&dir)?;
    let mut manifest = Manifest {
        created: crate::ledger::now_rfc3339(),
        files: vec![],
    };
    for (i, f) in plan.files.iter().enumerate() {
        let backup = if f.existed {
            let name = format!(
                "{i}-{}",
                f.path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            );
            write_private(&dir.join(&name), &f.before)?;
            log.push(format!(
                "backed up {} -> {}",
                pretty(&f.path),
                pretty(&dir.join(&name))
            ));
            Some(name)
        } else {
            None
        };
        manifest.files.push(ManifestFile {
            path: f.path.clone(),
            existed: f.existed,
            backup,
            after_sha256: sha(&f.after),
            reverts: f.reverts.clone(),
        });
    }
    write_private(
        &dir.join("manifest.json"),
        &serde_json::to_string_pretty(&manifest)?,
    )?;
    for f in &plan.files {
        write_atomic(&f.path, f.after.as_bytes(), Some(f.new_mode))?;
        log.push(format!("updated {}", pretty(&f.path)));
    }
    log.push(format!(
        "undo with `middleman setup claude --undo` (backups in {})",
        pretty(&dir)
    ));
    Ok(log)
}

fn revert_json(v: &mut Value, reverts: &[Revert]) {
    for r in reverts.iter().rev() {
        match r {
            Revert::SetKey { path, before } => {
                let Some((last, parent)) = path.split_last() else {
                    continue;
                };
                let Some(m) = parent
                    .iter()
                    .try_fold(&mut *v, |cur, k| cur.get_mut(k))
                    .and_then(Value::as_object_mut)
                else {
                    continue;
                };
                match before {
                    Some(b) => {
                        m.insert(last.clone(), b.clone());
                    }
                    None => {
                        m.remove(last);
                    }
                }
            }
            Revert::ArrayPush { path, item } => {
                if let Some(a) = path
                    .iter()
                    .try_fold(&mut *v, |cur, k| cur.get_mut(k))
                    .and_then(Value::as_array_mut)
                {
                    if let Some(i) = a.iter().position(|x| x == item) {
                        a.remove(i);
                    }
                }
            }
            Revert::ArrayReplace {
                path,
                before,
                after,
            } => {
                if let Some(a) = path
                    .iter()
                    .try_fold(&mut *v, |cur, k| cur.get_mut(k))
                    .and_then(Value::as_array_mut)
                {
                    if let Some(x) = a.iter_mut().find(|x| *x == after) {
                        *x = before.clone();
                    }
                }
            }
            Revert::MdBlock { .. } => {}
        }
    }
}

fn remove_md_block(text: &str) -> String {
    match (text.find(MD_BEGIN), text.find(MD_END)) {
        (Some(a), Some(b)) if b > a => {
            let mut end = b + MD_END.len();
            if text[end..].starts_with('\n') {
                end += 1;
            }
            let head = text[..a].strip_suffix('\n').unwrap_or(&text[..a]);
            format!("{head}{}", &text[end..])
        }
        _ => text.to_string(),
    }
}

/// Undo the most recent `apply`.
pub fn undo(backups: &Path) -> Result<Vec<String>> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(backups)
        .map(|r| {
            r.filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.join("manifest.json").is_file())
                .collect()
        })
        .unwrap_or_default();
    dirs.sort();
    let Some(dir) = dirs.pop() else {
        bail!("nothing to undo: no `middleman setup claude` backup found");
    };
    let m: Manifest = serde_json::from_str(&std::fs::read_to_string(dir.join("manifest.json"))?)
        .context("backup manifest is unreadable")?;
    let mut log = vec![];
    for f in m.files.iter().rev() {
        let (exists, now) = read_text(&f.path)?;
        if exists && sha(&now) == f.after_sha256 {
            match &f.backup {
                Some(b) => {
                    let text = std::fs::read_to_string(dir.join(b))?;
                    write_atomic(&f.path, text.as_bytes(), Some(0o600))?;
                    log.push(format!("restored {}", pretty(&f.path)));
                }
                None => {
                    std::fs::remove_file(&f.path)?;
                    log.push(format!("removed {} (setup created it)", pretty(&f.path)));
                }
            }
            continue;
        }
        if !exists {
            log.push(format!("{} no longer exists; skipped", pretty(&f.path)));
            continue;
        }
        let md = f.reverts.iter().find_map(|r| match r {
            Revert::MdBlock { before } => Some(before),
            _ => None,
        });
        let after = if let Some(before) = md {
            // a refreshed block goes back to its old text; an added one is removed
            match before {
                Some(b) => replace_md_block(&now, b).unwrap_or(now.clone()),
                None => remove_md_block(&now),
            }
        } else {
            let mut v = parse_json(&f.path, &now)?;
            revert_json(&mut v, &f.reverts);
            to_text(&v, &now)
        };
        write_atomic(&f.path, after.as_bytes(), Some(0o600))?;
        log.push(format!(
            "{} changed since setup; removed only middleman's entries",
            pretty(&f.path)
        ));
    }
    std::fs::rename(dir.join("manifest.json"), dir.join("manifest.undone.json"))?;
    Ok(log)
}

fn json_file(path: &Path) -> Option<Value> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
}

/// Doctor checks for the Claude Code wiring (all optional: warnings, not failures).
pub fn wiring_checks(home: &Path, project_dir: &Path) -> Vec<Check> {
    let mut out = vec![];
    let user_json = json_file(&home.join(".claude.json"));
    let proj_key = project_dir.display().to_string();
    let mcp_where = [
        user_json
            .as_ref()
            .and_then(|v| v.pointer("/mcpServers/middleman"))
            .map(|_| "~/.claude.json (user)".to_string()),
        user_json
            .as_ref()
            .and_then(|v| v.get("projects"))
            .and_then(|p| p.get(&proj_key))
            .and_then(|p| p.pointer("/mcpServers/middleman"))
            .map(|_| "~/.claude.json (local)".to_string()),
        json_file(&project_dir.join(".mcp.json"))
            .and_then(|v| v.pointer("/mcpServers/middleman").cloned())
            .map(|_| ".mcp.json (project)".to_string()),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    out.push(Check::optional(
        "Claude Code: MCP server",
        !mcp_where.is_empty(),
        if mcp_where.is_empty() {
            "not registered; run `middleman setup claude`".into()
        } else {
            mcp_where.join(", ")
        },
    ));
    let settings: Vec<(String, Value)> = [
        home.join(".claude/settings.json"),
        project_dir.join(".claude/settings.json"),
        project_dir.join(".claude/settings.local.json"),
    ]
    .iter()
    .filter_map(|p| json_file(p).map(|v| (pretty(p), v)))
    .collect();
    let find = |f: &dyn Fn(&Value) -> bool| -> Vec<String> {
        settings
            .iter()
            .filter(|(_, v)| f(v))
            .map(|(n, _)| n.clone())
            .collect()
    };
    let allow = find(&|v| {
        v.pointer("/permissions/allow")
            .and_then(Value::as_array)
            .is_some_and(|a| {
                a.iter().filter_map(Value::as_str).any(|s| {
                    TOOLS.contains(&s) || s == "mcp__middleman__*" || s == "mcp__middleman"
                })
            })
    });
    let hook = find(&|v| {
        v.pointer("/hooks/UserPromptSubmit")
            .map(|h| h.to_string())
            .is_some_and(|s| s.contains("route --hook"))
    });
    let sl = find(&|v| {
        v.pointer("/statusLine/command")
            .and_then(Value::as_str)
            .is_some_and(is_our_statusline)
    });
    for (name, found, missing) in [
        (
            "Claude Code: tool permissions",
            &allow,
            "not allow-listed (Claude will ask each time); `middleman setup claude` adds them",
        ),
        (
            "Claude Code: prompt hook",
            &hook,
            "not installed; `middleman setup claude` adds it",
        ),
    ] {
        out.push(Check::optional(
            name,
            !found.is_empty(),
            if found.is_empty() {
                missing.to_string()
            } else {
                found.join(", ")
            },
        ));
    }
    // the status line is a preference: on or off is information, never a warning
    out.push(Check::optional(
        "status line",
        true,
        if sl.is_empty() {
            "off (`middleman statusline on` shows it)".to_string()
        } else {
            format!(
                "on ({}; `middleman statusline off` hides it)",
                sl.join(", ")
            )
        },
    ));
    let md = [
        home.join(".claude/CLAUDE.md"),
        project_dir.join("CLAUDE.md"),
    ]
    .into_iter()
    .filter(|p| {
        std::fs::read_to_string(p).is_ok_and(|t| t.contains("mcp__middleman__delegate_task"))
    })
    .map(|p| pretty(&p))
    .collect::<Vec<_>>();
    out.push(Check::optional(
        "Claude Code: CLAUDE.md block",
        !md.is_empty(),
        if md.is_empty() {
            "missing; `middleman setup claude` adds it".into()
        } else {
            md.join(", ")
        },
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(home: &Path, scope: Scope) -> SetupOptions {
        SetupOptions {
            scope,
            home: home.to_path_buf(),
            project_dir: home.join("proj"),
            exe: PathBuf::from("/opt/mm/middleman"),
            config_path: home.join(".config/middleman/config.toml"),
            hook: true,
            statusline: true,
            statusline_combined: false,
            claude_md: true,
            permissions: true,
        }
    }

    fn read(p: &Path) -> Value {
        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
    }

    #[test]
    fn plan_apply_is_idempotent_and_preserves_keys() {
        let d = tempfile::tempdir().unwrap();
        let home = d.path();
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        std::fs::write(
            home.join(".claude.json"),
            r#"{"numStartups": 5, "zzz": {"keep": true}, "mcpServers": {"other": {"command": "x"}}}"#,
        )
        .unwrap();
        std::fs::write(
            home.join(".claude/settings.json"),
            r#"{"model": "opus", "permissions": {"allow": ["Bash(ls)"]}, "hooks": {"PreToolUse": []}}"#,
        )
        .unwrap();
        let o = opts(home, Scope::User);
        let plan = plan(&o).unwrap();
        assert_eq!(plan.files.len(), 3, "{}", plan.render());
        let text = plan.render();
        assert!(
            text.contains("+ register the middleman MCP server"),
            "{text}"
        );
        assert!(text.contains("+ allow the `delegate_task` tool"));
        assert!(text.contains("+ add the prompt hook"));
        assert!(text.contains("+ show the status line"));
        assert!(text.contains("CLAUDE.md (new file)"));
        // the normal preview has no raw JSON; --details adds the exact keys
        assert!(
            !text.contains('{') && !text.contains("mcpServers"),
            "{text}"
        );
        let details = plan.render_ui(&crate::ui::Ui::plain(), true);
        assert!(details.contains("+ mcpServers.middleman"));
        assert!(details.contains("permissions.allow += \"mcp__middleman__delegate_task\""));
        assert!(details.contains("hooks.UserPromptSubmit +="));
        assert!(details.contains("+ statusLine"));
        // dry run writes nothing
        assert!(!home.join(".claude/CLAUDE.md").exists());

        let log = apply(&plan, &backups_root(home)).unwrap();
        assert!(log.iter().any(|l| l.starts_with("backed up")));
        let cj = read(&home.join(".claude.json"));
        assert_eq!(cj["numStartups"], 5);
        assert_eq!(cj["zzz"]["keep"], true);
        assert_eq!(cj["mcpServers"]["other"]["command"], "x");
        assert_eq!(cj["mcpServers"]["middleman"]["args"][0], "mcp");
        // key order preserved
        let raw = std::fs::read_to_string(home.join(".claude.json")).unwrap();
        assert!(raw.find("numStartups").unwrap() < raw.find("zzz").unwrap());
        let st = read(&home.join(".claude/settings.json"));
        assert_eq!(st["model"], "opus");
        assert_eq!(st["permissions"]["allow"].as_array().unwrap().len(), 3);
        assert!(st["statusLine"]["command"]
            .as_str()
            .unwrap()
            .ends_with(&format!("statusline --config {}", o.cfg_s())));
        let md = std::fs::read_to_string(home.join(".claude/CLAUDE.md")).unwrap();
        assert!(md.contains("mcp__middleman__delegate_task"));

        // second run: nothing to do
        assert!(super::plan(&o).unwrap().is_empty());

        let checks = wiring_checks(home, &o.project_dir);
        assert!(checks.iter().all(|c| c.ok), "{checks:?}");

        // undo restores the exact bytes and removes created files
        let undo_log = undo(&backups_root(home)).unwrap();
        assert_eq!(undo_log.len(), 3, "{undo_log:?}");
        assert_eq!(
            read(&home.join(".claude.json")),
            serde_json::from_str::<Value>(
                r#"{"numStartups": 5, "zzz": {"keep": true}, "mcpServers": {"other": {"command": "x"}}}"#
            )
            .unwrap()
        );
        assert!(!home.join(".claude/CLAUDE.md").exists());
        assert!(undo(&backups_root(home)).is_err());
    }

    #[test]
    fn undo_after_external_change_only_removes_ours() {
        let d = tempfile::tempdir().unwrap();
        let home = d.path();
        std::fs::write(home.join(".claude.json"), r#"{"a": 1}"#).unwrap();
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        std::fs::write(home.join(".claude/CLAUDE.md"), "# Mine\n\nhello\n").unwrap();
        let o = opts(home, Scope::User);
        apply(&plan(&o).unwrap(), &backups_root(home)).unwrap();
        // Claude Code rewrites ~/.claude.json in between
        let mut cj = read(&home.join(".claude.json"));
        cj["b"] = json!(2);
        std::fs::write(home.join(".claude.json"), cj.to_string()).unwrap();
        let mut md = std::fs::read_to_string(home.join(".claude/CLAUDE.md")).unwrap();
        md.push_str("\nmore of mine\n");
        std::fs::write(home.join(".claude/CLAUDE.md"), &md).unwrap();
        let log = undo(&backups_root(home)).unwrap();
        assert!(log.iter().any(|l| l.contains("removed only")));
        let cj = read(&home.join(".claude.json"));
        assert_eq!(cj, json!({"a": 1, "mcpServers": {}, "b": 2}));
        let md = std::fs::read_to_string(home.join(".claude/CLAUDE.md")).unwrap();
        assert!(!md.contains("middleman:begin"));
        assert!(md.contains("# Mine") && md.contains("more of mine"));
    }

    #[test]
    fn foreign_statusline_and_old_hook() {
        let d = tempfile::tempdir().unwrap();
        let home = d.path();
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        std::fs::write(
            home.join(".claude/settings.json"),
            r#"{"statusLine": {"type": "command", "command": "~/my.sh"},
               "hooks": {"UserPromptSubmit": [{"hooks": [{"type": "command", "command": "/old/middleman route --hook"}]}]}}"#,
        )
        .unwrap();
        let o = opts(home, Scope::User);
        let pl = plan(&o).unwrap();
        assert!(pl
            .notes
            .iter()
            .any(|n| n.contains("statusLine is already set")));
        apply(&pl, &backups_root(home)).unwrap();
        let st = read(&home.join(".claude/settings.json"));
        assert_eq!(st["statusLine"]["command"], "~/my.sh");
        let ups = st["hooks"]["UserPromptSubmit"].as_array().unwrap();
        assert_eq!(ups.len(), 1, "old middleman hook replaced, not duplicated");
        assert!(ups[0]
            .to_string()
            .contains("/opt/mm/middleman route --hook"));
        let note = pl.notes.iter().find(|n| n.contains("statusLine")).unwrap();
        assert!(note.contains("--statusline combined") && note.contains("--middleman-only"));
    }

    #[test]
    fn combined_statusline_replaces_a_foreign_one_and_undo_restores_it() {
        let d = tempfile::tempdir().unwrap();
        let home = d.path();
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        let mine = r#"{"statusLine": {"type": "command", "command": "node ~/.claude/context-line/statusline.mjs"}}"#;
        std::fs::write(home.join(".claude/settings.json"), mine).unwrap();
        let mut o = opts(home, Scope::User);
        o.statusline_combined = true;
        let pl = plan(&o).unwrap();
        assert!(pl.render().contains("replace your status line"));
        apply(&pl, &backups_root(home)).unwrap();
        let st = read(&home.join(".claude/settings.json"));
        let cmd = st["statusLine"]["command"].as_str().unwrap();
        assert!(cmd.contains("statusline --lines 2 --config"), "{cmd}");
        undo(&backups_root(home)).unwrap();
        let st = read(&home.join(".claude/settings.json"));
        assert_eq!(
            st["statusLine"]["command"],
            "node ~/.claude/context-line/statusline.mjs"
        );
    }

    #[test]
    fn refuses_invalid_json_and_project_scope_paths() {
        let d = tempfile::tempdir().unwrap();
        let home = d.path();
        std::fs::write(home.join(".claude.json"), "{not json").unwrap();
        let e = plan(&opts(home, Scope::User)).unwrap_err().to_string();
        assert!(e.contains("not valid JSON"), "{e}");
        let o = opts(home, Scope::Project);
        let pl = plan(&o).unwrap();
        let paths: Vec<_> = pl.files.iter().map(|f| f.path.clone()).collect();
        assert!(paths.contains(&home.join("proj/.mcp.json")));
        assert!(paths.contains(&home.join("proj/.claude/settings.json")));
        assert!(paths.contains(&home.join("proj/CLAUDE.md")));
    }

    #[test]
    fn first_word_parsing() {
        assert_eq!(
            first_word("/a/middleman route --hook"),
            Some(("/a/middleman".into(), " route --hook"))
        );
        assert_eq!(
            first_word("'/a b/middleman' statusline"),
            Some(("/a b/middleman".into(), " statusline"))
        );
        assert_eq!(
            first_word(r"'/it'\''s/middleman' x"),
            Some(("/it's/middleman".into(), " x"))
        );
        assert_eq!(first_word("x;/a/middleman route --hook"), None);
        assert_eq!(first_word("$(evil)/middleman route --hook"), None);
        assert_eq!(first_word("'/unbalanced"), None);
        assert!(our_command("/a/middleman route --hook", "route").is_some());
        assert!(our_command("/a/middleman routex", "route").is_none());
        assert!(
            our_command("middleman route --hook", "route").is_none(),
            "not absolute"
        );
        assert!(our_command("/a/not-middleman route --hook", "route").is_none());
        assert!(our_command("~/my.sh | /a/middleman statusline", "statusline").is_none());
    }

    /// What 0.2.0's `setup claude` wrote (5 s hook timeout, the old binary path), next to
    /// entries that are not middleman's.
    fn old_wiring(home: &Path) -> Vec<(PathBuf, String)> {
        let files = vec![
            (
                home.join(".claude.json"),
                r#"{"numStartups": 3, "mcpServers": {"middleman": {"type": "stdio", "command": "/old/bin/middleman", "args": ["mcp", "--config", "/cfg/custom.toml"], "env": {"X": "1"}}, "other": {"command": "npx", "args": ["x"]}}}"#,
            ),
            (
                home.join(".claude/settings.json"),
                r#"{"model": "opus", "permissions": {"allow": ["Bash(ls)"]},
                   "hooks": {"UserPromptSubmit": [
                       {"hooks": [{"type": "command", "command": "/usr/local/bin/other-hook.sh", "timeout": 5}]},
                       {"hooks": [{"type": "command", "command": "/old/bin/middleman route --hook --config /cfg/custom.toml", "timeout": 5}]}],
                     "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "/old/bin/middleman-ish"}]}]},
                   "statusLine": {"type": "command", "command": "/old/bin/middleman statusline --config /cfg/custom.toml", "padding": 0}}"#,
            ),
            (
                home.join(".claude/CLAUDE.md"),
                "# mine\n\n<!-- middleman:begin (managed by `middleman setup claude`) -->\nold text\n<!-- middleman:end -->\n\nafter\n",
            ),
            (
                home.join("proj/.mcp.json"),
                r#"{"mcpServers": {"middleman": {"type": "stdio", "command": "/old/bin/middleman", "args": ["mcp", "--config", "/cfg/custom.toml"], "env": {}}}}"#,
            ),
            (
                home.join("proj/.claude/settings.json"),
                r#"{"statusLine": {"type": "command", "command": "~/my.sh | /old/bin/middleman statusline --middleman-only"}}"#,
            ),
        ];
        files
            .into_iter()
            .map(|(p, t)| {
                std::fs::create_dir_all(p.parent().unwrap()).unwrap();
                std::fs::write(&p, t).unwrap();
                (p, t.to_string())
            })
            .collect()
    }

    fn refresh_opts(home: &Path) -> RefreshOptions {
        RefreshOptions {
            home: home.to_path_buf(),
            project_dirs: vec![home.join("proj")],
            exe: PathBuf::from("/opt/mm/middleman"),
            config_path: home.join(".config/middleman/config.toml"),
        }
    }

    #[test]
    fn refresh_updates_only_middleman_entries_and_backs_up() {
        let d = tempfile::tempdir().unwrap();
        let home = d.path();
        let orig = old_wiring(home);
        let o = refresh_opts(home);
        assert!(!outdated_check(&o).ok);
        let pl = refresh_plan(&o);
        let text = pl.render();
        assert!(text.contains("timeout 5 s -> 150 s"), "{text}");
        assert!(
            text.contains("status line now runs /opt/mm/middleman"),
            "{text}"
        );
        assert!(
            text.contains("MCP server: now starts /opt/mm/middleman (was /old/bin/middleman)"),
            "{text}"
        );
        assert!(text.contains("the middleman block updated"), "{text}");
        let paths: Vec<_> = pl.files.iter().map(|f| f.path.clone()).collect();
        assert_eq!(paths.len(), 4, "{paths:?}");
        assert!(!paths.contains(&home.join("proj/.claude/settings.json")));

        let log = apply(&pl, &backups_root(home)).unwrap();
        assert_eq!(log.iter().filter(|l| l.starts_with("backed up")).count(), 4);

        let cj = read(&home.join(".claude.json"));
        assert_eq!(cj["numStartups"], 3);
        assert_eq!(
            cj["mcpServers"]["other"],
            json!({"command": "npx", "args": ["x"]})
        );
        assert_eq!(
            cj["mcpServers"]["middleman"],
            json!({"type": "stdio", "command": "/opt/mm/middleman", "args": ["mcp", "--config", "/cfg/custom.toml"], "env": {"X": "1"}})
        );
        let st = read(&home.join(".claude/settings.json"));
        let ups = st["hooks"]["UserPromptSubmit"].as_array().unwrap();
        assert_eq!(ups.len(), 2);
        assert_eq!(
            ups[0],
            json!({"hooks": [{"type": "command", "command": "/usr/local/bin/other-hook.sh", "timeout": 5}]}),
            "an unrelated hook keeps its 5 s timeout"
        );
        assert_eq!(
            ups[1],
            json!({"hooks": [{"type": "command", "command": "/opt/mm/middleman route --hook --config /cfg/custom.toml", "timeout": 150}]})
        );
        assert_eq!(
            st["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
            "/old/bin/middleman-ish"
        );
        assert_eq!(
            st["statusLine"],
            json!({"type": "command", "command": "/opt/mm/middleman statusline --config /cfg/custom.toml", "padding": 0})
        );
        assert_eq!(
            st["permissions"]["allow"],
            json!(["Bash(ls)"]),
            "nothing added"
        );
        let md = std::fs::read_to_string(home.join(".claude/CLAUDE.md")).unwrap();
        assert!(md.starts_with("# mine\n\n<!-- middleman:begin"));
        assert!(md.ends_with("<!-- middleman:end -->\n\nafter\n"));
        assert!(!md.contains("old text") && md.contains("mcp__middleman__delegate_task"));
        let pm = read(&home.join("proj/.mcp.json"));
        assert_eq!(
            pm["mcpServers"]["middleman"]["command"],
            "/opt/mm/middleman"
        );
        assert_eq!(
            std::fs::read_to_string(home.join("proj/.claude/settings.json")).unwrap(),
            orig[4].1,
            "a foreign status line that chains middleman is not touched"
        );

        // up to date now
        assert!(refresh_plan(&o).is_empty());
        assert!(outdated_check(&o).ok);
        // the project is found again from the backup manifest
        assert!(installed_project_dirs(home, &home.join("elsewhere")).contains(&home.join("proj")));

        // undo restores every byte
        undo(&backups_root(home)).unwrap();
        for (p, t) in &orig {
            assert_eq!(&std::fs::read_to_string(p).unwrap(), t, "{}", p.display());
        }
    }

    #[test]
    fn refresh_never_adds_and_reverts_a_changed_md_to_the_old_block() {
        let d = tempfile::tempdir().unwrap();
        let home = d.path();
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        std::fs::write(home.join(".claude.json"), r#"{"a": 1}"#).unwrap();
        std::fs::write(
            home.join(".claude/settings.json"),
            r#"{"statusLine": {"type": "command", "command": "~/my.sh"}}"#,
        )
        .unwrap();
        std::fs::write(home.join(".claude/CLAUDE.md"), "# no block\n").unwrap();
        let o = refresh_opts(home);
        let pl = refresh_plan(&o);
        assert!(pl.is_empty(), "{}", pl.render());
        assert!(!home.join("proj").exists());
        assert!(outdated_check(&o).ok);
        // an `mcpServers.middleman` that is not a middleman binary is reported, not changed
        std::fs::write(
            home.join(".claude.json"),
            r#"{"mcpServers": {"middleman": {"command": "npx", "args": ["some-middleman"]}}}"#,
        )
        .unwrap();
        let pl = refresh_plan(&o);
        assert!(pl.is_empty());
        assert!(
            pl.notes.iter().any(|n| n.contains("left alone")),
            "{:?}",
            pl.notes
        );
        // broken JSON is skipped with a note, not an error
        std::fs::write(home.join(".claude/settings.json"), "{nope").unwrap();
        assert!(refresh_plan(&o).notes.iter().any(|n| n.contains("skipped")));

        // CLAUDE.md edited after a refresh: undo puts the old block back, keeps the edit
        let old = format!("top\n{MD_BEGIN}\nold\n{MD_END}\n");
        std::fs::write(home.join(".claude/CLAUDE.md"), &old).unwrap();
        std::fs::write(home.join(".claude/settings.json"), "{}").unwrap();
        apply(&refresh_plan(&o), &backups_root(home)).unwrap();
        let mut md = std::fs::read_to_string(home.join(".claude/CLAUDE.md")).unwrap();
        md.push_str("mine\n");
        std::fs::write(home.join(".claude/CLAUDE.md"), &md).unwrap();
        undo(&backups_root(home)).unwrap();
        assert_eq!(
            std::fs::read_to_string(home.join(".claude/CLAUDE.md")).unwrap(),
            format!("{old}mine\n")
        );
    }

    #[test]
    fn snippet_is_the_fenced_block() {
        let s = snippet();
        assert!(s.starts_with("## Delegating to middleman"));
        assert!(!s.contains("```"));
    }
}
