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
            "{} statusline --config {}",
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
        let group =
            json!({"hooks": [{"type": "command", "command": o.hook_command(), "timeout": 5}]});
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
        let want = o.hook_command();
        let human = "add the prompt hook: a local check (~20 ms) that tells Claude when a job \
                     can be delegated; it never blocks a prompt";
        if !arr.iter().any(|g| cmds(g).contains(&want)) {
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
            Some(_) if !is_our_statusline(&cur_cmd) => plan.notes.push(format!(
                "statusLine is already set (`{cur_cmd}`); left alone. To add middleman to it, append the output of `{}` to your script.",
                o.statusline_command()
            )),
            _ => st.set(
                p(&["statusLine"]),
                new,
                "show middleman's status at the bottom of Claude Code",
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
        let is_md = f
            .reverts
            .iter()
            .any(|r| matches!(r, Revert::MdBlock { .. }));
        let after = if is_md {
            remove_md_block(&now)
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
        (
            "Claude Code: statusline",
            &sl,
            "not set; `middleman setup claude` adds it",
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
        assert!(text.contains("+ show middleman's status"));
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
    fn snippet_is_the_fenced_block() {
        let s = snippet();
        assert!(s.starts_with("## Delegating to middleman"));
        assert!(!s.contains("```"));
    }
}
