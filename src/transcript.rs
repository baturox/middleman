//! Count the Claude Code subagents a session started (`Agent` / `Task` tool uses in the main
//! transcript), incrementally: the byte offset of the last complete line and the counts are
//! cached per session (`<state>/sessions/<sid>.agents.json`, 0600), so each status line run
//! reads only the bytes appended since the last run. A partial last line is left for the next
//! run. Nothing from the transcript is stored or printed except the counts.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::LazyLock;

use aho_corasick::AhoCorasick;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Bytes read per block; a line longer than this cannot be a tool use we count.
const BLOCK: usize = 32 << 20;
/// Tool-use ids remembered for de-duplication (a message can be logged more than once).
const RECENT_IDS: usize = 256;

/// Tool names that start a subagent.
const AGENT_TOOLS: [&str; 2] = ["Agent", "Task"];

static NEEDLES: LazyLock<AhoCorasick> = LazyLock::new(|| {
    let mut pats = vec![];
    for t in AGENT_TOOLS {
        pats.push(format!("\"name\":\"{t}\""));
        pats.push(format!("\"name\": \"{t}\""));
    }
    AhoCorasick::new(pats).expect("static patterns")
});

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Cursor {
    /// File identity: path, and the first bytes' length check via `offset <= len`.
    pub path: String,
    pub offset: u64,
    pub agents: u64,
    pub recent_ids: Vec<String>,
}

fn tool_uses(line: &[u8], c: &mut Cursor) {
    let Ok(v) = serde_json::from_slice::<Value>(line) else {
        return;
    };
    if v.get("type").and_then(Value::as_str) != Some("assistant")
        || v.get("isSidechain").and_then(Value::as_bool) == Some(true)
    {
        return;
    }
    let Some(blocks) = v.pointer("/message/content").and_then(Value::as_array) else {
        return;
    };
    for b in blocks {
        let is_agent = b.get("type").and_then(Value::as_str) == Some("tool_use")
            && b.get("name")
                .and_then(Value::as_str)
                .is_some_and(|n| AGENT_TOOLS.contains(&n));
        if !is_agent {
            continue;
        }
        let id = b
            .get("id")
            .and_then(Value::as_str)
            .map(crate::statusline::safe_id)
            .unwrap_or_default();
        if !id.is_empty() {
            if c.recent_ids.contains(&id) {
                continue;
            }
            c.recent_ids.push(id);
            if c.recent_ids.len() > RECENT_IDS {
                c.recent_ids.remove(0);
            }
        }
        c.agents += 1;
    }
}

/// Scan complete lines of `buf` (which ends at the last newline) for agent tool uses.
fn scan(buf: &[u8], c: &mut Cursor) {
    let mut last_line_start = usize::MAX;
    for m in NEEDLES.find_iter(buf) {
        let start = buf[..m.start()]
            .iter()
            .rposition(|&b| b == b'\n')
            .map(|i| i + 1)
            .unwrap_or(0);
        if start == last_line_start {
            continue; // same line, already parsed
        }
        last_line_start = start;
        let end = buf[m.end()..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|i| m.end() + i)
            .unwrap_or(buf.len());
        tool_uses(&buf[start..end], c);
    }
}

/// Advance `c` over the transcript at `path`. Returns false when the file cannot be read.
pub fn advance(path: &Path, c: &mut Cursor) -> bool {
    let p = path.to_string_lossy().into_owned();
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    if c.path != p || len < c.offset {
        // another file, or truncated / rewritten: start over
        *c = Cursor {
            path: p,
            ..Default::default()
        };
    }
    while c.offset < len {
        if f.seek(SeekFrom::Start(c.offset)).is_err() {
            return false;
        }
        let want = ((len - c.offset) as usize).min(BLOCK);
        let mut buf = Vec::with_capacity(want);
        if (&mut f).take(want as u64).read_to_end(&mut buf).is_err() {
            return false;
        }
        match buf.iter().rposition(|&b| b == b'\n') {
            Some(i) => {
                scan(&buf[..=i], c);
                c.offset += i as u64 + 1;
            }
            None if want == BLOCK => c.offset += want as u64, // absurdly long line: skip it
            None => break,                                    // partial last line: next run
        }
    }
    true
}

/// Subagents started in this session so far (None when the transcript is unreadable).
pub fn count_agents(state_dir: &Path, sid: &str, transcript: &Path) -> Option<u64> {
    let cache = crate::session::session_file(state_dir, sid, "agents.json")?;
    let mut c: Cursor = std::fs::read(&cache)
        .ok()
        .and_then(|t| serde_json::from_slice(&t).ok())
        .unwrap_or_default();
    let before = c.clone();
    if !advance(transcript, &mut c) {
        return None;
    }
    if c != before && crate::ledger::ensure_private_dir(&crate::session::dir(state_dir)).is_ok() {
        if let Ok(t) = serde_json::to_vec(&c) {
            let _ = crate::fsutil::write_atomic(&cache, &t, Some(0o600));
        }
    }
    Some(c.agents)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn agent_line(id: &str, name: &str) -> String {
        serde_json::json!({
            "type": "assistant",
            "message": {"id": format!("msg_{id}"), "content": [
                {"type": "text", "text": "secret project text"},
                {"type": "tool_use", "id": id, "name": name, "input": {"prompt": "do x"}}
            ]}
        })
        .to_string()
    }

    #[test]
    fn counts_incrementally_with_partial_last_line() {
        let d = tempfile::tempdir().unwrap();
        let t = d.path().join("t.jsonl");
        let mut f = std::fs::File::create(&t).unwrap();
        writeln!(f, "{}", agent_line("toolu_1", "Agent")).unwrap();
        writeln!(
            f,
            r#"{{"type":"user","message":{{"content":"hi \"name\":\"Agent\""}}}}"#
        )
        .unwrap();
        writeln!(f, "{}", agent_line("toolu_2", "Bash")).unwrap();
        // the same tool use logged twice is counted once
        writeln!(f, "{}", agent_line("toolu_1", "Agent")).unwrap();
        // a subagent's own (sidechain) lines are not counted
        let mut side: Value = serde_json::from_str(&agent_line("toolu_9", "Agent")).unwrap();
        side["isSidechain"] = true.into();
        writeln!(f, "{side}").unwrap();
        // partial line: written without the newline yet
        let partial = agent_line("toolu_3", "Task");
        write!(f, "{}", &partial[..40]).unwrap();
        f.flush().unwrap();
        assert_eq!(count_agents(d.path(), "s1", &t), Some(1));
        let cache: Cursor = serde_json::from_slice(
            &std::fs::read(crate::session::session_file(d.path(), "s1", "agents.json").unwrap())
                .unwrap(),
        )
        .unwrap();
        let full_len = std::fs::metadata(&t).unwrap().len();
        assert_eq!(cache.offset, full_len - 40, "stops before the partial line");
        let raw = std::fs::read_to_string(
            crate::session::session_file(d.path(), "s1", "agents.json").unwrap(),
        )
        .unwrap();
        assert!(!raw.contains("secret") && !raw.contains("do x"), "{raw}");
        // finish the line, add another
        writeln!(f, "{}", &partial[40..]).unwrap();
        writeln!(f, "{}", agent_line("toolu_4", "Agent")).unwrap();
        f.flush().unwrap();
        assert_eq!(count_agents(d.path(), "s1", &t), Some(3));
        // truncation (a rewritten transcript) restarts from the top
        std::fs::write(&t, format!("{}\n", agent_line("toolu_5", "Agent"))).unwrap();
        assert_eq!(count_agents(d.path(), "s1", &t), Some(1));
        assert_eq!(
            count_agents(d.path(), "s1", &d.path().join("missing")),
            None
        );
    }
}
