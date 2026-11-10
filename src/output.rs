//! File-mode results: middleman writes the restored output to disk (inside roots, deny globs
//! apply) and Claude gets only a short summary. Existing files are never overwritten unless
//! `overwrite: true`; otherwise a staged `<path>.middleman.new` and a unified diff
//! `<path>.middleman.patch` (apply from the root with `patch -p1`) are written.

use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

use crate::audit::sha256_hex;
use crate::intake::{IntakeError, PathPolicy};

static FENCE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)```[^\n`]*\n(.*?)```").expect("static regex"));

/// The largest fenced code block, or the whole text if there is none.
pub fn extract_content(text: &str) -> String {
    let best = FENCE
        .captures_iter(text)
        .filter_map(|c| c.get(1))
        .max_by_key(|m| m.len())
        .map(|m| m.as_str().to_string());
    let mut s = best.unwrap_or_else(|| text.trim().to_string());
    if !s.ends_with('\n') {
        s.push('\n');
    }
    s
}

#[derive(Debug, Clone, Serialize)]
pub struct WriteResult {
    /// created | overwritten | staged
    pub action: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub staged_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch_path: Option<String>,
    pub bytes: u64,
    pub lines: usize,
    pub sha256: String,
}

fn io(path: &str, e: std::io::Error) -> IntakeError {
    IntakeError::Io {
        path: path.to_string(),
        reason: e.kind().to_string(),
    }
}

pub fn write_output(
    policy: &PathPolicy,
    raw_path: &str,
    content: &str,
    overwrite: bool,
) -> Result<WriteResult, IntakeError> {
    let (target, rel) = policy.check_write(raw_path)?;
    let mut r = WriteResult {
        action: String::new(),
        path: target.display().to_string(),
        staged_path: None,
        patch_path: None,
        bytes: content.len() as u64,
        lines: content.lines().count(),
        sha256: sha256_hex(content),
    };
    let exists = target.exists();
    if !exists || overwrite {
        if let Some(d) = target.parent() {
            std::fs::create_dir_all(d).map_err(|e| io(raw_path, e))?;
        }
        std::fs::write(&target, content).map_err(|e| io(raw_path, e))?;
        r.action = if exists { "overwritten" } else { "created" }.into();
        return Ok(r);
    }
    let old = std::fs::read_to_string(&target).map_err(|e| io(raw_path, e))?;
    let staged_raw = format!("{}.middleman.new", target.display());
    let patch_raw = format!("{}.middleman.patch", target.display());
    let (staged, _) = policy.check_write(&staged_raw)?;
    let (patch, _) = policy.check_write(&patch_raw)?;
    std::fs::write(&staged, content).map_err(|e| io(&staged_raw, e))?;
    let diff = unified_diff(&old, content, &format!("a/{rel}"), &format!("b/{rel}"));
    std::fs::write(&patch, diff).map_err(|e| io(&patch_raw, e))?;
    r.action = "staged".into();
    r.staged_path = Some(staged.display().to_string());
    r.patch_path = Some(patch.display().to_string());
    Ok(r)
}

#[derive(Clone, Copy, PartialEq)]
enum Op {
    Eq,
    Del,
    Ins,
}

fn diff_ops<'a>(a: &[&'a str], b: &[&'a str]) -> Vec<(Op, &'a str)> {
    let (n, m) = (a.len(), b.len());
    if n.saturating_mul(m) > 4_000_000 {
        // too large for the quadratic LCS: replace wholesale
        let mut v: Vec<(Op, &str)> = a.iter().map(|l| (Op::Del, *l)).collect();
        v.extend(b.iter().map(|l| (Op::Ins, *l)));
        return v;
    }
    let mut lcs = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let (mut i, mut j) = (0, 0);
    let mut ops = Vec::with_capacity(n + m);
    while i < n && j < m {
        if a[i] == b[j] {
            ops.push((Op::Eq, a[i]));
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            ops.push((Op::Del, a[i]));
            i += 1;
        } else {
            ops.push((Op::Ins, b[j]));
            j += 1;
        }
    }
    ops.extend(a[i..].iter().map(|l| (Op::Del, *l)));
    ops.extend(b[j..].iter().map(|l| (Op::Ins, *l)));
    ops
}

/// Unified diff with 3 lines of context.
pub fn unified_diff(old: &str, new: &str, old_label: &str, new_label: &str) -> String {
    const CTX: usize = 3;
    let a: Vec<&str> = old.split_inclusive('\n').collect();
    let b: Vec<&str> = new.split_inclusive('\n').collect();
    let ops = diff_ops(&a, &b);
    let mut keep = vec![false; ops.len()];
    for (k, (op, _)) in ops.iter().enumerate() {
        if *op != Op::Eq {
            let lo = k.saturating_sub(CTX);
            let hi = (k + CTX + 1).min(ops.len());
            keep[lo..hi].iter_mut().for_each(|x| *x = true);
        }
    }
    let mut out = format!("--- {old_label}\n+++ {new_label}\n");
    let mut k = 0;
    while k < ops.len() {
        if !keep[k] {
            k += 1;
            continue;
        }
        let start = k;
        while k < ops.len() && keep[k] {
            k += 1;
        }
        let before = &ops[..start];
        let hunk = &ops[start..k];
        let old_before = before.iter().filter(|(o, _)| *o != Op::Ins).count();
        let new_before = before.iter().filter(|(o, _)| *o != Op::Del).count();
        let old_n = hunk.iter().filter(|(o, _)| *o != Op::Ins).count();
        let new_n = hunk.iter().filter(|(o, _)| *o != Op::Del).count();
        let os = if old_n == 0 {
            old_before
        } else {
            old_before + 1
        };
        let ns = if new_n == 0 {
            new_before
        } else {
            new_before + 1
        };
        out.push_str(&format!("@@ -{os},{old_n} +{ns},{new_n} @@\n"));
        for (op, line) in hunk {
            out.push(match op {
                Op::Eq => ' ',
                Op::Del => '-',
                Op::Ins => '+',
            });
            out.push_str(line);
            if !line.ends_with('\n') {
                out.push_str("\n\\ No newline at end of file\n");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PathsCfg;

    #[test]
    fn extracts_largest_block() {
        let t = "Here:\n```py\nx = 1\n```\nand\n```python\ndef f():\n    return 2\n```\n";
        assert_eq!(extract_content(t), "def f():\n    return 2\n");
        assert_eq!(extract_content("plain"), "plain\n");
    }

    #[test]
    fn diff_shape() {
        let old = "a\nb\nc\nd\ne\nf\ng\nh\n";
        let new = "a\nb\nc\nD\ne\nf\ng\nh\ni\n";
        let d = unified_diff(old, new, "a/x", "b/x");
        assert!(d.starts_with("--- a/x\n+++ b/x\n@@ -1,8 +1,9 @@\n"), "{d}");
        assert!(d.contains("-d\n+D\n") && d.contains("+i\n"));
        assert_eq!(unified_diff("same\n", "same\n", "a", "b"), "--- a\n+++ b\n");
    }

    #[test]
    fn writes_creates_stages_and_refuses_escapes() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("proj");
        std::fs::create_dir_all(&root).unwrap();
        let pol = PathPolicy::new(&PathsCfg {
            roots: vec![root.clone()],
            deny: vec![],
            allow: vec!["nothing/**".into()],
        })
        .unwrap();
        let r = write_output(&pol, "tests/test_x.py", "x = 1\n", false).unwrap();
        assert_eq!(r.action, "created");
        assert_eq!(
            std::fs::read_to_string(root.join("tests/test_x.py")).unwrap(),
            "x = 1\n"
        );
        let r = write_output(&pol, "tests/test_x.py", "x = 2\n", false).unwrap();
        assert_eq!(r.action, "staged");
        assert_eq!(
            std::fs::read_to_string(root.join("tests/test_x.py")).unwrap(),
            "x = 1\n"
        );
        let patch = std::fs::read_to_string(r.patch_path.unwrap()).unwrap();
        assert!(patch.contains("-x = 1\n+x = 2\n"));
        let r = write_output(&pol, "tests/test_x.py", "x = 3\n", true).unwrap();
        assert_eq!(r.action, "overwritten");
        for bad in [
            "../evil.py",
            ".env",
            "a/.git/config",
            "secrets/x.py",
            "/etc/passwd_mm",
        ] {
            assert!(write_output(&pol, bad, "x", false).is_err(), "{bad}");
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(d.path(), root.join("out")).unwrap();
            assert!(write_output(&pol, "out/escape.py", "x", false).is_err());
        }
    }
}
