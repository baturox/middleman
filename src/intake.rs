//! File intake: middleman reads files itself. Only configured roots are readable; symlinks are
//! resolved before matching; deny globs always win; size caps; binary / non-UTF-8 rejected.

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::Deserialize;
use thiserror::Error;

use crate::config::{Limits, PathsCfg, BUILTIN_DENY};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRef {
    pub path: String,
    #[serde(default)]
    pub start_line: Option<usize>,
    #[serde(default)]
    pub end_line: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct LoadedFile {
    /// Root-relative path shown to the provider (itself scanned and pseudonymized).
    pub display: String,
    pub text: String,
    pub first_line: usize,
}

#[derive(Debug, Error)]
pub enum IntakeError {
    #[error("path denied by rule {rule}: {path}")]
    Denied { path: String, rule: String },
    #[error("path is outside the configured roots: {0}")]
    OutsideRoots(String),
    #[error("path does not allow-list match: {0}")]
    NotAllowed(String),
    #[error("file too large ({size} bytes > {max}): {path}")]
    TooLarge { path: String, size: u64, max: u64 },
    #[error("binary or non-UTF-8 file rejected: {0}")]
    Binary(String),
    #[error("cannot read {path}: {reason}")]
    Io { path: String, reason: String },
    #[error("too many files ({0} > max_files)")]
    TooManyFiles(usize),
    #[error("bad line range for {0}")]
    BadRange(String),
}

pub struct PathPolicy {
    roots: Vec<PathBuf>,
    deny: GlobSet,
    deny_src: Vec<String>,
    allow: Option<GlobSet>,
}

fn build_set(globs: &[String]) -> Result<GlobSet> {
    let mut b = GlobSetBuilder::new();
    for g in globs {
        b.add(Glob::new(g).with_context(|| format!("bad glob {g}"))?);
    }
    Ok(b.build()?)
}

impl PathPolicy {
    pub fn new(cfg: &PathsCfg) -> Result<PathPolicy> {
        let mut roots = Vec::new();
        for r in &cfg.roots {
            roots.push(
                std::fs::canonicalize(r)
                    .with_context(|| format!("cannot resolve root {}", r.display()))?,
            );
        }
        let deny_src: Vec<String> = BUILTIN_DENY
            .iter()
            .map(|s| s.to_string())
            .chain(cfg.deny.iter().cloned())
            .collect();
        let deny = build_set(&deny_src)?;
        let allow = if cfg.allow.is_empty() {
            None
        } else {
            Some(build_set(&cfg.allow)?)
        };
        Ok(PathPolicy {
            roots,
            deny,
            deny_src,
            allow,
        })
    }

    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    fn denied_by(&self, p: &Path) -> Option<String> {
        self.deny
            .matches(p)
            .first()
            .map(|&i| self.deny_src[i].clone())
    }

    /// Resolve `raw` (absolute, or relative to the first root) and enforce policy.
    /// Returns (canonical path, root-relative display path).
    pub fn check(&self, raw: &str) -> Result<(PathBuf, String), IntakeError> {
        let p = Path::new(raw);
        let joined = if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.roots
                .first()
                .map(|r| r.join(p))
                .unwrap_or_else(|| p.to_path_buf())
        };
        // deny on the path as given (before symlink resolution) ...
        if let Some(rule) = self.denied_by(&joined).or_else(|| self.denied_by(p)) {
            return Err(IntakeError::Denied {
                path: raw.to_string(),
                rule,
            });
        }
        let canon = std::fs::canonicalize(&joined).map_err(|e| IntakeError::Io {
            path: raw.to_string(),
            reason: e.kind().to_string(),
        })?;
        let Some(root) = self.roots.iter().find(|r| canon.starts_with(r)) else {
            return Err(IntakeError::OutsideRoots(raw.to_string()));
        };
        let rel = canon.strip_prefix(root).unwrap_or(&canon).to_path_buf();
        // ... and on the resolved path, absolute and root-relative
        if let Some(rule) = self.denied_by(&canon).or_else(|| self.denied_by(&rel)) {
            return Err(IntakeError::Denied {
                path: raw.to_string(),
                rule,
            });
        }
        if let Some(allow) = &self.allow {
            if !allow.is_match(&rel) {
                return Err(IntakeError::NotAllowed(raw.to_string()));
            }
        }
        Ok((canon, rel.to_string_lossy().into_owned()))
    }

    /// Write target check: the file may not exist yet. `..` components are rejected, the
    /// deepest existing ancestor is canonicalized (symlinks resolved), the result must be
    /// inside a root and must not match a deny glob. Allow globs scope reads only.
    /// Returns (absolute target, root-relative display path).
    pub fn check_write(&self, raw: &str) -> Result<(PathBuf, String), IntakeError> {
        let p = Path::new(raw);
        if p.components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(IntakeError::OutsideRoots(raw.to_string()));
        }
        let joined = if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.roots
                .first()
                .map(|r| r.join(p))
                .unwrap_or_else(|| p.to_path_buf())
        };
        if let Some(rule) = self.denied_by(&joined).or_else(|| self.denied_by(p)) {
            return Err(IntakeError::Denied {
                path: raw.to_string(),
                rule,
            });
        }
        let target = if joined.exists() {
            let c = std::fs::canonicalize(&joined).map_err(|e| IntakeError::Io {
                path: raw.to_string(),
                reason: e.kind().to_string(),
            })?;
            if !c.is_file() {
                return Err(IntakeError::Io {
                    path: raw.to_string(),
                    reason: "not a regular file".into(),
                });
            }
            c
        } else {
            let mut ancestor = joined.as_path();
            let mut tail = Vec::new();
            while !ancestor.exists() {
                let Some(name) = ancestor.file_name() else {
                    return Err(IntakeError::OutsideRoots(raw.to_string()));
                };
                tail.push(name.to_os_string());
                ancestor = ancestor
                    .parent()
                    .ok_or_else(|| IntakeError::OutsideRoots(raw.to_string()))?;
            }
            let mut c = std::fs::canonicalize(ancestor).map_err(|e| IntakeError::Io {
                path: raw.to_string(),
                reason: e.kind().to_string(),
            })?;
            for t in tail.iter().rev() {
                c.push(t);
            }
            c
        };
        let Some(root) = self.roots.iter().find(|r| target.starts_with(r)) else {
            return Err(IntakeError::OutsideRoots(raw.to_string()));
        };
        let rel = target.strip_prefix(root).unwrap_or(&target).to_path_buf();
        if rel.as_os_str().is_empty() {
            return Err(IntakeError::OutsideRoots(raw.to_string()));
        }
        if let Some(rule) = self.denied_by(&target).or_else(|| self.denied_by(&rel)) {
            return Err(IntakeError::Denied {
                path: raw.to_string(),
                rule,
            });
        }
        Ok((target, rel.to_string_lossy().into_owned()))
    }
}

pub fn load(
    policy: &PathPolicy,
    limits: &Limits,
    refs: &[FileRef],
) -> Result<Vec<LoadedFile>, IntakeError> {
    if refs.len() > limits.max_files {
        return Err(IntakeError::TooManyFiles(refs.len()));
    }
    let mut out = Vec::new();
    for r in refs {
        let (canon, display) = policy.check(&r.path)?;
        let io = |e: std::io::Error| IntakeError::Io {
            path: r.path.clone(),
            reason: e.kind().to_string(),
        };
        let meta = std::fs::metadata(&canon).map_err(io)?;
        if !meta.is_file() {
            return Err(IntakeError::Io {
                path: r.path.clone(),
                reason: "not a regular file".into(),
            });
        }
        if meta.len() > limits.max_file_bytes {
            return Err(IntakeError::TooLarge {
                path: r.path.clone(),
                size: meta.len(),
                max: limits.max_file_bytes,
            });
        }
        let mut bytes = Vec::new();
        std::fs::File::open(&canon)
            .map_err(io)?
            .take(limits.max_file_bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(io)?;
        if bytes.contains(&0) {
            return Err(IntakeError::Binary(r.path.clone()));
        }
        let text = String::from_utf8(bytes).map_err(|_| IntakeError::Binary(r.path.clone()))?;
        let (text, first_line) = slice_lines(&text, r.start_line, r.end_line)
            .ok_or_else(|| IntakeError::BadRange(r.path.clone()))?;
        out.push(LoadedFile {
            display,
            text,
            first_line,
        });
    }
    Ok(out)
}

/// 1-based inclusive line range.
fn slice_lines(text: &str, start: Option<usize>, end: Option<usize>) -> Option<(String, usize)> {
    if start.is_none() && end.is_none() {
        return Some((text.to_string(), 1));
    }
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let s = start.unwrap_or(1);
    let e = end.unwrap_or(lines.len()).min(lines.len());
    if s == 0 || s > e || s > lines.len() {
        return None;
    }
    Some((lines[s - 1..e].concat(), s))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(root: &Path) -> PathPolicy {
        PathPolicy::new(&PathsCfg {
            roots: vec![root.to_path_buf()],
            deny: vec!["internal/**".into()],
            allow: vec![],
        })
        .unwrap()
    }

    #[test]
    fn deny_globs_and_roots() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("proj");
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("internal")).unwrap();
        std::fs::create_dir_all(root.join("config")).unwrap();
        std::fs::write(root.join("src/a.py"), "x = 1\ny = 2\nz = 3\n").unwrap();
        std::fs::write(root.join(".env"), "A=1").unwrap();
        std::fs::write(root.join("config/.env.local"), "A=1").unwrap();
        std::fs::write(root.join("server.pem"), "x").unwrap();
        std::fs::write(root.join("internal/core.py"), "x").unwrap();
        std::fs::write(d.path().join("outside.py"), "x").unwrap();
        let p = policy(&root);
        let lim = Limits::default();

        assert!(p.check("src/a.py").is_ok());
        for bad in [
            ".env",
            "config/.env.local",
            "server.pem",
            "internal/core.py",
        ] {
            assert!(
                matches!(p.check(bad), Err(IntakeError::Denied { .. })),
                "{bad}"
            );
        }
        let abs_env = root.join(".env");
        assert!(matches!(
            p.check(abs_env.to_str().unwrap()),
            Err(IntakeError::Denied { .. })
        ));
        let outside = d.path().join("outside.py");
        assert!(matches!(
            p.check(outside.to_str().unwrap()),
            Err(IntakeError::OutsideRoots(_))
        ));
        assert!(matches!(
            p.check("../outside.py"),
            Err(IntakeError::OutsideRoots(_))
        ));

        let f = load(
            &p,
            &lim,
            &[FileRef {
                path: "src/a.py".into(),
                start_line: Some(2),
                end_line: Some(3),
            }],
        )
        .unwrap();
        assert_eq!(f[0].text, "y = 2\nz = 3\n");
        assert_eq!(f[0].first_line, 2);
        assert_eq!(f[0].display, "src/a.py");
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escape_and_symlink_to_denied() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("proj");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(d.path().join("secret.py"), "x").unwrap();
        std::fs::write(root.join(".env"), "A=1").unwrap();
        std::os::unix::fs::symlink(d.path().join("secret.py"), root.join("link.py")).unwrap();
        std::os::unix::fs::symlink(root.join(".env"), root.join("innocent.txt")).unwrap();
        let p = policy(&root);
        assert!(matches!(
            p.check("link.py"),
            Err(IntakeError::OutsideRoots(_))
        ));
        assert!(matches!(
            p.check("innocent.txt"),
            Err(IntakeError::Denied { .. })
        ));
    }

    #[test]
    fn binary_and_size() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("b.bin"), [0u8, 1, 2]).unwrap();
        std::fs::write(d.path().join("big.txt"), "a".repeat(100)).unwrap();
        let p = policy(d.path());
        let lim = Limits {
            max_file_bytes: 50,
            ..Limits::default()
        };
        let r = |path: &str| FileRef {
            path: path.into(),
            start_line: None,
            end_line: None,
        };
        assert!(matches!(
            load(&p, &lim, &[r("b.bin")]),
            Err(IntakeError::Binary(_))
        ));
        assert!(matches!(
            load(&p, &lim, &[r("big.txt")]),
            Err(IntakeError::TooLarge { .. })
        ));
    }
}
