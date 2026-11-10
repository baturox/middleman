//! File intake: middleman reads files itself. Only configured roots are readable; symlinks are
//! resolved before matching; deny globs always win (matched case-insensitively: macOS and
//! Windows file systems are); size caps; binary / non-UTF-8 rejected.
//!
//! File-mode writes additionally refuse `WRITE_DENY` (agent / editor / CI / hook / shell
//! config that would turn a write into code execution) and any symlink on the way.

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use globset::{Glob, GlobBuilder, GlobSet, GlobSetBuilder};
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

/// Never written by file mode (in addition to the read deny list): files that configure an
/// agent, editor, CI, git hooks, test collection or a shell, plus middleman's own artifacts.
pub const WRITE_DENY: &[&str] = &[
    "**/.claude/**",
    "**/.mcp.json",
    "**/.middleman.toml",
    "**/CLAUDE.md",
    "**/CLAUDE.local.md",
    "**/AGENTS.md",
    "**/.github/**",
    "**/.gitlab-ci.yml",
    "**/.vscode/**",
    "**/.idea/**",
    "**/.husky/**",
    "**/.git/**",
    "**/.gitmodules",
    "**/.gitattributes",
    "**/.gitconfig",
    "**/conftest.py",
    "**/sitecustomize.py",
    "**/usercustomize.py",
    "**/*.pth",
    "**/.pre-commit-config.yaml",
    "**/.envrc",
    "**/.bashrc",
    "**/.bash_profile",
    "**/.bash_login",
    "**/.bash_logout",
    "**/.profile",
    "**/.zshrc",
    "**/.zshenv",
    "**/.zprofile",
    "**/.zlogin",
    "**/.zlogout",
    "**/.cshrc",
    "**/.tcshrc",
    "**/.kshrc",
    "**/.config/fish/**",
];

/// middleman's own staging artifacts (`x.middleman.new`, `x.middleman.patch`): only
/// middleman itself creates them.
const ARTIFACT_GLOB: &str = "**/*.middleman.*";

pub struct PathPolicy {
    roots: Vec<PathBuf>,
    deny: GlobSet,
    deny_src: Vec<String>,
    write_deny: GlobSet,
    write_deny_src: Vec<String>,
    artifact: GlobSet,
    allow: Option<GlobSet>,
    write_allow: Option<GlobSet>,
}

/// Deny globs match case-insensitively (`.ENV`, `Secrets/`, `prod.PEM`).
fn build_set_ci(globs: &[String]) -> Result<GlobSet> {
    let mut b = GlobSetBuilder::new();
    for g in globs {
        b.add(
            GlobBuilder::new(g)
                .case_insensitive(true)
                .build()
                .with_context(|| format!("bad glob {g}"))?,
        );
    }
    Ok(b.build()?)
}

fn build_set(globs: &[String]) -> Result<GlobSet> {
    let mut b = GlobSetBuilder::new();
    for g in globs {
        b.add(Glob::new(g).with_context(|| format!("bad glob {g}"))?);
    }
    Ok(b.build()?)
}

fn present(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok()
}

fn is_symlink(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink())
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
        let deny = build_set_ci(&deny_src)?;
        let write_deny_src: Vec<String> = WRITE_DENY.iter().map(|s| s.to_string()).collect();
        let write_deny = build_set_ci(&write_deny_src)?;
        let artifact = build_set_ci(&[ARTIFACT_GLOB.to_string()])?;
        let opt = |v: &[String]| -> Result<Option<GlobSet>> {
            Ok(if v.is_empty() {
                None
            } else {
                Some(build_set(v)?)
            })
        };
        Ok(PathPolicy {
            roots,
            deny,
            deny_src,
            write_deny,
            write_deny_src,
            artifact,
            allow: opt(&cfg.allow)?,
            write_allow: opt(&cfg.write_allow)?,
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

    /// Read deny, then write deny, then (unless `staging`) the artifact glob.
    fn write_denied_by(&self, p: &Path, staging: bool) -> Option<String> {
        self.denied_by(p)
            .or_else(|| {
                self.write_deny
                    .matches(p)
                    .first()
                    .map(|&i| self.write_deny_src[i].clone())
            })
            .or_else(|| (!staging && self.artifact.is_match(p)).then(|| ARTIFACT_GLOB.to_string()))
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
    /// inside a root and must not match a deny or write-deny glob (nor `write_allow`, when
    /// set). The target itself must not be a symlink (dangling or not), and no existing
    /// component between the root and the target may be one.
    /// Returns (absolute target, root-relative display path).
    pub fn check_write(&self, raw: &str) -> Result<(PathBuf, String), IntakeError> {
        self.check_write_inner(raw, false)
    }

    /// `check_write` for middleman's own `.middleman.new` / `.middleman.patch` files.
    pub fn check_write_staging(&self, raw: &str) -> Result<(PathBuf, String), IntakeError> {
        self.check_write_inner(raw, true)
    }

    fn check_write_inner(
        &self,
        raw: &str,
        staging: bool,
    ) -> Result<(PathBuf, String), IntakeError> {
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
        let denied = |path: &Path| {
            self.write_denied_by(path, staging)
                .map(|rule| IntakeError::Denied {
                    path: raw.to_string(),
                    rule,
                })
        };
        if let Some(e) = denied(&joined).or_else(|| denied(p)) {
            return Err(e);
        }
        let symlink_err = || IntakeError::Io {
            path: raw.to_string(),
            reason: "symlinks are not followed for writes".into(),
        };
        if is_symlink(&joined) {
            return Err(symlink_err());
        }
        if let Some(r) = self.roots.iter().find(|r| joined.starts_with(r)) {
            let mut cur = r.clone();
            for comp in joined.strip_prefix(r).unwrap_or(&joined).components() {
                cur.push(comp);
                if is_symlink(&cur) {
                    return Err(symlink_err());
                }
            }
        }
        let target = if present(&joined) {
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
            while !present(ancestor) {
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
        // the canonical prefix has no symlinks by construction; re-check every existing
        // component below the root (and the leaf) in case one appeared meanwhile
        let mut cur = root.clone();
        for comp in rel.components() {
            cur.push(comp);
            if is_symlink(&cur) {
                return Err(symlink_err());
            }
        }
        if let Some(e) = denied(&target).or_else(|| denied(&rel)) {
            return Err(e);
        }
        if let Some(allow) = &self.write_allow {
            if !staging && !allow.is_match(&rel) {
                return Err(IntakeError::NotAllowed(raw.to_string()));
            }
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
            write_allow: vec![],
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
    fn deny_globs_are_case_insensitive() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("proj");
        std::fs::create_dir_all(root.join("Secrets")).unwrap();
        std::fs::create_dir_all(root.join("b")).unwrap();
        for f in [
            "Secrets/db.yaml",
            "prod.PEM",
            "b/Credentials.json",
            "b/ID_RSA",
            "ok.py",
        ] {
            std::fs::write(root.join(f), "x").unwrap();
        }
        let p = policy(&root);
        for bad in [
            "Secrets/db.yaml",
            "prod.PEM",
            "b/Credentials.json",
            "b/ID_RSA",
        ] {
            assert!(
                matches!(p.check(bad), Err(IntakeError::Denied { .. })),
                "{bad}"
            );
            assert!(p.check_write(bad).is_err(), "{bad}");
        }
        assert!(p.check("ok.py").is_ok());
        assert!(p.check_write(".GIT/hooks/pre-commit").is_err());
    }

    #[test]
    fn write_deny_set() {
        let d = tempfile::tempdir().unwrap();
        let p = policy(d.path());
        for bad in [
            ".claude/settings.local.json",
            ".claude/settings.json",
            "sub/.mcp.json",
            ".middleman.toml",
            "CLAUDE.md",
            "pkg/AGENTS.md",
            "tests/conftest.py",
            ".github/workflows/x.yml",
            ".vscode/tasks.json",
            ".idea/workspace.xml",
            ".husky/pre-commit",
            ".gitmodules",
            ".gitattributes",
            ".zshrc",
            ".bashrc",
            "x.py.middleman.new",
        ] {
            assert!(
                matches!(p.check_write(bad), Err(IntakeError::Denied { .. })),
                "{bad}"
            );
        }
        assert!(p.check_write("tests/test_x.py").is_ok());
        assert!(p
            .check_write_staging("tests/test_x.py.middleman.new")
            .is_ok());
        // reads are not affected by the write deny list
        std::fs::write(d.path().join("CLAUDE.md"), "x").unwrap();
        assert!(p.check("CLAUDE.md").is_ok());
        let pw = PathPolicy::new(&PathsCfg {
            roots: vec![d.path().to_path_buf()],
            write_allow: vec!["tests/**".into()],
            ..Default::default()
        })
        .unwrap();
        assert!(pw.check_write("tests/test_x.py").is_ok());
        assert!(matches!(
            pw.check_write("src/x.py"),
            Err(IntakeError::NotAllowed(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn dangling_symlink_write_target_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(d.path()).unwrap();
        let root = base.join("proj");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::os::unix::fs::symlink("../victim/authorized_keys", root.join("gen.py")).unwrap();
        std::os::unix::fs::symlink(root.join("sub"), root.join("linkdir")).unwrap();
        let p = policy(&root);
        assert!(p.check_write("gen.py").is_err());
        assert!(p.check_write("linkdir/x.py").is_err());
        assert!(p.check_write("sub/x.py").is_ok());
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
