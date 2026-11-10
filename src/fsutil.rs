//! Small filesystem helpers shared by the config editor, key store and `setup claude`.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// The real file behind `path` when it is a symlink (dotfile managers), so an atomic
/// rename replaces the target instead of the link.
pub fn resolve_link(path: &Path) -> PathBuf {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => {
            std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
        }
        _ => path.to_path_buf(),
    }
}

fn random_suffix() -> String {
    let mut b = [0u8; 6];
    let _ = getrandom::fill(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Write `bytes` to `path` atomically: a temp file in the same directory, fsync, rename.
/// An existing file keeps its permissions; a new file gets `new_mode` (unix) or 0600.
pub fn write_atomic(path: &Path, bytes: &[u8], new_mode: Option<u32>) -> Result<()> {
    let target = resolve_link(path);
    let dir = target
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".into());
    let tmp = dir.join(format!(".{name}.middleman-tmp-{}", random_suffix()));
    let existing = std::fs::metadata(&target).ok();
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mode = existing
            .as_ref()
            .map(|m| m.permissions().mode() & 0o777)
            .or(new_mode)
            .unwrap_or(0o600);
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = (&existing, new_mode);
    let res = (|| -> Result<()> {
        let mut f = opts
            .open(&tmp)
            .with_context(|| format!("cannot create {}", tmp.display()))?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        #[cfg(unix)]
        if let Some(m) = &existing {
            // create_new honours the umask; restore the original mode exactly
            std::fs::set_permissions(&tmp, m.permissions())?;
        }
        std::fs::rename(&tmp, &target)
            .with_context(|| format!("cannot replace {}", target.display()))?;
        Ok(())
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

/// `~`-relative display of a path, for messages.
pub fn pretty(path: &Path) -> String {
    if let Some(home) = std::env::var_os("HOME") {
        if let Ok(rest) = path.strip_prefix(&home) {
            return format!("~/{}", rest.display());
        }
    }
    path.display().to_string()
}

/// Make an untrusted string (provider model ids, labels, ledger fields) safe to print on a
/// terminal: control characters and ANSI escapes removed, at most `max` characters.
pub fn clean(s: &str, max: usize) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    let mut n = 0;
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // skip an escape sequence: ESC [ ... final byte, or ESC + one char
            if chars.peek() == Some(&'[') {
                chars.next();
                for d in chars.by_ref() {
                    if ('@'..='~').contains(&d) {
                        break;
                    }
                }
            } else {
                chars.next();
            }
            continue;
        }
        if c.is_control() || ('\u{80}'..='\u{9f}').contains(&c) {
            continue;
        }
        if n == max {
            out.push('…');
            break;
        }
        out.push(c);
        n += 1;
    }
    out
}

/// Quote a path for a shell command line (Claude Code runs hook/statusline commands in a shell).
pub fn shell_quote(s: &str) -> String {
    let safe = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-+:=@%,".contains(c));
    if safe {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_keeps_mode_and_follows_links() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a.json");
        write_atomic(&p, b"one", None).unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "one");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
            write_atomic(&p, b"two", None).unwrap();
            assert_eq!(
                std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o644
            );
            let link = d.path().join("link.json");
            std::os::unix::fs::symlink(&p, &link).unwrap();
            write_atomic(&link, b"three", None).unwrap();
            assert!(std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink());
            assert_eq!(std::fs::read_to_string(&p).unwrap(), "three");
        }
        let leftovers = std::fs::read_dir(d.path())
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains("middleman-tmp")
            })
            .count();
        assert_eq!(leftovers, 0);
    }

    #[test]
    fn clean_strips_escapes() {
        assert_eq!(clean("a\u{1b}[31mred\u{1b}[0m\nb", 50), "aredb");
        assert_eq!(clean("abcdef", 3), "abc…");
        assert_eq!(clean("x\u{9b}y\u{7}", 10), "xy");
    }

    #[test]
    fn quoting() {
        assert_eq!(shell_quote("/usr/bin/middleman"), "/usr/bin/middleman");
        assert_eq!(shell_quote("/a b/m"), "'/a b/m'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }
}
