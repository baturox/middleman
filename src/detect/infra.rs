//! Infrastructure identifiers: URL hosts, bare hostnames, IPv4/IPv6, absolute paths / home dirs.

use std::net::Ipv6Addr;
use std::sync::LazyLock;

use regex::Regex;

use super::{byte_at, byte_before, is_word_byte, Category, Finding};

/// Group 1: everything after `scheme://` (userinfo, host, port, path, query, fragment);
/// group 2: the host.
static URL_HOST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b[a-z][a-z0-9+.\-]*://((?:[^/\s@"'<>]+@)?(\[[0-9a-f:.]+\]|[^/\s:?#"'<>()\[\]{}`,;]+)[^\s"'<>`]*)"#)
        .expect("static regex")
});
static HOST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})\b")
        .expect("static regex")
});
static IPV4: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\b").expect("static regex")
});
static IPV6: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}").expect("static regex")
});
/// A home directory and everything below it.
static HOME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"/Users/[A-Za-z0-9._\-]+(?:/[A-Za-z0-9._\-~+@%]+)*|/home/[A-Za-z0-9._\-]+(?:/[A-Za-z0-9._\-~+@%]+)*|[A-Za-z]:\\Users\\[A-Za-z0-9._\-]+(?:\\[A-Za-z0-9._\-~+@%]+)*")
        .expect("static regex")
});
/// Other absolute filesystem paths (two or more segments under a usual top-level directory).
/// Route strings such as `/api/v1/users` are not filesystem paths and are left alone.
static ABS_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:^|[\s"'`(=,\[{:])(/(?:var|srv|opt|mnt|media|data|private|Volumes|root|tmp|etc|scratch|work|builds|projects|code|nfs|net|storage|usr/local)(?:/[A-Za-z0-9._\-~+@%]+)+)"#)
        .expect("static regex")
});
/// Absolute paths that say nothing about the machine or the project.
const GENERIC_PATHS: &[&str] = &[
    "/etc/hosts",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/resolv.conf",
    "/etc/os-release",
    "/var/log",
    "/var/tmp",
    "/usr/local/bin",
    "/usr/local/lib",
];

/// TLDs accepted for bare hostnames. File-extension-like TLDs (rs, py, md, sh, js...) are
/// deliberately absent; hosts inside URLs are caught regardless of TLD.
const TLDS: &[&str] = &[
    "com",
    "net",
    "org",
    "io",
    "dev",
    "ai",
    "co",
    "edu",
    "gov",
    "mil",
    "cloud",
    "tech",
    "xyz",
    "tr",
    "de",
    "uk",
    "fr",
    "nl",
    "eu",
    "us",
    "ca",
    "au",
    "jp",
    "cn",
    "ru",
    "br",
    "es",
    "ch",
    "pl",
    "at",
    "be",
    "kr",
    "internal",
    "local",
    "corp",
    "lan",
    "intra",
    "intranet",
    "priv",
    "localdomain",
    "svc",
    "cluster",
];

/// Last labels that are file extensions, never TLDs of a 3+ label host outside a host context.
const FILE_EXTS: &[&str] = &[
    "py", "rs", "js", "ts", "tsx", "jsx", "mjs", "cjs", "md", "json", "yaml", "yml", "toml", "txt",
    "html", "htm", "css", "scss", "sh", "go", "java", "kt", "rb", "php", "cpp", "hpp", "cc",
    "lock", "log", "cfg", "ini", "xml", "csv", "sql", "swift", "vue", "proto", "gradle", "scala",
    "pl", "lua", "dart", "ex", "exs", "erl", "hs", "ml", "zig", "nim", "jl", "tf", "bak", "tmp",
    "orig", "png", "jpg", "jpeg", "gif", "svg", "pdf", "zip", "gz", "tar", "whl", "egg", "so",
    "dylib", "dll", "exe", "bin", "dat", "db", "env", "pyc", "pyi", "ipynb", "class", "jar", "map",
    "min", "rst", "conf", "pem", "crt", "key", "pub", "spec", "test", "snap", "patch", "diff",
    "new", "old",
];

/// Words shortly before a token that make it a host (`connect to x.y.app`, `host: a.b`).
fn host_context(text: &str, start: usize) -> bool {
    static CTX: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)(?:host|server|domain|connect|ssh|scp|rsync|url|uri|endpoint|dns|cname|fqdn|ping|curl|wget|dial|address|addr|proxy|mirror|registry|origin|upstream|remote)[^\n]{0,16}$|(?:@|//)$")
            .expect("static regex")
    });
    let mut from = start.saturating_sub(32);
    while !text.is_char_boundary(from) {
        from += 1;
    }
    CTX.is_match(&text[from..start])
}

/// First labels that indicate a member access in code (`self.org`, `user.com`), not a host.
const CODE_LABELS: &[&str] = &[
    "self", "this", "cls", "obj", "ctx", "req", "res", "resp", "request", "response", "os", "sys",
    "std", "super", "crate", "window", "document", "console", "module", "exports", "process",
    "user", "item", "config", "cfg", "app", "model", "data", "node", "el", "e", "x", "args",
    "opts", "options", "props", "state", "event", "settings", "env", "params",
];

pub fn is_reserved_host(h: &str) -> bool {
    let h = h.to_ascii_lowercase();
    let h = h.trim_end_matches('.');
    h == "localhost"
        || h == "example.com"
        || h == "example.net"
        || h == "example.org"
        || h.ends_with(".example.com")
        || h.ends_with(".example.net")
        || h.ends_with(".example.org")
        || h.ends_with(".example")
        || h.ends_with(".invalid")
        || h.ends_with(".test")
        || h.ends_with(".localhost")
}

fn is_reserved_ipv4(o: [u8; 4]) -> bool {
    matches!(
        o,
        [127, _, _, _]
            | [0, 0, 0, 0]
            | [255, 255, 255, 255]
            | [192, 0, 2, _]
            | [198, 51, 100, _]
            | [203, 0, 113, _]
    )
}

pub struct InfraScanner {
    roots: Vec<String>,
    public_hosts: Vec<String>,
}

impl InfraScanner {
    pub fn new(mut roots: Vec<String>, public_hosts: Vec<String>) -> Self {
        // longest first so nested roots map to the most specific one
        roots.sort_by_key(|r| std::cmp::Reverse(r.len()));
        roots.retain(|r| r.len() > 1);
        InfraScanner {
            roots,
            public_hosts: public_hosts
                .into_iter()
                .map(|h| h.to_ascii_lowercase())
                .collect(),
        }
    }

    fn keep_host(&self, h: &str) -> bool {
        let l = h.to_ascii_lowercase();
        is_reserved_host(&l)
            || self.public_hosts.contains(&l)
            || l.parse::<std::net::Ipv4Addr>().is_ok()
            || l.starts_with('[')
    }

    pub fn scan(&self, text: &str, out: &mut Vec<Finding>) {
        // URLs (any TLD, including single-label service names). With nothing after the host
        // only the host is replaced; otherwise everything after `scheme://` (userinfo, port,
        // path, query) goes, so `https://h:8443/v2/charges` becomes `https://svc1.example.net/p1`.
        for c in URL_HOST.captures_iter(text) {
            let whole = c.get(1).unwrap();
            let h = c.get(2).unwrap();
            let host = h.as_str().trim_end_matches('.');
            if host.is_empty() || self.keep_url_host(host) {
                continue;
            }
            let end = whole.start() + trim_url_end(whole.as_str()).len();
            let rest_after_host = &text[h.start() + host.len()..end];
            let has_userinfo = h.start() > whole.start();
            if rest_after_host.is_empty() && !has_userinfo {
                if host.parse::<std::net::Ipv4Addr>().is_ok() {
                    continue; // a bare IP literal: the IPv4 scanner owns it
                }
                out.push(Finding::new(
                    Category::Url,
                    "URL host",
                    h.start(),
                    h.start() + host.len(),
                ));
            } else {
                out.push(Finding::new(Category::Url, "URL", whole.start(), end));
            }
        }
        // bare hostnames: listed TLDs anywhere; any 2-24 letter TLD for 3+ labels that look
        // like a host (a label with a digit or hyphen) or that sit in a host-like context
        for c in HOST.captures_iter(text) {
            let m = c.get(0).unwrap();
            let tld = c.get(1).unwrap().as_str().to_ascii_lowercase();
            if self.keep_host(m.as_str()) {
                continue;
            }
            if byte_before(text, m.start()).is_some_and(|b| b == b'.' || b == b'$') {
                continue;
            }
            let labels: Vec<&str> = m.as_str().split('.').collect();
            let first = labels[0].to_ascii_lowercase();
            let listed = TLDS.contains(&tld.as_str());
            let ctx = host_context(text, m.start());
            let call = byte_at(text, m.end()) == Some(b'(');
            let accept = if listed {
                if labels.len() == 2 {
                    !call && !CODE_LABELS.contains(&first.as_str())
                } else {
                    true
                }
            } else if FILE_EXTS.contains(&tld.as_str()) {
                false
            } else if labels.len() >= 3 {
                let hosty = labels[..labels.len() - 1]
                    .iter()
                    .any(|l| l.contains('-') || l.bytes().any(|b| b.is_ascii_digit()));
                (hosty && !CODE_LABELS.contains(&first.as_str()) && !call) || ctx
            } else {
                ctx && !call
            };
            if accept {
                out.push(Finding::new(Category::Host, "hostname", m.start(), m.end()));
            }
        }
        for c in IPV4.captures_iter(text) {
            let m = c.get(0).unwrap();
            let mut o = [0u8; 4];
            let mut ok = true;
            for (i, slot) in o.iter_mut().enumerate() {
                match c.get(i + 1).unwrap().as_str().parse::<u8>() {
                    Ok(v) => *slot = v,
                    Err(_) => ok = false,
                }
            }
            if !ok || is_reserved_ipv4(o) {
                continue;
            }
            if byte_before(text, m.start()) == Some(b'.') {
                continue; // part of a longer dotted version string
            }
            // a trailing '.' is a sentence end unless another number follows (1.2.3.4.5)
            if byte_at(text, m.end()) == Some(b'.')
                && byte_at(text, m.end() + 1).is_some_and(|b| b.is_ascii_digit())
            {
                continue;
            }
            out.push(Finding::new(Category::Ipv4, "IPv4", m.start(), m.end()));
        }
        for m in IPV6.find_iter(text) {
            let s = m.as_str();
            if !s.contains("::") && s.matches(':').count() < 7 {
                continue;
            }
            if s.len() < 3
                || byte_before(text, m.start()).is_some_and(is_word_byte)
                || byte_at(text, m.end()).is_some_and(is_word_byte)
            {
                continue;
            }
            let Ok(addr) = s.parse::<Ipv6Addr>() else {
                continue;
            };
            let seg = addr.segments();
            let has_letter_or_many = s.matches(':').count() >= 3;
            let documentation = seg[0] == 0x2001 && seg[1] == 0x0db8;
            if addr.is_loopback() || addr.is_unspecified() || documentation || !has_letter_or_many {
                continue;
            }
            out.push(Finding::new(Category::Ipv6, "IPv6", m.start(), m.end()));
        }
        // configured project roots, then home directories and other absolute paths (the
        // whole path, not just its first two segments)
        let mut root_starts = Vec::new();
        for root in &self.roots {
            let mut from = 0;
            while let Some(i) = text[from..].find(root.as_str()) {
                let s = from + i;
                let e = s + root.len();
                // `<root>-old`, `<root>2`, `<root>.bak` name another directory; `<root>.` ends
                // a sentence
                let next = byte_at(text, e);
                let longer = next.is_some_and(|b| is_word_byte(b) || b == b'-')
                    || (next == Some(b'.')
                        && byte_at(text, e + 1).is_some_and(|b| is_word_byte(b) || b == b'-'));
                if !longer && !root_starts.contains(&s) {
                    out.push(Finding::new(Category::Path, "project root", s, e));
                    root_starts.push(s);
                }
                from = e;
            }
        }
        for m in HOME.find_iter(text) {
            if root_starts.contains(&m.start()) {
                continue;
            }
            let p = m.as_str().trim_end_matches('.');
            out.push(Finding::new(
                Category::Path,
                "home directory",
                m.start(),
                m.start() + p.len(),
            ));
        }
        for c in ABS_PATH.captures_iter(text) {
            let m = c.get(1).unwrap();
            let p = m.as_str().trim_end_matches('.');
            if root_starts.contains(&m.start())
                || self.roots.iter().any(|r| p.starts_with(r.as_str()))
                || GENERIC_PATHS.iter().any(|g| p == *g)
            {
                continue;
            }
            out.push(Finding::new(
                Category::Path,
                "absolute path",
                m.start(),
                m.start() + p.len(),
            ));
        }
    }

    /// Hosts whose URLs are kept verbatim: reserved, configured public, loopback/doc IPs,
    /// and bracketed IPv6 literals (the IPv6 scanner handles those).
    fn keep_url_host(&self, h: &str) -> bool {
        let l = h.to_ascii_lowercase();
        if let Ok(ip) = l.parse::<std::net::Ipv4Addr>() {
            return is_reserved_ipv4(ip.octets());
        }
        is_reserved_host(&l) || self.public_hosts.contains(&l) || l.starts_with('[')
    }
}

/// Drop trailing sentence punctuation and unbalanced closing brackets from a URL match.
fn trim_url_end(u: &str) -> &str {
    let mut s = u;
    loop {
        let before = s.len();
        s = s.trim_end_matches(['.', ',', ';', ':', '!', '?']);
        for (open, close) in [('(', ')'), ('[', ']'), ('{', '}')] {
            if s.ends_with(close) && s.matches(close).count() > s.matches(open).count() {
                s = &s[..s.len() - 1];
            }
        }
        if s.len() == before {
            return s;
        }
    }
}

/// The host part of a URL finding's text (`user@host:port/path` -> `host`).
pub fn url_host(rest: &str) -> &str {
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let after_user = match rest[..auth_end].rfind('@') {
        Some(i) => i + 1,
        None => 0,
    };
    let r = &rest[after_user..];
    if r.starts_with('[') {
        return r.find(']').map(|i| &r[..=i]).unwrap_or(r);
    }
    let end = r.find([':', '/', '?', '#']).unwrap_or(r.len());
    r[..end].trim_end_matches('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(t: &str) -> Vec<(Category, String)> {
        let s = InfraScanner::new(vec!["/Users/jane/acme".into()], vec!["github.com".into()]);
        let mut v = vec![];
        s.scan(t, &mut v);
        v.into_iter()
            .map(|f| (f.category, t[f.start..f.end].to_string()))
            .collect()
    }

    #[test]
    fn hosts() {
        let r = scan("connect to https://billing.acme-corp.io:8443/v1/x and db.acme.internal");
        assert!(r.contains(&(Category::Url, "billing.acme-corp.io:8443/v1/x".into())));
        assert!(r.contains(&(Category::Host, "db.acme.internal".into())));
        let r = scan("http://billing-svc:8080/health");
        assert_eq!(r, vec![(Category::Url, "billing-svc:8080/health".into())]);
        let r = scan("see https://billing-svc.");
        assert_eq!(r, vec![(Category::Url, "billing-svc".into())]);
        let r = scan("(at https://a.acme.io/x/y), or postgres://rw@db1:5432/ledger.");
        assert!(
            r.contains(&(Category::Url, "a.acme.io/x/y".into())),
            "{r:?}"
        );
        assert!(
            r.contains(&(Category::Url, "rw@db1:5432/ledger".into())),
            "{r:?}"
        );
        assert_eq!(url_host("rw@db1:5432/ledger"), "db1");
        assert_eq!(url_host("a.acme.io/x?q=1"), "a.acme.io");
    }

    #[test]
    fn host_negatives() {
        assert!(scan("import os.path; main.rs; file.py; self.org = 1; README.md").is_empty());
        assert!(scan("see https://github.com/x/y and svc2.example.net").is_empty());
        assert!(scan("x = foo.com()").is_empty());
        for code in [
            "obj.method.call()",
            "self.config.get",
            "np.random.rand",
            "tests.test_billing.py",
            "lodash.debounce.min",
            "foo.bar.baz",
        ] {
            assert!(scan(code).is_empty(), "{code}: {:?}", scan(code));
        }
    }

    #[test]
    fn host_positives_beyond_tld_list() {
        for (t, want) in [
            (
                "connect to build01.payments-core.app on 5432",
                "build01.payments-core.app",
            ),
            (
                "see vault.payments-core.io(primary)",
                "vault.payments-core.io",
            ),
            (
                "scp deploy@bastion.payments-core.io:/srv x",
                "bastion.payments-core.io",
            ),
            ("host: api.payments.app", "api.payments.app"),
        ] {
            assert!(
                scan(t).contains(&(Category::Host, want.into())),
                "{t}: {:?}",
                scan(t)
            );
        }
    }

    #[test]
    fn ips() {
        let r = scan("hosts 10.20.30.40 and fe80::1ff:fe23:4567:890a and 127.0.0.1");
        assert!(r.contains(&(Category::Ipv4, "10.20.30.40".into())));
        assert!(r.contains(&(Category::Ipv6, "fe80::1ff:fe23:4567:890a".into())));
        assert!(!r.iter().any(|(_, s)| s == "127.0.0.1"));
        assert!(scan("version 1.2.3.4.5 and 198.51.100.7").is_empty());
        let r = scan("Primary database is 10.20.30.40.");
        assert!(r.contains(&(Category::Ipv4, "10.20.30.40".into())), "{r:?}");
        assert!(scan("use std::fmt; de::Error; at 12:30:45").is_empty());
    }

    #[test]
    fn paths() {
        let r = scan("open /Users/jane/acme/src/x.rs and /home/bob/.cache/acme.");
        assert!(
            r.contains(&(Category::Path, "/Users/jane/acme".into())),
            "{r:?}"
        );
        assert!(
            r.contains(&(Category::Path, "/home/bob/.cache/acme".into())),
            "{r:?}"
        );
        // the root at the end of a sentence; a longer sibling name is not the root
        let r = scan("the repo is at /Users/jane/acme. Also /Users/jane/acme.bak/x");
        assert!(
            r.contains(&(Category::Path, "/Users/jane/acme".into())),
            "{r:?}"
        );
        assert!(
            r.contains(&(Category::Path, "/Users/jane/acme.bak/x".into())),
            "{r:?}"
        );
        // other absolute filesystem paths go whole; routes and system paths stay
        let r = scan("data in /srv/zr/ledger/db, see \"/opt/acme/bin/run\" and /etc/hosts");
        assert!(
            r.contains(&(Category::Path, "/srv/zr/ledger/db".into())),
            "{r:?}"
        );
        assert!(
            r.contains(&(Category::Path, "/opt/acme/bin/run".into())),
            "{r:?}"
        );
        assert!(scan("GET \"/api/v1/users\" and /etc/hosts and /usr/bin/env").is_empty());
    }
}
