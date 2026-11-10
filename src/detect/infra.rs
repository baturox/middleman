//! Infrastructure identifiers: URL hosts, bare hostnames, IPv4/IPv6, absolute paths / home dirs.

use std::net::Ipv6Addr;
use std::sync::LazyLock;

use regex::Regex;

use super::{byte_at, byte_before, is_word_byte, Category, Finding};

static URL_HOST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b[a-z][a-z0-9+.\-]*://(?:[^/\s@"'<>]+@)?(\[[0-9a-f:.]+\]|[^/\s:?#"'<>()\[\]{}`,;]+)"#)
        .expect("static regex")
});
static HOST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})\b")
        .expect("static regex")
});
static IPV4: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b").expect("static regex")
});
static IPV6: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}").expect("static regex")
});
static HOME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"/Users/[A-Za-z0-9._\-]+|/home/[A-Za-z0-9._\-]+|[A-Za-z]:\\Users\\[A-Za-z0-9._\-]+")
        .expect("static regex")
});

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
        // URL hosts (any TLD, including single-label service names)
        for c in URL_HOST.captures_iter(text) {
            let h = c.get(1).unwrap();
            let host = h.as_str().trim_end_matches('.');
            if host.is_empty() || self.keep_host(host) {
                continue;
            }
            out.push(Finding::new(
                Category::Url,
                "URL host",
                h.start(),
                h.start() + host.len(),
            ));
        }
        // bare hostnames
        for c in HOST.captures_iter(text) {
            let m = c.get(0).unwrap();
            let tld = c.get(1).unwrap().as_str().to_ascii_lowercase();
            if !TLDS.contains(&tld.as_str()) || self.keep_host(m.as_str()) {
                continue;
            }
            if byte_at(text, m.end()) == Some(b'(') {
                continue; // method call
            }
            if byte_before(text, m.start()).is_some_and(|b| b == b'.' || b == b'$' || b == b'@') {
                continue;
            }
            let labels: Vec<&str> = m.as_str().split('.').collect();
            if labels.len() == 2 && CODE_LABELS.contains(&labels[0].to_ascii_lowercase().as_str()) {
                continue;
            }
            out.push(Finding::new(Category::Host, "hostname", m.start(), m.end()));
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
            if byte_before(text, m.start()) == Some(b'.') || byte_at(text, m.end()) == Some(b'.') {
                continue; // part of a longer dotted version string
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
        // configured project roots, then generic home directories
        for root in &self.roots {
            let mut from = 0;
            while let Some(i) = text[from..].find(root.as_str()) {
                let s = from + i;
                let e = s + root.len();
                if !byte_at(text, e).is_some_and(|b| is_word_byte(b) || b == b'-' || b == b'.') {
                    out.push(Finding::new(Category::Path, "project root", s, e));
                }
                from = e;
            }
        }
        for m in HOME.find_iter(text) {
            out.push(Finding::new(
                Category::Path,
                "home directory",
                m.start(),
                m.end(),
            ));
        }
    }
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
        assert!(r.contains(&(Category::Url, "billing.acme-corp.io".into())));
        assert!(r.contains(&(Category::Host, "db.acme.internal".into())));
        let r = scan("http://billing-svc:8080/health");
        assert_eq!(r, vec![(Category::Url, "billing-svc".into())]);
    }

    #[test]
    fn host_negatives() {
        assert!(scan("import os.path; main.rs; file.py; self.org = 1; README.md").is_empty());
        assert!(scan("see https://github.com/x/y and svc2.example.net").is_empty());
        assert!(scan("x = foo.com()").is_empty());
    }

    #[test]
    fn ips() {
        let r = scan("hosts 10.20.30.40 and fe80::1ff:fe23:4567:890a and 127.0.0.1");
        assert!(r.contains(&(Category::Ipv4, "10.20.30.40".into())));
        assert!(r.contains(&(Category::Ipv6, "fe80::1ff:fe23:4567:890a".into())));
        assert!(!r.iter().any(|(_, s)| s == "127.0.0.1"));
        assert!(scan("version 1.2.3.4.5 and 198.51.100.7").is_empty());
        assert!(scan("use std::fmt; de::Error; at 12:30:45").is_empty());
    }

    #[test]
    fn paths() {
        let r = scan("open /Users/jane/acme/src/x.rs and /home/bob/.cache");
        assert!(r.contains(&(Category::Path, "/Users/jane/acme".into())));
        assert!(r.contains(&(Category::Path, "/home/bob".into())));
    }
}
