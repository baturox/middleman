//! `middleman dict suggest`: bootstrap the private dictionary from the project itself.
//!
//! Everything here is local: files under the root, `git config` and `git log`. Nothing is
//! sent anywhere. Sources, strongest first:
//! - the root directory name, the git remote's org and repo, package names in manifests
//!   (high);
//! - author names and e-mail domains in manifests and `git log`, hostnames in config files
//!   (medium);
//! - capitalized, proper-noun-like identifier segments that recur across files and are
//!   neither English words nor library names (low: shown, not preselected).
//!
//! A candidate that is an ordinary English word is downgraded to low: putting `ledger` in
//! the dictionary would rewrite every ledger in your code.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;

use crate::detect::normalize::fold_str;
use crate::detect::{Category, Detector};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn parse(s: &str) -> Option<Confidence> {
        match s.to_ascii_lowercase().as_str() {
            "low" => Some(Confidence::Low),
            "medium" | "med" => Some(Confidence::Medium),
            "high" => Some(Confidence::High),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Candidate {
    pub term: String,
    pub sources: Vec<String>,
    /// Occurrences (or files, for identifiers) across all sources.
    pub count: usize,
    pub confidence: Confidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Spellings added next to the term so they are rewritten instead of blocking the
    /// request (`quasar_ledger`, `quasar-ledger`, `quasar ledger`).
    pub variants: Vec<String>,
}

/// Names that identify nobody: never suggested.
const GENERIC: &[&str] = &[
    "app",
    "apps",
    "api",
    "server",
    "client",
    "core",
    "common",
    "main",
    "src",
    "lib",
    "libs",
    "test",
    "tests",
    "demo",
    "example",
    "examples",
    "sample",
    "project",
    "repo",
    "frontend",
    "backend",
    "web",
    "service",
    "services",
    "utils",
    "tools",
    "my-app",
    "monorepo",
    "workspace",
    "root",
    "admin",
    "user",
    "users",
    "data",
    "docs",
    "readme",
    "license",
    "config",
    "origin",
    "master",
    "noreply",
    "users.noreply",
    "unknown",
    "none",
    "null",
    "home",
    "desktop",
    "personal",
    "documents",
    "downloads",
    "code",
    "dev",
    "work",
    "projects",
    "github",
    "gitlab",
    "bitbucket",
    "claude",
    "anthropic",
    "openai",
    "localhost",
];

/// Programming and library words that look like proper nouns in CamelCase identifiers.
const CODE_WORDS: &[&str] = &[
    "vec",
    "str",
    "json",
    "http",
    "https",
    "url",
    "uri",
    "api",
    "uuid",
    "toml",
    "yaml",
    "sha",
    "hmac",
    "utf",
    "ascii",
    "impl",
    "args",
    "cfg",
    "ctx",
    "req",
    "resp",
    "std",
    "cli",
    "mcp",
    "tty",
    "pty",
    "btree",
    "hashmap",
    "hashset",
    "arc",
    "mutex",
    "rwlock",
    "tokio",
    "serde",
    "regex",
    "anyhow",
    "async",
    "usize",
    "isize",
    "bool",
    "println",
    "eprintln",
    "todo",
    "fixme",
    "github",
    "gitlab",
    "openai",
    "anthropic",
    "claude",
    "linux",
    "macos",
    "windows",
    "python",
    "rust",
    "javascript",
    "typescript",
    "node",
    "react",
    "django",
    "flask",
    "pytest",
    "docker",
    "kubernetes",
    "postgres",
    "sqlite",
    "redis",
    "mongo",
    "mysql",
    "aws",
    "gcp",
    "azure",
    "wiremock",
    "reqwest",
    "clap",
    "dialoguer",
    "tempfile",
    "tracing",
    "openrouter",
    "deepseek",
    "ollama",
    "qwen",
    "kimi",
    "sonnet",
    "opus",
    "haiku",
    "gemini",
    "mistral",
    "jsonl",
    "html",
    "css",
    "svg",
    "pdf",
    "oauth",
    "jwt",
    "sql",
    "nfkc",
    "ipv4",
    "ipv6",
    "rexpect",
    "proptest",
    "keychain",
    "keyring",
    "zeroize",
    "globset",
    "aho",
    "corasick",
    "darwin",
    "unix",
    "posix",
    "stdin",
    "stdout",
    "stderr",
    "nonce",
    "enum",
    "struct",
    "trait",
    "dyn",
    "mut",
    "ref",
    "deref",
    "fmt",
    "repr",
    "derive",
    "cfg",
    "crate",
    "pub",
    "fn",
    "debug",
    "info",
    "email",
    "runtime",
    "formatter",
    "inline",
    "boilerplate",
    "classify",
    "docstring",
    "refactor",
    "deserialize",
    "serialize",
    "zeroizing",
    "catalog",
    "config",
    "english",
    "turkish",
    "german",
    "french",
    "spanish",
    "chinese",
    "japanese",
    "metadata",
    "timestamp",
    "username",
    "hostname",
    "localhost",
    "middleware",
    "webhook",
    "frontend",
    "backend",
    "dataclass",
    "namespace",
    "workflow",
    "endpoint",
    "params",
    "async",
    "readonly",
];

/// Common mail providers: their domains name nobody's company.
const MAIL_PROVIDERS: &[&str] = &[
    "gmail",
    "googlemail",
    "outlook",
    "hotmail",
    "live",
    "yahoo",
    "icloud",
    "me",
    "mac",
    "proton",
    "protonmail",
    "pm",
    "gmx",
    "yandex",
    "aol",
    "mail",
    "fastmail",
    "hey",
    "zoho",
    "noreply",
    "users",
    "example",
];

const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    "vendor",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
    ".middleman",
    ".claude",
    ".idea",
    ".vscode",
    ".next",
    ".cache",
    "coverage",
    ".tox",
];

const SOURCE_EXTS: &[&str] = &[
    "rs", "py", "js", "ts", "tsx", "jsx", "go", "java", "kt", "rb", "php", "cs", "swift", "scala",
    "c", "h", "cpp", "hpp", "md", "vue", "svelte",
];
const CONFIG_EXTS: &[&str] = &[
    "toml",
    "yaml",
    "yml",
    "json",
    "ini",
    "cfg",
    "conf",
    "properties",
    "tf",
    "hcl",
];

const MAX_FILES: usize = 600;
const MAX_FILE_BYTES: u64 = 256 * 1024;

#[derive(Default)]
struct Collector {
    by_key: BTreeMap<String, Candidate>,
}

impl Collector {
    fn add(&mut self, term: &str, source: &str, count: usize, conf: Confidence) {
        let term = term
            .trim()
            .trim_matches(|c: char| c == '"' || c == '\'' || c == '<' || c == '>');
        if term.chars().count() < 3
            || term
                .chars()
                .all(|c| c.is_ascii_digit() || !c.is_alphanumeric())
            || GENERIC.contains(&term.to_lowercase().as_str())
        {
            return;
        }
        let key = fold_str(term);
        let c = self.by_key.entry(key).or_insert_with(|| Candidate {
            term: term.to_string(),
            sources: vec![],
            count: 0,
            confidence: conf,
            note: None,
            variants: vec![],
        });
        if !c.sources.iter().any(|s| s == source) {
            c.sources.push(source.to_string());
        }
        c.count += count.max(1);
        if conf > c.confidence {
            c.confidence = conf;
            // prefer the spelling of the strongest source
            c.term = term.to_string();
        }
    }
}

/// The lower-case entries of the system word list (`/usr/share/dict/words`), if present.
fn english_words() -> HashSet<String> {
    let mut s = HashSet::new();
    for p in ["/usr/share/dict/words", "/usr/share/dict/web2"] {
        if let Ok(t) = std::fs::read_to_string(p) {
            for w in t.lines() {
                if w.chars().next().is_some_and(|c| c.is_lowercase()) {
                    s.insert(w.to_string());
                }
            }
            break;
        }
    }
    s
}

/// `w` (lower case) or a base form of it is in the word list: `stored` -> `store`,
/// `providers` -> `provider`, `cheapest` -> `cheap`, `running` -> `run`.
fn is_english(w: &str, words: &HashSet<String>) -> bool {
    if words.contains(w) {
        return true;
    }
    for suf in [
        "s", "es", "ed", "d", "ing", "er", "ers", "est", "ly", "ies", "ied",
    ] {
        if let Some(stem) = w.strip_suffix(suf) {
            if stem.len() < 3 {
                continue;
            }
            let y = format!("{stem}y");
            let e = format!("{stem}e");
            let undoubled = stem
                .as_bytes()
                .windows(2)
                .last()
                .filter(|p| p[0] == p[1])
                .map(|_| &stem[..stem.len() - 1]);
            if words.contains(stem)
                || ((suf == "ies" || suf == "ied") && words.contains(&y))
                || words.contains(&e)
                || undoubled.is_some_and(|u| words.contains(u))
            {
                return true;
            }
        }
    }
    false
}

fn git(root: &Path, args: &[&str]) -> Option<String> {
    let o = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .ok()?;
    o.status
        .success()
        .then(|| String::from_utf8_lossy(&o.stdout).to_string())
}

/// `git@host:org/repo.git`, `https://host/org/sub/repo`, `ssh://git@host/org/repo` ->
/// (host, org path segments, repo).
pub fn parse_remote(url: &str) -> Option<(String, Vec<String>, String)> {
    let u = url.trim();
    let (host, path) = if let Some(rest) = u.split_once("://").map(|(_, r)| r) {
        let rest = rest.rsplit_once('@').map(|(_, r)| r).unwrap_or(rest);
        let (h, p) = rest.split_once('/')?;
        (h.split(':').next().unwrap_or(h).to_string(), p.to_string())
    } else {
        let rest = u.rsplit_once('@').map(|(_, r)| r).unwrap_or(u);
        let (h, p) = rest.split_once(':')?;
        (h.to_string(), p.to_string())
    };
    let path = path.trim_end_matches('/').trim_end_matches(".git");
    let mut segs: Vec<String> = path
        .split('/')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    let repo = segs.pop()?;
    Some((host, segs, repo))
}

/// The label that names the owner of a host: `billing.zephyrine-corp.io` -> `zephyrine-corp`,
/// `db.prod.zphr.internal` -> `zphr`, `a.acme.co.uk` -> `acme`.
pub fn owner_label(host: &str) -> Option<String> {
    let labels: Vec<&str> = host.trim_end_matches('.').split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    let mut i = labels.len() - 2;
    while i > 0 && ["co", "com", "ac", "gov", "org", "net", "edu"].contains(&labels[i]) {
        i -= 1;
    }
    let l = labels[i].to_ascii_lowercase();
    (l.len() >= 3 && !l.chars().all(|c| c.is_ascii_digit())).then_some(l)
}

fn email_domain_label(email: &str) -> Option<String> {
    let domain = email.trim().rsplit_once('@')?.1.trim_end_matches('>');
    let l = owner_label(domain)?;
    (!MAIL_PROVIDERS.contains(&l.as_str())).then_some(l)
}

/// `Jane Doe <jane@acme.io>` -> ("Jane Doe", Some("jane@acme.io")).
fn split_person(s: &str) -> (String, Option<String>) {
    match s.split_once('<') {
        Some((n, rest)) => (
            n.trim().to_string(),
            Some(rest.trim_end_matches('>').trim().to_string()),
        ),
        None if s.contains('@') => (String::new(), Some(s.trim().to_string())),
        None => (s.trim().to_string(), None),
    }
}

fn walk(root: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if out.len() >= MAX_FILES * 4 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(root) else {
        return;
    };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let p = e.path();
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_symlink() {
            continue;
        }
        let name = e.file_name().to_string_lossy().to_string();
        if ft.is_dir() {
            if depth > 0 && !SKIP_DIRS.contains(&name.as_str()) && !name.starts_with('.') {
                walk(&p, depth - 1, out);
            }
        } else if ft.is_file() && !name.starts_with(".env") {
            out.push(p);
        }
    }
}

fn read_small(p: &Path) -> Option<String> {
    let m = std::fs::metadata(p).ok()?;
    if m.len() > MAX_FILE_BYTES {
        return None;
    }
    std::fs::read_to_string(p).ok()
}

fn ext_of(p: &Path) -> String {
    p.extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default()
}

/// Package names, authors and dependency names (the latter only to exclude them).
fn manifests(files: &[PathBuf], c: &mut Collector, deps: &mut HashSet<String>) {
    let person = |c: &mut Collector, s: &str, src: &str| {
        let (name, email) = split_person(s);
        if name.contains(' ') || name.chars().next().is_some_and(|ch| ch.is_uppercase()) {
            c.add(&name, &format!("{src} author"), 1, Confidence::Medium);
        }
        if let Some(l) = email.as_deref().and_then(email_domain_label) {
            c.add(&l, &format!("{src} author e-mail"), 1, Confidence::Medium);
        }
    };
    for p in files {
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let Some(text) = (match name.as_str() {
            "Cargo.toml" | "package.json" | "pyproject.toml" | "go.mod" | "composer.json" => {
                read_small(p)
            }
            _ => None,
        }) else {
            continue;
        };
        match name.as_str() {
            "Cargo.toml" | "pyproject.toml" => {
                let Ok(v) = text.parse::<toml::Table>() else {
                    continue;
                };
                for tbl in ["dependencies", "dev-dependencies", "build-dependencies"] {
                    if let Some(t) = v.get(tbl).and_then(|t| t.as_table()) {
                        deps.extend(t.keys().map(|k| k.to_lowercase()));
                    }
                }
                let pkgs = [
                    v.get("package"),
                    v.get("project"),
                    v.get("tool").and_then(|t| t.get("poetry")),
                ];
                for pk in pkgs.into_iter().flatten() {
                    if let Some(n) = pk.get("name").and_then(|n| n.as_str()) {
                        c.add(n, &format!("{name} name"), 1, Confidence::High);
                    }
                    for a in pk
                        .get("authors")
                        .and_then(|a| a.as_array())
                        .into_iter()
                        .flatten()
                    {
                        if let Some(s) = a.as_str() {
                            person(c, s, &name);
                        } else if let Some(t) = a.as_table() {
                            let n = t.get("name").and_then(|x| x.as_str()).unwrap_or("");
                            let e = t.get("email").and_then(|x| x.as_str()).unwrap_or("");
                            person(c, &format!("{n} <{e}>"), &name);
                        }
                    }
                }
            }
            "package.json" | "composer.json" => {
                let Ok(v) = serde_json::from_str::<Value>(&text) else {
                    continue;
                };
                for tbl in ["dependencies", "devDependencies", "require", "require-dev"] {
                    if let Some(o) = v.get(tbl).and_then(|o| o.as_object()) {
                        for k in o.keys() {
                            deps.insert(k.to_lowercase());
                            deps.extend(k.split(['/', '@', '-']).map(|s| s.to_lowercase()));
                        }
                    }
                }
                if let Some(n) = v.get("name").and_then(|n| n.as_str()) {
                    for part in n.trim_start_matches('@').split('/') {
                        c.add(part, &format!("{name} name"), 1, Confidence::High);
                    }
                }
                let mut people: Vec<&Value> = vec![];
                people.extend(v.get("author"));
                for k in ["contributors", "authors", "maintainers"] {
                    people.extend(v.get(k).and_then(|a| a.as_array()).into_iter().flatten());
                }
                for a in people {
                    if let Some(s) = a.as_str() {
                        person(c, s, &name);
                    } else {
                        let n = a.get("name").and_then(|x| x.as_str()).unwrap_or("");
                        let e = a.get("email").and_then(|x| x.as_str()).unwrap_or("");
                        person(c, &format!("{n} <{e}>"), &name);
                    }
                }
            }
            "go.mod" => {
                if let Some(m) = text.lines().find_map(|l| l.trim().strip_prefix("module ")) {
                    let segs: Vec<&str> = m.trim().split('/').collect();
                    for s in segs.iter().skip(1) {
                        c.add(s, "go.mod module", 1, Confidence::High);
                    }
                    if let Some(l) = segs.first().and_then(|h| owner_label(h)) {
                        if !["github", "gitlab", "bitbucket", "golang"].contains(&l.as_str()) {
                            c.add(&l, "go.mod module host", 1, Confidence::Medium);
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

fn config_hosts(files: &[PathBuf], c: &mut Collector, public: &[String]) {
    let det = Detector::new(vec![], public.to_vec(), None);
    let mut n = 0;
    for p in files {
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        let is_cfg = CONFIG_EXTS.contains(&ext_of(p).as_str())
            || name == "dockerfile"
            || name.starts_with("docker-compose");
        if !is_cfg || name.contains("lock") {
            continue;
        }
        n += 1;
        if n > MAX_FILES {
            break;
        }
        let Some(text) = read_small(p) else { continue };
        for f in det.scan(&text) {
            if !matches!(f.category, Category::Url | Category::Host) {
                continue;
            }
            let v = &text[f.start..f.end];
            let host = if f.category == Category::Url {
                crate::detect::infra::url_host(v)
            } else {
                v
            };
            if host.parse::<std::net::Ipv4Addr>().is_ok() {
                continue;
            }
            if let Some(l) = owner_label(host) {
                c.add(&l, "config host", 1, Confidence::Medium);
            }
        }
    }
}

/// CamelCase segments (`ZephyrineClient` -> `Zephyrine`, `Client`) and capitalized words.
fn segments(word: &str) -> Vec<&str> {
    let mut out = vec![];
    let b = word.as_bytes();
    let mut start = 0;
    for i in 1..b.len() {
        if b[i].is_ascii_uppercase() && b[i - 1].is_ascii_lowercase() {
            out.push(&word[start..i]);
            start = i;
        }
    }
    out.push(&word[start..]);
    out
}

fn identifiers(
    files: &[PathBuf],
    c: &mut Collector,
    english: &HashSet<String>,
    deps: &HashSet<String>,
) {
    let mut files_of: HashMap<String, (String, HashSet<usize>)> = HashMap::new();
    // files in which the word also appears as an ordinary lower-case word (`debug output`)
    let mut lower_in: HashMap<String, HashSet<usize>> = HashMap::new();
    let mut n = 0;
    for (fi, p) in files.iter().enumerate() {
        if !SOURCE_EXTS.contains(&ext_of(p).as_str()) {
            continue;
        }
        n += 1;
        if n > MAX_FILES {
            break;
        }
        let Some(text) = read_small(p) else { continue };
        for w in text.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_')) {
            if w.len() >= 4 && w.bytes().all(|b| b.is_ascii_lowercase()) {
                lower_in.entry(w.to_string()).or_default().insert(fi);
            }
        }
        for w in text.split(|ch: char| !ch.is_ascii_alphanumeric()) {
            if w.len() < 4 || !w.as_bytes()[0].is_ascii_uppercase() {
                continue;
            }
            for s in segments(w) {
                // Proper-noun shape: one capital, then lower case letters only
                if s.len() < 4
                    || !s.as_bytes()[0].is_ascii_uppercase()
                    || !s[1..].bytes().all(|b| b.is_ascii_lowercase())
                {
                    continue;
                }
                let lower = s.to_lowercase();
                if is_english(&lower, english)
                    || CODE_WORDS.contains(&lower.as_str())
                    || deps.contains(&lower)
                    || GENERIC.contains(&lower.as_str())
                {
                    continue;
                }
                files_of
                    .entry(lower)
                    .or_insert_with(|| (s.to_string(), HashSet::new()))
                    .1
                    .insert(fi);
            }
        }
    }
    let mut v: Vec<(String, usize)> = files_of
        .into_iter()
        .filter(|(lower, (_, f))| f.len() >= 3 && lower_in.get(lower).is_none_or(|l| l.len() < 2))
        .map(|(_, x)| x)
        .map(|(t, f)| (t, f.len()))
        .collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    for (t, k) in v.into_iter().take(20) {
        c.add(&t, "identifiers", k, Confidence::Low);
    }
}

/// Spellings the dictionary should also hold: `QuasarLedger` -> `quasar_ledger`,
/// `quasar-ledger`, `quasar ledger`. The folded matcher already covers case variants and
/// camel case; separator forms would otherwise only hit the skeleton pass, which blocks.
pub fn variants(term: &str) -> Vec<String> {
    let mut words: Vec<String> = vec![];
    for part in term.split(['_', '-', ' ', '.']) {
        for s in segments(part) {
            if !s.is_empty() {
                words.push(s.to_lowercase());
            }
        }
    }
    if words.len() < 2 {
        return vec![];
    }
    let own = fold_str(term);
    let mut out = vec![];
    for sep in ["_", "-", " ", ""] {
        let v = words.join(sep);
        if fold_str(&v) != own && !out.contains(&v) {
            out.push(v);
        }
    }
    out
}

/// Mine `root` for dictionary candidates. `existing` are folded terms already in the
/// dictionary (skipped). Sorted by confidence, then count.
pub fn mine(root: &Path, existing: &HashSet<String>, public_hosts: &[String]) -> Vec<Candidate> {
    let mut c = Collector::default();
    let english = english_words();

    if let Some(n) = root.file_name() {
        c.add(&n.to_string_lossy(), "root dir", 1, Confidence::High);
    }
    if let Some(out) = git(root, &["config", "--get-regexp", r"^remote\..*\.url$"]) {
        for line in out.lines() {
            let Some(url) = line.split_whitespace().nth(1) else {
                continue;
            };
            if let Some((host, org, repo)) = parse_remote(url) {
                for o in &org {
                    c.add(o, "git remote org", 1, Confidence::High);
                }
                c.add(&repo, "git remote repo", 1, Confidence::High);
                if let Some(l) = owner_label(&host) {
                    if !public_hosts.iter().any(|p| p.eq_ignore_ascii_case(&host))
                        && !["github", "gitlab", "bitbucket"].contains(&l.as_str())
                    {
                        c.add(&l, "git remote host", 1, Confidence::Medium);
                    }
                }
            }
        }
    }
    if let Some(out) = git(root, &["log", "--format=%an%x09%ae", "-n", "2000"]) {
        let mut seen: HashMap<String, usize> = HashMap::new();
        for line in out.lines() {
            *seen.entry(line.to_string()).or_default() += 1;
        }
        for (line, k) in seen {
            let (name, email) = line.split_once('\t').unwrap_or((&line, ""));
            if name.contains(' ') {
                c.add(name, "git author", k, Confidence::Medium);
            }
            if let Some(l) = email_domain_label(email) {
                c.add(&l, "git author e-mail", k, Confidence::Medium);
            }
        }
    }
    let mut files = vec![];
    walk(root, 6, &mut files);
    let mut deps = HashSet::new();
    manifests(&files, &mut c, &mut deps);
    config_hosts(&files, &mut c, public_hosts);
    identifiers(&files, &mut c, &english, &deps);

    let mut v: Vec<Candidate> = c
        .by_key
        .into_iter()
        .filter(|(k, _)| !existing.contains(k))
        .map(|(_, mut cand)| {
            let lower = cand.term.to_lowercase();
            if cand.confidence > Confidence::Low
                && !cand.term.contains(' ')
                && is_english(&lower, &english)
            {
                cand.confidence = Confidence::Low;
                cand.note = Some("common English word".into());
            }
            cand.variants = variants(&cand.term)
                .into_iter()
                .filter(|v| !existing.contains(&fold_str(v)))
                .collect();
            cand
        })
        .collect();
    v.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then(b.count.cmp(&a.count))
            .then(a.term.cmp(&b.term))
    });
    v
}

/// Folded terms of a dictionary file (empty when it does not exist).
pub fn existing_terms(path: &Path) -> HashSet<String> {
    std::fs::read_to_string(path)
        .map(|t| {
            t.lines()
                .map(|l| l.split('#').next().unwrap_or("").trim().to_string())
                .filter(|l| !l.is_empty())
                .map(|l| fold_str(&l))
                .collect()
        })
        .unwrap_or_default()
}

/// Append the chosen terms (and their variants) to the dictionary file (created 0600).
/// Returns the number of lines added.
pub fn append(path: &Path, chosen: &[&Candidate]) -> Result<usize> {
    let have = existing_terms(path);
    let mut lines: Vec<String> = vec![];
    let mut seen = have.clone();
    for c in chosen {
        for t in std::iter::once(&c.term).chain(c.variants.iter()) {
            if t.chars().count() >= 3 && seen.insert(fold_str(t)) {
                lines.push(t.clone());
            }
        }
    }
    if lines.is_empty() {
        return Ok(0);
    }
    let mut text = std::fs::read_to_string(path).unwrap_or_default();
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str("# added by `middleman dict suggest`\n");
    for l in &lines {
        text.push_str(l);
        text.push('\n');
    }
    // the dictionary must still load
    crate::detect::Dictionary::from_terms(
        text.lines()
            .map(|l| l.split('#').next().unwrap_or("").trim())
            .filter(|l| !l.is_empty()),
    )
    .context("the updated dictionary would not load; not written")?;
    crate::fsutil::write_atomic(path, text.as_bytes(), Some(0o600))?;
    Ok(lines.len())
}

/// One aligned line per candidate (no selection marker).
pub fn describe(c: &Candidate) -> String {
    let mut s = format!(
        "{:<24} {:<6}  {} ({})",
        c.term,
        c.confidence.as_str(),
        c.sources.join(", "),
        c.count
    );
    if let Some(n) = &c.note {
        s.push_str(&format!("  [{n}]"));
    }
    if !c.variants.is_empty() {
        s.push_str(&format!("  + {}", c.variants.join(" | ")));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn english_base_forms() {
        let w: HashSet<String> = ["store", "provider", "cheap", "run", "carry", "ledger"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        for x in [
            "stored",
            "providers",
            "cheapest",
            "running",
            "carried",
            "ledgers",
            "ledger",
        ] {
            assert!(is_english(x, &w), "{x}");
        }
        for x in ["zephyrine", "zorblax", "baturox"] {
            assert!(!is_english(x, &w), "{x}");
        }
    }

    #[test]
    fn remotes_hosts_and_variants() {
        assert_eq!(
            parse_remote("git@git.zephyrine.dev:platform/quasarledger.git"),
            Some((
                "git.zephyrine.dev".into(),
                vec!["platform".into()],
                "quasarledger".into()
            ))
        );
        let (h, o, r) = parse_remote("https://gitlab.acme.io/grp/sub/repo-x/").unwrap();
        assert_eq!(
            (h.as_str(), o.len(), r.as_str()),
            ("gitlab.acme.io", 2, "repo-x")
        );
        assert_eq!(
            parse_remote("ssh://git@host.x:22/org/r.git").unwrap().2,
            "r"
        );
        assert_eq!(
            owner_label("billing.zephyrine-corp.io").unwrap(),
            "zephyrine-corp"
        );
        assert_eq!(owner_label("db.prod.zphr.internal").unwrap(), "zphr");
        assert_eq!(owner_label("a.acme.co.uk").unwrap(), "acme");
        assert_eq!(email_domain_label("x@gmail.com"), None);
        assert_eq!(email_domain_label("m@zephyrine.io").unwrap(), "zephyrine");
        assert_eq!(
            variants("QuasarLedger"),
            vec!["quasar_ledger", "quasar-ledger", "quasar ledger"]
        );
        assert_eq!(
            variants("acme-billing"),
            vec!["acme_billing", "acme billing", "acmebilling"]
        );
        assert!(variants("Zephyrine").is_empty());
    }

    #[test]
    fn variants_are_rewritten_not_blocked() {
        let base = "QuasarLedger";
        let mut terms = vec![base.to_string()];
        terms.extend(variants(base));
        let d = crate::detect::Dictionary::from_terms(&terms).unwrap();
        for t in [
            "quasar_ledger",
            "QUASAR-LEDGER",
            "Quasar Ledger",
            "quasarLedger",
        ] {
            let mut f = vec![];
            d.scan(t, &mut f);
            assert!(
                f.iter().all(|f| f.category == Category::Dictionary) && !f.is_empty(),
                "{t}: {f:?}"
            );
        }
        // without the variants the separator forms only hit the blocking skeleton pass
        let d = crate::detect::Dictionary::from_terms([base]).unwrap();
        let mut f = vec![];
        d.scan("quasar_ledger", &mut f);
        assert!(f.iter().any(|f| f.category == Category::DictionaryEvasion));
    }

    #[test]
    fn mines_a_project_locally() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("quasarledger");
        let w = |rel: &str, t: &str| {
            let p = root.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, t).unwrap();
        };
        w(
            "Cargo.toml",
            "[package]\nname = \"zephyr-billing\"\nauthors = [\"Mehmet Karaca <mk@zephyrine.io>\"]\n[dependencies]\nserde = \"1\"\n",
        );
        w("config/app.yaml", "db: ledger-db-01.prod.zphr.internal\n");
        for i in 0..3 {
            w(
                &format!("src/m{i}.rs"),
                "struct ZorblaxClient; // Zorblax\nfn f(x: Serde) {}\n",
            );
        }
        w("src/one.rs", "struct Quuxian;\n");
        let v = mine(&root, &HashSet::new(), &[]);
        let get = |t: &str| v.iter().find(|c| c.term == t);
        assert_eq!(get("quasarledger").unwrap().confidence, Confidence::High);
        assert_eq!(get("zephyr-billing").unwrap().confidence, Confidence::High);
        assert!(get("zephyr-billing")
            .unwrap()
            .variants
            .contains(&"zephyr_billing".into()));
        assert_eq!(get("Mehmet Karaca").unwrap().confidence, Confidence::Medium);
        assert!(get("zephyrine").is_some());
        assert!(get("zphr")
            .unwrap()
            .sources
            .contains(&"config host".to_string()));
        assert_eq!(get("Zorblax").unwrap().confidence, Confidence::Low);
        assert!(get("Quuxian").is_none(), "one file is not recurring");
        assert!(get("Serde").is_none() && get("Client").is_none());
        // existing terms are not suggested again; append writes term + variants once
        let dict = d.path().join("dictionary.txt");
        let chosen: Vec<&Candidate> = v
            .iter()
            .filter(|c| c.confidence >= Confidence::Medium)
            .collect();
        let n = append(&dict, &chosen).unwrap();
        assert!(n >= 5, "{n}");
        assert_eq!(append(&dict, &chosen).unwrap(), 0);
        let again = mine(&root, &existing_terms(&dict), &[]);
        assert!(
            again.iter().all(|c| c.confidence == Confidence::Low),
            "{again:?}"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(&dict).unwrap().permissions().mode() & 0o777;
            assert_eq!(m, 0o600);
        }
    }
}
