//! Reversible pseudonymization. The `Vault` maps originals <-> typed surrogates, lives in
//! memory for one request, and is never written to disk.

use std::collections::HashMap;
use std::sync::LazyLock;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use hmac::{Hmac, Mac};
use regex::Regex;
use sha2::Sha256;

use crate::detect::{Category, Dictionary, Finding};

type HmacSha256 = Hmac<Sha256>;

/// Per-process HMAC key: dictionary surrogates are stable within one server process.
static PROCESS_KEY: LazyLock<[u8; 32]> = LazyLock::new(|| {
    let mut k = [0u8; 32];
    k[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    k[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    k
});

/// Label of a requested file's root-relative path (see `Vault::file_path_candidate`).
pub const FILE_PATH: &str = "file path";

/// Top-level directory names kept in file path surrogates: they say nothing about the project.
pub const CONVENTIONAL_DIRS: &[&str] = &[
    "src",
    "source",
    "lib",
    "libs",
    "app",
    "apps",
    "pkg",
    "pkgs",
    "packages",
    "cmd",
    "internal",
    "include",
    "test",
    "tests",
    "spec",
    "specs",
    "__tests__",
    "bench",
    "benches",
    "examples",
    "example",
    "docs",
    "doc",
    "scripts",
    "bin",
    "tools",
    "crates",
    "modules",
    "components",
    "server",
    "client",
    "web",
    "api",
    "core",
    "common",
    "shared",
    "utils",
    "config",
    "public",
];

const SYLLABLES: [&str; 16] = [
    "za", "ve", "lo", "ri", "ta", "no", "ki", "mu", "se", "do", "ra", "li", "fo", "ne", "pa", "tu",
];

static SURROGATE_SHAPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"user[0-9]+@example\.com|svc[0-9]+\.example\.net|198\.51\.100\.[0-9]+|203\.0\.113\.[0-9]+|198\.1[89]\.[0-9]+\.[0-9]+|2001:db8::[0-9a-f]+|MM_(?:SECRET|PHONE|IBAN|TCKN|CARD|IPV4)_[0-9]+|/workspace/app[0-9]*|/home/user[0-9]+|/srv/p[0-9]+")
        .expect("static regex")
});

/// Upper bound on candidate surrogates tried for one original. Reaching it fails closed.
const MAX_ATTEMPTS: u32 = 300_000;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("surrogate space exhausted for {0}; refusing to send")]
pub struct Exhausted(pub &'static str);

#[derive(Debug, Clone)]
struct Entry {
    original: String,
    /// Dictionary surrogates may be restored inside identifiers; others need a boundary.
    inner: bool,
}

pub struct Vault {
    key: [u8; 32],
    fwd: HashMap<String, String>,
    rev: HashMap<String, Entry>,
    counters: HashMap<&'static str, usize>,
    /// Top-level directory -> neutral name for file path surrogates (`billing` -> `d1`).
    /// Kept apart from `fwd`: a directory name is not an original that must be absent.
    dirs: HashMap<String, String>,
    corpus_lower: String,
    max_attempts: u32,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Vault({} entries)", self.fwd.len())
    }
}

fn case_shape(original: &str, word: &str) -> String {
    let has_upper = original.chars().any(|c| c.is_uppercase());
    let has_lower = original.chars().any(|c| c.is_lowercase());
    if !has_upper {
        word.to_lowercase()
    } else if !has_lower {
        word.to_uppercase()
    } else {
        let mut cs = word.chars();
        match cs.next() {
            Some(f) => f.to_uppercase().collect::<String>() + &cs.as_str().to_lowercase(),
            None => String::new(),
        }
    }
}

impl Vault {
    /// `corpus` is all text of the request; surrogates are guaranteed absent from it.
    pub fn new(corpus: &str) -> Vault {
        Self::with_key(*PROCESS_KEY, corpus)
    }

    pub fn with_key(key: [u8; 32], corpus: &str) -> Vault {
        Vault {
            key,
            fwd: HashMap::new(),
            rev: HashMap::new(),
            counters: HashMap::new(),
            dirs: HashMap::new(),
            corpus_lower: corpus.to_lowercase(),
            max_attempts: MAX_ATTEMPTS,
        }
    }

    /// Lower the per-original attempt bound (tests).
    pub fn with_max_attempts(mut self, n: u32) -> Vault {
        self.max_attempts = n.max(1);
        self
    }

    pub fn len(&self) -> usize {
        self.fwd.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fwd.is_empty()
    }

    pub fn originals(&self) -> impl Iterator<Item = &str> {
        self.fwd.keys().map(|s| s.as_str())
    }

    pub fn surrogates(&self) -> impl Iterator<Item = &str> {
        self.rev.keys().map(|s| s.as_str())
    }

    /// The surrogate already issued for `original`, if any.
    pub fn surrogate_of(&self, original: &str) -> Option<&str> {
        self.fwd.get(original).map(|s| s.as_str())
    }

    pub fn is_surrogate(&self, s: &str) -> bool {
        self.rev.contains_key(s)
    }

    pub fn is_dict_original(&self, s: &str) -> bool {
        self.fwd
            .get(s)
            .and_then(|sur| self.rev.get(sur))
            .is_some_and(|e| e.inner)
    }

    fn usable(&self, cand: &str, dict: Option<&Dictionary>) -> bool {
        !self.rev.contains_key(cand)
            && !self.corpus_lower.contains(&cand.to_lowercase())
            && !dict.is_some_and(|d| d.contains_any(cand))
    }

    fn next_n(&mut self, kind: &'static str) -> usize {
        let c = self.counters.entry(kind).or_insert(0);
        *c += 1;
        *c
    }

    fn dict_word(&self, lower: &str, attempt: u32) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("hmac key");
        mac.update(lower.as_bytes());
        mac.update(&attempt.to_le_bytes());
        let b = mac.finalize().into_bytes();
        // 4-5 syllables (8-10 letters): distinctive enough not to occur by chance
        let n = 4 + (b[0] % 2) as usize;
        let mut w = String::new();
        for i in 0..n {
            w.push_str(SYLLABLES[(b[i + 1] % 16) as usize]);
        }
        if attempt > 64 {
            w.push_str(&attempt.to_string());
        }
        w
    }

    fn ipv4_candidate(n: usize) -> String {
        // 198.51.100.0/24 and 203.0.113.0/24 (documentation), then 198.18.0.0/15
        // (benchmarking), then a typed token
        if n <= 254 {
            format!("198.51.100.{n}")
        } else if n <= 508 {
            format!("203.0.113.{}", n - 254)
        } else if n - 508 <= 2 * 65_536 - 2 {
            let k = (n - 508) as u32; // 1..=131_070
            let ip = (198u32 << 24) | (18u32 << 16) | k;
            let [a, b, c, d] = ip.to_be_bytes();
            format!("{a}.{b}.{c}.{d}")
        } else {
            format!("MM_IPV4_{}", n - 508 - (2 * 65_536 - 2))
        }
    }

    fn generate(
        &mut self,
        original: &str,
        f: &Finding,
        dict: Option<&Dictionary>,
    ) -> Result<String, Exhausted> {
        if f.category == Category::Dictionary {
            let lower = original.to_lowercase();
            for attempt in 0..self.max_attempts {
                let cand = case_shape(original, &self.dict_word(&lower, attempt));
                if self.usable(&cand, dict) {
                    return Ok(cand);
                }
            }
            return Err(Exhausted("dictionary"));
        }
        if f.category == Category::Url && f.label == "URL" {
            return self.url_candidate(original, dict);
        }
        if f.category == Category::FilePath {
            return self.file_path_candidate(original, dict);
        }
        for _ in 0..self.max_attempts {
            let cand = match f.category {
                Category::Email => format!("user{}@example.com", self.next_n("email")),
                Category::Url | Category::Host => {
                    format!("svc{}.example.net", self.next_n("host"))
                }
                Category::Ipv4 => Self::ipv4_candidate(self.next_n("ipv4")),
                Category::Ipv6 => format!("2001:db8::{:x}", self.next_n("ipv6")),
                Category::Path if f.label == "project root" => {
                    let n = self.next_n("root");
                    if n == 1 {
                        "/workspace/app".to_string()
                    } else {
                        format!("/workspace/app{n}")
                    }
                }
                Category::Path if f.label == "absolute path" => {
                    format!("/srv/p{}", self.next_n("abs"))
                }
                Category::Path => format!("/home/user{}", self.next_n("home")),
                Category::FilePath => unreachable!(),
                Category::Secret | Category::HighEntropy | Category::DictionaryEvasion => {
                    format!("MM_SECRET_{}", self.next_n("secret"))
                }
                Category::Phone => format!("MM_PHONE_{}", self.next_n("phone")),
                Category::Iban => format!("MM_IBAN_{}", self.next_n("iban")),
                Category::Tckn => format!("MM_TCKN_{}", self.next_n("tckn")),
                Category::Card => format!("MM_CARD_{}", self.next_n("card")),
                Category::Dictionary => unreachable!(),
            };
            if self.usable(&cand, dict) {
                return Ok(cand);
            }
        }
        Err(Exhausted(f.category.as_str()))
    }

    /// A whole URL after `scheme://`: the host's own surrogate plus a neutral path
    /// (`billing.acme.io:8443/v2/x` -> `svc1.example.net/p1`). The host is registered too,
    /// so its bare occurrences elsewhere map to the same `svcN`.
    fn url_candidate(
        &mut self,
        original: &str,
        dict: Option<&Dictionary>,
    ) -> Result<String, Exhausted> {
        let host = crate::detect::infra::url_host(original);
        let host_sur = if host.is_empty() {
            format!("svc{}.example.net", self.next_n("host"))
        } else {
            let cat = if host.parse::<std::net::Ipv4Addr>().is_ok() {
                Category::Ipv4
            } else {
                Category::Url
            };
            let hf = Finding::new(cat, "URL host", 0, host.len());
            self.surrogate_for(host, &hf, dict)?
        };
        for _ in 0..self.max_attempts {
            let cand = format!("{host_sur}/p{}", self.next_n("urlpath"));
            if self.usable(&cand, dict) {
                return Ok(cand);
            }
        }
        Err(Exhausted("url"))
    }

    /// A root-relative file path: `<top>/f<N>.<ext>`. The top-level directory is kept when it
    /// is a conventional name (src, tests, ...), else it becomes `d<K>`; deeper directories
    /// and the file name are dropped; the extension is kept.
    fn file_path_candidate(
        &mut self,
        original: &str,
        dict: Option<&Dictionary>,
    ) -> Result<String, Exhausted> {
        let norm = original.replace('\\', "/");
        let mut parts: Vec<&str> = norm.split('/').filter(|p| !p.is_empty()).collect();
        let name = parts.pop().unwrap_or("");
        let ext = std::path::Path::new(name)
            .extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase())
            .filter(|e| e.len() <= 8 && e.chars().all(|c| c.is_ascii_alphanumeric()));
        let dir = match parts.first() {
            None => String::new(),
            Some(top) if CONVENTIONAL_DIRS.contains(&top.to_ascii_lowercase().as_str()) => {
                format!("{}/", top.to_ascii_lowercase())
            }
            Some(top) => {
                let key = top.to_string();
                if let Some(d) = self.dirs.get(&key) {
                    format!("{d}/")
                } else {
                    let d = format!("d{}", self.next_n("dir"));
                    self.dirs.insert(key, d.clone());
                    format!("{d}/")
                }
            }
        };
        for _ in 0..self.max_attempts {
            let n = self.next_n("file");
            let cand = match &ext {
                Some(e) => format!("{dir}f{n}.{e}"),
                None => format!("{dir}f{n}"),
            };
            if self.usable(&cand, dict) {
                return Ok(cand);
            }
        }
        Err(Exhausted("file path"))
    }

    /// Use `surrogate` for `original` (both directions) when neither is taken and the
    /// surrogate is usable. Returns whether it was assigned.
    pub fn assign(&mut self, original: &str, surrogate: &str, dict: Option<&Dictionary>) -> bool {
        if original == surrogate || self.fwd.contains_key(original) || !self.usable(surrogate, dict)
        {
            return false;
        }
        self.fwd.insert(original.to_string(), surrogate.to_string());
        self.rev.insert(
            surrogate.to_string(),
            Entry {
                original: original.to_string(),
                inner: false,
            },
        );
        true
    }

    /// Restore-only mapping (never checked by the egress gate): an alias of an existing
    /// surrogate in another spelling the model may use (`src.f1` for `src/f1.py`).
    pub fn add_alias(&mut self, surrogate: &str, original: &str) {
        if surrogate.is_empty() || surrogate == original || self.rev.contains_key(surrogate) {
            return;
        }
        if self.corpus_lower.contains(&surrogate.to_lowercase()) {
            return;
        }
        self.rev.insert(
            surrogate.to_string(),
            Entry {
                original: original.to_string(),
                inner: false,
            },
        );
    }

    /// Same original -> same surrogate within this vault.
    pub fn surrogate_for(
        &mut self,
        original: &str,
        f: &Finding,
        dict: Option<&Dictionary>,
    ) -> Result<String, Exhausted> {
        if let Some(s) = self.fwd.get(original) {
            return Ok(s.clone());
        }
        let s = self.generate(original, f, dict)?;
        self.fwd.insert(original.to_string(), s.clone());
        self.rev.insert(
            s.clone(),
            Entry {
                original: original.to_string(),
                inner: f.category == Category::Dictionary,
            },
        );
        Ok(s)
    }

    fn automaton(&self) -> Option<(AhoCorasick, Vec<(&str, &Entry)>)> {
        if self.rev.is_empty() {
            return None;
        }
        let pairs: Vec<(&str, &Entry)> = self.rev.iter().map(|(k, v)| (k.as_str(), v)).collect();
        let ac = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostLongest)
            .build(pairs.iter().map(|(k, _)| *k))
            .ok()?;
        Some((ac, pairs))
    }

    /// Byte spans of known surrogates in `text`.
    pub fn surrogate_spans(&self, text: &str) -> Vec<(usize, usize)> {
        match self.automaton() {
            Some((ac, _)) => ac.find_iter(text).map(|m| (m.start(), m.end())).collect(),
            None => vec![],
        }
    }

    /// Replace exact known surrogates with their originals. Returns (text, replacements).
    pub fn restore(&self, text: &str) -> (String, usize) {
        let r = self.restore_with(text, |_, _| true);
        (r.text, r.restored)
    }

    /// `restore` with a veto: `allow(byte_start, surrogate)` false leaves that occurrence as
    /// the surrogate. Dictionary surrogates are restored only at identifier-segment
    /// boundaries (non-alphanumeric, `_`, or a case transition); others need a boundary too.
    pub fn restore_with<F>(&self, text: &str, allow: F) -> Restored
    where
        F: Fn(usize, &str) -> bool,
    {
        let mut r = Restored {
            text: String::with_capacity(text.len()),
            restored: 0,
            vetoed: 0,
            unbounded: 0,
        };
        let Some((ac, pairs)) = self.automaton() else {
            r.text = text.to_string();
            return r;
        };
        let bytes = text.as_bytes();
        let mut last = 0;
        for m in ac.find_iter(text) {
            let (sur, e) = pairs[m.pattern().as_usize()];
            if e.inner {
                if !segment_bounded(text, m.start(), m.end()) {
                    r.unbounded += 1;
                    continue;
                }
            } else {
                let before = m.start().checked_sub(1).map(|i| bytes[i]);
                let after = bytes.get(m.end()).copied();
                let bad = |b: Option<u8>| b.is_some_and(|b| b.is_ascii_alphanumeric());
                if bad(after) || (bad(before) && !text[m.start()..].starts_with('/')) {
                    continue;
                }
            }
            if !allow(m.start(), sur) {
                r.vetoed += 1;
                continue;
            }
            r.text.push_str(&text[last..m.start()]);
            r.text.push_str(&e.original);
            last = m.end();
            r.restored += 1;
        }
        r.text.push_str(&text[last..]);
        r
    }

    /// Surrogate-shaped tokens in `output` that this vault never issued and that were not
    /// already present in what was sent.
    pub fn unknown_surrogates(&self, output: &str, sent: &str) -> Vec<String> {
        let mut v: Vec<String> = SURROGATE_SHAPE
            .find_iter(output)
            .map(|m| m.as_str().to_string())
            .filter(|s| !self.rev.contains_key(s) && !sent.contains(s.as_str()))
            .collect();
        v.sort();
        v.dedup();
        v
    }
}

/// Result of `Vault::restore_with`.
#[derive(Debug, Clone)]
pub struct Restored {
    pub text: String,
    pub restored: usize,
    /// Occurrences left as surrogates by the caller's veto.
    pub vetoed: usize,
    /// Dictionary surrogates found glued inside a longer word (not restored).
    pub unbounded: usize,
}

/// A dictionary surrogate at `s..e` sits on identifier-segment boundaries on both sides.
fn segment_bounded(text: &str, s: usize, e: usize) -> bool {
    let first = text[s..e].chars().next();
    let last = text[s..e].chars().next_back();
    let before_ok = match text[..s].chars().next_back() {
        None => true,
        Some(p) if !p.is_alphanumeric() => true,
        // fooBar: lower -> upper; FOO_BAR handled by '_'
        Some(p) => p.is_lowercase() && first.is_some_and(|c| c.is_uppercase()),
    };
    let after_ok = match text[e..].chars().next() {
        None => true,
        Some(n) if !n.is_alphanumeric() => true,
        Some(n) => {
            // ZaveloBilling: lower -> upper; ZAVELOBilling is not a boundary we produce
            last.is_some_and(|c| c.is_lowercase()) && n.is_uppercase() || n.is_ascii_digit()
        }
    };
    before_ok && after_ok
}

/// Replace each finding's span with its surrogate. `findings` must be non-overlapping
/// (see `detect::resolve_overlaps`).
pub fn apply(
    text: &str,
    findings: &[Finding],
    vault: &mut Vault,
    dict: Option<&Dictionary>,
) -> Result<String, Exhausted> {
    let mut sorted: Vec<&Finding> = findings.iter().collect();
    sorted.sort_by_key(|f| f.start);
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for f in sorted {
        if f.start < last
            || f.end > text.len()
            || !text.is_char_boundary(f.start)
            || !text.is_char_boundary(f.end)
        {
            continue;
        }
        let original = &text[f.start..f.end];
        let s = vault.surrogate_for(original, f, dict)?;
        out.push_str(&text[last..f.start]);
        out.push_str(&s);
        last = f.end;
    }
    out.push_str(&text[last..]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::{resolve_overlaps, Detector};

    fn roundtrip(text: &str, terms: &[&str]) -> (String, String) {
        let dict = if terms.is_empty() {
            None
        } else {
            Some(Dictionary::from_terms(terms).unwrap())
        };
        let det = Detector::new(vec!["/Users/jane/acme".into()], vec![], dict);
        let fs = resolve_overlaps(det.scan(text));
        let mut v = Vault::new(text);
        let s = apply(text, &fs, &mut v, det.dictionary()).unwrap();
        let (r, _) = v.restore(&s);
        (s, r)
    }

    #[test]
    fn case_preserving_dictionary() {
        let (s, r) = roundtrip("AcmeBilling acme_billing ACME_KEY_NAME AcMe", &["acme"]);
        assert!(!s.to_lowercase().contains("acme"), "{s}");
        assert_eq!(r, "AcmeBilling acme_billing ACME_KEY_NAME AcMe");
        let w: Vec<&str> = s.split(' ').collect();
        assert!(w[0].ends_with("Billing") && w[0].chars().next().unwrap().is_uppercase());
        assert!(w[1].ends_with("_billing") && w[1].chars().all(|c| !c.is_uppercase()));
        assert!(w[2].ends_with("_KEY_NAME") && w[2].chars().all(|c| !c.is_lowercase()));
    }

    #[test]
    fn same_original_same_surrogate_and_typed() {
        let t = "a jane@acme-corp.io b jane@acme-corp.io c ops@acme-corp.io 10.1.2.3";
        let (s, r) = roundtrip(t, &[]);
        assert_eq!(s.matches("user1@example.com").count(), 2);
        assert!(s.contains("user2@example.com"));
        assert!(s.contains("198.51.100.1"));
        assert_eq!(r, t);
    }

    #[test]
    fn collision_with_existing_surrogate_shape() {
        let t = "keep user1@example.com, replace bob@acme.io";
        let (s, r) = roundtrip(t, &[]);
        assert!(
            s.contains("user1@example.com") && s.contains("user2@example.com"),
            "{s}"
        );
        assert_eq!(r, t);
    }

    #[test]
    fn restore_respects_boundaries() {
        let t = "ip 10.0.0.5";
        let det = Detector::new(vec![], vec![], None);
        let fs = resolve_overlaps(det.scan(t));
        let mut v = Vault::new(t);
        let _ = apply(t, &fs, &mut v, None).unwrap();
        let (r, n) = v.restore("198.51.100.12 vs 198.51.100.1.");
        assert_eq!(n, 1);
        assert_eq!(r, "198.51.100.12 vs 10.0.0.5.");
    }

    #[test]
    fn unknown_surrogates_flagged() {
        let v = Vault::new("");
        let u = v.unknown_surrogates("see user7@example.com and MM_SECRET_3", "");
        assert_eq!(
            u,
            vec!["MM_SECRET_3".to_string(), "user7@example.com".to_string()]
        );
    }

    #[test]
    fn ipv4_space_is_bounded_and_fails_closed() {
        let ips: Vec<String> = (0..600)
            .map(|i| format!("11.{}.{}.7", i / 200, i % 200))
            .collect();
        let t = ips.join(" ");
        let det = Detector::new(vec![], vec![], None);
        let fs = resolve_overlaps(det.scan(&t));
        assert_eq!(fs.len(), 600);
        let mut v = Vault::new(&t);
        let s = apply(&t, &fs, &mut v, None).unwrap();
        assert!(s.contains("198.51.100.254") && s.contains("203.0.113.254"));
        assert!(s.contains("198.18.0.92"), "third pool used");
        assert_eq!(v.restore(&s).0, t);
        // every candidate unusable -> error, not a hang
        let corpus = "198.51.100.1 198.51.100.2";
        let mut v = Vault::new(corpus).with_max_attempts(2);
        let f = Finding::new(Category::Ipv4, "IPv4", 0, 12);
        assert!(v.surrogate_for("10.0.0.1", &f, None).is_err());
    }

    #[test]
    fn dictionary_restore_needs_segment_boundaries() {
        let dict = Dictionary::from_terms(["acme"]).unwrap();
        let det = Detector::new(vec![], vec![], Some(dict));
        let t = "acme Acme";
        let fs = resolve_overlaps(det.scan(t));
        let mut v = Vault::new(t);
        let out = apply(t, &fs, &mut v, det.dictionary()).unwrap();
        let (s, cap) = out.split_once(' ').unwrap();
        assert!((8..=10).contains(&s.len()), "{s}");
        let crafted = format!("x{s}y pre{s}post {s} {s}_x Get{cap}Url");
        let r = v.restore_with(&crafted, |_, _| true);
        assert_eq!(r.restored, 3, "{:?}", r.text);
        assert_eq!(r.unbounded, 2);
        assert!(r
            .text
            .contains(&format!("x{s}y pre{s}post acme acme_x GetAcmeUrl")));
    }

    #[test]
    fn path_root_rewritten() {
        let (s, r) = roundtrip("open /Users/jane/acme/src/main.rs", &[]);
        assert_eq!(s, "open /workspace/app/src/main.rs");
        assert_eq!(r, "open /Users/jane/acme/src/main.rs");
    }
}
