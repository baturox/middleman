//! Detectors. A `Finding` records category and byte span only; it never carries the value,
//! so neither `Debug` nor `Display` can leak it.

pub mod dictionary;
pub mod entropy;
pub mod infra;
pub mod pii;
pub mod secrets;

use std::collections::BTreeMap;
use std::fmt;

use serde::Serialize;

pub use dictionary::Dictionary;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Secret,
    HighEntropy,
    Email,
    Url,
    Host,
    Ipv4,
    Ipv6,
    Path,
    Phone,
    Iban,
    Tckn,
    Card,
    Dictionary,
}

impl Category {
    pub fn as_str(&self) -> &'static str {
        match self {
            Category::Secret => "secret",
            Category::HighEntropy => "high_entropy",
            Category::Email => "email",
            Category::Url => "url_host",
            Category::Host => "host",
            Category::Ipv4 => "ipv4",
            Category::Ipv6 => "ipv6",
            Category::Path => "path",
            Category::Phone => "phone",
            Category::Iban => "iban",
            Category::Tckn => "tckn",
            Category::Card => "card",
            Category::Dictionary => "dictionary",
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            Category::Secret | Category::HighEntropy => Severity::Hard,
            Category::Phone | Category::Iban | Category::Tckn | Category::Card => Severity::Pii,
            Category::Email
            | Category::Url
            | Category::Host
            | Category::Ipv4
            | Category::Ipv6
            | Category::Path => Severity::Infra,
            Category::Dictionary => Severity::Dict,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Dict,
    Infra,
    Pii,
    Hard,
}

/// A detection: category, a static label, and a byte span into the scanned text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Finding {
    pub category: Category,
    pub label: &'static str,
    pub start: usize,
    pub end: usize,
}

impl Finding {
    pub fn new(category: Category, label: &'static str, start: usize, end: usize) -> Self {
        Finding {
            category,
            label,
            start,
            end,
        }
    }
    pub fn len(&self) -> usize {
        self.end - self.start
    }
    pub fn is_empty(&self) -> bool {
        self.end == self.start
    }
    pub fn severity(&self) -> Severity {
        self.category.severity()
    }
    fn overlaps(&self, o: &Finding) -> bool {
        self.start < o.end && o.start < self.end
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({}) at bytes {}..{}",
            self.category.as_str(),
            self.label,
            self.start,
            self.end
        )
    }
}

pub(crate) fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

pub(crate) fn byte_before(text: &str, i: usize) -> Option<u8> {
    if i == 0 {
        None
    } else {
        text.as_bytes().get(i - 1).copied()
    }
}

pub(crate) fn byte_at(text: &str, i: usize) -> Option<u8> {
    text.as_bytes().get(i).copied()
}

pub struct Detector {
    infra: infra::InfraScanner,
    dict: Option<Dictionary>,
}

impl Detector {
    /// `roots` are absolute project roots (rewritten to `/workspace/app`), `public_hosts` are kept verbatim.
    pub fn new(roots: Vec<String>, public_hosts: Vec<String>, dict: Option<Dictionary>) -> Self {
        Detector {
            infra: infra::InfraScanner::new(roots, public_hosts),
            dict,
        }
    }

    pub fn dictionary(&self) -> Option<&Dictionary> {
        self.dict.as_ref()
    }

    /// All findings, possibly overlapping.
    pub fn scan(&self, text: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        secrets::scan(text, &mut out);
        entropy::scan(text, &mut out);
        pii::scan(text, &mut out);
        self.infra.scan(text, &mut out);
        if let Some(d) = &self.dict {
            d.scan(text, &mut out);
        }
        out
    }
}

/// Keep a non-overlapping subset: higher severity first, then longest, then earliest.
/// Result is sorted by start.
pub fn resolve_overlaps(mut findings: Vec<Finding>) -> Vec<Finding> {
    findings.sort_by(|a, b| {
        b.severity()
            .cmp(&a.severity())
            .then(b.len().cmp(&a.len()))
            .then(a.start.cmp(&b.start))
    });
    let mut kept: Vec<Finding> = Vec::new();
    for f in findings {
        if f.is_empty() {
            continue;
        }
        if !kept.iter().any(|k| k.overlaps(&f)) {
            kept.push(f);
        }
    }
    kept.sort_by_key(|f| f.start);
    kept
}

/// `resolve_overlaps` plus consistency: every other exact occurrence of a detected value is
/// also covered (a detector heuristic may have skipped it in a different context). Partial
/// overlaps are left alone; the egress gate then blocks rather than leak.
pub fn finalize(text: &str, raw: Vec<Finding>) -> Vec<Finding> {
    let mut kept = resolve_overlaps(raw);
    let mut extra = Vec::new();
    for f in &kept {
        if f.category == Category::Dictionary {
            continue; // the dictionary automaton already finds every occurrence
        }
        let needle = &text[f.start..f.end];
        let mut from = 0;
        while let Some(i) = text[from..].find(needle) {
            let s = from + i;
            let cand = Finding::new(f.category, f.label, s, s + needle.len());
            let bounded = !byte_before(text, s).is_some_and(|b| b.is_ascii_alphanumeric())
                && !byte_at(text, cand.end).is_some_and(|b| b.is_ascii_alphanumeric());
            if bounded
                && !kept
                    .iter()
                    .chain(extra.iter())
                    .any(|k: &Finding| k.overlaps(&cand))
            {
                extra.push(cand);
            }
            from = s + needle.len().max(1);
        }
    }
    kept.extend(extra);
    kept.sort_by_key(|f| f.start);
    kept
}

pub fn counts(findings: &[Finding]) -> BTreeMap<String, usize> {
    let mut m = BTreeMap::new();
    for f in findings {
        *m.entry(f.category.as_str().to_string()).or_insert(0) += 1;
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_debug_never_shows_value() {
        let text = "key = AKIAABCDEFGHIJKLMNOP";
        let d = Detector::new(vec![], vec![], None);
        let fs = d.scan(text);
        assert!(!fs.is_empty());
        for f in &fs {
            let dbg = format!("{f:?} {f}");
            assert!(!dbg.contains("AKIA"), "{dbg}");
        }
    }

    #[test]
    fn overlap_prefers_severity_then_length() {
        let a = Finding::new(Category::Dictionary, "d", 0, 10);
        let b = Finding::new(Category::Secret, "s", 5, 8);
        let c = Finding::new(Category::Host, "h", 12, 20);
        let r = resolve_overlaps(vec![a, b, c]);
        assert_eq!(r, vec![b, c]);
    }
}
