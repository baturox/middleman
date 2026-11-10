//! Private term list (company, product, project, people names). Aho-Corasick, ASCII
//! case-insensitive, leftmost-longest, matches inside identifiers too (`AcmeBilling`).

use std::path::Path;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use anyhow::{bail, Context, Result};

use super::{Category, Finding};

pub struct Dictionary {
    ac: AhoCorasick,
    len: usize,
}

impl Dictionary {
    /// One term per line; `#` starts a comment; blank lines ignored. Terms shorter than 3 chars
    /// are rejected (they would match everywhere).
    pub fn load(path: &Path) -> Result<Dictionary> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read dictionary {}", path.display()))?;
        let terms: Vec<String> = text
            .lines()
            .map(|l| l.split('#').next().unwrap_or("").trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        Self::from_terms(terms)
    }

    pub fn from_terms<I, S>(terms: I) -> Result<Dictionary>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut v: Vec<String> = Vec::new();
        for t in terms {
            let t = t.as_ref().trim();
            if t.chars().count() < 3 {
                bail!("dictionary term too short (min 3 chars)");
            }
            if !v.iter().any(|x| x.eq_ignore_ascii_case(t)) {
                v.push(t.to_string());
            }
        }
        let ac = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostLongest)
            .build(&v)
            .context("cannot build dictionary automaton")?;
        Ok(Dictionary { ac, len: v.len() })
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn scan(&self, text: &str, out: &mut Vec<Finding>) {
        for m in self.ac.find_iter(text) {
            out.push(Finding::new(
                Category::Dictionary,
                "dictionary term",
                m.start(),
                m.end(),
            ));
        }
    }

    pub fn contains_any(&self, text: &str) -> bool {
        self.ac.is_match(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_insensitive_inside_identifiers_longest_first() {
        let d = Dictionary::from_terms(["acme", "AcmeBilling", "Zorblax"]).unwrap();
        let t = "class AcmeBillingClient: ACME_URL; acme; zorblaxService";
        let mut v = vec![];
        d.scan(t, &mut v);
        let s: Vec<&str> = v.iter().map(|f| &t[f.start..f.end]).collect();
        assert_eq!(s, vec!["AcmeBilling", "ACME", "acme", "zorblax"]);
    }

    #[test]
    fn rejects_short_terms() {
        assert!(Dictionary::from_terms(["ab"]).is_err());
    }
}
