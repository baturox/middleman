//! Private term list (company, product, project, people names). Matching runs on a
//! normalized view (NFKC, invisible characters removed, full case folding incl. Turkish
//! dotted/dotless i), leftmost-longest, inside identifiers too (`AcmeBilling`). Matches are
//! mapped back to the original span.
//!
//! A second pass runs on a skeleton view (separators removed, diacritics stripped, Cyrillic /
//! Greek look-alikes mapped to Latin). A hit that only that pass finds is reported as
//! `Category::DictionaryEvasion`, which always blocks: it cannot be rewritten reliably.

use std::path::Path;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use anyhow::{bail, Context, Result};

use super::normalize::{fold_str, normalize, skeleton, skeleton_str, View};
use super::{Category, Finding};

pub struct Dictionary {
    folded: AhoCorasick,
    skel: Option<AhoCorasick>,
    len: usize,
}

/// True when a match starting at byte `s` of `text` starts an identifier segment: start of
/// text, after a non-alphanumeric char, or at a lower->upper case transition.
fn segment_start(text: &str, s: usize) -> bool {
    let Some(prev) = text[..s].chars().next_back() else {
        return true;
    };
    if !prev.is_alphanumeric() {
        return true;
    }
    let cur = text[s..].chars().next();
    prev.is_lowercase() && cur.is_some_and(|c| c.is_uppercase())
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
        let mut folded: Vec<String> = Vec::new();
        let mut skel: Vec<String> = Vec::new();
        for t in terms {
            let t = t.as_ref().trim();
            if t.chars().count() < 3 {
                bail!("dictionary term too short (min 3 chars)");
            }
            let f = fold_str(t);
            if f.chars().count() < 3 {
                bail!("dictionary term too short after normalization (min 3 chars)");
            }
            if !folded.contains(&f) {
                folded.push(f);
            }
            let k = skeleton_str(t);
            if k.chars().count() >= 3 && !skel.contains(&k) {
                skel.push(k);
            }
        }
        let build = |v: &[String]| {
            AhoCorasickBuilder::new()
                .match_kind(MatchKind::LeftmostLongest)
                .build(v)
                .context("cannot build dictionary automaton")
        };
        let ac = build(&folded)?;
        let sk = if skel.is_empty() {
            None
        } else {
            Some(build(&skel)?)
        };
        Ok(Dictionary {
            folded: ac,
            skel: sk,
            len: folded.len(),
        })
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Matches on an already folded view, as original spans.
    pub fn find_folded(&self, view: &View) -> Vec<(usize, usize)> {
        self.folded
            .find_iter(&view.text)
            .map(|m| view.span(m.start(), m.end()))
            .collect()
    }

    pub fn scan(&self, text: &str, out: &mut Vec<Finding>) {
        let view = normalize(text, true);
        let primary = self.find_folded(&view);
        for &(s, e) in &primary {
            out.push(Finding::new(Category::Dictionary, "dictionary term", s, e));
        }
        let Some(sk_ac) = &self.skel else { return };
        let sk = skeleton(&view);
        for m in sk_ac.find_iter(&sk.text) {
            let (s, e) = sk.span(m.start(), m.end());
            if primary.iter().any(|&(ps, pe)| ps < e && s < pe) {
                continue;
            }
            if !segment_start(text, s) {
                continue;
            }
            out.push(Finding::new(
                Category::DictionaryEvasion,
                "dictionary term (obfuscated: separators / look-alikes)",
                s,
                e,
            ));
        }
    }

    /// Any term in `text` under the folded or skeleton view.
    pub fn contains_any(&self, text: &str) -> bool {
        let view = normalize(text, true);
        if self.folded.is_match(&view.text) {
            return true;
        }
        self.skel
            .as_ref()
            .is_some_and(|k| k.is_match(&skeleton(&view).text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hits(d: &Dictionary, t: &str) -> Vec<(Category, String)> {
        let mut v = vec![];
        d.scan(t, &mut v);
        v.into_iter()
            .map(|f| (f.category, t[f.start..f.end].to_string()))
            .collect()
    }

    #[test]
    fn case_insensitive_inside_identifiers_longest_first() {
        let d = Dictionary::from_terms(["acme", "AcmeBilling", "Zorblax"]).unwrap();
        let t = "class AcmeBillingClient: ACME_URL; acme; zorblaxService";
        let mut v = vec![];
        d.scan(t, &mut v);
        let s: Vec<&str> = v
            .iter()
            .filter(|f| f.category == Category::Dictionary)
            .map(|f| &t[f.start..f.end])
            .collect();
        assert_eq!(s, vec!["AcmeBilling", "ACME", "acme", "zorblax"]);
        assert!(v.iter().all(|f| f.category == Category::Dictionary));
    }

    #[test]
    fn rejects_short_terms() {
        assert!(Dictionary::from_terms(["ab"]).is_err());
    }

    #[test]
    fn unicode_case_and_invisibles() {
        let d = Dictionary::from_terms(["Yıldız Holding", "Şirketim", "acme"]).unwrap();
        for (t, want) in [
            ("YILDIZ HOLDING q3", "YILDIZ HOLDING"),
            ("şirketim icin", "şirketim"),
            ("ŞİRKETİM A.Ş.", "ŞİRKETİM"),
            ("the ac\u{200b}me module", "ac\u{200b}me"),
            ("the ＡＣＭＥ module", "ＡＣＭＥ"),
        ] {
            assert_eq!(
                hits(&d, t),
                vec![(Category::Dictionary, want.into())],
                "{t}"
            );
        }
    }

    #[test]
    fn skeleton_pass_reports_evasion() {
        let d = Dictionary::from_terms(["megacorp", "acme"]).unwrap();
        let h = hits(&d, "MEGA_CORP_BILLING_URL and the \u{0430}cme module");
        assert!(
            h.contains(&(Category::DictionaryEvasion, "MEGA_CORP".into())),
            "{h:?}"
        );
        assert!(
            h.contains(&(Category::DictionaryEvasion, "\u{0430}cme".into())),
            "{h:?}"
        );
        // no evasion finding for ordinary words that merely contain the letters
        assert!(hits(&d, "pac me omega corps").is_empty());
        assert!(d.contains_any("Mega-Corp"));
        assert!(!d.contains_any("zavelorita"));
    }
}
