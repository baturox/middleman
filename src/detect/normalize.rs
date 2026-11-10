//! Normalized views of a text for detection. Each view keeps a byte-level map back to the
//! original, so a match in the view is reported (and replaced) on the original span.
//!
//! - `normalize(text, false)`: NFKC per grapheme-ish cluster, invisible format characters
//!   (Unicode Cf, variation selectors, combining grapheme joiner) removed. Case preserved:
//!   used for the secret / PII / infra scanners.
//! - `normalize(text, true)`: the same plus case folding (Turkish `İ I ı i` all fold to `i`,
//!   `ß` -> `ss`, final sigma -> sigma). Used for the dictionary.
//! - `skeleton(&folded)`: separators (`_ - .`, whitespace, `'`) dropped, diacritics stripped,
//!   Cyrillic/Greek Latin look-alikes mapped to Latin. Used for the fail-closed second
//!   dictionary pass.
//! - `join_concat(text)`: `"abc" + "def"` string concatenations joined (`"abcdef"`), for
//!   split secret literals.

use unicode_normalization::char::canonical_combining_class;
use unicode_normalization::UnicodeNormalization;

/// A derived text plus, for every byte of it, the original byte span it came from.
#[derive(Debug, Clone)]
pub struct View {
    pub text: String,
    starts: Vec<u32>,
    ends: Vec<u32>,
}

impl View {
    fn with_capacity(n: usize) -> View {
        View {
            text: String::with_capacity(n),
            starts: Vec::with_capacity(n),
            ends: Vec::with_capacity(n),
        }
    }

    fn push_str(&mut self, s: &str, start: usize, end: usize) {
        self.text.push_str(s);
        for _ in 0..s.len() {
            self.starts.push(start as u32);
            self.ends.push(end as u32);
        }
    }

    fn push_char(&mut self, c: char, start: usize, end: usize) {
        let mut b = [0u8; 4];
        self.push_str(c.encode_utf8(&mut b), start, end);
    }

    /// Original byte span covering view bytes `s..e` (`e > s`).
    pub fn span(&self, s: usize, e: usize) -> (usize, usize) {
        if self.starts.is_empty() {
            return (0, 0);
        }
        let s = s.min(self.starts.len() - 1);
        let e = e.clamp(s + 1, self.ends.len());
        (self.starts[s] as usize, self.ends[e - 1] as usize)
    }

    pub fn len(&self) -> usize {
        self.text.len()
    }

    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }
}

/// Invisible formatting characters: the Unicode `Cf` category plus variation selectors and
/// the combining grapheme joiner. They render as nothing and are dropped before matching.
pub fn is_invisible(c: char) -> bool {
    matches!(c as u32,
        0x00AD
        | 0x034F
        | 0x0600..=0x0605
        | 0x061C
        | 0x06DD
        | 0x070F
        | 0x0890..=0x0891
        | 0x08E2
        | 0x180B..=0x180F
        | 0x200B..=0x200F
        | 0x202A..=0x202E
        | 0x2060..=0x2064
        | 0x2066..=0x206F
        | 0xFE00..=0xFE0F
        | 0xFEFF
        | 0xFFF9..=0xFFFB
        | 0x110BD
        | 0x110CD
        | 0x13430..=0x1343F
        | 0x1BCA0..=0x1BCA3
        | 0x1D173..=0x1D17A
        | 0xE0001
        | 0xE0020..=0xE007F
        | 0xE0100..=0xE01EF)
}

/// Full case folding for matching (simple folding plus the multi-char and Turkish cases that
/// matter for names). Every dotted/dotless i folds to `i`.
pub fn fold_char(c: char, out: &mut String) {
    match c {
        'I' | 'İ' | 'ı' => out.push('i'),
        'ß' | 'ẞ' => out.push_str("ss"),
        'ς' => out.push('σ'),
        'ſ' => out.push('s'),
        'ﬀ' => out.push_str("ff"),
        'ﬁ' => out.push_str("fi"),
        'ﬂ' => out.push_str("fl"),
        _ => out.extend(c.to_lowercase()),
    }
}

/// NFKC (+ optional case fold) with invisible characters removed, mapped to the original.
pub fn normalize(text: &str, fold: bool) -> View {
    let mut v = View::with_capacity(text.len());
    let mut it = text.char_indices().peekable();
    let mut cluster = String::new();
    let mut tmp = String::new();
    while let Some((start, c)) = it.next() {
        if is_invisible(c) {
            continue;
        }
        cluster.clear();
        cluster.push(c);
        let mut end = start + c.len_utf8();
        // attach following combining marks (and skip invisibles between them)
        while let Some(&(i, n)) = it.peek() {
            if is_invisible(n) {
                it.next();
                continue;
            }
            if canonical_combining_class(n) == 0 {
                break;
            }
            cluster.push(n);
            end = i + n.len_utf8();
            it.next();
        }
        if cluster.is_ascii() {
            if fold {
                cluster.make_ascii_lowercase();
            }
            v.push_str(&cluster, start, end);
            continue;
        }
        tmp.clear();
        for n in cluster.nfkc() {
            if is_invisible(n) {
                continue;
            }
            if fold {
                fold_char(n, &mut tmp);
            } else {
                tmp.push(n);
            }
        }
        v.push_str(&tmp, start, end);
    }
    v
}

/// Normalized + folded form of a short string (dictionary terms, vault originals).
pub fn fold_str(s: &str) -> String {
    normalize(s, true).text
}

/// Latin look-alike for common Cyrillic / Greek confusables (input already lowercase).
pub fn confusable(c: char) -> char {
    match c {
        // Cyrillic
        'а' => 'a',
        'в' => 'b',
        'с' | 'ϲ' => 'c',
        'ԁ' => 'd',
        'е' | 'ё' | 'є' => 'e',
        'һ' | 'н' => 'h',
        'і' | 'ї' | 'ӏ' => 'i',
        'ј' => 'j',
        'к' | 'κ' => 'k',
        'м' => 'm',
        'о' | 'ο' | 'σ' => 'o',
        'р' | 'ρ' => 'p',
        'ԛ' => 'q',
        'ѕ' => 's',
        'т' | 'τ' => 't',
        'у' | 'γ' => 'y',
        'х' | 'χ' => 'x',
        'ԝ' | 'ω' => 'w',
        'ɡ' => 'g',
        'ɩ' | 'ι' => 'i',
        // Greek
        'α' => 'a',
        'β' => 'b',
        'ε' => 'e',
        'η' => 'n',
        'ν' => 'v',
        'υ' | 'μ' => 'u',
        'ζ' => 'z',
        _ => c,
    }
}

fn is_separator(c: char) -> bool {
    c == '_' || c == '-' || c == '.' || c == '\'' || c == '·' || c.is_whitespace()
}

/// Skeleton of a folded view: separators removed, diacritics stripped, confusables mapped.
pub fn skeleton(folded: &View) -> View {
    let mut v = View::with_capacity(folded.len());
    for (i, c) in folded.text.char_indices() {
        if is_separator(c) {
            continue;
        }
        let (s, e) = folded.span(i, i + c.len_utf8());
        if c.is_ascii() {
            v.push_char(c, s, e);
            continue;
        }
        for d in std::iter::once(c).nfd() {
            if canonical_combining_class(d) != 0 {
                continue;
            }
            v.push_char(confusable(d), s, e);
        }
    }
    v
}

/// Skeleton of a short string (dictionary terms).
pub fn skeleton_str(s: &str) -> String {
    skeleton(&normalize(s, true)).text
}

/// Join adjacent string-literal concatenations: `"AKIA" + "XYZ"` -> `"AKIAXYZ"`. Returns
/// None when the text has none.
pub fn join_concat(text: &str) -> Option<View> {
    let b = text.as_bytes();
    let mut cuts: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let q = b[i];
        if q == b'"' || q == b'\'' {
            // closing quote, then optional spaces, '+', optional spaces/newlines, opening quote
            let mut j = i + 1;
            while j < b.len() && (b[j] == b' ' || b[j] == b'\t') {
                j += 1;
            }
            if j < b.len() && b[j] == b'+' {
                j += 1;
                while j < b.len() && b[j].is_ascii_whitespace() {
                    j += 1;
                }
                if j < b.len() && (b[j] == b'"' || b[j] == b'\'') {
                    cuts.push((i, j + 1));
                    i = j + 1;
                    continue;
                }
            }
        }
        i += 1;
    }
    if cuts.is_empty() {
        return None;
    }
    let mut v = View::with_capacity(text.len());
    let mut last = 0;
    for (s, e) in cuts {
        for (k, c) in text[last..s].char_indices() {
            let p = last + k;
            v.push_char(c, p, p + c.len_utf8());
        }
        last = e;
    }
    for (k, c) in text[last..].char_indices() {
        let p = last + k;
        v.push_char(c, p, p + c.len_utf8());
    }
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_invisibles_and_maps_back() {
        let t = "key AKIA\u{200b}ABCD";
        let v = normalize(t, false);
        assert_eq!(v.text, "key AKIAABCD");
        let s = v.text.find("AKIA").unwrap();
        let (os, oe) = v.span(s, v.text.len());
        assert_eq!(&t[os..oe], "AKIA\u{200b}ABCD");
    }

    #[test]
    fn folds_turkish_and_compat_forms() {
        assert_eq!(fold_str("YILDIZ HOLDİNG"), "yildiz holding");
        assert_eq!(fold_str("Yıldız"), "yildiz");
        assert_eq!(fold_str("ŞİRKETİM"), "şirketim");
        assert_eq!(fold_str("Ｍｅｇａ"), "mega");
        assert_eq!(fold_str("Straße"), "strasse");
        // decomposed input composes
        assert_eq!(fold_str("s\u{0327}irket"), "şirket");
    }

    #[test]
    fn skeleton_drops_separators_and_confusables() {
        assert_eq!(skeleton_str("MEGA_CORP"), "megacorp");
        assert_eq!(skeleton_str("\u{0430}cme"), "acme");
        assert_eq!(skeleton_str("Şirket-im"), "sirketim");
        let t = "x M\u{0415}GA-corp y";
        let f = normalize(t, true);
        let k = skeleton(&f);
        let s = k.text.find("megacorp").unwrap();
        let (os, oe) = k.span(s, s + "megacorp".len());
        assert_eq!(&t[os..oe], "M\u{0415}GA-corp");
    }

    #[test]
    fn joins_concatenated_literals() {
        let t = r#"k = "AKIA" + "ABCDEFGHIJKLMNOP""#;
        let v = join_concat(t).unwrap();
        assert_eq!(v.text, concat!(r#"k = "AKIA"#, r#"ABCDEFGHIJKLMNOP""#));
        let s = v.text.find("AKIA").unwrap();
        let (os, oe) = v.span(s, s + 20);
        assert_eq!(&t[os..oe], r#"AKIA" + "ABCDEFGHIJKLMNOP"#);
        assert!(join_concat("a + b").is_none());
    }
}
