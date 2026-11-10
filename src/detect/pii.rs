//! PII: email, phone, IBAN (mod-97), TCKN (checksum), payment cards (Luhn).

use std::sync::LazyLock;

use regex::Regex;

use super::{byte_at, byte_before, is_word_byte, Category, Finding};

static EMAIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[\p{L}\p{N}._%+\-]+@([\p{L}\p{N}\-]+(?:\.[\p{L}\p{N}\-]+)*\.\p{L}{2,})")
        .expect("static regex")
});
static PHONE_TR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(\+90|0090|0)?[ ]?\(?5[0-9]{2}\)?[ .\-]?[0-9]{3}[ .\-]?[0-9]{2}[ .\-]?[0-9]{2}")
        .expect("static regex")
});
static PHONE_INTL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\+[0-9]{1,3}[ .\-]?\(?[0-9]{2,4}\)?[ .\-]?[0-9]{3,4}[ .\-]?[0-9]{3,4}")
        .expect("static regex")
});
/// North-American style without a country code: `(415) 555-2671`, `415-555-2671`,
/// `415.555.2671` (a separator or parentheses is required).
static PHONE_NANP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:\([2-9][0-9]{2}\)[ ]?|[2-9][0-9]{2}[ .\-])[2-9][0-9]{2}[ .\-][0-9]{4}")
        .expect("static regex")
});
static IBAN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,4})?\b")
        .expect("static regex")
});
static DIGIT_RUN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[0-9]+").expect("static regex"));
static CARD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[0-9](?:[ \-]?[0-9]){12,18}").expect("static regex"));

pub fn is_reserved_email_domain(domain: &str) -> bool {
    let d = domain.to_ascii_lowercase();
    ["example.com", "example.org", "example.net"].contains(&d.as_str())
        || d.ends_with(".example")
        || d.ends_with(".invalid")
        || d.ends_with(".test")
        || d.ends_with(".example.com")
        || d.ends_with(".example.net")
        || d.ends_with(".example.org")
        || d == "localhost"
}

pub fn luhn(digits: &str) -> bool {
    let mut sum = 0u32;
    for (i, ch) in digits.bytes().rev().enumerate() {
        let mut d = (ch - b'0') as u32;
        if i % 2 == 1 {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
    }
    sum.is_multiple_of(10)
}

pub fn tckn_valid(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 11 || b[0] == b'0' || !b.iter().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let d: Vec<i32> = b.iter().map(|c| (c - b'0') as i32).collect();
    let odd: i32 = d[0] + d[2] + d[4] + d[6] + d[8];
    let even: i32 = d[1] + d[3] + d[5] + d[7];
    let d10 = (odd * 7 - even).rem_euclid(10);
    let d11 = d[..10].iter().sum::<i32>() % 10;
    d10 == d[9] && d11 == d[10]
}

pub fn iban_valid(s: &str) -> bool {
    let c: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !(15..=34).contains(&c.len()) {
        return false;
    }
    let rearranged = format!("{}{}", &c[4..], &c[..4]);
    let mut rem: u64 = 0;
    for ch in rearranged.chars() {
        let v = if ch.is_ascii_digit() {
            ch as u64 - '0' as u64
        } else if ch.is_ascii_uppercase() {
            ch as u64 - 'A' as u64 + 10
        } else {
            return false;
        };
        rem = if v >= 10 {
            (rem * 100 + v) % 97
        } else {
            (rem * 10 + v) % 97
        };
    }
    rem == 1
}

fn digit_bounded(text: &str, start: usize, end: usize) -> bool {
    !byte_before(text, start).is_some_and(|b| b.is_ascii_digit() || b == b'.')
        && !byte_at(text, end).is_some_and(|b| b.is_ascii_digit())
}

pub fn scan(text: &str, out: &mut Vec<Finding>) {
    for c in EMAIL.captures_iter(text) {
        let m = c.get(0).unwrap();
        let domain = c.get(1).unwrap().as_str();
        if is_reserved_email_domain(domain) {
            continue;
        }
        out.push(Finding::new(Category::Email, "email", m.start(), m.end()));
    }
    for c in PHONE_TR.captures_iter(text) {
        let m = c.get(0).unwrap();
        let s = m.as_str();
        let has_prefix = c.get(1).is_some();
        let seps = s.chars().filter(|ch| matches!(ch, ' ' | '.' | '-')).count();
        if !has_prefix && seps < 2 {
            continue; // a bare 10-digit number is more likely a constant than a phone
        }
        let start = m.start() + (s.len() - s.trim_start().len());
        if digit_bounded(text, start, m.end())
            && !byte_before(text, start).is_some_and(is_word_byte)
        {
            out.push(Finding::new(Category::Phone, "phone (TR)", start, m.end()));
        }
    }
    for m in PHONE_INTL.find_iter(text) {
        if !byte_before(text, m.start()).is_some_and(is_word_byte)
            && !byte_at(text, m.end()).is_some_and(|b| b.is_ascii_digit())
        {
            out.push(Finding::new(Category::Phone, "phone", m.start(), m.end()));
        }
    }
    for m in PHONE_NANP.find_iter(text) {
        if !byte_before(text, m.start()).is_some_and(|b| is_word_byte(b) || b == b'.' || b == b'-')
            && !byte_at(text, m.end()).is_some_and(|b| b.is_ascii_digit() || b == b'.' || b == b'-')
        {
            out.push(Finding::new(Category::Phone, "phone", m.start(), m.end()));
        }
    }
    for m in IBAN.find_iter(text) {
        if iban_valid(m.as_str()) {
            out.push(Finding::new(Category::Iban, "IBAN", m.start(), m.end()));
        }
    }
    for m in DIGIT_RUN.find_iter(text) {
        if m.len() == 11 && tckn_valid(m.as_str()) && digit_bounded(text, m.start(), m.end()) {
            out.push(Finding::new(Category::Tckn, "TCKN", m.start(), m.end()));
        }
    }
    for m in CARD.find_iter(text) {
        if !digit_bounded(text, m.start(), m.end()) {
            continue;
        }
        let digits: String = m.as_str().chars().filter(|c| c.is_ascii_digit()).collect();
        let Some(&first) = digits.as_bytes().first() else {
            continue;
        };
        if (13..=19).contains(&digits.len()) && (b'3'..=b'6').contains(&first) && luhn(&digits) {
            out.push(Finding::new(
                Category::Card,
                "payment card",
                m.start(),
                m.end(),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cats(t: &str) -> Vec<Category> {
        let mut v = vec![];
        scan(t, &mut v);
        v.into_iter().map(|f| f.category).collect()
    }

    #[test]
    fn tckn_vectors() {
        assert!(tckn_valid("10000000146"));
        assert!(!tckn_valid("10000000147"));
        assert!(!tckn_valid("01234567890"));
        assert!(cats("id: 10000000146").contains(&Category::Tckn));
        assert!(!cats("id: 10000000147").contains(&Category::Tckn));
    }

    #[test]
    fn luhn_vectors() {
        assert!(luhn("4111111111111111"));
        assert!(luhn("79927398713"));
        assert!(!luhn("4111111111111112"));
        assert!(cats("card 4111 1111 1111 1111 ok").contains(&Category::Card));
        assert!(!cats("card 4111 1111 1111 1112 ok").contains(&Category::Card));
        // ms timestamps start with 1 and are not cards
        assert!(!cats("ts = 1700000000005").contains(&Category::Card));
    }

    #[test]
    fn iban_vectors() {
        assert!(iban_valid("GB82 WEST 1234 5698 7654 32"));
        assert!(iban_valid("TR330006100519786457841326"));
        assert!(!iban_valid("GB82 WEST 1234 5698 7654 33"));
        assert!(cats("pay to GB82 WEST 1234 5698 7654 32 now").contains(&Category::Iban));
    }

    #[test]
    fn emails() {
        assert_eq!(cats("mail jane.doe@acme-corp.io"), vec![Category::Email]);
        assert!(cats("user3@example.com").is_empty());
        assert!(cats("a@b.test").is_empty());
        assert_eq!(cats("yaz: çağrı@gizlifirma.com"), vec![Category::Email]);
    }

    #[test]
    fn phones() {
        assert!(cats("call +90 532 123 45 67").contains(&Category::Phone));
        assert!(cats("call 0532 123 45 67").contains(&Category::Phone));
        assert!(cats("tel +1 415 555 2671").contains(&Category::Phone));
        assert!(!cats("const N: u64 = 5321234567;").contains(&Category::Phone));
        assert!(cats("call (415) 555-2671 now").contains(&Category::Phone));
        assert!(cats("call 415-555-2671").contains(&Category::Phone));
        assert!(!cats("version 1.415.555.2671").contains(&Category::Phone));
        assert!(!cats("date 2024-05-12").contains(&Category::Phone));
    }

    #[test]
    fn unicode_digits_do_not_panic() {
        let t = "\u{0661}\u{0662}\u{0663}\u{0664}\u{0665}\u{0666}\u{0667}\u{0668}\u{0669}\u{0660}\u{0661}\u{0662}\u{0663}";
        assert!(cats(t).is_empty());
    }
}
