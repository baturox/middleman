//! Shannon entropy over base64/hex-like tokens of 20+ chars. Tuned not to fire on UUIDs,
//! identifiers, or paths.

use std::sync::LazyLock;

use regex::Regex;

use super::{byte_at, byte_before, Category, Finding};

static TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/_\-]{20,}={0,2}").expect("static regex"));
static UUID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
        .expect("static regex")
});

pub fn shannon(s: &str) -> f64 {
    let mut counts = [0usize; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let n = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn is_high_entropy(tok: &str) -> bool {
    let tok = tok.trim_end_matches('=');
    let len = tok.len();
    if len < 20 || UUID.is_match(tok) || tok.starts_with("MM_") {
        return false;
    }
    if tok.matches('/').count() >= 3 || tok.contains("//") {
        return false; // path-like
    }
    let digits = tok.bytes().filter(|b| b.is_ascii_digit()).count();
    let upper = tok.bytes().any(|b| b.is_ascii_uppercase());
    let lower = tok.bytes().any(|b| b.is_ascii_lowercase());
    let all_hex = tok.bytes().all(|b| b.is_ascii_hexdigit());
    let h = shannon(tok);
    if all_hex {
        // hex digests / keys: 32+ chars with both digits and letters
        return len >= 32 && digits > 0 && digits < len && h >= 3.0;
    }
    // UUIDs embedded in longer hyphenated tokens: drop the UUID-looking parts first.
    if tok
        .split('-')
        .all(|p| p.bytes().all(|b| b.is_ascii_hexdigit()) || p.len() < 6)
    {
        return false;
    }
    let digit_ratio = digits as f64 / len as f64;
    let ceiling = (len as f64).log2();
    upper && lower && digits >= 2 && digit_ratio >= 0.08 && h >= 0.85 * ceiling.min(6.0)
}

pub fn scan(text: &str, out: &mut Vec<Finding>) {
    for m in TOKEN.find_iter(text) {
        // must be a standalone token (not part of a longer word with other chars like '.')
        if byte_before(text, m.start()).is_some_and(|b| b == b'.' || b == b'@')
            && byte_at(text, m.end()).is_some_and(|b| b == b'.')
        {
            continue;
        }
        if is_high_entropy(m.as_str()) {
            out.push(Finding::new(
                Category::HighEntropy,
                "high-entropy token",
                m.start(),
                m.end(),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fires(t: &str) -> bool {
        let mut v = vec![];
        scan(t, &mut v);
        !v.is_empty()
    }

    #[test]
    fn fires_on_random_base64_and_hex() {
        assert!(fires("k = 'q8Zr4TfX2bLm9WcN7vYp3KsD1hGe6JuA'"));
        assert!(fires(
            "sig=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        ));
    }

    #[test]
    fn quiet_on_uuids_identifiers_paths() {
        assert!(!fires("id = 550e8400-e29b-41d4-a716-446655440000"));
        assert!(!fires(
            "fn test_create_user_with_invalid_email_returns_error()"
        ));
        assert!(!fires("parseHttp2ResponseHeaders"));
        assert!(!fires("src/components/forms/UserProfileCard2"));
        assert!(!fires("MAX_RETRY_COUNT_2024_V2_FINAL"));
    }

    #[test]
    fn entropy_math() {
        assert!(shannon("aaaa") < 0.01);
        assert!((shannon("ab") - 1.0).abs() < 1e-9);
    }
}
