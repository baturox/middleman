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

/// Secret-ish keyword shortly before the token on the same line (`session ...`, `sig=`, ...).
fn secret_context(text: &str, start: usize) -> bool {
    static CTX: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)(?:key|token|secret|pass|pwd|auth|session|cookie|sig|cred|bearer|private|salt|hmac|nonce|api)")
            .expect("static regex")
    });
    let mut from = start.saturating_sub(40);
    while !text.is_char_boundary(from) {
        from += 1;
    }
    let before = &text[from..start];
    let line = before.rsplit('\n').next().unwrap_or(before);
    CTX.is_match(line)
}

/// Path-like: several `/` separators and mostly lowercase letters (random base64 is ~50%
/// uppercase, paths rarely are).
fn path_like(tok: &str) -> bool {
    if tok.contains("//") {
        return true;
    }
    if tok.matches('/').count() < 3 {
        return false;
    }
    let letters = tok
        .bytes()
        .filter(|b| b.is_ascii_alphabetic())
        .count()
        .max(1);
    let upper = tok.bytes().filter(|b| b.is_ascii_uppercase()).count();
    (upper as f64) / (letters as f64) < 0.2
}

fn is_high_entropy(tok: &str, ctx: bool) -> bool {
    let tok = tok.trim_end_matches('=');
    let len = tok.len();
    if len < 20 || UUID.is_match(tok) || tok.starts_with("MM_") {
        return false;
    }
    if path_like(tok) {
        return false;
    }
    let digits = tok.bytes().filter(|b| b.is_ascii_digit()).count();
    let upper = tok.bytes().any(|b| b.is_ascii_uppercase());
    let lower = tok.bytes().any(|b| b.is_ascii_lowercase());
    let letters = upper || lower;
    let all_hex = tok.bytes().all(|b| b.is_ascii_hexdigit());
    let h = shannon(tok);
    if all_hex {
        // hex digests / keys: 32+ chars with both digits and letters; 24+ next to a
        // secret-ish keyword
        // (hex-encoded ASCII has lower entropy than random hex, hence 2.5 in context)
        let (min, hmin) = if ctx { (24, 2.5) } else { (32, 3.0) };
        return len >= min && digits > 0 && digits < len && h >= hmin;
    }
    // UUIDs embedded in longer hyphenated tokens: drop the UUID-looking parts first.
    if tok
        .split('-')
        .all(|p| p.bytes().all(|b| b.is_ascii_hexdigit()) || p.len() < 6)
    {
        return false;
    }
    let ceiling = (len as f64).log2().min(6.0);
    if len >= 32 {
        // long random tokens need no digit (AWS secret keys often have 0-1)
        return upper && lower && h >= 0.8 * ceiling
            || (ctx && letters && digits > 0 && h >= 0.75 * ceiling);
    }
    let digit_ratio = digits as f64 / len as f64;
    let mixed = upper && lower && digits >= 1 && digit_ratio >= 0.04 && h >= 0.8 * ceiling;
    // near a secret-ish keyword: single-case + digits is enough (`session k3j4h5...`) when
    // letters and digits interleave (identifiers like `user_session_id_2024` do not)
    let transitions = tok
        .as_bytes()
        .windows(2)
        .filter(|w| w[0].is_ascii_digit() != w[1].is_ascii_digit())
        .count();
    let contextual = ctx && letters && digits >= 2 && transitions * 4 >= len && h >= 0.7 * ceiling;
    mixed || contextual
}

pub fn scan(text: &str, out: &mut Vec<Finding>) {
    for m in TOKEN.find_iter(text) {
        // must be a standalone token (not part of a longer word with other chars like '.')
        if byte_before(text, m.start()).is_some_and(|b| b == b'.' || b == b'@')
            && byte_at(text, m.end()).is_some_and(|b| b == b'.')
        {
            continue;
        }
        let ctx = secret_context(text, m.start());
        if is_high_entropy(m.as_str(), ctx) {
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
        // long token without digits; contextual hex and lower+digit tokens
        assert!(fires(concat!(
            "value: wJalrXUtnFEMI",
            "zKtMDENGgbPxRfiCYzzQWERTYqq"
        )));
        assert!(fires("secret_hex = 736b5f6c6976655f6162636465"));
        assert!(fires("session k3j4h5k2j3h4k5j6h7k8j9m2"));
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
        assert!(!fires("testCreateUserWithInvalidEmailReturnsError"));
        assert!(!fires("blob 736b5f6c6976655f6162636465"));
        assert!(!fires("very_long_snake_case_function_name_for_tests"));
        assert!(!fires("session = user_session_id_2024"));
    }

    #[test]
    fn entropy_math() {
        assert!(shannon("aaaa") < 0.01);
        assert!((shannon("ab") - 1.0).abs() < 1e-9);
    }
}
