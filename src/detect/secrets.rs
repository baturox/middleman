//! Hard secrets: provider key formats, PEM blocks, JWTs, URL credentials, assignment heuristics.
//! Ported from `metin_ajan.py gizli_tara`, tightened to cut false positives on ordinary code.

use std::sync::LazyLock;

use regex::Regex;

use super::{Category, Finding};

struct Pat {
    label: &'static str,
    re: Regex,
    /// Capture group whose span is reported (0 = whole match).
    group: usize,
    /// Optional post-filter on the reported text.
    check: Option<fn(&str) -> bool>,
}

fn pat(label: &'static str, re: &str) -> Pat {
    Pat {
        label,
        re: Regex::new(re).expect("static regex"),
        group: 0,
        check: None,
    }
}

fn pat_g(label: &'static str, re: &str, group: usize, check: fn(&str) -> bool) -> Pat {
    Pat {
        label,
        re: Regex::new(re).expect("static regex"),
        group,
        check: Some(check),
    }
}

/// A value on the right of `password = ...` that looks like a literal secret rather than code.
fn looks_secretish(v: &str) -> bool {
    let v = v.trim_matches(|c| c == '"' || c == '\'');
    if v.len() < 8 {
        return false;
    }
    if v.starts_with("MM_SECRET_") {
        return false;
    }
    // Plain identifiers / dotted paths without digits are code, not secrets.
    let identifier_like = v
        .chars()
        .all(|c| c.is_ascii_alphabetic() || c == '_' || c == '.');
    if identifier_like {
        return false;
    }
    if v.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let lower = v.to_ascii_lowercase();
    for placeholder in [
        "xxxx",
        "your_",
        "your-",
        "changeme",
        "placeholder",
        "example",
        "dummy",
    ] {
        if lower.contains(placeholder) {
            return false;
        }
    }
    true
}

/// Quoted literal assigned to a secret-named variable: fire on any quoted literal of 8+ chars
/// unless it is an obvious placeholder.
fn quoted_or_secretish(v: &str) -> bool {
    let quoted = v.starts_with('"') || v.starts_with('\'');
    if quoted {
        let inner = v.trim_matches(|c| c == '"' || c == '\'');
        if inner.len() < 8 {
            return false;
        }
        let lower = inner.to_ascii_lowercase();
        return ![
            "xxxx",
            "your_",
            "your-",
            "changeme",
            "placeholder",
            "example",
            "<",
        ]
        .iter()
        .any(|p| lower.contains(p))
            && !inner.contains('{')
            && !inner.contains('$')
            && !inner.starts_with("MM_SECRET_");
    }
    looks_secretish(v)
}

static PATTERNS: LazyLock<Vec<Pat>> = LazyLock::new(|| {
    vec![
        pat(
            "provider key (sk-ant/sk_live/hf_/npm_/glpat/ya29/SG.)",
            r"\b(?:sk-ant-[A-Za-z0-9_\-]{10,}|sk_live_[A-Za-z0-9]{10,}|sk_test_[A-Za-z0-9]{10,}|rk_live_[A-Za-z0-9]{10,}|hf_[A-Za-z0-9]{30,}|npm_[A-Za-z0-9]{30,}|glpat-[A-Za-z0-9_\-]{16,}|ya29\.[A-Za-z0-9_\-]{20,}|SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,})",
        ),
        pat_g(
            "api key (sk-/pk-/rk-)",
            r"\b((?:sk|pk|rk)[-_][A-Za-z0-9_\-]{16,})",
            1,
            |v| v.chars().any(|c| c.is_ascii_digit()),
        ),
        pat("AWS access key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        pat(
            "GitHub token",
            r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})",
        ),
        pat("Slack token", r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"),
        pat("Google API key", r"\bAIza[0-9A-Za-z_\-]{30,}"),
        pat(
            "JWT",
            r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}",
        ),
        pat("Bearer token", r"(?i)\bbearer\s+[A-Za-z0-9._~+/=\-]{20,}"),
        pat(
            "Authorization/x-api-key header",
            r"(?i)\b(?:authorization|x-api-key|api-key)\s*:\s*(?:[A-Za-z]+\s+)?[A-Za-z0-9._~+/=\-]{16,}",
        ),
        pat(
            "Stripe/Twilio-style key",
            r"\b(?:AC[a-f0-9]{32}|SK[a-f0-9]{32}|whsec_[A-Za-z0-9]{20,})\b",
        ),
        pat_g(
            "env/config secret line",
            r#"(?m)^\s*(?:export\s+)?[A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PWD)[A-Z0-9_]*\s*[=:]\s*(["']?[A-Za-z0-9_\-+/=.~!@#%^&*]{8,}["']?)\s*;?\s*$"#,
            1,
            quoted_or_secretish,
        ),
        pat_g(
            "secret assignment",
            r#"(?i)\b(?:password|passwd|pwd|parola|sifre|secret|client[_-]?secret|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|access[_-]?token|token)\b["']?\s*[=:]\s*(["'][^"'\s]{8,}["']|[^\s"'<>()\[\]{},;]{8,})"#,
            1,
            quoted_or_secretish,
        ),
        pat(
            "secret URL parameter",
            r"(?i)[?&](?:api[_-]?key|key|token|access_token|secret|sig|signature|auth|password)=[^&\s#]{8,}",
        ),
        pat("credentials in URL", r"://[^/\s:@]+:[^/\s@]+@"),
    ]
});

static PEM_BEGIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-----BEGIN [A-Z0-9 ]*(?:PRIVATE KEY|CERTIFICATE)[A-Z ]*-----").unwrap()
});
static PEM_END: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"-----END [A-Z0-9 ]*-----").unwrap());

pub fn scan(text: &str, out: &mut Vec<Finding>) {
    for p in PATTERNS.iter() {
        for caps in p.re.captures_iter(text) {
            let Some(m) = caps.get(p.group) else { continue };
            if let Some(check) = p.check {
                if !check(m.as_str()) {
                    continue;
                }
            }
            out.push(Finding::new(Category::Secret, p.label, m.start(), m.end()));
        }
    }
    for m in PEM_BEGIN.find_iter(text) {
        let end = PEM_END
            .find_at(text, m.end())
            .map(|e| e.end())
            .unwrap_or(text.len());
        out.push(Finding::new(Category::Secret, "PEM block", m.start(), end));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hits(t: &str) -> Vec<&'static str> {
        let mut v = vec![];
        scan(t, &mut v);
        v.into_iter().map(|f| f.label).collect()
    }

    #[test]
    fn positives() {
        for t in [
            "aws = AKIAIOSFODNN7EXAMPL3",
            "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            "sk-ant-api03-abcdefghijklmnop",
            "token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----",
            "DB_PASSWORD=hunter2hunter2",
            "password = \"s3cr3tP@ssword\"",
            "postgres://admin:pw123456@db.internal:5432/app",
            "https://x.test/cb?api_key=abcdef123456",
            "xoxb-123456789012-abcdefghij",
            "AIzaSyA1234567890abcdefghijklmnopqrstu",
        ] {
            assert!(!hits(t).is_empty(), "expected hit: {t}");
        }
    }

    #[test]
    fn negatives() {
        for t in [
            "let api_key = config.api_key;",
            "API_KEY = os.environ[\"API_KEY\"]",
            "token: Option<String>,",
            "password = request.form.password",
            "headers = {\"Authorization\": f\"Bearer {key}\"}",
            "max_tokens = 2000",
            "def get_secret_name(self): pass",
            "password = \"changeme_placeholder\"",
            "const TOKEN_EXPIRY_SECONDS = 3600;",
            "MM_SECRET_3",
        ] {
            assert!(hits(t).is_empty(), "unexpected hit {:?}: {t}", hits(t));
        }
    }

    #[test]
    fn pem_span_covers_block() {
        let t = "x\n-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\ny";
        let mut v = vec![];
        scan(t, &mut v);
        let f = v.iter().find(|f| f.label == "PEM block").unwrap();
        assert_eq!(&t[f.start..f.end], &t[2..t.len() - 2]);
    }
}
