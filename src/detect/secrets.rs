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

fn pat_k(label: &'static str, re: &str) -> Pat {
    Pat {
        label,
        re: Regex::new(re).expect("static regex"),
        group: 1,
        check: None,
    }
}

const PLACEHOLDERS: &[&str] = &[
    "xxxx",
    "your_",
    "your-",
    "changeme",
    "placeholder",
    "example",
    "dummy",
];

/// `${VAR}`, `$VAR`, `{name}`, `{{name}}`, `%(name)s`: a template reference, not a value.
fn is_template_ref(v: &str) -> bool {
    static T: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^(?:\$\{[A-Za-z_][A-Za-z0-9_.:\-]*\}|\$[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_.]*\}|\{\{\s*[A-Za-z_][A-Za-z0-9_.]*\s*\}\}|%\([A-Za-z_][A-Za-z0-9_]*\)s)$")
            .expect("static regex")
    });
    T.is_match(v.trim())
}

/// A value on the right of `password = ...` that looks like a literal secret rather than code.
fn looks_secretish(v: &str) -> bool {
    let v = v.trim_matches(|c| c == '"' || c == '\'');
    if v.len() < 8 {
        return false;
    }
    if v.starts_with("MM_SECRET_") || is_template_ref(v) {
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
    !PLACEHOLDERS.iter().any(|p| lower.contains(p))
}

/// Quoted literal assigned to a secret-named variable: fire on any quoted literal of 8+ chars
/// (spaces allowed) unless it is an obvious placeholder or exactly a template reference.
fn quoted_or_secretish(v: &str) -> bool {
    let quoted = v.starts_with('"') || v.starts_with('\'');
    if quoted {
        let inner = v.trim_matches(|c| c == '"' || c == '\'');
        if inner.chars().count() < 8 {
            return false;
        }
        let lower = inner.to_ascii_lowercase();
        return !PLACEHOLDERS.iter().any(|p| lower.contains(p))
            && !lower.contains('<')
            && !is_template_ref(inner)
            && !inner.starts_with("MM_SECRET_");
    }
    looks_secretish(v)
}

// Key-format patterns start with `(?:^|[^A-Za-z0-9])` instead of `\b` so a `_` prefix
// (`backup_AKIA...`, `x_ghp_...`) does not hide them; the key itself is capture group 1.
static PATTERNS: LazyLock<Vec<Pat>> = LazyLock::new(|| {
    vec![
        pat_k(
            "provider key (sk-ant/sk_live/hf_/npm_/glpat/ya29/SG.)",
            r"(?:^|[^A-Za-z0-9])(sk-ant-[A-Za-z0-9_\-]{10,}|sk_live_[A-Za-z0-9]{10,}|sk_test_[A-Za-z0-9]{10,}|rk_live_[A-Za-z0-9]{10,}|hf_[A-Za-z0-9]{30,}|npm_[A-Za-z0-9]{30,}|glpat-[A-Za-z0-9_\-]{16,}|ya29\.[A-Za-z0-9_\-]{20,}|SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,})",
        ),
        pat_g(
            "api key (sk-/pk-/rk-)",
            r"\b((?:sk|pk|rk)[-_][A-Za-z0-9_\-]{16,})",
            1,
            |v| v.chars().any(|c| c.is_ascii_digit()),
        ),
        pat_k(
            "AWS access key",
            r"(?:^|[^A-Za-z0-9])((?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]{16})(?:[^0-9A-Za-z]|$)",
        ),
        pat_k(
            "GitHub token",
            r"(?:^|[^A-Za-z0-9])(gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})",
        ),
        pat_k(
            "Slack token",
            r"(?:^|[^A-Za-z0-9])(xox[abprs]-[A-Za-z0-9\-]{10,})",
        ),
        pat_k(
            "Google API key",
            r"(?:^|[^A-Za-z0-9])(AIza[0-9A-Za-z_\-]{30,})",
        ),
        pat_k(
            "JWT",
            r"(?:^|[^A-Za-z0-9])(eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})",
        ),
        pat("Bearer token", r"(?i)\bbearer\s+[A-Za-z0-9._~+/=\-]{20,}"),
        pat(
            "Authorization/x-api-key header",
            r"(?i)\b(?:authorization|x-api-key|api-key)\s*:\s*(?:[A-Za-z]+\s+)?[A-Za-z0-9._~+/=\-]{16,}",
        ),
        pat_k(
            "Stripe/Twilio-style key",
            r"(?:^|[^A-Za-z0-9])(AC[a-f0-9]{32}|SK[a-f0-9]{32}|whsec_[A-Za-z0-9]{20,})(?:[^0-9A-Za-z]|$)",
        ),
        pat_g(
            "env/config secret line",
            r#"(?m)^[ \t]*(?:export[ \t]+)?[A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|PASS|CREDENTIAL|PWD)[A-Z0-9_]*[ \t]*[=:][ \t]*("[^"\n]{8,}"|'[^'\n]{8,}'|[A-Za-z0-9_\-+/=.~!@#$%^&*]{8,})[ \t]*;?[ \t]*$"#,
            1,
            quoted_or_secretish,
        ),
        pat_g(
            "secret assignment",
            r#"(?i)(?:^|[^A-Za-z0-9])(?:password|passwd|passphrase|pass|pwd|parola|sifre|secret|client[_-]?secret|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|access[_-]?token|token)\b["']?\s*[=:]\s*("[^"\n]{8,}"|'[^'\n]{8,}'|[^\s"'<>()\[\]{},;]{8,})"#,
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
            concat!("aws = AKIA", "IOSFODNN7EXAMPL3"),
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
            concat!("src/backup_AKIA", "ABCDEFGHIJKLMNOP.py"),
            "x_ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            "old_sk_live_abcdefghijklmnop",
            "v2_xoxb-123456789012-abcdefghijkl",
            "id_AIzaSyA1234567890abcdefghijklmnopqrstuv",
            "DB_PASS=S3cretPassw0rd!",
            "db_pass = \"S3cretPassw0rd!\"",
            "password = \"Tr0ub4dor$3xyz\"",
            "password: \"correct horse battery staple\"",
            "Server=db;User Id=sa;Pwd=Sup3rS3cret!;",
            concat!("aws_secret_access_key: wJalrXUtnFEMI", "zKtMDENGgbPxRfiCYzzQWERTY7q"),
            "MY_PASSPHRASE='hunter2 hunter2'",
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
            "password = \"${DB_PASSWORD}\"",
            "token: '{{ api_token }}'",
            "bypass = 12",
            "self.pass_count = 12345678",
            "risk_pk_user_reference",
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
