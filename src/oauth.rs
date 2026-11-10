//! `middleman login openrouter`: OpenRouter's OAuth PKCE flow, which mints a user-controlled
//! API key without copy-paste.
//!
//! Verified against <https://openrouter.ai/docs/guides/overview/auth/oauth> (2026-11-10):
//! 1. open `https://openrouter.ai/auth?callback_url=..&code_challenge=..&code_challenge_method=S256`
//!    (+ optional `key_label`, `state`); localhost callbacks are allowed on any port;
//! 2. the browser comes back to `callback_url?code=..&state=..`;
//! 3. `POST https://openrouter.ai/api/v1/auth/keys` with JSON
//!    `{code, code_verifier, code_challenge_method}` returns `{"key": "..."}`.
//!    Codes are single use and expire after 10 minutes.
//!
//! Headless mode (documented too): omit `callback_url`; the page shows the code and the user
//! pastes it into the terminal.
//!
//! The callback listener binds 127.0.0.1 on a random port, accepts connections until it gets
//! one `GET /callback` request (anything else gets a 404), checks the Host header and `state`,
//! answers that single request and stops. It gives up after a timeout.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use base64::Engine;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::config::Secret;

pub const AUTH_URL: &str = "https://openrouter.ai/auth";
pub const EXCHANGE_URL: &str = "https://openrouter.ai/api/v1/auth/keys";

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn random_b64(n: usize) -> Result<String> {
    let mut b = Zeroizing::new(vec![0u8; n]);
    getrandom::fill(&mut b).map_err(|e| anyhow::anyhow!("no OS randomness: {e}"))?;
    Ok(b64url(&b))
}

/// PKCE verifier (43 chars from 32 random bytes) and its S256 challenge.
pub struct Pkce {
    pub verifier: Zeroizing<String>,
    pub challenge: String,
}

pub fn challenge_s256(verifier: &str) -> String {
    b64url(&Sha256::digest(verifier.as_bytes()))
}

pub fn pkce() -> Result<Pkce> {
    let verifier = Zeroizing::new(random_b64(32)?);
    let challenge = challenge_s256(&verifier);
    Ok(Pkce {
        verifier,
        challenge,
    })
}

pub fn new_state() -> Result<String> {
    random_b64(24)
}

/// The `/auth` URL. `callback` None = headless mode (the page shows the code).
pub fn auth_url(
    callback: Option<&str>,
    challenge: &str,
    state: Option<&str>,
    key_label: &str,
) -> String {
    let mut params: Vec<(&str, &str)> = vec![];
    if let Some(c) = callback {
        params.push(("callback_url", c));
    }
    params.push(("code_challenge", challenge));
    params.push(("code_challenge_method", "S256"));
    params.push(("key_label", key_label));
    if let Some(s) = state {
        params.push(("state", s));
    }
    reqwest::Url::parse_with_params(AUTH_URL, &params)
        .map(|u| u.to_string())
        .unwrap_or_else(|_| AUTH_URL.to_string())
}

/// A bound, not yet used callback listener.
pub struct Callback {
    listener: TcpListener,
    pub port: u16,
}

impl Callback {
    pub fn bind() -> Result<Callback> {
        let listener =
            TcpListener::bind(("127.0.0.1", 0)).context("cannot open a localhost port")?;
        let port = listener.local_addr()?.port();
        Ok(Callback { listener, port })
    }

    /// `callback_url` to send to OpenRouter.
    pub fn url(&self) -> String {
        format!("http://localhost:{}/callback", self.port)
    }

    /// Wait for the browser's single callback request and return the authorization code.
    pub fn wait(self, expected_state: &str, timeout: Duration) -> Result<Zeroizing<String>> {
        let deadline = Instant::now() + timeout;
        self.listener.set_nonblocking(true)?;
        loop {
            if Instant::now() >= deadline {
                bail!(
                    "timed out after {}s waiting for the browser; nothing was stored. \
Re-run `middleman login openrouter` (or add --no-browser to paste a code instead)",
                    timeout.as_secs()
                );
            }
            let (stream, _) = match self.listener.accept() {
                Ok(s) => s,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
                Err(e) => return Err(e).context("callback listener failed"),
            };
            match handle(stream, self.port, expected_state)? {
                Some(code) => return Ok(code),
                None => continue, // not the callback (favicon, preconnect): keep waiting
            }
        }
    }
}

fn respond(mut s: &TcpStream, status: &str, body: &str) {
    let page = format!(
        "<!doctype html><meta charset=utf-8><title>middleman</title>\
<body style=\"font-family:system-ui;max-width:32em;margin:4em auto\"><h2>middleman</h2><p>{body}</p>"
    );
    let _ = write!(
        s,
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
Cache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n{page}",
        page.len()
    );
    let _ = s.flush();
}

/// One connection. Ok(None) = not our request, keep listening. Ok(Some) = the code.
/// Err = the callback arrived but is unusable (wrong state, denied): stop.
fn handle(stream: TcpStream, port: u16, expected_state: &str) -> Result<Option<Zeroizing<String>>> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut buf = Zeroizing::new(Vec::with_capacity(2048));
    let mut chunk = [0u8; 1024];
    let mut s = &stream;
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < 16 * 1024 {
        match s.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return Ok(None),
        }
    }
    let head = Zeroizing::new(String::from_utf8_lossy(&buf).into_owned());
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split(' ');
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    if method != "GET" || !(target == "/callback" || target.starts_with("/callback?")) {
        respond(&stream, "404 Not Found", "Not found.");
        return Ok(None);
    }
    let host = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.trim().to_ascii_lowercase())
        .unwrap_or_default();
    if host != format!("localhost:{port}") && host != format!("127.0.0.1:{port}") {
        respond(&stream, "400 Bad Request", "Unexpected Host header.");
        return Ok(None);
    }
    let url = reqwest::Url::parse(&format!("http://localhost{target}"))
        .context("malformed callback URL")?;
    let q = |k: &str| {
        url.query_pairs()
            .find(|(n, _)| n == k)
            .map(|(_, v)| Zeroizing::new(v.into_owned()))
    };
    if q("error").is_some() {
        respond(
            &stream,
            "200 OK",
            "Login was cancelled. You can close this tab.",
        );
        bail!("OpenRouter login was cancelled or denied; nothing was stored");
    }
    let state_ok = q("state").is_some_and(|s| ct_eq(s.as_bytes(), expected_state.as_bytes()));
    if !state_ok {
        respond(
            &stream,
            "400 Bad Request",
            "This login link does not match the one middleman opened. Nothing was stored.",
        );
        bail!("callback `state` did not match (possible CSRF); nothing was stored");
    }
    let Some(code) = q("code").filter(|c| !c.is_empty()) else {
        respond(&stream, "400 Bad Request", "No authorization code.");
        bail!("callback had no `code`; nothing was stored");
    };
    respond(
        &stream,
        "200 OK",
        "Logged in. You can close this tab and go back to the terminal.",
    );
    Ok(Some(code))
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Exchange the code for a key (`exchange_url` is a parameter for tests). The error never
/// includes the response body.
pub async fn exchange(exchange_url: &str, code: &str, verifier: &str) -> Result<Secret> {
    let body = serde_json::json!({
        "code": code,
        "code_verifier": verifier,
        "code_challenge_method": "S256",
    });
    let (status, v) = crate::http::post_json(exchange_url, &body).await?;
    if !(200..300).contains(&status) {
        let hint = match status {
            400 => ": invalid code_challenge_method",
            403 => ": invalid or expired code (codes expire after 10 minutes); run the login again",
            _ => "",
        };
        bail!("OpenRouter refused the code exchange (HTTP {status}){hint}");
    }
    let key = v
        .as_ref()
        .and_then(|v| v.get("key"))
        .and_then(|k| k.as_str())
        .map(|k| Zeroizing::new(k.trim().to_string()))
        .filter(|k| !k.is_empty())
        .context("OpenRouter reply had no `key`")?;
    Ok(Secret::new(key.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s256_matches_rfc7636_vector() {
        // RFC 7636 appendix B
        assert_eq!(
            challenge_s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        let p = pkce().unwrap();
        assert_eq!(p.verifier.len(), 43);
        assert_eq!(p.challenge, challenge_s256(&p.verifier));
        assert_ne!(pkce().unwrap().verifier, p.verifier);
    }

    #[test]
    fn auth_url_has_documented_params() {
        let u = auth_url(
            Some("http://localhost:5555/callback"),
            "CH",
            Some("ST"),
            "middleman",
        );
        let u = reqwest::Url::parse(&u).unwrap();
        assert_eq!(u.host_str(), Some("openrouter.ai"));
        assert_eq!(u.path(), "/auth");
        let q: std::collections::HashMap<_, _> = u.query_pairs().into_owned().collect();
        assert_eq!(q["callback_url"], "http://localhost:5555/callback");
        assert_eq!(q["code_challenge"], "CH");
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(q["state"], "ST");
        let headless = auth_url(None, "CH", None, "middleman");
        assert!(!headless.contains("callback_url"));
    }

    fn get(port: u16, path: &str, host: &str) -> String {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        write!(s, "GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n").unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out
    }

    #[test]
    fn listener_binds_loopback_and_checks_state() {
        let cb = Callback::bind().unwrap();
        assert!(cb.listener.local_addr().unwrap().ip().is_loopback());
        let port = cb.port;
        let h = std::thread::spawn(move || cb.wait("good-state", Duration::from_secs(10)));
        let host = format!("localhost:{port}");
        assert!(get(port, "/favicon.ico", &host).starts_with("HTTP/1.1 404"));
        assert!(get(port, "/callback?code=c&state=x", "evil.example").starts_with("HTTP/1.1 400"));
        let r = get(port, "/callback?code=the-code&state=good-state", &host);
        assert!(r.starts_with("HTTP/1.1 200"), "{r}");
        assert_eq!(h.join().unwrap().unwrap().as_str(), "the-code");
        // single request: the listener is gone
        assert!(TcpStream::connect(("127.0.0.1", port)).is_err());
    }

    #[test]
    fn wrong_state_aborts() {
        let cb = Callback::bind().unwrap();
        let port = cb.port;
        let h = std::thread::spawn(move || cb.wait("good", Duration::from_secs(10)));
        let r = get(
            port,
            "/callback?code=c&state=bad",
            &format!("127.0.0.1:{port}"),
        );
        assert!(r.starts_with("HTTP/1.1 400"));
        let e = h.join().unwrap().unwrap_err().to_string();
        assert!(e.contains("state"), "{e}");
    }

    #[test]
    fn times_out() {
        let cb = Callback::bind().unwrap();
        let e = cb
            .wait("s", Duration::from_millis(200))
            .unwrap_err()
            .to_string();
        assert!(e.contains("timed out"));
    }

    #[tokio::test]
    async fn exchange_posts_code_and_verifier() {
        use wiremock::matchers::{body_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/keys"))
            .and(body_json(serde_json::json!({
                "code": "abc", "code_verifier": "ver", "code_challenge_method": "S256"
            })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"key": "sk-or-new"})),
            )
            .mount(&server)
            .await;
        let url = format!("{}/api/v1/auth/keys", server.uri());
        let k = exchange(&url, "abc", "ver").await.unwrap();
        assert_eq!(k.expose(), "sk-or-new");
        let e = exchange(&url, "wrong", "ver")
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("HTTP 404"), "{e}");
    }
}
