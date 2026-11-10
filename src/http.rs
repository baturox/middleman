//! A small hardened HTTP helper for onboarding calls (key validation, OAuth code exchange):
//! no redirects, HTTPS only except loopback, response bodies capped at 1 MB, and errors that
//! carry the status code only, never the response body.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::config::{Secret, DEFAULT_UA};

pub const MAX_BODY: usize = 1 << 20;

fn is_loopback(url: &reqwest::Url) -> bool {
    url.scheme() == "http" && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))
}

pub fn client_for(url: &str) -> Result<(reqwest::Client, reqwest::Url)> {
    let u = reqwest::Url::parse(url).with_context(|| format!("invalid URL {url}"))?;
    let loopback = is_loopback(&u);
    if u.scheme() != "https" && !loopback {
        bail!("refusing non-HTTPS URL {url}");
    }
    let c = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .https_only(!loopback)
        .user_agent(DEFAULT_UA)
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(15))
        .build()?;
    Ok((c, u))
}

fn bearer(k: &Secret) -> reqwest::header::HeaderValue {
    let v = zeroize::Zeroizing::new(format!("Bearer {}", k.expose()));
    let mut h = reqwest::header::HeaderValue::from_str(&v)
        .unwrap_or_else(|_| reqwest::header::HeaderValue::from_static(""));
    h.set_sensitive(true);
    h
}

/// Status and parsed JSON body (None if the body is not JSON). Bodies over 1 MB are refused.
async fn finish(resp: reqwest::Response) -> Result<(u16, Option<Value>)> {
    let status = resp.status().as_u16();
    if resp.content_length().is_some_and(|n| n as usize > MAX_BODY) {
        bail!("response too large (HTTP {status})");
    }
    let mut resp = resp;
    let mut body = zeroize::Zeroizing::new(Vec::new());
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| anyhow::anyhow!("connection error: {}", e.without_url()))?
    {
        if body.len() + chunk.len() > MAX_BODY {
            bail!("response too large (HTTP {status})");
        }
        body.extend_from_slice(&chunk);
    }
    Ok((status, serde_json::from_slice(&body).ok()))
}

pub async fn get_json(url: &str, key: Option<&Secret>) -> Result<(u16, Option<Value>)> {
    let (c, u) = client_for(url)?;
    let mut rb = c.get(u);
    if let Some(k) = key.filter(|k| !k.expose().is_empty()) {
        rb = rb.header("authorization", bearer(k));
    }
    let resp = rb
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("cannot reach {}: {}", host(url), e.without_url()))?;
    finish(resp).await
}

pub async fn post_json(url: &str, body: &Value) -> Result<(u16, Option<Value>)> {
    let (c, u) = client_for(url)?;
    let resp = c
        .post(u)
        .json(body)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("cannot reach {}: {}", host(url), e.without_url()))?;
    finish(resp).await
}

fn host(url: &str) -> String {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(String::from))
        .unwrap_or_else(|| "the provider".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn https_only_except_loopback() {
        assert!(client_for("http://example.com/x").is_err());
        assert!(client_for("https://example.com/x").is_ok());
        assert!(client_for("http://127.0.0.1:9/x").is_ok());
        assert!(client_for("http://localhost:9/x").is_ok());
    }

    #[tokio::test]
    async fn no_redirects_and_capped_body() {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(302).insert_header("location", "https://evil.example/"),
            )
            .mount(&s)
            .await;
        let (st, _) = get_json(&format!("{}/a", s.uri()), None).await.unwrap();
        assert_eq!(st, 302);
        let s2 = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("x".repeat(MAX_BODY + 10)))
            .mount(&s2)
            .await;
        let e = get_json(&format!("{}/a", s2.uri()), None)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("too large"));
    }
}
