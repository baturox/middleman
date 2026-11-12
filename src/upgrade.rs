//! `middleman upgrade`: find a newer release, download it, verify it, replace this binary.
//!
//! Every step fails closed:
//! - The release comes from `api.github.com/repos/baturox/middleman/releases/{latest|tags/<v>}`.
//!   Its tag must be a plain semver tag; nothing else in the JSON is trusted except the notes,
//!   which are shown cleaned of control characters. Asset URLs are built here from the tag and
//!   the compile-time target triple, never taken from the response.
//! - Downloads are HTTPS only. Redirects may only go https -> https to [`ALLOWED_HOSTS`]. Each
//!   body is capped ([`MAX_DOWNLOAD`] for the archive).
//! - The archive's SHA-256 must match its line in `SHA256SUMS.txt`; a missing line is an error.
//! - When `gh` is on PATH and logged in, `gh attestation verify <file> --repo
//!   baturox/middleman` runs (argv, no shell) and a failure is fatal. Without `gh` (or not
//!   logged in) the check is skipped quietly, unless `--require-attestation` /
//!   `MIDDLEMAN_REQUIRE_ATTESTATION=1` makes that fatal too.
//! - Only the `middleman` entry of the tarball is extracted; absolute paths, `..`, symlinks,
//!   hardlinks and special files anywhere in the archive reject it.
//! - The new binary must answer `--version` with the release's version before anything is
//!   replaced. It is staged next to the current one, the old one is kept as `middleman.prev`,
//!   and a rename puts the new one in place.
//!
//! Tests point everything at a local mock with `MIDDLEMAN_TEST_BASE_URL_GITHUB`; only an
//! exact-loopback plain-http URL is accepted, and then redirects must stay on that origin.

use std::cmp::Ordering;
use std::fmt;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::fsutil::{clean, pretty};

pub const REPO: &str = "baturox/middleman";
/// The target triple this binary was compiled for (set by `build.rs`).
pub const TARGET: &str = env!("MIDDLEMAN_TARGET");
/// The running version.
pub const CURRENT: &str = env!("CARGO_PKG_VERSION");
/// Cap on the release archive.
pub const MAX_DOWNLOAD: u64 = 50 << 20;
/// Cap on the API answer and `SHA256SUMS.txt`.
pub const MAX_META: u64 = 2 << 20;
/// Hosts a download may be redirected to.
pub const ALLOWED_HOSTS: [&str; 3] = [
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
];
/// Loopback-only override of both the API and the download base (tests).
pub const TEST_BASE_ENV: &str = "MIDDLEMAN_TEST_BASE_URL_GITHUB";
/// The background check runs at most this often (seconds).
pub const CHECK_EVERY_S: i64 = 86_400;
/// Exit code of `upgrade --check` when a newer release exists.
pub const EXIT_UPDATE_AVAILABLE: u8 = 10;
pub const CARGO_CMD: &str =
    "cargo install --git https://github.com/baturox/middleman --locked --force";
pub const INSTALL_SH_CMD: &str = "curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/baturox/middleman/main/install.sh | sh";

// ------------------------------------------------------------------ versions

/// A semver version (`v` prefix accepted, build metadata ignored).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub pre: Vec<String>,
}

impl Version {
    pub fn parse(s: &str) -> Option<Version> {
        let s = s.trim();
        let s = s.strip_prefix('v').unwrap_or(s);
        let s = s.split('+').next()?;
        let (core, pre) = match s.split_once('-') {
            Some((c, p)) => (c, Some(p)),
            None => (s, None),
        };
        let num = |x: &str| -> Option<u64> {
            let ok = !x.is_empty()
                && x.chars().all(|c| c.is_ascii_digit())
                && (x == "0" || !x.starts_with('0'));
            ok.then(|| x.parse().ok()).flatten()
        };
        let mut it = core.split('.');
        let (major, minor, patch) = (num(it.next()?)?, num(it.next()?)?, num(it.next()?)?);
        if it.next().is_some() {
            return None;
        }
        let pre = match pre {
            None => vec![],
            Some(p) => {
                let ids: Vec<String> = p.split('.').map(String::from).collect();
                let valid = ids.iter().all(|i| {
                    !i.is_empty() && i.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                });
                if !valid {
                    return None;
                }
                ids
            }
        };
        Some(Version {
            major,
            minor,
            patch,
            pre,
        })
    }

    pub fn current() -> Version {
        Version::parse(CURRENT).expect("CARGO_PKG_VERSION is semver")
    }

    pub fn tag(&self) -> String {
        format!("v{self}")
    }

    pub fn is_prerelease(&self) -> bool {
        !self.pre.is_empty()
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if !self.pre.is_empty() {
            write!(f, "-{}", self.pre.join("."))?;
        }
        Ok(())
    }
}

impl Ord for Version {
    fn cmp(&self, o: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(o.major, o.minor, o.patch))
            .then_with(|| match (self.pre.is_empty(), o.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                // a pre-release sorts before its release
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => {
                    for (a, b) in self.pre.iter().zip(&o.pre) {
                        let c = match (a.parse::<u64>(), b.parse::<u64>()) {
                            (Ok(x), Ok(y)) => x.cmp(&y),
                            (Ok(_), Err(_)) => Ordering::Less,
                            (Err(_), Ok(_)) => Ordering::Greater,
                            (Err(_), Err(_)) => a.cmp(b),
                        };
                        if c != Ordering::Equal {
                            return c;
                        }
                    }
                    self.pre.len().cmp(&o.pre.len())
                }
            })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}

/// A release tag is `v<semver>` made of `[A-Za-z0-9._-]` only (it ends up in URLs and paths).
pub fn valid_tag(tag: &str) -> bool {
    tag.len() <= 64
        && tag.starts_with('v')
        && tag
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
        && Version::parse(tag).is_some()
}

/// `0.3.1` or `v0.3.1` -> `v0.3.1`.
pub fn normalize_tag(v: &str) -> Result<String> {
    let t = if v.starts_with('v') {
        v.to_string()
    } else {
        format!("v{v}")
    };
    if !valid_tag(&t) {
        bail!("--version must look like v1.2.3 (got {:?})", clean(v, 40));
    }
    Ok(t)
}

// ------------------------------------------------------------------ assets

/// The release targets (see `.github/workflows/release.yml`).
pub const RELEASE_TARGETS: [&str; 5] = [
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-pc-windows-msvc",
];

/// `middleman-<tag>-<target>` (the archive's top directory too).
pub fn archive_stem(tag: &str, target: &str) -> String {
    format!("middleman-{tag}-{target}")
}

/// The asset for `target`, or None when no release build exists for it.
pub fn asset_name(tag: &str, target: &str) -> Option<String> {
    if !RELEASE_TARGETS.contains(&target) {
        return None;
    }
    let ext = if target.contains("windows") {
        "zip"
    } else {
        "tar.gz"
    };
    Some(format!("{}.{ext}", archive_stem(tag, target)))
}

// ------------------------------------------------------------------ endpoints and HTTP

#[derive(Debug, Clone)]
pub struct Endpoints {
    api: String,
    download: String,
    /// Set in test mode: the only origin requests and redirects may use.
    test_origin: Option<reqwest::Url>,
}

impl Endpoints {
    pub fn github() -> Endpoints {
        Endpoints {
            api: format!("https://api.github.com/repos/{REPO}"),
            download: format!("https://github.com/{REPO}/releases/download"),
            test_origin: None,
        }
    }

    /// Point at a local mock (exact-loopback plain http only).
    pub fn local(base: &str) -> Option<Endpoints> {
        if !crate::config::is_local_url(base) {
            return None;
        }
        let base = base.trim_end_matches('/');
        Some(Endpoints {
            api: format!("{base}/repos/{REPO}"),
            download: format!("{base}/{REPO}/releases/download"),
            test_origin: reqwest::Url::parse(base).ok(),
        })
    }

    /// GitHub, unless [`TEST_BASE_ENV`] names a loopback URL.
    pub fn from_env() -> Endpoints {
        std::env::var(TEST_BASE_ENV)
            .ok()
            .and_then(|b| Endpoints::local(&b))
            .unwrap_or_else(Endpoints::github)
    }

    pub fn release_url(&self, tag: Option<&str>) -> String {
        match tag {
            Some(t) => format!("{}/releases/tags/{t}", self.api),
            None => format!("{}/releases/latest", self.api),
        }
    }

    pub fn asset_url(&self, tag: &str, name: &str) -> String {
        format!("{}/{tag}/{name}", self.download)
    }

    /// Release page for people (built here, not taken from the API answer).
    pub fn notes_url(tag: &str) -> String {
        format!("https://github.com/{REPO}/releases/tag/{tag}")
    }

    fn url_allowed(&self, u: &reqwest::Url) -> bool {
        match &self.test_origin {
            Some(o) => same_origin(o, u),
            None => u.scheme() == "https" && u.username().is_empty() && u.password().is_none(),
        }
    }

    fn client(&self) -> Result<reqwest::Client> {
        let test = self.test_origin.clone();
        let policy = reqwest::redirect::Policy::custom(move |a| {
            if a.previous().len() >= 10 {
                return a.error("too many redirects");
            }
            let prev = a.previous().last().cloned();
            let ok = match &prev {
                Some(p) => redirect_allowed(p, a.url(), test.as_ref()),
                None => false,
            };
            if ok {
                a.follow()
            } else {
                let host = a.url().host_str().unwrap_or("?").to_string();
                a.error(format!(
                    "refusing a redirect to {} (allowed: https to {})",
                    clean(&host, 80),
                    ALLOWED_HOSTS.join(", ")
                ))
            }
        });
        Ok(reqwest::Client::builder()
            .redirect(policy)
            .https_only(self.test_origin.is_none())
            // GitHub requires a User-Agent; this one carries no version or identifier
            .user_agent("middleman-upgrade")
            .timeout(Duration::from_secs(120))
            .connect_timeout(Duration::from_secs(15))
            .build()?)
    }
}

fn same_origin(a: &reqwest::Url, b: &reqwest::Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
        && b.username().is_empty()
        && b.password().is_none()
}

/// May a request to `prev` be redirected to `next`? https -> https to [`ALLOWED_HOSTS`] on the
/// default port, no credentials in the URL; in test mode only the mock's own origin.
pub fn redirect_allowed(
    prev: &reqwest::Url,
    next: &reqwest::Url,
    test_origin: Option<&reqwest::Url>,
) -> bool {
    if let Some(o) = test_origin {
        return same_origin(o, prev) && same_origin(o, next);
    }
    prev.scheme() == "https"
        && next.scheme() == "https"
        && next.port().is_none()
        && next.username().is_empty()
        && next.password().is_none()
        && next
            .host_str()
            .is_some_and(|h| ALLOWED_HOSTS.iter().any(|a| h.eq_ignore_ascii_case(a)))
}

fn transport(e: reqwest::Error) -> anyhow::Error {
    let e = e.without_url();
    let mut chain = e.to_string();
    let mut src = std::error::Error::source(&e);
    while let Some(s) = src {
        chain.push_str(": ");
        chain.push_str(&s.to_string());
        src = s.source();
    }
    anyhow::anyhow!("{}", clean(&chain, 300))
}

/// GET `url` and return (status, body). Bodies over `max` bytes are refused.
async fn get_capped(ep: &Endpoints, url: &str, max: u64, accept: &str) -> Result<(u16, Vec<u8>)> {
    let u = reqwest::Url::parse(url).with_context(|| format!("invalid URL {url}"))?;
    if !ep.url_allowed(&u) {
        bail!("refusing to download from {url}");
    }
    let mut resp = ep
        .client()?
        .get(u)
        .header("accept", accept)
        .send()
        .await
        .map_err(transport)?;
    let status = resp.status().as_u16();
    let too_big = || anyhow::anyhow!("download larger than the {} MB cap; refusing it", max >> 20);
    if resp.content_length().is_some_and(|n| n > max) {
        return Err(too_big());
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(transport)? {
        if body.len() as u64 + chunk.len() as u64 > max {
            return Err(too_big());
        }
        body.extend_from_slice(&chunk);
    }
    Ok((status, body))
}

/// Download a release file (HTTP 200 required).
pub async fn download(ep: &Endpoints, url: &str, max: u64) -> Result<Vec<u8>> {
    let (status, body) = get_capped(ep, url, max, "application/octet-stream").await?;
    if status != 200 {
        let name = url.rsplit('/').next().unwrap_or(url);
        bail!("downloading {} failed: HTTP {status}", clean(name, 120));
    }
    Ok(body)
}

// ------------------------------------------------------------------ the release

#[derive(Debug, Deserialize)]
struct ApiRelease {
    tag_name: String,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    draft: bool,
}

#[derive(Debug, Clone)]
pub struct Release {
    pub tag: String,
    pub version: Version,
    /// The release body, untrusted (clean before printing: see [`notes_summary`]).
    pub body: String,
}

/// The first `max_lines` non-empty lines of the release notes, cleaned for the terminal.
pub fn notes_summary(body: &str, max_lines: usize) -> Vec<String> {
    body.lines()
        .map(|l| clean(l, 160))
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .take(max_lines)
        .collect()
}

/// The latest release, or the one tagged `tag`.
pub async fn fetch_release(ep: &Endpoints, tag: Option<&str>) -> Result<Release> {
    let (status, body) = get_capped(
        ep,
        &ep.release_url(tag),
        MAX_META,
        "application/vnd.github+json",
    )
    .await
    .context("cannot reach api.github.com")?;
    match status {
        200 => {}
        404 => match tag {
            Some(t) => bail!("there is no release {t}"),
            None => bail!("{REPO} has no published release yet"),
        },
        403 | 429 => bail!("GitHub API rate limit hit (HTTP {status}); try again in an hour"),
        s => bail!("GitHub API answered HTTP {s}"),
    }
    let r: ApiRelease =
        serde_json::from_slice(&body).context("the GitHub API answer is not a release")?;
    if r.draft {
        bail!("the release is a draft");
    }
    if !valid_tag(&r.tag_name) {
        bail!("refusing odd release tag {:?}", clean(&r.tag_name, 40));
    }
    if let Some(t) = tag {
        if r.tag_name != t {
            bail!("asked for {t} but GitHub answered {}", r.tag_name);
        }
    }
    let version = Version::parse(&r.tag_name).expect("valid_tag checked it");
    Ok(Release {
        tag: r.tag_name,
        version,
        body: r.body.unwrap_or_default(),
    })
}

// ------------------------------------------------------------------ checksum

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The checksum listed for `name` in a `sha256sum`-format file.
pub fn expected_sha(sums: &str, name: &str) -> Result<String> {
    let mut found: Option<String> = None;
    for line in sums.lines() {
        let mut it = line.split_whitespace();
        let (Some(hash), Some(file)) = (it.next(), it.next()) else {
            continue;
        };
        if file.trim_start_matches('*') != name {
            continue;
        }
        let hash = hash.to_ascii_lowercase();
        if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!("SHA256SUMS.txt has a malformed entry for {name}; refusing to install");
        }
        if found.as_ref().is_some_and(|f| *f != hash) {
            bail!(
                "SHA256SUMS.txt lists {name} twice with different checksums; refusing to install"
            );
        }
        found = Some(hash);
    }
    found.with_context(|| format!("SHA256SUMS.txt has no entry for {name}; refusing to install"))
}

/// Fail unless `bytes` hash to the checksum listed for `name`.
pub fn verify_sha(bytes: &[u8], sums: &str, name: &str) -> Result<String> {
    let want = expected_sha(sums, name)?;
    let got = sha256_hex(bytes);
    if got != want {
        bail!("checksum mismatch for {name} (expected {want}, got {got}); refusing to install");
    }
    Ok(got)
}

// ------------------------------------------------------------------ attestation

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attestation {
    Verified,
    /// `gh` ran and did not verify the file: always fatal.
    Failed(String),
    /// `gh` is not on PATH.
    Unavailable,
    /// `gh` is installed but not logged in (`gh auth status` fails), so it cannot check.
    NotLoggedIn,
    /// `gh` could not run the check at all (too old for the current Sigstore trusted root,
    /// verifier service unreachable, timed out). Not evidence against the file.
    ToolError(String),
}

/// Does this `gh attestation verify` error mean the tool could not check (rather than that the
/// file failed the check)? E.g. gh 2.55 cannot parse Sigstore's Ed25519 trusted root.
pub fn is_tool_error(stderr: &str) -> bool {
    let e = stderr.to_ascii_lowercase();
    [
        "failed to get trusted root",
        "unsupported tlog public key",
        "failed to create public good sigstore verifier",
        "failed to create sigstore verifier",
        "unknown command \"attestation\"",
        "tls handshake",
        "connection refused",
        "no such host",
        "i/o timeout",
    ]
    .iter()
    .any(|k| e.contains(k))
}

/// `name` on PATH (no shell, no `which`).
pub fn find_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let exts: &[&str] = if cfg!(windows) {
        &[".exe", ".cmd", ""]
    } else {
        &[""]
    };
    std::env::split_paths(&path)
        .filter(|d| d.is_absolute())
        .flat_map(|d| exts.iter().map(move |e| d.join(format!("{name}{e}"))))
        .find(|p| p.is_file())
}

/// Run `cmd` with no stdin, waiting at most `limit`; the output, or None when it could not run
/// or timed out.
fn run_capped(mut cmd: std::process::Command, limit: Duration) -> Option<std::process::Output> {
    use std::process::Stdio;
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let (mut so, mut se) = (child.stdout.take()?, child.stderr.take()?);
    let t_out = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = (&mut so).take(1 << 20).read_to_end(&mut b);
        b
    });
    let t_err = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = (&mut se).take(1 << 20).read_to_end(&mut b);
        b
    });
    let start = std::time::Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if start.elapsed() > limit => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => return None,
        }
    };
    Some(std::process::Output {
        status,
        stdout: t_out.join().unwrap_or_default(),
        stderr: t_err.join().unwrap_or_default(),
    })
}

/// Is `gh` logged in? (`gh auth status`, output discarded.)
pub fn gh_logged_in(gh: &Path) -> bool {
    let mut c = std::process::Command::new(gh);
    c.args(["auth", "status"]);
    run_capped(c, Duration::from_secs(20)).is_some_and(|o| o.status.success())
}

/// `gh attestation verify <file> --repo baturox/middleman`, argv passed directly, when `gh` is
/// installed and logged in.
pub fn verify_attestation(gh: Option<&Path>, file: &Path) -> Attestation {
    let Some(gh) = gh else {
        return Attestation::Unavailable;
    };
    if !gh_logged_in(gh) {
        return Attestation::NotLoggedIn;
    }
    let mut c = std::process::Command::new(gh);
    c.arg("attestation")
        .arg("verify")
        .arg(file)
        .arg("--repo")
        .arg(REPO);
    match run_capped(c, Duration::from_secs(120)) {
        Some(o) if o.status.success() => Attestation::Verified,
        Some(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            let first = err.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
            if is_tool_error(&err) {
                Attestation::ToolError(clean(first, 200))
            } else {
                Attestation::Failed(clean(first, 200))
            }
        }
        None => Attestation::ToolError("gh attestation verify did not finish".into()),
    }
}

/// Apply the policy. Ok(detail) to go on (the detail is for `--verbose`), Err when fatal:
/// a failed verification always is; a check that could not run only with `require`.
pub fn attestation_policy(a: &Attestation, require: bool) -> Result<String> {
    match (a, require) {
        (Attestation::Verified, _) => Ok(format!(
            "provenance verified: built by {REPO}'s release workflow"
        )),
        (Attestation::Failed(e), _) => bail!(
            "attestation verification failed ({e}); refusing to install. The file matches its \
             checksum but GitHub could not confirm it was built by {REPO}'s release workflow."
        ),
        (Attestation::Unavailable, true) => bail!(
            "cannot verify the build attestation: the GitHub CLI (gh) is not installed; refusing to install (attestation required)"
        ),
        (Attestation::NotLoggedIn, true) => bail!(
            "cannot verify the build attestation: gh is not logged in (run `gh auth login`); refusing to install (attestation required)"
        ),
        (Attestation::Unavailable, false) => Ok(
            "build provenance not checked (the GitHub CLI is not installed); the checksum matched".into(),
        ),
        (Attestation::NotLoggedIn, false) => Ok(
            "build provenance not checked (gh is not logged in); the checksum matched".into(),
        ),
        (Attestation::ToolError(e), true) => bail!(
            "cannot verify the build attestation: gh could not run the check ({e}). Update the GitHub CLI (`brew upgrade gh`); refusing to install (attestation required)"
        ),
        (Attestation::ToolError(_), false) => Ok(
            "build provenance not checked (your GitHub CLI is too old to check it: run `brew upgrade gh`); the checksum matched".into(),
        ),
    }
}

#[cfg(test)]
mod attestation_tool_error_tests {
    use super::*;

    /// Regression: gh 2.55 cannot read Sigstore's Ed25519 trusted root; that blocked upgrades.
    #[test]
    fn outdated_gh_is_a_tool_error_not_a_failed_verification() {
        let e = "Error: failed to find recognized issuer from bundle content: failed to create Public Good Sigstore verifier: failed to get trusted root: unsupported tlog public key type: PKIX_ED25519";
        assert!(is_tool_error(e));
        let a = Attestation::ToolError(e.into());
        assert!(attestation_policy(&a, false)
            .unwrap()
            .contains("brew upgrade gh"));
        assert!(attestation_policy(&a, true).is_err());
        // a real mismatch stays fatal
        assert!(!is_tool_error(
            "Error: verifying with issuer \"sigstore.dev\": no matching attestations"
        ));
        assert!(attestation_policy(
            &Attestation::Failed("no matching attestations".into()),
            false
        )
        .is_err());
    }
}

// ------------------------------------------------------------------ automatic updates

/// What the background check may do with a newer release in `[update] mode = "auto"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutoDecision {
    /// A patch release of the same line: install it.
    Install,
    /// Newer, but a new major (or, for 0.x, a new minor) or a pre-release: only tell.
    Manual,
    /// Nothing newer.
    Current,
}

/// Auto-update only within the same compatibility line: same major, and for 0.x the same
/// minor too (0.3.0 -> 0.3.1 yes, 0.3.1 -> 0.4.0 no). Pre-releases never.
pub fn auto_decision(cur: &Version, latest: &Version) -> AutoDecision {
    if latest <= cur {
        return AutoDecision::Current;
    }
    let same_line = latest.major == cur.major && (cur.major > 0 || latest.minor == cur.minor);
    if same_line && !latest.is_prerelease() {
        AutoDecision::Install
    } else {
        AutoDecision::Manual
    }
}

/// `<state>/update.log`: one line per automatic update attempt (0600).
pub fn update_log_path(state: &Path) -> PathBuf {
    state.join("update.log")
}

/// Append `line` (time-stamped, cleaned) to the update log, keeping the file private.
pub fn log_update(state: &Path, line: &str) -> Result<()> {
    use std::io::Write;
    crate::ledger::ensure_private_dir(state)?;
    let p = update_log_path(state);
    let mut o = std::fs::OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o
        .open(&p)
        .with_context(|| format!("cannot write {}", pretty(&p)))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    }
    writeln!(f, "{} {}", crate::ledger::now_rfc3339(), clean(line, 400))?;
    Ok(())
}

/// How long the status line shows "updated to vX" after it first showed it (seconds).
pub const UPDATED_NOTICE_S: i64 = 900;

/// The "updated to vX" notice, if an automatic update installed the running version and the
/// notice has not run its course yet.
pub fn updated_notice(cache: Option<&UpdateCache>, now: i64, cur: &Version) -> Option<String> {
    let c = cache?;
    let v = Version::parse(c.updated_to.as_deref()?)?;
    if &v != cur {
        return None;
    }
    match c.notice_since {
        Some(t) if now - t >= UPDATED_NOTICE_S || t > now => None,
        _ => Some(v.tag()),
    }
}

// ------------------------------------------------------------------ code signature (macOS)

/// The designated requirement of the binary at `path` (`codesign -d -r-`), macOS only.
pub fn designated_requirement(path: &Path) -> Option<String> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let mut c = std::process::Command::new("/usr/bin/codesign");
    c.args(["-d", "-r-"]).arg(path);
    let o = run_capped(c, Duration::from_secs(15))?;
    if !o.status.success() {
        return None;
    }
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    text.lines()
        .find_map(|l| l.trim().strip_prefix("designated => "))
        .map(|s| s.trim().to_string())
}

/// Will the Keychain ask before the new binary may read a key the old one stored?
///
/// Two gates guard a file-keychain item: its ACL (trusted applications, matched by designated
/// requirement) and, since macOS 10.12, its partition list. securityd gives code that is not
/// signed by Apple, the App Store or a Developer ID certificate the partition `cdhash:<hash>`,
/// which changes with every build. So only two builds with the same Developer-ID-anchored
/// requirement pass both gates silently; anything else (ad-hoc, or a self-signed certificate)
/// is asked about once per new build.
pub fn keychain_prompt_expected(old_dr: Option<&str>, new_dr: Option<&str>) -> bool {
    match (old_dr, new_dr) {
        (Some(a), Some(b)) => a != b || !b.contains("anchor apple generic"),
        _ => true,
    }
}

// ------------------------------------------------------------------ archive

/// The `middleman` binary from a release tarball: exactly `<stem>/middleman`, a regular
/// file of at most `max` bytes. Absolute paths, `..`, links and special entries anywhere in
/// the archive reject it.
pub fn extract_binary(archive: &[u8], stem: &str, max: u64) -> Result<Vec<u8>> {
    let gz = flate2::read::GzDecoder::new(archive);
    // bound the decompressed stream (a gzip bomb ends as a truncated tar, an error)
    let mut ar = tar::Archive::new(gz.take(max.saturating_mul(4)));
    let mut found: Option<Vec<u8>> = None;
    for entry in ar.entries().context("not a tar.gz archive")? {
        let entry = entry.context("corrupt archive")?;
        let raw = entry.path().context("corrupt archive path")?.into_owned();
        let shown = clean(&raw.display().to_string(), 120);
        let mut parts = vec![];
        for c in raw.components() {
            match c {
                Component::Normal(p) => parts.push(p.to_string_lossy().into_owned()),
                Component::CurDir => {}
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    bail!("unsafe path in the archive: {shown}; refusing to install")
                }
            }
        }
        use tar::EntryType as E;
        match entry.header().entry_type() {
            E::Directory => continue,
            E::Symlink | E::Link => {
                bail!("the archive contains a link ({shown}); refusing to install")
            }
            E::Regular | E::Continuous => {}
            other => bail!(
                "unexpected entry type {other:?} in the archive ({shown}); refusing to install"
            ),
        }
        if parts.len() != 2 || parts[0] != stem || parts[1] != "middleman" {
            continue;
        }
        if found.is_some() {
            bail!("the archive contains {stem}/middleman twice; refusing to install");
        }
        if entry.header().size().unwrap_or(u64::MAX) > max {
            bail!("the binary in the archive is larger than {} MB", max >> 20);
        }
        let mut buf = Vec::new();
        entry
            .take(max + 1)
            .read_to_end(&mut buf)
            .context("corrupt archive")?;
        if buf.len() as u64 > max {
            bail!("the binary in the archive is larger than {} MB", max >> 20);
        }
        found = Some(buf);
    }
    found.with_context(|| format!("the archive has no {stem}/middleman"))
}

// ------------------------------------------------------------------ the new binary

/// Run `<path> --version` (15 s at most) and parse `middleman X.Y.Z`.
pub fn binary_version(path: &Path) -> Result<Version> {
    use std::process::{Command, Stdio};
    let mut child = Command::new(path)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("cannot run {}", pretty(path)))?;
    let start = std::time::Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if start.elapsed() > Duration::from_secs(15) {
            let _ = child.kill();
            let _ = child.wait();
            bail!("{} --version did not answer", pretty(path));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut out = String::new();
    if let Some(s) = child.stdout.take() {
        let _ = s.take(4096).read_to_string(&mut out);
    }
    let line = out.lines().next().unwrap_or("");
    let mut it = line.split_whitespace();
    match (it.next(), it.next().and_then(Version::parse)) {
        (Some("middleman"), Some(v)) => Ok(v),
        _ => bail!(
            "{} --version printed {:?}, not a middleman version",
            pretty(path),
            clean(line, 60)
        ),
    }
}

/// Fail unless the binary at `path` runs and reports `want`.
pub fn check_binary(path: &Path, want: &Version) -> Result<()> {
    let got = binary_version(path).context("the downloaded binary does not run here")?;
    if &got != want {
        bail!("the downloaded binary reports version {got}, expected {want}; refusing to install");
    }
    Ok(())
}

// ------------------------------------------------------------------ install location

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Managed {
    Cargo,
    Homebrew,
}

impl Managed {
    pub fn advice(self) -> String {
        match self {
            Managed::Cargo => format!(
                "this middleman was installed with cargo; upgrade it with:\n    {CARGO_CMD}\n  then run `middleman setup claude --refresh`"
            ),
            Managed::Homebrew => "this middleman is managed by Homebrew; upgrade it with:\n    brew upgrade middleman\n  then run `middleman setup claude --refresh`".into(),
        }
    }
}

/// Is `exe` (symlinks resolved) owned by a package manager that should upgrade it instead?
pub fn managed_by(exe: &Path, home: &Path, cargo_home: Option<&Path>) -> Option<Managed> {
    let cargo_bins = [
        cargo_home.map(|c| c.join("bin")),
        Some(home.join(".cargo").join("bin")),
    ];
    if cargo_bins
        .iter()
        .flatten()
        .any(|b| exe.parent() == Some(b.as_path()))
    {
        return Some(Managed::Cargo);
    }
    let brew = exe.components().any(|c| c.as_os_str() == "Cellar")
        || exe.starts_with("/opt/homebrew")
        || exe.starts_with("/home/linuxbrew/.linuxbrew");
    brew.then_some(Managed::Homebrew)
}

fn random_suffix() -> String {
    let mut b = [0u8; 6];
    let _ = getrandom::fill(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Can we create files next to `exe`?
pub fn dir_writable(dir: &Path) -> bool {
    let probe = dir.join(format!(".middleman-probe-{}", random_suffix()));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// The running binary with symlinks resolved.
pub fn current_exe() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("cannot find the running middleman binary")?;
    Ok(std::fs::canonicalize(&exe).unwrap_or(exe))
}

/// Where the previous binary is kept: `middleman.prev` next to it.
pub fn prev_path(exe: &Path) -> PathBuf {
    let name = exe
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "middleman".into());
    exe.with_file_name(format!("{name}.prev"))
}

/// A new binary written next to the current one; removed on drop unless installed.
pub struct Staged {
    pub path: PathBuf,
}

impl Drop for Staged {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn mode_of(path: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .ok()
            .map(|m| m.permissions().mode() & 0o7777)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// Write `bytes` to a temp file in `exe`'s directory with `exe`'s mode (0755 if unknown).
pub fn stage(exe: &Path, bytes: &[u8]) -> Result<Staged> {
    use std::io::Write;
    let dir = exe.parent().context("the binary has no parent directory")?;
    let path = dir.join(format!(".middleman.new-{}", random_suffix()));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o700);
    }
    let mut f = opts
        .open(&path)
        .with_context(|| format!("cannot write in {}", pretty(dir)))?;
    let staged = Staged { path };
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = mode_of(exe).unwrap_or(0o755);
        std::fs::set_permissions(&staged.path, std::fs::Permissions::from_mode(mode))?;
    }
    Ok(staged)
}

/// Copy `from` to `to` through a temp file and a rename (so `to` is never half written).
fn copy_atomic(from: &Path, to: &Path) -> Result<()> {
    let tmp = to.with_file_name(format!(".middleman.copy-{}", random_suffix()));
    let res = (|| -> Result<()> {
        std::fs::copy(from, &tmp)
            .with_context(|| format!("cannot copy {} to {}", pretty(from), pretty(&tmp)))?;
        std::fs::rename(&tmp, to).with_context(|| format!("cannot write {}", pretty(to)))?;
        Ok(())
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

/// Put `staged` at `exe`, keeping the old binary as `middleman.prev`. Returns the prev path.
pub fn install(exe: &Path, staged: Staged) -> Result<PathBuf> {
    let prev = prev_path(exe);
    #[cfg(not(windows))]
    {
        copy_atomic(exe, &prev)?;
        std::fs::rename(&staged.path, exe)
            .with_context(|| format!("cannot replace {}", pretty(exe)))?;
    }
    #[cfg(windows)]
    {
        // a running exe cannot be overwritten, but it can be renamed
        let old = exe.with_extension("old");
        let _ = std::fs::remove_file(&old);
        std::fs::rename(exe, &old).with_context(|| format!("cannot move {}", pretty(exe)))?;
        if let Err(e) = std::fs::rename(&staged.path, exe) {
            let _ = std::fs::rename(&old, exe);
            return Err(e).with_context(|| format!("cannot replace {}", pretty(exe)));
        }
        copy_atomic(&old, &prev)?;
    }
    std::mem::forget(staged);
    Ok(prev)
}

/// Swap `middleman.prev` back in; the replaced binary becomes the new `.prev` (so a second
/// rollback undoes the first). Returns the restored version.
pub fn rollback(exe: &Path) -> Result<Version> {
    let prev = prev_path(exe);
    if !std::fs::symlink_metadata(&prev).is_ok_and(|m| m.is_file()) {
        bail!("nothing to roll back to: {} does not exist", pretty(&prev));
    }
    let v = binary_version(&prev).context("the previous binary does not run; not restoring it")?;
    let keep = exe.with_file_name(format!(".middleman.rollback-{}", random_suffix()));
    #[cfg(not(windows))]
    {
        std::fs::copy(exe, &keep).with_context(|| format!("cannot copy {}", pretty(exe)))?;
        if let Err(e) = std::fs::rename(&prev, exe) {
            let _ = std::fs::remove_file(&keep);
            return Err(e).with_context(|| format!("cannot replace {}", pretty(exe)));
        }
    }
    #[cfg(windows)]
    {
        let old = exe.with_extension("old");
        let _ = std::fs::remove_file(&old);
        std::fs::rename(exe, &old).with_context(|| format!("cannot move {}", pretty(exe)))?;
        if let Err(e) = std::fs::rename(&prev, exe) {
            let _ = std::fs::rename(&old, exe);
            return Err(e).with_context(|| format!("cannot replace {}", pretty(exe)));
        }
        std::fs::copy(&old, &keep).with_context(|| format!("cannot copy {}", pretty(&old)))?;
    }
    std::fs::rename(&keep, &prev).with_context(|| format!("cannot write {}", pretty(&prev)))?;
    Ok(v)
}

// ------------------------------------------------------------------ private temp dir

/// A 0700 directory under the system temp dir, removed on drop.
pub struct TempDir {
    pub path: PathBuf,
}

impl TempDir {
    pub fn new() -> Result<TempDir> {
        let path = std::env::temp_dir().join(format!("middleman-upgrade-{}", random_suffix()));
        std::fs::create_dir(&path).with_context(|| format!("cannot create {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(TempDir { path })
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

// ------------------------------------------------------------------ daily check cache

/// `<state>/update-check.json`, written by `upgrade --check --write-cache`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct UpdateCache {
    pub checked_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Set by an automatic update: the version it installed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_to: Option<String>,
    /// When the status line first showed the "updated" notice.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notice_since: Option<i64>,
}

pub fn cache_path(state: &Path) -> PathBuf {
    state.join("update-check.json")
}

pub fn lock_path(state: &Path) -> PathBuf {
    state.join("update-check.lock")
}

pub fn load_cache(state: &Path) -> Option<UpdateCache> {
    serde_json::from_slice(&std::fs::read(cache_path(state)).ok()?).ok()
}

pub fn save_cache(state: &Path, c: &UpdateCache) -> Result<()> {
    crate::ledger::ensure_private_dir(state)?;
    crate::fsutil::write_atomic(&cache_path(state), &serde_json::to_vec(c)?, Some(0o600))
}

pub fn release_lock(state: &Path) {
    let _ = std::fs::remove_file(lock_path(state));
}

/// Background checks are on unless `[update] mode = "off"` (or `check = false`) or
/// `MIDDLEMAN_NO_UPDATE_CHECK=1`.
pub fn checks_enabled(cfg_check: bool, get: &dyn Fn(&str) -> Option<String>) -> bool {
    cfg_check && get("MIDDLEMAN_NO_UPDATE_CHECK").is_none_or(|v| v.trim() != "1")
}

/// The cached latest version when it is newer than `current`.
pub fn newer_cached(cache: Option<&UpdateCache>, current: &Version) -> Option<Version> {
    cache?
        .latest_version
        .as_deref()
        .and_then(Version::parse)
        .filter(|v| v > current)
}

/// If the last check is a day old (or missing), start `spawn` once, holding the lock until the
/// check finishes. Returns true when a check was started.
pub fn maybe_check(
    state: &Path,
    cache: Option<&UpdateCache>,
    now: i64,
    spawn: &mut dyn FnMut() -> std::io::Result<()>,
) -> bool {
    let fresh = cache.is_some_and(|c| (0..CHECK_EVERY_S).contains(&(now - c.checked_at)));
    if fresh || crate::ledger::ensure_private_dir(state).is_err() {
        return false;
    }
    let Some(lock) = crate::limits::try_lock_at(&lock_path(state)) else {
        return false;
    };
    match spawn() {
        Ok(()) => {
            lock.keep();
            true
        }
        Err(_) => false,
    }
}

/// The real spawner: `<exe> upgrade --check --quiet --write-cache [--auto] --config <cfg>`,
/// detached. With `auto` the check also installs a patch release (`[update] mode = "auto"`).
pub fn spawn_check(cfg_path: &Path, auto: bool) -> std::io::Result<()> {
    let mut args = vec!["upgrade", "--check", "--quiet", "--write-cache"];
    if auto {
        args.push("--auto");
    }
    crate::limits::spawn_detached(&args, cfg_path)
}

/// Doctor's line about updates (reads the cache only).
pub fn doctor_check(state: &Path, enabled: bool, now: i64) -> crate::setup::Check {
    use crate::setup::Check;
    let cur = Version::current();
    if !enabled {
        return Check::optional(
            "update check",
            true,
            "off ([update] mode = \"off\" or MIDDLEMAN_NO_UPDATE_CHECK=1); `middleman upgrade --check` checks now",
        );
    }
    let cache = load_cache(state);
    if let Some(v) = newer_cached(cache.as_ref(), &cur) {
        return Check::optional(
            "update",
            false,
            format!(
                "update available: v{cur} -> {} (run `middleman upgrade`)",
                v.tag()
            ),
        );
    }
    match cache {
        Some(c) if c.error.is_some() && c.latest_version.is_none() => Check::optional(
            "update",
            true,
            format!(
                "last check failed ({}); `middleman upgrade --check` retries",
                clean(c.error.as_deref().unwrap_or(""), 80)
            ),
        ),
        Some(c) => Check::optional(
            "update",
            true,
            format!(
                "v{cur} is current (latest release {}, checked {} ago)",
                c.latest_version
                    .as_deref()
                    .map(|v| clean(v, 20))
                    .unwrap_or_else(|| "?".into()),
                age((now - c.checked_at).max(0))
            ),
        ),
        None => Check::optional(
            "update",
            true,
            "not checked yet (a daily background check runs; `middleman upgrade --check` checks now)",
        ),
    }
}

fn age(s: i64) -> String {
    if s < 3600 {
        format!("{}m", s / 60)
    } else if s < 86_400 {
        format!("{}h", s / 3600)
    } else {
        format!("{}d", s / 86_400)
    }
}

#[cfg(test)]
mod tests;
