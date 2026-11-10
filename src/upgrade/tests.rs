use super::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn v(s: &str) -> Version {
    Version::parse(s).unwrap_or_else(|| panic!("{s} should parse"))
}

#[test]
fn semver_parse_and_compare() {
    assert_eq!(v("v0.3.0"), v("0.3.0"));
    assert_eq!(v("1.2.3+build.5"), v("1.2.3"));
    assert_eq!(v("1.2.3-rc.1").to_string(), "1.2.3-rc.1");
    for bad in [
        "",
        "1.2",
        "1.2.3.4",
        "01.2.3",
        "1.2.x",
        "1.2.3-",
        "1.2.3-a..b",
        "vv1.2.3",
    ] {
        assert!(Version::parse(bad).is_none(), "{bad:?}");
    }
    assert!(v("0.3.0") > v("0.2.0"));
    assert!(v("0.10.0") > v("0.9.9"));
    assert!(v("1.0.0") > v("0.99.99"));
    assert!(v("0.2.1") > v("0.2.0"));
    // pre-releases sort before their release, and by semver precedence among themselves
    let order = [
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-alpha.beta",
        "1.0.0-beta",
        "1.0.0-beta.2",
        "1.0.0-beta.11",
        "1.0.0-rc.1",
        "1.0.0",
        "1.0.1-rc.1",
    ];
    for w in order.windows(2) {
        assert!(v(w[0]) < v(w[1]), "{} < {}", w[0], w[1]);
    }
    assert!(v("1.0.0-rc.1").is_prerelease());
    assert_eq!(Version::current().to_string(), CURRENT);
}

#[test]
fn tags_are_validated() {
    assert!(valid_tag("v0.3.1"));
    assert!(valid_tag("v1.0.0-rc.1"));
    for bad in [
        "0.3.1",
        "v0.3",
        "v0.3.1/../x",
        "v0.3.1 ",
        "v0.3.1;rm",
        "latest",
    ] {
        assert!(!valid_tag(bad), "{bad:?}");
    }
    assert_eq!(normalize_tag("0.3.1").unwrap(), "v0.3.1");
    assert_eq!(normalize_tag("v0.3.1").unwrap(), "v0.3.1");
    assert!(normalize_tag("../../x").is_err());
}

#[test]
fn asset_per_target() {
    assert_eq!(
        asset_name("v0.3.1", "aarch64-apple-darwin").as_deref(),
        Some("middleman-v0.3.1-aarch64-apple-darwin.tar.gz")
    );
    assert_eq!(
        asset_name("v0.3.1", "x86_64-apple-darwin").as_deref(),
        Some("middleman-v0.3.1-x86_64-apple-darwin.tar.gz")
    );
    assert_eq!(
        asset_name("v0.3.1", "x86_64-unknown-linux-gnu").as_deref(),
        Some("middleman-v0.3.1-x86_64-unknown-linux-gnu.tar.gz")
    );
    assert_eq!(
        asset_name("v0.3.1", "aarch64-unknown-linux-gnu").as_deref(),
        Some("middleman-v0.3.1-aarch64-unknown-linux-gnu.tar.gz")
    );
    assert_eq!(
        asset_name("v0.3.1", "x86_64-pc-windows-msvc").as_deref(),
        Some("middleman-v0.3.1-x86_64-pc-windows-msvc.zip")
    );
    assert_eq!(asset_name("v0.3.1", "x86_64-unknown-linux-musl"), None);
    assert_eq!(asset_name("v0.3.1", "riscv64gc-unknown-linux-gnu"), None);
    // this build knows its own target
    assert!(!TARGET.is_empty());
    assert!(RELEASE_TARGETS.contains(&TARGET), "{TARGET}");
}

#[test]
fn checksum_file_parsing() {
    let a = "a".repeat(64);
    let b = "B".repeat(64);
    let sums = format!("{a}  middleman-v1-x.tar.gz\n{b} *middleman-v1-y.tar.gz\n");
    assert_eq!(expected_sha(&sums, "middleman-v1-x.tar.gz").unwrap(), a);
    assert_eq!(
        expected_sha(&sums, "middleman-v1-y.tar.gz").unwrap(),
        b.to_lowercase()
    );
    let e = expected_sha(&sums, "middleman-v1-z.tar.gz").unwrap_err();
    assert!(e.to_string().contains("no entry"), "{e}");
    // a name that only ends with ours does not count
    let e = expected_sha(
        &format!("{a}  evil-middleman-v1-z.tar.gz\n"),
        "middleman-v1-z.tar.gz",
    );
    assert!(e.is_err());
    assert!(expected_sha("xyz  f\n", "f")
        .unwrap_err()
        .to_string()
        .contains("malformed"));
    let dup = format!("{a}  f\n{}  f\n", "c".repeat(64));
    assert!(expected_sha(&dup, "f")
        .unwrap_err()
        .to_string()
        .contains("twice"));

    let data = b"hello";
    let good = format!("{}  f.tar.gz\n", sha256_hex(data));
    assert!(verify_sha(data, &good, "f.tar.gz").is_ok());
    let e = verify_sha(b"tampered", &good, "f.tar.gz").unwrap_err();
    assert!(e.to_string().contains("checksum mismatch"), "{e}");
}

#[test]
fn attestation_policy_is_fail_closed_when_required() {
    assert_eq!(
        attestation_policy(&Attestation::Verified, true).unwrap(),
        None
    );
    assert!(attestation_policy(&Attestation::Failed("x".into()), true).is_err());
    assert!(attestation_policy(&Attestation::Unavailable, true).is_err());
    assert!(attestation_policy(&Attestation::Failed("x".into()), false)
        .unwrap()
        .unwrap()
        .contains("MIDDLEMAN_REQUIRE_ATTESTATION"));
    assert!(attestation_policy(&Attestation::Unavailable, false)
        .unwrap()
        .is_some());
    assert_eq!(
        verify_attestation(None, Path::new("/x")),
        Attestation::Unavailable
    );
}

#[cfg(unix)]
fn script(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(unix)]
#[test]
fn gh_gets_argv_without_a_shell() {
    let d = tempfile::tempdir().unwrap();
    let log = d.path().join("argv");
    let gh = d.path().join("gh");
    script(
        &gh,
        &format!(
            "for a in \"$@\"; do echo \"$a\" >> '{}'; done; exit 0",
            log.display()
        ),
    );
    // a file name a shell would expand or split
    let f = d.path().join("a b;$(touch pwned).tar.gz");
    std::fs::write(&f, b"x").unwrap();
    assert_eq!(verify_attestation(Some(&gh), &f), Attestation::Verified);
    let argv = std::fs::read_to_string(&log).unwrap();
    let argv: Vec<&str> = argv.lines().collect();
    assert_eq!(
        argv,
        vec![
            "attestation",
            "verify",
            f.to_str().unwrap(),
            "--repo",
            "baturox/middleman"
        ]
    );
    assert!(!d.path().join("pwned").exists());
    script(&gh, "echo 'no attestations found' >&2; exit 1");
    assert_eq!(
        verify_attestation(Some(&gh), &f),
        Attestation::Failed("no attestations found".into())
    );
}

#[test]
fn redirect_policy() {
    let u = |s: &str| reqwest::Url::parse(s).unwrap();
    let gh = u("https://github.com/baturox/middleman/releases/download/v1/x");
    for ok in [
        "https://objects.githubusercontent.com/a",
        "https://release-assets.githubusercontent.com/a",
        "https://github.com/a",
    ] {
        assert!(redirect_allowed(&gh, &u(ok), None), "{ok}");
    }
    for bad in [
        "http://objects.githubusercontent.com/a",
        "https://evil.example/a",
        "https://objects.githubusercontent.com.evil.example/a",
        "https://objects.githubusercontent.com:8443/a",
        "https://user:pw@github.com/a",
    ] {
        assert!(!redirect_allowed(&gh, &u(bad), None), "{bad}");
    }
    // https -> https only: a redirect chain that went through http stays refused
    assert!(!redirect_allowed(
        &u("http://github.com/a"),
        &u("https://github.com/b"),
        None
    ));
    // test mode: only the mock's own origin
    let mock = u("http://127.0.0.1:4000");
    assert!(redirect_allowed(
        &u("http://127.0.0.1:4000/a"),
        &u("http://127.0.0.1:4000/b"),
        Some(&mock)
    ));
    assert!(!redirect_allowed(
        &u("http://127.0.0.1:4000/a"),
        &u("https://github.com/b"),
        Some(&mock)
    ));
    assert!(!redirect_allowed(
        &u("http://127.0.0.1:4000/a"),
        &u("http://127.0.0.1:4001/b"),
        Some(&mock)
    ));
}

#[test]
fn test_override_only_accepts_loopback() {
    assert!(Endpoints::local("http://127.0.0.1:9").is_some());
    assert!(Endpoints::local("http://localhost:9/").is_some());
    assert!(Endpoints::local("https://example.com").is_none());
    assert!(Endpoints::local("http://10.0.0.1:9").is_none());
    assert!(Endpoints::local("http://user@127.0.0.1:9").is_none());
    let ep = Endpoints::github();
    assert_eq!(
        ep.release_url(None),
        "https://api.github.com/repos/baturox/middleman/releases/latest"
    );
    assert_eq!(
        ep.release_url(Some("v0.3.1")),
        "https://api.github.com/repos/baturox/middleman/releases/tags/v0.3.1"
    );
    assert_eq!(
        ep.asset_url("v0.3.1", "SHA256SUMS.txt"),
        "https://github.com/baturox/middleman/releases/download/v0.3.1/SHA256SUMS.txt"
    );
}

async fn mock() -> (MockServer, Endpoints) {
    let s = MockServer::start().await;
    let ep = Endpoints::local(&s.uri()).unwrap();
    (s, ep)
}

#[tokio::test]
async fn fetches_and_validates_the_release() {
    let (s, ep) = mock().await;
    Mock::given(method("GET"))
        .and(path("/repos/baturox/middleman/releases/latest"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            serde_json::json!({"tag_name": "v0.3.1", "body": "## What's new\n\u{1b}[31mred\u{1b}[0m\n\nfix", "html_url": "https://evil.example"}),
        ))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/baturox/middleman/releases/tags/v9.0.0"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/baturox/middleman/releases/tags/v0.4.0"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"tag_name": "v0.4.0/../../x"})),
        )
        .mount(&s)
        .await;
    let r = fetch_release(&ep, None).await.unwrap();
    assert_eq!(r.tag, "v0.3.1");
    assert_eq!(r.version, v("0.3.1"));
    assert_eq!(
        notes_summary(&r.body, 5),
        vec!["## What's new", "red", "fix"]
    );
    let e = fetch_release(&ep, Some("v9.0.0")).await.unwrap_err();
    assert!(e.to_string().contains("no release v9.0.0"), "{e}");
    let e = fetch_release(&ep, Some("v0.4.0")).await.unwrap_err();
    assert!(e.to_string().contains("odd release tag"), "{e}");
}

#[tokio::test]
async fn oversized_download_is_refused() {
    let (s, ep) = mock().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0u8; 4096]))
        .mount(&s)
        .await;
    let url = ep.asset_url("v1.0.0", "big.tar.gz");
    let e = download(&ep, &url, 1024).await.unwrap_err();
    assert!(e.to_string().contains("larger than"), "{e}");
    assert_eq!(download(&ep, &url, 8192).await.unwrap().len(), 4096);
}

#[tokio::test]
async fn redirect_to_a_disallowed_host_is_refused() {
    let (s, ep) = mock().await;
    Mock::given(method("GET"))
        .and(path("/baturox/middleman/releases/download/v1.0.0/a.tar.gz"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", "https://evil.example/a.tar.gz"),
        )
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path("/baturox/middleman/releases/download/v1.0.0/b.tar.gz"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", "/ok"))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path("/ok"))
        .respond_with(ResponseTemplate::new(200).set_body_string("fine"))
        .mount(&s)
        .await;
    let e = download(&ep, &ep.asset_url("v1.0.0", "a.tar.gz"), 1 << 20)
        .await
        .unwrap_err();
    assert!(format!("{e:#}").contains("refusing a redirect"), "{e:#}");
    // a redirect on the same (mock) origin is followed
    let b = download(&ep, &ep.asset_url("v1.0.0", "b.tar.gz"), 1 << 20)
        .await
        .unwrap();
    assert_eq!(b, b"fine");
    // and nothing is ever fetched from a non-allowed origin to begin with
    let e = download(&ep, "https://evil.example/x", 1 << 20)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("refusing to download"), "{e}");
}

#[tokio::test]
async fn download_then_checksum_mismatch_and_missing_entry() {
    let (s, ep) = mock().await;
    let body = b"archive bytes".to_vec();
    Mock::given(method("GET"))
        .and(path("/baturox/middleman/releases/download/v1.0.0/a.tar.gz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path(
            "/baturox/middleman/releases/download/v1.0.0/SHA256SUMS.txt",
        ))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(format!("{}  a.tar.gz\n", "0".repeat(64))),
        )
        .mount(&s)
        .await;
    let a = download(&ep, &ep.asset_url("v1.0.0", "a.tar.gz"), MAX_DOWNLOAD)
        .await
        .unwrap();
    let sums = download(&ep, &ep.asset_url("v1.0.0", "SHA256SUMS.txt"), MAX_META)
        .await
        .unwrap();
    let sums = String::from_utf8(sums).unwrap();
    assert!(verify_sha(&a, &sums, "a.tar.gz")
        .unwrap_err()
        .to_string()
        .contains("mismatch"));
    assert!(verify_sha(&a, &sums, "b.tar.gz")
        .unwrap_err()
        .to_string()
        .contains("no entry"));
}

// ---------------------------------------------------------------- archives

/// A tar entry with a raw name (bypasses the builder's own path checks).
fn raw_entry(
    b: &mut tar::Builder<Vec<u8>>,
    name: &str,
    kind: tar::EntryType,
    data: &[u8],
    link: Option<&str>,
) {
    let mut h = tar::Header::new_old();
    let n = name.as_bytes();
    h.as_old_mut().name[..n.len()].copy_from_slice(n);
    h.set_entry_type(kind);
    h.set_mode(0o755);
    h.set_size(data.len() as u64);
    if let Some(l) = link {
        let l = l.as_bytes();
        h.as_old_mut().linkname[..l.len()].copy_from_slice(l);
    }
    h.set_cksum();
    b.append(&h, data).unwrap();
}

pub(crate) fn targz(entries: &[(&str, tar::EntryType, &[u8], Option<&str>)]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for (n, k, d, l) in entries {
        raw_entry(&mut b, n, *k, d, *l);
    }
    let tar = b.into_inner().unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    std::io::Write::write_all(&mut gz, &tar).unwrap();
    gz.finish().unwrap()
}

#[test]
fn extracts_only_the_binary() {
    use tar::EntryType as E;
    let stem = "middleman-v1.0.0-x";
    let a = targz(&[
        ("middleman-v1.0.0-x/", E::Directory, b"", None),
        ("middleman-v1.0.0-x/README.md", E::Regular, b"readme", None),
        ("middleman-v1.0.0-x/middleman", E::Regular, b"BINARY", None),
    ]);
    assert_eq!(extract_binary(&a, stem, 1024).unwrap(), b"BINARY");
    // another directory's middleman does not count
    let a = targz(&[("other/middleman", E::Regular, b"BINARY", None)]);
    assert!(extract_binary(&a, stem, 1024)
        .unwrap_err()
        .to_string()
        .contains("has no"));
    // size cap
    let a = targz(&[(
        "middleman-v1.0.0-x/middleman",
        E::Regular,
        &[0u8; 2048],
        None,
    )]);
    assert!(extract_binary(&a, stem, 1024).is_err());
    // duplicates
    let a = targz(&[
        ("middleman-v1.0.0-x/middleman", E::Regular, b"A", None),
        ("./middleman-v1.0.0-x/middleman", E::Regular, b"B", None),
    ]);
    assert!(extract_binary(&a, stem, 1024)
        .unwrap_err()
        .to_string()
        .contains("twice"));
    assert!(extract_binary(b"not gzip at all", stem, 1024).is_err());
}

#[test]
fn archive_traversal_links_and_absolute_paths_are_rejected() {
    use tar::EntryType as E;
    let stem = "middleman-v1.0.0-x";
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "traversal",
            targz(&[
                ("middleman-v1.0.0-x/../../evil", E::Regular, b"x", None),
                ("middleman-v1.0.0-x/middleman", E::Regular, b"B", None),
            ]),
        ),
        (
            "absolute",
            targz(&[
                ("/tmp/evil", E::Regular, b"x", None),
                ("middleman-v1.0.0-x/middleman", E::Regular, b"B", None),
            ]),
        ),
        (
            "symlink",
            targz(&[(
                "middleman-v1.0.0-x/middleman",
                E::Symlink,
                b"",
                Some("/bin/sh"),
            )]),
        ),
        (
            "hardlink",
            targz(&[
                ("middleman-v1.0.0-x/middleman", E::Regular, b"B", None),
                ("middleman-v1.0.0-x/x", E::Link, b"", Some("/etc/passwd")),
            ]),
        ),
        (
            "device",
            targz(&[("middleman-v1.0.0-x/dev", E::Char, b"", None)]),
        ),
    ];
    for (what, a) in cases {
        let e = extract_binary(&a, stem, 1024).unwrap_err().to_string();
        assert!(e.contains("refusing to install"), "{what}: {e}");
    }
}

#[cfg(unix)]
#[test]
fn wrong_binary_version_is_refused() {
    let d = tempfile::tempdir().unwrap();
    let b = d.path().join("middleman");
    script(&b, "echo 'middleman 1.0.0'");
    assert!(check_binary(&b, &v("1.0.0")).is_ok());
    let e = check_binary(&b, &v("2.0.0")).unwrap_err().to_string();
    assert!(e.contains("reports version 1.0.0, expected 2.0.0"), "{e}");
    script(&b, "echo 'something else 2.0.0'");
    assert!(check_binary(&b, &v("2.0.0")).is_err());
    script(&b, "exit 3");
    assert!(check_binary(&b, &v("2.0.0")).is_err());
    std::fs::write(&b, b"\x7fELF garbage").unwrap();
    assert!(check_binary(&b, &v("2.0.0")).is_err());
}

// ---------------------------------------------------------------- install

#[cfg(unix)]
#[test]
fn atomic_replace_keeps_mode_and_rollback_swaps_back() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    let exe = d.path().join("middleman");
    script(&exe, "echo 'middleman 0.2.0'");
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o751)).unwrap();
    let new = b"#!/bin/sh\necho 'middleman 0.3.1'\n";
    let staged = stage(&exe, new).unwrap();
    let staged_path = staged.path.clone();
    assert_eq!(staged_path.parent(), exe.parent(), "staged in the same dir");
    assert_eq!(
        std::fs::metadata(&staged_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o751
    );
    check_binary(&staged_path, &v("0.3.1")).unwrap();
    let prev = install(&exe, staged).unwrap();
    assert_eq!(prev, d.path().join("middleman.prev"));
    assert!(!staged_path.exists());
    assert_eq!(std::fs::read(&exe).unwrap(), new);
    assert_eq!(
        std::fs::metadata(&exe).unwrap().permissions().mode() & 0o7777,
        0o751
    );
    assert_eq!(binary_version(&prev).unwrap(), v("0.2.0"));
    assert_eq!(binary_version(&exe).unwrap(), v("0.3.1"));

    // rollback restores 0.2.0 and keeps 0.3.1 as .prev
    assert_eq!(rollback(&exe).unwrap(), v("0.2.0"));
    assert_eq!(binary_version(&exe).unwrap(), v("0.2.0"));
    assert_eq!(binary_version(&prev).unwrap(), v("0.3.1"));
    assert_eq!(rollback(&exe).unwrap(), v("0.3.1"));
    assert_eq!(binary_version(&exe).unwrap(), v("0.3.1"));

    // no leftovers
    let names: Vec<String> = std::fs::read_dir(d.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    let mut names = names;
    names.sort();
    assert_eq!(names, vec!["middleman", "middleman.prev"]);

    // a dropped stage leaves nothing behind
    let s = stage(&exe, b"x").unwrap();
    let p = s.path.clone();
    drop(s);
    assert!(!p.exists());

    // a broken .prev is not restored
    std::fs::write(&prev, b"garbage").unwrap();
    assert!(rollback(&exe).is_err());
    assert_eq!(binary_version(&exe).unwrap(), v("0.3.1"));
    std::fs::remove_file(&prev).unwrap();
    assert!(rollback(&exe)
        .unwrap_err()
        .to_string()
        .contains("nothing to roll back"));
}

#[test]
fn package_managed_installs_are_left_alone() {
    let home = Path::new("/home/u");
    assert_eq!(
        managed_by(Path::new("/home/u/.cargo/bin/middleman"), home, None),
        Some(Managed::Cargo)
    );
    assert_eq!(
        managed_by(
            Path::new("/opt/cargo/bin/middleman"),
            home,
            Some(Path::new("/opt/cargo"))
        ),
        Some(Managed::Cargo)
    );
    assert_eq!(
        managed_by(
            Path::new("/opt/homebrew/Cellar/middleman/0.2.0/bin/middleman"),
            home,
            None
        ),
        Some(Managed::Homebrew)
    );
    assert_eq!(
        managed_by(
            Path::new("/usr/local/Cellar/middleman/0.2.0/bin/middleman"),
            home,
            None
        ),
        Some(Managed::Homebrew)
    );
    assert_eq!(
        managed_by(Path::new("/home/u/.local/bin/middleman"), home, None),
        None
    );
    assert!(Managed::Cargo.advice().contains(CARGO_CMD));
    assert!(Managed::Homebrew.advice().contains("brew upgrade"));
    let d = tempfile::tempdir().unwrap();
    assert!(dir_writable(d.path()));
    assert!(!dir_writable(&d.path().join("missing")));
    assert_eq!(
        prev_path(Path::new("/x/middleman")),
        PathBuf::from("/x/middleman.prev")
    );
}

// ---------------------------------------------------------------- update notice

#[test]
fn daily_check_cache_and_lock() {
    let d = tempfile::tempdir().unwrap();
    let state = d.path().join("state");
    let now = 1_800_000_000;
    let n = std::cell::Cell::new(0);
    let mut spawn = || {
        n.set(n.get() + 1);
        Ok(())
    };
    // no cache: one check starts, the lock blocks a second one
    assert!(maybe_check(&state, None, now, &mut spawn));
    assert!(lock_path(&state).exists());
    assert!(!maybe_check(&state, None, now, &mut spawn));
    assert_eq!(n.get(), 1);
    // the check wrote its cache and released the lock: nothing for a day
    save_cache(
        &state,
        &UpdateCache {
            checked_at: now,
            latest_version: Some("v0.2.0".into()),
            error: None,
        },
    )
    .unwrap();
    release_lock(&state);
    let c = load_cache(&state);
    assert!(!maybe_check(&state, c.as_ref(), now + 3600, &mut spawn));
    assert_eq!(n.get(), 1);
    // a day later: check again
    assert!(maybe_check(
        &state,
        c.as_ref(),
        now + CHECK_EVERY_S + 1,
        &mut spawn
    ));
    assert_eq!(n.get(), 2);
    release_lock(&state);
    // a failing spawn does not keep the lock
    assert!(!maybe_check(&state, None, now, &mut || Err(
        std::io::Error::other("no")
    )));
    assert!(!lock_path(&state).exists());

    let cur = v("0.3.0");
    assert_eq!(newer_cached(c.as_ref(), &cur), None, "0.2.0 is older");
    let newer = UpdateCache {
        checked_at: now,
        latest_version: Some("v0.3.1".into()),
        error: None,
    };
    assert_eq!(newer_cached(Some(&newer), &cur), Some(v("0.3.1")));
    let junk = UpdateCache {
        latest_version: Some("\u{1b}[2Jv9".into()),
        ..newer
    };
    assert_eq!(newer_cached(Some(&junk), &cur), None);

    assert!(checks_enabled(true, &|_| None));
    assert!(!checks_enabled(false, &|_| None));
    assert!(!checks_enabled(true, &|k| (k
        == "MIDDLEMAN_NO_UPDATE_CHECK")
        .then(|| "1".to_string())));
    assert!(checks_enabled(true, &|k| (k
        == "MIDDLEMAN_NO_UPDATE_CHECK")
        .then(|| "0".to_string())));
}

#[test]
fn doctor_update_messages() {
    let d = tempfile::tempdir().unwrap();
    let state = d.path();
    let now = 1_800_000_000;
    let c = doctor_check(state, true, now);
    assert!(c.ok && c.detail.contains("not checked yet"), "{c:?}");
    let next = Version {
        minor: Version::current().minor + 1,
        patch: 0,
        ..Version::current()
    };
    save_cache(
        state,
        &UpdateCache {
            checked_at: now - 7200,
            latest_version: Some(next.tag()),
            error: None,
        },
    )
    .unwrap();
    let c = doctor_check(state, true, now);
    assert!(!c.ok && c.optional, "{c:?}");
    assert!(
        c.detail.contains("update available") && c.detail.contains("run `middleman upgrade`"),
        "{c:?}"
    );
    save_cache(
        state,
        &UpdateCache {
            checked_at: now - 7200,
            latest_version: Some("v0.0.1".into()),
            error: None,
        },
    )
    .unwrap();
    let c = doctor_check(state, true, now);
    assert!(
        c.ok && c.detail.contains("is current") && c.detail.contains("2h ago"),
        "{c:?}"
    );
    let c = doctor_check(state, false, now);
    assert!(c.ok && c.detail.starts_with("off"), "{c:?}");
}
