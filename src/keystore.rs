//! Where provider API keys live when they are not in an environment variable.
//!
//! Default: the OS credential store (macOS Keychain, Windows Credential Manager, the Linux
//! Secret Service), service `middleman`, account = provider name. Fallback, only when that
//! store is unavailable: one 0600 file per provider under `~/.config/middleman/keys/`.
//!
//! Errors from the credential store are reduced to a short category here: some of them can
//! carry raw secret bytes and must never reach a log or a message.
//!
//! Test hooks (never needed in normal use): `MIDDLEMAN_KEYSTORE=file` forces the file store,
//! `MIDDLEMAN_KEYRING_SERVICE` changes the service name, `MIDDLEMAN_KEYS_DIR` the file dir.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::config::{expand_tilde, Secret};

pub const SERVICE: &str = "middleman";

/// Where a stored key lives (`key_source` in the provider config).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum KeySource {
    Keychain,
    File,
}

impl KeySource {
    pub fn as_str(&self) -> &'static str {
        match self {
            KeySource::Keychain => "keychain",
            KeySource::File => "file",
        }
    }
}

pub fn keychain_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "macOS Keychain"
    } else if cfg!(windows) {
        "Windows Credential Manager"
    } else {
        "Secret Service"
    }
}

pub fn service() -> String {
    std::env::var("MIDDLEMAN_KEYRING_SERVICE")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| SERVICE.to_string())
}

pub fn keys_dir() -> PathBuf {
    std::env::var_os("MIDDLEMAN_KEYS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| expand_tilde(Path::new("~/.config/middleman/keys")))
}

fn forced_file() -> bool {
    std::env::var("MIDDLEMAN_KEYSTORE").is_ok_and(|v| v.eq_ignore_ascii_case("file"))
}

/// Where a new key will go, for prompts: "your macOS Keychain" or "a private file (0600)".
pub fn preferred_store_name() -> String {
    if forced_file() {
        "a private file (mode 0600)".into()
    } else {
        format!("your {}", keychain_name())
    }
}

fn valid_account(name: &str) -> Result<()> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("invalid provider name {name:?} (letters, digits, - and _ only)");
    }
    Ok(())
}

/// A short, value-free description of a credential-store error.
fn kc_err(e: &keyring::Error) -> String {
    use keyring::Error as E;
    match e {
        E::NoStorageAccess(_) => "the credential store is locked or access was denied".into(),
        E::PlatformFailure(_) => "the credential store reported a platform failure".into(),
        E::NoDefaultStore => format!("no {} is available on this system", keychain_name()),
        E::NoEntry => "no entry".into(),
        E::BadEncoding(_) | E::BadDataFormat(..) => "the stored value is not valid text".into(),
        E::TooLong(..) => "the value is too long for the credential store".into(),
        E::Invalid(..) => "invalid credential-store parameter".into(),
        E::Ambiguous(_) => "more than one matching credential".into(),
        _ => "credential store error".into(),
    }
}

#[derive(Debug, Clone)]
pub enum Store {
    Keychain { service: String },
    File { dir: PathBuf },
}

impl Store {
    pub fn keychain() -> Store {
        Store::Keychain { service: service() }
    }

    pub fn file() -> Store {
        Store::File { dir: keys_dir() }
    }

    pub fn for_source(s: KeySource) -> Store {
        match s {
            KeySource::Keychain => Store::keychain(),
            KeySource::File => Store::file(),
        }
    }

    pub fn source(&self) -> KeySource {
        match self {
            Store::Keychain { .. } => KeySource::Keychain,
            Store::File { .. } => KeySource::File,
        }
    }

    /// Human description of where `account`'s key is (never the key).
    pub fn describe(&self, account: &str) -> String {
        match self {
            Store::Keychain { service } => {
                format!("{} (service {service}, account {account})", keychain_name())
            }
            Store::File { dir } => crate::fsutil::pretty(&dir.join(account)),
        }
    }

    fn entry(service: &str, account: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(service, account)
            .map_err(|e| anyhow::anyhow!("{}: {}", keychain_name(), kc_err(&e)))
    }

    pub fn get(&self, account: &str) -> Result<Option<Secret>> {
        valid_account(account)?;
        match self {
            Store::Keychain { service } => match Self::entry(service, account)?.get_password() {
                Ok(v) => {
                    let v = Zeroizing::new(v);
                    Ok(Some(Secret::new(v.trim())))
                }
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => bail!("{}: {}", keychain_name(), kc_err(&e)),
            },
            Store::File { dir } => {
                let p = dir.join(account);
                match std::fs::read_to_string(&p) {
                    Ok(t) => {
                        let t = Zeroizing::new(t);
                        let v = t.trim();
                        if v.is_empty() {
                            return Ok(None);
                        }
                        Ok(Some(Secret::new(v)))
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                    Err(e) => Err(e).with_context(|| format!("cannot read {}", p.display())),
                }
            }
        }
    }

    pub fn set(&self, account: &str, key: &Secret) -> Result<()> {
        valid_account(account)?;
        match self {
            Store::Keychain { service } => Self::entry(service, account)?
                .set_password(key.expose())
                .map_err(|e| anyhow::anyhow!("{}: {}", keychain_name(), kc_err(&e))),
            Store::File { dir } => {
                crate::ledger::ensure_private_dir(dir)?;
                let p = dir.join(account);
                // a fresh file is created 0600 by write_atomic; force it in case one existed
                crate::fsutil::write_atomic(&p, key.expose().as_bytes(), Some(0o600))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
                }
                Ok(())
            }
        }
    }

    /// Remove the key. Returns false when there was nothing to remove.
    pub fn delete(&self, account: &str) -> Result<bool> {
        valid_account(account)?;
        match self {
            Store::Keychain { service } => match Self::entry(service, account)?.delete_credential()
            {
                Ok(()) => Ok(true),
                Err(keyring::Error::NoEntry) => Ok(false),
                Err(e) => bail!("{}: {}", keychain_name(), kc_err(&e)),
            },
            Store::File { dir } => match std::fs::remove_file(dir.join(account)) {
                Ok(()) => Ok(true),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(e) => Err(e.into()),
            },
        }
    }
}

/// Check the OS credential store can be used, without reading any real key.
pub fn keychain_status() -> Result<(), String> {
    if forced_file() {
        return Err("disabled by MIDDLEMAN_KEYSTORE=file".into());
    }
    let svc = service();
    match keyring::Entry::new(&svc, "middleman-doctor-probe") {
        Err(e) => Err(kc_err(&e)),
        Ok(e) => match e.get_password() {
            Ok(_) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(kc_err(&e)),
        },
    }
}

/// Outcome of storing a key.
pub struct Stored {
    pub source: KeySource,
    pub location: String,
    /// Set when the keychain was unavailable and the file store was used instead.
    pub warning: Option<String>,
}

/// Store a key in the OS credential store, or in a 0600 file if that store is unavailable.
pub fn store_key(account: &str, key: &Secret) -> Result<Stored> {
    if !forced_file() {
        let kc = Store::keychain();
        match kc.set(account, key) {
            Ok(()) => {
                // read back: some Secret Service setups accept writes they cannot serve
                if kc.get(account)?.is_some_and(|k| k.expose() == key.expose()) {
                    return Ok(Stored {
                        source: KeySource::Keychain,
                        location: kc.describe(account),
                        warning: None,
                    });
                }
                let _ = kc.delete(account);
                return store_in_file(
                    account,
                    key,
                    Some("the keychain accepted the key but could not read it back".into()),
                );
            }
            Err(e) => return store_in_file(account, key, Some(format!("{e:#}"))),
        }
    }
    store_in_file(account, key, None)
}

fn store_in_file(account: &str, key: &Secret, why: Option<String>) -> Result<Stored> {
    let f = Store::file();
    f.set(account, key)?;
    Ok(Stored {
        source: KeySource::File,
        location: f.describe(account),
        warning: why.map(|w| {
            format!(
                "the {} is unavailable ({w}); the key was saved to a private file (mode 0600) instead. \
Anyone who can read your home directory as you can read it.",
                keychain_name()
            )
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_store_roundtrip_is_private() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::File {
            dir: d.path().join("keys"),
        };
        assert!(s.get("openrouter").unwrap().is_none());
        s.set("openrouter", &Secret::new("sk-or-test-1")).unwrap();
        assert_eq!(
            s.get("openrouter").unwrap().unwrap().expose(),
            "sk-or-test-1"
        );
        s.set("openrouter", &Secret::new("sk-or-test-2")).unwrap();
        assert_eq!(
            s.get("openrouter").unwrap().unwrap().expose(),
            "sk-or-test-2"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(m(&d.path().join("keys/openrouter")), 0o600);
            assert_eq!(m(&d.path().join("keys")), 0o700);
        }
        assert!(s.delete("openrouter").unwrap());
        assert!(!s.delete("openrouter").unwrap());
        assert!(s.describe("openrouter").ends_with("keys/openrouter"));
    }

    #[test]
    fn rejects_path_like_accounts() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::File {
            dir: d.path().to_path_buf(),
        };
        for bad in ["../x", "a/b", "", "a b"] {
            assert!(s.set(bad, &Secret::new("k")).is_err(), "{bad}");
        }
    }

    #[test]
    fn keychain_errors_never_carry_bytes() {
        let e = keyring::Error::BadEncoding(b"sk-or-secret".to_vec());
        assert!(!kc_err(&e).contains("sk-or"));
    }
}
