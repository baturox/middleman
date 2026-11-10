//! The egress gate. `Sanitized<T>` can only be built by `seal`, which re-scans the final
//! payload and asserts that no vault original and no credential is present. Providers accept
//! only `&Sanitized<OutboundRequest>`, so no code path reaches the network with raw text.

use thiserror::Error;

use crate::config::Secret;
use crate::detect::Detector;
use crate::pseudo::Vault;

#[derive(Debug, Clone)]
pub struct OutboundRequest {
    pub model: String,
    pub system: String,
    pub user: String,
    pub max_tokens: u32,
}

impl OutboundRequest {
    pub fn payload_text(&self) -> String {
        format!("{}\n{}", self.system, self.user)
    }
}

/// Proof that the wrapped value passed the egress gate. The field is private to this module.
#[derive(Debug)]
pub struct Sanitized<T> {
    inner: T,
}

impl<T> Sanitized<T> {
    pub fn get(&self) -> &T {
        &self.inner
    }
}

#[derive(Debug, Error, PartialEq)]
pub enum EgressViolation {
    #[error("egress re-scan found un-pseudonymized {0}")]
    Finding(String),
    #[error("a vault original ({0}) is still present in the outbound payload")]
    Original(String),
    #[error("a provider credential is present in the outbound payload")]
    Credential,
}

pub fn seal(
    req: OutboundRequest,
    vault: &Vault,
    detector: &Detector,
    credentials: &[&Secret],
) -> Result<Sanitized<OutboundRequest>, EgressViolation> {
    let text = req.payload_text();
    for c in credentials {
        let k = c.expose();
        if k.len() >= 8 && text.contains(k) {
            return Err(EgressViolation::Credential);
        }
    }
    let spans = vault.surrogate_spans(&text);
    for f in detector.scan(&text) {
        let inside_surrogate = spans.iter().any(|&(s, e)| f.start >= s && f.end <= e);
        if inside_surrogate {
            continue;
        }
        // every detectable item must have been replaced (or blocked earlier); anything left
        // means the pipeline is wrong, so fail closed
        return Err(EgressViolation::Finding(format!(
            "{} ({})",
            f.category.as_str(),
            f.label
        )));
    }
    let lower = text.to_lowercase();
    for o in vault.originals() {
        let present = if vault.is_dict_original(o) {
            lower.contains(&o.to_lowercase())
        } else {
            text.contains(o)
        };
        if present {
            return Err(EgressViolation::Original(format!(
                "{} chars",
                o.chars().count()
            )));
        }
    }
    Ok(Sanitized { inner: req })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::{resolve_overlaps, Dictionary};
    use crate::pseudo::apply;

    fn req(user: &str) -> OutboundRequest {
        OutboundRequest {
            model: "m".into(),
            system: "sys".into(),
            user: user.into(),
            max_tokens: 10,
        }
    }

    #[test]
    fn raw_payload_is_rejected() {
        let det = Detector::new(vec![], vec![], None);
        let v = Vault::new("");
        let e = seal(req("mail bob@acme-corp.io"), &v, &det, &[]).unwrap_err();
        assert!(matches!(e, EgressViolation::Finding(_)));
    }

    #[test]
    fn pseudonymized_payload_passes() {
        let dict = Dictionary::from_terms(["acme"]).unwrap();
        let det = Detector::new(vec![], vec![], Some(dict));
        let t = "AcmeBilling mails bob@acme-corp.io at 10.2.3.4";
        let fs = resolve_overlaps(det.scan(t));
        let mut v = Vault::new(t);
        let s = apply(t, &fs, &mut v, det.dictionary());
        let sealed = seal(req(&s), &v, &det, &[]).unwrap();
        assert!(!sealed.get().user.to_lowercase().contains("acme"));
    }

    #[test]
    fn credential_is_rejected() {
        let det = Detector::new(vec![], vec![], None);
        let v = Vault::new("");
        let k = Secret::new("plainlookingkeyvalue");
        let e = seal(req("x plainlookingkeyvalue"), &v, &det, &[&k]).unwrap_err();
        assert_eq!(e, EgressViolation::Credential);
    }
}
