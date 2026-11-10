//! Rule-based sensitivity (S0..S3) and complexity (C0..C2). The main agent is the semantic
//! classifier (`declared_sensitivity`); these rules are the backstop and can only raise it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::config::{ClassifyCfg, PiiMode, SecretsMode};
use crate::detect::{Category, Finding, Severity};
use crate::TaskKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Sensitivity {
    S0,
    S1,
    S2,
    S3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Complexity {
    C0,
    C1,
    C2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Declared {
    Public,
    Internal,
    Confidential,
}

impl Declared {
    pub fn level(self) -> Sensitivity {
        match self {
            Declared::Public => Sensitivity::S0,
            Declared::Internal => Sensitivity::S1,
            Declared::Confidential => Sensitivity::S3,
        }
    }
    pub fn parse(s: &str) -> Option<Declared> {
        match s {
            "public" => Some(Declared::Public),
            "internal" => Some(Declared::Internal),
            "confidential" => Some(Declared::Confidential),
            _ => None,
        }
    }
}

pub struct ClassifyInput<'a> {
    pub task_kind: TaskKind,
    pub declared: Declared,
    pub findings: &'a [Finding],
    pub payload_chars: usize,
    pub secrets_mode: SecretsMode,
    pub pii_mode: PiiMode,
}

#[derive(Debug, Clone, Serialize)]
pub struct Classification {
    pub declared: Sensitivity,
    pub detected: Sensitivity,
    pub effective: Sensitivity,
    pub complexity: Complexity,
    pub reasons: Vec<String>,
}

/// Pluggable so a first-party LLM classifier can be added later (Phase 2).
pub trait Classifier {
    fn classify(&self, input: &ClassifyInput<'_>) -> Classification;
}

pub struct RuleClassifier {
    pub cfg: ClassifyCfg,
}

impl Classifier for RuleClassifier {
    fn classify(&self, i: &ClassifyInput<'_>) -> Classification {
        let mut reasons = Vec::new();
        let mut detected = Sensitivity::S0;
        let mut by_sev: BTreeMap<Severity, usize> = BTreeMap::new();
        for f in i
            .findings
            .iter()
            .filter(|f| f.category != Category::FilePath)
        {
            *by_sev.entry(f.severity()).or_insert(0) += 1;
        }
        let hard = by_sev.get(&Severity::Hard).copied().unwrap_or(0);
        let pii = by_sev.get(&Severity::Pii).copied().unwrap_or(0);
        let infra = by_sev.get(&Severity::Infra).copied().unwrap_or(0);
        let dict = by_sev.get(&Severity::Dict).copied().unwrap_or(0);

        if hard > 0 {
            if i.secrets_mode == SecretsMode::Block {
                detected = detected.max(Sensitivity::S3);
                reasons.push(format!("{hard} hard secret(s) detected"));
            } else {
                detected = detected.max(Sensitivity::S2);
                reasons.push(format!("{hard} secret(s) masked"));
            }
        }
        if pii > 0 {
            if i.pii_mode == PiiMode::Block {
                detected = detected.max(Sensitivity::S3);
                reasons.push(format!("{pii} PII item(s) detected"));
            } else {
                detected = detected.max(Sensitivity::S2);
                reasons.push(format!("{pii} PII item(s) pseudonymized"));
            }
        }
        if infra > 0 {
            detected = detected.max(Sensitivity::S2);
            reasons.push(format!("{infra} infra/email/path item(s) pseudonymized"));
        }
        if dict >= self.cfg.dict_hits_s2 {
            detected = detected.max(Sensitivity::S2);
            reasons.push(format!(
                "{dict} dictionary hits (>= {})",
                self.cfg.dict_hits_s2
            ));
        } else if dict > 0 {
            detected = detected.max(Sensitivity::S1);
        }

        let declared = i.declared.level();
        let effective = declared.max(detected);

        let mut complexity = match i.task_kind {
            TaskKind::Docstring
            | TaskKind::Boilerplate
            | TaskKind::Snippet
            | TaskKind::Translate
            | TaskKind::Summarize
            | TaskKind::Explain => Complexity::C0,
            TaskKind::WriteTests | TaskKind::RefactorSmall | TaskKind::Other => Complexity::C1,
        };
        if i.payload_chars > self.cfg.large_chars {
            complexity = match complexity {
                Complexity::C0 => Complexity::C1,
                _ => Complexity::C2,
            };
            reasons.push(format!("large payload ({} chars)", i.payload_chars));
        }
        Classification {
            declared,
            detected,
            effective,
            complexity,
            reasons,
        }
    }
}
