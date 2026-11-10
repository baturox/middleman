//! Provider-level gate: (task_kind, sensitivity, complexity) -> Allow{providers} | Block.
//! Default deny: no provider passing every rule means Block. Model choice within the allowed
//! providers is done by `routing`.

use serde::Serialize;

use crate::classify::{Classification, Complexity};
use crate::config::Config;
use crate::TaskKind;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "decision", rename_all = "lowercase")]
pub enum Decision {
    Allow { providers: Vec<String> },
    Block { reason: String },
}

impl Decision {
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow { .. })
    }
}

pub fn decide(cfg: &Config, task: TaskKind, c: &Classification) -> Decision {
    if c.complexity >= Complexity::C2 {
        return Decision::Block {
            reason: "complexity C2: do this task yourself".into(),
        };
    }
    let mut why = Vec::new();
    let mut allowed = Vec::new();
    for (name, p) in &cfg.providers {
        if !p.enabled {
            why.push(format!("{name}: disabled"));
        } else if c.effective > p.max_sensitivity {
            why.push(format!(
                "{name}: sensitivity {:?} > max {:?}",
                c.effective, p.max_sensitivity
            ));
        } else if !p.allows_task(task) {
            why.push(format!("{name}: task_kind {task} not allowed"));
        } else if c.complexity > p.max_complexity {
            why.push(format!(
                "{name}: complexity {:?} > max {:?}",
                c.complexity, p.max_complexity
            ));
        } else {
            allowed.push(name.clone());
        }
    }
    if !allowed.is_empty() {
        return Decision::Allow { providers: allowed };
    }
    if why.is_empty() {
        why.push("no providers configured".into());
    }
    Decision::Block {
        reason: format!(
            "sensitivity {:?} (declared {:?}, detected {:?}): no provider allowed ({})",
            c.effective,
            c.declared,
            c.detected,
            why.join("; ")
        ),
    }
}
