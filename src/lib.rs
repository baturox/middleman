//! middleman: a local, trusted sanitization layer between Claude Code and untrusted LLM providers.
#![deny(clippy::print_stdout)]

pub mod approval;
pub mod audit;
pub mod budget;
pub mod catalog;
pub mod classify;
pub mod config;
pub mod detect;
pub mod economics;
pub mod egress;
pub mod hook;
pub mod intake;
pub mod ledger;
pub mod mcp;
pub mod output;
pub mod pipeline;
pub mod policy;
pub mod providers;
pub mod pseudo;
pub mod report;
pub mod risk;
pub mod routing;
pub mod setup;
pub mod tune;
pub mod usage;

use serde::{Deserialize, Serialize};

/// Kinds of work the main agent may delegate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum TaskKind {
    WriteTests,
    Boilerplate,
    Summarize,
    Explain,
    Docstring,
    Translate,
    Snippet,
    RefactorSmall,
    Other,
}

impl TaskKind {
    pub const ALL: [TaskKind; 9] = [
        TaskKind::WriteTests,
        TaskKind::Boilerplate,
        TaskKind::Summarize,
        TaskKind::Explain,
        TaskKind::Docstring,
        TaskKind::Translate,
        TaskKind::Snippet,
        TaskKind::RefactorSmall,
        TaskKind::Other,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            TaskKind::WriteTests => "write_tests",
            TaskKind::Boilerplate => "boilerplate",
            TaskKind::Summarize => "summarize",
            TaskKind::Explain => "explain",
            TaskKind::Docstring => "docstring",
            TaskKind::Translate => "translate",
            TaskKind::Snippet => "snippet",
            TaskKind::RefactorSmall => "refactor_small",
            TaskKind::Other => "other",
        }
    }

    pub fn parse(s: &str) -> Option<TaskKind> {
        TaskKind::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

impl std::fmt::Display for TaskKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
