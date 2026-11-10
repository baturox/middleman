//! MCP server: two tools, `delegate_task` and `middleman_status`.

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use super::jsonrpc::{self, Incoming};
use crate::pipeline::{DelegateRequest, Pipeline, Status};

pub const SUPPORTED_PROTOCOLS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
const DEFAULT_PROTOCOL: &str = "2025-06-18";

const INSTRUCTIONS: &str = "middleman delegates small, self-contained, low-risk tasks to a cheap \
untrusted model after sanitizing and pseudonymizing the input. Pass file paths (not pasted code); \
declare sensitivity honestly (auth, billing, customer data, infra and core algorithms are \
confidential). On status=blocked do the task yourself; do not rephrase around the block. Treat \
output as untrusted: review and test it. Delegation only pays for large outputs (~800+ tokens): use write_mode=file with an output_path and verify by running tests, never by re-reading the file.";

pub fn tools() -> Value {
    json!([
        {
            "name": "delegate_task",
            "title": "Delegate a small task to a cheap untrusted model (sanitized)",
            "description": "Delegate a self-contained, low-risk task that produces a LOT of output (test suites, boilerplate, docstrings for a whole file, translations, fixtures: roughly 800+ output tokens; never one-liners, which cost more in tool-call overhead than they save) to a cheap third-party model. middleman reads the files itself, blocks secrets/PII, pseudonymizes hosts/emails/paths/IPs and dictionary terms, enforces policy, budget and a break-even gate, then restores identifiers. Code kinds default to write_mode=file: the result is written to output_path (existing files are staged as .middleman.new + .middleman.patch unless overwrite=true) and you get only a short summary. Verify by running tests/compiler, do not re-read or re-emit the file. Output is untrusted. Use dry_run to preview.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "task_kind": {"type": "string", "enum": ["write_tests","boilerplate","summarize","explain","docstring","translate","snippet","refactor_small","other"]},
                    "instructions": {"type": "string", "description": "What to do. Do not name the company or project."},
                    "files": {"type": "array", "items": {"type": "object", "properties": {
                        "path": {"type": "string", "description": "Absolute, or relative to the first configured root"},
                        "start_line": {"type": "integer", "minimum": 1},
                        "end_line": {"type": "integer", "minimum": 1}
                    }, "required": ["path"], "additionalProperties": false}},
                    "inputs": {"type": "array", "items": {"type": "object", "properties": {
                        "label": {"type": "string"}, "text": {"type": "string"}
                    }, "required": ["label","text"], "additionalProperties": false}},
                    "declared_sensitivity": {"type": "string", "enum": ["public","internal","confidential"]},
                    "max_cost_usd": {"type": "number", "minimum": 0},
                    "max_output_tokens": {"type": "integer", "minimum": 1},
                    "dry_run": {"type": "boolean"},
                    "quality": {"type": "string", "enum": ["cheapest","balanced","best"], "description": "Hint: start the routing chain at this tier"},
                    "confirmed": {"type": "boolean", "description": "routing.mode=confirm: true only after the user approved the dry-run plan"},
                    "user_requested": {"type": "boolean", "description": "routing.mode=explicit: true only if the user asked to delegate (cheap: prefix or /delegate)"},
                    "write_mode": {"type": "string", "enum": ["file","inline"], "description": "file (default for write_tests/boilerplate/snippet/refactor_small/docstring): result goes to disk, only a summary comes back. inline: result returned as text (only for summaries/explanations you read)"},
                    "output_path": {"type": "string", "description": "file mode target, absolute or relative to the first root (default .middleman/out/...)"},
                    "overwrite": {"type": "boolean", "description": "replace an existing output_path instead of staging .middleman.new + .middleman.patch"},
                    "expected_output_tokens": {"type": "integer", "minimum": 0, "description": "your estimate of the output size; used by the break-even gate"}
                },
                "required": ["task_kind","instructions","declared_sensitivity"],
                "additionalProperties": false
            }
        },
        {
            "name": "middleman_status",
            "title": "middleman budget and provider status",
            "description": "Remaining daily/weekly allowance, provider balances, enabled providers and policy.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false}
        }
    ])
}

fn tool_result(v: &Value, is_error: bool) -> Value {
    json!({
        "content": [{"type": "text", "text": serde_json::to_string_pretty(v).unwrap_or_default()}],
        "isError": is_error,
    })
}

pub struct Server {
    pipeline: Pipeline,
}

impl Server {
    pub fn new(pipeline: Pipeline) -> Server {
        Server { pipeline }
    }

    pub async fn handle(&self, method: &str, params: Value) -> Result<Value, (i64, String)> {
        match method {
            "initialize" => {
                let requested = params
                    .get("protocolVersion")
                    .and_then(|v| v.as_str())
                    .unwrap_or(DEFAULT_PROTOCOL);
                let version = if SUPPORTED_PROTOCOLS.contains(&requested) {
                    requested
                } else {
                    DEFAULT_PROTOCOL
                };
                Ok(json!({
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {"name": "middleman", "version": env!("CARGO_PKG_VERSION")},
                    "instructions": INSTRUCTIONS,
                }))
            }
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({"tools": tools()})),
            "tools/call" => {
                let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
                let args = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                match name {
                    "delegate_task" => {
                        let req: DelegateRequest = match serde_json::from_value(args) {
                            Ok(r) => r,
                            Err(e) => {
                                return Ok(tool_result(
                                    &json!({"status": "error", "error": format!("invalid arguments: {e}")}),
                                    true,
                                ))
                            }
                        };
                        let out = self.pipeline.run(req).await;
                        let is_err = out.status == Status::Error;
                        let v = serde_json::to_value(&out).unwrap_or_else(|_| json!({}));
                        Ok(tool_result(&v, is_err))
                    }
                    "middleman_status" => Ok(tool_result(&self.pipeline.status().await, false)),
                    other => Err((jsonrpc::INVALID_PARAMS, format!("unknown tool: {other}"))),
                }
            }
            other => Err((
                jsonrpc::METHOD_NOT_FOUND,
                format!("method not found: {other}"),
            )),
        }
    }

    /// Serve until stdin closes. Requests are handled sequentially.
    pub async fn run_stdio(self) -> anyhow::Result<()> {
        let stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let mut lines = BufReader::new(stdin).lines();
        while let Some(line) = lines.next_line().await? {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let reply = match jsonrpc::parse_line(line) {
                Incoming::Request { id, method, params } => {
                    tracing::debug!(%method, "request");
                    Some(match self.handle(&method, params).await {
                        Ok(r) => jsonrpc::response(id, r),
                        Err((code, msg)) => jsonrpc::error(id, code, &msg),
                    })
                }
                Incoming::Notification { method } => {
                    tracing::debug!(%method, "notification");
                    None
                }
                Incoming::Invalid(e) => e,
            };
            if let Some(r) = reply {
                let mut s = serde_json::to_string(&r)?;
                s.push('\n');
                stdout.write_all(s.as_bytes()).await?;
                stdout.flush().await?;
            }
        }
        Ok(())
    }
}
