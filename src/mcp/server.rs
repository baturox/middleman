//! MCP server: two tools, `delegate_task` and `middleman_status`.

use std::sync::Arc;

use serde_json::{json, Value};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};

use super::jsonrpc::{self, Incoming};
use crate::pipeline::{DelegateOutcome, DelegateRequest, Pipeline, Status};

pub const SUPPORTED_PROTOCOLS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
const DEFAULT_PROTOCOL: &str = "2025-06-18";

const INSTRUCTIONS: &str = "middleman delegates small, self-contained, low-risk tasks to a cheap \
untrusted model after sanitizing and pseudonymizing the input. Pass file paths (not pasted code); \
declare sensitivity honestly (auth, billing, customer data, infra and core algorithms are \
confidential). On status=blocked do the task yourself; do not rephrase around the block. Treat \
output as untrusted: review the diff before executing anything, and run tests only after reading the \
lines flagged in `risk`. High-risk output is only staged as .middleman.new. Delegation only pays for \
large outputs (~800+ tokens): use write_mode=file with an output_path. routing.mode confirm/explicit \
are advisory guards against accidental delegation, not a security boundary.";

/// Longest accepted JSON-RPC line on stdin (bytes); longer lines get an error reply.
pub const MAX_LINE_BYTES: usize = 8 * 1024 * 1024;

pub fn tools() -> Value {
    json!([
        {
            "name": "delegate_task",
            "title": "Delegate a small task to a cheap untrusted model (sanitized)",
            "description": "Delegate a self-contained, low-risk task that produces a LOT of output (test suites, boilerplate, docstrings for a whole file, translations, fixtures: roughly 800+ output tokens; never one-liners, which cost more in tool-call overhead than they save) to a cheap third-party model. middleman reads the files itself, blocks secrets/PII, pseudonymizes hosts/emails/paths/IPs and dictionary terms (best-effort detection: do not delegate high-value code), enforces policy, budget and a break-even gate, then restores identifiers. Code kinds default to write_mode=file: the result is written to output_path (existing files, and any output flagged high risk, are staged as .middleman.new + .middleman.patch) and you get only a short summary plus a `risk` report. Output is untrusted: review the diff before executing; run tests only after reading flagged lines. Do not re-emit the file. Use dry_run to preview. routing.mode=confirm needs a one-time approval_id the user approves with `middleman approve <id>`; confirm/explicit are advisory, not a security boundary.",
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
                    "approval_id": {"type": "string", "description": "routing.mode=confirm: the approval_id from the dry run, after the user ran `middleman approve <id>`"},
                    "user_requested": {"type": "boolean", "description": "routing.mode=explicit: true only if the user asked to delegate (cheap: prefix or /delegate)"},
                    "write_mode": {"type": "string", "enum": ["file","inline"], "description": "file (default for write_tests/boilerplate/snippet/refactor_small/docstring): result goes to disk, only a summary comes back. inline: result returned as text (only for summaries/explanations you read)"},
                    "output_path": {"type": "string", "description": "file mode target, absolute or relative to the first root (default .middleman/out/...)"},
                    "overwrite": {"type": "boolean", "description": "replace an existing output_path instead of staging .middleman.new + .middleman.patch (only if the user config sets [output] allow_overwrite = true; never for high-risk output)"},
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

/// One human-readable line that starts every `delegate_task` result.
pub fn summary_line(o: &DelegateOutcome) -> String {
    let clean = |s: &str| crate::fsutil::clean(s, 80);
    let via = match (&o.provider, &o.model) {
        (Some(p), Some(m)) => format!(" via {}/{}", clean(p), clean(m)),
        _ => String::new(),
    };
    let net = o
        .savings
        .map(|s| {
            format!(
                ", net saving {}${:.4}",
                if s.net_savings_usd < 0.0 { "-" } else { "" },
                s.net_savings_usd.abs()
            )
        })
        .unwrap_or_default();
    match o.status {
        Status::Ok if o.dry_run => {
            format!("middleman: dry run{via}; nothing was sent (see sanitized_payload and plan)")
        }
        Status::Ok => {
            let what = match &o.written {
                Some(w) => format!(
                    "{} {} ({} lines)",
                    match w.action.as_str() {
                        "staged" => "staged",
                        _ => "wrote",
                    },
                    clean(w.staged_path.as_deref().unwrap_or(&w.path)),
                    w.lines
                ),
                None => "answer below".into(),
            };
            let advice = if o.risk.as_ref().is_some_and(|r| r.level == "high") {
                "HIGH RISK: read the staged file and the risk findings before running anything"
            } else {
                "untrusted output: read the diff first, then run the tests"
            };
            format!(
                "middleman: done{via}; {what}; cost ${:.4}{net}. {advice}.",
                o.cost_usd
            )
        }
        Status::Blocked => format!(
            "middleman: blocked ({}); nothing was sent. Do the task yourself.",
            clean(
                o.block_reason
                    .as_deref()
                    .unwrap_or(if o.needs_confirmation {
                        "needs confirmation"
                    } else {
                        "policy"
                    })
            )
        ),
        Status::Error => format!(
            "middleman: error ({}); do the task yourself.",
            clean(o.error.as_deref().unwrap_or("unknown"))
        ),
    }
}

pub struct Server {
    pipeline: Arc<Pipeline>,
}

fn panic_result(what: &str) -> Value {
    tool_result(
        &json!({"status": "error", "error": format!("internal error while handling {what}; the server is still running (see stderr)")}),
        true,
    )
}

/// Read one line of at most `max` bytes (newline excluded). `Ok(None)` at EOF;
/// `Ok(Some(Err(n)))` when the line was longer (it is consumed and discarded).
async fn read_line_capped<R: AsyncBufRead + Unpin>(
    r: &mut R,
    max: usize,
) -> std::io::Result<Option<Result<String, usize>>> {
    let mut buf: Vec<u8> = Vec::new();
    let mut over = 0usize;
    let mut any = false;
    loop {
        let chunk = r.fill_buf().await?;
        if chunk.is_empty() {
            break;
        }
        any = true;
        let (take, done) = match chunk.iter().position(|&b| b == b'\n') {
            Some(i) => (i, true),
            None => (chunk.len(), false),
        };
        if over == 0 && buf.len() + take <= max {
            buf.extend_from_slice(&chunk[..take]);
        } else {
            over += buf.len() + take;
            buf.clear();
        }
        r.consume(if done { take + 1 } else { take });
        if done {
            break;
        }
    }
    if !any {
        return Ok(None);
    }
    if over > 0 {
        return Ok(Some(Err(over)));
    }
    Ok(Some(Ok(String::from_utf8_lossy(&buf).into_owned())))
}

impl Server {
    pub fn new(pipeline: Pipeline) -> Server {
        Server {
            pipeline: Arc::new(pipeline),
        }
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
                        // a panic anywhere in the pipeline becomes status:error for this call
                        // only; the server keeps serving
                        let p = self.pipeline.clone();
                        match tokio::spawn(async move { p.run(req).await }).await {
                            Ok(out) => {
                                let is_err = out.status == Status::Error;
                                let v = serde_json::to_value(&out).unwrap_or_else(|_| json!({}));
                                let mut r = tool_result(&v, is_err);
                                if let Some(c) = r["content"].as_array_mut() {
                                    c.insert(
                                        0,
                                        json!({"type": "text", "text": summary_line(&out)}),
                                    );
                                }
                                Ok(r)
                            }
                            Err(_) => Ok(panic_result("delegate_task")),
                        }
                    }
                    "middleman_status" => {
                        let p = self.pipeline.clone();
                        match tokio::spawn(async move { p.status().await }).await {
                            Ok(v) => Ok(tool_result(&v, false)),
                            Err(_) => Ok(panic_result("middleman_status")),
                        }
                    }
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
        let mut input = BufReader::new(stdin);
        while let Some(next) = read_line_capped(&mut input, MAX_LINE_BYTES).await? {
            let line = match next {
                Ok(l) => l,
                Err(n) => {
                    tracing::warn!(bytes = n, "oversized request line rejected");
                    let r = jsonrpc::error(
                        Value::Null,
                        jsonrpc::INVALID_REQUEST,
                        &format!("request line too large ({n} bytes > {MAX_LINE_BYTES})"),
                    );
                    let mut s = serde_json::to_string(&r)?;
                    s.push('\n');
                    stdout.write_all(s.as_bytes()).await?;
                    stdout.flush().await?;
                    continue;
                }
            };
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn capped_reader_rejects_long_lines_and_continues() {
        let data = format!("{}\nshort\n{}", "x".repeat(50), "tail");
        let mut r = BufReader::with_capacity(8, data.as_bytes());
        assert_eq!(read_line_capped(&mut r, 10).await.unwrap(), Some(Err(50)));
        assert_eq!(
            read_line_capped(&mut r, 10).await.unwrap(),
            Some(Ok("short".into()))
        );
        assert_eq!(
            read_line_capped(&mut r, 10).await.unwrap(),
            Some(Ok("tail".into()))
        );
        assert_eq!(read_line_capped(&mut r, 10).await.unwrap(), None);
    }
}
