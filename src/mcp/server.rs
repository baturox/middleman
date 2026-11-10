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
                    "expected_output_tokens": {"type": "integer", "minimum": 0, "description": "your estimate of the output size; used by the break-even gate"},
                    "verbose": {"type": "boolean", "description": "full result (plan, attempts, notes, savings breakdown). Default: a compact result"}
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

/// The `delegate_task` tool result exactly as Claude receives it. Claude re-reads it on every
/// later turn, so by default it is compact: the summary line plus the non-empty essentials.
/// `verbose: true` returns the whole outcome.
pub fn delegate_result(out: &DelegateOutcome) -> Value {
    if out.verbose {
        let v = serde_json::to_value(out).unwrap_or_else(|_| json!({}));
        let mut r = tool_result(&v, out.status == Status::Error);
        if let Some(c) = r["content"].as_array_mut() {
            c.insert(0, json!({"type": "text", "text": summary_line(out)}));
        }
        return r;
    }
    json!({
        "content": [
            {"type": "text", "text": summary_line(out)},
            {"type": "text", "text": serde_json::to_string(&compact(out)).unwrap_or_default()},
        ],
        "isError": out.status == Status::Error,
    })
}

/// The essentials of an outcome, empty fields left out.
pub fn compact(o: &DelegateOutcome) -> Value {
    let clean = |s: &str, n: usize| crate::fsutil::clean(s, n);
    let mut m = serde_json::Map::new();
    let mut put = |k: &str, v: Value| {
        m.insert(k.into(), v);
    };
    put("status", json!(o.status));
    if let Some(w) = &o.written {
        put("path", json!(w.path));
        put("lines", json!(w.lines));
        if let Some(sp) = &w.staged_path {
            put("staged", json!(sp));
        }
        if let Some(pp) = &w.patch_path {
            put("patch", json!(pp));
        }
    }
    if let Some(r) = &o.risk {
        put("risk", json!(r.level));
        if !r.findings.is_empty() {
            let f: Vec<String> = r.findings.iter().take(5).map(|x| clean(x, 100)).collect();
            put("risk_findings", json!(f));
        }
    }
    if o.cost_usd > 0.0 {
        put("cost_usd", json!((o.cost_usd * 1e6).round() / 1e6));
    }
    if let Some(s) = &o.savings {
        put("net_usd", json!((s.net_savings_usd * 1e4).round() / 1e4));
    }
    if let Some(x) = o.block_reason.as_deref() {
        put("reason", json!(clean(x, 300)));
    }
    if let Some(x) = o.error.as_deref() {
        put("error", json!(clean(x, 300)));
    }
    if o.needs_confirmation {
        put("needs_confirmation", json!(true));
    }
    if let Some(a) = &o.approval_id {
        put("approval_id", json!(a));
    }
    if o.dry_run {
        put("dry_run", json!(true));
        if let (Some(p), Some(mo)) = (&o.provider, &o.model) {
            put("model", json!(format!("{p}/{mo}")));
        }
        if let Some(sp) = &o.sanitized_payload {
            put("sanitized_payload", json!(sp));
        }
    }
    if let Some(x) = &o.output {
        put("output", json!(x));
    }
    let warnings: Vec<String> = o
        .warnings
        .iter()
        .filter(|w| !w.starts_with("dry run:"))
        .take(3)
        // the confirm-mode instruction must survive whole
        .map(|w| {
            clean(
                w,
                if w.starts_with("routing.mode") {
                    400
                } else {
                    160
                },
            )
        })
        .collect();
    if !warnings.is_empty() {
        put("warnings", json!(warnings));
    }
    Value::Object(m)
}

/// Characters of text Claude reads from the `delegate_task` result (every text block).
pub fn result_chars(out: &DelegateOutcome) -> u64 {
    delegate_result(out)["content"]
        .as_array()
        .map(|c| {
            c.iter()
                .filter_map(|b| b.get("text").and_then(Value::as_str))
                .map(|t| t.chars().count() as u64)
                .sum()
        })
        .unwrap_or(0)
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
            format!("middleman: dry run{via}; nothing was sent (see sanitized_payload; verbose=true adds the plan)")
        }
        Status::Ok => {
            let what = match &o.written {
                // the compact result carries the path in its JSON block
                Some(w) if !o.verbose => format!(
                    "{} {} lines (see {})",
                    if w.action == "staged" {
                        "staged"
                    } else {
                        "wrote"
                    },
                    w.lines,
                    if w.action == "staged" {
                        "staged, patch"
                    } else {
                        "path"
                    }
                ),
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
    /// What `initialize` negotiated (protocol version, client info), carried across a
    /// self re-exec after an upgrade.
    session: std::sync::Mutex<Option<(String, Value)>>,
    /// How many times this session was handed to a newer binary.
    generation: u64,
}

/// Set in the environment of a re-executed server: the session is already initialized.
pub const RESUMED_ENV: &str = "MIDDLEMAN_MCP_RESUMED";
const PROTOCOL_ENV: &str = "MIDDLEMAN_MCP_PROTOCOL";
const CLIENT_ENV: &str = "MIDDLEMAN_MCP_CLIENT";
const TOOLS_ENV: &str = "MIDDLEMAN_MCP_TOOLS_SHA";
const GENERATION_ENV: &str = "MIDDLEMAN_MCP_GENERATION";
/// How often (ms) to look at the binary on disk; default 3000. `MIDDLEMAN_MCP_NO_REEXEC=1`
/// turns the re-exec off.
const CHECK_MS_ENV: &str = "MIDDLEMAN_MCP_RELOAD_CHECK_MS";

/// SHA-256 of the tool list, to tell the client when a new binary changed it.
pub fn tools_digest() -> String {
    use sha2::{Digest, Sha256};
    let t = serde_json::to_vec(&tools()).unwrap_or_default();
    Sha256::digest(&t)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Should a resumed server send `notifications/tools/list_changed`?
pub fn tools_changed(previous_digest: Option<&str>) -> bool {
    previous_digest.is_some_and(|d| d != tools_digest())
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
        let resumed = std::env::var(RESUMED_ENV).is_ok_and(|v| v == "1");
        let session = resumed
            .then(|| {
                let proto = std::env::var(PROTOCOL_ENV).ok()?;
                let client = std::env::var(CLIENT_ENV)
                    .ok()
                    .and_then(|c| serde_json::from_str(&c).ok())
                    .unwrap_or(Value::Null);
                Some((proto, client))
            })
            .flatten();
        let generation = if resumed {
            std::env::var(GENERATION_ENV)
                .ok()
                .and_then(|g| g.parse().ok())
                .unwrap_or(1)
        } else {
            0
        };
        Server {
            pipeline: Arc::new(pipeline),
            session: std::sync::Mutex::new(session),
            generation,
        }
    }

    /// After a call that spent money, refresh the provider-limits cache the status line shows
    /// (free GETs; skipped while another refresh holds the lock).
    fn refresh_limits_in_background(&self) {
        let cfg = self.pipeline.config().clone();
        if let Some(lock) = crate::limits::try_lock(&cfg.state_dir()) {
            tokio::spawn(async move {
                let _ = crate::limits::refresh(&cfg).await;
                drop(lock);
            });
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
                if let Ok(mut s) = self.session.lock() {
                    *s = Some((
                        version.to_string(),
                        params.get("clientInfo").cloned().unwrap_or(Value::Null),
                    ));
                }
                Ok(json!({
                    "protocolVersion": version,
                    // a newer binary that re-executes in place tells the client when its tools change
                    "capabilities": {"tools": {"listChanged": true}},
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
                        // what Claude emitted for this call (JSON arguments, compact)
                        let call_chars = serde_json::to_string(&args)
                            .map(|s| s.chars().count() as u64)
                            .unwrap_or(0);
                        let req: DelegateRequest = match serde_json::from_value::<DelegateRequest>(
                            args,
                        ) {
                            Ok(mut r) => {
                                r.call_chars = Some(call_chars);
                                r
                            }
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
                                if !out.attempts.is_empty() {
                                    self.refresh_limits_in_background();
                                }
                                Ok(delegate_result(&out))
                            }
                            Err(_) => Ok(panic_result("delegate_task")),
                        }
                    }
                    "middleman_status" => {
                        let p = self.pipeline.clone();
                        match tokio::spawn(async move { p.status().await }).await {
                            Ok(mut v) => {
                                if let Some(m) = v.as_object_mut() {
                                    m.insert(
                                        "server".into(),
                                        json!({"version": env!("CARGO_PKG_VERSION"), "resumed": self.generation}),
                                    );
                                }
                                Ok(tool_result(&v, false))
                            }
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

    /// Serve until stdin closes. Requests are handled sequentially. Between requests (when no
    /// input is buffered) the binary on disk is watched; when an upgrade replaced it, the
    /// server re-executes the new one in place (unix), keeping the session.
    pub async fn run_stdio(self) -> anyhow::Result<()> {
        let stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let mut input = BufReader::new(stdin);
        let mut watch = reexec::Watch::start();
        if self.generation > 0 && tools_changed(std::env::var(TOOLS_ENV).ok().as_deref()) {
            let n = json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"});
            let mut s = serde_json::to_string(&n)?;
            s.push('\n');
            stdout.write_all(s.as_bytes()).await?;
            stdout.flush().await?;
        }
        loop {
            if input.buffer().is_empty() {
                if let Some(w) = watch.as_mut() {
                    // wait for input without reading it, so an exec loses nothing
                    loop {
                        let ready = w.wait_readable().await;
                        if let Some(path) = w.replaced() {
                            stdout.flush().await?;
                            let session = self.session.lock().ok().and_then(|s| s.clone());
                            let e = reexec::exec(&path, session, self.generation + 1);
                            tracing::warn!(error = %e, "re-exec failed; serving with this binary");
                        }
                        if ready {
                            break;
                        }
                    }
                }
            }
            let Some(next) = read_line_capped(&mut input, MAX_LINE_BYTES).await? else {
                break;
            };
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

/// Self re-exec after an upgrade replaced the binary (unix only).
mod reexec {
    use std::path::PathBuf;
    #[cfg(unix)]
    use std::time::{Duration, Instant};

    use serde_json::Value;

    #[cfg(unix)]
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct Sig {
        dev: u64,
        ino: u64,
        size: u64,
        mtime: i64,
        mtime_ns: i64,
    }

    #[cfg(unix)]
    fn sig(p: &std::path::Path) -> Option<Sig> {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata(p).ok()?;
        Some(Sig {
            dev: m.dev(),
            ino: m.ino(),
            size: m.size(),
            mtime: m.mtime(),
            mtime_ns: m.mtime_nsec(),
        })
    }

    pub struct Watch {
        #[cfg(unix)]
        path: PathBuf,
        #[cfg(unix)]
        seen: Sig,
        #[cfg(unix)]
        every: Duration,
        #[cfg(unix)]
        last: Instant,
    }

    impl Watch {
        /// None when re-exec is off or unsupported (Windows).
        pub fn start() -> Option<Watch> {
            #[cfg(unix)]
            {
                if std::env::var("MIDDLEMAN_MCP_NO_REEXEC").is_ok_and(|v| v == "1") {
                    return None;
                }
                let exe = std::env::current_exe().ok()?;
                let path = std::fs::canonicalize(&exe).unwrap_or(exe);
                let seen = sig(&path)?;
                let ms = std::env::var(super::CHECK_MS_ENV)
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(3000)
                    .clamp(50, 60_000);
                Some(Watch {
                    path,
                    seen,
                    every: Duration::from_millis(ms),
                    last: Instant::now(),
                })
            }
            #[cfg(not(unix))]
            None
        }

        /// Wait until stdin is readable (or EOF), at most one check interval. Nothing is read.
        pub async fn wait_readable(&self) -> bool {
            #[cfg(unix)]
            {
                let ms = self.every.as_millis().min(i32::MAX as u128) as i32;
                tokio::task::spawn_blocking(move || {
                    let mut fds = libc::pollfd {
                        fd: 0,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    // SAFETY: one valid pollfd for fd 0, count 1.
                    let n = unsafe { libc::poll(&mut fds, 1, ms) };
                    // an error or a hangup: let the read report it
                    n != 0
                })
                .await
                .unwrap_or(true)
            }
            #[cfg(not(unix))]
            true
        }

        /// The binary's path, when it was replaced by one that is safe to run (at most once
        /// per interval; a rejected file is not looked at again until it changes).
        pub fn replaced(&mut self) -> Option<PathBuf> {
            #[cfg(unix)]
            {
                if self.last.elapsed() < self.every {
                    return None;
                }
                self.last = Instant::now();
                let now = sig(&self.path)?;
                if now == self.seen {
                    return None;
                }
                self.seen = now;
                match safe_to_exec(&self.path) {
                    Ok(()) => Some(self.path.clone()),
                    Err(e) => {
                        tracing::warn!(error = %e, "the replaced binary is not used");
                        None
                    }
                }
            }
            #[cfg(not(unix))]
            None
        }
    }

    /// A regular file (not a link), owned by us, not group/world-writable, that answers
    /// `--version` like middleman.
    #[cfg(unix)]
    pub fn safe_to_exec(p: &std::path::Path) -> anyhow::Result<()> {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::symlink_metadata(p)?;
        anyhow::ensure!(m.file_type().is_file(), "not a regular file");
        // SAFETY: geteuid has no preconditions.
        let me = unsafe { libc::geteuid() };
        anyhow::ensure!(m.uid() == me, "owned by another user");
        anyhow::ensure!(m.mode() & 0o022 == 0, "group- or world-writable");
        crate::upgrade::binary_version(p)?;
        Ok(())
    }

    /// Replace this process with `path` (same args), passing the session. Returns only on
    /// failure.
    #[cfg(unix)]
    pub fn exec(
        path: &std::path::Path,
        session: Option<(String, Value)>,
        generation: u64,
    ) -> std::io::Error {
        use std::os::unix::process::CommandExt;
        let mut c = std::process::Command::new(path);
        c.args(std::env::args_os().skip(1))
            .env(super::RESUMED_ENV, "1")
            .env(super::GENERATION_ENV, generation.to_string())
            .env(super::TOOLS_ENV, super::tools_digest());
        match session {
            Some((proto, client)) => {
                c.env(super::PROTOCOL_ENV, proto)
                    .env(super::CLIENT_ENV, client.to_string());
            }
            None => {
                c.env_remove(super::PROTOCOL_ENV)
                    .env_remove(super::CLIENT_ENV);
            }
        }
        c.exec()
    }

    #[cfg(not(unix))]
    pub fn exec(
        _path: &std::path::Path,
        _session: Option<(String, Value)>,
        _generation: u64,
    ) -> std::io::Error {
        std::io::Error::other("re-exec is not supported here")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_list_change_detection() {
        assert!(!tools_changed(None));
        assert!(!tools_changed(Some(&tools_digest())));
        assert!(tools_changed(Some("an older list")));
    }

    #[cfg(unix)]
    #[test]
    fn exec_safety_checks() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("middleman");
        std::fs::write(&f, "#!/bin/sh\necho middleman 9.9.9\n").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        reexec::safe_to_exec(&f).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(reexec::safe_to_exec(&f).is_err(), "group-writable");
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        let l = d.path().join("link");
        std::os::unix::fs::symlink(&f, &l).unwrap();
        assert!(reexec::safe_to_exec(&l).is_err(), "a symlink");
        std::fs::write(&f, "#!/bin/sh\nexit 3\n").unwrap();
        assert!(reexec::safe_to_exec(&f).is_err(), "--version fails");
    }

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
