//! MCP stdio: initialize, tools/list, tools/call dry run; stdout is pure JSON-RPC.
//! Also the CLI `check` and `route --hook` contracts.

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use assert_cmd::assert::OutputAssertExt;
use serde_json::{json, Value};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_middleman"))
}

#[test]
fn mcp_session_over_stdio() {
    // provider points at a closed local port: only dry runs are exercised, nothing listens
    let e = common::env("http://127.0.0.1:9/v1", "openai", "S1", "");
    let mut child = bin()
        .args(["mcp", "--config"])
        .arg(&e.cfg_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let msgs = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        json!({"jsonrpc":"2.0","id":3,"method":"ping"}),
        json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"delegate_task","arguments":{
            "task_kind":"docstring","instructions":"Add docstrings.","declared_sensitivity":"internal","dry_run":true,
            "files":[{"path":"src/invoice.py"}]}}}),
        json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"delegate_task","arguments":{
            "task_kind":"docstring","instructions":"x","declared_sensitivity":"internal","files":[{"path":"config/settings.py"}]}}}),
        json!({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"delegate_task","arguments":{"bogus":1}}}),
        json!({"jsonrpc":"2.0","id":7,"method":"resources/list"}),
    ];
    {
        let stdin = child.stdin.as_mut().unwrap();
        for m in &msgs {
            writeln!(stdin, "{m}").unwrap();
        }
        writeln!(stdin, "{{not json").unwrap();
    }
    drop(child.stdin.take());
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let replies: Vec<Value> = stdout
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|_| panic!("non-JSON on stdout: {l}")))
        .collect();
    // 7 requests with ids + 1 parse error; the notification gets no reply
    assert_eq!(replies.len(), 8, "{stdout}");
    for r in &replies {
        assert_eq!(r["jsonrpc"], "2.0");
    }
    let by_id = |id: i64| replies.iter().find(|r| r["id"] == json!(id)).unwrap();
    assert_eq!(by_id(1)["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(by_id(1)["result"]["serverInfo"]["name"], "middleman");
    let tools = by_id(2)["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names, vec!["delegate_task", "middleman_status"]);
    assert_eq!(by_id(3)["result"], json!({}));

    let dry: Value =
        serde_json::from_str(by_id(4)["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(dry["dry_run"], true);
    let user = dry["sanitized_payload"]["user"].as_str().unwrap();
    assert!(!user.to_lowercase().contains("acme"), "{user}");

    let blocked: Value =
        serde_json::from_str(by_id(5)["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(blocked["status"], "blocked");
    assert!(!blocked.to_string().contains("AKIA"));

    assert_eq!(by_id(6)["result"]["isError"], true);
    assert_eq!(by_id(7)["error"]["code"], -32601);
    assert!(replies.iter().any(|r| r["error"]["code"] == -32700));
}

#[test]
fn check_command_shows_zero_originals() {
    let e = common::env("http://127.0.0.1:9/v1", "openai", "S2", "");
    let out = bin()
        .args(["check", "--config"])
        .arg(&e.cfg_path)
        .arg(common::fixtures().join("src/billing.py"))
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout.clone()).unwrap();
    out.assert().success();
    assert!(text.contains("egress gate: passed"));
    let json_part = &text[..text.rfind("\negress gate").unwrap()];
    let v: Value = serde_json::from_str(json_part).unwrap();
    let user = v["sanitized_payload"]["user"].as_str().unwrap();
    for orig in ["acme", "Acme", "10.20.30.40", "janedoe", "jane.doe"] {
        assert!(!user.contains(orig), "{orig} in {user}");
    }
    // secrets fixture: blocked, exit 3
    bin()
        .args(["check", "--config"])
        .arg(&e.cfg_path)
        .arg(common::fixtures().join("config/settings.py"))
        .assert()
        .code(3);
}

#[test]
fn route_hook_always_exits_zero() {
    let e = common::env("http://127.0.0.1:9/v1", "openai", "S1", "");
    let run = |input: &str, cfg: &std::path::Path| {
        let mut c = bin()
            .args(["route", "--hook", "--config"])
            .arg(cfg)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        c.stdin
            .as_mut()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        drop(c.stdin.take());
        c.wait_with_output().unwrap()
    };
    let o = run(
        r#"{"prompt":"write unit tests for zorblax_discount","hook_event_name":"UserPromptSubmit"}"#,
        &e.cfg_path,
    );
    assert!(o.status.success());
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    let ctx = v["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap();
    assert!(
        ctx.contains("delegable") && ctx.contains("dictionary"),
        "{ctx}"
    );
    for garbage in ["", "nope", "{\"prompt\": 5}"] {
        let o = run(garbage, &e.cfg_path);
        assert!(o.status.success());
        assert!(o.stdout.is_empty());
    }
    // broken config still exits 0
    let o = run(
        r#"{"prompt":"write unit tests"}"#,
        std::path::Path::new("/nonexistent/config.toml"),
    );
    assert!(o.status.success());
}
