//! After an upgrade replaces the binary under a running `middleman mcp`, the server re-executes
//! the new file in place: the session survives (no /mcp needed) and the new process answers.
#![cfg(unix)]

mod common;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

fn status_server(line: &str) -> Value {
    let r: Value = serde_json::from_str(line).unwrap();
    let text = r["result"]["content"][0]["text"].as_str().unwrap();
    let v: Value = serde_json::from_str(text).unwrap();
    v["server"].clone()
}

#[test]
fn swapped_binary_takes_over_the_session() {
    let e = common::env("http://127.0.0.1:9/v1", "openai", "S1", "");
    let d = tempfile::tempdir().unwrap();
    let exe = d.path().canonicalize().unwrap().join("middleman");
    std::fs::copy(env!("CARGO_BIN_EXE_middleman"), &exe).unwrap();
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();

    let mut child = Command::new(&exe)
        .args(["mcp", "--config"])
        .arg(&e.cfg_path)
        .env("MIDDLEMAN_MCP_RELOAD_CHECK_MS", "100")
        .env_remove("MIDDLEMAN_MCP_NO_REEXEC")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid = child.id();
    let mut stdin = child.stdin.take().unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut read = || {
        let mut l = String::new();
        out.read_line(&mut l).unwrap();
        assert!(!l.is_empty(), "the server closed stdout");
        l
    };
    let mut send = |v: Value| writeln!(stdin, "{v}").unwrap();

    send(
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}),
    );
    let init: Value = serde_json::from_str(&read()).unwrap();
    assert_eq!(init["result"]["capabilities"]["tools"]["listChanged"], true);
    send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    send(
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"middleman_status","arguments":{}}}),
    );
    assert_eq!(status_server(&read())["resumed"], 0, "the original process");

    // the "upgrade": a new file (new inode) renamed over the old one, as install does
    let staged = exe.with_file_name(".middleman.new");
    std::fs::copy(env!("CARGO_BIN_EXE_middleman"), &staged).unwrap();
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::rename(&staged, &exe).unwrap();
    // let the idle server notice (it checks every 100 ms while waiting for input)
    let start = Instant::now();
    std::thread::sleep(Duration::from_millis(600));

    send(
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"middleman_status","arguments":{}}}),
    );
    let line = read();
    let r: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(r["id"], 3, "{line}");
    assert_eq!(
        status_server(&line)["resumed"],
        1,
        "answered by the re-executed binary: {line}"
    );
    // still initialized: tools/list works without a new handshake, same process id
    send(json!({"jsonrpc":"2.0","id":4,"method":"tools/list"}));
    let l: Value = serde_json::from_str(&read()).unwrap();
    assert_eq!(l["result"]["tools"].as_array().unwrap().len(), 2);
    assert_eq!(child.id(), pid);
    assert!(start.elapsed() < Duration::from_secs(60));

    // a replacement that is not safe to run (world-writable) is ignored
    let staged = exe.with_file_name(".middleman.bad");
    std::fs::copy(env!("CARGO_BIN_EXE_middleman"), &staged).unwrap();
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o777)).unwrap();
    std::fs::rename(&staged, &exe).unwrap();
    std::thread::sleep(Duration::from_millis(400));
    send(
        json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"middleman_status","arguments":{}}}),
    );
    assert_eq!(status_server(&read())["resumed"], 1, "kept serving");

    drop(send);
    let _ = child.kill();
    let _ = child.wait();
}
