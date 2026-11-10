//! Line-delimited JSON-RPC 2.0 over stdin/stdout. stdout carries only protocol messages.

use serde_json::{json, Value};

pub const PARSE_ERROR: i64 = -32700;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;
pub const INTERNAL_ERROR: i64 = -32603;

#[derive(Debug)]
pub enum Incoming {
    Request {
        id: Value,
        method: String,
        params: Value,
    },
    Notification {
        method: String,
    },
    /// A response from the client (we never send requests) or garbage: reply with this error
    /// if it has an id, otherwise ignore.
    Invalid(Option<Value>),
}

pub fn parse_line(line: &str) -> Incoming {
    let v: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => return Incoming::Invalid(Some(error(Value::Null, PARSE_ERROR, "parse error"))),
    };
    let Some(obj) = v.as_object() else {
        return Incoming::Invalid(Some(error(
            Value::Null,
            INVALID_REQUEST,
            "expected a single JSON-RPC object (batches unsupported)",
        )));
    };
    let id = obj.get("id").cloned();
    let Some(method) = obj.get("method").and_then(|m| m.as_str()) else {
        // a response object or malformed request
        return match id {
            Some(_) if obj.contains_key("result") || obj.contains_key("error") => {
                Incoming::Invalid(None)
            }
            Some(id) => Incoming::Invalid(Some(error(id, INVALID_REQUEST, "missing method"))),
            None => Incoming::Invalid(None),
        };
    };
    let params = obj.get("params").cloned().unwrap_or(Value::Null);
    match id {
        Some(id) if !id.is_null() => Incoming::Request {
            id,
            method: method.to_string(),
            params,
        },
        _ => Incoming::Notification {
            method: method.to_string(),
        },
    }
}

pub fn response(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

pub fn error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_requests_and_notifications() {
        match parse_line(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#) {
            Incoming::Request { id, method, .. } => {
                assert_eq!(id, json!(1));
                assert_eq!(method, "ping");
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            parse_line(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#),
            Incoming::Notification { .. }
        ));
        assert!(matches!(parse_line("{nope"), Incoming::Invalid(Some(_))));
        assert!(matches!(parse_line("[1,2]"), Incoming::Invalid(Some(_))));
        assert!(matches!(
            parse_line(r#"{"jsonrpc":"2.0","id":3,"result":{}}"#),
            Incoming::Invalid(None)
        ));
    }
}
