//! Minimal JSON-RPC 2.0 + MCP message helpers.
//!
//! MCP stdio framing: one UTF-8 JSON object per line, newline-delimited,
//! on stdin/stdout. JSON-RPC batching was removed in MCP 2025-06-18, so
//! arrays are rejected outright.

use serde_json::{json, Map, Value};

pub const TOOLCAGE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Protocol revisions toolcage knows; newest first.
pub const SUPPORTED_PROTOCOLS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];
pub const PROTOCOL_FALLBACK: &str = "2025-06-18";

pub const CODE_GUEST_FAILED: i64 = -32000;
pub const CODE_NOT_INITIALIZED: i64 = -32002;
pub const CODE_POLICY_DENIED: i64 = -32003;
pub const CODE_BUDGET_EXCEEDED: i64 = -32005;
pub const CODE_INVALID_REQUEST: i64 = -32600;
pub const CODE_METHOD_NOT_FOUND: i64 = -32601;
pub const CODE_INVALID_PARAMS: i64 = -32602;
pub const CODE_PARSE_ERROR: i64 = -32700;

/// The request id toolcage uses for the payload message (tools/list or
/// tools/call) inside every guest transcript. The initialize handshake is
/// always id 1.
pub const GUEST_CALL_ID: u64 = 2;
pub const GUEST_INIT_ID: u64 = 1;

#[derive(Debug)]
pub enum Incoming {
    Request {
        id: Value,
        method: String,
        params: Value,
    },
    Notification {
        method: String,
        params: Value,
    },
    /// Valid JSON, but not a valid single JSON-RPC 2.0 message.
    Malformed { detail: String },
    /// Not valid JSON at all.
    ParseError { detail: String },
}

pub fn parse_line(line: &str) -> Incoming {
    let v: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            return Incoming::ParseError {
                detail: format!("invalid JSON: {}", e),
            }
        }
    };
    let obj = match v {
        Value::Array(_) => {
            return Incoming::Malformed {
                detail: "batch requests are not supported (removed in MCP 2025-06-18)".to_string(),
            }
        }
        Value::Object(o) => o,
        _ => {
            return Incoming::Malformed {
                detail: "expected a JSON object".to_string(),
            }
        }
    };
    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Incoming::Malformed {
            detail: "jsonrpc must be the string \"2.0\"".to_string(),
        };
    }
    let method = match obj.get("method").and_then(Value::as_str) {
        Some(m) => m.to_string(),
        None => {
            return Incoming::Malformed {
                detail: "method must be a string".to_string(),
            }
        }
    };
    let params = obj.get("params").cloned().unwrap_or(Value::Null);
    match obj.get("id") {
        Some(id) => Incoming::Request {
            id: id.clone(),
            method,
            params,
        },
        None => Incoming::Notification { method, params },
    }
}

// ---------------------------------------------------------------------------
// Outgoing message builders (no trailing newline; the writer adds it)
// ---------------------------------------------------------------------------

pub fn result_line(id: &Value, result: Value) -> String {
    let msg = json!({ "jsonrpc": "2.0", "id": id, "result": result });
    msg.to_string()
}

pub fn error_line(id: &Value, code: i64, message: &str, data: Option<Value>) -> String {
    let mut err = Map::new();
    err.insert("code".to_string(), json!(code));
    err.insert("message".to_string(), json!(message));
    if let Some(d) = data {
        err.insert("data".to_string(), d);
    }
    let msg = json!({ "jsonrpc": "2.0", "id": id, "error": Value::Object(err) });
    msg.to_string()
}

/// Pass a guest-produced JSON-RPC error object through under the client's id.
pub fn error_object_line(id: &Value, error: Value) -> String {
    let msg = json!({ "jsonrpc": "2.0", "id": id, "error": error });
    msg.to_string()
}

pub fn request_line(id: u64, method: &str, params: Value) -> String {
    let msg = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
    msg.to_string()
}

pub fn notification_line(method: &str) -> String {
    let msg = json!({ "jsonrpc": "2.0", "method": method });
    msg.to_string()
}

pub fn negotiate_protocol(requested: Option<&str>) -> &'static str {
    if let Some(r) = requested {
        for p in SUPPORTED_PROTOCOLS {
            if p == r {
                return p;
            }
        }
    }
    PROTOCOL_FALLBACK
}

// ---------------------------------------------------------------------------
// Guest transcripts
//
// Every guest instance runs to completion on a pre-built stdin transcript:
// initialize (id 1) -> notifications/initialized -> payload (id 2) -> EOF.
// ---------------------------------------------------------------------------

fn initialize_params(protocol: &str) -> Value {
    json!({
        "protocolVersion": protocol,
        "capabilities": {},
        "clientInfo": { "name": "toolcage", "version": TOOLCAGE_VERSION }
    })
}

pub fn guest_transcript_probe(protocol: &str) -> Vec<u8> {
    let lines = [
        request_line(GUEST_INIT_ID, "initialize", initialize_params(protocol)),
        notification_line("notifications/initialized"),
        request_line(GUEST_CALL_ID, "tools/list", json!({})),
    ];
    to_transcript(&lines)
}

pub fn guest_transcript_call(protocol: &str, tool: &str, arguments: &Value) -> Vec<u8> {
    let args = if arguments.is_null() {
        json!({})
    } else {
        arguments.clone()
    };
    let lines = [
        request_line(GUEST_INIT_ID, "initialize", initialize_params(protocol)),
        notification_line("notifications/initialized"),
        request_line(
            GUEST_CALL_ID,
            "tools/call",
            json!({ "name": tool, "arguments": args }),
        ),
    ];
    to_transcript(&lines)
}

fn to_transcript(lines: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for l in lines {
        out.extend_from_slice(l.as_bytes());
        out.push(b'\n');
    }
    out
}

/// Scan guest stdout for the JSON-RPC response with the wanted id.
///
/// Returns (response, garbage_lines, rpc_lines). Garbage lines are non-empty
/// lines that are not JSON objects; they are tolerated and counted so the
/// audit trail shows misbehaving-but-working servers. The first matching
/// response wins.
pub fn extract_response(stdout: &[u8], want_id: u64) -> (Option<Value>, u64, u64) {
    let mut found: Option<Value> = None;
    let mut garbage: u64 = 0;
    let mut rpc: u64 = 0;
    for raw_line in stdout.split(|b| *b == b'\n') {
        let line = trim_ascii(raw_line);
        if line.is_empty() {
            continue;
        }
        let parsed: Option<Value> = std::str::from_utf8(line)
            .ok()
            .and_then(|s| serde_json::from_str(s).ok());
        match parsed {
            Some(Value::Object(o)) => {
                rpc += 1;
                if found.is_none()
                    && o.get("id").and_then(Value::as_u64) == Some(want_id)
                    && (o.contains_key("result") || o.contains_key("error"))
                {
                    found = Some(Value::Object(o));
                }
            }
            _ => garbage += 1,
        }
    }
    (found, garbage, rpc)
}

fn trim_ascii(mut b: &[u8]) -> &[u8] {
    while let Some((first, rest)) = b.split_first() {
        if first.is_ascii_whitespace() {
            b = rest;
        } else {
            break;
        }
    }
    while let Some((last, rest)) = b.split_last() {
        if last.is_ascii_whitespace() {
            b = rest;
        } else {
            break;
        }
    }
    b
}
