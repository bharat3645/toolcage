//! toy-server: a deliberately naive stdio MCP server used as the CI smoke
//! guest for toolcage. It reads newline-delimited JSON-RPC from stdin and
//! answers on stdout. Some tools are intentionally hostile (spin, shout) so
//! the sandbox has something real to contain.

use std::io::{self, BufRead, Write};
use std::sync::atomic::{AtomicU32, Ordering};

use serde_json::{json, Value};

// Module-global state. If toolcage truly gives every tools/call a fresh
// wasmtime Store (a fresh guest instance, fresh linear memory), this counter
// resets to 0 every call and every response is "1" - never "2", "3", ...
// Any leakage across calls would show up as a growing count.
static CALL_COUNTER: AtomicU32 = AtomicU32::new(0);

fn main() {
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                respond(&json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": { "code": -32700, "message": format!("parse error: {}", e) }
                }));
                continue;
            }
        };
        let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
        let id = msg.get("id").cloned();
        let params = msg.get("params").cloned().unwrap_or(Value::Null);
        match (method, id) {
            ("initialize", Some(id)) => {
                let protocol = params
                    .get("protocolVersion")
                    .and_then(Value::as_str)
                    .unwrap_or("2025-06-18")
                    .to_string();
                respond(&json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "protocolVersion": protocol,
                        "capabilities": { "tools": {} },
                        "serverInfo": { "name": "toy-server", "version": "0.1.0" }
                    }
                }));
            }
            ("ping", Some(id)) => respond(&json!({ "jsonrpc": "2.0", "id": id, "result": {} })),
            ("tools/list", Some(id)) => {
                respond(&json!({ "jsonrpc": "2.0", "id": id, "result": { "tools": tools() } }))
            }
            ("tools/call", Some(id)) => handle_call(&id, &params),
            (_, Some(id)) => respond(&json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32601, "message": format!("method not found: {}", method) }
            })),
            (_, None) => { /* notification: ignore */ }
        }
    }
}

fn tools() -> Value {
    json!([
        {
            "name": "echo",
            "description": "Echo the text argument back.",
            "inputSchema": { "type": "object", "properties": { "text": { "type": "string" } }, "required": ["text"] }
        },
        {
            "name": "read_file",
            "description": "Read a file by path and return its contents.",
            "inputSchema": { "type": "object", "properties": { "path": { "type": "string" } }, "required": ["path"] }
        },
        {
            "name": "write_file",
            "description": "Write text to a file by path.",
            "inputSchema": { "type": "object", "properties": { "path": { "type": "string" }, "text": { "type": "string" } }, "required": ["path", "text"] }
        },
        {
            "name": "env",
            "description": "Read an environment variable.",
            "inputSchema": { "type": "object", "properties": { "name": { "type": "string" } }, "required": ["name"] }
        },
        {
            "name": "spin",
            "description": "Hostile: burn CPU forever.",
            "inputSchema": { "type": "object" }
        },
        {
            "name": "shout",
            "description": "Hostile: emit megabytes of output.",
            "inputSchema": { "type": "object", "properties": { "mb": { "type": "integer" } } }
        },
        {
            "name": "counter",
            "description": "Increment a process-global counter and return its new value. Used to probe for state leakage across calls.",
            "inputSchema": { "type": "object" }
        }
    ])
}

fn handle_call(id: &Value, params: &Value) {
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let args = params.get("arguments").cloned().unwrap_or(json!({}));
    match name {
        "echo" => {
            let text = args.get("text").and_then(Value::as_str).unwrap_or("");
            text_result(id, false, &format!("echo: {}", text));
        }
        "read_file" => {
            let path = args.get("path").and_then(Value::as_str).unwrap_or("");
            match std::fs::read_to_string(path) {
                Ok(content) => text_result(id, false, &content),
                Err(e) => text_result(id, true, &format!("read error for {}: {}", path, e)),
            }
        }
        "write_file" => {
            let path = args.get("path").and_then(Value::as_str).unwrap_or("");
            let text = args.get("text").and_then(Value::as_str).unwrap_or("");
            match std::fs::write(path, text.as_bytes()) {
                Ok(()) => text_result(id, false, &format!("wrote {} bytes to {}", text.len(), path)),
                Err(e) => text_result(id, true, &format!("write error for {}: {}", path, e)),
            }
        }
        "env" => {
            let var = args.get("name").and_then(Value::as_str).unwrap_or("");
            match std::env::var(var) {
                Ok(v) => text_result(id, false, &format!("{}={}", var, v)),
                Err(_) => text_result(id, true, &format!("{} is not set", var)),
            }
        }
        "spin" => {
            let mut x: u64 = 0;
            loop {
                x = x.wrapping_add(1);
                std::hint::black_box(x);
            }
        }
        "shout" => {
            let mb = args.get("mb").and_then(Value::as_u64).unwrap_or(8) as usize;
            let big = "A".repeat(mb * 1024 * 1024);
            text_result(id, false, &big);
        }
        "counter" => {
            let n = CALL_COUNTER.fetch_add(1, Ordering::SeqCst) + 1;
            text_result(id, false, &n.to_string());
        }
        other => respond(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32602, "message": format!("unknown tool: {}", other) }
        })),
    }
}

fn text_result(id: &Value, is_error: bool, text: &str) {
    respond(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [{ "type": "text", "text": text }],
            "isError": is_error
        }
    }));
}

fn respond(v: &Value) {
    let mut stdout = io::stdout();
    let line = v.to_string();
    let _ = stdout.write_all(line.as_bytes());
    let _ = stdout.write_all(b"\n");
    let _ = stdout.flush();
}
