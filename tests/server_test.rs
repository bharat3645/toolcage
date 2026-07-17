use std::cell::RefCell;
use std::path::Path;

use serde_json::{json, Value};
use toolcage::audit::Auditor;
use toolcage::policy::{Grant, Policy};
use toolcage::runner::{
    CallOutcome, CallResult, CallStats, FailClass, ProbeResult, Runner, ToolDef,
};
use toolcage::server::Session;

struct FakeRunner {
    probe: ProbeResult,
    script: RefCell<Vec<CallResult>>,
    calls: RefCell<Vec<(String, Value)>>,
}

impl FakeRunner {
    fn new(tools: &[&str], script: Vec<CallResult>) -> FakeRunner {
        FakeRunner {
            probe: ProbeResult {
                tools: tools
                    .iter()
                    .map(|n| ToolDef {
                        name: n.to_string(),
                        raw: json!({
                            "name": n,
                            "description": format!("{} tool", n),
                            "inputSchema": { "type": "object" }
                        }),
                    })
                    .collect(),
                protocol: "2025-06-18".to_string(),
                truncated: false,
                server_info: json!({ "name": "fake", "version": "0.0.0" }),
                stats: CallStats::default(),
            },
            script: RefCell::new(script),
            calls: RefCell::new(calls_empty()),
        }
    }
}

fn calls_empty() -> Vec<(String, Value)> {
    Vec::new()
}

impl Runner for FakeRunner {
    fn probe(&self) -> &ProbeResult {
        &self.probe
    }
    fn call(&self, tool: &str, arguments: &Value, _grant: &Grant) -> CallResult {
        self.calls
            .borrow_mut()
            .push((tool.to_string(), arguments.clone()));
        self.script.borrow_mut().remove(0)
    }
}

fn ok_result(result: Value) -> CallResult {
    CallResult {
        outcome: CallOutcome::Completed {
            response: json!({ "jsonrpc": "2.0", "id": 2, "result": result }),
        },
        stats: CallStats {
            duration_ms: 5,
            fuel_used: Some(1000),
            stdout_bytes: 100,
            stderr_bytes: 0,
            garbage_lines: 0,
            exit_code: Some(0),
        },
    }
}

fn guest_error_result(error: Value) -> CallResult {
    CallResult {
        outcome: CallOutcome::Completed {
            response: json!({ "jsonrpc": "2.0", "id": 2, "error": error }),
        },
        stats: CallStats::default(),
    }
}

fn failed_result(class: FailClass) -> CallResult {
    CallResult {
        outcome: CallOutcome::Failed {
            class,
            detail: "test detail".to_string(),
        },
        stats: CallStats::default(),
    }
}

fn policy(yaml: &str) -> Policy {
    Policy::from_yaml_str(yaml, Path::new("/base"), None).unwrap()
}

/// Drive a session line by line; collect the response line (if any) per input.
fn drive(runner: &FakeRunner, pol: &Policy, audit: &Auditor, lines: &[&str]) -> Vec<Option<Value>> {
    let mut session = Session::new(runner, pol, audit);
    let mut out = Vec::new();
    for line in lines {
        let mut buf: Vec<u8> = Vec::new();
        session.handle_line(line, &mut buf);
        if buf.is_empty() {
            out.push(None);
        } else {
            let text = String::from_utf8(buf).unwrap();
            out.push(Some(serde_json::from_str(text.trim_end()).unwrap()));
        }
    }
    session.finish();
    out
}

const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#;
const INITIALIZED: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;

#[test]
fn initialize_negotiates_and_reports_serverinfo() {
    let r = FakeRunner::new(&["echo"], vec![]);
    let p = policy("version: 1\nunlisted_tools: defaults\n");
    let a = Auditor::to_memory();
    let out = drive(&r, &p, &a, &[INIT]);
    let resp = out[0].as_ref().unwrap();
    assert_eq!(resp["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(resp["result"]["serverInfo"]["name"], "toolcage");
    assert!(resp["result"]["capabilities"]["tools"].is_object());
}

#[test]
fn initialize_falls_back_on_unknown_protocol() {
    let r = FakeRunner::new(&["echo"], vec![]);
    let p = policy("version: 1\n");
    let a = Auditor::to_memory();
    let line = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1990-01-01"}}"#;
    let out = drive(&r, &p, &a, &[line]);
    assert_eq!(
        out[0].as_ref().unwrap()["result"]["protocolVersion"],
        "2025-06-18"
    );
}

#[test]
fn requests_before_initialized_are_rejected() {
    let r = FakeRunner::new(&["echo"], vec![]);
    let p = policy("version: 1\nunlisted_tools: defaults\n");
    let a = Auditor::to_memory();
    let list = r#"{"jsonrpc":"2.0","id":9,"method":"tools/list"}"#;
    let out = drive(&r, &p, &a, &[list, INIT, INITIALIZED, list]);
    assert_eq!(out[0].as_ref().unwrap()["error"]["code"], -32002);
    assert!(out[1].as_ref().unwrap().get("result").is_some());
    assert!(out[2].is_none(), "notification produces no reply");
    let tools = out[3].as_ref().unwrap()["result"]["tools"].clone();
    assert_eq!(tools.as_array().unwrap().len(), 1);
}

#[test]
fn ping_works_before_initialization() {
    let r = FakeRunner::new(&[], vec![]);
    let p = policy("version: 1\n");
    let a = Auditor::to_memory();
    let out = drive(&r, &p, &a, &[r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#]);
    assert!(out[0].as_ref().unwrap()["result"].is_object());
}

#[test]
fn tools_list_is_policy_filtered() {
    let r = FakeRunner::new(&["a", "b", "c"], vec![]);
    let p = policy("version: 1\ntools:\n  a:\n  b:\n    deny: true\n");
    let a = Auditor::to_memory();
    let list = r#"{"jsonrpc":"2.0","id":4,"method":"tools/list"}"#;
    let out = drive(&r, &p, &a, &[INIT, INITIALIZED, list]);
    let tools = out[2].as_ref().unwrap()["result"]["tools"].clone();
    let names: Vec<&str> = tools
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["a"], "denied and unlisted tools are hidden");
}

#[test]
fn tools_list_unlisted_defaults_mode_shows_unlisted() {
    let r = FakeRunner::new(&["a", "b"], vec![]);
    let p = policy("version: 1\nunlisted_tools: defaults\ntools:\n  b:\n    deny: true\n");
    let a = Auditor::to_memory();
    let list = r#"{"jsonrpc":"2.0","id":4,"method":"tools/list"}"#;
    let out = drive(&r, &p, &a, &[INIT, INITIALIZED, list]);
    let tools = out[2].as_ref().unwrap()["result"]["tools"].clone();
    let names: Vec<&str> = tools
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["a"]);
}

#[test]
fn allowed_call_passes_result_through_under_client_id() {
    let result = json!({ "content": [{ "type": "text", "text": "hi there" }] });
    let r = FakeRunner::new(&["echo"], vec![ok_result(result)]);
    let p = policy("version: 1\ntools:\n  echo:\n");
    let a = Auditor::to_memory();
    let call = r#"{"jsonrpc":"2.0","id":"client-77","method":"tools/call","params":{"name":"echo","arguments":{"text":"x"}}}"#;
    let out = drive(&r, &p, &a, &[INIT, INITIALIZED, call]);
    let resp = out[2].as_ref().unwrap();
    assert_eq!(resp["id"], "client-77", "client id echoed, guest id discarded");
    assert_eq!(resp["result"]["content"][0]["text"], "hi there");
    let calls = r.calls.borrow();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "echo");
    assert_eq!(calls[0].1["text"], "x");
}

#[test]
fn denied_tool_never_reaches_the_runner() {
    let r = FakeRunner::new(&["danger"], vec![]);
    let p = policy("version: 1\ntools:\n  danger:\n    deny: true\n");
    let a = Auditor::to_memory();
    let call = r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"danger","arguments":{}}}"#;
    let out = drive(&r, &p, &a, &[INIT, INITIALIZED, call]);
    let resp = out[2].as_ref().unwrap();
    assert_eq!(resp["error"]["code"], -32003);
    assert!(r.calls.borrow().is_empty(), "sandbox must not be invoked");
    let audit = a.memory_contents().unwrap();
    assert!(audit.contains("\"decision\":\"deny_policy\""));
}

#[test]
fn unlisted_tool_denied_with_distinct_decision() {
    let r = FakeRunner::new(&["mystery"], vec![]);
    let p = policy("version: 1\ntools:\n  other:\n");
    let a = Auditor::to_memory();
    let call =
        r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"mystery"}}"#;
    let out = drive(&r, &p, &a, &[INIT, INITIALIZED, call]);
    assert_eq!(out[2].as_ref().unwrap()["error"]["code"], -32003);
    let audit = a.memory_contents().unwrap();
    assert!(audit.contains("\"decision\":\"deny_unlisted\""));
}

#[test]
fn unknown_tool_is_invalid_params() {
    let r = FakeRunner::new(&["echo"], vec![]);
    let p = policy("version: 1\nunlisted_tools: defaults\n");
    let a = Auditor::to_memory();
    let call = r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"nope"}}"#;
    let out = drive(&r, &p, &a, &[INIT, INITIALIZED, call]);
    let resp = out[2].as_ref().unwrap();
    assert_eq!(resp["error"]["code"], -32602);
    assert!(resp["error"]["message"].as_str().unwrap().contains("nope"));
    assert!(r.calls.borrow().is_empty());
}

#[test]
fn guest_rpc_error_passes_through() {
    let r = FakeRunner::new(
        &["echo"],
        vec![guest_error_result(
            json!({ "code": -32602, "message": "guest says bad args" }),
        )],
    );
    let p = policy("version: 1\nunlisted_tools: defaults\n");
    let a = Auditor::to_memory();
    let call = r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"echo"}}"#;
    let out = drive(&r, &p, &a, &[INIT, INITIALIZED, call]);
    let resp = out[2].as_ref().unwrap();
    assert_eq!(resp["id"], 6);
    assert_eq!(resp["error"]["code"], -32602);
    assert_eq!(resp["error"]["message"], "guest says bad args");
}

#[test]
fn failed_outcomes_map_to_documented_codes() {
    let cases = [
        (FailClass::Timeout, -32005, "timeout"),
        (FailClass::CpuBudget, -32005, "cpu_budget"),
        (FailClass::OutputOverflow, -32005, "output_overflow"),
        (FailClass::GuestTrap, -32000, "guest_trap"),
        (FailClass::NoResponse, -32000, "no_response"),
    ];
    for (class, code, class_str) in cases {
        let r = FakeRunner::new(&["echo"], vec![failed_result(class)]);
        let p = policy("version: 1\nunlisted_tools: defaults\n");
        let a = Auditor::to_memory();
        let call = r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"echo"}}"#;
        let out = drive(&r, &p, &a, &[INIT, INITIALIZED, call]);
        let resp = out[2].as_ref().unwrap();
        assert_eq!(resp["error"]["code"], code);
        assert_eq!(resp["error"]["data"]["class"], class_str);
        let audit = a.memory_contents().unwrap();
        assert!(audit.contains(&format!("\"outcome\":\"{}\"", class_str)));
    }
}

#[test]
fn malformed_and_unparseable_lines() {
    let r = FakeRunner::new(&[], vec![]);
    let p = policy("version: 1\n");
    let a = Auditor::to_memory();
    let out = drive(
        &r,
        &p,
        &a,
        &[
            "{this is not json",
            r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"no/such"}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/unknown"}"#,
        ],
    );
    assert_eq!(out[0].as_ref().unwrap()["error"]["code"], -32700);
    assert!(out[0].as_ref().unwrap()["id"].is_null());
    assert_eq!(out[1].as_ref().unwrap()["error"]["code"], -32600);
    assert_eq!(out[2].as_ref().unwrap()["error"]["code"], -32601);
    assert!(out[3].is_none());
}

#[test]
fn audit_never_contains_arguments_or_results() {
    let secret_arg = "ARG_CANARY_e77b2f";
    let secret_result = "RESULT_CANARY_a91c44";
    let result = json!({ "content": [{ "type": "text", "text": secret_result }] });
    let r = FakeRunner::new(&["echo"], vec![ok_result(result)]);
    let p = policy("version: 1\nunlisted_tools: defaults\n");
    let a = Auditor::to_memory();
    let call = format!(
        r#"{{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{{"name":"echo","arguments":{{"text":"{}"}}}}}}"#,
        secret_arg
    );
    let _ = drive(&r, &p, &a, &[INIT, INITIALIZED, &call]);
    let audit = a.memory_contents().unwrap();
    assert!(audit.contains("\"event\":\"call\""));
    assert!(audit.contains("args_sha256"));
    assert!(audit.contains("result_sha256"));
    assert!(
        !audit.contains(secret_arg),
        "arguments must never be audited"
    );
    assert!(
        !audit.contains(secret_result),
        "results must never be audited"
    );
    // session_end written by finish()
    assert!(audit.contains("\"event\":\"session_end\""));
}

#[test]
fn call_with_missing_name_is_invalid_params() {
    let r = FakeRunner::new(&["echo"], vec![]);
    let p = policy("version: 1\n");
    let a = Auditor::to_memory();
    let call = r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{}}"#;
    let out = drive(&r, &p, &a, &[INIT, INITIALIZED, call]);
    assert_eq!(out[2].as_ref().unwrap()["error"]["code"], -32602);
}
