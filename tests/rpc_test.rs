use serde_json::{json, Value};
use toolcage::rpc::{
    self, error_line, error_object_line, extract_response, guest_transcript_call,
    guest_transcript_probe, negotiate_protocol, parse_line, result_line, Incoming,
};

#[test]
fn parse_request_with_number_id() {
    match parse_line(r#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#) {
        Incoming::Request { id, method, params } => {
            assert_eq!(id, json!(7));
            assert_eq!(method, "ping");
            assert!(params.is_null());
        }
        other => panic!("expected request, got {:?}", other),
    }
}

#[test]
fn parse_request_with_string_id_and_params() {
    match parse_line(r#"{"jsonrpc":"2.0","id":"abc","method":"tools/call","params":{"name":"x"}}"#)
    {
        Incoming::Request { id, method, params } => {
            assert_eq!(id, json!("abc"));
            assert_eq!(method, "tools/call");
            assert_eq!(params["name"], "x");
        }
        other => panic!("expected request, got {:?}", other),
    }
}

#[test]
fn parse_notification() {
    match parse_line(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#) {
        Incoming::Notification { method, .. } => assert_eq!(method, "notifications/initialized"),
        other => panic!("expected notification, got {:?}", other),
    }
}

#[test]
fn parse_rejects_batch_arrays() {
    match parse_line(r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#) {
        Incoming::Malformed { detail } => assert!(detail.contains("batch")),
        other => panic!("expected malformed, got {:?}", other),
    }
}

#[test]
fn parse_rejects_wrong_jsonrpc_version() {
    match parse_line(r#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#) {
        Incoming::Malformed { detail } => assert!(detail.contains("2.0")),
        other => panic!("expected malformed, got {:?}", other),
    }
}

#[test]
fn parse_rejects_missing_method() {
    match parse_line(r#"{"jsonrpc":"2.0","id":1}"#) {
        Incoming::Malformed { detail } => assert!(detail.contains("method")),
        other => panic!("expected malformed, got {:?}", other),
    }
}

#[test]
fn parse_error_on_bad_json() {
    match parse_line("{nope") {
        Incoming::ParseError { .. } => {}
        other => panic!("expected parse error, got {:?}", other),
    }
}

#[test]
fn result_and_error_lines_round_trip() {
    let r: Value = serde_json::from_str(&result_line(&json!("id-9"), json!({"ok":true}))).unwrap();
    assert_eq!(r["jsonrpc"], "2.0");
    assert_eq!(r["id"], "id-9");
    assert_eq!(r["result"]["ok"], true);

    let e: Value =
        serde_json::from_str(&error_line(&json!(3), -32003, "denied", Some(json!({"a":1}))))
            .unwrap();
    assert_eq!(e["id"], 3);
    assert_eq!(e["error"]["code"], -32003);
    assert_eq!(e["error"]["message"], "denied");
    assert_eq!(e["error"]["data"]["a"], 1);

    let e2: Value = serde_json::from_str(&error_line(&Value::Null, -32700, "parse", None)).unwrap();
    assert!(e2["id"].is_null());
    assert!(e2["error"].get("data").is_none());
}

#[test]
fn error_object_passthrough_keeps_guest_error() {
    let guest_err = json!({"code": -32602, "message": "bad args", "data": {"x": 1}});
    let e: Value = serde_json::from_str(&error_object_line(&json!(5), guest_err)).unwrap();
    assert_eq!(e["id"], 5);
    assert_eq!(e["error"]["code"], -32602);
    assert_eq!(e["error"]["data"]["x"], 1);
}

#[test]
fn negotiate_protocol_rules() {
    assert_eq!(negotiate_protocol(None), rpc::PROTOCOL_FALLBACK);
    assert_eq!(negotiate_protocol(Some("2024-11-05")), "2024-11-05");
    assert_eq!(negotiate_protocol(Some("2025-06-18")), "2025-06-18");
    assert_eq!(negotiate_protocol(Some("1999-01-01")), rpc::PROTOCOL_FALLBACK);
}

#[test]
fn probe_transcript_shape() {
    let t = guest_transcript_probe("2025-06-18");
    let text = String::from_utf8(t).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3);
    let init: Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(init["id"], 1);
    assert_eq!(init["method"], "initialize");
    assert_eq!(init["params"]["protocolVersion"], "2025-06-18");
    assert_eq!(init["params"]["clientInfo"]["name"], "toolcage");
    let notif: Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(notif["method"], "notifications/initialized");
    assert!(notif.get("id").is_none());
    let list: Value = serde_json::from_str(lines[2]).unwrap();
    assert_eq!(list["id"], 2);
    assert_eq!(list["method"], "tools/list");
}

#[test]
fn call_transcript_carries_tool_and_arguments() {
    let t = guest_transcript_call("2025-06-18", "read_file", &json!({"path": "/data/x.txt"}));
    let text = String::from_utf8(t).unwrap();
    let call: Value = serde_json::from_str(text.lines().nth(2).unwrap()).unwrap();
    assert_eq!(call["method"], "tools/call");
    assert_eq!(call["params"]["name"], "read_file");
    assert_eq!(call["params"]["arguments"]["path"], "/data/x.txt");
}

#[test]
fn call_transcript_null_arguments_becomes_empty_object() {
    let t = guest_transcript_call("2025-06-18", "echo", &Value::Null);
    let text = String::from_utf8(t).unwrap();
    let call: Value = serde_json::from_str(text.lines().nth(2).unwrap()).unwrap();
    assert!(call["params"]["arguments"].is_object());
}

#[test]
fn extract_finds_response_among_noise() {
    let stdout = concat!(
        "starting up...\n",
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-06-18\"}}\n",
        "\n",
        "not json either\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"content\":[]}}\r\n",
    )
    .as_bytes();
    let (resp, garbage, rpc_lines) = extract_response(stdout, 2);
    let resp = resp.expect("response found");
    assert_eq!(resp["id"], 2);
    assert!(resp["result"]["content"].as_array().unwrap().is_empty());
    assert_eq!(garbage, 2);
    assert_eq!(rpc_lines, 2);
}

#[test]
fn extract_ignores_requests_with_matching_id() {
    // A guest-issued REQUEST with id 2 (no result/error) must not be taken.
    let stdout = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"roots/list\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"ok\":1}}\n",
    )
    .as_bytes();
    let (resp, _, _) = extract_response(stdout, 2);
    assert_eq!(resp.unwrap()["result"]["ok"], 1);
}

#[test]
fn extract_first_match_wins() {
    let stdout = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"n\":1}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"n\":2}}\n",
    )
    .as_bytes();
    let (resp, _, _) = extract_response(stdout, 2);
    assert_eq!(resp.unwrap()["result"]["n"], 1);
}

#[test]
fn extract_none_when_absent() {
    let (resp, garbage, _) = extract_response(b"hello\n", 2);
    assert!(resp.is_none());
    assert_eq!(garbage, 1);
}

#[test]
fn extract_error_responses_count() {
    let stdout = b"{\"jsonrpc\":\"2.0\",\"id\":2,\"error\":{\"code\":-32602,\"message\":\"bad\"}}\n";
    let (resp, _, _) = extract_response(stdout, 2);
    assert_eq!(resp.unwrap()["error"]["code"], -32602);
}
