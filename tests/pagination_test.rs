//! End-to-end pagination through the real `Session` loop: the client-facing
//! `tools/list` with cursors, driven over a `FakeRunner` so no wasm engine is
//! needed. Covers the empty list, single page, exact page boundaries, a full
//! multi-page walk, the security-critical "denied tools never appear on any
//! page" property, and rejection of invalid / tampered / expired cursors.

use std::path::Path;

use serde_json::{json, Value};
use toolcage::audit::Auditor;
use toolcage::policy::{Grant, Policy};
use toolcage::runner::{CallResult, CallStats, ProbeResult, Runner, ToolDef};
use toolcage::server::Session;

struct FakeRunner {
    probe: ProbeResult,
}

impl FakeRunner {
    fn new(tools: &[&str]) -> FakeRunner {
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
        }
    }
}

impl Runner for FakeRunner {
    fn probe(&self) -> &ProbeResult {
        &self.probe
    }
    fn call(&self, _tool: &str, _arguments: &Value, _grant: &Grant) -> CallResult {
        unreachable!("pagination tests never call a tool");
    }
}

fn policy(yaml: &str) -> Policy {
    Policy::from_yaml_str(yaml, Path::new("/base"), None).unwrap()
}

const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#;
const INITIALIZED: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;

fn send(session: &mut Session<'_, FakeRunner>, line: &str) -> Option<Value> {
    let mut buf: Vec<u8> = Vec::new();
    session.handle_line(line, &mut buf);
    if buf.is_empty() {
        None
    } else {
        let text = String::from_utf8(buf).unwrap();
        Some(serde_json::from_str(text.trim_end()).unwrap())
    }
}

fn list_request(cursor: Option<&str>) -> String {
    match cursor {
        Some(c) => format!(
            r#"{{"jsonrpc":"2.0","id":4,"method":"tools/list","params":{{"cursor":"{}"}}}}"#,
            c
        ),
        None => r#"{"jsonrpc":"2.0","id":4,"method":"tools/list"}"#.to_string(),
    }
}

/// Walk every page from the first, following `nextCursor`. Returns the tool
/// names in the order seen and the number of pages. Panics if any page is an
/// error or if the walk fails to terminate.
fn walk(session: &mut Session<'_, FakeRunner>) -> (Vec<String>, usize) {
    let mut cursor: Option<String> = None;
    let mut names = Vec::new();
    let mut pages = 0usize;
    loop {
        let resp = send(session, &list_request(cursor.as_deref())).unwrap();
        assert!(resp.get("error").is_none(), "unexpected error page: {resp}");
        let result = &resp["result"];
        for t in result["tools"].as_array().unwrap() {
            names.push(t["name"].as_str().unwrap().to_string());
        }
        pages += 1;
        assert!(pages < 100, "pagination must terminate");
        match result.get("nextCursor").and_then(Value::as_str) {
            Some(c) => cursor = Some(c.to_string()),
            None => return (names, pages),
        }
    }
}

fn all_names(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("t{i}")).collect()
}

// ---------------------------------------------------------------------------
// Edge cases: empty, single page, exact boundary, ragged walk
// ---------------------------------------------------------------------------

#[test]
fn empty_visible_list_is_one_empty_page() {
    let r = FakeRunner::new(&[]);
    let p = policy("version: 1\nunlisted_tools: defaults\n");
    let a = Auditor::to_memory();
    let mut s = Session::new_paginated(&r, &p, &a, 2, [9u8; 32]);
    send(&mut s, INIT);
    send(&mut s, INITIALIZED);
    let resp = send(&mut s, &list_request(None)).unwrap();
    assert_eq!(resp["result"]["tools"].as_array().unwrap().len(), 0);
    assert!(resp["result"].get("nextCursor").is_none());
}

#[test]
fn single_page_when_everything_fits() {
    let r = FakeRunner::new(&["a", "b"]);
    let p = policy("version: 1\nunlisted_tools: defaults\n");
    let a = Auditor::to_memory();
    // page_size 5 > 2 tools: one page, no cursor.
    let mut s = Session::new_paginated(&r, &p, &a, 5, [9u8; 32]);
    send(&mut s, INIT);
    send(&mut s, INITIALIZED);
    let resp = send(&mut s, &list_request(None)).unwrap();
    assert_eq!(resp["result"]["tools"].as_array().unwrap().len(), 2);
    assert!(
        resp["result"].get("nextCursor").is_none(),
        "no cursor when the whole list fits in one page"
    );
}

#[test]
fn exact_page_boundary_has_no_trailing_empty_page() {
    // 4 tools, page size 2 -> exactly two full pages, no empty third.
    let names = all_names(4);
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let r = FakeRunner::new(&refs);
    let p = policy("version: 1\nunlisted_tools: defaults\n");
    let a = Auditor::to_memory();
    let mut s = Session::new_paginated(&r, &p, &a, 2, [9u8; 32]);
    send(&mut s, INIT);
    send(&mut s, INITIALIZED);

    let p1 = send(&mut s, &list_request(None)).unwrap();
    assert_eq!(p1["result"]["tools"].as_array().unwrap().len(), 2);
    let c1 = p1["result"]["nextCursor"].as_str().unwrap().to_string();

    let p2 = send(&mut s, &list_request(Some(&c1))).unwrap();
    assert_eq!(p2["result"]["tools"].as_array().unwrap().len(), 2);
    assert!(
        p2["result"].get("nextCursor").is_none(),
        "second full page must not offer an empty third"
    );
}

#[test]
fn full_walk_yields_every_tool_once_in_order() {
    let names = all_names(5); // 2 + 2 + 1
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let r = FakeRunner::new(&refs);
    let p = policy("version: 1\nunlisted_tools: defaults\n");
    let a = Auditor::to_memory();
    let mut s = Session::new_paginated(&r, &p, &a, 2, [9u8; 32]);
    send(&mut s, INIT);
    send(&mut s, INITIALIZED);

    let (seen, pages) = walk(&mut s);
    assert_eq!(
        seen, names,
        "every tool exactly once, in stable probe order"
    );
    assert_eq!(pages, 3);
}

// ---------------------------------------------------------------------------
// Security: policy filtering composes with pagination
// ---------------------------------------------------------------------------

#[test]
fn denied_tools_never_appear_on_any_page() {
    // 6 tools; deny two of them. The denied names must be absent from every
    // page, and pagination must page over only the 4 visible ones.
    let r = FakeRunner::new(&["a", "secret1", "b", "c", "secret2", "d"]);
    let p = policy(
        "version: 1\n\
         unlisted_tools: defaults\n\
         tools:\n  secret1:\n    deny: true\n  secret2:\n    deny: true\n",
    );
    let a = Auditor::to_memory();
    let mut s = Session::new_paginated(&r, &p, &a, 2, [9u8; 32]);
    send(&mut s, INIT);
    send(&mut s, INITIALIZED);

    let (seen, pages) = walk(&mut s);
    assert_eq!(
        seen,
        vec!["a", "b", "c", "d"],
        "only visible tools, in order"
    );
    assert_eq!(pages, 2, "4 visible tools / page size 2");
    assert!(
        !seen.iter().any(|n| n.starts_with("secret")),
        "a denied tool must be unreachable from every page"
    );
}

#[test]
fn a_cursor_cannot_widen_the_visible_set() {
    // Sanity: even the last page's absence of a cursor is because the visible
    // set is exhausted, not truncated early. Deny all-but-one, expect one page.
    let r = FakeRunner::new(&["keep", "x", "y", "z"]);
    let p = policy(
        "version: 1\n\
         tools:\n  keep:\n  x:\n    deny: true\n  y:\n    deny: true\n  z:\n    deny: true\n",
    );
    let a = Auditor::to_memory();
    let mut s = Session::new_paginated(&r, &p, &a, 2, [9u8; 32]);
    send(&mut s, INIT);
    send(&mut s, INITIALIZED);
    let (seen, pages) = walk(&mut s);
    assert_eq!(seen, vec!["keep"]);
    assert_eq!(pages, 1);
}

// ---------------------------------------------------------------------------
// Cursor rejection: malformed / non-string / tampered / expired
// ---------------------------------------------------------------------------

#[test]
fn malformed_cursor_is_rejected() {
    let names = all_names(5);
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let r = FakeRunner::new(&refs);
    let p = policy("version: 1\nunlisted_tools: defaults\n");
    let a = Auditor::to_memory();
    let mut s = Session::new_paginated(&r, &p, &a, 2, [9u8; 32]);
    send(&mut s, INIT);
    send(&mut s, INITIALIZED);

    for bad in ["garbage", "tc1.", "tc1.!!!!", "xx.AAAA"] {
        let resp = send(&mut s, &list_request(Some(bad))).unwrap();
        assert_eq!(
            resp["error"]["code"], -32602,
            "cursor {bad:?} must be -32602"
        );
    }
    let audit = a.memory_contents().unwrap();
    assert!(audit.contains("\"outcome\":\"invalid_cursor\""));
}

#[test]
fn non_string_cursor_param_is_rejected() {
    let r = FakeRunner::new(&["a", "b", "c"]);
    let p = policy("version: 1\nunlisted_tools: defaults\n");
    let a = Auditor::to_memory();
    let mut s = Session::new_paginated(&r, &p, &a, 2, [9u8; 32]);
    send(&mut s, INIT);
    send(&mut s, INITIALIZED);
    let line = r#"{"jsonrpc":"2.0","id":4,"method":"tools/list","params":{"cursor":123}}"#;
    let resp = send(&mut s, line).unwrap();
    assert_eq!(resp["error"]["code"], -32602);
}

#[test]
fn tampered_cursor_is_rejected() {
    let names = all_names(5);
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let r = FakeRunner::new(&refs);
    let p = policy("version: 1\nunlisted_tools: defaults\n");
    let a = Auditor::to_memory();
    let mut s = Session::new_paginated(&r, &p, &a, 2, [9u8; 32]);
    send(&mut s, INIT);
    send(&mut s, INITIALIZED);

    let c = send(&mut s, &list_request(None)).unwrap()["result"]["nextCursor"]
        .as_str()
        .unwrap()
        .to_string();
    // Flip an interior base64 char (index 4 = first char after the "tc1."
    // prefix, part of the signed body). This stays a well-formed 28-byte
    // decode, so it exercises the MAC check specifically rather than the
    // base64/length guard.
    let mut chars: Vec<char> = c.chars().collect();
    chars[4] = if chars[4] == 'A' { 'B' } else { 'A' };
    let tampered: String = chars.into_iter().collect();

    let resp = send(&mut s, &list_request(Some(&tampered))).unwrap();
    assert_eq!(resp["error"]["code"], -32602);
    assert_eq!(resp["error"]["data"]["reason"], "bad_mac");
}

#[test]
fn expired_cursor_from_a_prior_process_is_rejected() {
    // A cursor minted by a session with a different per-process key (i.e. a
    // toolcage restart) must not validate against the new session.
    let names = all_names(5);
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let r = FakeRunner::new(&refs);
    let p = policy("version: 1\nunlisted_tools: defaults\n");

    // Old process: key A.
    let a_old = Auditor::to_memory();
    let mut old = Session::new_paginated(&r, &p, &a_old, 2, [1u8; 32]);
    send(&mut old, INIT);
    send(&mut old, INITIALIZED);
    let stale = send(&mut old, &list_request(None)).unwrap()["result"]["nextCursor"]
        .as_str()
        .unwrap()
        .to_string();

    // New process: same tools, different key B.
    let a_new = Auditor::to_memory();
    let mut new = Session::new_paginated(&r, &p, &a_new, 2, [2u8; 32]);
    send(&mut new, INIT);
    send(&mut new, INITIALIZED);
    let resp = send(&mut new, &list_request(Some(&stale))).unwrap();
    assert_eq!(resp["error"]["code"], -32602);
    assert_eq!(resp["error"]["data"]["reason"], "bad_mac");
}

#[test]
fn cursor_bound_to_a_changed_tool_set_is_rejected() {
    // Same key, but the visible tool set differs between the minting and
    // redeeming sessions -> snapshot mismatch.
    let p = policy("version: 1\nunlisted_tools: defaults\n");
    let names_a = all_names(5);
    let refs_a: Vec<&str> = names_a.iter().map(String::as_str).collect();
    let r_a = FakeRunner::new(&refs_a);
    let aud_a = Auditor::to_memory();
    let mut sa = Session::new_paginated(&r_a, &p, &aud_a, 2, [7u8; 32]);
    send(&mut sa, INIT);
    send(&mut sa, INITIALIZED);
    let cursor = send(&mut sa, &list_request(None)).unwrap()["result"]["nextCursor"]
        .as_str()
        .unwrap()
        .to_string();

    let names_b = all_names(6); // different set
    let refs_b: Vec<&str> = names_b.iter().map(String::as_str).collect();
    let r_b = FakeRunner::new(&refs_b);
    let aud_b = Auditor::to_memory();
    let mut sb = Session::new_paginated(&r_b, &p, &aud_b, 2, [7u8; 32]);
    send(&mut sb, INIT);
    send(&mut sb, INITIALIZED);
    let resp = send(&mut sb, &list_request(Some(&cursor))).unwrap();
    assert_eq!(resp["error"]["code"], -32602);
    assert_eq!(resp["error"]["data"]["reason"], "snapshot_mismatch");
}

// ---------------------------------------------------------------------------
// Backward compatibility: pagination disabled (page_size 0)
// ---------------------------------------------------------------------------

#[test]
fn disabled_pagination_returns_all_tools_without_a_cursor() {
    let names = all_names(50);
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let r = FakeRunner::new(&refs);
    let p = policy("version: 1\nunlisted_tools: defaults\n");
    let a = Auditor::to_memory();
    // Session::new is the disabled path (page_size 0); assert it matches.
    let mut s = Session::new(&r, &p, &a);
    send(&mut s, INIT);
    send(&mut s, INITIALIZED);
    let resp = send(&mut s, &list_request(None)).unwrap();
    assert_eq!(resp["result"]["tools"].as_array().unwrap().len(), 50);
    assert!(
        resp["result"].get("nextCursor").is_none(),
        "disabled pagination never emits a cursor"
    );
}

#[test]
fn disabled_pagination_ignores_a_stray_cursor() {
    let r = FakeRunner::new(&["a", "b", "c"]);
    let p = policy("version: 1\nunlisted_tools: defaults\n");
    let a = Auditor::to_memory();
    let mut s = Session::new(&r, &p, &a);
    send(&mut s, INIT);
    send(&mut s, INITIALIZED);
    // A cursor with pagination off is ignored (old behavior: unknown params
    // ignored), returning the full list rather than an error.
    let resp = send(&mut s, &list_request(Some("tc1.anything"))).unwrap();
    assert_eq!(resp["result"]["tools"].as_array().unwrap().len(), 3);
    assert!(resp["result"].get("nextCursor").is_none());
}

// ---------------------------------------------------------------------------
// Audit trail records paging without leaking anything
// ---------------------------------------------------------------------------

#[test]
fn audit_records_page_metadata() {
    let names = all_names(3);
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let r = FakeRunner::new(&refs);
    let p = policy("version: 1\nunlisted_tools: defaults\n");
    let a = Auditor::to_memory();
    let mut s = Session::new_paginated(&r, &p, &a, 2, [9u8; 32]);
    send(&mut s, INIT);
    send(&mut s, INITIALIZED);
    walk(&mut s);
    let audit = a.memory_contents().unwrap();
    assert!(audit.contains("\"event\":\"tools_list\""));
    assert!(audit.contains("\"total_visible\":3"));
    assert!(audit.contains("\"has_next\":true"));
    assert!(audit.contains("\"paginated\":true"));
}
