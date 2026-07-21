//! The client-facing stdio MCP server loop.
//!
//! Generic over `Runner` so the whole protocol surface is unit-testable
//! without a wasm engine. One line in, at most one line out.

use std::io::Write;
use std::time::Instant;

use serde_json::{json, Map, Value};

use crate::audit::{fields, sha256_hex, Auditor};
use crate::paginate::Paginator;
use crate::policy::{Decision, Policy};
use crate::rpc::{self, Incoming};
use crate::runner::{CallOutcome, Runner, ToolDef};

pub struct Session<'a, R: Runner> {
    runner: &'a R,
    policy: &'a Policy,
    audit: &'a Auditor,
    initialized: bool,
    calls: u64,
    started: Instant,
    /// Tools per `tools/list` page; `0` disables pagination (one unlimited
    /// page, no cursor ever emitted — the pre-pagination behavior).
    page_size: usize,
    /// Per-process ephemeral key that authenticates the cursors this session
    /// mints. Zeroed when pagination is disabled (no cursor is ever signed).
    cursor_key: [u8; 32],
}

impl<'a, R: Runner> Session<'a, R> {
    /// A session with pagination disabled: `tools/list` returns every visible
    /// tool in one page, exactly as before pagination existed.
    pub fn new(runner: &'a R, policy: &'a Policy, audit: &'a Auditor) -> Self {
        Session::new_paginated(runner, policy, audit, 0, [0u8; 32])
    }

    /// A session that paginates `tools/list` into pages of `page_size` tools
    /// (0 disables), minting cursors signed with `cursor_key`.
    pub fn new_paginated(
        runner: &'a R,
        policy: &'a Policy,
        audit: &'a Auditor,
        page_size: usize,
        cursor_key: [u8; 32],
    ) -> Self {
        Session {
            runner,
            policy,
            audit,
            initialized: false,
            calls: 0,
            started: Instant::now(),
            page_size,
            cursor_key,
        }
    }

    /// Handle one input line, writing at most one response line to `out`.
    pub fn handle_line(&mut self, line: &str, out: &mut impl Write) {
        if line.trim().is_empty() {
            return;
        }
        let reply = match rpc::parse_line(line) {
            Incoming::ParseError { detail } => Some(rpc::error_line(
                &Value::Null,
                rpc::CODE_PARSE_ERROR,
                "parse error",
                Some(json!({ "detail": detail })),
            )),
            Incoming::Malformed { detail } => Some(rpc::error_line(
                &Value::Null,
                rpc::CODE_INVALID_REQUEST,
                &detail,
                None,
            )),
            Incoming::Notification { method, .. } => {
                if method == "notifications/initialized" {
                    self.initialized = true;
                }
                None
            }
            Incoming::Request { id, method, params } => {
                Some(self.handle_request(&id, &method, &params))
            }
        };
        if let Some(r) = reply {
            let _ = out.write_all(r.as_bytes());
            let _ = out.write_all(b"\n");
            let _ = out.flush();
        }
    }

    fn handle_request(&mut self, id: &Value, method: &str, params: &Value) -> String {
        match method {
            "initialize" => {
                let requested = params
                    .get("protocolVersion")
                    .and_then(Value::as_str);
                let protocol = rpc::negotiate_protocol(requested);
                self.audit.log(
                    "client_initialize",
                    fields(json!({ "protocol": protocol, "requested": requested })),
                );
                rpc::result_line(
                    id,
                    json!({
                        "protocolVersion": protocol,
                        "capabilities": { "tools": {} },
                        "serverInfo": {
                            "name": "toolcage",
                            "version": rpc::TOOLCAGE_VERSION
                        }
                    }),
                )
            }
            "ping" => rpc::result_line(id, json!({})),
            "tools/list" => {
                if !self.initialized {
                    return self.not_initialized(id);
                }
                self.handle_list(id, params)
            }
            "tools/call" => {
                if !self.initialized {
                    return self.not_initialized(id);
                }
                self.handle_call(id, params)
            }
            _ => rpc::error_line(
                id,
                rpc::CODE_METHOD_NOT_FOUND,
                &format!("method not found: {}", method),
                None,
            ),
        }
    }

    fn not_initialized(&self, id: &Value) -> String {
        rpc::error_line(
            id,
            rpc::CODE_NOT_INITIALIZED,
            "server not initialized (send initialize, then notifications/initialized)",
            None,
        )
    }

    /// The probed tools this policy lets the client see, in stable probe
    /// order. Filtering happens here, before any paging, so a denied tool is
    /// unreachable from every page and every cursor value.
    fn visible_tool_defs(&self) -> Vec<&ToolDef> {
        self.runner
            .probe()
            .tools
            .iter()
            .filter(|t| self.policy.visible(&t.name))
            .collect()
    }

    /// `tools/list`, optionally paginated. The full visible set is filtered
    /// first; the requested page is then sliced from it and, if more tools
    /// remain, an opaque authenticated `nextCursor` is attached.
    fn handle_list(&self, id: &Value, params: &Value) -> String {
        let cursor = match params.get("cursor") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.as_str()),
            Some(_) => {
                self.audit.log(
                    "tools_list",
                    fields(json!({ "outcome": "invalid_cursor", "reason": "not_a_string" })),
                );
                return rpc::error_line(
                    id,
                    rpc::CODE_INVALID_PARAMS,
                    "tools/list cursor must be a string",
                    None,
                );
            }
        };

        let visible = self.visible_tool_defs();
        let names: Vec<&str> = visible.iter().map(|t| t.name.as_str()).collect();
        let paginator = Paginator::new(self.cursor_key, &names, self.page_size);

        let page = match paginator.page(cursor) {
            Ok(p) => p,
            Err(e) => {
                self.audit.log(
                    "tools_list",
                    fields(json!({ "outcome": "invalid_cursor", "reason": e.as_str() })),
                );
                return rpc::error_line(
                    id,
                    rpc::CODE_INVALID_PARAMS,
                    "invalid or expired tools/list cursor",
                    Some(json!({ "reason": e.as_str() })),
                );
            }
        };

        let tools: Vec<Value> = visible[page.start..page.end]
            .iter()
            .map(|t| t.raw.clone())
            .collect();
        let mut result = Map::new();
        result.insert("tools".to_string(), Value::Array(tools));
        if let Some(next) = &page.next_cursor {
            result.insert("nextCursor".to_string(), json!(next));
        }

        self.audit.log(
            "tools_list",
            fields(json!({
                "outcome": "ok",
                "total_visible": paginator.total(),
                "page_start": page.start,
                "page_len": page.end - page.start,
                "has_next": page.next_cursor.is_some(),
                "paginated": self.page_size > 0,
            })),
        );
        rpc::result_line(id, Value::Object(result))
    }

    fn handle_call(&mut self, id: &Value, params: &Value) -> String {
        let name = match params.get("name").and_then(Value::as_str) {
            Some(n) => n.to_string(),
            None => {
                return rpc::error_line(
                    id,
                    rpc::CODE_INVALID_PARAMS,
                    "tools/call requires a string params.name",
                    None,
                )
            }
        };
        let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);
        let args_bytes = serde_json::to_vec(&arguments).unwrap_or_default();
        self.calls += 1;

        let known = self.runner.probe().tools.iter().any(|t| t.name == name);
        if !known {
            self.audit.log(
                "call",
                fields(json!({
                    "tool": name,
                    "decision": "deny_unknown_tool",
                    "args_bytes": args_bytes.len(),
                    "args_sha256": sha256_hex(&args_bytes),
                })),
            );
            return rpc::error_line(
                id,
                rpc::CODE_INVALID_PARAMS,
                &format!("unknown tool: {}", name),
                None,
            );
        }

        let grant = match self.policy.decide(&name) {
            Decision::Deny { reason, listed } => {
                let decision = if listed { "deny_policy" } else { "deny_unlisted" };
                self.audit.log(
                    "call",
                    fields(json!({
                        "tool": name,
                        "decision": decision,
                        "args_bytes": args_bytes.len(),
                        "args_sha256": sha256_hex(&args_bytes),
                    })),
                );
                return rpc::error_line(id, rpc::CODE_POLICY_DENIED, &reason, None);
            }
            Decision::Allow(g) => g,
        };

        let result = self.runner.call(&name, &arguments, &grant);
        let stats = &result.stats;
        let mut audit_fields = fields(json!({
            "tool": name,
            "decision": "allow",
            "args_bytes": args_bytes.len(),
            "args_sha256": sha256_hex(&args_bytes),
            "duration_ms": stats.duration_ms,
            "stdout_bytes": stats.stdout_bytes,
            "stderr_bytes": stats.stderr_bytes,
            "garbage_lines": stats.garbage_lines,
            "timeout_ms": grant.limits.timeout_ms,
            "mounts": grant
                .mounts
                .iter()
                .map(|m| format!("{}:{}", m.guest_path, m.mode.as_str()))
                .collect::<Vec<_>>(),
        }));
        if let Some(f) = stats.fuel_used {
            audit_fields.insert("fuel_used".to_string(), json!(f));
        }
        if let Some(c) = stats.exit_code {
            audit_fields.insert("exit_code".to_string(), json!(c));
        }

        let reply = match result.outcome {
            CallOutcome::Completed { response } => {
                if let Some(guest_result) = response.get("result") {
                    let result_bytes = serde_json::to_vec(guest_result).unwrap_or_default();
                    let is_error = guest_result
                        .get("isError")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    audit_fields.insert("outcome".to_string(), json!("ok"));
                    audit_fields.insert("is_error".to_string(), json!(is_error));
                    audit_fields.insert("result_bytes".to_string(), json!(result_bytes.len()));
                    audit_fields
                        .insert("result_sha256".to_string(), json!(sha256_hex(&result_bytes)));
                    rpc::result_line(id, guest_result.clone())
                } else if let Some(guest_error) = response.get("error") {
                    audit_fields.insert("outcome".to_string(), json!("guest_rpc_error"));
                    audit_fields.insert(
                        "guest_error_code".to_string(),
                        guest_error.get("code").cloned().unwrap_or(Value::Null),
                    );
                    rpc::error_object_line(id, guest_error.clone())
                } else {
                    audit_fields.insert("outcome".to_string(), json!("invalid_guest_response"));
                    rpc::error_line(
                        id,
                        rpc::CODE_GUEST_FAILED,
                        "guest response had neither result nor error",
                        None,
                    )
                }
            }
            CallOutcome::Failed { class, detail } => {
                audit_fields.insert("outcome".to_string(), json!(class.as_str()));
                rpc::error_line(
                    id,
                    class.code(),
                    class.message(),
                    Some(json!({ "class": class.as_str(), "detail": detail })),
                )
            }
        };
        self.audit.log("call", audit_fields);
        reply
    }

    /// Call at EOF.
    pub fn finish(&mut self) {
        self.audit.log(
            "session_end",
            fields(json!({
                "calls": self.calls,
                "duration_ms": self.started.elapsed().as_millis() as u64,
            })),
        );
    }
}
