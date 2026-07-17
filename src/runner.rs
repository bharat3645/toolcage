//! The Runner abstraction: something that can list tools and execute one
//! tool call. The production implementation is `sandbox::WasmRunner`; tests
//! drive the server loop with a fake.

use serde_json::Value;

use crate::rpc;

#[derive(Debug, Clone)]
pub struct ToolDef {
    pub name: String,
    /// The full tool object as the guest declared it (schema included),
    /// re-served verbatim to the client for visible tools.
    pub raw: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailClass {
    /// Wall-clock budget exceeded (epoch deadline or join timeout).
    Timeout,
    /// Fuel (CPU instruction budget) exhausted.
    CpuBudget,
    /// Guest stdout exceeded output_max_kb.
    OutputOverflow,
    /// Guest trapped (wasm trap, including memory-limit allocation aborts).
    GuestTrap,
    /// Guest exited with a non-zero code before answering.
    GuestExit,
    /// Guest exited cleanly but never answered the call.
    NoResponse,
    /// Host-side failure (preopen missing, engine error).
    Internal,
}

impl FailClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            FailClass::Timeout => "timeout",
            FailClass::CpuBudget => "cpu_budget",
            FailClass::OutputOverflow => "output_overflow",
            FailClass::GuestTrap => "guest_trap",
            FailClass::GuestExit => "guest_exit",
            FailClass::NoResponse => "no_response",
            FailClass::Internal => "internal",
        }
    }

    pub fn code(&self) -> i64 {
        match self {
            FailClass::Timeout | FailClass::CpuBudget | FailClass::OutputOverflow => {
                rpc::CODE_BUDGET_EXCEEDED
            }
            _ => rpc::CODE_GUEST_FAILED,
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            FailClass::Timeout => "tool call exceeded its wall-clock budget",
            FailClass::CpuBudget => "tool call exhausted its CPU (fuel) budget",
            FailClass::OutputOverflow => "tool call exceeded its output budget",
            FailClass::GuestTrap => "guest trapped during the tool call",
            FailClass::GuestExit => "guest exited without answering the tool call",
            FailClass::NoResponse => "guest completed without answering the tool call",
            FailClass::Internal => "toolcage host error during the tool call",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CallStats {
    pub duration_ms: u64,
    pub fuel_used: Option<u64>,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub garbage_lines: u64,
    pub exit_code: Option<i32>,
}

#[derive(Debug)]
pub enum CallOutcome {
    /// The guest produced a JSON-RPC response (result or error) for the call.
    Completed { response: Value },
    Failed { class: FailClass, detail: String },
}

#[derive(Debug)]
pub struct CallResult {
    pub outcome: CallOutcome,
    pub stats: CallStats,
}

#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub tools: Vec<ToolDef>,
    /// Protocol version the guest agreed to during the probe handshake;
    /// reused for every per-call handshake.
    pub protocol: String,
    /// True if the guest paginated its tool listing (nextCursor present).
    /// v0.1 reads only the first page; this is surfaced honestly.
    pub truncated: bool,
    pub server_info: Value,
    pub stats: CallStats,
}

pub trait Runner {
    fn probe(&self) -> &ProbeResult;
    fn call(&self, tool: &str, arguments: &Value, grant: &crate::policy::Grant) -> CallResult;
}
