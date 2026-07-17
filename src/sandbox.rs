//! The wasmtime host: every guest execution is a fresh Store + fresh WASI
//! context built from one tool's Grant, run to completion on a pre-built
//! stdin transcript.
//!
//! Containment layers per call:
//!   - filesystem: only the policy's preopens exist (WASI capability model);
//!     no policy entry means no filesystem at all
//!   - network: does not exist (no socket API is linked in at all)
//!   - env: only the policy's variables
//!   - CPU: wasmtime fuel metering
//!   - wall clock: epoch deadline (ticker thread) + a worker-thread join
//!     timeout as the outer net
//!   - memory: store limits
//!   - output: bounded stdout/stderr pipes
//!
//! Honest caveat (documented in the README too): a guest blocked inside a
//! host call (e.g. a long poll_oneoff sleep) is not interrupted by fuel or
//! epochs; the join timeout answers the client promptly but the worker
//! thread is abandoned until process exit.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use wasmtime::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder, Trap};
use wasmtime_wasi::pipe::{MemoryInputPipe, MemoryOutputPipe};
use wasmtime_wasi::preview1::{self, WasiP1Ctx};
use wasmtime_wasi::{DirPerms, FilePerms, WasiCtxBuilder};

use crate::policy::{Grant, MountMode};
use crate::rpc;
use crate::runner::{CallOutcome, CallResult, CallStats, FailClass, ProbeResult, Runner, ToolDef};

const EPOCH_TICK_MS: u64 = 100;
const JOIN_GRACE_MS: u64 = 2_000;
const STDERR_CAP_BYTES: usize = 256 * 1024;
const OUTPUT_SLACK_BYTES: usize = 4_096;

struct HostState {
    wasi: WasiP1Ctx,
    limits: StoreLimits,
}

#[derive(Debug, Clone)]
enum ExitKind {
    Clean,
    Exit(i32),
    Trapped(FailClass, String),
    HostError(String),
}

#[derive(Debug)]
struct RunOutput {
    stdout: Vec<u8>,
    stderr_bytes: u64,
    exit: ExitKind,
    fuel_used: Option<u64>,
    duration_ms: u64,
}

pub struct WasmRunner {
    engine: Engine,
    module: Module,
    probe: ProbeResult,
    epoch_stop: Arc<AtomicBool>,
    debug_guest_stderr: bool,
}

impl Drop for WasmRunner {
    fn drop(&mut self) {
        self.epoch_stop.store(true, Ordering::Relaxed);
    }
}

impl WasmRunner {
    /// Compile the module once, start the epoch ticker, and probe the guest
    /// (initialize + tools/list) with the given grant. The probe grant
    /// should be capability-free: listing tools needs no filesystem.
    pub fn new(module_path: &Path, probe_grant: &Grant, debug_guest_stderr: bool) -> Result<WasmRunner> {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.epoch_interruption(true);
        let engine = Engine::new(&config).context("failed to create wasmtime engine")?;
        let module = Module::from_file(&engine, module_path)
            .with_context(|| format!("failed to load wasm module {}", module_path.display()))?;

        let epoch_stop = Arc::new(AtomicBool::new(false));
        {
            let engine = engine.clone();
            let stop = epoch_stop.clone();
            let _detached = thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_millis(EPOCH_TICK_MS));
                    engine.increment_epoch();
                }
            });
        }

        let transcript = rpc::guest_transcript_probe(rpc::PROTOCOL_FALLBACK);
        let run = run_guest(&engine, &module, probe_grant, transcript, debug_guest_stderr);
        let probe = parse_probe(run)?;

        Ok(WasmRunner {
            engine,
            module,
            probe,
            epoch_stop,
            debug_guest_stderr,
        })
    }
}

impl Runner for WasmRunner {
    fn probe(&self) -> &ProbeResult {
        &self.probe
    }

    fn call(&self, tool: &str, arguments: &Value, grant: &Grant) -> CallResult {
        let transcript = rpc::guest_transcript_call(&self.probe.protocol, tool, arguments);
        let run = run_guest(
            &self.engine,
            &self.module,
            grant,
            transcript,
            self.debug_guest_stderr,
        );

        let mut stats = CallStats {
            duration_ms: run.duration_ms,
            fuel_used: run.fuel_used,
            stdout_bytes: run.stdout.len() as u64,
            stderr_bytes: run.stderr_bytes,
            garbage_lines: 0,
            exit_code: match &run.exit {
                ExitKind::Clean => Some(0),
                ExitKind::Exit(c) => Some(*c),
                _ => None,
            },
        };

        let output_max_bytes = grant.limits.output_max_kb.saturating_mul(1024);
        if stats.stdout_bytes > output_max_bytes {
            return CallResult {
                outcome: CallOutcome::Failed {
                    class: FailClass::OutputOverflow,
                    detail: format!(
                        "guest stdout reached {} bytes (budget {})",
                        stats.stdout_bytes, output_max_bytes
                    ),
                },
                stats,
            };
        }

        let (response, garbage, _rpc_lines) = rpc::extract_response(&run.stdout, rpc::GUEST_CALL_ID);
        stats.garbage_lines = garbage;

        match response {
            Some(r) => CallResult {
                outcome: CallOutcome::Completed { response: r },
                stats,
            },
            None => {
                let (class, detail) = match run.exit {
                    ExitKind::Trapped(class, detail) => (class, detail),
                    ExitKind::HostError(detail) => (FailClass::Internal, detail),
                    ExitKind::Exit(code) if code != 0 => (
                        FailClass::GuestExit,
                        format!("guest exited with code {} before answering", code),
                    ),
                    ExitKind::Exit(_) | ExitKind::Clean => (
                        FailClass::NoResponse,
                        "guest completed without a response for the call id".to_string(),
                    ),
                };
                CallResult {
                    outcome: CallOutcome::Failed { class, detail },
                    stats,
                }
            }
        }
    }
}

fn parse_probe(run: RunOutput) -> Result<ProbeResult> {
    let stats = CallStats {
        duration_ms: run.duration_ms,
        fuel_used: run.fuel_used,
        stdout_bytes: run.stdout.len() as u64,
        stderr_bytes: run.stderr_bytes,
        garbage_lines: 0,
        exit_code: match &run.exit {
            ExitKind::Clean => Some(0),
            ExitKind::Exit(c) => Some(*c),
            _ => None,
        },
    };
    if let ExitKind::HostError(detail) = &run.exit {
        return Err(anyhow!("probe failed before execution: {}", detail));
    }
    let (init_resp, _, _) = rpc::extract_response(&run.stdout, rpc::GUEST_INIT_ID);
    let (list_resp, garbage, _) = rpc::extract_response(&run.stdout, rpc::GUEST_CALL_ID);

    let init_result = init_resp
        .as_ref()
        .and_then(|r| r.get("result"))
        .cloned()
        .unwrap_or(Value::Null);
    let protocol = init_result
        .get("protocolVersion")
        .and_then(Value::as_str)
        .unwrap_or(rpc::PROTOCOL_FALLBACK)
        .to_string();
    let server_info = init_result.get("serverInfo").cloned().unwrap_or(Value::Null);

    let list = match list_resp {
        Some(r) => r,
        None => {
            return Err(anyhow!(
                "guest did not answer the tools/list probe (exit: {:?}, {} stdout bytes)",
                run.exit,
                run.stdout.len()
            ))
        }
    };
    let list_result = list.get("result").cloned().unwrap_or(Value::Null);
    let truncated = list_result.get("nextCursor").is_some();
    let mut tools = Vec::new();
    if let Some(arr) = list_result.get("tools").and_then(Value::as_array) {
        for t in arr {
            if let Some(name) = t.get("name").and_then(Value::as_str) {
                tools.push(ToolDef {
                    name: name.to_string(),
                    raw: t.clone(),
                });
            }
        }
    } else {
        return Err(anyhow!(
            "tools/list probe response had no result.tools array"
        ));
    }

    let mut probe = ProbeResult {
        tools,
        protocol,
        truncated,
        server_info,
        stats,
    };
    probe.stats.garbage_lines = garbage;
    Ok(probe)
}

/// Run one fresh guest instance to completion with the grant's capabilities,
/// on its own worker thread, with fuel + epoch + join-timeout containment.
fn run_guest(
    engine: &Engine,
    module: &Module,
    grant: &Grant,
    stdin_bytes: Vec<u8>,
    debug_guest_stderr: bool,
) -> RunOutput {
    let started = Instant::now();
    let (tx, rx) = mpsc::channel();
    let engine2 = engine.clone();
    let module2 = module.clone();
    let grant2 = grant.clone();
    let handle = thread::spawn(move || {
        let out = execute(&engine2, &module2, &grant2, stdin_bytes, debug_guest_stderr);
        let _ = tx.send(out);
    });

    let budget = grant.limits.timeout_ms + 2 * EPOCH_TICK_MS + JOIN_GRACE_MS;
    match rx.recv_timeout(Duration::from_millis(budget)) {
        Ok(out) => {
            let _ = handle.join();
            out
        }
        Err(_) => RunOutput {
            stdout: Vec::new(),
            stderr_bytes: 0,
            exit: ExitKind::Trapped(
                FailClass::Timeout,
                "wall-clock budget exceeded inside a host call; worker thread abandoned"
                    .to_string(),
            ),
            fuel_used: None,
            duration_ms: started.elapsed().as_millis() as u64,
        },
    }
}

fn execute(
    engine: &Engine,
    module: &Module,
    grant: &Grant,
    stdin_bytes: Vec<u8>,
    debug_guest_stderr: bool,
) -> RunOutput {
    let started = Instant::now();
    let stdout_cap = (grant.limits.output_max_kb as usize)
        .saturating_mul(1024)
        .saturating_add(OUTPUT_SLACK_BYTES);
    let stdout_pipe = MemoryOutputPipe::new(stdout_cap);
    let stderr_pipe = MemoryOutputPipe::new(STDERR_CAP_BYTES);

    let mut builder = WasiCtxBuilder::new();
    builder.stdin(MemoryInputPipe::new(stdin_bytes));
    builder.stdout(stdout_pipe.clone());
    builder.stderr(stderr_pipe.clone());
    for (k, v) in &grant.env {
        builder.env(k, v);
    }
    for m in &grant.mounts {
        let (dir_perms, file_perms) = match m.mode {
            MountMode::ReadOnly => (DirPerms::READ, FilePerms::READ),
            MountMode::ReadWrite => (DirPerms::all(), FilePerms::all()),
        };
        if let Err(e) = builder.preopened_dir(&m.host_path, &m.guest_path, dir_perms, file_perms) {
            return RunOutput {
                stdout: Vec::new(),
                stderr_bytes: 0,
                exit: ExitKind::HostError(format!(
                    "preopen {} -> {} failed: {:#}",
                    m.host_path.display(),
                    m.guest_path,
                    e
                )),
                fuel_used: None,
                duration_ms: started.elapsed().as_millis() as u64,
            };
        }
    }
    let wasi = builder.build_p1();

    let limits = StoreLimitsBuilder::new()
        .memory_size((grant.limits.memory_max_mb as usize).saturating_mul(1024 * 1024))
        .build();
    let mut store = Store::new(engine, HostState { wasi, limits });
    store.limiter(|s| &mut s.limits);
    if let Err(e) = store.set_fuel(grant.limits.fuel) {
        return host_error(started, &stdout_pipe, &stderr_pipe, format!("set_fuel: {:#}", e));
    }
    store.epoch_deadline_trap();
    store.set_epoch_deadline(grant.limits.timeout_ms / EPOCH_TICK_MS + 2);

    let mut linker: Linker<HostState> = Linker::new(engine);
    if let Err(e) = preview1::add_to_linker_sync(&mut linker, |s: &mut HostState| &mut s.wasi) {
        return host_error(started, &stdout_pipe, &stderr_pipe, format!("wasi link: {:#}", e));
    }

    let exit = match linker.instantiate(&mut store, module) {
        Err(e) => classify_error(e),
        Ok(instance) => match instance.get_typed_func::<(), ()>(&mut store, "_start") {
            Err(e) => ExitKind::HostError(format!("module has no _start export: {:#}", e)),
            Ok(start) => match start.call(&mut store, ()) {
                Ok(()) => ExitKind::Clean,
                Err(e) => classify_error(e),
            },
        },
    };

    let fuel_used = store
        .get_fuel()
        .ok()
        .map(|left| grant.limits.fuel.saturating_sub(left));
    let stdout = stdout_pipe.contents().to_vec();
    let stderr_contents = stderr_pipe.contents();
    if debug_guest_stderr && !stderr_contents.is_empty() {
        eprintln!(
            "[toolcage] guest stderr ({} bytes):",
            stderr_contents.len()
        );
        eprintln!("{}", String::from_utf8_lossy(&stderr_contents));
    }

    RunOutput {
        stdout,
        stderr_bytes: stderr_contents.len() as u64,
        exit,
        fuel_used,
        duration_ms: started.elapsed().as_millis() as u64,
    }
}

fn host_error(
    started: Instant,
    stdout_pipe: &MemoryOutputPipe,
    stderr_pipe: &MemoryOutputPipe,
    detail: String,
) -> RunOutput {
    RunOutput {
        stdout: stdout_pipe.contents().to_vec(),
        stderr_bytes: stderr_pipe.contents().len() as u64,
        exit: ExitKind::HostError(detail),
        fuel_used: None,
        duration_ms: started.elapsed().as_millis() as u64,
    }
}

fn classify_error(e: anyhow::Error) -> ExitKind {
    if let Some(exit) = e.downcast_ref::<wasmtime_wasi::I32Exit>() {
        return ExitKind::Exit(exit.0);
    }
    if let Some(trap) = e.downcast_ref::<Trap>() {
        return match trap {
            Trap::OutOfFuel => ExitKind::Trapped(
                FailClass::CpuBudget,
                "fuel exhausted (wasmtime Trap::OutOfFuel)".to_string(),
            ),
            Trap::Interrupt => ExitKind::Trapped(
                FailClass::Timeout,
                "epoch deadline reached (wasmtime Trap::Interrupt)".to_string(),
            ),
            other => ExitKind::Trapped(FailClass::GuestTrap, format!("wasm trap: {:?}", other)),
        };
    }
    ExitKind::Trapped(FailClass::GuestTrap, format!("guest error: {:#}", e))
}
