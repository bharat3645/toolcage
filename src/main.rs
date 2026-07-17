#![forbid(unsafe_code)]

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use toolcage::audit::{fields, sha256_hex, Auditor};
use toolcage::policy::{Decision, Grant, Policy};
use toolcage::rpc;
use toolcage::runner::Runner as _;
use toolcage::sandbox::WasmRunner;
use toolcage::server::Session;

const USAGE: &str = "\
toolcage - per-tool-call WASM sandbox for MCP servers

USAGE:
  toolcage run --module <server.wasm> [--policy <policy.yaml>]
               [--audit <audit.jsonl>] [--debug-guest-stderr]
      Serve MCP over stdio; every tools/call runs in a fresh wasmtime
      instance with only that tool's granted capabilities.
      Without --policy: all tools run, but with no filesystem and no env
      (capability vacuum). With --policy: unlisted tools are denied unless
      the policy says otherwise.
      Without --audit: audit JSONL goes to stderr.

  toolcage inspect --module <server.wasm> [--json]
      Instantiate the module with zero capabilities and list its tools.

  toolcage check --policy <policy.yaml>
      Validate the policy and verify mounted host directories exist.
      Exits 1 on problems.

  toolcage --version | --help
";

fn main() {
    std::process::exit(real_main());
}

fn real_main() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("run") => cmd_run(&args[1..]),
        Some("inspect") => cmd_inspect(&args[1..]),
        Some("check") => cmd_check(&args[1..]),
        Some("--version") | Some("-V") => {
            println!("toolcage {}", rpc::TOOLCAGE_VERSION);
            0
        }
        Some("--help") | Some("-h") | None => {
            print!("{}", USAGE);
            if args.is_empty() {
                2
            } else {
                0
            }
        }
        Some(other) => {
            eprintln!("toolcage: unknown command {:?}\n", other);
            print!("{}", USAGE);
            2
        }
    }
}

struct FlagParser<'a> {
    args: &'a [String],
    pos: usize,
}

impl<'a> FlagParser<'a> {
    fn new(args: &'a [String]) -> Self {
        FlagParser { args, pos: 0 }
    }
    fn next(&mut self) -> Option<&'a str> {
        let a = self.args.get(self.pos).map(String::as_str);
        self.pos += 1;
        a
    }
    fn value(&mut self, flag: &str) -> Result<&'a str, String> {
        match self.next() {
            Some(v) if !v.starts_with("--") => Ok(v),
            _ => Err(format!("{} requires a value", flag)),
        }
    }
}

fn cmd_run(args: &[String]) -> i32 {
    let mut module: Option<PathBuf> = None;
    let mut policy_path: Option<PathBuf> = None;
    let mut audit_path: Option<PathBuf> = None;
    let mut debug_guest_stderr = false;
    let mut p = FlagParser::new(args);
    while let Some(a) = p.next() {
        match a {
            "--module" => match p.value("--module") {
                Ok(v) => module = Some(PathBuf::from(v)),
                Err(e) => return usage_error(&e),
            },
            "--policy" => match p.value("--policy") {
                Ok(v) => policy_path = Some(PathBuf::from(v)),
                Err(e) => return usage_error(&e),
            },
            "--audit" => match p.value("--audit") {
                Ok(v) => audit_path = Some(PathBuf::from(v)),
                Err(e) => return usage_error(&e),
            },
            "--debug-guest-stderr" => debug_guest_stderr = true,
            other => return usage_error(&format!("unknown flag {:?}", other)),
        }
    }
    let module = match module {
        Some(m) => m,
        None => return usage_error("run requires --module"),
    };

    let policy = match &policy_path {
        Some(path) => match Policy::load(path) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("toolcage: policy error: {:#}", e);
                return 2;
            }
        },
        None => Policy::permissive_vacuum(),
    };

    let audit = match &audit_path {
        Some(path) => match Auditor::to_file(path) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("toolcage: audit error: {:#}", e);
                return 2;
            }
        },
        None => Auditor::to_stderr(),
    };

    // Listing tools needs no capabilities at all.
    let probe_grant = Grant {
        limits: policy.defaults.limits,
        env: Vec::new(),
        mounts: Vec::new(),
    };
    let runner = match WasmRunner::new(&module, &probe_grant, debug_guest_stderr) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("toolcage: {:#}", e);
            return 2;
        }
    };

    let module_sha = std::fs::read(&module)
        .map(|b| sha256_hex(&b))
        .unwrap_or_else(|_| "unreadable".to_string());
    let policy_sha = policy_path
        .as_ref()
        .and_then(|p| std::fs::read(p).ok())
        .map(|b| sha256_hex(&b));
    audit.log(
        "session_start",
        fields(json!({
            "toolcage_version": rpc::TOOLCAGE_VERSION,
            "module": module.display().to_string(),
            "module_sha256": module_sha,
            "policy": policy_path.as_ref().map(|p| p.display().to_string()),
            "policy_sha256": policy_sha,
        })),
    );
    {
        let probe = runner.probe();
        audit.log(
            "probe",
            fields(json!({
                "tools": probe.tools.iter().map(|t| t.name.clone()).collect::<Vec<_>>(),
                "tool_count": probe.tools.len(),
                "truncated": probe.truncated,
                "protocol": probe.protocol,
                "duration_ms": probe.stats.duration_ms,
                "exit_code": probe.stats.exit_code,
            })),
        );
    }

    let mut session = Session::new(&runner, &policy, &audit);
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        match line {
            Ok(l) => session.handle_line(&l, &mut out),
            Err(_) => break,
        }
    }
    session.finish();
    let _ = out.flush();
    0
}

fn cmd_inspect(args: &[String]) -> i32 {
    let mut module: Option<PathBuf> = None;
    let mut as_json = false;
    let mut p = FlagParser::new(args);
    while let Some(a) = p.next() {
        match a {
            "--module" => match p.value("--module") {
                Ok(v) => module = Some(PathBuf::from(v)),
                Err(e) => return usage_error(&e),
            },
            "--json" => as_json = true,
            other => return usage_error(&format!("unknown flag {:?}", other)),
        }
    }
    let module = match module {
        Some(m) => m,
        None => return usage_error("inspect requires --module"),
    };
    let grant = Grant::default();
    let runner = match WasmRunner::new(&module, &grant, false) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("toolcage: {:#}", e);
            return 2;
        }
    };
    let probe = runner.probe();
    if as_json {
        let doc = json!({
            "serverInfo": probe.server_info,
            "protocol": probe.protocol,
            "truncated": probe.truncated,
            "tools": probe.tools.iter().map(|t| t.raw.clone()).collect::<Vec<_>>(),
        });
        match serde_json::to_string_pretty(&doc) {
            Ok(s) => println!("{}", s),
            Err(e) => {
                eprintln!("toolcage: {}", e);
                return 2;
            }
        }
    } else {
        let name = probe
            .server_info
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        println!(
            "server: {} (protocol {}) - {} tool(s){}",
            name,
            probe.protocol,
            probe.tools.len(),
            if probe.truncated {
                " [listing truncated: guest paginated]"
            } else {
                ""
            }
        );
        for t in &probe.tools {
            let desc = t
                .raw
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or("");
            println!("  {}  {}", t.name, desc);
        }
    }
    0
}

fn cmd_check(args: &[String]) -> i32 {
    let mut policy_path: Option<PathBuf> = None;
    let mut p = FlagParser::new(args);
    while let Some(a) = p.next() {
        match a {
            "--policy" => match p.value("--policy") {
                Ok(v) => policy_path = Some(PathBuf::from(v)),
                Err(e) => return usage_error(&e),
            },
            other => return usage_error(&format!("unknown flag {:?}", other)),
        }
    }
    let policy_path = match policy_path {
        Some(p) => p,
        None => return usage_error("check requires --policy"),
    };
    let policy = match Policy::load(&policy_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("toolcage: policy error: {:#}", e);
            return 1;
        }
    };

    let mut problems = 0;
    let listed = policy.listed_tools();
    let allowed = listed.iter().filter(|(_, a)| *a).count();
    println!(
        "policy {}: {} tool(s) listed ({} allowed, {} denied), unlisted tools: {}",
        policy_path.display(),
        listed.len(),
        allowed,
        listed.len() - allowed,
        match policy.unlisted {
            toolcage::policy::UnlistedMode::Deny => "deny",
            toolcage::policy::UnlistedMode::Defaults => "run with defaults",
        }
    );
    let check_grant = |label: &str, grant: &Grant, problems: &mut i32| {
        println!(
            "  {}: timeout {}ms, fuel {}, mem {}MB, output {}KB, {} env var(s), {} mount(s)",
            label,
            grant.limits.timeout_ms,
            grant.limits.fuel,
            grant.limits.memory_max_mb,
            grant.limits.output_max_kb,
            grant.env.len(),
            grant.mounts.len()
        );
        for m in &grant.mounts {
            let ok = m.host_path.is_dir();
            if !ok {
                *problems += 1;
            }
            println!(
                "    {} -> {} ({}){}",
                m.guest_path,
                m.host_path.display(),
                m.mode.as_str(),
                if ok { "" } else { "  [MISSING HOST DIR]" }
            );
        }
    };

    check_grant("defaults", &policy.defaults, &mut problems);
    for &(name, allowed) in &listed {
        if !allowed {
            println!("  {}: DENIED", name);
            continue;
        }
        if let Decision::Allow(grant) = policy.decide(name) {
            check_grant(name, &grant, &mut problems);
        }
    }
    if problems > 0 {
        eprintln!("toolcage: {} problem(s) found", problems);
        1
    } else {
        println!("check OK");
        0
    }
}

fn usage_error(msg: &str) -> i32 {
    eprintln!("toolcage: {}\n", msg);
    print!("{}", USAGE);
    2
}
