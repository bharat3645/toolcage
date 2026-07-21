# toolcage

[![CI](https://github.com/bharat3645/toolcage/actions/workflows/ci.yml/badge.svg)](https://github.com/bharat3645/toolcage/actions/workflows/ci.yml)

**A per-tool-call WASM sandbox for MCP servers.** toolcage speaks MCP over
stdio to your client and runs the wrapped server (a `wasm32-wasip1` module)
inside [wasmtime]. Every single `tools/call` executes in a **fresh instance**
with only the filesystem, environment, and budgets that tool's policy grants.
Network access does not exist for the guest - no socket API is linked in at
all.

Prompt injection against agents succeeds often enough that "the model will
behave" is not a security boundary. toolcage takes the other position:
**assume the tool call is hostile; contain the blast radius.**

```
client (Claude, etc.)
   | MCP over stdio
   v
+-----------------------------------------------------+
| toolcage                                            |
|   policy.yaml -> per-tool grants                    |
|   audit.jsonl <- every decision + outcome           |
|                                                     |
|   tools/call "read_file"                            |
|      -> fresh wasmtime instance                     |
|         fs: only /data (ro)   env: none             |
|         fuel + wall-clock + memory + output budgets |
|      -> instance destroyed after the call           |
+-----------------------------------------------------+
```

[wasmtime]: https://wasmtime.dev

## Containment layers

| Threat | Mechanism |
|---|---|
| File exfiltration / tampering | WASI preopens: a tool sees only its policy's mounts, `ro` or `rw`. No policy entry = no filesystem at all. `..` escapes stop at the preopen root (capability model, not path filtering) - and so do symlinks planted *inside* a mount that point outside it, a distinct vector from a literal `..` in the request path (both adversarially tested against a real guest, see Building and testing below). |
| Network exfiltration | No socket API is linked into the runtime. There is nothing to firewall because the guest has no network, period. |
| Env/credential leakage | Guest env contains exactly the policy's variables. Nothing is inherited from the host. |
| CPU burn (infinite loops) | wasmtime fuel metering (`fuel` budget) - deterministic instruction budget. |
| Wall-clock hangs | Epoch deadline (100ms ticks) plus a worker-thread join timeout as the outer net. |
| Memory balloons | Store limits (`memory_max_mb`). |
| Output floods | Bounded stdout pipe (`output_max_kb`); oversized output fails the call, never OOMs the host. |
| State accumulation / cross-call contamination | Every call is a fresh instance. A rug-pulled tool cannot poison the next call's runtime state (adversarially tested: a guest tool incrementing a global counter gets a fresh zero every call, never accumulates - see Building and testing below). |
| Denied/unlisted tools | Blocked before any guest code runs, and hidden from `tools/list`. |

## Quickstart

```sh
# 1. What does this server expose? (zero capabilities granted)
toolcage inspect --module server.wasm

# 2. Write a policy
cat > policy.yaml <<'EOF'
version: 1
defaults:
  timeout_ms: 30000
unlisted_tools: deny
tools:
  search_docs: {}                    # runs, but sees nothing
  read_project:
    fs:
      /project: { host: ./project, mode: ro }
  write_report:
    timeout_ms: 5000
    fs:
      /out: { host: ./reports, mode: rw }
  dangerous_thing:
    deny: true
EOF

# 3. Validate it (checks mount dirs exist, prints effective grants)
toolcage check --policy policy.yaml

# 4. Serve. Point your MCP client at this command:
toolcage run --module server.wasm --policy policy.yaml --audit audit.jsonl
```

Without `--policy`, every tool runs but in a **capability vacuum** (no
filesystem, no env, default budgets). With a policy, unlisted tools are
**denied by default**.

## Policy reference

```yaml
version: 1                  # required, must be 1
defaults:                   # applies to every allowed tool unless overridden
  timeout_ms: 30000         # wall clock, 1..600000
  fuel: 2000000000          # wasmtime instruction budget
  memory_max_mb: 256        # 1..4096
  output_max_kb: 4096       # guest stdout cap, 1..1048576
  env: { KEY: value }       # granted env vars (default: none)
  fs:                       # granted mounts (default: none)
    /guest/path: { host: ./host/path, mode: ro }   # ro | rw
unlisted_tools: deny        # deny (default) | defaults
tools:
  tool_a: {}                # allow with defaults
  tool_b:                   # allow with overrides (merged over defaults;
    timeout_ms: 5000        #  env and fs merge key-by-key, tool wins)
    fs:
      /data: { host: /srv/data, mode: ro }
  tool_c:
    deny: true              # deny (cannot be combined with grants)
```

Unknown fields anywhere are rejected (strict parsing). Relative `host` paths
resolve against the policy file's directory. Guest paths must be absolute,
must not be `/`, and must not contain `..`.

## Error codes

| Code | Meaning |
|---|---|
| `-32002` | server not initialized yet |
| `-32003` | tool denied by policy (listed `deny: true`, or unlisted under default-deny) |
| `-32005` | budget exceeded: `data.class` is `timeout`, `cpu_budget`, or `output_overflow` |
| `-32000` | guest failed: `data.class` is `guest_trap`, `guest_exit`, `no_response`, or `internal` |
| `-32602` | unknown tool name, or malformed `tools/call` params |

Guest-produced JSON-RPC errors (e.g. the tool rejecting its arguments) pass
through under the client's id. Guest results pass through verbatim,
including `isError`.

## Paginating `tools/list`

By default toolcage returns every visible tool in one `tools/list` response —
unchanged from before pagination existed. Pass `--page-size <n>` to `run` to
cap each page at `n` tools; when more remain, the response carries an opaque
`nextCursor` that the client sends back (per MCP) to fetch the next page:

```bash
toolcage run --module server.wasm --policy policy.yaml --page-size 50
```

Policy filtering happens **before** paging, so a denied or unlisted tool is
absent from every page and reachable by no cursor value — the same guarantee
the unpaginated list already gave.

Cursors are opaque, stateless, and authenticated — the same discipline as the
sandbox itself. toolcage keeps **no** server-side pagination state: the page
position travels inside the cursor, HMAC-SHA256-signed with a key generated
fresh for each `run` process and bound to a fingerprint of the exact visible
tool set. A cursor that is edited, truncated, replayed against a different
tool set, or reused after a restart fails verification and is rejected with
`-32602` (`data.reason` is `malformed`, `bad_mac`, `snapshot_mismatch`, or
`out_of_range`) — it is never silently mis-paginated. `--page-size 0` (the
default) disables pagination entirely, so upgrading changes nothing.

## Audit trail

JSONL, one event per line, file created `0600`. Events: `session_start`
(module + policy sha256 + `page_size`), `probe` (tool inventory),
`client_initialize`, `tools_list` (page metadata and rejected-cursor
attempts, counts only), `call`, `session_end`.

**Privacy invariant:** tool arguments, results, env values, and file
contents are never written to the audit log - only names, byte counts,
sha256 hashes, decisions, outcomes, budgets, and timings. Hashes give you
correlation power ("same arguments as yesterday's incident") without
content. This is enforced by tests, including an end-to-end canary check in
CI. Audit sink failures never break a call (counted and dropped).

Example `call` event:

```json
{"ts":"2026-07-18T09:14:03.219Z","event":"call","tool":"read_file",
 "decision":"allow","args_bytes":29,"args_sha256":"9f2c...","duration_ms":11,
 "fuel_used":184223,"stdout_bytes":412,"stderr_bytes":0,"garbage_lines":0,
 "timeout_ms":30000,"mounts":["/data:ro"],"exit_code":0,"outcome":"ok",
 "is_error":false,"result_bytes":301,"result_sha256":"c11a..."}
```

## How a call runs

1. Client sends `tools/call`. toolcage checks the tool exists (probed at
   startup) and what the policy says. Denials never instantiate the guest.
2. An allowed call gets a fresh `Store` + WASI context built from its grant:
   memory-backed stdin containing exactly three messages (`initialize`,
   `notifications/initialized`, the `tools/call`), bounded stdout/stderr
   pipes, the grant's preopens and env.
3. The instance runs to completion (EOF-driven), the matching response is
   extracted from its stdout, re-issued under the client's id, and the
   instance is destroyed. Fuel, epoch deadline, memory limits, and pipe caps
   apply throughout; a worker-thread join timeout is the outer net.

## Honest limitations (v0.1)

- **Guests must be `wasm32-wasip1` command modules speaking MCP over stdio.**
  Native MCP servers do not run under toolcage. Rust servers compile with
  `--target wasm32-wasip1`; Python/JS servers need a wasm build of their
  interpreter (not tested yet).
- **Request/response tools only.** The run-to-completion model means
  server-to-client requests (sampling, roots), progress notifications, and
  subscriptions are not supported in v0.1. A guest that waits for such
  responses hits its budget and the call fails closed.
- **Stateless guests only.** State resets on every call - that is the
  security feature, but it rules out servers that need cross-call memory.
- **The guest's own `tools/list` pagination is not followed during probe.**
  toolcage paginates *its own* client-facing listing (`--page-size`, see
  [Paginating `tools/list`](#paginating-toolslist)), but when it probes the
  wrapped server it reads only the first page; if the guest paginates,
  `inspect` and the audit `probe` event say so honestly (`truncated: true`).
  Following the guest across pages needs an interactive probe — a change to
  the one-shot execution model — and is future work.
- **A guest blocked inside a host call** (e.g. a long `poll_oneoff` sleep)
  is not interruptible by fuel or epochs; the join timeout answers the
  client promptly but the worker thread is abandoned until process exit.
- **Output-overflow classification is best-effort** (an over-budget guest
  may also surface as `guest_trap` if it crashes on the blocked write); the
  budget itself is always enforced.
- **The client side is trusted.** toolcage contains the *server*; it does
  not defend against a malicious client. Put [mcp-gateway-lite] in front
  for client-side policy, rate limits, and HTTP audit trails.
- Tool *descriptions* can still lie (that is a semantic attack, not a
  containment one). Pair with [mcp-sentinel] for lockfile pinning and
  rug-pull drift detection of tool schemas.

[mcp-sentinel]: https://github.com/bharat3645/mcp-sentinel
[mcp-gateway-lite]: https://github.com/bharat3645/mcp-gateway-lite

## The trust stack

toolcage is the containment layer of a set of small, composable tools:
[mcp-sentinel] pins and verifies *what tools claim to be* (lockfiles, drift
detection), [mcp-gateway-lite] governs *who may call what* at the HTTP layer
(allowlists, rate limits, audit), and toolcage bounds *what a call can
actually do* (capabilities, budgets). Use any alone; they compose.

## Building and testing

```sh
cargo build --release
cargo test                      # 96 unit/integration tests, no wasm needed
bash ci/smoke.sh                # full e2e: builds a real wasm guest
                                # (needs the wasm32-wasip1 target) and runs
                                # hostile-tool scenarios + audit assertions
                                # + the per-call overhead benchmark below
```

The smoke harness itself is validated: `ci/mock_toolcage.py` is a Python
stand-in reproducing the client-visible semantics, so the driver and audit
checker can be exercised without a Rust toolchain
(`python3 ci/smoke_driver.py WORK python3 ci/mock_toolcage.py x.wasm`).

The hostile guest (`fixtures/toy-server`) includes tools built specifically
to adversarially probe the containment table above against a *real* guest,
not just assert it: `counter` (a process-global that only ever answers "1"
if instances are truly fresh) and a symlink planted inside the read-only
mount, pointing at the host secret file just outside it
(`ci/make_workdir.sh`'s `escape-link`) - a different escape vector than the
literal `..` path already covered.

### Benchmark: per-call sandboxing overhead

`ci/bench.py` times 200 real `echo` round-trips through the compiled
binary + real wasm guest (every call pays for a fresh `Store`, WASI
context, and instantiation - see "How a call runs" above) and, as a rough
floor, the same 200 calls against the unsandboxed Python mock:

```sh
python3 ci/bench.py WORK ./target/release/toolcage x.wasm 200
```

Run in CI on every push (`ci/smoke.sh`'s last step) against GitHub Actions'
`ubuntu-latest`; the mock comparison is a floor for "protocol overhead
alone," not a rigorous native baseline (different language, different
process model), and is labeled as such in the benchmark's own output.

Real numbers, captured 2026-07-20 ([run](https://github.com/bharat3645/toolcage/actions/runs/29764204799),
`ubuntu-latest`, 200 `echo` calls each):

| | mean | median | p95 | p99 | min | max |
|---|---|---|---|---|---|---|
| real toolcage (wasmtime) | 0.423ms | 0.415ms | 0.509ms | 0.584ms | 0.384ms | 0.594ms |
| mock (no sandbox, Python) | 0.094ms | 0.089ms | 0.116ms | 0.159ms | 0.084ms | 0.162ms |

The fresh-`Store`-per-call guarantee costs roughly **+0.33ms median** over
the unsandboxed floor - sub-millisecond, and dwarfed in practice by the
guest MCP server's own work (a real `read_file`/`write_file`/tool call
does actual I/O; `echo` is close to the cheapest possible call, chosen
specifically to isolate sandboxing overhead from guest work). See future
runs' logs for current numbers as the implementation evolves.

## License

MIT
