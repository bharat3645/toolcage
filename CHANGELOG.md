# Changelog

## 0.1.0 - 2026-07-18

Initial release.

- Per-tool-call sandboxing of `wasm32-wasip1` stdio MCP servers under
  wasmtime: every `tools/call` runs in a fresh instance built from that
  tool's policy grant, destroyed afterwards.
- Capability policy (`policy.yaml`, strict parsing): per-tool filesystem
  mounts (`ro`/`rw` WASI preopens), env grants, and budgets (`timeout_ms`,
  `fuel`, `memory_max_mb`, `output_max_kb`) merged over defaults;
  `unlisted_tools: deny | defaults`; `deny: true` per tool. No policy file =
  capability vacuum (tools run with no filesystem, no env).
- Containment: fuel metering, epoch deadlines + join-timeout outer net,
  store memory limits, bounded output pipes, no network API linked at all.
- Client-facing MCP server over stdio (2025-06-18, 2025-03-26, 2024-11-05):
  policy-filtered `tools/list`, denials before instantiation (`-32003`),
  budget kills (`-32005` + class), guest failures (`-32000` + class),
  verbatim result/error passthrough under the client's id.
- JSONL audit trail (0600): session/probe/call/end events with decisions,
  outcomes, budgets, timings, and sha256 correlation hashes. Privacy
  invariant: arguments, results, env values, and file contents are never
  logged - enforced by unit tests and an end-to-end CI canary.
- CLI: `run`, `inspect` (capability-free tool listing), `check` (policy
  validation incl. mount existence), `--version`.
- Evidence: 67 unit/integration tests; CI smoke drives a real wasm guest
  (fixtures/toy-server) through hostile scenarios: mount escapes, ro-mount
  writes, env probes, infinite loops, output floods - plus 58 audit-trail
  assertions. The smoke harness is itself validated against a Python mock.
