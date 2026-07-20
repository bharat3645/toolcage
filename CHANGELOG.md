# Changelog

## Unreleased

Production-polish sprint: closes two real adversarial-test gaps in the
containment claims, plus the first real per-call overhead numbers.

- New adversarial e2e tests against the real hostile guest, not just
  design-level assertions: (1) a `counter` tool in `fixtures/toy-server`
  that increments a process-global and returns it — every call must see a
  fresh zero if instances are truly isolated, tested 3x in a row; (2) a
  symlink planted inside the read-only mount pointing at the host secret
  file just outside it (`ci/make_workdir.sh`'s `escape-link`) — a
  different escape vector than the `..`-in-path case already covered,
  since the raw guest path string never leaves the mount, only symlink
  resolution does. Both wired through `ci/smoke_driver.py`'s scenario A
  and `ci/audit_check.py`'s call-count assertions (updated: 6→7 tools,
  11→15 total calls, 2→3 flagged read_file escapes).
- New `ci/bench.py`: times 200 real `echo` round-trips through the
  compiled binary + real wasm guest (every call pays for a fresh `Store`,
  WASI context, and instantiation) and, as a rough floor, the same 200
  calls against the unsandboxed Python mock — labeled honestly as not a
  rigorous native baseline. Wired as the last step of `ci/smoke.sh`, so it
  runs against the real binary on every CI push.
- README: containment table now cites these two adversarial tests
  directly instead of asserting the guarantees in prose alone; new
  "Benchmark" subsection under Building and testing.

Verified locally first: the mock-based harness self-test
(`python3 ci/smoke_driver.py ... python3 ci/mock_toolcage.py ...` +
`ci/audit_check.py`) passed 45+64 checks, confirming the new checks and
count updates were well-formed before they ever touched real wasmtime.
`cargo test --workspace` (67 tests, unaffected — these changes are in the
fixture/CI-script layer, not the sandbox crate itself) and
`cargo clippy --workspace --all-targets -- -D warnings` both clean
locally (no `wasm32-wasip1` target on this machine — no rustup, only
Homebrew's rustc — so the real e2e leg needed CI either way).

**Real end-to-end run, CI**: [run #29764204799](https://github.com/bharat3645/toolcage/actions/runs/29764204799),
real compiled binary + real `wasm32-wasip1` guest, `ubuntu-latest`. Caught
one real bug on the first push — `counter` was added to the guest and to
every *expected*-tools list, but never actually granted in
`ci/make_workdir.sh`'s `policy-a.yaml`, so the real (policy-filtered)
`tools/list` correctly hid it under `unlisted_tools: deny` while the mock
(which doesn't parse policy YAML) missed the gap entirely — fixed in a
follow-up push. Second run: `DRIVER OK (45 checks)`, `AUDIT OK (64
checks)`, both new adversarial checks (symlink escape, 3x counter
statelessness) passing against the real sandbox. Real benchmark numbers
now in the README's Benchmark section.

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
