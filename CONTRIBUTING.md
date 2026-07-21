# Contributing to toolcage

Thanks for looking under the hood. This project values small, verifiable changes.

## Ground rules

- **Every change ships with evidence.** Bug fix → a test that fails without it. Feature → tests that pin its behavior AND its failure modes. This repo documents what it *doesn't* do as carefully as what it does — PRs that quietly widen claims get asked to narrow them.
- **New runtime dependencies need an issue discussing why first.** `unsafe` code is forbidden outright (`#![forbid(unsafe_code)]` in `src/lib.rs` and `src/main.rs`) — don't submit a PR that removes or works around that attribute.
- **Sandboxing and capability-boundary changes get extra scrutiny.** The core security claim of this repo is that a wrapped tool call has no network access "no socket API is linked into the runtime, period" and that filesystem access is capability-scoped to whatever a policy explicitly grants. Any PR touching the WASI setup, preopens, policy parsing/merging, fuel/epoch/memory budgets, or the audit sink should expect closer review and is expected to add or update the adversarial tests in `fixtures/toy-server` / `ci/smoke.sh`, not just unit tests, if it touches guest-facing behavior.
- **Honest docs.** If your change has a limitation, the README states it (see "Honest limitations" there). "Documented honestly" beats "silently best-effort".

## Getting started

```sh
cargo test --all-targets      # unit + integration tests, no wasm toolchain needed
```

CI runs that plus `cargo clippy --all-targets -- -D warnings` and, in a separate
job, `ci/smoke.sh` — a fuller end-to-end check against a **real compiled
`toolcage` binary and a real hostile wasm guest** (`fixtures/toy-server`),
including the symlink-escape and fresh-instance-state adversarial scenarios
described in the README. `ci/smoke.sh` needs the `wasm32-wasip1` target; if you
can't build wasm locally, `cargo test --all-targets` plus a green CI run on
your PR is fine. Green CI is required, no exceptions (including for
maintainers — check the history: it's how the whole repo was built).

## Good first issues

Issues tagged `good-first-issue` are scoped to be completable without deep context; each states the acceptance evidence expected. If you want one and it's unclear, comment — you'll get a response, not silence.

## Reporting security issues

Email 404ghost.2@gmail.com rather than opening a public issue. You'll get an acknowledgment within 48h and honest handling: if it's real, it ships as a fix with credit; if it's out of threat model, the threat-model doc gets clearer about why.
