#!/usr/bin/env python3
"""Per-call sandboxing overhead benchmark.

Every tools/call gets a fresh wasmtime Store (README's core containment
claim) - that's real work done on every single call: Store creation, WASI
context build, module instantiation. This measures what that actually
costs in wall-clock time, against the real compiled binary and real wasm
guest, not estimated.

Also times the same N calls against ci/mock_toolcage.py (a Python stand-in
with no sandboxing at all) as a rough floor for "protocol overhead alone,"
not a rigorous apples-to-apples baseline - it's a different language and a
different process model, called out explicitly below rather than presented
as equivalent.

Usage: bench.py WORKDIR CMD [ARG...] MODULE.wasm [N]
  Same WORKDIR/CMD/MODULE shape as smoke_driver.py. N defaults to 200.
"""

import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from smoke_driver import Client  # noqa: E402


def time_n_echo_calls(argv, n):
    c = Client(argv)
    c.handshake()
    samples = []
    for i in range(n):
        t0 = time.perf_counter()
        resp = c.call_tool("echo", {"text": "bench-%d" % i})
        samples.append((time.perf_counter() - t0) * 1000.0)
        if resp.get("result") is None:
            raise AssertionError("unexpected error response: %s" % resp)
    c.close_and_wait()
    return samples


def report(label, samples):
    samples_sorted = sorted(samples)
    n = len(samples_sorted)
    mean = statistics.mean(samples_sorted)
    median = statistics.median(samples_sorted)
    p95 = samples_sorted[int(n * 0.95)]
    p99 = samples_sorted[min(int(n * 0.99), n - 1)]
    print(
        "%-28s n=%-4d mean=%6.3fms median=%6.3fms p95=%6.3fms p99=%6.3fms min=%6.3fms max=%6.3fms"
        % (label, n, mean, median, p95, p99, samples_sorted[0], samples_sorted[-1])
    )
    return {"mean": mean, "median": median, "p95": p95, "p99": p99}


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    work = sys.argv[1]
    n = 200
    rest = sys.argv[2:]
    if rest and rest[-1].isdigit():
        n = int(rest[-1])
        rest = rest[:-1]
    base_cmd = rest[:-1]
    wasm = rest[-1]

    print("toolcage per-call sandboxing overhead: %d echo calls, policy-a\n" % n)

    real_samples = time_n_echo_calls(
        base_cmd + ["run", "--module", wasm, "--policy", os.path.join(work, "policy-a.yaml")], n
    )
    real_stats = report("real toolcage (wasmtime)", real_samples)

    mock_samples = time_n_echo_calls(
        [sys.executable, os.path.join(os.path.dirname(__file__), "mock_toolcage.py"), "run",
         "--module", wasm, "--policy", os.path.join(work, "policy-a.yaml")],
        n,
    )
    mock_stats = report("mock (no sandbox, Python)", mock_samples)

    print(
        "\nsandbox overhead vs mock floor: +%.3fms median, +%.3fms p95 "
        "(mock is an unsandboxed Python stand-in, not a rigorous native "
        "baseline - see docstring)"
        % (real_stats["median"] - mock_stats["median"], real_stats["p95"] - mock_stats["p95"])
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
