#!/usr/bin/env python3
"""End-to-end smoke driver for toolcage.

Speaks MCP over stdio to a `toolcage run` process (or the local mock used to
validate this harness itself) and asserts sandbox behavior: capability
containment, policy denials, budget kills, and clean protocol handling.

Usage: smoke_driver.py WORKDIR CMD [ARG...] MODULE.wasm
  WORKDIR must contain policy-a.yaml, policy-b.yaml, data/hello.txt,
  secret.txt, and an out/ directory (see ci/make_workdir.sh).
  CMD [ARG...] is the toolcage invocation prefix (the last argv entry is the
  module path); the driver appends per scenario:
  run --module MODULE [--policy P] [--audit A].

Exit code 0 and the line "DRIVER OK" mean every assertion passed.
"""

import json
import os
import queue
import subprocess
import sys
import threading
import time

RECV_TIMEOUT = 60.0
CANARY_ARG = "CANARY_ARG_77f2"
CANARY_OUT = "cage-out u3h8"

CHECKS = {"passed": 0}


def ok(cond, label):
    if not cond:
        raise AssertionError("FAILED: %s" % label)
    CHECKS["passed"] += 1
    print("  ok - %s" % label)


class Client:
    def __init__(self, argv):
        self.proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self.q = queue.Queue()
        self.stderr_lines = []
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()
        self.next_id = 0

    def _read_stdout(self):
        for line in self.proc.stdout:
            self.q.put(line)
        self.q.put(None)

    def _read_stderr(self):
        for line in self.proc.stderr:
            self.stderr_lines.append(line)

    def send(self, obj):
        self.proc.stdin.write(json.dumps(obj) + "\n")
        self.proc.stdin.flush()

    def recv(self, timeout=RECV_TIMEOUT):
        line = self.q.get(timeout=timeout)
        if line is None:
            raise AssertionError("toolcage closed stdout unexpectedly")
        return json.loads(line)

    def request(self, method, params=None, timeout=RECV_TIMEOUT):
        self.next_id += 1
        msg = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
        if params is not None:
            msg["params"] = params
        self.send(msg)
        resp = self.recv(timeout=timeout)
        if resp.get("id") != self.next_id:
            raise AssertionError(
                "response id mismatch: sent %r got %r" % (self.next_id, resp.get("id"))
            )
        return resp

    def notify(self, method):
        self.send({"jsonrpc": "2.0", "method": method})

    def handshake(self):
        resp = self.request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "smoke-driver", "version": "0"},
            },
        )
        ok(resp["result"]["serverInfo"]["name"] == "toolcage", "serverInfo.name is toolcage")
        ok(
            resp["result"]["protocolVersion"] == "2025-06-18",
            "protocol negotiated to 2025-06-18",
        )
        self.notify("notifications/initialized")

    def call_tool(self, name, arguments, timeout=RECV_TIMEOUT):
        return self.request(
            "tools/call", {"name": name, "arguments": arguments}, timeout=timeout
        )

    def close_and_wait(self):
        self.proc.stdin.close()
        rc = self.proc.wait(timeout=20)
        return rc


def tool_names(list_resp):
    return sorted(t["name"] for t in list_resp["result"]["tools"])


def text_of(call_resp):
    result = call_resp.get("result")
    if result is None:
        raise AssertionError("expected result, got %s" % json.dumps(call_resp))
    content = result.get("content") or []
    return "".join(c.get("text", "") for c in content if c.get("type") == "text")


def is_error_of(call_resp):
    return bool(call_resp.get("result", {}).get("isError"))


ALL_TOOLS = ["counter", "echo", "env", "read_file", "shout", "spin", "write_file"]


def run_a(work, base_cmd, wasm):
    print("scenario A: full policy, hostile tools contained")
    c = Client(
        base_cmd
        + [
            "run",
            "--module",
            wasm,
            "--policy",
            os.path.join(work, "policy-a.yaml"),
            "--audit",
            os.path.join(work, "audit_a.jsonl"),
        ]
    )
    c.handshake()

    resp = c.request("tools/list")
    ok(tool_names(resp) == ALL_TOOLS, "tools/list shows all %d listed tools" % len(ALL_TOOLS))

    resp = c.call_tool("echo", {"text": CANARY_ARG})
    ok(text_of(resp) == "echo: " + CANARY_ARG, "echo round-trips")
    ok(not is_error_of(resp), "echo is not an error")

    resp = c.call_tool("read_file", {"path": "/data/hello.txt"})
    ok("hello from the cage" in text_of(resp), "read_file reads inside the ro mount")

    resp = c.call_tool("read_file", {"path": "/data/../secret.txt"})
    ok(is_error_of(resp), "dot-dot escape from the mount fails")
    ok("TOP-SECRET" not in json.dumps(resp), "escape attempt never sees host secret")

    resp = c.call_tool("read_file", {"path": "/secret.txt"})
    ok(is_error_of(resp), "path outside any mount fails")
    ok("TOP-SECRET" not in json.dumps(resp), "unmounted path never sees host secret")

    # Symlink escape: escape-link lives INSIDE the ro mount (make_workdir.sh)
    # but points at the host secret OUTSIDE it - a different vector than the
    # dot-dot check above, since the raw guest path string never leaves the
    # mount; only symlink resolution does.
    resp = c.call_tool("read_file", {"path": "/data/escape-link"})
    ok(is_error_of(resp), "symlink escape from the mount fails")
    ok("TOP-SECRET" not in json.dumps(resp), "symlink escape never sees host secret")

    # State leakage across calls: if every tools/call truly gets a fresh
    # guest instance, this process-global counter resets every time and
    # every response is "1". A "2" here would mean state survived across
    # calls - a real containment failure, not just an unverified claim.
    for i in range(3):
        resp = c.call_tool("counter", {})
        ok(text_of(resp) == "1", "counter call %d returns 1, not accumulated state" % (i + 1))

    resp = c.call_tool("write_file", {"path": "/out/report.txt", "text": CANARY_OUT})
    ok(not is_error_of(resp), "write into rw mount succeeds")
    host_out = os.path.join(work, "out", "report.txt")
    ok(os.path.exists(host_out), "written file appears on the host")
    with open(host_out) as f:
        ok(f.read() == CANARY_OUT, "written content matches")

    resp = c.call_tool("write_file", {"path": "/data/evil.txt", "text": "nope"})
    ok(is_error_of(resp), "write into ro mount fails")
    ok(
        not os.path.exists(os.path.join(work, "data", "evil.txt")),
        "ro mount stayed unwritten on the host",
    )

    resp = c.call_tool("env", {"name": "CAGE_GREETING"})
    ok(text_of(resp) == "CAGE_GREETING=granted-hello", "granted env var visible")

    resp = c.call_tool("env", {"name": "HOME"})
    ok(is_error_of(resp), "ungranted env var invisible")

    t0 = time.time()
    resp = c.call_tool("spin", {}, timeout=30)
    elapsed = time.time() - t0
    err = resp.get("error") or {}
    ok(err.get("code") == -32005, "spin is killed with -32005 (budget)")
    ok(
        (err.get("data") or {}).get("class") in ("timeout", "cpu_budget"),
        "spin kill class is timeout/cpu_budget",
    )
    ok(elapsed < 25, "spin killed within budget window (%.1fs)" % elapsed)

    resp = c.call_tool("shout", {"mb": 1}, timeout=30)
    err = resp.get("error") or {}
    ok(err.get("code") in (-32005, -32000), "shout rejected (%s)" % err.get("code"))
    if err.get("code") == -32005:
        ok(
            (err.get("data") or {}).get("class") == "output_overflow",
            "shout class is output_overflow",
        )
    else:
        CHECKS["passed"] += 1
        print("  ok - shout failed as guest_trap/exit (acceptable)")

    resp = c.call_tool("nope", {})
    ok((resp.get("error") or {}).get("code") == -32602, "unknown tool is -32602")

    resp = c.request("ping")
    ok(resp.get("result") == {}, "ping answers")

    rc = c.close_and_wait()
    ok(rc == 0, "clean exit on EOF (rc=%s)" % rc)


def run_b(work, base_cmd, wasm):
    print("scenario B: restrictive policy, unlisted tools denied and hidden")
    c = Client(
        base_cmd
        + [
            "run",
            "--module",
            wasm,
            "--policy",
            os.path.join(work, "policy-b.yaml"),
            "--audit",
            os.path.join(work, "audit_b.jsonl"),
        ]
    )
    c.handshake()

    resp = c.request("tools/list")
    ok(tool_names(resp) == ["echo"], "only the listed tool is visible")

    resp = c.call_tool("read_file", {"path": "/data/hello.txt"})
    ok((resp.get("error") or {}).get("code") == -32003, "unlisted tool call is -32003")

    resp = c.call_tool("echo", {"text": "still works"})
    ok(text_of(resp) == "echo: still works", "listed tool still works")

    rc = c.close_and_wait()
    ok(rc == 0, "clean exit on EOF (rc=%s)" % rc)


def run_c(work, base_cmd, wasm):
    print("scenario C: no policy = capability vacuum")
    c = Client(base_cmd + ["run", "--module", wasm])

    resp = c.request("tools/list")
    ok(
        (resp.get("error") or {}).get("code") == -32002,
        "requests before initialized are rejected",
    )

    c.handshake()

    resp = c.request("tools/list")
    ok(tool_names(resp) == ALL_TOOLS, "vacuum mode still lists all tools")

    resp = c.call_tool("read_file", {"path": "/data/hello.txt"})
    ok(is_error_of(resp), "no filesystem exists without a policy")
    ok("hello from the cage" not in json.dumps(resp), "vacuum read sees nothing")

    resp = c.call_tool("env", {"name": "HOME"})
    ok(is_error_of(resp), "no env exists without a policy")

    resp = c.call_tool("echo", {"text": "vacuum"})
    ok(text_of(resp) == "echo: vacuum", "pure tools still work in vacuum")

    rc = c.close_and_wait()
    ok(rc == 0, "clean exit on EOF (rc=%s)" % rc)


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    work = sys.argv[1]
    base_cmd = sys.argv[2:-1]
    wasm = sys.argv[-1]
    run_a(work, base_cmd, wasm)
    run_b(work, base_cmd, wasm)
    run_c(work, base_cmd, wasm)
    print("DRIVER OK (%d checks)" % CHECKS["passed"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
