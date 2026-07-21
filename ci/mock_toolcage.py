#!/usr/bin/env python3
"""Harness-validation mock of `toolcage run`.

This is NOT toolcage. It is a tiny Python stand-in that reproduces the
client-visible semantics the smoke driver asserts, so that smoke_driver.py
and audit_check.py can themselves be tested in environments without a Rust
toolchain (the harness that checks the sandbox deserves its own check).
Scenario semantics are keyed off the policy filename that ci/smoke.sh
generates (policy-a.yaml / policy-b.yaml / none), not by parsing YAML.

Usage mirrors toolcage: mock_toolcage.py run --module X [--policy P] [--audit A]
"""

import base64
import hashlib
import hmac
import json
import os
import sys
import time

ALL_TOOLS = ["echo", "read_file", "write_file", "env", "spin", "shout", "counter"]

# Per-process cursor key, mirroring toolcage's ephemeral-key design: cursors do
# not survive a restart and cannot be forged. (This mock only needs the same
# client-visible contract, not byte-identical cursors — the driver is opaque.)
PAGE_KEY = os.urandom(32)


def _snapshot_id(names):
    h = hashlib.sha256()
    h.update(len(names).to_bytes(8, "little"))
    for n in names:
        h.update(len(n).to_bytes(8, "little"))
        h.update(n.encode())
    return h.digest()[:8]


def _encode_cursor(offset, snap):
    body = offset.to_bytes(4, "big") + snap
    tag = hmac.new(PAGE_KEY, body, hashlib.sha256).digest()[:16]
    return "tc1." + base64.urlsafe_b64encode(body + tag).decode().rstrip("=")


def _decode_cursor(cursor, snap, total, page_size):
    """Return the offset, or None if the cursor is invalid/tampered/expired."""
    if not isinstance(cursor, str) or not cursor.startswith("tc1."):
        return None
    b = cursor[4:]
    try:
        raw = base64.urlsafe_b64decode(b + "=" * (-len(b) % 4))
    except (ValueError, TypeError):
        return None
    if len(raw) != 28:
        return None
    body, tag = raw[:12], raw[12:]
    expect = hmac.new(PAGE_KEY, body, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(expect, tag):
        return None
    if body[4:12] != snap:
        return None
    offset = int.from_bytes(body[:4], "big")
    if offset == 0 or offset >= total or offset % page_size != 0:
        return None
    return offset


def now_rfc3339():
    ms = int(time.time() * 1000)
    t = time.gmtime(ms // 1000)
    return time.strftime("%Y-%m-%dT%H:%M:%S", t) + ".%03dZ" % (ms % 1000)


class Audit:
    def __init__(self, path):
        self.f = None
        if path:
            fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
            self.f = os.fdopen(fd, "w")

    def log(self, event, **fields):
        line = json.dumps({"ts": now_rfc3339(), "event": event, **fields})
        out = self.f if self.f else sys.stderr
        out.write(line + "\n")
        out.flush()


def sha256_of_file_or_name(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return hashlib.sha256(path.encode()).hexdigest()


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def parse_args(argv):
    opts = {"module": None, "policy": None, "audit": None, "page_size": 0}
    it = iter(argv)
    for a in it:
        if a == "run":
            continue
        if a in ("--module", "--policy", "--audit"):
            opts[a[2:]] = next(it)
        elif a == "--page-size":
            opts["page_size"] = int(next(it))
    return opts


def main():
    opts = parse_args(sys.argv[1:])
    scenario = "c"
    if opts["policy"]:
        base = os.path.basename(opts["policy"])
        scenario = "a" if "policy-a" in base else "b"
    work = os.path.dirname(os.path.abspath(opts["policy"])) if opts["policy"] else None
    audit = Audit(opts["audit"])
    page_size = opts["page_size"]

    listed = {"a": ALL_TOOLS, "b": ["echo"], "c": ALL_TOOLS}[scenario]
    mounts = {}
    env_grant = {}
    if scenario == "a":
        mounts = {"/data": (os.path.join(work, "data"), "ro"), "/out": (os.path.join(work, "out"), "rw")}
        env_grant = {"CAGE_GREETING": "granted-hello"}

    audit.log(
        "session_start",
        toolcage_version="0.1.0-mock",
        module=opts["module"],
        module_sha256=sha256_of_file_or_name(opts["module"]),
        policy=opts["policy"],
        policy_sha256=sha256_of_file_or_name(opts["policy"]) if opts["policy"] else None,
    )
    audit.log(
        "probe",
        tools=ALL_TOOLS,
        tool_count=len(ALL_TOOLS),
        truncated=False,
        protocol="2025-06-18",
        duration_ms=3,
        exit_code=0,
    )

    initialized = False
    calls = 0

    def reply(obj):
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()

    def error(mid, code, message, data=None):
        err = {"code": code, "message": message}
        if data is not None:
            err["data"] = data
        reply({"jsonrpc": "2.0", "id": mid, "error": err})

    def text_result(mid, is_error, text):
        return {
            "jsonrpc": "2.0",
            "id": mid,
            "result": {"content": [{"type": "text", "text": text}], "isError": is_error},
        }

    def resolve(guest_path):
        for g, (host, mode) in mounts.items():
            if guest_path == g or guest_path.startswith(g + "/"):
                real = os.path.realpath(os.path.join(host, guest_path[len(g) + 1 :]))
                if not (real + "/").startswith(os.path.realpath(host) + "/") and real != os.path.realpath(host):
                    return None, mode
                return real, mode
        return None, None

    def finish_call(name, args_b, outcome, is_error=None, result_b=None, grant_meta=True, timeout_ms=None):
        fields = {
            "tool": name,
            "decision": "allow",
            "args_bytes": len(args_b),
            "args_sha256": sha256_bytes(args_b),
            "duration_ms": 4,
            "stdout_bytes": 200,
            "stderr_bytes": 0,
            "garbage_lines": 0,
            "timeout_ms": timeout_ms if timeout_ms else 20000,
            "mounts": ["%s:%s" % (g, m[1]) for g, m in mounts.items() if name in ("read_file", "write_file")],
            "fuel_used": 12345,
            "outcome": outcome,
        }
        if outcome == "ok":
            fields["exit_code"] = 0
            fields["is_error"] = bool(is_error)
            fields["result_bytes"] = len(result_b or b"")
            fields["result_sha256"] = sha256_bytes(result_b or b"")
        audit.log("call", **fields)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            error(None, -32700, "parse error")
            continue
        method = msg.get("method", "")
        mid = msg.get("id")
        params = msg.get("params") or {}
        if mid is None:
            if method == "notifications/initialized":
                initialized = True
            continue
        if method == "initialize":
            req = params.get("protocolVersion")
            proto = req if req in ("2025-06-18", "2025-03-26", "2024-11-05") else "2025-06-18"
            audit.log("client_initialize", protocol=proto, requested=req)
            reply(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {
                        "protocolVersion": proto,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "toolcage", "version": "0.1.0-mock"},
                    },
                }
            )
        elif method == "ping":
            reply({"jsonrpc": "2.0", "id": mid, "result": {}})
        elif not initialized:
            error(mid, -32002, "server not initialized")
        elif method == "tools/list":
            visible = [n for n in ALL_TOOLS if n in listed]

            def tool_obj(n):
                return {"name": n, "description": n, "inputSchema": {"type": "object"}}

            if page_size == 0:
                # Pagination disabled: one page, cursor ignored (back-compat).
                result = {"tools": [tool_obj(n) for n in visible]}
            else:
                snap = _snapshot_id(visible)
                total = len(visible)
                cursor = params.get("cursor")
                if cursor is None:
                    start = 0
                elif not isinstance(cursor, str):
                    error(mid, -32602, "tools/list cursor must be a string")
                    continue
                else:
                    off = _decode_cursor(cursor, snap, total, page_size)
                    if off is None:
                        error(mid, -32602, "invalid or expired tools/list cursor")
                        continue
                    start = off
                end = min(start + page_size, total)
                result = {"tools": [tool_obj(n) for n in visible[start:end]]}
                if end < total:
                    result["nextCursor"] = _encode_cursor(end, snap)
            reply({"jsonrpc": "2.0", "id": mid, "result": result})
        elif method == "tools/call":
            calls += 1
            name = params.get("name", "")
            args = params.get("arguments")
            args_b = json.dumps(args, separators=(",", ":")).encode() if args is not None else b"null"
            if name not in ALL_TOOLS:
                audit.log(
                    "call",
                    tool=name,
                    decision="deny_unknown_tool",
                    args_bytes=len(args_b),
                    args_sha256=sha256_bytes(args_b),
                )
                error(mid, -32602, "unknown tool: %s" % name)
                continue
            if name not in listed:
                audit.log(
                    "call",
                    tool=name,
                    decision="deny_unlisted",
                    args_bytes=len(args_b),
                    args_sha256=sha256_bytes(args_b),
                )
                error(mid, -32003, "tool %r is not listed in the policy (default deny)" % name)
                continue
            args = args or {}
            if name == "echo":
                r = text_result(mid, False, "echo: %s" % args.get("text", ""))
            elif name == "read_file":
                real, mode = resolve(args.get("path", ""))
                if real is None:
                    r = text_result(mid, True, "read error: not capable")
                else:
                    try:
                        r = text_result(mid, False, open(real).read())
                    except OSError as e:
                        r = text_result(mid, True, "read error: %s" % e)
            elif name == "write_file":
                real, mode = resolve(args.get("path", ""))
                if real is None or mode != "rw":
                    r = text_result(mid, True, "write error: not capable")
                else:
                    with open(real, "w") as f:
                        f.write(args.get("text", ""))
                    r = text_result(mid, False, "wrote")
            elif name == "env":
                var = args.get("name", "")
                if var in env_grant:
                    r = text_result(mid, False, "%s=%s" % (var, env_grant[var]))
                else:
                    r = text_result(mid, True, "%s is not set" % var)
            elif name == "spin":
                time.sleep(0.5)
                finish_call(name, args_b, "timeout", timeout_ms=3000)
                error(mid, -32005, "tool call exceeded its wall-clock budget",
                      {"class": "timeout", "detail": "mock"})
                continue
            elif name == "shout":
                finish_call(name, args_b, "output_overflow")
                error(mid, -32005, "tool call exceeded its output budget",
                      {"class": "output_overflow", "detail": "mock"})
                continue
            elif name == "counter":
                # Real toolcage gives every call a fresh Store, so the
                # guest's global counter resets each time. The mock process
                # itself doesn't restart per call, so it just always answers
                # "1" - the value the fresh-instance guarantee predicts.
                r = text_result(mid, False, "1")
            result_b = json.dumps(r["result"], separators=(",", ":")).encode()
            finish_call(name, args_b, "ok", is_error=r["result"]["isError"], result_b=result_b)
            reply(r)
        else:
            error(mid, -32601, "method not found: %s" % method)

    audit.log("session_end", calls=calls, duration_ms=9)
    return 0


if __name__ == "__main__":
    sys.exit(main())
