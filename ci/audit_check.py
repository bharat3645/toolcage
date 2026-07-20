#!/usr/bin/env python3
"""Audit-trail assertions for the smoke run.

Usage: audit_check.py WORKDIR

Checks audit_a.jsonl and audit_b.jsonl written by the smoke driver scenarios:
schema shape, decisions, outcomes, permissions, and above all the privacy
invariant: tool arguments, results, env values, and file contents must NEVER
appear in the audit trail. Hashes and byte counts only.
"""

import json
import os
import re
import stat
import sys

HEX64 = re.compile(r"^[0-9a-f]{64}$")

CHECKS = {"passed": 0}


def ok(cond, label):
    if not cond:
        raise AssertionError("FAILED: %s" % label)
    CHECKS["passed"] += 1
    print("  ok - %s" % label)


def load(path):
    events = []
    with open(path) as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            ev = json.loads(line)
            ok("ts" in ev and "event" in ev, "%s:%d has ts+event" % (os.path.basename(path), n))
            events.append(ev)
    return events


def calls_for(events, tool):
    return [e for e in events if e["event"] == "call" and e.get("tool") == tool]


def check_perms(path):
    if os.name == "posix":
        mode = stat.S_IMODE(os.stat(path).st_mode)
        ok(mode == 0o600, "%s is 0600 (got %o)" % (os.path.basename(path), mode))


def check_a(work):
    path = os.path.join(work, "audit_a.jsonl")
    print("audit A: %s" % path)
    check_perms(path)
    events = load(path)
    raw = open(path).read()

    starts = [e for e in events if e["event"] == "session_start"]
    ok(len(starts) == 1, "exactly one session_start")
    ok(HEX64.match(starts[0].get("module_sha256", "")), "module_sha256 is a sha256")
    ok(HEX64.match(starts[0].get("policy_sha256") or ""), "policy_sha256 is a sha256")

    probes = [e for e in events if e["event"] == "probe"]
    ok(len(probes) == 1, "exactly one probe")
    ok(probes[0].get("tool_count") == 7, "probe saw 7 tools")
    ok(probes[0].get("truncated") is False, "probe not truncated")

    echo_calls = calls_for(events, "echo")
    ok(len(echo_calls) == 1, "one echo call audited")
    e = echo_calls[0]
    ok(e.get("decision") == "allow", "echo decision allow")
    ok(e.get("outcome") == "ok", "echo outcome ok")
    ok(e.get("is_error") is False, "echo is_error false")
    ok(HEX64.match(e.get("args_sha256", "")), "echo args_sha256 is a sha256")
    ok(HEX64.match(e.get("result_sha256", "")), "echo result_sha256 is a sha256")
    ok(isinstance(e.get("fuel_used"), int) and e["fuel_used"] > 0, "echo fuel_used > 0")
    ok(e.get("exit_code") == 0, "echo guest exited 0")

    reads = calls_for(events, "read_file")
    ok(len(reads) == 4, "four read_file calls audited")
    ok(all(r.get("decision") == "allow" for r in reads), "read_file decisions allow")
    escapes = [r for r in reads if r.get("is_error")]
    ok(
        len(escapes) == 3,
        "three read_file attempts flagged is_error (dot-dot escape, symlink escape, unmounted)",
    )

    counters = calls_for(events, "counter")
    ok(len(counters) == 3, "three counter calls audited")
    ok(all(c.get("decision") == "allow" and c.get("outcome") == "ok" for c in counters), "counter decisions/outcomes ok")

    writes = calls_for(events, "write_file")
    ok(len(writes) == 2, "two write_file calls audited")
    ok(len([w for w in writes if w.get("is_error")]) == 1, "ro write flagged is_error")

    spins = calls_for(events, "spin")
    ok(len(spins) == 1, "one spin call audited")
    ok(
        spins[0].get("outcome") in ("timeout", "cpu_budget"),
        "spin outcome is timeout/cpu_budget (got %s)" % spins[0].get("outcome"),
    )

    shouts = calls_for(events, "shout")
    ok(len(shouts) == 1, "one shout call audited")
    ok(
        shouts[0].get("outcome") in ("output_overflow", "guest_trap", "guest_exit"),
        "shout outcome contained (got %s)" % shouts[0].get("outcome"),
    )

    unknown = [e for e in events if e["event"] == "call" and e.get("tool") == "nope"]
    ok(len(unknown) == 1 and unknown[0].get("decision") == "deny_unknown_tool",
       "unknown tool audited as deny_unknown_tool")

    ends = [e for e in events if e["event"] == "session_end"]
    ok(len(ends) == 1, "exactly one session_end")
    ok(ends[0].get("calls") == 15, "session_end counts 15 tools/call requests (got %s)" % ends[0].get("calls"))

    for canary in (
        "CANARY_ARG_77f2",
        "TOP-SECRET",
        "granted-hello",
        "cage-out u3h8",
        "hello from the cage",
    ):
        ok(canary not in raw, "privacy: %r absent from audit" % canary)


def check_b(work):
    path = os.path.join(work, "audit_b.jsonl")
    print("audit B: %s" % path)
    check_perms(path)
    events = load(path)

    reads = calls_for(events, "read_file")
    ok(len(reads) == 1, "one read_file call audited")
    ok(reads[0].get("decision") == "deny_unlisted", "read_file denied as unlisted")
    ok("mounts" not in reads[0], "denied call carries no grant details")

    echoes = calls_for(events, "echo")
    ok(len(echoes) == 1 and echoes[0].get("outcome") == "ok", "echo ok")


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    work = sys.argv[1]
    check_a(work)
    check_b(work)
    print("AUDIT OK (%d checks)" % CHECKS["passed"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
