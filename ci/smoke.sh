#!/usr/bin/env bash
# CI smoke: build the real toolcage binary and the real wasm32-wasip1 guest,
# then drive end-to-end sandbox scenarios (ci/smoke_driver.py) and verify the
# audit trail (ci/audit_check.py).
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build --release
( cd fixtures/toy-server && cargo build --release --target wasm32-wasip1 )

BIN="$PWD/target/release/toolcage"
WASM="$PWD/fixtures/toy-server/target/wasm32-wasip1/release/toy-server.wasm"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

bash ci/make_workdir.sh "$WORK"

"$BIN" --version

echo "--- check: valid policy passes"
"$BIN" check --policy "$WORK/policy-a.yaml"

echo "--- check: missing host dir fails"
if "$BIN" check --policy "$WORK/policy-missing.yaml" >/dev/null 2>&1; then
  echo "expected check to fail on a missing host dir"
  exit 1
fi

echo "--- inspect: capability-free listing"
"$BIN" inspect --module "$WASM"
"$BIN" inspect --module "$WASM" --json > "$WORK/inspect.json"
python3 - "$WORK/inspect.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
names = sorted(t["name"] for t in doc["tools"])
assert names == ["echo", "env", "read_file", "shout", "spin", "write_file"], names
assert doc["serverInfo"]["name"] == "toy-server", doc["serverInfo"]
assert doc["truncated"] is False
print("inspect OK")
PY

echo "--- driver scenarios (real binary, real wasm guest)"
python3 ci/smoke_driver.py "$WORK" "$BIN" "$WASM"

echo "--- audit assertions"
python3 ci/audit_check.py "$WORK"

echo "SMOKE OK"
