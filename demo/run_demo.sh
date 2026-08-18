#!/usr/bin/env bash
# Real demo of toolcage's containment story, driven against the compiled
# release binary and the real fixtures/toy-server wasm guest — nothing here
# is simulated. Recorded with asciinema (see README's Demo section).
set -euo pipefail
cd "$(dirname "$0")/.."

BIN="$PWD/target/release/toolcage"
WASM="$PWD/fixtures/toy-server/target/wasm32-wasip1/release/toy-server.wasm"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/data"
echo "hello from the cage" > "$WORK/data/hello.txt"
echo "TOP-SECRET-HOST-FILE u9f3k" > "$WORK/secret.txt"
# A symlink that lives inside the read-only mount but points at a host file
# outside it — the escape vector the containment table calls out separately
# from a literal ".." in the request path.
ln -sf "$WORK/secret.txt" "$WORK/data/escape-link"

cat > "$WORK/policy.yaml" <<EOF
version: 1
defaults:
  timeout_ms: 20000
unlisted_tools: deny
tools:
  echo: {}
  read_file:
    fs:
      /data: { host: $WORK/data, mode: ro }
EOF

echo '$ toolcage inspect --module toy-server.wasm     # zero capabilities granted yet'
"$BIN" inspect --module "$WASM"
echo

echo '$ cat policy.yaml'
cat "$WORK/policy.yaml"
echo

echo '$ toolcage check --policy policy.yaml'
"$BIN" check --policy "$WORK/policy.yaml"
echo

echo '$ toolcage run --module toy-server.wasm --policy policy.yaml --audit audit.jsonl'
echo '  (piping in a client session: initialize, tools/list, three tools/call requests)'
echo

cat > "$WORK/requests.jsonl" <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/data/hello.txt"}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/data/escape-link"}}}
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/data/hello.txt","text":"pwned"}}}
EOF

"$BIN" run --module "$WASM" --policy "$WORK/policy.yaml" --audit "$WORK/audit.jsonl" \
  < "$WORK/requests.jsonl" | while IFS= read -r line; do
    id="$(echo "$line" | jq -r '.id // "notification"')"
    case "$id" in
      2) echo "# tools/list -> policy-filtered: only echo + read_file are visible (write_file exists in the guest but is hidden)" ;;
      3) echo "# read_file /data/hello.txt -> inside the ro mount, succeeds" ;;
      4) echo "# read_file /data/escape-link -> a symlink INSIDE the mount pointing OUTSIDE it, at the host secret" ;;
      5) echo "# write_file -> not listed in policy.yaml at all: denied before the guest ever runs" ;;
    esac
    echo "$line" | jq -c .
    echo
  done

echo '$ tail -3 audit.jsonl | jq -c .    # metadata only — hashes and outcomes, never contents'
tail -3 "$WORK/audit.jsonl" | jq -c .
echo

echo '$ grep -c "TOP-SECRET" audit.jsonl || echo "not found"   # the secret never touched the audit log'
grep -c "TOP-SECRET" "$WORK/audit.jsonl" || echo "not found"
