#!/usr/bin/env bash
# Prepare a smoke workdir: mount directories, canary files, and the three
# policies the driver scenarios use. Shared by CI smoke and by the local
# harness-validation run against ci/mock_toolcage.py.
set -euo pipefail

WORK="$1"
mkdir -p "$WORK/data" "$WORK/out"
echo "hello from the cage" > "$WORK/data/hello.txt"
echo "TOP-SECRET-HOST-FILE u9f3k" > "$WORK/secret.txt"

cat > "$WORK/policy-a.yaml" <<EOF
version: 1
defaults:
  timeout_ms: 20000
  fuel: 2000000000
  memory_max_mb: 128
  output_max_kb: 256
unlisted_tools: deny
tools:
  echo: {}
  env:
    env:
      CAGE_GREETING: "granted-hello"
  read_file:
    fs:
      /data: { host: $WORK/data, mode: ro }
  write_file:
    fs:
      /out: { host: $WORK/out, mode: rw }
      /data: { host: $WORK/data, mode: ro }
  spin:
    timeout_ms: 3000
    fuel: 400000000
  shout:
    output_max_kb: 64
EOF

cat > "$WORK/policy-b.yaml" <<EOF
version: 1
tools:
  echo: {}
EOF

cat > "$WORK/policy-missing.yaml" <<EOF
version: 1
tools:
  t:
    fs:
      /gone: { host: $WORK/does-not-exist, mode: ro }
EOF
