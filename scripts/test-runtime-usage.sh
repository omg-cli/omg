#!/usr/bin/env bash
# Real CLI fresh-start regression for #468. Run as an unprivileged Linux user.
# Downloads pinned Node once per telemetry mode; never changes caller data.
set -euo pipefail
[[ $# == 1 && $1 == /* && -x $1 ]] || { echo 'usage: test-runtime-usage.sh /absolute/path/to/omg' >&2; exit 2; }
[[ $(id -u) != 0 ]] || { echo 'requires an unprivileged user' >&2; exit 2; }
binary=$1
root=$(mktemp -d "$HOME/omg-runtime-usage.XXXXXX")
printf 'Evidence: %s\n' "$root"
# Preserve artifacts on failure; cleanup can follow investigation.
for telemetry in 0 1; do
  (
    umask 0002
    export OMG_DATA_DIR="$root/$telemetry/data" OMG_CACHE_DIR="$root/$telemetry/cache"
    export OMG_CONFIG_DIR="$root/$telemetry/config" OMG_TEST_MODE=0 OMG_DAEMON=0
    export OMG_TELEMETRY=$telemetry OMG_DISABLE_TELEMETRY=0
    for count in 1 2; do
      mkdir -p "$root/$telemetry"
      timeout --kill-after=5s 180 "$binary" use node 24.21.0 > "$root/$telemetry/use-$count.stdout" 2> "$root/$telemetry/use-$count.stderr"
      python3 - "$OMG_DATA_DIR" "$count" <<'PY'
import json, pathlib, stat, sys
root=pathlib.Path(sys.argv[1]); count=int(sys.argv[2])
assert stat.S_IMODE(root.stat().st_mode) == 0o700, 'new data directory is not private'
with (root/'usage.json').open() as f: usage=json.load(f)
assert usage['runtime_usage_counts']['node'] == count, usage
assert usage['commands']['runtime_switch'] == count, usage
assert usage['total_commands'] == count, usage
PY
    done
    "$OMG_DATA_DIR/versions/node/current/bin/node" -e 'if (process.version !== "v24.21.0" || 6*7 !== 42) process.exit(1)'
    printf 'PASS: fresh runtime usage with telemetry=%s\n' "$telemetry"
  )
done
