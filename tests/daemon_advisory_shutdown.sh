#!/usr/bin/env bash
# Fedora integration regression. Run as root in a disposable test host:
# bash tests/daemon_advisory_shutdown.sh /absolute/path/to/omgd unprivileged-user
# Only this process tree sees the replacement DNF command.
set -euo pipefail
if [[ $# != 2 || $(id -u) != 0 ]]; then
  echo 'usage (root): daemon_advisory_shutdown.sh /path/to/omgd test-user' >&2
  exit 2
fi
binary=$(realpath "$1")
user=$2
[[ -x "$binary" && $(id -u "$user") != 0 ]]
root=$(mktemp -d /tmp/omg-advisory-shutdown.XXXXXX)
trap 'rm -rf -- "$root"' EXIT
chmod 755 "$root"
cp -L /usr/bin/dnf "$root/dnf-real"
mkdir "$root/evidence"
chmod 700 "$root/evidence"
chown "$user" "$root/evidence"
cat > "$root/dnf" <<'WRAPPER'
#!/bin/bash
for arg in "$@"; do
  if [[ "$arg" == *dnf-security* ]]; then
    echo $$ > "$OMG_SHUTDOWN_FIXTURE/evidence/advisory.pid"
    exec sleep 90
  fi
done
exec "$OMG_SHUTDOWN_FIXTURE/dnf-real" "$@"
WRAPPER
chmod 755 "$root/dnf" "$root/dnf-real"
cat > "$root/probe" <<'PROBE'
#!/bin/bash
set -euo pipefail
root=$OMG_SHUTDOWN_FIXTURE/evidence
export OMG_SOCKET_PATH="$root/omg.sock" OMG_DAEMON_DATA_DIR="$root/daemon"
export OMG_DATA_DIR="$root/data" OMG_CACHE_DIR="$root/cache" OMG_CONFIG_DIR="$root/config"
export OMG_DISABLE_TELEMETRY=1 RUST_LOG=debug NO_COLOR=1
unset OMG_DISABLE_DAEMON OMG_NO_DAEMON
"$1" > "$root/daemon.log" 2>&1 &
daemon_pid=$!
cleanup() {
  status=$?
  trap - EXIT
  if [[ -n "$daemon_pid" ]] && kill -0 "$daemon_pid" 2>/dev/null; then
    kill -KILL "$daemon_pid" 2>/dev/null || true
  fi
  if [[ -n "$daemon_pid" ]]; then wait "$daemon_pid" 2>/dev/null || true; fi
  cat "$root/daemon.log"
  exit "$status"
}
trap cleanup EXIT
for _ in {1..300}; do
  [[ ! -s "$root/advisory.pid" ]] || break
  kill -0 "$daemon_pid"
  sleep 0.1
done
test -s "$root/advisory.pid"
started=$SECONDS
kill -TERM "$daemon_pid"
status=0
wait "$daemon_pid" || status=$?
daemon_pid=
elapsed=$((SECONDS-started))
printf 'daemon_exit=%s shutdown_seconds=%s\n' "$status" "$elapsed"
[[ "$status" == 0 && "$elapsed" -lt 10 ]]
! grep -Fq 'Security audit completed' "$root/daemon.log"
child=$(cat "$root/advisory.pid")
for _ in {1..50}; do
  kill -0 "$child" 2>/dev/null || break
  sleep 0.1
done
! kill -0 "$child" 2>/dev/null
[[ ! -e "$OMG_SOCKET_PATH" && ! -L "$OMG_SOCKET_PATH" ]]
echo 'PASS: cancelled advisory, reaped child, no false completed scan, socket removed'
PROBE
chmod 755 "$root/probe"
timeout --kill-after=5s 75s unshare --mount --propagation private -- bash -euc '
  mount --bind "$1/dnf" /usr/bin/dnf
  exec runuser -u "$3" -- env OMG_SHUTDOWN_FIXTURE="$1" bash "$1/probe" "$2"
' _ "$root" "$binary" "$user"
