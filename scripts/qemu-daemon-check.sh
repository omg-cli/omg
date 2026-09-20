#!/usr/bin/env bash
# Run as the unprivileged guest user against the binaries in the tested archive.
set -euo pipefail
# BEGIN EXPLICIT QUERY ORACLE
check_explicit_query_outputs() {
  local expected=$1 listing=$2 count=$3 shortcut=$4 jsoncount=$5 wanted output
  wanted=$(jq -er 'select(type == "array" and length > 0 and all(.[]; type == "string")) | length' "$expected") || return 1
  jq -e -s --slurpfile expected "$expected" '
    length == 1 and (.[0] | type == "object") and
    (.[0].packages | type == "array") and
    (.[0].packages | sort) == $expected[0] and
    .[0].count == ($expected[0] | length)
  ' "$listing" >/dev/null || return 1
  for output in "$count" "$shortcut"; do
    jq -e -s --argjson wanted "$wanted" 'length == 1 and .[0] == $wanted' "$output" >/dev/null || return 1
  done
  jq -e -s --argjson wanted "$wanted" 'length == 1 and (.[0] | type == "object") and .[0].count == $wanted' "$jsoncount" >/dev/null
}
# END EXPLICIT QUERY ORACLE
# BEGIN BACKEND FAULT ORACLE
check_backend_refusal() {
  local status=$1 stdout=$2 stderr=$3
  [[ "$status" == 1 && ! -s "$stdout" ]] &&
    grep -Fq 'Could not load DNF install reasons: dnf repoquery --userinstalled failed: omg-injected-dnf-reason-failure' "$stderr"
}
# END BACKEND FAULT ORACLE
# BEGIN BACKEND FAULT PROBE
check_fedora_reason_refusal() {
  local binary=$1 state=$2 evidence=$3 uid=$4 gid=$5 status=0
  local fixture="$state/backend-fault"
  [[ "$uid" =~ ^[0-9]+$ && "$uid" != 0 && "$gid" =~ ^[0-9]+$ ]] || return 2
  mkdir "$fixture"
  printf '#!/bin/sh\necho omg-injected-dnf-reason-failure >&2\nexit 17\n' > "$fixture/dnf"
  chmod 755 "$fixture/dnf"
  # The mount is private to this process tree. Drop all capabilities and return
  # to the guest user's identity before running the actual submitted binary.
  timeout --kill-after=5s 30s sudo -n unshare --mount --propagation private -- bash -euc '
    chown 0:0 "$1/dnf"
    chmod 755 "$1/dnf"
    mount --bind "$1/dnf" /usr/bin/dnf
    chown "$3:$4" "$1"
    exec setpriv --reuid="$3" --regid="$4" --clear-groups --no-new-privs \
      --bounding-set=-all --inh-caps=-all --ambient-caps=-all \
      env -i PATH=/usr/bin:/bin HOME="$1" LC_ALL=C NO_COLOR=1 \
      OMG_DATA_DIR="$1/data" OMG_CACHE_DIR="$1/cache" OMG_CONFIG_DIR="$1/config" \
      XDG_DATA_HOME="$1/data" XDG_CACHE_HOME="$1/cache" XDG_CONFIG_HOME="$1/config" \
      OMG_TEST_MODE=0 OMG_DISABLE_DAEMON=1 OMG_DISABLE_TELEMETRY=1 \
      "$2" --json status --fast
  ' _ "$fixture" "$binary" "$uid" "$gid" \
    > "$evidence/dnf-reason-fault.stdout.log" 2> "$evidence/dnf-reason-fault.stderr.log" || status=$?
  printf 'DNF reason failure: product exit=%s\n' "$status"
  head -c 4096 "$evidence/dnf-reason-fault.stderr.log"
  if ! check_backend_refusal "$status" "$evidence/dnf-reason-fault.stdout.log" "$evidence/dnf-reason-fault.stderr.log"; then
    printf 'assertion failed: DNF reason failure did not produce a specific product refusal\n' >&2
    return 1
  fi
  rm -rf -- "$fixture"
  [[ ! -e "$fixture" && ! -L "$fixture" ]]
}
# END BACKEND FAULT PROBE
[[ $# == 2 && $(id -u) != 0 ]] || exit 2
bin=$(realpath "$1")
daemon="${bin%/*}/omgd"
evidence=$(realpath "$2")
[[ -x "$bin" && -x "$daemon" && -d "$evidence" ]] || exit 1
export LC_ALL=C NO_COLOR=1
unset OMG_DISABLE_DAEMON OMG_NO_DAEMON
state=$(mktemp -d "$HOME/omg-daemon-check.XXXXXX")
chmod 700 "$state"
export OMG_SOCKET_PATH="$state/omg.sock"
export OMG_DATA_DIR="$state/data" OMG_DAEMON_DATA_DIR="$state/daemon"
export OMG_CACHE_DIR="$state/cache" OMG_CONFIG_DIR="$state/config"
query_cli() {
  local label=$1
  timeout 15 "$bin" --json explicit > "$evidence/$label-explicit.json"
  timeout 15 "$bin" explicit --count > "$evidence/$label-count.txt"
  timeout 15 "$bin" ec > "$evidence/$label-shortcut.txt"
  timeout 15 "$bin" --json explicit --count > "$evidence/$label-count.json"
  if ! check_explicit_query_outputs "$evidence/native-explicit.json" \
    "$evidence/$label-explicit.json" "$evidence/$label-count.txt" \
    "$evidence/$label-shortcut.txt" "$evidence/$label-count.json"; then
    printf 'assertion failed: %s explicit listing/count differs from native package inventory\n' "$label" >&2
    return 1
  fi
}
daemon_pid= launcher_pid=
cleanup() {
  local status=$?
  trap - EXIT
  # Only terminate children started by this probe, never a name-wide pkill.
  if [[ -n "$daemon_pid" ]] && kill -0 "$daemon_pid" 2>/dev/null; then
    kill -TERM "$daemon_pid" 2>/dev/null || true
    for _ in {1..50}; do kill -0 "$daemon_pid" 2>/dev/null || break; sleep 0.1; done
    kill -KILL "$daemon_pid" 2>/dev/null || true
  fi
  if [[ -n "$launcher_pid" ]]; then
    kill -TERM "$launcher_pid" 2>/dev/null || true
    wait "$launcher_pid" 2>/dev/null || true
  fi
  if ! rm -rf -- "$state" || [[ -e "$state" || -L "$state" ]]; then
    printf 'assertion failed: daemon fixture cleanup failed\n' >&2
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
# Independent native inventory, captured before starting either daemon mode.
# Register cleanup first, including failures while querying this reference.
# These commands query package state; none installs or removes packages.
source /etc/os-release
case "$ID" in
  arch) timeout 30 pacman -Qqe > "$evidence/native-explicit.txt" ;;
  debian|ubuntu) timeout 30 apt-mark showmanual > "$evidence/native-explicit.txt" ;;
  fedora) timeout 30 dnf --cacheonly repoquery --userinstalled --qf '%{name}\n' > "$evidence/native-explicit.txt" ;;
  *) printf 'Unsupported native query fixture: %s\n' "$ID" >&2; exit 2 ;;
esac
jq -Rn '[inputs | select(length > 0)] | sort | unique' < "$evidence/native-explicit.txt" > "$evidence/native-explicit.json"
for mode in direct foreground direct-sigint foreground-sigint; do
  if [[ "$mode" == direct* ]]; then
    "$daemon" > "$evidence/daemon-$mode.log" 2>&1 &
    launcher_pid=$!; daemon_pid=$launcher_pid
  else
    "$bin" daemon --foreground > "$evidence/daemon-$mode.log" 2>&1 &
    launcher_pid=$!
    for _ in {1..100}; do
      kill -0 "$launcher_pid"
      # Tokio may spawn from a worker thread; inspect every thread's children.
      for children_file in /proc/"$launcher_pid"/task/*/children; do
        [[ -r "$children_file" ]] || continue
        for child in $(cat "$children_file"); do
          if [[ $(readlink "/proc/$child/exe" 2>/dev/null) == "$daemon" ]]; then daemon_pid=$child; break; fi
        done
        [[ -z "$daemon_pid" ]] || break
      done
      [[ -z "$daemon_pid" ]] || break
      sleep 0.1
    done
    [[ -n "$daemon_pid" ]]
  fi
  ready=false
  for _ in {1..30}; do
    kill -0 "$daemon_pid"
    if [[ -S "$OMG_SOCKET_PATH" ]] && timeout 5 "$bin" daemon-status > "$evidence/daemon-$mode-status.txt" 2>&1 \
      && grep -Fq 'Daemon is running' "$evidence/daemon-$mode-status.txt" \
      && grep -Fq 'Requests total:' "$evidence/daemon-$mode-status.txt"; then ready=true; break; fi
    sleep 0.2
  done
  [[ "$ready" == true ]]
  [[ $(readlink "/proc/$daemon_pid/exe") == "$daemon" ]]
  [[ $(stat -c '%u' "$OMG_SOCKET_PATH") == "$(id -u)" ]]
  [[ $(stat -c '%a' "$OMG_SOCKET_PATH") == 600 ]]
  requests_before=$(awk '/Requests total:/ {print $NF}' "$evidence/daemon-$mode-status.txt")
  [[ "$requests_before" =~ ^[0-9]+$ ]]
  query_cli "daemon-$mode"
  timeout 5 "$bin" daemon-status > "$evidence/daemon-$mode-after-queries.txt" 2>&1
  requests_after=$(awk '/Requests total:/ {print $NF}' "$evidence/daemon-$mode-after-queries.txt")
  failed_after=$(awk '/Requests failed:/ {print $NF}' "$evidence/daemon-$mode-after-queries.txt")
  [[ "$requests_after" =~ ^[0-9]+$ && "$failed_after" == 0 ]]
  # daemon-status itself contributes three requests between snapshots: the
  # preceding Status plus the following Ping and Metrics. The three explicit
  # forms use IPC; ec can legitimately read the daemon's binary status cache.
  # Do not count diagnostic traffic as query coverage or require ec to lose
  # its zero-IPC fast path once the background worker publishes that cache.
  if [[ "$requests_after" -lt $((requests_before + 6)) ]]; then
    printf 'assertion failed: %s queries did not produce enough daemon requests (%s -> %s requests)\n' "$mode" "$requests_before" "$requests_after" >&2
    exit 1
  fi
  inode=$(stat -c '%i' "$OMG_SOCKET_PATH")
  # A second direct daemon must fail, not replace the live socket or hang.
  duplicate_status=0
  timeout 5 "$daemon" > "$evidence/daemon-$mode-duplicate.txt" 2>&1 || duplicate_status=$?
  [[ "$duplicate_status" != 0 && "$duplicate_status" != 124 && "$duplicate_status" != 137 ]]
  grep -Fq 'Another omgd daemon owns' "$evidence/daemon-$mode-duplicate.txt"
  [[ $(stat -c '%i' "$OMG_SOCKET_PATH") == "$inode" ]]
  timeout 5 "$bin" daemon > "$evidence/daemon-$mode-launcher.txt" 2>&1
  grep -Fq 'already running' "$evidence/daemon-$mode-launcher.txt"
  if [[ "$mode" == *-sigint ]]; then
    kill -INT "$daemon_pid"
  else
    kill -TERM "$daemon_pid"
  fi
  stopped=false
  for _ in {1..150}; do
    if ! kill -0 "$launcher_pid" 2>/dev/null; then stopped=true; break; fi
    sleep 0.2
  done
  [[ "$stopped" == true ]]
  wait "$launcher_pid"
  daemon_pid= launcher_pid=
  [[ ! -e "$OMG_SOCKET_PATH" && ! -L "$OMG_SOCKET_PATH" ]]
done
OMG_DISABLE_DAEMON=1 query_cli daemon-stopped
backend_faults='[]'
if [[ "$ID" == fedora ]]; then
  check_fedora_reason_refusal "$bin" "$state" "$evidence" "$(id -u)" "$(id -g)"
  backend_faults='["dnf-reason-refusal"]'
fi
# Cleanup is part of success, so it must precede the positive receipt.
rm -rf -- "$state"
[[ ! -e "$state" && ! -L "$state" ]]
jq -n --argjson faults "$backend_faults" '{schema_version:1,direct:true,foreground:true,ipc:true,singleton:true,shutdown:true,restart:true,query_parity:true,sigint:true,cleanup:true,backend_faults:$faults}' > "$evidence/daemon-lifecycle.json"
