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
report_explicit_query_difference() {
  local expected=$1 listing=$2 label=$3
  jq -r -s --slurpfile expected "$expected" --arg label "$label" '
    if length == 1 and (.[0] | type == "object") and
       (.[0].packages | type == "array") and
       ($expected | length == 1) and ($expected[0] | type == "array") then
      .[0].packages as $actual |
      (($expected[0] - $actual) | unique) as $native_only |
      (($actual - $expected[0]) | unique) as $omg_only |
      ($actual | sort | group_by(.) | map(select(length > 1) | .[0])) as $omg_duplicates |
      "\($label) native_count=\($expected[0] | length) omg_count=\($actual | length)",
      "native_only=\($native_only[0:50] | @json)",
      "omg_only=\($omg_only[0:50] | @json)",
      "omg_duplicates=\($omg_duplicates[0:50] | @json)",
      "difference_truncated=\(($native_only | length) > 50 or ($omg_only | length) > 50 or ($omg_duplicates | length) > 50)"
    else
      "\($label) package listing was not a single valid query document"
    end
  ' "$listing" >&2
}
# END EXPLICIT QUERY ORACLE
# BEGIN PACKAGE QUERY ORACLE
check_package_query_outputs() {
  local name=$1 daemon_search=$2 daemon_info=$3 direct_search=$4 direct_info=$5
  jq -e -s --arg name "$name" '
    def match_package($rows): $rows | map(select(.name == $name)) | .[0];
    def valid_search($rows):
      if ($rows | type) != "array" then false
      else ($rows | length) <= 50 and
        ([$rows[] | select(.name == $name)] | length) == 1 and
        (match_package($rows) |
          (.version | type) == "string" and (.version | length) > 0 and
          (.description | type) == "string" and (.description | length) > 0 and
          (.source | type) == "string" and
          (.source as $source | (["official", "apt"] | index($source | ascii_downcase)) != null))
      end;
    def valid_info($record):
      ($record | type) == "object" and $record.name == $name and
      ($record.version | type) == "string" and ($record.version | length) > 0 and
      ($record.description | type) == "string" and ($record.description | length) > 0 and
      $record.installed == true;
    length == 4 and
    (.[0] as $daemon_search | .[1] as $daemon_info |
     .[2] as $direct_search | .[3] as $direct_info |
     valid_search($daemon_search) and valid_search($direct_search) and
     valid_info($daemon_info) and valid_info($direct_info) and
     (match_package($daemon_search).version == $daemon_info.version) and
     (match_package($direct_search).version == $direct_info.version) and
     ($daemon_info.version == $direct_info.version))
  ' "$daemon_search" "$daemon_info" "$direct_search" "$direct_info" >/dev/null
}
# END PACKAGE QUERY ORACLE
# BEGIN PACKAGE IPC ORACLE
metric_counter() {
  local file=$1 metric=$2
  awk -v metric="$metric" '
    $1 == metric {
      found++
      if (NF == 2 && $2 ~ /^(0|[1-9][0-9]*)$/) value=$2
      else invalid=1
    }
    END {
      if (found != 1 || invalid) exit 1
      print value
    }
  ' "$file"
}
check_package_ipc_delta() {
  local before=$1 after=$2 expected_search=$3 expected_info=$4
  local search_before search_after info_before info_after
  [[ "$expected_search" == 0 || "$expected_search" == 1 ]] || return 2
  [[ "$expected_info" == 0 || "$expected_info" == 1 ]] || return 2
  search_before=$(metric_counter "$before" omg_search_requests_total) || return 1
  search_after=$(metric_counter "$after" omg_search_requests_total) || return 1
  info_before=$(metric_counter "$before" omg_info_requests_total) || return 1
  info_after=$(metric_counter "$after" omg_info_requests_total) || return 1
  (( search_after - search_before == expected_search && info_after - info_before == expected_info ))
}
# END PACKAGE IPC ORACLE
# BEGIN INFO PROVENANCE ORACLE
check_daemon_info_provenance() {
  local daemon_info=$1 native_info=$2
  jq -e -s '
    length == 2 and
    (.[0] | type) == "object" and (.[1] | type) == "object" and
    .[0].source == "Official" and
    (.[0].download_size | type) == "number" and
    (.[1].source != "Official" or (.[1].download_size | type) != "number")
  ' "$daemon_info" "$native_info" >/dev/null
}
# END INFO PROVENANCE ORACLE
# BEGIN TEXT INFO ORACLE
check_text_info_outputs() {
  local name=$1 daemon_output=$2 direct_output=$3 output
  for output in "$daemon_output" "$direct_output"; do
    grep -Eq "^[[:space:]]+Name: ${name}$" "$output" || return 1
    grep -Eq '^[[:space:]]+Installed: yes$' "$output" || return 1
  done
}
# END TEXT INFO ORACLE
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
case "${OMG_QEMU_ACCEL:-kvm}" in
  kvm) readiness_attempts=30; child_attempts=100; command_timeout=15; status_timeout=5 ;;
  tcg) readiness_attempts=300; child_attempts=300; command_timeout=60; status_timeout=30 ;;
  *) printf 'Unsupported QEMU acceleration mode: %s\n' "$OMG_QEMU_ACCEL" >&2; exit 2 ;;
esac
state=$(mktemp -d "$HOME/omg-daemon-check.XXXXXX")
chmod 700 "$state"
export OMG_SOCKET_PATH="$state/omg.sock"
export OMG_DATA_DIR="$state/data" OMG_DAEMON_DATA_DIR="$state/daemon"
export OMG_CACHE_DIR="$state/cache" OMG_CONFIG_DIR="$state/config"
query_cli() {
  local label=$1
  timeout "$command_timeout" "$bin" --json explicit > "$evidence/$label-explicit.json"
  timeout "$command_timeout" "$bin" explicit --count > "$evidence/$label-count.txt"
  timeout "$command_timeout" "$bin" ec > "$evidence/$label-shortcut.txt"
  timeout "$command_timeout" "$bin" --json explicit --count > "$evidence/$label-count.json"
  if ! check_explicit_query_outputs "$evidence/native-explicit.json" \
    "$evidence/$label-explicit.json" "$evidence/$label-count.txt" \
    "$evidence/$label-shortcut.txt" "$evidence/$label-count.json"; then
    report_explicit_query_difference "$evidence/native-explicit.json" \
      "$evidence/$label-explicit.json" "$label"
    printf 'assertion failed: %s explicit listing/count differs from native package inventory\n' "$label" >&2
    return 1
  fi
}
query_package_cli() {
  local label=$1
  if [[ "$label" == daemon-direct ]]; then
    timeout 5 "$bin" metrics > "$evidence/$label-before-search.prom"
  fi
  timeout 15 "$bin" --json search --no-aur --limit 50 bash > "$evidence/$label-search.json"
  if [[ "$label" == daemon-direct ]]; then
    timeout 5 "$bin" metrics > "$evidence/$label-after-search.prom"
    if ! check_package_ipc_delta "$evidence/$label-before-search.prom" \
      "$evidence/$label-after-search.prom" 1 0; then
      printf 'assertion failed: daemon search did not use one Search IPC request\n' >&2
      return 1
    fi
  fi
  timeout 15 "$bin" --json info bash > "$evidence/$label-info.json"
  if [[ "$label" == daemon-direct ]]; then
    timeout 5 "$bin" metrics > "$evidence/$label-after-info.prom"
    if ! check_package_ipc_delta "$evidence/$label-after-search.prom" \
      "$evidence/$label-after-info.prom" 0 1; then
      printf 'assertion failed: daemon JSON info did not use one Info IPC request\n' >&2
      return 1
    fi
  fi
  timeout 15 "$bin" info bash > "$evidence/$label-info.txt"
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
  arch) timeout 30 pacman -Qq bash >/dev/null; timeout 30 pacman -Qqe > "$evidence/native-explicit.txt" ;;
  debian|ubuntu) timeout 30 dpkg-query -W bash >/dev/null; timeout 30 apt-mark showmanual > "$evidence/native-explicit.txt" ;;
  fedora) timeout 30 rpm -q bash >/dev/null; timeout 30 dnf --cacheonly repoquery --userinstalled --qf '%{name}\n' > "$evidence/native-explicit.txt" ;;
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
    for ((attempt=0; attempt<child_attempts; attempt++)); do
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
  for ((attempt=0; attempt<readiness_attempts; attempt++)); do
    if ! kill -0 "$daemon_pid" 2>/dev/null; then
      printf 'assertion failed: %s daemon exited before its socket was ready\n' "$mode" >&2
      tail -n 25 "$evidence/daemon-$mode.log" >&2
      exit 1
    fi
    if [[ -S "$OMG_SOCKET_PATH" ]] && timeout "$status_timeout" "$bin" daemon-status > "$evidence/daemon-$mode-status.txt" 2>&1 \
      && grep -Fq 'Daemon is running' "$evidence/daemon-$mode-status.txt" \
      && grep -Fq 'Requests total:' "$evidence/daemon-$mode-status.txt"; then ready=true; break; fi
    sleep 0.2
  done
  if [[ "$ready" != true ]]; then
    printf 'assertion failed: %s daemon did not become ready within the %s-mode budget\n' "$mode" "${OMG_QEMU_ACCEL:-kvm}" >&2
    tail -n 25 "$evidence/daemon-$mode.log" >&2
    exit 1
  fi
  [[ $(readlink "/proc/$daemon_pid/exe") == "$daemon" ]]
  [[ $(stat -c '%u' "$OMG_SOCKET_PATH") == "$(id -u)" ]]
  [[ $(stat -c '%a' "$OMG_SOCKET_PATH") == 600 ]]
  # The pre-parser fast paths must reject duplicate Set/SetTrue flags even
  # when an actual daemon can satisfy the query. Without a daemon, fallback
  # to Clap can conceal a permissive fast parser.
  if [[ "$mode" == direct ]]; then
    invalid_invocations=(
      'search bash --no-aur --no-aur'
      'search bash --no-aur --limit 1 --limit 2'
      's bash --no-aur --limit=1 --limit 2'
      'info bash -q -q'
      'info bash -qq'
      'info bash --quiet -q'
      'info bash -vqvq'
    )
    for index in "${!invalid_invocations[@]}"; do
      read -r -a invalid_args <<< "${invalid_invocations[$index]}"
      status=0
      timeout "$command_timeout" "$bin" "${invalid_args[@]}" > "$evidence/daemon-invalid-$index.stdout" \
        2> "$evidence/daemon-invalid-$index.stderr" || status=$?
      if [[ "$status" != 2 || -s "$evidence/daemon-invalid-$index.stdout" ]] \
        || ! grep -Fq 'cannot be used multiple times' "$evidence/daemon-invalid-$index.stderr"; then
        printf 'assertion failed: invalid CLI arguments accepted with daemon running: %s (exit %s)\n' \
          "${invalid_invocations[$index]}" "$status" >&2
        exit 1
      fi
    done
  fi
  requests_before=$(awk '/Requests total:/ {print $NF}' "$evidence/daemon-$mode-status.txt")
  [[ "$requests_before" =~ ^[0-9]+$ ]]
  query_cli "daemon-$mode"
  if [[ "$mode" == direct ]]; then
    query_package_cli daemon-direct
  fi
  timeout "$status_timeout" "$bin" daemon-status > "$evidence/daemon-$mode-after-queries.txt" 2>&1
  requests_after=$(awk '/Requests total:/ {print $NF}' "$evidence/daemon-$mode-after-queries.txt")
  failed_after=$(awk '/Requests failed:/ {print $NF}' "$evidence/daemon-$mode-after-queries.txt")
  [[ "$requests_after" =~ ^[0-9]+$ && "$failed_after" == 0 ]]
  # daemon-status itself contributes three requests between snapshots: the
  # preceding Status plus the following Ping and Metrics. The three explicit
  # forms use IPC; ec can legitimately read the daemon's binary status cache.
  # Do not count diagnostic traffic as query coverage or require ec to lose
  # its zero-IPC fast path once the background worker publishes that cache.
  minimum_requests=6
  [[ "$mode" != direct ]] || minimum_requests=8
  if [[ "$requests_after" -lt $((requests_before + minimum_requests)) ]]; then
    printf 'assertion failed: %s queries did not produce enough daemon requests (%s -> %s requests)\n' "$mode" "$requests_before" "$requests_after" >&2
    exit 1
  fi
  inode=$(stat -c '%i' "$OMG_SOCKET_PATH")
  # A second direct daemon must fail, not replace the live socket or hang.
  duplicate_status=0
  timeout "$status_timeout" "$daemon" > "$evidence/daemon-$mode-duplicate.txt" 2>&1 || duplicate_status=$?
  [[ "$duplicate_status" != 0 && "$duplicate_status" != 124 && "$duplicate_status" != 137 ]]
  grep -Fq 'Another omgd daemon owns' "$evidence/daemon-$mode-duplicate.txt"
  [[ $(stat -c '%i' "$OMG_SOCKET_PATH") == "$inode" ]]
  timeout "$status_timeout" "$bin" daemon > "$evidence/daemon-$mode-launcher.txt" 2>&1
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
OMG_DISABLE_DAEMON=1 query_package_cli daemon-stopped
if ! check_daemon_info_provenance "$evidence/daemon-direct-info.json" \
  "$evidence/daemon-stopped-info.json"; then
  printf 'assertion failed: daemon JSON info lacks IPC response provenance\n' >&2
  exit 1
fi
if ! check_package_query_outputs bash \
  "$evidence/daemon-direct-search.json" "$evidence/daemon-direct-info.json" \
  "$evidence/daemon-stopped-search.json" "$evidence/daemon-stopped-info.json"; then
  printf 'assertion failed: daemon-backed search/info differs from direct native package data\n' >&2
  exit 1
fi
if ! check_text_info_outputs bash \
  "$evidence/daemon-direct-info.txt" "$evidence/daemon-stopped-info.txt"; then
  printf 'assertion failed: daemon-backed text info concealed native installation state\n' >&2
  exit 1
fi
backend_faults='[]'
if [[ "$ID" == fedora ]]; then
  check_fedora_reason_refusal "$bin" "$state" "$evidence" "$(id -u)" "$(id -g)"
  backend_faults='["dnf-reason-refusal"]'
fi
# Cleanup is part of success, so it must precede the positive receipt.
rm -rf -- "$state"
[[ ! -e "$state" && ! -L "$state" ]]
jq -n --argjson faults "$backend_faults" '{schema_version:1,direct:true,foreground:true,ipc:true,singleton:true,shutdown:true,restart:true,query_parity:true,sigint:true,cleanup:true,backend_faults:$faults}' > "$evidence/daemon-lifecycle.json"
