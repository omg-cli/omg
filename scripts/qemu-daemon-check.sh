#!/usr/bin/env bash
# Run as the unprivileged guest user against the binaries in the tested archive.
set -euo pipefail
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
  exit "$status"
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
for mode in direct foreground; do
  if [[ "$mode" == direct ]]; then
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
  inode=$(stat -c '%i' "$OMG_SOCKET_PATH")
  # A second direct daemon must fail, not replace the live socket or hang.
  duplicate_status=0
  timeout 5 "$daemon" > "$evidence/daemon-$mode-duplicate.txt" 2>&1 || duplicate_status=$?
  [[ "$duplicate_status" != 0 && "$duplicate_status" != 124 && "$duplicate_status" != 137 ]]
  grep -Fq 'Another omgd daemon owns' "$evidence/daemon-$mode-duplicate.txt"
  [[ $(stat -c '%i' "$OMG_SOCKET_PATH") == "$inode" ]]
  timeout 5 "$bin" daemon > "$evidence/daemon-$mode-launcher.txt" 2>&1
  grep -Fq 'already running' "$evidence/daemon-$mode-launcher.txt"
  kill -TERM "$daemon_pid"
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
printf '{"schema_version":1,"direct":true,"foreground":true,"ipc":true,"singleton":true,"shutdown":true,"restart":true}\n' > "$evidence/daemon-lifecycle.json"
