#!/usr/bin/env bash
set -euo pipefail

target=${1:?guest SSH target required}
shift

status_timeout=${OMG_QEMU_CLOUD_INIT_TIMEOUT_SECONDS:-180}
if [[ ! "$status_timeout" =~ ^[1-9][0-9]{0,2}$ ]] || (( status_timeout > 180 )); then
  echo 'cloud-init timeout must be an integer between 1 and 180 seconds' >&2
  exit 2
fi

boot_seconds() { local uptime rest; read -r uptime rest < /proc/uptime; printf '%s\n' "${uptime%%.*}"; }
helper_started=$(boot_seconds)
phase_started=0
start_phase() {
  phase_started=$(boot_seconds)
  printf 'cloud_init_phase=%s started_utc=%s\n' "$1" "$(date -u +%FT%TZ)" >&2
}

observe_phase() {
  printf 'cloud_init_phase=%s ended_utc=%s elapsed_seconds=%s timeout_ssh_exit=%s\n' \
    "$1" "$(date -u +%FT%TZ)" "$(( $(boot_seconds) - phase_started ))" "$2" >&2
}

collect_failed_guest_state() {
  local diagnostic_rc diagnostic_budget
  printf 'cloud_init_diagnostics_started_utc=%s\n' "$(date -u +%FT%TZ)" >&2
  # Keep observation inside the existing 180+60-second phase work allowance,
  # leaving its timeout kill graces and the outer 250-second limit intact.
  diagnostic_budget=$(( status_timeout + 60 - ($(boot_seconds) - helper_started) ))
  if (( diagnostic_budget <= 0 )); then
    printf 'cloud_init_diagnostics=unavailable_phase_budget\n' >&2
    return 0
  fi
  if (( diagnostic_budget > 5 )); then diagnostic_budget=5; fi
  # This is a read-only observation after failure, not a readiness retry.
  if timeout --kill-after=1s "${diagnostic_budget}s" ssh "$@" "$target" '
    for record in /run/cloud-init/status.json /run/cloud-init/result.json; do
      printf "cloud_init_record=%s\n" "$record"
      if test -f "$record"; then head -c 4096 "$record"; else echo unavailable; fi
      printf "\n"
    done
    systemctl show cloud-init-local.service cloud-init.service cloud-init-network.service cloud-init-main.service cloud-config.service cloud-final.service ssh.service sshd.service \
      --property=Id,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,ActiveEnterTimestamp,InactiveEnterTimestamp --no-pager
    sudo -n journalctl --boot --unit=cloud-init-local.service --unit=cloud-init.service --unit=cloud-init-network.service --unit=cloud-init-main.service \
      --unit=cloud-config.service --unit=cloud-final.service --unit=ssh.service --unit=sshd.service \
      --lines=80 --no-pager --output=short-iso --quiet
  ' 2>&1 | head -c 16384 >&2; then
    diagnostic_rc=0
  else
    diagnostic_rc=$?
  fi
  printf '\ncloud_init_diagnostics_ended_utc=%s diagnostic_exit=%s\n' \
    "$(date -u +%FT%TZ)" "$diagnostic_rc" >&2
}

# sshd may restart during cloud-init. Retry only SSH transport failures, using
# one controller deadline so reconnects cannot reset the stage's timeout.
retry_boot_ssh() {
  local budget=$1 stage=$2 code=124 remaining deadline=$(( $(boot_seconds) + $1 ))
  shift 2
  while (( (remaining = deadline - $(boot_seconds)) > 0 )); do
    if timeout --kill-after=5s "${remaining}s" ssh "$@"; then
      return 0
    else
      code=$?
    fi
    if [[ "$code" == 124 || "$code" == 137 ]]; then
      break
    elif [[ "$code" != 255 ]]; then
      printf 'cloud-init %s guest command failed (exit %s)\n' "$stage" "$code" >&2
      return "$code"
    fi
    sleep 1
  done
  printf 'cloud-init %s did not complete within %s seconds\n' "$stage" "$budget" >&2
  return "$code"
}

# cloud-init's status command reads these same runtime records. Read them from
# the controller so a crash in the guest's Python status CLI cannot block OMG
# coverage after the boot stages themselves have finished.
start_phase status
if status=$(retry_boot_ssh "$status_timeout" status "$@" "$target" '
  until test -f /run/cloud-init/result.json; do
    if systemctl is-failed --quiet cloud-final.service; then
      echo "cloud-final.service failed before publishing result.json" >&2
      exit 1
    fi
    sleep 0.25
  done
  cat /run/cloud-init/status.json
'); then
  observe_phase status 0
else
  status_rc=$?
  observe_phase status "$status_rc"
  printf 'cloud-init status observation failed; child exit=%s (deadline=%s seconds)\n' "$status_rc" "$status_timeout" >&2
  head -c 4096 <<< "$status" >&2
  collect_failed_guest_state "$@"
  exit 1
fi

if ! jq -e '
  . as $root |
  ($root.v1 | type == "object") and
  ($root.v1.datasource | type == "string" and startswith("DataSourceNoCloud")) and
  ($root.v1.stage == null) and
  (($root.v1 | has("recoverable_errors") | not) or $root.v1.recoverable_errors == {}) and
  all(["init-local", "init", "modules-config", "modules-final"][];
    . as $stage | $root.v1[$stage] as $entry |
    ($entry | type == "object") and
    ($entry.finished | type == "number") and
    ($entry.errors == []) and
    (($entry | has("recoverable_errors") | not) or ($entry.recoverable_errors == {})))
' <<< "$status" >/dev/null; then
  echo 'cloud-init status is incomplete, errored, or degraded:' >&2
  head -c 4096 <<< "$status" >&2
  collect_failed_guest_state "$@"
  exit 1
fi

start_phase target
if retry_boot_ssh 60 target "$@" "$target" '
  until systemctl is-active --quiet cloud-init.target; do
    for unit in cloud-init-local.service cloud-init-network.service cloud-init-main.service cloud-config.service cloud-final.service; do
      if systemctl is-failed --quiet "$unit"; then
        echo "$unit failed" >&2
        exit 1
      fi
    done
    sleep 0.25
  done
  for unit in cloud-init-local.service cloud-init-network.service cloud-init-main.service cloud-config.service cloud-final.service; do
    if systemctl is-failed --quiet "$unit"; then
      echo "$unit failed" >&2
      exit 1
    fi
  done
'; then
  observe_phase target 0
else
  target_rc=$?
  observe_phase target "$target_rc"
  collect_failed_guest_state "$@"
  exit "$target_rc"
fi
echo 'cloud-init stages, status, and systemd target verified'
