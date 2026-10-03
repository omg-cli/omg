#!/usr/bin/env bash
set -euo pipefail

target=${1:?guest SSH target required}
shift

status_timeout=${OMG_QEMU_CLOUD_INIT_TIMEOUT_SECONDS:-180}
if [[ ! "$status_timeout" =~ ^[1-9][0-9]{0,2}$ ]] || (( status_timeout > 180 )); then
  echo 'cloud-init timeout must be an integer between 1 and 180 seconds' >&2
  exit 2
fi

# sshd may restart during cloud-init. Retry only SSH transport failures, using
# one controller deadline so reconnects cannot reset the stage's timeout.
retry_boot_ssh() {
  local budget=$1 stage=$2 code remaining deadline=$((SECONDS + $1))
  shift 2
  while (( (remaining = deadline - SECONDS) > 0 )); do
    if timeout --kill-after=5s "${remaining}s" ssh "$@"; then
      return 0
    else
      code=$?
    fi
    if [[ "$code" == 124 || "$code" == 137 ]]; then
      break
    elif [[ "$code" != 255 ]]; then
      printf 'cloud-init %s guest command failed (exit %s)\n' "$stage" "$code" >&2
      return 1
    fi
    sleep 1
  done
  printf 'cloud-init %s did not complete within %s seconds\n' "$stage" "$budget" >&2
  return 1
}

# cloud-init's status command reads these same runtime records. Read them from
# the controller so a crash in the guest's Python status CLI cannot block OMG
# coverage after the boot stages themselves have finished.
if ! status=$(retry_boot_ssh "$status_timeout" status "$@" "$target" '
  until test -f /run/cloud-init/result.json; do
    if systemctl is-failed --quiet cloud-final.service; then
      echo "cloud-final.service failed before publishing result.json" >&2
      exit 1
    fi
    sleep 0.25
  done
  cat /run/cloud-init/status.json
'); then
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
  printf '%s\n' "$status" | head -c 4096 >&2
  exit 1
fi

retry_boot_ssh 60 target "$@" "$target" '
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
'
echo 'cloud-init stages, status, and systemd target verified'
