#!/usr/bin/env bash
set -euo pipefail

target=${1:?guest SSH target required}
shift

# cloud-init's status command reads these same runtime records. Read them from
# the controller so a crash in the guest's Python status CLI cannot block OMG
# coverage after the boot stages themselves have finished.
if ! status=$(timeout --kill-after=5s 180s ssh "$@" "$target" '
  until test -f /run/cloud-init/result.json; do
    if systemctl is-failed --quiet cloud-final.service; then
      echo "cloud-final.service failed before publishing result.json" >&2
      exit 1
    fi
    sleep 0.25
  done
  cat /run/cloud-init/status.json
'); then
  echo 'cloud-init did not publish complete status within 180 seconds' >&2
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

timeout --kill-after=5s 60s ssh "$@" "$target" '
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
