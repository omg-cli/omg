#!/bin/sh
# Both real workspace tasks must reach this rendezvous before either can pass.
# Fresh inventory row directories prevent signals from another invocation.
set -eu
root=$1
participant=$2
attempts=${3:-200}
case "$participant" in
  primary) peer=nested; marker=smoke-task-ok ;;
  nested) peer=primary; marker=nested-smoke-task-ok ;;
  *) echo 'invalid workspace participant' >&2; exit 2 ;;
esac
case "$attempts" in ''|*[!0-9]*) exit 2 ;; esac
state="$root/.overlap"
mkdir -p "$state"
# Reject duplicate invocations instead of letting stale receipts pass.
mkdir "$state/$participant"
trap 'rc=$?; if [ "$rc" -ne 0 ]; then rmdir "$state/$participant"; fi' EXIT
while [ "$attempts" -gt 0 ]; do
  if [ -d "$state/$peer" ]; then
    printf '%s\n' "$marker"
    exit 0
  fi
  attempts=$((attempts - 1))
  sleep 0.1
done
echo 'workspace peer did not overlap before the fixture deadline' >&2
exit 1
