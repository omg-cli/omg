#!/usr/bin/env bash
# Recover only controller-image transport failures, never guest/test failures.
set -euo pipefail

image=${1:?pinned controller image required}
attempt_log=${2:?attempt log path required}
[[ "$image" =~ ^debian:trixie@sha256:[0-9a-f]{64}$ ]] || {
  printf 'error: expected a digest-pinned Debian trixie controller\n' >&2
  exit 2
}

for attempt in 1 2 3; do
  printf 'Controller pull attempt %s/3: %s\n' "$attempt" "$image"
  if timeout --kill-after=5s 120s docker pull "$image" > "$attempt_log" 2>&1; then
    cat "$attempt_log"
    exit 0
  else
    status=$?
  fi
  cat "$attempt_log"
  if ((attempt == 3)); then exit "$status"; fi
  if ((status != 124)) && ! grep -Eiq \
    'TLS handshake timeout|Client.Timeout exceeded while awaiting headers|i/o timeout|connection reset by peer|unexpected EOF|HTTP status: 50[234]|503 Service Unavailable|502 Bad Gateway|504 Gateway Timeout' \
    "$attempt_log"; then
    exit "$status"
  fi
  sleep "$((attempt * 2))"
done
