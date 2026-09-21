#!/usr/bin/env bash
# Root CI containers must not run HOME/data-dir fixture tests against /var/lib/omg.
set -euo pipefail
[[ $# -gt 0 ]] || exit 2
case "${1##*/}" in
  cli_comprehensive-*|e2e_runtime_management-*|env_lockfile_integrity-*|security_daemon_optional-*)
    if [[ $(id -u) == 0 ]]; then
      exec runuser -u nobody -- "$@"
    fi
    ;;
esac
exec "$@"
