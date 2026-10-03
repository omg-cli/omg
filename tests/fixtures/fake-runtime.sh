#!/bin/sh
printf '%s\n' "$@" >> "$OMG_FAKE_RUNTIME_LOG"
if [ -n "$OMG_FAKE_RUNTIME_STDERR" ]; then
  printf '%s\n' "$OMG_FAKE_RUNTIME_STDERR" >&2
fi
if [ -n "$OMG_FAKE_RUNTIME_EXIT" ]; then
  exit "$OMG_FAKE_RUNTIME_EXIT"
fi
case "$1" in
  ps)
    printf 'abc123def\tweb-server\tubuntu:24.04\tUp 2 minutes\n'
    ;;
  images)
    printf 'ubuntu\t24.04\tsha256:def456\t120MB\n'
    ;;
esac
exit 0
