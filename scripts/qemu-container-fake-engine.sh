#!/bin/sh
# Guest-only engine stub: records argv without contacting a container runtime.
set -eu
: "${OMG_QEMU_ENGINE_CAPTURE:?}"
case "${1:-}" in
  --version)
    [ "$#" -eq 1 ] || exit 96
    printf 'version\n' >> "$OMG_QEMU_ENGINE_CAPTURE/calls"
    printf 'podman version fixture\n'
    ;;
  run|build)
    printf '%s\n' "$1" >> "$OMG_QEMU_ENGINE_CAPTURE/calls"
    shift
    printf '%s\0' "$@" > "$OMG_QEMU_ENGINE_CAPTURE/argv"
    printf 'fake-container-id\n'
    ;;
  *) exit 96 ;;
esac
