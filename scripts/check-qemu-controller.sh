#!/usr/bin/env bash
# Run inside the trusted Debian controller after apt installation, before QEMU.
set -euo pipefail
[[ $# == 1 ]] || exit 2
case "$1" in qemu-system-x86|qemu-system-arm) ;; *) exit 2 ;; esac
# Debian's first trixie fix for CVE-2026-48914. Epoch/revision comparisons
# must use dpkg, not lexical ordering or the upstream QEMU version banner.
# https://security-tracker.debian.org/tracker/CVE-2026-48914
minimum='1:10.0.11+ds-0+deb13u1'
for package in "$1" qemu-system-common qemu-utils; do
  version=$(dpkg-query -W -f='${Version}' "$package")
  [[ -n "$version" && "$version" != *$'\n'* ]] || exit 3
  printf '%s=%s minimum=%s\n' "$package" "$version" "$minimum"
  if ! dpkg --compare-versions "$version" ge "$minimum"; then
    printf 'error: %s is below the patched QEMU controller floor\n' "$package" >&2
    exit 3
  fi
done
# libslirp is separately packaged; a patched QEMU does not imply this floor.
# https://security-tracker.debian.org/tracker/source-package/libslirp
version=$(dpkg-query -W -f='${Version}' libslirp0)
[[ -n "$version" && "$version" != *$'\n'* ]] || exit 3
printf 'libslirp0=%s minimum=4.9.5-1\n' "$version"
if ! dpkg --compare-versions "$version" ge '4.9.5-1'; then
  printf 'error: libslirp0 is below the patched controller floor\n' >&2
  exit 3
fi
