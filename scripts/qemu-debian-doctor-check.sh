#!/usr/bin/env bash
# Read-only Debian/Ubuntu doctor fault probes. Root is used only for a private
# bind mount; both doctor processes run as the unprivileged QEMU guest user.
set -Eeuo pipefail

setup_failed() {
  printf 'OMG_QEMU_DOCTOR_FIXTURE_SETUP_FAILED: %s\n' "$1" >&2
  exit 120
}

[[ $# == 3 && $(id -u) == 0 ]] || setup_failed 'requires root and three arguments'
mode=$1 binary=$2 guest=$3
[[ "$mode" == status || "$mode" == index ]] || setup_failed 'unknown fault mode'
[[ "$binary" == /* && -x "$binary" && "$guest" =~ ^[a-z_][a-z0-9_-]*$ && "$guest" != root ]] \
  || setup_failed 'binary or guest identity unavailable'
for program in unshare mount runuser getent; do
  command -v "$program" >/dev/null || setup_failed "missing $program"
done
guest_home=$(getent passwd "$guest" | cut -d: -f6)
[[ "$guest_home" == /* && -d "$guest_home" ]] || setup_failed 'guest home unavailable'

fixture=$(mktemp -d /tmp/omg-qemu-doctor.XXXXXXXX)
trap 'rm -rf -- "$fixture"' EXIT
mkdir "$fixture/lists"
printf 'Package: corrupt\nStatus: install reinstreq half-configured\nVersion: 1\nArchitecture: amd64\n' > "$fixture/status"
printf 'Package: broken\nVersion: 1\nArchitecture: amd64\nSize: 123\n' > "$fixture/lists/omg_dists_test_main_binary-amd64_Packages"
chmod 644 "$fixture/status" "$fixture/lists/omg_dists_test_main_binary-amd64_Packages"

doctor_as_guest() {
  runuser -u "$guest" -- env HOME="$guest_home" NO_COLOR=1 OMG_DISABLE_DAEMON=1 OMG_TEST_MODE=0 "$binary" doctor
}

baseline_rc=0
doctor_as_guest > "$fixture/baseline.stdout" 2> "$fixture/baseline.stderr" || baseline_rc=$?
printf 'OMG_QEMU_DOCTOR_BASELINE:exit=%s\n' "$baseline_rc"
cat "$fixture/baseline.stdout"
cat "$fixture/baseline.stderr" >&2
if [[ "$baseline_rc" != 0 && "$baseline_rc" != 1 ]] \
  || ! grep -Fq 'dpkg package database (/var/lib/dpkg/status)' "$fixture/baseline.stdout" \
  || ! grep -Fq 'APT package indexes (/var/lib/apt/lists)' "$fixture/baseline.stdout"; then
  setup_failed 'native baseline is not healthy'
fi

baseline_count=0
if [[ "$baseline_rc" == 1 ]]; then
  mapfile -t counts < <(sed -nE 's/^Error: doctor found ([0-9]+) health issue\(s\)$/\1/p' "$fixture/baseline.stderr")
  [[ ${#counts[@]} == 1 && "${counts[0]}" =~ ^[1-9][0-9]*$ ]] \
    || setup_failed 'native baseline has no exact issue count'
  baseline_count=${counts[0]}
fi

variant_rc=0
unshare --mount --propagation private -- bash -euc '
  mode=$1; fixture=$2; binary=$3; guest=$4; guest_home=$5
  if [[ "$mode" == status ]]; then
    mount --bind "$fixture/status" /var/lib/dpkg/status
  else
    mount --bind "$fixture/lists" /var/lib/apt/lists
  fi
  : > "$fixture/variant-ready"
  runuser -u "$guest" -- env HOME="$guest_home" NO_COLOR=1 OMG_DISABLE_DAEMON=1 OMG_TEST_MODE=0 "$binary" doctor
' _ "$mode" "$fixture" "$binary" "$guest" "$guest_home" \
  > "$fixture/variant.stdout" 2> "$fixture/variant.stderr" || variant_rc=$?
printf 'OMG_QEMU_DOCTOR_VARIANT:exit=%s\n' "$variant_rc"
cat "$fixture/variant.stdout"
cat "$fixture/variant.stderr" >&2
[[ -f "$fixture/variant-ready" ]] || setup_failed 'private mount namespace or bind mount unavailable'
if [[ "$variant_rc" != 1 ]]; then
  printf 'assertion failed: corrupt %s database did not produce doctor exit 1\n' "$mode" >&2
  exit 121
fi

mapfile -t counts < <(sed -nE 's/^Error: doctor found ([0-9]+) health issue\(s\)$/\1/p' "$fixture/variant.stderr")
if [[ ${#counts[@]} != 1 || ! "${counts[0]}" =~ ^[1-9][0-9]*$ ]] \
  || (( counts[0] != baseline_count + 1 )); then
  printf 'assertion failed: corrupt %s database did not add exactly one doctor issue\n' "$mode" >&2
  exit 121
fi

case "$mode" in
  status)
    failed='dpkg package database unhealthy (/var/lib/dpkg/status)'
    still_healthy='APT package indexes (/var/lib/apt/lists)'
    other_failed='APT package indexes unhealthy (/var/lib/apt/lists)' ;;
  index)
    failed='APT package indexes unhealthy (/var/lib/apt/lists)'
    still_healthy='dpkg package database (/var/lib/dpkg/status)'
    other_failed='dpkg package database unhealthy (/var/lib/dpkg/status)' ;;
esac
if [[ $(grep -Fc "$failed" "$fixture/variant.stdout") != 1 ]] \
  || [[ $(grep -Fc "$still_healthy" "$fixture/variant.stdout") != 1 ]] \
  || grep -Fq "$other_failed" "$fixture/variant.stdout"; then
  printf 'assertion failed: doctor did not identify only the corrupt %s database\n' "$mode" >&2
  exit 121
fi

if [[ "$mode" == index ]] && ! grep -Fq 'lacks Filename' "$fixture/variant.stdout"; then
  printf 'assertion failed: doctor did not identify the missing APT Filename\n' >&2
  exit 121
fi

printf 'OMG_QEMU_DOCTOR_FAULT:%s:baseline=%s:variant=%s\n' \
  "$mode" "$baseline_count" "${counts[0]}"
exit 1
