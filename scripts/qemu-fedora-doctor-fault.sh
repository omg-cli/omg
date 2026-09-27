#!/usr/bin/env bash
# Run only in a disposable Fedora guest's private mount namespace. The empty
# RPMDB lives in the inventory row directory; the system RPMDB is never edited.
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin

setup_failed() {
  printf 'OMG_QEMU_DOCTOR_FAULT_SETUP_FAILED: %s\n' "$*" >&2
  exit 120
}
require_empty_rpm_inventory() {
  local packages
  packages=$("$@" rpm -qa) || setup_failed 'guest RPM query failed against isolated fixture'
  [[ -z "$packages" ]] || setup_failed 'guest RPM query did not see the empty fixture'
}

[[ $# == 4 ]] || setup_failed 'expected binary, row directory, guest user, and outer mount namespace'
binary=$1
rowdir=$2
guest_user=$3
outer_ns=$4
[[ $(id -u) == 0 && -x "$binary" && -d "$rowdir" && ! -L "$rowdir" ]] \
  || setup_failed 'fixture requires root, the release binary, and a real row directory'
[[ $(readlink /proc/self/ns/mnt) != "$outer_ns" ]] \
  || setup_failed 'fixture did not enter a private mount namespace'

uid=$(id -u "$guest_user") || setup_failed 'guest account is unavailable'
gid=$(id -g "$guest_user") || setup_failed 'guest group is unavailable'
[[ "$uid" != 0 && $(stat -c %u "$rowdir") == "$uid" ]] \
  || setup_failed 'row directory must belong to the unprivileged guest user'
guest_home=$(getent passwd "$guest_user" | cut -d: -f6)
[[ -d "$guest_home" ]] || setup_failed 'guest home is unavailable'

dbpath=$(HOME=/ rpm -E '%{_dbpath}') || setup_failed 'cannot resolve the native RPMDB path'
dbpath=$(readlink -f "$dbpath") || setup_failed 'cannot canonicalize the RPMDB path'
[[ "$dbpath" == /* && "$dbpath" != / && -d "$dbpath" && "$dbpath" != "$rowdir" \
  && "$dbpath" != "$rowdir/"* && $(stat -c %u "$dbpath") == 0 ]] \
  || setup_failed 'native RPMDB directory is unsafe or absent'
[[ $(findmnt -n -o PROPAGATION --target "$dbpath") == private ]] \
  || setup_failed 'RPMDB mount is not private to the guest fixture'
case "$(HOME=/ rpm -E '%{_db_backend}')" in
  sqlite) [[ -f "$dbpath/rpmdb.sqlite" ]] || setup_failed 'native SQLite RPMDB is absent' ;;
  ndb) [[ -f "$dbpath/Packages.db" ]] || setup_failed 'native NDB RPMDB is absent' ;;
  bdb) [[ -f "$dbpath/Packages" ]] || setup_failed 'native BDB RPMDB is absent' ;;
  *) setup_failed 'native RPMDB backend is unknown' ;;
esac
[[ -n $(HOME=/ rpm -qa) ]] || setup_failed 'native RPMDB is already empty'
native_inode=$(stat -Lc '%d:%i' "$dbpath")
mounted=0
cleanup_mount() {
  if [[ "$mounted" == 1 ]]; then
    if ! umount "$dbpath" || [[ $(stat -Lc '%d:%i' "$dbpath") != "$native_inode" ]]; then
      printf 'OMG_QEMU_DOCTOR_FAULT_SETUP_FAILED: native RPMDB mount was not restored\n' >&2
      exit 120
    fi
  fi
}
trap cleanup_mount EXIT

fixture="$rowdir/fault-rpmdb"
mkdir -m 700 "$fixture" || setup_failed 'cannot create isolated RPMDB directory'
chown "$uid:$gid" "$fixture" || setup_failed 'cannot grant guest access to isolated RPMDB'
rpmdb --initdb --dbpath "$fixture" || setup_failed 'cannot initialize isolated RPMDB'
chown -R "$uid:$gid" "$fixture" || setup_failed 'cannot grant guest access to isolated RPMDB'
mount --bind "$fixture" "$dbpath" || setup_failed 'cannot bind isolated RPMDB in private namespace'
mounted=1
[[ $(stat -Lc '%d:%i' "$fixture") == "$(stat -Lc '%d:%i' "$dbpath")" ]] \
  || setup_failed 'RPMDB bind mount did not take effect'

guest=(setpriv --reuid="$uid" --regid="$gid" --clear-groups --no-new-privs
  --bounding-set=-all --inh-caps=-all --ambient-caps=-all
  env HOME="$guest_home" USER="$guest_user" LOGNAME="$guest_user" NO_COLOR=1 LC_ALL=C
  OMG_TEST_MODE=0 OMG_DISABLE_DAEMON=1)
[[ "$("${guest[@]}" id -u)" == "$uid" ]] || setup_failed 'could not drop guest privileges'
require_empty_rpm_inventory "${guest[@]}"
if ! "${guest[@]}" dnf --cacheonly '--disable-repo=*' check \
  > "$rowdir/doctor-fault.native-dnf.log" 2>&1; then
  setup_failed 'offline native DNF check did not accept the isolated empty RPMDB'
fi

printf 'Fedora doctor fault reference: isolated RPMDB empty; offline DNF check succeeded\n' >&2
doctor_rc=0
"${guest[@]}" "$binary" doctor \
  > "$rowdir/doctor-fault.stdout.log" 2> "$rowdir/doctor-fault.stderr.log" || doctor_rc=$?
printf 'OMG_QEMU_DOCTOR_FAULT_PRODUCT_EXIT:%s\n' "$doctor_rc"
