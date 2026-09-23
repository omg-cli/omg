#!/usr/bin/env bash
# Actual bounded Fedora upgrade through OMG inside a disposable QEMU guest.
set -euo pipefail
[[ $# == 3 ]] || exit 2
mode=$1; binary=$2; guest_user=$3
[[ "$mode" == fast || "$mode" == turbo ]] || exit 2
[[ "$binary" == /* && -x "$binary" && ! -L "$binary" ]] || exit 2
[[ "$guest_user" =~ ^[a-z_][a-z0-9_-]*$ ]] || exit 2
[[ $(id -u) == 0 && -f /etc/fedora-release ]] || exit 2
for tool in rpm rpmbuild createrepo_c dnf jq sudo; do
  command -v "$tool" >/dev/null || { printf 'missing fixture tool: %s\nOMG_QEMU_FIXTURE_SETUP_FAILED\n' "$tool" >&2; exit 120; }
done
package=omg-qemu-update-oracle
repo_id=omg-qa-update
config=/etc/dnf/dnf.conf
[[ ! -L "$config" ]] || { echo 'DNF config is a symlink' >&2; echo 'OMG_QEMU_FIXTURE_SETUP_FAILED' >&2; exit 120; }
if rpm -q "$package" >/dev/null 2>&1; then echo 'fixture package already installed' >&2; echo 'OMG_QEMU_FIXTURE_SETUP_FAILED' >&2; exit 120; fi
base=$(mktemp -d /var/tmp/omg-qemu-update.XXXXXX) || { echo 'OMG_QEMU_FIXTURE_SETUP_FAILED' >&2; exit 120; }
chmod 755 "$base"
had_config=false
config_written=false
phase=setup
cleanup() {
  local status=$? failed=false
  trap - EXIT
  set +e
  if rpm -q "$package" >/dev/null 2>&1; then rpm -e "$package" >/dev/null || failed=true; fi
  if [[ "$config_written" == true ]]; then
    if [[ "$had_config" == true ]]; then cp -a "$base/original-dnf.conf" "$config" || failed=true
    else rm -f -- "$config" || failed=true; fi
  fi
  rm -rf -- "$base" || failed=true
  if [[ "$failed" == true ]]; then echo 'OMG_QEMU_FIXTURE_CLEANUP_FAILED' >&2; status=121
  elif [[ "$status" != 0 && "$phase" == setup ]]; then echo 'OMG_QEMU_FIXTURE_SETUP_FAILED' >&2; fi
  exit "$status"
}
trap cleanup EXIT
if [[ -e "$config" ]]; then cp -a "$config" "$base/original-dnf.conf"; had_config=true; fi
mkdir -p "$base/repo" "$base/repos"
chmod 755 "$base/repo" "$base/repos"
build_rpm() {
  local version=$1 top="$base/build-$1"
  mkdir -p "$top/SPECS" "$top/BUILD" "$top/BUILDROOT" "$top/RPMS" "$top/SOURCES" "$top/SRPMS"
  cat > "$top/SPECS/$package.spec" <<SPEC
Name:           $package
Version:        $version
Release:        1
Summary:        QEMU update behavior oracle
License:        MIT
BuildArch:      noarch

%description
A bounded native update transaction for OMG QEMU verification.

%prep
%build
%install
mkdir -p %{buildroot}/usr/share/$package
printf '%s\n' '$version' > %{buildroot}/usr/share/$package/version
%files
/usr/share/$package/version
SPEC
  rpmbuild --define "_topdir $top" -bb "$top/SPECS/$package.spec" > "$base/rpmbuild-$version.log" 2>&1 || {
    cat "$base/rpmbuild-$version.log" >&2; return 120;
  }
  printf '%s\n' "$top/RPMS/noarch/$package-$version-1.noarch.rpm"
}
v1=$(build_rpm 1); v2=$(build_rpm 2); v3=$(build_rpm 3)
[[ -f "$v1" && -f "$v2" && -f "$v3" ]] || exit 120
rpm -Uvh --nosignature "$v1" > "$base/install-v1.log" 2>&1 || { cat "$base/install-v1.log" >&2; exit 120; }
[[ $(rpm -q --qf '%{VERSION}\n' "$package") == 1 ]] || exit 120
rpm -qa --qf '%{NAME}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}|%{ARCH}\n' |
  grep -v "^$package|" | LC_ALL=C sort > "$base/system-before.tsv"
cat > "$base/repos/$repo_id.repo" <<REPO
[$repo_id]
name=OMG QEMU bounded update
baseurl=file://$base/repo
enabled=1
gpgcheck=0
repo_gpgcheck=0
skip_if_unavailable=0
metadata_expire=0
REPO
config_written=true
printf '[main]\nreposdir=%s/repos\n' "$base" > "$config"
chmod 644 "$config" "$base/repos/$repo_id.repo"
if [[ "$mode" == fast ]]; then cp "$v1" "$base/repo/"; else cp "$v2" "$base/repo/"; fi
createrepo_c "$base/repo" > "$base/createrepo.log" 2>&1 || { cat "$base/createrepo.log" >&2; exit 120; }
for user_mode in root "$guest_user"; do
  if [[ "$user_mode" == root ]]; then
    enabled=$(dnf -q repo list --enabled | awk 'NR > 1 && NF {print $1}')
    dnf --refresh makecache -y > "$base/makecache-root.log" 2>&1 || { cat "$base/makecache-root.log" >&2; exit 120; }
  else
    enabled=$(sudo -H -u "$guest_user" -- dnf -q repo list --enabled | awk 'NR > 1 && NF {print $1}')
    sudo -H -u "$guest_user" -- dnf --refresh makecache -y > "$base/makecache-user.log" 2>&1 || { cat "$base/makecache-user.log" >&2; exit 120; }
  fi
  [[ "$enabled" == "$repo_id" ]] || { printf 'expected only %s enabled for %s; observed %s\n' "$repo_id" "$user_mode" "$enabled" >&2; exit 120; }
done
cached=$(sudo -H -u "$guest_user" -- dnf --cacheonly repoquery --upgrades --qf '%{name}' "$package")
if [[ "$mode" == turbo ]]; then
  [[ "$cached" == "$package" ]] || { printf 'turbo fixture lacks cached upgrade: %s\n' "$cached" >&2; exit 120; }
  # A file:// repository is local but DNF5's cached-upgrade transaction still
  # requires an RPM in its package cache. Download without installing it.
  dnf upgrade -y --downloadonly "$package" > "$base/download.log" 2>&1 || {
    cat "$base/download.log" >&2; exit 120;
  }
  [[ $(rpm -q --qf '%{VERSION}\n' "$package") == 1 ]] || exit 120
  rm -f -- "$base/repo/$package-2-1.noarch.rpm"
  cp "$v3" "$base/repo/"
  createrepo_c --update "$base/repo" > "$base/createrepo-next.log" 2>&1 || { cat "$base/createrepo-next.log" >&2; exit 120; }
  cached=$(sudo -H -u "$guest_user" -- dnf --cacheonly repoquery --upgrades --qf '%{version}' "$package")
  [[ "$cached" == 2 ]] || { printf 'turbo fixture lost cached version 2: %s\n' "$cached" >&2; exit 120; }
else
  [[ -z "$cached" ]] || { printf 'fast fixture cache was not stale: %s\n' "$cached" >&2; exit 120; }
  rm -f -- "$base/repo/$package-1-1.noarch.rpm"
  cp "$v2" "$base/repo/"
  createrepo_c --update "$base/repo" > "$base/createrepo-next.log" 2>&1 || { cat "$base/createrepo-next.log" >&2; exit 120; }
  cached=$(sudo -H -u "$guest_user" -- dnf --cacheonly repoquery --upgrades --qf '%{name}' "$package")
  [[ -z "$cached" ]] || { printf 'fast fixture cache refreshed before OMG: %s\n' "$cached" >&2; exit 120; }
fi
printf 'OMG_QEMU_UPDATE_FIXTURE:before:%s:1\n' "$mode"
phase=product
sudo -H -u "$guest_user" -- "$binary" update "--$mode"
phase=verification
[[ $(rpm -q --qf '%{VERSION}\n' "$package") == 2 ]] || { echo 'OMG did not upgrade fixture to version 2' >&2; exit 1; }
rpm -qa --qf '%{NAME}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}|%{ARCH}\n' |
  grep -v "^$package|" | LC_ALL=C sort > "$base/system-after.tsv"
cmp "$base/system-before.tsv" "$base/system-after.tsv" || { echo 'OMG changed packages outside bounded fixture' >&2; exit 1; }
dnf history info --json last > "$base/history.json"
jq -e --arg package "$package" '
  type == "array" and length == 1 and .[0].status == "Ok" and
  any(.[0].packages[];
    .action == "Upgrade" and .repository == "omg-qa-update" and
    (.nevra | test("^" + $package + "-(?:[0-9]+:)?2-1[.]noarch$")))
' "$base/history.json" > /dev/null || {
  echo 'DNF native history did not record fixture upgrade' >&2
  cat "$base/history.json" >&2
  exit 1
}
printf 'OMG_QEMU_UPDATE_FIXTURE:after:%s:2:native-upgrade\n' "$mode"
