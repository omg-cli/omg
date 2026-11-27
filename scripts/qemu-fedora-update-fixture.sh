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
consent="$(dirname "${BASH_SOURCE[0]}")/qemu-runtime-advisory-oracle.py"
[[ -f "$consent" && ! -L "$consent" ]] || { echo 'missing real security-consent fixture' >&2; exit 120; }
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

snapshot_install_reasons() {
  local output=$1
  dnf --cacheonly --disable-repo='*' repoquery --installed \
    --queryformat '%{name}|%{arch}|%{reason}\n' > "$output" || return 1
  awk -F '|' 'NF != 3 || $1 == "" || $2 == "" || $3 == "" { bad = 1 }
    END { if (NR == 0 || bad) exit 1 }' "$output" || return 1
  # DNF omits RPM's gpg-pubkey pseudo packages. Every other installed
  # name/architecture must have a native reason before we trust this oracle.
  rpm -qa --qf '%{NAME}|%{ARCH}\n' |
    awk -F '|' '$1 != "gpg-pubkey" { print }' | LC_ALL=C sort > "$output.rpm" || return 1
  awk -F '|' '$1 != "gpg-pubkey" { print $1 "|" $2 }' "$output" |
    LC_ALL=C sort > "$output.pairs" || return 1
  cmp -s "$output.rpm" "$output.pairs"
}

# BEGIN DNF REASON DELTA ORACLE
check_reason_delta() {
  local before=$1 after=$2
  awk -F '|' -v package="$package" '$1 != package { print }' "$before" |
    LC_ALL=C sort > "$before.other" || return 1
  awk -F '|' -v package="$package" '$1 != package { print }' "$after" |
    LC_ALL=C sort > "$after.other" || return 1
  if ! cmp -s "$before.other" "$after.other"; then
    echo 'OMG changed DNF install reasons outside bounded fixture' >&2
    diff -u "$before.other" "$after.other" >&2 || true
    return 1
  fi
}
# END DNF REASON DELTA ORACLE

verify_configured_installroot() {
  local root="$base/alternate-root"
  local report="$base/alternate-report" home explicit
  local -a omg=(sudo -H -u "$guest_user" -- env OMG_DISABLE_DAEMON=1 "$binary")
  home=$(getent passwd "$guest_user" | cut -d: -f6)
  [[ "$home" == /* && "$home" != / ]] || return 1
  mkdir -p "$root/etc/dnf"
  install -d -o "$guest_user" -m 0700 "$report" "$root$home/.local/state" "$root$home/.cache"
  rpm --root "$root" -U --nosignature "$v1"
  printf '[main]\ninstallroot=%s\nplugins=0\nreposdir=\n' "$root" > "$root/etc/dnf/dnf.conf"
  config_written=true
  install -m 0644 "$root/etc/dnf/dnf.conf" "$config"
  [[ $(rpm --root "$root" -qa --qf '%{NAME}\n') == "$package" ]]
  if rpm -q "$package" >/dev/null 2>&1; then
    echo 'Alternate installroot fixture appeared in the host RPM database' >&2
    return 1
  fi
  rpm -q rpm >/dev/null
  # RPM installs the package payload. DNF owns its install reasons and state.
  if ! dnf --cacheonly --assumeyes mark user "$package" > "$base/alternate-mark.log" 2>&1; then
    cat "$base/alternate-mark.log" >&2
    return 120
  fi
  if ! explicit=$(sudo -H -u "$guest_user" -- dnf --cacheonly \
      --setopt=disable_excludes='*' repoquery --userinstalled --qf '%{name}\n') \
    || [[ "$explicit" != "$package" ]]; then
    printf 'Could not establish the alternate-root DNF install reason\n' >&2
    return 120
  fi
  phase=product
  "${omg[@]}" --json tc | jq -e '.count == 1' > /dev/null
  "${omg[@]}" --json status --fast |
    jq -e '.total_packages == 1 and .explicit_packages == 1 and .orphan_packages == 0 and .updates_available == 0' > /dev/null
  "${omg[@]}" --json explicit | jq -e --arg name "$package" '.packages == [$name]' > /dev/null
  "${omg[@]}" --json info "$package" |
    jq -e --arg name "$package.noarch" '.name == $name and .version == "1-1" and .installed == true' > /dev/null
  "${omg[@]}" --json search "$package" |
    jq -e --arg name "$package.noarch" 'map(.name) == [$name]' > /dev/null
  "${omg[@]}" --json search 'rpm' |
    jq -e 'length == 0' > /dev/null
  "${omg[@]}" size --limit 2 > "$base/alternate-size.log"
  grep -Fq "Number of Packages: 1" "$base/alternate-size.log"
  grep -Fq "$package-0:1-1.noarch" "$base/alternate-size.log"
  "${omg[@]}" audit sbom --inventory-only --output "$report/sbom.json"
  jq -e --arg name "$package" '.components | map(.name) == [$name]' "$report/sbom.json" > /dev/null
  if [[ "$had_config" == true ]]; then cp -a "$base/original-dnf.conf" "$config"
  else rm -f -- "$config"; fi
  config_written=false
}

verify_installed_commands() {
  local identity hidden
  local -a omg=(sudo -H -u "$guest_user" -- env OMG_DISABLE_DAEMON=1 "$binary")
  config_written=true
  printf '[main]\nreposdir=%s/repos\nexcludepkgs=%s\n' "$base" "$package" > "$config"
  chmod 644 "$config"
  dnf -q --cacheonly repo list --all --json | jq -e 'type == "array" and length == 0' > /dev/null
  hidden=$(dnf -q --cacheonly repoquery --installed --qf '%{name}\n' "$package")
  [[ -z "$hidden" ]] || { echo 'Configured exclusion did not hide the native control'; return 1; }
  identity=$(rpm -q --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' "$package")
  [[ -n "$identity" ]] || return 1
  "${omg[@]}" --json explicit | jq -e --arg fixture "$package" '.packages | index($fixture) != null' > /dev/null
  "${omg[@]}" --json explicit --count | jq -e '.count >= 1' > /dev/null
  for cmd in size why why-reverse blame; do
    case "$cmd" in
      size) "${omg[@]}" size --tree "$identity" ;;
      why) "${omg[@]}" why "$identity" ;;
      why-reverse) "${omg[@]}" why --reverse "$identity" ;;
      blame) "${omg[@]}" blame "$identity" ;;
    esac > "$base/$cmd.log"
    grep -Fq -- "$identity" "$base/$cmd.log" || { cat "$base/$cmd.log"; return 1; }
  done
  printf '[main]\nreposdir=%s/repos\n' "$base" > "$config"
  dnf -q history list --json > "$base/native-noop-before.json"
  "${omg[@]}" --json history > "$base/omg-noop-before.json"
  "${omg[@]}" remove --dry-run "$package-absent" > "$base/remove-noop.log"
  grep -Fq 'No packages to remove' "$base/remove-noop.log"
  "${omg[@]}" install --yes "$identity" > "$base/install-noop.log"
  grep -Fq 'No package changes needed' "$base/install-noop.log"
  if grep -Fq 'Installed 1 package' "$base/install-noop.log"; then
    cat "$base/install-noop.log"
    return 1
  fi
  "${omg[@]}" --json history > "$base/omg-noop-after.json"
  dnf -q history list --json > "$base/native-noop-after.json"
  cmp "$base/omg-noop-before.json" "$base/omg-noop-after.json"
  cmp "$base/native-noop-before.json" "$base/native-noop-after.json"
  [[ $(rpm -q --qf '%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' "$package") == 0:1-1.noarch ]]
}

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
verify_configured_installroot
phase=setup
rpm -Uvh --nosignature "$v1" > "$base/install-v1.log" 2>&1 || { cat "$base/install-v1.log" >&2; exit 120; }
[[ $(rpm -q --qf '%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' "$package") == 0:1-1.noarch ]] || exit 120
rpm -qa --qf '%{NAME}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}|%{ARCH}\n' |
  grep -v "^$package|" | LC_ALL=C sort > "$base/system-before.tsv"
snapshot_install_reasons "$base/reasons-before.tsv" ||
  { echo 'native DNF install reasons unavailable before update' >&2; exit 120; }
phase=product
verify_installed_commands
phase=setup
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
  [[ $(rpm -q --qf '%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' "$package") == 0:1-1.noarch ]] || exit 120
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
dnf history list --json > "$base/history-before-update.json"
printf 'OMG_QEMU_UPDATE_FIXTURE:before:%s:1\n' "$mode"
phase=product
sudo -H -u "$guest_user" -- python3 "$consent" --native --accept-only --require-review --timeout 600 -- "$binary" update "--$mode" --yes
phase=verification
[[ $(rpm -q --qf '%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' "$package") == 0:2-1.noarch ]] || { echo 'OMG did not upgrade fixture to version 2' >&2; exit 1; }
rpm -qa --qf '%{NAME}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}|%{ARCH}\n' |
  grep -v "^$package|" | LC_ALL=C sort > "$base/system-after.tsv"
cmp "$base/system-before.tsv" "$base/system-after.tsv" || { echo 'OMG changed packages outside bounded fixture' >&2; exit 1; }
snapshot_install_reasons "$base/reasons-after.tsv" ||
  { echo 'native DNF install reasons unavailable after update' >&2; exit 1; }
check_reason_delta "$base/reasons-before.tsv" "$base/reasons-after.tsv" || exit 1
dnf history list --json > "$base/history-after-update.json"
dnf history info --json last > "$base/history.json"
jq -e --arg package "$package" \
  --slurpfile before "$base/history-before-update.json" \
  --slurpfile after "$base/history-after-update.json" '
  def valid_id: type == "number" and . > 0 and . == floor;
  def history_ids:
    if length == 1 and (.[0] | type == "array") and all(.[0][]; .id | valid_id)
    then .[0] | map(.id) | sort
    else error("Invalid DNF history list")
    end;
  def fixture_nevra($version):
    . == ($package + "-0:" + $version + "-1.noarch") or
    . == ($package + "-" + $version + "-1.noarch");

  (type == "array" and length == 1) and
  (.[0] as $transaction |
    ($before | history_ids) as $prior |
    ($after | history_ids) as $current |
    $transaction.status == "Ok" and
    ($transaction.id | valid_id) and
    ($transaction.comment | type == "string" and
      test("^omg-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")) and
    ($prior | unique) == $prior and
    all($prior[]; . < $transaction.id) and
    $current == ($prior + [$transaction.id]) and
    ($transaction.packages |
      type == "array" and length == 2 and
      any(.[];
        .action == "Upgrade" and .repository == "@stored_transaction(omg-qa-update)" and
        (.nevra | fixture_nevra("2"))) and
      any(.[];
        .action == "Replaced" and .repository == "@System" and (.nevra | fixture_nevra("1")))))
' "$base/history.json" > /dev/null || {
  echo 'DNF native history did not prove exactly one stored fixture upgrade' >&2
  cat "$base/history.json" >&2
  exit 1
}
printf 'OMG_QEMU_UPDATE_FIXTURE:after:%s:2:native-upgrade\n' "$mode"
