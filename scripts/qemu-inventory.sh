#!/usr/bin/env bash
# qemu-inventory.sh â€” drive tests/cli_behavior_inventory.tsv rows inside a
# running QEMU guest over SSH and record machine-readable evidence.
#
# The guest must already be up (see scripts/benchmark-qemu.sh, which calls
# this when --inventory-tiers is set). Rows run in file order so the
# TSV `requires` DAG is satisfied naturally. Disposable guests make
# package/service-mutation rows safe, but they still need --allow-mutations.
set -euo pipefail
# BEGIN PRODUCT OUTPUT ORACLE
# This exact function is sent to the guest and exercised by fault-injection tests.
check_runtime_usage() {
  local runtime=$1 mode
  mode=$(stat -c %a "$OMG_DATA_DIR") || mode=""
  if [[ "$mode" != 700 ]] || ! jq -e -s --arg runtime "$runtime" \
    'length == 1 and (.[0] | .runtime_usage_counts[$runtime] == 1 and .commands.runtime_switch == 1 and .total_commands == 1)' \
    "$OMG_DATA_DIR/usage.json" >/dev/null; then
    printf 'assertion failed: runtime usage %s must persist exactly one switch in private data\n' "$runtime" >&2
    return 1
  fi
}

check_native_counter() {
  local distro=$1 counter=$2 output=$3 status=0 expected actual
  local -a native=()
  case "$distro:$counter" in
    arch:ec) native=(pacman -Qqe) ;;
    arch:tc) native=(pacman -Qq) ;;
    arch:oc) native=(pacman -Qdtq) ;;
    arch:uc) native=(pacman -Quq) ;;
    debian:tc|ubuntu:tc) native=(dpkg-query -W '-f=${db:Status-Status}\n') ;;
    debian:ec|ubuntu:ec) native=(apt-mark showmanual) ;;
    debian:oc|ubuntu:oc) native=(apt-get -s autoremove) ;;
    debian:uc|ubuntu:uc) native=(apt list --upgradable) ;;
    fedora:tc) native=(rpm -qa --qf '%{NAME}.%{ARCH}\n') ;;
    fedora:ec) native=(dnf --cacheonly repoquery --userinstalled --qf '%{name}\n') ;;
    fedora:oc) native=(dnf --cacheonly repoquery --unneeded --qf '%{name}.%{arch}\n') ;;
    fedora:uc) native=(dnf --cacheonly repoquery --upgrades --latest-limit=1 --qf '%{name}.%{arch}\n') ;;
    *) return 2 ;;
  esac
  timeout --kill-after=2s 30 "${native[@]}" > native-counter.raw 2> native-counter.stderr || status=$?
  # pacman uses 1 for an empty query; never accept a diagnostic-bearing error.
  if [[ "$distro" == arch && "$status" == 1 && ! -s native-counter.raw && ! -s native-counter.stderr ]]; then status=0; fi
  if [[ "$status" != 0 ]]; then
    printf 'native counter reference failed: %s %s exit=%s\n' "$distro" "$counter" "$status" >&2
    head -c 4096 native-counter.stderr >&2
    return 2
  fi
  expected=$(
    set -o pipefail
    case "$distro:$counter" in
      debian:tc|ubuntu:tc) awk '$0 == "installed" {n++} END {print n+0}' native-counter.raw ;;
      debian:oc|ubuntu:oc) awk '/^Remv / {n++} END {print n+0}' native-counter.raw ;;
      debian:uc|ubuntu:uc) awk '$1 ~ /\// {n++} END {print n+0}' native-counter.raw ;;
      *:ec|fedora:oc|fedora:uc) sort -u native-counter.raw | awk 'NF {n++} END {print n+0}' ;;
      *) awk 'NF {n++} END {print n+0}' native-counter.raw ;;
    esac
  ) || { printf 'native counter reference processing failed\n' >&2; return 2; }
  [[ $(wc -c < "$output") -le 32 ]] || { printf 'assertion failed: counter output exceeds scalar size\n' >&2; return 1; }
  actual=$(cat "$output")
  printf 'native counter %s expected=%s actual=%s\n' "$counter" "$expected" "$actual" >&2
  [[ "$actual" =~ ^[0-9]+$ && "$actual" == "$expected" ]]
}

check_status_native_counts() {
  local distro=$1 mode=$2 output=$3 line total explicit updates orphans field value oracle_rc
  local -a fields=(tc ec)
  if [[ $(grep -Ec '^[[:space:]]*[0-9]+ packages installed · [0-9]+ explicit$' "$output") != 1 ]]; then
    printf 'assertion failed: status lacks exactly one package-count summary\n' >&2
    return 1
  fi
  line=$(grep -E '^[[:space:]]*[0-9]+ packages installed · [0-9]+ explicit$' "$output")
  read -r total _ _ _ explicit _ <<< "$line"
  if [[ "$mode" == fast ]]; then
    if ! grep -Fq 'Updates and orphans not checked. Run omg status for a full check.' "$output" \
      || grep -Eq '^[[:space:]]*(Updates|Orphans)[[:space:]]+[0-9]+$' "$output"; then
      printf 'assertion failed: fast status did not distinguish unqueried updates and orphans\n' >&2
      return 1
    fi
  elif [[ "$mode" == full ]]; then
    if grep -Fq 'Updates and orphans not checked.' "$output" \
      || [[ $(grep -Ec '^[[:space:]]*Updates[[:space:]]+[0-9]+$' "$output") != 1 ]] \
      || [[ $(grep -Ec '^[[:space:]]*Orphans[[:space:]]+[0-9]+$' "$output") != 1 ]]; then
      printf 'assertion failed: full status lacks queried updates or orphan counts\n' >&2
      return 1
    fi
    updates=$(awk '$1 == "Updates" && $2 ~ /^[0-9]+$/ {print $2}' "$output")
    orphans=$(awk '$1 == "Orphans" && $2 ~ /^[0-9]+$/ {print $2}' "$output")
    fields+=(uc oc)
  else
    return 2
  fi
  for field in "${fields[@]}"; do
    case "$field" in tc) value=$total ;; ec) value=$explicit ;; uc) value=$updates ;; oc) value=$orphans ;; esac
    printf '%s\n' "$value" > native-count-observed
    oracle_rc=0
    check_native_counter "$distro" "$field" native-count-observed || oracle_rc=$?
    if [[ "$oracle_rc" != 0 ]]; then
      if [[ "$oracle_rc" == 1 ]]; then
        printf 'assertion failed: status %s disagrees with the native %s package database\n' "$field" "$distro" >&2
      fi
      return "$oracle_rc"
    fi
  done
}

check_outdated_native_count() {
  local distro=$1 format=$2 output=$3 actual oracle_rc=0
  if [[ "$format" == json ]]; then
    if ! jq -e -s 'length == 1 and (.[0] | type == "array" and
      all(.[]; (.name | type == "string" and length > 0) and
               (.current_version | type == "string" and length > 0) and
               (.new_version | type == "string" and length > 0)))' "$output" >/dev/null; then
      printf 'assertion failed: outdated JSON is not one nonempty-version update array\n' >&2
      return 1
    fi
    actual=$(jq -r 'length' "$output")
  elif [[ "$format" == text ]]; then
    if grep -Fq 'Everything is up to date!' "$output"; then
      if grep -Fq '[Available Updates]' "$output"; then
        printf 'assertion failed: outdated reports both updates and no updates\n' >&2
        return 1
      fi
      actual=0
    elif [[ $(grep -Ec '^\[Available Updates\] [0-9]+ packages total$' "$output") == 1 ]]; then
      actual=$(awk '$1 == "[Available" && $2 == "Updates]" {print $3}' "$output")
      if [[ "$actual" == 0 ]]; then
        printf 'assertion failed: outdated rendered zero as available updates\n' >&2
        return 1
      fi
    else
      printf 'assertion failed: outdated lacks a definitive update count\n' >&2
      return 1
    fi
  else
    return 2
  fi
  printf '%s\n' "$actual" > native-count-observed
  check_native_counter "$distro" uc native-count-observed || oracle_rc=$?
  if [[ "$oracle_rc" == 1 ]]; then
    printf 'assertion failed: outdated count disagrees with the native %s package manager\n' "$distro" >&2
  fi
  return "$oracle_rc"
}

# BEGIN DOCTOR BACKEND ORACLE
check_doctor_native_backend() {
  local distro=$1 output=$2 os_release=${3:-/etc/os-release} exec_receipt=${4:-} restricted_path=${5:-false} guest_id expected
  if [[ ! -f "$os_release" ]]; then
    printf 'native doctor reference lacks an os-release file\n' >&2
    return 2
  fi
  guest_id=$(awk -F= '$1 == "ID" {gsub(/"/, "", $2); print $2}' "$os_release")
  if [[ "$guest_id" != "$distro" ]]; then
    printf 'native doctor reference expected %s guest, found %s\n' "$distro" "$guest_id" >&2
    return 2
  fi
  case "$distro" in
    arch) expected='Arch Linux detected' ;;
    debian|ubuntu) expected='Debian/Ubuntu detected (apt backend)' ;;
    fedora) expected='Fedora/RHEL detected (dnf backend)' ;;
    *) return 2 ;;
  esac
  if [[ $(grep -Fxc "  $expected" "$output") != 1 ]] \
    || [[ $(grep -Ec '^  (Arch Linux detected|Debian/Ubuntu detected \(apt backend\)|Fedora/RHEL detected \(dnf backend\))$' "$output") != 1 ]]; then
    printf 'assertion failed: doctor did not identify the native %s backend exactly once\n' "$distro" >&2
    return 1
  fi
  if grep -Eq 'dependency: (curl|tar)$' "$output"; then
    printf 'assertion failed: doctor invented host curl or tar dependencies\n' >&2
    return 1
  fi
  if [[ $(id -u) != 0 && $(grep -Fxc '  Found dependency: sudo' "$output") != 1 ]]; then
    printf 'assertion failed: doctor did not verify trusted sudo for the unprivileged guest user\n' >&2
    return 1
  fi
  if [[ "$distro" == debian || "$distro" == ubuntu ]] \
    && [[ $(grep -Fxc '  Found dependency: apt-get' "$output") != 1 ]]; then
    printf 'assertion failed: doctor did not verify trusted apt-get\n' >&2
    return 1
  fi
  if [[ "$restricted_path" == true ]]; then
    if [[ $(grep -Fc 'Optional tool unavailable: git' "$output") != 1 ]] \
      || { [[ "$distro" == arch ]] \
        && [[ $(grep -Fc 'Optional tool unavailable: makepkg' "$output") != 1 ]]; }; then
      printf 'assertion failed: doctor did not report absent Git/AUR tools as optional\n' >&2
      return 1
    fi
  fi
  case "$distro" in
    arch)
      local native_count native_packages native_status=0
      timeout --kill-after=2s 30s pacman -Dk > native-doctor-db.raw 2> native-doctor-db.stderr || native_status=$?
      [[ "$native_status" == 0 ]] || {
        printf 'native doctor reference found an inconsistent Arch package database\n' >&2
        return 2
      }
      native_packages=$(timeout --kill-after=2s 30s pacman -Qq) || return 2
      native_count=$(printf '%s\n' "$native_packages" | wc -l)
      grep -Fq "ALPM local package database (/var/lib/pacman/local, $native_count packages verified)" "$output" || {
        printf 'assertion failed: doctor disagrees with native Arch package database health\n' >&2
        return 1
      } ;;
    debian|ubuntu)
      if ! grep -Fq 'dpkg package database (/var/lib/dpkg/status)' "$output" \
        || ! grep -Fq 'APT package indexes (/var/lib/apt/lists)' "$output"; then
        printf 'assertion failed: doctor omitted an APT or dpkg health check\n' >&2
        return 1
      fi ;;
    fedora)
      if [[ $(grep -Fxc '  DNF local package database healthy' "$output") != 1 ]]; then
        printf 'assertion failed: doctor omitted or duplicated the healthy Fedora package database result\n' >&2
        return 1
      fi
      if [[ $(grep -Fxc '  RPM installed package database nonempty' "$output") != 1 ]]; then
        printf 'assertion failed: doctor did not verify a nonempty RPM installed package database\n' >&2
        return 1
      fi
      if [[ -n "$exec_receipt" ]]; then
        if [[ ! -f "$exec_receipt" ]]; then
          printf 'native doctor DNF execution receipt is missing\n' >&2
          return 2
        fi
        local dnf_exec_line
        if ! dnf_exec_line=$(grep -Em 1 'execve\("(/usr/bin|/usr/sbin)/dnf5", \["[^"]+", "--cacheonly", "--disable-repo=\*", "check"\], .*\) = 0$' "$exec_receipt"); then
          printf 'assertion failed: doctor did not execute the trusted offline DNF5 package database check\n' >&2
          return 1
        fi
        local rpm_exec_line
        if ! rpm_exec_line=$(grep -Em 1 'execve\("(/usr/bin|/usr/sbin)/rpm", \["[^"]+", "-qa"\], .*\) = 0$' "$exec_receipt"); then
          printf 'assertion failed: doctor did not execute the trusted RPM installed package query\n' >&2
          return 1
        fi
        printf 'Fedora doctor RPM execution receipt: %s\n' "$rpm_exec_line" >&2
        printf 'Fedora doctor DNF execution receipt: %s\n' "$dnf_exec_line" >&2
      fi ;;
  esac
}
# END DOCTOR BACKEND ORACLE

# BEGIN INFO NATIVE PACKAGE ORACLE
check_info_native_package() {
  local distro=$1 output=$2 status=0 version source actual_version actual_source
  case "$distro" in
    arch)
      timeout --kill-after=2s 30 pacman -Si pacman > native-info.raw 2> native-info.stderr || status=$?
      version=$(awk '$1 == "Version" && $2 == ":" {print $3}' native-info.raw)
      source=$(awk '$1 == "Repository" && $2 == ":" {print "Official repository (" $3 ")"}' native-info.raw) ;;
    debian|ubuntu)
      timeout --kill-after=2s 30 apt-cache policy pacman > native-info.raw 2> native-info.stderr || status=$?
      version=$(awk '$1 == "Candidate:" {print $2}' native-info.raw)
      source='Official repository (apt)' ;;
    fedora)
      timeout --kill-after=2s 30 dnf --cacheonly repoquery pacman --latest-limit=1 --queryformat '%{evr}' > native-info.raw 2> native-info.stderr || status=$?
      version=$(cat native-info.raw)
      source='Official repository (dnf)' ;;
    *) return 2 ;;
  esac
  if [[ "$status" != 0 || -z "$version" || "$version" == '(none)' || "$version" == *$'\n'* || -z "$source" || "$source" == *$'\n'* ]]; then
    printf 'native info reference failed for %s: exit=%s version=%q source=%q\n' "$distro" "$status" "$version" "$source" >&2
    head -c 4096 native-info.stderr >&2
    return 2
  fi
  if [[ $(grep -Ec '^[[:space:]]*Name: pacman$' "$output") != 1 \
    || $(grep -Ec '^[[:space:]]*Version: ' "$output") != 1 \
    || $(grep -Ec '^[[:space:]]*Source: ' "$output") != 1 ]]; then
    printf 'assertion failed: info omitted a unique pacman name, version, or source\n' >&2
    return 1
  fi
  actual_version=$(awk '$1 == "Version:" {print $2}' "$output")
  actual_source=$(sed -n 's/^[[:space:]]*Source: //p' "$output")
  printf 'native info %s expected=%s source=%s actual=%s source=%s\n' "$distro" "$version" "$source" "$actual_version" "$actual_source" >&2
  if [[ "$actual_version" != "$version" || "$actual_source" != "$source" ]]; then
    printf 'assertion failed: info disagrees with the native %s package catalog\n' "$distro" >&2
    return 1
  fi
}
# END INFO NATIVE PACKAGE ORACLE

check_native_tree_state() {
  local distro=$1 expected=$2 tree_binary=${3:-/usr/bin/tree} installed=false inventory
  case "$distro" in
    arch)
      inventory=$(pacman -Qq) || { printf 'assertion failed: native pacman database query failed\n' >&2; return 1; }
      grep -Fxq tree <<< "$inventory" && installed=true ;;
    debian|ubuntu)
      inventory=$(dpkg-query -W '-f=${Package}\t${Status}\n') || { printf 'assertion failed: native dpkg database query failed\n' >&2; return 1; }
      grep -Fxq $'tree\tinstall ok installed' <<< "$inventory" && installed=true ;;
    fedora)
      inventory=$(rpm -qa --qf '%{NAME}\n') || { printf 'assertion failed: native rpm database query failed\n' >&2; return 1; }
      grep -Fxq tree <<< "$inventory" && installed=true ;;
    *) printf 'assertion failed: unknown package backend %s\n' "$distro" >&2; return 1 ;;
  esac
  if [[ -z "$inventory" ]]; then
    printf 'assertion failed: native %s database query returned no packages\n' "$distro" >&2
    return 1
  fi
  if [[ "$expected" == installed ]]; then
    if [[ "$installed" != true || ! -x "$tree_binary" ]] || ! "$tree_binary" --version >/dev/null 2>&1; then
      printf 'assertion failed: native %s database or executable lacks installed tree\n' "$distro" >&2
      return 1
    fi
  elif [[ "$expected" == absent ]]; then
    if [[ "$installed" == true || -e "$tree_binary" || -L "$tree_binary" ]]; then
      printf 'assertion failed: native %s database or executable still contains tree\n' "$distro" >&2
      return 1
    fi
  else
    printf 'assertion failed: unknown expected tree state %s\n' "$expected" >&2
    return 1
  fi
}

# The APT fixture checks the guest's dpkg database directly. The output
# contract harness runs on hosts that may have an unrelated /usr/bin/tree.
check_apt_tree_absent() {
  local distro=$1 inventory
  [[ "$distro" == debian || "$distro" == ubuntu ]] || return 1
  inventory=$(dpkg-query -W '-f=${Package}\t${Status}\n') || return 1
  [[ -n "$inventory" ]] || return 1
  if grep -Fxq $'tree\tinstall ok installed' <<< "$inventory"; then
    printf 'assertion failed: native APT database already has tree installed\n' >&2
    return 1
  fi
}

# The lifecycle already downloaded the native tree archive and removed tree.
# Repack that exact payload with an older version so both APT update modes must
# complete a real upgrade. A temporary native APT preference limits the planned
# transaction to tree, even when the cloud image has unrelated pending updates.
prepare_apt_update_fixture() {
  local distro=$1 rowdir=$2 archive candidate installed simulation pin
  local archives=("$HOME"/tree_*.deb)
  [[ ${#archives[@]} == 1 && -f "${archives[0]}" && ! -L "${archives[0]}" ]] || return 1
  check_apt_tree_absent "$distro" || return 1
  pin=/etc/apt/preferences.d/omg-qemu-tree.pref
  sudo -n test ! -e "$pin" && sudo -n test ! -L "$pin" || return 1
  archive=${archives[0]}
  mkdir -p "$rowdir/tree-old-package" || return 1
  dpkg-deb --raw-extract "$archive" "$rowdir/tree-old-package" >/dev/null || return 1
  [[ -f "$rowdir/tree-old-package/DEBIAN/control" ]] || return 1
  sed -i 's/^Version: .*/Version: 0.0.1/' "$rowdir/tree-old-package/DEBIAN/control" || return 1
  grep -Fxq 'Version: 0.0.1' "$rowdir/tree-old-package/DEBIAN/control" || return 1
  dpkg-deb --build "$rowdir/tree-old-package" "$rowdir/tree-old.deb" >/dev/null || return 1
  apt_fixture_installed=1
  sudo -n dpkg --install "$rowdir/tree-old.deb" >/dev/null || return 1
  installed=$(dpkg-query -W '-f=${Status}\t${Version}\n' tree 2>/dev/null) || return 1
  [[ "$installed" == $'install ok installed\t0.0.1' ]] || return 1
  printf 'Package: tree:any\nPin: version *\nPin-Priority: 500\n\nPackage: *:any\nPin: release *\nPin-Priority: -1\n' > "$rowdir/apt-tree.preferences" || return 1
  apt_fixture_pin_created=1
  sudo -n install -o root -g root -m 0644 "$rowdir/apt-tree.preferences" "$pin" || return 1
  [[ $(sudo -n stat -c '%u:%g:%a' "$pin") == 0:0:644 ]] || return 1
  candidate=$(apt-cache policy tree | awk '$1 == "Candidate:" { print $2; exit }') || return 1
  [[ -n "$candidate" && "$candidate" != '(none)' ]] || return 1
  dpkg --compare-versions "$candidate" gt 0.0.1 || return 1
  simulation=$(apt-get -s upgrade) || return 1
  [[ $(grep -Ec '^Inst ' <<< "$simulation" || true) == 1 ]] || return 1
  grep -Eq '^Inst tree \[0\.0\.1\]' <<< "$simulation" || return 1
}

check_apt_update_fixture() {
  local installed candidate
  installed=$(dpkg-query -W '-f=${Status}\t${Version}\n' tree 2>/dev/null) || return 1
  candidate=$(apt-cache policy tree | awk '$1 == "Candidate:" { print $2; exit }') || return 1
  if [[ "$installed" != "$(printf 'install ok installed\t%s' "$candidate")" ]] \
    || ! dpkg --compare-versions "$candidate" gt 0.0.1; then
    printf 'assertion failed: APT update did not upgrade tree from 0.0.1 to the native candidate %s (installed: %s)\n' "$candidate" "$installed" >&2
    return 1
  fi
}

apt_tree_removal_id() {
  local history=$1 version=$2
  jq -er --arg version "$version" '
    [.[] | select(.transaction_type == "Remove" and .success == true and
      (.changes | length) == 1 and .changes[0].name == "tree" and
      .changes[0].old_version == $version and .changes[0].new_version == null and
      .changes[0].source == "apt")] |
    if length == 1 then .[0].id else empty end
  ' "$history"
}

check_apt_tree_restoration() {
  local history=$1 version=$2
  jq -e --arg version "$version" '
    [.[] | select(.transaction_type == "Install" and .success == true and
      (.changes | length) == 1 and .changes[0].name == "tree" and
      .changes[0].new_version == $version and .changes[0].source == "rollback")] |
    length == 1
  ' "$history" >/dev/null
}

check_apt_tree_only_delta() {
  local before=$1 after=$2 before_other after_other
  before_other=$(awk -F '\t' '$1 != "tree" { print }' <<< "$before") || return 1
  after_other=$(awk -F '\t' '$1 != "tree" { print }' <<< "$after") || return 1
  [[ "$before_other" == "$after_other" ]]
}

check_apt_update_delta() {
  local before=$1 after=$2 before_other after_other
  before_other=$(awk -F '\t' '$1 != "tree" { print }' <<< "$before") || return 1
  after_other=$(awk -F '\t' '$1 != "tree" { print }' <<< "$after") || return 1
  if [[ "$before_other" != "$after_other" ]]; then
    printf 'assertion failed: APT update changed installed packages other than tree or their install reasons\n' >&2
    return 1
  fi
}

cleanup_apt_update_fixture() {
  local pin=/etc/apt/preferences.d/omg-qemu-tree.pref failed=0
  if [[ "${apt_fixture_installed:-0}" == 1 ]]; then
    sudo -n dpkg --purge tree >/dev/null || failed=1
    if check_apt_tree_absent "$1"; then apt_fixture_installed=0; else failed=1; fi
  fi
  if [[ "${apt_fixture_pin_created:-0}" == 1 ]]; then
    sudo -n rm -f -- "$pin" || failed=1
    if sudo -n test ! -e "$pin" && sudo -n test ! -L "$pin"; then
      apt_fixture_pin_created=0
    else
      failed=1
    fi
  fi
  ((failed == 0))
}

# Compare the installed package database around a dry run. Repository metadata
# may refresh, but an install/remove preview must not change installed state.
native_package_snapshot() {
  local distro=$1 inventory reasons
  case "$distro" in
    arch)
      inventory=$(pacman -Q) || return 1
      reasons=$(pacman -Qqe) || return 1 ;;
    debian|ubuntu)
      inventory=$(dpkg-query -W '-f=${Package}\t${Version}\t${Status}\t${Architecture}\n') || return 1
      reasons=$(apt-mark showmanual) || return 1 ;;
    fedora)
      inventory=$(rpm -qa --qf '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n') || return 1
      reasons=$(dnf --cacheonly --disable-repo='*' repoquery --installed --queryformat '%{name} %{arch} %{reason}\n') || return 1 ;;
    *) return 1 ;;
  esac
  [[ -n "$inventory" ]] || return 1
  printf 'installed packages\n%s\ninstall reasons\n%s\n' \
    "$(printf '%s\n' "$inventory" | LC_ALL=C sort)" \
    "$(printf '%s\n' "$reasons" | LC_ALL=C sort)"
}

check_native_tree_only_delta() {
  local before=$1 after=$2 before_other after_other
  before_other=$(awk '$1 != "tree" { print }' <<< "$before") || return 1
  after_other=$(awk '$1 != "tree" { print }' <<< "$after") || return 1
  if [[ "$before_other" != "$after_other" ]]; then
    printf 'assertion failed: native package or install-reason state changed outside tree\n' >&2
    return 1
  fi
}

cleanup_native_tree_fixture() {
  local distro=$1
  case "$distro" in
    arch)
      if pacman -Qq tree >/dev/null 2>&1; then sudo -n pacman -R --noconfirm tree >/dev/null || return 1; fi ;;
    debian|ubuntu)
      sudo -n dpkg --purge tree >/dev/null || return 1 ;;
    fedora)
      if rpm -q tree >/dev/null 2>&1; then sudo -n rpm -e tree >/dev/null || return 1; fi ;;
    *) return 1 ;;
  esac
  check_native_tree_state "$distro" absent
}

native_installed_version() {
  local distro=$1 package=$2
  case "$distro" in
    arch) pacman -Q "$package" | awk -v name="$package" '$1 == name { print $2 }' ;;
    debian|ubuntu) dpkg-query -W '-f=${Status}\t${Version}\n' "$package" | awk -F '\t' '$1 == "install ok installed" { print $2 }' ;;
    fedora) rpm -q --qf '%{VERSION}-%{RELEASE}\n' "$package" ;;
    *) return 1 ;;
  esac
}

check_native_remove_preview() {
  local output=$1 version=$2
  awk -v version="$version" '
    /The following .*packages would be removed:/ { in_list = 1; next }
    /No changes made \(dry run\)/ { in_list = 0 }
    in_list && $1 == "✗" && $2 == "bash" && $3 == version { found = 1 }
    END { exit !found }
  ' "$output"
}

prepare_native_apt_orphan() {
  local distro=$1
  check_native_tree_state "$distro" installed || return 1
  if ! dpkg-query -W '-f=${Package}\t${Status}\n' apt bash > baseline-packages.tsv \
    || [[ $(wc -l < baseline-packages.tsv) != 2 ]] \
    || grep -qv $'\tinstall ok installed$' baseline-packages.tsv; then
    printf 'assertion failed: APT baseline packages are not installed\n' >&2
    return 1
  fi
  if ! apt-get -s autoremove > baseline-autoremove.log 2>&1 \
    || grep -q '^Remv ' baseline-autoremove.log; then
    printf 'assertion failed: APT guest has unrelated pre-existing orphans\n' >&2
    return 1
  fi
  if ! sudo -n apt-mark auto tree > apt-mark.log 2>&1 \
    || ! apt-mark showauto > auto-marked.log 2>&1 \
    || ! grep -Fxq tree auto-marked.log \
    || ! apt-get -s autoremove > orphan-preview.log 2>&1 \
    || [[ $(awk '$1 == "Remv" {print $2}' orphan-preview.log) != tree ]]; then
    printf 'assertion failed: native APT did not select exactly tree as an orphan\n' >&2
    return 1
  fi
}

check_native_apt_orphan_removed() {
  local distro=$1 output=$2 tree_binary=${3:-/usr/bin/tree}
  check_native_tree_state "$distro" absent "$tree_binary" || return 1
  if ! dpkg-query -W '-f=${Package}\t${Status}\n' apt bash > after-packages.tsv \
    || ! cmp -s baseline-packages.tsv after-packages.tsv \
    || ! grep -Eq 'Removed 1 orphan package([^[:alpha:]]|$)' "$output"; then
    printf 'assertion failed: APT cleanup did not preserve baseline packages and report one verified removal\n' >&2
    return 1
  fi
}

check_go_install() (
  local version=$1 base expected active executable fixture observed status
  base="$OMG_DATA_DIR/versions/go"
  expected="$base/$version"
  active=$(readlink -f "$base/current") || active=""
  executable=$(readlink -f "$base/current/bin/go") || executable=""
  if [[ "$active" != "$expected" || ! -L "$base/current" || -L "$expected" \
        || "$executable" != "$expected/bin/go" || ! -f "$executable" || ! -x "$executable" ]]; then
    printf 'assertion failed: Go %s lacks an active confined compiler\n' "$version" >&2; return 1
  fi
  fixture=$(mktemp -d "$base/.qemu-go-XXXXXX") || return 1
  trap 'rm -rf -- "$fixture"' EXIT
  export GOROOT="$expected" GOTOOLCHAIN=local GOENV=off GOWORK=off GOPROXY=off GOSUMDB=off CGO_ENABLED=0 GOMAXPROCS=2
  export GOPATH="$fixture/gopath" GOCACHE="$fixture/gocache" GOMODCACHE="$fixture/modcache"
  unset GOFLAGS GOOS GOARCH
  cd "$fixture" || return 1
  status=0
  observed=$(timeout --kill-after=2s 10 "$executable" env GOROOT GOVERSION 2>&1) || status=$?
  if [[ "$status" != 0 || "$observed" != "$expected"$'\n'"go$version" ]]; then
    printf 'assertion failed: Go toolchain identity exit=%s observed=%s\n' "$status" "$observed" >&2; return 1
  fi
  printf 'module example.invalid/omg-probe\n\ngo 1.27\n' > go.mod
cat > main.go <<'GO'
package main
import("bytes";"compress/gzip";"crypto/sha256";"encoding/hex";"encoding/json";"fmt";"io";"runtime")
func probe() error {
  hash:=sha256.Sum256([]byte("abc"))
  if hex.EncodeToString(hash[:])!="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {return fmt.Errorf("digest mismatch")}
  var compressed bytes.Buffer
  writer:=gzip.NewWriter(&compressed)
  if _,err:=writer.Write([]byte("omg-go"));err!=nil{return err}; if err:=writer.Close();err!=nil{return err}
  reader,err:=gzip.NewReader(&compressed);if err!=nil{return err}
  raw,err:=io.ReadAll(reader);if err!=nil{return err};if err:=reader.Close();err!=nil{return err}
  if string(raw)!="omg-go" {return fmt.Errorf("compression mismatch")}
  data,err:=json.Marshal(map[string]int{"answer":42});if err!=nil{return err}
  var parsed map[string]int;if err:=json.Unmarshal(data,&parsed);err!=nil{return err}
  channel:=make(chan int);go func(){channel<-parsed["answer"]}()
  if <-channel!=42{return fmt.Errorf("channel result mismatch")}
  return nil
}
func main(){if err:=probe();err!=nil{panic(err)};fmt.Println("OMG_GO_RUNTIME_OK:"+runtime.Version())}
GO
cat > main_test.go <<'GO'
package main
import ("testing"; "os")
func TestProbe(t *testing.T){if err:=probe();err!=nil{t.Fatal(err)};if err:=os.WriteFile("test-complete",[]byte("go-test-executed"),0600);err!=nil{t.Fatal(err)}}
GO
  status=0
  timeout --kill-after=5s 120 "$executable" build -p 2 -o probe . > stage.log 2>&1 || status=$?
  if [[ "$status" != 0 || ! -x probe ]]; then
    printf 'assertion failed: Go compilation exit=%s\n' "$status" >&2; cat stage.log >&2; return 1
  fi
  status=0
  observed=$(timeout --kill-after=2s 10 ./probe 2>&1) || status=$?
  if [[ "$status" != 0 || "$observed" != "OMG_GO_RUNTIME_OK:go$version" ]]; then
    printf 'assertion failed: Go compiled program exit=%s observed=%s\n' "$status" "$observed" >&2; return 1
  fi
  status=0
  timeout --kill-after=5s 120 "$executable" test -p 2 -count=1 -timeout=10s -v . > stage.log 2>&1 || status=$?
  if [[ "$status" != 0 || ! -f test-complete || $(cat test-complete 2>/dev/null) != go-test-executed ]] \
      || ! grep -q '^--- PASS: TestProbe (' stage.log; then
    printf 'assertion failed: Go test execution exit=%s\n' "$status" >&2; cat stage.log >&2; return 1
  fi
  cd "$base" || return 1
  rm -rf -- "$fixture" || return 1
  if [[ -e "$fixture" || -L "$fixture" ]]; then printf 'assertion failed: Go fixture cleanup\n' >&2; return 1; fi
)

check_node_install() {
  local version=$1 base expected active executable npm output status=0
  base="$OMG_DATA_DIR/versions/node"
  expected="$base/$version"
  active=$(readlink -f "$base/current") || active=""
  executable=$(readlink -f "$base/current/bin/node") || executable=""
  npm=$(readlink -f "$expected/lib/node_modules/npm/bin/npm-cli.js") || npm=""
  if [[ "$active" != "$expected" || ! -L "$base/current" || -L "$expected" \
        || "$executable" != "$expected/bin/node" || ! -x "$executable" || ! -f "$executable" \
        || "$npm" != "$expected/"* || ! -f "$npm" ]]; then
    printf 'assertion failed: Node %s lacks an active confined runtime and bundled npm\n' "$version" >&2; return 1
  fi
  output=$(timeout --kill-after=2s 60 env -u NODE_OPTIONS -u NODE_PATH "$executable" - "$version" "$executable" "$npm" "$base" 2>&1 <<'JS'
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const {execFileSync} = require('node:child_process');
const [version, executable, npm, base] = process.argv.slice(2);
assert.equal(process.version, `v${version}`, 'Node version mismatch');
assert.equal(process.execPath, executable, 'Node executable mismatch');
assert.equal(crypto.createHash('sha256').update('abc').digest('hex'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
assert.equal(zlib.gunzipSync(zlib.gzipSync('omg-runtime')).toString(), 'omg-runtime');
assert.equal(execFileSync(executable, ['-e', 'process.stdout.write(String(6*7))'], {timeout: 5000}).toString(), '42');
const fixture = fs.mkdtempSync(path.join(base, '.qemu-node-'));
try {
  fs.writeFileSync(path.join(fixture, 'probe.cjs'), 'require("node:fs").writeFileSync("result.txt", "npm-script-executed")');
  fs.writeFileSync(path.join(fixture, 'package.json'), JSON.stringify({name:'omg-offline-probe',version:'1.0.0',scripts:{probe:'node probe.cjs'}}));
  assert.equal(JSON.parse(fs.readFileSync(path.join(fixture, 'package.json'))).name, 'omg-offline-probe');
  fs.writeFileSync(path.join(fixture, 'user.npmrc'), '');
  fs.writeFileSync(path.join(fixture, 'global.npmrc'), '');
  const env = {...process.env, PATH: path.dirname(executable) + ':' + process.env.PATH,
    npm_config_cache: path.join(fixture, 'cache'), npm_config_offline: 'true',
    npm_config_audit: 'false', npm_config_update_notifier: 'false',
    npm_config_userconfig: path.join(fixture, 'user.npmrc'),
    npm_config_globalconfig: path.join(fixture, 'global.npmrc')};
  const options = {cwd: fixture, env, timeout: 20000, encoding: 'utf8', maxBuffer: 1024 * 1024};
  const npmVersion = execFileSync(executable, [npm, '--version'], options).trim();
  assert.match(npmVersion, /^\d+\.\d+\.\d+$/);
  execFileSync(executable, [npm, 'run', 'probe'], options);
  assert.equal(fs.readFileSync(path.join(fixture, 'result.txt'), 'utf8'), 'npm-script-executed');
} finally {
  fs.rmSync(fixture, {recursive:true, force:true});
}
assert.equal(fs.existsSync(fixture), false, 'Node behavior fixture cleanup failed');
console.log(`OMG_NODE_RUNTIME_OK:${version}`);
JS
  ) || status=$?
  if [[ "$status" != 0 || "$output" != "OMG_NODE_RUNTIME_OK:$version" ]]; then
    printf 'assertion failed: Node runtime behavior expected=%s exit=%s observed=%s\n' "$version" "$status" "$output" >&2; return 1
  fi
}

check_python_install() {
  local version=$1 base expected active executable output status=0
  base="$OMG_DATA_DIR/versions/python"
  expected="$base/$version"
  active=$(readlink -f "$base/current") || active=""
  executable=$(readlink -f "$base/current/bin/python3") || executable=""
  if [[ "$active" != "$expected" || ! -L "$base/current" || -L "$expected" \
        || "$executable" != "$expected/"* || ! -f "$executable" || ! -x "$executable" ]]; then
    printf 'assertion failed: Python %s lacks an active executable inside its installed version\n' "$version" >&2; return 1
  fi
  output=$(timeout --kill-after=2s 10 "$executable" --version 2>&1) || status=$?
  if [[ "$status" != 0 || "$output" != "Python $version" ]]; then
    printf 'assertion failed: Python executable version expected=%s exit=%s observed=%s\n' "$version" "$status" "$output" >&2; return 1
  fi
  output=$(timeout --kill-after=2s 150 "$executable" -I - "$version" "$expected" "$base" 2>&1 <<'PY'
import bz2, ctypes, gzip, hashlib, json, lzma, pathlib, sqlite3, ssl, subprocess, sys, tempfile, venv

version, expected, base = sys.argv[1:]
assert sys.version.split()[0] == version, 'interpreter version mismatch'
assert pathlib.Path(sys.executable).resolve().is_relative_to(pathlib.Path(expected)), 'interpreter escaped installation'
payload = b'OMG installed Python behavior'
for codec in (bz2, gzip, lzma):
    assert codec.decompress(codec.compress(payload)) == payload, f'{codec.__name__} round trip failed'
assert hashlib.sha256(b'abc').hexdigest() == 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', 'SHA-256 mismatch'
with sqlite3.connect(':memory:') as database:
    database.execute('create table probe(value integer)')
    database.execute('insert into probe values (?)', (42,))
    assert database.execute('select value from probe').fetchall() == [(42,)], 'SQLite query mismatch'
libc = ctypes.CDLL(None)
libc.abs.argtypes = [ctypes.c_int]
libc.abs.restype = ctypes.c_int
assert libc.abs(-42) == 42, 'ctypes foreign call failed'
context = ssl.create_default_context()
assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname, 'TLS verification defaults disabled'
# ensurepip uses bundled wheels offline; no package index or second download.
def crash_context():
    diagnostics = []
    probes = (
        ('kernel', ['sudo', '-n', 'journalctl', '-k', '--no-pager', '--since', '2 minutes ago']),
        ('coredump', ['coredumpctl', '--no-pager', 'list', '--since', '2 minutes ago']),
    )
    for label, command in probes:
        try:
            result = subprocess.run(command, text=True, capture_output=True, timeout=5)
        except (OSError, subprocess.TimeoutExpired) as error:
            diagnostics.append(f'{label} unavailable: {error}')
            continue
        lines = result.stdout.splitlines()
        if label == 'kernel':
            lines = [line for line in lines if 'segfault' in line.lower()]
        else:
            lines = [line for line in lines if 'python' in line.lower()]
        diagnostics.append(f'{label} exit={result.returncode}: ' + (' | '.join(lines[-3:]) or 'no matching record'))
    return '; '.join(diagnostics)

def run_probe(arguments, timeout=10):
    result = subprocess.run(arguments, text=True, capture_output=True, timeout=timeout)
    if result.returncode != 0:
        detail = f'Python child exited {result.returncode}: {result.stdout[:4096]} {result.stderr[:4096]}'
        if result.returncode == -11 or 'SIGSEGV' in result.stderr:
            detail += f'\nCrash diagnostics: {crash_context()}'
        raise RuntimeError(detail)
    return result.stdout

# Each attempt must pass: a transient crash must fail the row, not become a green retry.
# ensurepip unpacks bundled wheels onto an emulated disk. Run 36204199869 (main
# Fedora) saw a cold venv need >40s at attempt 2/5 on a loaded guest, which the
# former 40s cap reported as a product FAIL. The allowance now covers slow
# guest I/O; the SSH ceiling below still bounds the whole five-attempt probe.
for attempt in range(1, 6):
    try:
        with tempfile.TemporaryDirectory(prefix='.qemu-python-', dir=base) as temporary:
            environment = pathlib.Path(temporary) / 'venv'
            venv.create(environment, with_pip=False)
            child = environment / 'bin/python'
            run_probe([str(child), '-I', '-m', 'ensurepip', '--upgrade', '--default-pip'], timeout=120)
            observed = run_probe([str(child), '-I', '-c', 'import json,sys; print(json.dumps([sys.version.split()[0],sys.prefix,sys.base_prefix]))'])
            child_version, prefix, base_prefix = json.loads(observed)
            assert child_version == version and pathlib.Path(prefix) == environment, 'venv identity mismatch'
            assert prefix != base_prefix, 'venv is not isolated from its base interpreter'
            pip = run_probe([str(child), '-I', '-m', 'pip', '--isolated', '--disable-pip-version-check', '--version'])
            assert pip.startswith('pip ') and str(environment) in pip, 'pip is outside its venv'
        assert not pathlib.Path(temporary).exists(), 'Python behavior fixture cleanup failed'
    except Exception as error:
        raise RuntimeError(f'Python installed runtime attempt {attempt}/5 failed: {error}') from error
print(f'OMG_PYTHON_RUNTIME_OK:{version}')
PY
  ) || status=$?
  if [[ "$status" != 0 || "$output" != "OMG_PYTHON_RUNTIME_OK:$version" ]]; then
    printf 'assertion failed: Python runtime behavior expected=%s exit=%s observed=%s\n' "$version" "$status" "$output" >&2; return 1
  fi
}
check_hook_lifecycle() (
  # Execute the installed scripts unchanged in a disposable second repository.
  local hooks=$1 fixture output
  fixture=$(mktemp -d) || exit 1
  trap 'rm -rf -- "$fixture"' EXIT
  cd "$fixture" || exit 1
  export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
  hook_git() {
    git -c user.name='OMG fixture' -c user.email=fixture@example.invalid \
      -c commit.gpgsign=false -c core.hooksPath="$hooks" "$@"
  }
  expect_notice() {
    local expected=$1 message=$2
    shift 2
    output=$(hook_git "$@" 2>&1) || { printf 'assertion failed: Git operation %s: %s\n' "$*" "$output" >&2; return 1; }
    if { [[ "$expected" == yes ]] && [[ "$output" != *"$message"* ]]; } \
      || { [[ "$expected" == no ]] && [[ "$output" == *"$message"* ]]; }; then
      printf 'assertion failed: hook notice expected=%s during %s: %s\n' "$expected" "$*" "$output" >&2; return 1
    fi
  }
  hook_git init -q -b baseline || exit 1
  printf 'baseline\n' > omg.lock
  hook_git add omg.lock || exit 1
  expect_notice no 'omg.lock has unstaged changes' commit -qm baseline || exit 1
  printf 'changed\n' > omg.lock
  expect_notice yes 'omg.lock has unstaged changes' commit --allow-empty -m unstaged || exit 1
  [[ $(hook_git show HEAD:omg.lock) == baseline ]] || exit 1
  hook_git checkout -qb changed || exit 1
  hook_git add omg.lock || exit 1
  expect_notice no 'omg.lock has unstaged changes' commit -qm changed || exit 1
  [[ $(hook_git show HEAD:omg.lock) == changed ]] || exit 1
  expect_notice yes 'Environment changed on branch switch' checkout baseline || exit 1
  expect_notice no 'Environment changed on branch switch' checkout baseline || exit 1
  printf 'working tree edit\n' > omg.lock
  expect_notice no 'Environment changed on branch switch' checkout -- omg.lock || exit 1
  expect_notice yes 'Environment changed after merge' merge --ff-only changed || exit 1
  [[ $(cat omg.lock) == changed ]] || exit 1
  expect_notice no 'Environment changed after merge' merge --ff-only changed || exit 1
)
check_config_value() {
  local file=$1 expected=$2
  [[ -f "$file" && ! -L "$file" ]] \
    && [[ $(grep -Ec '^[[:space:]]*telemetry_enabled[[:space:]]*=' "$file") == 1 ]] \
    && grep -Fxq "telemetry_enabled = $expected" "$file"
}
check_config_oracle() {
  local assertion=$1 output=$2 config_file backup
  [[ -n "${OMG_CONFIG_DIR:-}" && "${OMG_CONFIG_DIR:-}" == "$rowdir/config" ]] || {
    printf 'assertion failed: config row escaped its private directory\n' >&2; return 1
  }
  config_file="$OMG_CONFIG_DIR/config.toml"
  backup="$config_file.backup"
  case "$assertion" in
    config-set-persisted)
      check_config_value "$config_file" true \
        && grep -Fq 'Set telemetry.enabled = true' "$output" || {
          printf 'assertion failed: config set did not persist true in private config\n' >&2; return 1
        } ;;
    config-get-persisted)
      check_config_value "$config_file" true \
        && [[ $(cat "$output") == true ]] || {
          printf 'assertion failed: config get disagrees with persisted true\n' >&2; return 1
        } ;;
    config-list-persisted)
      check_config_value "$config_file" true \
        && grep -Eq '^[[:space:]]*telemetry.enabled = true$' "$output" || {
          printf 'assertion failed: config list omits persisted telemetry value\n' >&2; return 1
        } ;;
    config-validate-persisted)
      check_config_value "$config_file" true \
        && grep -Fq 'Configuration is valid!' "$output" || {
          printf 'assertion failed: config validate did not check persisted config\n' >&2; return 1
        } ;;
    config-path-isolated)
      [[ $(cat "$output") == "$config_file" && ! -e "$config_file" && ! -L "$config_file" ]] || {
        printf 'assertion failed: config path did not name the private config file\n' >&2; return 1
      } ;;
    config-reset-defaults)
      check_config_value "$config_file" false \
        && check_config_value "$backup" true \
        && grep -Fq 'Configuration reset to defaults' "$output" || {
          printf 'assertion failed: config reset did not restore defaults and retain backup\n' >&2; return 1
        } ;;
    *) return 2 ;;
  esac
}
check_privacy_oracle() {
  local assertion=$1 output=$2 config_file queue_file export_file
  [[ "${OMG_CONFIG_DIR:-}" == "$rowdir/privacy-config" \
    && "${OMG_DATA_DIR:-}" == "$rowdir/privacy-data" ]] || {
    printf 'assertion failed: privacy row escaped its private directories\n' >&2; return 1
  }
  config_file="$OMG_CONFIG_DIR/config.toml"
  queue_file="$OMG_DATA_DIR/telemetry_queue.json"
  export_file="$rowdir/privacy.json"
  case "$assertion" in
    artifact:privacy.json)
      if [[ ! -f "$export_file" || -L "$export_file" || $(stat -c %a "$export_file") != 600 ]] \
        || ! jq -e -s 'length == 1 and (.[0] |
          (keys == ["exported_at", "local", "scope"]) and
          .scope == "local" and (.exported_at | type == "string" and length > 0) and
          ((.local | keys) == ["config.toml", "license.json", "usage.json"]) and
          .local["usage.json"] == {"fixture":"usage","total_commands":7} and
          .local["config.toml"] == "telemetry_enabled = false\n" and
          .local["license.json"] == {
            "tier":"pro", "features":["sbom"], "customer":"fixture@example.invalid",
            "expires_at":null, "validated_at":1700000000, "machine_id":"fixture-machine"
          })' "$export_file" >/dev/null 2>&1; then
        printf 'assertion failed: privacy export omitted local data, exposed secrets, or lacks owner-only permissions\n' >&2; return 1
      fi ;;
    privacy-opted-out)
      check_config_value "$config_file" false \
        && [[ ! -e "$queue_file" && ! -L "$queue_file" ]] \
        && grep -Fq 'Telemetry disabled locally' "$output" || {
          printf 'assertion failed: privacy opt-out did not persist disabled and purge the queue\n' >&2; return 1
        } ;;
    privacy-status-disabled)
      check_config_value "$config_file" false \
        && grep -Eq '^[[:space:]]*Telemetry: Disabled$' "$output" || {
          printf 'assertion failed: privacy status did not reflect disabled telemetry\n' >&2; return 1
        } ;;
    privacy-status-enabled)
      check_config_value "$config_file" true \
        && grep -Eq '^[[:space:]]*Telemetry: Enabled$' "$output" || {
          printf 'assertion failed: privacy status did not reflect enabled telemetry\n' >&2; return 1
        } ;;
    privacy-opted-in)
      check_config_value "$config_file" true \
        && grep -Fq 'Telemetry enabled locally' "$output" || {
          printf 'assertion failed: privacy opt-in did not persist enabled telemetry\n' >&2; return 1
        } ;;
    *) return 2 ;;
  esac
}
check_runtime_uninstall() {
  local runtime=$1 version=$2 base sibling external guard
  [[ "${OMG_DATA_DIR:-}" == "$rowdir/runtime-data" ]] || {
    printf 'assertion failed: runtime uninstall escaped its private data directory\n' >&2; return 1
  }
  base="$OMG_DATA_DIR/versions/$runtime"
  sibling="$base/9.9.9"
  external="$rowdir/external-runtime"
  guard="$OMG_DATA_DIR/versions/other-guard/1.0.0"
  if [[ -e "$base/$version" || -L "$base/$version" ]] \
    || [[ ! -f "$sibling/sentinel" || $(cat "$sibling/sentinel") != keep-sibling ]] \
    || [[ ! -L "$base/current" || $(readlink "$base/current") != "$sibling" ]] \
    || [[ ! -f "$external/sentinel" || $(cat "$external/sentinel") != keep-external ]] \
    || [[ ! -f "$guard/sentinel" || $(cat "$guard/sentinel") != keep-other ]]; then
    printf 'assertion failed: runtime uninstall did not remove only the inactive version\n' >&2; return 1
  fi
}
check_doctor_issue_delta() {
  local baseline_rc=$1 baseline_out=$2 baseline_err=$3 variant_rc=$4 variant_err=$5 expected_delta=$6
  local baseline_count variant_count
  baseline_count=$(sed -nE 's/^Error: doctor found ([0-9]+) health issue\(s\)$/\1/p' "$baseline_err")
  variant_count=$(sed -nE 's/^Error: doctor found ([0-9]+) health issue\(s\)$/\1/p' "$variant_err")
  if [[ "$baseline_rc" == 0 ]]; then
    [[ -z "$baseline_count" ]] && grep -Fq 'System is healthy' "$baseline_out" || return 1
    baseline_count=0
  elif [[ "$baseline_rc" != 1 || ! "$baseline_count" =~ ^[1-9][0-9]*$ ]]; then
    return 1
  fi
  [[ "$variant_rc" == 1 && "$variant_count" =~ ^[1-9][0-9]*$ ]] || return 1
  (( variant_count == baseline_count + expected_delta ))
}
check_doctor_network_output() {
  python3 - "$1" "$2" <<'PY'
import re
import sys
from pathlib import Path

distro, output = sys.argv[1:]
mirrors = [('Arch Linux', 'https://archlinux.org'), ('Kernel.org', 'https://kernel.org'),
           ('GitHub', 'https://github.com'), ('AUR', 'https://aur.archlinux.org')]
if distro != 'arch':
    mirrors = mirrors[1:3]
hosts = ['archlinux.org', 'aur.archlinux.org', 'github.com'] if distro == 'arch' else ['kernel.org', 'github.com']
if distro not in ('arch', 'debian', 'ubuntu', 'fedora'):
    raise SystemExit('assertion failed: unknown doctor network backend')
text = Path(output).read_text()
if text.count('Network Diagnostics\n') != 1 or text.count('DNS Resolution:\n') != 1:
    raise SystemExit('assertion failed: missing or duplicated doctor network sections')
basic = text.split('Network Diagnostics\n', 1)[0]
basic_failures = re.findall(r'^  Connectivity probes failed \((.+)\)$', basic, re.MULTILINE)
basic_hosts = ['archlinux.org', 'kernel.org'] if distro == 'arch' else ['github.com', 'kernel.org']
if (len(basic_failures) != 1 or
        not basic_failures[0].startswith(basic_hosts[0] + ': ') or
        '; ' + basic_hosts[1] + ': ' not in basic_failures[0] or
        basic_failures[0].endswith(basic_hosts[1] + ': ') or
        re.search(r'(?i)\bhealthy\b', basic_failures[0])):
    raise SystemExit('assertion failed: offline doctor basic connectivity did not fail both independent endpoints')
section = text.split('Network Diagnostics\n', 1)[1].split('DNS Resolution:\n', 1)
mirror_rows = [re.fullmatch(r'  ([✓✗⚠]) (.+?) \((.+)\)', line) for line in section[0].splitlines() if line.strip()]
dns_rows = [re.fullmatch(r'    ([✓✗]) (\S+) \((.+)\)', line) for line in section[1].splitlines() if line.startswith('    ')]
if any(row is None for row in mirror_rows + dns_rows):
    raise SystemExit('assertion failed: malformed doctor network row')
if [(row[1], row[2]) for row in mirror_rows] != [('✗', name) for name, _ in mirrors]:
    raise SystemExit('assertion failed: wrong or successful backend mirror probe')
for row, (_, url) in zip(mirror_rows, mirrors):
    if row[3] != 'timeout' and url not in row[3]:
        raise SystemExit('assertion failed: backend mirror failure lacks its requested URL')
if [row[2] for row in dns_rows] != hosts:
    raise SystemExit('assertion failed: wrong or missing backend DNS probe')
for row in dns_rows:
    if row[1] == '✓' and not re.fullmatch(r'[1-9][0-9]* addresses', row[3]):
        raise SystemExit('assertion failed: DNS success lacks resolved addresses')
dns_failures = sum(row[1] == '✗' for row in dns_rows)
print(len(mirrors) + dns_failures)
PY
}
check_runtime_state() {
  local runtime=$1 selected=$2 active=$3 assertion=$4 output=$5 base current
  [[ "${OMG_DATA_DIR:-}" == "$rowdir/runtime-data" ]] || {
    printf 'assertion failed: runtime state escaped its private data directory\n' >&2; return 1
  }
  base="$OMG_DATA_DIR/versions/$runtime"
  current="$base/$active"
  [[ "$assertion" != runtime-switch-state ]] || current="$base/$selected"
  if [[ ! -f "$base/$selected/sentinel" || $(cat "$base/$selected/sentinel") != keep-selected ]] \
    || [[ ! -f "$base/$active/sentinel" || $(cat "$base/$active/sentinel") != keep-active ]] \
    || [[ ! -f "$base/8.8.8/.omg-installing" || $(cat "$base/8.8.8/.omg-installing") != keep-pending ]] \
    || [[ ! -L "$base/7.7.7" || $(readlink "$base/7.7.7") != "$rowdir/external-runtime" ]] \
    || [[ ! -f "$rowdir/external-runtime/sentinel" || $(cat "$rowdir/external-runtime/sentinel") != keep-external ]] \
    || [[ ! -L "$base/current" || $(readlink "$base/current") != "$current" ]]; then
    printf 'assertion failed: runtime state changed outside the selected active pointer\n' >&2; return 1
  fi
  if [[ "$assertion" == runtime-list-state ]]; then
    jq -e -s --arg runtime "$runtime" --arg selected "$selected" --arg active "$active" \
      'length == 1 and .[0] == {runtime:$runtime,current:$active,installed:[$selected,$active]}' \
      "$output" >/dev/null || {
        printf 'assertion failed: runtime list did not report exact installed and active versions\n' >&2; return 1
      }
  elif [[ "$assertion" == runtime-switch-state ]]; then
    check_runtime_usage "$runtime" || return 1
  else
    return 2
  fi
}
check_golden_path_state() {
  local assertion=$1 output=$2 store="$OMG_CONFIG_DIR/golden-paths.toml"
  if [[ ! -f "$store" || -L "$store" ]] || ! python3 - "$assertion" "$store" <<'PY'
import pathlib
import sys
import tomllib

assertion, path = sys.argv[1:]
document = tomllib.loads(pathlib.Path(path).read_text())
templates = document.get('templates')
valid = set(document) == {'templates'} and isinstance(templates, list)
if assertion == 'golden-path-deleted':
    valid = valid and templates == []
elif assertion == 'golden-path-flags':
    valid = valid and len(templates) == 2 and all(isinstance(item, dict) for item in templates)
    if valid:
        by_name = {item.get('name'): item for item in templates}
        flagged = by_name.get('flagged', {})
        valid = (set(by_name) == {'smoke', 'flagged'}
                 and by_name['smoke'].get('runtimes') == {}
                 and by_name['smoke'].get('packages') == []
                 and set(flagged) == {'name', 'runtimes', 'packages', 'created_at'}
                 and flagged['runtimes'] == {'node': '20', 'python': '3.12'}
                 and flagged['packages'] == ['ripgrep']
                 and type(flagged['created_at']) is int and flagged['created_at'] > 0)
else:
    valid = valid and len(templates) == 1 and isinstance(templates[0], dict)
    if valid:
        template = templates[0]
        valid = (set(template) == {'name', 'runtimes', 'packages', 'created_at'}
                 and template['name'] == 'smoke'
                 and template['runtimes'] == {}
                 and template['packages'] == []
                 and type(template['created_at']) is int
                 and template['created_at'] > 0)
if not valid:
    sys.exit(1)
PY
  then
    printf 'assertion failed: golden path store lacks the expected private template state\n' >&2
    return 1
  fi
  case "$assertion" in
    golden-path-created)
      [[ $(grep -Fc "Golden path 'smoke' created!" "$output") == 1 ]] ;;
    golden-path-listed)
      [[ $(grep -Fc '1 custom template(s)' "$output") == 1 \
        && $(grep -Fc 'smoke - runtimes: [], packages: 0' "$output") == 1 ]] ;;
    golden-path-deleted)
      [[ $(grep -Fc "Deleted template 'smoke'" "$output") == 1 ]] \
        && ! grep -Fq "Template 'smoke' not found" "$output" ;;
    golden-path-flags)
      [[ $(grep -Fc "Golden path 'flagged' created!" "$output") == 1 ]] \
        && grep -Fq 'Node: 20' "$output" && grep -Fq 'Python: 3.12' "$output" \
        && grep -Fq 'Packages: ripgrep' "$output" ;;
    *) return 2 ;;
  esac || { printf 'assertion failed: golden path output disagrees with the private template state\n' >&2; return 1; }
}
check_file_output_oracle() {
  local assertion=$1 code=$2 stdout=$3 stderr=$4 distro=${5:-arch} file count announced
  case "$assertion" in
    man-pages-generated)
      if [[ "$code" != 0 || ! -d man || -L man
        || ! -f man/omg.1 || -L man/omg.1 ]] \
        || ! grep -Eiq '^\.TH[[:space:]]+"?omg"?[[:space:]]' man/omg.1; then
        printf 'assertion failed: generate-man omitted its main page\n' >&2
        return 1
      fi
      count=$(find man -maxdepth 1 -type f -name 'omg*.1' | wc -l)
      announced=$(sed -nE 's/^.*Generated ([0-9]+) man pages$/\1/p' "$stdout")
      if [[ "$announced" != "$count" ]] \
        || find man -mindepth 1 -maxdepth 1 ! -type f | grep -q . \
        || find man -maxdepth 1 -type f ! -name 'omg*.1' | grep -q .; then
        printf 'assertion failed: generated man page count or file shape is invalid\n' >&2
        return 1
      fi
      if [[ "${OMG_QEMU_EXACT_MAN_PAGES:-0}" == 1 ]]; then
        if [[ ! -f "$HOME/man_page_inventory.txt" || -L "$HOME/man_page_inventory.txt" ]] \
          || ! cmp -s "$HOME/man_page_inventory.txt" \
            <(find man -maxdepth 1 -type f -name 'omg*.1' -printf '%f\n' | LC_ALL=C sort); then
          printf 'assertion failed: generated man page set disagrees with the reviewed CLI manifest\n' >&2
          return 1
        fi
      else
        local -a legacy_pages=(omg.1 omg-search.1 omg-install.1 omg-update.1 omg-doctor.1
          omg-audit.1 omg-audit-licenses.1 omg-run.1 omg-workspace.1
          omg-workspace-list.1 omg-env.1 omg-env-capture.1 omg-team.1
          omg-team-golden-path.1 omg-container.1 omg-container-build.1
          omg-snapshot.1 omg-snapshot-create.1 omg-generate-man.1)
        if [[ "$count" -lt 40 ]]; then
          printf 'assertion failed: published man page set has fewer than 40 pages\n' >&2
          return 1
        fi
        for file in "${legacy_pages[@]}"; do
          if [[ ! -f "man/$file" || -L "man/$file" ]]; then
            printf 'assertion failed: published man page set omitted %s\n' "$file" >&2
            return 1
          fi
        done
      fi
      while IFS= read -r file; do
        if ! grep -Eq '^\.TH[[:space:]]+' "$file" \
          || ! grep -Eq '^\.SH[[:space:]]+"?NAME"?$' "$file" \
          || ! grep -Eq '^\.SH[[:space:]]+"?SYNOPSIS"?$' "$file"; then
          printf 'assertion failed: generated man page lacks TH, NAME, or SYNOPSIS content: %s\n' "$file" >&2
          return 1
        fi
      done < <(find man -maxdepth 1 -type f -name 'omg*.1' -print) ;;
    enterprise-audit-export-evidence)
      if [[ "$distro" != arch ]]; then
        if [[ "$code" != 1 || -e enterprise-evidence-flags || -L enterprise-evidence-flags ]] \
          || ! grep -Fq 'Installed-package export requires the Arch package backend' "$stderr"; then
          printf 'assertion failed: unsupported enterprise export left evidence behind\n' >&2
          return 1
        fi
        return 0
      fi
      if [[ "$code" != 0 || ! -d enterprise-evidence-flags || -L enterprise-evidence-flags ]] \
        || ! grep -Fq 'Audit evidence exported' "$stdout" \
        || ! grep -Fq 'iso27001' "$stdout" || ! grep -Fq '2025-Q1' "$stdout"; then
        printf 'assertion failed: enterprise export omitted its success receipt\n' >&2
        return 1
      fi
      if ! python3 "$HOME/qemu-enterprise-export-oracle.py" enterprise-evidence-flags; then
        printf 'assertion failed: enterprise export lacks five private, valid evidence files\n' >&2
        return 1
      fi ;;
    audit-export-absolute-refusal)
      if [[ "$code" != 1 ]] || ! grep -Fq 'Absolute paths not allowed' "$stderr" \
        || grep -Eq 'Audit evidence exported|Evidence exported to' "$stdout" \
        || [[ -e audit-evidence || -L audit-evidence
              || -e audit-evidence-flags || -L audit-evidence-flags
              || -e enterprise-evidence || -L enterprise-evidence ]]; then
        printf 'assertion failed: absolute-path export did not refuse before creating evidence\n' >&2
        return 1
      fi ;;
    team-compliance-no-report)
      if [[ "$code" != 1 || -e compliance.json || -L compliance.json ]] \
        || ! grep -Fq "No compliance data is available to export to '$rowdir/compliance.json'" "$stderr" \
        || ! grep -Fq 'compliance evidence requires an evaluated report' "$stderr" \
        || grep -Fq 'Evidence exported' "$stdout"; then
        printf 'assertion failed: team compliance export fabricated an unevaluated report\n' >&2
        return 1
      fi ;;
    *) return 2 ;;
  esac
}
check_workspace_failure() {
  local assertion=$1 code=$2 stdout=$3 stderr=$4
  if [[ "$code" != 1 || -e omg.lock || -L omg.lock
    || ! -f omg-workspace.toml || -L omg-workspace.toml
    || ! -f Makefile || -L Makefile ]] \
    || [[ "$(sha256sum omg-workspace.toml Makefile)" != "$workspace_failure_before" ]]; then
    printf 'assertion failed: negative workspace fixture changed or exited incorrectly\n' >&2; return 1
  fi
  case "$assertion" in
    workspace-missing-task)
      grep -Fxq "→ Task 'true' not found, trying 'make true'..." "$stdout" \
        && grep -Fxq "  ✗ 'omg run true' in '.' exited with code 1" "$stdout" \
        && grep -Fxq '⚠ 0 succeeded, 1 failed' "$stdout" \
        && grep -Fxq "Error: 1 project(s) failed to run 'true'" "$stderr" \
        && grep -Fq "No rule to make target 'true'." "$stderr" ;;
    workspace-missing-lock)
      grep -Fxq '  ⚠ needs attention' "$stdout" \
        && grep -Fxq 'Error: No omg.lock file found' "$stderr" \
        && grep -Fxq 'Error: 1 project(s) need attention, 0 failed to check (of 1 total)' "$stderr" ;;
    *) return 2 ;;
  esac || { printf 'assertion failed: workspace refusal did not prove the intended missing input\n' >&2; return 1; }
}
check_product_output() {
  local safety=$1 assertion=$2 code=$3 stdout=$4 stderr=$5 distro=${6:-arch}
  if grep -Eq 'panicked at|thread .main. panicked' "$stdout" "$stderr"; then
    printf 'assertion failed: product emitted a panic report\n' >&2; return 1
  fi
  if [[ "$safety" == help-boundary ]] && ! grep -Fq 'Usage:' "$stdout"; then
    printf 'assertion failed: help output lacks Usage\n' >&2; return 1
  fi
  if [[ "$code" != 0 ]] && ! grep -q '[^[:space:]]' "$stderr"; then
    printf 'assertion failed: product refusal lacks its own stderr explanation\n' >&2; return 1
  fi
  case "$assertion" in
    workspace-missing-task|workspace-missing-lock)
      check_workspace_failure "$assertion" "$code" "$stdout" "$stderr" || return 1 ;;
    audit-log-filtered-export)
      [[ "$code" == 0 ]] && grep -Fxq '✓ Export successful' "$stdout" \
        && grep -Fxq "OMG Exporting audit log to $rowdir/audit-log-export.json..." "$stdout" \
        && python3 "$rowdir/qemu-audit-log-oracle.py" check "$rowdir" || {
          printf 'assertion failed: audit log export omitted exact filtered private evidence\n' >&2; return 1;
        } ;;
    man-pages-generated|audit-export-absolute-refusal|team-compliance-no-report|enterprise-audit-export-evidence)
      check_file_output_oracle "$assertion" "$code" "$stdout" "$stderr" "$distro" || return 1 ;;
  esac
  if [[ "$assertion" == license-* ]]; then
    local mode=${assertion#license-} report=$stdout
    if [[ "$distro" != arch ]]; then
      local refusal='Error: License scanning of installed packages is not available without the Arch backend'
      [[ "$mode" != enterprise-* ]] || refusal='Error: Enterprise license scan requires the Arch package backend'
      local allowed_output='^[[:space:]]*$'
      [[ "$mode" != audit-csv ]] || allowed_output+='|^OMG Scanning installed packages for license information\.\.\.$'
      if [[ "$code" != 1 || $(cat "$stderr") != "$refusal" ]] \
        || grep -Ev "$allowed_output" "$stdout" >/dev/null \
        || [[ -e licenses-export.csv || -L licenses-export.csv ]] \
        || compgen -G 'license-scan-*' >/dev/null; then
        printf 'assertion failed: unsupported license backend must refuse without a report or export\n' >&2; return 1
      fi
    else
      local expected_code=0
      [[ "$mode" != audit-mit-json ]] || expected_code=1
      [[ "$code" == "$expected_code" ]] || { printf 'assertion failed: Arch license scan returned the wrong status\n' >&2; return 1; }
      if [[ "$mode" == audit-csv ]]; then
        report=licenses-export.csv
      elif [[ "$mode" == enterprise-json ]]; then
        local -a exports=()
        mapfile -t exports < <(compgen -G 'license-scan-*.json' || true)
        [[ ${#exports[@]} == 1 ]] || { printf 'assertion failed: license scan must create exactly one JSON export\n' >&2; return 1; }
        report=${exports[0]}
      fi
      if [[ "$mode" == audit-mit-json ]]; then
        python3 qemu-license-oracle.py "$mode" "$report" "$stderr" || return 1
      else
        python3 qemu-license-oracle.py "$mode" "$report" || return 1
      fi
    fi
  fi
  if [[ "$assertion" == package-dry-run-install || "$assertion" == package-dry-run-remove || "$assertion" == package-dry-run-recursive ]]; then
    if [[ "$assertion" == package-dry-run-recursive && "$distro" != arch ]]; then
      local refusal='Recursive removal is not supported by the Debian backend'
      [[ "$distro" != fedora ]] || refusal='Recursive removal is not supported by this package backend'
      if [[ "$code" != 1 ]] || ! grep -Fxq "Error: $refusal" "$stderr" \
        || grep -Fq 'Remove Preview' "$stdout"; then
        printf 'assertion failed: unsupported recursive removal did not refuse before preview\n' >&2; return 1
      fi
    else
      local preview='  | Install Preview' changes='  ℹ • No changes will be made (dry run)' target=pacman
      if [[ "$assertion" != package-dry-run-install ]]; then
        preview='  | Remove Preview'; changes='  ℹ No changes made (dry run)'; target=bash
      fi
      if [[ "$code" != 0 ]] || ! grep -Fxq "$preview" "$stdout" \
        || ! grep -Fxq '    dry run' "$stdout" \
        || ! grep -Eq "(^|[^[:alnum:]_-])${target}([^[:alnum:]_-]|$)" "$stdout" \
        || ! grep -Fxq "$changes" "$stdout"; then
        printf 'assertion failed: package dry run lacks target-specific no-change preview\n' >&2; return 1
      fi
      if [[ "$assertion" == package-dry-run-recursive ]] \
        && ! grep -Fq 'Additional unneeded dependencies would also be removed' "$stdout"; then
        printf 'assertion failed: recursive dry run omitted dependent-package preview\n' >&2; return 1
      fi
    fi
  fi
  if [[ "$assertion" == audit-fix-refusal ]]; then
    case "$distro" in
      arch) assertion=audit-source-failure ;;
      debian|ubuntu|fedora)
        if [[ "$code" != 1 ]] \
          || ! grep -Fxq 'Error: Vulnerability auto-fix is not available without the Arch backend; upgrade the affected packages manually' "$stderr" \
          || grep -Eq 'Scanning for fixable vulnerabilities|No vulnerabilities found|Security audit completed' "$stdout"; then
          printf 'assertion failed: unsupported backend did not refuse auto-fix before scanning\n' >&2; return 1
        fi ;;
      *) printf 'assertion failed: unknown auto-fix backend %s\n' "$distro" >&2; return 1 ;;
    esac
  fi
  if [[ "$assertion" == audit-source-failure ]]; then
    if [[ "$code" != 1 ]] \
      || ! grep -Eq '^Error: (Failed to scan package .+ for vulnerabilities: Failed to query the OSV vulnerability database|Failed to query native security advisories)' "$stderr" \
      || grep -Eq 'No vulnerabilities found|Security audit completed' "$stdout"; then
      printf 'assertion failed: offline audit did not explicitly refuse an unavailable advisory source\n' >&2; return 1
    fi
  fi
  if [[ "$assertion" == audit-secret-scoped ]]; then
    if [[ "$code" != 0 ]] \
      || ! grep -Fxq '⚠ Found 1 potential secrets:' "$stdout" \
      || ! grep -Fxq '  ● 1 MEDIUM' "$stdout" \
      || ! grep -Fxq '  [MEDIUM] Password in project/config.txt:1' "$stdout" \
      || ! grep -Fxq '      pass**********...7429' "$stdout" \
      || [[ $(grep -Ec '^  \[(LOW|MEDIUM|HIGH|CRITICAL)\]' "$stdout") != 1 ]] \
      || grep -Eq 'No secrets detected|outside\.txt|qemuSecret7429|outsideSecret9031' "$stdout" "$stderr"; then
      printf 'assertion failed: scoped secret scan missed, misclassified, or exposed the fixture\n' >&2; return 1
    fi
  fi
  if [[ "$assertion" == audit-secret-critical ]]; then
    if [[ "$code" != 1 ]] \
      || ! grep -Fxq '⚠ Found 1 potential secrets:' "$stdout" \
      || ! grep -Fxq '  ● 1 CRITICAL' "$stdout" \
      || ! grep -Fxq '  [CRITICAL] Private Key in project/critical/key.pem:1' "$stdout" \
      || ! grep -Fxq '      ----**********...----' "$stdout" \
      || ! grep -Fxq 'Error: Secret scan failed: 1 critical secret finding(s) require remediation' "$stderr" \
      || [[ $(grep -Ec '^  \[(LOW|MEDIUM|HIGH|CRITICAL)\]' "$stdout") != 1 ]] \
      || grep -Fq -- "$(printf '%s%s' '-----BEGIN ' 'PRIVATE KEY-----')" "$stdout" "$stderr"; then
      printf 'assertion failed: critical secret scan did not fail closed and redact the fixture\n' >&2; return 1
    fi
  fi
  if [[ "$assertion" == audit-eol-state ]]; then
    if [[ "$code" != 0 ]] \
      || ! grep -Fxq '  ✗ node v16.20.2 - EOL (EOL: 2023-09-11)' "$stdout" \
      || ! grep -Fxq '  ✓ python v3.12.14 - Active (EOL: 2028-10-31)' "$stdout" \
      || ! grep -Fxq '⚠ 1 runtime(s) need attention. Consider upgrading to supported versions.' "$stdout" \
      || [[ $(grep -Fc 'node v16.20.2' "$stdout") != 1 ]] \
      || [[ $(grep -Fc 'python v3.12.14' "$stdout") != 1 ]] \
      || grep -Eq 'All runtimes are within support period|No managed runtimes were detected' "$stdout"; then
      printf 'assertion failed: audit EOL did not classify both confined runtimes and count one issue\n' >&2; return 1
    fi
  fi
  if [[ "$assertion" == sbom-source-failure ]]; then
    if [[ "$code" != 1 || -e sbom.json || -L sbom.json ]] \
      || ! grep -Eq '^Error: Failed to generate system SBOM: Failed to generate a complete security SBOM: (Failed to scan package .+ for vulnerabilities: Failed to query the OSV vulnerability database|Failed to query native security advisories)' "$stderr" \
      || grep -Eq 'No vulnerabilities found|SBOM generated|Security audit completed' "$stdout"; then
      printf 'assertion failed: offline SBOM did not refuse an unavailable advisory source without an artifact\n' >&2; return 1
    fi
  fi
  if [[ "$assertion" == self-update-downgrade-refusal ]]; then
    if [[ "$code" != 1 ]] \
      || ! grep -Fq 'Refusing to downgrade' "$stderr"; then
      printf 'assertion failed: self-update did not refuse an offline downgrade\n' >&2; return 1
    fi
  fi
  if [[ "$assertion" == env-share-missing-lock ]]; then
    if [[ "$code" != 1 ]] \
      || ! grep -Fq 'No omg.lock file found' "$stderr"; then
      printf 'assertion failed: env share did not refuse without an omg.lock\n' >&2; return 1
    fi
  fi
  if [[ "$assertion" == diff-missing-lock ]]; then
    if [[ "$code" != 1 || -e missing.lock || -L missing.lock ]] \
      || ! grep -Fq 'Failed to inspect lockfile missing.lock' "$stderr"; then
      printf 'assertion failed: diff did not refuse the requested missing lockfile\n' >&2; return 1
    fi
  fi
  if [[ "$assertion" == doctor-eol-state ]]; then
    if [[ "$code" != 1 ]] \
      || ! grep -Fq 'Runtime EOL Status' "$stdout" \
      || ! grep -Fxq '  ⚠ node 16.20.2 - EOL since 2023-09-11' "$stdout" \
      || ! grep -Fxq '  ✓ python 3.12.14' "$stdout" \
      || grep -Eq 'No managed runtimes were detected|All detected runtimes are within support period' "$stdout"; then
      printf 'assertion failed: doctor EOL did not classify both confined runtimes\n' >&2; return 1
    fi
  fi
  if [[ "$assertion" == doctor-network-state ]]; then
    if [[ "$code" != 1 ]] || ! grep -Fxq 'Network Diagnostics' "$stdout"; then
      printf 'assertion failed: doctor network did not report a failed diagnostic run\n' >&2; return 1
    fi
  fi
  if [[ "$code" == 0 ]]; then
    case "$assertion" in
      workspace-initialized|workspace-project-added|workspace-project-listed|workspace-project-removed)
        if [[ ! -f omg-workspace.toml || -L omg-workspace.toml ]] \
          || ! python3 - "$assertion" <<'PY'
import pathlib
import sys
import tomllib

workspace = tomllib.loads(pathlib.Path('omg-workspace.toml').read_text())
assert workspace.get('name') == 'smoke'
assert isinstance(workspace.get('created_at'), str) and workspace['created_at']
projects = workspace.get('projects', {})
assert isinstance(projects, dict)
if sys.argv[1] in ('workspace-initialized', 'workspace-project-removed'):
    assert projects == {}
else:
    assert set(projects) == {'fixture'}
    assert projects['fixture'].get('path') == '.'
    assert projects['fixture'].get('depends_on', []) == []
PY
        then
          printf 'assertion failed: workspace command did not persist the expected private workspace state\n' >&2; return 1
        fi
        if [[ "$assertion" == workspace-project-listed ]]; then
          if [[ $(grep -Fxc 'OMG Workspace: smoke' "$stdout" || true) != 1 ]] \
            || [[ $(grep -Fxc '  1. fixture → .' "$stdout" || true) != 1 ]] \
            || [[ $(grep -Ec '^[[:space:]]*[0-9]+\. ' "$stdout" || true) != 1 ]] \
            || grep -Fq 'No projects in workspace' "$stdout"; then
            printf 'assertion failed: workspace list did not render the persisted fixture project\n' >&2; return 1
          fi
        elif [[ "$assertion" == workspace-project-removed ]]; then
          if [[ $(grep -Fxc "✓ Removed project 'fixture'" "$stdout" || true) != 1 ]]; then
            printf 'assertion failed: workspace remove did not report the removed fixture project\n' >&2; return 1
          fi
        fi ;;
      container-init-scaffold)
        if [[ ! -f Dockerfile.omg || -L Dockerfile.omg || ! -f .dockerignore || -L .dockerignore ]] \
          || ! python3 - <<'PY'
from pathlib import Path

dockerfile = Path('Dockerfile.omg').read_text()
lines = dockerfile.splitlines()
assert lines[0] == 'FROM debian:bookworm'
assert sum(line.startswith('FROM ') for line in lines) == 1
assert lines[-1] == 'CMD ["/bin/bash"]'
assert [line.split(' ', 1)[0] for line in lines if line.startswith(
    ('RUN ', 'COPY ', 'ADD ', 'FROM ', 'CMD ', 'ENTRYPOINT '))] == [
    'FROM', 'RUN', 'COPY', 'CMD']
for line in ('RUN apt-get update && apt-get install -y \\',
             '    curl wget git build-essential ca-certificates \\',
             '    && rm -rf /var/lib/apt/lists/*',
             'WORKDIR /app', 'COPY . .', 'CMD ["/bin/bash"]'):
    assert lines.count(line) == 1, line
assert not any(line.startswith(('# WARNING: no pinned digest', 'ENV NODE_VERSION=',
                                'ENV GO_VERSION=', 'ENV PYTHON_VERSION=')) for line in lines)
protection = ['# added by omg container init', '.git', '.env', '.env.*',
              '!.env.example', '*.pem', '*.key', 'id_rsa*', '.omg/']
for name in ('.dockerignore', 'Dockerfile.omg.dockerignore', '.containerignore'):
    path = Path(name)
    assert path.is_file() and not path.is_symlink(), name
    rules = path.read_text().splitlines()
    assert rules[:2] == ['!.env', '!secrets.key'], name
    assert rules[-len(protection):] == protection, name
PY
        then
          printf 'assertion failed: container init omitted its Debian scaffold or final credential exclusions\n' >&2; return 1
        fi
        if [[ $(grep -Fxc '  ✓ Created Dockerfile.omg' "$stdout" || true) != 1 ]] \
          || [[ $(grep -Fc 'Base image: debian:bookworm' "$stdout" || true) != 1 ]]; then
          printf 'assertion failed: container init did not report the generated Debian scaffold\n' >&2; return 1
        fi ;;
      task-executed)
        if [[ ! -f smoke-task.marker || -L smoke-task.marker ]] \
          || [[ $(cat smoke-task.marker) != omg-qemu-smoke-task ]] \
          || [[ $(grep -Fxc 'smoke-task-ok' "$stdout" || true) != 1 ]]; then
          printf 'assertion failed: omg run lacks Makefile smoke task execution evidence\n' >&2; return 1
        fi ;;
      watch-task-rerun)
        if [[ ! -f watch-runs.marker || -L watch-runs.marker \
              || ! -f watch-evidence.json || -L watch-evidence.json ]] \
          || [[ $(grep -Fxc 'omg-qemu-watch-run' watch-runs.marker || true) != 2 \
                || $(wc -l < watch-runs.marker) != 2 ]] \
          || ! jq -e -s 'length == 1 and (.[0] == {
            "schema_version": 1, "initial_runs": 1, "runs_after_edit": 2,
            "readiness_seen": true, "rerun_seen": true, "ctrl_c_stopped": true
          })' watch-evidence.json >/dev/null \
          || [[ $(grep -Fc 'smoke-task-ok' "$stdout" || true) != 2 ]] \
          || ! grep -Fq 'Watching for changes...' "$stdout" \
          || ! grep -Fq 'File changed, re-running' "$stdout"; then
          printf 'assertion failed: run --watch lacks a bounded source-edit rerun and Ctrl+C receipt\n' >&2; return 1
        fi ;;
      parallel-tasks-executed)
        if [[ ! -f parallel-one.done || -L parallel-one.done \
              || ! -f parallel-two.done || -L parallel-two.done ]] \
          || [[ $(cat parallel-one.done) != parallel-one \
              || $(cat parallel-two.done) != parallel-two ]] \
          || [[ $(grep -Fxc 'parallel-one-ok' "$stdout" || true) != 1 \
              || $(grep -Fxc 'parallel-two-ok' "$stdout" || true) != 1 ]]; then
          printf 'assertion failed: omg run --parallel lacks overlapping task execution evidence\n' >&2; return 1
        fi ;;
      all-tasks-executed)
        if [[ ! -f smoke-task.marker || -L smoke-task.marker \
              || ! -f npm-task.marker || -L npm-task.marker ]] \
          || [[ $(cat smoke-task.marker) != omg-qemu-smoke-task \
              || $(cat npm-task.marker) != npm-smoke-task ]] \
          || [[ $(grep -Fxc 'smoke-task-ok' "$stdout" || true) != 1 \
              || $(grep -Fxc 'npm-task-ok' "$stdout" || true) != 1 ]]; then
          printf 'assertion failed: omg run --all lacks Make and npm task execution evidence\n' >&2; return 1
        fi ;;
      config-set-persisted|config-get-persisted|config-list-persisted|config-validate-persisted|config-path-isolated|config-reset-defaults)
        check_config_oracle "$assertion" "$stdout" || return 1 ;;
      golden-path-created|golden-path-listed|golden-path-deleted|golden-path-flags)
        check_golden_path_state "$assertion" "$stdout" || return 1 ;;
      privacy-opted-out|privacy-status-disabled|privacy-opted-in|privacy-status-enabled)
        check_privacy_oracle "$assertion" "$stdout" || return 1 ;;
      hooks-installed|hooks-absent)
        local hook label hook_path
        for hook in pre-commit post-checkout post-merge; do
          hook_path=".git/hooks/$hook"
          if [[ "$assertion" == hooks-absent ]]; then
            if [[ -e "$hook_path" || -L "$hook_path" ]]; then
              printf 'assertion failed: removed hook remains: %s\n' "$hook" >&2; return 1
            fi
          else
            case "$hook" in pre-commit) label=Pre-commit ;; post-checkout) label=Post-checkout ;; post-merge) label=Post-merge ;; esac
            if [[ ! -f "$hook_path" || -L "$hook_path" || ! -x "$hook_path" ]] \
              || ! grep -Fxq "# OMG $label Hook" "$hook_path" || ! sh -n "$hook_path"; then
              printf 'assertion failed: installed hook is missing, invalid, or not executable: %s\n' "$hook" >&2; return 1
            fi
          fi
        done
        if [[ "$assertion" == hooks-installed ]] && ! check_hook_lifecycle "$PWD/.git/hooks"; then
          printf 'assertion failed: installed hook lifecycle contract\n' >&2; return 1
        fi ;;
      workspace-filtered-output|workspace-all-output)
        local primary nested expected_nested=0
        primary=$(grep -Fxc 'smoke-task-ok' "$stdout" || true)
        nested=$(grep -Fxc 'nested-smoke-task-ok' "$stdout" || true)
        [[ "$assertion" != workspace-all-output ]] || expected_nested=1
        if [[ "$primary" != 1 || "$nested" != "$expected_nested" ]]; then
          printf 'assertion failed: workspace task counts primary=%s nested=%s; expected primary=1 nested=%s\n' "$primary" "$nested" "$expected_nested" >&2; return 1
        fi ;;
      ci-github-workflow|ci-github-workflow-advanced)
        local workflow=.github/workflows/ci.yml
        if [[ ! -f "$workflow" || -L "$workflow" ]] \
          || ! grep -Fxq 'name: CI' "$workflow" \
          || ! grep -Fxq 'on: [push, pull_request]' "$workflow" \
          || ! grep -Fxq '  contents: read' "$workflow" \
          || ! grep -Fxq '  build-and-test:' "$workflow" \
          || ! grep -Eq '^          OMG_VERSION=v[0-9]+\.[0-9]+\.[0-9]+ ' "$workflow" \
          || ! grep -Fxq '        run: omg run build' "$workflow" \
          || ! grep -Fxq '        run: omg run test' "$workflow"; then
          printf 'assertion failed: ci init did not create the expected GitHub build/test workflow\n' >&2; return 1
        fi
        if [[ "$assertion" == ci-github-workflow-advanced ]]; then
          if ! grep -Fxq '  security:' "$workflow" \
            || ! grep -Fxq '          cargo audit' "$workflow" \
            || ! grep -Eq '^          cargo cyclonedx ' "$workflow" \
            || ! grep -Fxq '          name: rust-dependencies-sbom' "$workflow"; then
            printf 'assertion failed: advanced ci init lacks its security audit and SBOM job\n' >&2; return 1
          fi
        elif grep -Fxq '  security:' "$workflow"; then
          printf 'assertion failed: basic ci init unexpectedly generated the advanced security job\n' >&2; return 1
        fi ;;
      json-stdout)
        if ! jq -e -s 'length == 1' "$stdout" >/dev/null 2>&1; then
          printf 'assertion failed: stdout is not exactly one JSON document\n' >&2; return 1
        fi ;;
      fingerprint:*)
        if ! python3 "$HOME/qemu-fingerprint-oracle.py" "${assertion#fingerprint:}" "$distro" "$PWD" "$stdout"; then
          printf 'assertion failed: native-backed fingerprint artifact oracle\n' >&2; return 1
        fi ;;
      native-tree-installed|native-tree-absent|native-apt-tree-rollback)
        local expected=installed
        [[ "$assertion" != native-tree-absent ]] || expected=absent
        check_native_tree_state "$distro" "$expected" || return 1 ;;
      native-apt-orphan-removed)
        check_native_apt_orphan_removed "$distro" "$stdout" || return 1 ;;
      search-official-tree-output)
        if ! awk '
          /^  [^[:space:]]+ [^[:space:]]+  / {
            results++
            if (results == 1 && ($1 != "tree" || $3 != "Official" || NF != 3)) bad=1
            if ($1 == "tree") trees++
          }
          END { exit !(results > 0 && trees == 1 && !bad) }
        ' "$stdout"; then
          printf 'assertion failed: search lacks a ranked official tree result\n' >&2; return 1
        fi ;;
      search-official-limit-three)
        if ! awk '
          /^  \| Search$/ { headings++; next }
          /^    git-$/ { queries++; next }
          /^  [^[:space:]]+ [^[:space:]]+  / {
            results++
            if ($1 !~ /^git-/ || $3 != "Official" || NF != 3) bad=1
            if (seen[$1]++) bad=1
            next
          }
          /^  \(\+[1-9][0-9]* more packages\.\.\.\)$/ { more++; next }
          /^[[:space:]]*$/ { next }
          /^OMG_QEMU_RECEIPT:/ { next }
          { bad=1 }
          END { exit !(headings == 1 && queries == 1 && results == 3 && more == 1 && !bad) }
        ' "$stdout"; then
          printf 'assertion failed: official git- prefix search lacks three results and a positive remainder\n' >&2; return 1
        fi ;;
      artifact:*)
        local artifact=${assertion#artifact:}
        if [[ ! -f "$artifact" || -L "$artifact" ]] || ! jq -e -s 'length == 1' "$artifact" >/dev/null 2>&1; then
          printf 'assertion failed: artifact %s is not a regular JSON document\n' "$artifact" >&2; return 1
        fi
        if [[ "$artifact" == privacy.json ]]; then
          check_privacy_oracle "$assertion" "$stdout" || return 1
        fi ;;
      sbom-inventory-only)
        if [[ ! -f sbom.json || -L sbom.json ]] || ! jq -e -s '
          length == 1 and (.[0] |
            .bomFormat == "CycloneDX" and
            (.components | type == "array" and length > 0) and
            ((.metadata.component.properties // []) |
              any(.[]; .name == "omg:advisory-scan" and .value == "not-performed")) and
            ((.vulnerabilities // []) | type == "array" and length == 0))
        ' sbom.json >/dev/null 2>&1 \
          || ! grep -Fq 'Inventory only: advisory matching was skipped' "$stdout"; then
          printf 'assertion failed: inventory-only SBOM lacks the advisory-scan marker or warning\n' >&2; return 1
        fi ;;
      update-fast-output)
        if ! grep -Fq 'Fast System Update' "$stdout" \
          || ! grep -Eqi 'Syncing package|Synced' "$stdout" \
          || ! grep -Eqi 'System is up to date|System updated successfully|Upgraded [0-9]+ packages?' "$stdout"; then
          printf 'assertion failed: update --fast lacked sync and completion evidence\n' >&2; return 1
        fi ;;
      update-turbo-output)
        if ! grep -Fq 'TURBO System Update' "$stdout" \
          || ! grep -Eqi 'Turbo upgrade|cached, no sync|Checking for updates.*cached' "$stdout" \
          || ! grep -Eqi 'System is up to date|System updated successfully|Upgraded [0-9]+ packages?' "$stdout"; then
          printf 'assertion failed: update --turbo lacked cached-mode and completion evidence\n' >&2; return 1
        fi ;;
      daemon-foreground-lifecycle)
        if [[ ! -f daemon-evidence/daemon-lifecycle.json || -L daemon-evidence/daemon-lifecycle.json ]] \
          || ! jq -e -s 'length == 1 and (.[0] | .schema_version == 1 and
            .direct == true and .foreground == true and .ipc == true and
            .singleton == true and .shutdown == true and .restart == true and
            .query_parity == true and .sigint == true and .cleanup == true and
            (.backend_faults | type == "array"))' daemon-evidence/daemon-lifecycle.json >/dev/null; then
          printf 'assertion failed: daemon --foreground lifecycle receipt is missing or incomplete\n' >&2; return 1
        fi ;;
    esac
  fi
  return 0
}
check_container_engine_argv() {
  local root=$1 assertion=$2 index operation
  local -a actual=() expected=()
  case "$assertion" in
    container-run-argv)
      operation=run
      expected=(--detach --name smoke -w /tmp/omg-smoke -e SMOKE=1
        -v "$root:/tmp/omg-smoke" -- debian:bookworm sh -c 'printf smoke') ;;
    container-shell-argv)
      operation=run
      expected=(--rm -it --name "$(basename "$root")-dev" -w /tmp
        -e TERM=xterm-256color -e SMOKE=1
        -v "$root:/app" -v "$root:/tmp/omg-smoke" -- debian:bookworm /bin/bash) ;;
    container-build-argv)
      operation=build
      expected=(-f Dockerfile -t smoke:latest --no-cache --build-arg SMOKE=1
        --target dev -- "$root") ;;
    *) return 2 ;;
  esac
  if [[ ! -f "$root/engine/calls" || -L "$root/engine/calls" \
        || ! -f "$root/engine/argv" || -L "$root/engine/argv" \
        || $(cat "$root/engine/calls") != "$(printf 'version\n%s' "$operation")" ]]; then
    printf 'assertion failed: fake container engine was not probed and invoked exactly once\n' >&2
    return 1
  fi
  mapfile -d '' -t actual < "$root/engine/argv"
  if [[ ${#actual[@]} -ne ${#expected[@]} ]]; then
    printf 'assertion failed: container engine argv length differs from the exact contract\n' >&2
    return 1
  fi
  for index in "${!expected[@]}"; do
    if [[ "${actual[$index]}" != "${expected[$index]}" ]]; then
      printf 'assertion failed: container engine argv differs at position %s\n' "$index" >&2
      return 1
    fi
  done
}
# END PRODUCT OUTPUT ORACLE
# BEGIN ROW LOG
write_row_log() {
  local destination=$1 stdout=$2 stderr=$3 identity=$4 verdict=$5
  {
    printf 'case=%s verdict=%s\n' "$identity" "$verdict"
    # The trusted reporter bounds excerpts. Keep the diagnosis ahead of large
    # JSON/list output, retaining the complete streams for artifact inspection.
    grep -m 4 '^assertion failed:' "$stderr" || true
    printf '\nstderr:\n'
    cat "$stderr"
    printf '\nstdout:\n'
    cat "$stdout"
  } > "$destination"
}
# END ROW LOG
trap 'rc=$?; if [[ "$rc" == 2 ]]; then printf "error: invalid inventory configuration or row %s\n" "${id:-<preflight>}" >&2; fi' EXIT

work=""; distro=""; tiers=""; tag=""; binary=""; tsv=""
allow_mutations=false
allow_credentialed=false
isolate_hermetic=false
network_scope=unconfined
network_policy=""
row_timeout=120
ssh_port=2222
ssh_user=bench
while (($#)); do
  case "$1" in
    --work|--distro|--tiers|--tag|--binary|--tsv|--row-timeout|--ssh-port|--ssh-user|--network-policy|--man-page-inventory)
      [[ $# -ge 2 && -n "$2" ]] || exit 2
      case "$1" in
        --work) work=$2 ;; --distro) distro=$2 ;; --tiers) tiers=$2 ;;
        --tag) tag=$2 ;; --binary) binary=$2 ;; --tsv) tsv=$2 ;;
        --network-policy) network_policy=$2 ;;
        --man-page-inventory) man_page_inventory=$2 ;;
        --row-timeout) row_timeout=$2 ;; --ssh-port) ssh_port=$2 ;; --ssh-user) ssh_user=$2 ;;
      esac
      shift 2 ;;
    --allow-mutations) allow_mutations=true; shift ;;
    --allow-credentialed) allow_credentialed=true; shift ;;
    --isolate-hermetic) isolate_hermetic=true; shift ;;
    --help) printf 'Usage: qemu-inventory.sh --work DIR --distro D --tiers CSV --tag TAG --binary GUEST_PATH --tsv FILE [--allow-mutations] [--allow-credentialed] [--row-timeout S]\nRuns TSV-selected rows in the guest at 127.0.0.1 and writes evidence.\n'; exit 0 ;;
    *) printf 'error: unknown argument %s\n' "$1" >&2; exit 2 ;;
  esac
done
[[ -n "$work" && -n "$distro" && -n "$tiers" && -n "$tag" && -n "$binary" && -n "$tsv" ]] || exit 2
man_page_inventory=${man_page_inventory:-}
if [[ -n "$man_page_inventory" ]]; then
  [[ -f "$man_page_inventory" && ! -L "$man_page_inventory" ]] || exit 2
  man_page_mode=exact
else
  man_page_mode=structural-legacy
fi
[[ "$row_timeout" =~ ^[0-9]+$ && "$row_timeout" -gt 0 ]] || exit 2
case "$distro" in arch|debian|ubuntu|fedora) ;; *) exit 2 ;; esac
for tool in ssh jq timeout sha256sum; do command -v "$tool" >/dev/null || exit 3; done
overlap_fixture=$(jq -rn --rawfile fixture "$(dirname "$0")/workspace-overlap-fixture.sh" '$fixture | @sh')
license_oracle_path="$(dirname "$0")/qemu-license-oracle.py"
license_oracle=$(jq -rn --rawfile fixture "$license_oracle_path" '$fixture | @sh')
container_engine_path="$(dirname "$0")/qemu-container-fake-engine.sh"
container_engine=$(jq -rn --rawfile fixture "$container_engine_path" '$fixture | @sh')
[[ "$binary" == /* && "$binary" != *$'\n'* ]] || exit 2
[[ "$ssh_user" =~ ^[a-z_][a-z0-9_-]*$ && "$ssh_port" =~ ^[0-9]+$ ]] || exit 2
[[ "$tiers" =~ ^[a-z,-]+$ && "$tiers" != ,* && "$tiers" != *, && "$tiers" != *,,* ]] || exit 2
IFS=',' read -ra requested_tiers <<< "$tiers"
for tier in "${requested_tiers[@]}"; do
  case "$tier" in hermetic|container|qemu|network|credentialed|pty|nested-container) ;; *) exit 2 ;; esac
done
[[ -f "$tsv" ]] || exit 2
scopes='{}'
if [[ "$isolate_hermetic" == true ]]; then
  [[ -f "$network_policy" && ! -L "$network_policy" && $(wc -c < "$network_policy") -le 1048576 ]] || exit 2
  inventory_digest=$(sha256sum "$tsv"); inventory_digest=${inventory_digest%% *}
  scopes=$(jq -ce --arg digest "$inventory_digest" '
    select(.inventory_sha256 == $digest) | .scopes |
    select(type=="object" and length>0 and
           all(.[]; .=="offline" or .=="network"))' "$network_policy")
fi

root=$(cd "$work" && pwd)
guest="$root/guest"
out="$root/inventory"
# Refuse to overwrite evidence from a previous invocation.
[[ ! -e "$out" ]] || { printf 'error: inventory evidence already exists: %s\n' "$out" >&2; exit 2; }
mkdir -p "$out/rows"
sha256sum "${BASH_SOURCE[0]}" "$tsv" "$license_oracle_path" "$container_engine_path" "$(dirname "$0")/qemu-run-watch-check.py" "$(dirname "$0")/qemu-enterprise-export-oracle.py" "$(dirname "$0")/qemu-audit-log-oracle.py" > "$out/input-sha256.txt"
if [[ "$man_page_mode" == exact ]]; then sha256sum "$man_page_inventory" >> "$out/input-sha256.txt"; fi
jq -n --arg release "$tag" --arg distro "$distro" --arg tiers "$tiers" --arg binary "$binary" --arg man_page_mode "$man_page_mode" \
  --argjson mutations "$allow_mutations" --argjson credentialed "$allow_credentialed" --argjson deadline "$row_timeout" \
  '{release:$release,distro:$distro,tiers:$tiers,binary:$binary,man_page_mode:$man_page_mode,allow_mutations:$mutations,allow_credentialed:$credentialed,row_timeout_seconds:$deadline}' > "$out/metadata.json"
# -n keeps ssh from forwarding (and draining) this loop's stdin, which is the
# TSV stream: without it only the first tier-matching row ever executes.
opts=(-n -i "$guest/client-key" -p "$ssh_port" -o BatchMode=yes -o ConnectTimeout=5
  -o ServerAliveInterval=5 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=yes
  -o UserKnownHostsFile="$guest/known_hosts")
target="$ssh_user@127.0.0.1"

# Selected tiers as comma-wrappedneedle, same idiom as release-smoke.sh.
want=",$tiers,"
# Publish each completed row atomically so an outer deadline cannot erase
# observed failures. Completion is a separate, last-written receipt.
summary_tmp="$out/results.json"
printf '[]' > "$summary_tmp"
printf '{"complete":false}\n' > "$out/summary.json"
pass=0; fail=0; skipped=0
record() { # case_id result exit_code elapsed
  local entry
  entry=$(jq -n --arg c "$1" --arg d "$distro" --arg r "$2" --argjson e "$3" --argjson s "$4" --arg scope "$network_scope" \
    '{case_id:$c, distro:$d, result:$r, artifact_source:"inventory", exit_code:$e, elapsed_seconds:$s, network_scope:$scope}')
  jq --slurpfile e <(printf '%s' "$entry") '. + [$e[0]]' "$summary_tmp" > "$summary_tmp.next"
  mv "$summary_tmp.next" "$summary_tmp"
}

# Prerequisite lookup for requires-chain replay (see below): id to the
# columns the skip gates need. Loaded once; the main loop streams the TSV
# a second time via process substitution.
resolve_exit() {
  local cell=$1 entry key seen=, value=""
  if [[ "$cell" =~ ^(0|[1-9][0-9]{0,2})$ ]] && ((cell <= 255)); then printf '%s' "$cell"; return; fi
  [[ "$cell" != *, ]] || return 1
  local entries=()
  IFS=',' read -ra entries <<< "$cell"
  for entry in "${entries[@]}"; do
    [[ "$entry" =~ ^(arch|debian|ubuntu|fedora):(0|[1-9][0-9]{0,2})$ ]] || return 1
    key=${entry%%:*}
    [[ "$seen" != *",$key,"* ]] && (( ${entry#*:} <= 255 )) || return 1
    seen+="$key,"
    [[ "$key" != "$distro" ]] || value=${entry#*:}
  done
  [[ ${#entries[@]} == 4 && -n "$value" ]] || return 1
  printf '%s' "$value"
}

# Validate the complete input before any guest action. Requires must point
# backwards, which rejects missing dependencies and cycles without a depth cap.
IFS= read -r header < "$tsv"
[[ "$header" == $'case\targs_json\tsafety\texpected_exit\texpected_ux\trequires\ttier\ttargets\tassertions\tcleanup' ]] || exit 2
awk -F '\t' 'NR > 1 { if (NF != 10) exit 1; for (i = 1; i <= NF; i++) if ($i == "") exit 1 }' "$tsv" || exit 2
declare -A row_args=() row_requires=() row_tier=() row_safety=() row_ux=() row_exit=() row_targets=() row_assertions=() row_cleanup=()
counter_for_case() {
  case "$1" in
    explicit-shortcut|explicit) printf ec ;; total-shortcut) printf tc ;;
    orphan-shortcut) printf oc ;; updates-shortcut) printf uc ;;
  esac
}
while IFS=$'\t' read -r id aj s e u r t tg a cleanup; do
  [[ "$id" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ && -z "${row_args[$id]:-}" ]] || exit 2
  [[ "$r" == - || "$r" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ ]] || exit 2
  [[ "$r" == - || -n "${row_args[$r]:-}" ]] || exit 2
  jq -e 'type == "array" and length > 0 and all(.[]; type == "string" and (explode | index(0) == null))' <<< "$aj" >/dev/null || exit 2
  counter=$(counter_for_case "$id")
  if [[ -n "$counter" ]]; then
    [[ "$a" == native-count ]] || exit 2
    if [[ "$id" == explicit ]]; then
      jq -e '. == ["explicit", "--count"]' <<< "$aj" >/dev/null || exit 2
    else
      jq -e --arg counter "$counter" 'length == 1 and .[0] == $counter' <<< "$aj" >/dev/null || exit 2
    fi
  elif [[ "$a" == native-count ]]; then
    exit 2
  fi
  case "$s" in read|isolated-write|controlled-error|help-boundary|interactive|package-mutation|service-mutation) ;; *) exit 2 ;; esac
  case "$u" in pass|declared) ;; *) exit 2 ;; esac
  [[ "$t" != *, && "$t" != ,* && "$t" != *,,* ]] || exit 2
  IFS=',' read -ra input_tiers <<< "$t"
  for input_tier in "${input_tiers[@]}"; do
    case "$input_tier" in hermetic|container|qemu|network|credentialed|pty|nested-container) ;; *) exit 2 ;; esac
  done
  if [[ "$tg" != hermetic:pass ]]; then
    [[ "$tg" != *, ]] || exit 2
    IFS=',' read -ra input_targets <<< "$tg"
    seen_targets=,
    for input_target in "${input_targets[@]}"; do
      [[ "$input_target" =~ ^(arch|debian|ubuntu|fedora):(pass|pending|known-defect|not-applicable)$ ]] || exit 2
      target_distro=${input_target%%:*}
      [[ "$seen_targets" != *",$target_distro,"* ]] || exit 2
      seen_targets+="$target_distro,"
    done
  fi
  resolved=""
  if [[ "$u" != declared ]]; then resolved=$(resolve_exit "$e") || exit 2; fi
  case "$a" in license-audit-json|license-audit-mit-json|license-audit-csv|license-enterprise-text|license-enterprise-json|-|native-count|audit-source-failure|audit-fix-refusal|audit-secret-scoped|audit-secret-critical|audit-eol-state|sbom-source-failure|sbom-inventory-only|json-stdout|hooks-installed|hooks-absent|workspace-initialized|workspace-project-added|workspace-project-listed|workspace-project-removed|workspace-filtered-output|workspace-all-output|container-init-scaffold|ci-github-workflow|ci-github-workflow-advanced|task-executed|watch-task-rerun|parallel-tasks-executed|all-tasks-executed|package-dry-run-install|package-dry-run-remove|package-dry-run-recursive|artifact:manifest.json|artifact:privacy.json|artifact:sbom.json|fingerprint:snapshot-create|fingerprint:migrate-export|fingerprint:migrate-import|fingerprint:env-capture|fingerprint:env-check|fingerprint:team-status|fingerprint:team-push|fingerprint:team-pull|update-fast-output|update-turbo-output|daemon-foreground-lifecycle|search-official-limit-three|search-official-tree-output|native-tree-installed|native-tree-absent|native-apt-tree-rollback|native-apt-orphan-removed|self-update-downgrade-refusal|env-share-missing-lock|diff-missing-lock|status-native-fast|status-native-full|outdated-native-count|outdated-json-native-count|doctor-native-backend|doctor-eol-state|doctor-network-state|info-native-package|config-set-persisted|config-get-persisted|config-list-persisted|config-validate-persisted|config-path-isolated|config-reset-defaults|golden-path-created|golden-path-listed|golden-path-deleted|golden-path-flags|privacy-opted-out|privacy-status-disabled|privacy-opted-in|privacy-status-enabled|runtime-version-removed|runtime-list-state|runtime-switch-state|container-run-argv|container-shell-argv|container-build-argv|man-pages-generated|audit-export-absolute-refusal|team-compliance-no-report|enterprise-audit-export-evidence|audit-log-filtered-export|workspace-missing-task|workspace-missing-lock) ;; *) exit 2 ;; esac
  case "$id:$a" in
    workspace-list:workspace-project-listed|workspace-remove:workspace-project-removed|container-init:container-init-scaffold) ;;
    workspace-list:*|workspace-remove:*|container-init:*|*:workspace-project-listed|*:workspace-project-removed|*:container-init-scaffold) exit 2 ;;
  esac
  case "$id" in
    generate-man)
      [[ "$a" == man-pages-generated && "$s" == isolated-write && "$resolved" == 0 ]] || exit 2
      jq -e '. == ["generate-man","--output","${ROOT}/man"]' <<< "$aj" >/dev/null || exit 2 ;;
    audit-log-flags)
      [[ "$a" == audit-log-filtered-export && "$s" == isolated-write && "$resolved" == 0 ]] || exit 2
      jq -e '. == ["audit","log","--limit","3","--severity","error","--export","${ROOT}/audit-log-export.json"]' <<< "$aj" >/dev/null || exit 2 ;;
    workspace-run|workspace-check)
      [[ "$s" == read && "$resolved" == 1 && "$r" == workspace-add ]] || exit 2
      if [[ "$id" == workspace-run ]]; then
        [[ "$a" == workspace-missing-task ]] || exit 2
        jq -e '. == ["workspace","run","true"]' <<< "$aj" >/dev/null || exit 2
      else
        [[ "$a" == workspace-missing-lock ]] || exit 2
        jq -e '. == ["workspace","check"]' <<< "$aj" >/dev/null || exit 2
      fi ;;
    audit-export)
      [[ "$a" == audit-export-absolute-refusal && "$s" == isolated-write && "$resolved" == 1 ]] || exit 2
      jq -e '. == ["audit","export","--output","${ROOT}/audit-evidence"]' <<< "$aj" >/dev/null || exit 2 ;;
    audit-export-flags)
      [[ "$a" == audit-export-absolute-refusal && "$s" == isolated-write && "$resolved" == 1 ]] || exit 2
      jq -e '. == ["audit","export","--framework","soc2","--period","2024-Q4","--output","${ROOT}/audit-evidence-flags"]' <<< "$aj" >/dev/null || exit 2 ;;
    enterprise-audit-export)
      [[ "$a" == audit-export-absolute-refusal && "$s" == controlled-error && "$resolved" == 1 ]] || exit 2
      jq -e '. == ["enterprise","audit-export","--output","${ROOT}/enterprise-evidence"]' <<< "$aj" >/dev/null || exit 2 ;;
    enterprise-audit-export-flags)
      [[ "$a" == enterprise-audit-export-evidence && "$s" == isolated-write
        && "$e" == 'arch:0,debian:1,ubuntu:1,fedora:1' ]] || exit 2
      jq -e '. == ["enterprise","audit-export","--framework","iso27001","--period","2025-Q1","--output","./enterprise-evidence-flags"]' <<< "$aj" >/dev/null || exit 2 ;;
    team-compliance-export)
      [[ "$a" == team-compliance-no-report && "$s" == controlled-error && "$resolved" == 1 && "$r" == team-init ]] || exit 2
      jq -e '. == ["team","compliance","--export","${ROOT}/compliance.json"]' <<< "$aj" >/dev/null || exit 2 ;;
    *) [[ "$a" != audit-log-filtered-export && "$a" != workspace-missing-task && "$a" != workspace-missing-lock && "$a" != man-pages-generated && "$a" != audit-export-absolute-refusal && "$a" != team-compliance-no-report && "$a" != enterprise-audit-export-evidence ]] || exit 2 ;;
  esac
  if [[ "$id" == run ]]; then
    [[ "$a" == task-executed && "$s" == read && "$resolved" == 0 ]] || exit 2
    jq -e '. == ["run", "smoke", "--using", "make"]' <<< "$aj" >/dev/null || exit 2
  elif [[ "$a" == task-executed ]]; then
    exit 2
  fi
  if [[ "$id" == run-watch ]]; then
    [[ "$a" == watch-task-rerun && "$s" == isolated-write && "$resolved" == 0 && "$t" == container,pty && "$cleanup" == tempdir-drop ]] || exit 2
    jq -e '. == ["run", "--watch", "smoke"]' <<< "$aj" >/dev/null || exit 2
  elif [[ "$a" == watch-task-rerun ]]; then
    exit 2
  fi
  if [[ "$id" == run-parallel ]]; then
    [[ "$a" == parallel-tasks-executed && "$s" == read && "$resolved" == 0 ]] || exit 2
    jq -e '. == ["run", "--parallel", "parallel-one,parallel-two"]' <<< "$aj" >/dev/null || exit 2
  elif [[ "$a" == parallel-tasks-executed ]]; then
    exit 2
  fi
  if [[ "$id" == run-all ]]; then
    [[ "$a" == all-tasks-executed && "$s" == read && "$resolved" == 0 ]] || exit 2
    jq -e '. == ["run", "--all", "smoke"]' <<< "$aj" >/dev/null || exit 2
  elif [[ "$a" == all-tasks-executed ]]; then
    exit 2
  fi
  case "$id" in
    install)
      [[ "$a" == package-dry-run-install && "$s" == read && "$resolved" == 0 ]] || exit 2
      jq -e '. == ["install", "--dry-run", "pacman"]' <<< "$aj" >/dev/null || exit 2 ;;
    install-flags)
      [[ "$a" == package-dry-run-install && "$s" == read && "$resolved" == 0 ]] || exit 2
      jq -e '. == ["install", "--yes", "--dry-run", "--allow-local-file", "pacman"]' <<< "$aj" >/dev/null || exit 2 ;;
    remove)
      [[ "$a" == package-dry-run-remove && "$s" == read && "$resolved" == 0 ]] || exit 2
      jq -e '. == ["remove", "--dry-run", "bash"]' <<< "$aj" >/dev/null || exit 2 ;;
    remove-flags)
      [[ "$a" == package-dry-run-recursive && "$s" == read ]] || exit 2
      jq -e '. == ["remove", "--recursive", "--yes", "--dry-run", "bash"]' <<< "$aj" >/dev/null || exit 2 ;;
    *)
      [[ "$a" != package-dry-run-install && "$a" != package-dry-run-remove && "$a" != package-dry-run-recursive ]] || exit 2 ;;
  esac
  if [[ "$id" == ci-init ]]; then
    [[ "$a" == ci-github-workflow && "$s" == isolated-write && "$resolved" == 0 ]] || exit 2
    jq -e '. == ["ci", "init", "github"]' <<< "$aj" >/dev/null || exit 2
  elif [[ "$id" == ci-init-advanced ]]; then
    [[ "$a" == ci-github-workflow-advanced && "$s" == isolated-write && "$resolved" == 0 ]] || exit 2
    jq -e '. == ["ci", "init", "github", "--advanced"]' <<< "$aj" >/dev/null || exit 2
  elif [[ "$a" == ci-github-workflow || "$a" == ci-github-workflow-advanced ]]; then
    exit 2
  fi
  case "$id" in
    snapshot-create|migrate-export|migrate-import|env-capture|env-check|team-status|team-push|team-pull)
      [[ "$a" == "fingerprint:$id" ]] || exit 2 ;;
    *) [[ "$a" != fingerprint:* ]] || exit 2 ;;
  esac
  case "$id" in
    team-golden-create)
      [[ "$a" == golden-path-created && "$r" == team-init ]] || exit 2 ;;
    team-golden-list)
      [[ "$a" == golden-path-listed && "$r" == team-golden-create ]] || exit 2 ;;
    team-golden-delete)
      [[ "$a" == golden-path-deleted && "$r" == team-golden-list ]] || exit 2 ;;
    team-golden-create-flags)
      [[ "$a" == golden-path-flags && "$r" == team-golden-list && "$resolved" == 0 ]] || exit 2
      jq -e '. == ["team","golden-path","create","flagged","--node","20","--python","3.12","--packages","ripgrep"]' <<< "$aj" >/dev/null || exit 2 ;;
    *) [[ "$a" != golden-path-created && "$a" != golden-path-listed && "$a" != golden-path-deleted && "$a" != golden-path-flags ]] || exit 2 ;;
  esac
  case "$id" in
    config-set)
      [[ "$a" == config-set-persisted ]] && jq -e '. == ["config","set","telemetry.enabled","true"]' <<< "$aj" >/dev/null || exit 2 ;;
    config-get)
      [[ "$a" == config-get-persisted && "$r" == config-set ]] && jq -e '. == ["config","get","telemetry.enabled"]' <<< "$aj" >/dev/null || exit 2 ;;
    config-list)
      [[ "$a" == config-list-persisted && "$r" == config-set ]] && jq -e '. == ["config","list"]' <<< "$aj" >/dev/null || exit 2 ;;
    config-validate)
      [[ "$a" == config-validate-persisted && "$r" == config-set ]] && jq -e '. == ["config","validate"]' <<< "$aj" >/dev/null || exit 2 ;;
    config-path)
      [[ "$a" == config-path-isolated ]] && jq -e '. == ["config","path"]' <<< "$aj" >/dev/null || exit 2 ;;
    config-reset)
      [[ "$a" == config-reset-defaults && "$r" == config-set ]] && jq -e '. == ["config","reset","--yes"]' <<< "$aj" >/dev/null || exit 2 ;;
    *) [[ "$a" != config-* ]] || exit 2 ;;
  esac
  case "$id" in
    runtime-node-uninstall|runtime-python-uninstall|runtime-go-uninstall)
      runtime=${id#runtime-}; runtime=${runtime%-uninstall}
      [[ "$a" == runtime-version-removed ]] && jq -e --arg runtime "$runtime" \
        '. == ["use", $runtime, (if $runtime == "node" then "24.21.0" elif $runtime == "python" then "3.12.14" else "1.27.1" end), "--uninstall"]' <<< "$aj" >/dev/null || exit 2 ;;
    *) [[ "$a" != runtime-version-removed ]] || exit 2 ;;
  esac
  case "$id" in
    runtime-node-list-installed|runtime-python-list-installed|runtime-go-list-installed|runtime-node-switch-installed|runtime-python-switch-installed|runtime-go-switch-installed)
      runtime=${id#runtime-}; runtime=${runtime%%-*}
      if [[ "$id" == *-list-installed ]]; then
        [[ "$a" == runtime-list-state ]] && jq -e --arg runtime "$runtime" '. == ["list",$runtime,"--json"]' <<< "$aj" >/dev/null || exit 2
      else
        [[ "$a" == runtime-switch-state ]] && jq -e --arg runtime "$runtime" \
          '. == ["use",$runtime,(if $runtime == "node" then "v24.21.0" elif $runtime == "python" then "v3.12.14" else "v1.27.1" end)]' <<< "$aj" >/dev/null || exit 2
      fi ;;
    *) [[ "$a" != runtime-list-state && "$a" != runtime-switch-state ]] || exit 2 ;;
  esac
  case "$id" in
    privacy-export)
      [[ "$a" == artifact:privacy.json ]] && jq -e '. == ["privacy","export","--output","${ROOT}/privacy.json"]' <<< "$aj" >/dev/null || exit 2 ;;
    privacy-opt-out)
      [[ "$a" == privacy-opted-out ]] && jq -e '. == ["privacy","opt-out"]' <<< "$aj" >/dev/null || exit 2 ;;
    privacy-status)
      [[ "$a" == privacy-status-disabled && "$r" == privacy-opt-out ]] && jq -e '. == ["privacy","status"]' <<< "$aj" >/dev/null || exit 2 ;;
    privacy-opt-in)
      [[ "$a" == privacy-opted-in && "$r" == privacy-opt-out ]] && jq -e '. == ["privacy","opt-in"]' <<< "$aj" >/dev/null || exit 2 ;;
    privacy-status-enabled)
      [[ "$a" == privacy-status-enabled && "$r" == privacy-opt-in ]] && jq -e '. == ["privacy","status"]' <<< "$aj" >/dev/null || exit 2 ;;
    *) [[ "$a" != artifact:privacy.json && "$a" != privacy-opted-out && "$a" != privacy-status-disabled && "$a" != privacy-opted-in && "$a" != privacy-status-enabled ]] || exit 2 ;;
  esac
  if [[ "$id" == doctor ]]; then
    [[ "$a" == doctor-native-backend ]] || exit 2
    jq -e '. == ["doctor"]' <<< "$aj" >/dev/null || exit 2
  elif [[ "$a" == doctor-native-backend ]]; then
    exit 2
  fi
  if [[ "$id" == doctor-eol ]]; then
    [[ "$a" == doctor-eol-state && "$s" == controlled-error && "$resolved" == 1 && "$t" == container ]] || exit 2
    jq -e '. == ["doctor", "--eol"]' <<< "$aj" >/dev/null || exit 2
  elif [[ "$a" == doctor-eol-state ]]; then
    exit 2
  fi
  if [[ "$id" == audit-eol ]]; then
    [[ "$a" == audit-eol-state && "$s" == read && "$resolved" == 0 && "$t" == hermetic ]] || exit 2
    jq -e '. == ["audit", "eol"]' <<< "$aj" >/dev/null || exit 2
  elif [[ "$a" == audit-eol-state ]]; then
    exit 2
  fi
  if [[ "$id" == doctor-network ]]; then
    [[ "$a" == doctor-network-state && "$s" == controlled-error && "$resolved" == 1 && "$t" == container ]] || exit 2
    jq -e '. == ["doctor", "--network"]' <<< "$aj" >/dev/null || exit 2
  elif [[ "$a" == doctor-network-state ]]; then
    exit 2
  fi
  if [[ "$id" == audit-secrets ]]; then
    [[ "$a" == audit-secret-scoped && "$s" == read && "$resolved" == 0 ]] || exit 2
    jq -e '. == ["audit", "secrets", "--path", "project"]' <<< "$aj" >/dev/null || exit 2
  elif [[ "$id" == audit-secrets-critical ]]; then
    [[ "$a" == audit-secret-critical && "$s" == controlled-error && "$resolved" == 1 ]] || exit 2
    jq -e '. == ["audit", "secrets", "--path", "project/critical"]' <<< "$aj" >/dev/null || exit 2
  elif [[ "$a" == audit-secret-scoped || "$a" == audit-secret-critical ]]; then
    exit 2
  fi
  if [[ "$id" == info ]]; then
    [[ "$a" == info-native-package ]] || exit 2
    jq -e '. == ["info", "pacman"]' <<< "$aj" >/dev/null || exit 2
  elif [[ "$a" == info-native-package ]]; then
    exit 2
  fi
  if [[ "$id" == status ]]; then
    [[ "$a" == status-native-fast ]] || exit 2
    jq -e '. == ["status", "--fast"]' <<< "$aj" >/dev/null || exit 2
  elif [[ "$id" == status-verbose ]]; then
    [[ "$a" == status-native-full ]] || exit 2
    jq -e '. == ["--verbose", "status"]' <<< "$aj" >/dev/null || exit 2
  elif [[ "$a" == status-native-fast || "$a" == status-native-full ]]; then
    exit 2
  fi
  if [[ "$id" == outdated ]]; then
    [[ "$a" == outdated-native-count ]] || exit 2
    jq -e '. == ["outdated"]' <<< "$aj" >/dev/null || exit 2
  elif [[ "$id" == outdated-json ]]; then
    [[ "$a" == outdated-json-native-count ]] || exit 2
    jq -e '. == ["--json", "outdated"]' <<< "$aj" >/dev/null || exit 2
  elif [[ "$a" == outdated-native-count || "$a" == outdated-json-native-count ]]; then
    exit 2
  fi
  if [[ "$a" == search-official-tree-output ]]; then [[ "$id" == release-package-search-tree ]] || exit 2; fi
  if [[ "$a" == native-tree-installed ]]; then [[ "$id" == release-package-install-tree ]] || exit 2; fi
  if [[ "$a" == native-tree-absent ]]; then [[ "$id" == release-package-remove-tree ]] || exit 2; fi
  if [[ "$a" == native-apt-tree-rollback ]]; then
    [[ "$id" == release-package-rollback-tree && "$r" == release-package-remove-tree && "$s" == package-mutation && "$resolved" == 0 && "$t" == container && "$tg" == arch:not-applicable,debian:pass,ubuntu:pass,fedora:not-applicable ]] || exit 2
    jq -e '. == ["rollback", "--yes"]' <<< "$aj" >/dev/null || exit 2
  fi
  if [[ "$a" == native-apt-orphan-removed ]]; then [[ "$id" == clean-orphans-native ]] || exit 2; fi
  if [[ "$id" == container-run-detached-argv ]]; then
    [[ "$a" == container-run-argv && "$s" == isolated-write && "$resolved" == 0 && "$t" == hermetic && "$tg" == hermetic:pass ]] || exit 2
    jq -e '. == ["container","run","--name","smoke","--detach","--env","SMOKE=1","--volume","${ROOT}:/tmp/omg-smoke","--workdir","/tmp/omg-smoke","debian:bookworm","--","sh","-c","printf smoke"]' <<< "$aj" >/dev/null || exit 2
  elif [[ "$id" == container-shell-argv ]]; then
    [[ "$a" == container-shell-argv && "$s" == isolated-write && "$resolved" == 0 && "$t" == hermetic && "$tg" == hermetic:pass ]] || exit 2
    jq -e '. == ["container","shell","--image","debian:bookworm","--workdir","/tmp","--env","SMOKE=1","--volume","${ROOT}:/tmp/omg-smoke"]' <<< "$aj" >/dev/null || exit 2
  elif [[ "$id" == container-build-argv ]]; then
    [[ "$a" == container-build-argv && "$s" == isolated-write && "$resolved" == 0 && "$t" == hermetic && "$tg" == hermetic:pass ]] || exit 2
    jq -e '. == ["container","build","--dockerfile","Dockerfile","--tag","smoke:latest","--no-cache","--build-arg","SMOKE=1","--target","dev"]' <<< "$aj" >/dev/null || exit 2
  elif [[ "$a" == container-run-argv || "$a" == container-shell-argv || "$a" == container-build-argv ]]; then
    exit 2
  fi
  case "$cleanup" in tempdir-drop|none|container-prune|host-state-restore|vm-revert|daemon-stop) ;; *) exit 2 ;; esac
  row_args["$id"]="$aj"; row_requires["$id"]="$r"
  row_tier["$id"]="$t"; row_safety["$id"]="$s"; row_ux["$id"]="$u"
  row_exit["$id"]="$resolved"; row_targets["$id"]="$tg"; row_assertions["$id"]="$a"
  row_cleanup["$id"]="$cleanup"
  if [[ "$id" == runtime-python-install ]]; then
    jq -e 'length == 3 and .[0] == "use" and .[1] == "python" and (.[2] | test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))' <<< "$aj" >/dev/null || exit 2
  fi
  if [[ "$id" == runtime-node-install ]]; then
    jq -e 'length == 3 and .[0] == "use" and .[1] == "node" and (.[2] | test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))' <<< "$aj" >/dev/null || exit 2
  fi
  if [[ "$id" == runtime-go-install ]]; then
    jq -e 'length == 3 and .[0] == "use" and .[1] == "go" and (.[2] | test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))' <<< "$aj" >/dev/null || exit 2
  fi
  if [[ "$id" == self-update-version ]]; then
    jq -e 'length == 3 and .[0] == "self-update" and .[1] == "--version" and (.[2] | test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))' <<< "$aj" >/dev/null || exit 2
  fi
  if [[ "$id" == env-share-missing-lock ]]; then
    jq -e 'length == 2 and .[0] == "env" and .[1] == "share"' <<< "$aj" >/dev/null || exit 2
  fi
done < <(tail -n +2 "$tsv")

# Replay only prerequisites permitted by the same target and safety gates.
# A gated prerequisite blocks the dependent row instead of running it without
# the required state.
prereq_runnable() { # id -> 0 when replayable
  local id=$1 t
  [[ -n "${row_args[$id]:-}" ]] || return 1
  [[ "${row_ux[$id]}" != declared ]] || return 1
  [[ "${row_targets[$id]}" == hermetic:pass || ",${row_targets[$id]}," == *",$distro:pass,"* || ",${row_targets[$id]}," == *",$distro:known-defect,"* ]] || return 1
  local hit=false
  IFS=',' read -ra tier_list <<< "${row_tier[$id]}"
  for t in "${tier_list[@]}"; do
    if [[ "$want" == *",$t,"* ]]; then hit=true; break; fi
  done
  [[ "$hit" == true ]] || return 1
  if [[ ",${row_tier[$id]}," == *",credentialed,"* && "$allow_credentialed" == false ]]; then return 1; fi
  case "${row_safety[$id]}" in
    interactive) return 1 ;;
    package-mutation|service-mutation)
      [[ "$allow_mutations" == true ]] || return 1 ;;
  esac
  return 0
}

# Process substitution (not a pipeline): pass/fail counters below must
# survive the loop; a `tail | while` pipeline would trap them in a subshell.
while IFS=$'\t' read -r case args_json safety _expected_exit expected_ux requires tier targets assertions cleanup; do
  # Case ids flow into a remote shell command below: reject anything
  # outside the identifier shape instead of executing it.
  if [[ ! "$case" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ ]]; then
    printf 'case=%s invalid identifier\n' "$case"
    # Sanitized id: one bad TSV row must fail loudly without poisoning
    # the whole results file for the downstream schema gate.
    safe="invalid-$(printf '%s' "$case" | tr -c 'a-z0-9-' '-' | cut -c1-80)"
    record "qemu-$distro-$safe" FAIL -1 0; fail=$((fail+1)); continue
  fi
  # Tier filter (tiers are comma-separated in the TSV too).
  hit=false
  IFS=',' read -ra tier_list <<< "$tier"
  for t in "${tier_list[@]}"; do
    if [[ "$want" == *",$t,"* ]]; then hit=true; break; fi
  done
  if [[ "$hit" == false ]]; then continue; fi
  network_scope=unconfined
  if [[ "$isolate_hermetic" == true ]]; then
    network_scope=$(jq -er --arg id "$case" '.[$id]' <<< "$scopes")
  fi
  # Declaration-only rows are parse-level, covered by cli_comprehensive.
  if [[ "$expected_ux" == declared ]]; then
    record "qemu-$distro-$case" SKIPPED -1 0; skipped=$((skipped+1)); continue
  fi
  # Per-distro target status.
  status=""
  if [[ "$targets" == hermetic:pass ]]; then status=pass
  else
    IFS=',' read -ra target_list <<< "$targets"
    for t in "${target_list[@]}"; do
      if [[ "$t" == "$distro:"* ]]; then status="${t#*:}"; break; fi
    done
  fi
  if [[ -z "$status" || "$status" == pending || "$status" == not-applicable ]]; then
    record "qemu-$distro-$case" SKIPPED -1 0; skipped=$((skipped+1)); continue
  fi
  case "$status" in pass|known-defect) ;; *) record "qemu-$distro-$case" HARNESS_ERROR -1 0; fail=$((fail+1)); continue ;; esac
  # Credentialed rows need a real token in the guest: never run them
  # without an explicit opt-in (tiers match by substring, so "network"
  # would otherwise select "network,credentialed" rows).
  if [[ ",$tier," == *",credentialed,"* && "$allow_credentialed" == false ]]; then
    record "qemu-$distro-$case" SKIPPED -1 0; skipped=$((skipped+1)); continue
  fi
  # Safety gate.
  case "$safety" in
    interactive) record "qemu-$distro-$case" SKIPPED -1 0; skipped=$((skipped+1)); continue ;;
    package-mutation|service-mutation)
      if [[ "$allow_mutations" == false ]]; then
        record "qemu-$distro-$case" SKIPPED -1 0; skipped=$((skipped+1)); continue
      fi ;;
  esac
  chain=()
  next="$requires"
  blocked=false
  while [[ "$next" != - ]]; do
    if ! prereq_runnable "$next"; then blocked=true; break; fi
    if [[ "$network_scope" == offline && $(jq -r --arg id "$next" '.[$id]' <<< "$scopes") != offline ]]; then
      blocked=true; break
    fi
    chain=("$next" "${chain[@]}")
    next="${row_requires[$next]}"
  done
  if [[ "$blocked" == true ]]; then
    printf 'dependency %s is gated\n' "$next" > "$out/rows/$case.log"
    record "qemu-$distro-$case" BLOCKED -1 0; fail=$((fail+1)); continue
  fi

  # Quote each literal segment, substituting only the documented ROOT token.
  # No eval or shell expansion of inventory argument text is permitted.
  quote_args() {
    jq -r '[.[] | if . == "" then @sh else split("${ROOT}") | map(@sh) | join("\"$rowdir\"") end] | join(" ")' <<< "$1"
  }
  quoted_binary=$(jq -rn --arg b "$binary" '$b | @sh')
  quoted_binary_dir=$(jq -rn --arg b "${binary%/*}" '$b | @sh')
  remote="set -eu; rowdir=\$(mktemp -d \"\$HOME/inventory-$case.XXXXXX\"); cd \"\$rowdir\""
  if [[ "$man_page_mode" == exact ]]; then remote+="; export OMG_QEMU_EXACT_MAN_PAGES=1"; fi
  if [[ "$assertions" == container-run-argv || "$assertions" == container-shell-argv || "$assertions" == container-build-argv ]]; then
    remote+="; mkdir -p \"\$rowdir/engine\"; printf '%s' $container_engine > \"\$rowdir/engine/podman\"; chmod 700 \"\$rowdir/engine/podman\"; ln -s /bin/false \"\$rowdir/engine/docker\""
    remote+="; export OMG_QEMU_ENGINE_CAPTURE=\"\$rowdir/engine\" PATH=\"\$rowdir/engine:\$PATH\"; [[ \$(command -v podman) == \"\$rowdir/engine/podman\" && \$(command -v docker) == \"\$rowdir/engine/docker\" ]] || { printf '\nOMG_QEMU_RECEIPT:dependency:2:1\n'; exit 0; }"
    remote+="; $(declare -f check_container_engine_argv)"
    if [[ "$assertions" == container-build-argv ]]; then
      remote+="; printf 'FROM scratch\\n' > \"\$rowdir/Dockerfile\""
    fi
  fi
  if [[ "$assertions" == fingerprint:* || "$case" == team-init || "$case" == snapshot-* ]]; then
    remote+="; export OMG_CONFIG_DIR=\"\$rowdir/fingerprint-config\" OMG_DATA_DIR=\"\$rowdir/fingerprint-data\" OMG_CACHE_DIR=\"\$rowdir/fingerprint-cache\" OMG_DISABLE_DAEMON=1 OMG_TEST_MODE=0"
  fi
  if [[ "$case" == team-golden-* ]]; then
    remote+="; export OMG_CONFIG_DIR=\"\$rowdir/golden-config\" OMG_DISABLE_DAEMON=1 OMG_TEST_MODE=0"
  fi
  if [[ "$assertions" == doctor-eol-state || "$assertions" == audit-eol-state ]]; then
    remote+="; [[ \$(id -u) != 0 ]] || { printf 'assertion failed: EOL fixture requires an unprivileged guest user\n' >&2; exit 2; }; export OMG_CONFIG_DIR=\"\$rowdir/eol-config\" OMG_DATA_DIR=\"\$rowdir/runtime-data\" OMG_CACHE_DIR=\"\$rowdir/eol-cache\" OMG_DISABLE_DAEMON=1 OMG_TEST_MODE=0"
    remote+="; mkdir -p \"\$OMG_DATA_DIR/versions/node/16.20.2\" \"\$OMG_DATA_DIR/versions/python/3.12.14\"; ln -s 16.20.2 \"\$OMG_DATA_DIR/versions/node/current\"; ln -s 3.12.14 \"\$OMG_DATA_DIR/versions/python/current\""
    if [[ "$assertions" == doctor-eol-state ]]; then remote+="; $(declare -f check_doctor_issue_delta)"; fi
  fi
  if [[ "$assertions" == doctor-network-state ]]; then
    remote+="; [[ \$(id -u) != 0 ]] || { printf 'assertion failed: doctor network fixture requires an unprivileged guest user\n' >&2; exit 2; }; export OMG_CONFIG_DIR=\"\$rowdir/network-config\" OMG_DATA_DIR=\"\$rowdir/network-data\" OMG_CACHE_DIR=\"\$rowdir/network-cache\" OMG_DISABLE_DAEMON=1 OMG_TEST_MODE=0"
    remote+="; $(declare -f check_doctor_issue_delta); $(declare -f check_doctor_network_output)"
  fi
  if [[ "$case" == config-* ]]; then
    remote+="; export OMG_CONFIG_DIR=\"\$rowdir/config\""
  fi
  if [[ "$case" == privacy-export || "$case" == privacy-opt-out || "$case" == privacy-status || "$case" == privacy-opt-in || "$case" == privacy-status-enabled ]]; then
    remote+="; export OMG_CONFIG_DIR=\"\$rowdir/privacy-config\" OMG_DATA_DIR=\"\$rowdir/privacy-data\""
    if [[ "$case" == privacy-export ]]; then
      remote+="; [[ \$(id -u) != 0 ]] || { printf 'assertion failed: privacy export fixture requires an unprivileged guest user\\n' >&2; exit 2; }; export OMG_DISABLE_DAEMON=1; mkdir -p \"\$OMG_DATA_DIR\" \"\$OMG_CONFIG_DIR\""
      remote+="; printf '%s\\n' '{\"fixture\":\"usage\",\"total_commands\":7}' > \"\$OMG_DATA_DIR/usage.json\""
      remote+="; printf '%s\\n' '{\"key\":\"qemu-secret-license-key\",\"tier\":\"pro\",\"features\":[\"sbom\"],\"customer\":\"fixture@example.invalid\",\"expires_at\":null,\"validated_at\":1700000000,\"token\":\"qemu-secret-license-token\",\"machine_id\":\"fixture-machine\"}' > \"\$OMG_DATA_DIR/license.json\""
      remote+="; printf 'telemetry_enabled = false\\n' > \"\$OMG_CONFIG_DIR/config.toml\"; printf old > privacy.json; chmod 644 privacy.json"
    else
      remote+="; mkdir -p \"\$OMG_DATA_DIR\"; printf 'queued' > \"\$OMG_DATA_DIR/telemetry_queue.json\""
    fi
  fi
  remote+="; export NO_COLOR=1 LC_ALL=C GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 PATH=$quoted_binary_dir:\"\$PATH\"; git init -q; printf 'smoke:\n\t@printf omg-qemu-smoke-task > smoke-task.marker\n\t@echo smoke-task-ok\nparallel-one:\n\t@touch parallel-one.started\n\t@timeout 15 sh -c \"until test -e parallel-two.started; do sleep 0.05; done\"\n\t@printf parallel-one > parallel-one.done\n\t@echo parallel-one-ok\nparallel-two:\n\t@touch parallel-two.started\n\t@timeout 15 sh -c \"until test -e parallel-one.started; do sleep 0.05; done\"\n\t@printf parallel-two > parallel-two.done\n\t@echo parallel-two-ok\noverlap:\n\t@sh workspace-overlap.sh . primary\n' > Makefile"
  if [[ "$case" == run-watch ]]; then
    remote+="; mkdir src; printf 'initial\\n' > src/watch-trigger.txt; printf 'smoke:\\n\\t@printf \\\"omg-qemu-watch-run\\\\n\\\" >> watch-runs.marker\\n\\t@echo smoke-task-ok\\n' > Makefile; export OMG_DISABLE_DAEMON=1"
  fi
  if [[ "$assertions" == container-init-scaffold ]]; then
    remote+="; for ignore in .dockerignore Dockerfile.omg.dockerignore .containerignore; do printf '!.env\\n!secrets.key\\n' > \"\$ignore\"; done"
  fi
  if [[ "$case" == run-all ]]; then
    remote+="; mkdir -p \"\$rowdir/run-all-bin\"; printf '#!/bin/sh\ncase \$1:\$2 in\n  --version:) echo 9.0.0 ;;\n  run:smoke) printf npm-smoke-task > npm-task.marker; echo npm-task-ok ;;\n  *) exit 96 ;;\nesac\n' > \"\$rowdir/run-all-bin/npm\"; printf '#!/bin/sh\necho v24.0.0\n' > \"\$rowdir/run-all-bin/node\"; chmod 755 \"\$rowdir/run-all-bin/npm\" \"\$rowdir/run-all-bin/node\"; export PATH=\"\$rowdir/run-all-bin:\$PATH\"; printf '%s\n' '{\"scripts\":{\"smoke\":\"echo npm-task-ok\"}}' > package.json"
  fi
  if [[ "$assertions" == audit-source-failure || "$assertions" == sbom-source-failure ]]; then
    # DNF5 can satisfy an offline advisory query from a previous row's cache.
    # A daemon launched by an earlier inventory row can also answer the audit
    # using its own warm cache and network access, bypassing this row's offline
    # namespace. Force the direct CLI path with a fresh cache for this oracle.
    remote+="; export OMG_CACHE_DIR=\"\$rowdir/audit-cache\" OMG_DISABLE_DAEMON=1"
  fi
  remote+="; printf '%s' $overlap_fixture > workspace-overlap.sh"
  if [[ "$assertions" == license-* ]]; then
    remote+="; printf '%s' $license_oracle > qemu-license-oracle.py"
    if [[ "$assertions" == license-audit-mit-json ]]; then
      if [[ "$distro" == arch ]]; then
        remote+="; [[ \$(id -u) != 0 ]] || { printf 'assertion failed: license policy fixture requires an unprivileged guest user\n' >&2; exit 2; }"
      fi
      remote+="; export OMG_CONFIG_DIR=\"\$rowdir/license-policy\"; mkdir -p \"\$OMG_CONFIG_DIR\"; printf '%s\n' 'allowed_licenses = [\"LicenseRef-QemuNoInstalledLicense\"]' > \"\$OMG_CONFIG_DIR/policy.toml\""
    fi
  fi
  remote+="; mkdir -p project; printf '# Nested audit fixture\n' > project/README.md"
  if [[ "$assertions" == audit-secret-scoped ]]; then
    remote+="; printf 'password=%s%s\n' 'qemuSecret' '7429' > project/config.txt; printf 'password=%s%s\n' 'outsideSecret' '9031' > outside.txt"
  elif [[ "$assertions" == audit-secret-critical ]]; then
    remote+="; mkdir -p project/critical; printf '%s%s\n' '-----BEGIN ' 'PRIVATE KEY-----' > project/critical/key.pem"
  fi
  remote+="; printf 'smoke:\n\t@echo nested-smoke-task-ok\noverlap:\n\t@sh ../workspace-overlap.sh .. nested\n' > project/Makefile"
  remote+="; command -v jq >/dev/null; command -v grep >/dev/null; $(declare -f check_hook_lifecycle); $(declare -f check_config_value); $(declare -f check_config_oracle); $(declare -f check_golden_path_state); $(declare -f check_privacy_oracle); $(declare -f check_file_output_oracle); $(declare -f check_workspace_failure); $(declare -f check_product_output)"
  if [[ "$assertions" == package-dry-run-* ]]; then
    remote+="; $(declare -f native_package_snapshot); $(declare -f native_installed_version); $(declare -f check_native_remove_preview)"
  fi
  if [[ ( "$distro" == debian || "$distro" == ubuntu ) && ( "$case" == update-fast || "$case" == update-turbo ) ]]; then
    remote+="; $(declare -f check_apt_tree_absent); $(declare -f prepare_apt_update_fixture); $(declare -f check_apt_update_fixture); $(declare -f native_package_snapshot); $(declare -f check_apt_update_delta); $(declare -f cleanup_apt_update_fixture)"
  fi
  if [[ "$assertions" == audit-log-filtered-export ]]; then
    audit_oracle=$(jq -rn --rawfile fixture "$(dirname "$0")/qemu-audit-log-oracle.py" '$fixture | @sh')
    remote+="; printf '%s' $audit_oracle > qemu-audit-log-oracle.py; python3 qemu-audit-log-oracle.py prepare \"\$rowdir\"; export OMG_DATA_DIR=\"\$rowdir/audit-log-data\""
  fi
  # The supervisor exits zero after recording a completed CLI's status.
  # Thus a CLI exit 125 cannot be mistaken for timeout's own exit 125.
  supervisor=$(jq -rn --arg s 'rc=0; "$@" 3>&- || rc=$?; printf "%s\n" "$rc" >&3' '$s | @sh')
  remote+="; status_file=\$(mktemp \"\$HOME/inventory-status.XXXXXX\"); trap 'rm -f \"\$status_file\"' EXIT"
  remote+="; run_omg() { local deadline=\$1; shift; execution_phase=executor; rc=0; timeout --kill-after=5s \"\$deadline\" bash -c $supervisor _ \"\$@\" 3>\"\$status_file\" || rc=\$?; if [ \"\$rc\" = 0 ]; then if IFS= read -r rc < \"\$status_file\"; then execution_phase=product; else rc=125; fi; fi; }"
  if [[ "$case" == release-package-install-tree || "$case" == release-package-remove-tree || "$case" == release-package-rollback-tree || "$case" == clean-orphans-native ]]; then
    remote+="; $(declare -f check_native_tree_state)"
  fi
  if [[ "$case" == clean-orphans-native ]]; then
    remote+="; $(declare -f prepare_native_apt_orphan); $(declare -f check_native_apt_orphan_removed)"
  fi
  if [[ "$case" == release-package-install-tree || "$case" == release-package-remove-tree || "$case" == clean-orphans-native ]]; then
    remote+="; if ! check_native_tree_state '$distro' absent; then printf '\nOMG_QEMU_RECEIPT:dependency:2:1\n'; exit 0; fi"
  fi
  if [[ "$case" == release-package-install-tree || "$case" == release-package-remove-tree ]]; then
    remote+="; $(declare -f native_package_snapshot); $(declare -f check_native_tree_only_delta); $(declare -f cleanup_native_tree_fixture)"
    remote+="; tree_before=\$(native_package_snapshot '$distro') || { printf 'assertion failed: native package baseline is unavailable\n' >&2; printf '\nOMG_QEMU_RECEIPT:dependency:2:1\n'; exit 0; }"
    remote+="; tree_owned=1; tree_exit_cleanup() { local original=\$?; if [[ \"\$tree_owned\" == 1 ]] && ! cleanup_native_tree_fixture '$distro'; then printf 'assertion failed: native tree cleanup failed on exit\n' >&2; exit 71; fi; rm -f \"\$status_file\"; exit \"\$original\"; }; trap tree_exit_cleanup EXIT"
  fi
  if [[ "$case" == release-package-rollback-tree ]]; then
    remote+="; $(declare -f check_apt_tree_absent); $(declare -f native_package_snapshot); $(declare -f apt_tree_removal_id); $(declare -f check_apt_tree_restoration); $(declare -f check_apt_tree_only_delta); export OMG_DATA_DIR=\"\$rowdir/rollback-data\" OMG_DISABLE_DAEMON=1"
    remote+="; if ! check_apt_tree_absent '$distro' || [[ -e \"\$OMG_DATA_DIR/history.json\" ]]; then printf '\nOMG_QEMU_RECEIPT:dependency:2:1\n'; exit 0; fi"
    remote+="; rollback_before=\$(native_package_snapshot '$distro') || { printf 'assertion failed: native APT baseline is unavailable\n' >&2; printf '\nOMG_QEMU_RECEIPT:dependency:2:1\n'; exit 0; }"
    remote+="; rollback_owned=1; rollback_cleanup() { if [[ \"\$rollback_owned\" == 1 ]]; then sudo -n dpkg --purge tree >/dev/null 2>&1 || return 1; check_apt_tree_absent '$distro' || return 1; fi; rm -f \"\$status_file\"; }"
    remote+="; rollback_exit_cleanup() { local original=\$?; if ! rollback_cleanup; then printf 'assertion failed: native APT rollback cleanup failed on exit\n' >&2; exit 71; fi; exit \"\$original\"; }; trap rollback_exit_cleanup EXIT"
  fi
  for p in "${chain[@]}"; do
    pargs=$(quote_args "${row_args[$p]}")
    remote+="; run_omg '$row_timeout' $quoted_binary $pargs > '$p.prereq.log' 2> '$p.prereq.stderr.log'"
    remote+="; printf 'prereq $p exit=%s\n' \"\$rc\" >&2; cat '$p.prereq.log' '$p.prereq.stderr.log' >&2"
    remote+="; if [ \"\$rc\" != '${row_exit[$p]}' ] || [ \"\$execution_phase\" != product ]; then printf '\nOMG_QEMU_RECEIPT:dependency:%s:0\n' \"\$rc\"; exit 0; fi"
    remote+="; if ! check_product_output '${row_safety[$p]}' '${row_assertions[$p]}' \"\$rc\" '$p.prereq.log' '$p.prereq.stderr.log' '$distro'; then printf '\nOMG_QEMU_RECEIPT:dependency:%s:1\n' \"\$rc\"; exit 0; fi"
    if [[ "$case" == release-package-rollback-tree && "$p" == release-package-install-tree ]]; then
      remote+="; rollback_version=\$(dpkg-query -W '-f=\${Version}' tree) || { printf '\nOMG_QEMU_RECEIPT:dependency:2:1\n'; exit 0; }; [[ -n \"\$rollback_version\" ]] || { printf '\nOMG_QEMU_RECEIPT:dependency:2:1\n'; exit 0; }"
    fi
  done
  if [[ "$assertions" == workspace-missing-task || "$assertions" == workspace-missing-lock ]]; then
    remote+="; [[ ! -e omg.lock && ! -L omg.lock ]]; workspace_failure_before=\"\$(sha256sum omg-workspace.toml Makefile)\""
  fi
  if [[ "$case" == release-package-rollback-tree ]]; then
    remote+="; rollback_id=\$(apt_tree_removal_id \"\$OMG_DATA_DIR/history.json\" \"\$rollback_version\") || { printf 'assertion failed: no unique native tree removal transaction with the installed version\n' >&2; printf '\nOMG_QEMU_RECEIPT:product:0:1\n'; exit 0; }"
    remote+="; [[ \"\$rollback_id\" =~ ^[0-9a-f-]{36}\$ ]] || { printf 'assertion failed: native tree removal transaction has an invalid ID\n' >&2; printf '\nOMG_QEMU_RECEIPT:product:0:1\n'; exit 0; }"
  fi
  if [[ "$assertions" == package-dry-run-* ]]; then
    remote+="; native_before=\$(native_package_snapshot '$distro') || { printf 'assertion failed: native package baseline is unavailable\n' >&2; printf '\nOMG_QEMU_RECEIPT:dependency:2:1\n'; exit 0; }"
    if [[ "$assertions" != package-dry-run-install ]]; then
      remote+="; installed_version=\$(native_installed_version '$distro' bash) || { printf 'assertion failed: native bash package query failed\n' >&2; printf '\nOMG_QEMU_RECEIPT:dependency:2:1\n'; exit 0; }"
      remote+="; [[ -n \"\$installed_version\" ]] || { printf 'assertion failed: bash is not installed in this guest\n' >&2; printf '\nOMG_QEMU_RECEIPT:dependency:2:1\n'; exit 0; }"
    fi
  fi
  if [[ "$case" == team-status || "$case" == team-pull ]]; then
    remote+="; python3 \"\$HOME/qemu-fingerprint-oracle.py\" prepare-team-refresh '$distro' \"\$rowdir\" /dev/null"
  fi
  if [[ "$case" == clean-orphans-native ]]; then
    remote+="; if ! prepare_native_apt_orphan '$distro'; then printf '\nOMG_QEMU_RECEIPT:dependency:2:1\n'; exit 0; fi; export OMG_DISABLE_DAEMON=1"
  fi
  if [[ "$case" == hooks-install-force ]]; then
    # An identical reinstall cannot prove --force is honored. Replace each
    # generated prerequisite hook with user content and non-executable mode;
    # the normal installed-hook oracle must observe real replacement.
    remote+="; for hook in pre-commit post-checkout post-merge; do printf '#!/bin/sh\\n# user-owned hook fixture\\nexit 23\\n' > \".git/hooks/\$hook\"; chmod 640 \".git/hooks/\$hook\"; done"
  fi
  if [[ "$assertions" == doctor-eol-state || "$assertions" == doctor-network-state ]]; then
    remote+="; run_omg '$row_timeout' $quoted_binary doctor > doctor.baseline.stdout.log 2> doctor.baseline.stderr.log; baseline_rc=\$rc; baseline_phase=\$execution_phase"
    remote+="; cat doctor.baseline.stdout.log doctor.baseline.stderr.log >&2"
  fi
  arg_string=$(quote_args "$args_json")
  command_timeout=$row_timeout
  # Official runtime archives are downloaded inside a fresh guest. A 34 MB
  # Python archive reached the generic 120s limit on Fedora before the CLI
  # returned (run 36086453655); Go already needs the same bounded allowance.
  # Keep the result fatal if either download exceeds this larger deadline.
  if [[ "$case" == runtime-python-install || "$case" == runtime-go-install ]]; then
    command_timeout=$((row_timeout * 3))
  fi
  # dnf5 cacheonly=metadata reuses repository metadata and still downloads
  # packages (dnf5-caching(7); cached_update_args). Run 35694347149 downloaded
  # 256 MiB and was killed at dnf step 419/420 when the 120s deadline
  # returned 124. The completed guest spent 26s on step 420 and finished the
  # same 204-package transaction in 72s. Twice the generic budget covers that
  # measured tail. The 3x ceiling stays on runtime-go-install and update --fast.
  if [[ "$case" == update-turbo ]]; then
    command_timeout=$((row_timeout * 2))
  elif [[ "$case" == update-fast ]]; then
    command_timeout=$((row_timeout * 3))
  elif [[ "$case" == daemon-foreground ]]; then
    command_timeout=240
    remote+="; mkdir -p daemon-evidence"
  fi
  counter=$(counter_for_case "$case")
  if [[ -n "$counter" ]]; then
    remote+="; $(declare -f check_native_counter)"
  elif [[ "$assertions" == doctor-native-backend ]]; then
    remote+="; $(declare -f check_doctor_native_backend); $(declare -f check_doctor_issue_delta)"
  elif [[ "$assertions" == info-native-package ]]; then
    remote+="; $(declare -f check_info_native_package)"
  elif [[ "$assertions" == status-native-fast || "$assertions" == status-native-full ]]; then
    remote+="; $(declare -f check_native_counter); $(declare -f check_status_native_counts)"
  elif [[ "$assertions" == outdated-native-count || "$assertions" == outdated-json-native-count ]]; then
    remote+="; $(declare -f check_native_counter); $(declare -f check_outdated_native_count)"
  fi
  if [[ "$case" == runtime-python-install || "$case" == runtime-node-install || "$case" == runtime-go-install ]]; then
    runtime_version=$(jq -r '.[2]' <<< "$args_json")
    runtime_name=$(jq -r '.[1]' <<< "$args_json")
    remote+="; umask 0002; export OMG_DATA_DIR=\"\$rowdir/runtime-data\" OMG_CACHE_DIR=\"\$rowdir/runtime-cache\" OMG_CONFIG_DIR=\"\$rowdir/runtime-config\" OMG_TEST_MODE=0; $(declare -f "check_${runtime_name}_install"); $(declare -f check_runtime_usage)"
  fi
  if [[ "$assertions" == runtime-version-removed ]]; then
    runtime_name=${case#runtime-}; runtime_name=${runtime_name%-uninstall}
    runtime_version=$(jq -r '.[2]' <<< "$args_json")
    remote+="; [[ \$(id -u) != 0 ]] || { printf 'assertion failed: runtime uninstall fixture requires an unprivileged guest user\\n' >&2; exit 2; }; export OMG_DATA_DIR=\"\$rowdir/runtime-data\" OMG_CACHE_DIR=\"\$rowdir/runtime-cache\" OMG_CONFIG_DIR=\"\$rowdir/runtime-config\" OMG_TEST_MODE=0 OMG_DISABLE_DAEMON=1"
    remote+="; versions=\"\$OMG_DATA_DIR/versions/$runtime_name\"; mkdir -p \"\$versions/$runtime_version\" \"\$versions/9.9.9\" \"\$OMG_DATA_DIR/versions/other-guard/1.0.0\" \"\$rowdir/external-runtime\""
    remote+="; printf remove-me > \"\$versions/$runtime_version/sentinel\"; printf keep-sibling > \"\$versions/9.9.9/sentinel\"; printf keep-other > \"\$OMG_DATA_DIR/versions/other-guard/1.0.0/sentinel\"; printf keep-external > \"\$rowdir/external-runtime/sentinel\""
    remote+="; ln -s \"\$rowdir/external-runtime\" \"\$versions/$runtime_version/external-link\"; ln -s \"\$versions/9.9.9\" \"\$versions/current\"; $(declare -f check_runtime_uninstall)"
  fi
  if [[ "$assertions" == runtime-list-state || "$assertions" == runtime-switch-state ]]; then
    runtime_name=${case#runtime-}; runtime_name=${runtime_name%%-*}
    case "$runtime_name" in
      node) runtime_version=24.21.0; runtime_active=22.21.0; runtime_launcher=node ;;
      python) runtime_version=3.12.14; runtime_active=3.11.14; runtime_launcher=python3 ;;
      go) runtime_version=1.27.1; runtime_active=1.26.0; runtime_launcher=go ;;
    esac
    remote+="; [[ \$(id -u) != 0 ]] || { printf 'assertion failed: runtime state fixture requires an unprivileged guest user\\n' >&2; exit 2; }; export OMG_DATA_DIR=\"\$rowdir/runtime-data\" OMG_CACHE_DIR=\"\$rowdir/runtime-cache\" OMG_CONFIG_DIR=\"\$rowdir/runtime-config\" OMG_TEST_MODE=0 OMG_DISABLE_DAEMON=1"
    remote+="; versions=\"\$OMG_DATA_DIR/versions/$runtime_name\"; mkdir -p \"\$versions/$runtime_version/bin\" \"\$versions/$runtime_active\" \"\$versions/8.8.8\" \"\$rowdir/external-runtime\"; chmod 700 \"\$OMG_DATA_DIR\""
    remote+="; printf keep-selected > \"\$versions/$runtime_version/sentinel\"; printf keep-active > \"\$versions/$runtime_active/sentinel\"; printf keep-pending > \"\$versions/8.8.8/.omg-installing\"; printf keep-external > \"\$rowdir/external-runtime/sentinel\""
    remote+="; printf '#!/bin/sh\\nprintf runtime-fixture\\n' > \"\$versions/$runtime_version/bin/$runtime_launcher\"; chmod 755 \"\$versions/$runtime_version/bin/$runtime_launcher\"; ln -s \"\$rowdir/external-runtime\" \"\$versions/7.7.7\"; ln -s \"\$versions/$runtime_active\" \"\$versions/current\"; $(declare -f check_runtime_state); $(declare -f check_runtime_usage)"
  fi
  if [[ "$distro" == arch && "$safety" == package-mutation && ( "$case" == update-fast || "$case" == update-turbo ) ]]; then
    # A loopback repository exposes a versioned native ALPM upgrade while
    # keeping every other installed package outside the transaction.
    remote+="; run_omg '$command_timeout' sudo -n bash \"\$HOME/qemu-arch-update-fixture.sh\" '${case#update-}' $quoted_binary '$ssh_user' > command.stdout.log 2> command.stderr.log; assertion=0"
  elif [[ "$distro" == fedora && ( "$case" == update-fast || "$case" == update-turbo ) ]]; then
    # Keep the real OMG path, but bound native DNF to a local versioned RPM.
    # The root-owned helper restores system repo policy and checks the RPMDB
    # plus native DNF history before it can report success.
    remote+="; run_omg '$command_timeout' sudo -n bash \"\$HOME/qemu-fedora-update-fixture.sh\" '${case#update-}' $quoted_binary '$ssh_user' > command.stdout.log 2> command.stderr.log; assertion=0"
  elif [[ ( "$distro" == debian || "$distro" == ubuntu ) && ( "$case" == update-fast || "$case" == update-turbo ) ]]; then
    remote+="; export OMG_DISABLE_DAEMON=1; apt_fixture_installed=0; apt_fixture_pin_created=0"
    remote+="; apt_fixture_exit_cleanup() { if [[ \"\$apt_fixture_installed\" == 1 || \"\$apt_fixture_pin_created\" == 1 ]]; then cleanup_apt_update_fixture '$distro' >/dev/null 2>&1 || true; fi; rm -f \"\$status_file\"; }; trap apt_fixture_exit_cleanup EXIT"
    remote+="; if ! prepare_apt_update_fixture '$distro' \"\$rowdir\" || ! apt_before=\$(native_package_snapshot '$distro'); then if ! cleanup_apt_update_fixture '$distro'; then printf 'assertion failed: APT setup cleanup failed\\n' >&2; fi; printf '\nOMG_QEMU_RECEIPT:dependency:2:1\n'; exit 0; fi"
    remote+="; run_omg '$command_timeout' $quoted_binary $arg_string > command.stdout.log 2> command.stderr.log; assertion=0"
  elif [[ "$case" == release-package-rollback-tree ]]; then
    remote+="; run_omg '$command_timeout' $quoted_binary rollback \"\$rollback_id\" --yes > command.stdout.log 2> command.stderr.log; assertion=0"
  elif [[ "$case" == daemon-foreground ]]; then
    remote+="; run_omg '$command_timeout' bash \"\$HOME/qemu-daemon-check.sh\" $quoted_binary \"\$rowdir/daemon-evidence\" > command.stdout.log 2> command.stderr.log; assertion=0"
  elif [[ "$case" == run-watch ]]; then
    remote+="; run_omg '$command_timeout' python3 \"\$HOME/qemu-run-watch-check.py\" $quoted_binary \"\$rowdir\" > command.stdout.log 2> command.stderr.log; assertion=0"
  elif [[ "$distro" == fedora && "$case" == doctor ]]; then
    remote+="; if ! command -v strace >/dev/null || ! strace --seccomp-bpf -f -qq -e trace=execve -o doctor.preflight.log true; then printf '\nOMG_QEMU_RECEIPT:dependency:2:1\n'; exit 0; fi"
    remote+="; run_omg '$command_timeout' strace --seccomp-bpf -f -qq -e trace=execve -o doctor.exec.log $quoted_binary $arg_string > command.stdout.log 2> command.stderr.log; assertion=0"
  else
    remote+="; run_omg '$command_timeout' $quoted_binary $arg_string > command.stdout.log 2> command.stderr.log; assertion=0"
  fi
  remote+="; cat command.stdout.log; cat command.stderr.log >&2"
  remote+="; if [ \"\$execution_phase\" = executor ]; then printf 'assertion failed: command exceeded ${command_timeout}s QEMU row deadline (executor exit %s)\n' \"\$rc\" >&2; assertion=1; elif ! check_product_output '$safety' '$assertions' \"\$rc\" command.stdout.log command.stderr.log '$distro'; then assertion=1; fi"
  if [[ "$case" == release-package-install-tree || "$case" == release-package-remove-tree ]]; then
    remote+="; tree_after=\$(native_package_snapshot '$distro') || { printf 'assertion failed: native package after-state is unavailable\n' >&2; assertion=1; tree_after=missing; }"
    remote+="; tree_delta_ok=1; if ! check_native_tree_only_delta \"\$tree_before\" \"\$tree_after\"; then tree_delta_ok=0; assertion=1; fi"
    remote+="; if ! cleanup_native_tree_fixture '$distro'; then printf 'assertion failed: native tree fixture cleanup failed\n' >&2; execution_phase=dependency; rc=2; assertion=1; else tree_owned=0; fi"
    remote+="; tree_final=\$(native_package_snapshot '$distro') || { printf 'assertion failed: native package cleanup after-state is unavailable\n' >&2; execution_phase=dependency; rc=2; assertion=1; tree_final=missing; }"
    remote+="; if [[ \"\$tree_before\" != \"\$tree_final\" ]]; then printf 'assertion failed: native tree row did not restore its package/reason baseline\n' >&2; assertion=1; if [[ \"\$tree_delta_ok\" == 1 ]]; then execution_phase=dependency; rc=2; fi; fi"
  fi
  if [[ "$case" == release-package-rollback-tree ]]; then
    remote+="; restored=\$(dpkg-query -W '-f=\${Status}\t\${Version}' tree 2>/dev/null) || restored=missing"
    remote+="; if [[ \"\$restored\" != \"\$(printf 'install ok installed\t%s' \"\$rollback_version\")\" ]]; then printf 'assertion failed: rollback did not restore native tree version %s (found %s)\n' \"\$rollback_version\" \"\$restored\" >&2; assertion=1; fi"
    remote+="; if ! check_apt_tree_restoration \"\$OMG_DATA_DIR/history.json\" \"\$rollback_version\"; then printf 'assertion failed: rollback did not record the native tree restoration\n' >&2; assertion=1; fi"
    remote+="; rollback_after=\$(native_package_snapshot '$distro') || { printf 'assertion failed: native APT after-state is unavailable\n' >&2; assertion=1; rollback_after=missing; }"
    remote+="; if ! check_apt_tree_only_delta \"\$rollback_before\" \"\$rollback_after\"; then printf 'assertion failed: rollback changed installed packages other than tree\n' >&2; assertion=1; fi"
    remote+="; if ! rollback_cleanup; then printf 'assertion failed: native APT rollback fixture cleanup failed\n' >&2; execution_phase=dependency; rc=2; assertion=1; else rollback_owned=0; fi"
    remote+="; rollback_final=\$(native_package_snapshot '$distro') || { printf 'assertion failed: native APT cleanup after-state is unavailable\n' >&2; execution_phase=dependency; rc=2; assertion=1; rollback_final=missing; }"
    remote+="; if [[ \"\$rollback_before\" != \"\$rollback_final\" ]]; then printf 'assertion failed: rollback fixture changed the native installed-package baseline\n' >&2; assertion=1; fi"
  fi
  if [[ "$assertions" == container-run-argv || "$assertions" == container-shell-argv || "$assertions" == container-build-argv ]]; then
    remote+="; if [[ \"\$execution_phase\" == product && \"\$rc\" == 0 ]] && ! check_container_engine_argv \"\$rowdir\" '$assertions'; then assertion=1; fi"
  fi
  if [[ "$assertions" == package-dry-run-* ]]; then
    if [[ "$assertions" != package-dry-run-install && "$assertions" != package-dry-run-recursive || "$assertions" == package-dry-run-recursive && "$distro" == arch ]]; then
      remote+="; if [[ \"\$execution_phase\" == product && \"\$rc\" == 0 ]] && ! check_native_remove_preview command.stdout.log \"\$installed_version\"; then printf 'assertion failed: remove preview lacks the native installed bash version\n' >&2; assertion=1; fi"
    fi
    remote+="; native_after=\$(native_package_snapshot '$distro') || { assertion=1; printf 'assertion failed: native package after-state is unavailable\n' >&2; }"
    remote+="; if [[ \"\$execution_phase\" == product && \"\$native_before\" != \"\$native_after\" ]]; then printf 'assertion failed: dry run changed native installed-package state or reasons\n' >&2; assertion=1; fi"
  fi
  if [[ "$assertions" == doctor-eol-state ]]; then
    remote+="; if [[ \"\$baseline_phase\" != product ]] || ! check_doctor_issue_delta \"\$baseline_rc\" doctor.baseline.stdout.log doctor.baseline.stderr.log \"\$rc\" command.stderr.log 1; then printf 'assertion failed: doctor EOL did not add exactly one health issue over its baseline\n' >&2; assertion=1; fi"
  fi
  if [[ "$assertions" == doctor-network-state ]]; then
    remote+="; expected_network_delta=\$(check_doctor_network_output '$distro' command.stdout.log) || assertion=1"
    remote+="; if [[ \"\$baseline_phase\" != product || \"\$assertion\" != 0 ]] || ! check_doctor_issue_delta \"\$baseline_rc\" doctor.baseline.stdout.log doctor.baseline.stderr.log \"\$rc\" command.stderr.log \"\$expected_network_delta\"; then printf 'assertion failed: doctor network issue count did not match failed probes\n' >&2; assertion=1; fi"
  fi
  if [[ ( "$distro" == fedora || "$distro" == arch && "$safety" == package-mutation ) && ( "$case" == update-fast || "$case" == update-turbo ) ]]; then
    remote+="; if [[ \"\$rc\" == 120 ]] && grep -Fq 'OMG_QEMU_FIXTURE_SETUP_FAILED' command.stderr.log; then execution_phase=dependency; fi"
    remote+="; if [[ \"\$rc\" == 121 ]] && grep -Fq 'OMG_QEMU_FIXTURE_CLEANUP_FAILED' command.stderr.log; then execution_phase=dependency; fi"
    remote+="; if [[ \"\$rc\" == 0 ]] && { ! grep -Fxq 'OMG_QEMU_UPDATE_FIXTURE:before:${case#update-}:1' command.stdout.log || ! grep -Fxq 'OMG_QEMU_UPDATE_FIXTURE:after:${case#update-}:2:native-upgrade' command.stdout.log; }; then printf 'assertion failed: bounded native update lacks before/after evidence\\n' >&2; assertion=1; fi"
  fi
  if [[ ( "$distro" == debian || "$distro" == ubuntu ) && ( "$case" == update-fast || "$case" == update-turbo ) ]]; then
    remote+="; if [[ \"\$execution_phase\" == product && \"\$rc\" == 0 ]]; then if ! check_apt_update_fixture; then assertion=1; fi; if ! apt_after=\$(native_package_snapshot '$distro'); then printf 'assertion failed: APT package/reason after-state is unavailable\\n' >&2; assertion=1; elif ! check_apt_update_delta \"\$apt_before\" \"\$apt_after\"; then assertion=1; fi; fi"
    remote+="; if ! cleanup_apt_update_fixture '$distro'; then printf 'assertion failed: APT update fixture cleanup failed\\n' >&2; execution_phase=dependency; rc=2; assertion=1; fi"
  fi
  if [[ -n "$counter" ]]; then
    remote+="; if [ \"\$rc\" = 0 ]; then oracle_rc=0; check_native_counter '$distro' '$counter' command.stdout.log || oracle_rc=\$?; if [ \"\$oracle_rc\" = 2 ]; then execution_phase=dependency; rc=2; elif [ \"\$oracle_rc\" != 0 ]; then assertion=1; fi; fi"
    remote+="; cd \"\$HOME\"; if ! rm -rf -- \"\$rowdir\" || [ -e \"\$rowdir\" ] || [ -L \"\$rowdir\" ]; then printf 'assertion failed: counter fixture cleanup failed\\n' >&2; assertion=1; fi"
  fi
  if [[ "$assertions" == doctor-native-backend ]]; then
    if [[ "$distro" == fedora ]]; then
      remote+="; if [ \"\$rc\" = 0 ]; then oracle_rc=0; check_doctor_native_backend '$distro' command.stdout.log /etc/os-release doctor.exec.log || oracle_rc=\$?; if [ \"\$oracle_rc\" = 2 ]; then execution_phase=dependency; rc=2; elif [ \"\$oracle_rc\" != 0 ]; then assertion=1; fi; fi"
    else
      remote+="; if [ \"\$rc\" = 0 ]; then oracle_rc=0; check_doctor_native_backend '$distro' command.stdout.log || oracle_rc=\$?; if [ \"\$oracle_rc\" = 2 ]; then execution_phase=dependency; rc=2; elif [ \"\$oracle_rc\" != 0 ]; then assertion=1; fi; fi"
    fi
    if [[ "$distro" == arch ]]; then
      remote+="; mkdir -p fault-db/local/broken-1.0-1; printf '%%NAME%%\\nbroken\\n\\n%%VERSION%%\\n1.0-1\\n' > fault-db/local/broken-1.0-1/desc"
      remote+="; fault_rc=0; OMG_PACMAN_DB_DIR=\"\$rowdir/fault-db\" OMG_DISABLE_DAEMON=1 timeout --kill-after=5s '$row_timeout' $quoted_binary doctor > doctor-fault.stdout.log 2> doctor-fault.stderr.log || fault_rc=\$?"
      remote+="; if [ \"\$fault_rc\" != 1 ] || ! grep -Fq 'ALPM local package database inconsistent (' doctor-fault.stdout.log; then printf 'assertion failed: doctor accepted a corrupt Arch local package entry\\n' >&2; assertion=1; fi"
    fi
    # POSIX PATH searches executable files in listed directories. Hold all
    # other Doctor inputs fixed, including a refused HTTPS proxy, so a live
    # connectivity fluctuation cannot masquerade as a PATH issue.
    remote+="; if [[ \"\$rc\" == 0 && \"\$execution_phase\" == product && \"\$assertion\" == 0 ]]; then path_without_omg=/usr/sbin:/usr/bin:/sbin:/bin; path_with_omg=$quoted_binary_dir:\"\$path_without_omg\""
    remote+="; if env PATH=\"\$path_without_omg\" sh -c 'command -v omg >/dev/null 2>&1'; then printf 'assertion failed: restricted guest PATH still resolves omg\\n' >&2; execution_phase=dependency; rc=2; assertion=1"
    remote+="; else mkdir -p shadow-bin relative-bin; printf '#!/bin/sh\\nexit 99\\n' > shadow-bin/omg; chmod 700 shadow-bin/omg; ln -s $quoted_binary relative-bin/omg; path_shadow=\"\$rowdir/shadow-bin:\$path_with_omg\"; path_relative=\"./relative-bin:\$path_without_omg\""
    remote+="; actual_shadow=\$(env PATH=\"\$path_shadow\" sh -c 'command -v omg'); actual_relative=\$(env PATH=\"\$path_relative\" sh -c 'command -v omg'); actual_relative_target=\$(readlink -f \"\$actual_relative\"); expected_binary=\$(readlink -f $quoted_binary); if [[ \"\$actual_shadow\" != \"\$rowdir/shadow-bin/omg\" || \"\$actual_relative\" != *relative-bin/omg || \"\$actual_relative_target\" != \"\$expected_binary\" ]]; then printf 'controlled Doctor shadow/relative PATH fixtures did not resolve: shadow=%q relative=%q\\n' \"\$actual_shadow\" \"\$actual_relative\" >&2; execution_phase=dependency; rc=2; assertion=1"
    remote+="; else doctor_path_probe() { local selected_path=\$1 output_prefix=\$2; run_omg '$row_timeout' env PATH=\"\$selected_path\" HTTPS_PROXY=http://127.0.0.1:1 https_proxy=http://127.0.0.1:1 HTTP_PROXY=http://127.0.0.1:1 http_proxy=http://127.0.0.1:1 ALL_PROXY=http://127.0.0.1:1 all_proxy=http://127.0.0.1:1 NO_PROXY= no_proxy= OMG_DISABLE_DAEMON=1 OMG_TEST_MODE=0 $quoted_binary doctor > \"\$output_prefix.stdout.log\" 2> \"\$output_prefix.stderr.log\"; }"
    remote+="; doctor_path_probe \"\$path_with_omg\" doctor-path-baseline; path_baseline_rc=\$rc; path_baseline_phase=\$execution_phase; cat doctor-path-baseline.stdout.log doctor-path-baseline.stderr.log >&2"
    remote+="; doctor_path_probe \"\$path_without_omg\" doctor-path-absent; path_absent_rc=\$rc; path_absent_phase=\$execution_phase; cat doctor-path-absent.stdout.log doctor-path-absent.stderr.log >&2"
    remote+="; doctor_path_probe \"\$path_shadow\" doctor-path-shadow; path_shadow_rc=\$rc; path_shadow_phase=\$execution_phase; cat doctor-path-shadow.stdout.log doctor-path-shadow.stderr.log >&2"
    remote+="; doctor_path_probe \"\$path_relative\" doctor-path-relative; path_relative_rc=\$rc; path_relative_phase=\$execution_phase; cat doctor-path-relative.stdout.log doctor-path-relative.stderr.log >&2"
    remote+="; if [[ \"\$path_baseline_phase\" != product || \"\$path_absent_phase\" != product || \"\$path_shadow_phase\" != product || \"\$path_relative_phase\" != product ]]; then if [[ \"\$path_baseline_phase\" != product ]]; then rc=\$path_baseline_rc; execution_phase=\$path_baseline_phase; elif [[ \"\$path_absent_phase\" != product ]]; then rc=\$path_absent_rc; execution_phase=\$path_absent_phase; elif [[ \"\$path_shadow_phase\" != product ]]; then rc=\$path_shadow_rc; execution_phase=\$path_shadow_phase; else rc=\$path_relative_rc; execution_phase=\$path_relative_phase; fi; printf 'controlled Doctor PATH probe did not execute as a product run\\n' >&2; assertion=1"
    remote+="; elif ! grep -Fqx '  PATH configured correctly' doctor-path-baseline.stdout.log || ! grep -Fqx '  omg executable not found on PATH' doctor-path-absent.stdout.log || grep -Fqx '  PATH configured correctly' doctor-path-absent.stdout.log || ! grep -Eq '^  PATH resolves a different omg executable first: \".*/shadow-bin/omg\"$' doctor-path-shadow.stdout.log || grep -Fqx '  PATH configured correctly' doctor-path-shadow.stdout.log || ! grep -Fqx '  PATH configured correctly' doctor-path-relative.stdout.log || ! grep -Eq '^  Connectivity probe.*failed' doctor-path-baseline.stdout.log || ! grep -Eq '^  Connectivity probe.*failed' doctor-path-absent.stdout.log || ! grep -Eq '^  Connectivity probe.*failed' doctor-path-shadow.stdout.log || ! grep -Eq '^  Connectivity probe.*failed' doctor-path-relative.stdout.log || ! check_doctor_issue_delta 0 command.stdout.log command.stderr.log \"\$path_baseline_rc\" doctor-path-baseline.stderr.log 1 || ! check_doctor_issue_delta \"\$path_baseline_rc\" doctor-path-baseline.stdout.log doctor-path-baseline.stderr.log \"\$path_absent_rc\" doctor-path-absent.stderr.log 1 || ! check_doctor_issue_delta \"\$path_baseline_rc\" doctor-path-baseline.stdout.log doctor-path-baseline.stderr.log \"\$path_shadow_rc\" doctor-path-shadow.stderr.log 1 || ! check_doctor_issue_delta \"\$path_baseline_rc\" doctor-path-baseline.stdout.log doctor-path-baseline.stderr.log \"\$path_relative_rc\" doctor-path-relative.stderr.log 0; then printf 'assertion failed: controlled Doctor PATH probe lacked the exact diagnostic and issue deltas\\n' >&2; assertion=1; rc=0; execution_phase=product"
    remote+="; else rc=0; execution_phase=product; fi; fi; fi; fi"
  fi
  if [[ "$assertions" == doctor-native-backend && "$case" == doctor ]]; then
    # The release binary must remain healthy when optional host executables
    # are absent from its PATH. Its backend and sudo checks still resolve real
    # native system tools, so the second run cannot pass by skipping them.
    remote+="; doctor_path=$quoted_binary_dir; for optional in curl tar git; do if env PATH=\"\$doctor_path\" /bin/bash -c 'command -v \"\$1\" >/dev/null' _ \"\$optional\"; then printf 'assertion failed: controlled doctor PATH still exposes %s\\n' \"\$optional\" >&2; execution_phase=dependency; rc=2; assertion=1; break; fi; done"
    if [[ "$distro" == arch ]]; then
      remote+="; if [ \"\$assertion\" = 0 ] && env PATH=\"\$doctor_path\" /bin/bash -c 'command -v makepkg >/dev/null'; then printf 'assertion failed: controlled doctor PATH still exposes makepkg\\n' >&2; execution_phase=dependency; rc=2; assertion=1; fi"
    fi
    if [[ "$distro" == fedora ]]; then
      remote+="; if [ \"\$assertion\" = 0 ]; then run_omg '$command_timeout' strace --seccomp-bpf -f -qq -e trace=execve -o doctor.minimal.exec.log env PATH=\"\$doctor_path\" $quoted_binary doctor > doctor.minimal.stdout.log 2> doctor.minimal.stderr.log; fi"
    else
      remote+="; if [ \"\$assertion\" = 0 ]; then run_omg '$command_timeout' env PATH=\"\$doctor_path\" $quoted_binary doctor > doctor.minimal.stdout.log 2> doctor.minimal.stderr.log; fi"
    fi
    remote+="; if [ \"\$assertion\" = 0 ]; then cat doctor.minimal.stdout.log doctor.minimal.stderr.log >&2; if [ \"\$execution_phase\" != product ] || [ \"\$rc\" != 0 ]; then printf 'assertion failed: doctor could not run with optional tools absent\\n' >&2; assertion=1; fi; fi"
    if [[ "$distro" == fedora ]]; then
      remote+="; if [ \"\$assertion\" = 0 ]; then oracle_rc=0; check_doctor_native_backend '$distro' doctor.minimal.stdout.log /etc/os-release doctor.minimal.exec.log true || oracle_rc=\$?; if [ \"\$oracle_rc\" = 2 ]; then execution_phase=dependency; rc=2; elif [ \"\$oracle_rc\" != 0 ]; then assertion=1; fi; fi"
    else
      remote+="; if [ \"\$assertion\" = 0 ]; then oracle_rc=0; check_doctor_native_backend '$distro' doctor.minimal.stdout.log /etc/os-release '' true || oracle_rc=\$?; if [ \"\$oracle_rc\" = 2 ]; then execution_phase=dependency; rc=2; elif [ \"\$oracle_rc\" != 0 ]; then assertion=1; fi; fi"
    fi
  fi
  if [[ "$assertions" == info-native-package ]]; then
    remote+="; if [ \"\$rc\" = 0 ]; then oracle_rc=0; check_info_native_package '$distro' command.stdout.log || oracle_rc=\$?; if [ \"\$oracle_rc\" = 2 ]; then execution_phase=dependency; rc=2; elif [ \"\$oracle_rc\" != 0 ]; then assertion=1; fi; fi"
  fi
  if [[ "$assertions" == status-native-fast || "$assertions" == status-native-full ]]; then
    mode=${assertions#status-native-}
    remote+="; if [ \"\$rc\" = 0 ]; then oracle_rc=0; check_status_native_counts '$distro' '$mode' command.stdout.log || oracle_rc=\$?; if [ \"\$oracle_rc\" = 2 ]; then execution_phase=dependency; rc=2; elif [ \"\$oracle_rc\" != 0 ]; then assertion=1; fi; fi"
  fi
  if [[ "$assertions" == outdated-native-count || "$assertions" == outdated-json-native-count ]]; then
    format=text
    [[ "$assertions" != outdated-json-native-count ]] || format=json
    remote+="; if [ \"\$rc\" = 0 ]; then oracle_rc=0; check_outdated_native_count '$distro' '$format' command.stdout.log || oracle_rc=\$?; if [ \"\$oracle_rc\" = 2 ]; then execution_phase=dependency; rc=2; elif [ \"\$oracle_rc\" != 0 ]; then assertion=1; fi; fi"
  fi
  if [[ "$case" == runtime-python-install || "$case" == runtime-node-install || "$case" == runtime-go-install ]]; then
    remote+="; if [ \"\$rc\" = 0 ] && ! check_${runtime_name}_install '$runtime_version'; then assertion=1; fi"
    remote+="; if [ \"\$rc\" = 0 ] && ! check_runtime_usage '$runtime_name'; then assertion=1; fi"
    remote+="; cd \"\$HOME\"; if ! rm -rf -- \"\$rowdir\" || [ -e \"\$rowdir\" ] || [ -L \"\$rowdir\" ]; then printf 'assertion failed: runtime fixture cleanup failed\\n' >&2; assertion=1; fi"
  fi
  if [[ "$assertions" == runtime-version-removed ]]; then
    remote+="; if [ \"\$rc\" = 0 ] && ! check_runtime_uninstall '$runtime_name' '$runtime_version'; then assertion=1; fi"
  fi
  if [[ "$assertions" == runtime-list-state || "$assertions" == runtime-switch-state ]]; then
    remote+="; if [ \"\$rc\" = 0 ] && ! check_runtime_state '$runtime_name' '$runtime_version' '$runtime_active' '$assertions' command.stdout.log; then assertion=1; fi"
  fi
  # Every inventory row receives a private fixture directory. Product-specific
  # cleanup assertions run above; removal here proves the harness itself does
  # not leak state that could make a later row pass.
  remote+="; cd \"\$HOME\"; if ! rm -rf -- \"\$rowdir\" || [ -e \"\$rowdir\" ] || [ -L \"\$rowdir\" ]; then printf 'assertion failed: row fixture cleanup failed (%s)\\n' '$cleanup' >&2; assertion=1; fi"
  # A receipt is emitted only after setup and the command complete. SSH
  # transport/tool failures cannot satisfy an expected product refusal.
  remote+="; printf '\nOMG_QEMU_RECEIPT:%s:%s:%s\n' \"\$execution_phase\" \"\$rc\" \"\$assertion\""
  remote="bash -c $(jq -rn --arg s "$remote" '$s | @sh')"
  if [[ "$network_scope" == offline ]]; then
    # Put the supervisor AND its receipt inside the namespace. A namespace
    # setup failure must be a transport/harness error, never an expected CLI
    # refusal. Drop back to the SSH user before creating fixtures or running OMG.
    if [[ "$case" == daemon-foreground ]]; then
      # The daemon fault probe owns a second, private mount namespace and must
      # use its tightly scoped passwordless sudo before dropping all privileges
      # around the submitted binary. Keep that capability inside this offline
      # network namespace while running the lifecycle itself as the SSH user.
      remote="sudo -n unshare --net -- sudo -n -u '$ssh_user' env HOME=\"\$HOME\" USER='$ssh_user' LOGNAME='$ssh_user' $remote"
    else
      remote="sudo -n unshare --net -- setpriv --reuid=\"\$(id -u)\" --regid=\"\$(id -g)\" --clear-groups --no-new-privs --bounding-set=-all --inh-caps=-all --ambient-caps=-all env HOME=\"\$HOME\" USER='$ssh_user' LOGNAME='$ssh_user' $remote"
    fi
  fi
  # Bash SECONDS follows wall-clock adjustments; WSL can step that clock
  # backwards while a guest case runs. /proc/uptime uses boot-time monotonic
  # time, so a passing case cannot acquire a negative elapsed duration.
  read -r uptime _ < /proc/uptime
  start_centis=${uptime/./}
  transport=0
  budget=$(( (row_timeout + 5) * ${#chain[@]} + command_timeout + 20 ))
  if [[ "$assertions" == doctor-eol-state || "$assertions" == doctor-network-state ]]; then budget=$((budget + row_timeout + 5)); fi
  if [[ "$assertions" == doctor-native-backend ]]; then
    # Four PATH variants plus the minimal-PATH run; Arch also exercises a
    # corrupt local database. Each run owns a separate row_timeout deadline.
    doctor_extra_runs=5
    if [[ "$distro" == arch ]]; then doctor_extra_runs=6; fi
    budget=$((budget + doctor_extra_runs * (row_timeout + 5)))
  fi
  if [[ -n "$counter" ]]; then budget=$((budget + 32)); fi
  if [[ "$assertions" == outdated-native-count || "$assertions" == outdated-json-native-count ]]; then budget=$((budget + 32)); fi
  if [[ "$assertions" == status-native-fast ]]; then budget=$((budget + 64)); fi
  if [[ "$assertions" == status-native-full ]]; then budget=$((budget + 128)); fi
  if [[ "$case" == runtime-python-install ]]; then
    # Five venv probes can outlast the former single-probe deadline on a slow
    # guest. The SSH ceiling includes the Python oracle's worst case: five
    # attempts of (venv create + 120s ensurepip + probes) plus cleanup.
    budget=$((budget + 660))
  elif [[ "$case" == runtime-node-install || "$case" == runtime-go-install ]]; then
    budget=$((budget + 74))
  fi
  if [[ "$case" == runtime-go-install ]]; then budget=$((budget + 210)); fi
  if [[ ( "$distro" == debian || "$distro" == ubuntu ) && ( "$case" == update-fast || "$case" == update-turbo ) ]]; then budget=$((budget + 60)); fi
  timeout --kill-after=5s "$budget" ssh "${opts[@]}" "$target" "$remote" > "$out/rows/$case.stdout.log" 2> "$out/rows/$case.stderr.log" || transport=$?
  read -r uptime _ < /proc/uptime
  elapsed=$(( (10#${uptime/./} - 10#$start_centis) / 100 ))
  verdict=HARNESS_ERROR; rc=$transport
  receipt=$(tail -n 1 "$out/rows/$case.stdout.log")
  if [[ "$transport" == 0 && "$receipt" =~ ^OMG_QEMU_RECEIPT:(product|executor|dependency):([0-9]{1,3}):([01])$ ]]; then
    phase=${BASH_REMATCH[1]}; rc=${BASH_REMATCH[2]}; assertion_rc=${BASH_REMATCH[3]}
    verdict=FAIL
    if [[ "$phase" == dependency ]]; then verdict=BLOCKED
    elif [[ "$phase" == executor ]]; then
      [[ "$rc" == 124 || "$rc" == 137 ]] || verdict=HARNESS_ERROR
    elif [[ "$rc" == "${row_exit[$case]}" && "$assertion_rc" == 0 ]]; then
      verdict=PASS
      if [[ "$assertions" == json-stdout && "$rc" == 0 ]]; then
        head -n -1 "$out/rows/$case.stdout.log" | jq -e -s 'length == 1' >/dev/null 2>&1 || verdict=FAIL
      fi
    fi
  fi
  write_row_log "$out/rows/$case.log" "$out/rows/$case.stdout.log" "$out/rows/$case.stderr.log" "$case" "$verdict"
  record "qemu-$distro-$case" "$verdict" "$rc" "$elapsed"
  if [[ "$verdict" == PASS ]]; then pass=$((pass+1)); else fail=$((fail+1)); fi
  printf 'case=%s exit=%s verdict=%s\n' "$case" "$rc" "$verdict"
done < <(tail -n +2 "$tsv")
if ((pass + fail == 0)); then
  record "qemu-$distro-inventory-selection" HARNESS_ERROR -1 0
  fail=$((fail+1))
fi
printf '{"complete":true,"pass":%s,"fail":%s,"skipped":%s}\n' "$pass" "$fail" "$skipped" > "$out/summary.json.next"
mv "$out/summary.json.next" "$out/summary.json"
cat "$out/summary.json"
[[ "$fail" -eq 0 ]]
