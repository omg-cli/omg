#!/usr/bin/env python3
"""Run the same exact Arch CLI coverage cases in disposable Docker or QEMU guests."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import xml.etree.ElementTree as ET


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


TESTS = {
    'coverage14': (
        'why_contracts::uninstalled_package_fails_naming_cause_and_remedy',
        'why_contracts::explicit_package_reports_reason_dependencies_and_safety',
        'why_contracts::orphan_dependency_is_flagged_safe_to_remove',
        'why_contracts::required_by_card_shows_dependent_and_dependency_path',
        'why_contracts::reverse_lists_dependents_with_safety_warning',
        'why_contracts::reverse_without_dependents_is_safe',
    ),
    'arch-contracts': (
        'dependency_reports_bound_large_reverse_dependency_lists',
        'native_size_tree_includes_installed_virtual_provider',
        'native_size_tree_counts_one_provider_for_multiple_virtual_requirements',
        'native_size_tree_respects_virtual_provider_version_constraints',
        'native_size_tree_preserves_exact_name_dependency_totals',
        'native_size_tree_refuses_absent_root_without_changing_private_data',
    ),
    'comprehensive': ('behavior_inventory_runs_in_hermetic_state',),
    'cli-unit': ('fast_path_tests::private_install_plan_rejects_missing_or_invalid_descriptors',),
}
ROLES = ('cli', 'daemon', *TESTS)
CASES = tuple((f'test-{index:02}', role, name)
              for index, (role, name) in enumerate(
                  ((role, name) for role, names in TESTS.items() for name in names), 1))
OMARCHY_PREFIX = (
    'omarchy-update-requires-free-space', 'sudo\ttrue', 'omarchy-update-pkg-prune',
    'omarchy-snapshot\tcreate', 'omarchy-update-stay-awake\tstart',
    'omarchy-update-dev', 'omarchy-update-keyring', 'omarchy-update-system-pkgs')
OMARCHY_SUFFIX = (
    'omarchy-migrate\t--pending', 'omarchy-restart-shell', 'omarchy-migrate',
    'omarchy-update-orphan-pkgs\t-y', 'omarchy-update-analyze-logs',
    'omarchy-shell\t-q\tomarchy.system-update\tclear',
    'omarchy-update-restart\t--services-only', 'omarchy-hook\tpost-update',
    'omarchy-update-mise', 'omarchy-update-boot', 'omarchy-update-stay-awake\tstop',
    'omarchy-update-restart\t--reboot-only')
OMARCHY_CASES = {
    'omarchy-success': (0, OMARCHY_PREFIX + OMARCHY_SUFFIX),
    'omarchy-vendor-failure': (1, OMARCHY_PREFIX + ('omarchy-update-stay-awake\tstop',)),
    'omarchy-declined': (0, ('omarchy-update-requires-free-space', 'omarchy-update-confirm')),
    'omarchy-optional-failures': (0, tuple(
        item for item in OMARCHY_PREFIX + OMARCHY_SUFFIX
        if item.split('\t')[0] not in ('omarchy-snapshot', 'omarchy-restart-shell', 'omarchy-update-mise'))),
    'omarchy-migration-refusal': (1, ()),
    'omarchy-unsupported-mode': (1, ()),
    'omarchy-invalid-transport': (1, ()),
}
PROCESS_STAGES = ('cli-q', 'cli-v', 'cli-vv', 'cli-vvv', 'daemon', *OMARCHY_CASES)
STAGES = tuple('registry-' + role for role in TESTS) + tuple(row[0] for row in CASES) + PROCESS_STAGES
PROFILE = re.compile(r'omg-extra-(' + '|'.join(map(re.escape, STAGES)) + r')-([0-9]+)-([0-9]+_[0-9]+)\.profraw')


def omarchy_guest_script():
    return r'''unshare --mount --net --fork bash -s <<'OMG_OMARCHY_NAMESPACE'
set -euo pipefail
mount --make-rprivate /
for tool in script flock tar mount mountpoint readlink runuser; do
  command -v "$tool" > /dev/null || { printf 'Missing Omarchy fixture command: %s\n' "$tool" >&2; exit 1; }
done
fixture=/opt/omg-omarchy-coverage
test ! -e "$fixture" && test ! -L "$fixture"
install -d -m 755 "$fixture"
printf 'ID=omarchy\nID_LIKE=arch\n' > "$fixture/release"
mount --bind "$fixture/release" /etc/os-release
mount -t tmpfs -o nosuid,nodev,mode=1777 tmpfs /tmp
install -d -m 755 "$fixture/runtime" "$fixture/runtime/migrations" /usr/share/omarchy
mount --bind "$fixture/runtime" /usr/share/omarchy
test "$(stat -c '%u:%a' /usr/share/omarchy)" = 0:755
test "$(stat -c '%u:%a' /usr/share/omarchy/migrations)" = 0:755
cat > "$fixture/stage" <<'OMG_INERT_OMARCHY_STAGE'
#!/bin/bash
set -euo pipefail
name=${0##*/}
omarchy_security_require_source_root() {
  local command_source command_name=${1##*/}
  command_source=$(/usr/bin/readlink -e -- "$1") || return 1

  # A runtime root selects the code used by this invocation. Accept the
  # canonical checkout containing the entrypoint or the package's bin links.
  if [[ ${OMARCHY_PATH:-} != /* || $(/usr/bin/realpath -e -- "$OMARCHY_PATH") != "$OMARCHY_PATH" ]] ||
    ! { [[ $command_source == "$OMARCHY_PATH/bin/$command_name" ]] ||
      [[ $OMARCHY_PATH == "/usr/share/omarchy" && $command_source == "/usr/bin/$command_name" ]]; }; then
    echo "OMARCHY_PATH does not match this Omarchy command." >&2
    return 1
  fi
}
case "$name" in omarchy-*) omarchy_security_require_source_root "$0" ;; esac
{ printf '%s' "$name"; if test "$#" -gt 0; then printf '\t%s' "$@"; fi; printf '\n'; } >> "$OMARCHY_HELPER_TRACE"
case "$name" in
  yay|aura|paru) printf 'external AUR helper must never run\n' >&2; exit 99 ;;
  omarchy-update-confirm) test "$OMARCHY_FIXTURE_CASE" != omarchy-declined ;;
  omarchy-update-system-pkgs) test "$OMARCHY_FIXTURE_CASE" != omarchy-vendor-failure ;;
  omarchy-snapshot|omarchy-update-mise) test "$OMARCHY_FIXTURE_CASE" != omarchy-optional-failures ;;
  *) exit 0 ;;
esac
OMG_INERT_OMARCHY_STAGE
cat > "$fixture/sudo" <<'OMG_INERT_SUDO'
#!/bin/bash
set -euo pipefail
case "$*" in true|'-n true') ;; *) printf 'unexpected fixture sudo request\n' >&2; exit 99 ;; esac
{ printf sudo; printf '\t%s' "$@"; printf '\n'; } >> "$OMARCHY_HELPER_TRACE"
OMG_INERT_SUDO
cat > "$fixture/foreign-stage-prefix" <<'OMG_FOREIGN_OMARCHY_STAGE_PREFIX'
#!/bin/bash
set -euo pipefail
printf 'foreign helper executed: %s\n' "$0" >> "$OMARCHY_HELPER_TRACE.unexpected"
OMG_FOREIGN_OMARCHY_STAGE_PREFIX
install -d -m 755 "$fixture/foreign" "$fixture/foreign/bin" "$fixture/saved"
for name in omarchy-snapshot omarchy-restart-shell omarchy-update-mise omarchy-update-confirm; do
  cat "$fixture/foreign-stage-prefix" > "$fixture/foreign/bin/$name"
  tail -n +2 "$fixture/stage" >> "$fixture/foreign/bin/$name"
  chmod 755 "$fixture/foreign/bin/$name"
done
chmod 755 "$fixture/stage" "$fixture/sudo"
mount --bind "$fixture/sudo" "$(readlink -f /usr/bin/sudo)"
created=()
trap 'for path in "${created[@]}"; do rm -f -- "$path"; done; rm -rf -- "$fixture"' EXIT
for name in omarchy-update-requires-free-space omarchy-update-confirm omarchy-update-pkg-prune \
  omarchy-snapshot omarchy-update-stay-awake omarchy-update-dev omarchy-update-keyring \
  omarchy-update-system-pkgs omarchy-migrate omarchy-restart-shell omarchy-update-orphan-pkgs \
  omarchy-update-analyze-logs omarchy-shell omarchy-update-restart omarchy-hook \
  omarchy-update-mise omarchy-update-boot yay aura paru; do
  test ! -e "/usr/bin/$name" && test ! -L "/usr/bin/$name"
  install -m 755 "$fixture/stage" "/usr/bin/$name"
  created+=("/usr/bin/$name")
done
case_root=/var/tmp/omg-extra-nobody/omarchy
install -d -m 700 -o nobody -g nobody "$case_root"
for stage in omarchy-success omarchy-vendor-failure omarchy-declined omarchy-optional-failures \
  omarchy-migration-refusal omarchy-unsupported-mode omarchy-invalid-transport; do
  case_dir="$case_root/$stage"
  install -d -m 700 -o nobody -g nobody "$case_dir" "$case_dir/config" "$case_dir/run" \
    "$case_dir/db" "$case_dir/db/local" "$case_dir/db/sync" "$case_dir/migrations" \
    "$case_dir/checkout/bin" "$case_dir/checkout/migrations"
  printf 'telemetry_enabled = false\n[aur]\nsecurity_profile = "standard"\n' > "$case_dir/config/config.toml"
  printf '[options]\nArchitecture = auto\nDBPath = %s/db\n[core]\nSigLevel = Never\nServer = file:///nonexistent\n' "$case_dir" > "$case_dir/pacman.conf"
  tar -czf "$case_dir/db/sync/core.db" --files-from /dev/null
  printf '9\n' > "$case_dir/db/local/ALPM_DB_VERSION"
  : > "$case_dir/helpers.tsv"
  printf '#!/bin/bash\nexit 88\n' > "$case_dir/checkout/bin/omarchy-migrate"
  chmod 755 "$case_dir/checkout/bin/omarchy-migrate"
  chown -R nobody:nobody "$case_dir"
  rm -f "$fixture/runtime/migrations/1.sh"
  case "$stage" in
    omarchy-success)
      printf 'omarchy-pkg-aur-add forbidden-home-fixture\n' > "$case_dir/checkout/migrations/1.sh"
      ;;
    omarchy-migration-refusal)
      printf 'omarchy-pkg-aur-add forbidden-installed-fixture\n' > "$fixture/runtime/migrations/1.sh"
      ;;
  esac
  args=(--yes)
  extra=()
  case "$stage" in
    omarchy-declined) args=() ;;
    omarchy-unsupported-mode) args=(--fast) ;;
    omarchy-invalid-transport) extra=(OMG_OMARCHY_LOCK_FD=999999) ;;
  esac
  if test "$stage" = omarchy-optional-failures; then
    for name in omarchy-snapshot omarchy-restart-shell omarchy-update-mise omarchy-update-confirm; do
      test -f "/usr/bin/$name" && test ! -L "/usr/bin/$name"
      if mountpoint -q "/usr/bin/$name"; then
        printf 'Refusing mounted optional fixture helper: %s\n' "$name" >&2
        exit 1
      fi
      mv "/usr/bin/$name" "$fixture/saved/$name"
      ln -s "$fixture/foreign/bin/$name" "/usr/bin/$name"
      test "$(readlink -e "/usr/bin/$name")" = "$fixture/foreign/bin/$name"
      test "$(stat -c '%u:%a' "$fixture/foreign/bin/$name")" = 0:755
    done
  fi
  result=0
  timeout --signal=TERM --kill-after=3 40 runuser -u nobody -- env -i \
    PATH=/usr/bin:/bin LANG=C.UTF-8 HOME="$case_dir" TMPDIR="$case_dir" \
    XDG_RUNTIME_DIR="$case_dir/run" XDG_CONFIG_HOME="$case_dir/config" \
    XDG_CACHE_HOME="$case_dir/cache" XDG_DATA_HOME="$case_dir/data" XDG_STATE_HOME="$case_dir/state" \
    OMG_CONFIG_DIR="$case_dir/config" OMG_CACHE_DIR="$case_dir/cache" OMG_DATA_DIR="$case_dir/data" \
    OMG_DAEMON_DATA_DIR="$case_dir/daemon" OMG_DISABLE_DAEMON=1 OMG_DISABLE_TELEMETRY=1 \
    OMG_PACMAN_CONF="$case_dir/pacman.conf" OMG_PACMAN_DB_DIR="$case_dir/db" \
    OMARCHY_PATH="$case_dir/checkout" OMARCHY_MIGRATION_STATE="$case_dir/migrations" \
    OMARCHY_FIXTURE_CASE="$stage" OMARCHY_HELPER_TRACE="$case_dir/helpers.tsv" \
    LLVM_PROFILE_FILE="/profiles/omg-extra-$stage-%p-%m.profraw" "${extra[@]}" \
    bash -c 'test "$(id -u)" -ne 0; test -z "${OMG_TEST_MODE+x}"; test -z "${CARGO_PRIMARY_PACKAGE+x}"; exec /omg-extra-bin/cli update "$@"' \
    bash "${args[@]}" < /dev/null > "/evidence/cli/$stage.log" 2>&1 || result=$?
  if test "$stage" = omarchy-optional-failures; then
    for name in omarchy-snapshot omarchy-restart-shell omarchy-update-mise omarchy-update-confirm; do
      test -L "/usr/bin/$name"
      test "$(readlink -e "/usr/bin/$name")" = "$fixture/foreign/bin/$name"
      rm -- "/usr/bin/$name"
      mv "$fixture/saved/$name" "/usr/bin/$name"
      test -f "/usr/bin/$name" && test ! -L "/usr/bin/$name"
      cmp "$fixture/stage" "/usr/bin/$name"
    done
    test ! -e "$case_dir/helpers.tsv.unexpected"
    printf 'foreign optional helpers never executed; original helpers restored\n' > "/evidence/cli/$stage-layout.txt"
  fi
  printf '%s\n' "$result" > "/evidence/cli/$stage-exit.txt"
  cp "$case_dir/helpers.tsv" "/evidence/cli/$stage-helpers.tsv"
  if test -f "$case_dir/run/omarchy-update.lock"; then
    flock --nonblock "$case_dir/run/omarchy-update.lock" true
    test "$(stat -c '%u:%a' "$case_dir/run/omarchy-update.lock")" = "$(id -u nobody):600"
    test "$(stat -c '%u:%a' /tmp/omarchy-update.log)" = "$(id -u nobody):600"
    test -s /tmp/omarchy-update.log
    cp /tmp/omarchy-update.log "/evidence/cli/$stage-transcript.log"
    printf 'released private lock; owned transcript mode=600\n' > "/evidence/cli/$stage-coordination.txt"
  fi
  printf '%s\t0\n' "$stage" >> /evidence/cli/process-checks.tsv
done
OMG_OMARCHY_NAMESPACE
'''


def guest_script(artifacts, compiled_cli):
    quote = shlex.quote
    receipt = json.dumps(dict(original=compiled_cli, copy='/omg-extra-bin/cli', sha256=artifacts['cli']['sha256']))
    artifact_lines = '\n'.join(f"{item['sha256']}  /omg-extra-bin/{role}" for role, item in artifacts.items()) + '\n'
    selection = '\n'.join('\t'.join(row) for row in CASES) + '\n'
    script = r'''set -euo pipefail
test "$(id -u)" = 0
test -f /etc/arch-release
. /etc/os-release
test "$ID" = arch
test "$(uname -m)" = x86_64
test "$(id -u nobody)" -ne 0
test "$(stat -c '%u:%a' /omg-extra-bin)" = 0:755
install -d -m 755 /evidence/cli
test "$(stat -c '%u:%a' /profiles)" = 0:1777
! compgen -G '/profiles/omg-extra-*.profraw'
install -d -m 755 -o nobody -g nobody /evidence/cli/inventory
install -d -m 700 -o nobody -g nobody /var/tmp/omg-extra-nobody
install -d -m 700 /var/tmp/omg-extra-root /var/tmp/omg-extra-root/data
printf '%s' RECEIPT > /omg-extra-bin/cli-receipt.json
chmod 644 /omg-extra-bin/cli-receipt.json
test "$(stat -c '%u:%a' /omg-extra-bin)" = 0:755
printf '%s' ARTIFACTS > /evidence/cli/artifacts.sha256
sha256sum -c /evidence/cli/artifacts.sha256 > /evidence/cli/artifact-check.txt
printf '%s' SELECTION > /evidence/cli/expected-tests.tsv
for role in cli daemon coverage14 arch-contracts comprehensive cli-unit; do
  test "$(stat -c '%u:%a' "/omg-extra-bin/$role")" = 0:755
  ldd "/omg-extra-bin/$role" > "/evidence/cli/abi-$role.txt" 2>&1
  ! grep -F 'not found' "/evidence/cli/abi-$role.txt"
done
getconf GNU_LIBC_VERSION > /evidence/cli/libc.txt
pacman -Q pacman libarchive > /evidence/cli/native-library-versions.txt
ln /omg-extra-bin/cli /omg-extra-bin/omg
ln /omg-extra-bin/daemon /omg-extra-bin/omgd
test "$(stat -c '%d:%i' /omg-extra-bin/cli)" = "$(stat -c '%d:%i' /omg-extra-bin/omg)"
test "$(stat -c '%d:%i' /omg-extra-bin/daemon)" = "$(stat -c '%d:%i' /omg-extra-bin/omgd)"
uname -a > /evidence/cli/kernel.txt
cat /proc/sys/kernel/random/boot_id > /evidence/cli/boot-id.txt
printf 'actual_id=%s ordinary_uid=%s root_uid=%s\n' "$ID" "$(id -u nobody)" "$(id -u)" > /evidence/cli/identity.txt
fingerprint_db() {
  printf 'scope=/var/lib/pacman exclusions=atime-only\n'
  find /var/lib/pacman -xdev -printf '%P\t%y\t%m\t%U\t%G\t%s\t%T@\t%C@\t%l\n' | LC_ALL=C sort
  find /var/lib/pacman -xdev -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum
}
fingerprint_db > /evidence/cli/db-before.txt
trap 'fingerprint_db > /evidence/cli/db-after.txt' EXIT
unshare --mount --net --fork bash -s <<'OMG_EXTRA_NAMESPACE'
set -euo pipefail
mount --make-rprivate /
ip link set lo up
test "$(ip -o link show | wc -l)" = 1
ip -o link show | grep -E '^[0-9]+: lo:' > /evidence/cli/network.txt
mount -t tmpfs -o nosuid,nodev,noexec,mode=755 tmpfs /var/log
ordinary() {
  runuser -u nobody -- env -i PATH=/usr/bin:/bin LANG=C.UTF-8 \
    HOME=/var/tmp/omg-extra-nobody TMPDIR=/var/tmp/omg-extra-nobody \
    XDG_CONFIG_HOME=/var/tmp/omg-extra-nobody/config XDG_CACHE_HOME=/var/tmp/omg-extra-nobody/cache \
    XDG_DATA_HOME=/var/tmp/omg-extra-nobody/data XDG_STATE_HOME=/var/tmp/omg-extra-nobody/state \
    XDG_RUNTIME_DIR=/var/tmp/omg-extra-nobody/run \
    OMG_CONFIG_DIR=/var/tmp/omg-extra-nobody/config/omg OMG_CACHE_DIR=/var/tmp/omg-extra-nobody/cache/omg \
    OMG_DATA_DIR=/var/tmp/omg-extra-nobody/data/omg OMG_DAEMON_DATA_DIR=/var/tmp/omg-extra-nobody/daemon \
    OMG_DISABLE_TELEMETRY=1 OMG_DISABLE_DAEMON=1 \
    OMG_CONTRACT_REQUIRE_NATIVE_ARCH=1 OMG_CONTRACT_EXPECTED_CLI=COMPILED_CLI \
    OMG_CONTRACT_CLI_ROOT_FIXTURE=/omg-extra-bin/cli-receipt.json \
    OMG_CLI_BEHAVIOR_EVIDENCE_DIR=/evidence/cli/inventory "$@"
}
ordinary bash -c 'test "$(id -u)" -ne 0; umask 077; mkdir -p "$HOME/work" "$XDG_RUNTIME_DIR" "$OMG_CONFIG_DIR"; printf "telemetry_enabled = false\n" > "$OMG_CONFIG_DIR/config.toml"'
ordinary bash -c 'missing=0; for tool in git make jq cmp; do if ! command -v "$tool"; then printf "Missing native fixture command: %s\n" "$tool" >&2; missing=1; fi; done; exit "$missing"' > /evidence/cli/prerequisites.txt
for role in coverage14 arch-contracts comprehensive cli-unit; do
  LLVM_PROFILE_FILE="/profiles/omg-extra-registry-$role-%p-%m.profraw" \
    /omg-extra-bin/"$role" --list --format terse > /evidence/cli/registry-"$role".txt 2>&1
done
while IFS=$'\t' read -r stage role name; do
  registry=/evidence/cli/registry-$role.txt
  test "$(grep -Fxc "$name: test" "$registry")" = 1
  log=/evidence/cli/$stage.log
  if test "$role" = cli-unit; then
    timeout --signal=TERM --kill-after=3 45 env -i PATH=/usr/bin:/bin LANG=C.UTF-8 \
      HOME=/var/tmp/omg-extra-root OMG_DATA_DIR=/var/tmp/omg-extra-root/data OMG_NATIVE_TEST_DATA_DIR=1 \
      OMG_DISABLE_TELEMETRY=1 LLVM_PROFILE_FILE="/profiles/omg-extra-$stage-%p-%m.profraw" \
      bash -c 'cd "$HOME"; test "$(id -u)" = 0; printf "[extra-root-test] uid=%s\n" "$(id -u)"; exec "$@"' \
      bash /omg-extra-bin/"$role" "$name" --exact --nocapture --test-threads=1 < /dev/null > "$log" 2>&1
  else
    limit=45
    if test "$role" = comprehensive; then limit=360; fi
    timeout --signal=TERM --kill-after=3 "$limit" \
      bash -c 'ordinary env LLVM_PROFILE_FILE="$1" bash -c '\''cd "$HOME/work"; test "$(id -u)" -ne 0; exec "$@"'\'' bash "$2" "$3" --exact --nocapture --test-threads=1' \
      bash "/profiles/omg-extra-$stage-%p-%m.profraw" "/omg-extra-bin/$role" "$name" < /dev/null > "$log" 2>&1
  fi
  grep -Eq '^test result: ok\. 1 passed; 0 failed; 0 ignored;' "$log"
  ! grep -E '\[omg-skip\]|\[native-arch-fixture-skip\]|\[native-inventory-unavailable\]|LLVM Profile (Error|Warning)' "$log"
  if test "$role" != cli-unit; then
    grep -Eq '\[native-arch-fixture\] uid=[1-9][0-9]* actual_id=arch' "$log"
  fi
  printf '%s\t%s\t%s\tPASS\n' "$stage" "$role" "$name" >> /evidence/cli/passed.tsv
done < /evidence/cli/expected-tests.tsv
for flags in q v vv vvv; do
  ordinary env LLVM_PROFILE_FILE="/profiles/omg-extra-cli-$flags-%p-%m.profraw" \
    bash -c 'cd "$HOME/work"; test -z "${RUST_LOG+x}"; exec /omg-extra-bin/cli "-$1" config' bash "$flags" \
    > /evidence/cli/cli-"$flags".log 2>&1
  printf 'cli-%s\t0\n' "$flags" >> /evidence/cli/process-checks.tsv
done
ordinary env LLVM_PROFILE_FILE='/profiles/omg-extra-daemon-%p-%m.profraw' RUST_LOG='[' \
  timeout --signal=TERM --kill-after=3 40 bash -c '
    set -euo pipefail
    test "$(id -u)" -ne 0
    cd "$HOME/work"
    socket="$XDG_RUNTIME_DIR/extra.sock"
    /omg-extra-bin/daemon --socket "$socket" &
    child=$!
    trap '\''kill -TERM "$child" 2>/dev/null || true; wait "$child" 2>/dev/null || true'\'' EXIT
    ready=0
    for ((i=0;i<100;i++)); do
      kill -0 "$child"
      if test -S "$socket"; then ready=1; break; fi
      sleep 0.1
    done
    test "$ready" = 1
    test "$(stat -c %u "$socket")" = "$(id -u)"
    printf "[extra-daemon] startup_socket=ready uid=%s\n" "$(id -u)"
    kill -TERM "$child"
    wait "$child"
    test ! -e "$socket"
    trap - EXIT
    printf "[extra-daemon] sigterm_exit=0 socket_removed=yes\n"
  ' > /evidence/cli/daemon.log 2>&1
printf 'daemon\t0\n' >> /evidence/cli/process-checks.tsv
OMARCHY_CASE_BODY
OMG_EXTRA_NAMESPACE
fingerprint_db > /evidence/cli/db-after.txt
cmp /evidence/cli/db-before.txt /evidence/cli/db-after.txt
trap - EXIT
printf 'PASS\n' > /evidence/cli/all-stages-pass.txt
'''
    script = script.replace('RECEIPT', quote(receipt)).replace('ARTIFACTS', quote(artifact_lines))
    script = script.replace('SELECTION', quote(selection)).replace('COMPILED_CLI', quote(compiled_cli))
    script = script.replace('OMARCHY_CASE_BODY', omarchy_guest_script())
    # The timeout shell inherits this function, never a caller-supplied environment.
    script = script.replace('ordinary bash -c', 'export -f ordinary\nordinary bash -c', 1)
    return script


def validate_evidence(evidence, profiles, artifacts, commit):
    require(evidence.is_dir() and not evidence.is_symlink(), 'Unsafe supplemental evidence directory')
    evidence_files = list(evidence.rglob('*'))
    require(len(evidence_files) <= 8192, 'Supplemental evidence has too many files')
    for path in evidence_files:
        require(not path.is_symlink() and (path.is_dir() or path.is_file()), 'Unsafe evidence member')
        require(not path.is_file() or path.stat().st_size <= 16 * 1024 ** 2,
                'Supplemental evidence member exceeds 16 MiB')
    require((evidence / 'all-stages-pass.txt').read_text() == 'PASS\n', 'Guest did not complete every stage')
    expected = ['\t'.join(row) for row in CASES]
    require((evidence / 'expected-tests.tsv').read_text().splitlines() == expected, 'Guest selection mismatch')
    require((evidence / 'passed.tsv').read_text().splitlines() == [row + '\tPASS' for row in expected], 'Incomplete/reordered tests')
    require((evidence / 'process-checks.tsv').read_text().splitlines() == [s + '\t0' for s in PROCESS_STAGES], 'Process checks incomplete')
    require((evidence / 'db-before.txt').read_bytes() == (evidence / 'db-after.txt').read_bytes(), 'Real guest package DB changed')
    require(re.fullmatch(r'actual_id=arch ordinary_uid=[1-9][0-9]* root_uid=0\n', (evidence / 'identity.txt').read_text()), 'Guest UID/distro identity differs')
    require((evidence / 'artifacts.sha256').read_text().splitlines() == [f"{a['sha256']}  /omg-extra-bin/{r}" for r, a in artifacts.items()], 'Guest artifact hash receipt mismatch')
    for role in ROLES:
        require('not found' not in (evidence / f'abi-{role}.txt').read_text(), 'Missing ABI dependency')
    grouped = {stage: [] for stage in STAGES}
    selected_profiles = list(profiles.glob('omg-extra-*.profraw'))
    require(len(selected_profiles) <= 8192, 'Supplemental profiles have too many files')
    for path in selected_profiles:
        match = PROFILE.fullmatch(path.name)
        require(match and path.is_file() and not path.is_symlink()
                and 0 < path.stat().st_size <= 64 * 1024 ** 2, 'Unsafe or empty raw profile')
        with path.open('rb') as raw:
            require(raw.read(8) == bytes.fromhex('8172666f72706cff'), 'Not an x86_64 LLVM raw profile')
        grouped[match[1]].append(path)
    require(all(grouped.values()), 'One or more stages have no raw profiles')
    require(sum(p.stat().st_size for rows in grouped.values() for p in rows) <= 512 * 1024 ** 2,
            'Supplemental profiles exceed the 512 MiB return budget')
    cli_modules = {PROFILE.fullmatch(p.name)[3] for p in grouped['cli-q']}
    require(len(cli_modules) == 1, 'Safe CLI identity must produce one module signature')
    suite = ET.Element('testsuite', name='extra-native-coverage', tests=str(len(CASES)))
    tests = []
    for stage, role, name in CASES:
        require((evidence / f'registry-{role}.txt').read_text().splitlines().count(name + ': test') == 1, 'Test registry mismatch')
        log = (evidence / f'{stage}.log').read_text()
        require(len(re.findall(r'^test result: ok\. 1 passed; 0 failed; 0 ignored;', log, re.M)) == 1, 'Test not exactly one PASS')
        require(len(re.findall(r'^test ' + re.escape(name) + r' \.\.\.', log, re.M)) == 1, 'Selected test execution missing/duplicated')
        require(not re.search(r'\[omg-skip\]|\[native-arch-fixture-skip\]|\[native-inventory-unavailable\]|LLVM Profile (Error|Warning)', log), 'Skip/LLVM diagnostic')
        modules = {PROFILE.fullmatch(p.name)[3] for p in grouped[stage]}
        if role != 'cli-unit':
            require(re.search(r'\[native-arch-fixture\] uid=[1-9][0-9]* actual_id=arch', log), 'Missing native ordinary admission')
            require(cli_modules <= modules and len(modules) >= 2, 'Missing matching child CLI/harness raw profiles')
        else:
            require('[extra-root-test] uid=0' in log, 'Root receiver branch not admitted')
        ET.SubElement(suite, 'testcase', name=name, classname=role)
        tests.append(dict(stage=stage, role=role, name=name, result='PASS'))
    inventory = (evidence / 'test-13.log').read_text()
    require('[native-inventory-coverage] unavailable_rows=0;' in inventory, 'Inventory native rows unavailable')
    rows = (evidence / 'inventory/index.tsv').read_text().splitlines()
    for name in ('why', 'why-reverse', 'size', 'size-tree', 'blame'):
        matches = [line.split('\t') for line in rows[1:] if line.split('\t')[0] == name]
        require(len(matches) == 1 and matches[0][3] == matches[0][4] and matches[0][-2] == 'none'
                and matches[0][-1] != 'unavailable', 'Missing/failed native inventory row: ' + name)
    daemon = (evidence / 'daemon.log').read_text()
    require('[extra-daemon] startup_socket=ready uid=' in daemon and '[extra-daemon] sigterm_exit=0 socket_removed=yes' in daemon, 'Daemon lifecycle incomplete')
    for stage, (status, helpers) in OMARCHY_CASES.items():
        require((evidence / f'{stage}-exit.txt').read_text() == f'{status}\n',
                'Omarchy CLI exit status differs: ' + stage)
        require((evidence / f'{stage}-helpers.tsv').read_text().splitlines() == list(helpers),
                'Omarchy helper execution differs: ' + stage)
        modules = {PROFILE.fullmatch(p.name)[3] for p in grouped[stage]}
        require(modules == cli_modules, 'Omarchy profiles do not match the actual CLI: ' + stage)
        log = (evidence / f'{stage}.log').read_text()
        if helpers:
            require((evidence / f'{stage}-coordination.txt').read_text()
                    == 'released private lock; owned transcript mode=600\n',
                    'Omarchy coordination cleanup differs: ' + stage)
            transcript = (evidence / f'{stage}-transcript.log').read_text()
            require(transcript.startswith('OMG Omarchy update started\n')
                    and '\nOMG Omarchy update finished: ' in transcript,
                    'Omarchy has no complete genuine PTY transcript: ' + stage)
        if stage in ('omarchy-success', 'omarchy-optional-failures'):
            require('up to date' in log.lower(),
                    'Native OMG AUR did not complete: ' + stage)
        if stage == 'omarchy-optional-failures':
            require((evidence / f'{stage}-layout.txt').read_text()
                    == 'foreign optional helpers never executed; original helpers restored\n',
                    'Optional Omarchy helper layout exclusion differs')
            require('snapshot' in log.lower() and 'mise' in log.lower(),
                    'Optional Omarchy update failures were not visible: ' + stage)
        elif stage == 'omarchy-vendor-failure':
            require('Omarchy update did not complete' in log, 'Missing vendor failure diagnostic')
        elif stage == 'omarchy-migration-refusal':
            require('external AUR helper' in log, 'Missing native-AUR migration refusal')
        elif stage == 'omarchy-unsupported-mode':
            require('complete update lifecycle' in log, 'Unsupported Omarchy scope accepted')
        elif stage == 'omarchy-invalid-transport':
            require('Incomplete Omarchy update transport' in log, 'Incomplete transport accepted')
    for path in evidence.rglob('*'):
        if path.is_file():
            require(not re.search(rb'LLVM Profile (Error|Warning)', path.read_bytes()), 'LLVM runtime diagnostic in evidence')
    ET.ElementTree(suite).write(evidence / 'tests.xml', encoding='unicode', xml_declaration=True)
    selected = sorted(path for paths in grouped.values() for path in paths)
    (evidence / 'verification.json').write_text(json.dumps(dict(source_commit=commit, tests=tests,
        process_checks=list(PROCESS_STAGES), artifacts=artifacts,
        profiles=[dict(name=p.name, bytes=p.stat().st_size, sha256=sha(p)) for p in selected]), indent=2) + '\n')
    return selected


def prepare(target, commit):
    require(re.fullmatch(r'[0-9a-f]{40}', commit), 'Expected a full source commit')
    target = target.resolve(strict=True)
    require(target.is_dir(), 'Coverage target is absent')
    paths = {'cli': target / 'debug/omg', 'daemon': target / 'debug/omgd'}
    for role, prefix in (('coverage14', 'coverage_14'), ('arch-contracts', 'arch_cli_contracts'),
                         ('comprehensive', 'cli_comprehensive'), ('cli-unit', 'omg')):
        matches = [path for path in (target / 'debug/deps').glob(prefix + '-*')
                   if re.fullmatch(re.escape(prefix) + r'-[0-9a-f]{16}', path.name)
                   and path.is_file() and not path.is_symlink() and os.access(path, os.X_OK)
                   and not path.samefile(paths['cli'])]
        require(len(matches) == 1, 'Expected exactly one instrumented harness for ' + role)
        paths[role] = matches[0]
    require(len({(path.stat().st_dev, path.stat().st_ino) for path in paths.values()}) == len(ROLES),
            'Supplemental artifact roles must be distinct')
    artifacts = {}
    for role, path in paths.items():
        require(path.resolve(strict=True) == path and path.is_relative_to(target),
                'Artifact source escapes the canonical coverage target: ' + role)
        require(path.is_file() and not path.is_symlink() and os.access(path, os.X_OK),
                'Unsafe or absent artifact: ' + role)
        require(0 < path.stat().st_size <= 512 * 1024 ** 2, 'Artifact size exceeds bound: ' + role)
        sections = subprocess.run(['readelf', '--wide', '--section-headers', str(path)],
                                  check=True, capture_output=True, text=True, timeout=30).stdout
        require('__llvm_covmap' in sections and '__llvm_prf' in sections,
                'Artifact lacks LLVM instrumentation: ' + role)
        artifacts[role] = dict(path=str(path), sha256=sha(path), bytes=path.stat().st_size)
    return dict(source_commit=commit, producer_sha256=sha(Path(__file__)), artifacts=artifacts)


def read_manifest(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 65536,
            'Unsafe or oversized supplemental manifest')
    value = json.loads(path.read_text())
    require(set(value) == {'source_commit', 'producer_sha256', 'artifacts'}, 'Unknown manifest schema')
    require(re.fullmatch(r'[0-9a-f]{40}', value['source_commit']), 'Invalid source identity')
    require(value['producer_sha256'] == sha(Path(__file__)), 'Producer source changed after admission')
    require(set(value['artifacts']) == set(ROLES), 'Supplemental artifacts are incomplete')
    for role, artifact in value['artifacts'].items():
        require(set(artifact) == {'path', 'sha256', 'bytes'}, 'Unknown artifact schema: ' + role)
        require(Path(artifact['path']).is_absolute(), 'Artifact source path must be absolute')
        require(re.fullmatch(r'[0-9a-f]{64}', artifact['sha256']), 'Invalid artifact digest')
        require(type(artifact['bytes']) is int and 0 < artifact['bytes'] <= 512 * 1024 ** 2,
                'Invalid artifact byte bound')
    return value


def run_guest(manifest):
    require(os.geteuid() == 0, 'Supplemental execution requires a disposable root guest')
    directory = Path('/omg-extra-bin')
    paths = [directory, Path(__file__), Path('/native-cli-manifest.json')]
    paths += [directory / role for role in ROLES]
    for path in paths:
        info = path.lstat()
        require(not stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o022 == 0,
                'Supplemental input is writable or not root-owned: ' + str(path))
    for role, artifact in manifest['artifacts'].items():
        path = directory / role
        require(path.is_file() and path.stat().st_size == artifact['bytes']
                and sha(path) == artifact['sha256'], 'Copied artifact identity differs: ' + role)
    script = guest_script(manifest['artifacts'], manifest['artifacts']['cli']['path'])
    subprocess.run(['bash', '-euo', 'pipefail', '-c', script], check=True, timeout=660)
    for role, artifact in manifest['artifacts'].items():
        require(sha(directory / role) == artifact['sha256'], 'Artifact changed during execution: ' + role)
    validate_evidence(Path('/evidence/cli'), Path('/profiles'), manifest['artifacts'], manifest['source_commit'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='operation', required=True)
    admission = commands.add_parser('prepare')
    admission.add_argument('--target', required=True, type=Path)
    admission.add_argument('--source-commit', required=True)
    admission.add_argument('--output', required=True, type=Path)
    commands.add_parser('run')
    verification = commands.add_parser('verify')
    verification.add_argument('--manifest', required=True, type=Path)
    verification.add_argument('--evidence', required=True, type=Path)
    verification.add_argument('--profiles', required=True, type=Path)
    args = parser.parse_args()
    if args.operation == 'prepare':
        value = prepare(args.target, args.source_commit)
        with args.output.open('x') as stream:
            json.dump(value, stream, indent=2)
            stream.write('\n')
    elif args.operation == 'run':
        run_guest(read_manifest(Path('/native-cli-manifest.json')))
    else:
        manifest = read_manifest(args.manifest)
        validate_evidence(args.evidence, args.profiles, manifest['artifacts'], manifest['source_commit'])


if __name__ == '__main__':
    main()
