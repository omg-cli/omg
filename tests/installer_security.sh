#!/usr/bin/env bash
# Exercise the real installer functions with isolated transport/tool fixtures.
set -euo pipefail
# Every assertion below aborts the run on failure. Report which command failed
# (and, inside the scenario loop, which scenario) so a hosted flake is
# diagnosable from the job log alone.
set -E
unset OMG_UNINSTALL
trap 'printf "installer_security: command failed (exit %s): %s\n" "$?" "$BASH_COMMAND" >&2' ERR
# A killed probe needs a moment to actually die on a loaded runner. The
# invariant is unchanged: nothing may survive the probe.
wait_until_dead() {
  local pid=$1 attempt
  for attempt in $(seq 1 25); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.2
  done
  return 1
}
cd "$(dirname "$0")/.."
bash tests/installer_source_features.sh
bash tests/native_make_targets.sh
bash tests/installer_preflight.sh
bash tests/installer_archive.sh
task_dir=$(mktemp -d)
trap 'rm -rf "$task_dir"' EXIT
sed '$d' install.sh > "$task_dir/functions.sh"
for scenario in missing rejected wrong_tag accepted accepted_fedora loader_error wrong_version missing_daemon daemon_loader_error hung_probe forked_probe second_install_failure \
    marker_invalid temp_failure archive_transport archive_over_limit sidecar_transport sidecar_over_limit sidecar_format sidecar_mismatch attestation_timeout; do
  (
    set --
    source "$task_dir/functions.sh"
    trap - EXIT
    set -e
    trap 'printf "installer_security: scenario %s: command failed (exit %s): %s\n" "$scenario" "$?" "$BASH_COMMAND" >&2' ERR
    scenario_dir="$task_dir/$scenario"
    mkdir -p "$scenario_dir"
    INSTALL_DIR="$scenario_dir/bin"
    OMG_VERSION=v1.2.3
    # Bash SECONDS has one-second resolution; a one-second deadline can expire
    # before a loaded runner starts the probe and writes its process receipt.
    MAX_VERSION_PROBE_SECONDS=2
    MAX_ATTESTATION_SECONDS=2
    case "$scenario" in
      accepted_fedora | marker_invalid) OMG_VERSION=latest ;;
      archive_over_limit) MAX_ARCHIVE_BYTES=16 ;;
      sidecar_over_limit) MAX_CHECKSUM_BYTES=80 ;;
    esac
    case "$scenario" in
      loader_error | wrong_version | missing_daemon | daemon_loader_error | hung_probe | forked_probe | second_install_failure)
        mkdir -p "$INSTALL_DIR"
        printf 'previous cli\n' > "$INSTALL_DIR/omg"
        printf 'previous daemon\n' > "$INSTALL_DIR/omgd"
        ;;
    esac
    for name in start_spinner stop_spinner fail_spinner header info success; do
      eval "$name() { :; }"
    done
    check_runtime_dependencies() { return 0; }
    if [[ "$scenario" == temp_failure ]]; then mktemp() { return 1; }; fi
    detect_os() { echo linux; }
    fake_distro=arch
    [[ "$scenario" != accepted_fedora ]] || fake_distro=fedora
    detect_distro() { printf '%s\n' "$fake_distro"; }
    detect_arch() { echo x86_64; }
    if [[ "$scenario" == wrong_tag ]]; then
      resolve_version() { printf 'v1.2.2\n'; }
    fi
    curl() {
      local url="${@: -1}" resource
      case "$url" in
        "$LATEST_VERSION_URL") resource=marker ;;
        *.sha256) resource=sidecar ;;
        "$RELEASES_BASE_URL/omg-v1.2.3-x86_64-linux-$fake_distro.tar.gz") resource=archive ;;
        *) printf 'Unexpected fixture URL: %s\n' "$url" >&2; return 1 ;;
      esac
      printf '%s\n' "$@" > "$scenario_dir/request-$resource"
      case "$scenario/$resource" in
        marker_invalid/marker) printf 'v1.2.3\n' ;;
        archive_transport/archive | sidecar_transport/sidecar)
          printf 'partial'
          return 28 ;;
        archive_over_limit/archive) printf '%017d' 0 ;;
        sidecar_over_limit/sidecar) printf '%081d' 0 ;;
        sidecar_format/sidecar) printf 'not-a-checksum\n' ;;
        sidecar_mismatch/sidecar) printf '%064d  archive\n' 1 ;;
        */marker) printf '1.2.3\r\n' ;;
        */archive) cat "$scenario_dir/fixture.tar.gz" ;;
        */sidecar) printf '%064d  archive\n' 0 ;;
      esac
    }
    calculate_sha256() { printf '%064d\n' 0; }
    printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$@" > "%s/gh-args"\n[[ "%s" != rejected ]]\n' \
      "$scenario_dir" "$scenario" > "$scenario_dir/gh"
    if [[ "$scenario" == attestation_timeout ]]; then
      printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$$" > "%s/gh-pid"\nexec sleep 5\n' \
        "$scenario_dir" > "$scenario_dir/gh"
    fi
    chmod +x "$scenario_dir/gh"
    trusted_gh() {
      [[ "$scenario" != missing ]] || return 1
      printf '%s\n' "$scenario_dir/gh"
    }
    prepare_release_fixture() {
      mkdir "$scenario_dir/payload"
      printf '#!/bin/sh\nprintf "omg 1.2.3\\n"\n' > "$scenario_dir/payload/omg"
      if [[ "$scenario" == loader_error ]]; then
        printf '#!/bin/sh\necho "missing libapt-pkg.so.6.0" >&2\nexit 127\n' > "$scenario_dir/payload/omg"
      elif [[ "$scenario" == wrong_version ]]; then
        printf '#!/bin/sh\nprintf "omg 1.2.2\\n"\n' > "$scenario_dir/payload/omg"
      elif [[ "$scenario" == hung_probe ]]; then
        printf '#!/bin/sh\necho "$$" > "%s/probe.pid"\nexec sleep 30\n' "$scenario_dir" > "$scenario_dir/payload/omg"
      elif [[ "$scenario" == forked_probe ]]; then
        printf '#!/bin/sh\n(while :; do printf x >> "%s/descendant.heartbeat"; sleep 0.01; done) >/dev/null 2>&1 &\necho "$!" > "%s/descendant.pid"\nwhile [ ! -s "%s/descendant.heartbeat" ]; do :; done\nprintf "omg 1.2.3\\n"\n' "$scenario_dir" "$scenario_dir" "$scenario_dir" > "$scenario_dir/payload/omg"
      fi
      chmod +x "$scenario_dir/payload/omg"
      if [[ "$scenario" != missing_daemon ]]; then
        printf '#!/bin/sh\nprintf "omgd 1.2.3\\n"\n' > "$scenario_dir/payload/omgd"
        if [[ "$scenario" == daemon_loader_error ]]; then
          printf '#!/bin/sh\necho "daemon missing native library" >&2\nexit 127\n' > "$scenario_dir/payload/omgd"
        fi
        chmod +x "$scenario_dir/payload/omgd"
      fi
      command tar -czf "$scenario_dir/fixture.tar.gz" -C "$scenario_dir/payload" .
    }
    prepare_release_fixture
    tar() {
      touch "$scenario_dir/extracted"
      command tar "$@"
    }
    if [[ "$scenario" == second_install_failure ]]; then
      eval "$(declare -f rename_install_binary | sed '1s/^rename_install_binary/real_release_rename/')"
      rename_install_binary() {
        [[ "$1" != */new-omgd ]] || return 1
        real_release_rename "$@"
      }
    fi
    if install_from_release > "$scenario_dir/output" 2>&1; then status=0; else status=$?; fi
    if [[ "$scenario" == accepted || "$scenario" == accepted_fedora ]]; then
      [[ "$status" == 0 && -x "$INSTALL_DIR/omg" && -x "$INSTALL_DIR/omgd" ]]
      [[ $("$INSTALL_DIR/omg" --version) == 'omg 1.2.3' ]]
      [[ $("$INSTALL_DIR/omgd" --version) == 'omgd 1.2.3' ]]
      grep -Fx -- '--source-ref' "$scenario_dir/gh-args"
      grep -Fx 'refs/tags/v1.2.3' "$scenario_dir/gh-args"
      grep -Fx 'omg-cli/omg/.github/workflows/release.yml' "$scenario_dir/gh-args"
      grep -F '/omg-v1.2.3-x86_64-linux-' "$scenario_dir/gh-args" |
        grep -Fq "linux-$fake_distro.tar.gz"
      if [[ "$scenario" == accepted_fedora ]]; then
        for resource in marker archive sidecar; do
          case "$resource" in
            marker) url="$LATEST_VERSION_URL"; bytes=256; seconds=20 ;;
            archive) url="$RELEASES_BASE_URL/omg-v1.2.3-x86_64-linux-fedora.tar.gz"; bytes=268435456; seconds=300 ;;
            sidecar) url="$RELEASES_BASE_URL/omg-v1.2.3-x86_64-linux-fedora.tar.gz.sha256"; bytes=1024; seconds=20 ;;
          esac
          cmp <(printf '%s\n' --disable -fsSL --proto '=https' --proto-redir '=https' \
            --connect-timeout 10 --max-time "$seconds" --max-filesize "$bytes" "$url") \
            "$scenario_dir/request-$resource"
          printf 'PASS: Fedora %s request protocol and deadlines\n' "$resource"
        done
      fi
      printf 'PASS: authenticated %s release fixture installed both binaries\n' "$fake_distro"
    elif [[ "$scenario" == loader_error || "$scenario" == wrong_version || "$scenario" == missing_daemon || "$scenario" == daemon_loader_error || "$scenario" == hung_probe || "$scenario" == forked_probe || "$scenario" == second_install_failure ]]; then
      if [[ "$status" == 0 ]]; then
        printf 'Installer accepted unusable pair: %s\n' "$scenario" >&2
        exit 1
      fi
      [[ $(cat "$INSTALL_DIR/omg") == 'previous cli' ]]
      [[ $(cat "$INSTALL_DIR/omgd") == 'previous daemon' ]]
      case "$scenario" in
        loader_error) grep -F 'missing libapt-pkg.so.6.0' "$scenario_dir/output" ;;
        wrong_version) grep -F 'does not report omg 1.2.3' "$scenario_dir/output" ;;
        missing_daemon) grep -F 'missing omgd binary' "$scenario_dir/output" ;;
        daemon_loader_error) grep -F 'daemon missing native library' "$scenario_dir/output" ;;
        hung_probe)
          grep -F 'omg version probe timed out' "$scenario_dir/output"
          [[ -s "$scenario_dir/probe.pid" ]]
          if ! wait_until_dead "$(cat "$scenario_dir/probe.pid")"; then
            printf 'Hung version probe was left running\n' >&2
            exit 1
          fi
          ;;
        forked_probe)
          grep -F 'omg version probe left descendant processes running' "$scenario_dir/output"
          [[ -s "$scenario_dir/descendant.pid" ]]
          if ! wait_until_dead "$(cat "$scenario_dir/descendant.pid")"; then
            kill -KILL "$(cat "$scenario_dir/descendant.pid")" 2>/dev/null || true
            printf 'Forked version probe descendant was left running\n' >&2
            exit 1
          fi
          heartbeat_before=$(wc -c < "$scenario_dir/descendant.heartbeat")
          sleep 0.1
          heartbeat_after=$(wc -c < "$scenario_dir/descendant.heartbeat")
          if [[ "$heartbeat_after" != "$heartbeat_before" ]]; then
            printf 'Forked version probe descendant kept writing after the probe\n' >&2
            exit 1
          fi
          ;;
      esac
    else
      [[ "$status" != 0 && ! -e "$scenario_dir/extracted" && ! -e "$INSTALL_DIR/omg" ]]
      case "$scenario" in
        marker_invalid)
          [[ "$status" == 1 && ! -e "$scenario_dir/request-archive" ]]
          grep -Fq 'not a valid bare semantic version' "$scenario_dir/output" ;;
        temp_failure)
          [[ "$status" == 1 && ! -e "$scenario_dir/request-archive" ]]
          grep -Fq 'Failed to create a private release directory' "$scenario_dir/output" ;;
        archive_transport)
          [[ "$status" == 1 && ! -e "$scenario_dir/request-sidecar" ]] ;;
        archive_over_limit)
          [[ "$status" == 1 && ! -e "$scenario_dir/request-sidecar" ]]
          grep -Fq 'exceeded the 16 byte bound' "$scenario_dir/output" ;;
        sidecar_transport)
          [[ "$status" == 2 ]]
          grep -Fq 'Unable to fetch .sha256 sidecar' "$scenario_dir/output" ;;
        sidecar_over_limit)
          [[ "$status" == 2 ]]
          grep -Fq 'exceeded the 80 byte bound' "$scenario_dir/output" ;;
        sidecar_format)
          [[ "$status" == 2 ]]
          grep -Fq 'is malformed' "$scenario_dir/output" ;;
        sidecar_mismatch)
          [[ "$status" == 2 ]]
          grep -Fq 'does not match its published sha256' "$scenario_dir/output" ;;
        attestation_timeout)
          [[ "$status" == 2 && -s "$scenario_dir/gh-pid" ]]
          grep -Fq 'Build provenance verification timed out' "$scenario_dir/output"
          if grep -Fq 'Possible supply-chain tampering' "$scenario_dir/output"; then exit 1; fi
          wait_until_dead "$(cat "$scenario_dir/gh-pid")" ;;
      esac
      case "$scenario" in
        marker_invalid | temp_failure | archive_* | sidecar_*)
          [[ ! -e "$scenario_dir/gh-args" ]]
          printf 'PASS: release refusal %s\n' "$scenario" ;;
        attestation_timeout) printf 'PASS: release refusal %s\n' "$scenario" ;;
      esac
    fi
  )
done
# Replace an initially absent destination with a directory after its pre-check,
# during staging. The real final rename must fail without touching its child.
for rename_platform in native darwin; do
  (
    set --
    source "$task_dir/functions.sh"
    trap - EXIT
    set -e
    INSTALL_DIR="$task_dir/raced-$rename_platform"
    mkdir -p "$INSTALL_DIR"
    printf 'new binary\n' > "$INSTALL_DIR/source"
    if [[ "$rename_platform" == darwin ]]; then
      uname() { printf 'Darwin\n'; }
    fi
    rename_install_binary "$INSTALL_DIR/source" "$INSTALL_DIR/control"
    [[ $(cat "$INSTALL_DIR/control") == 'new binary' ]]
    printf 'updated binary\n' > "$INSTALL_DIR/source"
    rename_install_binary "$INSTALL_DIR/source" "$INSTALL_DIR/control"
    [[ $(cat "$INSTALL_DIR/control") == 'updated binary' ]]
    printf 'new binary\n' > "$INSTALL_DIR/source"
    cp() {
      command cp "$@"
      mkdir "$INSTALL_DIR/omg"
      printf 'untouched\n' > "$INSTALL_DIR/omg/omg"
    }
    if install_binary_pair "$INSTALL_DIR/source" "$INSTALL_DIR/omg" \
        "$INSTALL_DIR/source" "$INSTALL_DIR/omgd"; then
      printf 'Installer followed a directory swapped in during staging\n' >&2
      exit 1
    fi
    [[ $(cat "$INSTALL_DIR/omg/omg") == untouched ]]
    [[ $(find "$INSTALL_DIR/omg" -type f | wc -l) -eq 1 ]]
    printf 'PASS: %s direct rename and directory-swap controls\n' "$rename_platform"
  )
done
# The final move must replace a destination symlink, never install inside its
# directory target. Exercise the real install function, including regular updates.
(
  set --
  source "$task_dir/functions.sh"
  trap - EXIT
  set -e
  INSTALL_DIR="$task_dir/atomic-bin"
  mkdir -p "$INSTALL_DIR" "$task_dir/outside"
  printf 'new binary\n' > "$task_dir/source"
  printf 'untouched\n' > "$task_dir/outside/omg"
  ln -s "$task_dir/outside" "$INSTALL_DIR/omg"
  install_binary_pair "$task_dir/source" "$INSTALL_DIR/omg" \
    "$task_dir/source" "$INSTALL_DIR/omgd"
  [[ ! -L "$INSTALL_DIR/omg" && -f "$INSTALL_DIR/omg" ]]
  [[ $(cat "$task_dir/outside/omg") == untouched ]]
  printf 'updated binary\n' > "$task_dir/source"
  install_binary_pair "$task_dir/source" "$INSTALL_DIR/omg" \
    "$task_dir/source" "$INSTALL_DIR/omgd"
  cmp "$task_dir/source" "$INSTALL_DIR/omg"
  rm "$INSTALL_DIR/omgd"
  mkdir "$INSTALL_DIR/omgd"
  if install_binary_pair "$task_dir/source" "$INSTALL_DIR/omg" \
      "$task_dir/source" "$INSTALL_DIR/omgd"; then
    printf 'Installer accepted a directory destination\n' >&2
    exit 1
  fi
  [[ ! -e "$INSTALL_DIR/omgd/source" && ! -e "$INSTALL_DIR/omgd/omgd" ]]
)
# Exercise the production pair operation through pre-publication, publication
# and recovery failures. Compare the original file identities as well as data.
exercise_pair_transaction() {
  local initial="$1" fault="$2"
  local pair_root="$task_dir/pair-$initial-$fault"
  local binary installed original staged_backup status=0
  set --
  source "$task_dir/functions.sh"
  trap - EXIT
  eval "$(declare -f rename_install_binary | sed '1s/^rename_install_binary/real_pair_rename/')"
  mkdir -p "$pair_root"/{bin,originals} || return 1
  INSTALL_DIR="$pair_root/bin"
  for binary in omg omgd; do
    printf '#!/bin/sh\nprintf "new %s\n"\n' "$binary" > "$pair_root/$binary" || return 1
    case "$initial/$binary" in
      empty/* | cli-only/omgd) continue ;;
    esac
    original="$pair_root/originals/$binary"
    printf 'old %s\n' "$binary" > "$original" || return 1
    if [[ "$initial" == symlinks ]]; then
      ln -s "$original" "$INSTALL_DIR/$binary" || return 1
    else
      ln "$original" "$INSTALL_DIR/$binary" || return 1
    fi
  done
  cp() {
    local source="${@: -2:1}"
    if [[ "$source" == "$pair_root/omg" && "$fault" == copy-cli ]] ||
       [[ "$source" == "$pair_root/omgd" && "$fault" == copy-daemon ]]; then
      return 1
    fi
    command cp "$@"
  }
  chmod() {
    case "${@: -1}" in
      */omg|*/new-omg) [[ "$fault" != mode-cli ]] || return 1 ;;
      */omgd|*/new-omgd) [[ "$fault" != mode-daemon ]] || return 1 ;;
    esac
    command chmod "$@"
  }
  rename_install_binary() {
    case "$1" in
      */new-omg | */omg)
        printf 'omg\n' >> "$pair_root/publication"
        [[ "$fault" != publish-cli ]] || return 1
        ;;
      */new-omgd | */omgd)
        printf 'omgd\n' >> "$pair_root/publication"
        [[ "$fault" != publish-daemon && "$fault" != blocked-restore ]] || return 1
        ;;
      */old-omg | */first-backup)
        [[ "$fault" != blocked-restore ]] || return 1
        ;;
    esac
    real_pair_rename "$@" || return 1
    case "$fault/${1##*/}" in
      after-cli/omg | after-cli/new-omg | after-daemon/omgd | after-daemon/new-omgd)
        return 1 ;;
      term-after-cli/omg | term-after-cli/new-omg | term-after-daemon/omgd | term-after-daemon/new-omgd)
        command sh -c 'kill -TERM "$PPID"' ;;
    esac
    return 0
  }
  install_binary_pair "$pair_root/omg" "$INSTALL_DIR/omg" "$pair_root/omgd" "$INSTALL_DIR/omgd" \
    > "$pair_root/result" 2>&1 || status=$?
  if [[ "$fault" == success ]]; then
    [[ "$status" == 0 ]] || return 1
    for binary in omg omgd; do
      installed="$INSTALL_DIR/$binary"
      [[ ! -L "$installed" && -x "$installed" ]] || return 1
      [[ $("$installed") == "new $binary" ]] || return 1
    done
  elif [[ "$fault" == blocked-restore ]]; then
    [[ "$status" != 0 && "$INSTALL_DIR/omgd" -ef "$pair_root/originals/omgd" ]] || return 1
    staged_backup=$(find "$INSTALL_DIR" \( -name old-omg -o -name first-backup \) -type f -print) || return 1
    [[ -n "$staged_backup" && "$staged_backup" -ef "$pair_root/originals/omg" ]] || return 1
    grep -Fq -- "${staged_backup%/*}" "$pair_root/result" || return 1
  else
    [[ "$status" != 0 ]] || return 1
    case "$fault" in
      copy-* | mode-*) [[ ! -e "$pair_root/publication" ]] || return 1 ;;
      term-*) [[ "$status" == 143 ]] || return 1 ;;
    esac
    for binary in omg omgd; do
      installed="$INSTALL_DIR/$binary"
      original="$pair_root/originals/$binary"
      if [[ -e "$original" ]]; then
        [[ "$installed" -ef "$original" && $(cat "$installed") == "old $binary" ]] || return 1
        if [[ "$initial" == symlinks ]]; then
          [[ -L "$installed" && $(readlink "$installed") == "$original" ]] || return 1
        else
          [[ ! -L "$installed" ]] || return 1
        fi
      else
        [[ ! -e "$installed" && ! -L "$installed" ]] || return 1
      fi
    done
  fi
  if [[ "$fault" != blocked-restore ]]; then
    [[ -z $(find "$INSTALL_DIR" -mindepth 1 -maxdepth 1 -type d -name 'omg-*' -print) ]] || return 1
  fi
}

pair_failures=0
for initial in empty cli-only both symlinks; do
  for fault in success copy-cli copy-daemon mode-cli mode-daemon publish-cli publish-daemon after-cli after-daemon; do
    if (exercise_pair_transaction "$initial" "$fault"); then
      printf 'PASS: installer pair %s %s\n' "$initial" "$fault"
    else
      printf 'FAIL: installer pair %s %s\n' "$initial" "$fault" >&2
      cat "$task_dir/pair-$initial-$fault/result" >&2
      pair_failures=$((pair_failures + 1))
    fi
  done
done
for fault in blocked-restore term-after-cli term-after-daemon; do
  if (exercise_pair_transaction both "$fault"); then
    printf 'PASS: installer pair both %s\n' "$fault"
  else
    printf 'FAIL: installer pair both %s\n' "$fault" >&2
    cat "$task_dir/pair-both-$fault/result" >&2
    pair_failures=$((pair_failures + 1))
  fi
done
[[ "$pair_failures" == 0 ]]

# Piped definitions run in an attacker-controlled checkout, even with the old
# auto-detection bait. They must never qualify as an explicit source install.
mkdir -p "$task_dir/ambient"
printf '[package]\nname = "omg"\n' > "$task_dir/ambient/Cargo.toml"
{ cat "$task_dir/functions.sh"; printf '\n[[ "$IS_SOURCE_INSTALL" == false ]]\n'; } | (cd "$task_dir/ambient"; bash)

# A custom install path is data, even when it contains shell syntax and
# regular-expression metacharacters. Shell setup and uninstall must round-trip
# the exact line without executing or matching another rc entry.
(
  set --
  source "$task_dir/functions.sh"
  trap - EXIT
  set -e
  HOME="$task_dir/shell-home"
  SHELL=/bin/bash
  mkdir -p "$HOME"
  marker="$task_dir/injected"
  INSTALL_DIR="$task_dir/bin'\";touch $marker;#[.*]"
  printf '# omg hook already configured\nexport PATH="keep:$PATH"\n' > "$HOME/.bashrc"
  header() { :; }
  info() { :; }
  success() { :; }
  setup_shell
  path_line=$(shell_path_line bash)
  grep -Fqx -- "$path_line" "$HOME/.bashrc"
  restored_path=$(bash --noprofile --rcfile "$HOME/.bashrc" -ic 'printf "%s" "$PATH"' 2>/dev/null)
  [[ "$restored_path" == "$INSTALL_DIR:"* ]]
  [[ ! -e "$marker" ]]
  uninstall_omg
  if grep -Fqx -- "$path_line" "$HOME/.bashrc"; then
    printf 'Uninstall left its PATH line in bashrc\n' >&2
    exit 1
  fi
  grep -Fqx -- 'export PATH="keep:$PATH"' "$HOME/.bashrc"
  [[ ! -e "$marker" ]]

  legacy_line="export PATH=\"$INSTALL_DIR:\$PATH\""
  printf '%s\n' "$legacy_line" >> "$HOME/.bashrc"
  setup_shell
  if grep -Fqx -- "$legacy_line" "$HOME/.bashrc"; then
    printf 'Reinstall left unsafe legacy PATH line in bashrc\n' >&2
    exit 1
  fi
  grep -Fqx -- "$path_line" "$HOME/.bashrc"
  [[ ! -e "$marker" ]]
  uninstall_omg
  if grep -Fq -- "$INSTALL_DIR" "$HOME/.bashrc"; then
    printf 'Uninstall left the migrated PATH line in bashrc\n' >&2
    exit 1
  fi
  grep -Fqx -- 'export PATH="keep:$PATH"' "$HOME/.bashrc"

  INSTALL_DIR=bin
  if (setup_shell >/dev/null 2>&1); then
    printf 'relative INSTALL_DIR unexpectedly accepted\n' >&2
    exit 1
  fi
  if grep -Fq -- 'export PATH='"'bin'" "$HOME/.bashrc"; then
    printf 'Invalid INSTALL_DIR changed bashrc\n' >&2
    exit 1
  fi
)

# Upgrades must recognize the PATH lines emitted by earlier installer releases.
# Reinstall must not duplicate them, and uninstall must remove only OMG's exact
# lines while retaining unrelated shell configuration.
(
  set --
  source "$task_dir/functions.sh"
  trap - EXIT
  set -e
  HOME="$task_dir/legacy-shell-home"
  INSTALL_DIR="$task_dir/legacy-bin"
  PATH="$INSTALL_DIR:$PATH"
  mkdir -p "$HOME/.config/fish"
  header() { :; }
  info() { :; }
  success() { :; }
  for shell_type in bash zsh fish; do
    case "$shell_type" in
      bash) rc_file="$HOME/.bashrc" ;;
      zsh) rc_file="$HOME/.zshrc" ;;
      fish) rc_file="$HOME/.config/fish/config.fish" ;;
    esac
    if [[ "$shell_type" == fish ]]; then
      legacy_line="fish_add_path $INSTALL_DIR"
    else
      legacy_line="export PATH=\"$INSTALL_DIR:\$PATH\""
    fi
    printf '%s\n%s\n' "$legacy_line" 'export PATH="keep:$PATH"' > "$rc_file"
    SHELL="/bin/$shell_type"
    setup_shell
    if grep -Fqx -- "$legacy_line" "$rc_file"; then
      printf 'Reinstall left the legacy %s PATH entry\n' "$shell_type" >&2
      exit 1
    fi
    [[ $(grep -Fxc -- "$(shell_path_line "$shell_type")" "$rc_file") == 1 ]]
    grep -Fqx -- "$legacy_line" "$rc_file.omg-backup"
    printf '%s\n' "$legacy_line" >> "$rc_file"
  done
  uninstall_omg
  for rc_file in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.config/fish/config.fish"; do
    if grep -Fq -- "$INSTALL_DIR" "$rc_file"; then
      printf 'Uninstall left a legacy PATH entry in %s\n' "$rc_file" >&2
      exit 1
    fi
    grep -Fqx -- 'export PATH="keep:$PATH"' "$rc_file"
    [[ -f "$rc_file.omg-backup" ]]
  done
)

# A fixed location is not sufficient if the selected binary or a directory
# leading to it can be replaced by another user.
if [[ "$EUID" == 0 ]]; then
  (
    source "$task_dir/functions.sh"
    trap - EXIT
    set -e
    gh_candidate_is_trusted /usr/bin/true >/dev/null
    if [[ -L /bin ]]; then
      [[ "$(gh_candidate_is_trusted /bin/true)" == /bin/true ]]
    fi
    if [[ -L /usr/bin/sh ]]; then
      [[ -n "$(gh_candidate_is_trusted /usr/bin/sh)" ]]
    fi
    mkdir -p "$task_dir/untrusted-gh"
    cp /usr/bin/true "$task_dir/untrusted-gh/gh"
    chmod 777 "$task_dir/untrusted-gh/gh"
    ! gh_candidate_is_trusted "$task_dir/untrusted-gh/gh"
    ln -s /usr/bin/true "$task_dir/untrusted-gh/link"
    ! gh_candidate_is_trusted "$task_dir/untrusted-gh/link"
  )
fi
(
  set --
  source "$task_dir/functions.sh"
  trap - EXIT
  CONFIG_DIR="$task_dir/config-fixture"
  DATA_DIR="$task_dir/config-data-fixture"
  setup_config
  [[ -f "$CONFIG_DIR/config.toml" ]]
  ! grep -Eq '^\[(security|general|cache)\]' "$CONFIG_DIR/config.toml"
  [[ ! -e "$CONFIG_DIR/policy.toml" ]]
  printf '[security]\nallow_aur = false\n' > "$CONFIG_DIR/config.toml"
  printf 'allow_aur = false\n' > "$CONFIG_DIR/policy.toml"
  cp "$CONFIG_DIR/config.toml" "$task_dir/config-before"
  cp "$CONFIG_DIR/policy.toml" "$task_dir/policy-before"
  setup_config
  cmp "$CONFIG_DIR/config.toml" "$task_dir/config-before"
  cmp "$CONFIG_DIR/policy.toml" "$task_dir/policy-before"
)
python3 tests/test_shell_backup_safety.py
printf 'Installer security scenarios passed\n'
