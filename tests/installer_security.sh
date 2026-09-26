#!/usr/bin/env bash
# Exercise the real installer functions with isolated transport/tool fixtures.
set -euo pipefail
# Every assertion below aborts the run on failure. Report which command failed
# (and, inside the scenario loop, which scenario) so a hosted flake is
# diagnosable from the job log alone.
set -E
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
task_dir=$(mktemp -d)
trap 'rm -rf "$task_dir"' EXIT
sed '$d' install.sh > "$task_dir/functions.sh"
for scenario in missing rejected wrong_tag accepted loader_error wrong_version missing_daemon daemon_loader_error hung_probe forked_probe second_install_failure; do
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
    MAX_VERSION_PROBE_SECONDS=1
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
    detect_os() { echo linux; }
    detect_distro() { echo arch; }
    detect_arch() { echo x86_64; }
    if [[ "$scenario" == wrong_tag ]]; then
      resolve_version() { printf 'v1.2.2\n'; }
    fi
    curl() {
      local url="${@: -1}"
      if [[ "$url" == *.sha256 ]]; then
        printf '%064d  archive\n' 0
      elif [[ "$url" == "$RELEASES_BASE_URL/omg-v1.2.3-x86_64-linux-arch.tar.gz" ]]; then
        printf 'fixture'
      else
        printf 'Unexpected fixture URL: %s\n' "$url" >&2
        return 1
      fi
    }
    calculate_sha256() { printf '%064d\n' 0; }
    printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$@" > "%s/gh-args"\n[[ "%s" != rejected ]]\n' \
      "$scenario_dir" "$scenario" > "$scenario_dir/gh"
    chmod +x "$scenario_dir/gh"
    trusted_gh() {
      [[ "$scenario" != missing ]] || return 1
      printf '%s\n' "$scenario_dir/gh"
    }
    tar() {
      touch "$scenario_dir/extracted"
      printf '#!/bin/sh\nprintf "omg 1.2.3\\n"\n' > "$tmp_dir/omg"
      if [[ "$scenario" == loader_error ]]; then
        printf '#!/bin/sh\necho "missing libapt-pkg.so.6.0" >&2\nexit 127\n' > "$tmp_dir/omg"
      elif [[ "$scenario" == wrong_version ]]; then
        printf '#!/bin/sh\nprintf "omg 1.2.2\\n"\n' > "$tmp_dir/omg"
      elif [[ "$scenario" == hung_probe ]]; then
        printf '#!/bin/sh\necho "$$" > "%s/probe.pid"\nexec sleep 30\n' "$scenario_dir" > "$tmp_dir/omg"
      elif [[ "$scenario" == forked_probe ]]; then
        printf '#!/bin/sh\n(while :; do printf x >> "%s/descendant.heartbeat"; sleep 0.01; done) >/dev/null 2>&1 &\necho "$!" > "%s/descendant.pid"\nwhile [ ! -s "%s/descendant.heartbeat" ]; do :; done\nprintf "omg 1.2.3\\n"\n' "$scenario_dir" "$scenario_dir" "$scenario_dir" > "$tmp_dir/omg"
      fi
      chmod +x "$tmp_dir/omg"
      if [[ "$scenario" != missing_daemon ]]; then
        printf '#!/bin/sh\nprintf "omgd 1.2.3\\n"\n' > "$tmp_dir/omgd"
        if [[ "$scenario" == daemon_loader_error ]]; then
          printf '#!/bin/sh\necho "daemon missing native library" >&2\nexit 127\n' > "$tmp_dir/omgd"
        fi
        chmod +x "$tmp_dir/omgd"
      fi
    }
    install_binary() {
      mkdir -p "$INSTALL_DIR"
      if [[ "$scenario" == second_install_failure && "$2" == "$INSTALL_DIR/omgd" ]]; then
        return 1
      fi
      cp "$1" "$2"
    }
    if install_from_release > "$scenario_dir/output" 2>&1; then status=0; else status=$?; fi
    if [[ "$scenario" == accepted ]]; then
      [[ "$status" == 0 && -x "$INSTALL_DIR/omg" && -x "$INSTALL_DIR/omgd" ]]
      [[ $("$INSTALL_DIR/omg" --version) == 'omg 1.2.3' ]]
      [[ $("$INSTALL_DIR/omgd" --version) == 'omgd 1.2.3' ]]
      grep -Fx -- '--source-ref' "$scenario_dir/gh-args"
      grep -Fx 'refs/tags/v1.2.3' "$scenario_dir/gh-args"
      grep -Fx 'omg-cli/omg/.github/workflows/release.yml' "$scenario_dir/gh-args"
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
    if (install_binary "$INSTALL_DIR/source" "$INSTALL_DIR/omg"); then
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
  install_binary "$task_dir/source" "$INSTALL_DIR/omg"
  [[ ! -L "$INSTALL_DIR/omg" && -f "$INSTALL_DIR/omg" ]]
  [[ $(cat "$task_dir/outside/omg") == untouched ]]
  printf 'updated binary\n' > "$task_dir/source"
  install_binary "$task_dir/source" "$INSTALL_DIR/omg"
  cmp "$task_dir/source" "$INSTALL_DIR/omg"
  mkdir "$INSTALL_DIR/omgd"
  if (install_binary "$task_dir/source" "$INSTALL_DIR/omgd"); then
    printf 'Installer accepted a directory destination\n' >&2
    exit 1
  fi
  [[ ! -e "$INSTALL_DIR/omgd/source" && ! -e "$INSTALL_DIR/omgd/omgd" ]]
)
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
printf 'Installer security scenarios passed\n'
