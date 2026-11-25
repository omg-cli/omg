#!/usr/bin/env bash
# Drive the complete release installer with ordinary generated release archives.
set -euo pipefail
cd "$(dirname "$0")/.."
task_dir=$(mktemp -d)
trap 'rm -rf "$task_dir"' EXIT
unset OMG_UNINSTALL
sed '$d' install.sh > "$task_dir/functions.sh"
asset=omg-v1.2.3-x86_64-linux-fedora.tar.gz

cases=(success docs extras normalizes-mode dot-prefix entry-limit tar-options missing-cli missing-daemon
       duplicate-cli duplicate-daemon empty-cli empty-daemon entry-over listing-over raw-over
       cli-over daemon-over truncated)
layouts=(flat wrapped)
failures=0

exercise_release_archive() {
  local layout="$1" scenario="$2" output="$3"
  local fixture="${output%/*}" status=0
  mkdir -p "$fixture"/{scratch,bin} || return 1
  python3 - "$fixture/archive" "$asset" "$layout" "$scenario" <<'PY' || return 1
import io
from pathlib import Path
import sys
import tarfile

target, asset, layout, scenario = sys.argv[1:]
wrapper = asset.removesuffix(".tar.gz")
prefix = wrapper + "/" if layout == "wrapped" else ""
if scenario == "dot-prefix":
    prefix = "./" + prefix

def payload(name):
    return f'#!/bin/sh\nprintf "{name} 1.2.3\\n"\n'.encode()

with tarfile.open(target, "w:gz", format=tarfile.USTAR_FORMAT) as archive:
    def add(path, data, mode=0o644):
        info = tarfile.TarInfo(path)
        info.mode = mode
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))

    if scenario == "extras":
        add("release-notes/omg", b"an ignored note with the same basename\n")
    for name, role in (("omg", "cli"), ("omgd", "daemon")):
        if scenario == f"missing-{role}":
            continue
        member = prefix + name
        if scenario == "mixed" and role == "daemon":
            member = f"{wrapper}/omgd" if layout == "flat" else "omgd"
        if scenario == "wrong-wrapper":
            member = "different-release/" + name
        if scenario == "directory-member" and role == "daemon":
            info = tarfile.TarInfo(member)
            info.type = tarfile.DIRTYPE
            archive.addfile(info)
            continue
        if scenario == "hardlink-member" and role == "daemon":
            info = tarfile.TarInfo(member)
            info.type = tarfile.LNKTYPE
            info.linkname = prefix + "omg"
            archive.addfile(info)
            continue
        data = payload(name)
        if scenario == f"empty-{role}":
            data = b""
        if scenario == f"{role}-over":
            data += b"# ordinary padding\n" * 30
        add(member, data, 0o600 if scenario == "normalizes-mode" else 0o755)
        if scenario == f"duplicate-{role}" or scenario == "both-layouts":
            alternate = member if scenario != "both-layouts" else (
                f"{wrapper}/{name}" if layout == "flat" else name
            )
            add(alternate, data, 0o755)
    if scenario == "docs":
        add(prefix + "README.md", b"Release notes\n")
        add(prefix + "LICENSE", b"Fixture license\n")
    if scenario in {"entry-limit", "entry-over"}:
        for index in range(14 if scenario == "entry-limit" else 15):
            add(prefix + f"note-{index}.txt", b"note\n")
    if scenario == "listing-over":
        add(prefix + "a-long-release-note-" + "x" * 50, b"ordinary notes\n")
    if scenario == "raw-over":
        add(prefix + "README.md", b"ordinary text\n" * 1500)
if scenario == "truncated":
    data = Path(target).read_bytes()
    Path(target).write_bytes(data[:-12])
PY
  local digest
  set --
  source "$task_dir/functions.sh"
  trap - EXIT
  digest=$(calculate_sha256 "$fixture/archive") || return 1
  INSTALL_DIR="$fixture/bin"
  TMPDIR="$fixture/scratch"
  export TMPDIR
  OMG_VERSION=v1.2.3
  case "$scenario" in
    raw-over) MAX_RELEASE_TAR_BYTES=16384 ;;
    listing-over) MAX_RELEASE_LIST_BYTES=64 ;;
    cli-over | daemon-over) MAX_RELEASE_BINARY_BYTES=256 ;;
    tar-options) export TAR_OPTIONS=--not-a-real-option ;;
  esac
  detect_os() { printf 'linux\n'; }
  detect_arch() { printf 'x86_64\n'; }
  detect_distro() { printf 'fedora\n'; }
  start_spinner() { :; }
  stop_spinner() { :; }
  fail_spinner() { :; }
  trusted_gh() { printf '/usr/bin/true\n'; }
  curl() {
    case "${@: -1}" in
      "$RELEASES_BASE_URL/$asset") cat "$fixture/archive" ;;
      "$RELEASES_BASE_URL/$asset.sha256") printf '%s  %s\n' "$digest" "$asset" ;;
      *) return 1 ;;
    esac
  }
  eval "$(declare -f probe_release_binary | sed '1s/^probe_release_binary/real_archive_probe/')"
  probe_release_binary() {
    find "$tmp_dir" -type f -print > "$fixture/staged-files"
    real_archive_probe "$@"
  }

  # Preserve existing binaries on every refusal.
  printf 'previous cli\n' > "$INSTALL_DIR/omg"
  printf 'previous daemon\n' > "$INSTALL_DIR/omgd"
  install_from_release > "$output" 2>&1 || status=$?
  case "$scenario" in
    success | docs | extras | normalizes-mode | dot-prefix | entry-limit | tar-options)
      [[ "$status" == 0 && -x "$INSTALL_DIR/omg" && -x "$INSTALL_DIR/omgd" ]] || return 1
      [[ $("$INSTALL_DIR/omg" --version) == 'omg 1.2.3' ]] || return 1
      [[ $("$INSTALL_DIR/omgd" --version) == 'omgd 1.2.3' ]] || return 1
      if grep -Eq '/(README\.md|LICENSE|release-notes/omg|note-[0-9]+\.txt)$' "$fixture/staged-files"; then return 1; fi
      ;;
    *)
      [[ "$status" == 1 && ! -e "$fixture/staged-files" ]] || return 1
      [[ $(cat "$INSTALL_DIR/omg") == 'previous cli' && $(cat "$INSTALL_DIR/omgd") == 'previous daemon' ]] || return 1
      local diagnostic
      case "$scenario" in
        missing-cli | wrong-wrapper) diagnostic='missing omg binary' ;;
        missing-daemon) diagnostic='missing omgd binary' ;;
        duplicate-cli | both-layouts) diagnostic='duplicate omg binaries' ;;
        duplicate-daemon) diagnostic='duplicate omgd binaries' ;;
        empty-cli | empty-daemon) diagnostic='Release member .* is empty' ;;
        entry-over) diagnostic='too many members' ;;
        listing-over) diagnostic='Failed to list release archive members|Release member listing exceeded' ;;
        raw-over | truncated) diagnostic='decompress release archive within the byte bound|Decompressed release archive exceeded' ;;
        cli-over | daemon-over) diagnostic='within the binary byte bound|Release member .* exceeded' ;;
        mixed) diagnostic='mixed binary layouts' ;;
        directory-member) diagnostic='missing omgd binary|must both be regular files' ;;
        hardlink-member) diagnostic='must both be regular files' ;;
        *) return 1 ;;
      esac
      grep -Eq "$diagnostic" "$output" || return 1
      ;;
  esac
  [[ -z $(find "$TMPDIR" -mindepth 1 -print -quit) ]]
}

run_case() {
  local layout="$1" scenario="$2" output="$task_dir/$1-$2/output"
  if (exercise_release_archive "$layout" "$scenario" "$output"); then
    printf 'PASS: release archive %s %s\n' "$layout" "$scenario"
  else
    printf 'FAIL: release archive %s %s\n' "$layout" "$scenario" >&2
    if [[ -f "$output" ]]; then tail -n 8 "$output" >&2; fi
    failures=$((failures + 1))
  fi
}

for layout in "${layouts[@]}"; do
  for scenario in "${cases[@]}"; do
    run_case "$layout" "$scenario"
  done
done
for scenario in mixed wrong-wrapper both-layouts directory-member hardlink-member; do
  run_case flat "$scenario"
done
[[ "$failures" == 0 ]]
