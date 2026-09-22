#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
inventory="$repo_root/tests/cli_behavior_inventory.tsv"

usage() {
  cat <<'EOF'
Usage: scripts/release-smoke.sh [--release latest|vX.Y.Z | --staged-dir PATH --release vX.Y.Z]
                                --distro arch|debian|ubuntu|fedora|macos|all
                                [--case ID] [--family package] [--tier container]
                                [--executor container|native]
                                [--container-engine docker|podman] [--evidence-dir PATH]

Verifies exact OMG release archives and runs selected release contracts inside
disposable, digest-pinned distro containers. With --executor native --distro
macos the same probes run directly on a macOS host (an ephemeral CI runner or
a machine whose Homebrew state may change) against the aarch64-darwin archive.

Options:
  --release TAG              Published tag, or the tag represented by --staged-dir
                             (default: latest without --staged-dir)
  --staged-dir PATH          Read archives and sidecars from a local staging directory
  --distro ID                arch, debian, ubuntu, fedora, macos, or all (default: all;
                             all covers the container distros; macos needs --executor native)
  --case ID                  Run one release contract
  --apt-abi 6|7              APT host ABI for debian/ubuntu (default: 6); ABI 7
                             uses Debian 13/Ubuntu 26.04 and the Trixie archive
  --family NAME              Run one contract family (default: package)
  --tier NAME                Run one execution tier (default: container)
  --executor NAME            container runs probes in distro images; native runs the
                             macos probes on the host (default: container;
                             native only pairs with --distro macos)
  --timeout-seconds N        Container execution limit, 1..9999 (default: 300)
  --container-engine ENGINE  docker or podman (default: $OMG_SMOKE_ENGINE or docker)
  --evidence-dir PATH        Evidence base (default: target/release-smoke)

Environment:
  OMG_SMOKE_REPOSITORY    GitHub repository used for published releases
  OMG_SMOKE_ENGINE        Default container engine
  OMG_SMOKE_EVIDENCE_DIR  Default evidence base directory
  OMG_SMOKE_DIGEST_PIN_FILE
                          sha256sum-style pin file (<sha256>  <filename> or a
                          bare <sha256> per line). When set, a release archive
                          is executed only if its verified sha256 matches a
                          pin. Required for --executor native, because native
                          execution runs release code directly on the host.
EOF
}

load_distro() {
  case "$1" in
    arch)
      distro_suffix="-x86_64-linux-arch"
      distro_image="archlinux:latest@sha256:b0deabeb3d283da2c7f7dbf0eea051b7b2cd0554e0b737cc457fd21683bdcdd1"
      distro_index_cmd="pacman-key --init && pacman-key --populate archlinux && pacman -Syu --noconfirm"
      distro_probe_pkg="tree"
      distro_installed_assert="pacman -Qi tree"
      distro_removed_assert="! pacman -Q tree"
      ;;
    debian)
      distro_suffix="-x86_64-linux-debian"
      distro_image="debian:bookworm@sha256:813017f3d62be4b5891a7acca6a01bdcd4b8513daa81b1ab99d3a50385b26931"
      distro_index_cmd="apt-get update && apt-get install -y --no-install-recommends ca-certificates"
      distro_installed_assert="dpkg-query -W -f='\${db:Status-Abbrev}' tree | grep -q '^ii'"
      distro_removed_assert="! dpkg-query -W -f='\${db:Status-Abbrev}' tree | grep -q '^ii'"
      ;;
    ubuntu)
      distro_suffix="-x86_64-linux-ubuntu"
      distro_image="ubuntu:24.04@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517"
      distro_index_cmd="apt-get update && apt-get install -y --no-install-recommends ca-certificates"
      distro_installed_assert="dpkg-query -W -f='\${db:Status-Abbrev}' tree | grep -q '^ii'"
      distro_removed_assert="! dpkg-query -W -f='\${db:Status-Abbrev}' tree | grep -q '^ii'"
      ;;
    fedora)
      distro_suffix="-x86_64-linux-fedora"
      distro_image="fedora:latest@sha256:6c75d5bf57cb0fa5aa4b92c6a83c86c791644496d9ac230de7711f5b8ec3b898"
      distro_index_cmd="dnf -y makecache"
      distro_installed_assert="rpm -q tree"
      distro_removed_assert="! rpm -q tree"
      ;;
    macos)
      # No container image: macos only pairs with --executor native, which runs
      # the probe on the host against the aarch64-darwin release archive.
      distro_suffix="-aarch64-darwin"
      distro_image=""
      # GitHub's macOS images can hold Homebrew's update lock briefly after a
      # previous refresh (or a background auto-update), which surfaces as
      # "Another `brew update` process is already running". Retry once after a
      # pause; a genuine failure still exits non-zero and fails the probe.
      distro_index_cmd="brew update || { sleep 15; brew update; }"
      distro_installed_assert="brew list tree >/dev/null"
      distro_removed_assert="! brew list tree >/dev/null"
      # Containers start every case from a fresh filesystem; the shared host
      # does not, so each native case resets the probe package first.
      distro_native_reset_cmd="brew uninstall tree || true"
      ;;
    *) return 1 ;;
  esac
  if [[ "$apt_abi" == 7 ]]; then
    distro_suffix="-x86_64-linux-debian-trixie"
    case "$1" in
      debian) distro_image="debian:trixie@sha256:34cd9e9fd437c0a095ec39cb2e73422c9f30821b0d0848ed74fd0d43bae4d958" ;;
      ubuntu) distro_image="ubuntu:26.04@sha256:da6fc2be547864451aa253836dd926da33623312df4a9a243e35dc877c378a78" ;;
      *) return 1 ;;
    esac
  fi
}

require_engine() {
  if ! command -v "$engine" >/dev/null 2>&1; then
    printf 'error: container engine %q not found in PATH.\n' "$engine" >&2
    return 3
  fi
  if ! "$engine" info >/dev/null 2>&1; then
    printf 'error: %q info failed; the container engine is unavailable.\n' "$engine" >&2
    return 3
  fi
}

case_family() {
  case "$1" in
    release-package-*) printf 'package\n' ;;
    *) printf 'unknown\n' ;;
  esac
}

# Bash 3.2 (macOS /usr/bin/bash, frozen at 3.2.57 since 2007 because Apple
# will not ship GPLv3 bash) has no associative arrays: `declare -A`/`-gA`,
# `mapfile`, and $BASHPID all arrived in bash 4.0. Per-case fields therefore
# live in parallel indexed arrays aligned with selected_cases; the release
# contract list is tens of rows, so a linear scan is plenty.
case_field() {
  # C-style index loop: ${!array[@]} index expansion is avoided so this
  # stays within bash 2.x-era features; ${#array[@]} is nounset-safe.
  local which=$1 id=$2 i
  for ((i = 0; i < ${#selected_cases[@]}; i++)); do
    if [[ "${selected_cases[$i]}" == "$id" ]]; then
      case "$which" in
        args) printf '%s' "${case_args_list[$i]}" ;;
        exit) printf '%s' "${case_exit_list[$i]}" ;;
        targets) printf '%s' "${case_targets_list[$i]}" ;;
        *) return 2 ;;
      esac
      return 0
    fi
  done
  return 1
}

load_release_cases() {
  local header id args safety expected_exit ux requires tiers targets assertions cleanup
  IFS= read -r header < "$inventory"
  local expected_header=$'case\targs_json\tsafety\texpected_exit\texpected_ux\trequires\ttier\ttargets\tassertions\tcleanup'
  if [[ "$header" != "$expected_header" ]]; then
    printf 'error: %s has an unsupported header.\n' "$inventory" >&2
    return 3
  fi

  selected_cases=()
  # Bash 3.2 (macOS /usr/bin/bash) has no associative arrays: per-case
  # fields live in parallel indexed arrays aligned with selected_cases.
  # Plain assignments stay global (no `local`) so run_case can read them.
  case_args_list=()
  case_exit_list=()
  case_targets_list=()
  while IFS=$'\t' read -r id args safety expected_exit ux requires tiers targets assertions cleanup; do
    [[ -n "$id" ]] || continue
    [[ "$id" =~ ^[a-z0-9][a-z0-9-]*$ ]] || {
      printf 'error: invalid release contract identifier %q.\n' "$id" >&2
      return 3
    }
    [[ "$ux" == "pass" ]] || continue
    [[ ",$tiers," == *",$tier,"* ]] || continue
    [[ "$targets" != "hermetic:pass" ]] || continue
    [[ "$(case_family "$id")" == "$family" ]] || continue
    [[ -z "$case_id" || "$id" == "$case_id" ]] || continue
    valid_expected_exit "$expected_exit" || {
      printf 'error: release contract %s has invalid expected exit %q.\n' "$id" "$expected_exit" >&2
      return 3
    }
    selected_cases+=("$id")
    case_args_list+=("$args")
    case_exit_list+=("$expected_exit")
    case_targets_list+=("$targets")
  done < <(tail -n +2 "$inventory")

  if [[ ${#selected_cases[@]} -eq 0 ]]; then
    printf 'error: no release contracts match case=%q family=%q tier=%q.\n' "$case_id" "$family" "$tier" >&2
    printf 'valid release contracts:\n' >&2
    awk -F '\t' '$1 ~ /^release-/ && $5 == "pass" && $8 != "hermetic:pass" { print "  " $1 }' "$inventory" >&2
    return 2
  fi
  for id in "${selected_cases[@]}"; do
    args="$(case_field args "$id")" || {
      printf 'error: release contract %s has no recorded args.\n' "$id" >&2
      return 3
    }
    if ! probe_kind_for_args "$args" >/dev/null; then
      printf 'error: release contract %s has no container executor for %s.\n' "$id" "$args" >&2
      return 3
    fi
  done
}

target_for_distro() {
  local targets=$1 wanted=$2 entry
  local entries=()
  IFS=',' read -ra entries <<< "$targets"
  for entry in "${entries[@]}"; do
    if [[ "${entry%%:*}" == "$wanted" ]]; then
      printf '%s\n' "${entry#*:}"
      return 0
    fi
  done
  return 1
}
# Resolve an expected_exit cell for one distro. Bare codes apply
# everywhere; per-distro cells (arch:N,debian:N,ubuntu:N,fedora:N, #303)
# select the matching entry. Prints the code, or nothing and fails.
exit_for_distro() {
  local cell=$1 wanted=$2
  if [[ "$cell" =~ ^[0-9]+$ ]]; then
    printf '%s\n' "$cell"
    return 0
  fi
  local entry
  local entries=()
  IFS=',' read -ra entries <<< "$cell"
  for entry in "${entries[@]}"; do
    if [[ "${entry%%:*}" == "$wanted" && "${entry#*:}" =~ ^[0-9]+$ ]]; then
      printf '%s\n' "${entry#*:}"
      return 0
    fi
  done
  return 1
}
# True when an expected_exit cell is a bare code or a complete
# arch/debian/ubuntu/fedora matrix of codes. Partial matrices are
# rejected so a missing distro can never inherit another's expectation.
valid_expected_exit() {
  local cell=$1
  [[ "$cell" =~ ^[0-9]+$ ]] && return 0
  local seen=""
  local entry distro
  local entries=()
  IFS=',' read -ra entries <<< "$cell"
  for entry in "${entries[@]}"; do
    [[ "$entry" =~ ^(arch|debian|ubuntu|fedora):[0-9]+$ ]] || return 1
    distro="${entry%%:*}"
    [[ "$seen" == *",$distro,"* ]] && return 1
    seen="$seen,$distro,"
  done
  [[ "$seen" == *,arch,* && "$seen" == *,debian,* && "$seen" == *,ubuntu,* && "$seen" == *,fedora,* ]]
}

select_tool() {
  local candidate path
  for candidate in "$@"; do
    if path="$(command -v "$candidate" 2>/dev/null)"; then printf '%s\n' "$path"; return 0; fi
  done
  return 1
}

validate_checksum() {
  local archive_path=$1 sidecar_path=$2 archive_name=$3
  [[ -f "$archive_path" && ! -L "$archive_path" ]] || return 1
  [[ -f "$sidecar_path" && ! -L "$sidecar_path" ]] || return 1
  local checksum_lines=() line
  while IFS= read -r line || [[ -n "$line" ]]; do
    checksum_lines+=("$line")
  done < "$sidecar_path"
  [[ ${#checksum_lines[@]} -eq 1 ]] || return 1
  local sidecar_digest sidecar_filename sidecar_extra
  read -r sidecar_digest sidecar_filename sidecar_extra <<< "${checksum_lines[0]}"
  [[ -z "${sidecar_extra:-}" ]] || return 1
  [[ "$sidecar_digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  [[ "$sidecar_filename" == "$archive_name" ]] || return 1
  # sha256sum (coreutils) or shasum -a 256 (macOS); selected once at startup.
  local actual
  if [[ "$(basename "$SHA256_BIN")" == "shasum" ]]; then
    actual="$("$SHA256_BIN" -a 256 "$archive_path" | awk '{print $1}')"
  else
    actual="$("$SHA256_BIN" "$archive_path" | awk '{print $1}')"
  fi
  [[ "$actual" == "$sidecar_digest" ]] || return 1
  printf '%s\n' "$sidecar_digest"
}

# Check a validated artifact digest against a maintainer-pinned digest file
# (sha256sum-style lines: "<sha256>  <filename>"; a bare "<sha256>" line also
# matches). The .sha256 sidecar ships with the release, so replacing both
# assets would pass validate_checksum; this closes that gap before anything
# extracted from the archive is executed.
verify_pinned_digest() {
  local digest=$1 archive=$2 pin_file=$3 line line_digest line_name
  [[ -f "$pin_file" && ! -L "$pin_file" ]] || return 1
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^([0-9a-f]{64})([[:space:]]+\*?([^[:space:]]+))?[[:space:]]*$ ]] || continue
    line_digest="${BASH_REMATCH[1]}"
    line_name="${BASH_REMATCH[3]:-}"
    [[ -z "$line_name" || "$line_name" == "$archive" ]] || continue
    [[ "$line_digest" == "$digest" ]] && return 0
  done < "$pin_file"
  return 1
}

write_result() {
  local evidence_dir=$1 case_id=$2 distro=$3 result=$4 exit_code=$5 elapsed=$6 expectation=$7
  printf '{"case_id":"%s","distro":"%s","result":"%s","exit_code":%s,"elapsed_seconds":%s,"expectation":"%s","artifact_source":"%s"}\n' \
    "$case_id" "$distro" "$result" "$exit_code" "$elapsed" "$expectation" "$artifact_source" > "$evidence_dir/result.json"
  cat "$evidence_dir/result.json" >> "$results_ndjson"
}

probe_kind_for_args() {
  case "$1" in
    '["search","tree"]') printf 'search-tree\n' ;;
    '["install","--yes","tree"]') printf 'install-tree\n' ;;
    '["remove","--yes","tree"]') printf 'remove-tree\n' ;;
    *) return 1 ;;
  esac
}

write_probe() {
  local path=$1
  cat > "$path" <<'PROBE'
#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
bin="${OMG_PROBE_ROOT:-/probe}/${OMG_PROBE_BIN}"
bash -c "${OMG_PROBE_INDEX_CMD}" || exit 120
version_line="$(printf '%s\n' "$("$bin" --version)" | head -n 1 | tr -d '[:space:]')"
[[ "$version_line" == "omg${OMG_PROBE_VERSION_NUM}" ]]
bash -c "${OMG_PROBE_REMOVED_ASSERT}" || exit 120
case "$OMG_SMOKE_PROBE_KIND" in
  search-tree)
    search_output="$("$bin" search tree)" || exit 1
    printf '%s\n' "$search_output"
    grep -Eqi '^[[:space:]]+tree[[:space:]]' <<< "$search_output"
    ;;
  install-tree)
    "$bin" install --yes tree || exit 1
    bash -c "${OMG_PROBE_INSTALLED_ASSERT}"
    ;;
  remove-tree)
    # A failing setup install is a PRODUCT signal (the product cannot
    # install), not rig noise: exit 1 keeps it comparable against the
    # expected exit instead of masking it as HARNESS_ERROR (see #277,
    # where "Package not found: tree" from install setup hid a real
    # repository-lookup defect behind exit 120).
    "$bin" install --yes tree || exit 1
    bash -c "${OMG_PROBE_INSTALLED_ASSERT}" || exit 120
    "$bin" remove --yes tree || exit 1
    bash -c "${OMG_PROBE_REMOVED_ASSERT}"
    ;;
  *)
    printf 'unknown release probe: %s\n' "$OMG_SMOKE_PROBE_KIND" >&2
    exit 2
    ;;
esac
PROBE
  chmod 700 "$path"
}

record_nonexecution() (
  local distro=$1 result=$2 message=$3 case_id expectation evidence_dir targets_entry
  # Resolve the requested inputs even when acquisition or engine setup failed.
  # These describe expectations, never an image or artifact actually executed.
  load_distro "$distro" || return 3
  for case_id in "${selected_cases[@]}"; do
    targets_entry="$(case_field targets "$case_id")" || targets_entry=""
    expectation="$(target_for_distro "$targets_entry" "$distro")" || expectation="missing"
    evidence_dir="$run_evidence/${distro}-${case_id}"
    mkdir -p "$evidence_dir"
    printf '%s: %s\n' "$result" "$message" > "$evidence_dir/transcript.txt"
    {
      printf 'case_id=%s\n' "$case_id"
      printf 'distro=%s\n' "$distro"
      printf 'result=%s\n' "$result"
      printf 'expectation=%s\n' "$expectation"
      printf 'release=%s\n' "$tag"
      printf 'expected_archive=omg-%s%s.tar.gz\n' "$tag" "$distro_suffix"
      printf 'expected_image=%s\n' "${distro_image:-native-host}"
      printf 'engine=%s\n' "$engine"
      printf 'elapsed_seconds=0\n'
    } > "$evidence_dir/metadata.txt"
    write_result "$evidence_dir" "$case_id" "$distro" "$result" 3 0 "$expectation"
  done
)

record_harness_error() {
  record_nonexecution "$1" "HARNESS_ERROR" "$2"
}

resolve_artifact() {
  local workdir=$1
  version="${tag#v}"
  archive="omg-${tag}${distro_suffix}.tar.gz"
  if [[ -n "$staged_dir" ]]; then
    [[ -f "$staged_dir/$archive" && ! -L "$staged_dir/$archive" ]] || return 1
    [[ -f "$staged_dir/${archive}.sha256" && ! -L "$staged_dir/${archive}.sha256" ]] || return 1
    cp "$staged_dir/$archive" "$workdir/$archive" || return 1
    cp "$staged_dir/${archive}.sha256" "$workdir/${archive}.sha256" || return 1
  else
    gh release download "$tag" --repo "$repo" \
      --pattern "$archive" --pattern "${archive}.sha256" --dir "$workdir" || return 1
  fi
  [[ "$(find "$workdir" -maxdepth 1 -type f | wc -l)" -eq 2 ]] || return 1
  digest="$(validate_checksum "$workdir/$archive" "$workdir/${archive}.sha256" "$archive")" || return 1
  if [[ -n "$digest_pin_file" ]]; then
    verify_pinned_digest "$digest" "$archive" "$digest_pin_file" || return 1
  fi
    if [[ "$executor" == "native" && -z "$staged_dir" ]]; then
      # A release uploader can replace an archive and its server-side digest.
      # Verify the release workflow identity before extracting or running it.
      local signer_repo="$repo"
      if [[ "$repo" == omg-cli/omg || "$repo" == PyRo1121/omg ]]; then
        signer_repo=omg-cli/omg
        local release_version="${tag#v}"
        if [[ "$release_version" == 0.0.* ]] || {
          [[ "$release_version" =~ ^0\.1\.([0-9]{1,3})([-+].*)?$ ]] &&
            (( 10#${BASH_REMATCH[1]} <= 221 ))
        }; then
          signer_repo=PyRo1121/omg
        fi
      fi
      gh attestation verify "$workdir/$archive" \
        --repo "$signer_repo" \
        --source-ref "refs/tags/$tag" \
        --signer-workflow "$signer_repo/.github/workflows/release.yml" || return 1
  fi
}

run_case() (
  local distro=$1 case_id=$2 stage=$3
  local expectation evidence_dir started elapsed probe_bin probe_kind observed_exit result
  # $BASHPID is bash 4.0+; $$ plus distro+case (cases run sequentially)
  # is unique here on bash 3.2 as well.
  local container_name="omg-smoke-$$-${distro}-${case_id}" cleanup_ok=true
  if [[ "$executor" == "native" ]]; then
    # The inventory targets name container distros only; a native macOS run
    # establishes the baseline, so a matching product exit is a pass.
    expectation="pass"
  else
    targets_entry="$(case_field targets "$case_id")" || targets_entry=""
    expectation="$(target_for_distro "$targets_entry" "$distro")" || expectation="missing"
  fi
  evidence_dir="$run_evidence/${distro}-${case_id}"
  mkdir -p "$evidence_dir"
  args_entry="$(case_field args "$case_id")" || return 3
  probe_kind="$(probe_kind_for_args "$args_entry")" || return 3
  write_probe "$stage/probe-${case_id}.sh"
  cp "$stage/probe-${case_id}.sh" "$evidence_dir/probe.sh"
  probe_bin="omg-${tag}${distro_suffix}/omg"

  cleanup_container() {
    local remaining
    "$TIMEOUT_BIN" --kill-after=5s 10s "$engine" rm --force "$container_name" >> "$evidence_dir/cleanup.txt" 2>&1 || true
    remaining="$("$TIMEOUT_BIN" --kill-after=5s 10s "$engine" ps --all --quiet --filter "name=^/${container_name}$" 2>> "$evidence_dir/cleanup.txt")" || return 1
    [[ -z "$remaining" ]] || return 1
    printf 'verified absent: %s\n' "$container_name" >> "$evidence_dir/cleanup.txt"
  }
  exec 3>&1 4>&2
  exec > >(tee "$evidence_dir/transcript.txt") 2>&1
  set -x
  started=$SECONDS
  observed_exit=0
  if [[ "$executor" == "native" ]]; then
    trap 'exit 130' INT
    trap 'exit 143' TERM
    # Best effort: the probe's own asserts stay authoritative.
    bash -c "${distro_native_reset_cmd:?native executor needs a reset command}" || true
    OMG_SMOKE_PROBE_KIND="$probe_kind" \
      OMG_PROBE_VERSION_NUM="$version" \
      OMG_PROBE_BIN="$probe_bin" \
      OMG_PROBE_INDEX_CMD="$distro_index_cmd" \
      OMG_PROBE_INSTALLED_ASSERT="$distro_installed_assert" \
      OMG_PROBE_REMOVED_ASSERT="$distro_removed_assert" \
      OMG_PROBE_ROOT="$stage" \
      "$TIMEOUT_BIN" --kill-after=5s "${timeout_seconds}s" \
      bash -x "$stage/probe-${case_id}.sh" || observed_exit=$?
    trap - INT TERM
  else
    trap 'cleanup_container || exit 3' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    "$TIMEOUT_BIN" --kill-after=5s "${timeout_seconds}s" "$engine" run --rm --name "$container_name" \
      -e OMG_SMOKE_PROBE_KIND="$probe_kind" \
      -e OMG_PROBE_VERSION_NUM="$version" \
      -e OMG_PROBE_BIN="$probe_bin" \
      -e OMG_PROBE_INDEX_CMD="$distro_index_cmd" \
      -e OMG_PROBE_INSTALLED_ASSERT="$distro_installed_assert" \
      -e OMG_PROBE_REMOVED_ASSERT="$distro_removed_assert" \
      -e OMG_PROBE_ROOT=/probe \
      -v "$stage:/probe:ro" \
      "$distro_image" bash -x "/probe/probe-${case_id}.sh" || observed_exit=$?
    cleanup_container || cleanup_ok=false
    trap - EXIT INT TERM
  fi
  elapsed=$((SECONDS - started))
  set +x
  exec 1>&3 2>&4
  exec 3>&- 4>&-

  # Native macOS runs have no matrix entry (matrices classify container
  # distros only, like targets): compare against the arch reference exit,
  # exactly matching the previous bare-code behavior on that lane.
  if [[ "$executor" == "native" ]]; then
    expected_exit="$(exit_for_distro "$(case_field exit "$case_id")" "arch")" || return 3
  else
    expected_exit="$(exit_for_distro "$(case_field exit "$case_id")" "$distro")" || return 3
  fi
  case "$expectation" in
    pass|known-defect)
      if [[ $observed_exit -eq "$expected_exit" ]]; then result="PASS"; else result="PRODUCT_FAIL"; fi
      ;;
    expected-rejection)
      if [[ $observed_exit -eq "$expected_exit" ]]; then result="EXPECTED_REJECTION"; else result="PRODUCT_FAIL"; fi
      ;;
    blocked|not-applicable) result="BLOCKED" ;;
    *) result="HARNESS_ERROR" ;;
  esac
  # Only proven-rig failures map to HARNESS_ERROR: 120 is this script's own
  # fixture marker, 125/126/127 are engine/exec failures, 255 is transport.
  # Timeouts (124) and OOM kills (137) stay comparable so a hanging or
  # memory-blowing product reports PRODUCT_FAIL instead of hiding as rig
  # noise (audit: every FAIL must first be proven a TRUE product signal).
  case "$observed_exit" in
    120|125|126|127|255) result="HARNESS_ERROR" ;;
  esac
  if [[ "$cleanup_ok" != true ]]; then
    result="HARNESS_ERROR"
  fi

  local image_label="$distro_image" engine_label="$engine"
  if [[ "$executor" == "native" ]]; then
    image_label="native-host"
    engine_label="native"
  fi
  {
    printf 'case_id=%s\n' "$case_id"
    printf 'distro=%s\n' "$distro"
    printf 'result=%s\n' "$result"
    printf 'expectation=%s\n' "$expectation"
    printf 'release=%s\n' "$tag"
    printf 'image=%s\n' "$image_label"
    printf 'archive=%s\n' "$archive"
    printf 'archive_sha256=%s\n' "$digest"
    printf 'engine=%s\n' "$engine_label"
    printf 'elapsed_seconds=%s\n' "$elapsed"
  } > "$evidence_dir/metadata.txt"
  write_result "$evidence_dir" "$case_id" "$distro" "$result" "$observed_exit" "$elapsed" "$expectation"
  printf '== %s %s: %s elapsed=%ss evidence=%s ==\n' "$distro" "$case_id" "$result" "$elapsed" "$evidence_dir"
  case "$result" in
    PASS|EXPECTED_REJECTION) return 0 ;;
    PRODUCT_FAIL) return 1 ;;
    HARNESS_ERROR|BLOCKED) return 3 ;;
  esac
)

run_distro() (
  set -euo pipefail
  local distro=$1 workdir stage case_id rc case_rc=0
  load_distro "$distro" || return 2
  local work_root="$HOME/.cache/build-targets/omg-release-smoke"
  mkdir -p "$work_root" || return 3
  workdir="$(mktemp -d "$work_root/${distro}.XXXXXX")" || return 3
  trap 'rm -rf "$workdir"' EXIT
  stage="$workdir/stage"
  mkdir -p "$stage"

  if ! resolve_artifact "$workdir"; then
    record_harness_error "$distro" "failed to acquire, validate, or pin-match the release artifact"
    return 3
  fi
  if ! tar -xzf "$workdir/$archive" -C "$stage"; then
    record_harness_error "$distro" "failed to extract the release artifact"
    return 3
  fi
  if [[ ! -f "$stage/omg-${tag}${distro_suffix}/omg" ]]; then
    record_harness_error "$distro" "release artifact does not contain the expected binary"
    return 3
  fi
  if [[ "$executor" == "native" ]]; then
    [[ -z "$distro_image" ]] || { record_harness_error "$distro" "native executor needs an imageless distro"; return 3; }
  elif ! "$engine" pull "$distro_image"; then
    record_harness_error "$distro" "failed to pull the pinned container image"
    return 3
  fi

  for case_id in "${selected_cases[@]}"; do
    rc=0
    run_case "$distro" "$case_id" "$stage" || rc=$?
    if [[ $rc -eq 3 ]]; then
      return 3
    fi
    if [[ $rc -ne 0 ]]; then
      case_rc=1
    fi
  done
  return "$case_rc"
)

finalize_results() {
  {
    printf '[\n'
    awk 'NR > 1 { printf ",\n" } { printf "  %s", $0 } END { if (NR > 0) printf "\n" }' "$results_ndjson"
    printf ']\n'
  } > "$run_evidence/results.json"
  if ! "$TIMEOUT_BIN" --kill-after=2s 12s env OMG_SMOKE_RELEASE="$tag" \
      "$repo_root/scripts/report-smoke-sentry.sh" "$run_evidence/results.json" \
      > "$run_evidence/reporting.log" 2>&1; then
    printf 'warning: Sentry reporting failed; results remain in %s\n' "$run_evidence" >&2
  fi
}

release="latest"
release_set=false
staged_dir=""
distro="all"
apt_abi=6
case_id=""
family="package"
tier="container"
executor="container"
timeout_seconds=300
engine="${OMG_SMOKE_ENGINE:-docker}"
digest_pin_file="${OMG_SMOKE_DIGEST_PIN_FILE:-}"
evidence_base="${OMG_SMOKE_EVIDENCE_DIR:-$repo_root/target/release-smoke}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --release|--staged-dir|--distro|--apt-abi|--case|--family|--tier|--executor|--timeout-seconds|--container-engine|--evidence-dir)
      [[ $# -ge 2 ]] || { printf 'error: %s requires a value\n' "$1" >&2; exit 2; }
      case "$1" in
        --release) release=$2; release_set=true ;;
        --staged-dir) staged_dir=$2 ;;
        --distro) distro=$2 ;;
        --apt-abi) apt_abi=$2 ;;
        --case) case_id=$2 ;;
        --family) family=$2 ;;
        --tier) tier=$2 ;;
        --executor) executor=$2 ;;
        --timeout-seconds) timeout_seconds=$2 ;;
        --container-engine) engine=$2 ;;
        --evidence-dir) evidence_base=$2 ;;
      esac
      shift 2
      ;;
    *) printf 'error: unknown argument %q\n' "$1" >&2; exit 2 ;;
  esac
done

if [[ "$release" != "latest" && ! "$release" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  printf 'error: --release must be latest or vX.Y.Z\n' >&2
  exit 2
fi
case "$distro" in
  arch|debian|ubuntu|fedora|macos|all) ;;
  *) printf 'error: invalid distro %q\n' "$distro" >&2; exit 2 ;;
esac
if [[ "$apt_abi" != 6 && "$apt_abi" != 7 ]] ||
   { [[ "$apt_abi" == 7 && "$distro" != debian && "$distro" != ubuntu ]]; }; then
  printf 'error: --apt-abi requires 6 or 7; ABI 7 requires --distro debian or ubuntu\n' >&2
  exit 2
fi
if [[ "$executor" != "container" && "$executor" != "native" ]]; then
  printf 'error: invalid executor %q; valid values: container|native\n' "$executor" >&2
  exit 2
fi
if [[ "$executor" == "native" && "$distro" != "macos" ]]; then
  # Native execution mutates the host package manager; only the imageless
  # macos distro may run there, and only on a disposable host.
  printf 'error: --executor native only pairs with --distro macos\n' >&2
  exit 2
fi
if [[ -n "$digest_pin_file" && ! -f "$digest_pin_file" ]]; then
  printf 'error: OMG_SMOKE_DIGEST_PIN_FILE is not a readable file: %s\n' "$digest_pin_file" >&2
  exit 2
fi
if [[ "$executor" == "native" && -z "$digest_pin_file" ]]; then
  # Native execution runs the extracted release binary directly on this
  # host; require a pinned digest before execution. The sidecar ships with the
  # release, so an attacker who replaces both assets defeats sidecar-only
  # checks — require an independently pinned digest before execution.
  printf 'error: --executor native requires OMG_SMOKE_DIGEST_PIN_FILE (sha256sum-style pin file) so release assets cannot be silently replaced.\n' >&2
  exit 2
fi
if [[ "$distro" == "macos" && "$executor" != "native" ]]; then
  printf 'error: --distro macos requires --executor native\n' >&2
  exit 2
fi
if [[ "$family" != "package" ]]; then
  printf 'error: invalid family %q; valid values: package\n' "$family" >&2
  exit 2
fi
if [[ "$tier" != "container" ]]; then
  printf 'error: invalid tier %q; valid values: container\n' "$tier" >&2
  exit 2
fi
if [[ -n "$staged_dir" ]]; then
  [[ "$release_set" == true && "$release" != "latest" ]] || {
    printf 'error: --staged-dir requires an explicit --release vX.Y.Z\n' >&2; exit 2;
  }
  if [[ ! -d "$staged_dir" ]]; then
    printf 'error: staged directory not found: %s\n' "$staged_dir" >&2
    exit 2
  fi
fi

if [[ ! "$timeout_seconds" =~ ^[1-9][0-9]{0,3}$ ]]; then
  printf 'error: --timeout-seconds must be an integer between 1 and 9999\n' >&2
  exit 2
fi
TIMEOUT_BIN="$(select_tool timeout gtimeout)" || {
  printf 'error: GNU timeout is required (macOS: brew install coreutils for gtimeout)\n' >&2
  exit 3
}
SHA256_BIN="$(select_tool sha256sum shasum)" || {
  printf 'error: sha256sum or shasum is required\n' >&2
  exit 3
}
artifact_source=published
if [[ -n "$staged_dir" ]]; then
  artifact_source=staged
fi
load_release_cases || exit $?
repo="${OMG_SMOKE_REPOSITORY:-${GITHUB_REPOSITORY:-PyRo1121/omg}}"
tag="$release"
if [[ "$distro" == "all" ]]; then
  distros=(arch debian ubuntu fedora)
else
  distros=("$distro")
fi
mkdir -p "$evidence_base"
run_evidence="$(mktemp -d "$evidence_base/run-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")"
results_ndjson="$run_evidence/.results.ndjson"
: > "$results_ndjson"
trap 'rm -f "$results_ndjson"' EXIT

if [[ "$executor" != "native" ]] && ! require_engine; then
  for selected_distro in "${distros[@]}"; do
    record_nonexecution "$selected_distro" "BLOCKED" "container engine is unavailable"
  done
  finalize_results
  exit 3
fi
if [[ -z "$staged_dir" ]]; then
  if ! command -v gh >/dev/null 2>&1; then
    for selected_distro in "${distros[@]}"; do
      record_harness_error "$selected_distro" "gh CLI not found"
    done
    finalize_results
    exit 3
  fi
  if [[ "$release" == "latest" ]]; then
    if ! tag="$(gh release view --repo "$repo" --json tagName --jq .tagName)"; then
      for selected_distro in "${distros[@]}"; do
        record_harness_error "$selected_distro" "latest release could not be resolved"
      done
      finalize_results
      exit 3
    fi
  fi
  if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    for selected_distro in "${distros[@]}"; do
      record_harness_error "$selected_distro" "release tag is not vX.Y.Z"
    done
    finalize_results
    exit 3
  fi
  if ! is_draft="$(gh release view "$tag" --repo "$repo" --json isDraft --jq .isDraft)"; then
    for selected_distro in "${distros[@]}"; do
      record_harness_error "$selected_distro" "release metadata could not be resolved"
    done
    finalize_results
    exit 3
  fi
  if [[ "$is_draft" != "false" ]]; then
    for selected_distro in "${distros[@]}"; do
      record_harness_error "$selected_distro" "release is not published"
    done
    finalize_results
    exit 3
  fi
fi

overall=0
for selected_distro in "${distros[@]}"; do
  rc=0
  run_distro "$selected_distro" || rc=$?
  if [[ $rc -eq 3 ]]; then overall=3; break; fi
  [[ $rc -eq 0 ]] || overall=1
done
finalize_results
exit "$overall"
