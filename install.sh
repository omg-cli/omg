#!/usr/bin/env bash
#
# 🚀 OMG Installer
# The fastest unified package manager for all platforms
# Canonical source: this file. The omg-web production copy must remain byte-identical.
#
# Usage:
#   curl -fsSL https://getomg.xyz/install.sh | bash
#
# Options (set before piping to bash):
#   OMG_NO_TELEMETRY=1  - Disable anonymous telemetry (no prompt)
#   OMG_SKIP_SHELL=1    - Skip shell integration
#   OMG_VERSION=v0.1.0  - Install specific version
#
# Uninstall:
#   curl -fsSL https://... | bash -s -- --uninstall
# (removes binaries and shell integration; rc files are backed up first)
#
# Example with no telemetry:
#   curl -fsSL https://... | OMG_NO_TELEMETRY=1 bash
#

set -uo pipefail

# 🔒 Telemetry opt-out (set before running to skip prompt)
# Usage: OMG_NO_TELEMETRY=1 curl ... | bash
OMG_NO_TELEMETRY="${OMG_NO_TELEMETRY:-}"

# 🎨 Colors (Chalk-like style)
RESET='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[34m'
MAGENTA='\033[35m'
CYAN='\033[36m'
BG_BLUE='\033[44m'
BG_RED='\033[41m'

# ⚙️ Configuration
OMG_VERSION="${OMG_VERSION:-latest}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/omg"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/omg"
REPO_OWNER="omg-cli"
REPO_NAME="omg"

RELEASES_BASE_URL="https://releases.omg.latham.cloud"
LATEST_VERSION_URL="${RELEASES_BASE_URL}/latest-version"
MAX_LATEST_VERSION_BYTES=256
MAX_ARCHIVE_BYTES=$((256 * 1024 * 1024))
MAX_CHECKSUM_BYTES=1024
MAX_VERSION_PROBE_SECONDS=10

# A PATH entry supplied by the caller must not select the release verifier.
gh_path_components_trusted() {
  local component="$1" metadata owner mode
  while :; do
    metadata=$(/usr/bin/stat -c '%u %a' -- "$component" 2>/dev/null) ||
      metadata=$(/usr/bin/stat -f '%u %Lp' "$component" 2>/dev/null) || return 1
    read -r owner mode <<<"$metadata"
    [[ "$owner" =~ ^[0-9]+$ && "$mode" =~ ^[0-7]+$ ]] || return 1
    [[ "$owner" == 0 || "$owner" == "$EUID" ]] || return 1
    if [[ ! -L "$component" ]]; then
      (( (8#$mode & 0022) == 0 )) || return 1
    fi
    [[ "$component" == / ]] && break
    component=${component%/*}
    [[ -n "$component" ]] || component=/
  done
}

gh_candidate_is_trusted() {
  local candidate="$1" resolved parent target hops
  [[ "$candidate" == /* && -f "$candidate" && -x "$candidate" ]] || return 1
  resolved="$candidate"
  for ((hops = 0; hops < 16; hops++)); do
    gh_path_components_trusted "$resolved" || return 1
    parent=$(cd -P -- "${resolved%/*}" && pwd -P) || return 1
    resolved="$parent/${resolved##*/}"
    gh_path_components_trusted "$resolved" || return 1
    if [[ ! -L "$resolved" ]]; then
      [[ -f "$resolved" && -x "$resolved" ]] || return 1
      # Execute the vetted launcher, not its target: snap aliases use argv[0].
      printf '%s\n' "$candidate"
      return 0
    fi
    target=$(/usr/bin/readlink "$resolved") || return 1
    if [[ "$target" == /* ]]; then
      resolved="$target"
    else
      resolved="$parent/$target"
    fi
  done
  return 1
}

trusted_gh() {
  local candidate resolved
  for candidate in /usr/bin/gh /usr/local/bin/gh /opt/homebrew/bin/gh /snap/bin/gh; do
    if resolved=$(gh_candidate_is_trusted "$candidate"); then
      printf '%s\n' "$resolved"
      return 0
    fi
  done
  return 1
}

# Detect directory
SCRIPT_SOURCE="${BASH_SOURCE[0]:-}"
SCRIPT_DIR=""
if [[ -n "$SCRIPT_SOURCE" && -f "$SCRIPT_SOURCE" ]]; then
  SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_SOURCE")" && pwd)"
fi
IS_SOURCE_INSTALL=false
if [[ "${1:-}" == "--from-source" && -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/Cargo.toml" ]]; then
  if grep -q 'name = "omg"' "$SCRIPT_DIR/Cargo.toml" 2>/dev/null; then
    IS_SOURCE_INSTALL=true
  fi
fi

# 🔄 UI Functions
spinner_pid=""
tmp_dir=""

tput_safe() {
  if command -v tput >/dev/null 2>&1 && [[ -n "${TERM-}" ]]; then
    tput "$@"
  fi
}

cleanup_tmp_dir() {
  if [[ -n "$tmp_dir" && -d "$tmp_dir" ]]; then
    rm -rf "$tmp_dir"
    tmp_dir=""
  fi
}

cleanup() {
  if [[ -n "$spinner_pid" ]]; then
    kill "$spinner_pid" >/dev/null 2>&1 || true
  fi
  cleanup_tmp_dir
  tput_safe cnorm # Show cursor
}

# Ask a yes/no question. Honors the documented default when stdin is not a
# terminal (e.g. `curl ... | bash`), so automation never hangs or gets prompted.
ask_yes_no() {
  local prompt="$1"
  local default="${2:-y}"
  local reply=""

  if [[ ! -t 0 ]]; then
    [[ "$default" == "y" ]]
    return
  fi

  local hint
  if [[ "$default" == "y" ]]; then
    hint="[Y/n]"
  else
    hint="[y/N]"
  fi

  read -r -p "${prompt} ${hint} " reply || return 1
  reply="${reply:-$default}"
  [[ "$reply" =~ ^[Yy]$ ]]
}

# Install a binary atomically: stage inside a private `mktemp -d` directory,
# chmod, then rename over the destination so an interrupted install never
# leaves a truncated binary.
#
# SECURITY (daybreak csf_00c97e45): the staging name must never be
# predictable (e.g. `${dst}.tmp.$$`). In a shared install dir a local
# attacker could pre-create that path as a symlink and redirect the copy
# onto an unrelated file outside the install location. `mktemp -d` creates
# an unpredictably named, mode-0700 directory no other user can traverse,
# so the staged copy cannot be redirected before the final rename.
install_binary() {
  local src="$1"
  local dst="$2"
  local staging_dir tmp_dst

  if [[ ! -f "$src" ]]; then
    warn "Skipping $(basename "$dst"): binary missing from install source"
    return 1
  fi

  if [[ -d "$dst" && ! -L "$dst" ]]; then
    error "Refusing to install over a directory: $dst"
  fi

  if ! staging_dir=$(mktemp -d "$(dirname "$dst")/omg-install.XXXXXX"); then
    error "Failed to create a private staging directory in $(dirname "$dst")"
  fi
  tmp_dst="$staging_dir/$(basename "$dst")"

  if ! cp "$src" "$tmp_dst"; then
    rm -rf "$staging_dir"
    error "Failed to copy $(basename "$src") to $INSTALL_DIR"
  fi
  chmod +x "$tmp_dst"
  if ! rename_install_binary "$tmp_dst" "$dst"; then
    rm -rf "$staging_dir"
    error "Failed to install $dst"
  fi
  rmdir "$staging_dir" 2>/dev/null || rm -rf "$staging_dir"
}

# Commit a release's CLI and daemon as one recoverable pair. The filesystem
# cannot rename two paths atomically, so preserve the original CLI until the
# daemon replacement succeeds and restore it on every failure or signal.
install_binary_pair() (
  local first_src="$1" first_dst="$2" second_src="$3" second_dst="$4"
  local transaction_dir first_backup
  local had_first=false first_committed=false

  if [[ ! -f "$first_src" || ! -f "$second_src" ]]; then
    warn "Refusing to install an incomplete binary pair"
    return 1
  fi
  for destination in "$first_dst" "$second_dst"; do
    if [[ -d "$destination" && ! -L "$destination" ]]; then
      warn "Refusing to install over a directory: $destination"
      return 1
    fi
  done
  if ! transaction_dir=$(mktemp -d "$(dirname "$first_dst")/omg-pair.XXXXXX"); then
    warn "Failed to create a private binary-pair transaction directory"
    return 1
  fi
  first_backup="$transaction_dir/first-backup"

  rollback_binary_pair() {
    if [[ "$first_committed" == true ]]; then
      if [[ "$had_first" == true ]]; then
        if ! rename_install_binary "$first_backup" "$first_dst"; then
          warn "CRITICAL: failed to restore $first_dst after daemon installation failed"
        fi
      else
        rm -f "$first_dst"
      fi
    fi
    rm -rf "$transaction_dir"
  }
  trap rollback_binary_pair EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM

  if [[ -e "$first_dst" || -L "$first_dst" ]]; then
    if ! cp -pP "$first_dst" "$first_backup"; then
      warn "Failed to preserve $first_dst before installing the binary pair"
      return 1
    fi
    had_first=true
  fi

  install_binary "$first_src" "$first_dst" || return 1
  first_committed=true
  install_binary "$second_src" "$second_dst" || return 1

  first_committed=false
  trap - EXIT HUP INT TERM
  rm -rf "$transaction_dir"
)

rename_install_binary() {
  # Destination is always a rename target, even if it became a directory
  # after staging began. BSD mv -h still makes a racy directory decision.
  if [[ $(uname -s) == Darwin ]]; then
    if [[ ! -x /usr/bin/perl ]]; then
      warn "Secure binary installation requires /usr/bin/perl on macOS"
      return 1
    fi
    /usr/bin/perl -e 'rename($ARGV[0], $ARGV[1]) or die "Binary rename failed: $!\n"' -- "$1" "$2"
  else
    mv -fT "$1" "$2"
  fi
}

check_runtime_dependencies() {
  local missing=()
  local deps=("curl" "tar" "head" "tr")

  for dep in "${deps[@]}"; do
    if ! command -v "$dep" >/dev/null 2>&1; then
      missing+=("$dep")
    fi
  done
  if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
    missing+=("sha256sum or shasum")
  fi

  if [[ ${#missing[@]} -gt 0 ]]; then
    warn "Missing runtime dependencies for prebuilt install: ${missing[*]}"
    return 1
  fi

  return 0
}

calculate_sha256() {
  local file="$1"

  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  else
    shasum -a 256 "$file" | awk '{print $1}'
  fi
}

check_file_size_bound() {
  local file="$1" max_bytes="$2" label="$3"
  local size
  size=$(wc -c < "$file") || return 1
  if (( size > max_bytes )); then
    warn "${label} exceeded the ${max_bytes} byte bound"
    return 1
  fi
}

# 🌍 OS/Distro/Arch Detection Functions

detect_os() {
  local os
  os="$(uname -s)"
  case "$os" in
  Linux*) echo "linux" ;;
  Darwin*) echo "darwin" ;;
  MINGW* | MSYS* | CYGWIN*) echo "unsupported-windows" ;;
  *) echo "unknown" ;;
  esac
}

detect_distro() {
  local os_release_file="${1:-/etc/os-release}"
  local distro="unknown"
  local id_like=""
  local ID=""
  local ID_LIKE=""

  if [[ -f "$os_release_file" ]]; then
    # shellcheck disable=SC1090
    . "$os_release_file"
    distro="${ID:-unknown}"
    id_like=" ${ID_LIKE:-} "

    case "$distro" in
    ubuntu | debian | arch | fedora) ;;
    rhel | centos) distro="fedora" ;;
    *)
      case "$id_like" in
      *" arch "*) distro="arch" ;;
      *" ubuntu "*) distro="ubuntu" ;;
      *" debian "*) distro="debian" ;;
      *" fedora "* | *" rhel "* | *" centos "*) distro="fedora" ;;
      *) distro="unknown" ;;
      esac
      ;;
    esac
  fi

  echo "$distro"
}

detect_arch() {
  local machine
  machine="$(uname -m)"
  case "$machine" in
  x86_64 | amd64) echo "x86_64" ;;
  aarch64) echo "aarch64" ;;
  arm64) echo "aarch64" ;; # macOS uses arm64, normalize to aarch64
  i686 | i386) echo "i686" ;;
  armv7l) echo "armv7l" ;;
  *) echo "$machine" ;;
  esac
}

probe_release_binary() (
  local binary="$1" name="$2" version="$3"
  local output
  output=$(mktemp "$tmp_dir/${name}-version-probe.XXXXXX") || return 1
  if [[ ! -f "$binary" || -L "$binary" || ! -x "$binary" ]]; then
    warn "Prebuilt ${name} is not a regular executable"
    return 1
  fi
  # A candidate is untrusted until this probe succeeds. Give it an isolated
  # process group so a forked helper cannot outlive a refusal or timeout.
  set -m
  "$binary" --version > "$output" 2>&1 &
  local probe_pid=$!
  local deadline=$((SECONDS + MAX_VERSION_PROBE_SECONDS))
  while kill -0 "$probe_pid" 2>/dev/null; do
    if (( SECONDS >= deadline )); then
      kill -KILL -- "-$probe_pid" 2>/dev/null || true
      wait "$probe_pid" 2>/dev/null || true
      warn "Prebuilt ${name} version probe timed out; existing binaries were not replaced"
      return 1
    fi
    sleep 0.1
  done
  if ! wait "$probe_pid"; then
    warn "Prebuilt ${name} cannot run on this system; existing binaries were not replaced"
    head -c 4096 "$output" >&2
    return 1
  fi
  if kill -0 -- "-$probe_pid" 2>/dev/null; then
    kill -KILL -- "-$probe_pid" 2>/dev/null || true
    warn "Prebuilt ${name} version probe left descendant processes running; existing binaries were not replaced"
    return 1
  fi
  local reported
  reported=$(head -c 4097 "$output")
  if [[ "$reported" != "${name} ${version#v}" ]]; then
    warn "Prebuilt ${name} does not report ${name} ${version#v}; existing binaries were not replaced"
    return 1
  fi
)

select_apt_release() {
  local distro="$1" arch="$2" root="${3:-/}" major directory
  # The published native APT pairs are x86_64. Never guess a foreign ABI,
  # consult caller-controlled loader paths, or downgrade to a different backend.
  if [[ "$arch" == x86_64 ]]; then
    for major in 7.0 6.0; do
      for directory in usr/lib/x86_64-linux-gnu lib/x86_64-linux-gnu; do
        if [[ -f "${root%/}/$directory/libapt-pkg.so.$major" ]]; then
          if [[ "$major" == 7.0 ]]; then
            printf 'debian-trixie\n'
          else
            printf '%s\n' "$distro"
          fi
          return 0
        fi
      done
    done
  fi
  printf 'No compatible native APT release for %s/%s: require a published architecture and libapt-pkg.so.6.0 or .7.0\n' "$distro" "$arch" >&2
  return 1
}

select_artifact() {
  local version="$1"
  local os="$2"
  local distro="$3"
  local arch="$4"
  local library_root="${5:-/}"
  local asset_name=""

  case "$os" in
  linux)
    case "$distro" in
    debian | ubuntu)
      local apt_target
      if ! apt_target=$(select_apt_release "$distro" "$arch" "$library_root"); then
        return 1
      fi
      asset_name="omg-${version}-${arch}-linux-${apt_target}.tar.gz"
      ;;
    arch | fedora)
      if [[ "$arch" != x86_64 ]]; then
        printf 'No published OMG Linux artifact for %s/%s; use a supported x86_64 host or build from source\n' "$distro" "$arch" >&2
        return 1
      fi
      asset_name="omg-${version}-${arch}-linux-${distro}.tar.gz"
      ;;
    *)
      if [[ "$arch" != x86_64 ]]; then
        printf 'No published OMG Linux artifact for %s/%s; use a supported x86_64 host or build from source\n' "$distro" "$arch" >&2
        return 1
      fi
      # Fallback to Fedora binary for unknown distros
      warn "Unknown Linux distro '${distro}', using Fedora binary (pure Rust, most portable)"
      asset_name="omg-${version}-${arch}-linux-fedora.tar.gz"
      ;;
    esac
    ;;
  darwin)
    asset_name="omg-${version}-${arch}-darwin.tar.gz"
    ;;
  *)
    return 1
    ;;
  esac

  echo "$asset_name"
}

validate_version_tag() {
  local tag="$1"
  [[ "$tag" == v* ]] && validate_bare_version "${tag#v}"
}

release_signer_repo() {
  local tag="$1"
  validate_version_tag "$tag" || return 1
  local version="${tag#v}"
  if [[ "$version" == 0.0.* ]] || {
    [[ "$version" =~ ^0\.1\.([0-9]{1,3})([-+].*)?$ ]] &&
      (( 10#${BASH_REMATCH[1]} <= 221 ))
  }; then
    printf '%s\n' 'PyRo1121/omg'
  else
    printf '%s\n' 'omg-cli/omg'
  fi
}

validate_bare_version() {
  local version="$1"
  if [[ ! "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]]; then
    return 1
  fi

  local without_build="${version%%+*}"
  if [[ "$without_build" == *-* ]]; then
    local prerelease="${without_build#*-}"
    local identifier
    local identifiers=()
    IFS='.' read -r -a identifiers <<< "$prerelease"
    for identifier in "${identifiers[@]}"; do
      if [[ "$identifier" =~ ^[0-9]+$ && "$identifier" != "0" && "$identifier" == 0* ]]; then
        return 1
      fi
    done
  fi
}

# GitHub's latest release cannot replace the R2 marker because rollback changes
# only that marker.
resolve_version() {
  if [[ "$OMG_VERSION" != "latest" ]]; then
    if ! validate_version_tag "$OMG_VERSION"; then
      warn "OMG_VERSION must be 'latest' or a version tag such as v1.2.3"
      return 1
    fi
    echo "$OMG_VERSION"
    return 0
  fi

  local marker="" LC_ALL=C
  # Preserve trailing newlines and reject NULs that command substitution would discard.
  if ! marker=$(curl -fsSL --max-filesize "$MAX_LATEST_VERSION_BYTES" "$LATEST_VERSION_URL" |
    head -c "$((MAX_LATEST_VERSION_BYTES + 1))" | tr '\000' '\001' && printf .); then
    warn "Unable to read the latest-version marker from ${LATEST_VERSION_URL}"
    return 1
  fi
  marker="${marker%.}"
  if (( ${#marker} > MAX_LATEST_VERSION_BYTES )); then
    warn "latest-version marker exceeded the ${MAX_LATEST_VERSION_BYTES} byte bound"
    return 1
  fi
  marker="${marker#"${marker%%[![:space:]]*}"}"
  marker="${marker%"${marker##*[![:space:]]}"}"
  if ! validate_bare_version "$marker"; then
    warn "latest-version marker is not a valid bare semantic version"
    return 1
  fi
  echo "v${marker}"
}

install_from_release() {
  if ! check_runtime_dependencies; then
    return 1
  fi

  # Detect system info
  local detected_os
  local detected_distro
  local detected_arch
  detected_os=$(detect_os)
  detected_distro=$(detect_distro)
  detected_arch=$(detect_arch)

  if [[ "$detected_os" == "darwin" && "$detected_arch" == "x86_64" ]]; then
    error "Intel macOS is unsupported. OMG supports macOS releases on Apple Silicon (aarch64)."
  fi

  local actual_version
  if ! actual_version=$(resolve_version); then
    return 1
  fi

  if [[ "$OMG_VERSION" != "latest" && "$actual_version" != "$OMG_VERSION" ]]; then
    warn "Release metadata does not match the requested version"
    return 1
  fi

  # Select correct artifact name
  local artifact_name
  if ! artifact_name=$(select_artifact "$actual_version" "$detected_os" "$detected_distro" "$detected_arch"); then
    return 1
  fi

  if [[ -z "$artifact_name" ]]; then
    warn "Unable to determine artifact name for ${detected_os}/${detected_distro}/${detected_arch}"
    return 1
  fi

  local asset_url="${RELEASES_BASE_URL}/${artifact_name}"

  header "Installing Prebuilt OMG"
  info "Platform: ${detected_os}/${detected_distro}/${detected_arch}"
  tmp_dir=$(mktemp -d)
  trap 'cleanup_tmp_dir' RETURN

  start_spinner "Downloading prebuilt binary"
  local download_file="$tmp_dir/$artifact_name"

  if curl -fsSL --max-filesize "$MAX_ARCHIVE_BYTES" "$asset_url" 2>/dev/null |
    head -c "$((MAX_ARCHIVE_BYTES + 1))" > "$download_file"; then
    stop_spinner "Download complete"
  else
    fail_spinner "Download failed"
    return 1
  fi

  if ! check_file_size_bound "$download_file" "$MAX_ARCHIVE_BYTES" "Downloaded ${artifact_name}"; then
    fail_spinner "Download failed"
    return 1
  fi

  # Verify against the release's .sha256 sidecar without trusting the
  # sidecar's filename field as a filesystem path. Note the trust limit:
  # sidecar and artifact share one origin, so this proves integrity
  # against a corrupted download, not against a compromised release.
  # The independent, release-bound provenance gate follows below.
  start_spinner "Verifying checksum"
  if curl -fsSL --max-filesize "$MAX_CHECKSUM_BYTES" "${asset_url}.sha256" 2>/dev/null |
    head -c "$((MAX_CHECKSUM_BYTES + 1))" > "${download_file}.sha256"; then
    if ! check_file_size_bound "${download_file}.sha256" "$MAX_CHECKSUM_BYTES" "Checksum sidecar for ${artifact_name}"; then
      fail_spinner "Checksum verification failed"
      return 2
    fi
    local expected_checksum
    local actual_checksum
    expected_checksum=$(awk 'NR == 1 { print $1 }' "${download_file}.sha256")
    if [[ ! "$expected_checksum" =~ ^[0-9a-f]{64}$ ]]; then
      fail_spinner "Checksum verification failed"
      warn "Published checksum for ${artifact_name} is malformed"
      return 2
    fi
    actual_checksum=$(calculate_sha256 "$download_file")
    if [[ "$actual_checksum" == "$expected_checksum" ]]; then
      stop_spinner "Checksum verified"
    else
      fail_spinner "Checksum verification failed"
      warn "Downloaded ${artifact_name} does not match its published sha256"
      return 2
    fi
  else
    fail_spinner "Checksum unavailable"
    warn "No .sha256 sidecar published for ${artifact_name}; refusing to install unverified binaries"
    return 2
  fi

  # Provenance gate: every release archive carries a Sigstore build-provenance
  # attestation generated by the release workflow. Both the requested tag
  # and workflow identity must match; a checksum alone is insufficient.
  local gh_bin
  if gh_bin=$(trusted_gh); then
    local signer_repo
    signer_repo=$(release_signer_repo "$actual_version") || return 1
    start_spinner "Verifying build provenance"
    if "$gh_bin" attestation verify "$download_file" -R "$signer_repo" --source-ref "refs/tags/${actual_version}" --signer-workflow "$signer_repo/.github/workflows/release.yml" >/dev/null 2>&1; then
      stop_spinner "Build provenance verified"
    else
      fail_spinner "Build provenance verification failed"
      warn "Sigstore attestation verification failed for ${artifact_name}"
      warn "Possible supply-chain tampering — run manually: gh attestation verify <archive> -R $signer_repo"
      return 2
    fi
  else
    warn "A trusted, system-installed GitHub CLI is required to verify release provenance. Install gh at a protected system path and retry."
    return 1
  fi

  start_spinner "Extracting binaries"
  if tar -xzf "$download_file" -C "$tmp_dir" >/dev/null 2>&1; then
    stop_spinner "Extraction complete"
  else
    fail_spinner "Extraction failed"
    return 1
  fi

  local omg_path
  local omgd_path
  omg_path=$(find "$tmp_dir" -maxdepth 3 -type f -name omg | head -n1)
  omgd_path=$(find "$tmp_dir" -maxdepth 3 -type f -name omgd | head -n1)

  if [[ -z "$omg_path" ]]; then
    warn "Prebuilt archive missing omg binary"
    return 1
  fi
  if [[ -z "$omgd_path" ]]; then
    warn "Prebuilt archive missing omgd binary; existing binaries were not replaced"
    return 1
  fi
  # Both authenticated candidates must start and match the requested release
  # before the first destination write. A distro name alone does not prove ABI.
  probe_release_binary "$omg_path" omg "$actual_version" || return 1
  probe_release_binary "$omgd_path" omgd "$actual_version" || return 1

  mkdir -p "$INSTALL_DIR"
  install_binary_pair "$omg_path" "$INSTALL_DIR/omg" "$omgd_path" "$INSTALL_DIR/omgd" || return 1

  success "Installed prebuilt binaries to $INSTALL_DIR"
  return 0
}

trap cleanup EXIT

info() {
  printf "${BLUE}${BOLD}info${RESET} %s\n" "$1"
}

success() {
  printf "${GREEN}${BOLD}success${RESET} %s\n" "$1"
}

warn() {
  printf "${YELLOW}${BOLD}warn${RESET} %s\n" "$1" >&2
}

error() {
  printf "${RED}${BOLD}error${RESET} %s\n" "$1" >&2
  exit 1
}

header() {
  printf "\n${BOLD}${MAGENTA}==>${RESET} ${BOLD}%s${RESET}\n" "$1"
}

start_spinner() {
  local msg="$1"
  tput_safe civis # Hide cursor

  (
    local chars="⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    while :; do
      for ((i = 0; i < ${#chars}; i++)); do
        local c="${chars:$i:1}"
        printf "\r${CYAN}${c}${RESET} %s..." "$msg"
        sleep 0.1
      done
    done
  ) &
  spinner_pid=$!
}

stop_spinner() {
  if [[ -n "$spinner_pid" ]]; then
    kill "$spinner_pid" >/dev/null 2>&1 || true
    wait "$spinner_pid" >/dev/null 2>&1 || true
    spinner_pid=""
  fi
  tput_safe cnorm # Show cursor
  printf "\r${GREEN}✓${RESET} %s\n" "$1"
}

fail_spinner() {
  if [[ -n "$spinner_pid" ]]; then
    kill "$spinner_pid" >/dev/null 2>&1 || true
    wait "$spinner_pid" >/dev/null 2>&1 || true
    spinner_pid=""
  fi
  tput_safe cnorm # Show cursor
  printf "\r${RED}✗${RESET} %s\n" "$1"
}

print_banner() {
  clear
  printf "${MAGENTA}${BOLD}"
  cat <<'EOF'
    ____  __  __  ____ 
   / __ \|  \/  |/ ___|
  | |  | | |\/| | |  _ 
  | |__| | |  | | |_| |
   \____/|_|  |_|\____|
EOF
  printf "${RESET}\n"
  printf "  ${DIM}The unified package manager for all platforms${RESET}\n\n"
}

# 🛡️ System Checks
check_platform() {
  header "Checking System"

  local detected_os
  local detected_distro
  local detected_arch
  detected_os=$(detect_os)
  detected_distro=$(detect_distro)
  detected_arch=$(detect_arch)

  info "Detected OS: ${detected_os}"
  info "Detected Distro: ${detected_distro}"
  info "Detected Architecture: ${detected_arch}"

  case "$detected_os" in
  linux)
    case "$detected_distro" in
    arch | debian | ubuntu | fedora)
      success "Supported platform detected"
      ;;
    unknown)
      warn "Unknown Linux distro detected - will use Fedora binary (pure Rust, most portable)"
      ;;
    *)
      warn "Untested platform - attempting installation with Fedora binary"
      ;;
    esac
    ;;
  darwin)
    success "macOS detected"
    ;;
  *)
    error "Unsupported platform: ${detected_os}. Please file an issue at https://github.com/PyRo1121/omg/issues"
    ;;
  esac
}

check_dependencies() {
  local missing=()
  local deps=("git" "cargo" "pkg-config" "gcc")

  for dep in "${deps[@]}"; do
    if ! command -v "$dep" >/dev/null 2>&1; then
      missing+=("$dep")
    fi
  done

  # Only the Arch backend (alpm/libalpm toolchain) links these system
  # libraries; Debian/Fedora/macOS source builds must not demand them.
  if [[ "$(detect_distro)" == "arch" ]]; then
    if ! pkg-config --exists libarchive 2>/dev/null; then missing+=("libarchive"); fi
    if ! pkg-config --exists openssl 2>/dev/null; then missing+=("openssl"); fi
  fi

  if [[ ${#missing[@]} -gt 0 ]]; then
    warn "Missing dependencies: ${missing[*]}"
    printf "\n"
    # Non-interactive default is "n": never run sudo without explicit consent.
    if ask_yes_no "Install missing dependencies with sudo?" "n"; then
      start_spinner "Installing dependencies"

      local detected_os
      detected_os=$(detect_os)

      case "$detected_os" in
      linux)
        local detected_distro
        detected_distro=$(detect_distro)
        case "$detected_distro" in
        arch)
          if sudo pacman -S --needed --noconfirm "${missing[@]}" base-devel >/dev/null 2>&1; then
            stop_spinner "Dependencies installed"
          else
            fail_spinner "Failed to install dependencies"
            error "Please install manually: sudo pacman -S ${missing[*]} base-devel"
          fi
          ;;
        debian | ubuntu)
          # Translate probe names to real Debian package names.
          local apt_pkgs=()
          local pkg
          for pkg in "${missing[@]}"; do
            case "$pkg" in
            libarchive) apt_pkgs+=("libarchive-dev") ;;
            openssl) apt_pkgs+=("libssl-dev") ;;
            *) apt_pkgs+=("$pkg") ;;
            esac
          done
          if sudo apt-get update >/dev/null 2>&1 && sudo apt-get install -y "${apt_pkgs[@]}" >/dev/null 2>&1; then
            stop_spinner "Dependencies installed"
          else
            fail_spinner "Failed to install dependencies"
            error "Please install manually: sudo apt-get install ${missing[*]}"
          fi
          ;;
        fedora)
          if sudo dnf install -y "${missing[@]}" >/dev/null 2>&1; then
            stop_spinner "Dependencies installed"
          else
            fail_spinner "Failed to install dependencies"
            error "Please install manually: sudo dnf install ${missing[*]}"
          fi
          ;;
        *)
          fail_spinner "Unknown package manager"
          error "Please install dependencies manually: ${missing[*]}"
          ;;
        esac
        ;;
      darwin)
        if command -v brew >/dev/null 2>&1; then
          if brew install "${missing[@]}" >/dev/null 2>&1; then
            stop_spinner "Dependencies installed"
          else
            fail_spinner "Failed to install dependencies"
            error "Please install manually: brew install ${missing[*]}"
          fi
        else
          fail_spinner "Homebrew not found"
          error "Please install Homebrew first: https://brew.sh"
        fi
        ;;
      *)
        fail_spinner "Unknown OS"
        error "Please install dependencies manually: ${missing[*]}"
        ;;
      esac
    else
      error "Dependencies required to proceed."
    fi
  else
    success "All dependencies satisfied"
  fi
}

# 🏗️ Build & Install
build_omg() {
  header "Building OMG"

  if [[ "$IS_SOURCE_INSTALL" != "true" ]]; then
    error "Remote source fallback is disabled; install a verified release or clone a reviewed tag before running install.sh"
  fi

  local work_dir="$SCRIPT_DIR"
  info "Installing from source directory"
  cd "$work_dir"

  # Select features based on platform. WSL reports Linux and uses its distro backend.
  local cargo_features=""
  local detected_os
  detected_os=$(detect_os)
  local detected_distro
  detected_distro=$(detect_distro)

  case "$detected_os" in
  linux)
    case "$detected_distro" in
    arch) cargo_features="--features arch,license,pgp" ;;
    debian | ubuntu) cargo_features="--no-default-features --features debian,license" ;;
    fedora) cargo_features="--no-default-features --features fedora,license,pgp" ;;
    *) cargo_features="--no-default-features --features fedora,license,pgp" ;;
    esac
    ;;
  darwin)
    cargo_features="--no-default-features --features macos,license,pgp"
    ;;
  *)
    # Runtimes only — no system package manager
    cargo_features="--no-default-features --features license"
    ;;
  esac

  local host_target target_dir
  host_target=$(rustc --print host-tuple) || return 1
  target_dir="${CARGO_TARGET_DIR:-target}"
  info "Build features: ${cargo_features}"
  export RUSTFLAGS="-C target-cpu=native"
  start_spinner "Compiling binary (release)"
  # shellcheck disable=SC2086
  if cargo build --release --quiet --target "$host_target" --target-dir "$target_dir" ${cargo_features} >/dev/null 2>&1; then
    stop_spinner "Build successful"
  else
    fail_spinner "Build failed"
    printf "\n${RED}Build output:${RESET}\n"
    # shellcheck disable=SC2086
    cargo build --release --target "$host_target" --target-dir "$target_dir" ${cargo_features}
    exit 1
  fi

  # Install
  mkdir -p "$INSTALL_DIR"
  install_binary "$target_dir/$host_target/release/omg" "$INSTALL_DIR/omg" || return 1
  if [[ -f "$target_dir/$host_target/release/omgd" ]]; then
    install_binary "$target_dir/$host_target/release/omgd" "$INSTALL_DIR/omgd" || return 1
  fi

  success "Installed to $INSTALL_DIR/omg"
}

# ⚙️ Configuration
setup_config() {
  header "Configuration"

  mkdir -p "$DATA_DIR"/{versions,cache,db}
  mkdir -p "$CONFIG_DIR"

  if [[ ! -f "$CONFIG_DIR/config.toml" ]]; then
    cat >"$CONFIG_DIR/config.toml" <<'EOF'
[general]
use_shims = false

[security]
minimum_grade = "community"

[cache]
ttl_hours = 24
EOF
    success "Default config created"
  else
    info "Config already exists"
  fi
}

# 🔒 Telemetry Setup
setup_telemetry() {
  header "Privacy & Telemetry"

  # Check if already opted out via environment variable
  if [[ "$OMG_NO_TELEMETRY" == "1" ]]; then
    info "Telemetry disabled via OMG_NO_TELEMETRY=1"
    set_telemetry_opt_out
    return
  fi

  # Show privacy disclosure
  printf "\\n${BOLD}Data Collection Disclosure:${RESET}\\n"
  printf "  OMG collects ${BOLD}anonymous${RESET} usage data to improve the product:\\n"
  printf "  • One-time install ping (version, platform, random UUID)\\n"
  printf "  • Command usage statistics (what commands you run)\\n"
  printf "  • Error reports (helps us fix bugs)\\n"
  printf "\\n"
  printf "  ${DIM}No personal information, file contents, or package names collected.${RESET}\\n"
  printf "  ${DIM}Data is sent to omg-api.latham.cloud. You can opt out at any time.${RESET}\\n"
  printf "\\n"

  # Ask for consent; non-interactive runs default to opted-out.
  if ask_yes_no "Allow anonymous telemetry to help improve OMG?" "n"; then
    success "Telemetry enabled. Thank you for helping improve OMG!"
    printf "  ${DIM}Opt out anytime with: export OMG_TELEMETRY=0${RESET}\n"
  else
    set_telemetry_opt_out
    success "Telemetry disabled. You can re-enable with: unset OMG_TELEMETRY"
  fi
}

# Helper to set telemetry opt-out in shell config
set_telemetry_opt_out() {
  local shell_type
  shell_type=$(basename "${SHELL:-/bin/sh}")
  local rc_file=""

  case "$shell_type" in
  bash) rc_file="$HOME/.bashrc" ;;
  zsh) rc_file="$HOME/.zshrc" ;;
  fish) rc_file="$HOME/.config/fish/config.fish" ;;
  *)
    warn "Unsupported shell: $shell_type"
    return
    ;;
  esac

  if [[ -f "$rc_file" ]]; then
    if ! grep -q "OMG_TELEMETRY" "$rc_file"; then
      echo >>"$rc_file"
      echo "# OMG Telemetry opt-out" >>"$rc_file"
      if [[ "$shell_type" == "fish" ]]; then
        echo "set -gx OMG_TELEMETRY 0" >>"$rc_file"
      else
        echo "export OMG_TELEMETRY=0" >>"$rc_file"
      fi
    fi
  fi
}

# 🐚 Shell Setup
quote_posix_path() {
  local value="$1"
  value=${value//\'/\'\\\'\'}
  printf "'%s'" "$value"
}

quote_fish_path() {
  local value="$1"
  value=${value//\\/\\\\}
  value=${value//\'/\\\'}
  printf "'%s'" "$value"
}

shell_path_line() {
  local shell_type="$1"
  local quoted
  if [[ "$shell_type" == fish ]]; then
    quoted=$(quote_fish_path "$INSTALL_DIR")
    printf 'fish_add_path -- %s\n' "$quoted"
  else
    quoted=$(quote_posix_path "$INSTALL_DIR")
    printf 'export PATH=%s:"$PATH"\n' "$quoted"
  fi
}

validate_install_dir_path() {
  if [[ "$INSTALL_DIR" != /* || "$INSTALL_DIR" == *:* || "$INSTALL_DIR" == *$'\n'* || "$INSTALL_DIR" == *$'\r'* ]]; then
    error "INSTALL_DIR must be an absolute path without PATH separators or newlines"
  fi
}

setup_shell() {
  if [[ "${OMG_SKIP_SHELL:-0}" == "1" ]]; then
    info "Skipping shell integration (OMG_SKIP_SHELL=1)"
    return
  fi

  header "Shell Integration"
  validate_install_dir_path

  local shell_type
  shell_type=$(basename "${SHELL:-/bin/sh}")
  local rc_file=""

  case "$shell_type" in
  bash) rc_file="$HOME/.bashrc" ;;
  zsh) rc_file="$HOME/.zshrc" ;;
  fish) rc_file="$HOME/.config/fish/config.fish" ;;
  *)
    warn "Unsupported shell: $shell_type"
    return
    ;;
  esac

  # Ensure PATH
  if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    if [[ -f "$rc_file" ]]; then
      local path_line
      path_line=$(shell_path_line "$shell_type")
      if ! grep -Fqx -- "$path_line" "$rc_file"; then
        printf '%s\n' "$path_line" >>"$rc_file"
        success "Added $INSTALL_DIR to PATH in $rc_file"
      fi
    fi
  fi

  # Ensure Hook
  #
  # SECURITY (daybreak csf_c17f3813): the hook line evaluates only the
  # installed omg binary's own output (`omg hook-env`), which single-quotes
  # every value and refuses repo-controlled `_.source`/`_.path` input. Never
  # source or eval any file from a project repository here.
  if [[ -f "$rc_file" ]]; then
    if ! grep -q "omg hook" "$rc_file"; then
      echo >>"$rc_file"
      echo "# OMG Package Manager" >>"$rc_file"
      if [[ "$shell_type" == "fish" ]]; then
        echo "omg hook fish | source" >>"$rc_file"
      else
        echo 'eval "$(omg hook '"$shell_type"')"' >>"$rc_file"
      fi
      success "Added hook to $rc_file"
    else
      info "Hook already present"
    fi
  fi

  # Generate completions
  "$INSTALL_DIR/omg" completions "$shell_type" >/dev/null 2>&1 || true
}

uninstall_omg() {
  header "Uninstall OMG"
  validate_install_dir_path

  for bin in omg omgd; do
    if [[ -f "$INSTALL_DIR/$bin" ]]; then
      rm -f "$INSTALL_DIR/$bin"
      success "Removed $INSTALL_DIR/$bin"
    else
      info "$bin not present in $INSTALL_DIR"
    fi
  done

  # Remove the exact lines setup_shell appends. Each rc file is backed up
  # first; only OMG's own marker, hook, and PATH lines are deleted.
  for rc_file in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.config/fish/config.fish"; do
    [[ -f "$rc_file" ]] || continue
    local shell_type=bash
    [[ "$rc_file" == */config.fish ]] && shell_type=fish
    local path_line
    path_line=$(shell_path_line "$shell_type")
    if grep -Fqx -- "$path_line" "$rc_file" || grep -qE "# OMG Package Manager|omg hook" "$rc_file"; then
      cp "$rc_file" "$rc_file.omg-backup"
      local filtered
      filtered=$(mktemp "${rc_file}.omg-remove.XXXXXX") || error "Failed to stage shell cleanup"
      cp -p "$rc_file" "$filtered" || error "Failed to preserve shell file permissions"
      OMG_PATH_LINE="$path_line" awk '
        $0 != ENVIRON["OMG_PATH_LINE"] &&
        $0 != "# OMG Package Manager" &&
        $0 != "omg hook fish | source" &&
        $0 != "eval \"$(omg hook bash)\"" &&
        $0 != "eval \"$(omg hook zsh)\""
      ' "$rc_file" >"$filtered" || error "Failed to filter shell integration"
      mv "$filtered" "$rc_file" || error "Failed to update shell integration"
      success "Removed OMG integration from $rc_file (backup at $rc_file.omg-backup)"
    fi
  done

  printf "\n"
  printf "${GREEN}${BOLD}Uninstall Complete!${RESET}\n"
  printf "\n"
  printf "  Config and caches were left in place.\n"
  printf "  Remove them manually if desired.\n"
  printf "\n"
}

finish() {
  printf "\n"
  printf "${GREEN}${BOLD}Installation Complete! 🚀${RESET}\n"
  printf "\n"
  printf "${BOLD}Next Steps:${RESET}\n"
  printf "  1. Restart your terminal\n"
  printf "  2. Run ${CYAN}omg doctor${RESET} to verify setup\n"
  printf "  3. Try ${CYAN}omg search firefox${RESET} to test\n"
  printf "\n"
}

# Run
if [[ "${1:-}" == "--uninstall" || "${OMG_UNINSTALL:-0}" == "1" ]]; then
  uninstall_omg
  exit 0
fi

main() {
  print_banner
  validate_install_dir_path
  if [[ "$IS_SOURCE_INSTALL" == "true" ]]; then
    check_platform
    check_dependencies
    build_omg
  else
    install_from_release || error "No verified prebuilt release is available; refusing unverified installation or source fallback"
  fi
  setup_config
  setup_telemetry
  setup_shell
  finish
}

main
