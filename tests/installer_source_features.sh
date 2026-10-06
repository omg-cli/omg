#!/usr/bin/env bash
# Run the complete source installer with disposable host/build fixtures.
# This checks producer argv, not compilation or a signed Swift installation.
set -euo pipefail
cd "$(dirname "$0")/.."
task_dir=$(mktemp -d "${PAPERCLIP_RUN_SCRATCH_DIR:-${TMPDIR:-/tmp}}/installer-source.XXXXXX")
trap 'rm -rf "$task_dir"' EXIT

for scenario in ubuntu22-x86 ubuntu22-arm ubuntu24-x86 ubuntu24-arm debian arch arch-missing-libarchive fedora macos ubuntu-retry ubuntu-rename-directory; do
  fixture="$task_dir/$scenario"
  mkdir -p "$fixture/source" "$fixture/tools" "$fixture/home"
  distro=ubuntu
  version=24.04
  machine=x86_64
  system=Linux
  case "$scenario" in
    ubuntu22-*) version=22.04 ;;
    debian) distro=debian; version=12 ;;
    arch*) distro=arch ;;
    fedora) distro=fedora ;;
    macos) system=Darwin ;;
  esac
  case "$scenario" in *-arm) machine=aarch64 ;; esac
  printf 'ID=%s\nVERSION_ID=%s\n' "$distro" "$version" > "$fixture/os-release"
  # Only substitute the external host-data path; entry, selection, build,
  # installation and configuration code remain the production installer.
  sed "s|/etc/os-release|$fixture/os-release|g" install.sh > "$fixture/source/install.sh"
  cp Cargo.toml "$fixture/source/Cargo.toml"
  cat > "$fixture/tools/uname" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  -s) printf '%s\n' "$FIXTURE_SYSTEM" ;;
  -m) printf '%s\n' "$FIXTURE_MACHINE" ;;
  *) exit 2 ;;
esac
EOF
  cat > "$fixture/tools/rustc" <<'EOF'
#!/usr/bin/env bash
[[ "$*" == '--print host-tuple' ]] || exit 2
printf '%s\n' "$FIXTURE_TARGET"
EOF
  cat > "$fixture/tools/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" >> "$FIXTURE/cargo-argv"
printf '\n' >> "$FIXTURE/cargo-argv"
if [[ "$FIXTURE_RETRY" == 1 && ! -e "$FIXTURE/retried" ]]; then
  touch "$FIXTURE/retried"
  exit 1
fi
mkdir -p "$CARGO_TARGET_DIR/$FIXTURE_TARGET/release"
for binary in omg omgd; do
  printf '#!/bin/sh\nprintf "fixture binary\\n"\n' > "$CARGO_TARGET_DIR/$FIXTURE_TARGET/release/$binary"
  chmod +x "$CARGO_TARGET_DIR/$FIXTURE_TARGET/release/$binary"
done
EOF
  # Native-library availability is fixture input, not a dependency on the host.
  cat > "$fixture/tools/pkg-config" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  '--exists libarchive') [[ "$FIXTURE_MISSING_LIBARCHIVE" == 0 ]] ;;
  '--exists openssl') exit 0 ;;
  *) exit 2 ;;
esac
EOF
  # The simulated Linux host needs file-target rename semantics even when
  # the real runner provides BSD mv. Keep this tool fixture inside its PATH.
  cat > "$fixture/tools/mv" <<'EOF'
#!/usr/bin/env bash
[[ $# == 3 && "$1" == -fT ]] || exit 2
if [[ "$FIXTURE_RENAME_DIRECTORY" == 1 ]]; then mkdir -p "$3"; fi
exec /usr/bin/perl -e 'rename($ARGV[0], $ARGV[1]) or die "Fixture rename failed: $!\n"' -- "$2" "$3"
EOF
  chmod +x "$fixture/tools/"*
  target="$machine-unknown-linux-gnu"
  [[ "$system" != Darwin ]] || target="$machine-apple-darwin"
  retry=0
  [[ "$scenario" != ubuntu-retry ]] || retry=1
  missing_libarchive=0
  [[ "$scenario" != arch-missing-libarchive ]] || missing_libarchive=1
  rename_directory=0
  [[ "$scenario" != ubuntu-rename-directory ]] || rename_directory=1
  status=0
  env -u BASH_ENV -u ENV -u OMG_UNINSTALL \
    HOME="$fixture/home" SHELL=/bin/sh TERM= \
    PATH="$fixture/tools:$PATH" FIXTURE="$fixture" \
    FIXTURE_SYSTEM="$system" FIXTURE_MACHINE="$machine" \
    FIXTURE_TARGET="$target" FIXTURE_RETRY="$retry" \
    FIXTURE_MISSING_LIBARCHIVE="$missing_libarchive" \
    FIXTURE_RENAME_DIRECTORY="$rename_directory" \
    INSTALL_DIR="$fixture/bin" XDG_CONFIG_HOME="$fixture/config" \
    XDG_DATA_HOME="$fixture/data" CARGO_TARGET_DIR="$fixture/target" \
    OMG_NO_TELEMETRY=1 OMG_SKIP_SHELL=1 \
    bash "$fixture/source/install.sh" --from-source > "$fixture/output" 2>&1 || status=$?
  # The diagnostic retry exits 1 even when its second build succeeds.
  expected_status=0
  [[ "$retry" == 0 ]] || expected_status=1
  [[ "$missing_libarchive" == 0 ]] || expected_status=1
  [[ "$rename_directory" == 0 ]] || expected_status=1
  if [[ "$status" != "$expected_status" ]]; then
    cat "$fixture/output" >&2
    printf '%s: expected exit %s, got %s\n' "$scenario" "$expected_status" "$status" >&2
    exit 1
  fi
  if [[ "$missing_libarchive" == 1 ]]; then
    grep -Fq 'Missing dependencies: libarchive' "$fixture/output"
    [[ ! -e "$fixture/cargo-argv" && ! -e "$fixture/bin/omg" ]]
    printf '%s: missing native library refused before build\n' "$scenario"
    continue
  fi
  expected_features=debian,license,pgp
  case "$scenario" in
    arch) expected_features=arch,license,pgp ;;
    fedora) expected_features=fedora,license,pgp ;;
    macos) expected_features=macos,license,pgp ;;
  esac
  expected_builds=$((1 + retry))
  # Check the actual argv delivered to the build tool, including retry.
  if [[ $(grep -Fxc -- "$expected_features" "$fixture/cargo-argv") != "$expected_builds" ]]; then
    cat "$fixture/cargo-argv" >&2
    printf '%s: build must enable %s on every invocation\n' "$scenario" "$expected_features" >&2
    exit 1
  fi
  [[ $(grep -Fxc -- '--features' "$fixture/cargo-argv") == "$expected_builds" ]]
  [[ $(grep -Fxc -- "$target" "$fixture/cargo-argv") == "$expected_builds" ]]
  if [[ "$scenario" != arch ]]; then
    [[ $(grep -Fxc -- '--no-default-features' "$fixture/cargo-argv") == "$expected_builds" ]]
  fi
  if [[ "$rename_directory" == 1 ]]; then
    grep -Fq 'Fixture rename failed:' "$fixture/output"
    [[ -d "$fixture/bin/omg" && ! -e "$fixture/bin/omg/omg" && ! -e "$fixture/bin/omgd" ]]
  elif [[ "$retry" == 0 ]]; then
    [[ -x "$fixture/bin/omg" && -x "$fixture/bin/omgd" ]]
    [[ -f "$fixture/config/omg/config.toml" ]]
  else
    [[ ! -e "$fixture/bin/omg" ]]
  fi
  printf '%s: producer features verified (%s build invocation(s))\n' "$scenario" "$expected_builds"
done
