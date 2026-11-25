#!/usr/bin/env bash
# Run the complete source installer with disposable host/build fixtures.
# This checks producer argv, not compilation or a signed Swift installation.
set -euo pipefail
cd "$(dirname "$0")/.."
task_dir=$(mktemp -d "${TMPDIR:-/tmp}/installer-source.XXXXXX")
trap 'rm -rf "$task_dir"' EXIT

cases=(
  ubuntu22-x86 ubuntu22-arm ubuntu24-x86 ubuntu24-arm debian arch arch-missing-libarchive
  fedora fedora-missing-daemon macos ubuntu-build-failure ubuntu-rename-directory
  ubuntu-missing-binary ubuntu-rustc-failure ubuntu-configured-success
  make-fedora make-fedora-arm make-fedora-rocky make-fedora-missing-daemon
  make-fedora-rename-directory make-fedora-build-failure make-fedora-rustc-failure
  make-fedora-rustflags make-fedora-encoded-flags make-fedora-uninstall-env
  binaries-fedora binaries-fedora-arm binaries-fedora-rocky binaries-fedora-missing-daemon
  binaries-fedora-build-failure binaries-fedora-rustflags binaries-fedora-no-manifest source-fedora-no-manifest
)
if [[ "$#" -gt 0 ]]; then cases=("$@"); fi

for test_name in "${cases[@]}"; do
  entry=source
  scenario="$test_name"
  case "$test_name" in
    make-*) entry=make; scenario="${test_name#make-}" ;;
    binaries-*) entry=binaries; scenario="${test_name#binaries-}" ;;
    source-*) scenario="${test_name#source-}" ;;
  esac
  fixture="$task_dir/$test_name"
  mkdir -p "$fixture/source" "$fixture/tools" "$fixture/home"
  distro=ubuntu
  version=24.04
  machine=x86_64
  system=Linux
  case "$scenario" in
    ubuntu22-*) version=22.04 ;;
    debian) distro=debian; version=12 ;;
    arch*) distro=arch ;;
    fedora*) distro=fedora ;;
    macos) system=Darwin ;;
  esac
  case "$scenario" in *-arm) machine=aarch64 ;; esac
  if [[ "$scenario" == fedora-rocky ]]; then distro=rocky; fi
  printf 'ID=%s\nVERSION_ID=%s\n' "$distro" "$version" > "$fixture/os-release"
  if [[ "$distro" == rocky ]]; then printf 'ID_LIKE="rhel fedora"\n' >> "$fixture/os-release"; fi
  # Only substitute the external host-data path; entry, selection, build,
  # installation and configuration code remain the production installer.
  sed "s|/etc/os-release|$fixture/os-release|g" install.sh > "$fixture/source/install.sh"
  if [[ "$scenario" != *-no-manifest ]]; then
    cp Cargo.toml "$fixture/source/Cargo.toml"
  fi
  if [[ "$entry" == make ]]; then cp Makefile "$fixture/source/Makefile"; fi
  for tool in git gcc curl sudo; do
    cat > "$fixture/tools/$tool" <<'EOF'
#!/usr/bin/env bash
printf 'Unexpected fixture tool invocation: %s\n' "$0" >&2
exit 2
EOF
  done
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
[[ "$FIXTURE_SCENARIO" != *-rustc-failure ]] || exit 1
printf '%s\n' "$FIXTURE_TARGET"
EOF
  cat > "$fixture/tools/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" >> "$FIXTURE/cargo-argv"
printf '\n' >> "$FIXTURE/cargo-argv"
printf '%s\n' "${RUSTFLAGS-unset}" "${CARGO_ENCODED_RUSTFLAGS-unset}" >> "$FIXTURE/rust-flags"
if [[ "$FIXTURE_SCENARIO" == *-build-failure && ! -e "$FIXTURE/failed-build" ]]; then
  touch "$FIXTURE/failed-build"
  printf 'original fixture build diagnostic\n' >&2
  exit 1
fi
mkdir -p "$CARGO_TARGET_DIR/$FIXTURE_TARGET/release"
for binary in omg omgd; do
  if [[ "$FIXTURE_SCENARIO/$binary" == ubuntu-missing-binary/omg ||
        "$FIXTURE_SCENARIO/$binary" == fedora-missing-daemon/omgd ]]; then
    continue
  fi
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
  missing_libarchive=0
  [[ "$scenario" != arch-missing-libarchive ]] || missing_libarchive=1
  rename_directory=0
  [[ "$scenario" != *-rename-directory ]] || rename_directory=1
  fixture_shell=/bin/sh
  skip_shell=1
  case "$scenario" in
    ubuntu-missing-binary | fedora-missing-daemon | ubuntu-rustc-failure | ubuntu-configured-success)
      fixture_shell=/bin/bash
      skip_shell=0
      printf '# Existing shell configuration\n' > "$fixture/home/.bashrc"
      cp "$fixture/home/.bashrc" "$fixture/original-bashrc"
      ;;
  esac
  status=0
  install_path="$fixture/bin"
  entry_command=(bash "$fixture/source/install.sh" --from-source)
  flags=(OMG_NO_TELEMETRY=1)
  case "$entry" in
    make)
      entry_command=(make --no-print-directory -C "$fixture/source" install)
      install_path="$fixture/home/.local/bin"
      ;;
    binaries) entry_command+=(--binaries-only) ;;
  esac
  if [[ "$entry" != source ]]; then
    fixture_shell=/bin/bash
    skip_shell=0
    printf '# Existing shell configuration\n' > "$fixture/home/.bashrc"
    cp "$fixture/home/.bashrc" "$fixture/original-bashrc"
  fi
  case "$scenario" in
    *-rustflags) flags+=(RUSTFLAGS="-C opt-level=2") ;;
    *-encoded-flags) flags+=(CARGO_ENCODED_RUSTFLAGS=$'-C\x1fopt-level=2') ;;
    *-uninstall-env) flags+=(OMG_UNINSTALL=1) ;;
  esac
  if [[ "$scenario" == *-uninstall-env || "$scenario" == *-rename-directory && "$entry" == make ]]; then
    mkdir -p "$install_path"
    printf 'existing bin data\n' > "$install_path/keep"
  fi
  env -u BASH_ENV -u ENV -u OMG_UNINSTALL -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS \
    HOME="$fixture/home" SHELL="$fixture_shell" TERM= \
    PATH="$fixture/tools:$PATH" FIXTURE="$fixture" \
    FIXTURE_SCENARIO="$scenario" \
    FIXTURE_SYSTEM="$system" FIXTURE_MACHINE="$machine" \
    FIXTURE_TARGET="$target" \
    FIXTURE_MISSING_LIBARCHIVE="$missing_libarchive" \
    FIXTURE_RENAME_DIRECTORY="$rename_directory" \
    INSTALL_DIR="$fixture/bin" XDG_CONFIG_HOME="$fixture/config" \
    XDG_DATA_HOME="$fixture/data" CARGO_TARGET_DIR="$fixture/target" \
    OMG_SKIP_SHELL="$skip_shell" \
    "${flags[@]}" "${entry_command[@]}" > "$fixture/output" 2>&1 || status=$?
  if grep -Fq 'Unexpected fixture tool invocation:' "$fixture/output"; then
    cat "$fixture/output" >&2
    exit 1
  fi

  expected_status=0
  [[ "$missing_libarchive" == 0 && "$rename_directory" == 0 ]] || expected_status=1
  case "$scenario" in
    *-missing-binary | *-missing-daemon | *-rustc-failure | *-build-failure | *-no-manifest)
      expected_status=1 ;;
  esac
  if [[ "$entry" == make && "$expected_status" == 1 ]]; then expected_status=2; fi
  if [[ "$status" != "$expected_status" ]]; then
    cat "$fixture/output" >&2
    printf '%s: expected exit %s, got %s\n' "$test_name" "$expected_status" "$status" >&2
    exit 1
  fi
  if [[ "$entry" != source || "$expected_status" != 0 ]]; then
    ! grep -Fq 'Installation Complete!' "$fixture/output"
    [[ ! -e "$fixture/config" && ! -e "$fixture/data" ]]
    if [[ -f "$fixture/original-bashrc" ]]; then cmp "$fixture/original-bashrc" "$fixture/home/.bashrc"; fi
    [[ ! -e "$fixture/home/.bashrc.omg-backup" ]]
  fi
  case "$scenario" in
    *-rustc-failure | *-no-manifest)
      [[ ! -e "$fixture/cargo-argv" && ! -e "$install_path/omg" && ! -e "$install_path/omgd" ]]
      if [[ "$scenario" == *-no-manifest ]]; then grep -Fq 'requires an OMG source checkout' "$fixture/output"; fi
      printf '%s: refused before build or configuration\n' "$test_name"
      continue
      ;;
  esac
  if [[ "$missing_libarchive" == 1 ]]; then
    grep -Fq 'Missing dependencies: libarchive' "$fixture/output"
    [[ ! -e "$fixture/cargo-argv" && ! -e "$fixture/bin/omg" ]]
    printf '%s: missing native library refused before build\n' "$scenario"
    continue
  fi
  expected_features=debian,license,pgp
  case "$scenario" in
    arch) expected_features=arch,license,pgp ;;
    fedora*) expected_features=fedora,license,pgp ;;
    macos) expected_features=macos,license,pgp ;;
  esac
  expected_builds=1
  # Validate the real argv and count each Cargo invocation independently.
  build_count=$(grep -Fxc -- 'build' "$fixture/cargo-argv")
  if [[ "$build_count" != "$expected_builds" ]]; then
    printf '%s: expected one Cargo invocation, observed %s\n' "$test_name" "$build_count" >&2
    exit 1
  fi
  if [[ $(grep -Fxc -- "$expected_features" "$fixture/cargo-argv") != "$expected_builds" ]]; then
    cat "$fixture/cargo-argv" >&2
    printf '%s: build must enable %s on every invocation\n' "$test_name" "$expected_features" >&2
    exit 1
  fi
  [[ $(grep -Fxc -- '--features' "$fixture/cargo-argv") == "$expected_builds" ]]
  [[ $(grep -Fxc -- '--locked' "$fixture/cargo-argv") == "$expected_builds" ]]
  [[ $(grep -Fxc -- "$target" "$fixture/cargo-argv") == "$expected_builds" ]]
  if [[ "$scenario" != arch ]]; then
    [[ $(grep -Fxc -- '--no-default-features' "$fixture/cargo-argv") == "$expected_builds" ]]
  fi
  case "$scenario" in
    *-rustflags) cmp <(printf '%s\n' '-C opt-level=2' unset) "$fixture/rust-flags" ;;
    *-encoded-flags) cmp <(printf '%s\n' unset $'-C\x1fopt-level=2') "$fixture/rust-flags" ;;
  esac
  case "$scenario" in
    *-missing-binary | *-missing-daemon)
      [[ ! -e "$install_path/omg" && ! -e "$install_path/omgd" ]]
      grep -Fq 'binary missing from install source' "$fixture/output"
      ;;
    *-build-failure)
      grep -Fq 'original fixture build diagnostic' "$fixture/output"
      [[ ! -e "$install_path/omg" && ! -e "$install_path/omgd" ]]
      ;;
    *-rename-directory)
      grep -Fq 'Fixture rename failed:' "$fixture/output"
      [[ -d "$install_path/omg" && ! -e "$install_path/omg/omg" && ! -e "$install_path/omgd" ]]
      ;;
    *)
      [[ -x "$install_path/omg" && -x "$install_path/omgd" ]]
      [[ $("$install_path/omg") == 'fixture binary' && $("$install_path/omgd") == 'fixture binary' ]]
      if [[ "$entry" == source ]]; then
        [[ -f "$fixture/config/omg/config.toml" ]]
        grep -Fq 'Installation Complete!' "$fixture/output"
      fi
      if [[ "$scenario" == ubuntu-configured-success ]]; then
        [[ -d "$fixture/data/omg/versions" && -d "$fixture/data/omg/cache" && -d "$fixture/data/omg/db" ]]
        grep -Fxq 'export OMG_TELEMETRY=0' "$fixture/home/.bashrc"
        grep -Fxq 'eval "$(omg hook bash)"' "$fixture/home/.bashrc"
        grep -Fq "$fixture/bin" "$fixture/home/.bashrc"
      fi
      if [[ "$scenario" == *-uninstall-env ]]; then grep -Fqx 'existing bin data' "$install_path/keep"; fi
      ;;
  esac
  printf '%s: producer features verified (%s build invocation(s))\n' "$test_name" "$expected_builds"
done
