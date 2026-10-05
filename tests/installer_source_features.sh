#!/usr/bin/env bash
# Run the complete source installer with disposable host/build fixtures.
# This checks producer argv, not compilation or a signed Swift installation.
set -euo pipefail
cd "$(dirname "$0")/.."
task_dir=$(mktemp -d "${PAPERCLIP_RUN_SCRATCH_DIR:-${TMPDIR:-/tmp}}/installer-source.XXXXXX")
trap 'rm -rf "$task_dir"' EXIT

for scenario in ubuntu22-x86 ubuntu22-arm ubuntu24-x86 ubuntu24-arm debian arch fedora macos ubuntu-retry; do
  fixture="$task_dir/$scenario"
  mkdir -p "$fixture/source" "$fixture/tools" "$fixture/home"
  distro=ubuntu
  version=24.04
  machine=x86_64
  system=Linux
  case "$scenario" in
    ubuntu22-*) version=22.04 ;;
    debian) distro=debian; version=12 ;;
    arch) distro=arch ;;
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
  chmod +x "$fixture/tools/"*
  target="$machine-unknown-linux-gnu"
  [[ "$system" != Darwin ]] || target="$machine-apple-darwin"
  retry=0
  [[ "$scenario" != ubuntu-retry ]] || retry=1
  status=0
  env -u BASH_ENV -u ENV -u OMG_UNINSTALL \
    HOME="$fixture/home" SHELL=/bin/sh TERM= \
    PATH="$fixture/tools:$PATH" FIXTURE="$fixture" \
    FIXTURE_SYSTEM="$system" FIXTURE_MACHINE="$machine" \
    FIXTURE_TARGET="$target" FIXTURE_RETRY="$retry" \
    INSTALL_DIR="$fixture/bin" XDG_CONFIG_HOME="$fixture/config" \
    XDG_DATA_HOME="$fixture/data" CARGO_TARGET_DIR="$fixture/target" \
    OMG_NO_TELEMETRY=1 OMG_SKIP_SHELL=1 \
    bash "$fixture/source/install.sh" --from-source > "$fixture/output" 2>&1 || status=$?
  # The diagnostic retry exits 1 even when its second build succeeds.
  expected_status=0
  [[ "$retry" == 0 ]] || expected_status=1
  if [[ "$status" != "$expected_status" ]]; then
    cat "$fixture/output" >&2
    printf '%s: expected exit %s, got %s\n' "$scenario" "$expected_status" "$status" >&2
    exit 1
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
  if [[ "$retry" == 0 ]]; then
    [[ -x "$fixture/bin/omg" && -x "$fixture/bin/omgd" ]]
    [[ -f "$fixture/config/omg/config.toml" ]]
  else
    [[ ! -e "$fixture/bin/omg" ]]
  fi
  printf '%s: producer features verified (%s build invocation(s))\n' "$scenario" "$expected_builds"
done
