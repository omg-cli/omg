#!/usr/bin/env bash
# Check real Make recipes with disposable OS release data and recorded Cargo argv.
set -euo pipefail
cd "$(dirname "$0")/.."
task_dir=$(mktemp -d)
trap 'rm -rf "$task_dir"' EXIT

hosts=(fedora fedora-arm fedora-vendor almalinux)
goals=(build release check clippy clippy-strict test test-lib test-property distro)
if [[ "$#" == 2 ]]; then
  hosts=("$1")
  goals=("$2")
fi

for host in "${hosts[@]}"; do
  fixture="$task_dir/$host"
  mkdir -p "$fixture"/{tools,home}
  cp Makefile Cargo.toml "$fixture/"
  sed -e "s|/etc/os-release|$fixture/primary|g" -e "s|/usr/lib/os-release|$fixture/vendor|g" \
    install.sh > "$fixture/install.sh"
  printf 'ID=arch\n' > "$fixture/vendor"
  expected_features=fedora,license,pgp
  case "$host" in
    arch | debian | macos)
      expected_features="$host,license,pgp"
      printf 'ID=%s\n' "$host" > "$fixture/primary"
      ;;
    almalinux) printf 'ID=almalinux\n' > "$fixture/primary" ;;
    fedora-vendor) printf 'ID=fedora\n' > "$fixture/vendor" ;;
    *) printf 'ID=fedora\n' > "$fixture/primary" ;;
  esac
  cat > "$fixture/tools/uname" <<'TOOL'
#!/usr/bin/env bash
case "$1" in
  -s) printf '%s\n' "$FIXTURE_SYSTEM" ;;
  -m) printf '%s\n' "$FIXTURE_MACHINE" ;;
  *) exit 2 ;;
esac
TOOL
  cat > "$fixture/tools/cargo" <<'TOOL'
#!/usr/bin/env bash
set -euo pipefail
if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
  printf 'target=<%s>\n' "$CARGO_BUILD_TARGET" >> "$FIXTURE_LOG"
fi
printf '<%s>\n' "$@" >> "$FIXTURE_LOG"
TOOL
  cat > "$fixture/tools/cargo-fuzz" <<'TOOL'
#!/usr/bin/env bash
exit 77
TOOL
  chmod 755 "$fixture/tools/"*
  machine=x86_64
  system=Linux
  [[ "$host" != fedora-arm ]] || machine=aarch64
  [[ "$host" != macos ]] || system=Darwin
  cargo_target=""
  [[ "$host" != fedora-arm ]] || cargo_target=aarch64-unknown-linux-gnu

  for goal in "${goals[@]}"; do
    if [[ "$goal" == distro ]]; then
      sed -n '/^detect_distro()/,/^}/p' "$fixture/install.sh" > "$fixture/detect-distro.sh"
      source "$fixture/detect-distro.sh"
      [[ "$(detect_distro)" == fedora ]] || {
        printf 'FAIL: %s distro detection returned %s\n' "$host" "$(detect_distro)" >&2
        exit 1
      }
      printf 'PASS: %s distro detection\n' "$host"
      continue
    fi
    case "$goal" in
      build) args=(build) ;;
      release) args=(build --release) ;;
      check) args=(check) ;;
      clippy) args=(clippy -- -D warnings) ;;
      clippy-strict) args=(clippy --all-targets -- -D warnings) ;;
      test) args=(test) ;;
      test-lib) args=(test --lib) ;;
      test-property) args=(test --test property_tests_v2) ;;
      test-security) args=(test --test security_audit_tests) ;;
      *) exit 2 ;;
    esac
    log="$fixture/$goal-argv"
    if ! env -u BASH_ENV -u ENV HOME="$fixture/home" \
      PATH="$fixture/tools:$PATH" FIXTURE_MACHINE="$machine" FIXTURE_SYSTEM="$system" FIXTURE_LOG="$log" \
      CARGO_BUILD_TARGET="$cargo_target" OMG_UNINSTALL=1 make --no-print-directory -C "$fixture" "$goal" > "$fixture/output" 2>&1; then
      cat "$fixture/output" >&2
      exit 1
    fi
    {
      if [[ -n "$cargo_target" ]]; then printf 'target=<%s>\n' "$cargo_target"; fi
      if [[ "$goal" == test-security ]]; then
        printf '<%s>\n' +nightly fuzz run package_names -- -max_total_time=180 -seed=42 \
          +nightly fuzz run ipc_messages -- -max_total_time=180 -seed=43
      fi
      printf '<%s>\n' "${args[0]}" --locked --no-default-features --features "$expected_features"
      if [[ "${#args[@]}" -gt 1 ]]; then printf '<%s>\n' "${args[@]:1}"; fi
    } > "$fixture/expected"
    if ! diff -u "$fixture/expected" "$log"; then
      printf 'FAIL: %s make %s invoked the wrong Cargo command\n' "$host" "$goal" >&2
      exit 1
    fi
    [[ ! -e "$fixture/home/.config" && ! -e "$fixture/home/.local" ]]
    printf 'PASS: %s make %s\n' "$host" "$goal"
  done
done

if [[ "$#" == 0 ]]; then
  # Also preserve the independent fuzz invocations in the security recipe.
  bash "$0" fedora test-security
  bash "$0" arch test-lib
  bash "$0" debian build
  bash "$0" macos clippy
fi
