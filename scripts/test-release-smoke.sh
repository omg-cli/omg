#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
runner="$repo_root/scripts/release-smoke.sh"
scratch_root="$HOME/.cache/build-targets"
mkdir -p "$scratch_root"
scratch="$(mktemp -d "$scratch_root/omg-release-smoke-tests.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/bin" "$scratch/tmp"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

(
  work="$scratch/source-install"
  mkdir -p "$work/bin" "$work/project/target/release" "$work/home"
  printf 'stale\n' > "$work/project/target/release/omg"
  printf 'stale\n' > "$work/project/target/release/omgd"
  cat > "$work/bin/rustc" <<'EOF'
#!/usr/bin/env bash
printf 'fixture-host\n'
EOF
  cat > "$work/bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
target_dir="${CARGO_TARGET_DIR:-target}"
host="${CARGO_BUILD_TARGET:-}"
while (($#)); do
  case "$1" in
    --target-dir) target_dir=$2; shift 2 ;;
    --target) host=$2; shift 2 ;;
    *) shift ;;
  esac
done
output="$target_dir${host:+/$host}/release"
mkdir -p "$output"
printf 'fresh omg\n' > "$output/omg"
printf 'fresh omgd\n' > "$output/omgd"
EOF
  chmod +x "$work/bin/cargo" "$work/bin/rustc"
  export PATH="$work/bin:$PATH" HOME="$work/home"
  export CARGO_TARGET_DIR="$work/redirected output" CARGO_BUILD_TARGET=foreign-host
  source <(sed -n '/^build_omg()/,/^}/p' "$repo_root/install.sh")
  header() { :; }
  info() { :; }
  start_spinner() { :; }
  stop_spinner() { :; }
  success() { :; }
  fail_spinner() { fail "$1"; }
  error() { fail "$1"; }
  detect_os() { printf linux; }
  detect_distro() { printf arch; }
  install_binary() { cp "$1" "$2"; }
  IS_SOURCE_INSTALL=true SCRIPT_DIR="$work/project" INSTALL_DIR="$work/installed"
  build_omg
  grep -qx 'fresh omg' "$INSTALL_DIR/omg" || fail 'source installer copied a stale binary'
  grep -qx 'fresh omgd' "$INSTALL_DIR/omgd" || fail 'source installer copied a stale daemon'
  make -f "$repo_root/Makefile" install >/dev/null
  grep -qx 'fresh omg' "$HOME/.local/bin/omg" || fail 'make install copied a stale binary'
  grep -qx 'fresh omgd' "$HOME/.local/bin/omgd" || fail 'make install copied a stale daemon'
)

results_file() {
  find "$1" -mindepth 2 -maxdepth 2 -name results.json -type f -print -quit
}

assert_rc() {
  local expected=$1
  shift
  local actual=0
  "$@" > "$scratch/command.out" 2>&1 || actual=$?
  [[ "$actual" -eq "$expected" ]] || {
    cat "$scratch/command.out" >&2
    fail "expected exit $expected, got $actual"
  }
}

cat > "$scratch/bin/fake-engine" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ -n "${FAKE_ENGINE_ARGS:-}" ]]; then printf '%s\n' "$@" >> "$FAKE_ENGINE_ARGS"; fi
if [[ "${1:-}" == buildx ]]; then
  case "${2:-}" in
    version) [[ "${FAKE_BUILDX_AVAILABLE:-0}" == 1 ]]; exit $? ;;
    build) shift ;;
    *) exit 2 ;;
  esac
fi
case "${1:-}" in
  info) exit "${FAKE_INFO_EXIT:-0}" ;;
  pull) exit 0 ;;
  build)
    [[ "${FAKE_BUILD_EXIT:-0}" == 0 ]] || exit "$FAKE_BUILD_EXIT"
    iidfile=""
    while (($#)); do
      if [[ "$1" == --iidfile ]]; then iidfile=$2; break; fi
      shift
    done
    [[ -n "$iidfile" ]] || exit 2
    # Docker --iidfile has no trailing newline.
    printf 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' > "$iidfile"
    ;;
  image)
    case "${2:-}" in
      inspect) exit "${FAKE_INSPECT_EXIT:-0}" ;;
      rm) exit "${FAKE_IMAGE_RM_EXIT:-0}" ;;
      *) exit 2 ;;
    esac
    ;;
  run)
    if [[ "${FAKE_HANG:-0}" == 1 ]]; then
      touch "$FAKE_CONTAINER_STATE"
      sleep 30
    fi
    exit "${FAKE_RUN_EXIT:-0}"
    ;;
  rm)
    [[ "${FAKE_CLEANUP_FAIL:-0}" != 1 ]] || exit 1
    rm -f "$FAKE_CONTAINER_STATE"
    ;;
  ps)
    [[ "${FAKE_CLEANUP_FAIL:-0}" != 1 ]] || exit 1
    if [[ -f "$FAKE_CONTAINER_STATE" ]]; then printf 'remaining-container\n'; fi
    ;;
  *) exit 2 ;;
esac
EOF
chmod 700 "$scratch/bin/fake-engine"
ln -s fake-engine "$scratch/bin/docker"
cat > "$scratch/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == "release" ]] || exit 2
case "${2:-}" in
  view)
    if [[ " $* " == *" isDraft "* ]]; then printf 'false\n'; else printf 'v9.9.9\n'; fi
    ;;
  download)
    destination=""
    while [[ $# -gt 0 ]]; do
      if [[ "$1" == "--dir" ]]; then destination=$2; break; fi
      shift
    done
    [[ -n "$destination" ]]
    cp "$FAKE_GH_SOURCE/omg-v9.9.9-x86_64-linux-arch.tar.gz" "$destination/"
    cp "$FAKE_GH_SOURCE/omg-v9.9.9-x86_64-linux-arch.tar.gz.sha256" "$destination/"
    ;;
  *) exit 2 ;;
esac
EOF
chmod 700 "$scratch/bin/gh"

make_stage() {
  local destination=$1
  local directory="omg-v9.9.9-x86_64-linux-${2:-arch}"
  local archive="$directory.tar.gz"
  rm -rf "$destination"
  mkdir -p "$destination/root/$directory"
  printf '#!/usr/bin/env bash\nexit 0\n' > "$destination/root/$directory/omg"
  chmod 700 "$destination/root/$directory/omg"
  tar -czf "$destination/$archive" -C "$destination/root" "$directory"
  printf '%s  %s\n' "$(sha256sum "$destination/$archive" | awk '{print $1}')" "$archive" > "$destination/${archive}.sha256"
}

base_args=(
  --release v9.9.9
  --distro arch
  --case release-package-search-tree
  --container-engine fake-engine
)
export PATH="$scratch/bin:$PATH"
export TMPDIR="$scratch/tmp"
export HOME="$scratch/home"
mkdir -p "$HOME"

assert_rc 2 "$runner" --timeout-seconds 0
assert_rc 2 "$runner" --timeout-seconds -1
assert_rc 2 "$runner" --timeout-seconds 1.5
assert_rc 2 "$runner" --family invalid
assert_rc 2 "$runner" --tier invalid
assert_rc 2 "$runner" --case not-a-contract

grep -q 'valid release contracts' "$scratch/command.out" || fail "unknown case did not list valid contracts"

# macOS runners execute release-smoke.sh with /bin/bash 3.2 (Apple froze it
# at 3.2.57, pre-GPLv3 bash 4.0 which introduced assoc arrays, mapfile and
# $BASHPID per Chet Ramey's 4.0 announcement). Comments are stripped first
# since they legitimately name these constructs. See issue #275.
stripped="$scratch/smoke-no-comments.sh"
sed 's/#.*//' "$runner" > "$stripped"
for token in 'declare -A' 'declare -g' mapfile readarray BASHPID SRANDOM EPOCHSECONDS ';;&' coproc 'printf -v' '|&'; do
  grep -qF "$token" "$stripped" && fail "bash-4+ construct '$token' breaks macOS Bash 3.2"
done

make_stage "$scratch/mismatch"
printf '0%.0s' {1..64} > "$scratch/mismatch/omg-v9.9.9-x86_64-linux-arch.tar.gz.sha256"
printf '  omg-v9.9.9-x86_64-linux-arch.tar.gz\n' >> "$scratch/mismatch/omg-v9.9.9-x86_64-linux-arch.tar.gz.sha256"
assert_rc 3 "$runner" "${base_args[@]}" --staged-dir "$scratch/mismatch" --evidence-dir "$scratch/mismatch-evidence"
grep -q '"result":"HARNESS_ERROR"' "$(results_file "$scratch/mismatch-evidence")" || fail "checksum mismatch was not a harness error"

make_stage "$scratch/missing"
rm "$scratch/missing/omg-v9.9.9-x86_64-linux-arch.tar.gz.sha256"
assert_rc 3 "$runner" "${base_args[@]}" --staged-dir "$scratch/missing" --evidence-dir "$scratch/missing-evidence"
grep -q '"result":"HARNESS_ERROR"' "$(results_file "$scratch/missing-evidence")" || fail "missing sidecar was not a harness error"

make_stage "$scratch/valid"
export FAKE_CONTAINER_STATE="$scratch/container-state"
assert_rc 2 "$runner" --apt-abi 8 --distro debian
assert_rc 2 "$runner" --apt-abi 7 --distro arch
make_stage "$scratch/apt7" debian-trixie
for apt_distro in debian ubuntu; do
  export FAKE_ENGINE_ARGS="$scratch/apt7-$apt_distro-engine"
  assert_rc 0 "$runner" --release v9.9.9 --distro "$apt_distro" --apt-abi 7 \
    --case release-package-search-tree --container-engine fake-engine \
    --staged-dir "$scratch/apt7" --evidence-dir "$scratch/apt7-$apt_distro-evidence"
  grep -q '"result":"PASS"' "$(results_file "$scratch/apt7-$apt_distro-evidence")" || fail 'APT 7 silently skipped the distro contract'
  grep -q "\"distro\":\"$apt_distro\"" "$(results_file "$scratch/apt7-$apt_distro-evidence")" || fail 'APT 7 lost the inventory distro identity'
  if [[ "$apt_distro" == debian ]]; then image_tag=debian:trixie; else image_tag=ubuntu:26.04; fi
  grep -q "$image_tag@sha256:" "$FAKE_ENGINE_ARGS" || fail 'APT 7 used the wrong host image'
  export FAKE_RUN_EXIT=1
  assert_rc 1 "$runner" --release v9.9.9 --distro "$apt_distro" --apt-abi 7 \
    --case release-package-search-tree --container-engine fake-engine \
    --staged-dir "$scratch/apt7" --evidence-dir "$scratch/apt7-$apt_distro-failure"
  grep -q '"result":"PRODUCT_FAIL"' "$(results_file "$scratch/apt7-$apt_distro-failure")" || fail 'APT 7 hid a failing behavior'
  unset FAKE_RUN_EXIT
  assert_rc 3 "$runner" --release v9.9.9 --distro "$apt_distro" --apt-abi 7 \
    --case release-package-search-tree --container-engine fake-engine \
    --staged-dir "$scratch/valid" --evidence-dir "$scratch/apt7-$apt_distro-missing"
  grep -q '"result":"HARNESS_ERROR"' "$(results_file "$scratch/apt7-$apt_distro-missing")" || fail 'missing APT 7 archive was silently skipped'
  missing_metadata="$(dirname "$(results_file "$scratch/apt7-$apt_distro-missing")")/$apt_distro-release-package-search-tree/metadata.txt"
  grep -Fxq 'expected_archive=omg-v9.9.9-x86_64-linux-debian-trixie.tar.gz' "$missing_metadata" || fail 'missing APT 7 evidence lost the expected archive'
  grep -q "^expected_image=$image_tag@sha256:" "$missing_metadata" || fail 'missing APT 7 evidence lost the pinned host image'
done
unset FAKE_ENGINE_ARGS
for failure_code in 120 125 126 127; do
  export FAKE_RUN_EXIT="$failure_code"
  assert_rc 3 "$runner" "${base_args[@]}" --staged-dir "$scratch/valid" --evidence-dir "$scratch/launch-error-$failure_code"
  grep -q '"result":"HARNESS_ERROR"' "$(results_file "$scratch/launch-error-$failure_code")" || fail "setup or engine failure was blamed on the product"
done
unset FAKE_RUN_EXIT

# A hung probe is a PRODUCT signal (timeout exits 124 only when the managed
# command times out; 125/126/127 are the tool/exec failures). The rig's
# responsibility — kill, cleanup proof, code preservation — is asserted
# below and stays HARNESS_ERROR-graded only when IT fails.
export FAKE_HANG=1
assert_rc 1 "$runner" "${base_args[@]}" --timeout-seconds 1 --staged-dir "$scratch/valid" --evidence-dir "$scratch/timeout"
unset FAKE_HANG
[[ ! -e "$FAKE_CONTAINER_STATE" ]] || fail "container survived timeout"
[[ -z "$(find "$HOME/.cache/build-targets/omg-release-smoke" -mindepth 1 -print -quit)" ]] || fail "artifact scratch survived timeout"
grep -R -q 'verified absent:' "$scratch/timeout" || fail "timeout has no cleanup proof"
grep -q '"exit_code":124' "$(results_file "$scratch/timeout")" || fail "timeout code was lost"
grep -q '"result":"PRODUCT_FAIL"' "$(results_file "$scratch/timeout")" || fail "hung product was excused as rig noise"

export FAKE_CLEANUP_FAIL=1
assert_rc 3 "$runner" "${base_args[@]}" --staged-dir "$scratch/valid" --evidence-dir "$scratch/cleanup-error"
unset FAKE_CLEANUP_FAIL
grep -q '"result":"HARNESS_ERROR"' "$(results_file "$scratch/cleanup-error")" || fail "unverified cleanup passed"

export FAKE_INFO_EXIT=1
assert_rc 3 "$runner" "${base_args[@]}" --staged-dir "$scratch/valid" --evidence-dir "$scratch/blocked-evidence"
unset FAKE_INFO_EXIT
grep -q '"result":"BLOCKED"' "$(results_file "$scratch/blocked-evidence")" || fail "unavailable engine was not blocked"

export FAKE_RUN_EXIT=7
assert_rc 1 "$runner" "${base_args[@]}" --staged-dir "$scratch/valid" --evidence-dir "$scratch/failing-evidence"
unset FAKE_RUN_EXIT
find "$scratch/tmp" -mindepth 1 -maxdepth 1 -name 'omg-release-smoke-*' -print -quit | grep -q . && fail "temporary workdir survived failing case"
work_root="$HOME/.cache/build-targets/omg-release-smoke"
[[ -d "$work_root" ]] || fail "runner did not use disk-backed artifact scratch"
[[ -z "$(find "$work_root" -mindepth 1 -print -quit)" ]] || fail "artifact scratch survived failing case"
grep -q '"result":"PRODUCT_FAIL"' "$(results_file "$scratch/failing-evidence")" || fail "failing case was not a product failure"

make_stage "$scratch/fedora" fedora
export FAKE_ENGINE_ARGS="$scratch/fedora-family-engine"
fedora_family_args=(--release v9.9.9 --distro fedora --family package --container-engine fake-engine --staged-dir "$scratch/fedora")
assert_rc 0 "$runner" "${fedora_family_args[@]}" --evidence-dir "$scratch/fedora-family"
[[ "$(grep -c '^build$' "$FAKE_ENGINE_ARGS")" -eq 1 ]] || fail 'Fedora metadata seed did not build exactly once'
[[ "$(grep -c '^run$' "$FAKE_ENGINE_ARGS")" -eq 3 ]] || fail 'Fedora cases did not run in three fresh containers'
[[ "$(grep -c '^image$' "$FAKE_ENGINE_ARGS")" -eq 2 ]] || fail 'Fedora prepared image was not inspected and cleaned up'
grep -Fxq -- '--no-cache' "$FAKE_ENGINE_ARGS" || fail 'Fedora metadata seed reused an unproven old build cache'
[[ "$(grep -c '^sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa$' "$FAKE_ENGINE_ARGS")" -eq 5 ]] || fail 'Fedora cases did not inspect, use and clean up the exact prepared image'
grep -Fxq 'OMG_PROBE_INDEX_CMD=dnf --cacheonly repoquery tree' "$FAKE_ENGINE_ARGS" || fail 'Fedora cases did not assert the seeded metadata cache'
grep -Fq 'fedora:latest@sha256:6c75d5bf57cb0fa5aa4b92c6a83c86c791644496d9ac230de7711f5b8ec3b898' "$(dirname "$(results_file "$scratch/fedora-family")")/fedora-cache-seed.Dockerfile" || fail 'Fedora metadata seed lost its pinned base'
unset FAKE_ENGINE_ARGS
export FAKE_BUILDX_AVAILABLE=1 FAKE_ENGINE_ARGS="$scratch/fedora-buildx-engine"
assert_rc 0 "$runner" "${fedora_family_args[@]}" --container-engine docker --evidence-dir "$scratch/fedora-buildx"
grep -Fxq -- '--load' "$FAKE_ENGINE_ARGS" || fail 'Buildx Fedora seed image was not loaded for fresh containers'
[[ "$(grep -c '^buildx$' "$FAKE_ENGINE_ARGS")" -eq 2 ]] || fail 'Buildx availability and build were not both verified'
unset FAKE_BUILDX_AVAILABLE FAKE_ENGINE_ARGS
export FAKE_BUILD_EXIT=7
assert_rc 3 "$runner" "${fedora_family_args[@]}" --evidence-dir "$scratch/fedora-seed-error"
unset FAKE_BUILD_EXIT
[[ "$(grep -c '"result":"HARNESS_ERROR"' "$(results_file "$scratch/fedora-seed-error")")" -eq 3 ]] || fail 'Fedora metadata seed failure was blamed on the product or skipped cases'
export FAKE_INSPECT_EXIT=7
assert_rc 3 "$runner" "${fedora_family_args[@]}" --evidence-dir "$scratch/fedora-image-missing"
unset FAKE_INSPECT_EXIT
[[ "$(grep -c '"result":"HARNESS_ERROR"' "$(results_file "$scratch/fedora-image-missing")")" -eq 3 ]] || fail 'Unloaded Fedora seed image was blamed on the product'
export FAKE_IMAGE_RM_EXIT=7
assert_rc 3 "$runner" "${fedora_family_args[@]}" --evidence-dir "$scratch/fedora-cleanup-error"
unset FAKE_IMAGE_RM_EXIT
grep -q '"case_id":"release-harness-cleanup".*"result":"HARNESS_ERROR"' "$(results_file "$scratch/fedora-cleanup-error")" || fail 'Fedora seed cleanup failure left aggregate evidence green'
[[ "$(grep -c '"result":"PASS"' "$(results_file "$scratch/fedora-cleanup-error")")" -eq 3 ]] || fail 'Fedora cleanup failure rewrote real package results'
fedora_args=(--release v9.9.9 --distro fedora --case release-package-search-tree --container-engine fake-engine --staged-dir "$scratch/fedora")
assert_rc 0 "$runner" "${fedora_args[@]}" --evidence-dir "$scratch/fixed-defect"
grep -q '"result":"PASS"' "$(results_file "$scratch/fixed-defect")" || fail "fixed defect was forced to fail"
grep -q '"expectation":"known-defect"' "$(results_file "$scratch/fixed-defect")" || fail "historical expectation was lost"
export FAKE_RUN_EXIT=7
assert_rc 1 "$runner" "${fedora_args[@]}" --evidence-dir "$scratch/remaining-defect"
unset FAKE_RUN_EXIT
grep -q '"result":"PRODUCT_FAIL"' "$(results_file "$scratch/remaining-defect")" || fail "remaining defect was hidden"

export FAKE_GH_SOURCE="$scratch/valid"
assert_rc 0 "$runner" "${base_args[@]}" --evidence-dir "$scratch/published-evidence"
grep -q '"result":"PASS"' "$(results_file "$scratch/published-evidence")" || fail "published artifact path did not pass"
grep -q '"artifact_source":"published"' "$(results_file "$scratch/published-evidence")" || fail "published source is not recorded"

family_args=(--release v9.9.9 --distro arch --family package --container-engine fake-engine)
export FAKE_ENGINE_ARGS="$scratch/engine-args"
assert_rc 0 "$runner" "${family_args[@]}" --staged-dir "$scratch/valid" --evidence-dir "$scratch/family-evidence"
grep -Fxq 'OMG_PROBE_INDEX_CMD=pacman-key --init && pacman-key --populate archlinux && pacman -Syu --noconfirm' "$FAKE_ENGINE_ARGS" || fail "Arch setup must initialize trust and perform a full upgrade"
unset FAKE_ENGINE_ARGS
[[ "$(grep -c '"case_id"' "$(results_file "$scratch/family-evidence")")" -eq 3 ]] || fail "package family did not select three contracts"
grep -R -q 'install --yes tree' "$scratch/family-evidence" || fail "install probe did not preserve canonical --yes"
grep -R -q 'remove --yes tree' "$scratch/family-evidence" || fail "remove probe did not preserve canonical --yes"
if grep -R -E '(install|remove) -y tree' "$scratch/family-evidence" >/dev/null; then
  fail "probe substituted the short -y alias"
fi

export GH_TOKEN='fixture-secret-that-must-not-leak'
assert_rc 0 "$runner" "${base_args[@]}" --staged-dir "$scratch/valid" --evidence-dir "$scratch/pass-evidence"
if grep -R -F "$GH_TOKEN" "$scratch/pass-evidence" >/dev/null; then
  fail "secret appeared in evidence"
fi
result="$(results_file "$scratch/pass-evidence")"
grep -q '"case_id":"release-package-search-tree"' "$result" || fail "result omits case id"
grep -q '"distro":"arch"' "$result" || fail "result omits distro"
grep -q '"result":"PASS"' "$result" || fail "result omits pass classification"
grep -q '"artifact_source":"staged"' "$result" || fail "staged result is indistinguishable from a published release"
grep -q '"exit_code":0' "$result" || fail "result omits exit code"
grep -Eq '"elapsed_seconds":[0-9]+' "$result" || fail "result omits elapsed seconds"
assert_rc 0 "$runner" "${base_args[@]}" --staged-dir "$scratch/valid" --evidence-dir "$scratch/pass-evidence"
[[ "$(find "$scratch/pass-evidence" -mindepth 2 -maxdepth 2 -name results.json -type f | wc -l)" -eq 2 ]] || fail "a later invocation replaced prior aggregate evidence"

reporter="$repo_root/scripts/report-smoke-sentry.sh"
mkdir -p "$scratch/sentry-run"
printf '%s\n' '{"dsn":"https://fixturekey@o123.ingest.us.sentry.io/123"}' > "$scratch/sentry-config.json"
printf '%s\n' '[{"case_id":"release-package-search-tree","distro":"arch","result":"PRODUCT_FAIL","exit_code":1,"elapsed_seconds":2,"stderr":"fixture-private-token","environment":{"GH_TOKEN":"fixture-private-token"}}]' > "$scratch/sentry-run/results.json"
cat > "$scratch/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
cat > "$FAKE_SENTRY_ENVELOPE"
printf '%s' "${FAKE_SENTRY_HTTP:-200}"
EOF
chmod 700 "$scratch/bin/curl"
export OMG_SMOKE_SENTRY_CONFIG="$scratch/sentry-config.json"
export FAKE_SENTRY_ENVELOPE="$scratch/envelope.txt"
assert_rc 0 "$reporter" "$scratch/sentry-run/results.json"
if grep -q 'fixture-private-token' "$FAKE_SENTRY_ENVELOPE"; then
  fail "Sentry reporter included unapproved fields"
fi
jq -se 'length == 3 and .[1].type == "event" and .[2].extra.failures[0].result == "PRODUCT_FAIL"' "$FAKE_SENTRY_ENVELOPE" >/dev/null || fail "invalid Sentry envelope"
rm "$FAKE_SENTRY_ENVELOPE"
printf '%s\n' '[{"case_id":"release-package-search-tree","distro":"macos","result":"HARNESS_ERROR","exit_code":3,"elapsed_seconds":2}]' > "$scratch/sentry-run/results-macos.json"
assert_rc 0 "$reporter" "$scratch/sentry-run/results-macos.json"
jq -se '.[2].extra.failures[0].distro == "macos"' "$FAKE_SENTRY_ENVELOPE" >/dev/null || fail "Sentry reporter dropped the macos distro"
rm "$FAKE_SENTRY_ENVELOPE"
# Inventory FAIL rows must reach telemetry without forwarding skipped rows.
printf '%s\n' '[{"case_id":"release-package-search-tree","distro":"arch","result":"PRODUCT_FAIL","exit_code":1,"elapsed_seconds":2},{"case_id":"update-turbo","distro":"arch","result":"FAIL","exit_code":-1,"elapsed_seconds":0},{"case_id":"doctor-eol","distro":"arch","result":"SKIPPED","exit_code":0,"elapsed_seconds":0}]' > "$scratch/sentry-run/results-mixed.json"
assert_rc 0 "$reporter" "$scratch/sentry-run/results-mixed.json"
jq -se '.[2].extra.failures | length == 2 and .[0].result == "PRODUCT_FAIL" and .[1].result == "FAIL"' "$FAKE_SENTRY_ENVELOPE" >/dev/null || fail "inventory failure missing from Sentry report"
rm "$FAKE_SENTRY_ENVELOPE"
assert_rc 0 "$reporter" "$result"
[[ ! -f "$FAKE_SENTRY_ENVELOPE" ]] || fail "passing run sent an error report"
export OMG_SMOKE_ENVIRONMENT=fixture-private-token
assert_rc 2 "$reporter" "$scratch/sentry-run/results.json"
[[ ! -f "$FAKE_SENTRY_ENVELOPE" ]] || fail 'unsupported environment reached Sentry'
unset OMG_SMOKE_ENVIRONMENT
truncate -s 1048577 "$scratch/sentry-run/oversize.json"
assert_rc 2 "$reporter" "$scratch/sentry-run/oversize.json"
[[ ! -f "$FAKE_SENTRY_ENVELOPE" ]] || fail 'oversized input reached Sentry'
export FAKE_SENTRY_HTTP=429
assert_rc 1 "$reporter" "$scratch/sentry-run/results.json"
export FAKE_RUN_EXIT=7
assert_rc 1 "$runner" "${base_args[@]}" --staged-dir "$scratch/valid" --evidence-dir "$scratch/reporting-failure"
unset FAKE_RUN_EXIT FAKE_SENTRY_HTTP OMG_SMOKE_SENTRY_CONFIG FAKE_SENTRY_ENVELOPE
grep -q '"result":"PRODUCT_FAIL"' "$(results_file "$scratch/reporting-failure")" || fail "reporting failure changed the test verdict"

cat > "$scratch/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  pull)
    [[ $# -eq 2 && "$2" =~ ^debian:trixie@sha256:[0-9a-f]{64}$ ]] || exit 99
    if [[ ${FAKE_QEMU_PULL_EXIT:-0} != 0 ]]; then printf 'manifest unknown\n' >&2; fi
    exit "${FAKE_QEMU_PULL_EXIT:-0}" ;;
  version)
    if [[ -n ${FAKE_QEMU_SUITE_PID:-} ]]; then kill -TERM "$FAKE_QEMU_SUITE_PID"; fi
    exit "${FAKE_QEMU_INFO_EXIT:-42}" ;;
  run)
    [[ "$2" == --pull=never ]] || exit 99
    for argument in "$@"; do
      if [[ "$argument" == type=bind,src=*,dst=/work ]]; then
        work=${argument#type=bind,src=}
        work=${work%,dst=/work}
        touch "$work/guest/"{client-key,guest-host-key,user-data,seed.img,overlay.qcow2,base.qcow2,vars.fd,qemu.pid}
        printf '%s\n' "${FAKE_QEMU_SERIAL:-Linux version 6.12 fixture}" > "$work/guest/serial.log"
      fi
    done
    printf '%s\n' "$work" > "$FAKE_QEMU_STATE"
    printf 'fixture-controller\n' ;;
  exec)
      if [[ "${!#}" == collect ]]; then
        cat >/dev/null
        [[ "${FAKE_QEMU_HEALTH_MISSING:-0}" == 0 ]] || exit 1
        printf '{"schema_version":1,"complete":true,"boot_id":"00000000-1111-2222-3333-444444444444","kernel_bytes":100,"fatal_signatures":[],"product_crashes":[]}\n'
        exit 0
      fi
    for argument in "$@"; do
      if [[ "$argument" == /work/qemu-inventory.sh ]]; then
        work=$(<"$FAKE_QEMU_STATE")
        if [[ -n "${FAKE_INVENTORY_RESULT:-}" ]]; then
          mkdir -p "$work/inventory"
          jq -Rn --arg verdict "$FAKE_INVENTORY_RESULT" '
            [inputs | split("\t") | select(.[6] == "hermetic") |
              {case_id:("qemu-arch-" + .[0]), distro:"arch", result:$verdict,
               artifact_source:"inventory", network_scope:"offline", exit_code:0, elapsed_seconds:0, stderr:"fixture-private-token"}]' < "$work/cases.tsv" > "$work/inventory/results.json"
          printf '{"complete":true}\n' > "$work/inventory/summary.json"
          case "${FAKE_INVENTORY_SHAPE:-}" in
            partial) jq '.[0:1]' "$work/inventory/results.json" > "$work/inventory/next.json" ;;
            mixed) jq '.[0].result = "FAIL" | .[1].result = "BLOCKED"' "$work/inventory/results.json" > "$work/inventory/next.json" ;;
            mixed-harness) jq '.[0].result = "FAIL" | .[1].result = "HARNESS_ERROR"' "$work/inventory/results.json" > "$work/inventory/next.json" ;;
            incomplete) printf '{"complete":false}\n' > "$work/inventory/summary.json" ;;
          esac
          [[ ! -f "$work/inventory/next.json" ]] || mv "$work/inventory/next.json" "$work/inventory/results.json"
          if [[ ${FAKE_INVENTORY_COUNTS:-0} == 1 ]]; then
            jq '{complete:true, pass:([.[]|select(.result=="PASS")]|length),
                 fail:([.[]|select(.result=="FAIL" or .result=="BLOCKED" or .result=="HARNESS_ERROR")]|length),
                 skipped:([.[]|select(.result=="SKIPPED")]|length)}' \
              "$work/inventory/results.json" > "$work/inventory/summary.json"
          fi
        fi
        exit "${FAKE_INVENTORY_EXIT:-0}"
      fi
      if [[ "$argument" == /work/qemu-transactions.sh && ${FAKE_QEMU_TRANSACTION_SHAPE:-} == partial ]]; then
        work=$(<"$FAKE_QEMU_STATE")
        mkdir -p "$work/transactions"
        printf '%s\n' '{"schema_version":2,"kind":"transaction-suite","complete":true,"distro":"arch","samples_per_tool":1,"expected_trials":4,"results":[],"bases":{"install":null,"remove":null}}' > "$work/transactions/summary.json"
      fi
      [[ "$argument" != ssh ]] || exit "${FAKE_QEMU_TRANSPORT_EXIT:-${FAKE_QEMU_GUEST_EXIT:-0}}"
      if [[ "$argument" == bench@127.0.0.1:evidence && ${FAKE_QEMU_MISSING_RECEIPT:-0} == 0 ]]; then
        work=$(<"$FAKE_QEMU_STATE")
        mkdir -p "$work/guest/evidence"
        printf '%s\n' "${FAKE_QEMU_GUEST_EXIT:-0}" > "$work/guest/evidence/exit-code"
        case ${FAKE_QEMU_DAEMON_RECEIPT:-valid} in
          valid) printf '%s\n' '{"schema_version":1,"direct":true,"foreground":true,"ipc":true,"singleton":true,"shutdown":true,"restart":true,"query_parity":true,"sigint":true,"cleanup":true,"backend_faults":[]}' > "$work/guest/evidence/daemon-lifecycle.json" ;;
          invalid) printf '%s\n' '{"schema_version":1,"ipc":false}' > "$work/guest/evidence/daemon-lifecycle.json" ;;
          missing) ;;
        esac
        case ${FAKE_QEMU_AUR_RECEIPT:-valid} in
          valid|wrong-events)
            printf '%s\n' '{"schema_version":1,"arch":true,"real_cli":true,"tls_fixture":true,"detailed_metadata":true,"no_aur_suppressed":true,"basic_metadata_absent":true,"expected_connects":2,"expected_requests":2,"unexpected_events":0}' > "$work/guest/evidence/aur-search-flags.json"
            printf '%s\n' \
              '{"event":"connect","value":"aur.archlinux.org:443"}' \
              '{"event":"request","value":"/rpc?v=5&type=search&arg=omgqemuaurprobe"}' \
              '{"event":"connect","value":"aur.archlinux.org:443"}' \
              '{"event":"request","value":"/rpc?v=5&type=search&arg=omgqemuaurprobe"}' \
              > "$work/guest/evidence/aur-fixture-events.jsonl"
            if [[ ${FAKE_QEMU_AUR_RECEIPT:-valid} == wrong-events ]]; then
              printf '%s\n' '{"event":"connect","value":"aur.archlinux.org:443"}' >> "$work/guest/evidence/aur-fixture-events.jsonl"
            fi ;;
          invalid) printf '%s\n' '{"schema_version":1,"no_aur_suppressed":false}' > "$work/guest/evidence/aur-search-flags.json" ;;
          missing) ;;
        esac
        if [[ ${FAKE_QEMU_BENCHMARK:-0} == 1 ]]; then
          benchmark="$work/guest/evidence/benchmarks"
          mkdir -p "$benchmark"
          for scenario in info search explicit; do
            jq -n '{results:(["OMG","pacman"]|map({command:.,times:[1,1],exit_codes:[0,0],
              mean:1,median:1,min:1,max:1,stddev:0,user:0,system:0}))}' > "$benchmark/$scenario.json"
          done
          jq -n '(["OMG","pacman"]|map({label:.,argv:["fixture"]})) as $commands |
            {schema_version:2,complete:true,distro:"arch",daemon:"disabled",min_runs:2,max_runs:2,
             operations:["info","search","explicit"],commands:{info:$commands,search:$commands,explicit:$commands},
             comparisons:{info:{equivalent:true},search:{equivalent:true},explicit:{equivalent:true}}}' > "$benchmark/summary.json"
        fi
      fi
    done ;;
  rm)
    [[ ${FAKE_QEMU_CLEANUP_FAIL:-0} == 0 ]] || exit 1
    rm -f "$FAKE_QEMU_STATE" ;;
  ps) [[ ! -f "$FAKE_QEMU_STATE" ]] || printf 'fixture-controller\n' ;;
  inspect) printf '{"Running":true,"OOMKilled":%s,"ExitCode":0}\n' "${FAKE_QEMU_OOM:-false}" ;;
  *) exit 99 ;;
esac
EOF
chmod 700 "$scratch/bin/docker"
qemu_runner="${OMG_QEMU_TEST_RUNNER:-$repo_root/scripts/benchmark-qemu.sh}"
# This host has no /dev/kvm, so the fixture legs below skip the KVM
# device probe; dedicated probe tests further down cover it explicitly.
export OMG_QEMU_ALLOW_NO_KVM=1
assert_rc 1 "$qemu_runner" --distro all --staged-dir "$scratch/valid" --evidence-dir "$scratch/qemu-unavailable"
qemu_result=$(find "$scratch/qemu-unavailable" -mindepth 2 -maxdepth 2 -name results.json -print -quit)
[[ -n "$qemu_result" ]] || fail 'QEMU suite omitted unavailable-engine results'
jq -e 'length == 4 and ([.[].distro] | sort) == ["arch", "debian", "fedora", "ubuntu"] and all(.[]; .result == "HARNESS_ERROR" and .exit_code == 3)' "$qemu_result" >/dev/null || fail 'QEMU suite omitted a requested distro or misclassified preflight failure'

assert_rc 143 bash -c 'export FAKE_QEMU_SUITE_PID=$$; exec "$@"' _ "$qemu_runner" --distro all --staged-dir "$scratch/valid" --evidence-dir "$scratch/qemu-interrupted"
qemu_result=$(find "$scratch/qemu-interrupted" -mindepth 2 -maxdepth 2 -name results.json -print -quit)
jq -e 'length == 4 and .[0].result == "INCOMPLETE" and all(.[1:][]; .result == "NOT_RUN")' "$qemu_result" >/dev/null || fail 'interrupted QEMU suite lost target states'
for _attempt in {1..100}; do
  child_result=$(find "$scratch/qemu-interrupted" -mindepth 4 -maxdepth 4 -name results.json -print -quit)
  if [[ -n "$child_result" ]] && jq -e '.[0].result == "HARNESS_ERROR"' "$child_result" >/dev/null 2>&1; then break; fi
  sleep 0.1
done
[[ -n "$child_result" ]] || fail 'interrupted QEMU child did not record its exit'

export FAKE_QEMU_INFO_EXIT=0 FAKE_QEMU_STATE="$scratch/qemu-controller"
for scenario in pass pull-failure product-failure product-exit-three timeout cleanup-failure transport-failure missing-receipt missing-daemon invalid-daemon missing-aur invalid-aur wrong-aur-events kernel-crash controller-oom missing-health; do
  export FAKE_QEMU_PULL_EXIT=0
  export FAKE_QEMU_DAEMON_RECEIPT=valid
  export FAKE_QEMU_AUR_RECEIPT=valid
  export FAKE_QEMU_GUEST_EXIT=0 FAKE_QEMU_CLEANUP_FAIL=0 FAKE_QEMU_MISSING_RECEIPT=0
  export FAKE_QEMU_SERIAL='Linux version 6.12 fixture' FAKE_QEMU_OOM=false FAKE_QEMU_HEALTH_MISSING=0
  unset FAKE_QEMU_TRANSPORT_EXIT
  expected_rc=0
  expected_result=PASS
  case "$scenario" in
    pull-failure) export FAKE_QEMU_PULL_EXIT=1; expected_rc=3; expected_result=HARNESS_ERROR ;;
    missing-daemon) export FAKE_QEMU_DAEMON_RECEIPT=missing; expected_rc=1; expected_result=HARNESS_ERROR ;;
    invalid-daemon) export FAKE_QEMU_DAEMON_RECEIPT=invalid; expected_rc=1; expected_result=HARNESS_ERROR ;;
    missing-aur) export FAKE_QEMU_AUR_RECEIPT=missing; expected_rc=1; expected_result=HARNESS_ERROR ;;
    invalid-aur) export FAKE_QEMU_AUR_RECEIPT=invalid; expected_rc=1; expected_result=HARNESS_ERROR ;;
    wrong-aur-events) export FAKE_QEMU_AUR_RECEIPT=wrong-events; expected_rc=1; expected_result=HARNESS_ERROR ;;
    kernel-crash) export FAKE_QEMU_SERIAL='Kernel panic - not syncing: fixture'; expected_rc=120; expected_result=HARNESS_ERROR ;;
    controller-oom) export FAKE_QEMU_OOM=true; expected_rc=120; expected_result=HARNESS_ERROR ;;
    missing-health) export FAKE_QEMU_HEALTH_MISSING=1; expected_rc=120; expected_result=HARNESS_ERROR ;;
    product-failure) export FAKE_QEMU_GUEST_EXIT=1; expected_rc=1; expected_result=PRODUCT_FAIL ;;
    product-exit-three) export FAKE_QEMU_GUEST_EXIT=3; expected_rc=3; expected_result=PRODUCT_FAIL ;;
    timeout) export FAKE_QEMU_GUEST_EXIT=124; expected_rc=124; expected_result=PRODUCT_FAIL ;;
    cleanup-failure) export FAKE_QEMU_CLEANUP_FAIL=1; expected_rc=3; expected_result=HARNESS_ERROR ;;
    transport-failure) export FAKE_QEMU_TRANSPORT_EXIT=1; expected_rc=3; expected_result=HARNESS_ERROR ;;
    missing-receipt) export FAKE_QEMU_MISSING_RECEIPT=1; expected_rc=3; expected_result=HARNESS_ERROR ;;
  esac
  evidence="$scratch/qemu-$scenario"
  assert_rc "$expected_rc" "$qemu_runner" --distro arch --release v9.9.9 --staged-dir "$scratch/valid" --evidence-dir "$evidence"
  qemu_result=$(results_file "$evidence")
  jq -e --arg result "$expected_result" --argjson rc "$expected_rc" 'length == 1 and .[0].result == $result and .[0].exit_code == $rc' "$qemu_result" >/dev/null || fail "QEMU $scenario verdict mismatch"
  work=${qemu_result%/results.json}
  for file in client-key guest-host-key user-data seed.img overlay.qcow2 base.qcow2 vars.fd qemu.pid; do
    if [[ "$scenario" == cleanup-failure ]]; then
      [[ -e "$work/guest/$file" ]] || fail "QEMU deleted $file while controller absence was unverified"
    else
      [[ ! -e "$work/guest/$file" ]] || fail "QEMU $scenario retained $file"
    fi
  done
  if [[ "$scenario" != cleanup-failure ]]; then
    [[ ! -f "$FAKE_QEMU_STATE" ]] || fail "QEMU $scenario retained its controller"
  fi
done
export FAKE_QEMU_GUEST_EXIT=0 FAKE_QEMU_CLEANUP_FAIL=0 FAKE_QEMU_MISSING_RECEIPT=0
export FAKE_QEMU_SERIAL='Linux version 6.12 fixture' FAKE_QEMU_OOM=false FAKE_QEMU_HEALTH_MISSING=0
unset FAKE_QEMU_TRANSPORT_EXIT
export FAKE_QEMU_BENCHMARK=1
for shape in missing partial; do
  export FAKE_QEMU_TRANSACTION_SHAPE="$shape"
  evidence="$scratch/qemu-transaction-$shape"
  assert_rc 120 "$qemu_runner" --distro arch --release v9.9.9 --staged-dir "$scratch/valid" \
    --evidence-dir "$evidence" --benchmark-transactions 1
  qemu_result=$(results_file "$evidence")
  work=${qemu_result%/results.json}
  grep -q 'Measurement validation passed' "$work/benchmark-validation.log" || fail 'read evidence did not reach the transaction gate'
  [[ -f "$work/transaction-validation.log" ]] || fail 'transaction evidence was not checked'
  jq -e '.[0].result=="HARNESS_ERROR"' "$qemu_result" >/dev/null || fail 'missing transaction coverage passed'
done
unset FAKE_QEMU_BENCHMARK FAKE_QEMU_TRANSACTION_SHAPE
for scenario in missing PASS FAIL HARNESS_ERROR BLOCKED SKIPPED partial mixed incomplete; do
  export FAKE_INVENTORY_RESULT="$scenario" FAKE_INVENTORY_EXIT=0
  expected_rc=3
  case "$scenario" in
    missing) unset FAKE_INVENTORY_RESULT ;;
    PASS) expected_rc=0 ;;
    FAIL) expected_rc=1 ;;
    partial|mixed|incomplete)
      export FAKE_INVENTORY_RESULT=PASS FAKE_INVENTORY_SHAPE="$scenario"
      [[ "$scenario" != mixed ]] || expected_rc=1 ;;
  esac
  assert_rc "$expected_rc" "$qemu_runner" --distro arch --release v9.9.9 --staged-dir "$scratch/valid" --inventory-tiers hermetic --evidence-dir "$scratch/qemu-inventory-$scenario"
  unset FAKE_INVENTORY_SHAPE
done
printf 'case\targs_json\tsafety\texpected_exit\texpected_ux\trequires\ttier\ttargets\tassertions\tcleanup\nfirst\t["status"]\tread\t0\tpass\t-\thermetic\thermetic:pass\t-\ttempdir-drop\nsecond\t["info","bash"]\tread\t0\tpass\t-\thermetic\thermetic:pass\t-\ttempdir-drop\n' > "$scratch/policy-cases.tsv"
policy_digest=$(sha256sum "$scratch/policy-cases.tsv" | cut -d ' ' -f 1)
jq -n --arg digest "$policy_digest" '{schema_version:1, profiles:{hermetic:["hermetic"]},
  inventories:{($digest):{cases:(["first","second"]|map({id:.,tiers:["hermetic"],network_scope:"offline",allowed_skips:{}}))}}}' > "$scratch/inventory-policy.json"
export FAKE_INVENTORY_RESULT=FAIL FAKE_INVENTORY_COUNTS=1
assert_rc 1 "$qemu_runner" --distro arch --release v9.9.9 --staged-dir "$scratch/valid" \
  --inventory-tiers hermetic --inventory-file "$scratch/policy-cases.tsv" \
  --inventory-policy "$scratch/inventory-policy.json" --evidence-dir "$scratch/qemu-policy-product-failure"
jq -e '.[0].result == "PASS" and .[0].exit_code == 0' \
  "$(results_file "$scratch/qemu-policy-product-failure")" >/dev/null || fail 'valid failed inventory was relabeled as a lifecycle harness error'
export FAKE_INVENTORY_SHAPE=mixed-harness
assert_rc 1 "$qemu_runner" --distro arch --release v9.9.9 --staged-dir "$scratch/valid" \
  --inventory-tiers hermetic --inventory-file "$scratch/policy-cases.tsv" \
  --inventory-policy "$scratch/inventory-policy.json" --evidence-dir "$scratch/qemu-policy-mixed-harness"
jq -e '.[0].result == "HARNESS_ERROR"' "$(results_file "$scratch/qemu-policy-mixed-harness")" >/dev/null || fail 'product failure hid a simultaneous harness failure'
unset FAKE_INVENTORY_SHAPE
jq '.inventories = {}' "$scratch/inventory-policy.json" > "$scratch/invalid-inventory-policy.json"
assert_rc 1 "$qemu_runner" --distro arch --release v9.9.9 --staged-dir "$scratch/valid" \
  --inventory-tiers hermetic --inventory-file "$scratch/policy-cases.tsv" \
  --inventory-policy "$scratch/invalid-inventory-policy.json" --evidence-dir "$scratch/qemu-policy-invalid"
jq -e '.[0].result == "HARNESS_ERROR"' "$(results_file "$scratch/qemu-policy-invalid")" >/dev/null || fail 'product failure hid invalid policy admission'
unset FAKE_INVENTORY_COUNTS
export FAKE_INVENTORY_RESULT=PASS FAKE_INVENTORY_SHAPE=mixed
export OMG_SMOKE_SENTRY_CONFIG="$scratch/sentry-config.json" FAKE_SENTRY_ENVELOPE="$scratch/qemu-envelope.txt"
assert_rc 1 "$qemu_runner" --distro arch --release v9.9.9 --staged-dir "$scratch/valid" --inventory-tiers hermetic --evidence-dir "$scratch/qemu-row-telemetry"
jq -se '.[2].extra.failures | length == 1 and .[0].result == "FAIL"' "$FAKE_SENTRY_ENVELOPE" >/dev/null || fail 'QEMU row failure duplicated as a lifecycle failure'
jq -e '.[0].result == "PASS" and .[0].exit_code == 0' "$(results_file "$scratch/qemu-row-telemetry")" >/dev/null || fail 'inventory failure overwrote passing lifecycle evidence'
if grep -q 'fixture-private-token' "$FAKE_SENTRY_ENVELOPE"; then fail 'QEMU telemetry included private fields'; fi
unset FAKE_INVENTORY_RESULT FAKE_INVENTORY_EXIT FAKE_INVENTORY_SHAPE OMG_SMOKE_SENTRY_CONFIG FAKE_SENTRY_ENVELOPE
export FAKE_QEMU_GUEST_EXIT=1
assert_rc 1 "$qemu_runner" --distro arch --release v9.9.9 --staged-dir "$scratch/valid" --inventory-tiers hermetic --evidence-dir "$scratch/qemu-blocked-inventory"
blocked_results=$(find "$scratch/qemu-blocked-inventory" -path '*/inventory/results.json' -print -quit)
blocked_ids=$(awk -F '\t' 'NR > 1 && $7 ~ /(^|,)hermetic(,|$)/ {print "qemu-arch-" $1}' \
  "$repo_root/tests/cli_behavior_inventory.tsv" | jq -Rsc 'split("\n") | map(select(length > 0)) | sort')
jq -e --argjson expected "$blocked_ids" '(map(.case_id) | sort) == $expected and all(.[]; .result == "BLOCKED")' \
  "$blocked_results" >/dev/null || fail 'lifecycle failure hid requested coverage'
export FAKE_QEMU_GUEST_EXIT=0
assert_rc 2 "$qemu_runner" --inventory-tiers "hermetic';exit 0;'"
assert_rc 2 "$qemu_runner" --inventory-tiers $'hermetic\n\047;exit 0;\047'
foreign_arch=aarch64
if [[ "$(uname -m)" == aarch64 || "$(uname -m)" == arm64 ]]; then foreign_arch=x86_64; fi
# Preflight probes fail closed to HARNESS_ERROR without needing a guest.
unset OMG_QEMU_ALLOW_NO_KVM
export OMG_QEMU_KVM_DEVICE="$scratch/does-not-exist"
assert_rc 3 "$qemu_runner" --distro arch --release v9.9.9 --staged-dir "$scratch/valid" --evidence-dir "$scratch/qemu-no-kvm"
jq -e 'length == 1 and .[0].result == "HARNESS_ERROR" and .[0].exit_code == 3 and .[0].case_id == "qemu-arch-lifecycle"' "$(results_file "$scratch/qemu-no-kvm")" >/dev/null || fail "missing KVM was not a harness error"
grep -q '^kvm=missing' "$scratch/qemu-no-kvm"/run-*/kvm-probe.log || fail "KVM probe left no evidence"
unset OMG_QEMU_KVM_DEVICE
export OMG_QEMU_ALLOW_NO_KVM=1
foreign_suffix=""; [[ "$foreign_arch" == aarch64 ]] && foreign_suffix="-aarch64"
assert_rc 3 "$qemu_runner" --distro debian --arch "$foreign_arch" --release v9.9.9 --staged-dir "$scratch/valid" --evidence-dir "$scratch/qemu-arch-mismatch"
jq -e --arg case "qemu-debian${foreign_suffix}-lifecycle" 'length == 1 and .[0].result == "HARNESS_ERROR" and .[0].exit_code == 3 and .[0].case_id == $case' "$(results_file "$scratch/qemu-arch-mismatch")" >/dev/null || fail "arch mismatch was not a harness error"
assert_rc 3 "$qemu_runner" --distro arch --arch aarch64 --release v9.9.9 --staged-dir "$scratch/valid" --evidence-dir "$scratch/qemu-arch-nopin"
jq -e 'length == 1 and .[0].result == "HARNESS_ERROR" and .[0].exit_code == 3' "$(results_file "$scratch/qemu-arch-nopin")" >/dev/null || fail "unpinned arch/aarch64 was not a harness error"
# Pin audit: exact publisher hashes, both arches, arch/aarch64 absent.
pins="$("$qemu_runner" --print-pins)"
[[ "$(printf '%s\n' "$pins" | wc -l)" -eq 7 ]] || fail "pin table lost a row"
printf '%s\n' "$pins" | grep -Fq 'debian	aarch64	https://cloud.debian.org/images/cloud/bookworm/20260903-2590/debian-12-generic-arm64-20260903-2590.qcow2	b0144c1c8e09b187b54af300c8ffc22f17b318d0aa6f5a2caba13f3102441572badbeb098458e599b6897bc80dad50fd0094d6e4b9da9f4a2bd63a8f4c99dea5' || fail "debian aarch64 pin mismatch"
printf '%s\n' "$pins" | grep -Fq 'ubuntu	aarch64	https://cloud-images.ubuntu.com/noble/20260826/noble-server-cloudimg-arm64.img	afa139bac6f2629c1e1f2f8f34215f3a9ad9779801bcb945521ba1a45016743f' || fail "ubuntu aarch64 pin mismatch"
printf '%s\n' "$pins" | grep -Fq 'fedora	aarch64	https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/aarch64/images/Fedora-Cloud-Base-Generic-44-1.7.aarch64.qcow2	55c60a3b80d3616a08705afd0459e75fe9f03c54aba7a46e4002a41a72fa0d5b' || fail "fedora aarch64 pin mismatch"
if printf '%s\n' "$pins" | grep -Fq 'arch	aarch64'; then fail "arch/aarch64 must have no pin"; fi
printf '%s\n' "$pins" | grep -Fq 'arch	x86_64' || fail "x86_64 pins missing"
unset FAKE_QEMU_INFO_EXIT FAKE_QEMU_STATE FAKE_QEMU_GUEST_EXIT FAKE_QEMU_CLEANUP_FAIL FAKE_QEMU_TRANSPORT_EXIT FAKE_QEMU_MISSING_RECEIPT OMG_QEMU_ALLOW_NO_KVM

cat > "$scratch/bin/brew" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
state="${FAKE_BREW_STATE:?}"
if [[ -n "${FAKE_BREW_LOG:-}" ]]; then printf '%s\n' "$*" >> "$FAKE_BREW_LOG"; fi
case "${1:-}" in
  update) exit 0 ;;
  list)
    [[ "${2:-}" == tree ]] || exit 1
    grep -qx 'tree' "$state" 2>/dev/null
    ;;
  install)
    [[ "${2:-}" == tree ]] || exit 1
    grep -qx 'tree' "$state" 2>/dev/null || printf 'tree\n' >> "$state"
    ;;
  uninstall|remove)
    [[ "${2:-}" == tree ]] || exit 1
    if [[ -f "$state" ]]; then grep -vx 'tree' "$state" > "$state.tmp" || true; mv "$state.tmp" "$state"; fi
    ;;
  *) exit 1 ;;
esac
EOF
chmod 700 "$scratch/bin/brew"

cat > "$scratch/fake-omg-good" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  --version) printf 'omg 9.9.9\n' ;;
  search)
    [[ "${2:-}" == tree ]] || exit 1
    printf '  tree  directory listing\n'
    ;;
  install) brew install tree ;;
  remove) brew uninstall tree ;;
  *) exit 2 ;;
esac
EOF
cat > "$scratch/fake-omg-bad-search" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  --version) printf 'omg 9.9.9\n' ;;
  search) exit 1 ;;
  install) brew install tree ;;
  remove) brew uninstall tree ;;
  *) exit 2 ;;
esac
EOF
cat > "$scratch/fake-omg-bad-version" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  --version) printf 'omgwrong\n' ;;
  search)
    [[ "${2:-}" == tree ]] || exit 1
    printf '  tree  directory listing\n'
    ;;
  install) brew install tree ;;
  remove) brew uninstall tree ;;
  *) exit 2 ;;
esac
EOF

make_macos_stage() {
  local destination=$1 body_file=$2
  local directory="omg-v9.9.9-aarch64-darwin"
  local archive="$directory.tar.gz"
  rm -rf "$destination"
  mkdir -p "$destination/root/$directory"
  cp "$body_file" "$destination/root/$directory/omg"
  chmod 700 "$destination/root/$directory/omg"
  tar -czf "$destination/$archive" -C "$destination/root" "$directory"
  printf '%s  %s\n' "$(sha256sum "$destination/$archive" | awk '{print $1}')" "$archive" > "$destination/${archive}.sha256"
}

# Native execution runs the extracted release binary on this host, so the runner
# requires an independently pinned digest (`OMG_SMOKE_DIGEST_PIN_FILE`). The
# `.sha256` sidecar ships with the release and cannot serve as that pin. Each
# stage builds its own archive, so pin exactly the bytes it produced.
make_macos_pins() {
  local stage=$1 pins=$2 archive
  : > "$pins"
  for archive in "$stage"/*.tar.gz; do
    [[ -f "$archive" ]] || continue
    printf '%s  %s\n' \
      "$(sha256sum "$archive" | awk '{print $1}')" \
      "$(basename "$archive")" >> "$pins"
  done
}

export FAKE_BREW_STATE="$scratch/brew-state"
export FAKE_BREW_LOG="$scratch/brew-log"
make_macos_stage "$scratch/macos" "$scratch/fake-omg-good"
native_args=(--release v9.9.9 --distro macos --executor native --staged-dir "$scratch/macos")
make_macos_pins "$scratch/macos" "$scratch/native-pins"
export OMG_SMOKE_DIGEST_PIN_FILE="$scratch/native-pins"
: > "$FAKE_BREW_STATE"
: > "$FAKE_BREW_LOG"
assert_rc 0 "$runner" "${native_args[@]}" --evidence-dir "$scratch/native-evidence"
native_result=$(results_file "$scratch/native-evidence")
[[ "$(grep -c '"case_id"' "$native_result")" -eq 3 ]] || fail "native macos did not run three contracts"
[[ "$(grep -c '"result":"PASS"' "$native_result")" -eq 3 ]] || fail "native macos run did not pass every contract"
grep -q '"expectation":"pass"' "$native_result" || fail "native result lost its baseline expectation"
grep -R -q '^engine=native$' "$scratch/native-evidence" || fail "native metadata mislabels the executor"
grep -R -q '^image=native-host$' "$scratch/native-evidence" || fail "native metadata invents a container image"
grep -q '^update$' "$FAKE_BREW_LOG" || fail "native probe skipped the Homebrew index refresh"
grep -q '^install tree$' "$FAKE_BREW_LOG" || fail "native probe never installed through Homebrew"
grep -q '^list tree$' "$FAKE_BREW_LOG" || fail "native probe never asserted through Homebrew"
grep -q '^uninstall tree$' "$FAKE_BREW_LOG" || fail "native cases did not reset the shared probe package"
grep -R -q 'OMG_PROBE_ROOT' "$scratch/native-evidence" || fail "native evidence hides probe rooting"
if grep -R -q 'docker\|fake-engine' "$scratch/native-evidence/macos-"*/transcript.txt 2>/dev/null; then
  fail "native probe shelled out to a container engine"
fi

assert_rc 2 "$runner" --release v9.9.9 --distro macos --staged-dir "$scratch/macos" --evidence-dir "$scratch/native-rejected"
assert_rc 2 "$runner" --release v9.9.9 --distro arch --executor native --staged-dir "$scratch/valid" --evidence-dir "$scratch/native-linux-rejected"
assert_rc 2 "$runner" "${native_args[@]}" --executor bogus --evidence-dir "$scratch/native-bogus"
# Native execution must fail closed when no independent digest pin is given,
# even though the staged archive ships a matching .sha256 sidecar.
(
  unset OMG_SMOKE_DIGEST_PIN_FILE
  assert_rc 2 "$runner" "${native_args[@]}" --evidence-dir "$scratch/native-unpinned"
)

: > "$FAKE_BREW_STATE"
make_macos_stage "$scratch/macos-bad-search" "$scratch/fake-omg-bad-search"
make_macos_pins "$scratch/macos-bad-search" "$scratch/native-pins"
assert_rc 1 "$runner" --release v9.9.9 --distro macos --executor native --case release-package-search-tree --staged-dir "$scratch/macos-bad-search" --evidence-dir "$scratch/native-product-fail"
grep -q '"result":"PRODUCT_FAIL"' "$(results_file "$scratch/native-product-fail")" || fail "native product failure was not blamed on the product"

: > "$FAKE_BREW_STATE"
make_macos_stage "$scratch/macos-bad-version" "$scratch/fake-omg-bad-version"
make_macos_pins "$scratch/macos-bad-version" "$scratch/native-pins"
assert_rc 1 "$runner" --release v9.9.9 --distro macos --executor native --case release-package-search-tree --staged-dir "$scratch/macos-bad-version" --evidence-dir "$scratch/native-version-fail"
grep -q '"result":"PRODUCT_FAIL"' "$(results_file "$scratch/native-version-fail")" || fail "native version mismatch was not blamed on the product"

mkdir -p "$scratch/macbin"
for tool in awk basename bash cat chmod cp date dirname env find grep gzip head mktemp mkdir mv rm tail tar tee tr wc; do
  ln -sf "$(command -v "$tool")" "$scratch/macbin/$tool"
done
if command -v shasum >/dev/null 2>&1; then
  ln -sf "$(command -v shasum)" "$scratch/macbin/shasum"
else
  cat > "$scratch/macbin/shasum" <<EOF
#!/usr/bin/env bash
[[ "\${1:-}" == -a && "\${2:-}" == 256 ]] || exit 2
shift 2
exec "$(command -v sha256sum)" "\$@"
EOF
  chmod 700 "$scratch/macbin/shasum"
fi
cat > "$scratch/macbin/gtimeout" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'gtimeout-stub %s\n' "\$*" >> "$scratch/gtimeout-log"
exec "$(command -v timeout)" "\$@"
EOF
chmod 700 "$scratch/macbin/gtimeout"
cp "$scratch/bin/brew" "$scratch/macbin/brew"
: > "$FAKE_BREW_STATE"
: > "$scratch/gtimeout-log"
make_macos_pins "$scratch/macos" "$scratch/native-pins"
PATH="$scratch/macbin" assert_rc 0 "$runner" "${native_args[@]}" --evidence-dir "$scratch/native-mac-tools"
mac_result=$(results_file "$scratch/native-mac-tools")
[[ "$(grep -c '"result":"PASS"' "$mac_result")" -eq 3 ]] || fail "macOS toolset run did not pass every contract"
grep -q 'gtimeout-stub' "$scratch/gtimeout-log" || fail "macOS toolset run did not fall back to gtimeout"

# Per-distro expected exits (#303): source only the pure resolvers out of
# the runner (anchored extraction keeps the suite hermetic).
# shellcheck disable=SC1090
source <(sed -n '/^exit_for_distro/,/^}/p;/^valid_expected_exit/,/^}/p' "$runner")
[[ "$(exit_for_distro "0" arch)" == "0" ]] || fail "bare exit must apply to every distro"
[[ "$(exit_for_distro "0" debian)" == "0" ]] || fail "bare exit must apply to debian"
[[ "$(exit_for_distro "arch:0,debian:1,ubuntu:1,fedora:1" debian)" == "1" ]] || fail "matrix must resolve debian refusal"
[[ "$(exit_for_distro "arch:0,debian:1,ubuntu:1,fedora:1" arch)" == "0" ]] || fail "matrix must resolve arch pass"
exit_for_distro "arch:0,debian:1,ubuntu:1,fedora:1" macos >/dev/null 2>&1 && fail "unlisted distro must not resolve"
exit_for_distro "arch:0,debian:1,ubuntu:1" fedora >/dev/null 2>&1 && fail "partial matrix must not resolve"
valid_expected_exit "0" || fail "bare exit must validate"
valid_expected_exit "arch:0,debian:1,ubuntu:1,fedora:1" || fail "complete matrix must validate"
valid_expected_exit "arch:0,debian:1,ubuntu:1" && fail "partial matrix must not validate"
valid_expected_exit "arch:0,arch:1,debian:1,ubuntu:1,fedora:1" && fail "duplicate distro must not validate"
valid_expected_exit "arch:0,debian:1,ubuntu:1,centos:1" && fail "unknown distro must not validate"
valid_expected_exit "arch:0,debian:x,ubuntu:1,fedora:1" && fail "non-numeric code must not validate"

# Exercise the real inventory runner and remote shell, with only SSH replaced.
# The fake product and guest HOME are disposable; no host package calls occur.
inventory_runner="$repo_root/scripts/qemu-inventory.sh"
cat > "$scratch/bin/ssh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ ${FAKE_INVENTORY_TRANSPORT:-0} == 0 ]] || exit "$FAKE_INVENTORY_TRANSPORT"
if [[ -n "${FAKE_INVENTORY_HOME:-}" ]]; then export HOME="$FAKE_INVENTORY_HOME"; fi
exec bash -c "${!#}"
EOF
cat > "$scratch/fake inventory omg" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  fail) printf 'deliberate fixture refusal\n' >&2; exit 1 ;;
  silent-fail) exit 1 ;;
  exit-code) printf 'deliberate fixture exit %s\n' "$2" >&2; exit "$2" ;;
  json) printf '{"ok":true}\n' ;;
  bad-json) printf 'not json\n' ;;
  artifact) printf '{}\n' > "$2" ;;
  sbom-marked)
    printf '{"bomFormat":"CycloneDX","components":[{"name":"fixture"}],"metadata":{"component":{"properties":[{"name":"omg:advisory-scan","value":"not-performed"}]}}}\n' > "$2"
    printf 'Inventory only: advisory matching was skipped\n'
    ;;
  sbom-unmarked)
    printf '{"bomFormat":"CycloneDX","components":[{"name":"fixture"}],"metadata":{"component":{"properties":[]}}}\n' > "$2"
    printf 'Inventory only: advisory matching was skipped\n'
    ;;
  sbom-silent)
    printf '{"bomFormat":"CycloneDX","components":[{"name":"fixture"}],"metadata":{"component":{"properties":[{"name":"omg:advisory-scan","value":"not-performed"}]}}}\n' > "$2"
    ;;
  require) test -s "$2" ;;
  missing) exit 0 ;;
  hang) sleep 30 ;;
  interrupt) kill -TERM "$FAKE_INVENTORY_PID" ;;
  literal) [[ "$2" == '$(touch MUST_NOT_EXIST)' ]] ;;
  empty-arg) [[ "$#" == 3 && "$2" == '' && "$3" == tail ]] ;;
  path) command -v 'fake inventory omg' ;;
  update)
    case "${2:-}" in
      --fast) printf 'Fast System Update\nSynced package catalogs\nUpgraded 5 packages\n' ;;
      --turbo) printf 'TURBO System Update\ncached, no sync\nUpgraded 1 packages\n' ;;
      *) exit 2 ;;
    esac
    ;;
  update-standard-sync) printf 'Update\nSynced package catalogs\nSystem is up to date\n' ;;
  update-standard-cached) printf 'Update\nChecking for updates · cached\nSystem is up to date\n' ;;
  *) exit 2 ;;
esac
EOF
chmod 700 "$scratch/bin/ssh" "$scratch/fake inventory omg"
inv_header=$'case\targs_json\tsafety\texpected_exit\texpected_ux\trequires\ttier\ttargets\tassertions\tcleanup'
inv_row() { printf '%s\t%s\t%s\t%s\tpass\t%s\thermetic\t%s\t%s\ttempdir-drop\n' "$1" "$2" "${6:-read}" "$3" "${4:--}" "${7:-hermetic:pass}" "${5:--}"; }
run_inventory() {
  local name=$1 expected=$2
  local mutation_args=()
  shift 2
  [[ ${FAKE_INVENTORY_ALLOW_MUTATIONS:-0} != 1 ]] || mutation_args+=(--allow-mutations)
  mkdir -p "$scratch/inventory-$name/guest"
  printf '%s\n' "$inv_header" > "$scratch/inventory-$name.tsv"
  printf '%s\n' "$@" >> "$scratch/inventory-$name.tsv"
  assert_rc "$expected" bash -c 'export FAKE_INVENTORY_PID=$$; exec "$@"' _ "$inventory_runner" --work "$scratch/inventory-$name" --distro arch --tiers hermetic --tag v9.9.9 --binary "$scratch/fake inventory omg" --tsv "$scratch/inventory-$name.tsv" --row-timeout 1 "${mutation_args[@]}"
}
inv_verdict() {
  jq -e --arg id "qemu-arch-$2" --arg verdict "$3" 'any(.[]; .case_id == $id and .result == $verdict)' "$scratch/inventory-$1/inventory/results.json" >/dev/null || fail "inventory $1/$2 expected $3"
}
run_inventory known-defect 1 "$(inv_row broken '["fail"]' 0 - - read 'arch:known-defect')"
inv_verdict known-defect broken FAIL
export FAKE_INVENTORY_TRANSPORT=1
run_inventory transport 1 "$(inv_row refusal '["fail"]' 1)"
inv_verdict transport refusal HARNESS_ERROR
unset FAKE_INVENTORY_TRANSPORT
run_inventory refusal 0 "$(inv_row refusal '["fail"]' 1)"
run_inventory silent-refusal 1 "$(inv_row refusal '["silent-fail"]' 1)"
inv_verdict silent-refusal refusal FAIL
run_inventory path 0 "$(inv_row path '["path"]' 0)"
inv_verdict refusal refusal PASS
for code in 124 125 126 127 137; do
  run_inventory "product-exit-$code" 0 "$(inv_row product "[\"exit-code\",\"$code\"]" "$code")"
  inv_verdict "product-exit-$code" product PASS
done
run_inventory missing-exit 2 "$(inv_row invalid '["json"]' 'debian:0')"
run_inventory duplicate-exit 2 "$(inv_row invalid '["json"]' 'arch:0,arch:1,debian:0,ubuntu:0,fedora:0')"
run_inventory cycle 2 "$(inv_row cycle '["json"]' 0 cycle)"
run_inventory invalid-prerequisite 2 "$(inv_row invalid '["json"]' 0 '$(touch MUST_NOT_EXIST)')"
run_inventory nul-argument 2 "$(inv_row invalid '["literal","a\u0000b"]' 0)"
run_inventory assertions 1 \
  "$(inv_row valid-json '["json"]' 0 - json-stdout)" \
  "$(inv_row invalid-json '["bad-json"]' 0 - json-stdout)" \
  "$(inv_row missing-artifact '["missing"]' 0 - artifact:manifest.json)" \
  "$(inv_row missing-child '["json"]' 0 missing-artifact)" \
  "$(inv_row export '["artifact","${ROOT}/manifest.json"]' 0 - artifact:manifest.json)" \
  "$(inv_row import '["require","${ROOT}/manifest.json"]' 0 export)" \
  "$(inv_row literal '["literal","$(touch MUST_NOT_EXIST)"]' 0)"
inv_verdict assertions valid-json PASS
inv_verdict assertions invalid-json FAIL
inv_verdict assertions missing-artifact FAIL
inv_verdict assertions missing-child BLOCKED
inv_verdict assertions export PASS
inv_verdict assertions import PASS
inv_verdict assertions literal PASS
run_inventory sbom-inventory-only 0 \
  "$(inv_row sbom-marked '["sbom-marked","${ROOT}/sbom.json"]' 0 - sbom-inventory-only)"
inv_verdict sbom-inventory-only sbom-marked PASS
run_inventory sbom-inventory-lies 1 \
  "$(inv_row sbom-unmarked '["sbom-unmarked","${ROOT}/sbom.json"]' 0 - sbom-inventory-only)" \
  "$(inv_row sbom-silent '["sbom-silent","${ROOT}/sbom.json"]' 0 - sbom-inventory-only)"
inv_verdict sbom-inventory-lies sbom-unmarked FAIL
inv_verdict sbom-inventory-lies sbom-silent FAIL
export FAKE_INVENTORY_ALLOW_MUTATIONS=1
run_inventory update-modes 0 \
  "$(inv_row update-fast '["update","--fast"]' 0 - update-fast-output package-mutation)" \
  "$(inv_row update-turbo '["update","--turbo"]' 0 - update-turbo-output package-mutation)"
inv_verdict update-modes update-fast PASS
inv_verdict update-modes update-turbo PASS
run_inventory update-mode-lies 1 \
  "$(inv_row update-fast '["update-standard-sync"]' 0 - update-fast-output package-mutation)" \
  "$(inv_row update-turbo '["update-standard-cached"]' 0 - update-turbo-output package-mutation)"
inv_verdict update-mode-lies update-fast FAIL
inv_verdict update-mode-lies update-turbo FAIL
mkdir -p "$scratch/inventory-home"
cat > "$scratch/inventory-home/qemu-daemon-check.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ $# == 2 && -x "$1" && -d "$2" ]]
printf '{"schema_version":1,"direct":true,"foreground":true,"ipc":true,"singleton":true,"shutdown":true,"restart":true,"query_parity":%s,"sigint":true,"cleanup":true,"backend_faults":[]}\n' \
  "${FAKE_DAEMON_QUERY_PARITY:-true}" > "$2/daemon-lifecycle.json"
printf 'foreground daemon lifecycle verified\n'
EOF
chmod 700 "$scratch/inventory-home/qemu-daemon-check.sh"
export FAKE_INVENTORY_HOME="$scratch/inventory-home"
run_inventory daemon-foreground 0 \
  "$(inv_row daemon-foreground '["daemon","--foreground"]' 0 - daemon-foreground-lifecycle service-mutation)"
inv_verdict daemon-foreground daemon-foreground PASS
export FAKE_DAEMON_QUERY_PARITY=false
run_inventory daemon-foreground-lies 1 \
  "$(inv_row daemon-foreground '["daemon","--foreground"]' 0 - daemon-foreground-lifecycle service-mutation)"
inv_verdict daemon-foreground-lies daemon-foreground FAIL
unset FAKE_DAEMON_QUERY_PARITY FAKE_INVENTORY_HOME FAKE_INVENTORY_ALLOW_MUTATIONS
run_inventory empty-argument 0 "$(inv_row empty '["empty-arg","","tail"]' 0)"
inv_verdict empty-argument empty PASS
run_inventory json-dependency 1 \
  "$(inv_row setup '["bad-json"]' 0 - json-stdout)" \
  "$(inv_row child '["json"]' 0 setup)"
inv_verdict json-dependency child BLOCKED
run_inventory dependency 1 \
  "$(inv_row setup '["fail"]' 0)" \
  "$(inv_row child '["json"]' 0 setup)"
inv_verdict dependency child BLOCKED
run_inventory gated 1 \
  "$(inv_row setup '["json"]' 0 - - package-mutation)" \
  "$(inv_row child '["json"]' 0 setup)"
inv_verdict gated setup SKIPPED
inv_verdict gated child BLOCKED
run_inventory deadline 1 "$(inv_row hang '["hang"]' 0)"
inv_verdict deadline hang FAIL
run_inventory interrupted 143 \
  "$(inv_row observed-failure '["fail"]' 0)" \
  "$(inv_row interrupt '["interrupt"]' 0)"
inv_verdict interrupted observed-failure FAIL
jq -e '.complete == false' "$scratch/inventory-interrupted/inventory/summary.json" >/dev/null || fail 'interrupted inventory claimed complete coverage'
jq -e '.[0].exit_code == 124' "$scratch/inventory-deadline/inventory/results.json" >/dev/null || fail 'guest deadline lost timeout status'
# Existing evidence is immutable, even on an otherwise valid rerun.
assert_rc 2 "$inventory_runner" --work "$scratch/inventory-refusal" --distro arch --tiers hermetic --tag v9.9.9 --binary "$scratch/fake inventory omg" --tsv "$scratch/inventory-refusal.tsv"

# Validate the checked-in inventory without executing any of its commands.
mkdir -p "$scratch/inventory-schema/guest"
assert_rc 1 "$inventory_runner" --work "$scratch/inventory-schema" --distro arch --tiers credentialed --tag v9.9.9 --binary "$scratch/fake inventory omg" --tsv "$repo_root/tests/cli_behavior_inventory.tsv"
inv_verdict schema inventory-selection HARNESS_ERROR

# Advertised update modes and the foreground daemon must remain executable
# behavioral rows. A declaration-only regression would silently restore the
# four-distro skips this harness is intended to prevent.
for covered in update-fast update-turbo daemon-foreground; do
  awk -F '\t' -v id="$covered" '
    $1 == id {
      if ($5 != "pass" || $8 != "arch:pass,debian:pass,ubuntu:pass,fedora:pass") exit 1
      found = 1
    }
    END { exit !found }
  ' "$repo_root/tests/cli_behavior_inventory.tsv" || fail "$covered is not an executable all-distro inventory row"
done

printf 'PASS: release smoke and QEMU fixture suite\n'
