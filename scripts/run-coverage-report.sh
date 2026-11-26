#!/usr/bin/env bash
set -euo pipefail

report_with_raw_profiles() {
    cargo llvm-cov report "$@"
    exit
}

if [[ ${COVERAGE_REUSE_MERGED_PROFILE:-false} != true ]]; then
    report_with_raw_profiles "$@"
fi

shopt -s nullglob
target="$PWD/target/llvm-cov-target"
merged="$target/omg.profdata"
inputs="$target/omg-profraw-list"
profiles=("$target/"*.profraw)

# cargo-llvm-cov reuses profdata when its raw input glob is empty. Preserve its
# normal merge path if the first report did not merge the current inputs.
if [[ ! -f "$merged" || -L "$merged" || ! -s "$merged" || ! -f "$inputs" || -L "$inputs" ]] ||
    (( ${#profiles[@]} == 0 )) ||
    ! cmp -s <(printf '%s\n' "${profiles[@]}" | LC_ALL=C sort) <(LC_ALL=C sort "$inputs"); then
    report_with_raw_profiles "$@"
fi
for profile in "${profiles[@]}"; do
    if [[ ! -f "$profile" || -L "$profile" || ! "$merged" -nt "$profile" ]]; then
        report_with_raw_profiles "$@"
    fi
done

staged=$(mktemp -d "$target/.report-raw.XXXXXX")
restore_raw_profiles() {
    status=$?
    late=("$target/"*.profraw)
    if (( ${#late[@]} != 0 )); then
        echo 'Raw coverage inputs changed during report generation' >&2
        status=1
    fi
    saved=("$staged/"*.profraw)
    if (( ${#saved[@]} != 0 )) && ! mv -n -- "${saved[@]}" "$target/"; then
        status=1
    fi
    if ! rmdir -- "$staged"; then
        status=1
    fi
    exit "$status"
}
trap restore_raw_profiles EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mv -- "${profiles[@]}" "$staged/"
echo 'Reusing merged coverage profile' >&2
cargo llvm-cov report "$@"
