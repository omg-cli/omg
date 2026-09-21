#!/usr/bin/env bash
# test-qa-audit.sh — harness for scripts/qa-audit.sh with fixture evidence.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
runner="$repo_root/scripts/qa-audit.sh"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
failures=0
fail() { printf 'FAIL: %s\n' "$1" >&2; failures=$((failures + 1)); }

# Fixture run: one pass, one product fail with a transcript carrying a
# secret and ANSI escapes, one skipped row.
mkdir -p "$scratch/run/arch-search-tree"
printf '\x1b[31mred\x1b[0m\ntoken ghp_fixturefakepattern00000000000000000000\nboom\n' > "$scratch/run/arch-search-tree/transcript.txt"
printf '%s' '[{"case_id":"search-tree","distro":"arch","result":"PRODUCT_FAIL","exit_code":1,"elapsed_seconds":2},{"case_id":"other","distro":"arch","result":"PASS","exit_code":0,"elapsed_seconds":1},{"case_id":"skipped-row","distro":"arch","result":"SKIPPED","exit_code":-1,"elapsed_seconds":0}]' > "$scratch/run/results.json"
printf 'case\targs_json\nsearch-tree\t["search","tree"]\n' > "$scratch/cases.tsv"
export GH_TOKEN='fixture-secret-that-must-not-leak'

out=""; rc=0
out=$("$runner" "$scratch/run/results.json" --tsv "$scratch/cases.tsv") || rc=$?
[[ "$rc" -eq 1 ]] || fail "audit with failures must exit 1, got $rc"
grep -q "verdicts:.*PRODUCT_FAIL=1" <<< "$out" || fail "audit omitted verdict counts: $out"
grep -q "### search-tree on arch: PRODUCT_FAIL (exit 1, 2s)" <<< "$out" || fail "audit omitted the failing row: $out"
grep -q "command: omg search tree" <<< "$out" || fail "audit omitted the TSV command: $out"
grep -q "boom" <<< "$out" || fail "audit omitted the excerpt"
grep -q "arch-search-tree/transcript.txt" <<< "$out" || fail "audit omitted the excerpt source"
grep -q "qa-file-issue.sh \"$scratch/run/results.json\"" <<< "$out" || fail "audit omitted the filing command"
grep -q "skipped-row" <<< "$out" && fail "audit printed a skipped row as failure"
if grep -q "fixture-secret-that-must-not-leak" <<< "$out"; then fail "audit leaked GH_TOKEN"; fi
if grep -q "ghp_fixture" <<< "$out"; then fail "audit leaked a token pattern"; fi
if grep -q $'\x1b' <<< "$out"; then fail "audit leaked ANSI escapes"; fi
grep -q "files=1 failing-rows=1" <<< "$out" || fail "audit bad summary: $out"
unset GH_TOKEN

# Clean run exits 0 and says so.
printf '%s' '[{"case_id":"other","distro":"arch","result":"PASS","exit_code":0,"elapsed_seconds":1}]' > "$scratch/clean.json"
out=$("$runner" "$scratch/clean.json"); rc=$?
[[ "$rc" -eq 0 ]] || fail "clean audit must exit 0, got $rc"
grep -q "clean" <<< "$out" || fail "clean audit printed no notice: $out"

# Directory scan finds nested results; junk files are skipped loudly.
mkdir -p "$scratch/suite/a/b"
printf '%s' '[{"case_id":"x","distro":"fedora","result":"HARNESS_ERROR","exit_code":3,"elapsed_seconds":0}]' > "$scratch/suite/a/b/results.json"
printf 'not json\n' > "$scratch/suite/a/notes.txt"
mkdir -p "$scratch/suite/bad"
printf '{"oops":true}\n' > "$scratch/suite/bad/results.json"
out=""; rc=0
out=$("$runner" "$scratch/suite") || rc=$?
[[ "$rc" -eq 1 ]] || fail "suite audit must exit 1, got $rc"
grep -q "invalid results.json; audit incomplete" <<< "$out" || fail "suite audit did not flag the junk file"
grep -q "files=2 failing-rows=1" <<< "$out" || fail "suite audit bad summary: $out"

# Malformed evidence alone must not be mistaken for a healthy run.
for invalid in '{"oops":true}' 'not json'; do
  printf '%s\n' "$invalid" > "$scratch/invalid.json"
  rc=0
  out=$("$runner" "$scratch/invalid.json") || rc=$?
  [[ "$rc" -eq 1 ]] || fail "invalid-only audit must exit 1, got $rc"
  grep -q 'invalid-files=1' <<< "$out" || fail "audit omitted invalid evidence count"
done

# Valid evidence remains visible even when another input is unusable.
rc=0
out=$("$runner" "$scratch/invalid.json" "$scratch/clean.json") || rc=$?
[[ "$rc" -eq 1 ]] || fail "mixed clean/invalid audit must exit 1, got $rc"
grep -q 'verdicts: PASS=1' <<< "$out" || fail "invalid input hid valid evidence"
grep -q 'files=2 failing-rows=0 invalid-files=1' <<< "$out" || fail "mixed audit bad summary"

if [[ "$failures" -ne 0 ]]; then printf '%s failure(s)\n' "$failures" >&2; exit 1; fi
printf 'qa-audit harness: all green\n'
