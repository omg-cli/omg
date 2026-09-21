#!/usr/bin/env bash
# test-qa-file-issue.sh — harness for scripts/qa-file-issue.sh with a fake gh.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
runner="$repo_root/scripts/qa-file-issue.sh"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/bin"
failures=0
fail() { printf 'FAIL: %s\n' "$1" >&2; failures=$((failures + 1)); }
assert_rc() { if [[ "$1" != "$2" ]]; then fail "expected exit $1, got $2 ($3)"; fi; }

# Fake gh: `list` prints $FAKE_ISSUES_JSON, `view` prints comment bodies,
# `create`/`comment` append their argv to the call log.
cat > "$scratch/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$CALL_LOG"
if [[ "${FAKE_FAIL_OPERATION:-}" == "$1 $2" ]]; then exit 7; fi
case "$1 $2" in
  "repo view") printf 'fork/omg\n';;
  "issue list") printf '%s' "${FAKE_ISSUES_JSON:-[]}";;
  "issue view") printf '%s' "${FAKE_COMMENTS_JSON:-[]}";;
  "issue create") printf 'https://github.com/x/y/issues/1\n';;
  "issue comment") printf '';;
  "issue close") printf '';;
  *) exit 9;;
esac
EOF
chmod 700 "$scratch/bin/gh"
export PATH="$scratch/bin:$PATH" CALL_LOG="$scratch/calls.log"
results="$scratch/results.json"

# 1. Fresh failure opens an issue carrying the fingerprint marker.
printf '%s' '[{"case_id":"search-tree","distro":"arch","result":"PRODUCT_FAIL","exit_code":1,"elapsed_seconds":2}]' > "$results"
: > "$CALL_LOG"; export FAKE_ISSUES_JSON='[]' FAKE_COMMENTS_JSON='[]'
out=$(bash "$runner" "$results" --run-url https://run/1 --source qemu); assert_rc 0 "$?" "create-new"
grep -q "issue create" "$CALL_LOG" || fail "create-new issued no create call"
grep -q "filed=1 updated=0 closed=0 errors=0" <<< "$out" || fail "create-new bad summary: $out"

# 2. Same fingerprint open already -> comment, never create.
export FAKE_ISSUES_JSON='[{"number":7,"body":"<!-- omg-qa-fingerprint: qemu:arch:search-tree -->"}]'
: > "$CALL_LOG"
out=$(bash "$runner" "$results" --run-url https://run/2 --source qemu); assert_rc 0 "$?" "dedup-comment"
grep -q "issue comment 7" "$CALL_LOG" || fail "dedup-comment issued no comment call"
grep -q "issue create" "$CALL_LOG" && fail "dedup-comment must not create"
grep -q "filed=0 updated=1 closed=0 errors=0" <<< "$out" || fail "dedup-comment bad summary: $out"

# 3. Run URL already recorded on the issue -> complete silence.
export FAKE_COMMENTS_JSON='Still failing on [https://run/2](https://run/2): PRODUCT_FAIL.'
: > "$CALL_LOG"
out=$(bash "$runner" "$results" --run-url https://run/2 --source qemu); assert_rc 0 "$?" "same-run-skip"
grep -q "issue create\|issue comment" "$CALL_LOG" && fail "same-run-skip must stay silent"
grep -q "filed=0 updated=0 closed=0 errors=0" <<< "$out" || fail "same-run-skip bad summary: $out"

# 4. Dry run performs no mutations beyond the issue list.
export FAKE_COMMENTS_JSON='[]'
: > "$CALL_LOG"
out=$(bash "$runner" "$results" --run-url https://run/3 --source qemu --dry-run); assert_rc 0 "$?" "dry-run"
grep -q "issue create\|issue comment" "$CALL_LOG" && fail "dry-run mutated"
grep -q "would comment on #7" <<< "$out" || fail "dry-run printed no plan: $out"

# 5. Malformed results fail closed before any gh mutation.
printf '%s' '[{"case_id":"x","distro":"mars","result":"PRODUCT_FAIL","exit_code":1,"elapsed_seconds":1}]' > "$results"
: > "$CALL_LOG"
if bash "$runner" "$results" --run-url https://run/4 --source qemu 2>/dev/null; then
  fail "schema violation must fail"
fi
[[ -s "$CALL_LOG" ]] && fail "schema violation must not call gh"

# 6. Clean run files nothing (and closes nothing when no issue is open).
printf '%s' '[{"case_id":"x","distro":"arch","result":"PASS","exit_code":0,"elapsed_seconds":1}]' > "$results"
: > "$CALL_LOG"
export FAKE_ISSUES_JSON='[]'
out=$(bash "$runner" "$results" --run-url https://run/5 --source qemu); assert_rc 0 "$?" "clean-run"
grep -q "No failures to file" <<< "$out" || fail "clean-run printed no notice"
grep -q "filed=0 updated=0 closed=0 errors=0" <<< "$out" || fail "clean-run bad summary: $out"

# 7. New issue carries a scrubbed failure excerpt plus an agent runbook.
# Assemble the github-pat-shaped fixture at runtime so the source file
# is not itself a gitleaks finding.
mkdir -p "$scratch/ev/arch-search-tree"
token_prefix="ghp"
token_body="_fixturefakepattern00000000000000000000"
fake_pat="${token_prefix}${token_body}"
printf 'line one\n\033[32mgreen output\033[0m\nGH_TOKEN is fixture-secret-that-must-not-leak\n%s\nboom: exit 1\n' "$fake_pat" > "$scratch/ev/arch-search-tree/transcript.txt"
printf '%s' '[{"case_id":"search-tree","distro":"arch","result":"PRODUCT_FAIL","exit_code":1,"elapsed_seconds":2}]' > "$results"
: > "$CALL_LOG"; export FAKE_ISSUES_JSON='[]' GH_TOKEN='fixture-secret-that-must-not-leak'
out=$(bash "$runner" "$results" --run-url https://run/7 --source qemu --evidence-dir "$scratch/ev"); assert_rc 0 "$?" "excerpt-create"
grep -q "issue create" "$CALL_LOG" || fail "excerpt-create issued no create call"
grep -q "boom: exit 1" "$CALL_LOG" || fail "excerpt-create omitted the failure tail"
grep -q "green output" "$CALL_LOG" || fail "excerpt-create dropped plain log text"
grep -q "Agent runbook" "$CALL_LOG" || fail "excerpt-create omitted the runbook"
grep -q "arch-search-tree/transcript.txt" "$CALL_LOG" || fail "excerpt-create omitted the evidence path"
if grep -q "fixture-secret-that-must-not-leak" "$CALL_LOG"; then fail "excerpt leaked GH_TOKEN"; fi
if grep -Fq "$fake_pat" "$CALL_LOG"; then fail "excerpt leaked a token pattern"; fi
if grep -q $'\x1b' "$CALL_LOG"; then fail "excerpt leaked ANSI escapes"; fi
unset GH_TOKEN

# 7b. Carriage-return progress spam (apt-style) is normalized away so the
# real error stays visible in the filed excerpt.
mkdir -p "$scratch/ev/debian-install-tree"
printf 'Reading package lists...\r0%% [Working]\r10%% [Working]\rErr: 2 http://deb.debian.org/debian tree amd64 2.1.0-1\rCould not open partial file\rError: APT commit error: media swap\n' > "$scratch/ev/debian-install-tree/transcript.txt"
printf '%s' '[{"case_id":"install-tree","distro":"debian","result":"PRODUCT_FAIL","exit_code":1,"elapsed_seconds":2}]' > "$results"
: > "$CALL_LOG"; export FAKE_ISSUES_JSON='[]'
out=$(bash "$runner" "$results" --run-url https://run/7b --source qemu --evidence-dir "$scratch/ev"); assert_rc 0 "$?" "progress-excerpt"
grep -q "issue create" "$CALL_LOG" || fail "progress-excerpt issued no create call"
grep -q "APT commit error" "$CALL_LOG" || fail "progress-excerpt buried the real error"
grep -q "Could not open partial file" "$CALL_LOG" || fail "progress-excerpt dropped error context"
if grep -q "Working" "$CALL_LOG"; then fail "progress-excerpt leaked progress spam"; fi

# 8. A passing case resolves its open issue (comment + close).
printf '%s' '[{"case_id":"search-tree","distro":"arch","result":"PASS","exit_code":0,"elapsed_seconds":2}]' > "$results"
export FAKE_ISSUES_JSON='[{"number":7,"state":"open","body":"<!-- omg-qa-fingerprint: qemu:arch:search-tree -->"}]'
: > "$CALL_LOG"
out=$(bash "$runner" "$results" --run-url https://run/8 --source qemu); assert_rc 0 "$?" "resolve-close"
grep -q "issue close 7" "$CALL_LOG" || fail "resolve-close issued no close call"
grep -q "filed=0 updated=0 closed=1 errors=0" <<< "$out" || fail "resolve-close bad summary: $out"

# 9. Resolve is scoped to cases present in this run: other open issues stay open.
export FAKE_ISSUES_JSON='[{"number":9,"state":"open","body":"<!-- omg-qa-fingerprint: qemu:debian:other-case -->"}]'
: > "$CALL_LOG"
out=$(bash "$runner" "$results" --run-url https://run/9 --source qemu); assert_rc 0 "$?" "resolve-scope"
grep -q "issue close\|issue comment" "$CALL_LOG" && fail "resolve-scope touched an unrelated issue"
grep -q "filed=0 updated=0 closed=0 errors=0" <<< "$out" || fail "resolve-scope bad summary: $out"

# 10. A recurrence after a close links the closed issue as a follow-up.
printf '%s' '[{"case_id":"search-tree","distro":"arch","result":"HARNESS_ERROR","exit_code":3,"elapsed_seconds":2}]' > "$results"
export FAKE_ISSUES_JSON='[{"number":9,"state":"closed","body":"<!-- omg-qa-fingerprint: qemu:arch:search-tree -->"}]'
: > "$CALL_LOG"
out=$(bash "$runner" "$results" --run-url https://run/10 --source qemu); assert_rc 0 "$?" "followup-link"
grep -q "issue create" "$CALL_LOG" || fail "followup-link issued no create call"
grep -q "Follow-up to #9" "$CALL_LOG" || fail "followup-link omitted the prior issue"
grep -q "filed=1 updated=0 closed=0 errors=0" <<< "$out" || fail "followup-link bad summary: $out"

# 11. Dry run plans closes without mutating.
printf '%s' '[{"case_id":"search-tree","distro":"arch","result":"PASS","exit_code":0,"elapsed_seconds":2}]' > "$results"
export FAKE_ISSUES_JSON='[{"number":7,"state":"open","body":"<!-- omg-qa-fingerprint: qemu:arch:search-tree -->"}]'
: > "$CALL_LOG"
out=$(bash "$runner" "$results" --run-url https://run/11 --source qemu --dry-run); assert_rc 0 "$?" "dry-run-close"
grep -q "issue close" "$CALL_LOG" && fail "dry-run-close mutated"
grep -q "would close #7" <<< "$out" || fail "dry-run-close printed no plan: $out"

# 12. The original issue body already records its first run. Replaying that
# reporting attempt must not add a redundant "still failing" comment.
printf '%s' '[{"case_id":"search-tree","distro":"arch","result":"PRODUCT_FAIL","exit_code":1,"elapsed_seconds":2}]' > "$results"
export FAKE_ISSUES_JSON='[{"number":7,"state":"open","body":"<!-- omg-qa-fingerprint: qemu:arch:search-tree -->\n- run: https://run/12"}]'
export FAKE_COMMENTS_JSON='[]'
: > "$CALL_LOG"
out=$(bash "$runner" "$results" --run-url https://run/12 --source qemu); assert_rc 0 "$?" "original-run-skip"
grep -q "issue create\|issue comment\|issue close" "$CALL_LOG" && fail "original-run-skip mutated"
grep -q "filed=0 updated=0 closed=0 errors=0" <<< "$out" || fail "original-run-skip bad summary: $out"

# 13. A run URL prefix is a different run and must retain its diagnosis.
: > "$CALL_LOG"
out=$(bash "$runner" "$results" --run-url https://run/1 --source qemu); assert_rc 0 "$?" "distinct-run-prefix"
grep -q "issue comment 7" "$CALL_LOG" || fail "distinct-run-prefix lost a recurrence"
grep -q "filed=0 updated=1 closed=0 errors=0" <<< "$out" || fail "distinct-run-prefix bad summary: $out"

# 14. Recurrence comments must also match the full run link, not a prefix.
export FAKE_COMMENTS_JSON='Still failing on [https://run/12](https://run/12): PRODUCT_FAIL.'
: > "$CALL_LOG"
out=$(bash "$runner" "$results" --run-url https://run/1 --source qemu); assert_rc 0 "$?" "comment-run-prefix"
grep -q "issue comment 7" "$CALL_LOG" || fail "comment-run-prefix lost a recurrence"

# 15. GitHub API failures must never be reported as successful delivery.
export FAKE_COMMENTS_JSON='[]'
for operation in create comment close view; do
  export FAKE_FAIL_OPERATION="issue $operation"
  export FAKE_ISSUES_JSON='[{"number":7,"state":"open","body":"<!-- omg-qa-fingerprint: qemu:arch:search-tree -->"}]'
  verdict=PRODUCT_FAIL; code=1
  if [[ "$operation" == create ]]; then export FAKE_ISSUES_JSON='[]'; fi
  if [[ "$operation" == close ]]; then verdict=PASS; code=0; fi
  printf '[{"case_id":"search-tree","distro":"arch","result":"%s","exit_code":%s,"elapsed_seconds":2}]' "$verdict" "$code" > "$results"
  : > "$CALL_LOG"
  if out=$(bash "$runner" "$results" --run-url https://run/15 --source qemu 2>"$scratch/error"); then
    fail "API $operation failure was reported as success"
  fi
  if [[ "$operation" == view ]]; then
    grep -q "issue create\|issue comment\|issue close" "$CALL_LOG" && fail "failed recurrence read must not mutate"
  fi
done
unset FAKE_FAIL_OPERATION

# 16. Contradictory evidence must not file and then close the same failure.
printf '%s' '[{"case_id":"search-tree","distro":"arch","result":"PRODUCT_FAIL","exit_code":1,"elapsed_seconds":2},{"case_id":"search-tree","distro":"arch","result":"PASS","exit_code":0,"elapsed_seconds":2}]' > "$results"
: > "$CALL_LOG"
if bash "$runner" "$results" --run-url https://run/16 --source qemu 2>"$scratch/error"; then
  fail "contradictory results were accepted"
fi
[[ -s "$CALL_LOG" ]] && fail "contradictory results reached GitHub"

# 17. A QEMU expected-refusal assertion can PASS with observed exit 1.
# Its runner already checked the expected code; preserve that verdict.
printf '%s' '[{"case_id":"search-tree","distro":"arch","result":"PASS","exit_code":1,"elapsed_seconds":2}]' > "$results"
: > "$CALL_LOG"
out=$(bash "$runner" "$results" --run-url https://run/17 --source qemu); assert_rc 0 "$?" "expected-refusal"
grep -q "issue close 7" "$CALL_LOG" || fail "expected-refusal lost verified closure"

# Local evidence may report a regression but must not close a hosted issue.
printf '%s' '[{"case_id":"search-tree","distro":"arch","result":"PASS","exit_code":0,"elapsed_seconds":2},{"case_id":"audit","distro":"arch","result":"PRODUCT_FAIL","exit_code":1,"elapsed_seconds":2}]' > "$results"
: > "$CALL_LOG"
if out=$(bash "$runner" "$results" --run-url https://run/local --source qemu --failures-only); then
  grep -q "issue create" "$CALL_LOG" || fail "local failure was not reported"
  grep -q "issue close" "$CALL_LOG" && fail "local pass closed a hosted issue"
  grep -q "closed=0" <<< "$out" || fail "local report counted a closure"
else
  fail "failures-only reporting failed"
fi

# Repository discovery failure must not silently file in an old upstream.
: > "$CALL_LOG"
export FAKE_FAIL_OPERATION='repo view'
if bash "$runner" "$results" --run-url https://run/unknown-repo --source qemu --failures-only >/dev/null 2>&1; then
  fail "repository discovery failure was accepted"
fi
grep -q 'issue list\|issue create\|issue comment\|issue close' "$CALL_LOG" && fail "unknown repository reached issue operations"
unset FAKE_FAIL_OPERATION

if [[ "$failures" -ne 0 ]]; then printf '%s failure(s)\n' "$failures" >&2; exit 1; fi
printf 'qa-file-issue harness: all green\n'
