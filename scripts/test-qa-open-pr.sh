#!/usr/bin/env bash
# test-qa-open-pr.sh — harness for scripts/qa-open-pr.sh with fake git/gh.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
runner="$repo_root/scripts/qa-open-pr.sh"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/bin"
failures=0
fail() { printf 'FAIL: %s\n' "$1" >&2; failures=$((failures + 1)); }
assert_rc() { if [[ "$1" != "$2" ]]; then fail "expected exit $1, got $2 ($3)"; fi; }

cat > "$scratch/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "gh $*" >> "$CALL_LOG"
case "$1 $2" in
  "issue view") printf '%s' "${FAKE_ISSUE_JSON:?test must set FAKE_ISSUE_JSON}";;
  "pr create") printf 'https://github.com/x/y/pull/1\n';;
  "repo view") printf 'fork/omg\n';;
  *) exit 9;;
esac
EOF
cat > "$scratch/bin/git" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "git $*" >> "$CALL_LOG"
case "$1" in
  status) printf '%s' "${FAKE_GIT_STATUS:-}" ;;
  rev-parse) exit "${FAKE_REV:-0}" ;;
  push) exit "${FAKE_PUSH:-0}" ;;
  *) exit 9 ;;
esac
EOF
chmod 700 "$scratch/bin/gh" "$scratch/bin/git"
export PATH="$scratch/bin:$PATH" CALL_LOG="$scratch/calls.log"
QA_BODY='<!-- omg-qa-fingerprint: qemu:arch:search-tree --> boom'

# 1. Dry run plans without pushing or opening.
: > "$CALL_LOG"; export FAKE_ISSUE_JSON='{"number":7,"state":"open","title":"[qa] x","body":"'"$QA_BODY"'"}'
out=$(bash "$runner" --issue 7 --branch fix-x --repo o/r --dry-run); assert_rc 0 "$?" "dry-run"
grep -q "would push branch fix-x and open draft PR" <<< "$out" || fail "dry-run printed no plan: $out"
grep -q "push -u" "$CALL_LOG" && fail "dry-run pushed"
grep -q "pr create" "$CALL_LOG" && fail "dry-run opened a PR"

# 2. Dirty tree fails closed before any publish.
: > "$CALL_LOG"; export FAKE_GIT_STATUS=' M src/foo.rs'
if bash "$runner" --issue 7 --branch fix-x --repo o/r 2>/dev/null; then fail "dirty tree must fail"; fi
grep -q "push -u\|pr create" "$CALL_LOG" && fail "dirty tree published"
export FAKE_GIT_STATUS=''

# 3. Non-[qa] issues are refused.
: > "$CALL_LOG"; export FAKE_ISSUE_JSON='{"number":8,"state":"open","title":"human issue","body":"no marker here"}'
if bash "$runner" --issue 8 --branch fix-x --repo o/r 2>/dev/null; then fail "non-qa issue must fail"; fi
grep -q "push -u\|pr create" "$CALL_LOG" && fail "non-qa issue published"

# 4. Closed issues are refused.
: > "$CALL_LOG"; export FAKE_ISSUE_JSON='{"number":7,"state":"closed","title":"[qa] x","body":"'"$QA_BODY"'"}'
if bash "$runner" --issue 7 --branch fix-x --repo o/r 2>/dev/null; then fail "closed issue must fail"; fi
grep -q "push -u\|pr create" "$CALL_LOG" && fail "closed issue published"

# 5. Happy path pushes and opens a DRAFT PR fixing the issue.
: > "$CALL_LOG"; export FAKE_ISSUE_JSON='{"number":7,"state":"OPEN","title":"[qa] x","body":"'"$QA_BODY"'"}'
out=$(bash "$runner" --issue 7 --branch fix-x --repo o/r); assert_rc 0 "$?" "happy-path"
grep -q "push -u origin fix-x" "$CALL_LOG" || fail "happy path did not push the branch"
grep -q "pr create" "$CALL_LOG" || fail "happy path opened no PR"
grep -qF -- "--draft" "$CALL_LOG" || fail "happy path PR is not a draft"
grep -q "Related QA issue: #7" "$CALL_LOG" || fail "happy path body lost the issue link"
grep -Eiq '(fix(es|ed)?|close[sd]?|resolve[sd]?) #7' "$CALL_LOG" && fail "merge must not close an issue before verified recovery"
grep -q "authoritative passing run" "$CALL_LOG" || fail "PR body omitted verification-based closure"
grep -q "opened https://github.com/x/y/pull/1" <<< "$out" || fail "happy path printed no URL: $out"

# 6. Bad arguments fail before any git/gh mutation.
: > "$CALL_LOG"
if bash "$runner" --issue abc --branch fix-x --repo o/r 2>/dev/null; then fail "bad issue must fail"; fi
if bash "$runner" --issue 7 --branch '../evil' --repo o/r 2>/dev/null; then fail "bad branch must fail"; fi
[[ -s "$CALL_LOG" ]] && fail "bad arguments must not call git/gh"

# 7. Missing local branch fails before pushing.
: > "$CALL_LOG"; export FAKE_REV=1
if bash "$runner" --issue 7 --branch fix-x --repo o/r 2>/dev/null; then fail "missing branch must fail"; fi
grep -q "push -u\|pr create" "$CALL_LOG" && fail "missing branch published"
unset FAKE_REV

# 8. The PR body embeds the issue's replication detail, not just a pointer.
: > "$CALL_LOG"
export FAKE_ISSUE_JSON='{"number":9,"state":"open","title":"[qa] y","body":"<!-- omg-qa-fingerprint: qemu:fedora:search-tree -->\n- case: `release-package-search-tree`\n- distro: `fedora`\n### Failure excerpt (`guest-check.log`, tail)\n````log\nError: boom\n````\n### Agent runbook\nRerun this leg: `./scripts/benchmark-qemu.sh --distro fedora`.\n"}'
bash "$runner" --issue 9 --branch fix-y --repo o/r >/dev/null || fail "replication case must open"
grep -q "## Failure replication" "$CALL_LOG" || fail "PR body has no replication section"
grep -q "release-package-search-tree" "$CALL_LOG" || fail "PR body lost the case facts"
grep -q "Error: boom" "$CALL_LOG" || fail "PR body lost the failure excerpt"
grep -q "Agent runbook" "$CALL_LOG" || fail "PR body lost the rerun runbook"
grep -q "Replicated from #9" "$CALL_LOG" || fail "PR body does not attribute the issue"

# 9. An issue without replication sections falls back to a pointer.
: > "$CALL_LOG"; export FAKE_ISSUE_JSON='{"number":7,"state":"open","title":"[qa] x","body":"'"$QA_BODY"'"}'
bash "$runner" --issue 7 --branch fix-x --repo o/r >/dev/null || fail "fallback case must open"
grep -q "See #7 for the failure excerpt" "$CALL_LOG" || fail "PR body has no fallback pointer"

if [[ "$failures" -ne 0 ]]; then printf '%s failure(s)\n' "$failures" >&2; exit 1; fi
printf 'qa-open-pr harness: all green\n'
