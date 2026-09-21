#!/usr/bin/env bash
# qa-evidence-lib.sh — shared evidence helpers for the QA scripts.
# Sourced (never executed): result validation, scrub() and excerpt_for().
# Callers set evidence_dir to the run/evidence directory before calling
# excerpt_for.
set -euo pipefail

# Validate and project the same evidence snapshot for local audits and issue filing.
qa_result_rows() {
  jq -ce '
  def identifier: type == "string" and test("^[a-z0-9][a-z0-9-]{0,127}$");
  def distro: type == "string" and IN("arch", "debian", "ubuntu", "fedora", "macos");
  if type != "array" then error("results must be an array") else . end |
  if length > 10000 then error("too many results") else . end |
  if (map([.distro, .case_id]) | unique | length) != length
  then error("duplicate case identity") else . end |
  if all(.[];
    (.case_id | identifier) and
    (.distro | distro) and
    (.result | IN("PASS", "SKIPPED", "EXPECTED_REJECTION", "PRODUCT_FAIL", "HARNESS_ERROR", "FAIL", "BLOCKED")) and
    (.exit_code | type == "number" and floor == . and . >= -1 and . <= 255) and
    (.elapsed_seconds | type == "number" and . >= 0 and . <= 86400))
  then . else error("invalid result fields") end |
  map({case_id, distro, result, exit_code, elapsed_seconds})
' "$1"
}

# Best-effort secret scrubber for log excerpts. By design the harnesses
# never print credentials; this is a second net, not the first.
scrub() {
  local token_esc="${GH_TOKEN:-}"
  token_esc="${token_esc//\\/\\\\}"
  token_esc="${token_esc//|/\\|}"
  token_esc="${token_esc//&/\\&}"
  sed -e 's/\x1b\[[0-9;]*[a-zA-Z]//g' -e 's/\x1b\][^\x07]*\x07//g' |
  if [[ -n "${GH_TOKEN:-}" ]]; then sed -e "s|${token_esc}|[redacted-gh-token]|g"; else cat; fi |
  sed -E -e 's/ghp_[A-Za-z0-9]{20,}/[redacted-token]/g' \
    -e 's/github_pat_[A-Za-z0-9_]+/[redacted-token]/g' \
    -e 's/gho_[A-Za-z0-9_]+/[redacted-token]/g' \
    -e 's/ghs_[A-Za-z0-9_]+/[redacted-token]/g' \
    -e 's/Bearer [A-Za-z0-9._~+\/-]+/[redacted-bearer]/g' |
  awk '
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/ {
      print "[redacted-private-key]"
      private_key = 1
    }
    private_key {
      if ($0 ~ /-----END [A-Z ]*PRIVATE KEY-----/) private_key = 0
      next
    }
    { print }
  '
}

# Locate the richest per-case log near $evidence_dir. On success prints
# the evidence-relative source path to FD 3 and the scrubbed tail to
# stdout. (FD 3 because command substitution would lose a global.)
excerpt_for() {
  local case_id=$1 distro=$2 candidate row
  candidate=""
  if [[ -f "$evidence_dir/$distro-$case_id/transcript.txt" ]]; then
    candidate="$evidence_dir/$distro-$case_id/transcript.txt"
  elif [[ "$case_id" == qemu-*-lifecycle && -f "$evidence_dir/guest-check.log" ]]; then
    candidate="$evidence_dir/guest-check.log"
  else
    row="$case_id"
    row="${row#qemu-"$distro"-}"
    if [[ -f "$evidence_dir/rows/$row.log" ]]; then
      candidate="$evidence_dir/rows/$row.log"
    elif [[ -f "$evidence_dir/inventory/rows/$row.log" ]]; then
      candidate="$evidence_dir/inventory/rows/$row.log"
    fi
  fi
  if [[ -z "$candidate" ]]; then
    printf 'note: no excerpt found for %s on %s (looked for transcript, guest-check, and row logs under %s)\n' "$case_id" "$distro" "$evidence_dir" >&2
    return 1
  fi
  printf '%s\n' "${candidate#"$evidence_dir"/}" >&3
  # Normalize carriage returns first: tools like apt render progress as
  # \r-separated updates, which would otherwise arrive as one giant line
  # and bury the actual error. Pure progress lines (`N% [Working]`) are
  # then dropped (sed, not grep -v, so an all-progress log cannot fail the
  # pipeline under pipefail); everything else is preserved verbatim.
  tr '\r' '\n' < "$candidate" |
    sed -E '/^[[:space:]]*([0-9]+% )?\[Working\][[:space:]]*$/d' |
    scrub | tail -n 40 | tail -c 3000
}
