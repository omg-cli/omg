#!/usr/bin/env bash
# qa-file-issue.sh — file (or update) one GitHub issue per QA failure.
#
# Reads a results.json array in the evidence schema
# (case_id, distro, result, exit_code, elapsed_seconds) and, for every
# PRODUCT_FAIL / HARNESS_ERROR / FAIL row, opens a `[qa]` issue unless one
# with the same fingerprint is already open — then it comments instead.
# Fingerprint is source+distro+case (NOT the result), so a flapping
# verdict updates the same issue instead of opening duplicates.
#
# Issues carry failure excerpts (scrubbed tails of the per-case logs) plus
# an agent runbook so a fixer agent can work them without asking for
# context. A passing retry does not prove a fix; link the fixing PR with a
# GitHub closing keyword so the issue closes with that change. A fresh failure whose fingerprint
# matches a *closed* issue links it as a follow-up instead of duplicating.
#
# Only allowlisted fields ever leave the machine; unknown result keys are
# dropped, excerpts are scrubbed of secrets, and full logs stay in the
# run's uploaded artifacts (the issue lists their relative paths).
set -euo pipefail

results=""; run_url=""; source=""; label="qa-failure"; repo=""; dry_run=false
evidence_dir=""
while (($#)); do
  case "$1" in
    --run-url|--source|--label|--repo|--evidence-dir)
      [[ $# -ge 2 && -n "$2" ]] || exit 2
      case "$1" in
        --run-url) run_url=$2 ;; --source) source=$2 ;; --label) label=$2 ;; --repo) repo=$2 ;;
        --evidence-dir) evidence_dir=$2 ;;
      esac
      shift 2 ;;
    --dry-run) dry_run=true; shift ;;
    --failures-only) shift ;;
    --help) printf 'Usage: qa-file-issue.sh RESULTS_JSON --run-url URL --source NAME [--evidence-dir DIR] [--label L] [--repo R] [--failures-only] [--dry-run]\nFiles or updates one issue per failing case. Passing retries never close issues; link the fixing PR with a GitHub closing keyword. Needs jq and gh (GH_TOKEN).\n'; exit 0 ;;
    -*) printf 'error: unknown argument %s\n' "$1" >&2; exit 2 ;;
    *) [[ -z "$results" ]] || exit 2; results=$1; shift ;;
  esac
done
[[ -n "$results" && -n "$run_url" && -n "$source" ]] || exit 2
[[ "$source" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] || exit 2
[[ -f "$results" ]] || exit 2
[[ -n "$evidence_dir" ]] || evidence_dir="$(dirname "$results")"
for tool in jq gh; do command -v "$tool" >/dev/null || exit 3; done

# shellcheck disable=SC1091
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/qa-evidence-lib.sh"
# Validate once, before any GitHub operations or filtering.
rows="$(qa_result_rows "$results")"
if [[ "$source" != qemu-matrix ]] && jq -e 'any(.[]; .distro == "matrix")' <<< "$rows" >/dev/null; then
  printf 'error: matrix identity is only valid for QEMU workflow reports\n' >&2
  exit 2
fi
failures="$(jq -ce 'map(select(.result == "PRODUCT_FAIL" or .result == "HARNESS_ERROR" or .result == "FAIL"))' <<< "$rows")"
# Retain --failures-only for existing local callers. All callers are now
# failure-only: a green retry, including a published run, cannot name the
# change that fixed an intermittent defect.
if [[ "$(jq 'length' <<< "$failures")" == 0 ]]; then
  printf 'No failures to file.\nfiled=0 updated=0 closed=0 errors=0\n'; exit 0
fi

runbook_for() {
  case "$source" in
    qemu-matrix)
      printf 'Rerun this leg: `./scripts/benchmark-qemu.sh --distro %s --release <same-tag-as-run> [--arch aarch64] --staged-dir <staged-binaries>`.\nFull per-case evidence (transcripts, guest logs, metadata) is in this run'"'"'s uploaded `qemu-*evidence-*` artifacts; paths below are relative to the evidence root.\n' "$1" ;;
    release-smoke)
      printf 'Rerun this leg: `./scripts/release-smoke.sh --distro %s --release <same-tag-as-run>%s`.\nFull per-case evidence (transcripts, metadata, result.json) is in this run'"'"'s uploaded `release-smoke-*` artifacts; paths below are relative to the evidence root.\n' "$1" "$2" ;;
    *) printf 'Full per-case evidence is in this run'"'"'s uploaded artifacts; paths below are relative to the evidence root.\n' ;;
  esac
}

if [[ -z "$repo" ]]; then
  # Local-first default: file to the checkout's own repo (covers forks).
  # An unknown destination must never fall back to a different repository.
  # Deliberately after the schema gate: junk input must fail before any
  # network call.
  repo="${GITHUB_REPOSITORY:-$(gh repo view --json nameWithOwner --jq .nameWithOwner 2>/dev/null || exit 3)}"
fi
[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || {
  printf 'error: repository must be an explicit owner/name or discoverable from this checkout\n' >&2
  exit 2
}
open_issues="$(gh issue list --repo "$repo" --label "$label" --state all --json number,body,state --limit 1000)"
filed=0; updated=0; closed=0; errors=0
while IFS= read -r row; do
  case_id=$(jq -r '.case_id' <<< "$row")
  distro=$(jq -r '.distro' <<< "$row")
  result=$(jq -r '.result' <<< "$row")
  exit_code=$(jq -r '.exit_code' <<< "$row")
  elapsed=$(jq -r '.elapsed_seconds' <<< "$row")
  fingerprint="$source:$distro:$case_id"
  marker="<!-- omg-qa-fingerprint: $fingerprint -->"
  existing=$(jq -r --arg m "$marker" '[.[] | select((.state // "open" | ascii_downcase) == "open" and .body != null and (.body | contains($m))) | .number] | first // empty' <<< "$open_issues")
  excerpt=""; excerpt_source=""
  src_tmp="$(mktemp)"
  if excerpt_text="$(excerpt_for "$case_id" "$distro" 3>"$src_tmp")"; then
    excerpt="$excerpt_text"
    excerpt_source="$(cat "$src_tmp")"
  fi
  rm -f "$src_tmp"
  if [[ -z "$existing" ]]; then
    title="[qa] $case_id fails on $distro ($source)"
    runbook_distro=$distro
    if [[ "$distro" == matrix ]]; then
      title="[qa] $case_id fails in QEMU workflow ($source)"
      runbook_distro=all
    fi
    followup=$(jq -r --arg m "$marker" '[.[] | select((.state // "" | ascii_downcase) == "closed" and .body != null and (.body | contains($m))) | .number] | max // empty' <<< "$open_issues")
    body=$(cat <<EOF
$marker
Automated QA failure. Excerpts are scrubbed of secrets; full logs are in the run artifacts.

- case: \`$case_id\`
- distro: \`$distro\`
- result: \`$result\` (exit $exit_code, ${elapsed}s)
- source: \`$source\`
- run: $run_url
EOF
)
    if [[ -n "$followup" ]]; then
      body+=$(printf '\n\nFollow-up to #%s (same fingerprint failed again after that issue closed).' "$followup")
    fi
    if [[ -n "$excerpt" ]]; then
      body+=$(printf '\n\n### Failure excerpt (`%s`, tail)\n````log\n%s\n````' "$excerpt_source" "$excerpt")
    fi
    body+=$(printf '\n\n### Agent runbook\n%s\nResolve criteria: verify the fix in a pull request and link this issue with a GitHub closing keyword. A passing retry alone does not close it. A recurrence while open lands as a new comment; after a close it files a follow-up like this one.' "$(runbook_for "$runbook_distro" "$([[ "$distro" == macos ]] && printf ' --executor native' || printf '')")")
    if [[ "$dry_run" == true ]]; then
      printf 'would create: %s\n' "$title"
    elif gh issue create --repo "$repo" --title "$title" --label "$label" --body "$body" >/dev/null; then
      filed=$((filed + 1))
    else
      printf 'warning: failed to create issue for %s\n' "$fingerprint" >&2
      errors=$((errors + 1))
    fi
  else
    # The first run is recorded in the issue body, later runs in comments.
    # Match the complete run line so /runs/12 cannot hide a distinct /runs/1.
    if jq -e --argjson number "$existing" --arg line "- run: $run_url" \
        'any(.[]; .number == $number and ((.body // "" | split("\n")) | index($line) != null))' \
        <<< "$open_issues" >/dev/null; then
      continue
    fi
    # Same run already recorded in a recurrence comment? Nothing new to say.
    if ! comments=$(gh issue view "$existing" --repo "$repo" --json comments --jq '.comments[].body'); then
      printf 'warning: failed to read recurrence history for %s\n' "$fingerprint" >&2
      errors=$((errors + 1))
      continue
    fi
    if grep -Fq "]($run_url)" <<< "$comments"; then
      continue
    fi
    comment=$(printf 'Still failing on [%s](%s): `%s` (exit %s, %ss).' "$run_url" "$run_url" "$result" "$exit_code" "$elapsed")
    if [[ -n "$excerpt" ]]; then
      comment+=$(printf '\n\n### Failure excerpt (`%s`, tail)\n````log\n%s\n````' "$excerpt_source" "$excerpt")
    fi
    if [[ "$dry_run" == true ]]; then
      printf 'would comment on #%s\n' "$existing"
    elif gh issue comment "$existing" --repo "$repo" --body "$comment" >/dev/null; then
      updated=$((updated + 1))
    else
      printf 'warning: failed to comment on #%s\n' "$existing" >&2
      errors=$((errors + 1))
    fi
  fi
done < <(jq -c '.[]' <<< "$failures")
if [[ "$(jq 'length' <<< "$failures")" == 0 ]]; then printf 'No failures to file.\n'; fi
printf 'filed=%s updated=%s closed=%s errors=%s\n' "$filed" "$updated" "$closed" "$errors"
[[ "$errors" -eq 0 ]]
