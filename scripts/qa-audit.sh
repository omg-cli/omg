#!/usr/bin/env bash
# qa-audit.sh — summarize QA evidence for the error audit.
#
# Walks results.json files (given explicitly, or found under the standard
# evidence roots) and prints a paste-ready report: per-file verdict
# counts, every non-passing row with its scrubbed failure excerpt, and
# the exact filing command for each file with failures. Excerpts go
# through the same secret scrubber as issue filing, so the output is
# safe to paste to an agent.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$here/qa-evidence-lib.sh"

tsv=""
paths=()
while (($#)); do
  case "$1" in
    --tsv)
      [[ $# -ge 2 && -n "$2" ]] || exit 2
      tsv=$2; shift 2 ;;
    --help) printf 'Usage: qa-audit.sh [RESULTS_JSON|DIR ...] [--tsv inventory.tsv]\nSummarizes QA evidence for the error audit. With no paths, scans the standard evidence roots.\n'; exit 0 ;;
    -*) printf 'error: unknown argument %s\n' "$1" >&2; exit 2 ;;
    *) paths+=("$1"); shift ;;
  esac
done
if [[ ${#paths[@]} -eq 0 ]]; then
  for root in "$HOME/.cache/build-targets/omg-qemu-benchmark" "$here/../target/release-smoke"; do
    [[ -d "$root" ]] && paths+=("$root")
  done
  [[ ${#paths[@]} -gt 0 ]] || { printf 'error: no evidence roots found; pass explicit paths\n' >&2; exit 2; }
fi

files=()
for path in "${paths[@]}"; do
  if [[ -f "$path" ]]; then files+=("$path")
  elif [[ -d "$path" ]]; then
    while IFS= read -r found; do files+=("$found"); done \
      < <(find "$path" -name results.json -not -path '*/node_modules/*' 2>/dev/null | sort)
  else printf 'error: not found: %s\n' "$path" >&2; exit 2; fi
done
[[ ${#files[@]} -gt 0 ]] || { printf 'No results.json files found.\n'; exit 0; }

command_for() {
  # Print the TSV command line for a row id, if --tsv can say. Tries the
  # id as-is, then without a qemu-<distro>- lifecycle/inventory prefix.
  local wanted=$1 args candidate
  [[ -n "$tsv" && -f "$tsv" ]] || return 1
  for candidate in "$wanted" "${wanted#qemu-*-}"; do
    args="$(awk -F '\t' -v row="$candidate" '$1 == row {print $2; exit}' "$tsv" 2>/dev/null)"
    [[ -n "$args" ]] && break
  done
  [[ -n "$args" ]] || return 1
  printf 'command: omg %s\n' "$(jq -rj '.[] | tostring + " "' <<< "$args" 2>/dev/null || printf '%s' "$args")"
}

total_fail=0; invalid_files=0; total_files=${#files[@]}
for results in "${files[@]}"; do
  evidence_dir="$(dirname "$results")"
  if ! rows="$(qa_result_rows "$results" 2>/dev/null)"; then
    invalid_files=$((invalid_files + 1))
    printf '## %s\ninvalid results.json; audit incomplete\n\n' "$results"
    continue
  fi
  counts="$(jq -r 'group_by(.result) | map("\(.[0].result)=\(length)") | join(" ")' <<< "$rows")"
  printf '## %s\nverdicts: %s\n' "$results" "${counts:-empty}"
  failing="$(jq -c '.[] | select(.result != "PASS" and .result != "EXPECTED_REJECTION" and .result != "SKIPPED")' <<< "$rows")"
  if [[ -z "$failing" ]]; then printf 'clean\n\n'; continue; fi
  while IFS= read -r row; do
    case_id=$(jq -r '.case_id' <<< "$row"); distro=$(jq -r '.distro' <<< "$row")
    result=$(jq -r '.result' <<< "$row"); exit_code=$(jq -r '.exit_code' <<< "$row")
    elapsed=$(jq -r '.elapsed_seconds' <<< "$row")
    total_fail=$((total_fail + 1))
    printf '\n### %s on %s: %s (exit %s, %ss)\n' "$case_id" "$distro" "$result" "$exit_code" "$elapsed"
    command_for "$case_id" || true
    src_tmp="$(mktemp)"
    if excerpt="$(excerpt_for "$case_id" "$distro" 3>"$src_tmp" 2>/dev/null)"; then
      printf 'excerpt (%s):\n````log\n%s\n````\n' "$(cat "$src_tmp")" "$excerpt"
    fi
    rm -f "$src_tmp"
  done <<< "$failing"
  printf '\nfile with: ./scripts/qa-file-issue.sh "%s" --run-url <run-url> --source <qemu-matrix|release-smoke> --failures-only [--dry-run]\n\n' "$results"
done
printf 'files=%s failing-rows=%s invalid-files=%s\n' "$total_files" "$total_fail" "$invalid_files"
[[ "$total_fail" -eq 0 && "$invalid_files" -eq 0 ]]
