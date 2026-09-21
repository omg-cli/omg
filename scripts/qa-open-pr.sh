#!/usr/bin/env bash
# qa-open-pr.sh — open a DRAFT fix PR for a [qa] issue from a local branch.
#
# The gate is running this script: nothing opens PRs unprompted. It
# refuses non-[qa] issues, dirty trees, and unpushed-branch surprises by
# pushing explicitly, then opens the PR as a draft so a human promotes it.
# Link the proposed fix without closing on merge. The issue remains open
# until qa-file-issue.sh receives authoritative passing evidence.
set -euo pipefail

issue=""; branch=""; base="main"; repo=""; dry_run=false
while (($#)); do
  case "$1" in
    --issue|--branch|--base|--repo)
      [[ $# -ge 2 && -n "$2" ]] || exit 2
      case "$1" in
        --issue) issue=$2 ;; --branch) branch=$2 ;; --base) base=$2 ;; --repo) repo=$2 ;;
      esac
      shift 2 ;;
    --dry-run) dry_run=true; shift ;;
    --help) printf 'Usage: qa-open-pr.sh --issue N --branch NAME [--base main] [--repo R] [--dry-run]\nPushes the branch and opens a DRAFT fix PR linked to a [qa] issue. Needs git and gh.\n'; exit 0 ;;
    -*) printf 'error: unknown argument %s\n' "$1" >&2; exit 2 ;;
    *) printf 'error: unexpected argument %s\n' "$1" >&2; exit 2 ;;
  esac
done
[[ -n "$issue" && -n "$branch" ]] || exit 2
[[ "$issue" =~ ^[0-9]+$ ]] || exit 2
[[ "$branch" =~ ^[a-zA-Z0-9][a-zA-Z0-9_./-]*$ ]] || exit 2
for tool in git gh; do command -v "$tool" >/dev/null || exit 3; done
if [[ -z "$repo" ]]; then
  repo="${GITHUB_REPOSITORY:-$(gh repo view --json nameWithOwner --jq .nameWithOwner 2>/dev/null || exit 3)}"
fi

# Only [qa] pipeline issues qualify: the body must carry our fingerprint.
issue_json="$(gh issue view "$issue" --repo "$repo" --json title,body,state 2>/dev/null || exit 3)"
[[ "$(jq -r .state <<< "$issue_json")" == "OPEN" || "$(jq -r .state <<< "$issue_json")" == "open" ]] ||
  { printf 'error: issue #%s is not open\n' "$issue" >&2; exit 2; }
grep -Fq 'omg-qa-fingerprint:' <<< "$(jq -r .body <<< "$issue_json")" ||
  { printf 'error: issue #%s is not a pipeline [qa] issue\n' "$issue" >&2; exit 2; }
title="$(jq -r .title <<< "$issue_json")"

# Replication detail travels IN the PR body so reviewers never chase links.
# Pulls the fingerprint, case facts, failure excerpt, and rerun runbook from
# the linked issue; fail-soft to a pointer when the issue format drifted.
# (awk/sed/grep only: no bash-4 constructs.)
replication_for_issue() {
  # The fingerprint marker is deliberately excluded: the gate above already
  # requires it, and the issue reference carries the identity. That keeps this empty
  # (and the pointer fallback live) when an issue has no replication yet.
  # Each consumer gets its own copy: the first grep would otherwise drain
  # the shared stdin and starve the awks.
  local input
  input="$(cat)"
  {
    printf '%s\n' "$input" | grep -E '^- (case|distro|result|source|run):' || true
    printf '%s\n' "$input" | awk '/^### Failure excerpt/{ show=1 } show { print } show && /^````$/ { show=0 }' | head -n 40
    printf '%s\n' "$input" | awk '/^### Agent runbook/{ show=1 } show { print }' | head -n 30
  } | head -n 80
}

# Fail closed on a dirty tree: fixes go up as commits, never as smudges.
if [[ -n "$(git status --porcelain)" ]]; then
  printf 'error: working tree is dirty; commit or stash first\n' >&2
  exit 2
fi
git rev-parse --verify --quiet "$branch" >/dev/null ||
  { printf 'error: no such local branch %s\n' "$branch" >&2; exit 2; }

if [[ "$dry_run" == true ]]; then
  printf 'would push branch %s and open draft PR: [qa-fix] #%s %s\n' "$branch" "$issue" "$title"
  exit 0
fi
git push -u origin "$branch" || exit 3
replication="$(jq -r .body <<< "$issue_json" | replication_for_issue)"
if [[ -z "$replication" ]]; then
  replication="See #$issue for the failure excerpt, evidence paths, and rerun command."
else
  replication="Replicated from #$issue (kept in sync by hand; the issue is authoritative):

$replication"
fi
pr_url="$(gh pr create --repo "$repo" --head "$branch" --base "$base" --draft \
  --title "[qa-fix] #$issue $title" \
  --body "$(cat <<EOF
Related QA issue: #$issue.

Automated fix PR for a pipeline [qa] failure. Opened as a draft:
verify locally, fill in verification below, then promote.

## Failure replication

$replication

## Verification (agent fills before promoting)

- [ ] Reran the failing leg from the issue runbook: PASS
- [ ] Fixture suites green: \`./scripts/test-release-smoke.sh\`, \`./scripts/test-qa-file-issue.sh\`, \`./scripts/test-qa-open-pr.sh\`, \`./scripts/test-qa-audit.sh\`

Keep the issue open after merge until an authoritative passing run verifies
the affected case. The issue reporter records that evidence before closure.
EOF
)" || exit 3)"
printf 'opened %s\n' "$pr_url"
