#!/usr/bin/env bash
set -euo pipefail

if [[ ${1:-} == --help ]]; then
  printf 'Usage: scripts/report-smoke-sentry.sh RESULTS_JSON\nSends sanitized failure summaries after a smoke run.\nConfiguration: OMG_SMOKE_SENTRY_CONFIG, ~/.config/omg-smoke/sentry.json, or OMG_SMOKE_SENTRY_DSN when no file exists.\nOptional release tag: OMG_SMOKE_RELEASE. Missing configuration disables reporting.\n'
  exit 0
fi
[[ $# == 1 ]] || { printf 'error: expected one results.json path\n' >&2; exit 2; }
config="${OMG_SMOKE_SENTRY_CONFIG:-$HOME/.config/omg-smoke/sentry.json}"
if [[ ! -f "$config" && -z "${OMG_SMOKE_SENTRY_DSN:-}" ]]; then
  printf 'Sentry reporting disabled: no configuration\n'
  exit 0
fi
[[ -f "$1" && $(wc -c < "$1") -le 1048576 ]] || { printf 'Sentry input missing or exceeds 1 MiB\n' >&2; exit 2; }
environment=${OMG_SMOKE_ENVIRONMENT:-release-smoke}
case "$environment" in release-smoke|qemu-matrix) ;; *) printf 'Unsupported Sentry environment\n' >&2; exit 2 ;; esac
for tool in jq curl; do
  command -v "$tool" >/dev/null || { printf 'reporting unavailable: missing %s\n' "$tool" >&2; exit 3; }
done
if [[ -f "$config" ]]; then
  # A maintainer-provided file takes precedence over the workflow secret.
  OMG_SMOKE_SENTRY_DSN="$(jq -er '.dsn | strings' "$config")" || exit 2
  export OMG_SMOKE_SENTRY_DSN
fi
if ! endpoint="$(jq -ner 'env.OMG_SMOKE_SENTRY_DSN | capture("^https://[A-Za-z0-9]+@(?<host>[a-z0-9.-]+\\.sentry\\.io)/(?<project>[0-9]+)$") | "https://\(.host)/api/\(.project)/envelope/"')"; then
  printf 'Sentry reporting disabled: DSN has an unexpected shape\n' >&2
  exit 2
fi
release="${OMG_SMOKE_RELEASE:-unknown}"
[[ "$release" == unknown || "$release" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 2
run_id="$(basename "$(dirname "$1")")"
[[ "$run_id" =~ ^[A-Za-z0-9_-]{1,100}$ ]] || exit 2

failures="$(jq -ce '
  def identifier: type == "string" and test("^[a-z0-9][a-z0-9-]{0,127}$");
  if type != "array" then error("results must be an array") else . end |
  if length > 10000 then error("too many results") else . end |
  if all(.[];
    (.case_id | identifier) and
    (.distro | IN("arch", "debian", "ubuntu", "fedora", "macos")) and
    (.result | IN("PASS", "SKIPPED", "EXPECTED_REJECTION", "PRODUCT_FAIL", "HARNESS_ERROR", "FAIL", "BLOCKED")) and
    (.exit_code | type == "number" and floor == . and . >= -1 and . <= 255) and
    (.elapsed_seconds | type == "number" and . >= 0 and . <= 86400))
  then . else error("invalid result fields") end |
  map(select(.result == "PRODUCT_FAIL" or .result == "HARNESS_ERROR" or .result == "FAIL") |
    {case_id, distro, result, exit_code, elapsed_seconds})
' "$1")"
[[ "$(jq 'length' <<< "$failures")" != 0 ]] || { printf 'Sentry report not needed: no failures\n'; exit 0; }
[[ ${#failures} -le 250000 ]] || { printf 'Sentry failure metadata exceeds payload limit\n' >&2; exit 2; }
if command -v uuidgen >/dev/null 2>&1; then
  event_id="$(uuidgen | tr -d '-' | tr -d '\n')"
else
  event_id="$(tr -d '-' < /proc/sys/kernel/random/uuid)"
fi
printf 'Sentry sending event %s for run %s\n' "$event_id" "$run_id"
http_code="$({
  jq -cn --arg id "$event_id" '{event_id:$id,dsn:env.OMG_SMOKE_SENTRY_DSN}'
  printf '{"type":"event"}\n'
  jq -cn --arg id "$event_id" --arg release "$release" --arg run_id "$run_id" \
    --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson failures "$failures" \
    --arg environment "$environment" \
    '{event_id:$id,timestamp:$timestamp,platform:"other",level:"error",logger:"omg-smoke",
      environment:$environment,release:$release,message:"OMG release smoke run has failures",
      fingerprint:["omg-smoke",$release,($failures | map(.distro+":"+.case_id+":"+.result) | sort | join(","))],
      tags:{run_id:$run_id,reporter:"post-run"},extra:{failures:$failures}}'
} | curl --silent --show-error --connect-timeout 3 --max-time 8 --proto '=https' \
  -H 'Content-Type: application/x-sentry-envelope' --data-binary @- \
  --output /dev/null --write-out '%{http_code}' "$endpoint")" || {
    printf 'Sentry transport failed; local evidence is unchanged\n' >&2
    exit 1
  }
if [[ "$http_code" != 2[0-9][0-9] ]]; then
  printf 'Sentry rejected report with HTTP %s; local evidence is unchanged\n' "$http_code" >&2
  exit 1
fi
printf 'Sentry accepted event %s for run %s\n' "$event_id" "$run_id"
