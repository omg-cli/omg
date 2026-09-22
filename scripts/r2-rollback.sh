#!/usr/bin/env bash
# Roll back the published "latest" version marker in the omg-releases R2 bucket.
#
# Usage:
#   ./scripts/r2-rollback.sh <version> [--dry-run] [--allow-legacy-apt6]
#
# Re-points the single mutable `latest-version` marker at an already-published
# release version WITHOUT touching any archives or checksums. Existing clients
# require `omg self-update --force` to accept an older version. The marker does
# not bypass downgrade protection or modify installed binaries.
#
# Requirements:
#   - env CLOUDFLARE_API_TOKEN + CLOUDFLARE_ACCOUNT_ID with object write
#     access to the `omg-releases` bucket (same credentials as release.yml)
#   - `wrangler` on PATH, or run from a repo checkout with
#     `.github/deps/release-tools` installed (`npm ci` in that directory)
#
# See SECURITY.md ("Release incident response") for the full runbook.
set -euo pipefail

usage() {
  local status="${1:-64}"
  sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
  exit "$status"
}

dry_run=false
allow_legacy_apt6=false
version=""
for arg in "$@"; do
  case "$arg" in
    --dry-run) dry_run=true ;;
    --allow-legacy-apt6) allow_legacy_apt6=true ;;
    -h|--help) usage 0 ;;
    -*) echo "error: unknown option: $arg" >&2; usage ;;
    *)
      if [[ -n "$version" ]]; then
        echo "error: multiple version arguments supplied" >&2
        usage
      fi
      version="$arg"
      ;;
  esac
done

if [[ -z "$version" ]]; then
  echo "error: version argument required" >&2
  usage
fi
semver_re='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
if [[ ! "$version" =~ $semver_re ]]; then
  echo "error: version must be an exact semver (e.g. 0.1.214, 1.2.3)" >&2
  exit 65
fi
: "${CLOUDFLARE_API_TOKEN:?must be set}" "${CLOUDFLARE_ACCOUNT_ID:?must be set}"

mkdir -p .github/deps/release-tools
if [[ -x ".github/deps/release-tools/node_modules/.bin/wrangler" ]]; then
  WRANGLER="$PWD/.github/deps/release-tools/node_modules/.bin/wrangler"
elif command -v wrangler >/dev/null 2>&1; then
  WRANGLER=wrangler
else
  echo "Installing pinned wrangler from vendored lockfile..." >&2
  npm ci --prefix .github/deps/release-tools
  WRANGLER="$PWD/.github/deps/release-tools/node_modules/.bin/wrangler"
fi

prefix="omg-v${version}"

# Pre-flight: the target version must be fully published (archive + checksum
# present for every supported platform) before the marker may move to it.
echo "Verifying $prefix artifacts exist in R2..."
platforms=(x86_64-linux-arch x86_64-linux-debian x86_64-linux-ubuntu x86_64-linux-fedora aarch64-darwin)
if [[ "$allow_legacy_apt6" == true ]]; then
  echo "WARNING: legacy rollback explicitly excludes APT7; APT7-only clients cannot install this release." >&2
else
  platforms+=(x86_64-linux-debian-trixie)
fi
for arch in "${platforms[@]}"; do
  for suffix in tar.gz tar.gz.sha256; do
    artifact="${prefix}-${arch}.${suffix}"
    object="omg-releases/${artifact}"
    "$WRANGLER" r2 object get "$object" --remote --file=/dev/null >/dev/null 2>&1 || {
      echo "error: missing R2 object: $object - cannot roll back to $version" >&2
      exit 66
    }
    echo "  ✓ ${artifact}"
  done
done

if [[ "$dry_run" == "true" ]]; then
  echo "DRY RUN: would set latest-version → $version"
  exit 0
fi

marker="$(mktemp)"
printf '%s' "$version" > "$marker"
trap 'rm -f "$marker"' EXIT
"$WRANGLER" r2 object put "omg-releases/latest-version" --remote \
  --file="$marker" \
  --content-type="text/plain" \
  --cache-control="no-store"

# Verify what was published.
body="$("$WRANGLER" r2 object get "omg-releases/latest-version" --remote --pipe 2>/dev/null || true)"
if [[ "$body" != "$version" ]]; then
  echo "error: latest-version marker does not match after publish (got: '$body')" >&2
  exit 1
fi

echo "✓ latest-version rolled back to $version"
echo "Note: archives and checksums for other versions were left untouched."
