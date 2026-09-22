#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <version> <artifact-directory> <release-directory>" >&2
  exit 64
fi

version="$1"
artifact_dir="$2"
release_dir="$3"

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "invalid release version" >&2
  exit 65
fi
if [[ ! -d "$artifact_dir" ]]; then
  echo "artifact directory does not exist" >&2
  exit 66
fi

archives=(
  "omg-v${version}-x86_64-linux-arch.tar.gz"
  "omg-v${version}-x86_64-linux-debian.tar.gz"
  "omg-v${version}-x86_64-linux-debian-trixie.tar.gz"
  "omg-v${version}-x86_64-linux-ubuntu.tar.gz"
  "omg-v${version}-x86_64-linux-fedora.tar.gz"
  "omg-v${version}-aarch64-darwin.tar.gz"
)

mkdir -p "$release_dir"
if find "$release_dir" -mindepth 1 -print -quit | grep -q .; then
  echo "release directory must be empty" >&2
  exit 73
fi

expected_names=("omg-v${version}.cdx.json")
for archive in "${archives[@]}"; do
  expected_names+=("$archive" "${archive}.sha256")
done

mapfile -t discovered < <(
  find "$artifact_dir" -type f \( -name '*.tar.gz' -o -name '*.tar.gz.sha256' -o -name '*.cdx.json' \) \
    -printf '%f\n' | sort
)
mapfile -t expected_sorted < <(printf '%s\n' "${expected_names[@]}" | sort)
if [[ "${discovered[*]}" != "${expected_sorted[*]}" ]]; then
  echo "release artifacts do not match the exact platform allowlist" >&2
  exit 65
fi

for name in "${expected_names[@]}"; do
  mapfile -t matches < <(find "$artifact_dir" -type f -name "$name" -print)
  if [[ ${#matches[@]} -ne 1 ]]; then
    echo "expected exactly one artifact named $name" >&2
    exit 65
  fi
  cp -- "${matches[0]}" "$release_dir/$name"
done

sbom="$release_dir/omg-v${version}.cdx.json"
if [[ ! -s "$sbom" ]] || ! grep -q '"bomFormat"[[:space:]]*:[[:space:]]*"CycloneDX"' "$sbom"; then
  echo "release SBOM is empty or not CycloneDX JSON" >&2
  exit 65
fi

for archive in "${archives[@]}"; do
  checksum_file="$release_dir/${archive}.sha256"
  mapfile -t checksum_lines < "$checksum_file"
  if [[ ${#checksum_lines[@]} -ne 1 ]]; then
    echo "checksum sidecar for $archive must contain exactly one entry" >&2
    exit 65
  fi

  read -r digest recorded_name extra <<<"${checksum_lines[0]}"
  recorded_name="${recorded_name#\*}"
  if [[ ! "$digest" =~ ^[0-9a-f]{64}$ || "$recorded_name" != "$archive" || -n "${extra:-}" ]]; then
    echo "checksum sidecar for $archive is malformed" >&2
    exit 65
  fi

  actual_digest=$(sha256sum "$release_dir/$archive" | awk '{print $1}')
  if [[ "$actual_digest" != "$digest" ]]; then
    echo "checksum mismatch for $archive" >&2
    exit 65
  fi
done

printf 'collected and verified %d release files\n' "${#expected_names[@]}"
