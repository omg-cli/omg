#!/usr/bin/env bash
# Regenerate the XZ variants used by
# `src/runtimes/common.rs::supported_xz_stream_variants_decode`. The fixtures
# exist to pin what the pure-Rust decoder (lzma-rs) can and cannot read:
#
#   * lzma-rs implements "a subset of the .xz file format"
#     (https://github.com/gendx/lzma-rs) and its changelog records the limitation
#     "Return an error instead of panicking on unsupported SHA-256 checksum for XZ
#     decoding" (CHANGELOG 0.1.3, upstream PR #40). 0.3.0 (2023-01-04) is still the
#     newest published version (crates.io max_version), so SHA-256 streams remain
#     unreadable.
#
# Run from anywhere; it writes next to itself:
#   bash tests/data/xz-subset/generate.sh
set -euo pipefail
dest=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

mkdir -p tree
for index in 1 2 3; do
  {
    echo "omg xz fixture file $index"
    # awk, not `yes | head`: pipefail would treat the SIGPIPE as a failure.
    # (`n`, not `index`: gawk reserves `index` as a builtin.)
    awk -v n="$index" 'BEGIN { for (line = 0; line < 400; line++) print "repeated line for block splitting " n }'
  } > "tree/file-$index.txt"
done
tar -cf payload.tar -C tree .

# One block, CRC64 (xz's default) and no integrity check.
xz -0 -k -c payload.tar > "$dest/single-block-crc64.tar.xz"
xz -0 --check=none -k -c payload.tar > "$dest/single-block-none.tar.xz"
# Many small blocks with CRC64: exercises the block loop, not the check type.
xz -0 --block-size=4KiB -k -c payload.tar > "$dest/multi-block-crc64.tar.xz"
# SHA-256 checked streams: documented as unsupported by lzma-rs 0.3.0.
xz -0 --check=sha256 -k -c payload.tar > "$dest/single-block-sha256.tar.xz"
xz -0 --block-size=4KiB --check=sha256 -k -c payload.tar > "$dest/multi-block-sha256.tar.xz"

for file in "$dest"/*.tar.xz; do
  printf '%s: %s bytes, %s\n' "$(basename "$file")" "$(stat -c%s "$file")" \
    "$(xz --list "$file" | awk 'NR==2 {printf "blocks=%s check=%s", $2, $(NF-1)}')"
done
