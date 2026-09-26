#!/usr/bin/env bash
# Regenerate the XZ variants used by
# `src/runtimes/common.rs::xz_stream_variants_decode_through_the_extraction_path`.
# The fixtures pin single/multi-block decoding and integrity checks with the
# system XZ encoder; SHA-256 streams must now decode and verify successfully.
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
tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
  -cf payload.tar -C tree .

# One block, CRC64 (xz's default) and no integrity check.
xz -0 -k -c payload.tar > "$dest/single-block-crc64.tar.xz"
xz -0 --check=none -k -c payload.tar > "$dest/single-block-none.tar.xz"
# Many small blocks with CRC64: exercises the block loop, not the check type.
xz -0 --block-size=4KiB -k -c payload.tar > "$dest/multi-block-crc64.tar.xz"
# SHA-256 checked streams exercise the decoder's full integrity-check path.
xz -0 --check=sha256 -k -c payload.tar > "$dest/single-block-sha256.tar.xz"
xz -0 --block-size=4KiB --check=sha256 -k -c payload.tar > "$dest/multi-block-sha256.tar.xz"

# Native package databases also consume XZ; keep one parseable record for each
# backend so tests exercise the production reader, not only the shared decoder.
mkdir -p pacman-db/fixture-1-1
printf '%%NAME%%\nfixture\n\n%%VERSION%%\n1-1\n\n%%DESC%%\nXZ fixture package\n\n' > pacman-db/fixture-1-1/desc
tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
  -cf pacman-sync.tar -C pacman-db fixture-1-1
xz -0 --check=sha256 -k -c pacman-sync.tar > "$dest/pacman-sync-sha256.db.xz"
printf 'Package: fixture\nVersion: 1.0\n\n' > Packages
xz -0 --check=sha256 -k -c Packages > "$dest/apt-packages-sha256.xz"

for file in "$dest"/*.tar.xz; do
  printf '%s: %s bytes, %s\n' "$(basename "$file")" "$(stat -c%s "$file")" \
    "$(xz --list "$file" | awk 'NR==2 {printf "blocks=%s check=%s", $2, $(NF-1)}')"
done
