#!/usr/bin/env bash
# Run the production HTTPS advisory contract only inside a disposable APT guest.
# https://manpages.debian.org/trixie/util-linux/unshare.1.en.html
set -euo pipefail
binary=$1; daemon=$2; archive_sha256=$3; evidence=$4
[[ "$archive_sha256" =~ ^[0-9a-f]{64}$ ]] || exit 120
mkdir -p "$evidence/osv"
sha256sum /etc/hosts /etc/ssl/certs/ca-certificates.crt > "$evidence/osv/parent-system-before.sha256"
worker_rc=0
timeout --kill-after=5s 120s sudo -n unshare --mount --net --propagation private \
  python3 "$HOME/qemu-osv-positive-oracle.py" --binary "$binary" --daemon "$daemon" \
  --fixture-root /tmp/omg-osv-qemu-616 --archive-sha256 "$archive_sha256" \
  > "$evidence/osv/worker.log" 2>&1 || worker_rc=$?
sha256sum /etc/hosts /etc/ssl/certs/ca-certificates.crt > "$evidence/osv/parent-system-after.sha256"
# Copy public diagnostics even when the worker fails; never copy its key or user directories.
files=(receipt.json native-query.tsv os-release fixture-events.json daemon.log)
for phase in untrusted-tls direct-plain direct-findings daemon-plain daemon-findings daemon-before daemon-after; do
  files+=("$phase.stdout" "$phase.stderr")
done
for name in "${files[@]}"; do
  source="/tmp/omg-osv-qemu-616/evidence/$name"
  if sudo -n test -f "$source"; then
    sudo -n install -m 644 -o "$(id -u)" -g "$(id -g)" "$source" "$evidence/osv/$name"
  fi
done
if ! cmp -s "$evidence/osv/parent-system-before.sha256" "$evidence/osv/parent-system-after.sha256"; then
  printf 'Parent guest hosts or trust changed during isolated OSV probe\n' >&2
  exit 1
fi
if [[ "$worker_rc" != 0 ]]; then
  tail -n 40 "$evidence/osv/worker.log" >&2
  exit "$worker_rc"
fi
# Host replay additionally requires every outcome, native query and bound archive.
printf 'PASS: production OSV advisory and fail-on-findings lifecycle\n'
