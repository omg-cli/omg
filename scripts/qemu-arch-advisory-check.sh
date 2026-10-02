#!/usr/bin/env bash
# Exercise the native Arch feed in private namespaces of a disposable QEMU guest.
# https://man.archlinux.org/man/nss-resolve.8.en
set -euo pipefail
binary=$1; daemon=$2; archive_sha256=$3; evidence=$4
[[ "$archive_sha256" =~ ^[0-9a-f]{64}$ ]] || exit 120
mkdir -p "$evidence/arch-advisory"
sha256sum /etc/hosts /etc/ssl/certs/ca-certificates.crt /etc/nsswitch.conf > "$evidence/arch-advisory/parent-system-before.sha256"
worker_rc=0
timeout --kill-after=5s 120s sudo -n unshare --mount --net --propagation private \
  python3 "$HOME/qemu-arch-advisory-oracle.py" --binary "$binary" --daemon "$daemon" \
  --fixture-root /tmp/omg-arch-advisory-qemu-616 --archive-sha256 "$archive_sha256" \
  > "$evidence/arch-advisory/worker.log" 2>&1 || worker_rc=$?
sha256sum /etc/hosts /etc/ssl/certs/ca-certificates.crt /etc/nsswitch.conf > "$evidence/arch-advisory/parent-system-after.sha256"
files=(receipt.json native-query.tsv os-release fixture-events.json daemon.log native-feed.json native-nss-before.conf private-nss.conf dns-isolation.json)
for phase in untrusted-tls direct-plain direct-findings daemon-plain daemon-findings daemon-before daemon-after; do
  files+=("$phase.stdout" "$phase.stderr")
done
for name in "${files[@]}"; do
  source="/tmp/omg-arch-advisory-qemu-616/evidence/$name"
  if sudo -n test -f "$source"; then
    sudo -n install -m 644 -o "$(id -u)" -g "$(id -g)" "$source" "$evidence/arch-advisory/$name"
  fi
done
if ! cmp -s "$evidence/arch-advisory/parent-system-before.sha256" "$evidence/arch-advisory/parent-system-after.sha256"; then
  printf 'Parent guest hosts, trust or NSS changed during isolated Arch probe\n' >&2
  exit 1
fi
if [[ "$worker_rc" != 0 ]]; then
  tail -n 40 "$evidence/arch-advisory/worker.log" >&2
  # A product-phase failure writes its receipt in finally; earlier refusal is setup failure.
  [[ -f "$evidence/arch-advisory/receipt.json" ]] || exit 120
  exit 1
fi
[[ -f "$evidence/arch-advisory/receipt.json" ]] || exit 120
printf 'PASS: production native Arch advisory and fail-on-findings lifecycle\n'
