#!/usr/bin/env bash
# Native signed advisory proof in private namespaces of a disposable Fedora VM.
# https://dnf5.readthedocs.io/en/latest/dnf5.conf.5.html#repo-gpgcheck
set -euo pipefail
binary=$1; daemon=$2; archive_sha256=$3; evidence=$4
[[ "$archive_sha256" =~ ^[0-9a-f]{64}$ ]] || exit 120
mkdir -p "$evidence/fedora-advisory"
sha256sum /etc/dnf/dnf.conf > "$evidence/fedora-advisory/parent-system-before.sha256"
worker_rc=0
timeout --kill-after=5s 120s sudo -n unshare --mount --net --propagation private \
  python3 "$HOME/qemu-fedora-advisory-oracle.py" --binary "$binary" --daemon "$daemon" \
  --fixture-root /tmp/omg-fedora-advisory-qemu-616 --archive-sha256 "$archive_sha256" \
  > "$evidence/fedora-advisory/worker.log" 2>&1 || worker_rc=$?
sha256sum /etc/dnf/dnf.conf > "$evidence/fedora-advisory/parent-system-after.sha256"
files=(receipt.json native-query.tsv os-release daemon.log commands.json native-version-comparison.txt native-dnf-before.conf private-dnf.conf fixture.repo fixture-key.asc updateinfo.xml updateinfo.xml.gz repomd.xml repomd.xml.asc)
for phase in untrusted-metadata direct-plain direct-findings daemon-plain daemon-findings daemon-before daemon-after native-advisory-list native-advisory-info native-repository verify; do
  files+=("$phase.stdout" "$phase.stderr")
done
for name in "${files[@]}"; do
  source="/tmp/omg-fedora-advisory-qemu-616/evidence/$name"
  if sudo -n test -f "$source"; then
    sudo -n install -m 644 -o "$(id -u)" -g "$(id -g)" "$source" "$evidence/fedora-advisory/$name"
  fi
done
if ! cmp -s "$evidence/fedora-advisory/parent-system-before.sha256" "$evidence/fedora-advisory/parent-system-after.sha256"; then
  printf 'Parent native DNF configuration changed during the isolated probe\n' >&2
  exit 1
fi
if [[ "$worker_rc" != 0 ]]; then
  tail -n 40 "$evidence/fedora-advisory/worker.log" >&2
  [[ -f "$evidence/fedora-advisory/receipt.json" ]] || exit 120
  exit 1
fi
[[ -f "$evidence/fedora-advisory/receipt.json" ]] || exit 120
printf 'PASS: native signed Fedora advisory and fail-on-findings lifecycle\n'
