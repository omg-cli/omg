#!/usr/bin/env bash
# Fast, deterministic multi-distro OCI container E2E verification for OMG.
# Runs natively inside Arch, Debian 12/13, Ubuntu 24.04, and Fedora containers
# on both x86_64 (ubuntu-24.04) and native aarch64 (ubuntu-24.04-arm) without
# QEMU, qcow2 images, SLIRP networking, or /dev/kvm.
set -euo pipefail

DISTRO="${1:?usage: distro-e2e.sh <arch|debian|debian-trixie|ubuntu|fedora> <omg-binary>}"
OMG_BIN="${2:?usage: distro-e2e.sh <arch|debian|debian-trixie|ubuntu|fedora> <omg-binary>}"

if [[ ! -x "$OMG_BIN" ]]; then
  echo "ERROR: omg binary is not executable: $OMG_BIN" >&2
  exit 1
fi

export OMG_DISABLE_DAEMON=1
export OMG_NO_TELEMETRY=1
export OMG_DATA_DIR="$(mktemp -d /tmp/omg-e2e-data.XXXXXX)"
export OMG_CONFIG_DIR="$(mktemp -d /tmp/omg-e2e-config.XXXXXX)"
export OMG_CACHE_DIR="$(mktemp -d /tmp/omg-e2e-cache.XXXXXX)"
trap 'rm -rf -- "$OMG_DATA_DIR" "$OMG_CONFIG_DIR" "$OMG_CACHE_DIR"' EXIT

# Put the tested binary first on PATH so `omg doctor` resolves this exact build.
BIN_DIR="$(dirname "$(readlink -f "$OMG_BIN")")"
export PATH="$BIN_DIR:$PATH"

echo "=== [distro-e2e:$DISTRO] Architecture: $(uname -m) ==="
"$OMG_BIN" --version

echo "=== [distro-e2e:$DISTRO] Verifying native package database reads ==="
case "$DISTRO" in
  arch)
    pacman -Sy --noconfirm >/dev/null
    "$OMG_BIN" search pacman --no-aur --limit 5 | grep -qi "pacman"
    "$OMG_BIN" info pacman | grep -q "Name:"
    ;;
  debian|debian-trixie|ubuntu)
    apt-get update -qq
    "$OMG_BIN" search bash --limit 5 | grep -qi "bash"
    "$OMG_BIN" info bash | grep -q "Name:"
    ;;
  fedora)
    dnf makecache -q
    "$OMG_BIN" search bash --limit 5 | grep -qi "bash"
    "$OMG_BIN" info bash | grep -q "Name:"
    ;;
  *)
    echo "ERROR: unsupported distro: $DISTRO" >&2
    exit 1
    ;;
esac

echo "=== [distro-e2e:$DISTRO] Verifying status and outdated JSON contracts ==="
"$OMG_BIN" status >/dev/null
"$OMG_BIN" outdated --json | python3 -c 'import json, sys; data = json.load(sys.stdin); assert isinstance(data, list), type(data)'

echo "=== [distro-e2e:$DISTRO] Verifying doctor health ==="
"$OMG_BIN" doctor

echo "=== [distro-e2e:$DISTRO] PASS ==="
