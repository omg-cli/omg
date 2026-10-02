#!/bin/bash
#
# AUR Installation Benchmark: OMG vs yay
#
# Compares installation performance for various AUR packages
# to quantify the improvements from all optimizations.
#
# Usage: ./benches/aur_install_bench.sh
#
# Requirements:
# - yay installed for comparison
# - sudo access
# - bc command for calculations
# - Clean system (packages will be uninstalled between runs)
# - Explicit opt-in: OMG_AUR_BENCH_CONFIRM_HOST_MUTATION=yes
#
# SAFETY: AUR packages are mutable third-party sources (VCS builds cannot be
# digest-pinned), so this benchmark executes unattested code and mutates the
# host package database with sudo. Run it only in a disposable VM/container
# snapshot, never against a valuable host.

set -e

# Explicit, non-interactive confirmation gate: the packages below are
# mutable third-party AUR builds, so no digest pin can attest what this
# script executes. Require a deliberate opt-in before touching the host.
if [[ "${OMG_AUR_BENCH_CONFIRM_HOST_MUTATION:-}" != "yes" ]]; then
    echo "error: this benchmark installs/uninstalls mutable third-party AUR" >&2
    echo "       packages (yay-bin, paru-bin, ttf-meslo) on this host using" >&2
    echo "       sudo. AUR builds cannot be digest-pinned; run it only in a" >&2
    echo "       disposable VM and re-run with:" >&2
    echo "         OMG_AUR_BENCH_CONFIRM_HOST_MUTATION=yes $0" >&2
    exit 2
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test packages - chosen for variety
PACKAGES=(
    "yay-bin"   # Binary package, minimal dependencies
    "paru-bin"  # Binary package, some dependencies
    "ttf-meslo" # Font package with downloads
)

echo -e "${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  AUR Installation Performance Benchmark             ║${NC}"
echo -e "${BLUE}║  OMG vs yay                                          ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════╝${NC}"
echo ""

# Build OMG in release mode first
echo -e "${YELLOW}Building OMG in release mode...${NC}"
cargo build --release --features arch
echo ""

# Function to uninstall package cleanly
uninstall_package() {
    local pkg=$1
    if pacman -Q "$pkg" &>/dev/null; then
        echo "  Uninstalling $pkg..." >&2
        if ! sudo pacman -Rns --noconfirm "$pkg" >&2; then
            echo "error: failed to remove $pkg; refusing an invalid benchmark" >&2
            return 1
        fi
    fi
    if pacman -Q "$pkg" &>/dev/null; then
        echo "error: $pkg is still installed; refusing an invalid benchmark" >&2
        return 1
    fi
}

# Function to benchmark installation
benchmark_install() {
    local tool=$1
    local package=$2

    echo -e "${YELLOW}Testing $tool: $package${NC}" >&2

    # Ensure package is not installed
    uninstall_package "$package" || return 1

    # Time the installation
    local start=$(date +%s.%N)

    if [ "$tool" = "omg" ]; then
        if ! ./target/release/omg install "$package" --yes >&2; then
            echo "error: OMG install failed for $package" >&2
            return 1
        fi
    elif ! yay -S --noconfirm "$package" >&2; then
        echo "error: yay install failed for $package" >&2
        return 1
    fi

    local end=$(date +%s.%N)
    local duration=$(echo "$end - $start" | bc)

    # Fail loudly on non-numeric timings instead of corrupting later bc math.
    case "$duration" in
    '' | *[!0-9.]*)
        echo "error: invalid timing measured for $tool/$package: '$duration'" >&2
        return 1
        ;;
    esac

    # Uninstall after test
    uninstall_package "$package" || return 1

    echo "$duration"
}

# Results storage
declare -A omg_times
declare -A yay_times

# Run benchmarks
for package in "${PACKAGES[@]}"; do
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${BLUE}Package: $package${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"

    # Benchmark OMG
    omg_time=$(benchmark_install "omg" "$package")
    omg_times[$package]=$omg_time
    echo -e "${GREEN}  OMG: ${omg_time}s${NC}"

    # Benchmark yay
    yay_time=$(benchmark_install "yay" "$package")
    yay_times[$package]=$yay_time
    echo -e "${GREEN}  yay: ${yay_time}s${NC}"

    # Calculate speedup
    speedup=$(echo "scale=2; $yay_time / $omg_time" | bc)
    echo -e "${YELLOW}  Speedup: ${speedup}x${NC}"
done

# Summary
echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  RESULTS SUMMARY                                     ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
printf "%-30s %12s %12s %12s\n" "Package" "OMG (s)" "yay (s)" "Speedup"
echo "─────────────────────────────────────────────────────────────────"

total_speedup=0
count=0

for package in "${PACKAGES[@]}"; do
    omg_time=${omg_times[$package]}
    yay_time=${yay_times[$package]}
    speedup=$(echo "scale=2; $yay_time / $omg_time" | bc)
    total_speedup=$(echo "$total_speedup + $speedup" | bc)
    count=$((count + 1))

    printf "%-30s %12.2f %12.2f %12.2fx\n" "$package" "$omg_time" "$yay_time" "$speedup"
done

echo "─────────────────────────────────────────────────────────────────"
avg_speedup=$(echo "scale=2; $total_speedup / $count" | bc)
echo -e "${GREEN}Average Speedup: ${avg_speedup}x${NC}"
echo ""
