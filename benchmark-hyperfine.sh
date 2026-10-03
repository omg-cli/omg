#!/bin/bash
set -euo pipefail

# The one-shot transaction benchmark uses this mode for both OMG and the
# native manager. Hyperfine's pipe output policy discards stderr, which hid
# the command's actual failure in QEMU evidence. Keep both streams without
# printing them into the measured terminal path, and preserve the exit code.
if [[ "${1:-}" == --capture-transaction ]]; then
    [[ $# -ge 4 ]] || exit 2
    transaction_stdout=$2 transaction_stderr=$3
    shift 3
    exec "$@" >"$transaction_stdout" 2>"$transaction_stderr"
fi

# ============================================================================
# OMG command measurements with Hyperfine
# ============================================================================
#
# Hyperfine: https://github.com/sharkdp/hyperfine
# Raw samples and exit codes are retained. Timing validity does not establish
# workload equivalence; guest comparisons check package identity and version.
#
# REQUIREMENTS:
#   omg install hyperfine       # Arch Linux
#   brew install hyperfine      # macOS
#
# USAGE:
#   ./benchmark-hyperfine.sh              # Full benchmark
#   ./benchmark-hyperfine.sh --fast       # Quick benchmark
#   ./benchmark-hyperfine.sh --update     # AUR update discovery benchmark only
#   ./benchmark-hyperfine.sh --help       # Show options
#
# ============================================================================

export PATH="$HOME/.cargo/bin:$PATH"

WARMUP=3
MIN_RUNS=20
MAX_RUNS=50
FAST_MODE=false
UPDATE_MODE=false
GUEST_MODE=false
GUEST_TRANSACTION=""
GUEST_TOOL=""
EXPORT_DIR="benchmark_results"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UPDATE_WORK_DIRS=()
DAEMON_PID=""
BENCH_DIR=""

print_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Options:
  --fast, -f    Run in fast mode (reduced warmup and runs)
  --guest       Benchmark info, complete JSON search, and explicit counts in
                a prepared Linux guest; requires OMG_BENCH_BINARY and tree
  --guest-transaction <install|remove> <omg|native>
                Run one transaction in a marked disposable QEMU guest;
                no warmups, exactly one sample, explicit before/after checks
  --update      Run ONLY the AUR update discovery benchmark (no daemon,
                no other benchmarks) and exit
  --help, -h    Show this help message

Environment Variables:
  OMG_BENCH_WARMUP        Number of warmup runs (default: 3, fast: 1)
  OMG_BENCH_RUNS          Minimum runs (default: 20, fast: 5)
  OMG_BENCH_MAX_RUNS      Maximum runs (default: 50, fast: 15)
  OMG_BENCH_EXPORT_DIR    Scratch JSON/MD directory (default: benchmark_results)
  OMG_BENCH_SKIP_RECORD   Set to 1 to skip writing benchmarks/records/
  OMG_BENCH_SKIP_UPDATE   Set to 1 to skip update discovery in a full run
  OMG_BENCH_BINARY        Path to a prebuilt omg binary (skips cargo build).
                          omgd is taken from the same directory.
  OMG_BENCH_TARGET_DIR    Cargo target directory (default:
                          ~/.cache/build-targets/omg-benchmark-hyperfine)
  OMG_BENCH_SOURCE_CACHE  Cache dir to copy AUR/package-DB fixtures from
                          (default: OMG_CACHE_DIR, else ~/.cache/omg)

Examples:
  $0                           # Full benchmark (3 warmup, 10+ runs)
  $0 --fast                    # Fast benchmark (1 warmup, 5+ runs)
  $0 --update                  # Update discovery benchmark only
  OMG_BENCH_RUNS=20 $0         # Custom run count
  OMG_BENCH_BINARY=./omg $0 --fast --update   # Benchmark a prebuilt binary
EOF
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --fast|-f)
            FAST_MODE=true
            shift
            ;;
        --guest)
            if [[ "$GUEST_MODE" == true ]]; then echo 'Select one guest mode.' >&2; exit 2; fi
            GUEST_MODE=true
            shift
            ;;
        --guest-transaction)
            if [[ $# -lt 3 || ( "$2" != install && "$2" != remove ) ]]; then
                echo 'Guest transaction requires install or remove and omg or native.' >&2; exit 2
            fi
            if [[ "$GUEST_MODE" == true || ( "$3" != omg && "$3" != native ) ]]; then
                echo 'Select one guest mode and tool: omg or native.' >&2; exit 2
            fi
            GUEST_MODE=true
            GUEST_TRANSACTION=$2
            GUEST_TOOL=$3
            shift 3
            ;;
        --update)
            UPDATE_MODE=true
            shift
            ;;
        --help|-h)
            print_usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
done

if [[ "$GUEST_MODE" == true && "$UPDATE_MODE" == true ]]; then
    echo 'Guest and development update modes are mutually exclusive.' >&2; exit 2
fi
if [[ -n "$GUEST_TRANSACTION" ]]; then
    marker=/run/omg-qemu-benchmark
    token=${OMG_BENCH_DISPOSABLE_GUEST:-}
    if [[ ! "$token" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] ||
       [[ ! -r "$marker" ]] ||
       [[ "$(LC_ALL=C stat -c '%u:%a:%F:%s' "$marker")" != '0:444:regular file:37' ]] ||
       [[ "$(<"$marker")" != "$token" ]]; then
        echo 'Transactions require an explicitly marked disposable QEMU guest.' >&2; exit 2
    fi
    case "$(systemd-detect-virt --vm 2>/dev/null)" in
        kvm|qemu) ;;
        *) echo 'Transactions require an explicitly marked disposable QEMU guest.' >&2; exit 2 ;;
    esac
fi

if [ "$FAST_MODE" = true ]; then
    WARMUP=${OMG_BENCH_WARMUP:-1}
    MIN_RUNS=${OMG_BENCH_RUNS:-5}
    MAX_RUNS=${OMG_BENCH_MAX_RUNS:-15}
else
    WARMUP=${OMG_BENCH_WARMUP:-3}
    MIN_RUNS=${OMG_BENCH_RUNS:-20}
    MAX_RUNS=${OMG_BENCH_MAX_RUNS:-50}
fi

EXPORT_DIR=${OMG_BENCH_EXPORT_DIR:-benchmark_results}
mkdir -p "$EXPORT_DIR"
EXPORT_DIR="$(cd "$EXPORT_DIR" && pwd)"
BENCH_SOURCE_CACHE="${OMG_BENCH_SOURCE_CACHE:-${OMG_CACHE_DIR:-$HOME/.cache/omg}}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

if ! command -v hyperfine &>/dev/null; then
    echo -e "${RED}❌ hyperfine not installed${NC}"
    echo ""
    echo "Install with:"
    echo "  Arch Linux:  omg install hyperfine"
    echo "  macOS:       brew install hyperfine"
    echo "  Cargo:       cargo install hyperfine"
    echo ""
    echo "Benchmark not run: hyperfine is required; no substitute timer is used." >&2
    exit 3
fi

cleanup() {
    if [ -n "${DAEMON_PID:-}" ]; then
        kill "$DAEMON_PID" >/dev/null 2>&1 || true
        wait "$DAEMON_PID" 2>/dev/null || true
        DAEMON_PID=""
    fi
    if [ -n "${BENCH_DIR:-}" ] && [ -d "$BENCH_DIR" ]; then
        rm -rf -- "$BENCH_DIR"
        BENCH_DIR=""
    fi
    local dir
    for dir in "${UPDATE_WORK_DIRS[@]}"; do
        rm -rf -- "$dir"
    done
}
trap cleanup EXIT

run_hyperfine() {
    local json="$1"
    local md="$2"
    shift 2
    hyperfine --shell=none --output=pipe \
        --warmup "$WARMUP" --min-runs "$MIN_RUNS" --max-runs "$MAX_RUNS" \
        --export-json "$json" --export-markdown "$md" \
        "$@" < /dev/null
}

command_json() {
    local command_label=$1
    shift
    jq -cn --arg command_label "$command_label" --args \
        '{"label":$command_label, argv:$ARGS.positional}' -- "$@"
}

preflight_match() {
    local label="$1"
    local needle="$2"
    local outfile="$3"
    shift 3
    if ! "$@" >"$outfile" 2>&1; then
        echo -e "${RED}❌ Preflight failed: ${label} (non-zero exit)${NC}" >&2
        cat "$outfile" >&2
        exit 1
    fi
    if ! grep -qiE "$needle" "$outfile"; then
        echo -e "${RED}❌ Preflight failed: ${label} (no match for /${needle}/)${NC}" >&2
        echo "----- output -----" >&2
        head -c 4000 "$outfile" >&2
        echo "" >&2
        exit 1
    fi
    local bytes lines
    bytes=$(wc -c < "$outfile" | tr -d ' ')
    lines=$(wc -l < "$outfile" | tr -d ' ')
    echo -e "  ${GREEN}ok${NC} ${label}  ${bytes} bytes, ${lines} lines"
}

archive_results() {
    if [ "${OMG_BENCH_SKIP_RECORD:-}" = 1 ]; then
        echo "Skipping benchmarks/records/ (OMG_BENCH_SKIP_RECORD=1)"
        return 0
    fi
    python3 "$REPO_ROOT/scripts/record-benchmark-run.py" \
        --source "$EXPORT_DIR" \
        --warmup "$WARMUP" \
        --min-runs "$MIN_RUNS" \
        --max-runs "$MAX_RUNS"
}

TARGET_DIR="${OMG_BENCH_TARGET_DIR:-$HOME/.cache/build-targets/omg-benchmark-hyperfine}"
if [[ "$GUEST_MODE" == true && ( "$UPDATE_MODE" == true || -z "${OMG_BENCH_BINARY:-}" ) ]]; then
    echo 'Guest benchmarks require a prebuilt binary and cannot use --update.' >&2
    exit 2
fi

if [ -n "${OMG_BENCH_BINARY:-}" ]; then
    echo -e "${BLUE}🔧 Using prebuilt binary: $OMG_BENCH_BINARY${NC}"
    if [ ! -x "$OMG_BENCH_BINARY" ]; then
        echo -e "${RED}❌ OMG_BENCH_BINARY is set but not executable: $OMG_BENCH_BINARY${NC}" >&2
        exit 1
    fi
    OMG="$OMG_BENCH_BINARY"
    bin_dir="$(cd "$(dirname "$OMG")" && pwd)"
    OMGD="$bin_dir/omgd"
else
    echo -e "${BLUE}🔨 Building release binaries...${NC}"
    CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="$TARGET_DIR" cargo build --release --locked --features arch --quiet

    OMG="$TARGET_DIR/release/omg"
    OMGD="$TARGET_DIR/release/omgd"
fi

if [ ! -x "$OMG" ]; then
    echo -e "${RED}❌ omg binary not executable: $OMG${NC}" >&2
    exit 1
fi
if [[ "$GUEST_MODE" == true ]]; then
    export LC_ALL=C NO_COLOR=1
    distro=$(awk -F= '$1 == "ID" {gsub(/"/, "", $2); print $2}' /etc/os-release)
    extra_native=()
    extra_name=""
    case "$distro" in
        arch) native=(pacman --color never -Qi tree); native_name=pacman ;;
        debian|ubuntu)
            native=(apt-cache --no-all-versions show tree); native_name=apt-cache
            extra_native=(apt show tree); extra_name=apt ;;
        fedora)
            native=(rpm -qi tree); native_name=rpm
            extra_native=(dnf -C info --installed tree); extra_name=dnf ;;
        *) echo "Unsupported guest distro: $distro" >&2; exit 2 ;;
    esac
    command -v jq >/dev/null || exit 3
    if [[ -n $(find "$EXPORT_DIR" -mindepth 1 -maxdepth 1 -print -quit) ]]; then
        echo 'Guest benchmark output must be empty; old evidence is never overwritten.' >&2
        exit 2
    fi
    date -u +%Y-%m-%dT%H:%M:%SZ > "$EXPORT_DIR/started-at.txt"
    # A private, absent socket prevents accidentally timing another run's daemon.
    export OMG_SOCKET_PATH="$EXPORT_DIR/no-daemon.sock"
    export OMG_CACHE_DIR="$EXPORT_DIR/cache"
    export OMG_DATA_DIR="$EXPORT_DIR/data"
    export OMG_CONFIG_DIR="$EXPORT_DIR/config"
    export OMG_NO_TELEMETRY=1
    mkdir -p "$OMG_CACHE_DIR" "$OMG_DATA_DIR" "$OMG_CONFIG_DIR"
    normalize_info() {
        awk -v rpm_release="$1" '
          {sub(/^[[:space:]]+/, ""); sub(/[[:space:]]+$/, "")}
          /^(Name|Package)[[:space:]]*:/ {sub(/^[^:]*:[[:space:]]*/, ""); name=$0; names++}
          /^Version[[:space:]]*:/ {sub(/^[^:]*:[[:space:]]*/, ""); version=$0; versions++}
          /^Release[[:space:]]*:/ {sub(/^[^:]*:[[:space:]]*/, ""); release=$0; releases++}
          END {
            if (names != 1 || versions != 1 || name != "tree" || version == "") exit 1;
            if (rpm_release == "true") {
              if (releases != 1 || release == "") exit 1;
              version=version "-" release;
            }
            print name "\t" version;
          }' "$2"
    }
    case "$distro" in
        arch) explicit_native=(pacman -Qqe); explicit_name=pacman ;;
        debian|ubuntu) explicit_native=(apt-mark showmanual); explicit_name=apt-mark ;;
        fedora) explicit_native=(dnf -C repoquery --userinstalled --qf '%{name}\n'); explicit_name=dnf ;;
    esac
    if [[ -n "$GUEST_TRANSACTION" ]]; then
        expected_version=${OMG_BENCH_EXPECTED_VERSION:-}
        if [[ ! "$expected_version" =~ ^[A-Za-z0-9][A-Za-z0-9.:+~_-]*$ ]]; then
            echo 'A prepared transaction requires an exact expected tree version.' >&2; exit 2
        fi
        # Privileged mutable state is not export evidence. Never loosen audit locks
        # merely so an unprivileged evidence copier can read them.
        root_state="/var/lib/omg-benchmark-$token"
        sudo -n install -d -m 700 "$root_state" "$root_state/cache" "$root_state/data" "$root_state/config"
        privileged=(sudo -n env LC_ALL=C NO_COLOR=1 OMG_NO_TELEMETRY=1
            "OMG_SOCKET_PATH=$root_state/no-daemon.sock" "OMG_CACHE_DIR=$root_state/cache"
            "OMG_DATA_DIR=$root_state/data" "OMG_CONFIG_DIR=$root_state/config")
        snapshot_version=$expected_version
        case "$distro" in
            arch)
                transaction_native=pacman
                if [[ "$GUEST_TRANSACTION" == install ]]; then transaction_args=(pacman -S --noconfirm tree)
                else transaction_args=(pacman -R --noconfirm tree); fi
                snapshot_name=tree ;;
            debian|ubuntu)
                transaction_native=apt
                transaction_args=(apt "$GUEST_TRANSACTION" --yes tree)
                snapshot_name=tree ;;
            fedora)
                transaction_native=dnf
                transaction_args=(dnf "$GUEST_TRANSACTION" -y tree)
                snapshot_name="tree.$(uname -m)"
                [[ "$snapshot_version" == *:* ]] || snapshot_version="0:$snapshot_version" ;;
        esac
        native_snapshot() {
            local phase=$1
            local raw="$EXPORT_DIR/installed-$phase.raw"
            case "$distro" in
                arch)
                    pacman -Q > "$raw" 2> "$raw.stderr"
                    awk 'NF != 2 {exit 1} {print $1 "\t" $2}' "$raw" ;;
                debian|ubuntu)
                    dpkg-query -W '-f=${binary:Package}\t${Version}\t${db:Status-Status}\n' > "$raw" 2> "$raw.stderr"
                    awk -F '\t' '$3 == "installed" {if (NF != 3 || $2 == "") exit 1; print $1 "\t" $2}' "$raw" ;;
                fedora)
                    rpm -qa --qf '%{NAME}.%{ARCH}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n' > "$raw" 2> "$raw.stderr"
                    awk -F '\t' 'NF != 2 || $1 == "" || $2 == "" {exit 1} {print}' "$raw" ;;
            esac | sort -u > "$EXPORT_DIR/installed-$phase.tsv"
            [[ -s "$EXPORT_DIR/installed-$phase.tsv" ]]
        }
        verify_tree_identity() {
            local phase=$1
            local -a identity_native=("${native[@]}")
            if [[ "$phase" == before && "$GUEST_TRANSACTION" == install ]]; then
                case "$distro" in
                    arch) identity_native=(pacman --color never -Si tree) ;;
                    fedora) identity_native=(dnf -C info --available tree) ;;
                esac
            fi
            "${privileged[@]}" "$OMG" info tree > "$EXPORT_DIR/omg-info-$phase.stdout" 2> "$EXPORT_DIR/omg-info-$phase.stderr"
            "${privileged[@]}" "${identity_native[@]}" > "$EXPORT_DIR/native-info-$phase.stdout" 2> "$EXPORT_DIR/native-info-$phase.stderr"
            normalize_info false "$EXPORT_DIR/omg-info-$phase.stdout" > "$EXPORT_DIR/omg-identity-$phase.tsv"
            normalize_info "$([[ "$distro" == fedora ]] && echo true || echo false)" \
                "$EXPORT_DIR/native-info-$phase.stdout" > "$EXPORT_DIR/native-identity-$phase.tsv"
            printf 'tree\t%s\n' "$expected_version" > "$EXPORT_DIR/expected-identity.tsv"
            cmp "$EXPORT_DIR/omg-identity-$phase.tsv" "$EXPORT_DIR/expected-identity.tsv"
            cmp "$EXPORT_DIR/native-identity-$phase.tsv" "$EXPORT_DIR/expected-identity.tsv"
        }
        cache_manifest() {
            local phase=$1
            sudo -n bash -c '
                set -euo pipefail
                for directory do
                    if [[ -d "$directory" ]]; then
                        printf "%s present\n" "$directory" >&2
                        find "$directory" -type f -exec sha256sum -- {} +
                    else printf "%s absent\n" "$directory" >&2; fi
                done
            ' bash "$root_state/cache" "$root_state/data" /var/cache/pacman/pkg \
                /var/lib/pacman/sync /var/cache/apt/archives /var/lib/apt/lists \
                /var/cache/dnf /var/cache/libdnf5 \
                2> "$EXPORT_DIR/cache-$phase-paths.txt" | sort > "$EXPORT_DIR/cache-$phase.sha256"
        }
        manual_snapshot() {
            local phase=$1
            "${privileged[@]}" "${explicit_native[@]}" > "$EXPORT_DIR/manual-$phase.stdout" 2> "$EXPORT_DIR/manual-$phase.stderr"
            sort -u "$EXPORT_DIR/manual-$phase.stdout" > "$EXPORT_DIR/manual-$phase.names"
            [[ -s "$EXPORT_DIR/manual-$phase.names" ]]
        }
        native_snapshot before
        manual_snapshot before
        tree_count=$(awk -F '\t' -v name="$snapshot_name" '$1 == name {count++} END {print count+0}' "$EXPORT_DIR/installed-before.tsv")
        if [[ "$GUEST_TRANSACTION" == install ]]; then
            if [[ "$tree_count" != 0 || -e /usr/bin/tree ]]; then
                echo 'Install sample requires tree absent; refusing a no-op measurement.' >&2; exit 1
            fi
            { cat "$EXPORT_DIR/installed-before.tsv"; printf '%s\t%s\n' "$snapshot_name" "$snapshot_version"; } |
                sort -u > "$EXPORT_DIR/installed-expected.tsv"
            { cat "$EXPORT_DIR/manual-before.names"; printf 'tree\n'; } | sort -u > "$EXPORT_DIR/manual-expected.names"
        else
            if [[ "$tree_count" != 1 || ! -x /usr/bin/tree ]]; then
                echo 'Remove sample requires exactly one installed tree package.' >&2; exit 1
            fi
            awk -F '\t' -v name="$snapshot_name" '$1 != name' "$EXPORT_DIR/installed-before.tsv" > "$EXPORT_DIR/installed-expected.tsv"
            grep -Fxq tree "$EXPORT_DIR/manual-before.names"
            awk '$0 != "tree"' "$EXPORT_DIR/manual-before.names" > "$EXPORT_DIR/manual-expected.names"
        fi
        verify_tree_identity before
        if [[ "$GUEST_TOOL" == omg ]]; then
            transaction=("${privileged[@]}" "$OMG" "$GUEST_TRANSACTION" --yes tree)
            transaction_label=OMG
        else
            transaction=("${privileged[@]}" "${transaction_args[@]}")
            transaction_label=$transaction_native
        fi
        command_json "$transaction_label" "${transaction[@]}" > "$EXPORT_DIR/command.json"
        cp /etc/os-release "$EXPORT_DIR/os-release"
        cp /proc/cpuinfo "$EXPORT_DIR/cpuinfo.txt"
        cp /proc/meminfo "$EXPORT_DIR/meminfo.txt"
        cp /proc/stat "$EXPORT_DIR/proc-stat-before.txt"
        cat /proc/sys/kernel/random/boot_id > "$EXPORT_DIR/boot-id.txt"
        uname -a > "$EXPORT_DIR/kernel.txt"
        "$OMG" --version > "$EXPORT_DIR/omg-version.txt"
        "$transaction_native" --version > "$EXPORT_DIR/native-version.txt" 2>&1
        hyperfine --version > "$EXPORT_DIR/hyperfine-version.txt"
        sha256sum "$OMG" "$(command -v "$transaction_native")" > "$EXPORT_DIR/binary-sha256.txt"
        # The audit needs a privileged read; evidence must remain user-owned.
        # shellcheck disable=SC2024
        sudo -n cat /var/lib/omg/audit/audit.jsonl > "$EXPORT_DIR/audit-before.jsonl"
        cache_manifest before
        printf -v transaction_command '%q ' bash "$REPO_ROOT/benchmark-hyperfine.sh" \
            --capture-transaction "$EXPORT_DIR/transaction.stdout" \
            "$EXPORT_DIR/transaction.stderr" "${transaction[@]}"
        WARMUP=0 MIN_RUNS=1 MAX_RUNS=1
        measurement_rc=0
        # Retain the actual program exit even on failure; admission below remains strict.
        run_hyperfine "$EXPORT_DIR/$GUEST_TRANSACTION.json" "$EXPORT_DIR/$GUEST_TRANSACTION.md" \
            --ignore-failure --command-name "$transaction_label" "$transaction_command" || measurement_rc=$?
        printf '%s\n' "$measurement_rc" > "$EXPORT_DIR/hyperfine.exit"
        cp /proc/stat "$EXPORT_DIR/proc-stat-after.txt"
        native_snapshot after
        manual_snapshot after
        # The audit needs a privileged read; evidence must remain user-owned.
        # shellcheck disable=SC2024
        sudo -n cat /var/lib/omg/audit/audit.jsonl > "$EXPORT_DIR/audit-after.jsonl"
        "${privileged[@]}" "$OMG" audit verify > "$EXPORT_DIR/audit-verify.stdout" 2> "$EXPORT_DIR/audit-verify.stderr"
        cache_manifest after
        [[ "$measurement_rc" == 0 ]]
        jq -e --arg label_name "$transaction_label" '
          .results | length == 1 and .[0].command == $label_name and
          .[0].exit_codes == [0] and (.[0].times|length == 1)
        ' "$EXPORT_DIR/$GUEST_TRANSACTION.json" >/dev/null
        cmp "$EXPORT_DIR/installed-expected.tsv" "$EXPORT_DIR/installed-after.tsv"
        cmp "$EXPORT_DIR/manual-expected.names" "$EXPORT_DIR/manual-after.names"
        if [[ "$GUEST_TRANSACTION" == install ]]; then
            [[ -x /usr/bin/tree ]]
            verify_tree_identity after
        else
            [[ ! -e /usr/bin/tree ]]
        fi
        jq -n --arg distro "$distro" --arg operation "$GUEST_TRANSACTION" --arg tool "$GUEST_TOOL" \
            --arg version "$expected_version" --slurpfile command "$EXPORT_DIR/command.json" \
            --rawfile boot_id "$EXPORT_DIR/boot-id.txt" '
          {schema_version:2,kind:"transaction-trial",complete:true,distro:$distro,
           operation:$operation,tool:$tool,package:"tree",expected_version:$version,
           state_change_verified:true,manual_state_change_verified:true,samples:1,warmup:0,daemon:"disabled",
           preparation:"metadata queries and cache-file hashes warm caches before timing; not a cold-cache claim",
           reset_evidence:"coordinator-required",
           boot_id:($boot_id|rtrimstr("\n")),command:$command[0]}
        ' > "$EXPORT_DIR/summary.json"
        exit 0
    fi
    "$OMG" info tree > "$EXPORT_DIR/omg-info.stdout" 2> "$EXPORT_DIR/omg-info.stderr"
    "${native[@]}" > "$EXPORT_DIR/native-info.stdout" 2> "$EXPORT_DIR/native-info.stderr"
    normalize_info false "$EXPORT_DIR/omg-info.stdout" > "$EXPORT_DIR/omg-identity.tsv"
    normalize_info "$([[ "$distro" == fedora ]] && echo true || echo false)" \
        "$EXPORT_DIR/native-info.stdout" > "$EXPORT_DIR/native-identity.tsv"
    cmp "$EXPORT_DIR/omg-identity.tsv" "$EXPORT_DIR/native-identity.tsv"
    if [[ ${#extra_native[@]} -gt 0 ]]; then
        "${extra_native[@]}" > "$EXPORT_DIR/extra-info.stdout" 2> "$EXPORT_DIR/extra-info.stderr"
        normalize_info "$([[ "$distro" == fedora ]] && echo true || echo false)" \
            "$EXPORT_DIR/extra-info.stdout" > "$EXPORT_DIR/extra-identity.tsv"
        cmp "$EXPORT_DIR/omg-identity.tsv" "$EXPORT_DIR/extra-identity.tsv"
        "$extra_name" --version > "$EXPORT_DIR/extra-version.txt" 2>&1
    fi
    cp /proc/cpuinfo "$EXPORT_DIR/cpuinfo.txt"
    cp /proc/meminfo "$EXPORT_DIR/meminfo.txt"
    cp /proc/stat "$EXPORT_DIR/proc-stat-before.txt"
    sha256sum "$OMG" > "$EXPORT_DIR/binary-sha256.txt"
    hyperfine --version > "$EXPORT_DIR/hyperfine-version.txt"
    "$native_name" --version > "$EXPORT_DIR/native-version.txt" 2>&1
    "$OMG" --version > "$EXPORT_DIR/omg-version.txt"
    uname -a > "$EXPORT_DIR/kernel.txt"
    cp /etc/os-release "$EXPORT_DIR/os-release"
    printf -v omg_command '%q ' "$OMG" info tree
    printf -v native_command '%q ' "${native[@]}"
    measured_commands=(--command-name OMG "$omg_command" --command-name "$native_name" "$native_command")
    expected_commands=2
    if [[ ${#extra_native[@]} -gt 0 ]]; then
        printf -v extra_command '%q ' "${extra_native[@]}"
        measured_commands+=(--command-name "$extra_name" "$extra_command")
        expected_commands=3
    fi
    run_hyperfine "$EXPORT_DIR/info.json" "$EXPORT_DIR/info.md" "${measured_commands[@]}"
    cp /proc/stat "$EXPORT_DIR/proc-stat-after.txt"
    jq -e --argjson minimum "$MIN_RUNS" --argjson maximum "$MAX_RUNS" \
        --argjson expected "$expected_commands" '
      (.results|length) == $expected and all(.results[];
        (.times|length) >= $minimum and (.times|length) <= $maximum and
        (.times|length) == (.exit_codes|length) and all(.exit_codes[]; . == 0))
    ' "$EXPORT_DIR/info.json" >/dev/null
    "$OMG" info tree > "$EXPORT_DIR/omg-info-after.stdout" 2> "$EXPORT_DIR/omg-info-after.stderr"
    "${native[@]}" > "$EXPORT_DIR/native-info-after.stdout" 2> "$EXPORT_DIR/native-info-after.stderr"
    normalize_info false "$EXPORT_DIR/omg-info-after.stdout" > "$EXPORT_DIR/omg-identity-after.tsv"
    normalize_info "$([[ "$distro" == fedora ]] && echo true || echo false)" \
        "$EXPORT_DIR/native-info-after.stdout" > "$EXPORT_DIR/native-identity-after.tsv"
    cmp "$EXPORT_DIR/omg-identity.tsv" "$EXPORT_DIR/omg-identity-after.tsv"
    cmp "$EXPORT_DIR/native-identity.tsv" "$EXPORT_DIR/native-identity-after.tsv"
    if [[ ${#extra_native[@]} -gt 0 ]]; then
        "${extra_native[@]}" > "$EXPORT_DIR/extra-info-after.stdout" 2> "$EXPORT_DIR/extra-info-after.stderr"
        normalize_info "$([[ "$distro" == fedora ]] && echo true || echo false)" \
            "$EXPORT_DIR/extra-info-after.stdout" > "$EXPORT_DIR/extra-identity-after.tsv"
        cmp "$EXPORT_DIR/extra-identity.tsv" "$EXPORT_DIR/extra-identity-after.tsv"
    fi
    {
        command_json OMG "$OMG" info tree
        command_json "$native_name" "${native[@]}"
        if [[ ${#extra_native[@]} -gt 0 ]]; then command_json "$extra_name" "${extra_native[@]}"; fi
    } | jq -s . > "$EXPORT_DIR/info.commands.json"

    # JSON preserves installable names rather than human-output alias grouping.
    omg_search=("$OMG" --json search ripgrep --no-aur --limit 100000)
    extra_search=()
    case "$distro" in
        arch) search_native=(pacman --color never -Ss ripgrep); search_name=pacman ;;
        debian|ubuntu)
            search_native=(apt-cache search ripgrep); search_name=apt-cache
            extra_search=(apt search ripgrep) ;;
        fedora)
            dnf -q makecache > "$EXPORT_DIR/native-cache-prepare.stdout" 2> "$EXPORT_DIR/native-cache-prepare.stderr"
            search_native=(dnf -C search ripgrep); search_name=dnf ;;
    esac
    omg_names() {
        jq -er --arg kind "$1" '
          (if $kind == "search" then map(.name) else .packages end) |
          if type == "array" and length > 0 and length < 100000 and
             all(.[]; type == "string" and test("^[A-Za-z0-9][A-Za-z0-9+._:@-]*$"))
          then .[] else error("invalid or potentially truncated package-name set") end
        ' "$2" | sort -u
    }
    search_names() {
        case "$1" in
            pacman) awk '/^[^[:space:]]+\/[^[:space:]]+[[:space:]]/ {split($1,p,"/"); print p[2]}' "$2" ;;
            apt-cache) awk '$2 == "-" {print $1}' "$2" ;;
            apt) awk '/^[^[:space:]]+\/[^[:space:]]+[[:space:]]/ {split($1,p,"/"); print p[1]}' "$2" ;;
            dnf) awk -v arch="$(uname -m)" '
                $1 ~ /^[A-Za-z0-9][A-Za-z0-9+._-]*\.[A-Za-z0-9_]+$/ {
                  name=$1; architecture=$1; sub(/^.*\./,"",architecture);
                  if (architecture != arch && architecture != "noarch") exit 1;
                  sub(/\.[^.]+$/,"",name); print name;
                }' "$2" ;;
        esac | sort -u
    }
    capture_search() {
        local phase=$1
        "${omg_search[@]}" > "$EXPORT_DIR/search-omg-$phase.stdout" 2> "$EXPORT_DIR/search-omg-$phase.stderr"
        "${search_native[@]}" > "$EXPORT_DIR/search-native-$phase.stdout" 2> "$EXPORT_DIR/search-native-$phase.stderr"
        omg_names search "$EXPORT_DIR/search-omg-$phase.stdout" > "$EXPORT_DIR/search-omg-$phase.names"
        search_names "$search_name" "$EXPORT_DIR/search-native-$phase.stdout" > "$EXPORT_DIR/search-native-$phase.names"
        grep -Fxq ripgrep "$EXPORT_DIR/search-omg-$phase.names"
        grep -Fxq ripgrep "$EXPORT_DIR/search-native-$phase.names"
        if [[ ${#extra_search[@]} -gt 0 ]]; then
            "${extra_search[@]}" > "$EXPORT_DIR/search-extra-$phase.stdout" 2> "$EXPORT_DIR/search-extra-$phase.stderr"
            search_names apt "$EXPORT_DIR/search-extra-$phase.stdout" > "$EXPORT_DIR/search-extra-$phase.names"
            grep -Fxq ripgrep "$EXPORT_DIR/search-extra-$phase.names"
        fi
    }
    capture_search before
    search_equivalent=true
    cmp -s "$EXPORT_DIR/search-omg-before.names" "$EXPORT_DIR/search-native-before.names" || search_equivalent=false
    printf -v search_omg_command '%q ' "${omg_search[@]}"
    printf -v search_native_command '%q ' "${search_native[@]}"
    search_commands=(--command-name OMG "$search_omg_command" --command-name "$search_name" "$search_native_command")
    if [[ ${#extra_search[@]} -gt 0 ]]; then
        cmp -s "$EXPORT_DIR/search-omg-before.names" "$EXPORT_DIR/search-extra-before.names" || search_equivalent=false
        printf -v search_extra_command '%q ' "${extra_search[@]}"
        search_commands+=(--command-name apt "$search_extra_command")
    fi
    {
        command_json OMG "${omg_search[@]}"
        command_json "$search_name" "${search_native[@]}"
        if [[ ${#extra_search[@]} -gt 0 ]]; then command_json apt "${extra_search[@]}"; fi
    } | jq -s . > "$EXPORT_DIR/search.commands.json"
    run_hyperfine "$EXPORT_DIR/search.json" "$EXPORT_DIR/search.md" "${search_commands[@]}"
    capture_search after
    if [[ "$search_equivalent" == false ]]; then
        echo 'NON-COMPARABLE search: package-name sets differ; timings are observations, not speedup evidence.' >&2
    fi
    cmp "$EXPORT_DIR/search-omg-before.names" "$EXPORT_DIR/search-omg-after.names"
    cmp "$EXPORT_DIR/search-native-before.names" "$EXPORT_DIR/search-native-after.names"
    if [[ ${#extra_search[@]} -gt 0 ]]; then cmp "$EXPORT_DIR/search-extra-before.names" "$EXPORT_DIR/search-extra-after.names"; fi

    capture_explicit() {
        local phase=$1
        "$OMG" --json explicit > "$EXPORT_DIR/explicit-omg-$phase.stdout" 2> "$EXPORT_DIR/explicit-omg-$phase.stderr"
        "${explicit_native[@]}" > "$EXPORT_DIR/explicit-native-$phase.stdout" 2> "$EXPORT_DIR/explicit-native-$phase.stderr"
        omg_names explicit "$EXPORT_DIR/explicit-omg-$phase.stdout" > "$EXPORT_DIR/explicit-omg-$phase.names"
        sort -u "$EXPORT_DIR/explicit-native-$phase.stdout" > "$EXPORT_DIR/explicit-native-$phase.names"
        cmp "$EXPORT_DIR/explicit-omg-$phase.names" "$EXPORT_DIR/explicit-native-$phase.names"
    }
    capture_explicit before
    if [[ "$distro" == debian || "$distro" == ubuntu ]]; then
        dpkg --print-foreign-architectures > "$EXPORT_DIR/foreign-architectures.txt"
        [[ ! -s "$EXPORT_DIR/foreign-architectures.txt" ]]
        dpkg-query -W '-f=${Package}\t${db:Status-Status}\n' |
            awk -F '\t' '$2 == "installed" {print $1}' | sort -u > "$EXPORT_DIR/installed.names"
        comm -23 "$EXPORT_DIR/explicit-native-before.names" "$EXPORT_DIR/installed.names" > "$EXPORT_DIR/uninstalled-manual.names"
        [[ ! -s "$EXPORT_DIR/uninstalled-manual.names" ]]
    fi
    count_wrapper="$EXPORT_DIR/count-command.sh"
    cat > "$count_wrapper" <<'COUNT'
#!/bin/bash
set -euo pipefail
case "$1" in
    omg) exec "$2" ec ;;
    arch) pacman -Qqe | wc -l ;;
    debian|ubuntu) apt-mark showmanual | wc -l ;;
    fedora) dnf -C repoquery --userinstalled --qf '%{name}\n' | wc -l ;;
    *) exit 2 ;;
esac
COUNT
    count_expected=$(wc -l < "$EXPORT_DIR/explicit-omg-before.names")
    capture_counts() {
        local phase=$1
        "$BASH" "$count_wrapper" omg "$OMG" > "$EXPORT_DIR/count-omg-$phase.stdout" 2> "$EXPORT_DIR/count-omg-$phase.stderr"
        "$BASH" "$count_wrapper" "$distro" > "$EXPORT_DIR/count-native-$phase.stdout" 2> "$EXPORT_DIR/count-native-$phase.stderr"
        for output in "$EXPORT_DIR/count-omg-$phase.stdout" "$EXPORT_DIR/count-native-$phase.stdout"; do
            awk -v expected="$count_expected" '
              NF != 1 || $1 !~ /^[0-9]+$/ || $1 != expected {exit 1}
              END {if (NR != 1) exit 1}' "$output"
        done
    }
    capture_counts before
    printf -v count_omg_command '%q ' "$BASH" "$count_wrapper" omg "$OMG"
    printf -v count_native_command '%q ' "$BASH" "$count_wrapper" "$distro"
    {
        command_json OMG "$BASH" "$count_wrapper" omg "$OMG"
        command_json "$explicit_name" "$BASH" "$count_wrapper" "$distro"
    } | jq -s . > "$EXPORT_DIR/explicit.commands.json"
    run_hyperfine "$EXPORT_DIR/explicit.json" "$EXPORT_DIR/explicit.md" \
        --command-name OMG "$count_omg_command" --command-name "$explicit_name" "$count_native_command"
    capture_counts after
    capture_explicit after
    cmp "$EXPORT_DIR/explicit-omg-before.names" "$EXPORT_DIR/explicit-omg-after.names"
    cmp "$EXPORT_DIR/explicit-native-before.names" "$EXPORT_DIR/explicit-native-after.names"
    jq -n --arg distro "$distro" --argjson search_equivalent "$search_equivalent" \
        --slurpfile info "$EXPORT_DIR/info.commands.json" \
        --slurpfile search "$EXPORT_DIR/search.commands.json" \
        --slurpfile explicit "$EXPORT_DIR/explicit.commands.json" \
        --argjson warmup "$WARMUP" --argjson minimum "$MIN_RUNS" --argjson maximum "$MAX_RUNS" \
        '{schema_version:2, complete:true, distro:$distro,
          operations:["info","search","explicit"], daemon:"disabled",
          cache:"warm after preflight and warmups", warmup:$warmup, min_runs:$minimum, max_runs:$maximum,
          comparisons:{info:{equivalent:true, scope:"freshly installed tree identity/version; extra fields differ"},
            search:{equivalent:$search_equivalent, scope:"ripgrep package-name sets, official repositories, no truncation"},
            explicit:{equivalent:true, scope:"installed manual package-name sets and counts; common Bash wrapper"}},
          commands:{info:$info[0],search:$search[0],explicit:$explicit[0]}}' > "$EXPORT_DIR/summary.json"
    exit 0
fi
if [ ! -x "$OMGD" ]; then
    echo -e "${RED}❌ omgd binary not found next to omg: $OMGD${NC}" >&2
    exit 1
fi

# ----------------------------------------------------------------------------
# AUR update discovery benchmark (--update)
#
# Benchmarks `omg update` update discovery against an isolated cache in two
# otherwise-identical variants:
#   (a) ready:    coherent, fresh AUR archive + binary index
#   (b) missing:  same archive but NO index (removed before every run via
#                 hyperfine --prepare), forcing the AUR RPC fallback path
#
# Deterministic regression guard: after the benchmark, variant (b) must NOT
# have created an index — update discovery must never synchronously rebuild
# global metadata. A statistical guard also fails only on a broad regression
# (missing-index mean > 3s AND > 5x ready-index mean), so small network
# variance does not make the benchmark flaky.
# ============================================================================
run_update_benchmark() {
    if [ "$EUID" -eq 0 ]; then
        echo -e "${RED}❌ Run the update benchmark as a regular user${NC}" >&2
        return 1
    fi

    local source_cache="$BENCH_SOURCE_CACHE"
    local fixture_archive="$source_cache/aur/_meta/packages-meta-ext-v1.json.gz"
    local fixture_index="$source_cache/aur/_meta/packages-meta-ext-v1.rkyv"
    local fixture_local_db="$source_cache/local_db_rdeps.bin"
    if [ ! -f "$fixture_local_db" ] && [ -f "$source_cache/local_db.bin" ]; then
        fixture_local_db="$source_cache/local_db.bin"
    fi
    local fixture_sync_db="$source_cache/sync_db.bin"

    local missing_fixture=0
    local fixture
    for fixture in "$fixture_local_db" "$fixture_sync_db" "$fixture_archive" "$fixture_index"; do
        if [ ! -f "$fixture" ]; then
            echo -e "${RED}❌ Missing benchmark fixture: $fixture${NC}" >&2
            missing_fixture=1
        fi
    done
    if [ "$missing_fixture" -ne 0 ]; then
        echo "" >&2
        echo "Update discovery benchmarks need a populated omg cache with:" >&2
        echo "  local_db_rdeps.bin (or legacy local_db.bin), sync_db.bin," >&2
        echo "  aur/_meta/packages-meta-ext-v1.rkyv" >&2
        echo "Populate the OMG metadata cache first, or set OMG_BENCH_SOURCE_CACHE." >&2
        return 1
    fi

    # Isolated scratch space under $HOME/.cache/build-targets (never /tmp),
    # removed on exit via trap.
    mkdir -p "$HOME/.cache/build-targets"
    local work_dir
    work_dir="$(mktemp -d "$HOME/.cache/build-targets/omg-update-bench-XXXXXX")"
    UPDATE_WORK_DIRS+=("$work_dir")

    local ready_cache="$work_dir/ready-cache"
    local missing_cache="$work_dir/missing-index-cache"
    local config_dir="$work_dir/config"
    mkdir -p "$ready_cache/aur/_meta" "$missing_cache/aur/_meta" "$config_dir"

    # (a) Ready cache: copy the archive BEFORE the index so the published
    # generation is coherent (index mtime >= archive mtime) and fresh
    # (archive mtime within the metadata TTL).
    cp "$fixture_archive" "$ready_cache/aur/_meta/"
    cp "$fixture_index" "$ready_cache/aur/_meta/"
    cp "$fixture_local_db" "$fixture_sync_db" "$ready_cache/"

    # (b) Same fixtures but no index; hyperfine --prepare re-removes it
    # before every run.
    cp "$fixture_archive" "$missing_cache/aur/_meta/"
    cp "$fixture_local_db" "$fixture_sync_db" "$missing_cache/"

    # Keep the benchmark hermetic: never talk to a live daemon.
    export OMG_SOCKET_PATH="$work_dir/unused-omg.sock"
    export OMG_DAEMON_DATA_DIR="$work_dir/data"

    # Wrapper around the REAL 'omg update' (no --yes). Unprivileged and
    # non-interactive, it completes update discovery, then either reports
    # "up to date" (exit 0) or bails with "Use --yes for non-interactive
    # updates" (exit 1). The wrapper accepts only those outcomes and only
    # when the output proves discovery finished; network or parse errors
    # propagate as failures so hyperfine fails the benchmark.
    local wrapper="$work_dir/omg-update-wrapper.sh"
    cat > "$wrapper" << 'WRAPPER'
#!/bin/bash
set -e
omg_bin="$1"
log="$(mktemp "${TMPDIR:?}/omg-update-log-XXXXXX")"
rc=0
"$omg_bin" update >"$log" 2>&1 || rc=$?
# "update available" (singular) covers the 1-update summary line.
if grep -q -e "updates available" -e "update available" -e "up to date" "$log" \
    && ! grep -q -e "AUR update check failed" -e "Failed to check AUR updates" "$log" \
    && { [ "$rc" -eq 0 ] || [ "$rc" -eq 1 ]; }; then
    rm -f "$log"
    exit 0
fi
echo "omg update discovery failed (exit $rc):" >&2
cat "$log" >&2
rm -f "$log"
exit 1
WRAPPER
    chmod +x "$wrapper"

    local missing_index="$missing_cache/aur/_meta/packages-meta-ext-v1.rkyv"

    echo "========================================================"
    echo -e "${GREEN}🚀 OMG Update Discovery Benchmark${NC}"
    echo "========================================================"
    echo ""
    echo -e "${YELLOW}CONFIGURATION:${NC}"
    echo "  Binary: $OMG"
    echo "  Warmup runs: $WARMUP"
    echo "  Minimum runs: $MIN_RUNS"
    echo "  Ready cache: $ready_cache"
    echo "  Missing-index cache: $missing_cache"
    echo "  Results: $EXPORT_DIR/update.md, $EXPORT_DIR/update.json"
    echo ""

    # NOTE: hyperfine --prepare applies to every run of every command; the
    # rm targets only the missing-index cache, so it is a no-op for the
    # ready-index command.
    hyperfine --warmup "$WARMUP" --min-runs "$MIN_RUNS" \
        --prepare "rm -f '$missing_index'" \
        --command-name "update discovery (ready index)" \
            "TMPDIR='$work_dir' OMG_CACHE_DIR='$ready_cache' OMG_CONFIG_DIR='$config_dir' '$wrapper' '$OMG'" \
        --command-name "update discovery (missing index)" \
            "TMPDIR='$work_dir' OMG_CACHE_DIR='$missing_cache' OMG_CONFIG_DIR='$config_dir' '$wrapper' '$OMG'" \
        --export-markdown "$EXPORT_DIR/update.md" \
        --export-json "$EXPORT_DIR/update.json"

    # Deterministic regression guard: the missing-index scenario must not
    # have rebuilt global metadata (i.e. created an AUR index).
    if [ -f "$missing_index" ]; then
        echo -e "${RED}❌ REGRESSION: missing-index update discovery created an AUR index at:${NC}" >&2
        echo "  $missing_index" >&2
        echo "Update discovery must not synchronously rebuild global metadata." >&2
        return 1
    fi
    echo -e "${GREEN}✅ Guard passed: missing-index run did not rebuild the AUR index${NC}"

    # Statistical guard: fail only on a broad regression so ordinary network
    # variance between the two scenarios stays non-fatal.
    python3 - "$EXPORT_DIR/update.json" << 'PYEOF'
import json
import sys

with open(sys.argv[1]) as handle:
    data = json.load(handle)

results = data.get("results", [])
ready = next((r for r in results if "ready index" in r["command"]), None)
missing = next((r for r in results if "missing index" in r["command"]), None)
if ready is None or missing is None:
    print("❌ update.json is missing the expected benchmark scenarios", file=sys.stderr)
    sys.exit(1)

ready_mean = ready["mean"]
missing_mean = missing["mean"]
limit = max(3.0, 5.0 * ready_mean)
print(f"Ready-index mean:   {ready_mean:.3f} s")
print(f"Missing-index mean: {missing_mean:.3f} s")
print(f"Regression limit:   {limit:.3f} s  (max(3 s, 5 x ready-index mean))")

if missing_mean > 3.0 and missing_mean > 5.0 * ready_mean:
    print(
        "❌ REGRESSION: missing-index update discovery mean exceeds both 3 s "
        "and 5x the ready-index mean",
        file=sys.stderr,
    )
    sys.exit(1)
print("✅ No broad update-discovery regression")
PYEOF

    echo ""
    echo -e "${GREEN}✅ Update discovery benchmark complete${NC}"
    echo "Results saved to: $EXPORT_DIR/update.md, $EXPORT_DIR/update.json"
}

if [ "$UPDATE_MODE" = true ]; then
    run_update_benchmark
    archive_results
    exit 0
fi

echo "========================================================"
echo -e "${GREEN}🚀 OMG Hyperfine Performance Benchmark${NC}"
echo "========================================================"
echo ""
if [ "$FAST_MODE" = true ]; then
    echo -e "${YELLOW}⚡ FAST MODE ENABLED${NC}"
fi
echo -e "${YELLOW}CONFIGURATION:${NC}"
echo "  Warmup runs: $WARMUP"
echo "  Minimum runs: $MIN_RUNS"
echo "  Maximum runs: $MAX_RUNS"
echo "  Scratch directory: $EXPORT_DIR/"
echo "  Records: benchmarks/records/"
echo ""
echo -e "${YELLOW}METHODOLOGY:${NC}"
echo "  • hyperfine --shell=none (no shell startup in the timed path)"
echo "  • --output=pipe so tools cannot skip work when stdout is /dev/null"
echo "  • Preflight: each command must print real results before timing starts"
echo "  • Warm cache (typical interactive use, not first-boot)"
echo ""

mkdir -p "$HOME/.cache/build-targets"
BENCH_DIR="$(mktemp -d "$HOME/.cache/build-targets/omg-bench-XXXXXX")"
export OMG_DAEMON_DATA_DIR="$BENCH_DIR/data"
export OMG_SOCKET_PATH="$BENCH_DIR/omg.sock"
export OMG_CACHE_DIR="$BENCH_DIR/cache"
DAEMON_LOG="$BENCH_DIR/omgd.log"
mkdir -p "$OMG_DAEMON_DATA_DIR" "$OMG_CACHE_DIR"

source_cache="${OMG_BENCH_SOURCE_CACHE:-${HOME}/.cache/omg}"
if [ -f "$source_cache/sync_db.bin" ]; then
    cp "$source_cache/sync_db.bin" "$OMG_CACHE_DIR/"
    if [ -f "$source_cache/local_db_rdeps.bin" ]; then
        cp "$source_cache/local_db_rdeps.bin" "$OMG_CACHE_DIR/"
    elif [ -f "$source_cache/local_db.bin" ]; then
        cp "$source_cache/local_db.bin" "$OMG_CACHE_DIR/"
    fi
    echo -e "${BLUE}📦 Seeded daemon cache from $source_cache${NC}"
fi

echo "Starting OMG Daemon..."
"$OMGD" > "$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!

echo -n "Waiting for daemon to be ready..."
daemon_ready=0
for _ in $(seq 1 80); do
    if "$OMG" status > /dev/null 2>&1; then
        daemon_ready=1
        echo " status ok"
        break
    fi
    sleep 0.1
done
if [ "$daemon_ready" -ne 1 ]; then
    echo -e "${RED}❌ OMG daemon failed to start${NC}" >&2
    tail -n 50 "$DAEMON_LOG" >&2 || true
    exit 1
fi

echo -n "Waiting for search index (firefox)..."
search_ready=0
for _ in $(seq 1 100); do
    if "$OMG" search firefox --no-aur 2>/dev/null | grep -qi firefox; then
        search_ready=1
        echo " ready"
        break
    fi
    sleep 0.1
done
if [ "$search_ready" -ne 1 ]; then
    echo -e "${RED}❌ Daemon never returned a firefox search hit${NC}" >&2
    tail -n 50 "$DAEMON_LOG" >&2 || true
    exit 1
fi

echo -e "\n${BLUE}🔎 Preflight (prove the timed commands do real work)${NC}"
PRE_DIR="$BENCH_DIR/preflight"
mkdir -p "$PRE_DIR"
preflight_match "omg search firefox --no-aur" "firefox" "$PRE_DIR/search.txt" \
    "$OMG" search firefox --no-aur
preflight_match "omg info firefox" "firefox" "$PRE_DIR/info.txt" \
    "$OMG" info firefox
preflight_match "omg status" "." "$PRE_DIR/status.txt" "$OMG" status
if ! "$OMG" ec >"$PRE_DIR/explicit.txt" 2>&1; then
    echo -e "${RED}❌ Preflight failed: omg ec${NC}" >&2
    cat "$PRE_DIR/explicit.txt" >&2
    exit 1
fi
EXPLICIT_COUNT="$(tr -d '[:space:]' < "$PRE_DIR/explicit.txt")"
if ! [[ "$EXPLICIT_COUNT" =~ ^[0-9]+$ ]] || [ "$EXPLICIT_COUNT" -le 0 ]; then
    echo -e "${RED}❌ Preflight failed: explicit count was '${EXPLICIT_COUNT}'${NC}" >&2
    exit 1
fi
echo -e "  ${GREEN}ok${NC} omg ec = ${EXPLICIT_COUNT}"
if command -v pacman >/dev/null 2>&1; then
    preflight_match "pacman -Ss firefox" "firefox" "$PRE_DIR/pacman-search.txt" \
        pacman -Ss firefox
    preflight_match "pacman -Si firefox" "firefox" "$PRE_DIR/pacman-info.txt" \
        pacman -Si firefox
fi
if command -v yay >/dev/null 2>&1; then
    preflight_match "yay -Ss --repo firefox" "firefox" "$PRE_DIR/yay-search.txt" \
        yay -Ss --repo firefox
fi

python3 - "$EXPORT_DIR/preflight.json" "$PRE_DIR" "$EXPLICIT_COUNT" << 'PY'
import json, sys
from pathlib import Path
out, pre_dir, count = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
evidence = {"explicit_count": int(count)}
for path in sorted(pre_dir.glob("*.txt")):
    text = path.read_text(errors="replace")
    evidence[path.stem] = {"bytes": len(text.encode()), "lines": text.count("\n")}
out.write_text(json.dumps(evidence, indent=2) + "\n")
PY

cat > "$BENCH_DIR/pacman-explicit-count" << 'EOF'
#!/bin/bash
set -euo pipefail
pacman -Qe | wc -l
EOF
cat > "$BENCH_DIR/yay-explicit-count" << 'EOF'
#!/bin/bash
set -euo pipefail
yay -Qe | wc -l
EOF
chmod +x "$BENCH_DIR/pacman-explicit-count" "$BENCH_DIR/yay-explicit-count"

echo -e "\n${BLUE}📦 Benchmark: SEARCH (firefox)${NC}"
echo "-------------------------------"
search_cmds=(--command-name "OMG" "$OMG search firefox --no-aur")
if command -v pacman >/dev/null 2>&1; then
    search_cmds+=(--command-name "pacman" "pacman -Ss firefox")
fi
if command -v yay >/dev/null 2>&1; then
    search_cmds+=(--command-name "yay (--repo)" "yay -Ss --repo firefox")
fi
run_hyperfine "$EXPORT_DIR/search.json" "$EXPORT_DIR/search.md" "${search_cmds[@]}"

echo -e "\n${BLUE}ℹ️  Benchmark: INFO (firefox)${NC}"
echo "-------------------------------"
info_cmds=(--command-name "OMG" "$OMG info firefox")
if command -v pacman >/dev/null 2>&1; then
    info_cmds+=(--command-name "pacman" "pacman -Si firefox")
fi
if command -v yay >/dev/null 2>&1; then
    info_cmds+=(--command-name "yay (--repo)" "yay -Si --repo firefox")
fi
run_hyperfine "$EXPORT_DIR/info.json" "$EXPORT_DIR/info.md" "${info_cmds[@]}"

echo -e "\n${BLUE}⚡ Benchmark: STATUS${NC}"
echo "-------------------------------"
status_cmds=(--command-name "OMG" "$OMG status")
run_hyperfine "$EXPORT_DIR/status.json" "$EXPORT_DIR/status.md" "${status_cmds[@]}"

echo -e "\n${BLUE}📋 Benchmark: EXPLICIT COUNT${NC}"
echo "-------------------------------"
explicit_cmds=(--command-name "OMG" "$OMG ec")
if command -v pacman >/dev/null 2>&1; then
    explicit_cmds+=(--command-name "pacman" "$BENCH_DIR/pacman-explicit-count")
fi
if command -v yay >/dev/null 2>&1; then
    explicit_cmds+=(--command-name "yay" "$BENCH_DIR/yay-explicit-count")
fi
run_hyperfine "$EXPORT_DIR/explicit.json" "$EXPORT_DIR/explicit.md" "${explicit_cmds[@]}"

if [ "$FAST_MODE" != true ] && [ "${OMG_BENCH_SKIP_UPDATE:-}" != 1 ]; then
    echo -e "\n${BLUE}🔄 Benchmark: UPDATE DISCOVERY${NC}"
    echo "-------------------------------"
    run_update_benchmark
fi

echo ""
echo "========================================================"
echo -e "${GREEN}✅ Benchmarks Complete!${NC}"
echo "========================================================"
echo ""
echo "Scratch JSON/MD: $EXPORT_DIR/"
echo ""
echo -e "${YELLOW}Summary:${NC}"
echo ""

for md_file in "$EXPORT_DIR"/*.md; do
    if [ -f "$md_file" ]; then
        echo "$(basename "$md_file" .md):"
        cat "$md_file"
        echo ""
    fi
done

archive_results
