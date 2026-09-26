#!/usr/bin/env bash
set -euo pipefail

distro=all
tag=v0.1.223
staged_dir=
release_dir=
inventory_file=
inventory_policy=
image_policy=
image_cache=
arch=
print_pins=false
benchmark=false
transaction_samples=0
inventory_tiers=
inventory_mutations=false
inventory_isolation=false
storage_faults=false
restrict_egress=false
allow_tcg=false
report_inventory='[]'
inventory_product_failure=false
root="$HOME/.cache/build-targets/omg-qemu-benchmark"
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
while (($#)); do
  case "$1" in
    --distro|--release|--staged-dir|--release-dir|--inventory-file|--inventory-policy|--image-policy|--image-cache|--evidence-dir|--inventory-tiers|--arch)
      [[ $# -ge 2 && -n "$2" ]] || exit 2
      case "$1" in
        --distro) distro=$2 ;; --release) tag=$2 ;; --staged-dir) staged_dir=$2 ;; --evidence-dir) root=$2 ;;
        --release-dir) release_dir=$2 ;; --inventory-file) inventory_file=$2 ;;
        --inventory-policy) inventory_policy=$2 ;;
        --image-policy) image_policy=$2 ;;
        --image-cache) image_cache=$2 ;;
        --inventory-tiers) inventory_tiers=$2 ;; --arch) arch=$2 ;;
      esac
      shift 2 ;;
    --benchmark) benchmark=true; shift ;;
    --benchmark-transactions)
      [[ $# -ge 2 && "$2" =~ ^([1-9]|[1-9][0-9]|100)$ ]] || exit 2
      benchmark=true; transaction_samples=$2; shift 2 ;;
    --print-pins) print_pins=true; shift ;;
    --inventory-allow-mutations) inventory_mutations=true; shift ;;
    --inventory-isolate-hermetic) inventory_isolation=true; shift ;;
    --storage-faults) storage_faults=true; shift ;;
    --restrict-egress) restrict_egress=true; shift ;;
    --allow-tcg) allow_tcg=true; shift ;;
    --help)
      cat <<'HELP'
Usage: scripts/benchmark-qemu.sh [--distro all|arch|debian|ubuntu|fedora]
  [--arch x86_64|aarch64] [--release vVERSION]
  [--staged-dir DIR | --release-dir DIR] [--inventory-file TSV]
  [--evidence-dir DIR] [--benchmark] [--benchmark-transactions COUNT]
  [--print-pins] [--inventory-tiers CSV] [--inventory-allow-mutations]
  [--inventory-policy JSON]
  [--image-policy JSON] [--image-cache DIR]
  [--inventory-isolate-hermetic]
  [--allow-tcg]

Runs disposable guests with pinned images, reboot, sudo, package lifecycle,
and optional warm read-query timing. KVM with matching host/guest architecture
is required by default. --allow-tcg explicitly enables a slower local
correctness audit, including cross-architecture ARM emulation. TCG timing is
not valid benchmark evidence. --print-pins lists images without booting guests.

--staged-dir uses locally built archives and the current source inventory.
--release-dir uses downloaded published archives without a GitHub token in the
harness. Published --inventory-tiers requires --inventory-file from the release
revision. Prepare both with scripts/prepare-qemu-release.py:
  python3 scripts/prepare-qemu-release.py --tag vVERSION --distro arch --destination published
  scripts/benchmark-qemu.sh --distro arch --release vVERSION --release-dir published --inventory-file published/cases.tsv --inventory-tiers hermetic,container

Inventory rows run over SSH after a passing lifecycle (scripts/qemu-inventory.sh).
CI requires --inventory-policy to pin the selection and permitted skips.
--benchmark-transactions COUNT runs independently reset install/remove trials
(1-100 per tool). Requires Docker, KVM, jq, and coreutils. Direct published
downloads need gh; release preparation and benchmarks need Python 3.
No compilation or host package changes. ARM still requires staged ARM binaries.
HELP
      exit 0 ;;
    *) printf 'error: unknown argument %s\n' "$1" >&2; exit 2 ;;
  esac
done
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 2
case "$distro" in all|arch|debian|ubuntu|fedora) ;; *) exit 2 ;; esac
if [[ -z "$arch" ]]; then
  case "$(uname -m)" in
    x86_64|amd64) arch=x86_64 ;;
    aarch64|arm64) arch=aarch64 ;;
    *) printf 'error: host architecture %s is not a QEMU guest architecture\n' "$(uname -m)" >&2; exit 2 ;;
  esac
fi
case "$arch" in x86_64|amd64) arch=x86_64 ;; aarch64|arm64) arch=aarch64 ;; *) exit 2 ;; esac
[[ -z "$staged_dir" || -d "$staged_dir" ]] || exit 2
[[ -z "$release_dir" || ( -d "$release_dir" && -z "$staged_dir" ) ]] || exit 2
tsv="${inventory_file:-$here/../tests/cli_behavior_inventory.tsv}"
if [[ -n "$inventory_tiers" && -z "$staged_dir" && -z "$inventory_file" ]]; then
  printf 'error: published inventory needs --inventory-file from the release revision (scripts/prepare-qemu-release.py)\n' >&2
  exit 2
fi
if [[ -n "$inventory_tiers" && ! -f "$tsv" ]]; then
  printf 'error: --inventory-tiers needs %s\n' "$tsv" >&2
  exit 2
fi
if [[ -n "$inventory_tiers" ]]; then
  [[ "$inventory_tiers" =~ ^[a-z,-]+$ ]] || exit 2
  [[ "$inventory_tiers" != ,* && "$inventory_tiers" != *, && "$inventory_tiers" != *,,* ]] || exit 2
  IFS=',' read -ra selected_tiers <<< "$inventory_tiers"
  for tier in "${selected_tiers[@]}"; do
    case "$tier" in hermetic|container|qemu|network|credentialed|pty|nested-container) ;; *) exit 2 ;; esac
  done
fi
command -v jq >/dev/null || exit 3
source_kind=published
[[ -z "$staged_dir" ]] || source_kind=staged
mkdir -p "$root"
root=$(cd "$root" && pwd)
controller_image_x86_64=debian:trixie@sha256:6788062a1b42ac281f053ac876170b79a3eaed5d61383b8ed7eaca6c6965f3b1
controller_image_aarch64=debian:trixie@sha256:0aa0908407cce3da2a90c1d80acc6ca5ca57401ed63eecfa8149b7ba3cc40829
controller_image_tcg=debian:sid@sha256:a2aa46262453eba3f464d8b1c7a8c31db85eb15af180ae34dd400615d7208547
# Pinned guest images per distro+arch. Hashes are verified against the
# publisher checksum files (Debian SHA512SUMS, Ubuntu SHA256SUMS, Fedora
# CHECKSUM, Arch .SHA256 sidecar). Arch publishes x86_64 cloud images
# only, so arch+aarch64 fails closed in pins_for.
pins_for() {
  local pin_distro=$1 pin_arch=$2
  hash_tool=sha256sum
  firmware=bios
  ssh_service=sshd
  qemu_bin=qemu-system-x86_64
  qemu_machine=q35
  qemu_pkg=qemu-system-x86
  firmware_pkg=ovmf
  firmware_code=/usr/share/OVMF/OVMF_CODE_4M.fd
  firmware_vars_src=/usr/share/OVMF/OVMF_VARS_4M.fd
  guest_uname=x86_64
  controller_image=$controller_image_x86_64
  case "$pin_distro-$pin_arch" in
    arch-x86_64)
      image_url=https://geo.mirror.pkgbuild.com/images/v20260901.583572/Arch-Linux-x86_64-cloudimg-20260901.583572.qcow2
      image_hash=e3e688f97a71b265ce202905a504253f60f3680cf57d011a45411c43bedfa930
      firmware=uefi ;;
    arch-aarch64)
      printf 'error: no aarch64 cloud image pinned for arch (upstream publishes x86_64 only)\n' >&2
      return 1 ;;
    debian-x86_64)
      image_url=https://cloud.debian.org/images/cloud/bookworm/20260903-2590/debian-12-generic-amd64-20260903-2590.qcow2
      image_hash=804377dd07318360c39a75e57b326243442a43bae1e12b33d5f490a64713c15c080a0323cb55d52b381139db9187702d38f36b8b142b8ef36da1031d9de41c2d
      hash_tool=sha512sum
      ssh_service=ssh ;;
    debian-aarch64)
      image_url=https://cloud.debian.org/images/cloud/bookworm/20260903-2590/debian-12-generic-arm64-20260903-2590.qcow2
      image_hash=b0144c1c8e09b187b54af300c8ffc22f17b318d0aa6f5a2caba13f3102441572badbeb098458e599b6897bc80dad50fd0094d6e4b9da9f4a2bd63a8f4c99dea5
      hash_tool=sha512sum
      ssh_service=ssh ;;
    ubuntu-x86_64)
      image_url=https://cloud-images.ubuntu.com/noble/20260826/noble-server-cloudimg-amd64.img
      image_hash=d0fe84bb5f80853425fa6be28e2c106f30104c3cfe8611933f2e65c9b63f0e30
      ssh_service=ssh ;;
    ubuntu-aarch64)
      image_url=https://cloud-images.ubuntu.com/noble/20260826/noble-server-cloudimg-arm64.img
      image_hash=afa139bac6f2629c1e1f2f8f34215f3a9ad9779801bcb945521ba1a45016743f
      ssh_service=ssh ;;
    fedora-x86_64)
      image_url=https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2
      image_hash=28680fe5b371a5a82ebf43a31926e086a168e59949d03969c5093e7071f90b7f ;;
    fedora-aarch64)
      image_url=https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/aarch64/images/Fedora-Cloud-Base-Generic-44-1.7.aarch64.qcow2
      image_hash=55c60a3b80d3616a08705afd0459e75fe9f03c54aba7a46e4002a41a72fa0d5b ;;
    *) printf 'error: unknown distro/arch %s/%s\n' "$pin_distro" "$pin_arch" >&2; return 1 ;;
  esac
  if [[ "$pin_arch" == aarch64 ]]; then
    # ARM cloud images boot UEFI only; the virt machine needs AAVMF firmware
    # and the ARM system emulator in the controller. The controller image
    # is pinned by arm64 per-arch digest (not the x86_64-era list digest),
    # so the pull is arch-correct by construction on arm64 runners.
    firmware=uefi
    qemu_bin=qemu-system-aarch64
    qemu_machine=virt
    qemu_pkg=qemu-system-arm
    firmware_pkg=qemu-efi-aarch64
    firmware_code=/usr/share/AAVMF/AAVMF_CODE.fd
    firmware_vars_src=/usr/share/AAVMF/AAVMF_VARS.fd
    guest_uname=aarch64
    controller_image=$controller_image_aarch64
  fi
}

# Lifecycle case ids carry the arch only for aarch64: x86_64 keeps the
# legacy qemu-<distro>-lifecycle id so existing evidence and [qa] issue
# fingerprints stay stable.
case_suffix=""
[[ "$arch" == aarch64 ]] && case_suffix="-aarch64"

if [[ "$print_pins" == true ]]; then
  # Audit mode: list every pinned image without booting anything.
  # Honors --distro; always covers both arches so pin reviews see the
  # whole table (unsupported combos like arch/aarch64 print nothing).
  for pin_distro in arch debian ubuntu fedora; do
    [[ "$distro" == all || "$distro" == "$pin_distro" ]] || continue
    for pin_arch in x86_64 aarch64; do
      if pins_for "$pin_distro" "$pin_arch" 2>/dev/null; then
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$pin_distro" "$pin_arch" "$image_url" "$image_hash" "$hash_tool" "$firmware"
      fi
    done
  done
  exit 0
fi
if [[ "$distro" == all ]]; then
  suite=$(mktemp -d "$root/suite-XXXXXX")
  rc=0
  args=(--release "$tag" --arch "$arch")
  [[ -z "$staged_dir" ]] || args+=(--staged-dir "$staged_dir")
  [[ -z "$release_dir" ]] || args+=(--release-dir "$release_dir")
  [[ -z "$inventory_file" ]] || args+=(--inventory-file "$inventory_file")
  [[ -z "$inventory_policy" ]] || args+=(--inventory-policy "$inventory_policy")
  [[ -z "$image_policy" ]] || args+=(--image-policy "$image_policy")
  [[ -z "$image_cache" ]] || args+=(--image-cache "$image_cache")
  [[ "$benchmark" == false ]] || args+=(--benchmark)
  [[ "$transaction_samples" == 0 ]] || args+=(--benchmark-transactions "$transaction_samples")
  [[ -z "$inventory_tiers" ]] || args+=(--inventory-tiers "$inventory_tiers")
  [[ "$inventory_mutations" == false ]] || args+=(--inventory-allow-mutations)
  [[ "$inventory_isolation" == false ]] || args+=(--inventory-isolate-hermetic)
  [[ "$storage_faults" == false ]] || args+=(--storage-faults)
  [[ "$restrict_egress" == false ]] || args+=(--restrict-egress)
  [[ "$allow_tcg" == false ]] || args+=(--allow-tcg)
  jq -n --arg source "$source_kind" --arg suffix "$case_suffix" '["arch", "debian", "ubuntu", "fedora"] | map({case_id:("qemu-"+.+$suffix+"-lifecycle"), distro:., result:"NOT_RUN", artifact_source:$source, exit_code:null, elapsed_seconds:0})' > "$suite/results.json"
  for target in arch debian ubuntu fedora; do
    jq --arg target "$target" 'map(if .distro == $target then .result = "INCOMPLETE" else . end)' "$suite/results.json" > "$suite/results.next.json"
    mv "$suite/results.next.json" "$suite/results.json"
    "$0" --distro "$target" --evidence-dir "$suite/$target" "${args[@]}" || rc=1
    reports=("$suite/$target"/run-*/results.json)
    if [[ ${#reports[@]} -eq 1 && -f "${reports[0]}" ]] && jq -e --arg target "$target" --arg suffix "$case_suffix" 'length == 1 and .[0].distro == $target and .[0].case_id == ("qemu-"+$target+$suffix+"-lifecycle")' "${reports[0]}" >/dev/null; then
      jq --arg target "$target" --slurpfile report "${reports[0]}" 'map(if .distro == $target then $report[0][0] else . end)' "$suite/results.json" > "$suite/results.next.json"
      mv "$suite/results.next.json" "$suite/results.json"
    else rc=1; fi
  done
  printf 'Suite evidence: %s\n' "$suite"
  exit "$rc"
fi
case_id="qemu-${distro}${case_suffix}-lifecycle"
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d "$root/run-XXXXXX")
controller="omg-qemu-${work##*/}"
printf 'Starting %s (%s). Evidence: %s\n' "$distro" "$arch" "$work"
result=HARNESS_ERROR
cleanup() {
  local rc=$? remaining safe_to_remove=true report_rc overall_result
  trap - EXIT
  if [[ ${started:-false} == true ]]; then
    safe_to_remove=false
    # Preserve controller state before forced cleanup destroys the OOM/exit evidence.
    timeout 15 docker inspect --format '{{json .State}}' "$controller" > "$work/controller-final-state.json" 2>> "$work/cleanup.log" || { rc=3; result=HARNESS_ERROR; }
    timeout --kill-after=5s 60s docker rm --force "$controller" >> "$work/cleanup.log" 2>&1 || { rc=3; result=HARNESS_ERROR; }
    if remaining=$(timeout 15 docker ps -aq --filter "name=^/${controller}$") && [[ -z "$remaining" ]]; then
      printf 'verified absent: %s\n' "$controller" >> "$work/cleanup.log"
      safe_to_remove=true
    else rc=3; result=HARNESS_ERROR; fi
  fi
  if [[ "$safe_to_remove" == true ]]; then
  if [[ ${egress_started:-false} == true ]]; then
    timeout 60 sudo -n python3 "$here/qemu-controller-egress.py" remove "$controller" >> "$work/cleanup.log" 2>&1 || { rc=3; result=HARNESS_ERROR; }
  fi
  # Only the stopped controller's owned disposable disks live here, not evidence.
  rm -rf "$work/guest/transaction-disks" || { rc=3; result=HARNESS_ERROR; }
  [[ ! -e "$work/guest/transaction-disks" ]] || { rc=3; result=HARNESS_ERROR; }
  rm -f "$work/guest"/{client-key,guest-host-key,user-data,seed.img,overlay.qcow2,base.qcow2,vars.fd,qemu.pid} || { rc=3; result=HARNESS_ERROR; }
  for file in client-key guest-host-key user-data seed.img overlay.qcow2 base.qcow2 vars.fd qemu.pid; do
    if [[ -e "$work/guest/$file" ]]; then rc=3; result=HARNESS_ERROR; fi
  done
  else
    printf 'Controller absence unverified; preserving guest disks and keys\n' >> "$work/cleanup.log"
  fi
  if [[ "$rc" -ne 0 && "$result" == PASS && ! ( "$inventory_product_failure" == true && "$rc" == 1 ) ]]; then result=HARNESS_ERROR; fi
  # The process represents the whole suite; this row represents the lifecycle.
  # Inventory failures have their own rows and must not manufacture a second bug.
  report_rc=$rc
  [[ "$result" != PASS ]] || report_rc=0
  jq -n --arg distro "$distro" --arg case_id "$case_id" --arg result "$result" --arg source "$source_kind" --argjson rc "$report_rc" --argjson elapsed "$SECONDS" \
    '[{case_id:$case_id,distro:$distro,result:$result,artifact_source:$source,exit_code:$rc,elapsed_seconds:$elapsed}]' > "$work/results.json"
  report_input="$work/results.json"
  if jq --argjson inventory "$report_inventory" '. + $inventory' "$work/results.json" > "$work/sentry-results.json"; then
    report_input="$work/sentry-results.json"
  else
    printf 'Inventory telemetry projection failed; reporting lifecycle result only\n' >> "$work/cleanup.log"
  fi
  reporting_rc=0
  timeout --kill-after=2s 12s env OMG_SMOKE_RELEASE="$tag" OMG_SMOKE_ENVIRONMENT=qemu-matrix "$repo_root/scripts/report-smoke-sentry.sh" "$report_input" > "$work/reporting.log" 2>&1 || reporting_rc=$?
  jq -n --argjson exit_code "$reporting_rc" '{exit_code:$exit_code}' > "$work/reporting-status.json"
  overall_result=$result
  if [[ "$result" == PASS && "$inventory_product_failure" == true ]]; then
    overall_result=PRODUCT_FAIL
  fi
  printf '%s lifecycle=%s overall=%s. Evidence: %s\n' "$distro" "$result" "$overall_result" "$work"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -p "$work/release" "$work/guest"
: > "$work/guest/serial.log"
# Preflight probes. Each fails closed to HARNESS_ERROR (exit 3 lands in
# the EXIT trap, which records the result). TCG is only selected by the
# explicit --allow-tcg local-audit option; CI and default runs stay on KVM.
pins_for "$distro" "$arch" || exit 3
kvm_device="${OMG_QEMU_KVM_DEVICE:-/dev/kvm}"
host_arch=x86_64
case "$(uname -m)" in aarch64|arm64) host_arch=aarch64 ;; esac
qemu_accel=kvm
qemu_cpu=host
docker_device_args=(--device "$kvm_device")
if [[ "$host_arch" != "$arch" ]]; then
  if [[ "$allow_tcg" == false ]]; then
    printf 'error: guest arch %s needs a %s host with KVM; pass --allow-tcg for a local correctness audit\n' "$arch" "$arch" >&2
    exit 3
  fi
  qemu_accel=tcg
  docker_device_args=()
elif [[ -c "$kvm_device" && -r "$kvm_device" && -w "$kvm_device" ]]; then
  printf 'kvm=ok device=%s\n' "$kvm_device" > "$work/kvm-probe.log"
elif [[ "$allow_tcg" == true ]]; then
  qemu_accel=tcg
  docker_device_args=()
elif [[ "${OMG_QEMU_ALLOW_NO_KVM:-0}" == 1 ]]; then
  # Test fixtures stub the launch itself; production has no implicit fallback.
  docker_device_args=()
  printf 'kvm=skipped device=%s (OMG_QEMU_ALLOW_NO_KVM=1; tests only)\n' "$kvm_device" > "$work/kvm-probe.log"
elif [[ ! -c "$kvm_device" ]]; then
  printf 'error: KVM device %s is missing; refusing TCG fallback\n' "$kvm_device" >&2
  printf 'kvm=missing device=%s\n' "$kvm_device" > "$work/kvm-probe.log"
  exit 3
else
  printf 'error: KVM device %s is not accessible\n' "$kvm_device" >&2
  {
    printf 'kvm=inaccessible device=%s\n' "$kvm_device"
    id
    stat -c 'device_mode=%a owner=%U group=%G' "$kvm_device"
  } > "$work/kvm-probe.log"
  exit 3
fi
if [[ "$qemu_accel" == tcg ]]; then
  case "$arch" in aarch64) qemu_cpu=cortex-a72 ;; x86_64) qemu_cpu=max ;; esac
  if [[ "$benchmark" == true || "$transaction_samples" != 0 ]]; then
    printf 'error: TCG is correctness-only; timing and transaction benchmarks require KVM\n' >&2
    exit 3
  fi
fi
if [[ "$qemu_accel" == tcg && "$host_arch" != "$arch" ]]; then
  # Keep the controller native to this x86 host. Local cross-arch TCG audits
  # use QEMU 11.1; trixie's 10.0.13 aborted this Ubuntu ARM guest.
  controller_image=$controller_image_tcg
fi
printf 'accel=%s host_arch=%s guest_arch=%s device=%s\n' "$qemu_accel" "$host_arch" "$arch" "${kvm_device:-none}" > "$work/kvm-probe.log"
if [[ "$arch" == aarch64 && -z "$staged_dir" ]]; then
  # The release workflow publishes x86_64-linux archives (plus
  # aarch64-darwin for macOS) but no aarch64-linux archives, so a
  # published ARM leg has nothing to download. Staged ARM builds on
  # arm64 runners are the supported path.
  printf 'error: no published aarch64-linux archives; use --staged-dir with arm64-built binaries\n' >&2
  exit 3
fi
for tool in docker timeout sha256sum; do command -v "$tool" >/dev/null || exit 3; done
[[ "$benchmark" == false ]] || { command -v python3 >/dev/null || exit 3; }
[[ -n "$staged_dir" || -n "$release_dir" ]] || { command -v gh >/dev/null || exit 3; }
timeout --kill-after=2s 15s docker version --format '{{.Server.Version}}' > "$work/engine-preflight.log" 2>&1 || exit 3
{ date -u; uname -a; cat /proc/loadavg; grep -E 'MemTotal|MemAvailable|SwapFree' /proc/meminfo; } > "$work/host-metadata.txt"
archive="omg-${tag}-${arch}-linux-${distro}.tar.gz"
if [[ -n "$staged_dir" ]]; then
  cp "$staged_dir/$archive" "$staged_dir/$archive.sha256" "$work/release/"
elif [[ -n "$release_dir" ]]; then
  cp "$release_dir/$archive" "$release_dir/$archive.sha256" "$work/release/"
else
  timeout 120 gh release download "$tag" --repo PyRo1121/omg --pattern "$archive" --pattern "$archive.sha256" --dir "$work/release"
fi
read -r digest filename extra < "$work/release/$archive.sha256"
[[ "$digest" =~ ^[0-9a-f]{64}$ && "$filename" == "$archive" && -z "${extra:-}" ]]
[[ $(wc -l < "$work/release/$archive.sha256") -eq 1 ]]
(cd "$work/release" && sha256sum -c "$archive.sha256") > "$work/release-checksum.txt"
printf 'distro=%s\narch=%s\nhost_arch=%s\naccel=%s\ntiming_scope=%s\nrelease=%s\nartifact_source=%s\nimage_url=%s\nimage_digest=%s\nfirmware=%s\nqemu=%s -machine %s\ncontroller=%s\ncase_id=%s\n' "$distro" "$arch" "$host_arch" "$qemu_accel" "$([[ "$qemu_accel" == kvm ]] && printf benchmark || printf correctness-only)" "$tag" "$source_kind" "$image_url" "$image_hash" "$firmware" "$qemu_bin" "$qemu_machine" "$controller_image" "$case_id" > "$work/metadata.txt"
bash "$here/pull-qemu-controller.sh" "$controller_image" "$work/controller-pull-attempt.log" \
  > "$work/controller-pull.log" 2>&1 || exit 3
started=true
timeout 120 docker run --pull=never -d --name "$controller" --cpus 2 --memory 3g --memory-swap 3g --pids-limit 512 --log-opt max-size=10m --log-opt max-file=2 "${docker_device_args[@]}" \
  --cap-drop NET_RAW --cap-drop NET_ADMIN --dns 1.1.1.1 --dns 9.9.9.9 \
  --mount "type=bind,src=$work,dst=/work" --workdir /work \
  "$controller_image" sleep infinity > "$work/controller-id.txt"
if [[ "$restrict_egress" == true ]]; then
  egress_started=true
  timeout 120 sudo -n python3 "$here/qemu-controller-egress.py" install "$controller" \
    > "$work/egress-policy.json" 2> "$work/egress-policy.log"
fi
timeout --kill-after=5s 600 docker exec "$controller" sh -c "apt-get -o APT::Update::Error-Mode=any -o Acquire::Retries=2 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 update && DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 install -y --no-install-recommends $qemu_pkg qemu-utils cloud-image-utils openssh-client curl ca-certificates $firmware_pkg jq" > "$work/controller-setup.log" 2>&1
cp "$here/check-qemu-controller.sh" "$work/check-qemu-controller.sh"
cp "$here/check-qemu-cloud-init.sh" "$work/check-qemu-cloud-init.sh"
timeout 30 docker exec "$controller" bash /work/check-qemu-controller.sh "$qemu_pkg" > "$work/controller-security.log" 2>&1
# A cache hit is only a transport optimization: copy and hash the bytes before
# handing them to the controller, then verify again there and against policy.
cache_file=
cache_hit=false
if [[ -n "$image_cache" ]]; then
  cache_file="$image_cache/${hash_tool%sum}-$image_hash.qcow2"
  if timeout 90 python3 "$here/qemu-image-cache.py" "$cache_file" "$work/guest/base.qcow2" --algorithm "${hash_tool%sum}" --digest "$image_hash" > "$work/image-cache.log" 2>&1; then
    cache_hit=true
    printf 'verified cache hit\n' >> "$work/image-cache.log"
  else
    printf 'cache miss; downloading pinned image\n' >> "$work/image-cache.log"
  fi
fi
# Fedora's pinned cloud image is 556 MiB: a valid mirror delivering about
# 1 MiB/s needs more than five minutes. Keep a finite transfer deadline and
# verify the complete image digest before any guest boot or cache write.
timeout 960 docker exec "$controller" bash -c 'set -e; cd /work/guest; if [[ ! -f base.qcow2 ]]; then curl --fail --location --connect-timeout 20 --max-time 900 --retry 4 --retry-all-errors --retry-delay 5 --retry-max-time 900 -o base.qcow2 "$1"; fi; printf "%s  base.qcow2\n" "$2" | "$3" -c -' _ "$image_url" "$image_hash" "$hash_tool" > "$work/image-setup.log" 2>&1
if [[ -n "$cache_file" && "$cache_hit" == false ]]; then
  timeout 90 python3 "$here/qemu-image-cache.py" "$work/guest/base.qcow2" "$cache_file" --algorithm "${hash_tool%sum}" --digest "$image_hash" >> "$work/image-cache.log" 2>&1
fi
if [[ -n "$image_policy" ]]; then
  timeout 90 python3 "$here/verify-qemu-image.py" --manifest "$image_policy" --identity "$distro-$arch" \
    --url "$image_url" --digest "$image_hash" --image "$work/guest/base.qcow2" > "$work/image-provenance.json"
fi
timeout 30 docker exec -w /work/guest "$controller" bash -c '"$1" --version; qemu-img info base.qcow2' _ "$qemu_bin" >> "$work/image-setup.log" 2>&1
cat > "$work/boot.sh" <<'BOOT'
#!/usr/bin/env bash
set -euo pipefail
cd /work/guest
initial=true
vm_disk=overlay.qcow2; vm_vars=vars.fd; vm_serial=serial.log
if [[ $# == 11 ]]; then
  initial=false
  vm_disk=$9; vm_vars=${10}; vm_serial=${11}
  [[ "$vm_disk" =~ ^/work/guest/transaction-disks/[a-z0-9-]+\.qcow2$ && -f "$vm_disk" ]] || exit 2
  [[ "$vm_vars" =~ ^/work/guest/transaction-disks/[a-z0-9-]+\.fd$ ]] || exit 2
  [[ "$vm_serial" == /work/transactions/* && "$vm_serial" != *'/../'* ]] || exit 2
elif [[ $# != 8 ]]; then exit 2; fi
[[ ! -e qemu.pid ]] || exit 2
if [[ "$initial" == true ]]; then
ssh-keygen -q -t ed25519 -N '' -f client-key
ssh-keygen -q -t ed25519 -N '' -f guest-host-key
{
  # Guest identity is the pinned SSH key, not a cosmetic hostname. Avoid
  # cloud-init's unnecessary hostname operation during early boot setup.
  printf '#cloud-config\npreserve_hostname: true\nusers:\n  - name: bench\n    sudo: "ALL=(ALL) NOPASSWD:ALL"\n    shell: /bin/bash\n    ssh_authorized_keys:\n      - '
  cat client-key.pub
  printf 'ssh_pwauth: false\ndisable_root: true\nssh_keys:\n  ed25519_private: |\n'
  sed 's/^/    /' guest-host-key
  printf '  ed25519_public: '
  cat guest-host-key.pub
  # Arch waits for time-sync.target before cloud-final starts SSH. Keep clock
  # synchronization within the controller's explicit NTP destination policy.
  cat <<'CLOCK'
bootcmd:
  - |
    if [ "$(systemctl show -p LoadState --value systemd-timesyncd.service)" != not-found ]; then
      mkdir -p /etc/systemd/timesyncd.conf.d
      printf '[Time]\nNTP=\nNTP=162.159.200.1 162.159.200.123\nFallbackNTP=\n' > /etc/systemd/timesyncd.conf.d/99-omg-qemu.conf
      systemctl restart --no-block systemd-timesyncd.service
    fi
write_files:
  - path: /etc/systemd/system/omg-boot-network.service
    permissions: '0644'
    content: |
      [Unit]
      Description=Bounded QEMU boot network diagnostics
      [Service]
      Type=oneshot
      TimeoutStartSec=15
      ExecStart=-/usr/bin/env ip -brief address
      ExecStart=-/usr/bin/env ip -4 route
      ExecStart=-/usr/bin/journalctl --boot --unit=systemd-networkd --unit=NetworkManager --lines=80 --no-pager
      StandardOutput=tty
      StandardError=tty
      TTYPath=/dev/ttyS0
  - path: /etc/systemd/system/omg-boot-network.timer
    permissions: '0644'
    content: |
      [Unit]
      Description=Capture QEMU networking without SSH
      [Timer]
      OnBootSec=45
      Unit=omg-boot-network.service
      [Install]
      WantedBy=timers.target
CLOCK
} > user-data
chmod 600 user-data
printf 'instance-id: omg-qemu-fresh\n' > meta-data
printf '[127.0.0.1]:2222 ' > known_hosts
cat guest-host-key.pub >> known_hosts
cloud-localds seed.img user-data meta-data
qemu-img create -f qcow2 -F qcow2 -b /work/guest/base.qcow2 overlay.qcow2
qemu-img resize overlay.qcow2 12G
fi
firmware=()
if [[ "$1" == uefi ]]; then
  if [[ "$initial" == true ]]; then cp "$4" "$vm_vars"; fi
  [[ -f "$vm_vars" ]] || exit 2
  firmware=(-drive if=pflash,format=raw,readonly=on,file="$3" -drive if=pflash,format=raw,file="$vm_vars")
fi
accel=$7
[[ "$accel" != tcg ]] || accel=tcg,thread=multi
nohup "$5" -machine "$6" -accel "$accel" -cpu "$8" -smp 2 -m 1536 \
  -run-with user=65534:65534 \
  -sandbox on,obsolete=deny,spawn=deny,resourcecontrol=deny \
  -monitor none \
  "${firmware[@]}" -display none -serial "file:$vm_serial" \
  -drive "file=$vm_disk,if=virtio,format=qcow2" -drive file=seed.img,if=virtio,format=raw \
  -netdev user,id=n,ipv6=off,hostfwd=tcp:127.0.0.1:2222-:22 -device virtio-net-pci,netdev=n,romfile= \
  -pidfile qemu.pid > qemu-startup.log 2>&1 < /dev/null &
# Launch from the controller instead of QEMU's daemonize fork, which would
# conflict with spawn=deny. The controller teardown owns the background process.
qemu_pid=$!
for attempt in {1..100}; do
  if [[ -r "/proc/$qemu_pid/status" ]] && [[ $(awk '/^Uid:/ {print $3}' "/proc/$qemu_pid/status") == 65534 ]]; then break; fi
  if ! kill -0 "$qemu_pid" 2>/dev/null; then cat qemu-startup.log; exit 1; fi
  sleep 0.1
done
# QEMU drops privileges after opening devices and enabling seccomp. Keep
# setuid available for that drop; verify the resulting process cannot retain
# root IDs/capabilities or gain privileges through exec. Never fall back to root.
qemu_pid=$(<qemu.pid)
[[ "$qemu_pid" =~ ^[0-9]+$ ]] || exit 1
awk '
  /^Uid:/ { uid = ($2 == 65534 && $3 == 65534 && $4 == 65534 && $5 == 65534) }
  /^Gid:/ { gid = ($2 == 65534 && $3 == 65534 && $4 == 65534 && $5 == 65534) }
  /^CapEff:/ { caps = ($2 ~ /^0+$/) }
  /^NoNewPrivs:/ { nnp = ($2 == 1) }
  /^Seccomp:/ { seccomp = ($2 == 2) }
  END { exit !(uid && gid && caps && nnp && seccomp) }
' "/proc/$qemu_pid/status" || { printf 'QEMU isolation verification failed\n' >&2; exit 1; }
printf 'QEMU isolation verified: uid=65534 gid=65534 capabilities=none no_new_privs=1 seccomp=2\n'
opts=(-i client-key -p 2222 -o BatchMode=yes -o ConnectTimeout=2 -o ServerAliveInterval=5 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=yes -o UserKnownHostsFile=known_hosts)
wait_ssh() {
  local pid serial_bytes kernel_banner qemu_state
  for attempt in {1..120}; do
    pid=$(<qemu.pid)
    if ! kill -0 "$pid" 2>/dev/null; then
      printf 'QEMU exited before SSH became ready (attempt %s)\n' "$attempt" >&2
      cat qemu-startup.log >&2
      return 1
    fi
    if timeout --kill-after=2s 12s ssh "${opts[@]}" bench@127.0.0.1 true 2>/dev/null; then return 0; fi
    sleep 2
  done
  serial_bytes=$(wc -c < "$vm_serial")
  kernel_banner=no
  if grep -aqm1 'Linux version ' "$vm_serial"; then kernel_banner=yes; fi
  qemu_state=$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null || printf 'unknown')
  printf 'SSH readiness timed out after 120 attempts: qemu_state=%s serial_bytes=%s kernel_banner_seen=%s\n' \
    "$qemu_state" "$serial_bytes" "$kernel_banner" >&2
  printf 'Last guest serial lines:\n' >&2
  tail -n 6 "$vm_serial" >&2
  return 1
}
wait_ssh
# The controller checks cloud-init's authoritative runtime records and
# systemd target without starting a second Python process inside the guest.
bash /work/check-qemu-cloud-init.sh bench@127.0.0.1 "${opts[@]}"
timeout 15 ssh "${opts[@]}" bench@127.0.0.1 'cat /etc/os-release && uname -r && sudo -n true'
if [[ "$initial" == false ]]; then exit 0; fi
# Arm diagnostics before the first reboot and every subsequent disk clone.
# The timer has no network-online dependency, so failed DHCP/SSH cannot hide it.
ssh "${opts[@]}" bench@127.0.0.1 'sudo -n systemctl daemon-reload && sudo -n systemctl enable omg-boot-network.timer'
ssh "${opts[@]}" bench@127.0.0.1 "sudo -n systemctl enable '$2'"
before=$(timeout --kill-after=2s 12s ssh "${opts[@]}" bench@127.0.0.1 cat /proc/sys/kernel/random/boot_id)
timeout --kill-after=2s 12s ssh "${opts[@]}" bench@127.0.0.1 'sudo -n systemctl reboot' || true
for attempt in {1..120}; do
  if after=$(timeout --kill-after=2s 12s ssh "${opts[@]}" bench@127.0.0.1 cat /proc/sys/kernel/random/boot_id 2>/dev/null) && [[ "$after" != "$before" ]]; then
    printf 'reboot verified: %s -> %s\n' "$before" "$after"
    ssh "${opts[@]}" bench@127.0.0.1 "sudo -n true; systemctl is-active '$2'"
    exit 0
  fi
  sleep 2
done
exit 1
BOOT
boot_timeout=700
guest_timeout=600
if [[ "$qemu_accel" == tcg ]]; then
  # Emulation is an explicit local correctness audit. Keep it bounded without
  # imposing native KVM startup deadlines on a software-emulated guest.
  boot_timeout=1800
  guest_timeout=2400
fi
printf 'boot_timeout=%s guest_timeout=%s\n' "$boot_timeout" "$guest_timeout" >> "$work/metadata.txt"
timeout "$boot_timeout" docker exec "$controller" bash /work/boot.sh "$firmware" "$ssh_service" "$firmware_code" "$firmware_vars_src" "$qemu_bin" "$qemu_machine" "$qemu_accel" "$qemu_cpu" > "$work/boot.log" 2>&1
if [[ -n "$inventory_tiers" ]]; then
  # The inventory executor runs inside the controller (same netns as the
  # guest); /work is bind-mounted there.
  cp "$here/qemu-inventory.sh" "$work/qemu-inventory.sh"
  cp "$here/qemu-fingerprint-oracle.py" "$work/qemu-fingerprint-oracle.py"
  cp "$here/qemu-fedora-update-fixture.sh" "$work/qemu-fedora-update-fixture.sh"
  cp "$here/workspace-overlap-fixture.sh" "$work/workspace-overlap-fixture.sh"
  cp "$tsv" "$work/cases.tsv"
  if [[ "$inventory_isolation" == true ]]; then
    cp "$inventory_policy" "$work/inventory-policy.json"
  fi
fi
if [[ "$benchmark" == true ]]; then
  cp "$here/../benchmark-hyperfine.sh" "$work/benchmark-hyperfine.sh"
  cp "$here/record-benchmark-run.py" "$work/record-benchmark-run.py"
  if [[ "$transaction_samples" != 0 ]]; then
    cp "$here/qemu-transactions.sh" "$work/qemu-transactions.sh"
    cp "$here/check-qemu-health.py" "$work/check-qemu-health.py"
    sha256sum "$work/qemu-transactions.sh" > "$work/transaction-runner-sha256.txt"
  fi
  sha256sum "$work/benchmark-hyperfine.sh" "$work/record-benchmark-run.py" > "$work/benchmark-driver-sha256.txt"
fi
cp "$here/qemu-daemon-check.sh" "$work/qemu-daemon-check.sh"
cp "$here/qemu-aur-check.sh" "$here/qemu-aur-fixture.py" "$work/"
cp "$here/../tests/daemon_advisory_shutdown.sh" "$work/daemon-advisory-shutdown.sh"
cat > "$work/guest-check.sh" <<'GUEST'
#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C NO_COLOR=1
cd "$HOME"
distro=$1; tag=$2; digest=$3; benchmark=$4; guest_arch=$5; expected_uname=$6; inventory_tiers=$7; accel=$8
case "$accel" in kvm) daemon_timeout=240 ;; tcg) daemon_timeout=900 ;; *) exit 120 ;; esac
actual_id=$(awk -F= '$1 == "ID" {gsub(/"/, "", $2); print $2}' /etc/os-release)
[[ "$actual_id" == "$distro" && $(uname -m) == "$expected_uname" ]] || exit 120
mkdir -p evidence
capture_audit_metadata() {
  timeout --kill-after=2s 5s sudo -n bash -c '
    for path in /var/log /var/log/omg /var/lib /var/lib/omg /var/lib/omg/audit; do
      if [[ -e "$path" || -L "$path" ]]; then
        stat -c "%n uid=%u gid=%g mode=%a type=%F" "$path"
      else
        printf "%s absent\n" "$path"
      fi
    done
  ' > evidence/audit-directory-after.txt 2>&1
}
trap 'status=$?; printf "%s\n" "$status" > evidence/exit-code; capture_audit_metadata || true' EXIT
# Preserve directory trust evidence before a privileged operation can fail.
stat -c '%n uid=%u gid=%g mode=%a type=%F' / /var /var/log > evidence/audit-directory-metadata.txt
if [[ -e /var/log/omg || -L /var/log/omg ]]; then
  stat -c '%n uid=%u gid=%g mode=%a type=%F' /var/log/omg >> evidence/audit-directory-metadata.txt
fi
printf '%s  release.tar.gz\n' "$digest" | sha256sum -c -
tar -xzf release.tar.gz
bin="$HOME/omg-${tag}-${guest_arch}-linux-${distro}/omg"
[[ $("$bin" --version | head -1 | tr -d '[:space:]') == "omg${tag#v}" ]]
daemon="${bin%/*}/omgd"
if [[ ! -x "$daemon" ]]; then
  printf 'Release %s for %s is missing executable omgd; publish an archive containing both omg and omgd.\n' "$tag" "$distro" >&2
  exit 1
fi
[[ $("$daemon" --version | head -1 | tr -d '[:space:]') == "omgd${tag#v}" ]]
case "$distro" in
  arch) sudo -n pacman -Syu --noconfirm >/dev/null || exit 120; native=(pacman -Qi tree); version_cmd=(pacman -Q tree) ;;
  debian|ubuntu)
    sudo -n systemctl stop apt-daily.timer apt-daily-upgrade.timer
    if [[ "$distro" == ubuntu ]]; then
      sudo -n sed -i 's|http://archive.ubuntu.com/ubuntu|https://archive.ubuntu.com/ubuntu|g; s|http://security.ubuntu.com/ubuntu|https://security.ubuntu.com/ubuntu|g' /etc/apt/sources.list.d/ubuntu.sources
    fi
    printf 'Acquire::ForceIPv4 "true";\nAcquire::Retries "2";\nAcquire::http::Timeout "30";\nAcquire::https::Timeout "30";\nAcquire::Languages "none";\nAcquire::IndexTargets::deb::DEP-11::DefaultEnabled "false";\nAcquire::IndexTargets::deb::CNF::DefaultEnabled "false";\n' | sudo -n tee /etc/apt/apt.conf.d/99omg-qa-network > evidence/apt-network.conf
    sudo -n apt-get update > evidence/index-update.txt 2>&1 || exit 120
    native=(apt-cache --no-all-versions show tree)
    version_cmd=(dpkg-query -W '-f=${Version}\n' tree) ;;
  fedora) sudo -n dnf -y makecache >/dev/null || exit 120; native=(rpm -qi tree); version_cmd=(rpm -q --qf '%{VERSION}-%{RELEASE}\n' tree) ;;
esac
installed() {
  case "$distro" in arch) pacman -Q tree ;; debian|ubuntu) [[ $(dpkg-query -W '-f=${Status}' tree 2>/dev/null) == 'install ok installed' ]] ;; fedora) rpm -q tree ;; esac
}
if installed >/dev/null 2>&1; then echo 'fixture requires tree absent' >&2; exit 120; fi
"$bin" search tree > evidence/search.txt
grep -Eqi '^[[:space:]]+tree[[:space:]]' evidence/search.txt
sudo -n "$bin" install --yes tree
installed
"$bin" info tree > evidence/omg-info.txt
"${native[@]}" > evidence/native-info.txt
version=$("${version_cmd[@]}")
[[ "$distro" != arch ]] || version=${version#tree }
[[ $(awk '$1 == "Name:" {print $2}' evidence/omg-info.txt) == tree ]]
[[ $(awk '$1 == "Version:" {print $2}' evidence/omg-info.txt) == "$version" ]]
# Exercise both direct daemon startup and the actual CLI foreground launcher
# while the package databases and installed fixture are available.
guest_tools=(jq)
[[ "$distro" != arch ]] || guest_tools+=(python openssl)
[[ "$benchmark" != true ]] || guest_tools+=(hyperfine)
case "$distro" in
  arch) sudo -n pacman -S --noconfirm --needed "${guest_tools[@]}" || exit 120 ;;
  debian|ubuntu) sudo -n env DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 install -y --no-install-recommends "${guest_tools[@]}" || exit 120 ;;
  fedora) sudo -n dnf install -y "${guest_tools[@]}" || exit 120 ;;
esac
printf 'daemon lifecycle start accel=%s timeout=%s\n' "$accel" "$daemon_timeout"
OMG_QEMU_ACCEL="$accel" timeout --kill-after=5s "$daemon_timeout" bash "$HOME/qemu-daemon-check.sh" "$bin" "$HOME/evidence"
if [[ "$distro" == arch ]]; then
  timeout --kill-after=5s 120s bash "$HOME/qemu-aur-check.sh" "$bin" "$HOME/evidence"
fi
# BEGIN ADVISORY SHUTDOWN REGRESSION
if [[ "$distro" == fedora ]]; then
  sudo -n bash "$HOME/daemon-advisory-shutdown.sh" "${bin%/*}/omgd" "$(id -un)" \
    2>&1 | tee "$HOME/evidence/daemon-advisory-shutdown.log"
fi
# END ADVISORY SHUTDOWN REGRESSION
if [[ "$benchmark" == true ]]; then
  OMG_BENCH_BINARY="$bin" OMG_BENCH_EXPORT_DIR="$HOME/evidence/benchmarks" \
    bash "$HOME/benchmark-hyperfine.sh" --guest || exit 120
fi
sudo -n "$bin" remove --yes tree
if installed >/dev/null 2>&1; then echo 'package remains installed' >&2; exit 1; fi
if [[ "$distro" == debian || "$distro" == ubuntu ]]; then
  apt-get download tree || exit 120
  packages=("$HOME"/tree_*.deb)
  [[ ${#packages[@]} -eq 1 && -f "${packages[0]}" ]] || exit 120
  sha256sum "${packages[0]}" > evidence/local-package.sha256
  if "$bin" install --yes "${packages[0]}" > evidence/local-consent.txt 2>&1; then
    echo 'local archive was accepted without consent' >&2; exit 1
  fi
  grep -Fq 'require explicit consent' evidence/local-consent.txt
  sudo -n "$bin" install --allow-local-file --yes "${packages[0]}"
  installed
  sudo -n "$bin" remove --yes tree
  if installed >/dev/null 2>&1; then echo 'local package remains installed' >&2; exit 1; fi
fi
sudo -n test -s /var/lib/omg/audit/audit.jsonl
sudo -n env OMG_DATA_DIR=/var/lib/omg "$bin" audit verify > evidence/system-audit-verify.txt 2>&1
case "$distro" in
  arch) pacman -Q > evidence/installed-after.txt; sha256sum /var/lib/pacman/sync/*.db > evidence/repository-hashes.txt ;;
  debian|ubuntu) dpkg-query -W > evidence/installed-after.txt; find /var/lib/apt/lists -maxdepth 1 -type f ! -name lock -exec sha256sum {} + > evidence/repository-hashes.txt ;;
  fedora) rpm -qa > evidence/installed-after.txt; find /var/cache/libdnf5 -type f -name repomd.xml -exec sha256sum {} + > evidence/repository-hashes.txt ;;
esac
{ cat /etc/os-release; uname -a; sha256sum "$bin"; printf 'native_version=%s\n' "$version"; } > evidence/guest-metadata.txt
# Inventory fixtures need these tools; missing tools are setup failures,
# never acceptable product refusals. Keep this after the lifecycle probe.
if [[ -n "$inventory_tiers" ]]; then
  case "$distro" in
    arch) sudo -n pacman -S --noconfirm --needed git make curl python strace ;;
    debian|ubuntu) sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends git make curl python3 strace ;;
    fedora) sudo -n dnf install -y git make curl python3 strace podman rpm-build createrepo_c ;;
  esac > evidence/inventory-setup.txt 2>&1 || exit 120
  # The hermetic `new` row exercises the missing-toolchain refusal. A guest
  # with Cargo installed is a different fixture, not a product failure.
  if command -v cargo > evidence/rust-toolchain.txt; then
    printf 'Inventory fixture requires Cargo to be absent for the new row\n' >&2
    exit 120
  fi
  if [[ "$distro" == fedora ]]; then
    command -v podman > evidence/container-engine.txt || exit 120
    podman --version >> evidence/container-engine.txt || exit 120
    if command -v docker >> evidence/container-engine.txt; then exit 120; fi
  else
    printf 'fixture requires no container engine\n' > evidence/container-engine.txt
    if command -v docker >> evidence/container-engine.txt || command -v podman >> evidence/container-engine.txt; then exit 120; fi
  fi
fi
echo 'PASS: package lifecycle and native version parity'
GUEST
opts=(-i client-key -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=known_hosts)
timeout 60 docker exec -w /work/guest "$controller" scp "${opts[@]}" -P 2222 "/work/release/$archive" bench@127.0.0.1:release.tar.gz
timeout 60 docker exec -w /work/guest "$controller" scp "${opts[@]}" -P 2222 /work/guest-check.sh bench@127.0.0.1:guest-check.sh
timeout 60 docker exec -w /work/guest "$controller" scp "${opts[@]}" -P 2222 /work/qemu-daemon-check.sh bench@127.0.0.1:qemu-daemon-check.sh
if [[ "$distro" == arch ]]; then
  timeout 60 docker exec -w /work/guest "$controller" scp "${opts[@]}" -P 2222 /work/qemu-aur-check.sh /work/qemu-aur-fixture.py bench@127.0.0.1:
fi
if [[ -n "$inventory_tiers" ]]; then
  timeout 60 docker exec -w /work/guest "$controller" scp "${opts[@]}" -P 2222 /work/qemu-fedora-update-fixture.sh bench@127.0.0.1:qemu-fedora-update-fixture.sh
  timeout 60 docker exec -w /work/guest "$controller" scp "${opts[@]}" -P 2222 /work/qemu-fingerprint-oracle.py bench@127.0.0.1:qemu-fingerprint-oracle.py
fi
timeout 60 docker exec -w /work/guest "$controller" scp "${opts[@]}" -P 2222 /work/daemon-advisory-shutdown.sh bench@127.0.0.1:daemon-advisory-shutdown.sh
if [[ "$benchmark" == true ]]; then
  timeout 60 docker exec -w /work/guest "$controller" scp "${opts[@]}" -P 2222 /work/benchmark-hyperfine.sh bench@127.0.0.1:benchmark-hyperfine.sh
fi
rc=0
timeout "$guest_timeout" docker exec -w /work/guest "$controller" ssh "${opts[@]}" -p 2222 bench@127.0.0.1 "bash guest-check.sh '$distro' '$tag' '$digest' '$benchmark' '$arch' '$guest_uname' '$inventory_tiers' '$qemu_accel'" > "$work/guest-check.log" 2>&1 || rc=$?
timeout 60 docker exec -w /work/guest "$controller" scp -r "${opts[@]}" -P 2222 bench@127.0.0.1:evidence /work/guest/ > "$work/evidence-copy.log" 2>&1
if [[ ! -f "$work/guest/evidence/exit-code" ]]; then
  printf 'Guest evidence receipt is missing (transport exit %s); see %s/evidence-copy.log and %s/guest-check.log\n' "$rc" "$work" "$work" >&2
  exit 3
fi
guest_rc=$(<"$work/guest/evidence/exit-code")
if [[ ! "$guest_rc" =~ ^[0-9]+$ || "$guest_rc" != "$rc" ]]; then
  printf 'Guest exit %s differs from transport exit %s\n' "$guest_rc" "$rc" >&2
  exit 3
fi
if [[ "$rc" == 0 ]]; then
  # A zero guest exit alone is insufficient: require the daemon probe receipt.
  daemon_receipt="$work/guest/evidence/daemon-lifecycle.json"
  if ! [[ -f "$daemon_receipt" && $(wc -c < "$daemon_receipt") -le 4096 ]] || ! jq -e -s --arg distro "$distro" '
    length == 1 and (.[0] | type == "object") and (.[0] |
    .schema_version == 1 and .direct == true and .foreground == true and
    .ipc == true and .singleton == true and .shutdown == true and .restart == true and .query_parity == true and .sigint == true and .cleanup == true and
    .backend_faults == (if $distro == "fedora" then ["dnf-reason-refusal"] else [] end))
  ' "$daemon_receipt" >/dev/null; then
    printf 'Missing or incomplete daemon lifecycle evidence\n' >&2
    exit 1
  fi
  if [[ "$distro" == arch ]]; then
    aur_receipt="$work/guest/evidence/aur-search-flags.json"
    aur_events="$work/guest/evidence/aur-fixture-events.jsonl"
    if ! [[ -f "$aur_receipt" && $(wc -c < "$aur_receipt") -le 4096 && -f "$aur_events" && $(wc -c < "$aur_events") -le 8192 ]] \
      || ! jq -e -s 'length == 1 and (.[0] | .schema_version == 1 and .arch == true and
        .real_cli == true and .tls_fixture == true and .detailed_metadata == true and
        .no_aur_suppressed == true and .basic_metadata_absent == true and
        .expected_connects == 2 and .expected_requests == 2 and .unexpected_events == 0)' \
        "$aur_receipt" >/dev/null \
      || ! jq -e -s 'length == 4 and
        .[0] == {event:"connect",value:"aur.archlinux.org:443"} and
        .[1] == {event:"request",value:"/rpc?v=5&type=search&arg=omgqemuaurprobe"} and
        .[2] == {event:"connect",value:"aur.archlinux.org:443"} and
        .[3] == {event:"request",value:"/rpc?v=5&type=search&arg=omgqemuaurprobe"}' \
        "$aur_events" >/dev/null; then
      printf 'Missing or incomplete Arch AUR flag evidence\n' >&2
      exit 1
    fi
  fi
fi
if [[ "$benchmark" == true && "$rc" == 0 ]]; then
  case "$distro" in
    arch) expected_commands='{"info":["OMG","pacman"],"search":["OMG","pacman"],"explicit":["OMG","pacman"]}' ;;
    debian|ubuntu) expected_commands='{"info":["OMG","apt-cache","apt"],"search":["OMG","apt-cache","apt"],"explicit":["OMG","apt-mark"]}' ;;
    fedora) expected_commands='{"info":["OMG","rpm","dnf"],"search":["OMG","dnf"],"explicit":["OMG","dnf"]}' ;;
  esac
  benchmark_evidence="$work/guest/evidence/benchmarks"
  if ! (
    [[ -f "$benchmark_evidence/summary.json" && $(wc -c < "$benchmark_evidence/summary.json") -le 1048576 ]] || exit 1
    python3 "$work/record-benchmark-run.py" --validate-only --scenario info --scenario search \
      --scenario explicit --source "$benchmark_evidence" || exit 1
    jq -e --arg distro "$distro" --argjson expected "$expected_commands" '
      .schema_version == 2 and .complete == true and .distro == $distro and
      .operations == ["info","search","explicit"] and .daemon == "disabled" and
      (.commands | with_entries(.value |= map(.label))) == $expected and
      all(.commands[][]; (.argv|type == "array" and length > 0 and all(.[]; type == "string"))) and
      .comparisons.info.equivalent == true and .comparisons.explicit.equivalent == true and
      (.comparisons.search.equivalent|type == "boolean") and
      (.min_runs|type == "number" and floor == . and . > 0) and
      (.max_runs|type == "number" and floor == . and . >= 1 and . <= 10000) and
      .min_runs <= .max_runs' "$benchmark_evidence/summary.json" >/dev/null || exit 1
    for scenario in info search explicit; do
      jq -e --argjson expected "$expected_commands" --arg scenario "$scenario" \
        --slurpfile summary "$benchmark_evidence/summary.json" '
        [.results[].command] == $expected[$scenario] and
        all(.results[]; (.times|length) >= $summary[0].min_runs and
          (.times|length) <= $summary[0].max_runs)' "$benchmark_evidence/$scenario.json" >/dev/null || exit 1
    done
  ) > "$work/benchmark-validation.log" 2>&1; then
    printf 'Benchmark evidence rejected; see %s/benchmark-validation.log\n' "$work" >&2
    rc=120
  fi
fi
if [[ "$transaction_samples" != 0 && "$rc" == 0 ]]; then
  transaction_rc=0
  timeout --kill-after=10s 21600 docker exec -w /work "$controller" bash /work/qemu-transactions.sh \
    "$distro" "$tag" "$arch" "$transaction_samples" "$firmware" "$ssh_service" \
    "$firmware_code" "$firmware_vars_src" "$qemu_bin" "$qemu_machine" "$qemu_accel" "$qemu_cpu" \
    > "$work/transactions.log" 2>&1 || transaction_rc=$?
  if [[ "$transaction_rc" != 0 ]]; then
    rc=120
    summary="$work/transactions/summary.json"
    if [[ "$transaction_rc" == 10 && -f "$summary" && $(wc -c < "$summary") -le 1048576 ]] &&
       jq -e --arg distro "$distro" --argjson count "$transaction_samples" '
         .schema_version==2 and .kind=="transaction-suite" and .distro==$distro and
         .complete==false and .phase=="measurement-command" and
         (.results|length)==($count*4) and
         ([.results[]|select(.result=="FAIL")]|length)==1 and
         all(.results[]|select(.result=="FAIL");
           (.id|test("^(install|remove)-(omg|native)-[0-9]{3}$")) and
           (.exit_code|type=="number" and floor==. and .>0 and .<124))
       ' "$summary" >/dev/null; then
      rc=1
    fi
  elif ! (
    summary="$work/transactions/summary.json"
    [[ -f "$summary" && $(wc -c < "$summary") -le 1048576 ]] || exit 1
    jq -e --arg distro "$distro" --argjson count "$transaction_samples" '
      . as $s |
      ([range(1;$count+1) as $round |
        ["install-omg-","install-native-","remove-omg-","remove-native-"][] |
        .+(("000"+($round|tostring))[-3:])] | sort) as $expected |
      .schema_version==2 and .kind=="transaction-suite" and .complete==true and
      .distro==$distro and .samples_per_tool==$count and .expected_trials==($count*4) and
      (.bases.install|test("^[0-9a-f]{64}$")) and (.bases.remove|test("^[0-9a-f]{64}$")) and
      ([.results[].id]|sort)==$expected and
      ([.results[].boot_id]|unique|length)==($count*4) and
      all(.results[];.result=="PASS" and .exit_code==0 and
        (.boot_id|test("^[0-9a-f-]{36}$")) and .base_sha256==$s.bases[.operation] and
        .id==(.operation+"-"+.tool+"-"+(("000"+(.round|tostring))[-3:])))
    ' "$summary" >/dev/null || exit 1
    expected_version=$(awk '$1=="Version:" {print $2}' "$work/guest/evidence/omg-info.txt")
    [[ "$(<"$work/transactions/expected-version.txt")" == "$expected_version" ]] || exit 1
    read -r expected_binary _ < "$work/guest/evidence/benchmarks/binary-sha256.txt"
    for operation in install remove; do
      read -r repository_digest _ < "$work/transactions/$operation-repository-state.sha256"
      actual_digest=$(sha256sum "$work/transactions/$operation-repository-state.tar.gz")
      [[ "$repository_digest" == "${actual_digest%% *}" ]] || exit 1
      for tool in omg native; do
        label_name=OMG
        if [[ "$tool" == native ]]; then
          case "$distro" in arch) label_name=pacman ;; debian|ubuntu) label_name=apt ;; fedora) label_name=dnf ;; esac
        fi
        for ((round=1;round<=transaction_samples;round++)); do
          printf -v trial_id '%s-%s-%03d' "$operation" "$tool" "$round"
          evidence="$work/transactions/trials/$trial_id/transaction-trial"
          trial_boot=$(jq -er --arg id "$trial_id" '.results[] | select(.id==$id) | .boot_id' "$summary")
          python3 "$here/check-qemu-health.py" verify-trial \
            --guest "$work/transactions/trials/$trial_id/health.json" \
            --serial "$work/transactions/trials/$trial_id/serial.log" --boot-id "$trial_boot" || exit 1
          python3 "$work/record-benchmark-run.py" --validate-only --scenario "$operation" --source "$evidence" || exit 1
          read -r actual_binary _ < "$evidence/binary-sha256.txt"
          [[ "$actual_binary" == "$expected_binary" ]] || exit 1
          cmp "$work/transactions/$operation-before.tsv" "$evidence/installed-before.tsv" || exit 1
          cmp "$work/transactions/$operation-manual-before.names" "$evidence/manual-before.names" || exit 1
          cmp "$evidence/installed-expected.tsv" "$evidence/installed-after.tsv" || exit 1
          cmp "$evidence/manual-expected.names" "$evidence/manual-after.names" || exit 1
          [[ -s "$evidence/cache-before.sha256" && -s "$evidence/cache-after.sha256" ]] || exit 1
          jq -e --arg label_name "$label_name" '
            .results|length==1 and .[0].command==$label_name and (.[0].times|length)==1
          ' "$evidence/$operation.json" >/dev/null || exit 1
          jq -e --arg distro "$distro" --arg operation "$operation" --arg tool "$tool" \
            --arg version "$expected_version" --arg label_name "$label_name" --arg id "$trial_id" \
            --slurpfile suite "$summary" '
            .schema_version==2 and .kind=="transaction-trial" and .complete==true and
            .distro==$distro and .operation==$operation and .tool==$tool and .expected_version==$version and
            .boot_id==([$suite[0].results[]|select(.id==$id)][0].boot_id) and
            .state_change_verified==true and .manual_state_change_verified==true and
            .samples==1 and .warmup==0 and .daemon=="disabled" and .command.label==$label_name and
            (.command.argv|type=="array" and length>0 and all(.[];type=="string"))
          ' "$evidence/summary.json" >/dev/null || exit 1
        done
      done
    done
  ) > "$work/transaction-validation.log" 2>&1; then
    rc=120
  fi
fi
inventory_harness_error=false
if [[ -n "$inventory_tiers" ]]; then
  expected_ids=$(jq -Rn --arg tiers "$inventory_tiers" --arg distro "$distro" '
    ($tiers | split(",")) as $wanted |
    [inputs | split("\t") | select(.[0] != "case") |
      select((.[6] | split(",")) as $row | any($row[]; . as $t | $wanted | index($t))) |
      "qemu-" + $distro + "-" + .[0]] | sort' < "$tsv")
fi
if [[ -n "$inventory_tiers" && "$rc" == 0 ]]; then
  # TSV-driven rows run only on a healthy guest, inside the controller
  # (same netns; /work is bind-mounted). Evidence lands in $work/inventory.
  inv_args=(--work /work --distro "$distro" --tiers "$inventory_tiers" --tag "$tag"
    --binary "/home/bench/omg-${tag}-${arch}-linux-${distro}/omg" --tsv /work/cases.tsv)
  [[ "$inventory_mutations" == false ]] || inv_args+=(--allow-mutations)
  [[ "$inventory_isolation" == false ]] || inv_args+=(--isolate-hermetic --network-policy /work/inventory-policy.json)
  inventory_rc=0
  timeout --kill-after=5s 3600 docker exec -w /work "$controller" bash /work/qemu-inventory.sh "${inv_args[@]}" > "$work/inventory.log" 2>&1 || inventory_rc=$?
  # Validate identity and values even for interrupted reports. Partial
  # reports may prove failures but can never prove a passing selection.
  inventory_snapshot='null'
  if [[ -f "$work/inventory/results.json" && $(wc -c < "$work/inventory/results.json") -le 1048576 ]]; then
    inventory_snapshot=$(<"$work/inventory/results.json")
  fi
  if ! jq -e --arg distro "$distro" --argjson expected "$expected_ids" '
    type == "array" and length > 0 and
    ([.[].case_id] | length == (unique | length)) and
    all(.[];
      .distro == $distro and .artifact_source == "inventory" and
      (.case_id as $id | $expected | index($id) != null) and
      (.result == "PASS" or .result == "FAIL" or .result == "BLOCKED" or .result == "HARNESS_ERROR" or .result == "SKIPPED") and
      (.exit_code | type == "number" and floor == . and . >= -1 and . <= 255) and
      (.elapsed_seconds | type == "number" and . >= 0 and . <= 86400))' <<< "$inventory_snapshot" >/dev/null 2>&1; then
    printf 'Inventory evidence missing or invalid; see %s/inventory.log\n' "$work" >&2
    inventory_harness_error=true
  else
    report_inventory=$(jq -c 'map({case_id,distro,result,exit_code,elapsed_seconds})' <<< "$inventory_snapshot")
    if jq -e 'any(.[]; .result == "FAIL")' <<< "$inventory_snapshot" >/dev/null; then
      inventory_product_failure=true
    elif [[ "$inventory_rc" != 0 ]] ||
      ! jq -e '.complete == true' "$work/inventory/summary.json" >/dev/null 2>&1 ||
      ! jq -e --argjson expected "$expected_ids" '
        ([.[].case_id] | sort) == $expected and
        any(.[]; .result == "PASS") and
        all(.[]; .result == "PASS" or .result == "SKIPPED")' <<< "$inventory_snapshot" >/dev/null; then
      inventory_harness_error=true
    fi
  fi
  [[ "$inventory_harness_error" == false ]] || rc=3
elif [[ -n "$inventory_tiers" ]]; then
  # A lifecycle failure must not make the requested inventory disappear.
  mkdir -p "$work/inventory"
  jq -n --argjson ids "$expected_ids" --arg distro "$distro" '
    $ids | map({case_id:., distro:$distro, artifact_source:"inventory",
      result:"BLOCKED", exit_code:-1, elapsed_seconds:0})' > "$work/inventory/results.json"
  printf '{"complete":false,"reason":"guest lifecycle failed"}\n' > "$work/inventory/summary.json"
fi
if [[ -n "$inventory_policy" ]]; then
  policy_rc=0
  python3 "$here/check-qemu-inventory.py" --policy "$inventory_policy" --inventory "$tsv" \
    --results "$work/inventory/results.json" --summary "$work/inventory/summary.json" \
    --distro "$distro" --tiers "$inventory_tiers" > "$work/inventory-admission.json" || policy_rc=$?
  if [[ "$policy_rc" == 1 && "$inventory_product_failure" == true ]] &&
    jq -e '.schema_version == 1 and .passed == false and
           (.counts.failed | type == "number") and .counts.failed > 0 and
           .counts.harness_error == 0' "$work/inventory-admission.json" >/dev/null 2>&1; then
    # Exit 1 with a validated failure receipt means the selected product
    # cases failed. Preserve independent lifecycle evidence; the row failure
    # still makes the overall command fail below. Invalid admission is exit 2.
    :
  elif [[ "$policy_rc" != 0 ]]; then
    [[ "$rc" != 0 ]] || rc=120
    inventory_harness_error=true
  fi
fi
if [[ "$storage_faults" == true && "$rc" == 0 ]]; then
  quoted_fault_binary=$(jq -rn --arg b "/home/bench/omg-${tag}-${arch}-linux-${distro}/omg" '$b | @sh')
  fault_setup='set -eu; token=$(cat /proc/sys/kernel/random/uuid); printf "%s\n" "$token" > /run/omg-qemu-storage-faults; chmod 444 /run/omg-qemu-storage-faults; exec unshare --mount --propagation private python3 - --binary "$1" --token "$token"'
  quoted_fault_setup=$(jq -rn --arg s "$fault_setup" '$s | @sh')
  fault_rc=0
  timeout --kill-after=5s 180s docker exec -i -w /work/guest "$controller" \
    ssh -i client-key -p 2222 -o BatchMode=yes -o ConnectTimeout=5 \
      -o ServerAliveInterval=5 -o ServerAliveCountMax=3 \
      -o StrictHostKeyChecking=yes -o UserKnownHostsFile=known_hosts \
      bench@127.0.0.1 "sudo -n bash -c $quoted_fault_setup bash $quoted_fault_binary" \
      < "$here/qemu-storage-faults.py" > "$work/storage-faults.json" 2> "$work/storage-faults.log" || fault_rc=$?
  if [[ "$fault_rc" == 1 && -f "$work/storage-faults.json" && $(wc -c < "$work/storage-faults.json") -le 65536 ]] &&
     jq -e '.schema_version==1 and .scope=="privacy-export-atomic-write" and .complete==false and .failure_kind=="product"' "$work/storage-faults.json" >/dev/null; then
    rc=1
  elif [[ "$fault_rc" != 0 ]] || ! python3 "$here/qemu-storage-faults.py" --receipt "$work/storage-faults.json" >> "$work/storage-faults.log" 2>&1; then
    rc=120
  fi
fi
# Health is an independent admission gate after the selected test work. Query
# boot-scoped kernel/crash identity only, never raw cores or process environments.
health_rc=0
timeout --kill-after=5s 60s docker exec -i -w /work/guest "$controller" \
  ssh -i client-key -p 2222 -o BatchMode=yes -o ConnectTimeout=5 \
    -o ServerAliveInterval=5 -o ServerAliveCountMax=3 \
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile=known_hosts \
    bench@127.0.0.1 sudo -n python3 - collect \
  < "$here/check-qemu-health.py" > "$work/guest-health.json" 2> "$work/health-validation.log" || health_rc=$?
timeout 15 docker inspect --format '{{json .State}}' "$controller" > "$work/controller-health.json" 2>> "$work/health-validation.log" || health_rc=120
if [[ "$health_rc" == 0 ]]; then
  python3 "$here/check-qemu-health.py" verify --guest "$work/guest-health.json" \
    --serial "$work/guest/serial.log" --controller "$work/controller-health.json" \
    >> "$work/health-validation.log" 2>&1 || health_rc=120
fi
if [[ "$health_rc" != 0 ]]; then
  printf 'Final guest/controller health failed admission\n' >&2
  [[ "$rc" != 0 ]] || rc=120
fi
# Verdict map: only proven-rig codes are HARNESS_ERROR. Per the GNU
# coreutils manual, timeout exits 124 when the managed command times out
# and 125/126/127 when timeout/the-exec itself fails
# (https://www.gnu.org/software/coreutils/manual/html_node/timeout-invocation.html):
# A deadline or SIGKILL is a failed execution, not proof of its cause.
# Status 137 alone cannot distinguish a killed command from killed timeout. 120 is this
# pipeline's own fixture marker; 125/126/127/255 are exec/transport.
case "$rc" in 0) result=PASS ;; 120|125|126|127|255) result=HARNESS_ERROR ;; *) result=PRODUCT_FAIL ;; esac
[[ "$inventory_harness_error" == false ]] || result=HARNESS_ERROR
[[ "$inventory_product_failure" == false ]] || rc=1
exit "$rc"
