#!/usr/bin/env bash
# Runs inside the existing QEMU controller; measurement stays in the root driver.
set -euo pipefail
[[ $# == 12 ]] || exit 2
distro=$1; tag=$2; arch=$3; samples=$4
shift 4
boot_args=("$@")
case "$distro" in arch|debian|ubuntu|fedora) ;; *) exit 2 ;; esac
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ && "$arch" =~ ^(x86_64|aarch64)$ ]] || exit 2
[[ "$samples" =~ ^([1-9]|[1-9][0-9]|100)$ ]] || exit 2
cd /work/guest
[[ -f client-key && -f known_hosts && -f qemu.pid ]] || exit 2
output=/work/transactions
disks=/work/guest/transaction-disks
[[ ! -e "$output" && ! -e "$disks" ]] || exit 2
mkdir -p "$output/trials" "$disks"
# The host owns teardown after the controller stops. File ownership need not be
# weakened: ownership of this directory is sufficient to unlink its disks.
chown --reference=/work/guest "$disks"
opts=(-i client-key -p 2222 -o BatchMode=yes -o ConnectTimeout=5
  -o ServerAliveInterval=5 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=yes
  -o UserKnownHostsFile=known_hosts)
scp_opts=(-i client-key -P 2222 -o BatchMode=yes -o ConnectTimeout=5
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile=known_hosts)
bin="/home/bench/omg-${tag}-${arch}-linux-${distro}/omg"
current_id=
failure_result=HARNESS_ERROR
failure_exit=
phase=preparation
jq -n --argjson count "$samples" '
  [range(1;$count+1) as $round | ["install","remove"][] as $operation |
   ["omg","native"][] as $tool |
   {id:($operation+"-"+$tool+"-"+(("000"+($round|tostring))[-3:])),
    operation:$operation,tool:$tool,round:$round,result:"NOT_RUN",exit_code:null,
    boot_id:null,base_sha256:null}] | sort_by(.id)
' > "$output/results.json"
jq -n '{install:null,remove:null}' > "$output/bases.json"
write_summary() {
  jq -n --arg distro "$distro" --arg phase "$phase" --argjson count "$samples" \
    --argjson complete "$1" --slurpfile rows "$output/results.json" \
    --slurpfile bases "$output/bases.json" '
    {schema_version:2,kind:"transaction-suite",distro:$distro,complete:$complete,
     phase:$phase,samples_per_tool:$count,expected_trials:($count*4),
     bases:$bases[0],results:$rows[0]}
  ' > "$output/summary.next.json"
  mv "$output/summary.next.json" "$output/summary.json"
}
set_result() {
  jq --arg id "$current_id" --arg result "$1" --argjson code "$2" \
    'map(if .id==$id then .result=$result | .exit_code=$code else . end)' \
    "$output/results.json" > "$output/results.next.json"
  mv "$output/results.next.json" "$output/results.json"
}
finish() {
  local code=$?
  trap - EXIT
  if [[ $code != 0 ]]; then
    if [[ -n "$current_id" ]]; then
      set_result "$failure_result" "${failure_exit:-$code}" || printf 'Could not record failed trial\n' >&2
    fi
    write_summary false || printf 'Could not update incomplete summary\n' >&2
  fi
  exit "$code"
}
trap finish EXIT
write_summary false
ssh_guest() { timeout --kill-after=5s 600 ssh "${opts[@]}" bench@127.0.0.1 "$@"; }
remote_argv() {
  local command
  printf -v command '%q ' "$@"
  ssh_guest "$command"
}
stop_guest() {
  local pid state
  pid=$(<qemu.pid)
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  remote_argv sudo -n sync
  remote_argv sudo -n systemctl poweroff || true
  for ((attempt=0;attempt<120;attempt++)); do
    if [[ ! -r "/proc/$pid/stat" ]]; then rm -f qemu.pid; return 0; fi
    if ! state=$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null); then
      if [[ ! -e "/proc/$pid" ]]; then rm -f qemu.pid; return 0; fi
      sleep 1; continue
    fi
    if [[ "$state" == Z || "$state" == X ]]; then rm -f qemu.pid; return 0; fi
    sleep 1
  done
  printf 'QEMU did not stop; refusing to snapshot an active image\n' >&2
  return 1
}
start_clone() {
  local disk=$1 vars=$2 serial=$3 log=$4
  [[ ! -e qemu.pid ]] || return 1
  timeout --kill-after=5s 360 bash /work/boot.sh "${boot_args[@]}" "$disk" "$vars" "$serial" > "$log" 2>&1
}
freeze_base() {
  local source=$1 operation=$2 vars=$3
  [[ ! -e qemu.pid ]] || return 1
  qemu-img convert -f qcow2 -O qcow2 "$source" "$disks/$operation-base.qcow2"
  qemu-img check "$disks/$operation-base.qcow2" > "$output/$operation-base-check.log"
  if [[ "${boot_args[0]}" == uefi ]]; then
    cp "$vars" "$disks/$operation-vars.fd"
    sha256sum "${boot_args[2]}" "$disks/$operation-vars.fd" > "$output/$operation-firmware.sha256"
  fi
  chmod 444 "$disks/$operation-base.qcow2"
  local digest
  digest=$(sha256sum "$disks/$operation-base.qcow2")
  digest=${digest%% *}
  jq --arg operation "$operation" --arg digest "$digest" '.[$operation]=$digest' \
    "$output/bases.json" > "$output/bases.next.json"
  mv "$output/bases.next.json" "$output/bases.json"
}
native_change() {
  local operation=$1
  case "$distro:$operation" in
    arch:install) remote_argv sudo -n pacman -S --noconfirm tree ;;
    arch:remove) remote_argv sudo -n pacman -R --noconfirm tree ;;
    debian:install|ubuntu:install) remote_argv sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y tree ;;
    debian:remove|ubuntu:remove) remote_argv sudo -n env DEBIAN_FRONTEND=noninteractive apt-get remove -y tree ;;
    fedora:install|fedora:remove) remote_argv sudo -n dnf "$operation" -y tree ;;
    *) return 2 ;;
  esac
}
capture_repository_state() {
  local operation=$1
  remote_argv sudo -n bash -c '
    set -euo pipefail
    case "$1" in
      arch) paths=(etc/pacman.conf etc/pacman.d/mirrorlist var/lib/pacman/sync
        var/lib/pacman/local etc/pacman.d/gnupg/pubring.gpg etc/pacman.d/gnupg/trustdb.gpg) ;;
      debian|ubuntu) paths=(etc/apt/sources.list etc/apt/sources.list.d etc/apt/trusted.gpg.d
        var/lib/apt/lists var/lib/dpkg/status var/lib/apt/extended_states) ;;
      fedora) paths=(etc/yum.repos.d etc/dnf/dnf.conf etc/pki/rpm-gpg
        usr/lib/sysimage/rpm var/lib/rpm var/cache/dnf var/cache/libdnf5) ;;
      *) exit 2 ;;
    esac
    present=()
    for path in "${paths[@]}"; do
      if [[ -e "/$path" ]]; then present+=("$path"); printf "%s present\n" "$path" >&2
      else printf "%s absent\n" "$path" >&2; fi
    done
    [[ ${#present[@]} -gt 0 ]]
    tar -C / -czf - -- "${present[@]}"
  ' bash "$distro" > "$output/$operation-repository-state.tar.gz" 2> "$output/$operation-repository-state.log"
  sha256sum "$output/$operation-repository-state.tar.gz" > "$output/$operation-repository-state.sha256"
}
mask_units() {
  remote_argv sudo -n bash -c '
    set -euo pipefail
    for unit do
      state=$(systemctl show --property=LoadState --value "$unit")
      if [[ "$state" == not-found ]]; then printf "%s not installed\n" "$unit"
      else systemctl mask --now "$unit"; fi
    done
  ' bash "$@"
}
# Both tools receive the same base for a given operation. Cache state is inherited,
# not described as cold, and no guest boot or SSH time enters Hyperfine.
case "$distro" in
  debian|ubuntu)
    mask_units apt-daily.service apt-daily-upgrade.service \
      apt-daily.timer apt-daily-upgrade.timer > "$output/automatic-updates.log" 2>&1 ;;
  fedora)
    mask_units dnf-makecache.timer dnf-makecache.service dnf-automatic.timer \
      dnf-automatic-install.timer dnf-automatic-download.timer dnf5-automatic.timer \
      dnf5-makecache.timer dnf5-makecache.service > "$output/automatic-updates.log" 2>&1 ;;
  arch)
    mask_units paccache.timer paccache.service > "$output/automatic-updates.log" 2>&1 ;;
esac
native_change install > "$output/prepare-remove.log" 2>&1
case "$distro" in
  arch) version=$(remote_argv pacman -Q tree); version=${version#tree } ;;
  debian|ubuntu) version=$(remote_argv dpkg-query -W '-f=${Version}\n' tree) ;;
  fedora) version=$(remote_argv rpm -q --qf '%{VERSION}-%{RELEASE}\n' tree) ;;
esac
[[ "$version" =~ ^[A-Za-z0-9][A-Za-z0-9.:+~_-]*$ ]] || exit 1
printf '%s\n' "$version" > "$output/expected-version.txt"
capture_repository_state remove
stop_guest > "$output/stop-prepared-remove.log" 2>&1
freeze_base overlay.qcow2 remove vars.fd
qemu-img create -f qcow2 -F qcow2 -b "$disks/remove-base.qcow2" "$disks/prepare-install.qcow2"
if [[ "${boot_args[0]}" == uefi ]]; then cp "$disks/remove-vars.fd" "$disks/prepare-vars.fd"; fi
start_clone "$disks/prepare-install.qcow2" "$disks/prepare-vars.fd" "$output/prepare-install-serial.log" "$output/prepare-install-boot.log"
native_change remove > "$output/prepare-install.log" 2>&1
capture_repository_state install
stop_guest > "$output/stop-prepared-install.log" 2>&1
freeze_base "$disks/prepare-install.qcow2" install "$disks/prepare-vars.fd"
rm -f "$disks/prepare-install.qcow2" "$disks/prepare-vars.fd"
: > "$output/boot-ids.txt"
for operation in install remove; do
  base="$disks/$operation-base.qcow2"
  digest=$(jq -er --arg operation "$operation" '.[$operation]' "$output/bases.json")
  for ((round=1;round<=samples;round++)); do
    tools=(omg native)
    if ((round % 2 == 0)); then tools=(native omg); fi
    for tool in "${tools[@]}"; do
      printf -v current_id '%s-%s-%03d' "$operation" "$tool" "$round"
      trial="$output/trials/$current_id"
      mkdir "$trial"
      phase=boot
      failure_result=HARNESS_ERROR; failure_exit=
      set_result INCOMPLETE null
      write_summary false
      disk="$disks/$current_id.qcow2"
      vars="$disks/$current_id.fd"
      qemu-img create -f qcow2 -F qcow2 -b "$base" "$disk" > "$trial/disk-create.log"
      if [[ "${boot_args[0]}" == uefi ]]; then cp "$disks/$operation-vars.fd" "$vars"; fi
      start_clone "$disk" "$vars" "$trial/serial.log" "$trial/boot.log"
      boot_id=$(remote_argv cat /proc/sys/kernel/random/boot_id)
      [[ "$boot_id" =~ ^[0-9a-f-]{36}$ ]] || exit 1
      if grep -Fxq "$boot_id" "$output/boot-ids.txt"; then
        printf 'Repeated boot identity: reset not proven\n' >&2; exit 1
      fi
      printf '%s\n' "$boot_id" >> "$output/boot-ids.txt"
      jq --arg id "$current_id" --arg boot "$boot_id" --arg digest "$digest" \
        'map(if .id==$id then .boot_id=$boot | .base_sha256=$digest else . end)' \
        "$output/results.json" > "$output/results.next.json"
      mv "$output/results.next.json" "$output/results.json"
      token=$(remote_argv cat /proc/sys/kernel/random/uuid)
      printf '%s\n' "$token" | ssh_guest 'sudo -n tee /run/omg-qemu-benchmark >/dev/null; sudo -n chmod 444 /run/omg-qemu-benchmark'
      phase=measurement
      code=0
      remote_argv env "OMG_BENCH_BINARY=$bin" \
        'OMG_BENCH_EXPORT_DIR=/home/bench/evidence/transaction-trial' \
        "OMG_BENCH_DISPOSABLE_GUEST=$token" "OMG_BENCH_EXPECTED_VERSION=$version" \
        bash /home/bench/benchmark-hyperfine.sh --guest-transaction "$operation" "$tool" \
        > "$trial/guest.log" 2>&1 || code=$?
      printf '%s\n' "$code" > "$trial/driver.exit"
      timeout --kill-after=5s 120 scp "${scp_opts[@]}" -r \
        bench@127.0.0.1:/home/bench/evidence/transaction-trial "$trial/" > "$trial/copy.log" 2>&1
      evidence="$trial/transaction-trial"
      if [[ "$code" != 0 ]]; then
        expected_label=OMG
        if [[ "$tool" == native ]]; then
          case "$distro" in arch) expected_label=pacman ;; debian|ubuntu) expected_label=apt ;; fedora) expected_label=dnf ;; esac
        fi
        # Only an identified command receipt proves a workload failure. Reserved
        # execution/timeout/signal codes and missing evidence remain harness errors.
        raw="$evidence/$operation.json"
        if [[ -f "$raw" && $(wc -c < "$raw") -le 1048576 ]] &&
           jq -e --arg expected "$expected_label" '
             .results|length==1 and .[0].command==$expected and
             (.[0].times|length==1) and (.[0].exit_codes|length==1) and
             (.[0].exit_codes[0]|type=="number" and floor==. and .>0 and .<124)
           ' "$raw" >/dev/null; then
          failure_result=FAIL
          failure_exit=$(jq -r '.results[0].exit_codes[0]' "$raw")
          phase=measurement-command
          exit 10
        fi
        exit 1
      fi
      phase=verification
      python3 /work/record-benchmark-run.py --validate-only --scenario "$operation" --source "$evidence" > "$trial/validation.log" 2>&1
      jq -e --arg distro "$distro" --arg operation "$operation" --arg tool "$tool" --arg boot "$boot_id" \
        '.schema_version==2 and .kind=="transaction-trial" and .complete==true and
         .distro==$distro and .operation==$operation and .tool==$tool and .boot_id==$boot and
         .state_change_verified==true and .manual_state_change_verified==true and .samples==1 and .warmup==0' "$evidence/summary.json" >/dev/null
      if [[ -f "$output/$operation-before.tsv" ]]; then
        cmp "$output/$operation-before.tsv" "$evidence/installed-before.tsv"
      else cp "$evidence/installed-before.tsv" "$output/$operation-before.tsv"; fi
      if [[ -f "$output/$operation-manual-before.names" ]]; then
        cmp "$output/$operation-manual-before.names" "$evidence/manual-before.names"
      else cp "$evidence/manual-before.names" "$output/$operation-manual-before.names"; fi
      phase=cleanup
      remote_argv sudo -n python3 - collect < /work/check-qemu-health.py \
        > "$trial/health.json" 2> "$trial/health.log"
      python3 /work/check-qemu-health.py verify-trial --guest "$trial/health.json" \
        --serial "$trial/serial.log" --boot-id "$boot_id" >> "$trial/health.log" 2>&1
      stop_guest > "$trial/stop.log" 2>&1
      rm -f "$disk" "$vars"
      set_result PASS 0
      write_summary false
      current_id=
    done
  done
  printf '%s  %s\n' "$digest" "$base" | sha256sum --check > "$output/$operation-base-unchanged.log"
done
# Return a live, tree-absent guest to the inventory coordinator. These disks are
# owned disposable state and are removed by its teardown after the controller.
phase=restore
qemu-img create -f qcow2 -F qcow2 -b "$disks/install-base.qcow2" "$disks/resume.qcow2" > "$output/resume-disk.log"
if [[ "${boot_args[0]}" == uefi ]]; then cp "$disks/install-vars.fd" "$disks/resume.fd"; fi
start_clone "$disks/resume.qcow2" "$disks/resume.fd" "$output/resume-serial.log" "$output/resume-boot.log"
phase=complete
jq -e --argjson expected "$((samples*4))" \
  'length==$expected and all(.[];.result=="PASS") and ([.[].boot_id]|unique|length)==$expected' \
  "$output/results.json" >/dev/null
write_summary true
