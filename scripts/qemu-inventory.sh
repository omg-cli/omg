#!/usr/bin/env bash
# qemu-inventory.sh â€” drive tests/cli_behavior_inventory.tsv rows inside a
# running QEMU guest over SSH and record machine-readable evidence.
#
# The guest must already be up (see scripts/benchmark-qemu.sh, which calls
# this when --inventory-tiers is set). Rows run in file order so the
# TSV `requires` DAG is satisfied naturally. Disposable guests make
# package/service-mutation rows safe, but they still need --allow-mutations.
set -euo pipefail
# BEGIN PRODUCT OUTPUT ORACLE
# This exact function is sent to the guest and exercised by fault-injection tests.
check_hook_lifecycle() (
  # Execute the installed scripts unchanged in a disposable second repository.
  local hooks=$1 fixture output
  fixture=$(mktemp -d) || exit 1
  trap 'rm -rf -- "$fixture"' EXIT
  cd "$fixture" || exit 1
  export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
  hook_git() {
    git -c user.name='OMG fixture' -c user.email=fixture@example.invalid \
      -c commit.gpgsign=false -c core.hooksPath="$hooks" "$@"
  }
  expect_notice() {
    local expected=$1 message=$2
    shift 2
    output=$(hook_git "$@" 2>&1) || { printf 'assertion failed: Git operation %s: %s\n' "$*" "$output" >&2; return 1; }
    if { [[ "$expected" == yes ]] && [[ "$output" != *"$message"* ]]; } \
      || { [[ "$expected" == no ]] && [[ "$output" == *"$message"* ]]; }; then
      printf 'assertion failed: hook notice expected=%s during %s: %s\n' "$expected" "$*" "$output" >&2; return 1
    fi
  }
  hook_git init -q -b baseline || exit 1
  printf 'baseline\n' > omg.lock
  hook_git add omg.lock || exit 1
  expect_notice no 'omg.lock has unstaged changes' commit -qm baseline || exit 1
  printf 'changed\n' > omg.lock
  expect_notice yes 'omg.lock has unstaged changes' commit --allow-empty -m unstaged || exit 1
  [[ $(hook_git show HEAD:omg.lock) == baseline ]] || exit 1
  hook_git checkout -qb changed || exit 1
  hook_git add omg.lock || exit 1
  expect_notice no 'omg.lock has unstaged changes' commit -qm changed || exit 1
  [[ $(hook_git show HEAD:omg.lock) == changed ]] || exit 1
  expect_notice yes 'Environment changed on branch switch' checkout baseline || exit 1
  expect_notice no 'Environment changed on branch switch' checkout baseline || exit 1
  printf 'working tree edit\n' > omg.lock
  expect_notice no 'Environment changed on branch switch' checkout -- omg.lock || exit 1
  expect_notice yes 'Environment changed after merge' merge --ff-only changed || exit 1
  [[ $(cat omg.lock) == changed ]] || exit 1
  expect_notice no 'Environment changed after merge' merge --ff-only changed || exit 1
)
check_product_output() {
  local safety=$1 assertion=$2 code=$3 stdout=$4 stderr=$5
  if grep -Eq 'panicked at|thread .main. panicked' "$stdout" "$stderr"; then
    printf 'assertion failed: product emitted a panic report\n' >&2; return 1
  fi
  if [[ "$safety" == help-boundary ]] && ! grep -Fq 'Usage:' "$stdout"; then
    printf 'assertion failed: help output lacks Usage\n' >&2; return 1
  fi
  if [[ "$code" != 0 ]] && ! grep -q '[^[:space:]]' "$stderr"; then
    printf 'assertion failed: product refusal lacks its own stderr explanation\n' >&2; return 1
  fi
  if [[ "$code" == 0 ]]; then
    case "$assertion" in
      hooks-installed|hooks-absent)
        local hook label hook_path
        for hook in pre-commit post-checkout post-merge; do
          hook_path=".git/hooks/$hook"
          if [[ "$assertion" == hooks-absent ]]; then
            if [[ -e "$hook_path" || -L "$hook_path" ]]; then
              printf 'assertion failed: removed hook remains: %s\n' "$hook" >&2; return 1
            fi
          else
            case "$hook" in pre-commit) label=Pre-commit ;; post-checkout) label=Post-checkout ;; post-merge) label=Post-merge ;; esac
            if [[ ! -f "$hook_path" || -L "$hook_path" || ! -x "$hook_path" ]] \
              || ! grep -Fxq "# OMG $label Hook" "$hook_path" || ! sh -n "$hook_path"; then
              printf 'assertion failed: installed hook is missing, invalid, or not executable: %s\n' "$hook" >&2; return 1
            fi
          fi
        done
        if [[ "$assertion" == hooks-installed ]] && ! check_hook_lifecycle "$PWD/.git/hooks"; then
          printf 'assertion failed: installed hook lifecycle contract\n' >&2; return 1
        fi ;;
      workspace-filtered-output|workspace-all-output)
        local primary nested expected_nested=0
        primary=$(grep -Fxc 'smoke-task-ok' "$stdout" || true)
        nested=$(grep -Fxc 'nested-smoke-task-ok' "$stdout" || true)
        [[ "$assertion" != workspace-all-output ]] || expected_nested=1
        if [[ "$primary" != 1 || "$nested" != "$expected_nested" ]]; then
          printf 'assertion failed: workspace task counts primary=%s nested=%s; expected primary=1 nested=%s\n' "$primary" "$nested" "$expected_nested" >&2; return 1
        fi ;;
      json-stdout)
        if ! jq -e -s 'length == 1' "$stdout" >/dev/null 2>&1; then
          printf 'assertion failed: stdout is not exactly one JSON document\n' >&2; return 1
        fi ;;
      artifact:*)
        local artifact=${assertion#artifact:}
        if [[ ! -f "$artifact" || -L "$artifact" ]] || ! jq -e -s 'length == 1' "$artifact" >/dev/null 2>&1; then
          printf 'assertion failed: artifact %s is not a regular JSON document\n' "$artifact" >&2; return 1
        fi ;;
    esac
  fi
  return 0
}
# END PRODUCT OUTPUT ORACLE
# BEGIN ROW LOG
write_row_log() {
  local destination=$1 stdout=$2 stderr=$3 identity=$4 verdict=$5
  {
    printf 'case=%s verdict=%s\n' "$identity" "$verdict"
    # The trusted reporter bounds excerpts. Keep the diagnosis ahead of large
    # JSON/list output, retaining the complete streams for artifact inspection.
    grep -m 4 '^assertion failed:' "$stderr" || true
    printf '\nstderr:\n'
    cat "$stderr"
    printf '\nstdout:\n'
    cat "$stdout"
  } > "$destination"
}
# END ROW LOG
trap 'rc=$?; if [[ "$rc" == 2 ]]; then printf "error: invalid inventory configuration or row %s\n" "${id:-<preflight>}" >&2; fi' EXIT

work=""; distro=""; tiers=""; tag=""; binary=""; tsv=""
allow_mutations=false
allow_credentialed=false
isolate_hermetic=false
network_scope=unconfined
network_policy=""
row_timeout=120
ssh_port=2222
ssh_user=bench
while (($#)); do
  case "$1" in
    --work|--distro|--tiers|--tag|--binary|--tsv|--row-timeout|--ssh-port|--ssh-user|--network-policy)
      [[ $# -ge 2 && -n "$2" ]] || exit 2
      case "$1" in
        --work) work=$2 ;; --distro) distro=$2 ;; --tiers) tiers=$2 ;;
        --tag) tag=$2 ;; --binary) binary=$2 ;; --tsv) tsv=$2 ;;
        --network-policy) network_policy=$2 ;;
        --row-timeout) row_timeout=$2 ;; --ssh-port) ssh_port=$2 ;; --ssh-user) ssh_user=$2 ;;
      esac
      shift 2 ;;
    --allow-mutations) allow_mutations=true; shift ;;
    --allow-credentialed) allow_credentialed=true; shift ;;
    --isolate-hermetic) isolate_hermetic=true; shift ;;
    --help) printf 'Usage: qemu-inventory.sh --work DIR --distro D --tiers CSV --tag TAG --binary GUEST_PATH --tsv FILE [--allow-mutations] [--allow-credentialed] [--row-timeout S]\nRuns TSV-selected rows in the guest at 127.0.0.1 and writes evidence.\n'; exit 0 ;;
    *) printf 'error: unknown argument %s\n' "$1" >&2; exit 2 ;;
  esac
done
[[ -n "$work" && -n "$distro" && -n "$tiers" && -n "$tag" && -n "$binary" && -n "$tsv" ]] || exit 2
[[ "$row_timeout" =~ ^[0-9]+$ && "$row_timeout" -gt 0 ]] || exit 2
case "$distro" in arch|debian|ubuntu|fedora) ;; *) exit 2 ;; esac
for tool in ssh jq timeout sha256sum; do command -v "$tool" >/dev/null || exit 3; done
overlap_fixture=$(jq -rn --rawfile fixture "$(dirname "$0")/workspace-overlap-fixture.sh" '$fixture | @sh')
[[ "$binary" == /* && "$binary" != *$'\n'* ]] || exit 2
[[ "$ssh_user" =~ ^[a-z_][a-z0-9_-]*$ && "$ssh_port" =~ ^[0-9]+$ ]] || exit 2
[[ "$tiers" =~ ^[a-z,-]+$ && "$tiers" != ,* && "$tiers" != *, && "$tiers" != *,,* ]] || exit 2
IFS=',' read -ra requested_tiers <<< "$tiers"
for tier in "${requested_tiers[@]}"; do
  case "$tier" in hermetic|container|qemu|network|credentialed|pty|nested-container) ;; *) exit 2 ;; esac
done
[[ -f "$tsv" ]] || exit 2
scopes='{}'
if [[ "$isolate_hermetic" == true ]]; then
  [[ -f "$network_policy" && ! -L "$network_policy" && $(wc -c < "$network_policy") -le 1048576 ]] || exit 2
  inventory_digest=$(sha256sum "$tsv"); inventory_digest=${inventory_digest%% *}
  scopes=$(jq -ce --arg digest "$inventory_digest" '
    .inventories[$digest].cases | select(type=="array" and length>0) |
    if all(.[]; .network_scope=="offline" or .network_scope=="network") then
      map({key:.id,value:.network_scope}) | from_entries else error("invalid network scope") end' "$network_policy")
fi

root=$(cd "$work" && pwd)
guest="$root/guest"
out="$root/inventory"
# Refuse to overwrite evidence from a previous invocation.
[[ ! -e "$out" ]] || { printf 'error: inventory evidence already exists: %s\n' "$out" >&2; exit 2; }
mkdir -p "$out/rows"
sha256sum "${BASH_SOURCE[0]}" "$tsv" > "$out/input-sha256.txt"
jq -n --arg release "$tag" --arg distro "$distro" --arg tiers "$tiers" --arg binary "$binary" \
  --argjson mutations "$allow_mutations" --argjson credentialed "$allow_credentialed" --argjson deadline "$row_timeout" \
  '{release:$release,distro:$distro,tiers:$tiers,binary:$binary,allow_mutations:$mutations,allow_credentialed:$credentialed,row_timeout_seconds:$deadline}' > "$out/metadata.json"
# -n keeps ssh from forwarding (and draining) this loop's stdin, which is the
# TSV stream: without it only the first tier-matching row ever executes.
opts=(-n -i "$guest/client-key" -p "$ssh_port" -o BatchMode=yes -o ConnectTimeout=5
  -o ServerAliveInterval=5 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=yes
  -o UserKnownHostsFile="$guest/known_hosts")
target="$ssh_user@127.0.0.1"

# Selected tiers as comma-wrappedneedle, same idiom as release-smoke.sh.
want=",$tiers,"
# Publish each completed row atomically so an outer deadline cannot erase
# observed failures. Completion is a separate, last-written receipt.
summary_tmp="$out/results.json"
printf '[]' > "$summary_tmp"
printf '{"complete":false}\n' > "$out/summary.json"
pass=0; fail=0; skipped=0
record() { # case_id result exit_code elapsed
  local entry
  entry=$(jq -n --arg c "$1" --arg d "$distro" --arg r "$2" --argjson e "$3" --argjson s "$4" --arg scope "$network_scope" \
    '{case_id:$c, distro:$d, result:$r, artifact_source:"inventory", exit_code:$e, elapsed_seconds:$s, network_scope:$scope}')
  jq --slurpfile e <(printf '%s' "$entry") '. + [$e[0]]' "$summary_tmp" > "$summary_tmp.next"
  mv "$summary_tmp.next" "$summary_tmp"
}

# Prerequisite lookup for requires-chain replay (see below): id to the
# columns the skip gates need. Loaded once; the main loop streams the TSV
# a second time via process substitution.
resolve_exit() {
  local cell=$1 entry key seen=, value=""
  if [[ "$cell" =~ ^(0|[1-9][0-9]{0,2})$ ]] && ((cell <= 255)); then printf '%s' "$cell"; return; fi
  [[ "$cell" != *, ]] || return 1
  local entries=()
  IFS=',' read -ra entries <<< "$cell"
  for entry in "${entries[@]}"; do
    [[ "$entry" =~ ^(arch|debian|ubuntu|fedora):(0|[1-9][0-9]{0,2})$ ]] || return 1
    key=${entry%%:*}
    [[ "$seen" != *",$key,"* ]] && (( ${entry#*:} <= 255 )) || return 1
    seen+="$key,"
    [[ "$key" != "$distro" ]] || value=${entry#*:}
  done
  [[ ${#entries[@]} == 4 && -n "$value" ]] || return 1
  printf '%s' "$value"
}

# Validate the complete input before any guest action. Requires must point
# backwards, which rejects missing dependencies and cycles without a depth cap.
IFS= read -r header < "$tsv"
[[ "$header" == $'case\targs_json\tsafety\texpected_exit\texpected_ux\trequires\ttier\ttargets\tassertions\tcleanup' ]] || exit 2
awk -F '\t' 'NR > 1 { if (NF != 10) exit 1; for (i = 1; i <= NF; i++) if ($i == "") exit 1 }' "$tsv" || exit 2
declare -A row_args=() row_requires=() row_tier=() row_safety=() row_ux=() row_exit=() row_targets=() row_assertions=()
while IFS=$'\t' read -r id aj s e u r t tg a _cleanup; do
  [[ "$id" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ && -z "${row_args[$id]:-}" ]] || exit 2
  [[ "$r" == - || "$r" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ ]] || exit 2
  [[ "$r" == - || -n "${row_args[$r]:-}" ]] || exit 2
  jq -e 'type == "array" and length > 0 and all(.[]; type == "string" and (explode | index(0) == null))' <<< "$aj" >/dev/null || exit 2
  case "$s" in read|isolated-write|controlled-error|help-boundary|interactive|package-mutation|service-mutation) ;; *) exit 2 ;; esac
  case "$u" in pass|declared) ;; *) exit 2 ;; esac
  [[ "$t" != *, && "$t" != ,* && "$t" != *,,* ]] || exit 2
  IFS=',' read -ra input_tiers <<< "$t"
  for input_tier in "${input_tiers[@]}"; do
    case "$input_tier" in hermetic|container|qemu|network|credentialed|pty|nested-container) ;; *) exit 2 ;; esac
  done
  if [[ "$tg" != hermetic:pass ]]; then
    [[ "$tg" != *, ]] || exit 2
    IFS=',' read -ra input_targets <<< "$tg"
    seen_targets=,
    for input_target in "${input_targets[@]}"; do
      [[ "$input_target" =~ ^(arch|debian|ubuntu|fedora):(pass|pending|known-defect)$ ]] || exit 2
      target_distro=${input_target%%:*}
      [[ "$seen_targets" != *",$target_distro,"* ]] || exit 2
      seen_targets+="$target_distro,"
    done
  fi
  resolved=""
  if [[ "$u" != declared ]]; then resolved=$(resolve_exit "$e") || exit 2; fi
  case "$a" in -|json-stdout|hooks-installed|hooks-absent|workspace-filtered-output|workspace-all-output|artifact:manifest.json|artifact:privacy.json|artifact:sbom.json) ;; *) exit 2 ;; esac
  row_args["$id"]="$aj"; row_requires["$id"]="$r"
  row_tier["$id"]="$t"; row_safety["$id"]="$s"; row_ux["$id"]="$u"
  row_exit["$id"]="$resolved"; row_targets["$id"]="$tg"; row_assertions["$id"]="$a"
done < <(tail -n +2 "$tsv")

# Replay only prerequisites permitted by the same target and safety gates.
# A gated prerequisite blocks the dependent row instead of running it without
# the required state.
prereq_runnable() { # id -> 0 when replayable
  local id=$1 t
  [[ -n "${row_args[$id]:-}" ]] || return 1
  [[ "${row_ux[$id]}" != declared ]] || return 1
  [[ "${row_targets[$id]}" == hermetic:pass || ",${row_targets[$id]}," == *",$distro:pass,"* || ",${row_targets[$id]}," == *",$distro:known-defect,"* ]] || return 1
  local hit=false
  IFS=',' read -ra tier_list <<< "${row_tier[$id]}"
  for t in "${tier_list[@]}"; do
    if [[ "$want" == *",$t,"* ]]; then hit=true; break; fi
  done
  [[ "$hit" == true ]] || return 1
  if [[ ",${row_tier[$id]}," == *",credentialed,"* && "$allow_credentialed" == false ]]; then return 1; fi
  case "${row_safety[$id]}" in
    interactive) return 1 ;;
    package-mutation|service-mutation)
      [[ "$allow_mutations" == true ]] || return 1 ;;
  esac
  return 0
}

# Process substitution (not a pipeline): pass/fail counters below must
# survive the loop; a `tail | while` pipeline would trap them in a subshell.
while IFS=$'\t' read -r case args_json safety _expected_exit expected_ux requires tier targets assertions _cleanup; do
  # Case ids flow into a remote shell command below: reject anything
  # outside the identifier shape instead of executing it.
  if [[ ! "$case" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ ]]; then
    printf 'case=%s invalid identifier\n' "$case"
    # Sanitized id: one bad TSV row must fail loudly without poisoning
    # the whole results file for the downstream schema gate.
    safe="invalid-$(printf '%s' "$case" | tr -c 'a-z0-9-' '-' | cut -c1-80)"
    record "qemu-$distro-$safe" FAIL -1 0; fail=$((fail+1)); continue
  fi
  # Tier filter (tiers are comma-separated in the TSV too).
  hit=false
  IFS=',' read -ra tier_list <<< "$tier"
  for t in "${tier_list[@]}"; do
    if [[ "$want" == *",$t,"* ]]; then hit=true; break; fi
  done
  if [[ "$hit" == false ]]; then continue; fi
  network_scope=unconfined
  if [[ "$isolate_hermetic" == true ]]; then
    network_scope=$(jq -er --arg id "$case" '.[$id]' <<< "$scopes")
  fi
  # Declaration-only rows are parse-level, covered by cli_comprehensive.
  if [[ "$expected_ux" == declared ]]; then
    record "qemu-$distro-$case" SKIPPED -1 0; skipped=$((skipped+1)); continue
  fi
  # Per-distro target status.
  status=""
  if [[ "$targets" == hermetic:pass ]]; then status=pass
  else
    IFS=',' read -ra target_list <<< "$targets"
    for t in "${target_list[@]}"; do
      if [[ "$t" == "$distro:"* ]]; then status="${t#*:}"; break; fi
    done
  fi
  if [[ -z "$status" || "$status" == pending ]]; then
    record "qemu-$distro-$case" SKIPPED -1 0; skipped=$((skipped+1)); continue
  fi
  case "$status" in pass|known-defect) ;; *) record "qemu-$distro-$case" HARNESS_ERROR -1 0; fail=$((fail+1)); continue ;; esac
  # Credentialed rows need a real token in the guest: never run them
  # without an explicit opt-in (tiers match by substring, so "network"
  # would otherwise select "network,credentialed" rows).
  if [[ ",$tier," == *",credentialed,"* && "$allow_credentialed" == false ]]; then
    record "qemu-$distro-$case" SKIPPED -1 0; skipped=$((skipped+1)); continue
  fi
  # Safety gate.
  case "$safety" in
    interactive) record "qemu-$distro-$case" SKIPPED -1 0; skipped=$((skipped+1)); continue ;;
    package-mutation|service-mutation)
      if [[ "$allow_mutations" == false ]]; then
        record "qemu-$distro-$case" SKIPPED -1 0; skipped=$((skipped+1)); continue
      fi ;;
  esac
  chain=()
  next="$requires"
  blocked=false
  while [[ "$next" != - ]]; do
    if ! prereq_runnable "$next"; then blocked=true; break; fi
    if [[ "$network_scope" == offline && $(jq -r --arg id "$next" '.[$id]' <<< "$scopes") != offline ]]; then
      blocked=true; break
    fi
    chain=("$next" "${chain[@]}")
    next="${row_requires[$next]}"
  done
  if [[ "$blocked" == true ]]; then
    printf 'dependency %s is gated\n' "$next" > "$out/rows/$case.log"
    record "qemu-$distro-$case" BLOCKED -1 0; fail=$((fail+1)); continue
  fi

  # Quote each literal segment, substituting only the documented ROOT token.
  # No eval or shell expansion of inventory argument text is permitted.
  quote_args() {
    jq -r '[.[] | if . == "" then @sh else split("${ROOT}") | map(@sh) | join("\"$rowdir\"") end] | join(" ")' <<< "$1"
  }
  quoted_binary=$(jq -rn --arg b "$binary" '$b | @sh')
  quoted_binary_dir=$(jq -rn --arg b "${binary%/*}" '$b | @sh')
  remote="set -eu; rowdir=\$(mktemp -d \"\$HOME/inventory-$case.XXXXXX\"); cd \"\$rowdir\""
  remote+="; export NO_COLOR=1 LC_ALL=C GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 PATH=$quoted_binary_dir:\"\$PATH\"; git init -q; printf 'smoke:\n\t@echo smoke-task-ok\noverlap:\n\t@sh workspace-overlap.sh . primary\n' > Makefile"
  remote+="; printf '%s' $overlap_fixture > workspace-overlap.sh"
  remote+="; mkdir -p project; printf '# Nested audit fixture\n' > project/README.md"
  remote+="; printf 'smoke:\n\t@echo nested-smoke-task-ok\noverlap:\n\t@sh ../workspace-overlap.sh .. nested\n' > project/Makefile"
  remote+="; command -v jq >/dev/null; command -v grep >/dev/null; $(declare -f check_hook_lifecycle); $(declare -f check_product_output)"
  # The supervisor exits zero after recording a completed CLI's status.
  # Thus a CLI exit 125 cannot be mistaken for timeout's own exit 125.
  supervisor=$(jq -rn --arg s 'rc=0; "$@" 3>&- || rc=$?; printf "%s\n" "$rc" >&3' '$s | @sh')
  remote+="; status_file=\$(mktemp \"\$HOME/inventory-status.XXXXXX\"); trap 'rm -f \"\$status_file\"' EXIT"
  remote+="; run_omg() { execution_phase=executor; rc=0; timeout --kill-after=5s '$row_timeout' bash -c $supervisor _ \"\$@\" 3>\"\$status_file\" || rc=\$?; if [ \"\$rc\" = 0 ]; then if IFS= read -r rc < \"\$status_file\"; then execution_phase=product; else rc=125; fi; fi; }"
  for p in "${chain[@]}"; do
    pargs=$(quote_args "${row_args[$p]}")
    remote+="; run_omg $quoted_binary $pargs > '$p.prereq.log' 2> '$p.prereq.stderr.log'"
    remote+="; printf 'prereq $p exit=%s\n' \"\$rc\" >&2; cat '$p.prereq.log' '$p.prereq.stderr.log' >&2"
    remote+="; if [ \"\$rc\" != '${row_exit[$p]}' ] || [ \"\$execution_phase\" != product ]; then printf '\nOMG_QEMU_RECEIPT:dependency:%s:0\n' \"\$rc\"; exit 0; fi"
    remote+="; if ! check_product_output '${row_safety[$p]}' '${row_assertions[$p]}' \"\$rc\" '$p.prereq.log' '$p.prereq.stderr.log'; then printf '\nOMG_QEMU_RECEIPT:dependency:%s:1\n' \"\$rc\"; exit 0; fi"
  done
  if [[ "$case" == hooks-install-force ]]; then
    # An identical reinstall cannot prove --force is honored. Replace each
    # generated prerequisite hook with user content and non-executable mode;
    # the normal installed-hook oracle must observe real replacement.
    remote+="; for hook in pre-commit post-checkout post-merge; do printf '#!/bin/sh\\n# user-owned hook fixture\\nexit 23\\n' > \".git/hooks/\$hook\"; chmod 640 \".git/hooks/\$hook\"; done"
  fi
  arg_string=$(quote_args "$args_json")
  remote+="; run_omg $quoted_binary $arg_string > command.stdout.log 2> command.stderr.log; assertion=0"
  remote+="; cat command.stdout.log; cat command.stderr.log >&2"
  remote+="; if ! check_product_output '$safety' '$assertions' \"\$rc\" command.stdout.log command.stderr.log; then assertion=1; fi"
  # A receipt is emitted only after setup and the command complete. SSH
  # transport/tool failures cannot satisfy an expected product refusal.
  remote+="; printf '\nOMG_QEMU_RECEIPT:%s:%s:%s\n' \"\$execution_phase\" \"\$rc\" \"\$assertion\""
  remote="bash -c $(jq -rn --arg s "$remote" '$s | @sh')"
  if [[ "$network_scope" == offline ]]; then
    # Put the supervisor AND its receipt inside the namespace. A namespace
    # setup failure must be a transport/harness error, never an expected CLI
    # refusal. Drop back to the SSH user before creating fixtures or running OMG.
    remote="sudo -n unshare --net -- setpriv --reuid=\"\$(id -u)\" --regid=\"\$(id -g)\" --clear-groups --no-new-privs --bounding-set=-all --inh-caps=-all --ambient-caps=-all env HOME=\"\$HOME\" USER='$ssh_user' LOGNAME='$ssh_user' $remote"
  fi
  start=$SECONDS
  transport=0
  budget=$(( (row_timeout + 5) * (${#chain[@]} + 1) + 15 ))
  timeout --kill-after=5s "$budget" ssh "${opts[@]}" "$target" "$remote" > "$out/rows/$case.stdout.log" 2> "$out/rows/$case.stderr.log" || transport=$?
  elapsed=$((SECONDS - start))
  verdict=HARNESS_ERROR; rc=$transport
  receipt=$(tail -n 1 "$out/rows/$case.stdout.log")
  if [[ "$transport" == 0 && "$receipt" =~ ^OMG_QEMU_RECEIPT:(product|executor|dependency):([0-9]{1,3}):([01])$ ]]; then
    phase=${BASH_REMATCH[1]}; rc=${BASH_REMATCH[2]}; assertion_rc=${BASH_REMATCH[3]}
    verdict=FAIL
    if [[ "$phase" == dependency ]]; then verdict=BLOCKED
    elif [[ "$phase" == executor ]]; then
      [[ "$rc" == 124 || "$rc" == 137 ]] || verdict=HARNESS_ERROR
    elif [[ "$rc" == "${row_exit[$case]}" && "$assertion_rc" == 0 ]]; then
      verdict=PASS
      if [[ "$assertions" == json-stdout && "$rc" == 0 ]]; then
        head -n -1 "$out/rows/$case.stdout.log" | jq -e -s 'length == 1' >/dev/null 2>&1 || verdict=FAIL
      fi
    fi
  fi
  write_row_log "$out/rows/$case.log" "$out/rows/$case.stdout.log" "$out/rows/$case.stderr.log" "$case" "$verdict"
  record "qemu-$distro-$case" "$verdict" "$rc" "$elapsed"
  if [[ "$verdict" == PASS ]]; then pass=$((pass+1)); else fail=$((fail+1)); fi
  printf 'case=%s exit=%s verdict=%s\n' "$case" "$rc" "$verdict"
done < <(tail -n +2 "$tsv")
if ((pass + fail == 0)); then
  record "qemu-$distro-inventory-selection" HARNESS_ERROR -1 0
  fail=$((fail+1))
fi
printf '{"complete":true,"pass":%s,"fail":%s,"skipped":%s}\n' "$pass" "$fail" "$skipped" > "$out/summary.json.next"
mv "$out/summary.json.next" "$out/summary.json"
cat "$out/summary.json"
[[ "$fail" -eq 0 ]]
