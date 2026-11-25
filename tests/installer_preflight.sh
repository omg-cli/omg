#!/usr/bin/env bash
# Check the real executable probe using bounded, disposable command fixtures.
set -euo pipefail
cd "$(dirname "$0")/.."
task_dir=$(mktemp -d)
sed '$d' install.sh > "$task_dir/functions.sh"
set --
OMG_UNINSTALL=0 INSTALL_DIR="$task_dir/no-install" source "$task_dir/functions.sh"
trap 'rm -rf "$task_dir"' EXIT

cat > "$task_dir/candidate" <<'CANDIDATE'
#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == --version ]]
line="$FIXTURE_NAME 1.2.3"
case "$FIXTURE_SCENARIO" in
  clean) printf '%s\n' "$line" ;;
  warning)
    printf '%s\n' 'benign startup warning' >&2
    printf '%s\n' "$line" ;;
  stderr-only) printf '%s\n' "$line" >&2 ;;
  closed-stdin)
    if IFS= read -r ignored; then exit 23; fi
    printf '%s\n' "$line" ;;
  wrong-name) printf 'other 1.2.3\n' ;;
  wrong-version) printf '%s 1.2.2\n' "$FIXTURE_NAME" ;;
  extra-line) printf '%s\n%s\n' "$line" extra ;;
  empty) : ;;
  binary-output) printf '%s\000\n' "$line" ;;
  nonzero) printf 'executable startup failed\n' >&2; exit 23 ;;
  stdout-limit | stdout-over-limit)
    length=4096
    [[ "$FIXTURE_SCENARIO" != stdout-over-limit ]] || length=4097
    printf '%s' "$line"
    head -c "$((length - ${#line}))" /dev/zero | tr '\000' '\n' ;;
  stderr-limit | stderr-over-limit | kernel-bound)
    length=4096
    case "$FIXTURE_SCENARIO" in
      stderr-over-limit) length=4097 ;;
      kernel-bound) length=12288 ;;
    esac
    printf '%s\n' "$line"
    head -c "$length" /dev/zero | tr '\000' w >&2 ;;
  nonzero-helper)
    sleep 5 >/dev/null 2>&1 &
    printf '%s\n' "$!" > "$FIXTURE_PID_PATH"
    exit 23 ;;
  *) exit 3 ;;
esac
CANDIDATE
chmod 755 "$task_dir/candidate"
printf 'fixture should remain unread\n' > "$task_dir/input"

failures=0
for name in omg omgd; do
  for scenario in clean warning stderr-only closed-stdin wrong-name wrong-version extra-line empty binary-output nonzero \
      stdout-limit stdout-over-limit stderr-limit stderr-over-limit kernel-bound nonzero-helper symlink; do
    tmp_dir="$task_dir/$name-$scenario"
    mkdir "$tmp_dir"
    candidate="$task_dir/candidate"
    if [[ "$scenario" == symlink ]]; then
      candidate="$tmp_dir/linked"
      ln -s "$task_dir/candidate" "$candidate"
    fi
    expected=1
    case "$scenario" in clean | warning | closed-stdin | stdout-limit | stderr-limit) expected=0 ;; esac
    status=0
    FIXTURE_NAME="$name" FIXTURE_SCENARIO="$scenario" FIXTURE_PID_PATH="$tmp_dir/helper-pid" \
      probe_release_binary "$candidate" "$name" v1.2.3 < "$task_dir/input" > "$tmp_dir/result" 2>&1 || status=$?

    passed=true
    [[ "$status" == "$expected" ]] || passed=false
    if [[ "$scenario" == nonzero ]]; then
      grep -Fq 'executable startup failed' "$tmp_dir/result" || passed=false
    fi
    if [[ "$scenario" == nonzero-helper ]]; then
      [[ -s "$tmp_dir/helper-pid" ]] || passed=false
      if [[ -s "$tmp_dir/helper-pid" ]]; then
        helper=$(cat "$tmp_dir/helper-pid")
        for attempt in 1 2 3 4 5; do
          state=$(ps -o stat= -p "$helper" 2>/dev/null) || state=""
          [[ -n "$state" && "$state" != Z* ]] || break
          sleep 0.05
        done
        if [[ -n "$state" && "$state" != Z* ]]; then
          kill "$helper" 2>/dev/null || true
          passed=false
        fi
        grep -Fq 'left descendant processes running' "$tmp_dir/result" || passed=false
      fi
    fi
    if [[ "$scenario" == kernel-bound ]]; then
      for output in "$tmp_dir"/*version-probe*; do
        [[ -f "$output" && $(wc -c < "$output") -le 8192 ]] || passed=false
      done
    fi
    if [[ "$passed" == true ]]; then
      printf 'PASS: version probe %s %s\n' "$name" "$scenario"
    else
      printf 'FAIL: version probe %s %s expected %s got %s\n' "$name" "$scenario" "$expected" "$status" >&2
      head -c 300 "$tmp_dir/result" >&2
      failures=$((failures + 1))
    fi
  done
done
[[ "$failures" == 0 ]]
