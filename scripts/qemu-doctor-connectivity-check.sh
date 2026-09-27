#!/usr/bin/env bash
# Exercise the release Doctor binary against a private, deterministic HTTPS proxy.
set -euo pipefail
setup_fail() {
  printf 'OMG_QEMU_DOCTOR_CONNECTIVITY_SETUP_FAILED: %s\n' "$1" >&2
  exit 120
}
[[ $# == 3 ]] || setup_fail 'expected binary, distro, and evidence directory'
[[ $(id -u) != 0 ]] || setup_fail 'must run unprivileged'

bin=$(realpath "$1") || setup_fail 'binary path'
distro=$2
evidence=$(realpath "$3") || setup_fail 'evidence path'
fixture=$(realpath "${BASH_SOURCE[0]%/*}/qemu-doctor-connectivity-fixture.py") || setup_fail 'fixture path'
case "$distro" in
  arch) primary=archlinux.org ;;
  debian|ubuntu|fedora) primary=github.com ;;
  *) setup_fail 'unsupported distro' ;;
esac
source /etc/os-release || setup_fail 'os-release unavailable'
[[ "$ID" == "$distro" ]] || setup_fail 'guest distro mismatch'
[[ -x "$bin" ]] || setup_fail 'binary unavailable'
[[ -d "$evidence" ]] || setup_fail 'evidence directory unavailable'
[[ -f "$fixture" ]] || setup_fail 'proxy fixture unavailable'
for tool in python3 openssl jq timeout; do
  command -v "$tool" >/dev/null || setup_fail "missing tool $tool"
done

state=$(mktemp -d "$HOME/omg-doctor-connectivity.XXXXXX") || setup_fail 'private state directory'
chmod 700 "$state"
server_pid=
cleanup() {
  local status=$?
  trap - EXIT
  if [[ -n "$server_pid" ]]; then
    kill -TERM "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if ! rm -rf -- "$state" || [[ -e "$state" || -L "$state" ]]; then
    printf 'OMG_QEMU_DOCTOR_CONNECTIVITY_SETUP_FAILED: private state cleanup\n' >&2
    status=120
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

# The CA affects only these two OMG invocations. No guest trust store or
# public DNS setting is changed. See the already-proven QEMU AUR TLS fixture.
if ! openssl req -x509 -newkey rsa:2048 -nodes -keyout "$state/ca.key" -out "$state/ca.pem" \
    -subj /CN=OMG-QEMU-Doctor-Test-CA -addext basicConstraints=critical,CA:TRUE \
    -addext keyUsage=critical,keyCertSign,cRLSign -days 1 > "$evidence/doctor-connectivity-cert.log" 2>&1 \
  || ! openssl req -newkey rsa:2048 -nodes -keyout "$state/server.key" -out "$state/server.csr" \
    -subj /CN=fixture.invalid \
    -addext subjectAltName=DNS:fixture.invalid,DNS:archlinux.org,DNS:github.com,DNS:kernel.org \
    -addext basicConstraints=critical,CA:FALSE -addext extendedKeyUsage=serverAuth \
    -addext keyUsage=digitalSignature,keyEncipherment >> "$evidence/doctor-connectivity-cert.log" 2>&1 \
  || ! openssl x509 -req -in "$state/server.csr" -CA "$state/ca.pem" -CAkey "$state/ca.key" \
    -CAcreateserial -out "$state/server.pem" -days 1 -copy_extensions copy \
    >> "$evidence/doctor-connectivity-cert.log" 2>&1; then
  setup_fail 'certificate setup'
fi

run_case() {
  local mode=$1 healthy=$2 port proxy rc=0 server_status=0
  python3 "$fixture" --cert "$state/server.pem" --key "$state/server.key" \
    --log "$state/events.jsonl" --port-file "$state/port" \
    --primary "$primary" --mode "$mode" \
    > "$evidence/doctor-connectivity-$mode.fixture.stdout" \
    2> "$evidence/doctor-connectivity-$mode.fixture.stderr" &
  server_pid=$!
  local ready=false
  for _ in {1..50}; do
    kill -0 "$server_pid" 2>/dev/null || break
    if [[ -s "$state/port" ]]; then ready=true; break; fi
    sleep 0.1
  done
  if [[ "$ready" != true ]]; then
    setup_fail 'proxy did not start'
  fi
  port=$(<"$state/port")
  [[ "$port" =~ ^[0-9]{2,5}$ ]] || setup_fail 'proxy port invalid'
  proxy="http://127.0.0.1:$port"

  # This proves the proxy and ephemeral CA before the release binary runs.
  if ! NO_PROXY= no_proxy= python3 - "$proxy" "$state/ca.pem" <<'PY' \
      > "$evidence/doctor-connectivity-$mode.preflight.log" 2>&1
import ssl
import sys
import urllib.request

context = ssl.create_default_context(cafile=sys.argv[2])
opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({"https": sys.argv[1]}),
    urllib.request.HTTPSHandler(context=context),
)
with opener.open("https://fixture.invalid/ready", timeout=5) as response:
    assert response.status == 200
PY
  then
    setup_fail 'proxy TLS preflight'
  fi
  if ! jq -e -s '. == [{event:"connect",host:"fixture.invalid"},
                       {event:"request",host:"fixture.invalid"}]' \
      "$state/events.jsonl" >/dev/null; then
    setup_fail 'proxy preflight route'
  fi
  : > "$state/events.jsonl"

  HTTPS_PROXY="$proxy" https_proxy="$proxy" ALL_PROXY="$proxy" all_proxy="$proxy" \
    NO_PROXY= no_proxy= SSL_CERT_FILE="$state/ca.pem" \
    OMG_TEST_MODE=0 OMG_DISABLE_DAEMON=1 OMG_DISABLE_TELEMETRY=1 \
    OMG_CONFIG_DIR="$state/config" OMG_DATA_DIR="$state/data" OMG_CACHE_DIR="$state/cache" \
    NO_COLOR=1 PATH="${bin%/*}:$PATH" \
    timeout --kill-after=5s 30s "$bin" doctor \
    > "$evidence/doctor-connectivity-$mode.stdout" \
    2> "$evidence/doctor-connectivity-$mode.stderr" || rc=$?
  if ! kill -0 "$server_pid" 2>/dev/null; then
    setup_fail 'proxy died during Doctor'
  fi
  cp "$state/events.jsonl" "$evidence/doctor-connectivity-$mode.events.jsonl" || setup_fail 'proxy event copy'
  kill -TERM "$server_pid" 2>/dev/null || setup_fail 'proxy shutdown signal'
  wait "$server_pid" || server_status=$?
  [[ "$server_status" == 0 || "$server_status" == 143 ]] || setup_fail 'proxy shutdown status'
  server_pid=
  rm -f "$state/port" "$state/events.jsonl"

  if [[ "$rc" == 124 || "$rc" == 137 ]]; then
    printf 'assertion failed: Doctor %s run timed out\n' "$mode" >&2
    return 1
  fi
  if [[ $(grep -Fxc "  Internet connectivity ($healthy reachable)" \
      "$evidence/doctor-connectivity-$mode.stdout" || true) != 1 ]] \
    || grep -Fq 'Connectivity probes failed' "$evidence/doctor-connectivity-$mode.stdout"; then
    printf 'assertion failed: Doctor %s did not report the expected reachable site\n' "$mode" >&2
    return 1
  fi
  if ! jq -e -s --arg primary "$primary" --arg mode "$mode" '
    any(.[]; . == {event:"connect",host:$primary}) and
    (if $mode == "primary" then
      any(.[]; . == {event:"request",host:$primary}) and
      all(.[]; (.host == $primary or .host == "kernel.org") and
        (.event == "connect" or .event == "request" or .event == "denied"))
    else
      any(.[]; . == {event:"denied",host:$primary}) and
      any(.[]; . == {event:"connect",host:"kernel.org"}) and
      any(.[]; . == {event:"request",host:"kernel.org"}) and
      all(.[]; (.host == $primary or .host == "kernel.org") and
        (.event == "connect" or .event == "request" or .event == "denied"))
    end)' "$evidence/doctor-connectivity-$mode.events.jsonl" >/dev/null; then
    printf 'assertion failed: Doctor %s did not make the expected private HTTPS requests\n' "$mode" >&2
    return 1
  fi
  if [[ "$rc" == 0 ]]; then
    if ! grep -Fq 'System is healthy' "$evidence/doctor-connectivity-$mode.stdout" \
      || [[ -s "$evidence/doctor-connectivity-$mode.stderr" ]]; then
      printf 'assertion failed: Doctor %s lacked a healthy zero-issue verdict\n' "$mode" >&2
      return 1
    fi
    case_issue_count=0
  elif [[ "$rc" == 1 ]]; then
    case_issue_count=$(sed -nE 's/^Error: doctor found ([0-9]+) health issue\(s\)$/\1/p' \
      "$evidence/doctor-connectivity-$mode.stderr")
    if [[ ! "$case_issue_count" =~ ^[1-9][0-9]*$ ]]; then
      printf 'assertion failed: Doctor %s lacked a counted failure verdict\n' "$mode" >&2
      return 1
    fi
  else
    printf 'assertion failed: Doctor %s returned unexpected status %s\n' "$mode" "$rc" >&2
    return 1
  fi
}

run_case primary "$primary"
baseline_count=$case_issue_count
run_case alternate kernel.org
fallback_count=$case_issue_count
if [[ "$fallback_count" != "$baseline_count" || "$fallback_count" != 0 ]]; then
  printf 'assertion failed: Doctor fallback changed health issue count (%s to %s)\n' \
    "$baseline_count" "$fallback_count" >&2
  exit 1
fi
printf '{"schema_version":1,"distro":"%s","primary":"%s","alternate":"kernel.org","real_cli":true,"baseline_issues":%s,"fallback_issues":%s}\n' \
  "$distro" "$primary" "$baseline_count" "$fallback_count" \
  > "$evidence/doctor-connectivity-fallback.json"
