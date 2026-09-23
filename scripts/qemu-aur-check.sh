#!/usr/bin/env bash
# Arch guest: prove AUR search flags against the submitted OMG binary.
set -euo pipefail
[[ $# == 2 && $(id -u) != 0 ]] || exit 2
source /etc/os-release
[[ "$ID" == arch ]] || exit 2
bin=$(realpath "$1")
evidence=$(realpath "$2")
fixture=$(realpath "${BASH_SOURCE[0]%/*}/qemu-aur-fixture.py")
[[ -x "$bin" && -d "$evidence" && -f "$fixture" ]] || exit 120
for tool in python3 openssl jq timeout; do command -v "$tool" >/dev/null || exit 120; done

state=$(mktemp -d "$HOME/omg-aur-check.XXXXXX")
chmod 700 "$state"
server_pid=
cleanup() {
  local status=$?
  trap - EXIT
  if [[ -n "$server_pid" ]]; then
    kill -TERM "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if [[ -f "$state/events.jsonl" ]]; then
    cp "$state/events.jsonl" "$evidence/aur-fixture-events.jsonl" || status=120
  fi
  if ! rm -rf -- "$state" || [[ -e "$state" || -L "$state" ]]; then status=120; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

# Create an ephemeral CA and server certificate. SSL_CERT_FILE makes only
# this OMG process trust the fixture; the guest system trust store stays intact.
if ! openssl req -x509 -newkey rsa:2048 -nodes -keyout "$state/ca.key" -out "$state/ca.pem" \
    -subj /CN=OMG-QEMU-AUR-Test-CA -addext basicConstraints=critical,CA:TRUE \
    -addext keyUsage=critical,keyCertSign,cRLSign -days 1 > "$evidence/aur-cert.log" 2>&1 \
  || ! openssl req -newkey rsa:2048 -nodes -keyout "$state/server.key" -out "$state/server.csr" \
    -subj /CN=aur.archlinux.org -addext subjectAltName=DNS:aur.archlinux.org \
    -addext basicConstraints=critical,CA:FALSE -addext extendedKeyUsage=serverAuth \
    -addext keyUsage=digitalSignature,keyEncipherment >> "$evidence/aur-cert.log" 2>&1 \
  || ! openssl x509 -req -in "$state/server.csr" -CA "$state/ca.pem" -CAkey "$state/ca.key" \
    -CAcreateserial -out "$state/server.pem" -days 1 -copy_extensions copy \
    >> "$evidence/aur-cert.log" 2>&1; then
  printf 'AUR fixture certificate setup failed\n' >&2
  exit 120
fi
python3 "$fixture" --cert "$state/server.pem" --key "$state/server.key" \
  --log "$state/events.jsonl" --port-file "$state/port" \
  > "$evidence/aur-fixture.stdout" 2> "$evidence/aur-fixture.stderr" &
server_pid=$!
ready=false
for _ in {1..50}; do
  kill -0 "$server_pid" 2>/dev/null || break
  if [[ -s "$state/port" ]]; then ready=true; break; fi
  sleep 0.1
done
if [[ "$ready" != true ]]; then
  printf 'AUR fixture did not start\n' >&2
  exit 120
fi
port=$(<"$state/port")
[[ "$port" =~ ^[0-9]{2,5}$ ]] || exit 120
proxy="http://127.0.0.1:$port"
query=omgqemuaurprobe
package=omgqemuaurprobe-fixture
# Prove proxy routing, TLS trust and the exact RPC fixture before attributing
# any later failure to OMG. Discard this setup traffic from product evidence.
if ! python3 - "$proxy" "$state/ca.pem" <<'PY' > "$evidence/aur-fixture-preflight.log" 2>&1
import json
import ssl
import sys
import urllib.request

context = ssl.create_default_context(cafile=sys.argv[2])
opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({"https": sys.argv[1]}),
    urllib.request.HTTPSHandler(context=context),
)
with opener.open("https://aur.archlinux.org/rpc?v=5&type=search&arg=omgqemuaurprobe", timeout=5) as response:
    payload = json.load(response)
assert payload["resultcount"] == 1
assert payload["results"][0]["Name"] == "omgqemuaurprobe-fixture"
assert payload["results"][0]["NumVotes"] == 17
PY
then
  printf 'AUR fixture TLS/RPC preflight failed\n' >&2
  exit 120
fi
if ! jq -e -s 'length == 2 and
  .[0] == {event:"connect",value:"aur.archlinux.org:443"} and
  .[1] == {event:"request",value:"/rpc?v=5&type=search&arg=omgqemuaurprobe"}' \
  "$state/events.jsonl" >/dev/null; then
  printf 'AUR fixture preflight did not take the expected local route\n' >&2
  exit 120
fi
: > "$state/events.jsonl"
run_search() {
  local output=$1
  shift
  HTTPS_PROXY="$proxy" https_proxy="$proxy" ALL_PROXY="$proxy" all_proxy="$proxy" \
    NO_PROXY= no_proxy= SSL_CERT_FILE="$state/ca.pem" \
    OMG_TEST_MODE=0 OMG_DISABLE_DAEMON=1 OMG_DISABLE_TELEMETRY=1 \
    timeout 30 "$bin" --json search "$@" --limit 5 "$query" > "$evidence/$output"
}
fixture_counts() {
  jq -c -s -e '[(map(select(.event == "connect")) | length),
             (map(select(.event == "request")) | length),
             (map(select(.event == "error" or .event == "rejected-connect" or .event == "rejected-request")) | length)]' \
    "$state/events.jsonl"
}

run_search aur-detailed.json --detailed
jq -e --arg name "$package" 'length == 1 and .[0].name == $name and
  .[0].version == "9.8.7-1" and .[0].source == "AUR" and
  .[0].votes == 17 and .[0].popularity == 1.25 and
  .[0].maintainer == "omg-qemu-fixture" and .[0].out_of_date == true' \
  "$evidence/aur-detailed.json" >/dev/null || {
    printf 'assertion failed: --detailed did not expose fixture AUR metadata\n' >&2; exit 1;
  }
[[ $(fixture_counts) == '[1,1,0]' ]] || {
  printf 'assertion failed: detailed search did not make exactly one valid AUR RPC request\n' >&2; exit 1;
}

run_search aur-no-aur.json --detailed --no-aur
jq -e 'type == "array" and length == 0' "$evidence/aur-no-aur.json" >/dev/null || {
  printf 'assertion failed: --no-aur returned an AUR result\n' >&2; exit 1;
}
[[ $(fixture_counts) == '[1,1,0]' ]] || {
  printf 'assertion failed: --no-aur made an AUR connection\n' >&2; exit 1;
}

run_search aur-basic.json
jq -e --arg name "$package" 'length == 1 and .[0].name == $name and
  .[0].source == "AUR" and
  (.[0] | [has("votes"), has("popularity"), has("maintainer"), has("out_of_date")] | any | not)' \
  "$evidence/aur-basic.json" >/dev/null || {
    printf 'assertion failed: basic search unexpectedly exposed detailed AUR metadata\n' >&2; exit 1;
  }
[[ $(fixture_counts) == '[2,2,0]' ]] || {
  printf 'assertion failed: basic search did not make exactly one valid AUR RPC request\n' >&2; exit 1;
}

# Positive receipt is written only after every observed product assertion.
jq -n '{schema_version:1, arch:true, real_cli:true, tls_fixture:true,
  detailed_metadata:true, no_aur_suppressed:true, basic_metadata_absent:true,
  expected_connects:2, expected_requests:2, unexpected_events:0}' \
  > "$evidence/aur-search-flags.json"
