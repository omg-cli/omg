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
check_runtime_usage() {
  local runtime=$1 mode
  mode=$(stat -c %a "$OMG_DATA_DIR") || mode=""
  if [[ "$mode" != 700 ]] || ! jq -e -s --arg runtime "$runtime" \
    'length == 1 and (.[0] | .runtime_usage_counts[$runtime] == 1 and .commands.runtime_switch == 1 and .total_commands == 1)' \
    "$OMG_DATA_DIR/usage.json" >/dev/null; then
    printf 'assertion failed: runtime usage %s must persist exactly one switch in private data\n' "$runtime" >&2
    return 1
  fi
}

check_native_counter() {
  local distro=$1 counter=$2 output=$3 status=0 expected actual
  local -a native=()
  case "$distro:$counter" in
    arch:ec) native=(pacman -Qqe) ;;
    arch:tc) native=(pacman -Qq) ;;
    arch:oc) native=(pacman -Qdtq) ;;
    arch:uc) native=(pacman -Quq) ;;
    debian:tc|ubuntu:tc) native=(dpkg-query -W '-f=${db:Status-Status}\n') ;;
    debian:ec|ubuntu:ec) native=(apt-mark showmanual) ;;
    debian:oc|ubuntu:oc) native=(apt-get -s autoremove) ;;
    debian:uc|ubuntu:uc) native=(apt list --upgradable) ;;
    fedora:tc) native=(rpm -qa --qf '%{NAME}.%{ARCH}\n') ;;
    fedora:ec) native=(dnf --cacheonly repoquery --userinstalled --qf '%{name}\n') ;;
    fedora:oc) native=(dnf --cacheonly repoquery --unneeded --qf '%{name}.%{arch}\n') ;;
    fedora:uc) native=(dnf --cacheonly repoquery --upgrades --latest-limit=1 --qf '%{name}.%{arch}\n') ;;
    *) return 2 ;;
  esac
  timeout --kill-after=2s 30 "${native[@]}" > native-counter.raw 2> native-counter.stderr || status=$?
  # pacman uses 1 for an empty query; never accept a diagnostic-bearing error.
  if [[ "$distro" == arch && "$status" == 1 && ! -s native-counter.raw && ! -s native-counter.stderr ]]; then status=0; fi
  if [[ "$status" != 0 ]]; then
    printf 'native counter reference failed: %s %s exit=%s\n' "$distro" "$counter" "$status" >&2
    head -c 4096 native-counter.stderr >&2
    return 2
  fi
  expected=$(
    set -o pipefail
    case "$distro:$counter" in
      debian:tc|ubuntu:tc) awk '$0 == "installed" {n++} END {print n+0}' native-counter.raw ;;
      debian:oc|ubuntu:oc) awk '/^Remv / {n++} END {print n+0}' native-counter.raw ;;
      debian:uc|ubuntu:uc) awk '$1 ~ /\// {n++} END {print n+0}' native-counter.raw ;;
      *:ec|fedora:oc|fedora:uc) sort -u native-counter.raw | awk 'NF {n++} END {print n+0}' ;;
      *) awk 'NF {n++} END {print n+0}' native-counter.raw ;;
    esac
  ) || { printf 'native counter reference processing failed\n' >&2; return 2; }
  [[ $(wc -c < "$output") -le 32 ]] || { printf 'assertion failed: counter output exceeds scalar size\n' >&2; return 1; }
  actual=$(cat "$output")
  printf 'native counter %s expected=%s actual=%s\n' "$counter" "$expected" "$actual" >&2
  [[ "$actual" =~ ^[0-9]+$ && "$actual" == "$expected" ]]
}

check_native_tree_state() {
  local distro=$1 expected=$2 tree_binary=${3:-/usr/bin/tree} installed=false inventory
  case "$distro" in
    arch)
      inventory=$(pacman -Qq) || { printf 'assertion failed: native pacman database query failed\n' >&2; return 1; }
      grep -Fxq tree <<< "$inventory" && installed=true ;;
    debian|ubuntu)
      inventory=$(dpkg-query -W '-f=${Package}\t${Status}\n') || { printf 'assertion failed: native dpkg database query failed\n' >&2; return 1; }
      grep -Fxq $'tree\tinstall ok installed' <<< "$inventory" && installed=true ;;
    fedora)
      inventory=$(rpm -qa --qf '%{NAME}\n') || { printf 'assertion failed: native rpm database query failed\n' >&2; return 1; }
      grep -Fxq tree <<< "$inventory" && installed=true ;;
    *) printf 'assertion failed: unknown package backend %s\n' "$distro" >&2; return 1 ;;
  esac
  if [[ -z "$inventory" ]]; then
    printf 'assertion failed: native %s database query returned no packages\n' "$distro" >&2
    return 1
  fi
  if [[ "$expected" == installed ]]; then
    if [[ "$installed" != true || ! -x "$tree_binary" ]] || ! "$tree_binary" --version >/dev/null 2>&1; then
      printf 'assertion failed: native %s database or executable lacks installed tree\n' "$distro" >&2
      return 1
    fi
  elif [[ "$expected" == absent ]]; then
    if [[ "$installed" == true || -e "$tree_binary" || -L "$tree_binary" ]]; then
      printf 'assertion failed: native %s database or executable still contains tree\n' "$distro" >&2
      return 1
    fi
  else
    printf 'assertion failed: unknown expected tree state %s\n' "$expected" >&2
    return 1
  fi
}

prepare_native_apt_orphan() {
  local distro=$1
  check_native_tree_state "$distro" installed || return 1
  if ! dpkg-query -W '-f=${Package}\t${Status}\n' apt bash > baseline-packages.tsv \
    || [[ $(wc -l < baseline-packages.tsv) != 2 ]] \
    || grep -qv $'\tinstall ok installed$' baseline-packages.tsv; then
    printf 'assertion failed: APT baseline packages are not installed\n' >&2
    return 1
  fi
  if ! apt-get -s autoremove > baseline-autoremove.log 2>&1 \
    || grep -q '^Remv ' baseline-autoremove.log; then
    printf 'assertion failed: APT guest has unrelated pre-existing orphans\n' >&2
    return 1
  fi
  if ! sudo -n apt-mark auto tree > apt-mark.log 2>&1 \
    || ! apt-mark showauto > auto-marked.log 2>&1 \
    || ! grep -Fxq tree auto-marked.log \
    || ! apt-get -s autoremove > orphan-preview.log 2>&1 \
    || [[ $(awk '$1 == "Remv" {print $2}' orphan-preview.log) != tree ]]; then
    printf 'assertion failed: native APT did not select exactly tree as an orphan\n' >&2
    return 1
  fi
}

check_native_apt_orphan_removed() {
  local distro=$1 output=$2 tree_binary=${3:-/usr/bin/tree}
  check_native_tree_state "$distro" absent "$tree_binary" || return 1
  if ! dpkg-query -W '-f=${Package}\t${Status}\n' apt bash > after-packages.tsv \
    || ! cmp -s baseline-packages.tsv after-packages.tsv \
    || ! grep -Eq 'Removed 1 orphan package([^[:alpha:]]|$)' "$output"; then
    printf 'assertion failed: APT cleanup did not preserve baseline packages and report one verified removal\n' >&2
    return 1
  fi
}

check_go_install() (
  local version=$1 base expected active executable fixture observed status
  base="$OMG_DATA_DIR/versions/go"
  expected="$base/$version"
  active=$(readlink -f "$base/current") || active=""
  executable=$(readlink -f "$base/current/bin/go") || executable=""
  if [[ "$active" != "$expected" || ! -L "$base/current" || -L "$expected" \
        || "$executable" != "$expected/bin/go" || ! -f "$executable" || ! -x "$executable" ]]; then
    printf 'assertion failed: Go %s lacks an active confined compiler\n' "$version" >&2; return 1
  fi
  fixture=$(mktemp -d "$base/.qemu-go-XXXXXX") || return 1
  trap 'rm -rf -- "$fixture"' EXIT
  export GOROOT="$expected" GOTOOLCHAIN=local GOENV=off GOWORK=off GOPROXY=off GOSUMDB=off CGO_ENABLED=0 GOMAXPROCS=2
  export GOPATH="$fixture/gopath" GOCACHE="$fixture/gocache" GOMODCACHE="$fixture/modcache"
  unset GOFLAGS GOOS GOARCH
  cd "$fixture" || return 1
  status=0
  observed=$(timeout --kill-after=2s 10 "$executable" env GOROOT GOVERSION 2>&1) || status=$?
  if [[ "$status" != 0 || "$observed" != "$expected"$'\n'"go$version" ]]; then
    printf 'assertion failed: Go toolchain identity exit=%s observed=%s\n' "$status" "$observed" >&2; return 1
  fi
  printf 'module example.invalid/omg-probe\n\ngo 1.27\n' > go.mod
cat > main.go <<'GO'
package main
import("bytes";"compress/gzip";"crypto/sha256";"encoding/hex";"encoding/json";"fmt";"io";"runtime")
func probe() error {
  hash:=sha256.Sum256([]byte("abc"))
  if hex.EncodeToString(hash[:])!="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {return fmt.Errorf("digest mismatch")}
  var compressed bytes.Buffer
  writer:=gzip.NewWriter(&compressed)
  if _,err:=writer.Write([]byte("omg-go"));err!=nil{return err}; if err:=writer.Close();err!=nil{return err}
  reader,err:=gzip.NewReader(&compressed);if err!=nil{return err}
  raw,err:=io.ReadAll(reader);if err!=nil{return err};if err:=reader.Close();err!=nil{return err}
  if string(raw)!="omg-go" {return fmt.Errorf("compression mismatch")}
  data,err:=json.Marshal(map[string]int{"answer":42});if err!=nil{return err}
  var parsed map[string]int;if err:=json.Unmarshal(data,&parsed);err!=nil{return err}
  channel:=make(chan int);go func(){channel<-parsed["answer"]}()
  if <-channel!=42{return fmt.Errorf("channel result mismatch")}
  return nil
}
func main(){if err:=probe();err!=nil{panic(err)};fmt.Println("OMG_GO_RUNTIME_OK:"+runtime.Version())}
GO
cat > main_test.go <<'GO'
package main
import ("testing"; "os")
func TestProbe(t *testing.T){if err:=probe();err!=nil{t.Fatal(err)};if err:=os.WriteFile("test-complete",[]byte("go-test-executed"),0600);err!=nil{t.Fatal(err)}}
GO
  status=0
  timeout --kill-after=5s 120 "$executable" build -p 2 -o probe . > stage.log 2>&1 || status=$?
  if [[ "$status" != 0 || ! -x probe ]]; then
    printf 'assertion failed: Go compilation exit=%s\n' "$status" >&2; cat stage.log >&2; return 1
  fi
  status=0
  observed=$(timeout --kill-after=2s 10 ./probe 2>&1) || status=$?
  if [[ "$status" != 0 || "$observed" != "OMG_GO_RUNTIME_OK:go$version" ]]; then
    printf 'assertion failed: Go compiled program exit=%s observed=%s\n' "$status" "$observed" >&2; return 1
  fi
  status=0
  timeout --kill-after=5s 120 "$executable" test -p 2 -count=1 -timeout=10s -v . > stage.log 2>&1 || status=$?
  if [[ "$status" != 0 || ! -f test-complete || $(cat test-complete 2>/dev/null) != go-test-executed ]] \
      || ! grep -q '^--- PASS: TestProbe (' stage.log; then
    printf 'assertion failed: Go test execution exit=%s\n' "$status" >&2; cat stage.log >&2; return 1
  fi
  cd "$base" || return 1
  rm -rf -- "$fixture" || return 1
  if [[ -e "$fixture" || -L "$fixture" ]]; then printf 'assertion failed: Go fixture cleanup\n' >&2; return 1; fi
)

check_node_install() {
  local version=$1 base expected active executable npm output status=0
  base="$OMG_DATA_DIR/versions/node"
  expected="$base/$version"
  active=$(readlink -f "$base/current") || active=""
  executable=$(readlink -f "$base/current/bin/node") || executable=""
  npm=$(readlink -f "$expected/lib/node_modules/npm/bin/npm-cli.js") || npm=""
  if [[ "$active" != "$expected" || ! -L "$base/current" || -L "$expected" \
        || "$executable" != "$expected/bin/node" || ! -x "$executable" || ! -f "$executable" \
        || "$npm" != "$expected/"* || ! -f "$npm" ]]; then
    printf 'assertion failed: Node %s lacks an active confined runtime and bundled npm\n' "$version" >&2; return 1
  fi
  output=$(timeout --kill-after=2s 60 env -u NODE_OPTIONS -u NODE_PATH "$executable" - "$version" "$executable" "$npm" "$base" 2>&1 <<'JS'
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const {execFileSync} = require('node:child_process');
const [version, executable, npm, base] = process.argv.slice(2);
assert.equal(process.version, `v${version}`, 'Node version mismatch');
assert.equal(process.execPath, executable, 'Node executable mismatch');
assert.equal(crypto.createHash('sha256').update('abc').digest('hex'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
assert.equal(zlib.gunzipSync(zlib.gzipSync('omg-runtime')).toString(), 'omg-runtime');
assert.equal(execFileSync(executable, ['-e', 'process.stdout.write(String(6*7))'], {timeout: 5000}).toString(), '42');
const fixture = fs.mkdtempSync(path.join(base, '.qemu-node-'));
try {
  fs.writeFileSync(path.join(fixture, 'probe.cjs'), 'require("node:fs").writeFileSync("result.txt", "npm-script-executed")');
  fs.writeFileSync(path.join(fixture, 'package.json'), JSON.stringify({name:'omg-offline-probe',version:'1.0.0',scripts:{probe:'node probe.cjs'}}));
  assert.equal(JSON.parse(fs.readFileSync(path.join(fixture, 'package.json'))).name, 'omg-offline-probe');
  fs.writeFileSync(path.join(fixture, 'user.npmrc'), '');
  fs.writeFileSync(path.join(fixture, 'global.npmrc'), '');
  const env = {...process.env, PATH: path.dirname(executable) + ':' + process.env.PATH,
    npm_config_cache: path.join(fixture, 'cache'), npm_config_offline: 'true',
    npm_config_audit: 'false', npm_config_update_notifier: 'false',
    npm_config_userconfig: path.join(fixture, 'user.npmrc'),
    npm_config_globalconfig: path.join(fixture, 'global.npmrc')};
  const options = {cwd: fixture, env, timeout: 20000, encoding: 'utf8', maxBuffer: 1024 * 1024};
  const npmVersion = execFileSync(executable, [npm, '--version'], options).trim();
  assert.match(npmVersion, /^\d+\.\d+\.\d+$/);
  execFileSync(executable, [npm, 'run', 'probe'], options);
  assert.equal(fs.readFileSync(path.join(fixture, 'result.txt'), 'utf8'), 'npm-script-executed');
} finally {
  fs.rmSync(fixture, {recursive:true, force:true});
}
assert.equal(fs.existsSync(fixture), false, 'Node behavior fixture cleanup failed');
console.log(`OMG_NODE_RUNTIME_OK:${version}`);
JS
  ) || status=$?
  if [[ "$status" != 0 || "$output" != "OMG_NODE_RUNTIME_OK:$version" ]]; then
    printf 'assertion failed: Node runtime behavior expected=%s exit=%s observed=%s\n' "$version" "$status" "$output" >&2; return 1
  fi
}

check_python_install() {
  local version=$1 base expected active executable output status=0
  base="$OMG_DATA_DIR/versions/python"
  expected="$base/$version"
  active=$(readlink -f "$base/current") || active=""
  executable=$(readlink -f "$base/current/bin/python3") || executable=""
  if [[ "$active" != "$expected" || ! -L "$base/current" || -L "$expected" \
        || "$executable" != "$expected/"* || ! -f "$executable" || ! -x "$executable" ]]; then
    printf 'assertion failed: Python %s lacks an active executable inside its installed version\n' "$version" >&2; return 1
  fi
  output=$(timeout --kill-after=2s 10 "$executable" --version 2>&1) || status=$?
  if [[ "$status" != 0 || "$output" != "Python $version" ]]; then
    printf 'assertion failed: Python executable version expected=%s exit=%s observed=%s\n' "$version" "$status" "$output" >&2; return 1
  fi
  output=$(timeout --kill-after=2s 150 "$executable" -I - "$version" "$expected" "$base" 2>&1 <<'PY'
import bz2, ctypes, gzip, hashlib, json, lzma, pathlib, sqlite3, ssl, subprocess, sys, tempfile, venv

version, expected, base = sys.argv[1:]
assert sys.version.split()[0] == version, 'interpreter version mismatch'
assert pathlib.Path(sys.executable).resolve().is_relative_to(pathlib.Path(expected)), 'interpreter escaped installation'
payload = b'OMG installed Python behavior'
for codec in (bz2, gzip, lzma):
    assert codec.decompress(codec.compress(payload)) == payload, f'{codec.__name__} round trip failed'
assert hashlib.sha256(b'abc').hexdigest() == 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', 'SHA-256 mismatch'
with sqlite3.connect(':memory:') as database:
    database.execute('create table probe(value integer)')
    database.execute('insert into probe values (?)', (42,))
    assert database.execute('select value from probe').fetchall() == [(42,)], 'SQLite query mismatch'
libc = ctypes.CDLL(None)
libc.abs.argtypes = [ctypes.c_int]
libc.abs.restype = ctypes.c_int
assert libc.abs(-42) == 42, 'ctypes foreign call failed'
context = ssl.create_default_context()
assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname, 'TLS verification defaults disabled'
# ensurepip uses bundled wheels offline; no package index or second download.
def crash_context():
    diagnostics = []
    probes = (
        ('kernel', ['sudo', '-n', 'journalctl', '-k', '--no-pager', '--since', '2 minutes ago']),
        ('coredump', ['coredumpctl', '--no-pager', 'list', '--since', '2 minutes ago']),
    )
    for label, command in probes:
        try:
            result = subprocess.run(command, text=True, capture_output=True, timeout=5)
        except (OSError, subprocess.TimeoutExpired) as error:
            diagnostics.append(f'{label} unavailable: {error}')
            continue
        lines = result.stdout.splitlines()
        if label == 'kernel':
            lines = [line for line in lines if 'segfault' in line.lower()]
        else:
            lines = [line for line in lines if 'python' in line.lower()]
        diagnostics.append(f'{label} exit={result.returncode}: ' + (' | '.join(lines[-3:]) or 'no matching record'))
    return '; '.join(diagnostics)

def run_probe(arguments, timeout=10):
    result = subprocess.run(arguments, text=True, capture_output=True, timeout=timeout)
    if result.returncode != 0:
        detail = f'Python child exited {result.returncode}: {result.stdout[:4096]} {result.stderr[:4096]}'
        if result.returncode == -11 or 'SIGSEGV' in result.stderr:
            detail += f'\nCrash diagnostics: {crash_context()}'
        raise RuntimeError(detail)
    return result.stdout

# Each attempt must pass: a transient crash must fail the row, not become a green retry.
for attempt in range(1, 6):
    try:
        with tempfile.TemporaryDirectory(prefix='.qemu-python-', dir=base) as temporary:
            environment = pathlib.Path(temporary) / 'venv'
            venv.create(environment, with_pip=False)
            child = environment / 'bin/python'
            run_probe([str(child), '-I', '-m', 'ensurepip', '--upgrade', '--default-pip'], timeout=40)
            observed = run_probe([str(child), '-I', '-c', 'import json,sys; print(json.dumps([sys.version.split()[0],sys.prefix,sys.base_prefix]))'])
            child_version, prefix, base_prefix = json.loads(observed)
            assert child_version == version and pathlib.Path(prefix) == environment, 'venv identity mismatch'
            assert prefix != base_prefix, 'venv is not isolated from its base interpreter'
            pip = run_probe([str(child), '-I', '-m', 'pip', '--isolated', '--disable-pip-version-check', '--version'])
            assert pip.startswith('pip ') and str(environment) in pip, 'pip is outside its venv'
        assert not pathlib.Path(temporary).exists(), 'Python behavior fixture cleanup failed'
    except Exception as error:
        raise RuntimeError(f'Python installed runtime attempt {attempt}/5 failed: {error}') from error
print(f'OMG_PYTHON_RUNTIME_OK:{version}')
PY
  ) || status=$?
  if [[ "$status" != 0 || "$output" != "OMG_PYTHON_RUNTIME_OK:$version" ]]; then
    printf 'assertion failed: Python runtime behavior expected=%s exit=%s observed=%s\n' "$version" "$status" "$output" >&2; return 1
  fi
}
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
  local safety=$1 assertion=$2 code=$3 stdout=$4 stderr=$5 distro=${6:-arch}
  if grep -Eq 'panicked at|thread .main. panicked' "$stdout" "$stderr"; then
    printf 'assertion failed: product emitted a panic report\n' >&2; return 1
  fi
  if [[ "$safety" == help-boundary ]] && ! grep -Fq 'Usage:' "$stdout"; then
    printf 'assertion failed: help output lacks Usage\n' >&2; return 1
  fi
  if [[ "$code" != 0 ]] && ! grep -q '[^[:space:]]' "$stderr"; then
    printf 'assertion failed: product refusal lacks its own stderr explanation\n' >&2; return 1
  fi
  if [[ "$assertion" == audit-fix-refusal ]]; then
    case "$distro" in
      arch) assertion=audit-source-failure ;;
      debian|ubuntu|fedora)
        if [[ "$code" != 1 ]] \
          || ! grep -Fxq 'Error: Vulnerability auto-fix is not available without the Arch backend; upgrade the affected packages manually' "$stderr" \
          || grep -Eq 'Scanning for fixable vulnerabilities|No vulnerabilities found|Security audit completed' "$stdout"; then
          printf 'assertion failed: unsupported backend did not refuse auto-fix before scanning\n' >&2; return 1
        fi ;;
      *) printf 'assertion failed: unknown auto-fix backend %s\n' "$distro" >&2; return 1 ;;
    esac
  fi
  if [[ "$assertion" == audit-source-failure ]]; then
    if [[ "$code" != 1 ]] \
      || ! grep -Eq '^Error: (Failed to scan package .+ for vulnerabilities: Failed to query the OSV vulnerability database|Failed to query native security advisories)' "$stderr" \
      || grep -Eq 'No vulnerabilities found|Security audit completed' "$stdout"; then
      printf 'assertion failed: offline audit did not explicitly refuse an unavailable advisory source\n' >&2; return 1
    fi
  fi
  if [[ "$assertion" == sbom-source-failure ]]; then
    if [[ "$code" != 1 || -e sbom.json || -L sbom.json ]] \
      || ! grep -Eq '^Error: Failed to generate system SBOM: Failed to generate a complete security SBOM: (Failed to scan package .+ for vulnerabilities: Failed to query the OSV vulnerability database|Failed to query native security advisories)' "$stderr" \
      || grep -Eq 'No vulnerabilities found|SBOM generated|Security audit completed' "$stdout"; then
      printf 'assertion failed: offline SBOM did not refuse an unavailable advisory source without an artifact\n' >&2; return 1
    fi
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
      native-tree-installed|native-tree-absent)
        local expected=installed
        [[ "$assertion" == native-tree-installed ]] || expected=absent
        check_native_tree_state "$distro" "$expected" || return 1 ;;
      native-apt-orphan-removed)
        check_native_apt_orphan_removed "$distro" "$stdout" || return 1 ;;
      search-official-tree-output)
        if ! awk '
          /^  [^[:space:]]+ [^[:space:]]+  / {
            results++
            if (results == 1 && ($1 != "tree" || $3 != "Official" || NF != 3)) bad=1
            if ($1 == "tree") trees++
          }
          END { exit !(results > 0 && trees == 1 && !bad) }
        ' "$stdout"; then
          printf 'assertion failed: search lacks a ranked official tree result\n' >&2; return 1
        fi ;;
      search-official-limit-three)
        if ! awk '
          /^  \| Search$/ { headings++; next }
          /^    git-$/ { queries++; next }
          /^  [^[:space:]]+ [^[:space:]]+  / {
            results++
            if ($1 !~ /^git-/ || $3 != "Official" || NF != 3) bad=1
            if (seen[$1]++) bad=1
            next
          }
          /^  \(\+[1-9][0-9]* more packages\.\.\.\)$/ { more++; next }
          /^[[:space:]]*$/ { next }
          /^OMG_QEMU_RECEIPT:/ { next }
          { bad=1 }
          END { exit !(headings == 1 && queries == 1 && results == 3 && more == 1 && !bad) }
        ' "$stdout"; then
          printf 'assertion failed: official git- prefix search lacks three results and a positive remainder\n' >&2; return 1
        fi ;;
      artifact:*)
        local artifact=${assertion#artifact:}
        if [[ ! -f "$artifact" || -L "$artifact" ]] || ! jq -e -s 'length == 1' "$artifact" >/dev/null 2>&1; then
          printf 'assertion failed: artifact %s is not a regular JSON document\n' "$artifact" >&2; return 1
        fi ;;
      sbom-inventory-only)
        if [[ ! -f sbom.json || -L sbom.json ]] || ! jq -e -s '
          length == 1 and (.[0] |
            .bomFormat == "CycloneDX" and
            (.components | type == "array" and length > 0) and
            ((.metadata.component.properties // []) |
              any(.[]; .name == "omg:advisory-scan" and .value == "not-performed")) and
            ((.vulnerabilities // []) | type == "array" and length == 0))
        ' sbom.json >/dev/null 2>&1 \
          || ! grep -Fq 'Inventory only: advisory matching was skipped' "$stdout"; then
          printf 'assertion failed: inventory-only SBOM lacks the advisory-scan marker or warning\n' >&2; return 1
        fi ;;
      update-fast-output)
        if ! grep -Fq 'Fast System Update' "$stdout" \
          || ! grep -Eqi 'Syncing package|Synced' "$stdout" \
          || ! grep -Eqi 'System is up to date|System updated successfully|Upgraded [0-9]+ packages?' "$stdout"; then
          printf 'assertion failed: update --fast lacked sync and completion evidence\n' >&2; return 1
        fi ;;
      update-turbo-output)
        if ! grep -Fq 'TURBO System Update' "$stdout" \
          || ! grep -Eqi 'Turbo upgrade|cached, no sync|Checking for updates.*cached' "$stdout" \
          || ! grep -Eqi 'System is up to date|System updated successfully|Upgraded [0-9]+ packages?' "$stdout"; then
          printf 'assertion failed: update --turbo lacked cached-mode and completion evidence\n' >&2; return 1
        fi ;;
      daemon-foreground-lifecycle)
        if [[ ! -f daemon-evidence/daemon-lifecycle.json || -L daemon-evidence/daemon-lifecycle.json ]] \
          || ! jq -e -s 'length == 1 and (.[0] | .schema_version == 1 and
            .direct == true and .foreground == true and .ipc == true and
            .singleton == true and .shutdown == true and .restart == true and
            .query_parity == true and .sigint == true and .cleanup == true and
            (.backend_faults | type == "array"))' daemon-evidence/daemon-lifecycle.json >/dev/null; then
          printf 'assertion failed: daemon --foreground lifecycle receipt is missing or incomplete\n' >&2; return 1
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
declare -A row_args=() row_requires=() row_tier=() row_safety=() row_ux=() row_exit=() row_targets=() row_assertions=() row_cleanup=()
counter_for_case() {
  case "$1" in
    explicit-shortcut) printf ec ;; total-shortcut) printf tc ;;
    orphan-shortcut) printf oc ;; updates-shortcut) printf uc ;;
  esac
}
while IFS=$'\t' read -r id aj s e u r t tg a cleanup; do
  [[ "$id" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ && -z "${row_args[$id]:-}" ]] || exit 2
  [[ "$r" == - || "$r" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ ]] || exit 2
  [[ "$r" == - || -n "${row_args[$r]:-}" ]] || exit 2
  jq -e 'type == "array" and length > 0 and all(.[]; type == "string" and (explode | index(0) == null))' <<< "$aj" >/dev/null || exit 2
  counter=$(counter_for_case "$id")
  if [[ -n "$counter" ]]; then
    jq -e --arg counter "$counter" 'length == 1 and .[0] == $counter' <<< "$aj" >/dev/null || exit 2
  fi
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
      [[ "$input_target" =~ ^(arch|debian|ubuntu|fedora):(pass|pending|known-defect|not-applicable)$ ]] || exit 2
      target_distro=${input_target%%:*}
      [[ "$seen_targets" != *",$target_distro,"* ]] || exit 2
      seen_targets+="$target_distro,"
    done
  fi
  resolved=""
  if [[ "$u" != declared ]]; then resolved=$(resolve_exit "$e") || exit 2; fi
  case "$a" in -|audit-source-failure|audit-fix-refusal|sbom-source-failure|sbom-inventory-only|json-stdout|hooks-installed|hooks-absent|workspace-filtered-output|workspace-all-output|artifact:manifest.json|artifact:privacy.json|artifact:sbom.json|update-fast-output|update-turbo-output|daemon-foreground-lifecycle|search-official-limit-three|search-official-tree-output|native-tree-installed|native-tree-absent|native-apt-orphan-removed) ;; *) exit 2 ;; esac
  if [[ "$a" == search-official-tree-output ]]; then [[ "$id" == release-package-search-tree ]] || exit 2; fi
  if [[ "$a" == native-tree-installed ]]; then [[ "$id" == release-package-install-tree ]] || exit 2; fi
  if [[ "$a" == native-tree-absent ]]; then [[ "$id" == release-package-remove-tree ]] || exit 2; fi
  if [[ "$a" == native-apt-orphan-removed ]]; then [[ "$id" == clean-orphans-native ]] || exit 2; fi
  case "$cleanup" in tempdir-drop|none|container-prune|host-state-restore|vm-revert|daemon-stop) ;; *) exit 2 ;; esac
  row_args["$id"]="$aj"; row_requires["$id"]="$r"
  row_tier["$id"]="$t"; row_safety["$id"]="$s"; row_ux["$id"]="$u"
  row_exit["$id"]="$resolved"; row_targets["$id"]="$tg"; row_assertions["$id"]="$a"
  row_cleanup["$id"]="$cleanup"
  if [[ "$id" == runtime-python-install ]]; then
    jq -e 'length == 3 and .[0] == "use" and .[1] == "python" and (.[2] | test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))' <<< "$aj" >/dev/null || exit 2
  fi
  if [[ "$id" == runtime-node-install ]]; then
    jq -e 'length == 3 and .[0] == "use" and .[1] == "node" and (.[2] | test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))' <<< "$aj" >/dev/null || exit 2
  fi
  if [[ "$id" == runtime-go-install ]]; then
    jq -e 'length == 3 and .[0] == "use" and .[1] == "go" and (.[2] | test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))' <<< "$aj" >/dev/null || exit 2
  fi
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
while IFS=$'\t' read -r case args_json safety _expected_exit expected_ux requires tier targets assertions cleanup; do
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
  if [[ -z "$status" || "$status" == pending || "$status" == not-applicable ]]; then
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
  if [[ "$assertions" == audit-source-failure || "$assertions" == sbom-source-failure ]]; then
    # DNF5 can satisfy an offline advisory query from a previous row's cache.
    # A daemon launched by an earlier inventory row can also answer the audit
    # using its own warm cache and network access, bypassing this row's offline
    # namespace. Force the direct CLI path with a fresh cache for this oracle.
    remote+="; export OMG_CACHE_DIR=\"\$rowdir/audit-cache\" OMG_DISABLE_DAEMON=1"
  fi
  remote+="; printf '%s' $overlap_fixture > workspace-overlap.sh"
  remote+="; mkdir -p project; printf '# Nested audit fixture\n' > project/README.md"
  remote+="; printf 'smoke:\n\t@echo nested-smoke-task-ok\noverlap:\n\t@sh ../workspace-overlap.sh .. nested\n' > project/Makefile"
  remote+="; command -v jq >/dev/null; command -v grep >/dev/null; $(declare -f check_hook_lifecycle); $(declare -f check_product_output)"
  # The supervisor exits zero after recording a completed CLI's status.
  # Thus a CLI exit 125 cannot be mistaken for timeout's own exit 125.
  supervisor=$(jq -rn --arg s 'rc=0; "$@" 3>&- || rc=$?; printf "%s\n" "$rc" >&3' '$s | @sh')
  remote+="; status_file=\$(mktemp \"\$HOME/inventory-status.XXXXXX\"); trap 'rm -f \"\$status_file\"' EXIT"
  remote+="; run_omg() { local deadline=\$1; shift; execution_phase=executor; rc=0; timeout --kill-after=5s \"\$deadline\" bash -c $supervisor _ \"\$@\" 3>\"\$status_file\" || rc=\$?; if [ \"\$rc\" = 0 ]; then if IFS= read -r rc < \"\$status_file\"; then execution_phase=product; else rc=125; fi; fi; }"
  if [[ "$case" == release-package-install-tree || "$case" == release-package-remove-tree || "$case" == clean-orphans-native ]]; then
    remote+="; $(declare -f check_native_tree_state)"
  fi
  if [[ "$case" == clean-orphans-native ]]; then
    remote+="; $(declare -f prepare_native_apt_orphan); $(declare -f check_native_apt_orphan_removed)"
  fi
  if [[ "$case" == release-package-install-tree || "$case" == clean-orphans-native ]]; then
    remote+="; if ! check_native_tree_state '$distro' absent; then printf '\nOMG_QEMU_RECEIPT:dependency:2:1\n'; exit 0; fi"
  fi
  for p in "${chain[@]}"; do
    pargs=$(quote_args "${row_args[$p]}")
    remote+="; run_omg '$row_timeout' $quoted_binary $pargs > '$p.prereq.log' 2> '$p.prereq.stderr.log'"
    remote+="; printf 'prereq $p exit=%s\n' \"\$rc\" >&2; cat '$p.prereq.log' '$p.prereq.stderr.log' >&2"
    remote+="; if [ \"\$rc\" != '${row_exit[$p]}' ] || [ \"\$execution_phase\" != product ]; then printf '\nOMG_QEMU_RECEIPT:dependency:%s:0\n' \"\$rc\"; exit 0; fi"
    remote+="; if ! check_product_output '${row_safety[$p]}' '${row_assertions[$p]}' \"\$rc\" '$p.prereq.log' '$p.prereq.stderr.log' '$distro'; then printf '\nOMG_QEMU_RECEIPT:dependency:%s:1\n' \"\$rc\"; exit 0; fi"
  done
  if [[ "$case" == clean-orphans-native ]]; then
    remote+="; if ! prepare_native_apt_orphan '$distro'; then printf '\nOMG_QEMU_RECEIPT:dependency:2:1\n'; exit 0; fi; export OMG_DISABLE_DAEMON=1"
  fi
  if [[ "$case" == hooks-install-force ]]; then
    # An identical reinstall cannot prove --force is honored. Replace each
    # generated prerequisite hook with user content and non-executable mode;
    # the normal installed-hook oracle must observe real replacement.
    remote+="; for hook in pre-commit post-checkout post-merge; do printf '#!/bin/sh\\n# user-owned hook fixture\\nexit 23\\n' > \".git/hooks/\$hook\"; chmod 640 \".git/hooks/\$hook\"; done"
  fi
  arg_string=$(quote_args "$args_json")
  command_timeout=$row_timeout
  # Official runtime archives are downloaded inside a fresh guest. A 34 MB
  # Python archive reached the generic 120s limit on Fedora before the CLI
  # returned (run 36086453655); Go already needs the same bounded allowance.
  # Keep the result fatal if either download exceeds this larger deadline.
  if [[ "$case" == runtime-python-install || "$case" == runtime-go-install ]]; then
    command_timeout=$((row_timeout * 3))
  fi
  # dnf5 cacheonly=metadata reuses repository metadata and still downloads
  # packages (dnf5-caching(7); cached_update_args). Run 35694347149 downloaded
  # 256 MiB and was killed at dnf step 419/420 when the 120s deadline
  # returned 124. The completed guest spent 26s on step 420 and finished the
  # same 204-package transaction in 72s. Twice the generic budget covers that
  # measured tail. The 3x ceiling stays on runtime-go-install and update --fast.
  if [[ "$case" == update-turbo ]]; then
    command_timeout=$((row_timeout * 2))
  elif [[ "$case" == update-fast ]]; then
    command_timeout=$((row_timeout * 3))
  elif [[ "$case" == daemon-foreground ]]; then
    command_timeout=240
    remote+="; mkdir -p daemon-evidence"
  fi
  counter=$(counter_for_case "$case")
  if [[ -n "$counter" ]]; then
    remote+="; $(declare -f check_native_counter)"
  fi
  if [[ "$case" == runtime-python-install || "$case" == runtime-node-install || "$case" == runtime-go-install ]]; then
    runtime_version=$(jq -r '.[2]' <<< "$args_json")
    runtime_name=$(jq -r '.[1]' <<< "$args_json")
    remote+="; umask 0002; export OMG_DATA_DIR=\"\$rowdir/runtime-data\" OMG_CACHE_DIR=\"\$rowdir/runtime-cache\" OMG_CONFIG_DIR=\"\$rowdir/runtime-config\" OMG_TEST_MODE=0; $(declare -f "check_${runtime_name}_install"); $(declare -f check_runtime_usage)"
  fi
  if [[ "$distro" == fedora && ( "$case" == update-fast || "$case" == update-turbo ) ]]; then
    # Keep the real OMG path, but bound native DNF to a local versioned RPM.
    # The root-owned helper restores system repo policy and checks the RPMDB
    # plus native DNF history before it can report success.
    remote+="; run_omg '$command_timeout' sudo -n bash \"\$HOME/qemu-fedora-update-fixture.sh\" '${case#update-}' $quoted_binary '$ssh_user' > command.stdout.log 2> command.stderr.log; assertion=0"
  elif [[ "$case" == daemon-foreground ]]; then
    remote+="; run_omg '$command_timeout' bash \"\$HOME/qemu-daemon-check.sh\" $quoted_binary \"\$rowdir/daemon-evidence\" > command.stdout.log 2> command.stderr.log; assertion=0"
  else
    remote+="; run_omg '$command_timeout' $quoted_binary $arg_string > command.stdout.log 2> command.stderr.log; assertion=0"
  fi
  remote+="; cat command.stdout.log; cat command.stderr.log >&2"
  remote+="; if [ \"\$execution_phase\" = executor ]; then printf 'assertion failed: command exceeded ${command_timeout}s QEMU row deadline (executor exit %s)\n' \"\$rc\" >&2; assertion=1; elif ! check_product_output '$safety' '$assertions' \"\$rc\" command.stdout.log command.stderr.log '$distro'; then assertion=1; fi"
  if [[ "$distro" == fedora && ( "$case" == update-fast || "$case" == update-turbo ) ]]; then
    remote+="; if [[ \"\$rc\" == 120 ]] && grep -Fq 'OMG_QEMU_FIXTURE_SETUP_FAILED' command.stderr.log; then execution_phase=dependency; fi"
    remote+="; if [[ \"\$rc\" == 121 ]] && grep -Fq 'OMG_QEMU_FIXTURE_CLEANUP_FAILED' command.stderr.log; then execution_phase=dependency; fi"
    remote+="; if [[ \"\$rc\" == 0 ]] && { ! grep -Fxq 'OMG_QEMU_UPDATE_FIXTURE:before:${case#update-}:1' command.stdout.log || ! grep -Fxq 'OMG_QEMU_UPDATE_FIXTURE:after:${case#update-}:2:native-upgrade' command.stdout.log; }; then printf 'assertion failed: bounded Fedora update lacks native before/after evidence\\n' >&2; assertion=1; fi"
  fi
  if [[ -n "$counter" ]]; then
    remote+="; if [ \"\$rc\" = 0 ]; then oracle_rc=0; check_native_counter '$distro' '$counter' command.stdout.log || oracle_rc=\$?; if [ \"\$oracle_rc\" = 2 ]; then execution_phase=dependency; rc=2; elif [ \"\$oracle_rc\" != 0 ]; then assertion=1; fi; fi"
    remote+="; cd \"\$HOME\"; if ! rm -rf -- \"\$rowdir\" || [ -e \"\$rowdir\" ] || [ -L \"\$rowdir\" ]; then printf 'assertion failed: counter fixture cleanup failed\\n' >&2; assertion=1; fi"
  fi
  if [[ "$case" == runtime-python-install || "$case" == runtime-node-install || "$case" == runtime-go-install ]]; then
    remote+="; if [ \"\$rc\" = 0 ] && ! check_${runtime_name}_install '$runtime_version'; then assertion=1; fi"
    remote+="; if [ \"\$rc\" = 0 ] && ! check_runtime_usage '$runtime_name'; then assertion=1; fi"
    remote+="; cd \"\$HOME\"; if ! rm -rf -- \"\$rowdir\" || [ -e \"\$rowdir\" ] || [ -L \"\$rowdir\" ]; then printf 'assertion failed: runtime fixture cleanup failed\\n' >&2; assertion=1; fi"
  fi
  # Every inventory row receives a private fixture directory. Product-specific
  # cleanup assertions run above; removal here proves the harness itself does
  # not leak state that could make a later row pass.
  remote+="; cd \"\$HOME\"; if ! rm -rf -- \"\$rowdir\" || [ -e \"\$rowdir\" ] || [ -L \"\$rowdir\" ]; then printf 'assertion failed: row fixture cleanup failed (%s)\\n' '$cleanup' >&2; assertion=1; fi"
  # A receipt is emitted only after setup and the command complete. SSH
  # transport/tool failures cannot satisfy an expected product refusal.
  remote+="; printf '\nOMG_QEMU_RECEIPT:%s:%s:%s\n' \"\$execution_phase\" \"\$rc\" \"\$assertion\""
  remote="bash -c $(jq -rn --arg s "$remote" '$s | @sh')"
  if [[ "$network_scope" == offline ]]; then
    # Put the supervisor AND its receipt inside the namespace. A namespace
    # setup failure must be a transport/harness error, never an expected CLI
    # refusal. Drop back to the SSH user before creating fixtures or running OMG.
    if [[ "$case" == daemon-foreground ]]; then
      # The daemon fault probe owns a second, private mount namespace and must
      # use its tightly scoped passwordless sudo before dropping all privileges
      # around the submitted binary. Keep that capability inside this offline
      # network namespace while running the lifecycle itself as the SSH user.
      remote="sudo -n unshare --net -- sudo -n -u '$ssh_user' env HOME=\"\$HOME\" USER='$ssh_user' LOGNAME='$ssh_user' $remote"
    else
      remote="sudo -n unshare --net -- setpriv --reuid=\"\$(id -u)\" --regid=\"\$(id -g)\" --clear-groups --no-new-privs --bounding-set=-all --inh-caps=-all --ambient-caps=-all env HOME=\"\$HOME\" USER='$ssh_user' LOGNAME='$ssh_user' $remote"
    fi
  fi
  # Bash SECONDS follows wall-clock adjustments; WSL can step that clock
  # backwards while a guest case runs. /proc/uptime uses boot-time monotonic
  # time, so a passing case cannot acquire a negative elapsed duration.
  read -r uptime _ < /proc/uptime
  start_centis=${uptime/./}
  transport=0
  budget=$(( (row_timeout + 5) * ${#chain[@]} + command_timeout + 20 ))
  if [[ -n "$counter" ]]; then budget=$((budget + 32)); fi
  if [[ "$case" == runtime-python-install ]]; then
    # Five venv probes can outlast the former single-probe deadline on a slow
    # guest. The SSH ceiling includes the Python oracle's 150s plus cleanup.
    budget=$((budget + 164))
  elif [[ "$case" == runtime-node-install || "$case" == runtime-go-install ]]; then
    budget=$((budget + 74))
  fi
  if [[ "$case" == runtime-go-install ]]; then budget=$((budget + 210)); fi
  timeout --kill-after=5s "$budget" ssh "${opts[@]}" "$target" "$remote" > "$out/rows/$case.stdout.log" 2> "$out/rows/$case.stderr.log" || transport=$?
  read -r uptime _ < /proc/uptime
  elapsed=$(( (10#${uptime/./} - 10#$start_centis) / 100 ))
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
