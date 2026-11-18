#!/usr/bin/env bash
set -Eeuo pipefail

mode=$1
distro=$2
archive_sha=$3
jobs=$4
[[ "$mode" =~ ^(provision|build|seal)$ && "$distro" =~ ^(arch|debian|debian-trixie|ubuntu|fedora)$ ]]
[[ "$archive_sha" =~ ^[0-9a-f]{64}$ && "$jobs" =~ ^[1-4]$ ]]
[[ "$EUID" -ne 0 && "$(id -un)" == bench && "$HOME" == /home/bench ]]
cd /home/bench
[[ ! -L result.json ]]
rm -f -- result.json
stage=validation
trap 'status=$?; printf "{\"stage\":\"failed\",\"failedStage\":\"%s\",\"mode\":\"%s\",\"distro\":\"%s\",\"sourceArchiveSha256\":\"%s\",\"passed\":false,\"exitCode\":%d,\"line\":%d}\n" "$stage" "$mode" "$distro" "$archive_sha" "$status" "$LINENO" > /home/bench/result.json; exit "$status"' ERR
. /etc/os-release
[[ "$(uname -m)" == x86_64 ]]
case "$distro" in
    arch) [[ "$ID" == arch ]]; features=arch,pgp,license ;;
    debian) [[ "$ID" == debian && "$VERSION_ID" == 12 ]]; features=debian,pgp,license ;;
    debian-trixie) [[ "$ID" == debian && "$VERSION_ID" == 13 ]]; features=debian,pgp,license ;;
    ubuntu) [[ "$ID" == ubuntu && "$VERSION_ID" == 24.04 ]]; features=debian,pgp,license ;;
    fedora) [[ "$ID" == fedora && "$VERSION_ID" == 44 ]]; features=fedora,pgp,license ;;
esac
export PATH=/home/bench/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export MODE="$mode" DISTRO="$distro" SOURCE_ARCHIVE_SHA256="$archive_sha" FEATURES="$features"

if [[ "$mode" == seal ]]; then
    stage=seal
    [[ ! -e /home/bench/source && ! -e /home/bench/source.tar.gz && ! -e /var/tmp/omg-whpx-marker && ! -L /var/tmp/omg-whpx-marker ]]
    sudo -n shutdown -h +1
    sudo -n cloud-init clean --logs --seed --machine-id
    rm -f -- /home/bench/.ssh/authorized_keys
    sudo -n find /etc/ssh -maxdepth 1 -type f -name 'ssh_host_*' -delete
    [[ ! -e /home/bench/.ssh/authorized_keys ]]
    sudo -n test ! -e /var/lib/cloud/seed
    [[ -z "$(sudo -n find /etc/ssh -maxdepth 1 -name 'ssh_host_*' -print -quit)" ]]
    sync
    printf '{"scheduledPoweroff":true,"credentialsRemoved":true,"sourceAndTargetAbsent":true}\n'
    exit 0
fi

[[ ! -e /home/bench/source && ! -L /home/bench/source && ! -e /var/tmp/omg-whpx-marker && ! -L /var/tmp/omg-whpx-marker ]]
if [[ "$mode" == provision ]]; then
    stage=packages
    case "$distro" in
        arch)
            timeout -k 15s 20m sudo -n pacman -Syu --noconfirm --needed base-devel git pkgconf openssl libarchive clang cmake curl python fish tar gzip xz
            ;;
        debian|debian-trixie|ubuntu)
            timeout -k 15s 10m sudo -n apt-get -o APT::Update::Error-Mode=any -o Acquire::Retries=2 update
            timeout -k 15s 20m sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl git build-essential pkg-config sudo python3 python3-apt python3-venv fish zstd libssl-dev libapt-pkg-dev clang cmake zlib1g-dev liblzma-dev libbz2-dev tar gzip xz-utils
            ;;
        fedora)
            timeout -k 15s 20m sudo -n dnf --setopt='*.skip_if_unavailable=False' --disable-repo=fedora-cisco-openh264 install -y --setopt=install_weak_deps=False gcc gcc-c++ git clang cmake make perl-core openssl-devel pkgconf-pkg-config findutils curl procps-ng python3 zsh fish rpm dnf sqlite yum-utils fedora-release tar gzip xz
            ;;
    esac
    stage=toolchain
    [[ ! -e /home/bench/rustup-init && ! -L /home/bench/rustup-init ]]
    curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 20 --max-time 300 --retry 2 https://static.rust-lang.org/rustup/archive/1.28.2/x86_64-unknown-linux-gnu/rustup-init -o /home/bench/rustup-init
    printf '20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c  /home/bench/rustup-init\n' | sha256sum --check
    chmod 0700 /home/bench/rustup-init
    timeout -k 15s 15m /home/bench/rustup-init -y --no-modify-path --profile minimal --default-toolchain 1.95.0
    rm -f -- /home/bench/rustup-init
    timeout -k 15s 10m rustup component add --toolchain 1.95.0 rustfmt clippy
fi

stage=source
python3 - "$archive_sha" <<'PY'
import hashlib, os, pathlib, shutil, stat, sys, tarfile
archive = pathlib.Path('/home/bench/source.tar.gz')
assert not archive.is_symlink() and stat.S_ISREG(archive.stat().st_mode)
assert archive.stat().st_size <= 512 * 1024 * 1024
assert hashlib.sha256(archive.read_bytes()).hexdigest() == sys.argv[1], 'source archive digest mismatch'
destination = pathlib.Path('/home/bench/source')
destination.mkdir(exist_ok=False)
with tarfile.open(archive, 'r:*') as incoming:
    members = incoming.getmembers()
    assert len(members) <= 100000 and sum(m.size for m in members) <= 1024 * 1024 * 1024
    seen = set()
    for member in members:
        name = pathlib.PurePosixPath(member.name)
        assert name.parts and not name.is_absolute() and '..' not in name.parts and '.git' not in name.parts
        assert '\\' not in member.name and member.name not in seen and (member.isfile() or member.isdir())
        seen.add(member.name)
        target = destination.joinpath(*name.parts)
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            with incoming.extractfile(member) as source, target.open('xb') as output:
                shutil.copyfileobj(source, output)
            os.chmod(target, 0o755 if member.mode & 0o111 else 0o644)
assert (destination/'Cargo.lock').is_file() and (destination/'Cargo.toml').is_file()
PY
cd /home/bench/source
[[ "$(rustc --version)" == 'rustc 1.95.0 '* ]]
[[ "$(rustc -vV | sed -n 's/^host: //p')" == x86_64-unknown-linux-gnu ]]
rustc -vV > /home/bench/compiler.txt

if [[ "$mode" == provision ]]; then
    stage=fetch
    timeout -k 15s 20m cargo fetch --locked --target x86_64-unknown-linux-gnu > /home/bench/fetch.log 2>&1
    [[ ! -e target ]]
    python3 - <<'PY'
import hashlib, json, os, pathlib, subprocess, tomllib
root = pathlib.Path('/home/bench/source')
toolchain = tomllib.loads((root/'rust-toolchain.toml').read_text())['toolchain']['channel']
assert toolchain == '1.95.0'
commands = {'arch':['pacman','-Q'], 'fedora':['rpm','-qa','--qf','%{NAME}\t%{ARCH}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n']}
command = commands.get(os.environ['DISTRO'], ['dpkg-query','-W','-f','${binary:Package}\t${Version}\t${db:Status-Status}\n'])
packages = sorted(subprocess.check_output(command, text=True).splitlines())
receipt = {'stage':'provisioned','passed':True,'mode':'provision','distro':os.environ['DISTRO'],
    'sourceArchiveSha256':os.environ['SOURCE_ARCHIVE_SHA256'],'features':os.environ['FEATURES'],
    'bootId':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
    'toolchain':toolchain,'compiler':pathlib.Path('/home/bench/compiler.txt').read_text(),
    'packageInventorySha256':hashlib.sha256('\n'.join(packages).encode()).hexdigest(),
    'packageCount':len(packages),'cachedInputs':{name:hashlib.sha256((root/name).read_bytes()).hexdigest()
      for name in ['Cargo.toml','Cargo.lock','rust-toolchain.toml']},'compiledProjectTargets':False}
pathlib.Path('/home/bench/result.json').write_text(json.dumps(receipt,indent=2)+'\n')
PY
    cd /home/bench
    python3 - <<'PY'
import pathlib, shutil
p = pathlib.Path('/home/bench/source')
assert p.resolve() == p and not p.is_symlink()
shutil.rmtree(p)
pathlib.Path('/home/bench/source.tar.gz').unlink()
PY
    exit 0
fi

stage=build
[[ ! -e target && ! -L target && ! -e /var/tmp/omg-whpx-marker && ! -L /var/tmp/omg-whpx-marker ]]
cat /proc/sys/kernel/random/boot_id > /var/tmp/omg-whpx-marker
unset OMG_TEST_MODE CARGO_ENCODED_RUSTFLAGS RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="$jobs" CARGO_TERM_COLOR=never NO_COLOR=1
export RUSTFLAGS=''
if [[ "$distro" == arch ]]; then export RUSTFLAGS='-C target-cpu=x86-64-v2'; fi
python3 - <<'PY'
import json, os, pathlib, subprocess
commands = {'arch':['pacman','-Q'], 'fedora':['rpm','-qa','--qf','%{NAME}\t%{ARCH}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n']}
command = commands.get(os.environ['DISTRO'], ['dpkg-query','-W','-f','${binary:Package}\t${Version}\t${db:Status-Status}\n'])
rows = sorted(subprocess.check_output(command,text=True).splitlines())
pathlib.Path('/home/bench/packages-before.json').write_text(json.dumps(rows))
PY
timeout -k 15s 90m cargo build --bins --no-default-features --features "$features" --locked --offline --message-format=json > /home/bench/build.log 2> /home/bench/build.stderr.log
stage=tests
case "$distro" in
    arch) methods=$'package_managers::pacman_db::db::tests::parse_sync_db_handles_gzip_and_zstd_after_magic_probe\npackage_managers::pacman_db::db::tests::malformed_sync_package_does_not_hide_valid_repository_entries' ;;
    fedora) methods=$'package_managers::dnf::tests::installed_details_preserve_canonical_names_and_native_versions\npackage_managers::dnf::tests::installed_details_preserve_order_and_distinct_native_reasons' ;;
    *) methods=$'package_managers::debian_db::db::tests::parse_packages_file_sync_reads_valid_packages\npackage_managers::debian_db::db::tests::installed_status_accepts_held_packages_but_not_partial_states' ;;
esac
printf '%s\n' "$methods" > /home/bench/test-names.txt
number=0
while IFS= read -r method; do
    number=$((number+1))
    timeout -k 15s 45m cargo test --lib --no-default-features --features "$features" --locked --offline "$method" -- --exact --nocapture --test-threads=1 > "/home/bench/test-$number.log" 2>&1
done < /home/bench/test-names.txt
stage=behavior
python3 - <<'PY'
import hashlib, json, os, pathlib, re, subprocess, tomllib
home = pathlib.Path('/home/bench')
source = home/'source'
version = tomllib.loads((source/'Cargo.toml').read_text())['package']['version']
build = [json.loads(line) for line in (home/'build.log').read_text().splitlines() if line.strip()]
assert build[-1].get('reason') == 'build-finished' and build[-1].get('success') is True
artifacts = {item['target']['name']:item for item in build if item.get('reason') == 'compiler-artifact' and item.get('executable') and item['target']['name'] in ('omg','omgd')}
assert set(artifacts) == {'omg','omgd'}
hashes, execution = {}, []
for name in ('omg','omgd'):
    binary = source/'target/debug'/name
    assert not binary.is_symlink() and binary.is_file() and os.access(binary,os.X_OK)
    assert artifacts[name]['executable'] == str(binary) and artifacts[name]['fresh'] is False
    hashes[name] = hashlib.sha256(binary.read_bytes()).hexdigest()
    outputs = {}
    for option in ('--version','--help'):
        result = subprocess.run([str(binary),option],capture_output=True,text=True,timeout=30)
        assert result.returncode == 0, (name,option,result.stderr)
        (home/(name+option+'.log')).write_text(result.stdout+result.stderr)
        outputs[option] = result.stdout
    assert outputs['--version'].strip() == name+' '+version
    assert 'Usage:' in outputs['--help'] and name in outputs['--help']
    execution.append({'binary':name,'version':outputs['--version'].strip(),'versionExit':0,'helpExit':0})
tests = []
for i,name in enumerate((home/'test-names.txt').read_text().splitlines(),1):
    text = (home/f'test-{i}.log').read_text()
    assert re.search(r'(?m)^test '+re.escape(name)+r' \.\.\. ok\s*$',text),name
    assert re.search(r'(?m)^test result: ok\. 1 passed; 0 failed; 0 ignored;',text),name
    tests.append({'name':name,'passed':1,'failed':0,'ignored':0,'logSha256':hashlib.sha256(text.encode()).hexdigest()})
assert len(tests) == 2
distro = os.environ['DISTRO']
commands = {'arch':['pacman','-Q'], 'fedora':['rpm','-qa','--qf','%{NAME}\t%{ARCH}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n']}
snapshot_command = commands.get(distro,['dpkg-query','-W','-f','${binary:Package}\t${Version}\t${db:Status-Status}\n'])
before = json.loads((home/'packages-before.json').read_text())
if distro == 'arch':
    expected = set(subprocess.check_output(['pacman','-Qqe'],text=True).splitlines())
elif distro == 'fedora':
    expected = set(subprocess.check_output(['dnf','--cacheonly','--disable-repo=*','--setopt=disable_excludes=*','repoquery','--userinstalled','--qf','%{name}\\n'],text=True,timeout=90).splitlines())
else:
    manual = set(subprocess.check_output(['apt-mark','showmanual'],text=True).splitlines())
    installed = subprocess.check_output(['dpkg-query','-W','-f','${Package}\t${db:Status-Status}\n'],text=True)
    expected = manual & {line.split('\t')[0] for line in installed.splitlines() if line.endswith('\tinstalled')}
result = subprocess.run([str(source/'target/debug/omg'),'--json','explicit'],capture_output=True,text=True,timeout=90)
(home/'inventory.log').write_text(result.stdout+result.stderr)
assert result.returncode == 0,result.stderr
value = json.loads(result.stdout)
names = value['packages']
assert expected and isinstance(names,list) and all(isinstance(n,str) and n for n in names)
assert len(names) == len(set(names)) == value['count'] and set(names) == expected
after = sorted(subprocess.check_output(snapshot_command,text=True).splitlines())
assert before == after,'installed package state changed'
environment = {name:os.environ[name] for name in ['CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG','CARGO_INCREMENTAL','CARGO_BUILD_JOBS','RUSTFLAGS']}
receipt = {'stage':'built','passed':True,'mode':'build','distro':distro,'sourceArchiveSha256':os.environ['SOURCE_ARCHIVE_SHA256'],
    'bootId':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'toolchain':'1.95.0',
    'compiler':(home/'compiler.txt').read_text(),'profile':'dev','environment':environment,'features':os.environ['FEATURES'],
    'binaryHashes':hashes,'buildArgv':['cargo','build','--bins','--no-default-features','--features',os.environ['FEATURES'],'--locked','--offline','--message-format=json'],
    'buildLogSha256':hashlib.sha256((home/'build.log').read_bytes()).hexdigest(),'tests':tests,'binaryexecution':execution,
    'inventoryproof':{'command':['omg','--json','explicit'],'nativeExplicitCount':len(expected),'completeNamesEqual':True,'nativeStateUnchanged':True,
      'installedInventorySha256':hashlib.sha256('\n'.join(after).encode()).hexdigest()}}
(home/'result.json').write_text(json.dumps(receipt,indent=2)+'\n')
PY
