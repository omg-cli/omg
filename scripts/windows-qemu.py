#!/usr/bin/env python3
"""Build current OMG source in disposable native Windows WHPX guests."""
import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import time
import tomllib
import uuid

ROOT = Path(__file__).resolve().parents[1]
GIB = 1024**3
MANIFEST = ROOT / 'tests/qemu-image-provenance/manifest.json'
RECIPE = ROOT / 'scripts/windows-qemu-guest.sh'


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


FEATURES = module('native_recipe', ROOT / 'scripts/native-build-artifact.py').FEATURES
IMAGES = module('image_verifier', ROOT / 'scripts/verify-qemu-image.py')
SMOKE_TESTS = {
    'arch': ['package_managers::pacman_db::db::tests::parse_sync_db_handles_gzip_and_zstd_after_magic_probe',
             'package_managers::pacman_db::db::tests::malformed_sync_package_does_not_hide_valid_repository_entries'],
    'debian': ['package_managers::debian_db::db::tests::parse_packages_file_sync_reads_valid_packages',
               'package_managers::debian_db::db::tests::installed_status_accepts_held_packages_but_not_partial_states'],
    'fedora': ['package_managers::dnf::tests::installed_details_preserve_canonical_names_and_native_versions',
               'package_managers::dnf::tests::installed_details_preserve_order_and_distinct_native_reasons'],
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def command(args, **kwargs):
    kwargs.setdefault('creationflags', 0x08000000 if os.name == 'nt' else 0)
    return subprocess.check_output([str(a) for a in args], text=True, encoding='utf-8', timeout=60, **kwargs).strip()


def owned(path, parent):
    path, parent = Path(path).absolute(), Path(parent).resolve()
    require(path.resolve().is_relative_to(parent) and path.resolve() != parent, 'path escapes its owner')
    for item in [path, *path.parents]:
        if item.exists():
            info = item.lstat()
            require(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400,
                    'reparse or symlink path is not admitted')
    return path


def allocated(path):
    if os.name != 'nt':
        return path.stat().st_size
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    function = kernel.GetCompressedFileSizeW
    function.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint32)]
    function.restype = ctypes.c_uint32
    high = ctypes.c_uint32()
    ctypes.set_last_error(0)
    low = function(str(path), ctypes.byref(high))
    require(low != 0xffffffff or ctypes.get_last_error() == 0, 'cannot measure allocated disk space')
    return (high.value << 32) + low


def storage_guard(state, disk=None, projected=0):
    used = sum(allocated(p) for p in state.rglob('*') if p.is_file())
    require(used + projected <= 70 * GIB, 'local guest storage exceeds its 70 GiB operating budget')
    require(shutil.disk_usage(state).free >= 20 * GIB + projected, 'C: host reserve would be exhausted')
    if disk and disk.exists():
        require(allocated(disk) <= 24 * GIB, 'owned guest disk exceeds its 24 GiB growth budget')
    return used


def memory_status():
    class Memory(ctypes.Structure):
        _fields_ = [('length', ctypes.c_ulong), ('load', ctypes.c_ulong),
                    *[(name, ctypes.c_ulonglong) for name in
                      ('total', 'available', 'page_total', 'page_available', 'virtual_total', 'virtual_available', 'extended')]]
    value = Memory()
    value.length = ctypes.sizeof(value)
    require(ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(value)), 'cannot measure Windows memory')
    return {'availablePhysicalBytes': value.available, 'availableCommitBytes': value.page_available,
            'physicalLoadPercent': value.load}


def memory_guard(memory_mib):
    value = memory_status()
    require(value['availableCommitBytes'] >= memory_mib * 1024**2 + 2 * GIB,
            'guest would exhaust Windows commit headroom')
    require(value['availablePhysicalBytes'] >= 512 * 1024**2, 'Windows is already under acute memory pressure')
    return value


def peak_working_set(process):
    class Counters(ctypes.Structure):
        _fields_ = [('size', ctypes.c_ulong), ('faults', ctypes.c_ulong),
                    *[(name, ctypes.c_size_t) for name in
                      ('peak', 'current', 'paged_peak', 'paged', 'nonpaged_peak', 'nonpaged', 'commit', 'commit_peak')]]
    value = Counters()
    value.size = ctypes.sizeof(value)
    function = ctypes.windll.psapi.GetProcessMemoryInfo
    function.argtypes = [ctypes.c_void_p, ctypes.POINTER(Counters), ctypes.c_ulong]
    require(function(int(process._handle), ctypes.byref(value), value.size), 'cannot measure owned QEMU working set')
    return value.peak


def snapshot_source(destination, root=ROOT):
    names = subprocess.check_output(['git', '-C', str(root), 'ls-files', '--cached', '--others', '--exclude-standard', '-z']).split(b'\0')
    indexed = subprocess.check_output(['git', '-C', str(root), 'ls-files', '--stage', '-z']).split(b'\0')
    modes = {row.split(b'\t', 1)[1].decode(): int(row.split(b' ', 1)[0], 8) for row in indexed if row}
    files, metadata, total = {}, {}, 0
    with tarfile.open(destination, 'w:gz') as archive:
        for name in sorted(set(os.fsdecode(n) for n in names if n)):
            relative = Path(name)
            require(not relative.is_absolute() and '..' not in relative.parts and '.git' not in relative.parts,
                    'unsafe source archive path')
            path = owned(root / relative, root)
            if not path.exists():
                continue
            require(path.is_file() and path.stat().st_size <= 32 * 1024**2, 'source is not a bounded regular file')
            data = path.read_bytes()
            total += len(data)
            require(total <= 256 * 1024**2, 'source snapshot exceeds 256 MiB')
            files[relative.as_posix()] = hashlib.sha256(data).hexdigest()
            if name in ('Cargo.toml', 'rust-toolchain.toml'):
                metadata[name] = tomllib.loads(data.decode())
            info = tarfile.TarInfo(relative.as_posix())
            info.size, info.mode = len(data), 0o755 if modes.get(name, 0) & 0o111 else 0o644
            archive.addfile(info, io.BytesIO(data))
    required = ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', '.cargo/config.toml', 'scripts/windows-qemu-guest.sh')
    require(all(name in files for name in required), 'source snapshot lacks required Rust inputs')
    dependencies = {n: h for n, h in files.items()
                    if n.endswith('Cargo.toml') or n.startswith('.cargo/') or n in required}
    return {'head': command(['git', '-C', root, 'rev-parse', 'HEAD']),
            'dirty': bool(command(['git', '-C', root, 'status', '--porcelain'])),
            'archiveSha256': digest(destination), 'files': files, 'dependencyInputs': dependencies,
            'rustVersion': metadata['rust-toolchain.toml']['toolchain']['channel'],
            'packageVersion': metadata['Cargo.toml']['package']['version']}


def freeze_recipe(archive, source, destination):
    with tarfile.open(archive, 'r:gz') as bundle:
        data = bundle.extractfile('scripts/windows-qemu-guest.sh').read()
    require(hashlib.sha256(data).hexdigest() == source['files']['scripts/windows-qemu-guest.sh'],
            'captured guest recipe identity changed')
    destination.write_bytes(data)


def template_key(source, distro, image_digest):
    inputs = {'dependencyInputs': source['dependencyInputs'], 'distro': distro,
              'features': FEATURES[distro], 'image': image_digest, 'target': 'x86_64-unknown-linux-gnu'}
    return hashlib.sha256(json.dumps(inputs, sort_keys=True).encode()).hexdigest()


def verify_build(result, request):
    require(result.get('passed') is True and result.get('stage') == 'built', 'guest did not complete a real build')
    for name in ('distro', 'sourceArchiveSha256', 'bootId', 'features'):
        require(result.get(name) == request[name], 'guest result identity mismatch: ' + name)
    require(result.get('profile') == 'dev', 'unexpected Cargo profile')
    require(result.get('toolchain') == request['rustVersion'] and
            result.get('compiler', '').startswith('rustc ' + request['rustVersion'] + ' ') and
            'host: x86_64-unknown-linux-gnu' in result['compiler'].splitlines(), 'wrong Rust compiler')
    require(set(result.get('binaryHashes', {})) == {'omg', 'omgd'} and
            all(re.fullmatch('[0-9a-f]{64}', h) for h in result['binaryHashes'].values()), 'missing compiled binaries')
    execution = result.get('binaryexecution', [])
    require(len(execution) == 2 and {x.get('binary') for x in execution} == {'omg', 'omgd'} and
            all(x.get('versionExit') == 0 and x.get('helpExit') == 0 and
                x.get('version') == x['binary'] + ' ' + request['packageVersion'] for x in execution),
            'compiled binaries did not execute successfully')
    inventory = result.get('inventoryproof', {})
    require(inventory.get('completeNamesEqual') is True and inventory.get('nativeStateUnchanged') is True and
            type(inventory.get('nativeExplicitCount')) is int and inventory['nativeExplicitCount'] > 0,
            'actual native inventory check failed')
    tests = result.get('tests', [])
    expected = SMOKE_TESTS[FEATURES[request['distro']].split(',')[0]]
    require(len(tests) == 2 and {t.get('name') for t in tests} == set(expected) and
            all(t.get('passed') == 1 and t.get('failed') == 0 and t.get('ignored') == 0 for t in tests),
            'required named tests did not execute successfully')


class Guest:
    def __init__(self, args, run, backing, online, receipt):
        self.args, self.run, self.backing, self.online, self.receipt = args, run, backing, online, receipt
        self.disk, self.vm = run / 'disk.qcow2', None
        self.ssh = None
        self.preserve_disk = False
        self.low_memory_since = None

    def progress(self):
        storage_guard(self.args.state, self.disk)
        memory = memory_status()
        self.receipt['minimumHostPhysicalBytes'] = min(self.receipt.get('minimumHostPhysicalBytes', memory['availablePhysicalBytes']), memory['availablePhysicalBytes'])
        if self.vm and self.vm.poll() is None:
            self.receipt['peakQemuWorkingSetBytes'] = max(self.receipt.get('peakQemuWorkingSetBytes', 0), peak_working_set(self.vm))
        require(memory['availableCommitBytes'] >= GIB, 'Windows commit headroom exhausted during guest work')
        if memory['availablePhysicalBytes'] < 256 * 1024**2:
            if self.low_memory_since is None:
                self.low_memory_since = time.monotonic()
            require(time.monotonic() - self.low_memory_since < 15, 'sustained Windows memory pressure during guest work')
        else:
            self.low_memory_since = None

    def monitored(self, argv, label, timeout, input_file=None):
        log = self.run / (label + '.log')
        stream = input_file.open('rb') if input_file else subprocess.DEVNULL
        try:
            with log.open('wb') as output:
                process = subprocess.Popen([str(a) for a in argv], stdin=stream, stdout=output,
                                           stderr=subprocess.STDOUT, creationflags=subprocess.CREATE_NO_WINDOW)
                started = time.monotonic()
                try:
                    while process.poll() is None:
                        self.progress()
                        require(self.vm is None or self.vm.poll() is None, 'owned QEMU stopped during ' + label)
                        require(time.monotonic() - started < timeout, label + ' exceeded its deadline')
                        time.sleep(2)
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=15)
                require(process.returncode == 0, f'{label} failed with exit {process.returncode}; see {log}')
        finally:
            if input_file:
                stream.close()
        return log

    def shell(self, script, label, timeout=180):
        path = self.run / (label + '.sh')
        path.write_text(script, encoding='utf-8', newline='\n')
        return self.monitored([*self.ssh, 'bash -se'], label, timeout, path)

    def phase(self, mode, distro, source, jobs):
        remote = shlex.join(['bash', '-se', '--', mode, distro, source['archiveSha256'], str(jobs)])
        return self.monitored([*self.ssh, remote], mode, 5400, self.run / 'guest-recipe.sh')

    def diagnostics(self):
        script = '''python3 - <<'PY'
import hashlib, json, pathlib
names = ['result.json','compiler.txt','fetch.log','build.log','build.stderr.log','test-1.log','test-2.log',
         'inventory.log','omg--version.log','omgd--version.log','omg--help.log','omgd--help.log']
out = {}
for name in names:
    p = pathlib.Path('/home/bench') / name
    if p.is_file() and not p.is_symlink():
        raw = p.read_bytes()
        out[name] = {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
                     'tail':raw[-1024*1024:].decode('utf-8', errors='replace')}
print(json.dumps(out))
PY
'''
        path = self.shell(script, 'diagnostics', 90)
        value = json.loads(path.read_text(encoding='utf-8'))
        require(bool(value), 'guest diagnostics are empty')
        write_json(self.run / 'guest-diagnostics.json', value)
        self.receipt['guestDiagnosticsSha256'] = digest(self.run / 'guest-diagnostics.json')

    def transfer(self, local, remote, download=False):
        args = ['scp', *self.ssh[1:-1]]
        args[args.index('-p')] = '-P'
        address = self.ssh[-1] + ':' + remote
        return self.monitored([*args, address, local] if download else [*args, local, address],
                              'download-' + Path(remote).name if download else 'upload', 180)

    def start(self):
        tools = self.args.tools
        storage_guard(self.args.state, projected=24 * GIB)
        self.receipt['availableHostMemoryBefore'] = memory_guard(self.args.memory_mib)
        command([tools / 'ucrt64/bin/qemu-img.exe', 'create', '-f', 'qcow2', '-F', 'qcow2',
                 '-b', self.backing, self.disk, '40G'])
        for name in ('client-key', 'host-key'):
            command(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', self.run / name])
        public = (self.run / 'host-key.pub').read_text().strip()
        config = {'preserve_hostname': True, 'users': [{'name': 'bench', 'shell': '/bin/bash',
                  'sudo': 'ALL=(ALL) NOPASSWD:ALL', 'lock_passwd': True,
                  'ssh_authorized_keys': [(self.run / 'client-key.pub').read_text().strip()]}],
                  'ssh_pwauth': False, 'disable_root': True, 'ssh_deletekeys': True,
                  'ssh_keys': {'ed25519_private': (self.run / 'host-key').read_text(), 'ed25519_public': public},
                  'ssh': {'emit_keys_to_console': False}, 'package_update': False, 'package_upgrade': False,
                  'bootcmd': [['systemctl', 'mask', '--now', 'snapd.service', 'snapd.socket',
                               'snapd.seeded.service', 'snapd.autoimport.service']] if self.args.distro == 'ubuntu' else []}
        if self.args.distro == 'arch':
            config['bootcmd'] = [['systemctl', 'mask', '--now', 'systemd-time-wait-sync.service'],
                                 'mkdir -p /etc/systemd/network; printf "[Match]\\nMACAddress=52:54:00:12:34:56\\n[Network]\\nAddress=10.0.2.15/24\\nGateway=10.0.2.2\\nDNS=10.0.2.3\\nDHCP=no\\nIPv6AcceptRA=no\\n" > /etc/systemd/network/05-omg-whpx.network',
                                 ['systemctl', 'restart', '--no-block', 'systemd-networkd']]
        (self.run / 'user-data').write_text('#cloud-config\n' + json.dumps(config), encoding='utf-8')
        (self.run / 'meta-data').write_text('instance-id: ' + self.run.name + '\n', encoding='utf-8')
        command([tools / 'usr/bin/xorriso.exe', '-as', 'mkisofs', '-output', 'seed.iso',
                 '-volid', 'CIDATA', '-joliet', '-rock', 'user-data', 'meta-data'], cwd=self.run, stderr=subprocess.DEVNULL)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        (self.run / 'known-hosts').write_text(f'[127.0.0.1]:{port} {public}\n', encoding='utf-8')
        self.ssh = ['ssh', '-F', 'NUL', '-i', str(self.run / 'client-key'), '-p', str(port),
                    '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                    '-o', 'UserKnownHostsFile=' + str(self.run / 'known-hosts'), '-o', 'ConnectTimeout=2', 'bench@127.0.0.1']
        argv = [tools / 'ucrt64/bin/qemu-system-x86_64.exe', '-name', self.run.name, '-machine', 'pc',
                '-accel', 'whpx', '-cpu', 'host', '-smp', '4', '-m', str(self.args.memory_mib),
                '-display', 'none', '-vga', 'none', '-monitor', 'none', '-no-reboot',
                '-serial', 'file:' + str(self.run / 'serial.log')]
        for path, node, fmt, readonly in ((self.disk, 'root', 'qcow2', False), (self.run / 'seed.iso', 'seed', 'raw', True)):
            argv += ['-blockdev', json.dumps({'driver': fmt, 'file': {'driver': 'file', 'filename': str(path)},
                                             'node-name': node, 'read-only': readonly}),
                     '-device', 'virtio-blk-pci,drive=' + node]
        if self.args.distro == 'arch':
            firmware = tools / 'ucrt64/share/qemu'
            shutil.copyfile(firmware / 'edk2-i386-vars.fd', self.run / 'vars.fd')
            for path, readonly in ((firmware / 'edk2-x86_64-code.fd', True), (self.run / 'vars.fd', False)):
                require(',' not in str(path), 'UEFI filename contains a QEMU option delimiter')
                argv += ['-drive', f'if=pflash,format=raw,readonly={"on" if readonly else "off"},file={path}']
        argv += ['-netdev', f'user,id=n,restrict={"off" if self.online else "on"},ipv6=off,hostfwd=tcp:127.0.0.1:{port}-:22',
                 '-device', 'virtio-net-pci,netdev=n,romfile=,mac=52:54:00:12:34:56']
        self.receipt.update(qemuArgv=[str(a) for a in argv], networking='development NAT' if self.online else 'restricted user networking; Cargo offline', memoryMiB=self.args.memory_mib)
        with (self.run / 'qemu.log').open('wb') as log:
            self.vm = subprocess.Popen([str(a) for a in argv], stdout=log, stderr=subprocess.STDOUT,
                                       creationflags=subprocess.CREATE_NO_WINDOW)
        self.receipt['ownedQemuPid'] = self.vm.pid
        self.receipt['qemuExecutableSha256'] = digest(tools / 'ucrt64/bin/qemu-system-x86_64.exe')
        started = time.monotonic()
        while time.monotonic() - started < 240:
            require(self.vm.poll() is None, 'QEMU exited before SSH readiness')
            self.progress()
            try:
                result = subprocess.run([*self.ssh, 'cat /proc/sys/kernel/random/boot_id'], capture_output=True, text=True, timeout=8)
            except subprocess.TimeoutExpired:
                time.sleep(2)
                continue
            if result.returncode == 0:
                boot = result.stdout.strip()
                require(re.fullmatch('[0-9a-f-]{36}', boot), 'invalid guest boot identity')
                self.receipt['bootId'] = boot
                self.shell('timeout 180 cloud-init status --wait\ntest ! -e /var/tmp/omg-whpx-marker\ntest ! -e /home/bench/source\n', 'cloud-init', 210)
                self.receipt['readySeconds'] = round(time.monotonic() - started, 3)
                return
            time.sleep(2)
        raise TimeoutError('guest SSH readiness exceeded 240 seconds')

    def poweroff(self):
        result = subprocess.run([*self.ssh, 'sudo poweroff'], capture_output=True, timeout=15)
        self.receipt['poweroffTransportExit'] = result.returncode
        require(self.vm.wait(timeout=45) == 0, 'QEMU did not power off successfully')

    def close(self):
        if self.vm and self.vm.poll() is None:
            self.vm.terminate()
            self.vm.wait(timeout=30)
        self.receipt['processStopped'] = self.vm is None or self.vm.poll() is not None
        if self.disk.exists():
            self.receipt['retiredDiskSha256'] = digest(self.disk)
            self.receipt['peakDiskAllocatedBytes'] = allocated(self.disk)
        require(self.receipt['processStopped'], 'refusing to retire a live guest disk')
        if self.preserve_disk and self.disk.exists():
            self.receipt['retainedFailureDisk'] = str(self.disk)
        names = ['vars.fd', 'seed.iso', 'user-data', 'client-key', 'client-key.pub', 'host-key', 'host-key.pub']
        if not self.preserve_disk:
            names.append('disk.qcow2')
        for name in names:
            path = owned(self.run / name, self.run)
            if path.exists():
                path.unlink()
        self.receipt['overlayAndSecretsRetired'] = not self.preserve_disk


def execute(args):
    require(os.name == 'nt', 'this runner requires native Windows')
    args.state = owned(args.state, ROOT / '.git')
    args.state.mkdir(parents=True, exist_ok=True)
    require(args.state.drive.upper() == 'C:', 'guest data must stay on C:')
    args.tools = args.tools.resolve()
    run = args.state / ('run-' + uuid.uuid4().hex)
    run.mkdir()
    receipt = {'schemaVersion': 1, 'kind': 'local-windows-whpx-development', 'status': 'NOT VERIFIED',
               'mode': args.action, 'distro': args.distro, 'startedAt': datetime.now(timezone.utc).isoformat()}
    guest = None
    try:
        source = snapshot_source(run / 'source.tar.gz')
        freeze_recipe(run / 'source.tar.gz', source, run / 'guest-recipe.sh')
        write_json(run / 'source.json', source)
        receipt['source'] = source
        entry = json.loads(MANIFEST.read_text())['images'][args.distro + '-x86_64']
        image = args.image.resolve()
        env = os.environ.copy()
        os.environ['PATH'] = str(args.tools / 'usr/bin') + os.pathsep + env['PATH']
        try:
            receipt['image'] = IMAGES.verify(MANIFEST, args.distro + '-x86_64', entry['url'], entry['digest'], image,
                                             str(args.tools / 'usr/bin/gpgv.exe'))
        finally:
            os.environ.clear()
            os.environ.update(env)
        key = template_key(source, args.distro, entry['digest'])
        templates = args.state / 'templates'
        templates.mkdir(exist_ok=True)
        template = templates / (args.distro + '-' + key + '.qcow2')
        metadata = template.with_suffix('.json')
        backing = image
        if args.action == 'run':
            require(template.is_file() and metadata.is_file(), 'matching template is missing; prepare this distro first')
            record = json.loads(metadata.read_text())
            require(record['key'] == key and record['templateSha256'] == digest(template), 'template identity changed')
            require(record['basePath'] == str(image) and record['baseDigest'] == entry['digest'], 'template backing image changed')
            backing = template
        else:
            require(not template.exists() and not metadata.exists(), 'matching template already exists; run it instead')
        receipt['templateKey'] = key
        before = digest(backing)
        guest = Guest(args, run, backing, args.action == 'prepare', receipt)
        guest.start()
        if args.action == 'run':
            require(receipt['bootId'] != record['preparationBootId'], 'fresh child reused preparation boot identity')
        guest.transfer(run / 'source.tar.gz', '/home/bench/source.tar.gz')
        guest.phase('provision' if args.action == 'prepare' else 'build', args.distro, source, args.jobs)
        guest.transfer(run / 'result.json', '/home/bench/result.json', download=True)
        result = json.loads((run / 'result.json').read_text())
        receipt['guest'] = result
        guest.diagnostics()
        if args.action == 'prepare':
            require(result.get('passed') is True and result.get('stage') == 'provisioned', 'provisioning did not complete')
            log = guest.phase('seal', args.distro, source, args.jobs)
            seal = json.loads(log.read_text().splitlines()[-1])
            require(all(seal.get(k) is True for k in ('scheduledPoweroff', 'credentialsRemoved', 'sourceAndTargetAbsent')), 'template sanitation did not complete')
            require(guest.vm.wait(timeout=90) == 0, 'template did not power off')
            require(digest(backing) == before, 'publisher base changed')
            guest.disk.rename(template)
            template.chmod(0o444)
            write_json(metadata, {'key': key, 'templateSha256': digest(template), 'basePath': str(image),
                                 'baseDigest': entry['digest'], 'preparationBootId': receipt['bootId'],
                                 'provisioning': result, 'sanitation': seal})
            receipt['template'] = str(template)
        else:
            verify_build(result, {'distro': args.distro, 'sourceArchiveSha256': source['archiveSha256'],
                                 'bootId': receipt['bootId'], 'features': FEATURES[args.distro], 'rustVersion': source['rustVersion'],
                                 'packageVersion': source['packageVersion']})
            guest.poweroff()
            require(digest(backing) == before, 'read-only template changed')
        receipt['status'] = 'VERIFIED'
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        receipt['error'] = str(error)
        if guest and guest.vm and guest.receipt.get('bootId') and not receipt.get('guestDiagnosticsSha256'):
            try:
                guest.diagnostics()
            except (OSError, ValueError, subprocess.SubprocessError) as diagnostics_error:
                receipt['diagnosticsError'] = str(diagnostics_error)
                guest.preserve_disk = True
        raise
    finally:
        try:
            if guest:
                guest.close()
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            receipt['status'], receipt['cleanupError'] = 'NOT VERIFIED', str(error)
            raise
        finally:
            if sys.exc_info()[0] is not None:
                receipt['status'] = 'NOT VERIFIED'
            write_json(run / 'receipt.json', receipt)
            print(json.dumps({'status': receipt['status'], 'receipt': str(run / 'receipt.json'), 'error': receipt.get('error')}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'run'))
    parser.add_argument('--distro', required=True, choices=tuple(FEATURES))
    parser.add_argument('--tools', required=True, type=Path, help='MSYS2 root containing ucrt64/bin and usr/bin')
    parser.add_argument('--image', required=True, type=Path, help='reviewed publisher QCOW2 image')
    parser.add_argument('--state', type=Path, default=ROOT / '.git/omg-whpx')
    parser.add_argument('--memory-mib', type=int, default=4096, choices=(4096, 6144, 8192))
    parser.add_argument('--jobs', type=int, default=2, choices=(1, 2, 3, 4))
    args = parser.parse_args()
    try:
        execute(args)
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
