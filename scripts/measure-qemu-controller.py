#!/usr/bin/env python3
"""Measure an optional controller image on native disposable CI runners."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import tempfile
import time
import uuid

SCRIPTS = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('controller_image', SCRIPTS / 'qemu-controller-image.py')
IMAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IMAGE)
PLATFORMS = {
    'amd64': ('x86_64', '6788062a1b42ac281f053ac876170b79a3eaed5d61383b8ed7eaca6c6965f3b1',
              'qemu-system-x86', 'ovmf'),
    'arm64': ('aarch64', '0aa0908407cce3da2a90c1d80acc6ca5ca57401ed63eecfa8149b7ba3cc40829',
              'qemu-system-arm', 'qemu-efi-aarch64'),
}
APT = ('apt-get -o APT::Update::Error-Mode=any -o Acquire::Retries=2 '
       '-o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 update && '
       'DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=2 '
       '-o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 '
       'install -y --no-install-recommends "$1" qemu-utils cloud-image-utils '
       'openssh-client curl ca-certificates "$2" jq python3 && '
       'python3 /checks/install-qemu-libslirp.py "$1" && '
       'bash /checks/check-qemu-controller.sh "$1"')
RUNTIME = r'''
import ctypes,json,re,subprocess,sys
arch,binary=sys.argv[1:]
installed=subprocess.check_output(['dpkg-query','-W','-f=${db:Status-Status}\n${Version}\n${Architecture}','libslirp0'],text=True,timeout=10).splitlines()
assert installed==['installed','4.9.5-1',arch],installed
links=subprocess.check_output(['ldd','/usr/bin/'+binary],text=True,timeout=10)
paths=re.findall(r'^\s*libslirp\.so\.0 => (/[^\s]+) \(0x[0-9a-f]+\)$',links,re.MULTILINE)
assert len(paths)==1,paths
library=ctypes.CDLL(paths[0]);library.slirp_version_string.restype=ctypes.c_char_p
version=library.slirp_version_string().decode('ascii');assert version=='4.9.5',version
print(json.dumps(dict(installed=installed,library=paths[0],runtime=version)))
'''


def sha(path):
    with Path(path).open('rb') as stream:
        return IMAGE.digest(stream, IMAGE.MAX_ARCHIVE)[0]


class Measurement:
    def __init__(self, args):
        self.args = args
        machine, digest, self.package, self.firmware = PLATFORMS[args.architecture]
        if platform.system() != 'Linux' or platform.machine() != machine:
            raise ValueError('native Linux architecture is required; emulation is not measured')
        if not re.fullmatch(r'[0-9a-f]{40}', args.source):
            raise ValueError('invalid source commit')
        actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=SCRIPTS,
                                         text=True, timeout=10).strip()
        if actual != args.source:
            raise ValueError('checkout differs from expected source')
        self.base_digest = 'sha256:' + digest
        self.base = 'debian:trixie@' + self.base_digest
        self.output = Path(args.output).resolve()
        self.output.mkdir(parents=True, exist_ok=True)
        self.records = []

    def run(self, name, command, timeout=120, watched=None, check=True):
        log = self.output / (name + '.log')
        if log.exists():
            raise ValueError('measurement step already has a receipt: ' + name)
        started = time.monotonic()
        failure = None
        with log.open('xb') as stream:
            child = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT,
                                     stdin=subprocess.DEVNULL, start_new_session=True)
            try:
                while child.poll() is None:
                    if (time.monotonic() - started > timeout or log.stat().st_size > 32 * 1024**2
                            or (watched and watched.exists() and watched.stat().st_size > IMAGE.MAX_ARCHIVE)):
                        raise TimeoutError('measurement exceeded its time or byte limit: ' + name)
                    time.sleep(0.2)
            except (TimeoutError, OSError) as error:
                failure = error
            finally:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
        result = dict(name=name, exit=child.returncode, seconds=time.monotonic() - started,
                      log_sha256=sha(log))
        if failure is not None:
            result['failure'] = str(failure)
        self.records.append(result)
        (self.output / 'steps.json').write_text(json.dumps(self.records, indent=2) + '\n')
        if failure is not None:
            raise failure
        if check and child.returncode:
            raise RuntimeError('measurement command failed: ' + name)
        return log.read_text(), result

    def verify(self, archive, archive_sha, config_sha):
        return IMAGE.verify_archive(archive, archive_sha, config_sha, self.args.architecture,
                                    self.args.source, self.base_digest, self.package)

    def build(self):
        tag = 'omg-controller-measurement:' + uuid.uuid4().hex
        files = ['qemu-controller.Dockerfile', 'install-qemu-libslirp.py', 'check-qemu-controller.sh']
        with tempfile.TemporaryDirectory(prefix='omg-controller-context-') as directory:
            for name in files:
                shutil.copyfile(SCRIPTS / name, Path(directory) / name)
            self.run('build', ['docker', 'build', '--no-cache', '--pull', '--file',
                              str(Path(directory) / files[0]), '--tag', tag,
                              '--build-arg', 'BASE_IMAGE=' + self.base,
                              '--build-arg', 'BASE_DIGEST=' + self.base_digest,
                              '--build-arg', 'SOURCE_SHA=' + self.args.source,
                              '--build-arg', 'QEMU_PACKAGE=' + self.package,
                              '--build-arg', 'FIRMWARE_PACKAGE=' + self.firmware, directory], 900)
        raw, _ = self.run('inspect-built', ['docker', 'image', 'inspect', tag])
        config_sha = json.loads(raw)[0]['Id'].removeprefix('sha256:')
        archive = self.output / 'image.tar'
        if archive.exists():
            raise ValueError('image archive already exists')
        self.run('save', ['docker', 'image', 'save', '--output', str(archive), tag], 180, archive)
        record = self.verify(archive, sha(archive), config_sha)
        record.update(helper_sha256={name: sha(SCRIPTS / name) for name in files},
                      measurement='same-run artifact candidate; no registry publication', steps=self.records)
        packet = self.output / 'image.json'
        packet.write_text(json.dumps(record, indent=2) + '\n')
        outputs = {'archive_sha256': record['archive_sha256'], 'config_sha256': config_sha,
                   'packet_sha256': sha(packet)}
        output_path = os.environ.get('GITHUB_OUTPUT')
        if output_path:
            with Path(output_path).open('a') as stream:
                stream.writelines(f'{key}={value}\n' for key, value in outputs.items())
        print(json.dumps(outputs))

    def container(self, name, image, command, timeout):
        container = 'omg-controller-measurement-' + uuid.uuid4().hex
        args = ['docker', 'run', '--rm', '--name', container, '--cpus', '2', '--memory', '3g',
                '--memory-swap', '3g', '--pids-limit', '512', '--cap-drop', 'NET_RAW',
                '--cap-drop', 'NET_ADMIN', '--log-opt', 'max-size=10m', '--log-opt', 'max-file=2',
                '--dns', '1.1.1.1', '--dns', '9.9.9.9', '--mount',
                'type=bind,src=' + str(SCRIPTS) + ',dst=/checks,readonly', image, *command]
        try:
            return self.run(name, args, timeout)
        finally:
            # Only this unique disposable measurement container can be removed.
            self.run(name + '-cleanup', ['docker', 'container', 'rm', '-f', container], 20, check=False)

    def consume(self):
        packet = Path(self.args.input) / 'image.json'
        archive = Path(self.args.input) / 'image.tar'
        if (not packet.is_file() or packet.is_symlink() or packet.stat().st_size > IMAGE.MAX_JSON
                or sha(packet) != self.args.packet_sha):
            raise ValueError('packet differs from trusted producer output')
        record = json.loads(packet.read_text(), object_pairs_hook=IMAGE.unique_object)
        verified = self.verify(archive, self.args.archive_sha, self.args.config_sha)
        for key in ('archive_sha256', 'config_sha256', 'source_sha', 'architecture', 'base_digest'):
            if record.get(key) != verified[key]:
                raise ValueError('packet identity differs from verified image')
        image = 'sha256:' + self.args.config_sha
        _, existing = self.run('candidate-before-load', ['docker', 'image', 'inspect', image], check=False)
        if existing['exit'] != 1:
            raise ValueError('consumer must begin without the candidate image')
        self.run('images-before-load', ['docker', 'image', 'ls', '--no-trunc', '--digests'])
        self.run('load', ['docker', 'image', 'load', '--input', str(archive)], 180)
        raw, _ = self.run('inspect-loaded', ['docker', 'image', 'inspect', image])
        loaded = json.loads(raw)[0]
        if loaded['Id'] != image or loaded['Architecture'] != self.args.architecture:
            raise ValueError('loaded image identity differs from verified archive')
        self.container('prebuilt-ready', image,
                       ['bash', '/checks/check-qemu-controller.sh', self.package], 30)
        binary = 'qemu-system-x86_64' if self.args.architecture == 'amd64' else 'qemu-system-aarch64'
        self.container('prebuilt-runtime', image,
                       ['python3', '-c', RUNTIME, self.args.architecture, binary], 30)
        self.container('apt-controller-ready', self.base,
                       ['bash', '-euc', APT, 'controller-setup', self.package, self.firmware], 720)
        result = dict(verified_image=verified, steps=self.records,
                      limitation='Single sample. Artifact transfer is not registry pull; shared base layers and host caches are not cold. No guest transport or production adoption is certified.')
        (self.output / 'measurement.json').write_text(json.dumps(result, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('build', 'consume'))
    parser.add_argument('--architecture', choices=PLATFORMS, required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--input')
    parser.add_argument('--archive-sha')
    parser.add_argument('--config-sha')
    parser.add_argument('--packet-sha')
    args = parser.parse_args()
    if args.mode == 'consume' and not all((args.input, args.archive_sha, args.config_sha, args.packet_sha)):
        parser.error('consume requires the trusted producer digests and input directory')
    measurement = Measurement(args)
    getattr(measurement, args.mode)()


if __name__ == '__main__':
    main()
