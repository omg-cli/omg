#!/usr/bin/env python3
"""Preserve actual OS evidence while projecting controlled guard inputs in /etc.

This is Debian execution with an unsupported input, never an Arch attestation.
The caller owns resource/deadline controls. No global markers are modified.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import sys


def require(condition, message):
    if not condition:
        raise ValueError(message)


def snapshot():
    return {'os_release': Path('/etc/os-release').read_text(),
            'debian_marker': Path('/etc/debian_version').exists(),
            'arch': platform.machine(), 'uid': os.geteuid()}


def namespace():
    return os.readlink('/proc/self/ns/mnt')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--condition', required=True,
                        choices=['supported', 'controlled-unsupported'])
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    require(command, 'missing checkpoint command')
    require(os.geteuid() != 0, 'checkpoint tests require ordinary user')
    output = args.output.resolve()
    if args.inside:
        actual = json.loads((output / 'actual-environment.json').read_text())
        parent_namespace = actual.pop('mount_namespace')
        distro = os.environ['OMG_TEST_DISTRO']
        visible = snapshot()
        is_ubuntu = distro == 'ubuntu' or 'Ubuntu' in visible['os_release']
        is_debian = distro == 'debian' or (visible['debian_marker'] and not is_ubuntu)
        supported = args.condition == 'supported'
        require(namespace() != parent_namespace, 'mount namespace was not isolated')
        require(is_debian == supported and not is_ubuntu, 'guard input isolation failed')
        require(supported or not visible['debian_marker'], 'Debian discovery marker remains')
        receipt = {'condition': args.condition, 'actual_environment': actual,
                   'parent_mount_namespace': parent_namespace, 'mount_namespace': namespace(),
                   'guard_inputs': dict(visible, target_distro=distro,
                                        is_debian=is_debian, is_ubuntu=is_ubuntu),
                   'execution_label': 'Debian' if supported else 'Debian controlled unsupported input'}
        (output / 'guard-inputs.json').write_text(json.dumps(receipt, indent=2) + '\n')
        os.execvpe(command[0], command, os.environ)
    actual = snapshot()
    require(actual['debian_marker'] and 'ID=debian' in actual['os_release'].splitlines(),
            'checkpoint requires actual Debian environment')
    actual['mount_namespace'] = namespace()
    output.mkdir(parents=True, exist_ok=False)
    (output / 'actual-environment.json').write_text(json.dumps(actual, indent=2) + '\n')
    argv = ['bwrap', '--ro-bind', '/', '/', '--proc', '/proc', '--dev', '/dev',
            '--die-with-parent', '--unshare-pid', '--bind', str(output), str(output)]
    if args.condition == 'controlled-unsupported':
        # Preserve every other /etc entry (including symlink semantics). Neither
        # marker is hidden by covering a file with a directory: exists() would
        # still be true. A private /etc projection actually omits that entry.
        argv += ['--tmpfs', '/etc']
        for entry in sorted(Path('/etc').iterdir()):
            if entry.name in ('debian_version', 'os-release'):
                continue
            if entry.is_symlink():
                argv += ['--symlink', os.readlink(entry), str(entry)]
            else:
                argv += ['--ro-bind', str(entry), str(entry)]
        neutral = output / 'controlled-os-release'
        neutral.write_text('ID=omg-controlled-unsupported\nNAME="Controlled unsupported input"\n')
        argv += ['--ro-bind', str(neutral), '/etc/os-release']
    # Source, tools and host markers stay read-only. The outer container grants
    # only bounded scratch writes; preserve its writable bind in this namespace.
    if os.environ.get('OMG_CHECKPOINT_SCRATCH'):
        scratch = Path(os.environ['OMG_CHECKPOINT_SCRATCH']).resolve()
        require(output.is_relative_to(scratch), 'condition output escapes bounded scratch')
        argv += ['--bind', str(scratch), str(scratch)]
    argv += ['--setenv', 'OMG_TEST_DISTRO',
             'debian' if args.condition == 'supported' else 'arch', '--',
             sys.executable, str(Path(__file__).resolve()), '--inside',
             '--condition', args.condition, '--output', str(output), '--', *command]
    result = subprocess.run(argv, check=False)
    after = snapshot()
    after['mount_namespace'] = namespace()
    require(after == actual, 'parent marker state changed')
    return result.returncode


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError) as error:
        print('Checkpoint isolation failed: ' + str(error), file=sys.stderr)
        raise SystemExit(2)
