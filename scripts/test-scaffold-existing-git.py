#!/usr/bin/env python3
"""Verify that a new scaffold preserves files created by a concurrent process."""

import ctypes
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile


PTRACE_TRACEME = 0
PTRACE_DETACH = 17
PTRACE_SYSCALL = 24
PTRACE_SETOPTIONS = 0x4200
PTRACE_O_TRACESYSGOOD = 0x00000001
PTRACE_O_EXITKILL = 0x00100000


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def verify_scaffold(binary, owner, mode):
    command = ctypes.CDLL(None, use_errno=True).ptrace
    command.argtypes = (ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
    command.restype = ctypes.c_long

    def trace(request, pid=0, data=None):
        if command(request, pid, None, data) == -1:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))

    target = owner / 'project'
    git = owner / 'git'
    git_marker = owner / 'git-invoked'
    git.write_text('#!/bin/sh\nprintf invoked > "$HOME/git-invoked"\nprintf "Unexpected git invocation\\n" >&2\nexit 73\n')
    git.chmod(0o700)
    # The fixture owns every path and supplies a Git command that must stay unused.
    env = dict(PATH=str(owner), HOME=str(owner), XDG_CONFIG_HOME=str(owner / 'config'),
               XDG_DATA_HOME=str(owner / 'data'), XDG_CACHE_HOME=str(owner / 'cache'),
               OMG_DATA_DIR=str(owner / 'data'),
               OMG_DISABLE_DAEMON='1', OMG_DISABLE_TELEMETRY='1')
    rust = owner / 'data/versions/rust'
    (rust / '1.95.0').mkdir(parents=True)
    (rust / 'current').symlink_to('1.95.0', target_is_directory=True)
    for name in ('LD_LIBRARY_PATH', 'LLVM_PROFILE_FILE'):
        if name in os.environ:
            env[name] = os.environ[name]

    def stop_at_exec():
        trace(PTRACE_TRACEME)

    with tempfile.TemporaryFile() as output:
        with subprocess.Popen([binary, 'new', 'rust', target.name], cwd=owner, env=env,
                              stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                              preexec_fn=stop_at_exec) as cli:
            try:
                pid = cli.pid
                _, status = os.waitpid(pid, 0)
                require(os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGTRAP,
                        'expected the traced child exec stop')
                trace(PTRACE_SETOPTIONS, pid, PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD)
                syscall_stop = signal.SIGTRAP | 0x80
                while not target.is_dir():
                    trace(PTRACE_SYSCALL, pid)
                    _, status = os.waitpid(pid, 0)
                    require(os.WIFSTOPPED(status) and os.WSTOPSIG(status) == syscall_stop,
                            'scaffolder did not stop at successful directory creation')

                lock = target / '.tool-versions'
                if mode == 'manifest-collision':
                    manifest = target / 'Cargo.toml'
                    before = b'[package]\nname = "owned-before-scaffold"\nversion = "9.9.9"\n'
                    manifest.write_bytes(before)
                elif mode == 'lock-collision':
                    absent = owner / 'unwritten-lock-target'
                    lock.symlink_to(absent)
                else:
                    # The child has created the directory and will only continue after Git initializes it.
                    subprocess.run(['/usr/bin/git', 'init', '--quiet', '--initial-branch=existing'],
                                   cwd=target, env={**env, 'PATH': '/usr/bin:/bin'}, check=True, timeout=5)
                    head = target / '.git/HEAD'
                    config = target / '.git/config'
                    lock.write_bytes(b'rust 1.78.0\n')
                    before = head.read_bytes(), config.read_bytes(), lock.read_bytes()
                trace(PTRACE_DETACH, pid)
                exit_code = cli.wait(timeout=10)
                output.seek(0)
                transcript = output.read(64 * 1024).decode(errors='replace')
                require(not git_marker.exists(), 'scaffold invoked the forbidden Git fixture')
                if mode != 'git':
                    context = 'Rust Cargo.toml' if mode == 'manifest-collision' else 'runtime .tool-versions'
                    expected = f'Error: Failed to write the {context}: File exists (os error 17)'
                    require(exit_code == 1, f'collision exited {exit_code}: {transcript}')
                    diagnostics = [line for line in transcript.splitlines() if line.startswith('Error: ')]
                    require(diagnostics == [expected], f'wrong collision diagnostic: {transcript}')
                    entries = sorted(entry.name for entry in target.iterdir())
                    if mode == 'manifest-collision':
                        require(manifest.read_bytes() == before, 'scaffold changed the owned manifest')
                        require(entries == ['Cargo.toml'], 'scaffold continued after the manifest collision')
                    else:
                        require(lock.is_symlink() and lock.readlink() == absent and not absent.exists(),
                                'scaffold followed or replaced an existing runtime lock symlink')
                        require(entries == ['.gitignore', '.tool-versions', 'Cargo.toml', 'src'],
                                'unexpected files after the runtime lock collision')
                else:
                    require(exit_code == 0, f'scaffold exited {exit_code}: {transcript}')
                    require((target / 'Cargo.toml').is_file(), 'Rust scaffold did not create its manifest')
                    require('Unexpected git invocation' not in transcript, 'scaffold reran git init')
                    require((head.read_bytes(), config.read_bytes(), lock.read_bytes()) == before,
                            'scaffold changed existing Git or runtime metadata')
            finally:
                if cli.returncode is None:
                    cli.kill()

    if mode != 'git':
        return {'scaffold': 'rust', 'case': mode, 'exit': exit_code, 'diagnostic': expected,
                'existing_entry_preserved': True, 'git_invocations': 0, 'entries': entries}
    return {'scaffold': 'rust', 'git_head': before[0].decode().strip(), 'exit': exit_code}


def main(binary, mode):
    require(os.getuid() != 0, 'scaffold fixture requires an ordinary user')

    def deadline(_signum, _frame):
        raise TimeoutError('scaffold fixture exceeded its deadline')

    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(20)
    try:
        with tempfile.TemporaryDirectory(prefix='omg-scaffold-') as work:
            print(json.dumps(verify_scaffold(Path(binary).resolve(strict=True), Path(work), mode)))
    finally:
        signal.alarm(0)


if __name__ == '__main__':
    require(len(sys.argv) in (2, 3), 'expected CLI path and optional fixture mode')
    mode = 'git' if len(sys.argv) == 2 else sys.argv[2].removeprefix('--')
    require(mode in ('git', 'manifest-collision', 'lock-collision'), 'unknown fixture mode')
    main(sys.argv[1], mode)
