"""Execute the Arch CI setup against contained package-manager fixtures."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

CI_YML = Path(__file__).resolve().parents[1] / '.github/workflows/ci.yml'


def arch_setup(text):
    """Extract this workflow's unique literal Arch matrix setup, or refuse."""
    jobs = list(re.finditer(r'(?m)^  linux-matrix:\n', text))
    if len(jobs) != 1:
        raise ValueError('Expected one linux-matrix job')
    remaining = text[jobs[0].end():]
    end = re.search(r'(?m)^  [a-zA-Z0-9_-]+:\n', remaining)
    job = remaining[:end.start()] if end else remaining
    rows = list(re.finditer(r'(?m)^          - platform: ([^\n]+)\n', job))
    selected = [i for i, row in enumerate(rows) if row[1] == 'arch']
    if len(selected) != 1:
        raise ValueError('Expected one literal Arch matrix row')
    index = selected[0]
    row = job[rows[index].end():rows[index + 1].start() if index + 1 < len(rows) else len(job)]
    starts = list(re.finditer(r'(?m)^            setup: \|\n', row))
    if len(starts) != 1:
        raise ValueError('Expected one literal Arch setup')
    lines = row[starts[0].end():].splitlines(True)
    script = []
    for line in lines:
        if line.strip() and not line.startswith('              '):
            break
        script.append(line[14:] if line.startswith('              ') else line)
    value = ''.join(script)
    if not value.strip():
        raise ValueError('Empty Arch setup')
    return value


def bash_program():
    if os.name != 'nt':
        program = shutil.which('bash')
        if program:
            return program
    else:
        git = shutil.which('git')
        roots = [Path(git).resolve().parents[1]] if git else []
        roots += [Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'Git']
        for root in roots:
            for path in [root / 'bin/bash.exe', root / 'usr/bin/bash.exe']:
                if path.is_file():
                    return str(path)
    raise RuntimeError('Installed Bash and POSIX sh are required for Arch setup tests')


def shell_path(path):
    value = path.resolve().as_posix()
    if os.name == 'nt':
        if len(value) < 3 or value[1:3] != ':/':
            raise ValueError('Git Bash fixture requires an absolute drive path')
        return '/' + value[0].lower() + value[2:]
    return value


FAKE_PACMAN = '''#!/bin/sh
set -eu
if [ "$*" = "-Syu --noconfirm" ]; then
  printf 'upgrade\\n' >> "$FIXTURE_STATE"
  if [ "$SCENARIO" = upgrade_fail ]; then printf 'upgrade refused\\n' >&2; exit 7; fi
  exit 0
fi
if [ "$*" != "-S --noconfirm --needed base-devel git pkgconf openssl libarchive clang cmake curl jq python fish" ]; then
  printf 'unexpected package command\\n' >&2; exit 64
fi
n=0
if [ -f "$FIXTURE_COUNT" ]; then read -r n < "$FIXTURE_COUNT"; fi
n=$((n+1)); printf '%s\\n' "$n" > "$FIXTURE_COUNT"
printf 'packages:%s\\n' "$n" >> "$FIXTURE_STATE"
case "$SCENARIO:$n" in
  transient:1|permanent:*)
    printf 'error: failed retrieving file from fixture mirror : \\nerror: failed to commit transaction (failed to retrieve some files)\\n' >&2; exit 1;;
  mixed_signature:1)
    printf 'error: failed to commit transaction (failed to retrieve some files)\\nerror: failed to commit transaction (invalid or corrupted package (PGP signature))\\n' >&2; exit 3;;
  mixed_unknown:1)
    printf 'error: failed to commit transaction (failed to retrieve some files)\\nerror: failed to commit transaction (unknown fixture failure)\\n' >&2; exit 9;;
  observed_trailer:1)
    printf 'error: failed to commit transaction (failed to retrieve some files)\\nErrors occurred, no packages were upgraded.\\n' >&2; exit 1;;
  mixed_trailer:1)
    printf 'error: failed to commit transaction (failed to retrieve some files)\\nerror: failed to commit transaction (PGP signature)\\nErrors occurred, no packages were upgraded.\\n' >&2; exit 3;;
  unknown_trailer:1)
    printf 'error: failed to commit transaction (failed to retrieve some files)\\nUnexpected trailer\\n' >&2; exit 9;;
  signature:*) printf 'error: invalid or corrupted package (PGP signature)\\n' >&2; exit 3;;
  unknown:*) printf 'unclassified fixture failure\\n' >&2; exit 9;;
esac
printf 'dependency transaction completed\\n'
'''


class ArchSetupBehaviorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bash = bash_program()

    def run_setup(self, scenario, overrides=None):
        script = arch_setup(CI_YML.read_text(encoding='utf-8'))
        with tempfile.TemporaryDirectory(prefix='arch-setup-') as directory:
            root = Path(directory)
            folder = root / 'bin'
            folder.mkdir()
            (folder / 'pacman').write_text(FAKE_PACMAN, encoding='utf-8', newline='\n')
            (folder / 'sleep').write_text(
                '#!/bin/sh\nprintf "backoff:%s\\n" "$*" >> "$FIXTURE_STATE"\n',
                encoding='utf-8', newline='\n')
            for name, body in (overrides or {}).items():
                (folder / name).write_text(body, encoding='utf-8', newline='\n')
            (root / 'subject.sh').write_text(
                script + '\nprintf "build\\n" >> "$FIXTURE_STATE"\n',
                encoding='utf-8', newline='\n')
            env = {key: value for key, value in os.environ.items()
                   if key not in ['BASH_ENV', 'ENV', 'SHELLOPTS', 'BASHOPTS']
                   and not key.startswith('GIT_')}
            env.update(FIXTURE_BIN=shell_path(folder), TMPDIR=shell_path(root),
                       SCENARIO=scenario, FIXTURE_STATE=shell_path(root / 'state'),
                       FIXTURE_COUNT=shell_path(root / 'count'))
            result = subprocess.run(
                [self.bash, '--noprofile', '--norc', '-c',
                 'PATH="$FIXTURE_BIN:/usr/bin:/bin"; export PATH; '
                 'chmod +x bin/* && exec sh -e ./subject.sh'],
                cwd=root, env=env, capture_output=True, timeout=20)
            state = (root / 'state').read_text().splitlines() if (root / 'state').exists() else []
            return result, state

    def test_transient_retrieval_recovers_before_build(self):
        result, state = self.run_setup('transient')
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(state, ['upgrade', 'packages:1', 'backoff:2', 'packages:2', 'build'])
        self.assertIn(b'failed to commit transaction (failed to retrieve some files)', result.stdout + result.stderr)
        self.assertIn(b'dependency transaction completed', result.stdout)

    def test_permanent_retrieval_stays_failed_without_build(self):
        result, state = self.run_setup('permanent')
        self.assertEqual((result.returncode, state), (1, ['upgrade', 'packages:1', 'backoff:2', 'packages:2']))
        self.assertEqual((result.stdout + result.stderr).count(b'failed to commit transaction (failed to retrieve some files)'), 2)

    def test_first_success_reaches_build_without_retry(self):
        result, state = self.run_setup('success')
        self.assertEqual((result.returncode, state), (0, ['upgrade', 'packages:1', 'build']))
        self.assertIn(b'dependency transaction completed', result.stdout)

    def test_upgrade_failure_prevents_dependency_and_build(self):
        result, state = self.run_setup('upgrade_fail')
        self.assertEqual((result.returncode, state), (7, ['upgrade']))
        self.assertIn(b'upgrade refused', result.stderr)

    def test_signature_failure_is_not_retried(self):
        result, state = self.run_setup('signature')
        self.assertEqual((result.returncode, state), (3, ['upgrade', 'packages:1']))
        self.assertIn(b'PGP signature', result.stdout + result.stderr)

    def test_unknown_failure_is_not_retried(self):
        result, state = self.run_setup('unknown')
        self.assertEqual((result.returncode, state), (9, ['upgrade', 'packages:1']))
        self.assertIn(b'unclassified fixture failure', result.stdout + result.stderr)

    def test_signature_terminal_after_retrieval_marker_cannot_reach_build(self):
        result, state = self.run_setup('mixed_signature')
        self.assertEqual((result.returncode, state), (3, ['upgrade', 'packages:1']))

    def test_unknown_terminal_after_retrieval_marker_cannot_reach_build(self):
        result, state = self.run_setup('mixed_unknown')
        self.assertEqual((result.returncode, state), (9, ['upgrade', 'packages:1']))

    def test_classification_command_failure_preserves_pacman_failure(self):
        result, state = self.run_setup('transient', {'awk': '#!/bin/sh\nexit 2\n'})
        self.assertEqual((result.returncode, state), (1, ['upgrade', 'packages:1']))

    def test_success_log_print_failure_cannot_reach_build(self):
        result, state = self.run_setup('success', {'cat': '#!/bin/sh\nexit 23\n'})
        self.assertEqual((result.returncode, state), (23, ['upgrade', 'packages:1']))

    def test_failure_log_print_failure_preserves_pacman_status(self):
        result, state = self.run_setup('permanent', {'cat': '#!/bin/sh\nexit 23\n'})
        self.assertEqual((result.returncode, state), (1, ['upgrade', 'packages:1']))

    def test_capture_creation_failure_cannot_reach_package_or_build(self):
        result, state = self.run_setup('success', {'mktemp': '#!/bin/sh\nexit 24\n'})
        self.assertEqual((result.returncode, state), (24, ['upgrade']))

    def test_exact_observed_benign_trailer_allows_recovery(self):
        result, state = self.run_setup('observed_trailer')
        self.assertEqual((result.returncode, state), (0, ['upgrade', 'packages:1', 'backoff:2', 'packages:2', 'build']))

    def test_benign_trailer_cannot_hide_intervening_terminal(self):
        result, state = self.run_setup('mixed_trailer')
        self.assertEqual((result.returncode, state), (3, ['upgrade', 'packages:1']))

    def test_unrecognized_trailer_is_not_authorized(self):
        result, state = self.run_setup('unknown_trailer')
        self.assertEqual((result.returncode, state), (9, ['upgrade', 'packages:1']))


class ArchSetupExtractionTests(unittest.TestCase):
    def test_missing_arch_row_is_fatal(self):
        text = CI_YML.read_text(encoding='utf-8')
        with self.assertRaises(ValueError):
            arch_setup(text.replace('          - platform: arch\n', '          - platform: unavailable\n'))

    def test_duplicate_arch_row_is_fatal(self):
        text = CI_YML.read_text(encoding='utf-8')
        with self.assertRaises(ValueError):
            arch_setup(text.replace('          - platform: arch\n', '          - platform: arch\n          - platform: arch\n', 1))

    def test_missing_setup_is_fatal(self):
        text = CI_YML.read_text(encoding='utf-8')
        start = text.index('          - platform: arch\n')
        changed = text[:start] + text[start:].replace('            setup: |\n', '            setup_unavailable: |\n', 1)
        with self.assertRaises(ValueError):
            arch_setup(changed)

    def test_empty_setup_is_fatal(self):
        with self.assertRaises(ValueError):
            arch_setup('  linux-matrix:\n          - platform: arch\n            setup: |\n            other: value\n')

    def test_duplicate_setup_is_fatal(self):
        with self.assertRaises(ValueError):
            arch_setup('  linux-matrix:\n          - platform: arch\n            setup: |\n              first\n            setup: |\n              second\n')

    def test_duplicate_job_is_fatal(self):
        text = CI_YML.read_text(encoding='utf-8')
        with self.assertRaises(ValueError):
            arch_setup(text + '\n  linux-matrix:\n')


if __name__ == '__main__':
    unittest.main()
