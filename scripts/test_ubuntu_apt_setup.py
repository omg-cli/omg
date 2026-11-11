"""Execute the bootstrap action without changing the machine's APT configuration."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import unittest


ACTION = Path(__file__).resolve().parents[1] / '.github/actions/ubuntu-apt/action.yml'
SETUP = ACTION.with_name('setup.sh')
BASH = 'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else 'bash'
KEYRING = '/usr/share/keyrings/ubuntu-archive-keyring.gpg'
EDGE = 'https://mirrors.edge.kernel.org/ubuntu/'


class UbuntuAptSetup(unittest.TestCase):
    def fixture(self, root, *, host=False, ca=True, codename='noble'):
        tools = root / 'bin'
        tools.mkdir()
        source = root / 'etc/apt/sources.list.d/ubuntu.sources'
        source.parent.mkdir(parents=True)
        mirror = root / 'etc/apt/apt-mirrors.txt'
        ca_path = root / 'etc/ssl/certs/ca-certificates.crt'
        ca_path.parent.mkdir(parents=True)
        if ca:
            ca_path.write_text('fixture certificate bundle\n')
        keyring = root / 'keyring.gpg'
        keyring.write_text('existing trusted Ubuntu keyring\n')
        release = root / 'os-release'
        release.write_text('ID=ubuntu\nVERSION_ID=' + ('24.04' if codename == 'noble' else '26.04') +
                           '\nVERSION_CODENAME=' + codename + '\n')
        archive = 'mirror+file:/etc/apt/apt-mirrors.txt' if host else 'http://archive.ubuntu.com/ubuntu/'
        source.write_text(f'Types: deb\nURIs: {archive}\n'
                          f'Suites: {codename} {codename}-updates {codename}-backports\n'
                          f'Components: main restricted universe multiverse\nSigned-By: {KEYRING}\n\n'
                          f'Types: deb\nURIs: ' +
                          ('mirror+file:/etc/apt/apt-mirrors.txt' if host else 'http://security.ubuntu.com/ubuntu') +
                          f'\nSuites: {codename}-security\nComponents: main restricted universe multiverse\n'
                          f'Signed-By: {KEYRING}\n')
        mirror.write_text('http://azure.archive.ubuntu.com/ubuntu/\tpriority:1\n'
                          'https://archive.ubuntu.com/ubuntu/\tpriority:2\n'
                          'https://security.ubuntu.com/ubuntu/\tpriority:3\n')
        third_party = source.with_name('microsoft-prod.list')
        third_party.write_text('deb [signed-by=/existing/microsoft.gpg] https://packages.microsoft.com/ubuntu/24.04/prod noble main\n')
        (root / 'tmp').mkdir()
        log = root / 'commands.jsonl'
        scripts = {
            'id': 'printf "%s\\n" "${FIXTURE_UID:-0}"\n',
            'dpkg': 'test "$*" = --print-architecture || exit 91\nprintf "%s\\n" "${FIXTURE_ARCH:-amd64}"\n',
            'sudo': 'test "$1" = -n || exit 92\nshift\nprintf "sudo\\n" >> "$SUDO_LOG"\nexec "$@"\n',
            'install': '''
                case "$4" in *apt-mirrors.txt) test "${FAIL_MIRROR_WRITE:-0}" = 0 || exit 41 ;; esac
                exec /usr/bin/install "$@"
            ''',
            'apt-get': '''
                printf '%s\\n' "$*" >> "$COMMAND_LOG"
                if grep -qi '^URIs: mirror+file:' "$SOURCE_PATH"; then
                  selected=$(cat "$MIRROR_PATH")
                else
                  selected=$(grep -i '^URIs:' "$SOURCE_PATH")
                fi
                case "$selected" in
                  *https://mirrors.edge.kernel.org/ubuntu*) scheme=https ;;
                  *http://mirrors.edge.kernel.org/ubuntu*) scheme=http ;;
                  *) scheme=canonical ;;
                esac
                printf '%s\\n' "$scheme" >> "$SCHEME_LOG"
                case " $* " in
                  *' update '*)
                    test "${FAIL_UPDATE:-0}" = 0 || exit 23
                    if [ "$scheme" = https ] && [ "${FAIL_HTTPS_UPDATE:-0}" = 1 ]; then exit 29; fi
                    case "$selected" in
                      *archive.ubuntu.com*|*security.ubuntu.com*)
                        test "${DNS_BROKEN:-0}" = 0 || exit 100 ;;
                    esac
                    case "$selected" in
                      *https:*) test -s "$CA_PATH" || exit 24 ;;
                    esac ;;
                  *' install '*)
                    test "${FAIL_INSTALL:-0}" = 0 || exit 37
                    case " $* " in
                      *' ca-certificates '*)
                        if [ "${OMIT_CA:-0}" = 0 ]; then printf 'installed bundle\\n' > "$CA_PATH"; fi ;;
                    esac ;;
                  *) exit 93 ;;
                esac
            ''',
        }
        for name, script in scripts.items():
            file = tools / name
            file.write_text('#!/bin/sh\nset -eu\n' + textwrap.dedent(script))
            file.chmod(0o755)
        env = dict(os.environ, PATH=tools.as_posix() + os.pathsep + os.environ['PATH'],
                   TMPDIR=(root / 'tmp').as_posix(), COMMAND_LOG=log.as_posix(),
                   SOURCE_PATH=source.as_posix(), MIRROR_PATH=mirror.as_posix(),
                   CA_PATH=ca_path.as_posix(), SUDO_LOG=(root / 'sudo.log').as_posix(),
                   SCHEME_LOG=(root / 'schemes.log').as_posix(), FIXTURE_TOOLS=tools.as_posix())
        replacements = {'os_release=/etc/os-release': release,
                        'source_file=/etc/apt/sources.list.d/ubuntu.sources': source,
                        'mirror_file=/etc/apt/apt-mirrors.txt': mirror,
                        'ca_bundle=/etc/ssl/certs/ca-certificates.crt': ca_path,
                        'keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg': keyring}
        script = 'PATH="$(cd "$FIXTURE_TOOLS" && pwd):$PATH"\n' + SETUP.read_text(encoding='utf-8')
        for assignment, destination in replacements.items():
            script = script.replace(assignment, assignment.split('=', 1)[0] + '=' +
                                    "'" + destination.as_posix() + "'")
        return dict(script=script, env=env, source=source, mirror=mirror, ca=ca_path,
                    release=release, keyring=keyring, log=log, third_party=third_party)

    def execute(self, fixture, **values):
        return subprocess.run([BASH, '--noprofile', '--norc', '-c', fixture['script']],
                              env=dict(fixture['env'], **values), capture_output=True,
                              text=True, timeout=15)

    def commands(self, fixture):
        return fixture['log'].read_text().splitlines() if fixture['log'].exists() else []

    def test_dns_failure_uses_independent_mirror(self):
        for host in (False, True):
            with self.subTest(host=host), tempfile.TemporaryDirectory() as tmp:
                f = self.fixture(Path(tmp), host=host)
                before = f['third_party'].read_bytes()
                result = self.execute(f, DNS_BROKEN='1')
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                selected = f['mirror'] if host else f['source']
                self.assertIn(EDGE, selected.read_text())
                self.assertNotIn('archive.ubuntu.com', selected.read_text())
                self.assertEqual(f['third_party'].read_bytes(), before)
                self.assertEqual(len(self.commands(f)), 1)

    def test_healthy_sources_preserve_identity_and_are_idempotent(self):
        for codename in ('noble', 'resolute'):
            with self.subTest(codename=codename), tempfile.TemporaryDirectory() as tmp:
                f = self.fixture(Path(tmp), codename=codename)
                original = f['source'].read_text().splitlines()
                for _ in range(2):
                    result = self.execute(f)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    current = f['source'].read_text().splitlines()
                    self.assertEqual([x for x in current if not x.startswith('URIs:')],
                                     [x for x in original if not x.startswith('URIs:')])
                    self.assertTrue(all(x == 'URIs: ' + EDGE for x in current if x.startswith('URIs:')))
                self.assertEqual(len(self.commands(f)), 2)

    def test_missing_ca_bootstraps_signed_http_then_requires_https(self):
        for host in (False, True):
            with self.subTest(host=host), tempfile.TemporaryDirectory() as tmp:
                f = self.fixture(Path(tmp), host=host, ca=False, codename='resolute')
                result = self.execute(f, DNS_BROKEN='1')
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                commands = self.commands(f)
                self.assertEqual(len(commands), 3)
                self.assertTrue(commands[0].endswith(' update'))
                self.assertIn(' install -y --no-install-recommends ca-certificates', commands[1])
                self.assertTrue(commands[2].endswith(' update'))
                self.assertEqual((Path(tmp) / 'schemes.log').read_text().splitlines(),
                                 ['http', 'http', 'https'])
                for command in (commands[0], commands[2]):
                    self.assertIn('-o APT::Update::Error-Mode=any', command)
                self.assertTrue(f['ca'].is_file())
                self.assertNotIn('URIs: http:', f['source'].read_text())

    def test_unknown_source_is_rejected_before_any_mutation(self):
        for host in (False, True):
            with self.subTest(host=host), tempfile.TemporaryDirectory() as tmp:
                f = self.fixture(Path(tmp), host=host)
                target = f['mirror'] if host else f['source']
                target.write_text(target.read_text().replace('archive.ubuntu.com', 'unexpected.example'))
                before = {name: f[name].read_bytes() for name in ('source', 'mirror')}
                result = self.execute(f)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.commands(f), [])
                self.assertEqual({name: f[name].read_bytes() for name in before}, before)

    def test_wrong_distribution_architecture_key_or_suite_is_rejected(self):
        for change in ('distro', 'arch', 'key', 'suite', 'trust'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp:
                f = self.fixture(Path(tmp))
                values = {}
                if change == 'distro':
                    f['release'].write_text('ID=debian\nVERSION_ID=12\nVERSION_CODENAME=bookworm\n')
                elif change == 'arch':
                    values['FIXTURE_ARCH'] = 'arm64'
                elif change == 'key':
                    f['source'].write_text(f['source'].read_text().replace(KEYRING, '/other/key.gpg'))
                elif change == 'suite':
                    f['source'].write_text(f['source'].read_text().replace('noble-security', 'bookworm-security'))
                else:
                    f['source'].write_text(f['source'].read_text() + 'Trusted: yes\n')
                before = f['source'].read_bytes()
                result = self.execute(f, **values)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.commands(f), [])
                self.assertEqual(f['source'].read_bytes(), before)

    def test_failed_update_or_install_remains_fatal(self):
        for failure, expected in (('FAIL_UPDATE', 23), ('FAIL_INSTALL', 37)):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                f = self.fixture(Path(tmp), ca=False)
                result = self.execute(f, **{failure: '1'})
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                self.assertEqual(len(self.commands(f)), 1 if failure == 'FAIL_UPDATE' else 2)

    def test_non_root_execution_uses_noninteractive_sudo(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = self.fixture(Path(tmp), host=True)
            result = self.execute(f, FIXTURE_UID='1000')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue((Path(tmp) / 'sudo.log').is_file())

    def test_missing_keyring_is_refused_before_source_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = self.fixture(Path(tmp))
            f['keyring'].unlink()
            original = f['source'].read_bytes()
            result = self.execute(f)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(self.commands(f), [])
            self.assertEqual(f['source'].read_bytes(), original)

    def test_mirror_source_field_case_and_whitespace_follow_deb822(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = self.fixture(Path(tmp), host=True)
            f['source'].write_text(f['source'].read_text().replace('URIs:', 'uris:')
                                   .replace('apt-mirrors.txt\n', 'apt-mirrors.txt  \n'))
            result = self.execute(f, DNS_BROKEN='1')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(f['mirror'].read_text(), EDGE + '\tpriority:1\n')

    def test_comment_only_paragraphs_preserve_valid_stock_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = self.fixture(Path(tmp))
            f['source'].write_text('# Ubuntu source configuration\n\n' + f['source'].read_text())
            result = self.execute(f, DNS_BROKEN='1')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(f['source'].read_text().startswith('# Ubuntu source configuration\n\n'))

    def test_partial_bootstrap_failures_remain_red_and_can_be_repeated(self):
        for failure, expected in (('FAIL_MIRROR_WRITE', 41), ('FAIL_INSTALL', 37),
                                  ('FAIL_HTTPS_UPDATE', 29)):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                f = self.fixture(Path(tmp), host=True, ca=False)
                result = self.execute(f, **{failure: '1'})
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                repeated = self.execute(f, DNS_BROKEN='1')
                self.assertEqual(repeated.returncode, 0, repeated.stdout + repeated.stderr)
                self.assertEqual(f['mirror'].read_text(), EDGE + '\tpriority:1\n')

    def test_successful_install_without_ca_bundle_cannot_enable_https(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = self.fixture(Path(tmp), ca=False)
            result = self.execute(f, OMIT_CA='1')
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(len(self.commands(f)), 2)
            self.assertEqual((Path(tmp) / 'schemes.log').read_text().splitlines(), ['http', 'http'])

    def test_composite_wrapper_uses_translated_whole_action_path(self):
        action = ACTION.read_text(encoding='utf-8')
        self.assertIn('UBUNTU_APT_ACTION_PATH: ${{ github.action_path }}', action)
        command = re.search(r'^      run: (.+)$', action, re.M).group(1)
        self.assertNotIn('${{', command)
        self.assertNotIn('inputs:', action)
        with tempfile.TemporaryDirectory() as tmp:
            f = self.fixture(Path(tmp), host=True)
            directory = Path(tmp) / 'downloaded action with spaces'
            directory.mkdir()
            (directory / 'setup.sh').write_text(f['script'])
            result = subprocess.run([BASH, '--noprofile', '--norc', '-c', command],
                                    env=dict(f['env'], UBUNTU_APT_ACTION_PATH=directory.as_posix(),
                                             DNS_BROKEN='1'),
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(f['mirror'].read_text(), EDGE + '\tpriority:1\n')


if __name__ == '__main__':
    unittest.main()
