#!/usr/bin/env python3
"""Prepare private fixtures and verify selected local OMG command contracts."""
import hashlib
import datetime
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import subprocess
import sys
import time
import tomllib

ACCOUNT_CAUSE = 'No dashboard account linked. Run `omg account link --token-stdin` to sync usage to the dashboard.'

REFUSALS = {
    'diff': 'Failed to inspect lockfile missing.lock',
    'diff-from': 'Failed to inspect lockfile missing.lock',
    'audit-export': 'Absolute paths not allowed',
    'audit-export-flags': 'Absolute paths not allowed',
    'rollback': 'No history entries available for rollback',
    'rollback-yes': 'No history entries available for rollback',
    'env-export-missing-lock': 'Failed to inspect lockfile omg.lock',
    'metrics': 'Daemon not running. Performance metrics require the daemon',
    'workspace-run': "1 project(s) failed to run 'true'",
    'workspace-check': '1 project(s) need attention, 0 failed to check (of 1 total)',
    'team-members': ACCOUNT_CAUSE,
    'team-activity': ACCOUNT_CAUSE,
    'fleet-status': ACCOUNT_CAUSE,
    'enterprise-reports': ACCOUNT_CAUSE,
    'enterprise-reports-type': ACCOUNT_CAUSE,
    'enterprise-policy-show': ACCOUNT_CAUSE,
    'enterprise-policy-scope': ACCOUNT_CAUSE,
    'enterprise-audit-export': 'Absolute paths not allowed',
    'account-link-stdin': 'Dashboard token is empty',
    'team-compliance-export': 'compliance evidence requires an evaluated report',
}

OUTPUTS = {'snapshot-list', 'list', 'list-available', 'hooks-status', 'hooks-run',
           'workspace-diff', 'hook-env', 'which', 'hook-uninstall', 'config', 'privacy',
           'audit-log', 'audit-log-flags', 'audit-verify', 'audit-policy',
           'tool-list', 'tool-search', 'tool-registry', 'team-init', 'team-roles-list',
           'team-golden-create', 'team-golden-list', 'team-golden-delete',
           'team-golden-create-flags', 'team-compliance', 'team-compliance-enforce',
           'account-status', 'account-unlink', 'history', 'history-flags', 'stats', 'init'}

ROLES = {'admin': 'Full access (push, policy, members)',
         'lead': 'Can push to team lock, manage policies',
         'developer': 'Can pull, cannot push without approval',
         'readonly': 'Can only view status'}

REGISTRY = [('ripgrep', 'pacman:ripgrep', 'Ultra-fast regex search tool', 'search'), ('rg', 'pacman:ripgrep', 'Alias for ripgrep', 'search'), ('fd', 'pacman:fd', 'Fast find alternative', 'search'), ('fzf', 'pacman:fzf', 'Fuzzy finder', 'search'), ('jq', 'pacman:jq', 'JSON processor', 'data'), ('yq', 'pacman:yq', 'YAML processor', 'data'), ('bat', 'pacman:bat', 'Cat with syntax highlighting', 'files'), ('eza', 'pacman:eza', 'Modern ls replacement', 'files'), ('zoxide', 'pacman:zoxide', 'Smarter cd command', 'navigation'), ('delta', 'pacman:git-delta', 'Better git diffs', 'git'), ('lazygit', 'pacman:lazygit', 'Terminal UI for git', 'git'), ('htop', 'pacman:htop', 'Interactive process viewer', 'system'), ('btop', 'pacman:btop', 'Resource monitor', 'system'), ('dust', 'pacman:dust', 'Disk usage analyzer', 'system'), ('duf', 'pacman:duf', 'Disk usage/free utility', 'system'), ('procs', 'pacman:procs', 'Modern ps replacement', 'system'), ('hyperfine', 'pacman:hyperfine', 'Command benchmarking', 'dev'), ('tokei', 'pacman:tokei', 'Code statistics', 'dev'), ('just', 'pacman:just', 'Command runner', 'dev'), ('watchexec', 'pacman:watchexec', 'File watcher', 'dev'), ('tldr', 'npm:tldr', 'Simplified man pages', 'docs'), ('serve', 'npm:serve', 'Static file server', 'web'), ('http-server', 'npm:http-server', 'Simple HTTP server', 'web'), ('yarn', 'npm:yarn', 'Package manager', 'node'), ('pnpm', 'npm:pnpm', 'Fast package manager', 'node'), ('tsx', 'npm:tsx', 'TypeScript execute', 'node'), ('nodemon', 'npm:nodemon', 'Node.js auto-restart', 'node'), ('prettier', 'npm:prettier', 'Code formatter', 'formatting'), ('eslint', 'npm:eslint', 'JavaScript linter', 'linting'), ('typescript', 'npm:typescript', 'TypeScript compiler', 'node'), ('turbo', 'npm:turbo', 'Monorepo build system', 'node'), ('vercel', 'npm:vercel', 'Vercel CLI', 'deploy'), ('netlify-cli', 'npm:netlify-cli', 'Netlify CLI', 'deploy'), ('wrangler', 'npm:wrangler', 'Cloudflare Workers CLI', 'deploy'), ('cargo-watch', 'cargo:cargo-watch', 'Watch and rebuild', 'rust'), ('cargo-edit', 'cargo:cargo-edit', 'Cargo add/rm/upgrade', 'rust'), ('cargo-expand', 'cargo:cargo-expand', 'Macro expansion', 'rust'), ('cargo-nextest', 'cargo:cargo-nextest', 'Fast test runner', 'rust'), ('cargo-audit', 'cargo:cargo-audit', 'Security audits', 'rust'), ('cargo-outdated', 'cargo:cargo-outdated', 'Check outdated deps', 'rust'), ('diesel', 'cargo:diesel_cli', 'Diesel ORM CLI', 'rust'), ('sqlx', 'cargo:sqlx-cli', 'SQLx CLI', 'rust'), ('bacon', 'cargo:bacon', 'Background code checker', 'rust'), ('sccache', 'cargo:sccache', 'Shared compilation cache', 'rust'), ('yt-dlp', 'pip:yt-dlp', 'Video downloader', 'media'), ('glances', 'pip:glances', 'System monitor', 'system'), ('httpie', 'pip:httpie', 'HTTP client', 'web'), ('black', 'pip:black', 'Python formatter', 'python'), ('ruff', 'pip:ruff', 'Fast Python linter', 'python'), ('mypy', 'pip:mypy', 'Python type checker', 'python'), ('poetry', 'pip:poetry', 'Python packaging', 'python'), ('pipx', 'pip:pipx', 'Install Python apps', 'python'), ('rich-cli', 'pip:rich-cli', 'Rich text in terminal', 'cli'), ('hey', 'go:github.com/rakyll/hey', 'HTTP load generator', 'web'), ('dive', 'go:github.com/wagoodman/dive', 'Docker image explorer', 'docker'), ('lazydocker', 'go:github.com/jesseduffield/lazydocker', 'Docker TUI', 'docker'), ('glow', 'go:github.com/charmbracelet/glow', 'Markdown renderer', 'docs'), ('air', 'go:github.com/cosmtrek/air', 'Go live reload', 'go'), ('golangci-lint', 'go:github.com/golangci/golangci-lint/cmd/golangci-lint', 'Go linter', 'go')]


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def regular_bytes(path, limit=4 * 1024 * 1024):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), f'missing regular artifact: {path}')
    with path.open('rb') as stream:
        content = stream.read(limit + 1)
    require(len(content) <= limit, f'artifact too large: {path}')
    return content


def regular_text(path):
    return regular_bytes(path).decode('utf-8')


def identity(path):
    return hashlib.sha256(regular_bytes(path)).hexdigest()


def write(path, content, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    require(not path.is_symlink(), f'fixture destination is a symlink: {path}')
    path.write_text(content)
    path.chmod(mode)


def absent(path):
    path = Path(path)
    return not path.exists() and not path.is_symlink()


def runtime_fixture(data):
    for runtime, versions in {'node': ['24.21.0', '22.16.0'], 'python': ['3.12.14']}.items():
        for version in versions:
            executable = 'python3' if runtime == 'python' else runtime
            write(data / f'versions/{runtime}/{version}/bin/{executable}', '#!/bin/sh\nexit 0\n', 0o755)
        current = data / f'versions/{runtime}/current'
        if absent(current):
            current.symlink_to(versions[0], target_is_directory=True)


def golden_templates(path):
    return tomllib.loads(regular_text(path))['templates']


def write_golden(path, templates):
    lines = []
    for item in templates:
        lines += ['[[templates]]', 'name = ' + json.dumps(item['name']),
                  'packages = ' + json.dumps(item['packages']), 'created_at = ' + str(item['created_at']),
                  '[templates.runtimes]']
        lines += [key + ' = ' + json.dumps(value) for key, value in item['runtimes'].items()]
    write(path, '\n'.join(lines) + '\n')


def audit_entries():
    entries, previous = [], 'genesis'
    for number, severity in enumerate(['info', 'error', 'critical', 'warning'], 1):
        entry = {'id': f'fixture-audit-{number}', 'timestamp': f'2025-06-0{number}T12:00:00Z',
                 'event_type': 'package_install', 'severity': severity, 'user': 'fixture',
                 'resource': f'fixture-package-{number}', 'description': f'Fixture event number {number}',
                 'prev_hash': previous, 'hash_version': 1}
        # Published AuditEntry v1: invalid-UTF-8 domain, Rust Debug enum names,
        # and all nine u64-prefixed fields, including absent metadata as empty.
        digest = hashlib.sha256(b'\xff\x01')
        values = [entry[key] for key in ('id', 'timestamp')]
        values += ['PackageInstall', severity.title()]
        values += [entry[key] for key in ('user', 'resource', 'description')]
        values += ['', previous]
        for value in values:
            encoded = value.encode(); digest.update(len(encoded).to_bytes(8, 'big')); digest.update(encoded)
        entry['hash'] = previous = digest.hexdigest()
        entries.append(entry)
    return entries


def history_entries():
    entries = []
    for number, date, kind, name in [(1, '2023-06-01', 'Install', 'pacman-old'),
                                    (2, '2025-06-02', 'Install', 'pacman-a'),
                                    (3, '2025-06-03', 'Remove', 'pacman-removed'),
                                    (4, '2025-06-04', 'Install', 'unrelated-tool'),
                                    (5, '2025-06-05', 'Install', 'pacman-b')]:
        entries.append({'id': f'hist000{number}-fixture', 'timestamp': date + 'T12:00:00Z',
                        'transaction_type': kind, 'success': True,
                        'changes': [{'name': name, 'old_version': '1.0', 'new_version': '2.0', 'source': 'core'}]})
    return entries


def prepare(case):
    require(case in REFUSALS or case in OUTPUTS, f'unknown local fixture: {case}')
    for name in ('OMG_DATA_DIR', 'OMG_CONFIG_DIR', 'OMG_CACHE_DIR'):
        directory = Path(os.environ[name])
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.chmod(0o700)
    data, config, home = (Path(os.environ[name]) for name in ('OMG_DATA_DIR', 'OMG_CONFIG_DIR', 'HOME'))
    if absent(config / 'config.toml'):
        write(config / 'config.toml', 'telemetry_enabled = false\n[aur]\nbuild_concurrency = 3\nenable_ccache = false\n')
    write(data / 'fixture-unrelated.txt', 'keep unrelated data\n')
    write(config / 'fixture-unrelated.txt', 'keep unrelated configuration\n')
    if case in {'rollback', 'rollback-yes'}:
        require(os.environ.get('OMG_QEMU_DISTRO') in {'arch', 'debian', 'ubuntu', 'fedora'}, 'rollback fixture requires the selected backend')
        require(absent(data / 'history.json'), 'rollback fixture must start without private history')
    if case == 'metrics':
        # The harness sets this before execution too; subprocess environment changes
        # cannot propagate from this fixture process to its caller.
        require(os.environ.get('OMG_DISABLE_DAEMON') == '0', 'metrics must test the selected missing socket')
    if case in {'list', 'list-available', 'which', 'hook-env'}:
        runtime_fixture(data)
        write('.node-version', '24.21.0\n')
        write('mise.toml', '[tools]\nnode = "24.21.0"\n[env]\nQEMU_MUST_NOT_AUTO_APPLY = "unsafe"\n')
    if case in {'hooks-run', 'hooks-status'}:
        write('.git/hooks/pre-commit', '#!/bin/sh\nprintf "executed fixture pre-commit\\n" > hook-executed.txt\n', 0o755)
    if case == 'hook-uninstall':
        write(home / '.bashrc', 'alias keep="echo preserved"\n# OMG Package Manager\neval "$(omg hook bash)"\nexport KEEP_VALUE=42\n')
    if case == 'snapshot-list':
        write(data / 'snapshots/index.json', json.dumps({'snapshots': [
            {'id': 'snap-fixture-a', 'created_at': 1750000000, 'hash': 'abc12345' + '0' * 56, 'message': 'fixture snapshot alpha'},
            {'id': 'snap-fixture-b', 'created_at': 1750000600, 'hash': 'def67890' + '1' * 56, 'message': 'fixture snapshot beta'}]}))
    if case in {'history', 'history-flags'}:
        write(data / 'history.json', json.dumps(history_entries()))
    if case == 'stats':
        write(data / 'usage.json', json.dumps({'total_commands': 37, 'commands': {'search': 21, 'list': 16},
              'time_saved_ms': 60000, 'queries_today': 3, 'queries_this_month': 9,
              'last_query_date': '2025-06-05', 'last_month': '2025-06', 'last_sync': 0}))
    if case in {'audit-log', 'audit-log-flags', 'audit-verify'}:
        write(data / 'audit/audit.jsonl', ''.join(json.dumps(entry) + '\n' for entry in audit_entries()))
    if case == 'audit-policy':
        write(config / 'policy.toml', 'minimum_grade = "Verified"\nallow_aur = false\nrequire_pgp = true\nallowed_licenses = ["MIT", "Apache-2.0"]\nbanned_packages = ["fixture-banned"]\n')
    if case == 'account-unlink':
        write(data / 'license.json', json.dumps({'key': 'QEMU-not-a-real-dashboard-token', 'tier': 'enterprise',
              'features': ['policy'], 'customer': 'QEMU Fixture', 'expires_at': '2000-01-01',
              'validated_at': 0, 'token': 'not-a-jwt', 'machine_id': None}))
        write(data / 'license-clock.highwater', '1790000000\n')
    if case == 'tool-list':
        for name in ('fixture-rg', 'fixture-jq'):
            target = data / f'tools/{name}/bin/{name}'
            write(target, '#!/bin/sh\nexit 0\n', 0o755)
            link = data / f'bin/{name}'; link.parent.mkdir(exist_ok=True)
            if absent(link): link.symlink_to(target)
        write(data / 'bin/ignored-regular-file', 'not an installed tool\n')
    if case.startswith('team-golden-'):
        path = config / 'golden-paths.toml'
        templates = golden_templates(path) if path.exists() else []
        sibling = {'name': 'keep-sibling', 'packages': ['jq'], 'runtimes': {'go': '1.24.0'}, 'created_at': 1750000000}
        if not any(item['name'] == sibling['name'] for item in templates): templates.append(sibling)
        if case in {'team-golden-list', 'team-golden-delete', 'team-golden-create-flags'} and not any(item['name'] == 'smoke' for item in templates):
            templates.append({'name': 'smoke', 'packages': [], 'runtimes': {}, 'created_at': 1750000001})
        write_golden(path, templates)
    if case in {'workspace-run', 'workspace-check', 'workspace-diff'} and absent('omg-workspace.toml'):
        write('omg-workspace.toml', 'name = "smoke"\ncreated_at = "2025-06-01T12:00:00Z"\n[projects.fixture]\npath = "."\ndepends_on = []\n[projects.fixture.commands]\nbuild = "make build"\ntest = "make test"\n')
    if case.startswith('team-') and case != 'team-init' and absent('.omg/team.toml'):
        member = pwd.getpwuid(os.getuid()).pw_name
        write('.omg/team.toml', 'team_id = "smoke/team"\nname = "Smoke Team"\nmember_id = ' + json.dumps(member) + '\nauto_push = false\n')
    if case == 'init':
        runtime_fixture(data)
        for path in [home / '.bashrc', home / '.zshrc', home / '.config/fish/config.fish', home / '.config/systemd/user/omgd.service']:
            write(path, '# preserve existing init fixture\n')
    baseline = {str(path): identity(path) for path in [Path('Makefile'), Path('project/README.md'), Path('project/Makefile'),
               data / 'fixture-unrelated.txt', config / 'fixture-unrelated.txt', config / 'config.toml']}
    for path in [Path('.omg/team.toml'), Path('.omg/team-status.json'), Path('omg-workspace.toml'),
                 data / 'audit/audit.jsonl', data / 'history.json', data / 'snapshots/index.json', config / 'policy.toml',
                 home / '.bashrc', home / '.zshrc', home / '.config/fish/config.fish', home / '.config/systemd/user/omgd.service',
                 data / 'license-clock.highwater', Path('.git/hooks/pre-commit')]:
        if path.is_file(): baseline[str(path)] = identity(path)
    if case in {'list', 'list-available', 'which', 'hook-env', 'init', 'tool-list'}:
        for path in data.rglob('*'):
            if path.is_file() and not path.is_symlink(): baseline[str(path)] = identity(path)
    before = {'case': case, 'time': int(time.time()), 'files': baseline}
    if case.startswith('team-golden-'): before['golden'] = templates
    if case == 'tool-list': before['tools'] = {str(link): os.readlink(link) for link in (data / 'bin').iterdir() if link.is_symlink()}
    if case == 'init': before['packages'] = native_packages(os.environ['OMG_QEMU_DISTRO'])
    if case in {'rollback', 'rollback-yes'}: before['rollback_distro'] = os.environ['OMG_QEMU_DISTRO']
    write('.qemu-local-before.json', json.dumps(before))


def check(case, code, stdout, stderr):
    require(case in REFUSALS or case in OUTPUTS, f'unknown local contract: {case}')
    before = json.loads(regular_text('.qemu-local-before.json'))
    require(before['case'] == case, 'fixture is bound to another command')
    allowed_changes = {str(Path(os.environ['HOME']) / '.bashrc')} if case == 'hook-uninstall' else set()
    require(all(path in allowed_changes or identity(path) == digest for path, digest in before['files'].items()), 'command modified unrelated or read-only fixture')
    data, config, home = (Path(os.environ[name]) for name in ('OMG_DATA_DIR', 'OMG_CONFIG_DIR', 'HOME'))
    stdout = re.sub(r'\x1b\[[0-9;]*m', '', stdout)
    if case in REFUSALS:
        if case in {'rollback', 'rollback-yes'}:
            distro = os.environ.get('OMG_QEMU_DISTRO')
            require(distro == before['rollback_distro'], 'rollback fixture is bound to another backend')
            cause = ('Package rollback is not implemented for the selected Fedora backend'
                     if distro == 'fedora' else REFUSALS[case])
            require(code == 1 and stdout == '' and stderr == f'Error: {cause}\n', f'incorrect {case} refusal cause')
            require(absent(data / 'history.json'), 'rollback refusal created private history')
        else:
            require(code == 1 and REFUSALS[case] in stderr, f'incorrect {case} refusal cause')
        for name in ('omg.lock', '.omg.toml', 'missing.lock', 'missing-b.lock', 'audit-evidence',
                     'audit-evidence-flags', 'enterprise-evidence', 'compliance.json'):
            require(absent(name), f'refusal created forbidden artifact: {name}')
        require(absent(data / 'license.json'), 'refusal created an account credential')
        require(not list(Path('.').glob('omg-report-*.json')), 'refusal published an enterprise report')
        if case.startswith('enterprise-reports'):
            require('Failed to fetch team members for enterprise report' in stderr, 'report refusal omitted its fetch boundary')
        if case == 'team-compliance-export':
            require(str(Path.cwd() / 'compliance.json') in stderr, 'compliance refusal omitted selected output')
        if case == 'workspace-run':
            require("'omg run true' in '.' exited with code" in stdout, 'workspace run omitted failing project')
        if case == 'workspace-check':
            require('fixture' in stdout and 'needs attention' in stdout, 'workspace check omitted missing-lock project')
        return check_metrics(case, stdout, stderr)
    require(code == 0, 'local output command did not succeed')
    if case in {'list', 'list-available', 'which', 'hook-env'}:
        runtime_contract(case, data, stdout)
    elif case in {'hooks-status', 'hooks-run', 'hook-uninstall', 'init'}:
        hook_contract(case, home, stdout, before)
    elif case.startswith('team-'):
        team_contract(case, config, stdout, before)
    elif case.startswith('tool-'):
        tool_contract(case, data, stdout, before)
    elif case.startswith('audit-'):
        audit_contract(case, data, config, stdout)
    elif case.startswith('history'):
        entries = list(reversed(history_entries()))
        if case == 'history-flags': entries = [entry for entry in entries if entry['transaction_type'] == 'Install' and entry['changes'][0]['name'].startswith('pacman') and entry['timestamp'].startswith('2025')]
        entries = entries[:3]
        require('Transaction History (filtered)' in stdout if case == 'history-flags' else 'Transaction History (last 3)' in stdout, 'history omitted selected mode')
        require(re.findall(r'\[(hist000\d)\]', stdout) == [entry['id'][:8] for entry in entries], 'history displayed wrong selection/order')
        for entry in entries:
            require(f"- {entry['transaction_type']} (1 changes)" in stdout and f"{entry['changes'][0]['name']} 1.0 → 2.0" in stdout, 'history displayed wrong package/type/version')
    elif case == 'snapshot-list':
        require(re.findall(r'\b(snap-fixture-[a-z])\b', stdout) == ['snap-fixture-b', 'snap-fixture-a'], 'snapshot list order or identities differ')
        for value in ['OMG Snapshots', '2 snapshots total', 'abc12345', 'def67890', 'fixture snapshot alpha', 'fixture snapshot beta']:
            require(value in stdout, 'snapshot list omitted persisted metadata')
        metadata = json.loads(regular_text(data / 'snapshots/index.json'))['snapshots']
        for item in metadata:
            date = datetime.datetime.fromtimestamp(item['created_at'], datetime.timezone.utc).strftime('%Y-%m-%d %H:%M')
            require(re.search(re.escape(item['id']) + r'\s+' + re.escape(date) + r'\s+' + re.escape(item['hash'][:8]) + r'\s+' + re.escape(item['message']), stdout), 'snapshot list displayed wrong persisted date/hash/message mapping')
    elif case == 'workspace-diff':
        require('Comparing workspace environments vs main' in stdout and 'fixture' in stdout and stdout.count('No omg.lock file') == 1, 'workspace diff did not identify selected missing lock')
        require(absent('omg.lock'), 'workspace diff fabricated a lock')
    elif case == 'config':
        for value in ['OMG Configuration', 'telemetry.enabled = false', 'aur.build_concurrency = 3', 'aur.enable_ccache = false', str(config / 'config.toml'), str(data)]:
            require(value in stdout, 'config disagrees with persisted private settings')
    elif case == 'privacy':
        require('OMG Privacy Settings' in stdout and 'Telemetry: Disabled' in stdout and 'Telemetry: Enabled' not in stdout, 'privacy disagrees with persisted disabled telemetry')
    elif case == 'account-status':
        require('OMG Dashboard account' in stdout and 'Status: Not linked' in stdout and 'Status: Linked' not in stdout and absent(data / 'license.json'), 'account status invented or changed account state')
    elif case == 'account-unlink':
        require(absent(data / 'license.json') and 'Dashboard account unlinked.' in stdout and 'Local commands are unchanged.' in stdout, 'account unlink did not remove selected credential')
    elif case == 'stats':
        for value in ['OMG Usage Statistics', 'Total Commands: 37', 'Queries Today: 3', 'Queries This Month: 9', 'Time Saved: 1.0min', 'search (21x)', 'list (16x)']:
            require(value in stdout, 'stats disagrees with saved counters')
        require(stdout.index('search (21x)') < stdout.index('list (16x)'), 'stats top commands are not ranked by usage')


def check_metrics(case, stdout, stderr):
    if case == 'metrics':
        socket = Path(os.environ['OMG_SOCKET_PATH'])
        require(absent(socket), 'metrics fixture socket is not absent')
        require('Failed to connect to daemon at ' + str(socket) in stderr, 'metrics tested another connection boundary')
        require('omg_requests_total' not in stdout, 'metrics fabricated counters during refusal')


def runtime_contract(case, data, stdout):
    base = data / 'versions'
    require(os.readlink(base / 'node/current') == '24.21.0' and os.readlink(base / 'python/current') == '3.12.14', 'runtime read modified active links')
    if case == 'which':
        require(stdout.strip() == 'node 24.21.0', 'which did not resolve project runtime pin')
    elif case == 'hook-env':
        selected = str(base / 'node/24.21.0/bin')
        probe = subprocess.run(['bash', '-c', 'source "$1"; printf "%s\\n%s" "$PATH" "${QEMU_MUST_NOT_AUTO_APPLY-unset}"', '_', 'command.stdout.log'],
                               env=dict(os.environ, PATH='/usr/bin:/bin', _OMG_PATH_BASE='/usr/bin:/bin'), capture_output=True, text=True, timeout=5)
        require(probe.returncode == 0 and probe.stdout == selected + ':/usr/bin:/bin\nunset', 'hook-env did not select confined PATH or applied project environment')
        require(stdout.strip() == 'export PATH=' + shlex.quote(selected) + ':"${_OMG_PATH_BASE:-$PATH}"' or stdout.strip() == "export PATH='" + selected + "':\"${_OMG_PATH_BASE:-$PATH}\"", 'hook-env emitted unexpected shell operations')
    elif case == 'list':
        entries = re.findall(r'\b(node|python) ([\d.]+)([^\n]*)', stdout)
        require({(name, version): '(active)' in rest for name, version, rest in entries} == {('node', '24.21.0'): True, ('node', '22.16.0'): False, ('python', '3.12.14'): True} and len(entries) == 3, 'installed list disagrees with fixture versions/active state')
        require(len(re.findall(r'^\s*• ', stdout, re.M)) == 3, 'installed list invented another runtime')
    else:
        require('Installed runtime versions' in stdout and re.findall(r'Node\.js[^\n]*?([\d.]+)', stdout) == ['24.21.0'] and re.findall(r'Python[^\n]*?([\d.]+)', stdout) == ['3.12.14'], 'available-without-runtime disagrees with current probes')
        require('22.16.0' not in stdout, 'available-without-runtime displayed inactive version')
        require(len(re.findall(r'^\s*• ', stdout, re.M)) == 2, 'available-without-runtime invented another current provider')


def hook_contract(case, home, stdout, before):
    if case == 'hooks-status':
        require(stdout.count('pre-commit - installed (unrecognized or modified)') == 1 and 'Hooks directory: ' + str(Path.cwd() / '.git/hooks') in stdout, 'hook status disagrees with seeded custom hook')
        for name in ('post-checkout', 'post-merge'):
            expected = 'installed (OMG)' if Path('.git/hooks', name).exists() else 'not installed'
            require(f'{name} - {expected}' in stdout, 'hook status disagrees with actual installed hook')
    elif case == 'hooks-run':
        require(regular_text('hook-executed.txt') == 'executed fixture pre-commit\n' and 'Running pre-commit hook...' in stdout and 'Hook completed successfully' in stdout, 'hooks run did not execute controlled hook')
    elif case == 'hook-uninstall':
        rc = home / '.bashrc'; backup = home / '.bashrc.omg-backup'
        require(regular_text(rc) == 'alias keep="echo preserved"\nexport KEEP_VALUE=42\n' and identity(backup) == before['files'][str(rc)], 'hook uninstall damaged unrelated shell content or backup')
        require('Shell integration removed (rc file backed up with .omg-backup)' in stdout, 'hook uninstall omitted real removal result')
    else:
        for value in ['Setting up with defaults', 'Shell hook: skipped', 'Daemon setup: skipped', 'Setup complete!']:
            require(value in stdout, 'init did not honor skip modes')
        # Every admitted distro artifact has a native fingerprint provider.
        # A skipped capture is therefore a failed contract even if init exits 0.
        require(Path('omg.lock').exists(), 'native init skipped required environment capture')
        if Path('omg.lock').exists():
            lock = tomllib.loads(regular_text('omg.lock'))
            require(isinstance(lock.get('hash'), str) and len(lock['hash']) == 64 and isinstance(lock.get('packages'), list), 'init captured malformed lock state')
            digest = hashlib.sha256()
            require(lock.get('schema_version') == 1 and isinstance(lock.get('runtimes'), dict) and isinstance(lock.get('timestamp'), int), 'init captured incomplete lock schema')
            for name, version in sorted(lock['runtimes'].items()): digest.update(f'{name}:{version};'.encode())
            for name in sorted(set(lock['packages'])): digest.update((name + ';').encode())
            require(lock['hash'] == digest.hexdigest(), 'init captured inconsistent fingerprint')
            require(lock['packages'] == before['packages'] and lock['runtimes'] == {'node': '24.21.0', 'python': '3.12.14'}, 'init capture differs from independent package/runtime fixture')
            require(before['time'] <= lock['timestamp'] <= int(time.time()) + 2, 'init capture timestamp is stale')
            require('Capturing environment...' in stdout and '✓' in stdout and '(failed:' not in stdout and '(skipped:' not in stdout, 'init did not report successful capture')
        require(absent(os.environ['OMG_SOCKET_PATH']), 'skip-daemon started a socket')


def team_contract(case, config, stdout, before):
    if case == 'team-init':
        team = tomllib.loads(regular_text('.omg/team.toml')); status = json.loads(regular_text('.omg/team-status.json'))
        member = pwd.getpwuid(os.getuid()).pw_name
        require(team == {'team_id': 'smoke/team', 'name': 'Smoke Team', 'member_id': member, 'auto_push': False}, 'team init saved wrong identity/configuration')
        require(status['format_version'] == 1 and status['config'] == dict(team, remote_url=None) and status['lock_hash'] == '' and len(status['members']) == 1, 'team init status disagrees with config')
        item = status['members'][0]
        require(item['id'] == member and item['env_hash'] == '' and item['in_sync'] is True and item['drift_summary'] is None and before['time'] <= item['last_sync'] <= int(time.time()) + 2 and before['time'] <= status['updated_at'] <= int(time.time()) + 2, 'team init saved wrong member state/time')
        require('Team workspace initialized!' in stdout and 'smoke/team' in stdout and 'Smoke Team' in stdout, 'team init output disagrees with persisted identity')
        for name in ('post-checkout', 'post-merge'):
            path = Path('.git/hooks', name); content = regular_text(path)
            require(os.access(path, os.X_OK) and '# OMG Team Sync Hook' in content and os.environ['OMG_QEMU_EXECUTABLE'] in content and 'env check' in content, 'team init did not bind executable Git hook')
            require(subprocess.run(['sh', '-n', str(path)], capture_output=True).returncode == 0, 'team init wrote invalid hook shell')
            invocation = '"' + os.environ['OMG_QEMU_EXECUTABLE'] + '" env check'
            active = [line.strip() for line in content.splitlines() if not line.lstrip().startswith('#')]
            require(sum(line.startswith(invocation + ' ') for line in active) == 1, 'team hook executable binding exists only in comments or invokes another binary')
            probe = Path('.qemu-team-hook-probe.sh').absolute()
            write(probe, '#!/bin/sh\nprintf "%s\\n" "$@" > .qemu-team-hook-called\n', 0o755)
            copied = Path('.qemu-team-hook-copy.sh')
            write(copied, content.replace(invocation, shlex.quote(str(probe)) + ' env check'), 0o755)
            marker = Path('.qemu-team-hook-called')
            if marker.exists(): marker.unlink()
            require(absent('omg.lock'), 'team hook fixture unexpectedly has a lock')
            run = subprocess.run(['sh', str(copied)], capture_output=True, timeout=5)
            require(run.returncode == 0 and absent(marker), 'team hook runs without its guarded lock')
            write('omg.lock', 'fixture hook guard only\n')
            run = subprocess.run(['sh', str(copied)], capture_output=True, timeout=5)
            Path('omg.lock').unlink()
            require(run.returncode == 0 and regular_text(marker) == 'env\ncheck\n', 'team hook did not execute guarded env check')
            marker.unlink(); copied.unlink(); probe.unlink()
    elif case == 'team-roles-list':
        for name, description in ROLES.items(): require(stdout.count(name + ' - ' + description) == 1, 'roles list omitted or changed permissions')
        require('Team Roles' in stdout and len(re.findall(r'(?:admin|lead|developer|readonly) - ', stdout)) == 4, 'roles list invented role entries')
    elif case in {'team-compliance', 'team-compliance-enforce'}:
        require('Compliance Status' in stdout and 'No local data' in stdout and 'Compliance scoring is not computed locally; view evaluated results on the dashboard' in stdout, 'compliance invented evaluation data')
        if case.endswith('enforce'): require('no compliance evaluation engine exists locally; nothing can be enforced yet' in stdout, 'compliance claimed enforcement capability')
        require(absent('compliance.json'), 'compliance published unevaluated evidence')
    else:
        templates = golden_templates(config / 'golden-paths.toml')
        require(len({item['name'] for item in templates}) == len(templates), 'golden store has duplicate names')
        old = {item['name']: item for item in before['golden']}; current = {item['name']: item for item in templates}
        selected = 'flagged' if case.endswith('flags') else 'smoke'
        expected = dict(old)
        if case == 'team-golden-delete':
            expected.pop('smoke', None)
            require(current == expected and "Deleted template 'smoke'" in stdout, 'golden delete removed wrong template or was a no-op')
        elif case == 'team-golden-list':
            require(current == old and f'{len(current)} custom template(s)' in stdout, 'golden list changed store or advertised wrong count')
            displayed = re.findall(r'([\w-]+) - runtimes: \[([^]]*)\], packages: (\d+)', stdout)
            require({name for name, _, _ in displayed} == set(current) and len(displayed) == len(current), 'golden list advertised wrong names')
            for name, keys, count in displayed:
                require(set(filter(None, keys.replace('"', '').replace(' ', '').split(','))) == set(current[name]['runtimes']) and int(count) == len(current[name]['packages']), 'golden list values disagree with store')
        else:
            require(selected in current, 'golden create did not persist selected template')
            created = current[selected]
            require(created['runtimes'] == ({'node': '20', 'python': '3.12'} if selected == 'flagged' else {}) and created['packages'] == (['ripgrep'] if selected == 'flagged' else []) and before['time'] <= created['created_at'] <= int(time.time()) + 2, 'golden create persisted wrong runtime/package constraints')
            expected[selected] = created
            require(current == expected and f"Golden path '{selected}' created!" in stdout, 'golden create changed sibling or output identity')


def tool_contract(case, data, stdout, before):
    if case == 'tool-list':
        expected = {Path(path).name: target for path, target in before['tools'].items()}
        observed = dict(re.findall(r'^\s+(\S+) points to -> (.+)$', stdout, re.M))
        require(observed == expected and len(re.findall(' points to -> ', stdout)) == len(expected), 'tool list disagrees with symlink targets')
        require(all(os.readlink(path) == target and Path(target).is_file() for path, target in before['tools'].items()), 'tool list changed fixture links/targets')
        require('ignored-regular-file' not in stdout, 'tool list advertised regular file as symlink tool')
    elif case == 'tool-search':
        require("Searching for 'rip'..." in stdout and 'Found 5 tools:' in stdout, 'tool search advertised wrong query/count')
        results = re.findall(r'\b([\w-]+) \[([^]]+)\] via (\w+)', stdout)
        expected = [(name, category, source.split(':')[0]) for name, source, description, category in REGISTRY
                    if 'rip' in name.lower() or 'rip' in description.lower() or 'rip' in category.lower()]
        require(results == expected, 'tool search returned wrong bundled matches')
        for name, _, description, category in REGISTRY:
            if any('rip' in value.lower() for value in (name, description, category)):
                require(description in stdout, 'tool search changed selected description')
    else:
        observed = re.findall(r'^\s+(\S+) \((\w+)\) - (.+)$', stdout, re.M)
        expected = [(name, source.split(':')[0], description) for name, source, description, _ in sorted(REGISTRY, key=lambda item: item[3])]
        require(observed == expected and f'Total: {len(REGISTRY)} tools available' in stdout, 'registry advertised wrong records/managers/order/count')
        categories = re.findall(r'\[([^]]+)\] \((\d+) tools\)', stdout)
        require(categories == [(category, str(sum(item[3] == category for item in REGISTRY))) for category in sorted({item[3] for item in REGISTRY})], 'registry category counts differ')


def audit_contract(case, data, config, stdout):
    if case == 'audit-policy':
        for value in ['Security Policy Status', 'Minimum Grade: VERIFIED (PGP/Checksum)', 'AUR Allowed: No', 'PGP Required: Yes', 'fixture-banned', 'MIT', 'Apache-2.0']:
            require(value in stdout, 'audit policy disagrees with persisted constraints')
    elif case == 'audit-verify':
        for value in ['Local audit chain consistency verified', 'Total: 4 entries', 'Valid: 4 entries', 'Internally consistent; not authenticated', 'does not prove authenticity or completeness', str(data / 'audit/audit.jsonl')]:
            require(value in stdout, 'audit verify omitted chain counts or authenticity limit')
    elif case == 'audit-log-flags':
        path = Path('audit-log-export.json'); entries = json.loads(regular_text(path))
        require(entries == [audit_entries()[2], audit_entries()[1]] and path.stat().st_mode & 0o777 == 0o600, 'audit export disregarded severity/order/limit/schema/privacy')
        require(str(Path.cwd() / path) in stdout and 'Export successful' in stdout, 'audit export omitted selected artifact')
    else:
        require(re.findall(r'Fixture event number (\d)', stdout) == ['4', '3', '2'] and 'Showing 3 of 3 entries' in stdout, 'audit log displayed wrong selection/order/count')
        for entry in audit_entries()[1:]:
            require('[' + entry['severity'].upper() + '] PackageInstall - ' + entry['description'] in stdout and 'Resource: ' + entry['resource'] in stdout, 'audit log displayed wrong event/severity/resource')


def native_packages(distro):
    if distro == 'arch':
        command = ['pacman', '-Qqe']
    elif distro in {'debian', 'ubuntu'}:
        command = ['apt-mark', 'showmanual']
    elif distro == 'fedora':
        command = ['dnf', '--cacheonly', '--disable-repo=*', '--setopt=disable_excludes=*',
                   'repoquery', '--userinstalled', '--qf', '%{name}\\n']
    else:
        raise ValueError('unknown native fingerprint provider')
    query = subprocess.run(command, capture_output=True, text=True, timeout=30)
    names = sorted(set(query.stdout.splitlines()))
    require(query.returncode == 0 and names and all(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+_.:@-]*', name) for name in names), 'independent explicit package fixture is unavailable or malformed')
    return names


def main():
    action, case = sys.argv[1:3]
    if action == 'prepare':
        prepare(case)
    elif action == 'check':
        check(case, int(sys.argv[3]), regular_text(sys.argv[4]), regular_text(sys.argv[5]))
    else:
        raise ValueError('unknown local oracle action')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SystemExit(f'assertion failed: local command contract: {error}')
