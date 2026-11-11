#!/usr/bin/env python3
"""Execute complete module shards and admit their exact successful CI owners."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile


WORKFLOW = '.github/workflows/ci.yml'
SHARDS = 2
MAX_RECEIPT = 4 * 1024 * 1024
PRIVILEGED_ID = 'test_qemu_health.HealthTests.test_native_systemd_collection'
EXPORT_ID = 'test_export_qemu_evidence.DescriptorTests.test_root_owned_diagnostics_export_for_runner_without_changing_source'
AUXILIARY = {
    'ci-artifacts-unit': ['bun', 'test', 'services/ci-artifacts/test/worker.test.ts'],
    'ci-artifacts-types': ['bun', 'run', '--cwd', 'services/ci', 'tsc', '--project', '../ci-artifacts/tsconfig.json', '--noEmit'],
    'ci-artifacts-deploy-contract': ['node', '--test', 'services/ci-artifacts/test/deploy.test.mjs'],
    'ci-artifacts-offline': ['node', 'services/ci/node_modules/wrangler/bin/wrangler.js', 'deploy', '--dry-run',
                             '--config', 'services/ci-artifacts/wrangler.jsonc', '--outdir', '{scratch}'],
}
EXPLICIT = (
    'test_benchmark_records.py', 'test_terminal_update_notice.py',
    'test_audit_repair_shell.py', 'test_changelog_workflow_security.py',
    'test_ci_config_path_security.py', 'test_container_path_security.py',
    'test_daemon_path_security.py', 'test_shell_backup_safety.py',
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def read_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique,
                      parse_constant=lambda value: require(False, 'nonfinite JSON number'))


def write_json(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + '.next')
    temporary.write_bytes(canonical(value) + b'\n')
    temporary.replace(path)


def test_identities(suite):
    rows = []
    def visit(item):
        if isinstance(item, unittest.TestSuite):
            for child in item:
                visit(child)
        else:
            rows.append(item.id())
    visit(suite)
    require(len(rows) == len(set(rows)), 'duplicate discovered test identity')
    require(rows, 'unexpectedly empty helper module')
    return sorted(rows)


def cases(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from cases(item)
        else:
            yield item


def load_module(root, relative):
    path = root / relative
    require(path.is_file() and not path.is_symlink(), 'missing or unsafe helper module')
    # Separate discovery roots preserve the existing unittest import names.
    sys.modules.pop(path.stem, None)
    old_path = sys.path[:]
    try:
        sys.path[:0] = [str(path.parent), str(root)]
        spec = importlib.util.spec_from_file_location(path.stem, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[path.stem] = module
        spec.loader.exec_module(module)
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromModule(module)
        require(not loader.errors, 'helper discovery failed: ' + '\n'.join(loader.errors))
        return suite, test_identities(suite)
    finally:
        sys.path[:] = old_path


def discover(root):
    files = set(root.glob('scripts/test_*.py')) | set(root.glob('tests/test_qemu_*.py'))
    files.update(root / 'tests' / name for name in EXPLICIT)
    require(any(path.parent == root / 'scripts' for path in files), 'missing script helper suites')
    require(any(path.name.startswith('test_qemu_') for path in files), 'missing QEMU helper suites')
    modules = []
    for path in sorted(files):
        relative = path.relative_to(root).as_posix()
        _, identities = load_module(root, relative)
        row = dict(path=relative, sha256=digest(path.read_bytes()), identities=identities)
        if relative == 'scripts/test_qemu_boot_timeout_budget.py':
            companion = root / 'scripts/run_qemu_boot_timeout_budget.py'
            spec = importlib.util.spec_from_file_location('helper_boot_companion', companion)
            reviewed = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(reviewed)
            require(sorted(reviewed.REQUIRED_IDENTITIES) == identities, 'reviewed QEMU companion identities changed')
            row['required_passes'] = identities
        if relative == 'scripts/test_export_qemu_evidence.py':
            require(EXPORT_ID in identities, 'native exporter probe is missing')
            row['required_passes'] = [EXPORT_ID]
        modules.append(row)
    all_ids = [name for row in modules for name in row['identities']]
    require(len(all_ids) == len(set(all_ids)), 'duplicate helper identities across modules')
    return modules


def selection(manifest, shard, shards):
    require(type(shard) is int and type(shards) is int and 0 <= shard < shards
            and shards in (1, SHARDS), 'invalid helper shard')
    selected = [row for index, row in enumerate(manifest) if index % shards == shard]
    require(selected, 'unexpectedly empty helper shard')
    return selected


def source_context(root, environment, *, check_clean=False):
    hosted = environment.get('GITHUB_ACTIONS') == 'true'
    def git(*args):
        result = subprocess.run(['git', '-c', 'safe.directory=' + str(root), '-C', str(root), *args],
                                capture_output=True, text=True, timeout=20)
        if result.returncode:
            require(not hosted, 'helper checkout identity unavailable')
            return None
        return result.stdout.strip()
    source = git('rev-parse', 'HEAD')
    # Developer runs may be dirty and never authorize remote reuse. Avoid an
    # expensive DrvFS status walk there; hosted and privileged proof must check.
    clean = git('status', '--porcelain', '--untracked-files=all') == '' if hosted or check_clean else False
    context = dict(repository=environment.get('GITHUB_REPOSITORY'), source_sha=source,
                   tree_sha=git('rev-parse', 'HEAD^{tree}'), source_clean=clean,
                   run_id=environment.get('GITHUB_RUN_ID'),
                   run_attempt=int(environment.get('GITHUB_RUN_ATTEMPT', '0')),
                   workflow_ref=environment.get('GITHUB_WORKFLOW_REF'),
                   event=environment.get('GITHUB_EVENT_NAME', 'local'),
                   ref=environment.get('GITHUB_REF'), api_head_sha=source,
                   python=dict(implementation=platform.python_implementation(),
                               version=list(sys.version_info[:3])),
                   platform=sys.platform, uid=os.getuid() if hasattr(os, 'getuid') else None)
    if context['event'] == 'pull_request':
        event = read_json(Path(environment['GITHUB_EVENT_PATH']).read_bytes())
        context['api_head_sha'] = event['pull_request']['head']['sha']
    if hosted:
        require(source == environment.get('GITHUB_SHA') and clean, 'helper source is dirty or mismatched')
        require(re.fullmatch(r'[0-9a-f]{40}', source or '')
                and re.fullmatch(r'[0-9a-f]{40}', context['tree_sha'] or '')
                and re.fullmatch(r'[0-9a-f]{40}', context['api_head_sha'] or '')
                and re.fullmatch(r'[0-9]+', context['run_id'] or '')
                and context['run_attempt'] > 0, 'invalid hosted helper identity')
        allowed = (WORKFLOW, '.github/workflows/benchmark.yml', '.github/workflows/qemu-matrix.yml')
        require(context['workflow_ref'] in [context['repository'] + '/' + path + '@' + context['ref'] for path in allowed],
                'helper producer must be an exact ordinary workflow ref')
    return context


def empty_receipt(root, manifest, shard, shards, environment, static_complete):
    return dict(schema_version=1, kind='workflow-helper-shard',
                context=source_context(root, environment), shard=shard, shards=shards,
                static_complete=bool(static_complete), manifest=manifest,
                manifest_sha256=digest(canonical(manifest)),
                runner_sha256=digest(Path(__file__).read_bytes()),
                discovered=sorted(name for row in manifest for name in row['identities']),
                selected=sorted(name for row in selection(manifest, shard, shards) for name in row['identities']),
                executed=[], auxiliary=[], privileged=None, complete=False, success=False, failure_kind=None)


def validate_execution(receipt, manifest):
    require(type(receipt) is dict and type(receipt.get('schema_version')) is int and receipt['schema_version'] == 1
            and receipt.get('kind') == 'workflow-helper-shard', 'invalid helper receipt schema')
    require(receipt.get('manifest') == manifest
            and receipt.get('manifest_sha256') == digest(canonical(manifest)), 'foreign helper manifest')
    discovered = sorted(name for row in manifest for name in row['identities'])
    wanted = sorted(name for row in selection(manifest, receipt.get('shard'), receipt.get('shards'))
                    for name in row['identities'])
    require(receipt.get('discovered') == discovered and receipt.get('selected') == wanted,
            'missing or foreign selected helper work')
    executed = receipt.get('executed')
    require(isinstance(executed, list) and len(executed) == len(wanted)
            and all(type(row) is dict for row in executed), 'incomplete helper execution')
    require(sorted(row.get('id', '') for row in executed) == wanted,
            'duplicate, missing or foreign executed helper identity')
    for row in executed:
        require(row.get('status') in ('passed', 'skipped'), 'failed or incomplete helper identity')
        elapsed = row.get('elapsed_seconds')
        require(type(elapsed) in (int, float) and math.isfinite(elapsed) and elapsed >= 0,
                'invalid helper timing')
        if row['status'] == 'skipped':
            require(isinstance(row.get('reason'), str) and bool(row['reason']), 'unexplained helper skip')
    if receipt.get('context', {}).get('platform') == 'linux':
        required = {name for module in manifest for name in module.get('required_passes', []) if name in wanted}
        require(all(row['status'] == 'passed' for row in executed if row['id'] in required),
                'reviewed QEMU companion did not pass')
    require(receipt.get('complete') is True and receipt.get('success') is True
            and receipt.get('failure_kind') is None, 'helper work did not complete successfully')


def execute_module(root, relative, output, only=None):
    suite, identities = load_module(root, relative)
    if only is not None:
        require(only in identities, 'missing exact privileged helper identity')
        suite = unittest.TestSuite(test for test in cases(suite) if test.id() == only)
        identities = test_identities(suite)
    rows = {}
    started = {}
    def save():
        write_json(output, dict(identities=identities, executed=list(rows.values()),
                               actor=dict(uid=os.getuid() if hasattr(os, 'getuid') else None,
                                          platform=sys.platform, python=list(sys.version_info[:3]))))
    class Recorded(unittest.TextTestResult):
        def startTest(self, test):
            super().startTest(test)
            require(test.id() not in rows, 'duplicate executed helper identity')
            started[test.id()] = time.monotonic()
            rows[test.id()] = dict(id=test.id(), status='running', elapsed_seconds=0)
            save()
        def addSuccess(self, test):
            super().addSuccess(test); rows[test.id()]['status'] = 'passed'
        def addFailure(self, test, error):
            super().addFailure(test, error); rows[test.id()]['status'] = 'failed'
        def addError(self, test, error):
            super().addError(test, error)
            rows.setdefault(test.id(), dict(id=test.id(), elapsed_seconds=0))['status'] = 'failed'
            save()
        def addSkip(self, test, reason):
            super().addSkip(test, reason)
            if test.id() in rows:
                rows[test.id()].update(status='skipped', reason=str(reason) or 'unittest skip')
        def addExpectedFailure(self, test, error):
            super().addExpectedFailure(test, error); rows[test.id()]['status'] = 'failed'
        def addUnexpectedSuccess(self, test):
            super().addUnexpectedSuccess(test); rows[test.id()]['status'] = 'failed'
        def addSubTest(self, test, subtest, error):
            super().addSubTest(test, subtest, error)
            if error is not None:
                rows[test.id()]['status'] = 'failed'
        def stopTest(self, test):
            rows[test.id()]['elapsed_seconds'] = time.monotonic() - started[test.id()]
            save(); super().stopTest(test)
    # Own timing works on Python 3.11 as well as hosted 3.12; no new durations kwarg.
    result = unittest.TextTestRunner(verbosity=2, resultclass=Recorded).run(suite)
    return 0 if result.wasSuccessful() and all(row['status'] in ('passed', 'skipped') for row in rows.values()) else 1


def terminate(process):
    if os.name == 'posix':
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + 2
        while not exited_unreaped(process) and time.monotonic() < deadline:
            time.sleep(.05)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    else:
        subprocess.run(['taskkill', '/F', '/T', '/PID', str(process.pid)],
                       capture_output=True, timeout=15, check=False)
    process.wait(timeout=10)


def exited_unreaped(process):
    return os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None


def child_process(root, arguments, environment, deadline, log_path, argv=None):
    require(os.name != 'posix' or all(hasattr(os, name) for name in ('waitid', 'WNOWAIT')),
            'POSIX helpers require non-reaping child observation')
    with tempfile.TemporaryDirectory(prefix='omg-helper-') as scratch, log_path.open('wb') as log:
        if os.name == 'posix':
            Path(scratch).chmod(0o711)
        child_env = dict(environment, TMPDIR=scratch, TEMP=scratch, TMP=scratch, PYTHONDONTWRITEBYTECODE='1')
        command = [sys.executable, '-B', str(Path(__file__).resolve()), *arguments] if argv is None else argv
        process = subprocess.Popen(command,
                                   cwd=root, env=child_env, stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=os.name == 'posix')
        failure = None
        try:
            while not (exited_unreaped(process) if os.name == 'posix' else process.poll() is not None):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(arguments, 0)
                require(log_path.stat().st_size <= 16 * 1024 * 1024, 'helper module log exceeds limit')
                time.sleep(min(.05, remaining))
        except BaseException as error:
            failure = error
            raise
        finally:
            try:
                terminate(process)
            except BaseException as cleanup_error:
                if failure is None:
                    raise
                failure.add_note('Owned helper cleanup failed: ' + type(cleanup_error).__name__)
    with log_path.open('rb') as log:
        if log_path.stat().st_size > 1024 * 1024:
            log.seek(-1024 * 1024, os.SEEK_END)
        print(log.read().decode('utf-8', errors='replace'), flush=True)
    require(log_path.stat().st_size <= 16 * 1024 * 1024, 'helper module log exceeds limit')
    return process.returncode


def privileged_probe(root, output):
    require(sys.platform == 'linux' and os.getuid() == 0 and shutil.which('journalctl'),
            'native helper probe requires actual Linux root and journalctl')
    started_at = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    status = execute_module(root, 'scripts/test_qemu_health.py', output, PRIVILEGED_ID)
    result = read_json(output.read_bytes())
    require(status == 0 and len(result['executed']) == 1 and result['executed'][0]['status'] == 'passed',
            'native helper probe failed or skipped')
    result.update(schema_version=1, kind='workflow-helper-privileged',
                  started_at=started_at, completed_at=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                  context=source_context(root, os.environ, check_clean=True),
                  module_sha256=digest((root / 'scripts/test_qemu_health.py').read_bytes()),
                  runner_sha256=digest(Path(__file__).read_bytes()))
    write_json(output, result)


def validate_privileged(proof, manifest, context):
    module = next((row for row in manifest if PRIVILEGED_ID in row['identities']), None)
    require(module is not None and type(proof) is dict
            and proof.get('kind') == 'workflow-helper-privileged' and type(proof.get('schema_version')) is int
            and proof['schema_version'] == 1
            and proof.get('module_sha256') == module['sha256']
            and proof.get('runner_sha256') == digest(Path(__file__).read_bytes())
            and proof.get('identities') == [PRIVILEGED_ID], 'invalid native helper probe recipe')
    actor, execution = proof.get('actor', {}), proof.get('executed', [])
    require(actor.get('uid') == 0 and type(actor['uid']) is int and actor.get('platform') == 'linux'
            and actor.get('python', [])[:2] == context.get('python', {}).get('version', [])[:2],
            'native helper probe lacks the actual privileged actor')
    require(isinstance(execution, list) and len(execution) == 1 and type(execution[0]) is dict
            and execution[0].get('id') == PRIVILEGED_ID
            and execution[0].get('status') == 'passed', 'native helper probe failed or skipped')
    elapsed = execution[0].get('elapsed_seconds')
    require(type(elapsed) in (int, float) and math.isfinite(elapsed) and elapsed >= 0,
            'invalid native helper probe timing')
    require(timestamp(proof.get('started_at')) <= timestamp(proof.get('completed_at')),
            'invalid native helper probe interval')
    require(all(proof.get('context', {}).get(key) == context.get(key)
                for key in ('source_sha', 'tree_sha', 'source_clean')), 'native helper probe source mismatch')


def validate_auxiliary(rows):
    require(isinstance(rows, list) and len(rows) == len(AUXILIARY)
            and all(type(row) is dict for row in rows)
            and sorted(row.get('id', '') for row in rows) == sorted(AUXILIARY),
            'missing or duplicate Worker checks')
    for row in rows:
        require(row.get('recipe_argv') == AUXILIARY[row['id']] and row.get('exit_code') == 0
                and type(row['exit_code']) is int and row.get('complete') is True
                and type(row.get('elapsed_seconds')) in (int, float)
                and math.isfinite(row['elapsed_seconds']) and row['elapsed_seconds'] >= 0,
                'failed or foreign Worker check')


def run_shard(root, output, shard=0, shards=1, timeout=1800, static_complete=False, environment=None,
              privileged_receipt=None, worker_checks=False):
    require(math.isfinite(timeout) and timeout > 0, 'helper deadline must be positive')
    environment = dict(os.environ if environment is None else environment)
    output.mkdir(parents=True, exist_ok=False)
    deadline = time.monotonic() + timeout
    receipt = dict(schema_version=1, kind='workflow-helper-shard', complete=False, success=False,
                   failure_kind=None, executed=[])
    write_json(output / 'receipt.json', receipt)
    try:
        status = child_process(root, ['_manifest', '--root', str(root), '--output', str(output / 'manifest.json')],
                               environment, deadline, output / 'discovery.log')
        require(status == 0, 'helper discovery failed')
        manifest = read_json((output / 'manifest.json').read_bytes())
        receipt = empty_receipt(root, manifest, shard, shards, environment, static_complete)
        require(not static_complete or shard == 0, 'static checks have exactly one helper owner')
        if environment.get('GITHUB_ACTIONS') == 'true' and shards == SHARDS:
            require(static_complete is (shard == 0), 'missing or duplicate hosted static owner')
            if shard == 0 and PRIVILEGED_ID in receipt['discovered']:
                require(privileged_receipt is not None, 'missing native helper probe receipt')
            if shard == 0 and (root / 'services/ci-artifacts/src/index.ts').is_file():
                require(worker_checks, 'missing Worker checks owner')
        require(shard == 0 or (privileged_receipt is None and not worker_checks),
                'non-Python and privileged checks have exactly one owner')
        if privileged_receipt is not None:
            require(privileged_receipt.is_file() and not privileged_receipt.is_symlink()
                    and privileged_receipt.stat().st_size <= MAX_RECEIPT, 'invalid native helper probe file')
            receipt['privileged'] = read_json(privileged_receipt.read_bytes())
            validate_privileged(receipt['privileged'], manifest, receipt['context'])
        if worker_checks:
            for name, recipe in AUXILIARY.items():
                with tempfile.TemporaryDirectory(prefix='omg-worker-offline-') as scratch:
                    argv = [scratch if value == '{scratch}' else value for value in recipe]
                    started = time.monotonic()
                    status = child_process(root, [], dict(environment, WRANGLER_SEND_METRICS='false'), deadline,
                                           output / (name + '.log'), argv)
                receipt['auxiliary'].append(dict(id=name, recipe_argv=recipe, exit_code=status,
                                                 elapsed_seconds=time.monotonic() - started, complete=True))
                write_json(output / 'receipt.json', receipt)
                require(status == 0, 'Worker check failed: ' + name)
            validate_auxiliary(receipt['auxiliary'])
        write_json(output / 'receipt.json', receipt)
        for index, module in enumerate(selection(manifest, shard, shards)):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(module['path'], timeout)
            child_receipt = output / f'module-{index}.json'
            try:
                status = child_process(root, ['_module', '--root', str(root), '--module', module['path'],
                                              '--output', str(child_receipt)], environment, deadline,
                                       output / f'module-{index}.log')
            except BaseException:
                if child_receipt.exists():
                    receipt['executed'].extend(read_json(child_receipt.read_bytes())['executed'])
                raise
            require(child_receipt.is_file() and child_receipt.stat().st_size <= MAX_RECEIPT,
                    'helper module produced no bounded execution receipt')
            result = read_json(child_receipt.read_bytes())
            require(result.get('identities') == module['identities'], 'helper discovery changed during execution')
            receipt['executed'].extend(result['executed'])
            write_json(output / 'receipt.json', receipt)
            require(status == 0, 'helper module failed: ' + module['path'])
        final_context = source_context(root, environment)
        require(final_context == receipt['context'], 'helper source context changed during execution')
        receipt.update(complete=True, success=True)
        validate_execution(receipt, manifest)
    except BaseException as error:
        receipt.update(success=False, failure_kind='timeout' if isinstance(error, subprocess.TimeoutExpired)
                       else 'failure', error=str(error))
        write_json(output / 'receipt.json', receipt)
        raise
    write_json(output / 'receipt.json', receipt)
    return receipt


class Pending(ValueError):
    """The exact producer exists but its required owners are not terminal."""


class NoProducer(ValueError):
    """A standalone scheduled/manual caller has no exact CI producer."""


class GitHub:
    def __init__(self, deadline):
        self.deadline = deadline

    def request(self, endpoint, binary=False):
        # Reuse the native admission transport/header parser; clip every retry
        # to this owner's one absolute deadline instead of renewing a request budget.
        spec = importlib.util.spec_from_file_location('helper_native_transport', Path(__file__).with_name('native-build-artifact.py'))
        transport = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(transport)
        for attempt in range(3):
            remaining = self.deadline - time.monotonic()
            require(remaining > 0, 'helper admission deadline exhausted')
            try:
                content = transport.api(endpoint, MAX_RECEIPT if binary else 1024 * 1024 + 65536,
                                        include_status=not binary, timeout=min(60, remaining))
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as error:
                if isinstance(error, subprocess.CalledProcessError):
                    if binary or not error.output or not error.output.startswith(b'HTTP/'):
                        raise
                    status, _, retry_after = transport.metadata_response(error.output)
                    if status not in (502, 503, 504) or retry_after:
                        raise
                delay = 2 ** attempt
                if attempt == 2 or self.deadline - time.monotonic() <= delay:
                    raise
                time.sleep(delay)
            else:
                if binary:
                    return content
                status, content, _ = transport.metadata_response(content)
                require(200 <= status < 300, 'unsuccessful helper metadata response')
                return read_json(content)

    def listing(self, endpoint, field):
        # Same complete-list semantics as coverage admission: no partial or changing pages.
        rows, seen, total = [], set(), None
        for page in range(1, 21):
            result = self.request(endpoint + ('&' if '?' in endpoint else '?') + f'per_page=100&page={page}')
            batch, count = result.get(field), result.get('total_count')
            require(type(count) is int and 0 <= count <= 2000 and isinstance(batch, list)
                    and len(batch) <= 100 and (total is None or total == count), 'incomplete or changing helper listing')
            total = count
            for row in batch:
                identity = row.get('id')
                require(type(identity) is int and identity > 0 and identity not in seen, 'duplicate helper listing ID')
                seen.add(identity); rows.append(row)
            if len(rows) == total:
                return rows
            require(batch and len(rows) < total, 'incomplete helper listing')
        raise ValueError('helper listing exceeds page budget')


def timestamp(value):
    require(isinstance(value, str) and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z', value),
            'invalid helper ownership timestamp')
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def validate_run(run, repository, workflow_id, source, event='push', ref='main'):
    require(run.get('repository', {}).get('full_name') == repository
            and run.get('path') == WORKFLOW and run.get('workflow_id') == workflow_id
            and run.get('head_sha') == source and run.get('event') == event
            and run.get('head_branch') == ref and type(run.get('id')) is int and run['id'] > 0
            and type(run.get('run_attempt')) is int and run['run_attempt'] > 0,
            'foreign helper workflow run')


def owner(api, repository, run, shard):
    attempt, snapshot = run['run_attempt'], run
    name = f'Workflow helpers ({shard}/{SHARDS})'
    def job(number):
        rows = api.listing(f'repos/{repository}/actions/runs/{run["id"]}/attempts/{number}/jobs', 'jobs')
        selected = [row for row in rows if row.get('name') == name]
        if not selected and run.get('status') != 'completed':
            raise Pending('helper owner is not scheduled yet')
        require(len(selected) == 1, 'missing or ambiguous helper owner')
        selected = selected[0]
        require(selected.get('run_id') == run['id'] and selected.get('head_sha') == run['head_sha'],
                'foreign helper owner')
        require(type(selected.get('run_attempt')) is int and 0 < selected['run_attempt'] <= number,
                'foreign helper owner attempt')
        if selected.get('status') != 'completed':
            raise Pending('latest helper owner is incomplete')
        require(selected.get('conclusion') == 'success', 'latest helper owner failed')
        require('ubuntu-24.04' in selected.get('labels', []), 'foreign helper runner recipe')
        return selected
    selected = job(attempt)
    start, finish = timestamp(selected.get('started_at')), timestamp(selected.get('completed_at'))
    require(start < finish, 'invalid helper owner interval')
    while start < timestamp(snapshot.get('run_started_at')):
        require(attempt > 1, 'helper owner predates its workflow')
        attempt -= 1
        snapshot = api.request(f'repos/{repository}/actions/runs/{run["id"]}/attempts/{attempt}')
        require(all(snapshot.get(key) == run.get(key) for key in ('id', 'head_sha', 'workflow_id', 'path', 'event'))
                and snapshot.get('run_attempt') == attempt, 'foreign carried helper attempt')
        previous = job(attempt)
        require((previous['started_at'], previous['completed_at']) == (selected['started_at'], selected['completed_at']),
                'carried helper execution changed')
        selected = previous
    return attempt, selected


def unpack_receipt(content, artifact):
    require(len(content) == artifact.get('size_in_bytes') and 0 < len(content) <= MAX_RECEIPT
            and artifact.get('digest') == 'sha256:' + digest(content), 'helper archive size or digest mismatch')
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        members = archive.infolist()
        require(len(members) == 1 and members[0].filename == 'receipt.json'
                and not members[0].is_dir() and not members[0].flag_bits & 1
                and stat.S_IFMT(members[0].external_attr >> 16) in (0, stat.S_IFREG)
                and 0 < members[0].file_size <= MAX_RECEIPT, 'unsafe helper receipt archive')
        return read_json(archive.read(members[0]))


def admit_pair(api, root, repository, run, source, manifest=None, expected_ref='refs/heads/main'):
    manifest = discover(root) if manifest is None else manifest
    remaining = getattr(api, 'deadline', time.monotonic() + 20) - time.monotonic()
    require(remaining > 0, 'helper admission deadline exhausted')
    tree = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD^{tree}'],
                                   text=True, timeout=min(20, remaining)).strip()
    artifacts = api.listing(f'repos/{repository}/actions/runs/{run["id"]}/artifacts', 'artifacts')
    admitted = []
    for shard in range(SHARDS):
        attempt, producer = owner(api, repository, run, shard)
        name = f'workflow-helpers-{run["id"]}-{attempt}-{shard}-of-{SHARDS}'
        selected = [row for row in artifacts if row.get('name') == name]
        require(len(selected) == 1, 'missing or ambiguous helper artifact')
        artifact = selected[0]
        require(type(artifact.get('size_in_bytes')) is int and 0 < artifact['size_in_bytes'] <= MAX_RECEIPT
                and artifact.get('expired') is False and artifact.get('workflow_run', {}).get('id') == run['id']
                and artifact['workflow_run'].get('head_sha') == run['head_sha']
                and timestamp(producer['started_at']) <= timestamp(artifact.get('created_at'))
                <= timestamp(producer['completed_at']), 'helper artifact lacks exact owner')
        receipt = unpack_receipt(api.request(f'repos/{repository}/actions/artifacts/{artifact["id"]}/zip', True), artifact)
        validate_execution(receipt, manifest)
        context = receipt.get('context', {})
        if shard == 0:
            if PRIVILEGED_ID in receipt['discovered']:
                validate_privileged(receipt.get('privileged'), manifest, context)
                require(timestamp(producer['started_at']) <= timestamp(receipt['privileged']['started_at'])
                        <= timestamp(receipt['privileged']['completed_at']) <= timestamp(producer['completed_at']),
                        'native helper probe is outside its successful owner interval')
            if (root / 'services/ci-artifacts/src/index.ts').is_file():
                validate_auxiliary(receipt.get('auxiliary'))
        else:
            require(receipt.get('privileged') is None and receipt.get('auxiliary') == [],
                    'duplicate privileged or Worker owner')
        require(receipt.get('shard') == shard and receipt.get('shards') == SHARDS
                and receipt.get('static_complete') is (shard == 0)
                and receipt.get('runner_sha256') == digest(Path(__file__).read_bytes()), 'foreign helper recipe')
        require(context.get('repository') == repository and context.get('source_sha') == source
                and context.get('tree_sha') == tree
                and context.get('api_head_sha') == run['head_sha'] and context.get('run_id') == str(run['id'])
                and context.get('run_attempt') == attempt and context.get('event') == run['event']
                and context.get('ref') == expected_ref and context.get('source_clean') is True
                and context.get('workflow_ref') == repository + '/' + WORKFLOW + '@' + expected_ref
                and context.get('platform') == 'linux' and type(context.get('uid')) is int and context['uid'] > 0
                and context.get('python', {}).get('implementation') == 'CPython'
                and context['python'].get('version', [])[:2] == [3, 12], 'helper source or environment mismatch')
        admitted.append(dict(shard=shard, producer_attempt=attempt, producer_job=producer['id'],
                             artifact_id=artifact['id'], artifact_digest=artifact['digest'],
                             selected=receipt['selected']))
    combined = [identity for row in admitted for identity in row['selected']]
    require(sorted(combined) == sorted(name for row in manifest for name in row['identities'])
            and len(combined) == len(set(combined)), 'incomplete helper shard union')
    refreshed = api.request(f'repos/{repository}/actions/runs/{run["id"]}')
    require(all(refreshed.get(key) == run.get(key) for key in ('id', 'head_sha', 'run_attempt', 'workflow_id', 'path', 'event')),
            'helper producer attempt changed during admission')
    for shard, row in enumerate(admitted):
        attempt, latest = owner(api, repository, refreshed, shard)
        require(attempt == row['producer_attempt'] and latest['id'] == row['producer_job'],
                'helper owner changed during admission')
    return dict(schema_version=1, kind='workflow-helper-admission', repository=repository,
                source_sha=source, run_id=run['id'], current_producer_attempt=run['run_attempt'],
                complete=True, success=True, manifest_sha256=digest(canonical(manifest)), producers=admitted)


def admit(root, environment, timeout, current_run=False):
    require(math.isfinite(timeout) and timeout > 0, 'helper admission deadline must be positive')
    repository, source = environment.get('GITHUB_REPOSITORY', ''), environment.get('GITHUB_SHA', '')
    require(re.fullmatch(r'[\w.-]+/[\w.-]+', repository) and re.fullmatch(r'[a-f0-9]{40}', source),
            'missing helper consumer identity')
    api = GitHub(time.monotonic() + timeout)
    def consumer_source():
        for arguments, expected in ((['rev-parse', 'HEAD'], source),
                                    (['status', '--porcelain', '--untracked-files=all'], '')):
            remaining = api.deadline - time.monotonic()
            require(remaining > 0, 'helper admission deadline exhausted')
            actual = subprocess.check_output(['git', '-C', str(root), *arguments], text=True,
                                             timeout=min(20, remaining)).strip()
            require(actual == expected, 'helper consumer checkout is dirty or mismatched')
    consumer_source()
    with tempfile.TemporaryDirectory(prefix='omg-helper-admission-') as directory:
        scratch = Path(directory)
        status = child_process(root, ['_manifest', '--root', str(root), '--output', str(scratch / 'manifest.json')],
                               environment, api.deadline, scratch / 'discovery.log')
        require(status == 0, 'helper admission discovery failed')
        manifest = read_json((scratch / 'manifest.json').read_bytes())
    workflow = api.request(f'repos/{repository}/actions/workflows/ci.yml')
    require(workflow.get('path') == WORKFLOW and type(workflow.get('id')) is int, 'foreign CI workflow')
    event, head, branch, expected_ref = 'push', source, 'main', 'refs/heads/main'
    selected = None
    if current_run:
        event, expected_ref = environment.get('GITHUB_EVENT_NAME'), environment.get('GITHUB_REF')
        branch = environment.get('GITHUB_HEAD_REF') if event == 'pull_request' else environment.get('GITHUB_REF_NAME')
        require(event in ('push', 'pull_request', 'merge_group', 'workflow_dispatch')
                and isinstance(expected_ref, str) and isinstance(branch, str)
                and environment.get('GITHUB_WORKFLOW_REF') == repository + '/' + WORKFLOW + '@' + expected_ref,
                'current helper admission must be the exact CI caller')
        if event == 'pull_request':
            payload = read_json(Path(environment['GITHUB_EVENT_PATH']).read_bytes())
            head = payload['pull_request']['head']['sha']
            require(re.fullmatch(r'[a-f0-9]{40}', head), 'invalid helper PR API head')
        require(re.fullmatch(r'[1-9][0-9]*', environment.get('GITHUB_RUN_ID', ''))
                and re.fullmatch(r'[1-9][0-9]*', environment.get('GITHUB_RUN_ATTEMPT', '')),
                'missing exact current helper run/attempt')
        selected = dict(id=int(environment['GITHUB_RUN_ID']))
    while time.monotonic() < api.deadline:
        if selected is None:
            runs = api.listing(f'repos/{repository}/actions/workflows/ci.yml/runs?event=push&head_sha={source}', 'workflow_runs')
            runs = [row for row in runs if row.get('head_branch') == 'main']
            if not runs and environment.get('GITHUB_EVENT_NAME') in ('schedule', 'workflow_dispatch'):
                raise NoProducer('no exact CI push run; execute standalone helper proof')
            if runs:
                selected = max(runs, key=lambda row: row['id'])
        if selected is not None:
            selected = api.request(f'repos/{repository}/actions/runs/{selected["id"]}')
            validate_run(selected, repository, workflow['id'], head, event, branch)
            if current_run:
                require(selected['run_attempt'] == int(environment['GITHUB_RUN_ATTEMPT']),
                        'current helper consumer attempt changed')
            try:
                admitted = admit_pair(api, root, repository, selected, source, manifest, expected_ref)
                if current_run:
                    consumer_source()
                    return admitted
                latest = api.listing(f'repos/{repository}/actions/workflows/ci.yml/runs?event=push&head_sha={source}',
                                     'workflow_runs')
                latest = [row for row in latest if row.get('head_branch') == 'main']
                require(latest and max(row['id'] for row in latest) == selected['id'],
                        'newer exact-source CI run replaced the helper producer')
                consumer_source()
                return admitted
            except Pending:
                pass
        time.sleep(min(5, max(0, api.deadline - time.monotonic())))
    raise ValueError('latest helper owners did not succeed before the common deadline')


def main():
    def interrupted(signum, frame):
        raise InterruptedError('helper execution cancelled by signal ' + str(signum))
    signal.signal(signal.SIGTERM, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('run', '_module', '_manifest', 'admit', 'privileged'):
        command = commands.add_parser(name)
        command.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
        command.add_argument('--output', type=Path, required=name != 'run')
        if name == 'run':
            command.add_argument('--shard', type=int, default=0)
            command.add_argument('--shards', type=int, default=1)
            command.add_argument('--timeout', type=float, default=1800)
            command.add_argument('--static-complete', action='store_true')
            command.add_argument('--privileged-receipt', type=Path)
            command.add_argument('--worker-checks', action='store_true')
        elif name == '_module':
            command.add_argument('--module', required=True)
        elif name == 'admit':
            command.add_argument('--timeout', type=float, default=1200)
            command.add_argument('--current-run', action='store_true')
    args = parser.parse_args()
    root = args.root.resolve()
    if args.command == 'run' and args.output is None:
        with tempfile.TemporaryDirectory(prefix='omg-helper-proof-') as directory:
            run_shard(root, Path(directory) / 'proof', args.shard, args.shards,
                      args.timeout, args.static_complete,
                      privileged_receipt=args.privileged_receipt, worker_checks=args.worker_checks)
        return 0
    output = args.output.resolve()
    if args.command == '_module':
        return execute_module(root, args.module, output)
    if args.command == '_manifest':
        write_json(output, discover(root))
        return 0
    if args.command == 'privileged':
        privileged_probe(root, output)
        return 0
    if args.command == 'admit':
        write_json(output, admit(root, os.environ, args.timeout, args.current_run))
    else:
        run_shard(root, output, args.shard, args.shards, args.timeout, args.static_complete,
                  privileged_receipt=args.privileged_receipt, worker_checks=args.worker_checks)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except NoProducer as error:
        print(str(error), file=sys.stderr); sys.exit(3)
    except (ValueError, OSError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        print('workflow helpers: ' + str(error), file=sys.stderr); sys.exit(1)
