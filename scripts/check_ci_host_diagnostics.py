#!/usr/bin/env python3
"""Offline parsed-graph checks; run with Python and PyYAML 6.0.3.

This checks the supported job-expression subset, not GitHub execution.
Unknown expression nodes/contexts fail rather than approximating them.
"""
import ast
import itertools
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parent.parent
BASE = '71be150267251014aa761658e0b4f62e76c4339e'
TOKEN = re.compile(r"'[^']*'|[A-Za-z_][A-Za-z0-9_.-]*|&&|\|\||!=|==|!|[()]|\s+")


def expression(source, context, success=True):
    source = source.strip().removeprefix('${{').removesuffix('}}').strip()
    position = 0
    translated = []
    for match in TOKEN.finditer(source):
        if match.start() != position:
            raise ValueError('Unsupported expression syntax')
        position = match.end()
        token = match.group()
        if token.isspace():
            continue
        if token.startswith("'") or token in ('(', ')', '==', '!='):
            translated.append(token)
        elif token in ('&&', '||', '!'):
            translated.append({'&&': 'and', '||': 'or', '!': 'not'}[token])
        elif token in ('true', 'false'):
            translated.append(str(token == 'true'))
        elif token == 'always':
            translated.append('True')
        elif token == 'cancelled':
            translated.append('False')
        else:
            translated.append(repr(context[token]))
    if position != len(source):
        raise ValueError('Unsupported expression suffix')
    encoded = ' '.join(translated).replace('True ( )', 'True').replace('False ( )', 'False')
    tree = ast.parse(encoded.strip(), mode='eval')
    allowed = (ast.Expression, ast.Constant, ast.BoolOp, ast.And, ast.Or,
               ast.UnaryOp, ast.Not, ast.Compare, ast.Eq, ast.NotEq)
    if any(not isinstance(node, allowed) for node in ast.walk(tree)):
        raise ValueError('Unsupported expression node')
    result = eval(compile(tree, '<workflow condition>', 'eval'), {'__builtins__': {}}, {})
    return bool(result) and (success or 'always()' in source or 'cancelled()' in source)


def graph(workflow, context, failed=()):
    jobs = workflow['jobs']
    admitted = set()
    unresolved = set(jobs)
    while unresolved:
        ready = []
        for name in unresolved:
            needs = jobs[name].get('needs', [])
            if isinstance(needs, str):
                needs = [needs]
            if not set(needs) <= set(jobs):
                raise ValueError('Unknown dependency')
            if set(needs) & unresolved:
                continue
            successful = all(item in admitted and item not in failed for item in needs)
            observed = dict(context)
            for item in needs:
                observed[f'needs.{item}.result'] = 'failure' if item in failed else 'success' if item in admitted else 'skipped'
            if expression(jobs[name].get('if', 'true'), observed, successful):
                admitted.add(name)
            ready.append(name)
        if not ready:
            raise ValueError('Dependency cycle')
        unresolved.difference_update(ready)
    return admitted


class HostDiagnosticGraphTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.current = yaml.load((ROOT / '.github/workflows/ci.yml').read_text(), Loader=yaml.BaseLoader)
        original = subprocess.run([os.environ.get('CI_GRAPH_GIT', 'git'), 'show', f'{BASE}:.github/workflows/ci.yml'],
                                  cwd=ROOT, check=True, capture_output=True, text=True)
        cls.original = yaml.load(original.stdout, Loader=yaml.BaseLoader)

    def context(self, event, flag, required, act=False, main=False):
        return {'github.event_name': event, 'inputs.host-diagnostics': flag,
                'needs.quick-gate.outputs.should-build': str(required).lower(),
                'github.event.act': act,
                'github.ref': 'refs/heads/main' if main else 'refs/heads/PER-32-host-diagnostics'}

    def test_complete_graph_isolated_only_for_explicit_dispatch(self):
        expected = {'quick-gate', 'ubuntu', 'runtime-usage', 'native-health-diagnostics'}
        for event, flag, required, act, main in itertools.product(
                ('workflow_dispatch', 'pull_request', 'push', 'merge_group'),
                (True, False, '', 'true', 'false'), (True, False), (True, False), (True, False)):
            with self.subTest(event=event, flag=flag, required=required, act=act, main=main):
                context = self.context(event, flag, required, act, main)
                actual = graph(self.current, context)
                if event == 'workflow_dispatch' and flag is True:
                    self.assertEqual(actual, expected)
                    self.assertNotIn('ci-success', actual)
                else:
                    self.assertEqual(actual, graph(self.original, context))

    def test_diagnostics_preserve_dependency_failures(self):
        context = self.context('workflow_dispatch', True, True)
        self.assertEqual(graph(self.current, context, {'quick-gate'}), {'quick-gate'})
        self.assertNotIn('runtime-usage', graph(self.current, context, {'ubuntu'}))

    def test_original_jobs_keep_dependencies_steps_and_permissions(self):
        for name, original in self.original['jobs'].items():
            actual = dict(self.current['jobs'][name])
            actual.pop('if', None)
            baseline = dict(original)
            baseline.pop('if', None)
            self.assertEqual(actual, baseline, name)

    def test_event_trigger_definitions_unchanged_except_new_dispatch_input(self):
        import copy
        actual = copy.deepcopy(self.current['on'])
        declared = actual['workflow_dispatch']['inputs'].pop('host-diagnostics')
        self.assertEqual(declared['type'], 'boolean')
        self.assertEqual(declared['default'], 'false')
        self.assertEqual(actual, self.original['on'])

    def test_separate_non_cancelling_concurrency(self):
        concurrency = self.current['concurrency']
        self.assertIn('inputs.host-diagnostics == true', concurrency['group'])
        self.assertIn('host-diagnostics-', concurrency['group'])
        for event, flag, main in itertools.product(('workflow_dispatch', 'pull_request', 'push', 'merge_group'), (True, False), (True, False)):
            context = self.context(event, flag, True, main=main)
            actual = expression(concurrency['cancel-in-progress'], context)
            expected = False if event == 'workflow_dispatch' and flag else not main
            self.assertEqual(actual, expected)

    def test_native_diagnostics_remain_full_root_suite_with_failure_artifacts(self):
        job = self.current['jobs'].get('native-health-diagnostics')
        self.assertIsNotNone(job)
        self.assertEqual(job['runs-on'], 'ubuntu-24.04')
        self.assertEqual(job['needs'], 'quick-gate')
        steps = job['steps']
        script = next(step['run'] for step in steps if step.get('name') == 'Run full native health suite')
        self.assertIn('sudo -n timeout --kill-after=5s 120s python3 -m unittest discover -s scripts -p test_qemu_health.py -v', script)
        self.assertIn('exit "$status"', script)
        upload = next(step for step in steps if 'upload-artifact@' in step.get('uses', ''))
        self.assertEqual(upload['if'], 'always()')
        self.assertEqual(upload['with']['if-no-files-found'], 'error')
        text = yaml.dump(job)
        for forbidden in ('continue-on-error', 'sysctl', 'apt-get', 'systemctl enable', 'systemctl start', '/dev/kvm', 'qemu-system', 'secrets.'):
            self.assertNotIn(forbidden, text)

    def test_actual_step_shell_retains_capture_and_native_failures(self):
        job = self.current['jobs']['native-health-diagnostics']
        script = next(step['run'] for step in job['steps'] if step.get('name') == 'Run full native health suite')
        # Executable command fixtures prove shell failure handling only. They
        # produce no health receipt and cannot prove a supported host channel.
        for capture_exit, native_exit in ((0, 37), (3, 0)):
            with self.subTest(capture=capture_exit, native=native_exit), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                commands = root / 'bin'
                commands.mkdir()
                for name, code in (('python3', capture_exit), ('sudo', native_exit)):
                    command = commands / name
                    command.write_text(f'#!/bin/sh\nexit {code}\n')
                    command.chmod(0o700)
                evidence = root / 'evidence'
                env = dict(os.environ, PATH=str(commands) + os.pathsep + os.environ['PATH'],
                           HOST_DIAGNOSTICS=str(evidence), GITHUB_ENV=str(root / 'github-env'))
                result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', script], env=env,
                                        cwd=ROOT, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, native_exit or capture_exit, result.stderr)
                import json
                self.assertEqual(json.loads((evidence / 'outcome.json').read_text()),
                                 {'capture_exit': capture_exit, 'native_health_exit': native_exit})


if __name__ == '__main__':
    unittest.main(verbosity=2)
