"""Refuse source/run/artifact substitution before coverage comparison."""
import copy
import os
import sys
import subprocess
import tempfile
import importlib.util
from pathlib import Path
import unittest
import textwrap
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "base_coverage", Path(__file__).with_name("require-base-coverage.py"))
coverage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(coverage)
SHA = "a" * 40


class BaseCoverageTests(unittest.TestCase):
    def run_fixture(self):
        return {"id": 101, "head_sha": SHA, "event": "push", "head_branch": "main",
                "path": coverage.WORKFLOW, "workflow_id": 123,
                "repository": {"full_name": coverage.REPOSITORY},
                "status": "completed", "conclusion": "success"}

    def artifact_fixture(self):
        return {"id": 102, "name": "coverage-lcov", "expired": False,
                "workflow_run": {"id": 101, "head_sha": SHA}}

    def test_exact_base_is_acquired_after_multi_commit_push_into_shallow_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); origin = root / "origin"; origin.mkdir()
            def git(*args):
                return subprocess.check_output(["git", "-c", "maintenance.auto=false", "-c", "gc.auto=0", *args], stderr=subprocess.DEVNULL).decode().strip()
            git("-C", str(origin), "init")
            (origin / "source.rs").write_text("fn baseline() {}\n")
            git("-C", str(origin), "add", ".")
            git("-C", str(origin), "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-m", "base")
            base = git("-C", str(origin), "rev-parse", "HEAD")
            for index in range(3):
                (origin / "sequence.txt").write_text(str(index)); git("-C", str(origin), "add", ".")
                git("-C", str(origin), "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-m", str(index))
            shallow = root / "shallow"; git("clone", "--depth", "2", origin.as_uri(), str(shallow))
            self.assertNotEqual(subprocess.run(["git", "-C", str(shallow), "cat-file", "-e", base + "^{commit}"], capture_output=True).returncode, 0)
            acquire = getattr(coverage, "ensure_source_commit", None)
            self.assertIsNotNone(acquire, "Exact source acquisition must handle a pushed base outside depth2")
            acquire(shallow, base)
            self.assertEqual(git("-C", str(shallow), "show", base + ":source.rs"), "fn baseline() {}")

    def test_exact_base_run(self):
        coverage.validate_run(self.run_fixture(), SHA, "push", 123, base=True)

    def test_wrong_or_failed_base_is_refused(self):
        for key, value in [("head_sha", "b" * 40), ("event", "pull_request"),
                           ("head_branch", "feature"), ("path", "other.yml"),
                           ("workflow_id", 999), ("repository", {"full_name": "fork/omg"}),
                           ("status", "in_progress"), ("conclusion", "failure")]:
            run = self.run_fixture()
            run[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                coverage.validate_run(run, SHA, "push", 123, base=True)

    def test_current_run_can_be_in_progress_while_its_result_job_executes(self):
        run = self.run_fixture()
        run.update(event="pull_request", head_branch="feature", status="in_progress", conclusion=None)
        coverage.validate_run(run, SHA, "pull_request", 123)

    def test_regions_require_the_same_exact_run_and_commit(self):
        artifact = self.artifact_fixture()
        artifact["name"] = "coverage-regions"
        self.assertEqual(coverage.validate_artifact([artifact], 101, SHA, "coverage-regions"), artifact)
        with self.assertRaises(ValueError):
            coverage.validate_artifact([artifact], 101, "b" * 40, "coverage-regions")
        with self.assertRaises(ValueError):
            coverage.validate_artifact([artifact], 101, SHA)
        artifact["expired"] = True
        with self.assertRaises(ValueError):
            coverage.validate_artifact([artifact], 101, SHA, "coverage-regions")

    def test_exact_artifact(self):
        artifact = self.artifact_fixture()
        self.assertEqual(coverage.validate_artifact([artifact], 101, SHA), artifact)

    def test_missing_duplicate_expired_or_substituted_artifact_is_refused(self):
        artifact = self.artifact_fixture()
        bad = [[], [artifact, artifact]]
        for key, value in [("expired", True), ("expired", None), ("name", "wrong"),
                           ("workflow_run", {"id": 999, "head_sha": SHA}),
                           ("workflow_run", {"id": 101, "head_sha": "b" * 40})]:
            altered = copy.deepcopy(artifact)
            altered[key] = value
            bad.append([altered])
        for artifacts in bad:
            with self.subTest(artifacts=artifacts), self.assertRaises(ValueError):
                coverage.validate_artifact(artifacts, 101, SHA)

    def test_exact_event_commits(self):
        base, head = "a" * 40, "b" * 40
        self.assertEqual(coverage.identities("pull_request", {
            "pull_request": {"base": {"sha": base}, "head": {"sha": head}}}, "c" * 40),
            (base, head))
        self.assertEqual(coverage.identities("merge_group", {
            "merge_group": {"base_sha": base, "head_sha": head}}, head), (base, head))
        self.assertEqual(coverage.identities("push", {"before": base}, head), (base, head))

    def test_missing_invalid_or_initial_commit_is_refused(self):
        for value in (None, "", "0" * 40, "main", "a" * 39, "A" * 40):
            with self.subTest(value=value), self.assertRaises(ValueError):
                coverage.sha(value)
        with self.assertRaises(ValueError):
            coverage.identities("schedule", {}, SHA)


class GenuineNodeCoverageTests(unittest.TestCase):
    def test_actual_workflow_admits_only_one_executed_first_attempt(self):
        repository = Path(__file__).resolve().parent.parent
        workflow = (repository / '.github/workflows/coverage.yml').read_text()
        step = workflow.split('      - name: Cover genuine Node installation and activation\n', 1)[1]
        program = textwrap.dedent(step.split("python3 - <<'PY'\n", 1)[1].split('\n          PY', 1)[0])
        case = '<testcase classname="omg::e2e_runtime_management" name="test_use_node_with_version" time="0.1">{}</testcase>'
        for body, accepted in [
            (case.format(''), True),
            ('', False),
            (case.format('') * 2, False),
            (case.format('<skipped/>'), False),
            (case.format('<failure>install failed</failure>'), False),
            (case.format('<system-err>[omg-skip] network unavailable</system-err>'), False),
            (case.format('<flakyFailure time="0.1">first failure</flakyFailure>'), False),
        ]:
            with self.subTest(body=body), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'scripts').mkdir()
                for name in ('check-test-selection.py', 'check-contract-coverage.py'):
                    (root / 'scripts' / name).write_bytes((repository / 'scripts' / name).read_bytes())
                report = root / 'target/nextest/ci/junit.xml'
                report.parent.mkdir(parents=True)
                report.write_text('<testsuites><testsuite name="omg::e2e_runtime_management">' + body + '</testsuite></testsuites>')
                result = subprocess.run([sys.executable, '-I', '-c', program], cwd=root, capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, accepted, result.stderr)
                self.assertEqual((root / 'node-install-coverage.receipt.json').exists(), accepted)


class DownloadMemberBehaviorTests(unittest.TestCase):
    payload = b"SF:/fixture/src/shared.rs\nDA:1,1\nLF:1\nLH:1\nend_of_record\n"

    def download(self, destination, extra):
        real_run = subprocess.run
        fixture = Path(__file__).parent / "fixtures" / "coverage_gh.py"
        def transport(argv, **kwargs):
            if not argv or argv[0] != "gh":
                raise AssertionError("Undeclared transport command: " + repr(argv))
            return real_run([sys.executable, "-X", "utf8", "-I", "-B",
                             str(fixture), *argv[1:]], **kwargs)
        with patch.dict(os.environ, {"COVERAGE_GH_EXTRA": "1" if extra else "0"}):
            with patch.object(coverage.subprocess, "run", side_effect=transport):
                return coverage.download({"id": 101}, "a" * 40, destination)

    def test_download_refuses_unexpected_artifact_member(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "download"
            with self.assertRaisesRegex(
                    ValueError, "^Coverage artifact must contain one bounded lcov[.]info report$"):
                self.download(destination, extra=True)

    def test_download_returns_exact_single_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "download"
            artifact, report = self.download(destination, extra=False)
            self.assertEqual(artifact["id"], 102)
            self.assertEqual(report, destination / "lcov.info")
            self.assertEqual(report.read_bytes(), self.payload)

if __name__ == "__main__":
    unittest.main()
