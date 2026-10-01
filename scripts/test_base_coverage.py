"""Refuse source/run/artifact substitution before coverage comparison."""
import copy
import importlib.util
from pathlib import Path
import unittest

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


if __name__ == "__main__":
    unittest.main()
