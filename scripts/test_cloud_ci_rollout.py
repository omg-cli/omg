"""Deployment completion must precede expensive CI admission."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("rollout_gate", Path(__file__).with_name("check-cloud-ci-rollout.py"))
GATE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(GATE)
DIGEST = "sha256:" + "a" * 64


def fixture():
    image = GATE.REGISTRY + DIGEST
    return (
        {"id": GATE.APPLICATION, "version": 9, "configuration": {"image": image},
         "health": {"errors": [], "instances": {"active": 0}}},
        [{"id": "settled", "status": "completed", "target_version": 9,
          "target_configuration": {"image": image},
          "steps": [{"status": "completed", "completed_at": "2026-10-21T09:30:42Z"}],
          "progress": {"updated_instances": 2, "total_instances": 2,
                       "version_distribution": {"target_version_percentage": 100,
                                                "target_version_instances": 2,
                                                "current_version_instances": 0}}}],
    )


class RolloutTests(unittest.TestCase):
    def test_settled_exact_target_admits_without_running_slots(self):
        app, rows = fixture()
        self.assertEqual(GATE.admit(app, rows, DIGEST), {
            "state": "ADMITTED", "applicationId": GATE.APPLICATION, "version": 9,
            "image": GATE.REGISTRY + DIGEST, "rolloutId": "settled",
            "completedAt": "2026-10-21T09:30:42Z",
        })

    def test_pending_mixed_wrong_and_incomplete_targets_hold(self):
        for change in [
            lambda a, r: a.update(id="codeloud"),
            lambda a, r: a.update(version=10),
            lambda a, r: a["configuration"].update(image=GATE.REGISTRY + "sha256:" + "b" * 64),
            lambda a, r: a["health"].update(errors=["not-ready"]),
            lambda a, r: r[0].update(status="running"),
            lambda a, r: r[0]["target_configuration"].update(image="other-image"),
            lambda a, r: r[0]["steps"][0].update(status="running"),
            lambda a, r: r[0].update(steps=[]),
            lambda a, r: r[0]["progress"]["version_distribution"].update(current_version_instances=1),
            lambda a, r: r[0]["progress"]["version_distribution"].update(target_version_percentage=50),
            lambda a, r: r[0]["progress"].update(updated_instances=1),
            lambda a, r: r.clear(),
            lambda a, r: r.append(copy.deepcopy(r[0])),
            lambda a, r: r.append({"id": "newer", "status": "running", "target_version": 10}),
        ]:
            app, rows = fixture()
            change(app, rows)
            with self.subTest(app=app, rows=rows), self.assertRaises(ValueError):
                GATE.admit(app, rows, DIGEST)

    def test_second_read_catches_deployment_that_supersedes_first_read(self):
        app, rows = fixture()
        newer = copy.deepcopy(app)
        newer["version"] = 10
        values = iter([app, rows, newer, rows])
        with self.assertRaises(ValueError):
            GATE.readiness(lambda path: next(values), DIGEST)

    def test_stable_readback_returns_the_same_admission(self):
        app, rows = fixture()
        values = iter([app, rows, copy.deepcopy(app), copy.deepcopy(rows)])
        self.assertEqual(GATE.readiness(lambda path: next(values), DIGEST), {
            "state": "ADMITTED", "applicationId": GATE.APPLICATION, "version": 9,
            "image": GATE.REGISTRY + DIGEST, "rolloutId": "settled",
            "completedAt": "2026-10-21T09:30:42Z",
        })


if __name__ == "__main__":
    unittest.main()
