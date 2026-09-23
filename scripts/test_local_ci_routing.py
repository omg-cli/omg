"""Protect the one-job local runner pilot from accidental matrix routing."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"


class LocalCiRoutingTests(unittest.TestCase):
    def test_only_trusted_main_fedora_guest_can_use_local_runner(self) -> None:
        routes: list[tuple[str, str, str]] = []
        for workflow in sorted(WORKFLOWS.glob("*.yml")):
            job = ""
            for line in workflow.read_text(encoding="utf-8").splitlines():
                if re.fullmatch(r"  [\w-]+:", line):
                    job = line.strip()[:-1]
                if "vars.OMG_CI_LINUX_RUNNER" in line:
                    routes.append((workflow.name, job, line.strip()))

        self.assertEqual(len(routes), 1, routes)
        workflow, job, selector = routes[0]
        self.assertEqual((workflow, job), ("qemu-lane.yml", "guest"))
        for required in (
            "inputs.distro == 'fedora'",
            "github.ref == 'refs/heads/main'",
            "github.event_name == 'push'",
            "github.event_name == 'schedule'",
            "github.event_name == 'workflow_dispatch'",
            "vars.OMG_CI_LINUX_RUNNER || 'ubuntu-24.04'",
        ):
            with self.subTest(required=required):
                self.assertIn(required, selector)

        guide = (ROOT / "docs" / "local-ci-runner.md").read_text(encoding="utf-8")
        allowed = re.findall(
            r"^omg-cli/omg/\.github/workflows/([\w-]+\.yml)@refs/heads/main$",
            guide,
            flags=re.MULTILINE,
        )
        self.assertEqual(allowed, ["qemu-lane.yml"])


if __name__ == "__main__":
    unittest.main()
