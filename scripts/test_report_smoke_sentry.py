"""Exercise Sentry result admission without making a network request."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("report-smoke-sentry.sh")


class SentryResultAdmissionTests(unittest.TestCase):
    def run_report(self, case_id):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "curl").write_text("#!/bin/sh\ncat >/dev/null\nprintf 200\n")
            (root / "curl").chmod(0o755)
            config = root / "sentry.json"
            config.write_text(json.dumps({"dsn": "https://abc@fake.sentry.io/123"}))
            results = root / "results.json"
            results.write_text(json.dumps([dict(case_id=case_id, distro="matrix",
                                                result="HARNESS_ERROR", exit_code=1,
                                                elapsed_seconds=0)]))
            env = dict(os.environ, OMG_SMOKE_SENTRY_CONFIG=str(config),
                       OMG_SMOKE_ENVIRONMENT="qemu-matrix", OMG_SMOKE_RELEASE="unknown",
                       PATH=f"{root}{os.pathsep}{os.environ['PATH']}")
            return subprocess.run(["bash", str(SCRIPT), str(results)],
                                  env=env, capture_output=True, text=True, check=False)

    def test_matrix_workflow_failure_is_reportable(self):
        result = self.run_report("qemu-matrix-x86-workflow")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Sentry accepted event", result.stdout)

    def test_unrecognized_matrix_case_is_rejected(self):
        result = self.run_report("qemu-matrix-untrusted")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid result fields", result.stderr)


if __name__ == "__main__":
    unittest.main()
