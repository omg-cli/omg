"""Run production Make recipes with mocked Cargo; no real fuzz campaign."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ("test-fuzz", "test-fuzz-quick", "test-security")


class FuzzArtifactRecipes(unittest.TestCase):
    def run_recipe(self, target, state, fail_call=0):
        with tempfile.TemporaryDirectory(dir=os.environ.get("PAPERCLIP_RUN_SCRATCH_DIR")) as directory:
            root = Path(directory)
            shutil.copyfile(ROOT / "Makefile", root / "Makefile")
            binaries = root / "bin"
            binaries.mkdir()
            cargo = binaries / "cargo"
            cargo.write_text("#!/bin/sh\n"
                             'printf "%s\\n" "$*" >> "$CALL_LOG"\n'
                             'count=$(wc -l < "$CALL_LOG")\n'
                             'if [ "$count" -eq "$FAIL_CALL" ]; then exit 42; fi\n')
            if not os.access(cargo, os.X_OK):
                cargo.chmod(0o755)
            fuzz = binaries / "cargo-fuzz"
            fuzz.write_text("#!/bin/sh\nexit 0\n")
            if not os.access(fuzz, os.X_OK):
                fuzz.chmod(0o755)
            artifacts = root / "fuzz/artifacts"
            if state != "absent":
                artifacts.mkdir(parents=True)
            if state in ("nested-empty", "crash", "zero-byte"):
                (artifacts / "ipc_messages").mkdir()
            crash = artifacts / "ipc_messages/crash-historical"
            payload = b"historical crash input" if state == "crash" else b""
            if state in ("crash", "zero-byte"):
                crash.write_bytes(payload)
            log = root / "calls"
            result = subprocess.run(
                ["make", "--silent", "--no-print-directory", target], cwd=root,
                env={**os.environ, "PATH": str(binaries) + os.pathsep + os.environ["PATH"],
                     "CALL_LOG": str(log), "FAIL_CALL": str(fail_call)},
                capture_output=True, text=True, timeout=20,
            )
            if state in ("crash", "zero-byte"):
                self.assertEqual(crash.read_bytes(), payload, "historical evidence changed")
            calls = log.read_text().splitlines()
            return result, calls

    def test_no_artifact_files_pass(self):
        for target in TARGETS:
            for state in ("absent", "empty", "nested-empty"):
                with self.subTest(target=target, state=state):
                    result, calls = self.run_recipe(target, state)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertNotIn("found", result.stdout)
                    self.assertEqual(len(calls), 3 if target == "test-security" else 2)

    def test_historical_artifact_files_fail_and_are_preserved(self):
        for target in TARGETS:
            for state in ("crash", "zero-byte"):
                with self.subTest(target=target, state=state):
                    result, _ = self.run_recipe(target, state)
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertIn("found", result.stdout)

    def test_upstream_failures_stop_recipe(self):
        for target in TARGETS:
            for fail_call in range(1, 4 if target == "test-security" else 3):
                with self.subTest(target=target, fail_call=fail_call):
                    result, calls = self.run_recipe(target, "empty", fail_call)
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertIn("Error 42", result.stderr)
                    self.assertEqual(len(calls), fail_call)
                    self.assertNotIn("tests passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
