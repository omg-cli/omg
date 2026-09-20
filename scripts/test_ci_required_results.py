"""Execute the actual workflow final gate against required/skipped job states."""
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import tomllib
import unittest

from test_ci_gates import CI_YML, job_block
from test_native_contracts import NATIVE


class RequiredResultsTests(unittest.TestCase):
    def evaluate(self, required, overrides=None):
        block = job_block(CI_YML.read_text(encoding="utf-8"), "ci-success")
        script = textwrap.dedent(block.split("        run: |\n", 1)[1])
        with tempfile.TemporaryDirectory() as directory:
            env = dict(os.environ, QUICK_GATE="success", BUILD_REQUIRED=required,
                       PORTABLE="success", LINUX_MATRIX="success", SANDBOX_CANCELLATION="success",
                       FEATURE_INTERSECTIONS="success", MACOS="success", UBUNTU="success",
                       GITHUB_STEP_SUMMARY=str(Path(directory) / "summary"))
            env.update(overrides or {})
            bash = "C:/Program Files/Git/bin/bash.exe" if os.name == "nt" else "bash"
            return subprocess.run([bash, "-c", script], env=env, capture_output=True, text=True, timeout=15)

    def test_required_job_skips_fail(self):
        for job in ("PORTABLE", "LINUX_MATRIX", "SANDBOX_CANCELLATION", "FEATURE_INTERSECTIONS", "MACOS", "UBUNTU"):
            with self.subTest(job=job):
                self.assertNotEqual(self.evaluate("true", {job: "skipped"}).returncode, 0)

    def test_docs_only_skips_pass(self):
        jobs = ("PORTABLE", "LINUX_MATRIX", "SANDBOX_CANCELLATION", "FEATURE_INTERSECTIONS", "MACOS", "UBUNTU")
        self.assertEqual(self.evaluate("false", {job: "skipped" for job in jobs}).returncode, 0)

    def test_all_success_passes_and_failure_never_does(self):
        self.assertEqual(self.evaluate("true").returncode, 0)
        for required in ("true", "false"):
            for state in ("failure", "cancelled", ""):
                self.assertNotEqual(self.evaluate(required, {"PORTABLE": state}).returncode, 0)

    def test_binary_unit_targets_in_every_unit_lane(self):
        text = CI_YML.read_text(encoding="utf-8")
        for job in ("portable", "linux-matrix", "macos", "ubuntu"):
            self.assertIn("python3 scripts/run-native-contracts.py --features", job_block(text, job))
        for feature in ('pgp,license', 'arch,pgp,license', 'debian,pgp,license',
                        'fedora,pgp,license', 'macos,pgp,license'):
            args = NATIVE.cargo_test_args(feature)
            self.assertEqual(args[:2], ['--lib', '--bins'])
            self.assertEqual(args[args.index('--test') + 1], 'cli_surface')
            self.assertEqual(args[args.index('--features') + 1], feature)
            self.assertIn('--locked', args)
            self.assertIn('--no-default-features', args)
        self.assertEqual(NATIVE.cargo_test_args('debian-pure')[:2], ['--lib', '--bins'])

    def test_native_reports_keep_success_output_and_first_parser_failures(self):
        config = tomllib.loads((CI_YML.parents[2] / '.config/nextest.toml').read_text())
        junit = config['profile']['ci']['junit']
        self.assertEqual(junit['path'], 'junit.xml')
        self.assertTrue(junit['store-success-output'])
        self.assertTrue(junit['store-failure-output'])
        parser_rules = [rule for rule in config['profile']['default']['overrides']
                        if 'binary(=cli_surface)' in rule['filter']]
        self.assertEqual(len(parser_rules), 1)
        self.assertEqual(parser_rules[0]['retries'], 0)
        self.assertIn('socket_parser_preserves_literal_paths', parser_rules[0]['filter'])

    def test_sandbox_lane_requires_tools_and_security_cases(self):
        block = job_block(CI_YML.read_text(encoding="utf-8"), "sandbox-cancellation")
        for expected in ("bubblewrap fakeroot", "command -v bwrap", "command -v fakeroot",
                         'test "$(id -u)" = 0', "getent passwd nobody",
                         "bwrap_readonly_root_blocks_arbitrary_writes",
                         "sandbox_fakeroot_skips_unmappable_real_chown",
                         "invocation_ownership_setup_uses_only_private_directory_handles",
                         "makepkg_invocations_isolate_every_writable_cache",
                         "--include-ignored", "sandbox-evidence"):
            self.assertIn(expected, block)


if __name__ == "__main__":
    unittest.main()
