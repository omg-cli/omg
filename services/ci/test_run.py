import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('plain_ci', Path(__file__).with_name('run.py'))
RUN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUN)


class NativeChecks(unittest.TestCase):
    def test_exact_selected_test_requires_successful_exit_and_one_real_execution(self):
        name = 'package_managers::debian_db::db::tests::parse_packages_file_sync_reads_valid_packages'
        passed = f'test {name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;'
        with patch.object(RUN, 'ORACLE', ROOT / 'scripts/build-comparison.py'):
            RUN.verify_selected_test(passed, name, 0)
            for text, code in [(passed, 101), ('test result: ok. 0 passed; 0 failed; 0 ignored;', 0),
                               (passed.replace(name, 'another::test'), 0)]:
                with self.subTest(code=code, text=text), self.assertRaises(ValueError):
                    RUN.verify_selected_test(text, name, code)

    def test_candidate_environment_has_no_controller_secrets_or_profile_overrides(self):
        environment = RUN.candidate_environment()
        self.assertEqual(environment['CARGO_BUILD_JOBS'], '4')
        self.assertEqual(environment['CARGO_INCREMENTAL'], '0')
        self.assertEqual(environment['CARGO_TARGET_DIR'], '/work/target')
        self.assertFalse(any(key.startswith('CARGO_PROFILE_') for key in environment))
        self.assertNotIn('OMG_TEST_MODE', environment)
        self.assertNotIn('CLOUDFLARE_API_TOKEN', environment)
        self.assertNotIn('AWS_SECRET_ACCESS_KEY', environment)


if __name__ == '__main__':
    unittest.main()
