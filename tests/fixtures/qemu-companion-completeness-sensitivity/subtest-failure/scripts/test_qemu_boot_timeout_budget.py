import json
import unittest


class ObservedRequiredCase(unittest.TestCase):
    def run(self, result=None):
        if result is None:
            result = self.defaultTestResult()
        fields = ("testsRun", "skipped", "failures", "errors", "expectedFailures", "unexpectedSuccesses")
        before = {name: getattr(result, name) if name == "testsRun" else len(getattr(result, name)) for name in fields}
        returned = super().run(result)
        delta = {name: (getattr(result, name) if name == "testsRun" else len(getattr(result, name))) - before[name] for name in fields}
        outcome = next((name for name in fields[1:] if delta[name]), "success")
        print("FIXTURE_OUTCOME " + json.dumps({"identity": self.id(), "outcome": outcome, "actual_result_delta": delta}), flush=True)
        return returned



class BootTimeoutExceedsReadinessWait(ObservedRequiredCase):
    def test_driver_derives_boot_timeout_from_the_wait_budget(self):
        print('FIXTURE_BODY_EXECUTED ' + self.id(), flush=True)
        with self.subTest(control='required-body'):
            self.assertEqual(2 + 2, 5)

    def test_driver_no_longer_hardcodes_a_short_boot_timeout(self):
        print('FIXTURE_BODY_EXECUTED ' + self.id(), flush=True)
        self.assertEqual(2 + 2, 4)

    def test_driver_boot_timeout_clears_the_inner_budget(self):
        print('FIXTURE_BODY_EXECUTED ' + self.id(), flush=True)
        self.assertEqual(2 + 2, 4)

    def test_clone_timeout_clears_the_inner_budget(self):
        print('FIXTURE_BODY_EXECUTED ' + self.id(), flush=True)
        self.assertEqual(2 + 2, 4)

    def test_wait_loop_still_has_the_documented_shape(self):
        print('FIXTURE_BODY_EXECUTED ' + self.id(), flush=True)
        self.assertEqual(2 + 2, 4)



class BootShellDeadlineTests(ObservedRequiredCase):
    def test_term_resistant_probe_keeps_readiness_diagnostics(self):
        print('FIXTURE_BODY_EXECUTED ' + self.id(), flush=True)
        self.assertEqual(2 + 2, 4)

    def test_reboot_expiry_keeps_old_identity_and_serial(self):
        print('FIXTURE_BODY_EXECUTED ' + self.id(), flush=True)
        self.assertEqual(2 + 2, 4)

    def test_term_resistant_intermediate_command_has_total_deadline(self):
        print('FIXTURE_BODY_EXECUTED ' + self.id(), flush=True)
        self.assertEqual(2 + 2, 4)

    def test_setup_dispatch_preserves_exact_argument_vector(self):
        print('FIXTURE_BODY_EXECUTED ' + self.id(), flush=True)
        self.assertEqual(2 + 2, 4)

    def test_setup_dispatch_stops_on_command_pipeline_and_nounset_failure(self):
        print('FIXTURE_BODY_EXECUTED ' + self.id(), flush=True)
        self.assertEqual(2 + 2, 4)

    def test_slow_successful_initial_and_clone_compositions(self):
        print('FIXTURE_BODY_EXECUTED ' + self.id(), flush=True)
        self.assertEqual(2 + 2, 4)


def load_tests(loader, tests, pattern):
    def identities(suite):
        for test in suite:
            if isinstance(test, unittest.TestSuite):
                yield from identities(test)
            else:
                yield test.id()
    print("FIXTURE_DISCOVERED " + json.dumps(list(identities(tests))), flush=True)
    return tests
