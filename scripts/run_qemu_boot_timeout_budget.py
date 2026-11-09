"""Require the reviewed QEMU companion bodies through standard unittest."""
from collections import Counter
import json
import unittest


REQUIRED_IDENTITIES = (
    'test_qemu_boot_timeout_budget.BootTimeoutExceedsReadinessWait.test_driver_derives_boot_timeout_from_the_wait_budget',
    'test_qemu_boot_timeout_budget.BootTimeoutExceedsReadinessWait.test_driver_no_longer_hardcodes_a_short_boot_timeout',
    'test_qemu_boot_timeout_budget.BootTimeoutExceedsReadinessWait.test_driver_boot_timeout_clears_the_inner_budget',
    'test_qemu_boot_timeout_budget.BootTimeoutExceedsReadinessWait.test_clone_timeout_clears_the_inner_budget',
    'test_qemu_boot_timeout_budget.BootTimeoutExceedsReadinessWait.test_wait_loop_still_has_the_documented_shape',
    'test_qemu_boot_timeout_budget.BootShellDeadlineTests.test_term_resistant_probe_keeps_readiness_diagnostics',
    'test_qemu_boot_timeout_budget.BootShellDeadlineTests.test_reboot_expiry_keeps_old_identity_and_serial',
    'test_qemu_boot_timeout_budget.BootShellDeadlineTests.test_term_resistant_intermediate_command_has_total_deadline',
    'test_qemu_boot_timeout_budget.BootShellDeadlineTests.test_setup_dispatch_preserves_exact_argument_vector',
    'test_qemu_boot_timeout_budget.BootShellDeadlineTests.test_setup_dispatch_stops_on_command_pipeline_and_nounset_failure',
    'test_qemu_boot_timeout_budget.BootShellDeadlineTests.test_slow_successful_initial_and_clone_compositions',
)


class RequiredCompanionResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.required_starts = []
        self.required_successes = []
        self.required_adverse = []

    def startTest(self, test):
        super().startTest(test)
        self.required_starts.append(test.id())

    def addSuccess(self, test):
        super().addSuccess(test)
        self.required_successes.append(test.id())

    def addError(self, test, err):
        super().addError(test, err)
        self.required_adverse.append({'identity': test.id(), 'kind': 'error'})

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.required_adverse.append({'identity': test.id(), 'kind': 'failure'})

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.required_adverse.append({'identity': test.id(), 'kind': 'skip'})

    def addExpectedFailure(self, test, err):
        super().addExpectedFailure(test, err)
        self.required_adverse.append({'identity': test.id(), 'kind': 'expected-failure'})

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        self.required_adverse.append({'identity': test.id(), 'kind': 'unexpected-success'})

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            self.required_adverse.append({'identity': test.id(), 'kind': 'subtest'})

    def required_report(self):
        wanted = Counter(REQUIRED_IDENTITIES)
        return {
            'required': list(REQUIRED_IDENTITIES),
            'starts': self.required_starts,
            'successes': self.required_successes,
            'adverse': self.required_adverse,
            'complete': Counter(self.required_starts) == wanted
                        and Counter(self.required_successes) == wanted
                        and not self.required_adverse,
        }


class RequiredCompanionRunner(unittest.TextTestRunner):
    resultclass = RequiredCompanionResult

    def run(self, test):
        result = super().run(test)
        self.stream.writeln('REQUIRED_QEMU_COMPANION ' + json.dumps(result.required_report()))
        return result


def main():
    program = unittest.TestProgram(module=None, testRunner=RequiredCompanionRunner, exit=False)
    result = program.result
    return 0 if result.wasSuccessful() and result.required_report()['complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
