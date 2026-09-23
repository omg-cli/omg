"""Exercise bounded transport recovery without Docker or network access."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASH = 'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else 'bash'
IMAGE = 'debian:trixie@sha256:' + 'a' * 64
TCG_IMAGE = 'debian:sid@sha256:' + 'b' * 64


class ControllerPullTests(unittest.TestCase):
    def run_pull(self, failures=0, message='net/http: TLS handshake timeout', status=1, image=IMAGE):
        script = (ROOT / 'scripts/pull-qemu-controller.sh').read_text()
        mocks = r'''
fixture_attempt=0
timeout() {
    [[ "$1 $2 $3 $4 $5" == "--kill-after=5s 120s docker pull $EXPECTED_IMAGE" ]] || return 99
    fixture_attempt=$((fixture_attempt + 1))
    printf 'pull %s\n' "$fixture_attempt" >> "$CALLS"
    if ((fixture_attempt <= FAILURES)); then printf '%s\n' "$ERROR_MESSAGE"; return "$ERROR_STATUS"; fi
    printf 'pull succeeded\n'
}
sleep() { printf 'sleep %s\n' "$1" >> "$CALLS"; }
'''
        with tempfile.TemporaryDirectory() as directory:
            calls = Path(directory) / 'calls'
            result = subprocess.run([BASH, '-c', mocks + script, '_', image,
                                     str(Path(directory) / 'attempt.log')],
                env=dict(os.environ, EXPECTED_IMAGE=image, CALLS=str(calls),
                         FAILURES=str(failures), ERROR_MESSAGE=message, ERROR_STATUS=str(status)),
                capture_output=True, text=True, timeout=10)
            return result, calls.read_text().splitlines() if calls.exists() else []

    def test_success_does_not_retry(self):
        result, calls = self.run_pull()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, ['pull 1'])

    def test_digest_pinned_sid_controller_for_local_tcg(self):
        result, calls = self.run_pull(image=TCG_IMAGE)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, ['pull 1'])

    def test_transient_failure_recovers_with_bounded_backoff(self):
        for message in ('net/http: TLS handshake timeout', 'dial tcp: i/o timeout',
                        'net/http: request canceled while waiting for connection (Client.Timeout exceeded while awaiting headers)',
                        'connection reset by peer', 'unexpected EOF',
                        'received unexpected HTTP status: 503 Service Unavailable'):
            with self.subTest(message=message):
                result, calls = self.run_pull(2, message)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(calls, ['pull 1', 'sleep 2', 'pull 2', 'sleep 4', 'pull 3'])
                self.assertIn(message, result.stdout)

    def test_exhaustion_and_timeout_still_fail(self):
        for status in (1, 124):
            with self.subTest(status=status):
                result, calls = self.run_pull(5, status=status)
                self.assertEqual(result.returncode, status)
                self.assertEqual(calls, ['pull 1', 'sleep 2', 'pull 2', 'sleep 4', 'pull 3'])

    def test_permanent_failures_are_not_retried(self):
        for message in ('unauthorized: authentication required', 'manifest unknown',
                        'digest mismatch', 'no space left on device', 'unknown failure'):
            with self.subTest(message=message):
                result, calls = self.run_pull(5, message)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(calls, ['pull 1'])

    def test_unpinned_or_invalid_image_is_rejected_before_docker(self):
        for image in ('debian:trixie', 'debian:sid', IMAGE[:-1], TCG_IMAGE[:-1], IMAGE + ';false'):
            with self.subTest(image=image):
                result, calls = self.run_pull(image=image)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, [])

    def test_lifecycle_pulls_before_start_and_disables_implicit_pull(self):
        source = (ROOT / 'scripts/benchmark-qemu.sh').read_text()
        self.assertLess(source.index('"$here/pull-qemu-controller.sh"'), source.index('started=true'))
        self.assertIn('docker run --pull=never -d', source)
        # All PR changes reach CI; its documentation-only classifier cannot
        # exclude controller scripts from the dependent QEMU job.
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        self.assertIn('  pull_request:\n  merge_group:', workflow)
        self.assertIn('uses: ./.github/workflows/qemu-matrix.yml', workflow)


if __name__ == '__main__':
    unittest.main()
