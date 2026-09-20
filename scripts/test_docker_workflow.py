"""Exercise the Docker workflow's failure gates without a Docker daemon."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest


WORKFLOW = Path(__file__).resolve().parents[1] / '.github/workflows/docker-e2e.yml'


def step(name):
    workflow = WORKFLOW.read_text(encoding='utf-8')
    return workflow.split('      - name: ' + name + '\n', 1)[1].split('\n      - name:', 1)[0]


class DockerProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bash = os.environ.get('OMG_TEST_BASH') or shutil.which('bash')
        if not cls.bash:
            raise RuntimeError('Docker workflow tests require Bash on PATH')
        block = step('Verify image provenance')
        cls.script = textwrap.dedent(re.search(r'        run: \|\n(.*)', block, re.S)[1])

    def provenance(self, image=None, inspected=None, revision=None, inspect_status=0):
        image_id = 'sha256:' + 'a' * 64
        commit = 'b' * 40
        # Substitute only the daemon boundary; execute the actual workflow gate.
        docker = '''docker() {
          test "$1 $2 $3" = 'image inspect --format' || return 90
          test "$5" = "$IMAGE_ID" || return 91
          test "$INSPECT_STATUS" = 0 || return "$INSPECT_STATUS"
          if test "$4" = '{{.Id}}'; then
            printf '%s\\n' "$INSPECTED_ID"
          else
            printf '%s\\n' "$INSPECTED_REVISION"
          fi
        }
        '''
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            evidence = directory / 'docker-e2e-evidence'
            evidence.mkdir()
            env = dict(os.environ, RUNNER_TEMP=directory.as_posix(), GITHUB_SHA=commit,
                       IMAGE_ID=image_id if image is None else image,
                       INSPECTED_ID=image_id if inspected is None else inspected,
                       INSPECTED_REVISION=commit if revision is None else revision,
                       INSPECT_STATUS=str(inspect_status))
            result = subprocess.run([self.bash, '--noprofile', '--norc', '-c', docker + self.script],
                                    env=env, text=True, capture_output=True)
            record = evidence / 'build.txt'
            return result, record.read_text() if record.exists() else ''

    def test_records_exact_built_image(self):
        result, record = self.provenance()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(record, 'image-id=sha256:' + 'a' * 64 + '\n')

    def test_rejects_mutable_empty_and_malformed_image_references(self):
        for image in ['', 'omg-arch-e2e:latest', 'sha256:abc', 'sha256:' + 'z' * 64]:
            with self.subTest(image=image):
                result, record = self.provenance(image=image)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(record, '')

    def test_rejects_wrong_image_content(self):
        result, record = self.provenance(inspected='sha256:' + 'c' * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(record, '')

    def test_rejects_wrong_or_missing_revision(self):
        for revision in ['', 'c' * 40]:
            with self.subTest(revision=revision):
                result, record = self.provenance(revision=revision)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(record, '')

    def test_rejects_unavailable_image(self):
        result, record = self.provenance(inspect_status=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(record, '')

    def test_driver_compile_failure_is_fatal(self):
        compile_step = step('Compile std-only Docker test driver')
        command = re.search(r'^        run: (.*)$', compile_step, re.M)[1]
        fake_rustc = '''rustc() {
          test "$1 $2 $3 $4" = '--edition=2024 --test tests/docker_e2e.rs -o' || return 91
          test "$5" = "$RUNNER_TEMP/docker-e2e-tests" || return 92
          return 42
        }
        '''
        result = subprocess.run([self.bash, '--noprofile', '--norc', '-e', '-c', fake_rustc + command],
                                env=dict(os.environ, RUNNER_TEMP='/tmp'), text=True, capture_output=True)
        self.assertEqual(result.returncode, 42, result.stderr)

    def test_driver_failure_survives_log_pipeline(self):
        block = step('Run Docker E2E Tests')
        run = re.search(r'        run: \|\n((?:          [^\n]*\n)+)', block)[1]
        script = textwrap.dedent(run).replace('"$RUNNER_TEMP/docker-e2e-tests"', 'test_driver')
        fake_driver = '''test_driver() {
          test "$1 $2" = '--ignored --test-threads=1' || return 91
          printf 'test driver failed\\n'
          return 42
        }
        '''
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run([self.bash, '--noprofile', '--norc', '-c', fake_driver + script],
                                    cwd=tmp, env=dict(os.environ, RUNNER_TEMP='.'),
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 42, result.stderr)
            self.assertIn('test driver failed', (Path(tmp) / 'docker-e2e-evidence/tests.log').read_text())


if __name__ == '__main__':
    unittest.main()
