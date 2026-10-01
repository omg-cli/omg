"""Oracle boundary tests with a mock compiler; real toolchain proof is separate."""
import importlib.util
import json
import os
import shlex
from pathlib import Path
import pwd
import subprocess
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
ORACLE = HERE / "qemu-rust-install-oracle.py"
spec = importlib.util.spec_from_file_location("rust_install_oracle", ORACLE)
SUBJECT = importlib.util.module_from_spec(spec)
spec.loader.exec_module(SUBJECT)
RUNNER_SPEC = importlib.util.spec_from_file_location("rust_row_runner", HERE / "test_qemu_output_contracts.py")
RUNNER = importlib.util.module_from_spec(RUNNER_SPEC)
RUNNER_SPEC.loader.exec_module(RUNNER)


class RustOracleBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        parent = Path(self.temporary.name).resolve()
        parent.chmod(0o755)
        self.root = parent / "row"
        self.root.mkdir()
        self.user = pwd.getpwnam("nobody") if os.geteuid() == 0 else None
        if self.user:
            os.chown(self.root, self.user.pw_uid, self.user.pw_gid)
        result = self.call("prepare")
        self.assertEqual(result.returncode, 0, result.stderr)
        host = SUBJECT.HOSTS[SUBJECT.platform.machine()]
        self.base = self.root / "runtime-data/versions/rust"
        self.installed = self.base / f"{SUBJECT.PIN}-{host}"
        (self.installed / "bin").mkdir(parents=True)
        (self.base / "current").symlink_to(self.installed.name)
        self.metadata = self.installed / ".omg-toolchain.toml"
        self.metadata.write_text('release = ' + json.dumps(SUBJECT.RELEASE) + '\ncomponents = '
                                 + json.dumps(sorted(SUBJECT.COMPONENTS)) + '\ntargets = []\n')
        self.compiler = self.installed / "bin/rustc"
        self.compiler.write_text("#!/bin/sh\nif [ \"$1\" = --version ]; then\n"
                                 + "  printf 'rustc " + SUBJECT.RELEASE + "\\n'\nelse\n"
                                 + "  printf \"#!/bin/sh\\nprintf 'OMG_RUST_RUNTIME_OK:42\\\\n'\\n\" > \"$3\"\n"
                                 + '  chmod 700 "$3"\nfi\n')
        self.compiler.chmod(0o700)
        self.own_fixture()

    def own_fixture(self):
        if self.user:
            for parent, directories, files in os.walk(self.root):
                for name in (parent, *(str(Path(parent) / n) for n in directories + files)):
                    os.chown(name, self.user.pw_uid, self.user.pw_gid, follow_symlinks=False)

    def call(self, operation):
        prefix = ["runuser", "-u", self.user.pw_name, "--"] if self.user else []
        return subprocess.run(prefix + ["python3", str(ORACLE), operation, str(self.root)],
                              capture_output=True, text=True, timeout=15)

    def rejects(self, message):
        result = self.call("check")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(message, result.stderr)
        self.assertFalse((self.root / "rust-install-proof.json").exists())

    def rerun_row_body_unprivileged(self):
        if not self.user:
            print(f"Rust executor fixture UID={os.geteuid()} sourceSHA256={SUBJECT.sha(ORACLE)}")
            return False
        source_hash = SUBJECT.sha(Path(__file__))
        test_name = f"scripts.{Path(__file__).stem}.{type(self).__qualname__}.{self._testMethodName}"
        command = ["runuser", "-u", self.user.pw_name, "--", "python3", "-m", "unittest", test_name, "-v"]
        result = subprocess.run(command, cwd=HERE.parent,
                                env=dict(os.environ, TMPDIR="/var/tmp", PYTHONDONTWRITEBYTECODE="1"),
                                capture_output=True, text=True, timeout=40)
        print(result.stdout, end="")
        print(result.stderr, end="")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Ran 1 test", result.stderr)
        self.assertIn("\nOK\n", result.stderr)
        self.assertNotIn("skipped=", result.stderr)
        self.assertEqual(SUBJECT.sha(Path(__file__)), source_hash)
        return True

    def rust_row(self, pin="1.85.0", case="runtime-rust-install"):
        return f'{case}\t["use","rust","{pin}"]\tisolated-write\t0\tpass\t-\tcontainer\tarch:pass,debian:pass,ubuntu:pass,fedora:pass\truntime-rust-installed\ttempdir-drop'

    def test_mock_compiler_boundary_emits_typed_identity_and_sibling_proof(self):
        result = self.call("check")
        self.assertEqual(result.returncode, 0, result.stderr)
        proof = json.loads(result.stdout)
        self.assertEqual(proof["pin"], "1.85.0")
        self.assertNotEqual(proof["uid"], 0)
        self.assertEqual(proof["release"], SUBJECT.RELEASE)
        self.assertEqual(proof["components"], sorted(SUBJECT.COMPONENTS))
        self.assertEqual(proof["programOutput"], "OMG_RUST_RUNTIME_OK:42\n")
        self.assertEqual(proof["otherRuntimeOutput"], "OMG_OTHER_RUNTIME_OK\n")
        self.assertEqual(json.loads((self.root / "rust-install-proof.json").read_text()), proof)

    def test_wrong_compiler_version_cannot_satisfy_installation(self):
        self.compiler.write_text(self.compiler.read_text().replace(SUBJECT.RELEASE, "1.84.0"))
        self.rejects("compiler identity differs")

    def test_external_current_link_cannot_select_a_host_toolchain(self):
        current = self.base / "current"
        current.unlink()
        current.symlink_to(self.root / "runtime-home")
        self.rejects("current does not resolve inside")

    def test_compiler_symlink_cannot_substitute_a_host_executable(self):
        self.compiler.unlink()
        self.compiler.symlink_to("/bin/true")
        self.rejects("compiler is not confined")

    def test_missing_default_component_cannot_satisfy_installation(self):
        self.metadata.write_text(self.metadata.read_text().replace(', "rust-docs"', ""))
        self.rejects("default components differ")

    def test_manifest_release_mismatch_cannot_satisfy_installation(self):
        self.metadata.write_text(self.metadata.read_text().replace(SUBJECT.RELEASE, "1.84.0"))
        self.rejects("release or default components differ")

    def test_failed_compilation_cannot_emit_positive_proof(self):
        self.compiler.write_text(self.compiler.read_text().replace('  chmod 700 "$3"', "  exit 19"))
        self.rejects("exit status 19")

    def test_failed_program_cannot_emit_positive_proof(self):
        self.compiler.write_text(self.compiler.read_text().replace("OMG_RUST_RUNTIME_OK:42", "WRONG_RESULT"))
        self.rejects("program did not execute")

    def test_changed_other_runtime_cannot_be_hidden_by_valid_compiler(self):
        (self.root / "runtime-data/versions/other-guard/1.0.0/bin/guard").write_bytes(b"changed")
        self.rejects("other runtime executable changed")

    def test_permissive_data_directory_cannot_satisfy_private_state(self):
        (self.root / "runtime-data").chmod(0o755)
        self.rejects("directory is not private")

    def test_incomplete_installation_cannot_satisfy_publication(self):
        (self.installed / ".omg-installing").touch()
        self.own_fixture()
        self.rejects("incomplete marker")

    def test_root_invocation_is_refused_before_fixture_preparation(self):
        with mock.patch.object(SUBJECT.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(AssertionError, "requires an unprivileged user"):
                SUBJECT.prepare(self.root)

    def test_missing_native_linker_is_a_fixture_failure(self):
        with mock.patch.object(SUBJECT.os, "geteuid", return_value=self.root.stat().st_uid):
            with mock.patch.object(SUBJECT.shutil, "which", return_value=None):
                with self.assertRaisesRegex(AssertionError, "native C linker prerequisite is missing"):
                    SUBJECT.prepare(self.root)

    def test_native_linker_compile_failure_precedes_runtime_installation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake = subprocess.CompletedProcess(['cc', '--version'], 0, stdout='fixture cc\n', stderr='')
            with mock.patch.object(SUBJECT.os, "geteuid", return_value=1000), \
                    mock.patch.object(SUBJECT, "owned_directory"), \
                    mock.patch.object(SUBJECT, "run", side_effect=[(fake, 0), subprocess.CalledProcessError(19, ['cc'])]):
                with self.assertRaises(subprocess.CalledProcessError):
                    SUBJECT.prepare(root)
            self.assertFalse((root / "runtime-data").exists())
            self.assertFalse((root / "rust-before.json").exists())

    def test_native_linker_program_failure_precedes_runtime_installation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identity = subprocess.CompletedProcess(['cc', '--version'], 0, stdout='fixture cc\n', stderr='')
            compile_result = subprocess.CompletedProcess(['cc'], 0, stdout='', stderr='')
            execution = subprocess.CompletedProcess(['probe'], 0, stdout='WRONG\n', stderr='')
            with mock.patch.object(SUBJECT.os, "geteuid", return_value=1000), \
                    mock.patch.object(SUBJECT, "owned_directory"), \
                    mock.patch.object(SUBJECT, "run", side_effect=[(identity, 0), (compile_result, 0), (execution, 0)]):
                with self.assertRaisesRegex(AssertionError, 'native C linker probe did not execute'):
                    SUBJECT.prepare(root)
            self.assertFalse((root / "runtime-data").exists())
            self.assertFalse((root / "rust-before.json").exists())

    def test_actual_executor_rejects_false_success_without_installed_compiler(self):
        if self.rerun_row_body_unprivileged():
            return
        result, evidence, logs = RUNNER.OutputContracts().run_inventory(
            "printf 'Installed Rust 1.85.0\\n'\n", [self.rust_row()], tiers="container")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual([row["result"] for row in evidence], ["FAIL"])
        self.assertIn("assertion failed: native Rust installation", logs["runtime-rust-install.log"])

    def test_actual_executor_rejects_unreviewed_pin_before_running_product(self):
        if self.rerun_row_body_unprivileged():
            return
        result, evidence, _ = RUNNER.OutputContracts().run_inventory(
            "printf 'PRODUCT_MUST_NOT_RUN'\n", [self.rust_row(pin="1.84.0")], tiers="container")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(evidence, [])
        self.assertNotIn("PRODUCT_MUST_NOT_RUN", result.stdout)

    def test_actual_executor_rejects_install_assertion_on_another_case(self):
        if self.rerun_row_body_unprivileged():
            return
        result, evidence, _ = RUNNER.OutputContracts().run_inventory(
            "printf 'PRODUCT_MUST_NOT_RUN'\n", [self.rust_row(case="unreviewed-rust-row")], tiers="container")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(evidence, [])
        self.assertNotIn("PRODUCT_MUST_NOT_RUN", result.stdout)


class RustGuestPrerequisiteTests(unittest.TestCase):
    def run_setup(self, distro, installer_exit=0):
        driver = (HERE / "benchmark-qemu.sh").read_text()
        marker = '# Inventory fixtures need these tools; missing tools are setup failures,'
        setup = driver.split(marker, 1)[1]
        setup = setup[setup.index('  case "$distro" in'):]
        end = '  esac > evidence/inventory-setup.txt 2>&1 || exit 120'
        setup = setup[:setup.index(end) + len(end)]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "evidence").mkdir()
            recorder = root / "sudo"
            recorder.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$SETUP_ARGUMENTS"\nexit "$SETUP_EXIT"\n')
            recorder.chmod(0o700)
            environment = dict(os.environ, PATH=f"{root}:/usr/bin:/bin",
                               SETUP_ARGUMENTS=str(root / "arguments"), SETUP_EXIT=str(installer_exit))
            result = subprocess.run(['bash', '-c', 'set -euo pipefail\ndistro='
                                     + shlex.quote(distro) + '\n' + setup], cwd=root, env=environment,
                                    capture_output=True, text=True, timeout=5)
            return result, (root / "arguments").read_text().splitlines()

    def test_guest_setup_supplies_linker_and_native_headers_for_each_distro(self):
        for distro in ('arch', 'debian', 'ubuntu', 'fedora'):
            with self.subTest(distro=distro):
                result, arguments = self.run_setup(distro)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('gcc', arguments)
                if distro in ('debian', 'ubuntu'):
                    self.assertIn('libc6-dev', arguments)
                if distro == 'fedora':
                    self.assertIn('glibc-devel', arguments)
                self.assertNotIn('rustc', arguments)
                self.assertNotIn('cargo', arguments)

    def test_failed_guest_prerequisite_installation_is_a_setup_failure(self):
        for distro in ('arch', 'debian', 'ubuntu', 'fedora'):
            with self.subTest(distro=distro):
                result, _ = self.run_setup(distro, installer_exit=42)
                self.assertEqual(result.returncode, 120, result.stderr)


if __name__ == "__main__":
    unittest.main()
