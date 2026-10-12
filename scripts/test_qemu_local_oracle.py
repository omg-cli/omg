"""Join confined hook output, real Bash execution and the local guest oracle.

Source-only runs use the captured four-line hook contract from frozen CLI
SHA256 6f7e9fbd9c2ca3ac4c329f64f7d4a578ce8af67eedda519104050349f9831565.
Set OMG_TEST_LOCAL_ORACLE_CLI for a joined actual-CLI run; no case is skipped.
The legacy fixture is the exact one-line emitter at published v0.1.224
(f0d8cb5d8a95dbbc6cae50460178702ac0263ebb). Set
OMG_TEST_LEGACY_LOCAL_ORACLE_CLI to bind it to the actual released binary.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "local_oracle", Path(__file__).with_name("qemu-local-oracle.py")
)
ORACLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ORACLE)


class HookEnvironmentOracleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hook oracle's fixture ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = self.root / "data"
        self.original_cwd = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, self.original_cwd)
        environment = {
            "HOME": str(self.root / "home"),
            "OMG_DATA_DIR": str(self.data),
            "OMG_CONFIG_DIR": str(self.root / "config"),
            "OMG_CACHE_DIR": str(self.root / "cache"),
            "OMG_NATIVE_TEST_DATA_DIR": "1",
            "OMG_DISABLE_TELEMETRY": "1",
            "OMG_TELEMETRY": "0",
            "PATH": "/usr/bin:/bin",
            "NO_COLOR": "1",
        }
        self.environment = patch.dict(os.environ, environment)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        for name in ("OMG_TEST_MODE", "QEMU_MUST_NOT_AUTO_APPLY", "_OMG_PATH_PREFIX",
                     "_OMG_PATH_BASE", "_omg_base"):
            os.environ.pop(name, None)
        for name in ("Makefile", "project/README.md", "project/Makefile"):
            ORACLE.write(name, "preserve project fixture\n")
        ORACLE.prepare("hook-env")
        self.selected = str(self.data / "versions/node/24.21.0/bin")
        executable = os.environ.get("OMG_TEST_LOCAL_ORACLE_CLI")
        if executable:
            binary = Path(executable)
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            result = subprocess.run(
                [str(binary), "hook-env", "-s", "bash"],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
            self.output = result.stdout
            print("ACTUAL_CLI_HOOK_SHA256=" + digest)
        else:
            # Captured emitted operations, with only its private fixture path
            # rebound. This is input data, not a replacement shell evaluator.
            quoted = "'" + self.selected.replace("'", "'\\''") + "'"
            self.output = (
                "_OMG_PATH_ADDITIONS=(" + quoted + ")\n"
                "_omg_base=${_OMG_PATH_BASE-$PATH}\n"
                'export PATH="${_OMG_PATH_PREFIX:+${_OMG_PATH_PREFIX}:}"'
                + quoted + '"${_omg_base:+:${_omg_base}}"\n'
                "unset _omg_base\n"
            )
        quoted = "'" + self.selected.replace("'", "'\\''") + "'"
        self.legacy_output = 'export PATH=' + quoted + ':"${_OMG_PATH_BASE:-$PATH}"\n'
        legacy_executable = os.environ.get("OMG_TEST_LEGACY_LOCAL_ORACLE_CLI")
        if legacy_executable:
            binary = Path(legacy_executable)
            result = subprocess.run(
                [str(binary), "hook-env", "-s", "bash"],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
            self.assertEqual(result.stdout, self.legacy_output)
            self.legacy_output = result.stdout
            print("ACTUAL_LEGACY_CLI_HOOK_SHA256="
                  + hashlib.sha256(binary.read_bytes()).hexdigest())

    def check(self, output=None):
        output = self.output if output is None else output
        ORACLE.write("command.stdout.log", output)
        ORACLE.check("hook-env", 0, output, "")

    def roundtrip(self, base, prefix=""):
        environment = dict(os.environ, PATH="/usr/bin:/bin", _OMG_PATH_PREFIX=prefix)
        if base is None:
            environment.pop("_OMG_PATH_BASE", None)
        else:
            environment["_OMG_PATH_BASE"] = base
        ORACLE.write("command.stdout.log", self.output)
        return subprocess.run(
            ["/bin/bash", "-c",
             'source "$1"; printf "%s\\n%s\\n%s\\n%s" "$PATH" '
             '"${QEMU_MUST_NOT_AUTO_APPLY-unset}" "${_omg_base-unset}" '
             '"${_OMG_PATH_ADDITIONS[*]}"', "_", "command.stdout.log"],
            env=environment, capture_output=True, text=True, timeout=5,
        )

    def test_current_hook_and_real_path_roundtrips_reach_full_oracle(self):
        for base, prefix in (("/usr/bin:/bin", ""), (None, ""), ("", ""),
                             ("/usr/bin:/bin", "/private/prefix"),
                             ("", "/private/prefix")):
            with self.subTest(base=base, prefix=prefix):
                result = self.roundtrip(base, prefix)
                path = ":".join(part for part in (
                    prefix, self.selected, "/usr/bin:/bin" if base is None else base
                ) if part)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, path + "\nunset\nunset\n" + self.selected)
                self.check()

    def test_unexpected_shell_operation_is_refused_before_execution(self):
        marker = self.root / "unexpected-operation"
        for family, output in (("current", self.output), ("published", self.legacy_output)):
            with self.subTest(family=family):
                with self.assertRaisesRegex(ValueError, "unexpected shell operations"):
                    self.check(output + "printf executed > unexpected-operation\n")
                self.assertFalse(marker.exists(), "oracle executed an unapproved operation")

    def test_project_environment_operation_is_refused_before_execution(self):
        marker = self.root / "project-env-operation"
        for family, output in (("current", self.output), ("published", self.legacy_output)):
            with self.subTest(family=family):
                with self.assertRaisesRegex(ValueError, "unexpected shell operations"):
                    self.check(output + "export QEMU_MUST_NOT_AUTO_APPLY=unsafe\n"
                               "printf executed > project-env-operation\n")
                self.assertFalse(marker.exists(), "oracle executed an unapproved project operation")

    def test_published_one_line_output_preserves_normal_base_and_reaches_full_oracle(self):
        for base in ("/usr/bin:/bin", None):
            with self.subTest(base=base):
                environment = dict(os.environ, PATH="/usr/bin:/bin")
                environment.pop("_OMG_PATH_BASE", None)
                if base is not None:
                    environment["_OMG_PATH_BASE"] = base
                result = subprocess.run(
                    ["/bin/bash", "-c", self.legacy_output
                     + '\nprintf "%s\\n%s" "$PATH" "${QEMU_MUST_NOT_AUTO_APPLY-unset}"'],
                    env=environment, capture_output=True, text=True, timeout=5,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, self.selected + ":/usr/bin:/bin\nunset")
                self.check(self.legacy_output)

    def test_other_runtime_path_is_not_admitted(self):
        with self.assertRaises(ValueError):
            self.check(self.output.replace("node/24.21.0", "node/22.16.0"))

    def test_modified_runtime_storage_is_refused(self):
        ORACLE.write(self.data / "versions/node/24.21.0/bin/node", "modified\n")
        with self.assertRaisesRegex(ValueError, "modified unrelated or read-only fixture"):
            self.check()

    def test_modified_active_runtime_link_is_refused(self):
        current = self.data / "versions/node/current"
        current.unlink()
        current.symlink_to("22.16.0", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "modified active links"):
            self.check()


if __name__ == "__main__":
    unittest.main()
