"""Real pinned-rustfmt reachability checks; no compilation or guest execution."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
ENTRY_FILES = (
    "tests/env-portable/src/lib.rs",
    "tests/mise-compat/src/lib.rs",
    "fuzz/fuzz_targets/parse_config.rs",
    "fuzz/fuzz_targets/ipc_messages.rs",
    "fuzz/fuzz_targets/package_names.rs",
)


class FormattingCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.source = Path(cls.temporary.name)
        for directory, children, files in os.walk(ROOT):
            children[:] = [name for name in children
                           if name not in (".git", "target", "node_modules", ".audit")]
            for name in files:
                if name.endswith((".rs", ".toml")) or name == "Makefile":
                    source = Path(directory) / name
                    destination = cls.source / source.relative_to(ROOT)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, destination)
        # Normalize the disposable baseline so pre-existing mechanical formatting
        # cannot masquerade as rejection of the planted fault.
        for manifest in ("Cargo.toml", "tests/env-portable/Cargo.toml",
                         "tests/mise-compat/Cargo.toml", "fuzz/Cargo.toml"):
            result = cls.run_command(
                ["cargo", "fmt", "--manifest-path", manifest, "--all"]
            )
            if result.returncode:
                raise RuntimeError(result.stdout)

    @classmethod
    def run_command(cls, command):
        return subprocess.run(command, cwd=cls.source, capture_output=True,
                              text=True, timeout=60, env=dict(os.environ, CARGO_NET_OFFLINE="true"))

    def test_formatted_positive_control_passes(self):
        result = self.run_command(["make", "fmt-check"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_gate_rejects_each_owned_standalone_entry_file(self):
        for name in ENTRY_FILES:
            with self.subTest(path=name):
                path = self.source / name
                original = path.read_bytes()
                try:
                    path.write_bytes(original + b"\nconst FORMAT_COVERAGE_PROBE :u8=0;\n")
                    old = self.run_command(["cargo", "fmt", "--all", "--", "--check"])
                    self.assertEqual(old.returncode, 0, old.stdout + old.stderr)
                    repaired = self.run_command(["make", "fmt-check"])
                    self.assertNotEqual(repaired.returncode, 0,
                                        f"formatting gate missed {name}")
                    self.assertIn(str(path), repaired.stdout)
                finally:
                    path.write_bytes(original)


if __name__ == "__main__":
    unittest.main()
