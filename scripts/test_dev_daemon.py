"""Exercise the real make recipe without signalling any existing daemon."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DevDaemonTests(unittest.TestCase):
    def setUp(self):
        scratch = os.environ.get("PAPERCLIP_RUN_SCRATCH_DIR") or os.environ.get("PAPERCLIP_SCRATCH_DIR")
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copy(ROOT / "Makefile", self.root)
        (self.root / "scripts").mkdir()
        helper = ROOT / "scripts/dev-daemon.py"
        if helper.exists():
            shutil.copy(helper, self.root / "scripts")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.env = os.environ.copy()
        self.env["PATH"] = str(self.bin) + os.pathsep + self.env["PATH"]
        self.env["PROBE_ROOT"] = str(self.root)
        self.write_command("pkill", '#!/bin/sh\necho mocked > "$PROBE_ROOT/pkill-called"\n')
        self.write_command("cargo", '''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
root = Path(os.environ["PROBE_ROOT"])
(root / "cargo-args").write_text(json.dumps(sys.argv[1:]))
print(json.dumps({"reason": "compiler-artifact", "target": {"name": "omgd", "kind": ["bin"]}, "executable": os.environ.get("PROBE_EXECUTABLE")}))
sys.exit(int(os.environ.get("PROBE_BUILD_EXIT", "0")))
''')

    def write_command(self, name, content):
        path = self.bin / name
        path.write_text(content)
        path.chmod(0o755)

    def daemon(self, path, content=None):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content or '#!/bin/sh\necho launched > "$PROBE_ROOT/launched"\nsleep 2\n')
        path.chmod(0o755)
        self.env["PROBE_EXECUTABLE"] = str(path)

    def run_dev(self):
        with (self.root / "receipt").open("w+") as log:
            result = subprocess.run(["make", "dev"], cwd=self.root, env=self.env,
                                    stdout=log, stderr=log, timeout=15)
            # Successful fixture processes expire on their own; never use pkill.
            time.sleep(2)
            log.seek(0)
            return result.returncode, log.read()

    def test_relative_target_directory(self):
        self.env["CARGO_TARGET_DIR"] = "relocated output"
        self.daemon(self.root / "relocated output/debug/omgd")
        code, output = self.run_dev()
        self.assertEqual(code, 0, output)
        self.assertTrue((self.root / "launched").exists(), output)

    def test_absolute_target_directory_and_configured_target_layout(self):
        self.env["CARGO_TARGET_DIR"] = str(self.root / "absolute output")
        self.daemon(self.root / "absolute output/host-triple/debug/omgd")
        code, output = self.run_dev()
        self.assertEqual(code, 0, output)
        self.assertTrue((self.root / "launched").exists(), output)

    def test_default_output(self):
        self.env.pop("CARGO_TARGET_DIR", None)
        self.daemon(self.root / "target/debug/omgd")
        code, output = self.run_dev()
        self.assertEqual(code, 0, output)
        self.assertTrue((self.root / "launched").exists(), output)

    def test_missing_executable_fails_before_signalling(self):
        self.env["PROBE_EXECUTABLE"] = str(self.root / "missing/omgd")
        code, output = self.run_dev()
        self.assertNotEqual(code, 0, output)
        self.assertIn("executable", output.lower())
        self.assertFalse((self.root / "pkill-called").exists())

    def test_missing_artifact_fails(self):
        code, output = self.run_dev()
        self.assertNotEqual(code, 0, output)
        self.assertIn("omgd", output)

    def test_immediate_exit_fails_even_with_zero_status(self):
        for status in (0, 7):
            with self.subTest(status=status):
                self.daemon(self.root / "target/debug/omgd", f"#!/bin/sh\nexit {status}\n")
                code, output = self.run_dev()
                self.assertNotEqual(code, 0, output)
                self.assertIn("exited", output.lower())

    def test_exec_error_fails(self):
        self.daemon(self.root / "target/debug/omgd", "#!/nonexistent-interpreter\n")
        code, output = self.run_dev()
        self.assertNotEqual(code, 0, output)
        self.assertIn("launch", output.lower())

    def test_non_executable_fails_before_signalling(self):
        self.daemon(self.root / "target/debug/omgd")
        Path(self.env["PROBE_EXECUTABLE"]).chmod(0o644)
        code, output = self.run_dev()
        self.assertNotEqual(code, 0, output)
        self.assertIn("not executable", output.lower())
        self.assertFalse((self.root / "pkill-called").exists())

    def test_delayed_start_failure(self):
        self.daemon(self.root / "target/debug/omgd", "#!/bin/sh\nsleep 0.2\nexit 9\n")
        code, output = self.run_dev()
        self.assertNotEqual(code, 0, output)
        self.assertIn("status 9", output)

    def test_real_cargo_build_and_launch(self):
        # A tiny real Rust binary tests Cargo's path contract and OS execution.
        # This is a launcher smoke test, not OMG IPC readiness or guest evidence.
        (self.bin / "cargo").unlink()
        (self.root / "src").mkdir()
        (self.root / "Cargo.toml").write_text(
            '[package]\nname = "omgd"\nversion = "0.0.0"\nedition = "2021"\n'
            '[features]\narch = []\n'
        )
        (self.root / "src/main.rs").write_text(
            'fn main() {\n'
            'std::fs::write(std::path::PathBuf::from(std::env::var("PROBE_ROOT").unwrap())'
            '.join("launched"), "real Rust process").unwrap();\n'
            'std::thread::sleep(std::time::Duration::from_secs(2));\n}\n'
        )
        self.env["CARGO_TARGET_DIR"] = str(self.root / "real cargo output")
        self.env["CARGO_BUILD_JOBS"] = "2"
        code, output = self.run_dev()
        self.assertEqual(code, 0, output)
        self.assertTrue((self.root / "launched").exists(), output)
        self.assertEqual((self.root / "launched").read_text(), "real Rust process")
        self.assertTrue((self.root / "real cargo output/debug/omgd").is_file())
        self.assertIn("readiness not checked", output)

    def test_build_failure_never_launches_or_signals(self):
        self.env["PROBE_BUILD_EXIT"] = "5"
        self.daemon(self.root / "target/debug/omgd")
        code, output = self.run_dev()
        self.assertNotEqual(code, 0, output)
        self.assertFalse((self.root / "launched").exists())
        self.assertFalse((self.root / "pkill-called").exists())


if __name__ == "__main__":
    unittest.main()
