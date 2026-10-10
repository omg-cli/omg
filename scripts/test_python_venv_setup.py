"""Exercise the real venv/pip prerequisites used by managed-tool regressions."""

import base64
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile


@unittest.skipUnless(os.name == "posix", "Native Linux CI uses POSIX venv console paths")
class PythonVenvSetupTests(unittest.TestCase):
    def test_venv_installs_and_runs_an_offline_console_entry_point(self):
        with tempfile.TemporaryDirectory(prefix="omg-python-setup-") as directory:
            root = Path(directory)
            environment = root / "environment with spaces"
            created = subprocess.run(
                [sys.executable, "-m", "venv", "--copies", str(environment)],
                capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(created.returncode, 0, created.stdout + created.stderr)

            entries = {
                "omg_setup_fixture.py": b'def main():\n    print("offline-venv-ready")\n',
                "omg_setup_fixture-0.0.1.dist-info/METADATA":
                    b"Metadata-Version: 2.1\nName: omg-setup-fixture\nVersion: 0.0.1\n",
                "omg_setup_fixture-0.0.1.dist-info/WHEEL":
                    b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
                "omg_setup_fixture-0.0.1.dist-info/entry_points.txt":
                    b"[console_scripts]\nomg-setup-fixture = omg_setup_fixture:main\n",
            }
            records = []
            for name, content in entries.items():
                digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
                records.append(f"{name},sha256={digest},{len(content)}")
            records.append("omg_setup_fixture-0.0.1.dist-info/RECORD,,")
            entries["omg_setup_fixture-0.0.1.dist-info/RECORD"] = ("\n".join(records) + "\n").encode()
            wheel = root / "omg_setup_fixture-0.0.1-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                for name, content in entries.items():
                    archive.writestr(name, content)

            installed = subprocess.run(
                [str(environment / "bin/python3"), "-m", "pip", "install",
                 "--disable-pip-version-check", "--no-index", "--no-deps", str(wheel)],
                capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
            executed = subprocess.run(
                [str(environment / "bin/omg-setup-fixture")],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(executed.returncode, 0, executed.stderr)
            self.assertEqual(executed.stdout, "offline-venv-ready\n")


if __name__ == "__main__":
    unittest.main()
