from contextlib import redirect_stdout
import importlib.util
import io
from pathlib import Path
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("check-qemu-runner-isolation.py")
SPEC = importlib.util.spec_from_file_location("check_qemu_runner_isolation", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RunnerIsolationTests(unittest.TestCase):
    def test_rejects_wsl_drvfs_even_when_automount_is_disabled(self):
        mounts = "C: /mnt/c 9p rw,relatime,aname=drvfs;path=C:,access=client 0 0\n"
        self.assertEqual(MODULE.windows_drive_mounts(mounts), ["/mnt/c"])

    def test_guard_fails_closed_on_visible_drive(self):
        mounts = "C: /mnt/c 9p rw,aname=drvfs;path=C: 0 0\n"
        output = io.StringIO()
        with mock.patch.object(MODULE.Path, "read_text", return_value=mounts):
            with redirect_stdout(output):
                self.assertEqual(MODULE.main(), 1)
        self.assertIn("::error::Windows DrvFs mount visible", output.getvalue())

    def test_rejects_native_drvfs_and_bound_mounts(self):
        mounts = (
            "C: /windows drvfs rw 0 0\n"
            "C: /work/host 9p rw,aname=drvfs;path=C: 0 0\n"
        )
        self.assertEqual(
            MODULE.windows_drive_mounts(mounts), ["/windows", "/work/host"]
        )

    def test_allows_linux_and_non_drive_9p_mounts(self):
        mounts = (
            "/dev/sda / ext4 rw,relatime 0 0\n"
            "transport /mnt/share 9p rw,aname=vmshare 0 0\n"
        )
        self.assertEqual(MODULE.windows_drive_mounts(mounts), [])


if __name__ == "__main__":
    unittest.main()
