"""Behavioral checks for the WSL runner's private KVM device contract."""

import importlib.util
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


@unittest.skipUnless(os.name == "posix", "KVM device nodes require Linux")
class KvmDeviceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        script = Path(__file__).with_name("omg-kvm-device.py")
        spec = importlib.util.spec_from_file_location("omg_kvm_device", script)
        cls.device = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.device)

    def test_parent_rejects_symlink_and_group_writable_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = root / "parent"
            parent.mkdir()
            link = root / "link"
            link.symlink_to(parent, target_is_directory=True)
            with self.assertRaisesRegex(self.device.KvmDeviceError, "not a symlink"):
                self.device.private_parent(link, create=False)
            parent.chmod(0o777)
            with self.assertRaisesRegex(self.device.KvmDeviceError, "non-writable"):
                self.device.private_parent(parent, create=False)

    def test_alias_rejects_non_device_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            alias = Path(directory) / "kvm"
            alias.write_text("not a device", encoding="utf-8")
            with self.assertRaises(self.device.KvmDeviceError):
                self.device.character_device(alias)
            alias.unlink()
            alias.symlink_to("/dev/kvm")
            with self.assertRaises(self.device.KvmDeviceError):
                self.device.character_device(alias)

    def test_probe_requires_expected_major_minor_and_api(self):
        with self.assertRaisesRegex(self.device.KvmDeviceError, "major/minor"):
            self.device.probe(Path("/dev/null"), os.stat("/dev/zero").st_rdev)
        with self.assertRaisesRegex(self.device.KvmDeviceError, "unexpected KVM API"):
            with mock.patch.object(self.device.fcntl, "ioctl", return_value=11):
                self.device.probe(Path("/dev/null"))

    def test_setup_requires_root(self):
        with mock.patch.object(self.device.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(self.device.KvmDeviceError, "requires root"):
                self.device.setup_alias()

    @unittest.skipUnless(os.name == "posix" and os.geteuid() == 0,
                         "real device-node lifecycle needs root")
    def test_real_alias_is_idempotent_and_rejects_tampering(self):
        if not Path("/dev/kvm").exists():
            self.skipTest("KVM unavailable")
        with tempfile.TemporaryDirectory(dir="/var/lib") as directory:
            alias = Path(directory) / "kvm"
            Path(directory).chmod(0o755)
            group = "root"
            self.device.setup_alias(alias=alias, group=group)
            before = alias.lstat()
            self.assertTrue(stat.S_ISCHR(before.st_mode))
            self.assertEqual(stat.S_IMODE(before.st_mode), 0o660)
            self.device.setup_alias(alias=alias, group=group)
            self.assertEqual(alias.lstat().st_ino, before.st_ino)
            alias.chmod(0o666)
            with self.assertRaisesRegex(self.device.KvmDeviceError, "mode 0660"):
                self.device.setup_alias(alias=alias, group=group)
            alias.chmod(0o660)
            alias.unlink()
            os.mknod(alias, stat.S_IFCHR | 0o660, os.stat("/dev/null").st_rdev)
            alias.chmod(0o660)
            with self.assertRaisesRegex(self.device.KvmDeviceError, "major/minor"):
                self.device.setup_alias(alias=alias, group=group)
            alias.unlink()
            alias.symlink_to("/dev/kvm")
            with self.assertRaisesRegex(self.device.KvmDeviceError, "not a character device"):
                self.device.setup_alias(alias=alias, group=group)

    @unittest.skipUnless(os.name == "posix" and os.geteuid() == 0,
                         "real ACL inheritance needs root")
    def test_rejects_parent_default_acl_and_inherited_alias_acl(self):
        if not Path("/dev/kvm").exists():
            self.skipTest("KVM unavailable")
        if not shutil.which("setfacl"):
            self.skipTest("setfacl unavailable")
        with tempfile.TemporaryDirectory(dir="/var/lib") as directory:
            parent = Path(directory)
            parent.chmod(0o755)
            subprocess.run(["setfacl", "-m", "d:u:nobody:rw", directory], check=True)
            self.assertIn("system.posix_acl_default", os.listxattr(parent))
            with self.assertRaisesRegex(self.device.KvmDeviceError, "extended POSIX ACL"):
                self.device.setup_alias(alias=parent / "kvm", group="root")
            alias = parent / "kvm"
            os.mknod(alias, stat.S_IFCHR | 0o660, os.stat("/dev/kvm").st_rdev)
            alias.chmod(0o660)
            self.assertIn("system.posix_acl_access", os.listxattr(alias))
            subprocess.run(["setfacl", "-k", directory], check=True)
            with self.assertRaisesRegex(self.device.KvmDeviceError, "extended POSIX ACL"):
                self.device.verify_alias(alias=alias, group="root")


if __name__ == "__main__":
    unittest.main()
