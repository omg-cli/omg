import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "qemu_crash_provision", Path(__file__).with_name("provision-qemu-crash-channel.py"))
PROVISION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROVISION)
PATTERN = "|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h"


class ProvisionTests(unittest.TestCase):
    def test_vendor_settings_select_only_supported_crash_fields(self):
        self.assertEqual(PROVISION.vendor_settings(
            f"# vendor\nfs.suid_dumpable=2\nkernel.core_pattern = {PATTERN}\n"
            "kernel.core_pipe_limit=16\n"), (PATTERN, "16", "/usr/lib/systemd/systemd-coredump"))

    def test_invalid_vendor_settings_refused(self):
        for text in (
            "kernel.core_pattern=core\nkernel.core_pipe_limit=16",
            f"kernel.core_pattern={PATTERN}\nkernel.core_pipe_limit=0",
            f"kernel.core_pattern={PATTERN}\nkernel.core_pipe_limit=65",
            f"kernel.core_pattern={PATTERN}\nkernel.core_pattern={PATTERN}\nkernel.core_pipe_limit=16",
            f"kernel.core_pattern={PATTERN}\nkernel.core_pipe_limit=16\nkernel.core_pipe_limit=16",
            f"kernel.core_pattern={PATTERN.replace('%c', '42')}\nkernel.core_pipe_limit=16",
        ):
            with self.subTest(text=text), self.assertRaises(ValueError):
                PROVISION.vendor_settings(text)

    def test_debian_vendor_literal_preserves_exact_handler_abi(self):
        pattern = PATTERN.replace("/usr/lib/", "/lib/").replace("%c", "9223372036854775808") + " %d"
        self.assertEqual(PROVISION.vendor_settings(
            f"kernel.core_pattern={pattern}\nkernel.core_pipe_limit=16"),
            (pattern, "16", "/lib/systemd/systemd-coredump"))

    def test_non_guest_refused_before_any_write(self):
        with patch.object(PROVISION.os, "geteuid", return_value=0, create=True), \
                patch.object(PROVISION.HEALTH, "query", return_value="wsl\n") as query:
            with self.assertRaisesRegex(ValueError, "QEMU/KVM guest"):
                PROVISION.provision()
            query.assert_called_once_with(["systemd-detect-virt", "--vm"])

    def test_unprivileged_refused_before_any_command(self):
        with patch.object(PROVISION.os, "geteuid", return_value=1000, create=True), \
                patch.object(PROVISION.HEALTH, "query") as query:
            with self.assertRaisesRegex(ValueError, "guest root"):
                PROVISION.provision()
            query.assert_not_called()


if __name__ == "__main__":
    unittest.main()
