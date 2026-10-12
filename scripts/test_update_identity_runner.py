"""Exercise APT update identities through the real inventory runner using fixtures.

No guest or native package transaction runs. OMG_AUDIT_SOURCE optionally selects
a frozen source snapshot; normal discovery uses this script's checkout.
"""
import json
import os
from pathlib import Path
import runpy
import shlex
import shutil
import unittest

SOURCE = Path(os.environ.get("OMG_AUDIT_SOURCE") or Path(__file__).resolve().parents[1])
Harness = runpy.run_path(str(SOURCE / "scripts/test_qemu_output_contracts.py"))["OutputContracts"]


class UpdateIdentityRunnerRegression(unittest.TestCase):
    # Reuse the real existing runner harness, not a reimplemented validator.
    run_inventory = Harness.run_inventory
    lanes = ("debian", "debian-trixie", "ubuntu")
    row = ('outdated-json\t["--json","outdated"]\tread\t0\tpass\t-\t'
           'hermetic\thermetic:pass\toutdated-json-native-count\ttempdir-drop')

    @classmethod
    def setUpClass(cls):
        if os.name == "nt":
            raise RuntimeError("Run under POSIX; a Windows skip is not proof")
        for command in ("bash", "jq", "timeout", "sha256sum", "python3"):
            if not shutil.which(command):
                raise RuntimeError(f"Required runner dependency missing: {command}")

    def check_rows(self, product_rows, native_rows, expected, native_output_override=None):
        native_output = "Listing...\n" + "".join(
            f"{name}/stable {new} amd64 [upgradable from: {old}]\n"
            for name, old, new in native_rows)
        if native_output_override is not None:
            native_output = native_output_override
        native = {"apt": ('[[ "$*" == "list --upgradable" ]] || exit 17\n'
                          'printf "%s" ' + shlex.quote(native_output) + '\n')}
        product = 'printf "%s\\n" ' + shlex.quote(json.dumps(product_rows)) + '\n'
        for distro in self.lanes:
            with self.subTest(distro=distro):
                result, evidence, logs = self.run_inventory(
                    product, [self.row], native_commands=native, distro=distro)
                self.assertEqual(result.returncode, 0 if expected == "PASS" else 1, logs)
                self.assertEqual(len(evidence), 1, logs)
                self.assertEqual(evidence[0]["case_id"], f"qemu-{distro}-outdated-json", logs)
                self.assertEqual(evidence[0]["result"], expected, logs)

    @staticmethod
    def item(name="c", old="1", new="2"):
        return {"name": name, "current_version": old, "new_version": new,
                "repo": "apt", "update_type": "unknown"}

    def test_native_parity_positive_control(self):
        self.check_rows([self.item()], [("c", "1", "2")], "PASS")

    def test_same_count_wrong_package_rejected(self):
        self.check_rows([self.item(name="wrong")], [("c", "1", "2")], "FAIL")

    def test_same_count_wrong_installed_version_rejected(self):
        self.check_rows([self.item(old="77")], [("c", "1", "2")], "FAIL")

    def test_same_count_wrong_selected_candidate_rejected(self):
        self.check_rows([self.item(new="88")], [("c", "1", "2")], "FAIL")

    def test_same_count_duplicate_replaces_other_package_rejected(self):
        self.check_rows([self.item(), self.item()],
                        [("c", "1", "2"), ("d", "3", "4")], "FAIL")

    def test_reordered_exact_rows_positive_control(self):
        self.check_rows([self.item("d", "3", "4"), self.item()],
                        [("c", "1", "2"), ("d", "3", "4")], "PASS")

    def test_epoch_and_revision_native_parity_positive_control(self):
        self.check_rows([self.item("c", "1:1.0-2", "1:1.0-3")],
                        [("c", "1:1.0-2", "1:1.0-3")], "PASS")

    def test_malformed_native_reference_is_blocked(self):
        # A successful native command with unreadable data cannot prove zero updates.
        self.check_rows([], [], "BLOCKED", native_output_override="Listing...\nmalformed-native-record\n")

    def test_empty_native_parity_positive_control(self):
        self.check_rows([], [], "PASS")


# Keep the bound method, but hide the imported TestCase from unittest discovery.
del Harness

if __name__ == "__main__":
    unittest.main(verbosity=2)
