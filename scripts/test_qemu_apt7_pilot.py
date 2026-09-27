"""Contracts for the dispatch-only APT 7 guest pilot."""
from datetime import date
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests/qemu-image-provenance/apt7-manifest.json"
MATERIAL = MANIFEST.parent
PILOT = (ROOT / ".github/workflows/qemu-apt7.yml").read_text()
LANE = (ROOT / ".github/workflows/qemu-lane.yml").read_text()
MATRIX = (ROOT / ".github/workflows/qemu-matrix.yml").read_text()


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


IMAGE = module("qemu_image", "scripts/verify-qemu-image.py")
POLICY = module("qemu_inventory", "scripts/check-qemu-inventory.py")
EXPORT = module("qemu_evidence", "scripts/export-qemu-evidence.py")


class Apt7PilotTests(unittest.TestCase):
    def test_one_archive_fans_out_to_distinct_manual_guests(self):
        self.assertIn("on:\n  workflow_dispatch:", PILOT)
        self.assertIn('guests=\'["debian13","ubuntu2604"]\'', PILOT)
        self.assertEqual(PILOT.count("name: staged-debian-trixie"), 1)
        self.assertIn("archive-distro: debian-trixie", PILOT)
        self.assertIn("shared-staged: true", PILOT)
        self.assertIn("name: qemu-evidence-${{ inputs.distro }}", LANE)
        self.assertIn("if: always()", PILOT)
        self.assertIn('"$GUEST" == success', PILOT)
        self.assertIn('distros=\'["arch","debian","ubuntu","fedora"]\'', MATRIX)
        self.assertNotIn("debian13", MATRIX)
        self.assertNotIn("ubuntu2604", MATRIX)

    def test_new_image_pins_match_publisher_material(self):
        data = json.loads(MANIFEST.read_text())
        debian = data["images"]["debian13-x86_64"]
        ubuntu = data["images"]["ubuntu2604-x86_64"]
        for identity, entry in (("debian13-x86_64", debian), ("ubuntu2604-x86_64", ubuntu)):
            self.assertEqual(IMAGE.policy(MANIFEST, identity, entry["url"], entry["digest"],
                                          date(2026, 9, 27)), entry)
        self.assertEqual(len(debian["digest"]), 128)
        signed_checksums = (MATERIAL / "ubuntu-2604-checksums").read_text()
        self.assertEqual(sum(line.startswith(ubuntu["digest"] + " *ubuntu-26.04-server-cloudimg-amd64.img")
                             for line in signed_checksums.splitlines()), 1)
        gpgv = shutil.which("gpgv")
        if not gpgv and Path("C:/Program Files/Git/usr/bin/gpgv.exe").is_file():
            gpgv = "C:/Program Files/Git/usr/bin/gpgv.exe"
        if gpgv:
            self.assertTrue(IMAGE.verify_signature(ubuntu, MATERIAL, Path("unused"), gpgv)["signature_verified"])

    def test_benchmark_pin_selector_keeps_legacy_all_and_pilot_separate(self):
        bash = ("C:/Program Files/Git/bin/bash.exe" if os.name == "nt" else shutil.which("bash"))
        if not bash or not Path(bash).is_file() or not shutil.which("jq"):
            self.skipTest("Bash and jq are required to exercise the pin selector")
        images = json.loads(MANIFEST.read_text())["images"]
        for lane in ("debian13", "ubuntu2604"):
            lines = subprocess.check_output([bash, "scripts/benchmark-qemu.sh", "--distro", lane,
                                             "--print-pins"], cwd=ROOT, text=True).splitlines()
            self.assertEqual(len(lines), 1)
            identity, arch, url, digest, algorithm, _ = lines[0].split("\t")
            self.assertEqual((identity, arch), (lane, "x86_64"))
            pin = images[lane + "-x86_64"]
            self.assertEqual((url, digest, algorithm),
                             (pin["url"], pin["digest"], pin["algorithm"] + "sum"))
            unstaged = subprocess.run([bash, "scripts/benchmark-qemu.sh", "--distro", lane],
                                      cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(unstaged.returncode, 2)
        legacy = subprocess.check_output([bash, "scripts/benchmark-qemu.sh", "--print-pins"],
                                         cwd=ROOT, text=True).splitlines()
        self.assertEqual(len(legacy), 7)

    def test_inventory_admission_keeps_lane_identity_and_family_expectations(self):
        inventory = (POLICY.HEADER + "\n"
                     "abi-probe\t[\"doctor\"]\tread\tarch:0,debian:3,ubuntu:4,fedora:0\tpass\t-\thermetic\thermetic:pass\t-\tnone\n").encode()
        digest = hashlib.sha256(inventory).hexdigest()
        rules = {"inventories": {digest: {"cases": [{"id": "abi-probe", "tiers": ["hermetic"],
                                                       "allowed_skips": {}, "network_scope": "offline"}]}},
                 "profiles": {"hermetic,container": ["hermetic", "container"]}}
        policy = json.dumps(rules).encode()
        summary = b'{"complete":true,"pass":1,"fail":0,"skipped":0}'
        for identity, family, code in (("debian13", "debian", 3), ("ubuntu2604", "ubuntu", 4)):
            row = {"case_id": f"qemu-{identity}-abi-probe", "distro": identity,
                   "artifact_source": "inventory", "result": "PASS", "exit_code": code,
                   "network_scope": "offline"}
            result = POLICY.admit_contents(policy, inventory, json.dumps([row]).encode(), summary,
                                           family, "hermetic,container", identity)
            self.assertTrue(result["passed"])
            with self.assertRaises(ValueError):
                POLICY.admit_contents(policy, inventory, json.dumps([row]).encode(), summary,
                                      family, "hermetic,container", "debian" if family == "ubuntu" else "ubuntu")
            row["distro"] = family
            with self.assertRaises(ValueError):
                POLICY.admit_contents(policy, inventory, json.dumps([row]).encode(), summary,
                                      family, "hermetic,container", identity)

    def test_apt_abi_receipt_is_exported_with_guest_evidence(self):
        self.assertTrue(EXPORT.allowed_file(("run-pilot", "guest", "evidence", "apt-abi.txt")))


if __name__ == "__main__":
    unittest.main()
