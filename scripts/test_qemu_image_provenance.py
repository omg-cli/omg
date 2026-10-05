from datetime import date
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests/qemu-image-provenance/manifest.json"
SPEC = importlib.util.spec_from_file_location("image_provenance", ROOT / "scripts/verify-qemu-image.py")
IMAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IMAGE)
GPGV = shutil.which("gpgv") or ("C:/Program Files/Git/usr/bin/gpgv.exe" if os.name == "nt" else None)


class ImageProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads(MANIFEST.read_text())

    def test_current_pins_have_exact_reviewed_policies(self):
        bash = os.environ.get("OMG_TEST_BASH") or shutil.which("bash")
        self.assertIsNotNone(bash)
        lines = subprocess.check_output([bash, str(ROOT / "scripts/benchmark-qemu.sh"), "--print-pins"], text=True).splitlines()
        self.assertEqual(len(lines), 8)
        for line in lines:
            distro, arch, url, digest, algorithm, _ = line.split("\t")
            entry = IMAGE.policy(MANIFEST, distro + "-" + arch, url, digest, date(2026, 10, 3))
            self.assertEqual(entry["algorithm"] + "sum", algorithm)

    def test_expired_or_changed_pin_cannot_boot(self):
        entry = self.manifest["images"]["ubuntu-x86_64"]
        with self.assertRaises(ValueError):
            IMAGE.policy(MANIFEST, "ubuntu-x86_64", entry["url"], entry["digest"], date(2026, 10, 15))
        with self.assertRaises(ValueError):
            IMAGE.policy(MANIFEST, "ubuntu-x86_64", entry["url"], "0" * 64, date(2026, 10, 3))

    def test_trixie_has_a_versioned_x64_pin_and_explicit_unsigned_checksum_policy(self):
        bash = os.environ.get("OMG_TEST_BASH") or shutil.which("bash")
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([bash, str(ROOT / 'scripts/benchmark-qemu.sh'),
                                     '--distro', 'debian-trixie', '--print-pins',
                                     '--evidence-dir', directory], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [line.split('\t') for line in result.stdout.splitlines()]
        self.assertEqual(len(rows), 1, 'Trixie ARM is not an admitted build profile')
        distro, arch, url, digest, algorithm, _ = rows[0]
        self.assertEqual((distro, arch, algorithm), ('debian-trixie', 'x86_64', 'sha512sum'))
        self.assertEqual(url, 'https://cloud.debian.org/images/cloud/trixie/20261001-2618/debian-13-genericcloud-amd64-20261001-2618.qcow2')
        self.assertEqual(digest, 'f46f0671a6e5bdec5291ab8972bae2f10e5408c2f64a74078f11efc2f06a436a9d0313ed50e0472542eeabf780e9f7c792ac0a314c6c20507fcd9fd81b468c3d')
        entry = IMAGE.policy(MANIFEST, 'debian-trixie-x86_64', url, digest, date(2026, 10, 3))
        self.assertEqual(entry['algorithm'], 'sha512')
        self.assertEqual(entry['signature_policy'], 'publisher-unsigned-cloud-checksums')
        self.assertFalse(IMAGE.verify_signature(entry, MANIFEST.parent, Path('unused'))['signature_verified'])

    @unittest.skipUnless(GPGV, "OpenPGP verification requires gpgv")
    def test_real_publisher_checksum_signatures(self):
        for identity in ("ubuntu-x86_64", "ubuntu-aarch64", "fedora-x86_64", "fedora-aarch64"):
            with self.subTest(identity=identity):
                entry = self.manifest["images"][identity]
                receipt = IMAGE.verify_signature(entry, MANIFEST.parent, Path("unused"), GPGV)
                self.assertTrue(receipt["signature_verified"])
                with self.assertRaises(ValueError):
                    IMAGE.verify_signature(dict(entry, fingerprint="0" * 40), MANIFEST.parent, Path("unused"), GPGV)
                with self.assertRaises(ValueError):
                    IMAGE.verify_signature(dict(entry, digest="0" * 64), MANIFEST.parent, Path("unused"), GPGV)

    def test_debian_exception_is_explicit_and_cannot_cover_other_publishers(self):
        entry = self.manifest["images"]["debian-x86_64"]
        self.assertFalse(IMAGE.verify_signature(entry, MANIFEST.parent, Path("unused"))["signature_verified"])
        with self.assertRaises(ValueError):
            IMAGE.verify_signature(dict(entry, publisher="ubuntu"), MANIFEST.parent, Path("unused"))

    def test_key_or_material_substitution_fails(self):
        entry = self.manifest["images"]["ubuntu-x86_64"]
        with self.assertRaises(ValueError):
            IMAGE.verify_signature(dict(entry, keyring_sha256="0" * 64), MANIFEST.parent, Path("unused"), GPGV)
        with self.assertRaises(ValueError):
            IMAGE.material(MANIFEST.parent, "../other-key")

    def test_verification_precedes_image_parser_and_is_required_by_ci(self):
        source = (ROOT / "scripts/benchmark-qemu.sh").read_text()
        self.assertLess(source.index('"$here/verify-qemu-image.py"'), source.index("qemu-img info base.qcow2"))
        workflow = (ROOT / ".github/workflows/qemu-matrix.yml").read_text() + (ROOT / ".github/workflows/qemu-lane.yml").read_text()
        self.assertEqual(workflow.count("--image-policy tests/qemu-image-provenance/manifest.json"), 2)


if __name__ == "__main__":
    unittest.main()
