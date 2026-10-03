"""Validate real Debian archives before the controller can install them."""
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("slirp_installer", ROOT / "install-qemu-libslirp.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class LibslirpPackageTests(unittest.TestCase):
    def archive(self, directory, **changes):
        fields = {"Package": "libslirp0", "Source": "libslirp", "Version": "4.9.5-1",
                  "Architecture": "amd64", "Maintainer": "Fixture <fixture@example.invalid>",
                  "Description": "Synthetic package identity fixture"}
        fields.update(changes)
        source = Path(directory) / "package"
        (source / "DEBIAN").mkdir(parents=True)
        (source / "DEBIAN/control").write_text(
            "".join(f"{key}: {value}\n" for key, value in fields.items()))
        archive = Path(directory) / "package.deb"
        subprocess.run(["dpkg-deb", "--build", "--root-owner-group", str(source), str(archive)],
                       check=True, capture_output=True, timeout=10)
        raw = archive.read_bytes()
        return archive, {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

    def test_accepts_actual_debian_archive_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, pin = self.archive(directory)
            fields = installer.verify_package(archive, "amd64", pin)
            self.assertEqual(fields, {"Package": "libslirp0", "Source": "libslirp",
                                     "Version": "4.9.5-1", "Architecture": "amd64"})

    def test_rejects_coherent_wrong_package_source_version_or_architecture(self):
        for changes in ({"Package": "another-package"}, {"Source": "another-source"},
                        {"Version": "4.8.0-1+deb13u1"}, {"Architecture": "arm64"}):
            with self.subTest(changes=changes), tempfile.TemporaryDirectory() as directory:
                archive, pin = self.archive(directory, **changes)
                with self.assertRaisesRegex(ValueError, "identity mismatch"):
                    installer.verify_package(archive, "amd64", pin)

    def test_rejects_tampered_bytes_before_debian_archive_parser(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, pin = self.archive(directory)
            raw = bytearray(archive.read_bytes())
            raw[-1] ^= 1
            archive.write_bytes(raw)
            # dpkg-deb is an external parser: digest failure must precede it.
            with patch.object(installer.subprocess, "check_output", side_effect=AssertionError("parser reached")):
                with self.assertRaisesRegex(ValueError, "digest mismatch"):
                    installer.verify_package(archive, "amd64", pin)

    def test_rejects_truncated_or_extended_archive_before_parser(self):
        for delta in (-1, 1):
            with self.subTest(delta=delta), tempfile.TemporaryDirectory() as directory:
                archive, pin = self.archive(directory)
                raw = archive.read_bytes()
                archive.write_bytes(raw[:-1] if delta < 0 else raw + b"x")
                with patch.object(installer.subprocess, "check_output", side_effect=AssertionError("parser reached")):
                    with self.assertRaisesRegex(ValueError, "size or digest mismatch"):
                        installer.verify_package(archive, "amd64", pin)

    def test_rejects_unknown_architecture_before_archive_parser(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, pin = self.archive(directory)
            with self.assertRaisesRegex(ValueError, "Unsupported controller architecture"):
                installer.verify_package(archive, "riscv64", pin)


if __name__ == "__main__":
    unittest.main()
