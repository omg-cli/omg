import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("bundle", Path(__file__).with_name("qemu-controller-bundle.py"))
bundle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bundle)

class ControllerBundleTests(unittest.TestCase):
    def fixture(self, root):
        archive = b"recorded Docker-save bytes\n"
        (root / "controller-image.tar").write_bytes(archive)
        receipt = {
            "schema_version": 1, "repository": "omg-cli/omg",
            "source_sha": "a" * 40, "run_id": "42", "run_attempt": 2,
            "architecture": "amd64", "image_id": "sha256:" + "b" * 64,
            "archive": {"size": 27, "sha256": "7d7a1719ef7a5075c6606fab64ea61cfa2cf85df7111e16f0063928953778e66"},
        }
        (root / "controller.json").write_text(json.dumps(receipt), encoding="utf-8")
        return receipt

    def admit(self, root):
        return bundle.verify_transport(root, "omg-cli/omg", "a" * 40, "42", 2, "amd64",
                                       "7d7a1719ef7a5075c6606fab64ea61cfa2cf85df7111e16f0063928953778e66", "sha256:" + "b" * 64, "0ebf2ba376ecff75a6fc8a5bd0e83bc748a6b79e4d3b3894b6ca4089656692f5")

    def test_accepts_exact_byte_join_and_returns_image_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self.fixture(root)
            self.assertEqual(self.admit(root)["image_id"], "sha256:" + "b" * 64)

    def test_refuses_same_size_archive_corruption(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self.fixture(root)
            (root / "controller-image.tar").write_bytes(b"X" * 27)
            with self.assertRaisesRegex(ValueError, "archive digest"):
                self.admit(root)

    def test_refuses_unrelated_run_attempt_source_or_architecture(self):
        for key, value in [("repository", "other/repo"), ("source_sha", "c" * 40),
                           ("run_id", "43"), ("run_attempt", 1), ("run_attempt", True),
                           ("architecture", "arm64")]:
            with self.subTest(key=key, value=value), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); receipt = self.fixture(root); receipt[key] = value
                (root / "controller.json").write_text(json.dumps(receipt), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "identity"):
                    self.admit(root)

    def test_refuses_duplicate_json_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self.fixture(root)
            raw = (root / "controller.json").read_text()
            (root / "controller.json").write_text(raw[:-1] + ', "run_id": "42"}')
            with self.assertRaisesRegex(ValueError, "duplicate"):
                self.admit(root)

    def test_merges_real_firmware_bytes_with_equal_collision(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); qemu = root / "qemu"; bios = root / "seabios"
            qemu.mkdir(); bios.mkdir()
            (qemu / "e1000.rom").write_bytes(b"network ROM")
            (qemu / "shared.bin").write_bytes(b"identical")
            (bios / "shared.bin").write_bytes(b"identical")
            (bios / "bios-256k.bin").write_bytes(b"stable BIOS")
            bundle.merge_firmware([qemu, bios], root / "merged")
            self.assertEqual({p.name: p.read_bytes() for p in (root / "merged").iterdir()},
                             {"e1000.rom": b"network ROM", "shared.bin": b"identical", "bios-256k.bin": b"stable BIOS"})

    def test_runtime_admits_only_configured_qemu_suffix_firmware(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            firmware = root / 'firmware/qemu'
            firmware.mkdir(parents=True)
            (firmware / 'bios-256k.bin').write_bytes(b'fixture BIOS')
            receipt = {'qemu_version': bundle.VERSION, 'source': bundle.SOURCE_PIN,
                       'key_sha256': bundle.KEY_SHA256, 'signer_fingerprint': bundle.FINGERPRINT,
                       'binaries': {'qemu-system-x86_64': {}, 'qemu-img': {}},
                       'firmware': {'bios-256k.bin': bundle.stable_digest(firmware / 'bios-256k.bin', 100)}}
            with patch.object(bundle, 'verify_executable'):
                self.assertEqual(bundle.verify_runtime(receipt, root)['firmware'], receipt['firmware'])
                (firmware / 'bios-256k.bin').rename(root / 'firmware/bios-256k.bin')
                with self.assertRaisesRegex(ValueError, 'runtime firmware mismatch'):
                    bundle.verify_runtime(receipt, root)

    def test_refuses_different_firmware_collision(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); first = root / "first"; second = root / "second"
            first.mkdir(); second.mkdir()
            (first / "bios.bin").write_bytes(b"trusted BIOS")
            (second / "bios.bin").write_bytes(b"different BIOS")
            with self.assertRaisesRegex(ValueError, "firmware collision"):
                bundle.merge_firmware([first, second], root / "merged")

    def test_authenticates_reviewed_key_bytes_and_rejects_tampering(self):
        key = Path(__file__).resolve().parent.parent / "tests/qemu-controller/release-manager.asc"
        self.assertEqual(bundle.verify_key_bytes(key), "CEACC9E15534EBABB82D3FA03353C9CEF108B584")
        with tempfile.TemporaryDirectory() as directory:
            changed = Path(directory) / "key.asc"
            changed.write_bytes(key.read_bytes() + b"changed")
            with self.assertRaisesRegex(ValueError, "key digest"):
                bundle.verify_key_bytes(changed)

    def test_refuses_unreviewed_source_before_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "qemu.tar.xz"
            source.write_bytes(b"not the authenticated archive")
            with self.assertRaisesRegex(ValueError, "source archive"):
                bundle.verify_source_bytes(source)

    def test_producer_pin_refuses_forged_archive_and_self_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); receipt = self.fixture(root)
            (root / "controller-image.tar").write_bytes(b"X" * 27)
            receipt["archive"]["sha256"] = "65700c0b349cebbbe96fea79ba20f41adb9089edf87abca0009d7b6f6ab03f52"
            (root / "controller.json").write_text(json.dumps(receipt), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "producer archive"):
                bundle.verify_transport(root, "omg-cli/omg", "a" * 40, "42", 2, "amd64",
                                        "7d7a1719ef7a5075c6606fab64ea61cfa2cf85df7111e16f0063928953778e66", "sha256:" + "b" * 64, "0ebf2ba376ecff75a6fc8a5bd0e83bc748a6b79e4d3b3894b6ca4089656692f5")

    def test_producer_pin_refuses_self_declared_other_image(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); receipt = self.fixture(root)
            receipt["image_id"] = "sha256:" + "c" * 64
            (root / "controller.json").write_text(json.dumps(receipt), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "producer image"):
                bundle.verify_transport(root, "omg-cli/omg", "a" * 40, "42", 2, "amd64",
                                        "7d7a1719ef7a5075c6606fab64ea61cfa2cf85df7111e16f0063928953778e66", "sha256:" + "b" * 64, "0ebf2ba376ecff75a6fc8a5bd0e83bc748a6b79e4d3b3894b6ca4089656692f5")

    def test_load_inspects_actual_image_and_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); receipt = self.fixture(root)
            with patch.object(bundle.subprocess, "run") as run:
                run.side_effect = [None, bundle.subprocess.CompletedProcess([], 0,
                    json.dumps([{"Id": "sha256:" + "b" * 64, "Architecture": "amd64", "Os": "linux", "Config": {"Labels": {
                        "org.opencontainers.image.revision": "a" * 40}}}]), "")]
                self.assertEqual(bundle.load_controller(root, receipt), "sha256:" + "b" * 64)
                self.assertEqual(run.call_args_list[0].args[0],
                                 ["docker", "load", "--input", str(root / "controller-image.tar")])
                self.assertEqual(run.call_args_list[1].args[0],
                                 ["docker", "image", "inspect", "sha256:" + "b" * 64])

    def test_load_refuses_wrong_actual_image_or_revision(self):
        for image, revision in [("sha256:" + "c" * 64, "a" * 40),
                                ("sha256:" + "b" * 64, "c" * 40)]:
            with self.subTest(image=image, revision=revision), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); receipt = self.fixture(root)
                with patch.object(bundle.subprocess, "run") as run:
                    run.side_effect = [None, bundle.subprocess.CompletedProcess([], 0,
                        json.dumps([{"Id": image, "Architecture": "amd64", "Os": "linux", "Config": {"Labels": {
                            "org.opencontainers.image.revision": revision}}}]), "")]
                    with self.assertRaisesRegex(ValueError, "loaded controller"):
                        bundle.load_controller(root, receipt)

    def test_load_refuses_actual_wrong_platform(self):
        for architecture, operating_system in (("arm64", "linux"), ("amd64", "windows")):
            with self.subTest(architecture=architecture, os=operating_system), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); receipt = self.fixture(root)
                with patch.object(bundle.subprocess, "run") as run:
                    run.side_effect = [None, bundle.subprocess.CompletedProcess([], 0,
                        json.dumps([{"Id": receipt["image_id"], "Architecture": architecture,
                                     "Os": operating_system, "Config": {"Labels": {
                                         "org.opencontainers.image.revision": receipt["source_sha"]}}}]), "")]
                    with self.assertRaisesRegex(ValueError, "loaded controller"):
                        bundle.load_controller(root, receipt)

    def test_load_refuses_archive_changed_during_docker_load(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); receipt = self.fixture(root)
            def docker(command, **kwargs):
                if command[1] == "load":
                    (root / "controller-image.tar").write_bytes(b"X" * 27)
                    return None
                return bundle.subprocess.CompletedProcess([], 0, json.dumps([{
                    "Id": receipt["image_id"], "Architecture": "amd64", "Os": "linux",
                    "Config": {"Labels": {"org.opencontainers.image.revision": receipt["source_sha"]}}}]), "")
            with patch.object(bundle.subprocess, "run", side_effect=docker):
                with self.assertRaisesRegex(ValueError, "archive changed"):
                    bundle.load_controller(root, receipt)

    def test_runtime_refuses_wrong_executable_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "qemu-system-x86_64"
            binary.write_bytes(b"wrong installed package executable")
            with patch.object(bundle.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "executable digest"):
                    bundle.verify_executable(binary, {"size": 27, "sha256":
                        "7d7a1719ef7a5075c6606fab64ea61cfa2cf85df7111e16f0063928953778e66"}, "QEMU emulator version 10.0.14")
                run.assert_not_called()

    def test_runtime_requires_actual_version_from_pinned_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "qemu-system-x86_64"
            binary.write_bytes(b"recorded Docker-save bytes\n")
            pin = {"size": 27, "sha256": "7d7a1719ef7a5075c6606fab64ea61cfa2cf85df7111e16f0063928953778e66"}
            with patch.object(bundle.subprocess, "run") as run:
                run.return_value = bundle.subprocess.CompletedProcess([], 0, "QEMU emulator version 10.0.13\n", "")
                with self.assertRaisesRegex(ValueError, "executable version"):
                    bundle.verify_executable(binary, pin, "QEMU emulator version 10.0.14")
                self.assertEqual(run.call_args.args[0], [str(binary), "--version"])
                run.return_value = bundle.subprocess.CompletedProcess([], 0, "QEMU emulator version 10.0.14\n", "")
                self.assertEqual(bundle.verify_executable(binary, pin, "QEMU emulator version 10.0.14"), pin)

    def test_signature_requires_pinned_validsig_even_when_verifier_exits_zero(self):
        for status in ("", "[GNUPG:] VALIDSIG " + "A" * 40 + " 2026-10-12\n"):
            with self.subTest(status=status), patch.object(bundle, "verify_source_bytes"), \
                    patch.object(bundle, "verify_key_bytes"), patch.object(bundle.subprocess, "run") as run:
                run.side_effect = [None, bundle.subprocess.CompletedProcess([], 0, status, "")]
                with self.assertRaisesRegex(ValueError, "signature fingerprint"):
                    bundle.authenticate_source("archive", "signature", "key")

    def test_signature_preserves_verifier_failure(self):
        with patch.object(bundle, "verify_source_bytes"), patch.object(bundle, "verify_key_bytes"), \
                patch.object(bundle.subprocess, "run") as run:
            run.side_effect = [None, bundle.subprocess.CalledProcessError(1, ["gpgv"])]
            with self.assertRaises(bundle.subprocess.CalledProcessError):
                bundle.authenticate_source("archive", "signature", "key")

    @unittest.skipIf(os.name == "nt", "production shell commands require POSIX executables")
    def test_all_image_operations_execute_selected_tool_despite_wrong_path_tool(self):
        source_root = Path(__file__).resolve().parent
        benchmark = (source_root / "benchmark-qemu.sh").read_text()
        transactions = (source_root / "qemu-transactions.sh").read_text()
        commands = [
            ('"$2" info base.qcow2', ["info", "base.qcow2"]),
            (next(line for line in benchmark.splitlines() if ' create ' in line and 'overlay.qcow2' in line),
             ["create", "-f", "qcow2", "-F", "qcow2", "-b", "/work/guest/base.qcow2", "overlay.qcow2"]),
            (next(line for line in benchmark.splitlines() if ' resize overlay.qcow2 ' in line),
             ["resize", "overlay.qcow2", "12G"]),
        ]
        for fragment, expected in [
            (' convert ', ["convert", "-f", "qcow2", "-O", "qcow2", "source", "disks/op-base.qcow2"]),
            (' check ', ["check", "disks/op-base.qcow2"]),
            ('prepare-install.qcow2', ["create", "-f", "qcow2", "-F", "qcow2", "-b", "disks/remove-base.qcow2", "disks/prepare-install.qcow2"]),
            (' -b "$base" "$disk"', ["create", "-f", "qcow2", "-F", "qcow2", "-b", "base", "disk"]),
            ('resume.qcow2', ["create", "-f", "qcow2", "-F", "qcow2", "-b", "disks/install-base.qcow2", "disks/resume.qcow2"]),
        ]:
            commands.append((next(line.strip().split(" > ")[0] for line in transactions.splitlines()
                                  if fragment in line and '"$qemu_img"' in line), expected))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            chosen = root / "selected-image-tool"
            chosen.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$OBSERVED"\n')
            chosen.chmod(0o755)
            wrong = root / "qemu-img"
            wrong.write_text('#!/bin/sh\nexit 99\n')
            wrong.chmod(0o755)
            for command, expected in commands:
                with self.subTest(expected=expected):
                    prefix = ('set -euo pipefail\nqemu_img=$1\nsource=source; disks=disks; '
                              'operation=op; base=base; disk=disk\n')
                    result = bundle.subprocess.run(["/bin/bash", "-c", prefix + command, "image-operations",
                                                    str(chosen), str(chosen)],
                                                   env={**os.environ, "PATH": str(root),
                                                        "OBSERVED": str(root / "observed")},
                                                   capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual((root / "observed").read_text().splitlines(), expected)

    def test_producer_pin_refuses_changed_self_receipt_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); receipt = self.fixture(root)
            receipt["claimed_packages"] = "forged dependency observation"
            (root / "controller.json").write_text(json.dumps(receipt), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "producer receipt"):
                self.admit(root)

if __name__ == "__main__":
    unittest.main()
