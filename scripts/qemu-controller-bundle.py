#!/usr/bin/env python3
"""Admit one same-run Docker-save controller bundle and merge stable firmware."""
import hashlib
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile


def _identity(row):
    return (row.st_dev, row.st_ino, row.st_mode, row.st_size, row.st_mtime_ns,
            row.st_ctime_ns, getattr(row, "st_birthtime_ns", None))


def _cross_identity(row):
    return (row.st_dev, row.st_ino, row.st_mode, row.st_size, row.st_mtime_ns,
            getattr(row, "st_birthtime_ns", None))


def stable_digest(path, limit, capture=False):
    path = Path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= limit:
        raise ValueError("expected a bounded regular file")
    digest = hashlib.sha256()
    content = bytearray() if capture else None
    observed = 0
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if _cross_identity(before) != _cross_identity(opened):
            raise ValueError("opened file identity changed")
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            observed += len(block)
            if observed > limit:
                raise ValueError("file exceeded read bound")
            digest.update(block)
            if capture:
                content.extend(block)
        final = os.fstat(stream.fileno())
        if _identity(opened) != _identity(final):
            raise ValueError("opened file changed during read")
    after = path.lstat()
    if _identity(before) != _identity(after) or _cross_identity(after) != _cross_identity(final):
        raise ValueError("file path changed during read")
    result = {"size": before.st_size, "sha256": digest.hexdigest()}
    if capture:
        result["content"] = bytes(content)
    return result


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate receipt key")
        result[key] = value
    return result


def verify_transport(directory, repository, source_sha, run_id, run_attempt, architecture, archive_sha256, image_id, receipt_sha256):
    directory = Path(directory)
    receipt_path = directory / "controller.json"
    raw = stable_digest(receipt_path, 65536, capture=True)
    receipt = json.loads(raw["content"], object_pairs_hook=_unique_object)
    expected = {"schema_version": 1, "repository": repository, "source_sha": source_sha,
                "run_id": run_id, "run_attempt": run_attempt, "architecture": architecture}
    for key, value in expected.items():
        if type(receipt.get(key)) is not type(value) or receipt[key] != value:
            raise ValueError("controller identity mismatch: " + key)
    if not isinstance(receipt.get("image_id"), str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", receipt["image_id"]):
        raise ValueError("invalid controller image identity")
    if receipt["image_id"] != image_id:
        raise ValueError("producer image identity mismatch")
    archive = receipt.get("archive")
    if (not isinstance(archive, dict) or set(archive) != {"size", "sha256"}
            or type(archive["size"]) is not int or not 0 < archive["size"] <= 4 * 1024**3
            or not isinstance(archive["sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", archive["sha256"])):
        raise ValueError("invalid archive digest declaration")
    if archive["sha256"] != archive_sha256:
        raise ValueError("producer archive digest mismatch")
    if stable_digest(directory / "controller-image.tar", 4 * 1024**3) != archive:
        raise ValueError("archive digest mismatch")
    if raw["sha256"] != receipt_sha256:
        raise ValueError("producer receipt digest mismatch")
    for name, pin in receipt.get("build", {}).items():
        if name not in ("packages.tsv", "compiler.txt", "configure-argv.txt", "config-host.mak",
                        "compile.sh", "Dockerfile.build", "Dockerfile.runtime", "runtime-packages.tsv"):
            raise ValueError("invalid build observation path")
        if stable_digest(directory / name, 1024 * 1024) != pin:
            raise ValueError("build observation digest mismatch")
    return receipt


def record_bundle(directory, installation, repository, source_sha, run_id, run_attempt, image_id):
    installation = Path(installation)
    binaries = {name: stable_digest(installation / "omg-qemu-10.0.14/bin" / name, 512 * 1024**2)
                for name in ("qemu-system-x86_64", "qemu-img")}
    firmware = {}
    root = installation / "omg-qemu-10.0.14/firmware/qemu"
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("packaged firmware symlink")
        if path.is_file():
            firmware[path.relative_to(root).as_posix()] = stable_digest(path, 16 * 1024**2)
    for required in ("bios-256k.bin", "vgabios-stdvga.bin", "kvmvapic.bin", "pxe-e1000.rom", "efi-e1000.rom"):
        if required not in firmware:
            raise ValueError("required firmware absent: " + required)
    receipt = {"schema_version": 1, "repository": repository, "source_sha": source_sha,
               "run_id": run_id, "run_attempt": run_attempt, "architecture": "amd64",
               "image_id": image_id,
               "archive": stable_digest(Path(directory) / "controller-image.tar", 4 * 1024**3),
               "qemu_version": VERSION, "source": SOURCE_PIN, "key_sha256": KEY_SHA256,
               "signer_fingerprint": FINGERPRINT, "binaries": binaries, "firmware": firmware,
               "build": {name: stable_digest(Path(directory) / name, 1024 * 1024)
                         for name in ("packages.tsv", "compiler.txt", "configure-argv.txt", "config-host.mak",
                                      "compile.sh", "Dockerfile.build", "Dockerfile.runtime", "runtime-packages.tsv")}}
    with (Path(directory) / "controller.json").open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, sort_keys=True, indent=2)
        stream.write("\n")
    return receipt


def verify_runtime(receipt, installation):
    if (receipt.get("qemu_version") != VERSION or receipt.get("source") != SOURCE_PIN
            or receipt.get("key_sha256") != KEY_SHA256 or receipt.get("signer_fingerprint") != FINGERPRINT):
        raise ValueError("source controller provenance mismatch")
    installation = Path(installation)
    binaries = receipt.get("binaries")
    if not isinstance(binaries, dict) or set(binaries) != {"qemu-system-x86_64", "qemu-img"}:
        raise ValueError("invalid controller executable declaration")
    for name, prefix in (("qemu-system-x86_64", "QEMU emulator version 10.0.14"),
                         ("qemu-img", "qemu-img version 10.0.14")):
        verify_executable(installation / "bin" / name, binaries[name], prefix)
    firmware = receipt.get("firmware")
    if not isinstance(firmware, dict) or not firmware:
        raise ValueError("invalid firmware declaration")
    root = installation / "firmware/qemu"
    actual = {path.relative_to(root).as_posix(): stable_digest(path, 16 * 1024**2)
              for path in root.rglob("*") if path.is_file()}
    if actual != firmware or any(path.is_symlink() for path in root.rglob("*")):
        raise ValueError("runtime firmware mismatch")
    return {"binaries": binaries, "firmware": firmware}


def merge_firmware(sources, destination):
    destination = Path(destination)
    destination.mkdir()
    manifest = {}
    for source in sources:
        source = Path(source)
        if source.is_symlink() or not source.is_dir():
            raise ValueError("firmware source must be a real directory")
        for root, directories, files in os.walk(source):
            if any((Path(root) / name).is_symlink() for name in directories):
                raise ValueError("firmware directory symlink is not supported")
            for name in files:
                path = Path(root) / name
                relative = path.relative_to(source)
                pin = stable_digest(path.resolve(strict=True), 16 * 1024**2)
                target = destination / relative
                if target.exists():
                    if stable_digest(target, 16 * 1024**2) != pin:
                        raise ValueError("firmware collision: " + str(relative))
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with path.open("rb") as incoming, target.open("xb") as outgoing:
                        while block := incoming.read(1024 * 1024):
                            outgoing.write(block)
                    if stable_digest(target, 16 * 1024**2) != pin or stable_digest(path.resolve(strict=True), 16 * 1024**2) != pin:
                        raise ValueError("firmware changed during copy")
                manifest[relative.as_posix()] = pin
    return manifest


def load_controller(directory, receipt):
    subprocess.run(["docker", "load", "--input", str(Path(directory) / "controller-image.tar")],
                   check=True, timeout=180, stdout=sys.stderr)
    loaded = subprocess.run(["docker", "image", "inspect", receipt["image_id"]],
                            check=True, capture_output=True, text=True, timeout=30)
    rows = json.loads(loaded.stdout, object_pairs_hook=_unique_object)
    if (not isinstance(rows, list) or len(rows) != 1
            or rows[0].get("Id") != receipt["image_id"]
            or rows[0].get("Architecture") != "amd64" or rows[0].get("Os") != "linux"
            or rows[0].get("Config", {}).get("Labels", {}).get("org.opencontainers.image.revision") != receipt["source_sha"]):
        raise ValueError("loaded controller image or revision mismatch")
    if stable_digest(Path(directory) / "controller-image.tar", 4 * 1024**3) != receipt["archive"]:
        raise ValueError("controller archive changed during load")
    return receipt["image_id"]


def verify_executable(path, pin, version_prefix):
    path = Path(path)
    if not path.is_absolute() or stable_digest(path, 512 * 1024**2) != pin:
        raise ValueError("controller executable digest mismatch")
    version = subprocess.run([str(path), "--version"], check=True, capture_output=True,
                             text=True, timeout=10)
    lines = version.stdout.splitlines()
    if not lines or (lines[0] != version_prefix and not lines[0].startswith(version_prefix + " (")):
        raise ValueError("controller executable version mismatch")
    if stable_digest(path, 512 * 1024**2) != pin:
        raise ValueError("controller executable changed during execution")
    return pin

VERSION = "10.0.14"
SOURCE_PIN = {"size": 141709008, "sha256": "c7230968906fdb5540d803e2af1f515e77590a414f2a4dbd3ec9ada3c47083d0"}
KEY_SHA256 = "05d6f38c5acd314bf22670393240f79d5fa199628ee8a46bdf565144083da3ab"
FINGERPRINT = "CEACC9E15534EBABB82D3FA03353C9CEF108B584"


def verify_key_bytes(path):
    if stable_digest(path, 65536)["sha256"] != KEY_SHA256:
        raise ValueError("release-manager key digest mismatch")
    return FINGERPRINT


def verify_source_bytes(path):
    if stable_digest(path, SOURCE_PIN["size"]) != SOURCE_PIN:
        raise ValueError("source archive size or digest mismatch")
    return SOURCE_PIN


def authenticate_source(archive, signature, key):
    verify_source_bytes(archive)
    verify_key_bytes(key)
    with tempfile.TemporaryDirectory(prefix="omg-qemu-signature-") as directory:
        keyring = str(Path(directory) / "release-manager.gpg")
        subprocess.run(["gpg", "--batch", "--yes", "--dearmor", "--output", keyring, str(key)],
                       check=True, timeout=15)
        verified = subprocess.run(["gpgv", "--status-fd", "1", "--keyring", keyring,
                                   str(signature), str(archive)], check=True,
                                  capture_output=True, text=True, timeout=30)
        valid = [line.split() for line in verified.stdout.splitlines()
                 if line.startswith("[GNUPG:] VALIDSIG ")]
        if len(valid) != 1 or valid[0][2] != FINGERPRINT:
            raise ValueError("source signature fingerprint mismatch")
    return {"source": SOURCE_PIN, "key_sha256": KEY_SHA256, "fingerprint": FINGERPRINT}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    signature = commands.add_parser("authenticate-source")
    signature.add_argument("archive")
    signature.add_argument("signature")
    signature.add_argument("key")
    firmware = commands.add_parser("merge-firmware")
    firmware.add_argument("destination")
    firmware.add_argument("sources", nargs="+")
    load = commands.add_parser("load")
    load.add_argument("directory")
    for name in ("repository", "source-sha", "run-id", "architecture", "archive-sha256", "image-id", "receipt-sha256"):
        load.add_argument("--" + name, required=True)
    load.add_argument("--run-attempt", type=int, required=True)
    record = commands.add_parser("record")
    record.add_argument("directory")
    record.add_argument("installation")
    for name in ("repository", "source-sha", "run-id", "image-id"):
        record.add_argument("--" + name, required=True)
    record.add_argument("--run-attempt", type=int, required=True)
    outputs = commands.add_parser("outputs")
    outputs.add_argument("directory")
    runtime = commands.add_parser("runtime")
    runtime.add_argument("receipt")
    runtime.add_argument("installation")
    args = parser.parse_args()
    if args.command == "authenticate-source":
        result = authenticate_source(args.archive, args.signature, args.key)
    elif args.command == "merge-firmware":
        result = merge_firmware(args.sources, args.destination)
    elif args.command == "record":
        result = record_bundle(args.directory, args.installation, args.repository, args.source_sha,
                               args.run_id, args.run_attempt, args.image_id)
    elif args.command == "outputs":
        row = json.loads(stable_digest(Path(args.directory) / "controller.json", 65536, True)["content"],
                         object_pairs_hook=_unique_object)
        print("archive-sha256=" + row["archive"]["sha256"])
        print("image-id=" + row["image_id"])
        print("receipt-sha256=" + stable_digest(Path(args.directory) / "controller.json", 65536)["sha256"])
        return
    elif args.command == "runtime":
        row = json.loads(stable_digest(args.receipt, 65536, True)["content"], object_pairs_hook=_unique_object)
        result = verify_runtime(row, args.installation)
    else:
        receipt = verify_transport(args.directory, args.repository, args.source_sha, args.run_id,
                                   args.run_attempt, args.architecture, args.archive_sha256, args.image_id, args.receipt_sha256)
        result = {"image_id": load_controller(args.directory, receipt), "receipt": receipt,
                  "receipt_sha256": args.receipt_sha256}
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
