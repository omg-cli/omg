#!/usr/bin/env python3
"""Install only the reviewed libslirp package inside the disposable controller."""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

# Debian's signed sid Packages indexes and matching downloads, 2026-10-03.
# https://security-tracker.debian.org/tracker/CVE-2026-95507
# https://security-tracker.debian.org/tracker/CVE-2026-95508
VERSION = "4.9.5-1"
PINS = {
    "amd64": {"size": 71872, "sha256": "3fad48bcc3830a8d236678042e246121cfac26931311874d0a69f862dd82e5d3"},
    "arm64": {"size": 62600, "sha256": "ae1f711bc86fc0336773f67a1df9f5372c9596016181b4130c6fdf36efe159bb"},
}


def verify_package(path, architecture, pin):
    if architecture not in PINS:
        raise ValueError("Unsupported controller architecture")
    if Path(path).stat().st_size != pin["size"]:
        raise ValueError("libslirp package size or digest mismatch")
    raw = Path(path).read_bytes()
    if len(raw) != pin["size"] or hashlib.sha256(raw).hexdigest() != pin["sha256"]:
        raise ValueError("libslirp package size or digest mismatch")
    fields = {}
    for field in ("Package", "Source", "Version", "Architecture"):
        fields[field] = subprocess.check_output(
            ["dpkg-deb", "--field", str(path), field], text=True, timeout=10).strip()
    expected = {"Package": "libslirp0", "Source": "libslirp", "Version": VERSION,
                "Architecture": architecture}
    if fields != expected:
        raise ValueError("libslirp package identity mismatch")
    return fields


def install(qemu_package):
    architecture = subprocess.check_output(
        ["dpkg", "--print-architecture"], text=True, timeout=10).strip()
    if architecture not in PINS:
        raise ValueError("Unsupported controller architecture")
    pin = PINS[architecture]
    filename = f"libslirp0_{VERSION}_{architecture}.deb"
    url = "https://deb.debian.org/debian/pool/main/libs/libslirp/" + filename
    with tempfile.TemporaryDirectory(prefix="omg-libslirp-") as directory:
        path = Path(directory) / filename
        subprocess.run(["curl", "--fail", "--show-error", "--silent", "--location",
                        "--proto", "=https", "--proto-redir", "=https",
                        "--connect-timeout", "20", "--max-time", "60",
                        "--max-filesize", str(pin["size"]), "--output", str(path), url],
                       check=True, timeout=65, stdin=subprocess.DEVNULL)
        fields = verify_package(path, architecture, pin)
        subprocess.run(["dpkg", "--install", str(path)], check=True, timeout=20,
                       stdin=subprocess.DEVNULL)
    installed = subprocess.check_output(
        ["dpkg-query", "-W", "-f=${db:Status-Status}\n${Version}\n${Architecture}", "libslirp0"],
        text=True, timeout=10).splitlines()
    if installed != ["installed", VERSION, architecture]:
        raise ValueError("Installed libslirp identity mismatch")
    binary = "qemu-system-x86_64" if qemu_package == "qemu-system-x86" else "qemu-system-aarch64"
    links = subprocess.check_output(["ldd", "/usr/bin/" + binary], text=True, timeout=10)
    matches = re.findall(r"^\s*libslirp\.so\.0 => (/[^\s]+) \(0x[0-9a-f]+\)$", links, re.MULTILINE)
    if len(matches) != 1:
        raise ValueError("QEMU must resolve exactly one libslirp library")
    library = ctypes.CDLL(matches[0])
    library.slirp_version_string.restype = ctypes.c_char_p
    runtime = library.slirp_version_string().decode("ascii")
    if runtime != "4.9.5":
        raise ValueError("Loaded libslirp version mismatch")
    print(json.dumps({"url": url, "sha256": pin["sha256"], "size": pin["size"],
                      "package": fields, "installed": installed, "library": matches[0],
                      "runtime_version": runtime, "qemu_binary": binary}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("qemu_package", choices=("qemu-system-x86", "qemu-system-arm"))
    install(parser.parse_args().qemu_package)


if __name__ == "__main__":
    main()
