#!/usr/bin/env python3
"""Exercise native advisory consent with real ALPM writes in private namespaces."""
import argparse
from datetime import datetime, timezone
import errno
import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import pty
import re
import select
import signal
import socket
import ssl
import subprocess
import threading
import time

NAME = "package_managers::alpm_ops::tests::native_advisory_consent_installs_only_the_accepted_transaction"
# The policy mutation is last because cases share this disposable home.
CASES = ("accept", "generic-yes", "blank", "wrong-review", "eof", "no-tty", "archive-change", "interrupt", "terminate", "hangup", "policy-change")
MARKER = "OMG_NATIVE_ADVISORY_CONSENT_RESULT="


def sha(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def oracle():
    spec = importlib.util.spec_from_file_location("arch_oracle", Path(__file__).with_name("qemu-arch-advisory-oracle.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def setup(command):
    result = subprocess.run(command, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stderr.decode(errors="replace")


def certificates(root, host):
    setup(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=OMG disposable fixture CA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", str(root / "ca.key"), "-out", str(root / "ca.crt")])
    setup(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=" + host, "-keyout", str(root / "server.key"), "-out", str(root / "server.csr")])
    (root / "server.ext").write_text("subjectAltName=DNS:" + host + "\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
    setup(["openssl", "x509", "-req", "-in", str(root / "server.csr"), "-CA", str(root / "ca.crt"), "-CAkey", str(root / "ca.key"), "-CAcreateserial", "-days", "1", "-extfile", str(root / "server.ext"), "-out", str(root / "server.crt")])


def terminal_case(unit, case, environment, expected=(b"possible match", b"1-1", b"https://security.archlinux.org/CVE-OMG-QEMU-616"), before_answer=None):
    command = [str(unit), "--exact", NAME, "--include-ignored", "--nocapture", "--test-threads=1"]
    if case == "no-tty":
        result = subprocess.run(command, env=environment, capture_output=True, start_new_session=True, timeout=20)
        return result.returncode, result.stdout + result.stderr
    pid, descriptor = pty.fork()
    if pid == 0:
        os.execve(str(unit), command, environment)
    transcript = bytearray()
    status = None
    sent = False
    deadline = time.monotonic() + 20
    try:
        while time.monotonic() < deadline:
            ready, _, _ = select.select([descriptor], [], [], 0.1)
            if ready:
                try:
                    chunk = os.read(descriptor, 8192)
                except OSError as error:
                    if error.errno == errno.EIO:
                        break
                    raise
                if not chunk:
                    break
                transcript.extend(chunk)
                assert len(transcript) <= 128 * 1024, "terminal capture exceeded limit"
                prompt = re.search(rb"Type accept ([0-9a-f]{64}).*default: cancel", transcript)
                if prompt and not sent:
                    assert all(fragment in transcript for fragment in expected), transcript.decode(errors="replace")
                    if before_answer:
                        before_answer()
                    if case in ("terminate", "hangup"):
                        os.kill(pid, {"terminate": signal.SIGTERM, "hangup": signal.SIGHUP}[case])
                    elif case == "split-accept":
                        # Canonical EOF after pending bytes delivers a partial
                        # read without closing the terminal or accepting a line.
                        os.write(descriptor, b"accept " + prompt[1][:24] + b"\x04")
                        time.sleep(0.15)
                        os.write(descriptor, prompt[1][24:] + b"\n")
                    else:
                        answer = {"generic-yes": b"yes\n", "blank": b"\n", "wrong-review": b"accept another-review\n", "eof": b"\x04", "interrupt": b"\x03"}.get(case, b"accept " + prompt[1] + b"\n")
                        os.write(descriptor, answer)
                    sent = True
        while time.monotonic() < deadline:
            child, completed = os.waitpid(pid, os.WNOHANG)
            if child:
                status = completed
                break
            time.sleep(0.01)
        assert status is not None and sent, transcript.decode(errors="replace")
        return os.waitstatus_to_exitcode(status), bytes(transcript)
    finally:
        if status is None:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        os.close(descriptor)


def inside(args):
    assert os.geteuid() == 0 and os.statvfs("/").f_flag & os.ST_RDONLY
    namespaces = {kind: os.readlink("/proc/self/ns/" + kind) for kind in ("mnt", "net")}
    assert all(namespaces[kind] != os.readlink("/proc/1/ns/" + kind) for kind in namespaces)
    mounts = Path("/proc/self/mountinfo").read_text().splitlines()
    for destination in ("/root", "/tmp"):
        assert any(line.split()[4] == destination and line.split(" - ", 1)[1].split()[0] == "tmpfs" for line in mounts), "fixture home and package roots require private tmpfs mounts"
    temporary = os.statvfs("/tmp")
    assert temporary.f_blocks * temporary.f_frsize <= 64 * 1024 * 1024
    setup(["ip", "link", "set", "lo", "up"])
    assert [row["ifname"] for row in json.loads(subprocess.check_output(["ip", "-j", "link"]))] == ["lo"]
    assert all(row.get("dev") == "lo" for row in json.loads(subprocess.check_output(["ip", "-j", "route", "show", "table", "all"])))
    source = oracle()
    assert {row[4][0] for row in socket.getaddrinfo(source.ARCH_HOST, 443, type=socket.SOCK_STREAM)} == {"127.0.0.1"}
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.output / "server.crt", args.output / "server.key")
    events = []

    class Server(http.server.ThreadingHTTPServer):
        daemon_threads = True

        def get_request(self):
            stream, address = super().get_request()
            stream.settimeout(5)
            return context.wrap_socket(stream, server_side=True), address

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_arguments):
            return

        def do_GET(self):
            observed = source.iso_timestamp(datetime.now(timezone.utc))
            status, response = source.snapshot_response(self.headers.get("Host"), self.path, "1-1", observed)
            if args.coverage == "unavailable":
                status, response = 503, {"error": "controlled unavailable advisory source"}
            elif args.coverage == "unmapped":
                response["payload_json"] = "[]"
                response["payload_sha256"] = hashlib.sha256(b"[]").hexdigest()
            encoded = json.dumps(response).encode()
            events.append(dict(host=self.headers.get("Host"), path=self.path, status=status, response=response))
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    server = Server(("127.0.0.1", 443), Handler)
    worker = threading.Thread(target=server.serve_forever)
    worker.start()
    records = []
    try:
        for case in CASES:
            start = len(events)
            profile = "omg-fixture-" + NAME.replace("::", "_") + "-" + args.coverage + "-" + case + "-%p-%m.profraw"
            environment = os.environ | {"HOME": "/root", "TMPDIR": "/tmp", "OMG_ARCH_INSTALL_FIXTURE": "isolated-container", "OMG_ADVISORY_INSTALL_CASE": case, "OMG_ADVISORY_INSTALL_COVERAGE": args.coverage, "SSL_CERT_FILE": str(args.output / "ca.crt"), "LLVM_PROFILE_FILE": str(args.profiles / profile)}
            for key in list(environment):
                if key.startswith("SUDO_") or key.startswith("XDG_") or key.startswith("OMG_TEST"):
                    environment.pop(key)
            expected = (b"possible match", b"1-1", b"https://security.archlinux.org/CVE-OMG-QEMU-616") if args.coverage == "finding" else (b"coverage", b"unknown", b"1-1")
            code, transcript = terminal_case(args.unit, case, environment, expected=expected)
            (args.output / (case + ".log")).write_bytes(transcript)
            (args.output / (case + "-requests.json")).write_text(json.dumps(events[start:], indent=2) + "\n")
            assert code == 0 and b"test result: ok. 1 passed; 0 failed; 0 ignored;" in transcript, transcript.decode(errors="replace")
            assert not any(value in transcript for value in (b"[omg-skip]", b"skipped:", b"LLVM Profile Error", b"LLVM Profile Warning")), transcript.decode(errors="replace")
            marker = re.findall(MARKER.encode() + rb"(\{[^\r\n]*\})", transcript)
            assert len(marker) == 1, "missing or duplicate native state result"
            record = json.loads(marker[0])
            assert record["case"] == case and record["installed"] == (case == "accept")
            assert len(events) == start + 1 and events[-1]["status"] == (503 if args.coverage == "unavailable" else 200), "the default native owner must query the actual HTTPS fixture once"
            records.append(record | {"exit_code": code, "requests": events[start:]})
            (args.output / "receipt.json").write_text(json.dumps(dict(scope="local native owner plus real private-root ALPM install; not full CLI/QEMU/release acceptance", coverage=args.coverage, unit_sha256=sha(args.unit), namespaces=namespaces, cases=records), indent=2) + "\n")
    finally:
        server.shutdown()
        worker.join(timeout=5)
        server.server_close()
    assert len(records) == len(CASES)
    print(json.dumps(dict(passed=len(records), unit_sha256=sha(args.unit), receipt=str(args.output / "receipt.json"))))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unit", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profiles", type=Path)
    parser.add_argument("--coverage", choices=("finding", "unavailable", "unmapped"), default="finding")
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    args.unit = args.unit.resolve(strict=True)
    args.output = args.output.absolute()
    if args.inside:
        inside(args)
        return
    assert os.geteuid() == 0 and args.output.is_absolute() and not args.output.exists()
    assert args.output.parent.resolve(strict=True) == args.output.parent and args.unit.is_file()
    args.output.mkdir(mode=0o700)
    args.profiles = args.profiles.resolve(strict=True) if args.profiles else args.output / "profiles"
    args.profiles.mkdir(exist_ok=True)
    source = oracle()
    originals = {Path(path): sha(Path(path)) for path in ("/etc/hosts", "/etc/nsswitch.conf", "/etc/ssl/certs/ca-certificates.crt")}
    (args.output / "hosts").write_text(source.private_hosts(Path("/etc/hosts").read_text()))
    (args.output / "nsswitch.conf").write_text(source.private_hosts_nss(Path("/etc/nsswitch.conf").read_text()))
    certificates(args.output, source.ARCH_HOST)
    command = ["bwrap", "--die-with-parent", "--unshare-net", "--ro-bind", "/", "/", "--dev-bind", "/dev", "/dev", "--tmpfs", "/root", "--size", str(64 * 1024 * 1024), "--tmpfs", "/tmp", "--tmpfs", "/run", "--bind", str(args.output), str(args.output), "--bind", str(args.profiles), str(args.profiles)]
    for filename, destination in (("hosts", "/etc/hosts"), ("nsswitch.conf", "/etc/nsswitch.conf"), ("ca.crt", "/etc/ssl/certs/ca-certificates.crt")):
        command.extend(["--ro-bind", str(args.output / filename), str(Path(destination).resolve(strict=True))])
    command.extend(["--", "/usr/bin/python3", str(Path(__file__).resolve()), "--inside", "--unit", str(args.unit), "--output", str(args.output), "--profiles", str(args.profiles), "--coverage", args.coverage])
    try:
        result = subprocess.run(command, timeout=180)
        assert result.returncode == 0, "isolated native consent drill failed"
    finally:
        assert all(sha(path) == digest for path, digest in originals.items()), "host configuration changed"


if __name__ == "__main__":
    main()
