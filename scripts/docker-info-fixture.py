#!/usr/bin/env python3
"""Run real Arch info absence and untrusted-TLS refusal in a private HTTPS fixture."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import threading

from qemu_aur_fixture import FixtureServer


QUERY = "package-does-not-exist-xyz"
RESPONSE = b'{"version":5,"type":"search","resultcount":0,"results":[]}'


def main():
    assert os.getuid() != 0, "the product must run as an ordinary user"
    before = subprocess.check_output(["pacman", "-Q"])
    with tempfile.TemporaryDirectory(prefix="omg-docker-info-") as directory:
        state = Path(directory)
        ca, key, cert = state / "ca.pem", state / "server.key", state / "server.pem"
        commands = [
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(state / "ca.key"), "-out", str(ca), "-subj", "/CN=OMG-Info-Fixture-CA",
             "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-days", "1"],
            ["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
             "-out", str(state / "server.csr"), "-subj", "/CN=aur.archlinux.org",
             "-addext", "subjectAltName=DNS:aur.archlinux.org", "-addext", "basicConstraints=critical,CA:FALSE",
             "-addext", "extendedKeyUsage=serverAuth", "-addext", "keyUsage=digitalSignature,keyEncipherment"],
            ["openssl", "x509", "-req", "-in", str(state / "server.csr"), "-CA", str(ca),
             "-CAkey", str(state / "ca.key"), "-CAcreateserial", "-out", str(cert), "-days", "1", "-copy_extensions", "copy"],
        ]
        for command in commands:
            subprocess.run(command, check=True, capture_output=True, timeout=10)
        for trusted in (False, True):
            log = state / ("trusted.jsonl" if trusted else "untrusted.jsonl")
            with FixtureServer(("127.0.0.1", 0), cert, key, log,
                               query=QUERY, response=RESPONSE) as server:
                worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
                worker.start()
                try:
                    proxy = f"http://127.0.0.1:{server.server_address[1]}"
                    env = dict(os.environ, HTTPS_PROXY=proxy, https_proxy=proxy, ALL_PROXY=proxy,
                               all_proxy=proxy, NO_PROXY="", no_proxy="", OMG_TEST_MODE="0",
                               OMG_DISABLE_DAEMON="1", OMG_DISABLE_TELEMETRY="1")
                    env["SSL_CERT_FILE"] = str(ca) if trusted else "/etc/ssl/certs/ca-certificates.crt"
                    result = subprocess.run(["/usr/local/bin/omg", "info", QUERY], env=env,
                                            capture_output=True, text=True, timeout=30)
                finally:
                    server.shutdown()
                    worker.join(timeout=5)
                    assert not worker.is_alive(), "fixture did not stop"
            plain = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", result.stdout + result.stderr)
            print(json.dumps({"trusted": trusted, "exit": result.returncode, "output": plain}), flush=True)
            assert result.returncode == 1, plain
            events = [json.loads(line) for line in log.read_text().splitlines()]
            assert events[0] == {"event": "connect", "value": "aur.archlinux.org:443"}, events
            if trusted:
                assert "Package 'package-does-not-exist-xyz' not found" in plain, plain
                assert "transport failed" not in plain, plain
                assert events == [events[0], {"event": "request", "value": "/rpc?v=5&type=search&arg=package-does-not-exist-xyz"}], events
            else:
                assert "AUR RPC transport failed" in plain and "not found" not in plain, plain
                assert events == [events[0], {"event": "error", "value": "SSLError"}], events
            assert subprocess.check_output(["pacman", "-Q"]) == before, "lookup changed installed packages"
    print("INFO_FIXTURE_PASS missing=1 untrusted_tls=1 native_state_unchanged=1", flush=True)


if __name__ == "__main__":
    main()
