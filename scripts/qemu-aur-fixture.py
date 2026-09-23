#!/usr/bin/env python3
"""Loopback HTTPS proxy serving one deterministic AUR RPC search response."""

import argparse
import json
from pathlib import Path
import socketserver
import ssl
import threading
from urllib.parse import parse_qs, urlsplit


QUERY = "omgqemuaurprobe"
PACKAGE = "omgqemuaurprobe-fixture"
RESPONSE = json.dumps(
    {
        "version": 5,
        "type": "search",
        "resultcount": 1,
        "results": [
            {
                "Name": PACKAGE,
                "Version": "9.8.7-1",
                "Description": "Deterministic QEMU AUR flag fixture",
                "Maintainer": "omg-qemu-fixture",
                "NumVotes": 17,
                "Popularity": 1.25,
                "OutOfDate": 1700000000,
                "FirstSubmitted": 1600000000,
                "LastModified": 1700000000,
                "URL": "https://example.org/omg-qemu-fixture",
                "Depends": [],
                "License": ["MIT"],
            }
        ],
    },
    separators=(",", ":"),
).encode()


def read_headers(stream):
    line = stream.readline(4097)
    if len(line) > 4096:
        raise ValueError("oversized request line")
    headers = []
    for _ in range(64):
        header = stream.readline(4097)
        if len(header) > 4096:
            raise ValueError("oversized header")
        if header in (b"\r\n", b"\n", b""):
            return line, headers
        headers.append(header)
    raise ValueError("too many headers")


class FixtureServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, cert, key, log):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)
        self.log_path = Path(log)
        self.log_lock = threading.Lock()
        super().__init__(address, FixtureHandler)

    def record(self, event, value):
        with self.log_lock:
            with self.log_path.open("a", encoding="utf-8") as output:
                output.write(json.dumps({"event": event, "value": value}) + "\n")


class FixtureHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            connect, _ = read_headers(self.request.makefile("rb"))
            parts = connect.decode("ascii", "strict").strip().split()
            if len(parts) != 3 or parts[:2] != ["CONNECT", "aur.archlinux.org:443"]:
                self.server.record("rejected-connect", connect.decode("ascii", "replace").strip())
                self.request.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                return
            self.server.record("connect", "aur.archlinux.org:443")
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            with self.server.context.wrap_socket(self.request, server_side=True) as tls:
                request, _ = read_headers(tls.makefile("rb"))
                parts = request.decode("ascii", "strict").strip().split()
                if len(parts) != 3 or parts[0] != "GET":
                    self.server.record("rejected-request", request.decode("ascii", "replace").strip())
                    return
                parsed = urlsplit(parts[1])
                query = parse_qs(parsed.query)
                if parsed.path != "/rpc" or query != {"v": ["5"], "type": ["search"], "arg": [QUERY]}:
                    self.server.record("rejected-request", parts[1])
                    tls.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                    return
                self.server.record("request", parts[1])
                tls.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                    + str(len(RESPONSE)).encode()
                    + b"\r\nConnection: close\r\n\r\n"
                    + RESPONSE
                )
        except (OSError, ValueError, ssl.SSLError) as error:
            self.server.record("error", type(error).__name__)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--port-file", required=True)
    args = parser.parse_args()
    with FixtureServer(("127.0.0.1", 0), args.cert, args.key, args.log) as server:
        Path(args.port_file).write_text(str(server.server_address[1]), encoding="ascii")
        server.serve_forever(poll_interval=0.1)


if __name__ == "__main__":
    main()
