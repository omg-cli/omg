#!/usr/bin/env python3
"""Private TLS CONNECT proxy for a QEMU Doctor fallback probe."""

import argparse
import json
from pathlib import Path
import socketserver
import ssl
import threading


def read_headers(stream):
    line = stream.readline(4097)
    if not line or len(line) > 4096:
        raise ValueError("missing or oversized request line")
    headers = []
    for _ in range(64):
        header = stream.readline(4097)
        if len(header) > 4096:
            raise ValueError("oversized header")
        if header in (b"\r\n", b"\n"):
            return line, headers
        if not header:
            raise ValueError("incomplete headers")
        headers.append(header)
    raise ValueError("too many headers")


class FixtureServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, cert, key, log, primary, mode):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)
        self.log_path = Path(log)
        self.log_lock = threading.Lock()
        self.primary_seen = threading.Event()
        self.primary = primary
        self.mode = mode
        super().__init__(address, FixtureHandler)

    def record(self, event, host):
        with self.log_lock:
            with self.log_path.open("a", encoding="utf-8") as output:
                output.write(json.dumps({"event": event, "host": host}) + "\n")


class FixtureHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        host = "unknown"
        try:
            connect, _ = read_headers(self.request.makefile("rb"))
            parts = connect.decode("ascii", "strict").strip().split()
            if len(parts) != 3 or parts[0] != "CONNECT":
                self.server.record("unexpected", "malformed-connect")
                return
            host_port = parts[1]
            if not host_port.endswith(":443"):
                self.server.record("unexpected", host_port)
                return
            host = host_port[:-4]
            if host not in ("fixture.invalid", self.server.primary, "kernel.org"):
                self.server.record("unexpected", host)
                self.request.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                return
            self.server.record("connect", host)
            healthy = (host == "fixture.invalid" or
                       (self.server.mode == "primary" and host == self.server.primary) or
                       (self.server.mode == "alternate" and host == "kernel.org"))
            if not healthy:
                self.server.record("denied", host)
                self.request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
                if host == self.server.primary:
                    # Release the alternate only after the primary denial is
                    # both logged and sent; the checker copies this log as soon
                    # as Doctor exits.
                    self.server.primary_seen.set()
                return
            if host == "kernel.org" and self.server.mode == "alternate":
                # The healthy alternate must not finish before the primary is
                # observed. This makes the product race deterministic.
                if not self.server.primary_seen.wait(3):
                    self.server.record("missing-primary", host)
                    self.request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
                    return
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            with self.server.context.wrap_socket(self.request, server_side=True) as tls:
                request, headers = read_headers(tls.makefile("rb"))
                request_parts = request.decode("ascii", "strict").strip().split()
                expected_path = "/ready" if host == "fixture.invalid" else "/"
                expected_hosts = {("Host: " + host).lower().encode(),
                                  ("Host: " + host + ":443").lower().encode()}
                if (len(request_parts) != 3 or request_parts[:2] != ["GET", expected_path] or
                        not expected_hosts.intersection(header.strip().lower() for header in headers)):
                    self.server.record("unexpected", host)
                    tls.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                    return
                self.server.record("request", host)
                tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        except (OSError, ValueError, ssl.SSLError) as error:
            self.server.record("error", host + ":" + type(error).__name__)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--port-file", required=True)
    parser.add_argument("--primary", required=True, choices=("archlinux.org", "github.com"))
    parser.add_argument("--mode", required=True, choices=("primary", "alternate"))
    args = parser.parse_args()
    with FixtureServer(("127.0.0.1", 0), args.cert, args.key, args.log, args.primary, args.mode) as server:
        Path(args.port_file).write_text(str(server.server_address[1]), encoding="ascii")
        server.serve_forever(poll_interval=0.1)


if __name__ == "__main__":
    main()
