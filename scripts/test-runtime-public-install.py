#!/usr/bin/env python3
"""Run fixed-public runtime installers only inside disposable native namespaces."""
import argparse
import gzip
import hashlib
import http.server
from itertools import chain
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import threading
import time
from typing import NamedTuple
import urllib.request
import zlib


class Route(NamedTuple):
    host: str
    path: str
    status: int
    body: bytes


class FileRoute(NamedTuple):
    host: str
    path: str
    status: int
    file: Path
    bytes: int
    sha256: str


MAX_BODY = 4 * 1024 ** 2
MAX_TOTAL_BODY = 8 * 1024 ** 2
MAX_MANIFEST = 33 * 1024 ** 2
MAX_CAPTURE = 128 * 1024
MAX_PROFILES = 512 * 1024 ** 2
SWIFT_INPUTS = Path("/swift-authenticated-inputs")
SWIFT_WORK = Path("/swift-runtime-work")
SWIFT_BUDGET = 8 * 1024 ** 3
SWIFT_OS_RELEASE = 'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\n'
SWIFT_ARCHIVE_URL = "https://download.swift.org/swift-6.0.3-release/ubuntu2404/swift-6.0.3-RELEASE/swift-6.0.3-RELEASE-ubuntu24.04.tar.gz"
SWIFT_SOURCES = {
    "all-keys.asc": ("https://www.swift.org/keys/all-keys.asc", 1024 ** 2, None),
    "swift.tar.gz": (SWIFT_ARCHIVE_URL, 1024 ** 3, 783919592),
    "swift.tar.gz.sig": (SWIFT_ARCHIVE_URL + ".sig", 1024 ** 2, 819),
}
PROVIDERS = ("bun", "deno", "erlang", "github_tool", "go", "php", "python", "ruby", "zig")
HOSTS = (
    "api.github.com", "github.com", "raw.githubusercontent.com", "go.dev", "dl.google.com",
    "www.python.org", "downloads.python.org", "cache.ruby-lang.org", "www.ruby-lang.org",
    "builds.hex.pm", "get.erlware.org", "ziglang.org", "php.net", "www.php.net", "downloads.php.net",
    "download.swift.org", "www.swift.org",
)
ROUTES = Path("/tmp/omg-runtime-public-fixture/routes.json")
PARENT_FILES = ("/etc/hosts", "/etc/nsswitch.conf", "/etc/ssl/certs/ca-certificates.crt")
TMPFS_MIB = {"/tmp": 48, "/root": 8, "/var/lib": 4, "/run": 2, "/var/log": 2}
PUBLIC_IP = "1.1.1.1"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def authenticated_file(file, size, digest):
    require(file in {SWIFT_INPUTS / name for name in SWIFT_SOURCES}, "File route escapes fixed Swift inputs")
    info = file.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
            and info.st_mode & 0o222 == 0, "File route must reference a readonly owned regular input")
    require(type(size) is int and 0 < size <= SWIFT_SOURCES[file.name][1]
            and info.st_size == size, "File route size differs from authenticated input")
    require(type(digest) is str and re.fullmatch(r"[a-f0-9]{64}", digest)
            and sha(file) == digest, "File route hash differs from authenticated input")


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "Duplicate route manifest field")
        value[key] = item
    return value


def parse_routes(raw):
    require(type(raw) is bytes and len(raw) <= MAX_MANIFEST, "Route manifest exceeds its byte bound")
    rows = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    require(type(rows) is list and 0 < len(rows) <= 64, "Route manifest must contain a bounded nonempty list")
    routes = []
    total = 0
    for row in rows:
        require(type(row) is dict and set(row) in ({"host", "path", "status", "body"},
                {"host", "path", "status", "file", "bytes", "sha256"}), "Invalid route schema")
        require(type(row["host"]) is str and row["host"] in HOSTS, "Route host is not a fixed vendor")
        path = row["path"]
        require(type(path) is str and path.startswith("/") and len(path) <= 8192
                and all(33 <= ord(character) <= 126 for character in path)
                and "#" not in path and "\\" not in path, "Invalid exact route path")
        require(type(row["status"]) is int and row["status"] == 200, "Fixture routes require exact successful responses")
        if "body" in row:
            body = row["body"]
            require(type(body) is list and len(body) <= MAX_BODY
                    and all(type(byte) is int and 0 <= byte <= 255 for byte in body), "Invalid bounded route body")
            total += len(body)
            require(total <= MAX_TOTAL_BODY, "Route bodies exceed their total bound")
            routes.append(Route(row["host"], path, row["status"], bytes(body)))
        else:
            require(type(row["file"]) is str, "Invalid exact Swift input pointer")
            file = Path(row["file"])
            authenticated_file(file, row["bytes"], row["sha256"])
            routes.append(FileRoute(row["host"], path, row["status"], file, row["bytes"], row["sha256"]))
    return routes


def route_metadata(route):
    if isinstance(route, FileRoute):
        size, digest = route.bytes, route.sha256
    else:
        size, digest = len(route.body), hashlib.sha256(route.body).hexdigest()
    return {"host": route.host, "path": route.path, "status": route.status,
            "body_bytes": size, "body_sha256": digest}


def write_route(route, stream):
    if isinstance(route, FileRoute):
        count, digest = 0, hashlib.sha256()
        with route.file.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                count += len(chunk)
                require(count <= route.bytes, "Readonly source grew during streaming")
                digest.update(chunk)
                stream.write(chunk)
        require(count == route.bytes and digest.hexdigest() == route.sha256, "Readonly source changed during streaming")
    else:
        stream.write(route.body)


def content_encoding(name, value):
    require(value in (None, "identity", "gzip") and (value != "gzip" or name == "all-keys.asc"),
            "Unsupported official Swift content encoding")
    return value


def validate_representation(path, name, encoding, maximum):
    if content_encoding(name, encoding) == "gzip":
        try:
            with gzip.open(path, "rb") as source:
                decoded = source.read(maximum + 1)
        except (OSError, EOFError, zlib.error) as error:
            raise ValueError("Invalid official Swift gzip representation") from error
        require(0 < len(decoded) <= maximum, "Decoded Swift representation exceeds its bound")


def response_headers(route, sources):
    headers = [("Content-Length", str(route_metadata(route)["body_bytes"]))]
    if isinstance(route, FileRoute):
        source = sources.get(route.file.name)
        require(type(source) is dict and source.get("url") == SWIFT_SOURCES[route.file.name][0]
                and source.get("bytes") == route.bytes and source.get("sha256") == route.sha256,
                "Swift response representation differs from its authenticated input")
        encoding = content_encoding(route.file.name, source.get("content_encoding"))
        require("content_encoding" in source, "Swift input lacks its official representation encoding")
        if encoding is not None:
            headers.append(("Content-Encoding", encoding))
    return headers


def free_bytes(path):
    volume = os.statvfs(path)
    return volume.f_bavail * volume.f_frsize


def disk_bytes(paths):
    total = 0
    for path in paths:
        for entry in chain((path,), path.rglob("*")):
            info = entry.lstat()
            total += max(info.st_size, info.st_blocks * 512)
    return total


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, _request, _response, _code, _message, _headers, _new_url):
        raise ValueError("Official Swift inputs must not redirect")


def download_swift_input(opener, name, output, deadline):
    url, maximum, expected = SWIFT_SOURCES[name]
    request = urllib.request.Request(url, headers={"User-Agent": "omg-native-runtime-proof/1", "Accept-Encoding": "identity"})
    temporary = output / (name + ".part")
    count, digest = 0, hashlib.sha256()
    with opener.open(request, timeout=30) as response:
        require(response.status == 200 and response.geturl() == url, "Official Swift input returned an unexpected URL or status")
        encoding = content_encoding(name, response.headers.get("content-encoding"))
        length = response.headers.get("content-length")
        if length is not None:
            require(re.fullmatch(r"[0-9]+", length) and 0 < int(length) <= maximum, "Official Swift input declared an invalid size")
            require(expected is None or int(length) == expected, "Official Swift archive size differs from the pinned release")
        with temporary.open("xb") as stream:
            while chunk := response.read(1024 * 1024):
                require(time.monotonic() < deadline, "Official Swift preparation exceeded its deadline")
                count += len(chunk)
                require(count <= maximum and (expected is None or count <= expected), "Official Swift input exceeds its bound")
                require(free_bytes(output) >= 20 * 1024 ** 3 + len(chunk), "Official Swift preparation exhausted its host reserve")
                digest.update(chunk)
                stream.write(chunk)
    require(count > 0 and (expected is None or count == expected), "Official Swift input was truncated or has the wrong release size")
    require(length is None or count == int(length), "Official Swift input differs from its declared length")
    validate_representation(temporary, name, encoding, maximum)
    temporary.rename(output / name)
    (output / name).chmod(0o444)
    return {"url": url, "bytes": count, "sha256": digest.hexdigest(), "content_encoding": encoding}


def prepare_swift(output):
    require(not output.exists() and output.parent.resolve(strict=True) == output.parent, "Swift inputs require a new canonical owned directory")
    require(free_bytes(output.parent) >= 20 * 1024 ** 3 + SWIFT_BUDGET, "Swift input preparation lacks its 8 GiB forecast and host reserve")
    if "microsoft" in Path("/proc/sys/kernel/osrelease").read_text().lower():
        require(output.is_relative_to(Path("/mnt/c").resolve(strict=True)), "Local Swift input staging must stay on C")
    output.mkdir(mode=0o700)
    owner = {"purpose": "genuine-swift-public-inputs", "source_commit": os.environ["GITHUB_SHA"], "complete": False,
             "scratch_budget_bytes": SWIFT_BUDGET, "host_reserve_bytes": 20 * 1024 ** 3}
    (output / "owner.json").write_text(json.dumps(owner, indent=2) + "\n")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                       urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=PARENT_FILES[-1])))
    deadline = time.monotonic() + 180
    sources = {name: download_swift_input(opener, name, output, deadline) for name in SWIFT_SOURCES}
    manifest = {"files": {name: {"bytes": source["bytes"], "sha256": source["sha256"]} for name, source in sources.items()}}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    owner.update(complete=True, manifest_sha256=sha(output / "manifest.json"), sources=sources)
    (output / "owner.json").write_text(json.dumps(owner, indent=2) + "\n")
    for file in output.iterdir():
        file.chmod(0o444)
    output.chmod(0o555)
    print(json.dumps({"prepared": "Swift 6.0.3 genuine signed inputs", "manifest_sha256": owner["manifest_sha256"], "bytes": disk_bytes([output])}))


def swift_inputs(source_commit):
    directory = SWIFT_INPUTS.lstat()
    require(stat.S_ISDIR(directory.st_mode) and directory.st_uid == os.geteuid()
            and directory.st_mode & 0o222 == 0, "Swift inputs directory must be readonly and owned")
    for name in ("manifest.json", "owner.json"):
        info = (SWIFT_INPUTS / name).lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
                and info.st_mode & 0o222 == 0 and info.st_size <= 64 * 1024, "Unsafe Swift input metadata")
    owner = json.loads((SWIFT_INPUTS / "owner.json").read_bytes(), object_pairs_hook=unique_object)
    require(type(owner) is dict and owner.get("purpose") == "genuine-swift-public-inputs" and owner.get("complete") is True
            and owner.get("source_commit") == source_commit
            and owner.get("manifest_sha256") == sha(SWIFT_INPUTS / "manifest.json"), "Swift source owner or manifest identity differs")
    require(type(owner.get("sources")) is dict and set(owner["sources"]) == set(SWIFT_SOURCES),
            "Swift source receipt is incomplete or malformed")
    manifest = json.loads((SWIFT_INPUTS / "manifest.json").read_bytes(), object_pairs_hook=unique_object)
    require(type(manifest) is dict and set(manifest) == {"files"}
            and type(manifest["files"]) is dict and set(manifest["files"]) == set(SWIFT_SOURCES), "Incomplete Swift input manifest")
    require({path.name for path in SWIFT_INPUTS.iterdir()} == {*SWIFT_SOURCES, "manifest.json", "owner.json"},
            "Unexpected file in authenticated Swift inputs")
    for name, value in manifest["files"].items():
        require(type(value) is dict and set(value) == {"bytes", "sha256"}, "Invalid Swift file identity")
        authenticated_file(SWIFT_INPUTS / name, value["bytes"], value["sha256"])
        url, _maximum, expected = SWIFT_SOURCES[name]
        require(expected is None or value["bytes"] == expected, "Swift input is not the pinned release")
        source = owner["sources"][name]
        require(type(source) is dict and "content_encoding" in source, "Swift source representation is missing")
        encoding = content_encoding(name, source["content_encoding"])
        require(source == {"url": url, **value, "content_encoding": encoding}, "Swift source receipt does not match its fixed official URL")
        validate_representation(SWIFT_INPUTS / name, name, encoding, _maximum)
    return manifest


def swift_disk_monitor(output, parent_copy_bytes):
    last = -float("inf")

    def check():
        nonlocal last
        require(free_bytes(SWIFT_WORK) >= 20 * 1024 ** 3, "Swift fixture exhausted the backing host reserve")
        if time.monotonic() - last >= 5:
            require(disk_bytes([SWIFT_INPUTS, SWIFT_WORK, output]) + parent_copy_bytes <= SWIFT_BUDGET,
                    "Swift fixture exceeded its 8 GiB owned disk budget including the parent input copy")
            last = time.monotonic()
    return check


def validate_unit_output(output, name, returncode):
    require(len(output) <= MAX_CAPTURE and returncode == 0, "Native unit failed or exceeded capture bound")
    require(re.search(rb"^test result: ok\. 1 passed; 0 failed; 0 ignored;", output, re.M), "Native unit did not execute one successful test")
    require(re.findall(rb"^test (\S+) \.\.\. ok$", output, re.M) == [name.encode()], "Native unit identity differs")
    require(not re.search(rb"\[omg-skip\]|skipped:|LLVM Profile (Error|Warning)", output), "Native unit skipped or produced invalid profile data")


class RouteSession:
    def __init__(self, manifest=ROUTES):
        self.manifest = manifest
        self.routes = None
        self.manifest_sha256 = None
        self.requests = []
        self.errors = []
        self.lock = threading.Lock()

    def request(self, host, path):
        with self.lock:
            if self.routes is None:
                info = self.manifest.lstat()
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                        and info.st_uid == os.geteuid() and info.st_mode & 0o022 == 0
                        and info.st_size <= MAX_MANIFEST, "Unsafe route manifest file")
                raw = self.manifest.read_bytes()
                self.routes = parse_routes(raw)
                self.manifest_sha256 = hashlib.sha256(raw).hexdigest()
            index = len(self.requests)
            require(index < len(self.routes), "Unexpected additional public HTTP request")
            route = self.routes[index]
            require((host, path) == (route.host, route.path), "Public request does not match the next exact vendor route")
            self.requests.append({"index": index, **route_metadata(route)})
            return route

    def fail(self, error):
        with self.lock:
            self.errors.append(str(error)[:500])

    def snapshot(self):
        with self.lock:
            return {"manifest_sha256": self.manifest_sha256, "requests": list(self.requests), "errors": list(self.errors),
                    "declared_routes": [route_metadata(route) for route in self.routes or []]}

    def finish(self):
        with self.lock:
            require(not self.errors, "Public TLS fixture failed: " + "; ".join(self.errors))
            require(self.routes is not None and len(self.requests) == len(self.routes), "Declared public routes were not all consumed")
            require(sha(self.manifest) == self.manifest_sha256, "Route manifest changed during execution")
            return {"manifest_sha256": self.manifest_sha256, "requests": list(self.requests)}


def profile_bytes(profiles):
    paths = list(profiles.glob("omg-fixture-runtime_public_*.profraw"))
    require(all(path.is_file() and not path.is_symlink() for path in paths), "Unsafe public fixture profile")
    total = sum(path.stat().st_size for path in paths)
    require(total <= MAX_PROFILES, "Public fixture profiles exceed their owned size budget")
    return total


def bounded_command(command, environment, log, profiles, timeout=35, check_resources=None):
    output = bytearray()
    process = subprocess.Popen(["/usr/bin/setpriv", "--pdeathsig", "KILL", "--", *command], env=environment, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    settled = False
    deadline = time.monotonic() + timeout
    try:
        require(process.stdout is not None, "Missing native process capture")
        with selectors.DefaultSelector() as reader, log.open("xb") as capture:
            reader.register(process.stdout, selectors.EVENT_READ)
            while reader.get_map() or process.poll() is None:
                require(time.monotonic() < deadline, "Native public fixture exceeded its deadline")
                profile_bytes(profiles)
                if check_resources is not None:
                    check_resources()
                for key, _ in reader.select(min(0.05, max(0, deadline - time.monotonic()))):
                    chunk = os.read(key.fileobj.fileno(), 8192)
                    if not chunk:
                        reader.unregister(key.fileobj)
                        continue
                    require(len(output) + len(chunk) <= MAX_CAPTURE, "Native public fixture exceeded capture bound")
                    output.extend(chunk)
                    capture.write(chunk)
            code = process.wait(timeout=5)
            profile_bytes(profiles)
            settled = True
            return code, bytes(output)
    finally:
        if not settled:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                if process.poll() is None:
                    process.kill()
        process.wait(timeout=5)
        if process.stdout is not None:
            process.stdout.close()


def certificate(output):
    def run(arguments):
        subprocess.run(arguments, check=True, capture_output=True, timeout=30)
    run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=OMG disposable runtime CA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", str(output / "ca.key"), "-out", str(output / "ca.crt")])
    run(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=api.github.com", "-keyout", str(output / "server.key"), "-out", str(output / "server.csr")])
    (output / "server.ext").write_text("subjectAltName=" + ",".join("DNS:" + host for host in HOSTS) + "\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
    run(["openssl", "x509", "-req", "-in", str(output / "server.csr"), "-CA", str(output / "ca.crt"), "-CAkey", str(output / "ca.key"), "-CAcreateserial", "-days", "1", "-extfile", str(output / "server.ext"), "-out", str(output / "server.crt")])


def inside(args):
    require(os.geteuid() == 0 and os.statvfs("/").f_flag & os.ST_RDONLY, "Public fixture needs an isolated read-only root")
    owner = json.loads((args.output / "owner.json").read_text())
    require(owner["purpose"] == "runtime-public-install" and sha(args.unit) == owner["unit_sha256"], "Public fixture owner or binary differs")
    require(owner.get("phase") == ("swift" if args.swift_only else "small"), "Public fixture phase differs")
    check_resources = None
    swift_sources = {}
    if args.swift_only:
        require(os.uname().machine == "x86_64" and Path("/etc/os-release").read_text() == SWIFT_OS_RELEASE,
                "Genuine Swift fixture requires its private Ubuntu 24.04 x86_64 identity")
        require(os.statvfs(SWIFT_INPUTS).f_flag & os.ST_RDONLY, "Genuine Swift inputs must be mounted readonly")
        manifest = swift_inputs(owner["source_commit"])
        swift_sources = json.loads((SWIFT_INPUTS / "owner.json").read_bytes(), object_pairs_hook=unique_object)["sources"]
        require(sha(SWIFT_INPUTS / "manifest.json") == owner["swift_inputs_manifest_sha256"], "Genuine Swift inputs changed across namespace setup")
        check_resources = swift_disk_monitor(args.output, owner["swift_parent_copy_bytes"])
        check_resources()
    namespaces = {kind: os.readlink("/proc/self/ns/" + kind) for kind in ("mnt", "net")}
    require(all(value != os.readlink("/proc/1/ns/" + kind) for kind, value in namespaces.items()), "Private mount and network namespaces are required")
    mounts = Path("/proc/self/mountinfo").read_text().splitlines()
    for path, mib in TMPFS_MIB.items():
        require(any(line.split()[4] == path and line.split(" - ", 1)[1].split()[0] == "tmpfs" for line in mounts), "Private fixture path lacks tmpfs")
        fs = os.statvfs(path)
        require(fs.f_blocks * fs.f_frsize <= mib * 1024 ** 2, "Private tmpfs exceeds its budget")
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True, capture_output=True, timeout=5)
    subprocess.run(["ip", "addr", "add", PUBLIC_IP + "/32", "dev", "lo"], check=True, capture_output=True, timeout=5)
    links = json.loads(subprocess.check_output(["ip", "-j", "link"], timeout=5))
    routes = json.loads(subprocess.check_output(["ip", "-j", "route", "show", "table", "all"], timeout=5))
    require([link["ifname"] for link in links] == ["lo"] and all(route.get("dev") == "lo" for route in routes), "Public fixture has an external network route")
    for host in HOSTS:
        require({row[4][0] for row in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)} == {PUBLIC_IP}, "Fixed vendor DNS differs from isolated public address")
    os.umask(0o077)
    ROUTES.parent.mkdir(mode=0o700)
    Path("/tmp/empty-ca").mkdir()
    environment = {"HOME": "/root", "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TMPDIR": "/tmp",
                   "SSL_CERT_FILE": str(args.output / "ca.crt"), "SSL_CERT_DIR": "/tmp/empty-ca",
                   "OMG_RUNTIME_PUBLIC_FIXTURE": "isolated-namespaces", "GITHUB_SHA": owner["source_commit"],
                   "LLVM_PROFILE_FILE": str(args.profiles / ("omg-fixture-runtime_public_swift_registry-%p-%m.profraw" if args.swift_only else "omg-fixture-runtime_public_registry-%p-%m.profraw"))}
    code, registry = bounded_command([str(args.unit), "--list", "--ignored", "--format", "terse"], environment,
                                     args.output / "registry.log", args.profiles)
    require(code == 0, "Native unit registry failed")
    names = {provider: f"runtimes::{provider}::tests::native_public_install_preserves_authenticated_download_boundary" for provider in PROVIDERS}
    if args.swift_only:
        names = {"swift": "runtimes::swift::tests::genuine_public_install_refuses_changed_signed_content"}
    for name in names.values():
        require(registry.splitlines().count((name + ": test").encode()) == 1, "Missing or duplicate ignored public installer test: " + name)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.output / "server.crt", args.output / "server.key")
    state = {"session": RouteSession()}

    def select_host(_stream, host, _context):
        if host not in HOSTS:
            state["session"].fail("TLS SNI differs from fixed vendor allowlist")
            raise ssl.SSLError("Unrecognized fixture SNI")
    context.set_servername_callback(select_host)

    class Server(http.server.ThreadingHTTPServer):
        daemon_threads = False

        def get_request(self):
            stream, address = super().get_request()
            stream.settimeout(5)
            try:
                return context.wrap_socket(stream, server_side=True), address
            except (OSError, ssl.SSLError) as error:
                state["session"].fail(error)
                stream.close()
                raise

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_arguments):
            return

        def send_error(self, code, message=None, explain=None):
            state["session"].fail(f"Unexpected HTTP protocol or method: {code}")
            super().send_error(code, message, explain)

        def do_GET(self):
            try:
                route = state["session"].request(self.headers.get("Host"), self.path)
                self.send_response(route.status)
                for name, value in response_headers(route, swift_sources):
                    self.send_header(name, value)
                self.send_header("Connection", "close")
                self.end_headers()
                write_route(route, self.wfile)
            except (ValueError, OSError) as error:
                state["session"].fail(error)
                self.close_connection = True

    server = Server((PUBLIC_IP, 443), Handler)
    worker = threading.Thread(target=server.serve_forever)
    worker.start()
    cases = []
    try:
        for provider, name in names.items():
            prefix = "omg-fixture-runtime_public_" + provider + "-"
            require(not list(args.profiles.glob(prefix + "*.profraw")), "Native public profiles must be fresh")
            require(not ROUTES.exists(), "Prior route manifest was not retired")
            state["session"] = RouteSession()
            environment["LLVM_PROFILE_FILE"] = str(args.profiles / (prefix + "%p-%m.profraw"))
            try:
                code, output = bounded_command([str(args.unit), "--exact", name, "--ignored", "--test-threads=1"],
                                                environment, args.output / (provider + ".log"), args.profiles,
                                                timeout=180 if args.swift_only else 35, check_resources=check_resources)
                validate_unit_output(output, name, code)
                consumed = state["session"].finish()
            finally:
                (args.output / (provider + "-routes.json")).write_text(json.dumps(state["session"].snapshot(), indent=2) + "\n")
            profiles = sorted(args.profiles.glob(prefix + "*.profraw"))
            require(profiles and all(path.is_file() and not path.is_symlink() and path.stat().st_size > 0 for path in profiles), "Native public test lacks fresh profile evidence")
            case = {"provider": provider, "test": name, "result": "PASS", "attempts": 1, **consumed,
                    "profiles": [{"path": str(path), "bytes": path.stat().st_size, "sha256": sha(path)} for path in profiles]}
            (args.output / (provider + ".json")).write_text(json.dumps(case, indent=2) + "\n")
            cases.append(case)
            ROUTES.unlink()
    finally:
        server.shutdown()
        worker.join(timeout=5)
        require(not worker.is_alive(), "Public TLS fixture server did not settle")
        server.server_close()
    require(len(cases) == len(names), "Public installer coverage is incomplete")
    require(sha(args.unit) == owner["unit_sha256"], "Native unit changed during public fixture execution")
    receipt = {"scope": "Actual fixed-public installer boundaries in isolated native namespaces; not full release acceptance",
               "result": "PASS", "source_commit": owner["source_commit"], "unit_sha256": owner["unit_sha256"],
               "driver_sha256": sha(Path(__file__).resolve()), "namespaces": namespaces, "links": links, "routes": routes,
               "tmpfs_budget_bytes": sum(TMPFS_MIB.values()) * 1024 ** 2, "profiles_budget_bytes": MAX_PROFILES,
               "profile_bytes": profile_bytes(args.profiles), "cases": cases}
    if args.swift_only:
        check_resources()
        receipt.update(scope="Genuine Swift vendor-signed archive authentication and extraction followed by owned staging-tamper refusal; no SDK execution or smoke success",
                       swift_input_manifest_sha256=owner["swift_inputs_manifest_sha256"], swift_disk_budget_bytes=SWIFT_BUDGET,
                       swift_parent_copy_bytes=owner["swift_parent_copy_bytes"], swift_inputs=manifest)
        receipt["swift_source_representations"] = swift_sources
    (args.output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"passed": len(cases), "receipt": str(args.output / "receipt.json")}))


def namespace_command(args, swift=False):
    argv = ["bwrap", "--die-with-parent", "--unshare-net", "--ro-bind", "/", "/", "--dev-bind", "/dev", "/dev",
            "--bind", str(args.output), str(args.output), "--bind", str(args.profiles), str(args.profiles)]
    for destination, mib in TMPFS_MIB.items():
        argv += ["--size", str(mib * 1024 ** 2), "--tmpfs", destination]
    for name, destination in (("hosts", "/etc/hosts"), ("nsswitch.conf", "/etc/nsswitch.conf"), ("ca.crt", "/etc/ssl/certs/ca-certificates.crt")):
        argv += ["--ro-bind", str(args.output / name), str(Path(destination).resolve(strict=True))]
    if swift:
        argv += ["--ro-bind", str(SWIFT_INPUTS), str(SWIFT_INPUTS), "--bind", str(SWIFT_WORK), str(SWIFT_WORK),
                 "--ro-bind", str(args.output / "os-release"), str(Path("/etc/os-release").resolve(strict=True))]
    argv += ["--", "/usr/bin/python3", str(Path(__file__).resolve()), "--inside", "--unit", str(args.unit), "--output", str(args.output), "--profiles", str(args.profiles)]
    if swift:
        argv.append("--swift-only")
    return argv


def run_swift(args, owner):
    manifest = swift_inputs(owner["source_commit"])
    require(not SWIFT_WORK.exists() and not SWIFT_WORK.is_symlink(), "Swift work directory must be new")
    parent_copy_bytes = disk_bytes([SWIFT_INPUTS]) + 64 * 1024
    remaining = SWIFT_BUDGET - 2 * parent_copy_bytes
    require(remaining > 0 and free_bytes(Path("/")) >= 20 * 1024 ** 3 + remaining,
            "Genuine Swift work lacks its remaining disk forecast and backing host reserve")
    SWIFT_WORK.mkdir(mode=0o700)
    work_owner = {"purpose": "swift-public-install", "source_commit": owner["source_commit"], "unit_sha256": owner["unit_sha256"]}
    marker = SWIFT_WORK / ".omg-runtime-public-owner.json"
    marker.write_text(json.dumps(work_owner, indent=2) + "\n")
    output = args.output / "swift"
    output.mkdir(mode=0o700)
    swift_args = argparse.Namespace(unit=args.unit, output=output, profiles=args.profiles)
    swift_owner = {**owner, "phase": "swift", "swift_inputs_manifest_sha256": sha(SWIFT_INPUTS / "manifest.json"),
                   "swift_parent_copy_bytes": parent_copy_bytes}
    (output / "owner.json").write_text(json.dumps(swift_owner, indent=2) + "\n")
    for name in ("hosts", "nsswitch.conf", "ca.crt", "server.crt", "server.key"):
        shutil.copyfile(args.output / name, output / name)
    (output / "os-release").write_text(SWIFT_OS_RELEASE)
    (output / "swift-input-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    shutil.copyfile(SWIFT_INPUTS / "owner.json", output / "swift-input-owner.json")
    for name in ("all-keys.asc", "swift.tar.gz.sig"):
        shutil.copyfile(SWIFT_INPUTS / name, output / name)
    result = subprocess.run(namespace_command(swift_args, swift=True), timeout=220)
    require(result.returncode == 0, "Genuine Swift authenticated-content refusal fixture failed")
    receipt = json.loads((output / "receipt.json").read_text())
    require(receipt.get("result") == "PASS" and len(receipt.get("cases", [])) == 1, "Genuine Swift success evidence is missing")
    require(not SWIFT_WORK.is_symlink() and SWIFT_WORK.parent == Path("/")
            and json.loads(marker.read_text()) == work_owner, "Swift scratch owner changed before retirement")
    retirement = {"superseded_by": "receipt.json genuine signed-content refusal proof", "work_path": str(SWIFT_WORK),
                  "generated_work_bytes": disk_bytes([SWIFT_WORK]), "retired_inputs": manifest["files"],
                  "parent_input_copy_preserved_for_controller_retirement": True}
    shutil.rmtree(SWIFT_WORK)
    for name in SWIFT_SOURCES:
        file = SWIFT_INPUTS / name
        authenticated_file(file, manifest["files"][name]["bytes"], manifest["files"][name]["sha256"])
        file.unlink()
    (output / "retirement.json").write_text(json.dumps(retirement, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unit", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profiles", type=Path)
    parser.add_argument("--prepare-swift", action="store_true")
    parser.add_argument("--include-swift", action="store_true")
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--swift-only", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    require(sys.platform == "linux", "Runtime fixture preparation requires native Linux")
    require(re.fullmatch(r"[a-f0-9]{40}", os.environ.get("GITHUB_SHA", "")), "Missing exact source revision")
    if args.prepare_swift:
        require(args.unit is None and args.profiles is None and not args.inside and not args.include_swift and not args.swift_only,
                "Swift source preparation must be separate from native execution")
        prepare_swift(args.output.absolute())
        return
    require(sys.platform == "linux" and os.geteuid() == 0, "Public runtime fixtures require native Linux root namespaces")
    require(args.unit is not None and args.profiles is not None, "Native execution requires unit and profile paths")
    require(args.unit.is_file() and not args.unit.is_symlink() and os.access(args.unit, os.X_OK), "Unsafe or missing native unit")
    args.unit = args.unit.resolve(strict=True)
    args.output = args.output.absolute()
    args.profiles = args.profiles.resolve(strict=True)
    if args.inside:
        inside(args)
        return
    require(re.fullmatch(r"[a-f0-9]{40}", os.environ.get("GITHUB_SHA", "")), "Missing exact source revision")
    require(not args.output.exists() and args.output.parent.resolve(strict=True) == args.output.parent, "Output must be new under a canonical owned parent")
    require(args.profiles.is_dir(), "Profile output directory is missing")
    require(not list(args.profiles.glob("omg-fixture-runtime_public_*.profraw")), "Public profile wave must be fresh")
    guest = os.statvfs("/")
    require(guest.f_bavail * guest.f_frsize >= 2 * 1024 ** 3 + sum(TMPFS_MIB.values()) * 1024 ** 2, "Insufficient native guest reserve")
    if "microsoft" in Path("/proc/sys/kernel/osrelease").read_text().lower():
        backing = Path("/mnt/c").resolve(strict=True)
        require(args.output.is_relative_to(backing) and args.profiles.is_relative_to(backing), "Local native evidence and profiles must stay on C")
    else:
        backing = args.profiles
    host = os.statvfs(backing)
    require(host.f_bavail * host.f_frsize >= 20 * 1024 ** 3 + MAX_PROFILES, "Insufficient backing host reserve")
    originals = {path: sha(Path(path)) for path in (*PARENT_FILES, "/etc/os-release")}
    args.output.mkdir(mode=0o700)
    owner = {"purpose": "runtime-public-install", "phase": "small", "source_commit": os.environ["GITHUB_SHA"], "unit_sha256": sha(args.unit), "parent_hashes": originals}
    (args.output / "owner.json").write_text(json.dumps(owner, indent=2) + "\n")
    try:
        certificate(args.output)
        hosts = Path("/etc/hosts").read_text()
        require(all(not re.search(r"(?:^|\s)" + re.escape(host) + r"(?:\s|$)", hosts) for host in HOSTS), "A fixed vendor host is already mapped")
        (args.output / "hosts").write_text(hosts + "\n" + PUBLIC_IP + " " + " ".join(HOSTS) + "\n")
        nss, count = re.subn(r"(?m)^hosts:[^\n]*$", "hosts: files", Path("/etc/nsswitch.conf").read_text())
        require(count == 1, "Native NSS must contain exactly one hosts service")
        (args.output / "nsswitch.conf").write_text(nss)
        result = subprocess.run(namespace_command(args), timeout=360)
        require(result.returncode == 0, "Public runtime installer fixture failed")
        if args.include_swift:
            run_swift(args, owner)
    finally:
        require({path: sha(Path(path)) for path in originals} == originals, "Parent hosts, NSS, OS identity or trust configuration changed")
        (args.output / "parent-trust-unchanged.json").write_text(json.dumps({"parent_configuration_unchanged": True, "sha256": originals}, indent=2) + "\n")


if __name__ == "__main__":
    main()
