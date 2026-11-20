"""Controls for the native public-runtime fixture driver, not installer acceptance."""
import importlib.util
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import textwrap
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("runtime_public_driver", Path(__file__).with_name("test-runtime-public-install.py"))
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)


def route(host="github.com", path="/release/archive.zip", body=None):
    return dict(host=host, path=path, status=200, body=[0, 1, 255] if body is None else body)


class PublicRuntimeDriver(unittest.TestCase):
    def test_java_public_installer_requires_fixed_adoptium_metadata_route(self):
        self.assertIn("java", DRIVER.PROVIDERS)
        self.assertIn("api.adoptium.net", DRIVER.HOSTS)
        metadata = route(host="api.adoptium.net", path="/v3/assets/latest/21/hotspot?architecture=x64&image_type=jdk&os=linux&vendor=eclipse")
        parsed, = DRIVER.parse_routes(json.dumps([metadata]).encode())
        self.assertEqual((parsed.host, parsed.path, parsed.body),
                         (metadata["host"], metadata["path"], bytes(metadata["body"])))

    @unittest.skipIf(os.name == "nt", "Native mounts and input ownership require POSIX")
    def test_swift_namespace_adds_only_private_disk_work_inputs_and_os_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = SimpleNamespace(output=root / "evidence", profiles=root / "profiles", unit=root / "unit")
            normal = DRIVER.namespace_command(args)
            swift = DRIVER.namespace_command(args, swift=True)
            self.assertIn("--unshare-net", normal)
            self.assertEqual(normal[normal.index("--ro-bind"):][:3], ["--ro-bind", "/", "/"])
            self.assertNotIn(str(DRIVER.SWIFT_WORK), normal)
            self.assertNotIn(str(DRIVER.SWIFT_INPUTS), normal)
            self.assertNotIn("--swift-only", normal)
            for triple in (["--bind", str(DRIVER.SWIFT_WORK), str(DRIVER.SWIFT_WORK)],
                           ["--ro-bind", str(DRIVER.SWIFT_INPUTS), str(DRIVER.SWIFT_INPUTS)],
                           ["--ro-bind", str(args.output / "os-release"), str(Path("/etc/os-release").resolve(strict=True))]):
                self.assertTrue(any(swift[index:index + 3] == triple for index in range(len(swift))))
            self.assertIn("--swift-only", swift)
            self.assertEqual(sum(int(normal[index + 1]) for index, value in enumerate(normal) if value == "--size"), 64 * 1024 ** 2)

    @unittest.skipIf(os.name == "nt", "Authenticated metadata requires POSIX ownership")
    def test_swift_input_manifest_requires_matching_owned_complete_source_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commit = "a" * 40
            sources = {name: (url, maximum, None) for name, (url, maximum, _expected) in DRIVER.SWIFT_SOURCES.items()}
            files = {}
            for name in sources:
                path = root / name
                path.write_bytes(name.encode())
                path.chmod(0o444)
                files[name] = {"bytes": path.stat().st_size, "sha256": DRIVER.sha(path)}
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"files": files}))
            manifest.chmod(0o444)
            owner = {"purpose": "genuine-swift-public-inputs", "source_commit": commit, "complete": True,
                     "manifest_sha256": DRIVER.sha(manifest),
                     "sources": {name: {"url": sources[name][0], **identity, "content_encoding": None} for name, identity in files.items()}}
            path = root / "owner.json"
            try:
                with patch.object(DRIVER, "SWIFT_INPUTS", root), patch.object(DRIVER, "SWIFT_SOURCES", sources):
                    for changed in [owner, dict(owner, sources=[]), dict(owner, sources={}),
                                    dict(owner, complete=False), dict(owner, source_commit="b" * 40),
                                    dict(owner, manifest_sha256="0" * 64)]:
                        root.chmod(0o700)
                        if path.exists():
                            path.chmod(0o600)
                        path.write_text(json.dumps(changed))
                        path.chmod(0o444)
                        root.chmod(0o555)
                        if changed is owner:
                            self.assertEqual(DRIVER.swift_inputs(commit), {"files": files})
                        else:
                            with self.subTest(changed=changed), self.assertRaises(ValueError):
                                DRIVER.swift_inputs(commit)
            finally:
                root.chmod(0o700)

    @unittest.skipIf(os.name == "nt", "Authenticated file routes require native POSIX metadata")
    def test_file_routes_bind_only_exact_readonly_inputs_size_and_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "all-keys.asc"
            body = b"controlled input bytes"
            path.write_bytes(body)
            path.chmod(0o444)
            row = dict(host="www.swift.org", path="/keys/all-keys.asc", status=200,
                       file=str(path), bytes=len(body), sha256=hashlib.sha256(body).hexdigest())
            with patch.object(DRIVER, "SWIFT_INPUTS", root):
                self.assertEqual(DRIVER.parse_routes(json.dumps([row]).encode()), [
                    DRIVER.FileRoute("www.swift.org", "/keys/all-keys.asc", 200, path, len(body), hashlib.sha256(body).hexdigest())])
                for changed in [dict(row, file=str(root.parent / "all-keys.asc")),
                                dict(row, file=str(root / ".." / root.name / "all-keys.asc")),
                                dict(row, bytes=len(body) + 1), dict(row, bytes=True),
                                dict(row, sha256="0" * 64), dict(row, sha256="g" * 64)]:
                    with self.subTest(changed=changed), self.assertRaises(ValueError):
                        DRIVER.parse_routes(json.dumps([changed]).encode())
                path.chmod(0o644)
                with self.assertRaisesRegex(ValueError, "readonly"):
                    DRIVER.parse_routes(json.dumps([row]).encode())
                path.chmod(0o444)
                target = root / "actual-keys"
                path.rename(target)
                path.symlink_to(target)
                with self.assertRaisesRegex(ValueError, "readonly"):
                    DRIVER.parse_routes(json.dumps([row]).encode())
                path.unlink()
                os.link(target, path)
                with self.assertRaisesRegex(ValueError, "readonly"):
                    DRIVER.parse_routes(json.dumps([row]).encode())

    @unittest.skipIf(os.name == "nt", "Authenticated file routes require native POSIX metadata")
    def test_file_stream_matches_admitted_bytes_and_refuses_changed_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "all-keys.asc"
            path.write_bytes(b"keys")
            path.chmod(0o444)
            route = DRIVER.FileRoute("www.swift.org", "/keys/all-keys.asc", 200, path, 4, hashlib.sha256(b"keys").hexdigest())
            output = io.BytesIO()
            DRIVER.write_route(route, output)
            self.assertEqual(output.getvalue(), b"keys")
            path.chmod(0o644)
            path.write_bytes(b"evil")
            path.chmod(0o444)
            with self.assertRaisesRegex(ValueError, "changed"):
                DRIVER.write_route(route, io.BytesIO())

    def test_swift_preparer_pins_url_status_release_size_and_stream_hash_without_network(self):
        url = "https://www.swift.org/keys/all-keys.asc"

        class Reply:
            def __init__(self, body=b"keys", status=200, selected=url, length="4", encoding=None):
                self.body = io.BytesIO(body)
                self.status = status
                self.selected = selected
                self.headers = {} if length is None else {"content-length": length}
                if encoding is not None:
                    self.headers["content-encoding"] = encoding

            def geturl(self): return self.selected
            def read(self, count): return self.body.read(count)
            def __enter__(self): return self
            def __exit__(self, *_args): self.body.close()

        class Opener:
            def __init__(self, response): self.response = response
            def open(self, request, timeout):
                self.request = request
                self.timeout = timeout
                return self.response

        with patch.dict(DRIVER.SWIFT_SOURCES, {"all-keys.asc": (url, 8, 4)}):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory)
                opener = Opener(Reply())
                with patch.object(DRIVER, "free_bytes", return_value=30 * 1024 ** 3):
                    result = DRIVER.download_swift_input(opener, "all-keys.asc", path, time.monotonic() + 5)
                self.assertEqual(result, dict(url=url, bytes=4, sha256=hashlib.sha256(b"keys").hexdigest(), content_encoding=None))
                self.assertEqual((path / "all-keys.asc").read_bytes(), b"keys")
                self.assertEqual(opener.request.full_url, url)
                self.assertEqual(opener.request.get_header("Accept-encoding"), "identity")
            for reply in [Reply(status=302), Reply(selected="https://attacker.invalid/keys"), Reply(length="9"),
                          Reply(body=b"key"), Reply(body=b"too-large", length=None)]:
                with self.subTest(status=reply.status, url=reply.selected), tempfile.TemporaryDirectory() as directory:
                    path = Path(directory)
                    with patch.object(DRIVER, "free_bytes", return_value=30 * 1024 ** 3), self.assertRaises(ValueError):
                        DRIVER.download_swift_input(Opener(reply), "all-keys.asc", path, time.monotonic() + 5)
                    self.assertFalse((path / "all-keys.asc").exists(), "Rejected inputs cannot become authenticated files")
            with self.assertRaisesRegex(ValueError, "must not redirect"):
                DRIVER.NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://attacker.invalid/")

        clear = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\ncontrolled key metadata\n"
        wire = gzip.compress(clear, mtime=0)
        with patch.dict(DRIVER.SWIFT_SOURCES, {"all-keys.asc": (url, 1024, None)}):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory)
                with patch.object(DRIVER, "free_bytes", return_value=30 * 1024 ** 3):
                    result = DRIVER.download_swift_input(Opener(Reply(wire, length=str(len(wire)), encoding="gzip")), "all-keys.asc", path, time.monotonic() + 5)
                self.assertEqual((path / "all-keys.asc").read_bytes(), wire)
                self.assertEqual(result, dict(url=url, bytes=len(wire), sha256=hashlib.sha256(wire).hexdigest(), content_encoding="gzip"))
                selected = DRIVER.FileRoute("www.swift.org", "/keys/all-keys.asc", 200, path / "all-keys.asc", len(wire), result["sha256"])
                self.assertEqual(dict(DRIVER.response_headers(selected, {"all-keys.asc": result})),
                                 {"Content-Length": str(len(wire)), "Content-Encoding": "gzip"})
                self.assertEqual(gzip.decompress(wire), clear)
            for compressed, encoding in [(wire, "br"), (wire, "gzip, identity"), (wire, "gzip\r\nInjected: bad"),
                                         (wire[:-4], "gzip"), (b"not-gzip", "gzip"),
                                         (gzip.compress(b"x" * 1025), "gzip")]:
                with self.subTest(encoding=encoding, wire=len(compressed)), tempfile.TemporaryDirectory() as directory:
                    path = Path(directory)
                    with patch.object(DRIVER, "free_bytes", return_value=30 * 1024 ** 3), self.assertRaises(ValueError):
                        DRIVER.download_swift_input(Opener(Reply(compressed, length=str(len(compressed)), encoding=encoding)), "all-keys.asc", path, time.monotonic() + 5)
                    self.assertFalse((path / "all-keys.asc").exists())

    def test_manifest_retains_exact_order_query_bytes_and_duplicate_routes(self):
        rows = [route(), route("api.github.com", "/releases?page=1"), route()]
        self.assertEqual(DRIVER.parse_routes(json.dumps(rows).encode()), [
            DRIVER.Route("github.com", "/release/archive.zip", 200, b"\0\1\xff"),
            DRIVER.Route("api.github.com", "/releases?page=1", 200, b"\0\1\xff"),
            DRIVER.Route("github.com", "/release/archive.zip", 200, b"\0\1\xff"),
        ])

    def test_manifest_refuses_untrusted_hosts_paths_status_and_byte_types(self):
        invalid = [route("localhost"), route("127.0.0.1"), route(path="https://github.com/release"),
                   route(path="/release\r\nInjected: bad"), route(body=[True]), route(body=[256]),
                   route(body=[-1]), route(body="zip"), dict(route(), status=302), dict(route(), extra=True)]
        for row in invalid:
            with self.subTest(row=row), self.assertRaises(ValueError):
                DRIVER.parse_routes(json.dumps([row]).encode())
        for raw in [b'[]', b'{}', b'[{"host":"github.com","host":"go.dev","path":"/","status":200,"body":[]}]']:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                DRIVER.parse_routes(raw)

    def test_manifest_body_and_raw_bounds_are_enforced_before_credit(self):
        with patch.object(DRIVER, "MAX_BODY", 4):
            self.assertEqual(DRIVER.parse_routes(json.dumps([route(body=[1] * 4)]).encode())[0].body, b"\1" * 4)
            with self.assertRaises(ValueError):
                DRIVER.parse_routes(json.dumps([route(body=[1] * 5)]).encode())
        with patch.object(DRIVER, "MAX_TOTAL_BODY", 5):
            with self.assertRaises(ValueError):
                DRIVER.parse_routes(json.dumps([route(), route()]).encode())
        with patch.object(DRIVER, "MAX_MANIFEST", 8):
            with self.assertRaises(ValueError):
                DRIVER.parse_routes(json.dumps([route()]).encode())

    def test_unit_credit_requires_one_exact_unskipped_success(self):
        name = "runtimes::go::tests::native_public_install_preserves_authenticated_download_boundary"
        output = f"running 1 test\ntest {name} ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 3 filtered out\n".encode()
        DRIVER.validate_unit_output(output, name, 0)
        for invalid, code in [(output, 1), (output.replace(b"1 passed", b"0 passed"), 0),
                              (output.replace(b"0 ignored", b"1 ignored"), 0),
                              (output.replace(name.encode(), b"another::test"), 0),
                              (output + b"[omg-skip] unavailable\n", 0),
                              (output + b"LLVM Profile Warning: corrupt\n", 0),
                              (output + b"test another::test ... ok\n", 0)]:
            with self.subTest(output=invalid, code=code), self.assertRaises(ValueError):
                DRIVER.validate_unit_output(invalid, name, code)

    @unittest.skipIf(os.name == "nt", "Manifest ownership requires native POSIX metadata")
    def test_route_session_consumes_exact_plan_and_rejects_missing_extra_or_changed_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "routes.json"
            path.write_text(json.dumps([route(), route()]))
            path.chmod(0o600)
            session = DRIVER.RouteSession(path)
            self.assertEqual(session.request("github.com", "/release/archive.zip").body, b"\0\1\xff")
            with self.assertRaisesRegex(ValueError, "all consumed"):
                session.finish()
            self.assertEqual(session.request("github.com", "/release/archive.zip").status, 200)
            self.assertEqual(len(session.finish()["requests"]), 2)
            with self.assertRaisesRegex(ValueError, "additional"):
                session.request("github.com", "/release/archive.zip")
            path.write_text(json.dumps([route(body=[42])]))
            with self.assertRaisesRegex(ValueError, "changed"):
                session.finish()
            path.chmod(0o666)
            with self.assertRaisesRegex(ValueError, "Unsafe"):
                DRIVER.RouteSession(path).request("github.com", "/release/archive.zip")

    @unittest.skipIf(os.name == "nt", "Owned process groups require POSIX")
    def test_supervisor_death_kills_and_reaps_its_detached_native_child(self):
        observer = textwrap.dedent('''
            import ctypes, importlib.util, json, os, signal, subprocess, sys, time
            from pathlib import Path
            root, driver = Path(sys.argv[1]), sys.argv[2]
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.prctl(36, 1, 0, 0, 0) != 0:
                raise OSError(ctypes.get_errno(), "Cannot establish isolated child subreaper")
            child_program = "import json,os,time; from pathlib import Path; ready=Path(" + repr(str(root / "child.tmp")) + "); ready.write_text(json.dumps([os.getpid(),os.getppid(),os.getsid(0)])); ready.rename(" + repr(str(root / "child.json")) + "); time.sleep(15)"
            supervisor_program = "import importlib.util,os,sys; from pathlib import Path; spec=importlib.util.spec_from_file_location('driver',sys.argv[1]); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); module.bounded_command([sys.executable,'-c',sys.argv[3]],os.environ.copy(),Path(sys.argv[2])/'capture.log',Path(sys.argv[2]),timeout=12)"
            supervisor = subprocess.Popen([sys.executable, '-c', supervisor_program, driver, str(root), child_program])
            child = None
            reaped = False
            try:
                deadline = time.monotonic() + 5
                while not (root / 'child.json').exists():
                    if time.monotonic() >= deadline or supervisor.poll() is not None:
                        raise AssertionError('Native child did not become ready')
                    time.sleep(0.01)
                child, parent, session = json.loads((root / 'child.json').read_text())
                assert parent == supervisor.pid and session == child, 'Child was not owned and detached'
                supervisor.kill()
                supervisor.wait(timeout=2)
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    adopted, status = os.waitpid(child, os.WNOHANG)
                    if adopted:
                        reaped = True
                        assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL, 'Wrong native child termination'
                        print('Detached child killed on supervisor death and reaped', flush=True)
                        break
                    time.sleep(0.01)
                assert reaped, 'Detached native child survived supervisor death'
            finally:
                if supervisor.poll() is None:
                    supervisor.kill()
                supervisor.wait(timeout=2)
                if child is not None and not reaped:
                    os.kill(child, signal.SIGKILL)
                    os.waitpid(child, 0)
        ''')
        with tempfile.TemporaryDirectory() as directory:
            result = DRIVER.subprocess.run([sys.executable, "-c", observer, directory, str(Path(DRIVER.__file__).resolve())],
                                           capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b"Detached child killed on supervisor death and reaped", result.stdout)

    @unittest.skipIf(os.name == "nt", "Owned process groups require POSIX")
    def test_native_capture_and_deadline_failures_stop_and_reap_the_owned_process(self):
        for large in (True, False):
            with self.subTest(large=large), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                pidfile = root / "child.pid"
                program = ("import os,time\n"
                           f"open({str(pidfile)!r},'w').write(str(os.getpid()))\n"
                           + (f"print('x'*{DRIVER.MAX_CAPTURE + 1024},flush=True)\n" if large else "")
                           + "time.sleep(30)\n")
                with self.assertRaisesRegex(ValueError, "capture bound" if large else "deadline"):
                    DRIVER.bounded_command([sys.executable, "-c", program], os.environ.copy(),
                                           root / "capture.log", root, timeout=0.3)
                self.assertLessEqual((root / "capture.log").stat().st_size, DRIVER.MAX_CAPTURE)
                with self.assertRaises(ProcessLookupError):
                    os.kill(int(pidfile.read_text()), 0)


if __name__ == "__main__":
    unittest.main()
