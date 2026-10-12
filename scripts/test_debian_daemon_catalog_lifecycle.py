#!/usr/bin/env python3
"""Behavioral orchestration tests: synthetic adapters, never native daemon proof."""
import contextlib
import importlib.util
import json
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

REAL_POPEN = subprocess.Popen

SCRIPT = Path(__file__).with_name("test-debian-daemon-catalog.py")


class CatalogueCase:
    """Exercise actual script acceptance with controlled process lifecycle outcomes."""
    def __init__(self, root, shutdown_code=0, leave_socket=False, drift=False, already_exited=False):
        self.root = root
        self.shutdown_code = shutdown_code
        self.already_exited = already_exited
        self.leave_socket = leave_socket
        self.drift = drift
        self.counter = 0
        self.shutdown = False
        self.listener = None
        self.environment = None
        version = types.SimpleNamespace(ver_str="1.0-1", file_list=[(object(), 0)])
        packages = [types.SimpleNamespace(name=name, current_ver=version)
                    for name in ["apt", "bash"] + [f"fixture-{i:05d}" for i in range(24998)]]
        by_name = {p.name: p for p in packages}
        class Cache:
            def __init__(self, unused):
                self.packages = packages
            def __getitem__(self, name):
                return by_name[name]
        class Records:
            short_desc = "native-adapter summary"
            def __init__(self, cache):
                pass
            def lookup(self, location):
                return True
        self.apt = types.SimpleNamespace(init=lambda: None, Cache=Cache,
                                        DepCache=lambda cache: types.SimpleNamespace(
                                            get_candidate_ver=lambda package: package.current_ver),
                                        PackageRecords=Records)

    def info(self, name):
        return {"name": name, "version": "1.0-1", "description": "native-adapter summary",
                "installed": True}

    def native_state(self):
        return {"owned-status": "changed" if self.shutdown and self.drift else "initial"}

    def run(self, argv, environment):
        if argv[1] == "metrics":
            return f"omg_info_requests_total {self.counter}\n"
        if argv[1] != "info":
            raise AssertionError(f"unexpected command {argv!r}")
        if "OMG_DISABLE_DAEMON" not in environment:
            self.counter += 1
            # Synthetic enabled-CLI request accounting; no wire response is sent.
        return json.dumps(self.info(argv[2]))

    def popen(self, argv, env, stdout, stderr):
        case = self
        self.environment = env
        path = Path(env["OMG_SOCKET_PATH"])
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(str(path))
        path.chmod(0o600)
        stdout.write(b"Package index loaded: 25000 packages\n")
        stdout.flush()
        class Process:
            returncode = None
            shutdown_requested = False
            def poll(self):
                if case.already_exited and case.counter >= 2:
                    self.returncode = case.shutdown_code
                return self.returncode
            def send_signal(self, value):
                if value != signal.SIGINT:
                    raise AssertionError(value)
                self.shutdown_requested = True
            def wait(self, timeout):
                if self.returncode is None and (not self.shutdown_requested or case.shutdown_code == "timeout"):
                    raise subprocess.TimeoutExpired(argv, timeout)
                case.shutdown = True
                case.listener.close()
                if not case.leave_socket:
                    path.unlink(missing_ok=True)
                if self.returncode is None:
                    self.returncode = case.shutdown_code
                return self.returncode
            def kill(self):
                self.returncode = -signal.SIGKILL
        return Process()

    @contextlib.contextmanager
    def module(self):
        spec = importlib.util.spec_from_file_location("catalogue_under_test", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {"apt_pkg": self.apt}):
            spec.loader.exec_module(module)
        binary = self.root / "omg"
        daemon = self.root / "omgd"
        binary.write_bytes(b"owned synthetic CLI producer")
        daemon.write_bytes(b"owned synthetic daemon producer")
        arguments = [str(SCRIPT), "--omg-binary", str(binary), "--omgd-binary", str(daemon),
                     "--evidence-dir", str(self.root / "evidence")]
        try:
            with contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(sys, "argv", arguments))
                stack.enter_context(patch.object(module, "native_state", self.native_state))
                stack.enter_context(patch.object(module, "run", self.run))
                stack.enter_context(patch.object(module.subprocess, "Popen", self.popen))
                # Ordinary-user contract stays tested by a matching current uid;
                # run as a nonroot user so the real owned socket uid check applies.
                yield module
        finally:
            if self.listener is not None:
                self.listener.close()

    def receipt(self):
        return json.loads((self.root / "evidence/receipt.json").read_text())


class DaemonCatalogueAcceptance(unittest.TestCase):
    def exercise_refusal(self, message, **kwargs):
        with tempfile.TemporaryDirectory(prefix="catalogue-oracle-") as directory:
            case = CatalogueCase(Path(directory), **kwargs)
            with case.module() as module:
                with self.assertRaisesRegex((AssertionError, subprocess.TimeoutExpired), message):
                    module.main()
            receipt_path = case.root / "evidence/receipt.json"
            self.assertTrue(receipt_path.exists(), "failed gate must retain a refused receipt")
            self.assertFalse(case.receipt()["accepted"], "failed gate must leave a refused receipt")

    def test_nonzero_shutdown_cannot_produce_accepted_receipt(self):
        self.exercise_refusal("daemon shutdown exited 17", shutdown_code=17)

    def test_already_nonzero_before_finally_cannot_produce_accepted_receipt(self):
        self.exercise_refusal("daemon shutdown exited 17", shutdown_code=17, already_exited=True)

    def test_retained_socket_cannot_produce_accepted_receipt(self):
        self.exercise_refusal("daemon socket remains after shutdown", leave_socket=True)

    def test_post_shutdown_native_drift_cannot_produce_accepted_receipt(self):
        self.exercise_refusal("native package installation or reason state changed", drift=True)

    def test_shutdown_timeout_retains_refused_receipt(self):
        self.exercise_refusal("timed out", shutdown_code="timeout")

    def test_successful_sample_and_clean_shutdown_remain_accepted(self):
        with tempfile.TemporaryDirectory(prefix="catalogue-oracle-") as directory:
            case = CatalogueCase(Path(directory))
            with case.module() as module:
                module.main()
            self.assertTrue(case.receipt()["accepted"])
            self.assertTrue(case.shutdown)
            self.assertFalse(Path(case.environment["OMG_SOCKET_PATH"]).exists())
            # Successful acceptance is lifecycle proof only, not framed Info proof.


class DanglingSocketCase(CatalogueCase):
    def popen(self, argv, env, stdout, stderr):
        process = super().popen(argv, env, stdout, stderr)
        original_wait = process.wait
        path = Path(env["OMG_SOCKET_PATH"])

        def wait(timeout):
            result = original_wait(timeout)
            # The listener is closed, the original owned socket is removed,
            # but an unresolved entry remains at that same private path.
            path.symlink_to(path.with_name("absent-owned-socket-target"))
            return result

        process.wait = wait
        return process


class OperationFailureCase(CatalogueCase):
    def run(self, argv, environment):
        if argv[1] == "info" and "OMG_DISABLE_DAEMON" not in environment:
            raise RuntimeError("primary Info fixture failure")
        return super().run(argv, environment)


class SupplementaryCatalogueLifecycle(unittest.TestCase):
    def test_dangling_socket_entry_refuses_acceptance(self):
        with tempfile.TemporaryDirectory(prefix="catalogue-dangling-") as directory:
            case = DanglingSocketCase(Path(directory))
            with case.module() as module:
                with self.assertRaisesRegex(AssertionError, "daemon socket remains after shutdown"):
                    module.main()
            receipt = case.receipt()
            self.assertFalse(receipt["accepted"])
            self.assertIn("daemon socket remains after shutdown", receipt["cleanup_error"])
            residue = Path(case.environment["OMG_SOCKET_PATH"])
            self.assertTrue(residue.is_symlink(), "fixture must retain an actual owned dangling entry")
            self.assertFalse(residue.exists(), "the retained entry must specifically be dangling")
            self.assertTrue(case.shutdown)

    def test_primary_operation_failure_survives_cleanup_failure(self):
        with tempfile.TemporaryDirectory(prefix="catalogue-combined-failure-") as directory:
            case = OperationFailureCase(Path(directory), shutdown_code=17)
            with case.module() as module:
                with self.assertRaisesRegex(RuntimeError, "^primary Info fixture failure$") as raised:
                    module.main()
            receipt = case.receipt()
            self.assertFalse(receipt["accepted"])
            self.assertEqual(receipt["operation_error"], "RuntimeError: primary Info fixture failure")
            self.assertEqual(receipt["cleanup_error"], "AssertionError: daemon shutdown exited 17")
            self.assertEqual(receipt["shutdown_returncode"], 17)
            self.assertTrue(case.shutdown)
            notes = getattr(raised.exception, "__notes__", [])
            self.assertEqual(notes, ["daemon cleanup also failed: daemon shutdown exited 17"])

    def test_primary_operation_failure_with_clean_cleanup_retains_refusal(self):
        with tempfile.TemporaryDirectory(prefix="catalogue-primary-failure-") as directory:
            case = OperationFailureCase(Path(directory))
            with case.module() as module:
                with self.assertRaisesRegex(RuntimeError, "^primary Info fixture failure$") as raised:
                    module.main()
            receipt = case.receipt()
            self.assertFalse(receipt["accepted"])
            self.assertEqual(receipt["operation_error"], "RuntimeError: primary Info fixture failure")
            self.assertNotIn("cleanup_error", receipt)
            self.assertEqual(getattr(raised.exception, "__notes__", []), [])
            self.assertEqual(receipt["shutdown_returncode"], 0)
            self.assertTrue(receipt["socket_absent_after_shutdown"])
            self.assertEqual(receipt["native_state_after_shutdown"], {"owned-status": "initial"})
            self.assertTrue(case.shutdown)

    def test_stable_success_control_remains_accepted(self):
        with tempfile.TemporaryDirectory(prefix="catalogue-extra-positive-") as directory:
            case = CatalogueCase(Path(directory))
            with case.module() as module:
                module.main()
            receipt = case.receipt()
            self.assertTrue(receipt["accepted"])
            self.assertEqual(receipt["info_requests_delta"], 2)
            self.assertEqual(receipt["shutdown_returncode"], 0)
            self.assertTrue(receipt["socket_absent_after_shutdown"])
            self.assertEqual(receipt["native_state_after_shutdown"], {"owned-status": "initial"})
            self.assertNotIn("operation_error", receipt)
            self.assertNotIn("cleanup_error", receipt)
            self.assertTrue(case.shutdown)


class ChildProcessCase(CatalogueCase):
    def popen(self, argv, env, stdout, stderr):
        # A real owned child must receive SIGINT, clean its socket and exit.
        # APT and CLI adapters remain synthetic; this is no native daemon proof.
        self.environment = env
        child = r"""
import os
from pathlib import Path
import signal
import socket
import time
stopping = False
def stop(signum, frame):
    global stopping
    stopping = True
signal.signal(signal.SIGINT, stop)
path = Path(os.environ["OMG_SOCKET_PATH"])
listener = socket.socket(socket.AF_UNIX)
listener.bind(str(path))
path.chmod(0o600)
print("Package index loaded: 25000 packages", flush=True)
try:
    while not stopping:
        time.sleep(0.01)
finally:
    listener.close()
    path.unlink()
"""
        self.process = REAL_POPEN([sys.executable, "-B", "-c", child], env=env,
                                  stdout=stdout, stderr=stderr)
        return self.process

    @contextlib.contextmanager
    def module(self):
        self.process = None
        try:
            with super().module() as module:
                yield module
        finally:
            if self.process is not None and self.process.poll() is None:
                self.process.kill()
                self.process.wait(timeout=5)


class ChildProcessShutdown(unittest.TestCase):
    def test_owned_child_exits_cleanly_after_shutdown_request(self):
        with tempfile.TemporaryDirectory(prefix="catalogue-child-") as directory:
            case = ChildProcessCase(Path(directory))
            with case.module() as module:
                module.main()
            receipt = case.receipt()
            self.assertTrue(receipt["accepted"])
            self.assertEqual(case.process.returncode, 0)
            self.assertEqual(receipt["shutdown_returncode"], 0)
            self.assertTrue(receipt["socket_absent_after_shutdown"])
            self.assertFalse(Path(case.environment["OMG_SOCKET_PATH"]).exists())


if __name__ == "__main__":
    unittest.main()
