#!/usr/bin/env python3
"""Require a complete native APT daemon catalogue within its readiness budget."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import time

import apt_pkg


def run(argv, environment):
    result = subprocess.run(argv, env=environment, text=True, capture_output=True, timeout=20)
    if result.returncode:
        raise AssertionError(f"{argv!r} exited {result.returncode}: {result.stderr}")
    return result.stdout


def native_state():
    return {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (Path("/var/lib/dpkg/status"), Path("/var/lib/apt/extended_states"))
            if path.exists()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--omg-binary", type=Path, required=True)
    parser.add_argument("--omgd-binary", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    assert os.getuid() != 0, "native daemon regression must run as an ordinary user"
    binary = args.omg_binary.resolve(strict=True)
    daemon_binary = args.omgd_binary.resolve(strict=True)
    work = args.evidence_dir.resolve()
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    private = work / "private"
    private.mkdir(mode=0o700)
    environment = dict(os.environ, HOME=str(private), NO_COLOR="1", OMG_TEST_MODE="0",
                       OMG_DISABLE_TELEMETRY="1", OMG_DATA_DIR=str(private / "data"),
                       OMG_CACHE_DIR=str(private / "cache"), OMG_CONFIG_DIR=str(private / "config"),
                       OMG_DAEMON_DATA_DIR=str(private / "daemon"),
                       OMG_SOCKET_PATH=str(private / "daemon.sock"), OMG_DISABLE_DAEMON="1")
    environment.pop("OMG_TEST_DISTRO", None)
    environment.pop("OMG_TEST_BACKEND", None)
    apt_pkg.init()
    cache = apt_pkg.Cache(None)
    depcache = apt_pkg.DepCache(cache)
    candidates = [(package, version) for package in cache.packages
                  if (version := depcache.get_candidate_ver(package) or package.current_ver) is not None]
    assert len(candidates) >= 25000, "regression requires a full native repository catalogue"
    canonical = sorted((package.name, version.ver_str) for package, version in candidates)
    receipt = {"accepted": False, "source_sha": os.environ.get("OMG_CONTRACT_SOURCE_SHA"), "native_candidate_count": len(candidates),
               "native_candidate_sha256": hashlib.sha256(json.dumps(canonical).encode()).hexdigest(),
               "omg_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
               "omgd_sha256": hashlib.sha256(daemon_binary.read_bytes()).hexdigest(),
               "readiness_budget_seconds": 30}
    before = native_state()
    direct = {name: json.loads(run([str(binary), "info", name, "--json"], environment))
              for name in ("apt", "bash")}
    records = apt_pkg.PackageRecords(cache)
    for name, result in direct.items():
        version = depcache.get_candidate_ver(cache[name]) or cache[name].current_ver
        assert result["version"] == version.ver_str, (name, result, version.ver_str)
        assert records.lookup(version.file_list[0])
        assert result["description"] == records.short_desc, (name, result)
    daemon_environment = dict(environment)
    daemon_environment.pop("OMG_DISABLE_DAEMON")
    process = None
    try:
        started = time.monotonic()
        with (work / "daemon.log").open("wb") as log:
            process = subprocess.Popen([str(daemon_binary)], env=daemon_environment,
                                       stdout=log, stderr=subprocess.STDOUT)
            socket = Path(environment["OMG_SOCKET_PATH"])
            deadline = started + 30
            while time.monotonic() < deadline:
                assert process.poll() is None, "daemon exited before readiness"
                if socket.exists():
                    break
                time.sleep(0.1)
            receipt["readiness_elapsed_seconds"] = time.monotonic() - started
            assert socket.is_socket(), "native daemon catalogue did not become ready within 30 seconds"
            socket_state = socket.stat()
            assert stat.S_IMODE(socket_state.st_mode) == 0o600 and socket_state.st_uid == os.getuid()
            loaded = re.findall(r"Package index loaded: (\d+) packages", (work / "daemon.log").read_text())
            assert loaded == [str(len(candidates))], (loaded, len(candidates))
            def info_counter():
                metrics = run([str(binary), "metrics"], daemon_environment)
                values = re.findall(r"^omg_info_requests_total (\d+)$", metrics, re.M)
                assert len(values) == 1, metrics
                return int(values[0])
            initial = info_counter()
            for name, expected in direct.items():
                actual = json.loads(run([str(binary), "info", name, "--json"], daemon_environment))
                assert all(actual.get(key) == value for key, value in expected.items()), (name, expected, actual)
            delta = info_counter() - initial
            assert delta == len(direct), "info fell back to direct queries instead of using the daemon"
            receipt["info_requests_delta"] = delta
            assert native_state() == before, "native package installation or reason state changed"
            receipt["native_state_unchanged"] = before
            receipt["accepted"] = True
    finally:
        if process is not None and process.poll() is None:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                raise
        (work / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
