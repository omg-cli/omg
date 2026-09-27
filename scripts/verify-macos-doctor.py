#!/usr/bin/env python3
"""Exercise the release Doctor against native Homebrew and controlled failures."""

import os
import re
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
from pathlib import Path


class RejectingProxy(socketserver.BaseRequestHandler):
    requests: list[str] = []

    def handle(self) -> None:
        self.request.settimeout(3)
        with self.request.makefile("rb") as stream:
            request_line = stream.readline(4096).decode("ascii", "replace")
        self.requests.append(request_line.strip())
        self.request.sendall(
            b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )


def run_doctor(binary: Path, env: dict[str, str], *flags: str) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [str(binary), "doctor", *flags],
        env=env,
        capture_output=True,
        text=True,
        timeout=65,
        check=False,
    )
    print(f"$ omg doctor {' '.join(flags)}\n{result.stdout}{result.stderr}")
    return result


def require(condition: bool, result: subprocess.CompletedProcess[str], message: str) -> None:
    if not condition:
        raise AssertionError(f"{message}\nexit={result.returncode}\n{result.stdout}{result.stderr}")


def issue_count(result: subprocess.CompletedProcess[str]) -> int:
    summaries = re.findall(r"Found ([0-9]+) issue\(s\)\.", result.stdout)
    require(len(summaries) == 1, result, "Doctor must print one issue summary")
    return int(summaries[0])


def path_without_sudo(binary: Path, original: str, scratch: Path) -> str:
    """Keep real host executables available while removing sudo from PATH."""
    aliases = scratch / "without-sudo-bin"
    aliases.mkdir()
    for directory in original.split(os.pathsep):
        source = Path(directory)
        if not directory or not source.is_dir():
            continue
        for entry in source.iterdir():
            target = aliases / entry.name
            if entry.name == "sudo" or target.exists() or target.is_symlink():
                continue
            if entry.is_file() and os.access(entry, os.X_OK):
                target.symlink_to(entry.resolve())
    controlled = os.pathsep.join((str(binary.parent), str(aliases)))
    if shutil.which("sudo", path=controlled) is not None:
        raise AssertionError("controlled Doctor PATH still contains sudo")
    return controlled


def path_without_omg(binary: Path, env: dict[str, str]) -> str:
    """Remove only paths Doctor accepts as OMG's executable directory."""
    home = Path(env.get("HOME", str(Path.home())))
    accepted = {binary.parent, Path(env["OMG_DATA_DIR"]) / "bin", home / ".local/bin"}
    entries = [entry for entry in env["PATH"].split(os.pathsep) if entry]
    if not any(Path(entry) in accepted for entry in entries):
        raise AssertionError("baseline PATH has no OMG directory to remove")
    remaining = [
        entry for entry in entries if Path(entry) not in accepted
    ]
    if not remaining:
        raise AssertionError("removing OMG left no usable PATH entries")
    return os.pathsep.join(remaining)


def check_native_doctor(binary: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    baseline = run_doctor(binary, env)
    require(baseline.returncode == 1, baseline, "blocked connectivity must fail Doctor")
    require(issue_count(baseline) == 1, baseline, "only the blocked connectivity should be an issue")
    require("Connectivity probes failed (github.com:" in baseline.stdout and
            "; kernel.org:" in baseline.stdout, baseline,
            "the controlled proxy must block both basic connectivity probes")
    for option in ("--prefix", "--cellar", "--caskroom"):
        require(baseline.stdout.count(f"Homebrew {option} matches backend") == 1, baseline,
                f"native Homebrew {option} must match the selected backend")
    require("Daemon is not used on macOS" in baseline.stdout, baseline,
            "macOS must not require the Linux daemon")
    require("Found dependency: sudo" not in baseline.stdout, baseline,
            "routine Homebrew operations must not require sudo")

    eol = run_doctor(binary, env, "--eol")
    require(eol.returncode == 1 and issue_count(eol) == issue_count(baseline) + 1, eol,
            "EOL flag must add exactly the old managed Node runtime issue")
    require("  ⚠ node 16.20.2 - EOL since 2023-09-11" in eol.stdout, eol,
            "managed Node 16 must be classified as end of life")
    require("  ✓ python 3.12.14" in eol.stdout, eol,
            "managed Python 3.12 must be classified as supported")

    network = run_doctor(binary, env, "--network")
    require(network.returncode == 1, network, "blocked Homebrew API probes must fail Doctor")
    require(network.stdout.count("Network Diagnostics\n") == 1 and
            network.stdout.count("DNS Resolution:\n") == 1, network,
            "network diagnostics must print one HTTP and DNS section")
    http_section, dns_section = network.stdout.split("Network Diagnostics\n", 1)[1].split(
        "DNS Resolution:\n", 1
    )
    http_rows = re.findall(r"^  ([✓✗⚠]) (.+?) \((.+)\)$", http_section, re.MULTILINE)
    require([(status, name) for status, name, _ in http_rows] == [
        ("✗", "Homebrew formula API"),
        ("✗", "Homebrew cask API"),
        ("✗", "GitHub"),
    ], network, "macOS must probe both real Homebrew APIs and GitHub")
    dns_rows = re.findall(r"^    ([✓✗]) (\S+) \((.+)\)$", dns_section, re.MULTILINE)
    require([host for _, host, _ in dns_rows] == ["formulae.brew.sh", "github.com"], network,
            "macOS DNS probes must match the backends it uses")
    for status, _, detail in dns_rows:
        require(status != "✓" or re.fullmatch(r"[1-9][0-9]* addresses", detail) is not None,
                network, "a successful DNS probe must resolve at least one address")
    dns_failures = sum(status == "✗" for status, _, _ in dns_rows)
    require(issue_count(network) == issue_count(baseline) + 3 + dns_failures, network,
            "network issue count must match all failed HTTP and DNS probes")
    require(sum("formulae.brew.sh:443" in request for request in RejectingProxy.requests) >= 2,
            network, "both Homebrew API requests must reach the controlled proxy")
    return baseline


def main() -> None:
    if sys.platform != "darwin":
        raise SystemExit("native macOS Doctor verification requires macOS")
    binary = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="omg-macos-doctor-") as scratch:
        data = Path(scratch) / "data"
        for runtime, version in (("node", "16.20.2"), ("python", "3.12.14")):
            versions = data / "versions" / runtime
            (versions / version).mkdir(parents=True)
            (versions / "current").symlink_to(version)

        with socketserver.ThreadingTCPServer(("127.0.0.1", 0), RejectingProxy) as proxy:
            proxy.daemon_threads = True
            thread = threading.Thread(target=proxy.serve_forever, daemon=True)
            thread.start()
            address = f"http://127.0.0.1:{proxy.server_address[1]}"
            env = os.environ.copy()
            env.update({
                "PATH": f"{binary.parent}:{env.get('PATH', '')}",
                "NO_COLOR": "1",
                "OMG_DATA_DIR": str(data),
                "OMG_TEST_MODE": "0",
                "HTTP_PROXY": address,
                "HTTPS_PROXY": address,
                "ALL_PROXY": address,
                "http_proxy": address,
                "https_proxy": address,
                "all_proxy": address,
                "NO_PROXY": "",
                "no_proxy": "",
            })
            try:
                baseline = check_native_doctor(binary, env)
                missing_path_env = env.copy()
                missing_path_env["PATH"] = path_without_omg(binary, env)
                missing_path = run_doctor(binary, missing_path_env)
                require(missing_path.returncode == 1 and
                        issue_count(missing_path) == issue_count(baseline) + 1,
                        missing_path, "removing OMG from PATH must add exactly one issue")
                require(len(re.findall(r"^  OMG bin directory not in PATH$",
                                       missing_path.stdout, re.MULTILINE)) == 1,
                        missing_path, "Doctor must name the missing OMG PATH exactly once")
                require("PATH configured correctly" not in missing_path.stdout,
                        missing_path, "Doctor must not report a healthy PATH when OMG is absent")
                no_sudo_env = env.copy()
                no_sudo_env["PATH"] = path_without_sudo(binary, env["PATH"], Path(scratch))
                no_sudo = run_doctor(binary, no_sudo_env)
                require(no_sudo.returncode == 1 and issue_count(no_sudo) == 1, no_sudo,
                        "missing sudo must not add a macOS Doctor issue")
                for option in ("--prefix", "--cellar", "--caskroom"):
                    require(no_sudo.stdout.count(f"Homebrew {option} matches backend") == 1,
                            no_sudo, f"Homebrew {option} must work without sudo on PATH")
                require("Missing dependency: sudo" not in no_sudo.stdout, no_sudo,
                        "macOS Doctor must not demand sudo")
            finally:
                proxy.shutdown()
                thread.join(timeout=5)


if __name__ == "__main__":
    main()
