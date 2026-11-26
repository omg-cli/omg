#!/usr/bin/env python3
"""Verify live Fedora caches across repository, advisory, installroot, and inventory changes.

Run as root in private mount and network namespaces without network routes.
The arguments are the inert Fedora fixture directory and the built omg and
omgd binaries. All RPM writes go to a disposable installroot.
"""
from contextlib import ExitStack, closing, contextmanager
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import socket
import sqlite3
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import datetime
import uuid
import tomllib
from urllib.parse import parse_qs
import xml.etree.ElementTree as ET

if not __debug__ or len(sys.argv) not in (4, 5):
    raise SystemExit("requires assertions and arguments FIXTURE_DIR OMG OMGD [NATIVE_CONSENT_ORACLE]")
fixture, candidate, daemon = (Path(value).resolve(strict=True) for value in sys.argv[1:4])
consent_oracle = Path(sys.argv[4]).resolve(strict=True) if len(sys.argv) == 5 else None
assert os.getuid() == 0
for namespace in ("mnt", "net"):
    assert os.readlink(f"/proc/self/ns/{namespace}") != os.readlink(f"/proc/1/ns/{namespace}")
assert json.loads(subprocess.check_output(["/usr/bin/ip", "-j", "route", "show", "table", "all"])) == []
account = pwd.getpwnam("nobody")
ordinary = dict(user=account.pw_uid, group=account.pw_gid, extra_groups=[])
base_env = dict(PATH="/usr/sbin:/usr/bin:/sbin:/bin", LC_ALL="C.UTF-8")
config = Path("/etc/dnf/dnf.conf")
rpm = "/usr/bin/rpm"
dnf = "/usr/bin/dnf"
package = "omg-observer-fixture"
advisory_id = "OMG-FIXTURE-STATUS-1"
repo_ns = "{http://linux.duke.edu/metadata/repo}"
ET.register_namespace("", repo_ns[1:-1])

def append_metadata(manifest, kind, relative_path, payload):
    compressed = gzip.compress(payload, mtime=0)
    (repo / relative_path).write_bytes(compressed)
    entry = ET.SubElement(manifest, f"{repo_ns}data", type=kind)
    for key, contents in (("checksum", compressed), ("open-checksum", payload)):
        ET.SubElement(entry, f"{repo_ns}{key}", type="sha256").text = hashlib.sha256(contents).hexdigest()
    ET.SubElement(entry, f"{repo_ns}location", href=relative_path)
    timestamp = str(int(time.time()))
    for key, value in (("timestamp", timestamp), ("size", len(compressed)), ("open-size", len(payload))):
        ET.SubElement(entry, f"{repo_ns}{key}").text = str(value)
    manifest.find(f"{repo_ns}revision").text = timestamp

def advisory_metadata(manifest):
    payload = f"""<updates>
      <update from="omg-fixture.invalid" status="stable" type="security" version="1">
        <id>{advisory_id}</id><title>Synthetic local advisory</title>
        <severity>Important</severity><description>Package-manager test fixture.</description>
        <issued date="2026-10-02 00:00:00"/><updated date="2026-10-02 00:00:00"/>
        <references/>
        <pkglist><collection short="local"><name>Local fixture</name>
          <package name="{package}" epoch="0" version="1" release="1" arch="noarch"/>
        </collection></pkglist>
      </update>
    </updates>""".encode()
    append_metadata(manifest, "updateinfo", "repodata/updateinfo.xml.gz", payload)

def command(args, env=base_env, identity=None, *, timeout=30):
    return subprocess.run([str(part) for part in args], cwd=env.get("HOME", "/"),
                          stdin=subprocess.DEVNULL, capture_output=True, text=True,
                          env=env, timeout=timeout, **(identity or {}))

def checked(args, env=base_env, identity=None):
    result = command(args, env, identity)
    assert result.returncode == 0, (list(map(str, args)), result.stdout[-1200:], result.stderr[-1600:])
    return result.stdout

def stage_runtime_fixture(directory):
    source = Path(__file__).with_name("runtime_advisory_fixture.py")
    if not source.is_file():
        source = fixture.parents[1] / "runtime_advisory_fixture.py"
    payload = source.read_bytes()
    staged = directory / source.name
    staged.write_bytes(payload)
    staged.chmod(0o644)
    digest = hashlib.sha256(payload).hexdigest()
    result = command([sys.executable, "-I", "-B", "-c",
                      "import hashlib, pathlib, sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())",
                      staged], identity=ordinary)
    mode = staged.stat()
    checks.append(dict(phase="task-runtime-fixture", case="ordinary-worker-reads-staged-helper",
                       status=result.returncode,
                       passed=(result.returncode == 0 and result.stdout.strip() == digest
                               and mode.st_uid == 0 and stat.S_IMODE(mode.st_mode) == 0o644),
                       diagnostic=result.stderr[-1000:]))
    return staged

def inventory():
    installed = sorted(checked([rpm, "-qa", "--qf", "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n"]).splitlines())
    state = Path("/usr/lib/sysimage/libdnf5")
    reasons = {str(path.relative_to(state)): hashlib.sha256(path.read_bytes()).hexdigest()
               for path in sorted(state.rglob("*.toml"))}
    return installed, reasons

def wait_for(predicate, proc):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        assert proc.poll() is None, f"daemon terminated with {proc.returncode}"
        try:
            matched = predicate()
        except (FileNotFoundError, ValueError):
            matched = False
        if matched:
            return
        time.sleep(0.12)
    raise AssertionError("expected daemon publication did not appear")

before = inventory()
config_before = config.read_bytes()
host_count = len(before[0])
checks = []
started_at = time.monotonic()


def mark_progress(label):
    elapsed = time.monotonic() - started_at
    print(f"Fedora status suite: {label}, {len(checks)} checks, {elapsed:.1f}s",
          file=sys.stderr, flush=True)


mark_progress("starting")
with tempfile.TemporaryDirectory(prefix="omg-fedora-cache-scope-", dir="/tmp") as directory:
    root = Path(directory)
    root.chmod(0o755)
    private_dnf = root / "dnf"
    shutil.copytree("/etc/dnf", private_dnf, symlinks=True)
    checked(["/usr/bin/mount", "--bind", private_dnf, "/etc/dnf"])
    for name in ("cache", "log"):
        (root / name).mkdir()
        checked(["/usr/bin/mount", "--bind", root / name, f"/var/{name}"])
    work = root / "user"
    runtime = work / "run"
    for path in (work, runtime):
        path.mkdir(mode=0o700)
        os.chown(path, account.pw_uid, account.pw_gid)
    bin_dir = root / "bin"
    bin_dir.mkdir()
    cli, server = bin_dir / "omg", bin_dir / "omgd"
    shutil.copy2(candidate, cli)
    shutil.copy2(daemon, server)
    binaries = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in (cli, server)}
    env = dict(base_env, PATH=f"{bin_dir}:{base_env['PATH']}", HOME=str(work), XDG_RUNTIME_DIR=str(runtime), XDG_CACHE_HOME=str(work/"cache"),
               XDG_CONFIG_HOME=str(work/"config"), XDG_DATA_HOME=str(work/"data"),
               XDG_STATE_HOME=str(work/"state"), OMG_DAEMON_DATA_DIR=str(work/"daemon-data"),
               OMG_SOCKET_PATH=str(runtime/"omg.sock"), OMG_DISABLE_TELEMETRY="1", NO_COLOR="1")
    disabled = dict(env, OMG_DISABLE_DAEMON="1")
    repo = root / "repo"
    shutil.copytree(fixture, repo)
    keys = root / "keys"
    keys.mkdir(mode=0o700)
    gpg = ["/usr/bin/gpg", "--homedir", keys, "--batch", "--pinentry-mode", "loopback", "--passphrase", ""]
    public = root / "metadata.asc"
    alternate = root / "alternate"
    (alternate / "etc/dnf").mkdir(parents=True)
    for suffix in (".local/state", ".cache", "state"):
        path = alternate / work.relative_to("/") / suffix
        path.mkdir(parents=True)
        path.chmod(0o700)
        os.chown(path, account.pw_uid, account.pw_gid)
    checked([rpm, "--root", alternate, "-U", "--nosignature", fixture/"observer-fixture.rpm"])
    assert checked([rpm, "--root", alternate, "-qa", "--qf", "%{NAME}\n"]).splitlines() == [package]
    system_state = alternate / "usr/lib/sysimage/libdnf5"
    system_state.mkdir(parents=True, exist_ok=True)
    os.chown(system_state, account.pw_uid, account.pw_gid)
    repo_config = (
        "[signed-fixture]\nname=Local signed fixture\n"
        f"baseurl={repo.as_uri()}\n"
        "enabled=1\ngpgcheck=1\nrepo_gpgcheck=1\nskip_if_unavailable=false\nbuild_cache=0\n"
        f"gpgkey={public.as_uri()}\n"
    )
    main = "[main]\nplugins=0\nreposdir=\n"
    repo_configs = private_dnf / "omg-fixture-repos"
    repo_configs.mkdir()
    repo_file = repo_configs / "fixture.repo"
    repo_file.write_text(repo_config)
    host_config = (
        main.replace("reposdir=\n", "reposdir=/etc/dnf/omg-fixture-repos\n")
        + f"cachedir={work / 'custom-dnf-cache'}\n"
    )
    alternate_config = (
        main.replace("reposdir=\n", "reposdir=/etc/dnf/omg-fixture-repos\n")
        + f"installroot={alternate}\n"
    )
    alternate_repo = alternate / "etc/dnf/omg-fixture-repos/fixture.repo"
    alternate_repo.parent.mkdir()
    alternate_repo.write_text(repo_config)
    (alternate / "etc/dnf/dnf.conf").write_text(alternate_config)
    config.write_text(host_config)
    fast = runtime / "omg.status"
    persisted = work / "daemon-data/status-cache.json"

    native_env = {key: value for key, value in env.items() if not key.startswith("XDG_")}

    def ordinary_control(command_line):
        return checked(command_line, native_env, ordinary)

    def inspect_self_update():
        old_pair = {path: (path.stat().st_ino, hashlib.sha256(path.read_bytes()).digest())
                    for path in (cli, server)}
        version = checked([cli, "--version"], disabled, ordinary).strip().removeprefix("omg ")
        current = version.split("+", 1)[0]
        major, minor, patch = map(int, current.split("-", 1)[0].split("."))
        newer = f"{major}.{minor}.{patch + 1}"
        newest_major = f"{major + 1}.0.0"
        already = "You are already on the latest version."
        refused = "Refusing to downgrade"
        invalid = "is not valid semver"
        download_failed = "Failed to fetch"
        phases = [
            ("current", ["self-update", "--version", version], 0, already),
            ("current-alias", ["up", "--version", version], 0, already),
            ("current-prefixed", ["self-update", "--version", f"v{current}"], 0, already),
            ("current-whitespace", ["up", "--version", f"  {current}  "], 0, already),
            ("current-build", ["self-update", "--version", f"{current}+other"], 0, already),
            ("current-build-prefixed", ["up", "--version", f"v{current}+build.42"], 0, already),
            ("older", ["self-update", "--version", "0.0.0"], 1, refused),
            ("older-alias", ["up", "--version", "0.0.0"], 1, refused),
            ("older-prefixed", ["self-update", "--version", "v0.0.0"], 1, refused),
            ("older-prerelease", ["up", "--version", "0.0.0-rc.10"], 1, refused),
            ("older-build", ["self-update", "--version", "0.0.0+build.42"], 1, refused),
            ("older-whitespace", ["up", "--version", "  v0.0.0  "], 1, refused),
            ("invalid-empty", ["self-update", "--version", ""], 1, invalid),
            ("invalid-prefix-only", ["up", "--version", "v"], 1, invalid),
            ("invalid-short", ["self-update", "--version", "1.2"], 1, invalid),
            ("invalid-extra-component", ["up", "--version", "1.2.3.4"], 1, invalid),
            ("invalid-leading-zero", ["self-update", "--version", "1.02.3"], 1, invalid),
            ("invalid-empty-build", ["up", "--version", "1.2.3+"], 1, invalid),
            ("newer-patch", ["self-update", "--version", newer], 1, download_failed),
            ("newer-major", ["up", "--version", newest_major], 1, download_failed),
            ("newer-prerelease", ["self-update", "--version", f"{newer}-rc.10"], 1, download_failed),
            ("newer-build", ["up", "--version", f"{newer}+build.42"], 1, download_failed),
            ("newer-prefixed", ["self-update", "--version", f"v{newer}"], 1, download_failed),
            ("newer-whitespace", ["up", "--version", f"  {newer}  "], 1, download_failed),
            ("force-current", ["self-update", "--force", "--version", version], 1, download_failed),
            ("force-current-build", ["up", "--force", "--version", f"{current}+build.42"], 1, download_failed),
            ("force-older", ["self-update", "--force", "--version", "0.0.0"], 1, download_failed),
            ("force-older-prefixed", ["up", "--force", "--version", "v0.0.0"], 1, download_failed),
            ("help", ["self-update", "--help"], 0, "Update OMG to the latest version"),
            ("alias-help", ["up", "--help"], 0, "Update OMG to the latest version"),
        ]
        for phase, args, status, expected in phases:
            result = command([cli, *args], disabled, ordinary)
            output = result.stdout + result.stderr
            if expected == download_failed:
                selected = args[-1].strip().removeprefix("v")
                artifact = f"omg-v{selected}-x86_64-linux-fedora.tar.gz"
                expected_stage = f"Downloading {artifact}" in result.stdout and f"{artifact}.sha256" in result.stderr
            else:
                expected_stage = "Downloading " not in result.stdout
            checked_unchanged = all(path.stat().st_ino == inode for path, (inode, _) in old_pair.items())
            checks.append(dict(phase=f"self-update-{phase}", case="native Fedora self-update exit",
                               passed=result.returncode == status and expected in output
                               and expected_stage and checked_unchanged,
                               status=result.returncode, diagnostic=output[-900:]))
        assert all(hashlib.sha256(path.read_bytes()).digest() == digest
                   for path, (_, digest) in old_pair.items())
        assert not (bin_dir / ".omg-self-update.lock").exists()

    inspect_self_update()

    def inspect_doctor(phase, installroot, expected_packages):
        rpm_installed = checked(
            [rpm, "--root", installroot, "-qa", "--qf", "%{NAME}\n"],
            native_env, ordinary,
        ).splitlines()
        assert len(rpm_installed) == expected_packages, (phase, rpm_installed[:10])
        total = checked([cli, "tc"], disabled, ordinary).strip()
        assert total == str(expected_packages), (phase, total)
        settings = checked([dnf, "--cacheonly", "--dump-main-config"], native_env, ordinary)
        assert f"installroot = {installroot}" in settings.splitlines(), (phase, installroot)
        dnf_check = command([dnf, "--cacheonly", "check"], native_env, ordinary)
        assert dnf_check.returncode == 0, (phase, dnf_check.stdout, dnf_check.stderr)
        result = command([cli, "doctor"], disabled, ordinary)
        rpm_verdicts = [line.strip() for line in result.stdout.splitlines()
                        if "RPM installed package" in line]
        expected = "RPM installed package database nonempty" if expected_packages else (
            "✗ RPM installed package database is empty"
        )
        lines = result.stdout.splitlines()
        passed = (result.returncode == 1 and len(rpm_verdicts) == 1
                  and rpm_verdicts[0].endswith(expected)
                  and any("DNF local package database healthy" in line for line in lines)
                  and any("Connectivity probes failed" in line for line in lines)
                  and any(f"{1 + (expected_packages == 0)} health issue" in line
                          for line in result.stderr.splitlines()))
        checks.append(dict(phase=phase, case="doctor checks active RPM inventory",
                           passed=passed, status=result.returncode,
                           diagnostic=(rpm_verdicts,
                                       [line.strip() for line in lines if "DNF local package" in line],
                                       result.stderr[-500:])))

    inspect_doctor("doctor-host", "/", host_count)
    config.write_text(host_config.replace("/etc/dnf/omg-fixture-repos", "/etc/dnf/no-repos"))
    inspect_doctor("doctor-host-without-repositories", "/", host_count)
    config.write_text(alternate_config)
    inspect_doctor("doctor-populated-installroot", alternate, 1)
    alternate_repo.unlink()
    try:
        inspect_doctor("doctor-populated-installroot-without-repositories", alternate, 1)
    finally:
        alternate_repo.write_text(repo_config)
    empty = root / "empty-installroot"
    (empty / "etc/dnf").mkdir(parents=True)
    for suffix in (".local/state", ".cache", "state"):
        directory = empty / work.relative_to("/") / suffix
        directory.mkdir(parents=True)
        directory.chmod(0o700)
        os.chown(directory, account.pw_uid, account.pw_gid)
    empty_config = alternate_config.replace(f"installroot={alternate}\n", f"installroot={empty}\n")
    (empty / "etc/dnf/dnf.conf").write_text(empty_config)
    (empty / "etc/dnf/omg-fixture-repos").mkdir()
    (empty / "etc/dnf/omg-fixture-repos/fixture.repo").write_text(repo_config)
    # Build the empty database through the same native transaction path as the
    # populated root. The hosted guest disallows the standalone initdb lock.
    checked([rpm, "--root", empty, "-U", "--nosignature", fixture/"observer-fixture.rpm"])
    checked([rpm, "--root", empty, "-e", package])
    config.write_text(empty_config)
    inspect_doctor("doctor-empty-installroot", empty, 0)
    (empty / "etc/dnf/omg-fixture-repos/fixture.repo").unlink()
    inspect_doctor("doctor-empty-installroot-without-repositories", empty, 0)
    config.write_text(host_config)

    def inspect_daemon_metrics():
        phase = "daemon-metrics"
        names = (
            "requests_total", "requests_failed_total", "rate_limit_hits_total",
            "validation_failures_total", "active_connections", "security_audit_requests_total",
            "search_requests_total", "info_requests_total", "status_requests_total",
            "cache_hits_total", "cache_misses_total", "bytes_received_total", "bytes_sent_total",
        )

        def scrape(label):
            response = command([cli, "metrics"], env, ordinary)
            lines = response.stdout.splitlines()
            values = {}
            checks.append(dict(phase=phase, case=f"{label}-exit", passed=response.returncode == 0,
                               status=response.returncode, diagnostic=response.stderr[-600:]))
            for name in names:
                metric = f"omg_{name}"
                kind = "gauge" if name == "active_connections" else "counter"
                sample = [line.removeprefix(f"{metric} ") for line in lines if line.startswith(f"{metric} ")]
                help_text = [line for line in lines if line.startswith(f"# HELP {metric} ")]
                typed = lines.count(f"# TYPE {metric} {kind}") == 1
                passed = len(sample) == len(help_text) == 1 and sample[0].isascii() and sample[0].isdigit() and typed
                if passed:
                    values[name] = int(sample[0])
                checks.append(dict(phase=phase, case=f"{label}-{name}", passed=passed, value=sample))
            return values

        before = scrape("before")
        status = command([cli, "daemon-status"], env, ordinary)
        checks.append(dict(phase=phase, case="daemon-status", passed=status.returncode == 0
                           and "Daemon is running" in status.stdout and "Package Cache" in status.stdout
                           and "Requests total:" in status.stdout, status=status.returncode,
                           diagnostic=status.stderr[-600:]))
        after = scrape("after")
        for metric, delta in (("requests_total", 4), ("status_requests_total", 1),
                              ("requests_failed_total", 0), ("bytes_received_total", None),
                              ("bytes_sent_total", None)):
            old = before.get(metric)
            new = after.get(metric)
            observed = new - old if old is not None and new is not None else None
            expected = observed is not None and (observed > 0 if delta is None else observed == delta)
            checks.append(dict(phase=phase, case=f"delta-{metric}", passed=expected, value=observed))

        for label, mode in (("disabled", disabled), ("missing", dict(env, OMG_SOCKET_PATH=str(runtime / "missing.sock")))):
            response = command([cli, "metrics"], mode, ordinary)
            checks.append(dict(phase=phase, case=label, passed=response.returncode != 0
                               and not response.stdout and "Daemon not running" in response.stderr,
                               status=response.returncode, diagnostic=response.stderr[-600:]))

        with open("/dev/full", "wb") as sink:
            write = subprocess.run([str(cli), "metrics"], cwd=work, env=env, stdout=sink,
                                   stderr=subprocess.PIPE, text=True, timeout=15, **ordinary)
        checks.append(dict(phase=phase, case="output-error", passed=write.returncode == 1
                           and "No space left on device" in write.stderr and "panicked" not in write.stderr,
                           status=write.returncode, diagnostic=write.stderr[-600:]))

    def request_counters():
        counters = dict(line.split() for line in checked([cli, "metrics"], env, ordinary).splitlines()
                        if line.startswith(("omg_requests_total ", "omg_requests_failed_total ")))
        return int(counters["omg_requests_total"]), int(counters["omg_requests_failed_total"])

    def inspect(phase, expected_total, expected_explicit, *, host=False, fixture_explicit=False):
        hook = work / "hook.bash"
        hook.write_text(checked([cli, "hook", "bash"], env, ordinary))
        shell = command(["/usr/bin/bash", "--noprofile", "--norc", "-c",
                         'source "$1"; omg-total-count; omg-explicit-count', "bash", hook], env, ordinary)
        values = shell.stdout.splitlines()
        checks.extend(dict(phase=phase, case=label, passed=shell.returncode == 0 and len(values) == 2
                           and values[index] == str(expected), value=values)
                      for index, (label, expected) in enumerate((
                          ("bash-total", expected_total), ("bash-explicit", expected_explicit)
                      )))
        cases = [
            ("tc-json", ["--json", "tc"], lambda value: value == {"count": expected_total}),
            ("tc-text", ["tc"], lambda value: value == expected_total),
            ("status-json", ["--json", "status"], lambda value: value["total_packages"] == expected_total and value["explicit_packages"] == expected_explicit),
            ("status-fast", ["--json", "status", "--fast"], lambda value: value["total_packages"] == expected_total),
            ("explicit", ["--json", "explicit"], lambda value: len(value["packages"]) == expected_explicit and (package in value["packages"]) == fixture_explicit),
            ("explicit-count", ["--json", "explicit", "--count"], lambda value: value["count"] == expected_explicit),
            ("ec-json", ["--json", "ec"], lambda value: value["count"] == expected_explicit),
            ("ec-text", ["ec"], lambda value: value == expected_explicit),
            ("search", ["--json", "search", "bash"], lambda value: any(item["name"] == f"bash.{os.uname().machine}" for item in value) == host),
            ("tc-after-search", ["--json", "tc"], lambda value: value["count"] == expected_total),
            ("explicit-after-search", ["--json", "explicit"], lambda value: len(value["packages"]) == expected_explicit),
            ("status-after-search", ["--json", "status"], lambda value: value["total_packages"] == expected_total),
        ]
        daemon_log = root / "daemon.log"
        for label, args, verify in cases:
            counters_before = request_counters() if label == "status-json" else None
            log_offset = daemon_log.stat().st_size if counters_before is not None else 0
            result = command([cli, *args], env, ordinary)
            if counters_before is not None:
                requests, failures = request_counters()
                # The second metrics call contributes one request alongside Status.
                requests -= counters_before[0] + 1
                failures -= counters_before[1]
                value = dict(requests=requests, failures=failures)
                if failures:
                    with daemon_log.open("rb") as stream:
                        stream.seek(max(log_offset, daemon_log.stat().st_size - 8192))
                        recent = stream.read(8192)
                    value["reply_write_failed"] = any(signal in recent for signal in
                                                       (b"Client error: Broken pipe",
                                                        b"Client error: Connection reset by peer"))
                checks.append(dict(phase=phase, case="status-ipc", passed=requests == 1 and failures == 0,
                                   value=value))
            try:
                value = json.loads(result.stdout)
                matched = result.returncode == 0 and verify(value)
            except (ValueError, KeyError, TypeError):
                value = result.stdout[-600:]
                matched = False
            detail = value
            if isinstance(value, list):
                detail = {"length": len(value)}
            if isinstance(value, dict) and "packages" in value:
                detail = {"length": len(value["packages"])}
            checks.append(dict(phase=phase, case=label, passed=matched, value=detail, status=result.returncode,
                               diagnostic=result.stderr[-1000:] if result.returncode else None))
        no_daemon = command([cli, "--json", "tc"], disabled, ordinary)
        try:
            matched = no_daemon.returncode == 0 and json.loads(no_daemon.stdout) == {"count": expected_total}
        except ValueError:
            matched = False
        checks.append(dict(phase=phase, case="file-with-ipc-disabled", passed=matched,
                           value=no_daemon.stdout[-600:].strip(), status=no_daemon.returncode,
                           diagnostic=no_daemon.stderr[-1000:] if no_daemon.returncode else None))


    def inspect_info_attempts():
        phase = "info-single-daemon-attempt"
        identity = f"{package}.noarch"
        native = ordinary_control([dnf, "--cacheonly", "repoquery", "--installed",
                                   "--qf", "%{name}.%{arch}\t%{evr}\\n", package])
        assert native.splitlines() == [f"{identity}\t1-1"], native

        def info_count():
            metrics = checked([cli, "metrics"], env, ordinary)
            prefix = "omg_info_requests_total "
            count, = (int(line.removeprefix(prefix)) for line in metrics.splitlines() if line.startswith(prefix))
            return count

        selectors = (
            ("name", package, "found"),
            ("arch", identity, "found"),
            ("nevra", f"{package}-0:1-1.noarch", "found"),
            ("missing", "omg-fixture-name-absent", "missing"),
            ("wrong-arch", f"{package}.aarch64", "missing"),
            ("invalid", f"../{package}", "invalid"),
        )
        formats = (
            ("text", ["info"]),
            ("text-after-separator", ["info", "--"]),
            ("json", ["--json", "info"]),
        )
        for role, mode in (("daemon", env), ("direct", disabled)):
            for form, options in formats:
                for label, selector, outcome in selectors:
                    before = info_count()
                    started = time.monotonic_ns()
                    result = command([cli, *options, selector], mode, ordinary)
                    elapsed_ms = (time.monotonic_ns() - started) / 1_000_000
                    calls = info_count() - before
                    expected_calls = int(role == "daemon" and outcome != "invalid")
                    if outcome == "found" and form == "json":
                        try:
                            value = json.loads(result.stdout)
                            output_ok = (value["name"] == identity and value["version"] == "1-1"
                                         and value["installed"] is True and result.returncode == 0)
                        except (ValueError, KeyError, TypeError):
                            output_ok = False
                    elif outcome == "found":
                        fields = dict(line.strip().split(": ", 1) for line in result.stdout.splitlines()
                                      if ": " in line)
                        output_ok = (fields.get("Name") == identity and fields.get("Version") == "1-1"
                                     and fields.get("Installed") == "yes" and result.returncode == 0)
                    else:
                        expected_error = ("Package name cannot start with '.'" if outcome == "invalid"
                                          else f"Package '{selector}' not found")
                        output_ok = result.returncode != 0 and not result.stdout.strip() and expected_error in result.stderr
                    checks.append(dict(phase=phase, case=f"{role}-{form}-{label}",
                                       passed=output_ok and calls == expected_calls,
                                       status=result.returncode, output_ok=output_ok, requests=calls,
                                       expected_requests=expected_calls, elapsed_ms=round(elapsed_ms, 3),
                                       diagnostic=(result.stderr or result.stdout)[-750:]))


    def inspect_epoch_read_paths():
        phase = "read-nonzero-rpm-epoch"
        values = checked([rpm, "-qa", "--qf", r"%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n"])
        rows = [tuple(line.split("\t")) for line in values.splitlines()]
        matching = sorted(row for row in rows if row[0] in ("findutils", "xz-libs", "openssl-libs", "gmp")
                          and int(row[1]) > 0
                          and sum((other[0], other[4]) == (row[0], row[4]) for other in rows) == 1)
        assert matching, "Fedora host fixture requires a package with a nonzero RPM epoch"
        name, epoch, version, release, architecture = matching[0]
        identity = f"{name}.{architecture}"
        evr = f"{epoch}:{version}-{release}"
        for role, mode in (("daemon", env), ("direct", disabled)):
            for args, label in (
                (["--json", "info", identity], "json-info-arch"),
                (["--json", "info", f"{name}-{evr}.{architecture}"], "json-info-nevra"),
                (["--json", "search", "--limit", "20", identity], "json-search"),
                (["info", identity], "text-info-arch"),
                (["info", f"{name}-{evr}.{architecture}"], "text-info-nevra"),
            ):
                result = command([cli, *args], mode, ordinary)
                try:
                    if label == "json-search":
                        row, = [item for item in json.loads(result.stdout) if item["name"] == identity]
                        correct = row["version"] == evr and row["source"] == "Official"
                    elif label.startswith("json"):
                        row = json.loads(result.stdout)
                        correct = row["name"] == identity and row["version"] == evr and row["installed"] is True
                    else:
                        fields = dict(line.strip().split(": ", 1) for line in result.stdout.splitlines()
                                      if ": " in line)
                        correct = (fields.get("Name") == identity and fields.get("Version") == evr
                                   and fields.get("Installed") == "yes")
                except (ValueError, KeyError, TypeError):
                    correct = False
                checks.append(dict(phase=phase, case=f"{role}-{label}", passed=correct and result.returncode == 0,
                                   status=result.returncode, expected=(identity, evr),
                                   diagnostic=(result.stderr or result.stdout)[-900:]))

    def inspect_repository(phase, expected_available):
        native = ordinary_control([dnf, "--cacheonly", "repoquery", "--available",
                                   "--qf", r"%{name}.%{arch}\n", package]).splitlines()
        identity = f"{package}.noarch"
        assert native == ([identity] if expected_available else []), (phase, native)

        def search_count():
            metrics = checked([cli, "metrics"], env, ordinary)
            return int(next(line.split()[1] for line in metrics.splitlines()
                            if line.startswith("omg_search_requests_total ")))

        before = search_count()
        for role, mode in (("warm", env), ("direct", disabled)):
            for query in (package, identity, "observer-fixture"):
                result = command([cli, "--json", "search", "--limit", "2", query], mode, ordinary)
                try:
                    names = [row["name"] for row in json.loads(result.stdout)]
                    matched = result.returncode == 0 and names == native
                except (ValueError, KeyError, TypeError):
                    names, matched = result.stdout[-600:], False
                checks.append(dict(phase=phase, case=f"{role}-search-{query}", passed=matched,
                                   value=names, status=result.returncode))
            result = command([cli, "--json", "info", package], mode, ordinary)
            if expected_available:
                try:
                    info = json.loads(result.stdout)
                    matched = result.returncode == 0 and info["name"] == identity and info["installed"] is False
                except (ValueError, KeyError, TypeError):
                    matched = False
            else:
                matched = result.returncode != 0 and "not found" in result.stderr.lower() and not result.stdout.strip()
            checks.append(dict(phase=phase, case=f"{role}-info", passed=matched,
                               status=result.returncode, value=(result.stdout or result.stderr)[-650:]))
        daemon_searches = search_count() - before
        checks.append(dict(phase=phase, case="warm-search-ipc", passed=daemon_searches == 3,
                           value=daemon_searches))
        assert package not in checked([rpm, "-qa", "--qf", "%{NAME}\n"]).splitlines()

    def inspect_update_status(phase, expected_updates, expected_findings):
        native = ordinary_control([dnf, "--cacheonly", "repoquery", "--upgrades",
                                   "--qf", r"%{name}\n"]).splitlines()
        assert native == ([package] if expected_updates else []), (phase, native)
        def advisory_status(value, finding):
            summaries = [line.split(maxsplit=1)[1] for line in value.splitlines()
                         if line.split() and line.split()[0] == "Security"]
            return summaries == ["1 findings"] if finding else summaries in (
                ["No reported findings"], ["Advisory coverage unreported"]
            )

        def updates_status(value):
            counts = [line.split()[1] for line in value.splitlines()
                      if line.split() and line.split()[0] == "Updates"]
            return counts == [str(expected_updates)]

        commands = [
            ("uc-json", ["--json", "uc"], env, lambda value: json.loads(value) == {"count": expected_updates}),
            ("uc", ["uc"], env, lambda value: int(value) == expected_updates),
            ("direct-uc", ["--json", "uc"], disabled, lambda value: json.loads(value) == {"count": expected_updates}),
            ("status-json", ["--json", "status"], env, lambda value: json.loads(value)["updates_available"] == expected_updates),
            ("status-fast-json", ["--json", "status", "--fast"], env, lambda value: json.loads(value)["updates_available"] == 0),
            ("direct-status-json", ["--json", "status"], disabled, lambda value: json.loads(value)["updates_available"] == expected_updates),
            ("tc", ["--json", "tc"], env, lambda value: json.loads(value) == {"count": 1}),
            ("ec", ["--json", "ec"], env, lambda value: json.loads(value) == {"count": 1}),
            ("advisory-status", ["status", "--fast"], env, lambda value: "Advisory coverage unreported" in value),
            ("advisory-bare-status", ["status"], env, lambda value: advisory_status(value, expected_findings) and updates_status(value)),
            ("direct-bare-status", ["status"], disabled, lambda value: advisory_status(value, False) and updates_status(value)),
        ]
        for label, args, mode, check in commands:
            before = request_counters() if label == "status-json" else None
            result = command([cli, *args], mode, ordinary)
            try:
                passed = result.returncode == 0 and check(result.stdout)
            except (ValueError, KeyError, TypeError):
                passed = False
            checks.append(dict(phase=phase, case=label, passed=passed, value=result.stdout[-900:],
                               diagnostic=result.stderr[-450:] if result.returncode else None))
            if before is not None:
                after = request_counters()
                checks.append(dict(phase=phase, case="status-ipc", passed=(after[0] - before[0], after[1] - before[1]) == (2, 0),
                                   value=(after[0] - before[0], after[1] - before[1])))

    @contextmanager
    def reject_native_selection(option, *, executable=dnf, prefix=False, after=None):
        target = Path(executable).resolve(strict=True)
        pattern = shlex.quote(option) + ("*" if prefix else "")
        preceding = f' && "$previous" == {shlex.quote(after)}' if after else ""
        diagnostic = ("Unexpected DNF selection subprocess" if executable == dnf
                      else "Unexpected RPM version comparison subprocess")
        with tempfile.TemporaryDirectory(prefix="native-selection-", dir=root) as directory:
            gate = Path(directory)
            gate.chmod(0o755)
            native_executable = gate / target.name
            shutil.copy2(target, native_executable)
            wrapper = gate / "check-native-query"
            wrapper.write_text(f"""#!/usr/bin/bash
previous=""
for argument in "$@"; do
    if [[ "$argument" == {pattern}{preceding} ]]; then
        printf '%s\\n' {shlex.quote(diagnostic)} >&2
        exit 197
    fi
    previous=$argument
done
exec {shlex.quote(str(native_executable))} "$@"
""")
            wrapper.chmod(0o755)
            checked(["/usr/bin/mount", "--bind", wrapper, target])
            try:
                yield
            finally:
                checked(["/usr/bin/umount", target])

    @contextmanager
    def stall_native_report(executable, option):
        target = Path(executable).resolve(strict=True)
        with tempfile.TemporaryDirectory(prefix="native-report-", dir=root) as directory:
            fixture = Path(directory)
            fixture.chmod(0o755)
            native_executable = fixture / target.name
            shutil.copy2(target, native_executable)
            pid = fixture / "pid"
            pid.touch()
            os.chown(pid, account.pw_uid, account.pw_gid)
            wrapper = fixture / "delay-report"
            wrapper.write_text(f"""#!/usr/bin/bash
for argument in "$@"; do
    if [[ "$argument" == {shlex.quote(option)} ]]; then
        printf '%s\\n' "$$" > {shlex.quote(str(pid))}
        exec /usr/bin/sleep 8
    fi
done
exec {shlex.quote(str(native_executable))} "$@"
""")
            wrapper.chmod(0o755)
            checked(["/usr/bin/mount", "--bind", wrapper, target])
            try:
                yield pid
            finally:
                checked(["/usr/bin/umount", target])

    def inspect_native_report_deadlines():
        identity = f"{package}.noarch"
        cases = (
            ("dnf-config-native-fallback", dnf, "--dump-main-config", host_config, True),
            ("rpm-macro-query-refusal", rpm, "--eval", alternate_config, False),
        )
        for label, executable, option, settings, available in cases:
            config.write_text(settings)
            try:
                with stall_native_report(executable, option) as child_pid:
                    started = time.monotonic()
                    result = command([cli, "--json", "search", "--limit", "1", package], disabled, ordinary)
                    elapsed = time.monotonic() - started
                    recorded = child_pid.read_text().strip()
                    reaped = recorded.isdecimal() and not Path(f"/proc/{recorded}").exists()
                    try:
                        matched = result.returncode == 0 and [row["name"] for row in json.loads(result.stdout)] == [identity]
                    except (KeyError, TypeError, ValueError):
                        matched = False
                    if not available:
                        matched = (result.returncode != 0 and not result.stdout.strip()
                                   and "Native package query timed out" in result.stderr)
                    checks.append(dict(phase="native-report-deadline", case=label,
                                       passed=matched and reaped and 2.5 <= elapsed < 6,
                                       elapsed_seconds=elapsed, child_reaped=reaped, status=result.returncode,
                                       diagnostic=(result.stderr or result.stdout)[-800:]))
            finally:
                config.write_text(host_config)

    def inspect_update_query_refusal(phase, blocked_option, expected_empty):
        operations = [
            ("count", ["uc"], lambda value: value == {"count": 0}),
            ("outdated", ["outdated"], lambda value: value == []),
            ("status", ["status"], lambda value: value["total_packages"] == 1
             and value["updates_available"] == 0),
        ]
        with reject_native_selection(blocked_option):
            for label, args, check in operations:
                result = command([cli, "--json", *args], disabled, ordinary)
                blocked = "Unexpected DNF selection subprocess" in result.stderr
                if expected_empty:
                    try:
                        passed = result.returncode == 0 and not blocked and check(json.loads(result.stdout))
                    except (KeyError, TypeError, ValueError):
                        passed = False
                else:
                    passed = result.returncode != 0 and blocked and not result.stdout.strip()
                checks.append(dict(phase=phase, case=f"blocked-update-native-{label}", passed=passed,
                                   status=result.returncode, diagnostic=(result.stderr or result.stdout)[-900:]))




    def audit_fixture_segment(tag, count, *, legacy=False, broken_link=False, severities=None, description_size=0):
        previous = "genesis"
        rows = []
        for sequence in range(count):
            row = dict(id=f"{tag}-{sequence}", timestamp=f"2026-01-01T12:00:{sequence:02d}Z",
                       event_type="policy_violation", severity=severities[sequence] if severities is not None else "info", user="fixture",
                       resource=f"{tag}-{sequence}", description=f"Inventory event {sequence}" + "x" * description_size,
                       prev_hash=previous)
            if broken_link and sequence == 1:
                row["prev_hash"] = "unlinked"
            parts = [row["id"], row["timestamp"], "PolicyViolation", row["severity"].capitalize(),
                     row["user"], row["resource"], row["description"]]
            if legacy:
                preimage = "".join([*parts, row["prev_hash"]]).encode()
            else:
                row["hash_version"] = 1
                fields = [value.encode() for value in (*parts, "", row["prev_hash"])]
                preimage = bytes((255, 1)) + b"".join(len(value).to_bytes(8, "big") + value for value in fields)
            row["hash"] = hashlib.sha256(preimage).hexdigest()
            previous = row["hash"]
            rows.append(row)
        return rows

    def write_audit_fixture_segment(path, rows):
        path.write_text("".join(json.dumps(row) + "\n" for row in rows))
        path.chmod(0o600)
        os.chown(path, account.pw_uid, account.pw_gid)

    def inspect_audit_segments():
        phase = "audit-segment-verification"

        cases = [(index, kind) for index in range(1, 6) for kind in
                 ("valid", "archive-only", "invalid-digest", "invalid-link", "invalid-json", "invalid-file", "incomplete")]
        cases.extend(((1, "empty"), (2, "non-utf8"), (3, "multiple-segments")))
        for index, kind in cases:
            root_data = Path(tempfile.mkdtemp(prefix=f"{phase}-{index}-{kind}-", dir=work))
            os.chown(root_data, account.pw_uid, account.pw_gid)
            data = root_data / os.fsdecode(b"audited-\xff") if kind == "non-utf8" else root_data
            directory = data / "audit"
            directory.mkdir(parents=True)
            for path in (data, directory):
                os.chown(path, account.pw_uid, account.pw_gid)
                path.chmod(0o700)
            active = directory / "audit.jsonl"
            archive = directory / f"audit.jsonl.{index}"
            if kind not in ("empty", "archive-only"):
                write_audit_fixture_segment(active, audit_fixture_segment("active", 1))
            if kind == "invalid-file":
                archive.mkdir()
            elif kind != "empty":
                rows = audit_fixture_segment(f"archive-{index}", 2, legacy=index % 2 == 1, broken_link=kind == "invalid-link")
                if kind == "invalid-digest":
                    rows[1]["description"] = "Unexpected inventory event"
                write_audit_fixture_segment(archive, rows)
                if kind == "invalid-json":
                    with archive.open("ab") as file:
                        file.write(b"{incomplete record\n")
            if kind == "multiple-segments":
                write_audit_fixture_segment(directory / "audit.jsonl.1", audit_fixture_segment("second-segment", 1))
            if kind == "incomplete":
                (directory / "incomplete").touch()
            before = {path.name: path.read_bytes() for path in directory.iterdir() if path.is_file()}
            result = command([cli, "audit", "verify"], dict(disabled, OMG_DATA_DIR=str(data)), ordinary)
            lines = result.stdout.splitlines()
            verified = "Local audit chain consistency verified" in result.stdout
            if kind == "incomplete":
                correct = (result.returncode == 1 and not verified
                           and "Audit collection is incomplete" in result.stderr)
            elif kind == "empty":
                correct = result.returncode == 0 and not verified and "No audit log exists yet." in result.stdout
            elif kind == "invalid-file":
                correct = (result.returncode == 1 and not verified
                           and archive.name in result.stderr and "regular file" in result.stderr)
            else:
                total = {"archive-only": 2, "multiple-segments": 4, "invalid-json": 4}.get(kind, 3)
                invalid = kind.startswith("invalid-")
                valid = total - int(kind in ("invalid-json", "invalid-digest"))
                counts = f"Total: {total} entries" in result.stdout and f"Valid: {valid} entries" in result.stdout
                if invalid:
                    first_invalid = "line_3" if kind == "invalid-json" else f"archive-{index}-1"
                    correct = (result.returncode == 1 and not verified and counts
                               and any("First Invalid:" in line and archive.name in line and first_invalid in line for line in lines))
                else:
                    correct = result.returncode == 0 and verified and counts
            after = {path.name: path.read_bytes() for path in directory.iterdir()
                     if path.is_file() and path.name != "audit.lock"}
            assert before == after, (index, kind)
            checks.append(dict(phase=phase, case=f"{index}-{kind}", passed=correct, status=result.returncode,
                               diagnostic=(result.stdout + result.stderr)[-1200:]))



    def inspect_team_storage():
        phase = "team-storage"
        with tempfile.TemporaryDirectory(prefix="team-storage-", dir=work) as directory:
            here = Path(directory)
            os.chown(here, account.pw_uid, account.pw_gid)
            isolated = dict(disabled, HOME=str(here), XDG_DATA_HOME=str(here/"data"),
                            XDG_CONFIG_HOME=str(here/"config"), XDG_CACHE_HOME=str(here/"cache"),
                            XDG_STATE_HOME=str(here/"state"))
            lockfile = here / "omg.lock"
            config = here / ".omg/team.toml"
            stored_status = here / ".omg/team-status.json"
            status_lock = here / ".omg/team-status.lock"
            write_lock = here / ".omg.lock.write.lock"
            status_args = ("team", "status")
            limit = 16 * 1024 * 1024

            def run(label, args, markers=(), *, fails=False, inspect=None,
                    preserve_status=False, umask=-1):
                before = stored_status.read_bytes() if preserve_status else None
                try:
                    result = command([cli, *args], isolated, dict(ordinary, umask=umask), timeout=8)
                except subprocess.TimeoutExpired:
                    checks.append(dict(phase=phase, case=label, passed=False, status=None,
                                       diagnostic="command exceeded local deadline"))
                    return
                text = result.stdout + result.stderr
                okay = ((result.returncode != 0) == fails and all(marker in text for marker in markers)
                        and (inspect is None or inspect())
                        and (not preserve_status or stored_status.read_bytes() == before))
                checks.append(dict(phase=phase, case=label, passed=okay, status=result.returncode,
                                   diagnostic=text[-1000:]))

            def is_private_file(path):
                return path.is_file() and path.stat().st_mode & 0o777 == 0o600

            def reset(path):
                try:
                    if stat.S_ISDIR(path.lstat().st_mode):
                        path.rmdir()
                    else:
                        path.unlink()
                except FileNotFoundError:
                    pass

            def variant(path, kind, alternative):
                reset(path)
                if kind == "directory":
                    path.mkdir()
                elif kind == "symlink":
                    path.symlink_to(alternative)
                else:
                    assert kind == "fifo"
                    os.mkfifo(path)
                    os.chown(path, account.pw_uid, account.pw_gid)

            def guarded(label, args):
                before = lockfile.read_bytes()
                write_lock.touch()
                write_lock.chmod(0o666)
                with write_lock.open("rb") as guard:
                    fcntl.flock(guard, fcntl.LOCK_EX)
                    with subprocess.Popen([str(cli), *args], cwd=here, env=isolated, text=True,
                                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, **ordinary) as process:
                        try:
                            process.wait(timeout=0.55)
                        except subprocess.TimeoutExpired:
                            waited = True
                        else:
                            waited = False
                        held_original = lockfile.read_bytes() == before
                        fcntl.flock(guard, fcntl.LOCK_UN)
                        try:
                            output, errors = process.communicate(timeout=8)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            output, errors = process.communicate()
                            waited = False
                checks.append(dict(phase=phase, case=label,
                                   passed=(waited and held_original and process.returncode == 0
                                           and lockfile.stat().st_mode & 0o777 == 0o600),
                                   status=process.returncode, waited=waited,
                                   diagnostic=(output + errors)[-1000:]))

            run("init", ("team", "init", "fixture/storage"), ("fixture/storage",))
            run("status-without-lockfile", status_args, ("members in sync",))
            run("capture-baseline", ("env", "capture"), ("Environment state captured",),
                inspect=lambda: lockfile.stat().st_mode & 0o777 == 0o600)
            run("status-with-lockfile", status_args, ("members in sync",))
            good_config = config.read_bytes()
            good_status = stored_status.read_bytes()
            (here/"config-source").write_bytes(good_config)
            (here/"status-source").write_bytes(good_status)
            (here/"lock-source").write_bytes(b"fixture lock target\n")

            config.write_text("team_id = [\n")
            run("config-invalid-toml", status_args, ("Failed to parse team config",),
                fails=True, preserve_status=True)
            config.write_bytes(b"\xff")
            run("config-invalid-utf8", status_args, ("Failed to read Team config",),
                fails=True, preserve_status=True)
            for kind in ("directory", "symlink", "fifo"):
                variant(config, kind, here/"config-source")
                run(f"config-{kind}", status_args, ("Team config must be a regular file",),
                    fails=True, preserve_status=True,
                    inspect=lambda: (here/"config-source").read_bytes() == good_config)
            reset(config)
            config.write_bytes(good_config.ljust(limit, b" "))
            run("config-at-bound", status_args, ("members in sync",))
            config.write_bytes(good_config.ljust(limit + 1, b" "))
            run("config-above-bound", status_args, ("Team config exceeds",),
                fails=True, preserve_status=True)
            config.write_bytes(good_config)
            run("config-restored", status_args, ("members in sync",))

            stored_status.write_text("{\n")
            run("status-invalid-json", status_args, ("Failed to parse team status",),
                fails=True, preserve_status=True)
            stored_status.write_bytes(b"\xff")
            run("status-invalid-utf8", status_args, ("Failed to read Team status",),
                fails=True, preserve_status=True)
            for kind in ("directory", "symlink", "fifo"):
                variant(stored_status, kind, here/"status-source")
                run(f"status-{kind}", status_args, ("Team status must be a regular file",),
                    fails=True, inspect=lambda: (here/"status-source").read_bytes() == good_status)
            reset(stored_status)
            stored_status.write_bytes(good_status.ljust(limit, b" "))
            run("status-at-bound", status_args, ("members in sync",))
            stored_status.write_bytes(good_status.ljust(limit + 1, b" "))
            run("status-above-bound", status_args, ("Team status exceeds",),
                fails=True, preserve_status=True)
            stored_status.write_bytes(good_status)
            run("status-restored", status_args, ("members in sync",))

            for kind in ("directory", "symlink", "fifo"):
                variant(status_lock, kind, here/"lock-source")
                run(f"status-lock-{kind}", status_args, ("must be a regular file",),
                    fails=True, preserve_status=True,
                    inspect=lambda: (here/"lock-source").read_bytes() == b"fixture lock target\n")
            reset(status_lock)

            for trial in range(4):
                guarded(f"capture-waits-{trial}", ("env", "capture"))
            for trial in range(3):
                guarded(f"team-push-waits-{trial}", ("team", "push"))

            for kind in ("directory", "symlink", "fifo"):
                variant(write_lock, kind, here/"lock-source")
                retained = lockfile.read_bytes()
                run(f"write-lock-{kind}", ("env", "capture"), ("must be a regular file",),
                    fails=True, inspect=lambda: lockfile.read_bytes() == retained
                    and (here/"lock-source").read_bytes() == b"fixture lock target\n")
            reset(write_lock)
            run("capture-restored", ("env", "capture"), ("Environment state captured",), umask=0o777,
                inspect=lambda: is_private_file(write_lock) and is_private_file(lockfile))
            reset(status_lock)
            run("status-lock-created", status_args, ("members in sync",), umask=0o777,
                inspect=lambda: is_private_file(status_lock))
            run("status-lock-reused", status_args, ("members in sync",), umask=0o777,
                inspect=lambda: is_private_file(status_lock) and status_lock.read_bytes() == b"")

    def inspect_team_commands():
        import tomllib

        phase = "team-commands"
        with tempfile.TemporaryDirectory(prefix="team-commands-", dir=work) as directory:
            here = Path(directory)
            os.chown(here, account.pw_uid, account.pw_gid)
            profile = here / "profile"
            isolated = dict(disabled, HOME=str(here), OMG_CONFIG_DIR=str(profile),
                            XDG_DATA_HOME=str(here/"data"), XDG_CONFIG_HOME=str(here/"config"),
                            XDG_CACHE_HOME=str(here/"cache"), XDG_STATE_HOME=str(here/"state"))
            team = here / ".omg/team.toml"
            status = here / ".omg/team-status.json"
            lock = here / "omg.lock"
            templates = profile / "golden-paths.toml"
            templates_guard = profile / "golden-paths.lock"

            def run(label, args, markers=(), *, fails=False, inspect=None, forbidden=()):
                try:
                    result = command([cli, "team", *args], isolated, ordinary, timeout=6)
                except subprocess.TimeoutExpired:
                    checks.append(dict(phase=phase, case=label, passed=False, status=None,
                                       diagnostic="command exceeded local deadline"))
                    return
                output = result.stdout + result.stderr
                okay = ((result.returncode != 0) == fails
                        and all(marker in output for marker in markers)
                        and all(marker not in output for marker in forbidden)
                        and (inspect is None or inspect()))
                checks.append(dict(phase=phase, case=label, passed=okay, status=result.returncode,
                                   diagnostic=output[-1200:]))

            def contents():
                return tomllib.loads(templates.read_text())["templates"]

            def workspace_absent():
                return not team.parent.exists() and not lock.exists()

            for action in ("status", "push", "pull"):
                run(f"{action}-missing-workspace", (action,), ("Not a team workspace",),
                    fails=True, inspect=workspace_absent)
            run("bad-team-id", ("init", "bad id"), ("Invalid team ID",),
                fails=True, inspect=workspace_absent)
            run("team-name-newline", ("init", "fixture/team", "--name", "line\nbreak"),
                ("Invalid team name",), fails=True, inspect=workspace_absent)
            run("team-name-over-limit", ("init", "fixture/team", "--name", "a"*129),
                ("Invalid team name",), fails=True, inspect=workspace_absent)
            run("init", ("init", "fixture/team", "--name", "Équipe"), ("Équipe",))
            original_config = team.read_bytes()
            original_status = status.read_bytes()
            run("init-existing", ("init", "other/team"), ("already initialized",), fails=True,
                inspect=lambda: (team.read_bytes(), status.read_bytes()) == (original_config, original_status))
            run("pull-no-lock", ("pull",), ("No team omg.lock",), fails=True,
                inspect=lambda: not lock.exists(),
                forbidden=("Environment is in sync",))
            run("push", ("push",), ("Team lock updated",), inspect=lock.is_file)
            run("pull-matching-lock", ("pull",), ("Environment is in sync",))
            saved_lock = lock.read_bytes()
            lock.write_text("runtimes = [\n")
            run("pull-broken-lock", ("pull",), fails=True, forbidden=("Environment is in sync",))
            lock.write_bytes(saved_lock)

            # Rejected inputs must leave the persisted remote and lock alone.
            for label, url in (
                ("wrong-scheme", "http://gist.github.com/ci/0123abcdef"),
                ("wrong-host", "https://example.invalid/ci/0123abcdef"),
                ("missing-id", "https://gist.github.com/"),
                ("short-id", "https://gist.github.com/ci/abc"),
                ("nonhex-id", "https://gist.github.com/ci/example"),
                ("query", "https://gist.github.com/ci/0123abcdef?view=1"),
                ("fragment", "https://gist.github.com/ci/0123abcdef#file"),
                ("nonstandard-port", "https://gist.github.com:8443/ci/0123abcdef"),
            ):
                team.write_bytes(original_config)
                run(f"join-{label}", ("join", url), fails=True,
                    inspect=lambda: team.read_bytes() == original_config and lock.read_bytes() == saved_lock)
            team.write_bytes(original_config)
            status_data = json.loads(status.read_bytes())
            peer = dict(status_data["members"][0], id="fixture-peer", name="peer\u2028fixture")
            status_data["members"].append(peer)
            status.write_text(json.dumps(status_data))
            original_name = 'name = "Équipe"'.encode()
            assert original_name in original_config
            team.write_bytes(original_config.replace(original_name, 'name = "Équipe\u2028fixture"'.encode()))
            run("status-keeps-fields-on-one-line", ("status",), ("Équipefixture", "peerfixture"),
                forbidden=("\u2028",),
                inspect=lambda: any(member["name"] == peer["name"]
                                    for member in json.loads(status.read_bytes())["members"]))
            team.write_bytes(original_config)
            status.write_bytes(original_status)
            run("status-restored", ("status",), ("Équipe", "members in sync"))

            def gp(*args):
                return ("golden-path", *args)

            run("templates-empty", gp("list"), ("No custom templates",))
            run("template-empty-name", gp("create", ""), ("Invalid template name",), fails=True,
                inspect=lambda: not templates.exists())
            templates.unlink(missing_ok=True)
            run("template-bad-name", gp("create", "bad name"), ("Invalid template name",),
                fails=True, inspect=lambda: not templates.exists())
            run("template-bad-version", gp("create", "valid", "--node", "20 21"),
                ("Invalid Node version",), fails=True, inspect=lambda: not templates.exists())
            run("template-empty-package", gp("create", "valid", "--packages", "python,"),
                ("Invalid package name",), fails=True, inspect=lambda: not templates.exists())
            run("template-create", gp("create", "starter", "--python", "3.12", "--node", "20"),
                ("created",), inspect=lambda: len(contents()) == 1)
            run("template-replace", gp("create", "starter", "--python", "3.13", "--node", "22"),
                ("created",), inspect=lambda: [entry["runtimes"] for entry in contents()]
                == [{"node": "22", "python": "3.13"}])
            run("template-list-ordered", gp("list"), ("starter - runtimes: [node, python]",))
            original_templates = templates.read_bytes()
            run("template-delete-missing", gp("delete", "missing"), ("not found",),
                inspect=lambda: templates.read_bytes() == original_templates)

            templates_guard.touch()
            os.chown(templates_guard, account.pw_uid, account.pw_gid)
            with templates_guard.open("rb") as guard:
                fcntl.flock(guard, fcntl.LOCK_EX)
                with subprocess.Popen([str(cli), "team", *gp("create", "second")], cwd=here,
                                      env=isolated, text=True, stdin=subprocess.DEVNULL,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, **ordinary) as child:
                    try:
                        child.wait(timeout=0.55)
                        waited = False
                    except subprocess.TimeoutExpired:
                        waited = True
                    preserved = templates.read_bytes() == original_templates
                    run("template-read-during-write", gp("list"), ("starter",), forbidden=("second",))
                    fcntl.flock(guard, fcntl.LOCK_UN)
                    try:
                        output, errors = child.communicate(timeout=8)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        output, errors = child.communicate()
                        waited = False
            checks.append(dict(phase=phase, case="template-writer-waits", status=child.returncode,
                               passed=(waited and preserved and child.returncode == 0
                                       and {entry["name"] for entry in contents()} == {"starter", "second"}),
                               diagnostic=(output + errors)[-1200:]))
            run("template-delete", gp("delete", "second"), ("Deleted template",),
                inspect=lambda: [entry["name"] for entry in contents()] == ["starter"])

            original_templates = templates.read_bytes()
            limit = 16 * 1024 * 1024
            templates.write_bytes(original_templates.ljust(limit, b" "))
            run("template-file-at-bound", gp("list"), ("starter",))
            templates.write_bytes(original_templates.ljust(limit + 1, b" "))
            run("template-file-above-bound", gp("list"), ("Golden path config exceeds",), fails=True)
            templates.unlink()
            reference = here / "template-source"
            reference.write_bytes(original_templates)
            templates.symlink_to(reference)
            run("template-file-symlink", gp("list"), ("Golden path config must be a regular file",),
                fails=True, inspect=lambda: reference.read_bytes() == original_templates)
            templates.unlink()
            templates.mkdir()
            run("template-file-directory", gp("list"), ("Golden path config must be a regular file",), fails=True)
            templates.rmdir()
            os.mkfifo(templates, 0o644)
            run("template-file-fifo", gp("list"), ("Golden path config must be a regular file",), fails=True)
            templates.unlink()
            templates.write_bytes(original_templates)
            run("template-file-restored", gp("list"), ("starter",))


    def inspect_team_push_publication():
        import tomllib

        phase = "team-push-publication"
        with tempfile.TemporaryDirectory(prefix="team-push-publication-", dir=work) as directory:
            here = Path(directory)
            os.chown(here, account.pw_uid, account.pw_gid)
            isolated = dict(disabled, HOME=str(here), XDG_DATA_HOME=str(here/"data"),
                            XDG_CONFIG_HOME=str(here/"config"), XDG_CACHE_HOME=str(here/"cache"),
                            XDG_STATE_HOME=str(here/"state"))
            lock = here / "omg.lock"
            status = here / ".omg/team-status.json"
            guard = here / ".omg/team-status.lock"
            writer = here / ".omg.lock.write.lock"
            prior = b"previous environment bytes\n"
            push = ("team", "push")

            def run(label, args, markers=(), *, fails=False, inspect=None):
                try:
                    result = command([cli, *args], isolated, ordinary, timeout=8)
                except subprocess.TimeoutExpired:
                    checks.append(dict(phase=phase, case=label, passed=False, status=None,
                                       diagnostic="command exceeded local deadline"))
                    return
                output = result.stdout + result.stderr
                okay = ((result.returncode != 0) == fails
                        and all(marker in output for marker in markers)
                        and (inspect is None or inspect()))
                checks.append(dict(phase=phase, case=label, passed=okay, status=result.returncode,
                                   diagnostic=output[-1000:]))

            expected = sorted(set(checked([dnf, "--cacheonly", "--setopt=disable_excludes=*",
                                           "repoquery", "--userinstalled", "--qf", r"%{name}\n"],
                                          isolated, ordinary).splitlines()))
            assert len(expected) > 1
            run("init", ("team", "init", "fixture/push"), ("initialized",))
            initial_status = status.read_bytes()

            def published():
                current = tomllib.loads(lock.read_text())
                team = json.loads(status.read_text())
                members = [member for member in team["members"] if member["id"] == team["config"]["member_id"]]
                return (current["packages"] == expected and len(members) == 1
                        and members[0]["env_hash"] == current["hash"] == team["lock_hash"]
                        and members[0]["in_sync"] and lock.stat().st_mode & 0o777 == 0o600)

            run("first-push", push, ("Team lock updated",), inspect=published)
            run("check-first-push", ("env", "check"), ("Environment is in sync",))
            run("pull-first-push", ("team", "pull"), ("Environment is in sync",))
            run("status-first-push", ("team", "status"), ("1/1 members in sync",), inspect=published)

            document = json.loads(initial_status)
            limit = 16 * 1024 * 1024
            for label, obstruction, marker in (
                ("missing", None, "Failed to inspect Team status"),
                ("malformed", b"{\n", "Failed to parse team status"),
                ("invalid-utf8", b"\xff", "Failed to read Team status"),
                ("too-large", initial_status.ljust(limit + 1, b" "), "Team status exceeds"),
                ("newer-format", json.dumps(dict(document, format_version=99)).encode(),
                 "was written by a newer omg"),
                ("wrong-team", json.dumps(dict(document, config=dict(document["config"],
                 team_id="other/team"))).encode(), "belongs to a different team"),
            ):
                status.unlink(missing_ok=True)
                if obstruction is not None:
                    status.write_bytes(obstruction)
                lock.write_bytes(prior)
                run(f"push-status-{label}", push, (marker,), fails=True,
                    inspect=lambda: lock.read_bytes() == prior
                    and (not status.exists() if obstruction is None else status.read_bytes() == obstruction))
            status.unlink(missing_ok=True)
            link_target = here / "status-source"
            link_target.write_bytes(initial_status)
            for label in ("directory", "symlink", "fifo"):
                if label == "directory":
                    status.mkdir()
                elif label == "symlink":
                    status.symlink_to(link_target)
                else:
                    os.mkfifo(status, 0o644)
                lock.write_bytes(prior)
                run(f"push-status-{label}", push, ("Team status must be a regular file",), fails=True,
                    inspect=lambda: lock.read_bytes() == prior and link_target.read_bytes() == initial_status)
                if label == "directory":
                    status.rmdir()
                else:
                    status.unlink()
            status.write_bytes(initial_status)
            guard.unlink()
            guard.mkdir()
            run("push-status-guard-directory", push, ("Lock path must be a regular file",), fails=True,
                inspect=lambda: lock.read_bytes() == prior and status.read_bytes() == initial_status)
            guard.rmdir()
            guard.touch()
            os.chown(guard, account.pw_uid, account.pw_gid)

            lock.write_bytes(prior)
            status.parent.chmod(0o500)
            try:
                run("push-status-parent-read-only", push, ("Failed to create temporary file",),
                    fails=True, inspect=lambda: lock.read_bytes() == prior
                    and status.read_bytes() == initial_status)
            finally:
                status.parent.chmod(0o700)

            for trial in range(4):
                lock.write_bytes(prior)
                status.write_bytes(initial_status)
                with guard.open("rb") as held:
                    fcntl.flock(held, fcntl.LOCK_EX)
                    with subprocess.Popen([str(cli), *push], cwd=here, env=isolated, text=True,
                                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, **ordinary) as child:
                        try:
                            child.wait(timeout=0.4)
                            waited = False
                        except subprocess.TimeoutExpired:
                            waited = True
                        stayed = lock.read_bytes() == prior and status.read_bytes() == initial_status
                        fcntl.flock(held, fcntl.LOCK_UN)
                        try:
                            output, errors = child.communicate(timeout=8)
                        except subprocess.TimeoutExpired:
                            child.kill()
                            output, errors = child.communicate()
                            waited = False
                checks.append(dict(phase=phase, case=f"push-waits-before-publication-{trial}",
                                   status=child.returncode, waited=waited, prior_preserved=stayed,
                                   passed=(waited and stayed and child.returncode == 0 and published()),
                                   diagnostic=(output + errors)[-1000:]))

            writer.unlink()
            writer.symlink_to(link_target)
            lock.write_bytes(prior)
            status.write_bytes(initial_status)
            run("push-invalid-workspace-guard", push, ("Lock path must be a regular file",), fails=True,
                inspect=lambda: lock.read_bytes() == prior and status.read_bytes() == initial_status)
            writer.unlink()
            lock.unlink()
            lock.mkdir()
            (lock/"kept").write_bytes(prior)
            run("push-target-directory", push, ("Failed to replace lockfile",), fails=True,
                inspect=lambda: (lock/"kept").read_bytes() == prior and status.read_bytes() == initial_status)
            (lock/"kept").unlink()
            lock.rmdir()
            run("push-after-obstructions", push, ("Team lock updated",), inspect=published)

            # A status file exactly at the read limit remains usable when its
            # serialized replacement fits.
            status.write_bytes(status.read_bytes().ljust(limit, b" "))
            run("push-status-at-bound", push, ("Team lock updated",), inspect=published)

            for trial in range(3):
                peer_doc = json.loads(initial_status)
                peer = dict(peer_doc["members"][0], id=f"peer-{trial}", name=f"Peer {trial}", in_sync=False)
                peer_doc["members"].append(peer)
                status.write_text(json.dumps(peer_doc))
                run(f"push-preserves-peer-{trial}", push, ("Team lock updated",),
                    inspect=lambda: published() and json.loads(status.read_bytes())["members"][1] == peer)

            run("status-after-repeated-push", ("team", "status"), ("1/2 members in sync",), inspect=published)
            run("env-check-after-repeated-push", ("env", "check"), ("Environment is in sync",))
            run("pull-after-repeated-push", ("team", "pull"), ("Environment is in sync",))


    def inspect_git_workflow():
        phase = "git-workflow"
        executable = shutil.which("git", path=base_env["PATH"])
        assert executable is not None, "Git is required for the staged workflow checks"
        with tempfile.TemporaryDirectory(prefix="git-workflow-", dir=work) as directory:
            here = Path(directory)
            os.chown(here, account.pw_uid, account.pw_gid)
            isolated = dict(disabled, HOME=str(here), GIT_CONFIG_NOSYSTEM="1",
                            XDG_DATA_HOME=str(here/"data"), XDG_CONFIG_HOME=str(here/"config"),
                            XDG_CACHE_HOME=str(here/"cache"), XDG_STATE_HOME=str(here/"state"))

            def child(program, args, cwd):
                return subprocess.run([str(program), *args], cwd=cwd, env=isolated, text=True,
                                      stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, timeout=10, **ordinary)

            def git(*args, cwd=here):
                result = child(executable, args, cwd)
                assert result.returncode == 0, (args, result.stderr)
                return result.stdout

            def run(label, args, markers=(), *, cwd=here, fails=False, inspect=None):
                try:
                    result = child(cli, args, cwd)
                except subprocess.TimeoutExpired:
                    checks.append(dict(phase=phase, case=label, passed=False, status=None,
                                       diagnostic="command exceeded local deadline"))
                    return
                output = result.stdout + result.stderr
                okay = ((result.returncode != 0) == fails
                        and all(marker in output for marker in markers)
                        and (inspect is None or inspect()))
                checks.append(dict(phase=phase, case=label, passed=okay, status=result.returncode,
                                   diagnostic=output[-1100:]))

            def owned_dir(path):
                path.mkdir()
                os.chown(path, account.pw_uid, account.pw_gid)

            def init_repo(path):
                git("init", "--quiet", cwd=path)
                git("config", "user.name", "Fedora audit", cwd=path)
                git("config", "user.email", "fixture@example.invalid", cwd=path)
                git("config", "commit.gpgsign", "false", cwd=path)

            def set_hook(path, body):
                path.write_text(body)
                path.chmod(0o755)

            def auto_push(path):
                config = path / ".omg/team.toml"
                old = config.read_text()
                assert "auto_push = false" in old
                config.write_text(old.replace("auto_push = false", "auto_push = true"))

            run("status-outside-repo", ("hooks", "status"), ("Not a git repository",))
            run("install-outside-repo", ("hooks", "install"), ("Not a git repository",), fails=True)
            init_repo(here)
            git("commit", "--allow-empty", "--quiet", "-m", "Fixture base")
            git("config", "core.hooksPath", "fixture hooks")
            hooks = here / "fixture hooks"
            pre = hooks / "pre-commit"
            nested = here / "nested"
            owned_dir(nested)
            all_names = ("pre-commit", "post-checkout", "post-merge")
            run("status-no-hooks", ("hooks", "status"), ("pre-commit - not installed",))
            run("install-from-nested", ("hooks", "install"), ("Installed 3 hook(s)",), cwd=nested,
                inspect=lambda: all((hooks/name).stat().st_mode & 0o100 for name in all_names))
            generated = pre.read_bytes()
            run("status-generated", ("hooks", "status"), ("pre-commit - installed (OMG)",), cwd=nested)
            run("manual-generated", ("hooks", "run", "pre-commit"), ("Hook completed successfully",))
            run("install-idempotent", ("hooks", "install"), ("already installed",),
                inspect=lambda: pre.read_bytes() == generated)
            pre.chmod(0o644)
            run("status-disabled-generated", ("hooks", "status"), ("pre-commit - installed (OMG, not executable)",))
            run("install-restores-executable", ("hooks", "install"), ("pre-commit",),
                inspect=lambda: pre.read_bytes() == generated and bool(pre.stat().st_mode & 0o100))
            pre.chmod(0o755)
            set_hook(pre, "#!/bin/sh\n[ -f hook-cwd-marker ] || exit 17\nprintf 'fixture hook saw repository root\\n'\n")
            (here/"hook-cwd-marker").touch()
            custom = pre.read_bytes()
            run("status-custom", ("hooks", "status"), ("unrecognized or modified",))
            run("install-preserves-custom", ("hooks", "install"), ("exists, use --force",),
                inspect=lambda: pre.read_bytes() == custom)
            run("manual-custom-from-root", ("hooks", "run", "pre-commit"), ("fixture hook saw repository root",))
            run("manual-custom-from-nested", ("hooks", "run", "pre-commit"),
                ("fixture hook saw repository root",), cwd=nested)
            run("force-replaces-custom", ("hooks", "install", "--force"), ("Installed 3 hook(s)",),
                inspect=lambda: pre.read_bytes() == generated)
            post = hooks / "post-merge"
            set_hook(post, "#!/bin/sh\nprintf 'custom post merge\\n'\n")
            run("uninstall-keeps-custom", ("hooks", "uninstall"), ("Removed 2 hook(s)",),
                inspect=lambda: not pre.exists() and post.is_file())
            run("status-after-uninstall", ("hooks", "status"), ("pre-commit - not installed", "unrecognized or modified"))
            run("manual-missing-managed", ("hooks", "run", "pre-commit"), ("is not installed",), fails=True)
            run("manual-unknown", ("hooks", "run", "fixture-extra"), ("Unknown hook",), fails=True)
            set_hook(pre, "#!/bin/sh\nprintf 'deliberate hook rejection\\n' >&2\nexit 18\n")
            run("manual-returns-hook-failure", ("hooks", "run", "pre-commit"),
                ("deliberate hook rejection", "failed"), fails=True)

            run("team-init", ("team", "init", "fixture/auto-git"), ("initialized",))
            auto_push(here)
            lock = here / "omg.lock"
            unrelated = here / "unrelated"
            unrelated.write_text("staged fixture\n")
            git("add", "--", unrelated.name)
            unrelated.write_text("unstaged fixture\n")
            unrelated_stage = git("ls-files", "--stage", "--", unrelated.name)
            initial_head = git("rev-parse", "HEAD")

            def unrelated_preserved():
                return (git("ls-files", "--stage", "--", unrelated.name) == unrelated_stage
                        and unrelated.read_text() == "unstaged fixture\n")

            push = ("team", "push")
            run("auto-first-rejected", push, ("deliberate hook rejection",), fails=True,
                inspect=lambda: (git("rev-parse", "HEAD") == initial_head and unrelated_preserved()
                                 and not git("diff", "--cached", "--ita-invisible-in-index", "--name-only", "--", lock.name)))
            set_hook(pre, "#!/bin/sh\nexit 0\n")
            run("auto-first-retry", push, ("Team lock updated",),
                inspect=lambda: (git("show", "--format=", "--name-only", "HEAD") == "omg.lock\n"
                                 and git("show", "HEAD:omg.lock").encode() == lock.read_bytes()
                                 and unrelated_preserved()))

            (here/".gitattributes").write_text("omg.lock filter=auditlock\n")
            git("config", "filter.auditlock.clean", "sed -E 's/^timestamp = [0-9]+$/timestamp = 1700000000/'")
            git("add", "--", lock.name)
            git("commit", "--only", "--quiet", "-m", "Deterministic lock dates", "--", lock.name)
            stable_head = git("rev-parse", "HEAD")
            lock.write_text("manually staged lock contents\n")
            git("add", "--", lock.name)
            candidate_staged = git("show", ":omg.lock")
            set_hook(pre, "#!/bin/sh\nprintf 'deliberate hook rejection\\n' >&2\nexit 18\n")
            run("auto-unchanged-preserves-staged", push, ("Team lock updated",),
                inspect=lambda: (git("rev-parse", "HEAD") == stable_head and unrelated_preserved()
                                 and git("show", ":omg.lock") == candidate_staged))

            git("rm", "-qf", "--cached", "--", lock.name)
            run("auto-unchanged-preserves-staged-deletion", push, ("Team lock updated",),
                inspect=lambda: (git("rev-parse", "HEAD") == stable_head and unrelated_preserved()
                                 and git("ls-files", "--stage", "--", lock.name) == ""))
            git("add", "--", lock.name)

            lock.write_text("different historical lock\n")
            set_hook(pre, "#!/bin/sh\nexit 0\n")
            git("commit", "--only", "--quiet", "-m", "Different historical lock", "--", lock.name)
            stable_head = git("rev-parse", "HEAD")
            lock.write_text(candidate_staged)
            git("add", "--", lock.name)
            set_hook(pre, "#!/bin/sh\nprintf 'deliberate hook rejection\\n' >&2\nexit 18\n")
            run("auto-tracked-rejection-preserves-staging", push, ("deliberate hook rejection",), fails=True,
                inspect=lambda: (git("rev-parse", "HEAD") == stable_head and unrelated_preserved()
                                 and git("show", ":omg.lock") == candidate_staged))
            git("rm", "-qf", "--cached", "--", lock.name)
            run("auto-rejection-preserves-staged-deletion", push, ("deliberate hook rejection",), fails=True,
                inspect=lambda: (git("rev-parse", "HEAD") == stable_head and unrelated_preserved()
                                 and git("ls-files", "--stage", "--", lock.name) == ""))

            set_hook(pre, "#!/bin/sh\nexit 0\n")
            run("auto-tracked-retry", push, ("Team lock updated",),
                inspect=lambda: (git("rev-parse", "HEAD") != stable_head and unrelated_preserved()
                                 and git("show", "--format=", "--name-only", "HEAD") == "omg.lock\n"))

            unborn = here / "unborn"
            owned_dir(unborn)
            init_repo(unborn)
            run("unborn-team-init", ("team", "init", "fixture/unborn"), ("initialized",), cwd=unborn)
            auto_push(unborn)
            run("unborn-commits-lock", push, ("Team lock updated",), cwd=unborn,
                inspect=lambda: git("show", "--format=", "--name-only", "HEAD", cwd=unborn) == "omg.lock\n")

            ignored = here / "ignored"
            owned_dir(ignored)
            init_repo(ignored)
            (ignored/".gitignore").write_text("omg.lock\n")
            run("ignored-team-init", ("team", "init", "fixture/ignored"), ("initialized",), cwd=ignored)
            auto_push(ignored)
            run("auto-respects-ignored-lock", push, ("ignored",), cwd=ignored, fails=True,
                inspect=lambda: git("ls-files", "--stage", "--", "omg.lock", cwd=ignored) == "")


    def inspect_scaffold_publication():
        phase = "scaffold-publication"
        git = shutil.which("git", path=base_env["PATH"])
        assert git is not None
        with tempfile.TemporaryDirectory(prefix="scaffold-publication-", dir=work) as directory:
            here = Path(directory)
            os.chown(here, account.pw_uid, account.pw_gid)
            data = here / "data"
            isolated = dict(disabled, HOME=str(here), OMG_DATA_DIR=str(data), GIT_CONFIG_NOSYSTEM="1",
                            XDG_DATA_HOME=str(data), XDG_CONFIG_HOME=str(here/"config"),
                            XDG_CACHE_HOME=str(here/"cache"), XDG_STATE_HOME=str(here/"state"))
            bin_dir = here / "fixture-bin"
            bin_dir.mkdir()
            marker = here / "ambient-command"
            signals = here / "signals"
            signals.mkdir()
            os.chown(signals, account.pw_uid, account.pw_gid)
            git_fixture = bin_dir / "git"
            git_fixture.write_text(f"""#!/bin/sh
case "$OMG_FIXTURE_GIT_MODE" in
  fail)
    printf 'fixture git init failed\\n' >&2
    exit 23
    ;;
  wait)
    : > "$OMG_FIXTURE_SIGNALS/$OMG_FIXTURE_SIDE"
    while [ ! -f "$OMG_FIXTURE_SIGNALS/release" ]; do /usr/bin/sleep 0.01; done
    ;;
esac
exec {shlex.quote(git)} "$@"
""")
            git_fixture.chmod(0o755)
            for program in ("node", "npm", "cargo", "rustc", "python", "go"):
                path = bin_dir / program
                path.write_text(f"#!/bin/sh\n: > {shlex.quote(str(marker))}\nexit 73\n")
                path.chmod(0o755)
            isolated = dict(isolated, PATH=f"{bin_dir}:{base_env['PATH']}",
                            OMG_FIXTURE_SIGNALS=str(signals))

            def run(label, args, markers=(), *, fails=False, inspect=None, env=None, umask=-1):
                try:
                    result = command([cli, *args], isolated if env is None else env,
                                     dict(ordinary, umask=umask), timeout=8)
                except subprocess.TimeoutExpired:
                    checks.append(dict(phase=phase, case=label, passed=False, status=None,
                                       diagnostic="command exceeded local deadline"))
                    return
                output = result.stdout + result.stderr
                okay = ((result.returncode != 0) == fails and all(item in output for item in markers)
                        and (inspect is None or inspect()))
                checks.append(dict(phase=phase, case=label, passed=okay, status=result.returncode,
                                   diagnostic=output[-1000:]))

            def complete(path, manifest):
                return ((path/manifest).is_file() and (path/".git/HEAD").is_file()
                        and not (path/"node_modules").exists() and not marker.exists())

            def clean():
                return not any(here.rglob(".omg-new-*"))

            cases = [
                ("rust", "Cargo.toml"), ("rs", "Cargo.toml"), ("react", "package.json"),
                ("react-ts", "package.json"), ("node", "package.json"), ("ts", "package.json"),
                ("python", "pyproject.toml"), ("py", "pyproject.toml"), ("go", "go.mod"),
                ("golang", "go.mod"),
            ]
            run("help", ("new", "--help"), ("Create",))
            for stack, manifest in cases:
                name = f"examples/{stack}-sample"
                target = here / name
                run(f"scaffold-{stack}", ("new", stack, name), ("Project created successfully",),
                    inspect=lambda: complete(target, manifest) and clean()
                    and (stack != "go" or (target/manifest).read_text().startswith(f"module {name}\n")))
            for stack, name in [
                ("rust", "bad-rust/with.dot"), ("react", "bad-react/Uppercase"),
                ("node", "bad-node/with+plus"), ("python", "bad-python/trailing_"),
                ("go", "bad-go@module/go-starter"),
            ]:
                run(f"invalid-{stack}-manifest", ("new", stack, name), ("project manifest name",),
                    fails=True, inspect=lambda: not (here/name.split("/")[0]).exists())
            run("invalid-stack", ("new", "unknown-stack", "unknown/project"), ("invalid value",),
                fails=True, inspect=lambda: not (here/"unknown").exists())

            (here/"old-directory").mkdir()
            (here/"old-directory/keep").write_text("directory fixture\n")
            (here/"old-file").write_text("file fixture\n")
            run("occupied-target-directory", ("new", "rust", "old-directory"), ("already exists",),
                fails=True, inspect=lambda: (here/"old-directory/keep").read_text() == "directory fixture\n")
            run("occupied-target-file", ("new", "rust", "old-file"), ("already exists",),
                fails=True, inspect=lambda: (here/"old-file").read_text() == "file fixture\n")
            run("parent-is-file", ("new", "rust", "old-file/project"), fails=True,
                inspect=lambda: (here/"old-file").read_text() == "file fixture\n")
            adjacent = here / "sibling"
            adjacent.mkdir()
            os.chown(adjacent, account.pw_uid, account.pw_gid)
            (here/"parent-link").symlink_to(adjacent)
            run("reject-symlink-parent", ("new", "rust", "parent-link/sample"), ("must be a real directory",), fails=True,
                inspect=lambda: not (adjacent/"sample").exists() and (here/"parent-link").is_symlink())

            for stack, manifest in cases[::2]:
                prefix = f"failed-{stack}"
                name = f"{prefix}/layer/project"
                target = here / name
                run(f"git-failure-{stack}", ("new", stack, name), ("git init failed",), fails=True,
                    env=dict(isolated, OMG_FIXTURE_GIT_MODE="fail"),
                    inspect=lambda: not (here/prefix).exists() and clean())
                run(f"git-retry-{stack}", ("new", stack, name), ("Project created successfully",),
                    inspect=lambda: complete(target, manifest) and clean())

            versions = data / "versions/node"
            for version in ("1~2", "26.13.1"):
                (versions/version).mkdir(parents=True)
                (versions/version/".omg-install-complete").write_text(f"{version}\n")
            current = versions / "current"
            current.symlink_to("1~2")
            run("invalid-runtime", ("new", "node", "runtime-collision/retry"),
                ("unsafe for filesystem paths",), fails=True,
                inspect=lambda: not (here/"runtime-collision").exists() and clean())
            current.unlink()
            current.symlink_to("26.13.1")
            run("runtime-retry", ("new", "node", "runtime-collision/retry"), ("Locked node",),
                inspect=lambda: complete(here/"runtime-collision/retry", "package.json")
                and (here/"runtime-collision/retry/.tool-versions").read_text() == "node 26.13.1\n")
            run("caller-umask", ("new", "rust", "mode-check"), ("Project created successfully",),
                umask=0o027, inspect=lambda: (here/"mode-check").stat().st_mode & 0o777 == 0o750)

            def concurrent(label, first, second, shared_path, expected_codes):
                for entry in signals.iterdir():
                    entry.unlink()
                results = []
                with ExitStack() as children:
                    for side, name in (("first", first), ("second", second)):
                        env = dict(isolated, OMG_FIXTURE_GIT_MODE="wait", OMG_FIXTURE_SIDE=side)
                        process = children.enter_context(subprocess.Popen(
                            [str(cli), "new", "rust", name], cwd=here, env=env, text=True,
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **ordinary))
                        results.append(process)
                        deadline = time.monotonic() + 4
                        while not (signals/side).exists() and process.poll() is None and time.monotonic() < deadline:
                            time.sleep(0.01)
                    unpublished = not (here/shared_path).exists()
                    (signals/"release").touch()
                    outputs = []
                    for process in results:
                        try:
                            output, errors = process.communicate(timeout=8)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            output, errors = process.communicate()
                        outputs.append((output + errors)[-450:])
                codes = sorted(process.returncode for process in results)
                checks.append(dict(phase=phase, case=label, passed=(
                    unpublished and codes == expected_codes and all(complete(here/name, "Cargo.toml")
                    for name in (first, second)) and clean()), status=codes, unpublished=unpublished,
                    invocations=2, diagnostic=" ".join(outputs)))

            concurrent("concurrent-same-target", "same/project", "same/project", "same", [0, 1])
            concurrent("concurrent-shared-parent", "shared/a", "shared/b", "shared", [0, 0])


    def inspect_workspace_lifecycle():
        phase = "workspace-lifecycle"
        with tempfile.TemporaryDirectory(prefix="workspace-lifecycle-", dir=work) as directory:
            here = Path(directory)
            os.chown(here, account.pw_uid, account.pw_gid)
            isolated = dict(disabled, HOME=str(here), XDG_DATA_HOME=str(here/"data"),
                            XDG_CONFIG_HOME=str(here/"config"), XDG_CACHE_HOME=str(here/"cache"),
                            XDG_STATE_HOME=str(here/"state"))
            config = here / "omg-workspace.toml"
            guard = here / ".omg-workspace.write.lock"
            a = here / "api"
            b = here / "web"
            c = here / "worker"
            for project in (a, b, c):
                project.mkdir()
                os.chown(project, account.pw_uid, account.pw_gid)
            (here/"file-project").write_text("regular file\n")
            (a/"Makefile").write_text("test:\n\t@printf 'fixture here\\n'\n")

            def run(label, args, markers=(), *, fails=False, inspect=None, binary=cli, env=isolated):
                try:
                    result = command([binary, "workspace", *args], env, ordinary, timeout=6)
                except subprocess.TimeoutExpired:
                    checks.append(dict(phase=phase, case=label, passed=False, status=None,
                                       diagnostic="command exceeded local deadline"))
                    return
                output = result.stdout + result.stderr
                okay = ((result.returncode != 0) == fails and all(marker in output for marker in markers)
                        and (inspect is None or inspect()))
                checks.append(dict(phase=phase, case=label, passed=okay, status=result.returncode,
                                   diagnostic=output[-1050:]))

            def projects():
                return tomllib.loads(config.read_text())["projects"]

            for action in ("list", "status", "check"):
                run(f"{action}-before-init", (action,), ("No workspace found",),
                    fails=True, inspect=lambda: not config.exists() and not guard.exists())
            run("init", ("init", "fixture"), ("Created omg-workspace.toml",), inspect=lambda: projects() == {})
            original = config.read_bytes()
            run("init-existing", ("init", "other"), ("Workspace already exists",), fails=True,
                inspect=lambda: config.read_bytes() == original)
            run("add-api", ("add", "./api", "--name", "backend"), ("Added project 'backend'",))
            run("add-web", ("add", "web"), ("Added project 'web'",))
            saved = config.read_bytes()
            run("add-file", ("add", "file-project"), ("Project path is not a directory",),
                fails=True, inspect=lambda: config.read_bytes() == saved)
            config.write_bytes(saved)
            run("add-missing", ("add", "not-here"), ("Project path does not exist",),
                fails=True, inspect=lambda: config.read_bytes() == saved)
            run("add-duplicate", ("add", "api", "--name", "backend"), ("already exists",),
                fails=True, inspect=lambda: config.read_bytes() == saved)
            run("list-members", ("list",), ("backend", "web", "commands:"), inspect=lambda: projects()["backend"]["path"] == "./api")
            run("status-missing-locks", ("status",), ("0 healthy, 2 need attention", "no omg.lock"))
            run("check-missing-locks", ("check",), ("No omg.lock file found", "2 project(s) need attention, 0 failed to check"),
                fails=True, inspect=lambda: not (a/"omg.lock").exists() and not (b/"omg.lock").exists())

            capture = command([cli, "env", "capture"], dict(isolated, HOME=str(a)), ordinary)
            assert capture.returncode == 0, capture.stderr
            content = (a/"omg.lock").read_bytes()
            (b/"omg.lock").write_bytes(content)
            run("check-matching-locks", ("check",), ("All 2 project environment(s) healthy",),
                inspect=lambda: (a/"omg.lock").read_bytes() == (b/"omg.lock").read_bytes() == content)
            run("status-matching-locks", ("status",), ("2 healthy, 0 need attention",))
            (b/"omg.lock").write_text("runtimes = [\n")
            run("status-invalid-lock", ("status",), ("web - invalid omg.lock", "1 healthy, 1 need attention"))
            run("check-invalid-lock", ("check",), ("Invalid lockfile", "1 project(s) need attention, 0 failed to check"),
                fails=True, inspect=lambda: (b/"omg.lock").read_text() == "runtimes = [\n")
            (b/"omg.lock").unlink()
            (b/"omg.lock").mkdir()
            run("status-lock-directory", ("status",), ("web - invalid omg.lock",))
            (b/"omg.lock").rmdir()
            (b/"omg.lock").write_bytes(content)
            absent = here / "web-away"
            b.rename(absent)
            run("check-missing-member", ("check",), ("0 project(s) need attention, 1 failed to check",),
                fails=True, inspect=lambda: not b.exists())
            absent.rename(b)

            alternate = here / "renamed-cli"
            alternate.mkdir()
            relocated = alternate / "workspace-cli"
            shutil.copy2(cli, relocated)
            run("check-relocated-cli", ("check",), ("All 2 project environment(s) healthy",), binary=relocated)

            amended = saved.decode() + '\n[projects.web.commands]\nfixture = "printf workspace-task-ok"\n'
            # Serialization already contains a commands table for every project.
            amended = re.sub(r"(?m)^\[projects\.web\.commands\]\n", "", amended, count=1)
            config.write_text(amended)
            run("task-refuses-without-consent", ("run", "fixture", "--filter", "web"),
                ("without an interactive terminal",), fails=True)
            run("task-respects-explicit-consent", ("run", "fixture", "--filter", "web", "--yes"),
                ("workspace-task-ok", "1 succeeded, 0 failed"))
            config.write_bytes(saved)

            for label, content_to_read, marker in (
                ("malformed", b"name = [\n", "Failed to parse workspace file"),
                ("invalid-utf8", b"\xff", "UTF-8"),
                ("above-bound", saved.ljust(16 * 1024 * 1024 + 1, b" "), "Workspace file exceeds"),
            ):
                config.write_bytes(content_to_read)
                run(f"file-{label}", ("list",), (marker,), fails=True,
                    inspect=lambda: config.read_bytes() == content_to_read)
            config.write_bytes(saved.ljust(16 * 1024 * 1024, b" "))
            run("file-at-bound", ("list",), ("backend", "web"))
            config.unlink()
            adjacent = here / "workspace-reference"
            adjacent.write_bytes(saved)
            for label in ("directory", "symlink", "fifo"):
                if label == "directory":
                    config.mkdir()
                elif label == "symlink":
                    config.symlink_to(adjacent)
                else:
                    os.mkfifo(config, 0o644)
                run(f"file-{label}", ("list",), ("Workspace file must be a regular file",),
                    fails=True, inspect=lambda: adjacent.read_bytes() == saved)
                if label == "directory":
                    config.rmdir()
                else:
                    config.unlink()
            config.symlink_to(here/"no-workspace")
            run("init-preserves-dangling-link", ("init", "other"), ("Workspace already exists",),
                fails=True, inspect=lambda: config.is_symlink() and not (here/"no-workspace").exists())
            config.unlink()
            config.write_bytes(saved)

            run("remove-relative-path", ("remove", "api"), ("Removed project 'backend'",),
                inspect=lambda: set(projects()) == {"web"})
            config.write_bytes(saved)
            run("remove-absolute-path", ("remove", str(a)), ("Removed project 'backend'",),
                inspect=lambda: set(projects()) == {"web"})
            config.write_bytes(saved)
            duplicate = saved + b'\n[projects.alias]\npath = "api"\n'
            config.write_bytes(duplicate)
            run("remove-ambiguous-path", ("remove", "api"), ("matches multiple projects",),
                fails=True, inspect=lambda: config.read_bytes() == duplicate)
            config.write_bytes(saved)
            run("remove-unknown", ("remove", "none"), ("not found in workspace",), fails=True,
                inspect=lambda: config.read_bytes() == saved)

            guard.touch()
            os.chown(guard, account.pw_uid, account.pw_gid)
            results = []
            with guard.open("rb") as held:
                fcntl.flock(held, fcntl.LOCK_EX)
                with ExitStack() as children:
                    for label, args in (("add", ("add", "worker")), ("remove", ("remove", "backend"))):
                        child = children.enter_context(subprocess.Popen(
                            [str(cli), "workspace", *args], cwd=here, env=isolated, text=True,
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **ordinary))
                        results.append((label, child))
                    time.sleep(0.4)
                    blocked = config.read_bytes() == saved and all(child.poll() is None for _, child in results)
                    fcntl.flock(held, fcntl.LOCK_UN)
                    outcomes = []
                    for label, child in results:
                        try:
                            output, errors = child.communicate(timeout=8)
                        except subprocess.TimeoutExpired:
                            child.kill()
                            output, errors = child.communicate()
                        outcomes.append((label, child.returncode, output + errors))
            updated = set(projects()) == {"web", "worker"}
            for label, code, output in outcomes:
                checks.append(dict(phase=phase, case=f"held-config-{label}", status=code,
                                   passed=blocked and updated and code == 0, diagnostic=output[-1050:]))


    def inspect_workspace_graph_and_diff():
        phase = "workspace-graph-diff"
        executable = shutil.which("git", path=base_env["PATH"])
        assert executable is not None
        with tempfile.TemporaryDirectory(prefix="workspace-graph-diff-", dir=work) as directory:
            here = Path(directory)
            os.chown(here, account.pw_uid, account.pw_gid)
            env = dict(disabled, HOME=str(here), GIT_CONFIG_NOSYSTEM="1",
                       XDG_DATA_HOME=str(here/"data"), XDG_CONFIG_HOME=str(here/"config"),
                       XDG_CACHE_HOME=str(here/"cache"), XDG_STATE_HOME=str(here/"state"))
            config = here / "omg-workspace.toml"
            trace = here / "trace"

            def run(label, args, markers=(), *, fails=False, inspect=None):
                trace.unlink(missing_ok=True)
                try:
                    result = command([cli, "workspace", *args], env, ordinary, timeout=7)
                except subprocess.TimeoutExpired:
                    checks.append(dict(phase=phase, case=label, passed=False, status=None,
                                       diagnostic="command exceeded local deadline"))
                    return
                output = result.stdout + result.stderr
                okay = ((result.returncode != 0) == fails and all(marker in output for marker in markers)
                        and (inspect is None or inspect()))
                checks.append(dict(phase=phase, case=label, passed=okay, status=result.returncode,
                                   diagnostic=output[-1200:]))

            def graph(entries):
                lines = ['name = "graph"', 'created_at = "2026-01-01T00:00:00Z"']
                for name, relative, dependencies, script in entries:
                    lines.extend((f"[projects.{name}]", f"path = {json.dumps(relative)}",
                                  f"depends_on = {json.dumps(dependencies)}"))
                    if script is not None:
                        lines.extend((f"[projects.{name}.commands]", f"probe = {json.dumps(script)}"))
                config.write_text("\n".join(lines) + "\n")

            def entry(name, dependencies=(), script=None):
                return name, ".", dependencies, script if script is not None else f"printf '%s\\n' {name} >> trace"

            def recorded(*expected):
                return trace.is_file() and trace.read_text().splitlines() == list(expected)

            sequential = ("run", "probe", "--yes")
            parallel = ("run", "probe", "--yes", "--parallel")
            graph([])
            run("empty-list", ("list",), ("No projects in workspace",))
            run("empty-run", sequential, ("No matching projects",), inspect=lambda: not trace.exists())
            graph([entry("base"), entry("middle", ["base", "base"]), entry("leaf", ["middle"])])
            run("list-ordered", ("list",), ("1. base", "2. middle", "3. leaf"))
            run("sequential-dependencies", sequential, ("3 succeeded, 0 failed",),
                inspect=lambda: recorded("base", "middle", "leaf"))
            run("parallel-dependencies", parallel, ("3 succeeded, 0 failed",),
                inspect=lambda: recorded("base", "middle", "leaf"))
            run("filtered-dependent", (*parallel, "--filter", "leaf"), ("1 succeeded, 0 failed",),
                inspect=lambda: recorded("leaf"))
            run("filter-no-match", (*parallel, "--filter", "unknown"), ("No matching projects",),
                inspect=lambda: not trace.exists())

            graph([entry("main", ["missing"])])
            run("missing-dependency-list", ("list",), ("Unknown project 'missing'",), fails=True)
            run("missing-dependency-run", parallel, ("Unknown project 'missing'",), fails=True,
                inspect=lambda: not trace.exists())
            graph([entry("first", ["second"]), entry("second", ["first"])])
            run("cycle-list", ("list",), ("Circular dependency",), fails=True)
            run("cycle-sequential", sequential, ("Circular dependency",), fails=True, inspect=lambda: not trace.exists())
            run("cycle-parallel", parallel, ("Circular dependency",), fails=True, inspect=lambda: not trace.exists())

            graph([entry("bad", script="exit 23"), entry("dependent", ["bad"]),
                   entry("transitive", ["dependent"]), entry("independent")])
            run("sequential-failure-propagation", sequential, ("1 succeeded, 3 failed",), fails=True,
                inspect=lambda: recorded("independent"))
            run("parallel-failure-propagation", parallel, ("1 succeeded, 3 failed",), fails=True,
                inspect=lambda: recorded("independent"))

            graph([entry("argument", script="printf '%s\\n' \"$@\" > trace")])
            run("parallel-keeps-args", (*parallel, "--", "one value", "--flag"), ("1 succeeded, 0 failed",),
                inspect=lambda: recorded("one value", "--flag"))
            run("parallel-refuses-unattended-task", ("run", "probe", "--parallel"),
                ("without an interactive terminal",), fails=True, inspect=lambda: not trace.exists())
            graph([entry("a_base"),
                   entry("b_dependent", ["a_base"], "printf 'b_dependent\\n' >> trace; : > ready"),
                   entry("z_independent", script="for step in $(seq 1 60); do "
                         "if test -f ready; then printf 'z_saw_dependent\\n' >> trace; exit 0; fi; "
                         "sleep 0.02; done; exit 31")])
            run("parallel-releases-ready-dependent", parallel, ("3 succeeded, 0 failed",),
                inspect=lambda: recorded("a_base", "b_dependent", "z_saw_dependent"))

            def git(repo, *args):
                result = command([executable, *args], dict(env, HOME=str(repo)), ordinary, timeout=9)
                assert result.returncode == 0, (args, result.stderr)
                return result.stdout

            def owned_dir(path):
                path.mkdir()
                os.chown(path, account.pw_uid, account.pw_gid)

            repo = here / "repo"
            owned_dir(repo)
            graph([("member", "repo", [], None)])
            run("no-repo-no-lock", ("diff", "main"), ("No omg.lock file",))
            git(repo, "init", "--quiet", "--initial-branch=main")
            git(repo, "config", "user.name", "Fedora audit")
            git(repo, "config", "user.email", "fixture@example.invalid")
            git(repo, "config", "commit.gpgsign", "false")
            git(repo, "commit", "--allow-empty", "--quiet", "-m", "Empty base")
            run("empty-branch-no-lock", ("diff", "main"), ("No omg.lock file",))
            lock = repo / "omg.lock"
            initial = "one\nsecond row\n"
            lock.write_text(initial)
            run("untracked-lock-added", ("diff", "main"), ("+2 lines, -0 lines",),
                inspect=lambda: git(repo, "ls-files", "--", "omg.lock") == "")
            git(repo, "add", "--", "omg.lock")
            git(repo, "commit", "--quiet", "-m", "Track lock")
            run("tracked-identical", ("diff", "main"), ("No changes",))
            lock.write_text("one\nchanged row\n")
            run("tracked-one-line-edit", ("diff", "main"), ("+1 lines, -1 lines",))
            lock.write_text(initial + "++preserve leading plus signs\n")
            run("added-plus-prefixed-line", ("diff", "main"), ("+1 lines, -0 lines",))
            lock.write_text(initial)
            git(repo, "rm", "-qf", "--cached", "--", "omg.lock")
            run("staged-deletion-worktree-identical", ("diff", "main"), ("No changes",),
                inspect=lambda: git(repo, "ls-files", "--", "omg.lock") == "")
            lock.unlink()
            run("missing-tracked-lock", ("diff", "main"), ("+0 lines, -2 lines",))
            lock.mkdir()
            run("nonregular-active-lock", ("diff", "main"), ("not a regular file",), fails=True)
            lock.rmdir()
            lock.write_bytes(b"\xff\n")
            run("invalid-active-utf8", ("diff", "main"), ("not UTF-8",), fails=True)
            lock.write_text(initial)
            run("unknown-revision", ("diff", "no-such-branch"), ("git diff failed",), fails=True)

            nested = repo / "nested"
            owned_dir(nested)
            (nested/"omg.lock").write_text("nested fixture\n")
            git(repo, "add", "--", "omg.lock", "nested/omg.lock")
            git(repo, "commit", "--quiet", "-m", "Nested lock")
            graph([("nested", "repo/nested", [], None)])
            run("nested-revision-path", ("diff", "main"), ("No changes",))
            (nested/"omg.lock").write_text("nested fixture\nadditional text\n")
            run("nested-lock-updated", ("diff", "main"), ("+1 lines, -0 lines",))
            graph([("missing", "repo/missing", [], None), ("nested", "repo/nested", [], None)])
            run("missing-project-still-reports-other-members", ("diff", "main"),
                ("Missing project directory", "+1 lines, -0 lines"), fails=True)

            graph([("member", "repo", [], None)])
            lock.unlink()
            (repo/"saved-lock").write_text(initial)
            lock.symlink_to(repo/"saved-lock")
            git(repo, "add", "--", "omg.lock")
            git(repo, "commit", "--quiet", "-m", "Fixture symlink")
            lock.unlink()
            lock.write_text(initial)
            run("nonregular-reference-lock", ("diff", "main"), ("Reference omg.lock must be a regular file",), fails=True)


    def inspect_task_selection():
        phase = "task-selection"
        with tempfile.TemporaryDirectory(prefix="task-selection-", dir=work) as directory:
            here = Path(directory)
            os.chown(here, account.pw_uid, account.pw_gid)
            bin_dir = here / "bin"
            bin_dir.mkdir()
            trace = here / "trace"
            for manager in ("make", "composer", "task", "rake", "fixture-direct"):
                script = bin_dir / manager
                script.write_text(f"""#!/bin/sh
printf '%s|%s|%s\\n' {manager} "$#" "$*" >> "$OMG_FIXTURE_TASK_TRACE"
if [ "$OMG_FIXTURE_TASK_FAIL" = {manager} ]; then exit 17; fi
""")
                script.chmod(0o755)
            env = dict(disabled, HOME=str(here), PATH=f"{bin_dir}:{base_env['PATH']}",
                       OMG_FIXTURE_TASK_TRACE=str(trace), XDG_DATA_HOME=str(here/"data"),
                       XDG_CONFIG_HOME=str(here/"config"), XDG_CACHE_HOME=str(here/"cache"),
                       XDG_STATE_HOME=str(here/"state"))
            makefile = here/"Makefile"
            composer = here/"composer.json"
            preferred = here/".omg.toml"

            def records(*expected, unordered=False):
                result = trace.read_text().splitlines() if trace.exists() else []
                return (sorted(result) == sorted(expected)) if unordered else (result == list(expected))

            def run(label, args, markers=(), *, fails=False, inspect=None, child_env=env):
                trace.unlink(missing_ok=True)
                try:
                    result = command([cli, "run", *args], child_env, ordinary, timeout=6)
                except subprocess.TimeoutExpired:
                    checks.append(dict(phase=phase, case=label, passed=False, status=None,
                                       diagnostic="command exceeded local deadline"))
                    return
                output = result.stdout + result.stderr
                okay = ((result.returncode != 0) == fails and all(marker in output for marker in markers)
                        and (inspect is None or inspect()))
                checks.append(dict(phase=phase, case=label, passed=okay, status=result.returncode,
                                   diagnostic=output[-1200:]))

            run("direct-task", ("fixture-direct",), inspect=lambda: records("fixture-direct|0|"))
            run("direct-task-arguments", ("fixture-direct", "--", "one value", "--flag"),
                inspect=lambda: records("fixture-direct|2|one value --flag"))
            run("using-requires-ecosystem", ("fixture-direct", "--using", "make"),
                ("No task 'fixture-direct' found for ecosystem 'make'",), fails=True,
                inspect=lambda: records())
            run("all-requires-ecosystem", ("fixture-direct", "--all"), ("No project task",),
                fails=True, inspect=lambda: records())
            run("parallel-empty-entry", ("fixture-direct,", "--parallel"), ("must not be empty",),
                fails=True, inspect=lambda: records())
            run("parallel-over-limit", (",".join(["fixture-direct"]*17), "--parallel"),
                ("At most 16 parallel tasks",), fails=True, inspect=lambda: records())
            run("parallel-invalid-name-preflight", ("fixture-direct,bad/name", "--parallel"),
                ("Invalid task name",), fails=True, inspect=lambda: records())
            run("watch-invalid-name-preflight", ("bad/name", "--watch"),
                ("Invalid task name",), fails=True, inspect=lambda: records())
            run("using-and-all-conflict", ("fixture-direct", "--using", "make", "--all"),
                ("cannot be used with",), fails=True, inspect=lambda: records())

            make_source = "test:\n\t@true\nbuild:\n\t@true\n"
            composer_source = '{"scripts":{"test":"fixture","lint":"fixture"}}\n'
            makefile.write_text(make_source)
            composer.write_text(composer_source)
            (here/"Taskfile.yml").write_text("version: '3'\ntasks: {}\n")
            (here/"Rakefile").write_text("# fixture\n")
            run("detected-default-priority", ("test",), inspect=lambda: records("composer|2|run-script test"))
            run("detected-make-selection", ("test", "--using", "make"), inspect=lambda: records("make|1|test"))
            run("detected-make-alias", ("test", "--using", "makefile"), inspect=lambda: records("make|1|test"))
            run("detected-composer-alias", ("test", "--using", "composer"),
                inspect=lambda: records("composer|2|run-script test"))
            run("detected-argv-separator", ("test", "--using", "php", "--", "one value", "--flag"),
                inspect=lambda: records("composer|5|run-script test -- one value --flag"))
            preferred.write_text('[scripts]\ntest = "make"\n')
            run("project-preference", ("test",), inspect=lambda: records("make|1|test"))
            run("explicit-overrides-preference", ("test", "--using", "php"),
                inspect=lambda: records("composer|2|run-script test"))
            run("all-ignores-preference", ("test", "--all"),
                inspect=lambda: records("composer|2|run-script test", "make|1|test"))
            preferred.unlink()
            run("all-stops-on-peer-failure", ("test", "--all"), ("Task failed with exit code",),
                fails=True, child_env=dict(env, OMG_FIXTURE_TASK_FAIL="composer"),
                inspect=lambda: records("composer|2|run-script test"))
            run("fallback-default-make", ("dynamic",), ("trying 'make dynamic'",),
                inspect=lambda: records("make|1|dynamic"))
            run("fallback-selected-composer", ("dynamic", "--using", "composer"),
                ("trying 'composer run-script dynamic'",), inspect=lambda: records("composer|2|run-script dynamic"))
            run("fallback-selected-task", ("dynamic", "--using", "task"),
                ("trying 'task dynamic'",), inspect=lambda: records("task|1|dynamic"))
            run("fallback-selected-rake", ("dynamic", "--using", "ruby"),
                ("trying 'rake dynamic'",), inspect=lambda: records("rake|1|dynamic"))
            run("using-does-not-choose-different-fallback", ("dynamic", "--using", "node"),
                ("No task 'dynamic' found for ecosystem 'node'",), fails=True, inspect=lambda: records())
            run("unknown-ecosystem-does-not-run-fallback", ("dynamic", "--using", "example"),
                ("No task 'dynamic' found for ecosystem 'example'",), fails=True, inspect=lambda: records())
            run("explicit-ecosystem-can-use-its-fallback", ("lint", "--using", "make"),
                inspect=lambda: records("make|1|lint"))
            run("all-requires-detected-match", ("dynamic", "--all"), ("No project task",),
                fails=True, inspect=lambda: records())
            run("single-task-with-parallel-flag", ("build", "--parallel"), inspect=lambda: records("make|1|build"))
            run("parallel-success", ("build,lint", "--parallel"), ("All tasks completed successfully",),
                inspect=lambda: records("make|1|build", "composer|2|run-script lint", unordered=True))
            run("parallel-nonzero-and-peer-success", ("build,lint", "--parallel"), ("Some tasks failed",),
                fails=True, child_env=dict(env, OMG_FIXTURE_TASK_FAIL="composer"),
                inspect=lambda: records("make|1|build", "composer|2|run-script lint", unordered=True))

            preferred.write_text("scripts = [\n")
            run("invalid-project-config", ("build",), ("Failed to parse", ".omg.toml"), fails=True,
                inspect=lambda: records())
            preferred.unlink()
            composer.write_text("{\n")
            run("invalid-composer-config", ("build",), ("Failed to parse", "composer.json"), fails=True,
                inspect=lambda: records())
            composer.write_text(composer_source)
            run("restored-config", ("build",), inspect=lambda: records("make|1|build"))

    def inspect_task_watch():
        phase = "task-watch"
        with tempfile.TemporaryDirectory(prefix="task-watch-", dir=work) as directory:
            here = Path(directory)
            here.chmod(0o755)
            bin_dir = here / "bin"
            bin_dir.mkdir()
            stub = bin_dir / "fixture-watch"
            stub.write_text("""#!/bin/sh
printf 'watch fixture started\\n'
if [ -n "$OMG_WATCH_INITIAL_GATE" ] && [ ! -e "$OMG_WATCH_INITIAL_ONCE" ]; then
    touch "$OMG_WATCH_INITIAL_ONCE"
    while [ ! -e "$OMG_WATCH_INITIAL_GATE" ]; do sleep 0.025; done
fi
if [ -n "$OMG_WATCH_FAIL_ONCE" ] && [ ! -e "$OMG_WATCH_FAIL_ONCE" ]; then
    touch "$OMG_WATCH_FAIL_ONCE"
    exit 17
fi
printf 'watch fixture completed\\n'
""")
            stub.chmod(0o755)

            def change(path):
                path.write_text("changed\n")

            def run(label, action, *, parent=None, scope="src", generated=None, expected=2,
                    initial_gate=False, fail_first=False, expected_while_editing=False):
                case = here / label
                case.mkdir()
                os.chown(case, account.pw_uid, account.pw_gid)
                project = case / parent / "project" if parent else case / "project"
                project.mkdir(parents=True)
                os.chown(project, account.pw_uid, account.pw_gid)
                source = project / "src" if scope == "src" else project
                source.mkdir(exist_ok=True)
                if scope == "src-file":
                    (project / "src").write_text("ordinary file\n")
                item = source / "source.txt"
                item.write_text("original\n")
                (project / "notes.txt").write_text("notes\n")
                if generated:
                    subtree = source / generated
                    subtree.mkdir()
                    (subtree / "artifact").write_text("generated\n")

                output = case / "output"
                gate = case / "initial-gate"
                launch = dict(disabled, HOME=str(case), PATH=f"{bin_dir}:{base_env['PATH']}",
                              XDG_DATA_HOME=str(case/"data"), XDG_CONFIG_HOME=str(case/"config"),
                              XDG_CACHE_HOME=str(case/"cache"), XDG_STATE_HOME=str(case/"state"))
                if initial_gate:
                    launch.update(OMG_WATCH_INITIAL_GATE=str(gate),
                                  OMG_WATCH_INITIAL_ONCE=str(case/"gate-once"))
                if fail_first:
                    launch["OMG_WATCH_FAIL_ONCE"] = str(case/"fail-once")

                with output.open("wb") as sink:
                    process = subprocess.Popen([cli, "run", "fixture-watch", "--watch"], cwd=project,
                                               stdin=subprocess.DEVNULL, stdout=sink, stderr=sink,
                                               env=launch, start_new_session=True, **ordinary)
                try:
                    def await_condition(condition, limit=3):
                        deadline = time.monotonic() + limit
                        while process.poll() is None and time.monotonic() < deadline:
                            if condition(output.read_bytes()):
                                return True
                            time.sleep(0.02)
                        return False

                    ready = b"watch fixture started" if initial_gate else b"Watching for changes"
                    assert await_condition(lambda log: ready in log), "watch did not start"
                    if not initial_gate:
                        marker = b"Task failed" if fail_first else b"watch fixture completed"
                        assert await_condition(lambda log: marker in log), "initial result missing"
                    overlap = action(project, source, item, output)
                    if initial_gate:
                        gate.touch()
                    if expected_while_editing:
                        assert overlap, "no rerun while writes continued"
                        assert await_condition(lambda log: log.count(b"watch fixture completed") >= expected)
                    elif expected > 1 or fail_first:
                        assert await_condition(lambda log: log.count(b"watch fixture completed") >= expected), \
                            "expected rerun did not finish"

                    time.sleep(0.52)
                    found = output.read_bytes().count(b"watch fixture completed")
                    if expected_while_editing:
                        assert expected <= found <= expected + 2, f"unexpected execution count {found}"
                    else:
                        assert found == expected, f"expected {expected} executions, observed {found}"
                    assert process.poll() is None, "watch terminated early"
                    checks.append(dict(phase=phase, case=label, passed=True, status=None,
                                       diagnostic=f"{found} completed executions"))
                except AssertionError as error:
                    data = output.read_bytes().decode(errors="replace")
                    checks.append(dict(phase=phase, case=label, passed=False, status=process.poll(),
                                       diagnostic=f"{error}\n{data[-1100:]}"))
                finally:
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=6)

            def append(path):
                with path.open("a") as stream:
                    stream.write("appended\n")

            def replace_atomically(path):
                temporary = path.with_suffix(".next-save")
                temporary.write_text("updated\n")
                temporary.replace(path)

            def add_nested_file(source, output):
                nested = source / "new-directory"
                nested.mkdir()
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    if output.read_bytes().count(b"watch fixture completed") >= 2:
                        change(nested / "new-source")
                        return
                    time.sleep(0.02)
                raise AssertionError("new directory did not trigger first rerun")

            def sustained_writes(path, output):
                before = time.monotonic()
                triggered_during_writes = False
                for index in range(42):
                    path.write_text(f"{index}\n")
                    if time.monotonic() - before >= 0.3:
                        triggered_during_writes |= output.read_bytes().count(b"watch fixture completed") >= 2
                    time.sleep(0.045)
                return triggered_during_writes

            def open_for_write_without_changes(path):
                os.close(os.open(path, os.O_WRONLY))

            def burst(path):
                for index in range(14):
                    path.write_text(f"{index}\n")

            run("ordinary-edit", lambda p, s, f, o: change(f))
            run("append", lambda p, s, f, o: append(f))
            run("create", lambda p, s, f, o: change(s / "new.txt"))
            run("delete", lambda p, s, f, o: f.unlink())
            run("rename", lambda p, s, f, o: f.rename(s / "renamed.txt"))
            run("permission-change", lambda p, s, f, o: f.chmod(0o600))
            run("atomic-replace", lambda p, s, f, o: replace_atomically(f))
            run("new-nested-folder-and-file", lambda p, s, f, o: add_nested_file(s, o), expected=3)
            run("root-fallback", lambda p, s, f, o: change(f), scope="root")
            run("regular-src-file-keeps-root-fallback", lambda p, s, f, o: change(p / "notes.txt"), scope="src-file")
            for parent in ("build", "target", "node_modules"):
                run(f"project-below-{parent}", lambda p, s, f, o: change(f), parent=parent)
            run("read-file", lambda p, s, f, o: f.read_bytes(), expected=1)
            run("read-directory", lambda p, s, f, o: list(s.iterdir()), expected=1)
            run("open-write-without-change", lambda p, s, f, o: open_for_write_without_changes(f), expected=1)
            for subtree in ("target", "node_modules", ".git", "dist", "build", "out", ".next", "coverage", "__pycache__"):
                run(f"ignore-root-{subtree}", lambda p, s, f, o: change(s / subtree / "artifact"),
                    scope="root", generated=subtree, expected=1)
            run("ignore-nested-generated", lambda p, s, f, o: change(s / "target" / "artifact"),
                generated="target", expected=1)
            run("move-source-into-generated", lambda p, s, f, o: f.rename(s / "target" / "renamed"),
                generated="target")
            run("move-generated-into-source", lambda p, s, f, o: (s / "target" / "artifact").rename(s / "restored"),
                generated="target")
            run("conventional-directory-scope", lambda p, s, f, o: change(p / "notes.txt"), expected=1)
            run("edit-during-first-execution", lambda p, s, f, o: change(f), initial_gate=True)
            run("recover-after-first-execution-fails", lambda p, s, f, o: change(f), fail_first=True, expected=1)
            run("sustained-writes", lambda p, s, f, o: sustained_writes(f, o), expected_while_editing=True)
            run("short-burst-one-rerun", lambda p, s, f, o: burst(f))


    def inspect_task_runtime_admissions():
        import ctypes
        import struct

        phase = "task-runtime-admissions"
        helper = runtime_advisory_fixture
        assert helper.is_file(), helper
        with tempfile.TemporaryDirectory(prefix="task-runtime-admissions-", dir=work) as directory:
            here = Path(directory)
            os.chown(here, account.pw_uid, account.pw_gid)
            runtimes = {
                "node": ("24.22.3", "node", "bin"),
                "python": ("3.13.7", "python3", "bin"),
                "bun": ("1.2.20", "bun", "."),
                "deno": ("2.4.5", "deno", "bin"),
            }
            seed = """
import importlib.util, json, os, sys
from pathlib import Path
helper, home, definitions = sys.argv[1:]
spec = importlib.util.spec_from_file_location("runtime_advisory_fixture", helper)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
home = Path(home)
config = Path(fixture.fixture_cli_environment(home)["OMG_CONFIG_DIR"])
for name, (version, executable, bin_dir) in json.loads(definitions).items():
    runtime = home / "data" / "versions" / name / version
    binary = runtime / bin_dir / executable
    binary.parent.mkdir(parents=True)
    payload = runtime / "fixture-payload"
    payload.write_bytes(bytes(32768))
    output_version = "v" + version if name == "node" else version
    binary.write_text(f'''#!/bin/sh
if [ "${{1:-}}" = --version ]; then
    printf '%s\\\\n' '{output_version}'
    exit
fi
printf 'fixture runtime %s' '{name}'
printf '|<%s>' "$@"
printf '\\\\n'
''')
    binary.chmod(0o755)
    alias = {"node": "nodejs", "python": "python"}.get(name)
    if alias:
        (binary.parent / alias).symlink_to(executable)
    fixture.seed_runtime_advisory_fixture(runtime, name, version, config)
standalone = home / "bin" / "fixture-task-tool"
standalone.parent.mkdir()
standalone.write_text('''#!/bin/sh
printf 'fixture runtime ordinary'
printf '|<%s>' "$@"
printf '\\\\n'
''')
standalone.chmod(0o755)
"""
            checked([sys.executable, "-I", "-B", "-c", seed, helper, here, json.dumps(runtimes)],
                    dict(disabled, HOME=str(here)), ordinary)
            roots = {name: here/"data"/"versions"/name/version
                     for name, (version, _, _) in runtimes.items()}
            bins = {name: roots[name]/bin_dir for name, (_, _, bin_dir) in runtimes.items()}
            environment = dict(disabled, HOME=str(here), OMG_DATA_DIR=str(here/"data"),
                               OMG_CONFIG_DIR=str(here/"config"/"omg"), OMG_NATIVE_TEST_DATA_DIR="1",
                               XDG_CONFIG_HOME=str(here/"config"), XDG_DATA_HOME=str(here/"xdg-data"),
                               XDG_CACHE_HOME=str(here/"cache"), XDG_STATE_HOME=str(here/"state"))
            libc = ctypes.CDLL(None, use_errno=True)
            libc.inotify_init1.argtypes = [ctypes.c_int]
            libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
            in_open, in_close_nowrite = 0x20, 0x10
            notice = struct.Struct("iIII")

            def run(label, executable, chosen, expected, *, pins=(), path=(), venv=None,
                    ancestor=False, mise=False, raw_path=False, no_path=False, pin_request=None):
                folder = here / label
                folder.mkdir()
                project = folder / "project" if ancestor else folder
                project.mkdir(exist_ok=True)
                for name in pins:
                    (folder / f".{name}-version").write_text((pin_request or runtimes[name][0]) + "\n")
                if venv:
                    venv_home = project / ".venv"
                    (venv_home / "bin").mkdir(parents=True)
                    (venv_home / "pyvenv.cfg").write_text(f"home = {bins['python']}\n")
                    interpreter = bins["python"] / "python3"
                    entry = venv_home / "bin" / "python3"
                    if venv == "copy":
                        shutil.copy2(interpreter, entry)
                    else:
                        entry.symlink_to(interpreter)
                if mise:
                    (project / "mise.toml").write_text(f"""[tasks.fixture]
run = '{chosen} "$@"'
""")

                path_values = [str(bins[name]) for name in path] + [str(here/"bin"), base_env["PATH"]]
                env = dict(environment, PATH=":".join(path_values))
                if raw_path:
                    opaque = folder / os.fsdecode(b"opaque-\xff")
                    opaque.mkdir()
                    env["PATH"] = os.fsencode(opaque) + b":" + os.fsencode(env["PATH"])
                if no_path:
                    env.pop("PATH")
                fd = libc.inotify_init1(os.O_CLOEXEC | os.O_NONBLOCK)
                assert fd >= 0, ctypes.get_errno()
                log = ""
                try:
                    watched = {}
                    reads = {name: 0 for name in runtimes}
                    for name, root in roots.items():
                        watch_id = libc.inotify_add_watch(fd, os.fsencode(root/"fixture-payload"),
                                                        in_open | in_close_nowrite)
                        assert watch_id >= 0, (root, ctypes.get_errno())
                        watched[watch_id] = name
                    result = subprocess.run([cli, "run", executable, "--", "two words", "--literal"],
                                            cwd=project, stdin=subprocess.DEVNULL, capture_output=True,
                                            text=True, timeout=10, env=env, **ordinary)
                    log = result.stdout + result.stderr
                    try:
                        events = os.read(fd, 65536)
                    except BlockingIOError:
                        events = b""
                    offset = 0
                    while offset < len(events):
                        watch_id, kind, _, length = notice.unpack_from(events, offset)
                        reads[watched[watch_id]] += bool(kind & in_open)
                        offset += notice.size + length
                    observed = {name: total for name, total in reads.items() if total}
                    correct_output = f"fixture runtime {chosen}|<two words>|<--literal>" in result.stdout
                    checks.append(dict(phase=phase, case=label, status=result.returncode,
                                       passed=result.returncode == 0 and correct_output and observed == expected,
                                       reported_reads=observed, expected_reads=expected, diagnostic=log[-1000:]))
                except subprocess.TimeoutExpired:
                    checks.append(dict(phase=phase, case=label, status=None, passed=False,
                                       diagnostic="runtime task did not finish"))
                finally:
                    os.close(fd)

            for name, (_, executable, _) in runtimes.items():
                run(f"{name}-selected", executable, name, {name: 3}, pins=(name,))
                run(f"{name}-path-only", executable, name, {name: 3}, path=(name,))
                run(f"{name}-selected-and-on-path", executable, name, {name: 3},
                    pins=(name,), path=(name,))
                run(f"{name}-ordinary-task", "fixture-task-tool", "ordinary", {name: 3}, pins=(name,))
            run("nodejs-alias", "nodejs", "node", {"node": 3}, pins=("node",))
            run("python-alias", "python", "python", {"python": 3}, pins=("python",))

            for mode in ("link", "copy"):
                for pinned in (False, True):
                    pins = ("python",) if pinned else ()
                    kind = "pinned" if pinned else "implicit"
                    run(f"venv-{mode}-{kind}-python", "python3", "python", {"python": 3}, pins=pins, venv=mode)
                    run(f"venv-{mode}-{kind}-ordinary", "fixture-task-tool", "ordinary", {"python": 3},
                        pins=pins, venv=mode)

            run("node-with-deno", "node", "node", {"node": 3, "deno": 3}, pins=("node", "deno"))
            run("bun-with-python", "bun", "bun", {"python": 3, "bun": 3}, pins=("python", "bun"))
            run("ordinary-with-two-runtimes", "fixture-task-tool", "ordinary", {"python": 3, "deno": 3},
                pins=("python", "deno"))
            run("bun-with-node", "bun", "bun", {"node": 3, "bun": 3}, pins=("node", "bun"))
            run("node-pin-from-parent", "node", "node", {"node": 3}, pins=("node",), ancestor=True)
            run("runtime-in-mise-task", "fixture", "node", {"node": 3}, pins=("node",), mise=True)
            run("managed-runtime-opaque-path", "node", "node", {"node": 3}, pins=("node",), raw_path=True)
            run("managed-runtime-initially-unset-path", "node", "node", {"node": 3}, pins=("node",), no_path=True)

            phase = "task-runtime-admission-probes"
            for name in ("node", "bun"):
                version, executable, _ = runtimes[name]
                major, minor, _ = version.split(".")
                for spelling, request in (
                    ("exact", version),
                    ("v-prefixed", f"v{version}"),
                    ("minor", f"{major}.{minor}"),
                    ("caret", f"^{major}.{minor}.0"),
                ):
                    cases = (
                        ("direct-with-path", executable, name, (name,), False),
                        ("ordinary-with-path", "fixture-task-tool", "ordinary", (name,), False),
                        ("mise-with-path", "fixture", name, (name,), True),
                        ("selected-only", executable, name, (), False),
                    )
                    for mode, command, output, path, mise in cases:
                        run(f"{name}-{spelling}-{mode}", command, output, {name: 3},
                            pins=(name,), path=path, mise=mise, pin_request=request)


    def inspect_task_version_requirements():
        definitions = {
            "node": ("node", "bin", ("24.22.3", "24.23.1", "24.22.4-rc.1")),
            "bun": ("bun", ".", ("1.2.20", "1.3.1", "1.4.0-rc.1")),
            "java": ("java", "bin", ("21",)),
        }
        seed = r"""
import importlib.util, json, sys
from pathlib import Path
helper, home, definitions = sys.argv[1:]
spec = importlib.util.spec_from_file_location("runtime_advisory_fixture", helper)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
home = Path(home)
config = Path(fixture.fixture_cli_environment(home)["OMG_CONFIG_DIR"])
for runtime, (name, bindir, versions) in json.loads(definitions).items():
    for version in versions:
        root = home / "data" / "versions" / runtime / version
        program = root / bindir / name
        program.parent.mkdir(parents=True)
        output_version = f"v{version}" if runtime == "node" else version
        program.write_text(f'''#!/bin/sh
if [ "$1" = --version ]; then
    printf '%s\\n' '{output_version}'
    exit
fi
printf 'fixture runtime {runtime} {version}|<%s>\\n' "$@"
''')
        program.chmod(0o755)
        fixture.seed_runtime_advisory_fixture(root, runtime, version, config)
"""
        phase = "task-version-requirements"
        cases = (
            ("node-exact", "node", "24.22.3", "24.22.3"),
            ("node-v-exact", "node", "v24.22.3", "24.22.3"),
            ("node-absent-exact", "node", "24.22.2", None),
            ("node-minor", "node", "24.22", "24.22.3"),
            ("node-absent-minor", "node", "24.21", None),
            ("node-major", "node", "24", "24.23.1"),
            ("node-prerelease", "node", "24.22.4-rc.1", "24.22.4-rc.1"),
            ("node-absent-prerelease", "node", "24.22.4-rc.0", None),
            ("node-space-range", "node", ">=24.22.0 <24.23.0", "24.22.3"),
            ("node-comma-range", "node", ">= 24.22.0, < 24.23.0", "24.22.3"),
            ("node-spaced-range", "node", ">= 24.22.0 < 24.23.0", "24.22.3"),
            ("node-extra-component", "node", "24.22.3.0", None),
            ("node-lts-requires-release-identity", "node", "lts", None),
            ("node-named-lts-requires-release-identity", "node", "lts/krypton", None),
            ("node-latest-stable", "node", "latest", "24.23.1"),
            ("bun-v-exact", "bun", "v1.2.20", "1.2.20"),
            ("bun-minor", "bun", "1.2", "1.2.20"),
            ("bun-absent-minor", "bun", "1.1", None),
            ("bun-latest-stable", "bun", "latest", "1.3.1"),
            ("java-feature", "java", "21", "21"),
            ("java-zero-minor", "java", "21.0", "21"),
            ("java-missing-feature", "java", "22.0", None),
            ("java-full-release", "java", "21.0.5", None),
        )
        with tempfile.TemporaryDirectory(prefix="task-version-requirements-", dir=work) as directory:
            here = Path(directory)
            os.chown(here, account.pw_uid, account.pw_gid)
            checked([sys.executable, "-I", "-B", "-c", seed, runtime_advisory_fixture, here, json.dumps(definitions)],
                    dict(disabled, HOME=str(here)), ordinary)
            data = here / "data"
            env = dict(disabled, HOME=str(here), NVM_DIR=str(here/"absent-nvm"), OMG_DATA_DIR=str(data),
                       OMG_CONFIG_DIR=str(here/"config"/"omg"), OMG_NATIVE_TEST_DATA_DIR="1",
                       XDG_CONFIG_HOME=str(here/"config"), XDG_DATA_HOME=str(here/"xdg-data"),
                       XDG_CACHE_HOME=str(here/"cache"), XDG_STATE_HOME=str(here/"state"))
            for label, runtime, request, version in cases:
                command_name, bindir, available = definitions[runtime]
                project = here / label
                project.mkdir()
                (project / f".{runtime}-version").write_text(request + "\n")
                versions = data / "versions" / runtime
                present = [str(versions / local / bindir) for local in available]
                matching = present[available.index(version)] if version else None
                # Exercise preflight even when a compatible-looking runtime is already on PATH.
                inherited = dict(env, PATH=f"{present[0]}:{base_env['PATH']}")
                for mode, args in (
                    ("hook", ("hook-env", "--shell", "bash")),
                    ("task", ("run", command_name, "--", "two words")),
                ):
                    result = subprocess.run([cli, *args], cwd=project, env=inherited, stdin=subprocess.DEVNULL,
                                            capture_output=True, text=True, timeout=8, **ordinary)
                    log = result.stdout + result.stderr
                    runtime_output = [line for line in result.stdout.splitlines() if line.startswith("fixture runtime ")]
                    emitted = [path for path in present if f"'{path}'" in result.stdout]
                    if mode == "hook":
                        passed = result.returncode == 0 and emitted == ([matching] if matching else []) and not runtime_output
                    elif version:
                        passed = (result.returncode == 0 and
                                  runtime_output == [f"fixture runtime {runtime} {version}|<two words>"])
                    else:
                        diagnostic = ("Invalid Java version" if label == "java-full-release"
                                      else "Interactive confirmation required:")
                        passed = result.returncode != 0 and not runtime_output and diagnostic in result.stderr
                    checks.append(dict(phase=phase, case=f"{label}-{mode}", status=result.returncode,
                                       passed=passed, expected_version=version, diagnostic=log[-1100:]))


    def inspect_node_alias_selection():
        managed = ("24.15.3", "24.15.9", "24.16.2", "v23.1.7")
        external = ("v26.0.5", "v26.1.0")
        seed = r"""
import importlib.util, json, sys
from pathlib import Path
helper, home, managed, external = sys.argv[1:]
spec = importlib.util.spec_from_file_location("runtime_advisory_fixture", helper)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
home = Path(home)
config = Path(fixture.fixture_cli_environment(home)["OMG_CONFIG_DIR"])
for directory, versions in (("data", managed), ("nvm", external)):
    for version in json.loads(versions):
        root = home / directory / "versions/node" / version
        program = root / "bin/node"
        program.parent.mkdir(parents=True)
        program.write_text(f'''#!/bin/sh
if [ "$1" = --version ]; then
    printf '%s\\n' 'v{version.removeprefix("v")}'
    exit
fi
printf 'fixture node {directory} {version}|<%s>\\n' "$@"
''')
        program.chmod(0o755)
        fixture.seed_runtime_advisory_fixture(root, "node", version, config)
"""
        with tempfile.TemporaryDirectory(prefix="task-node-aliases-", dir=work) as directory:
            here = Path(directory)
            os.chown(here, account.pw_uid, account.pw_gid)
            checked([sys.executable, "-I", "-B", "-c", seed, runtime_advisory_fixture, here,
                     json.dumps(managed), json.dumps(external)], dict(disabled, HOME=str(here)), ordinary)
            nvm = here / "nvm"
            aliases = nvm / "alias"
            (aliases / "lts").mkdir(parents=True)
            for name, value in (
                ("default", "# Managed team default\n  v24.15.3 # exact\n"),
                ("team", "default"),
                ("project-minor", "24.15"),
                ("project-major", "v24"),
                ("newest", "node"),
                ("lts/*", "lts/krypton"),
                ("lts/krypton", "v24.15.9"),
                ("unavailable", "v28.0.0"),
                ("external", "v26.0.5"),
                ("vendor", "v24.15.3"),
                ("review-cycle-one", "review-cycle-two"),
                ("review-cycle-two", "review-cycle-one"),
            ):
                (aliases / name).write_text(value + "\n")
            for depth in (64, 65):
                for index in range(depth):
                    target = f"chain-{depth}-{index+1}" if index + 1 < depth else "v24.15.3"
                    (aliases / f"chain-{depth}-{index}").write_text(target + "\n")
            env = dict(disabled, HOME=str(here), NVM_DIR=str(nvm), OMG_DATA_DIR=str(here/"data"),
                       OMG_CONFIG_DIR=str(here/"config"/"omg"), OMG_NATIVE_TEST_DATA_DIR="1",
                       XDG_CONFIG_HOME=str(here/"config"), XDG_DATA_HOME=str(here/"xdg-data"),
                       XDG_CACHE_HOME=str(here/"cache"), XDG_STATE_HOME=str(here/"state"))
            cases = (
                ("managed-exact", "24.15.3", ("data", "24.15.3")),
                ("named-exact", "default", ("data", "24.15.3")),
                ("named-chain", "team", ("data", "24.15.3")),
                ("named-minor", "project-minor", ("data", "24.15.9")),
                ("named-major", "project-major", ("data", "24.16.2")),
                ("builtin-node", "node", ("data", "24.16.2")),
                ("named-builtin", "newest", ("data", "24.16.2")),
                ("default-lts", "lts", ("data", "24.15.9")),
                ("wildcard-lts", "lts/*", ("data", "24.15.9")),
                ("named-lts", "lts/krypton", ("data", "24.15.9")),
                ("maximum-chain", "chain-64-0", ("data", "24.15.3")),
                ("excess-chain", "chain-65-0", "Nvm alias chain exceeds 64 resolutions"),
                ("undefined-alias", "unlisted", "Interactive confirmation required:"),
                ("alias-target-unavailable", "unavailable", "Node.js '28.0.0' is missing"),
                ("nvm-exact", "v26.0.5", ("nvm", "v26.0.5")),
                ("nvm-major", "26", ("nvm", "v26.1.0")),
                ("nvm-alias", "external", ("nvm", "v26.0.5")),
                ("nvm-cycle", "review-cycle-one", "Nvm alias cycle"),
            )
            bins = [str(here / directory / "versions/node" / version / "bin")
                    for directory, versions in (("data", managed), ("nvm", external)) for version in versions]
            for label, request, want in cases:
                project = here / label
                project.mkdir()
                (project / ".nvmrc").write_text(request + "\n")
                for mode, args in (
                    ("hook", ("hook-env", "--shell", "bash")),
                    ("task", ("run", "node", "--", "two words")),
                ):
                    result = subprocess.run([cli, *args], cwd=project, env=env, stdin=subprocess.DEVNULL,
                                            capture_output=True, text=True, timeout=8, **ordinary)
                    output = [line for line in result.stdout.splitlines() if line.startswith("fixture node ")]
                    if mode == "hook":
                        matching = str(here / want[0] / "versions/node" / want[1] / "bin") if isinstance(want, tuple) else None
                        emitted = [path for path in bins if f"'{path}'" in result.stdout]
                        passed = result.returncode == 0 and emitted == ([matching] if matching else []) and not output
                    elif isinstance(want, tuple):
                        passed = result.returncode == 0 and output == [f"fixture node {want[0]} {want[1]}|<two words>"]
                    else:
                        passed = result.returncode != 0 and not output and want in result.stderr
                    checks.append(dict(phase="task-node-aliases", case=f"{label}-{mode}", status=result.returncode,
                                       passed=passed, expected=want, diagnostic=(result.stdout + result.stderr)[-1100:]))

            phase = "nvmrc-pin-reading"
            cases = (
                ("plain", "24.15.3", None, None, "24.15.3", "24.15.3"),
                ("comments", "# node selection\n\n\tv24.15.3\t# approved\n", None, None,
                 "24.15.3", "24.15.3"),
                ("metadata-crlf", "track = stable # note\r\n\tv24.15.3\r\nempty=\r\nnotes=one=two\r\n",
                 None, None, "24.15.3", "24.15.3"),
                ("vendor-alias", "vendor\n", None, None, "vendor", "24.15.3"),
                ("compound-range", ">=24.15.0 <24.16.0 # patch series\n", None, None,
                 ">=24.15.0 <24.16.0", "24.15.9"),
                ("exact-comparator", "=24.15.3 # exact comparator\n", None, None,
                 "=24.15.3", "24.15.3"),
                ("parent-pin", None, "# parent pin\n24.15.9\n", None, "24.15.9", "24.15.9"),
                ("child-pin", "24.15.3 # child pin\n", "24.16.2\n", None, "24.15.3", "24.15.3"),
                ("dedicated-pin", "24.15.3\n24.16.2\n", None, "24.15.9\n", "24.15.9", "24.15.9"),
                ("multiple-selectors", "24.15.3\n24.15.9\n", "24.16.2\n", None, None, None),
                ("duplicate-metadata", "track=fixture-note-first\n24.15.3\ntrack = fixture-note-second\n",
                 "24.16.2\n", None, None, None),
                ("reserved-node-key", "node=fixture-note-invalid\n24.15.3\n",
                 "24.16.2\n", None, None, None),
                ("metadata-only", "track=fixture-note-missing\n# No selector\n", "24.16.2\n",
                 None, None, None),
                ("empty", "", "24.16.2\n", None, None, None),
                ("control-character", "track=note\x0btext\n24.15.3\n", "24.16.2\n",
                 None, None, None),
                ("malformed-ancestor", None, "24.15.3\n24.15.9\n", None, "24.16.2", "24.16.2"),
            )
            for label, local, parent, dedicated, selector, version in cases:
                family = here / f"pin-{label}"
                middle = family / "middle"
                project = middle / "project"
                project.mkdir(parents=True)
                if label == "malformed-ancestor":
                    (family / ".nvmrc").write_text("24.16.2\n")
                if local is not None:
                    (project / ".nvmrc").write_bytes(local.encode())
                if parent is not None:
                    (middle / ".nvmrc").write_bytes(parent.encode())
                if dedicated is not None:
                    (project / ".node-version").write_text(dedicated)
                hook_version = version or "24.16.2"
                hook_path = str(here / "data" / "versions/node" / hook_version / "bin")
                for mode, args in (
                    ("hook", ("hook-env", "--shell", "bash")),
                    ("task", ("run", "node", "--", "two words")),
                    ("which", ("which", "node")),
                ):
                    result = subprocess.run([cli, *args], cwd=project, env=env, stdin=subprocess.DEVNULL,
                                            capture_output=True, text=True, timeout=8, **ordinary)
                    log = result.stdout + result.stderr
                    lines = result.stdout.splitlines()
                    output = [line for line in lines if line.startswith("fixture node ")]
                    if mode == "hook":
                        emitted = [path for path in bins if f"'{path}'" in result.stdout]
                        passed = result.returncode == 0 and emitted == [hook_path] and not output
                    elif selector is None:
                        passed = result.returncode != 0 and not lines and "Invalid .nvmrc" in result.stderr
                    elif mode == "task":
                        passed = result.returncode == 0 and output == [f"fixture node data {version}|<two words>"]
                    else:
                        passed = result.returncode == 0 and len(lines) == 1 and lines[0].endswith(f" {selector}")
                    checks.append(dict(phase=phase, case=f"{label}-{mode}", status=result.returncode,
                                       passed=passed and "fixture-note-" not in log, diagnostic=log[-1100:],
                                       expected_selector=selector, expected_version=version))

            phase = "node-use-installed"
            current = here / "data/versions/node/current"
            initial = current.with_name("24.15.3")
            def seed_unreviewed(version):
                program = current.with_name(version) / "bin/node"
                program.parent.mkdir(parents=True)
                program.write_text(f"#!/bin/sh\nprintf 'v{version}\\n'\n")
                program.chmod(0o755)
                for path in (program.parent.parent, program.parent, program):
                    os.chown(path, account.pw_uid, account.pw_gid)

            seed_unreviewed("19.7.2")
            cases = (
                ("exact", "24.15.9", (), "24.15.9", None),
                ("v-exact", "v24.15.9", (), "24.15.9", None),
                ("upper-v-exact", "V24.15.9", (), "24.15.9", None),
                ("major", "24", (), "24.16.2", None),
                ("minor", "24.15", (), "24.15.9", None),
                ("caret", "^24.15.0", (), "24.16.2", None),
                ("compound", ">=24.15.0 <24.16.0", (), "24.15.9", None),
                ("exact-comparator", "=24.15.3", (), "24.15.3", None),
                ("named", "default", (), "24.15.3", None),
                ("vendor", "vendor", (), "24.15.3", None),
                ("chain", "team", (), "24.15.3", None),
                ("latest", "latest", (), "24.16.2", None),
                ("builtin", "node", (), "24.16.2", None),
                ("lts", "lts", (), "24.15.9", None),
                ("lts-wildcard", "lts/*", (), "24.15.9", None),
                ("lts-name", "lts/krypton", (), "24.15.9", None),
                ("prefixed-directory", "23.1", (), "v23.1.7", None),
                ("external-only", "external", (), None, "Node.js checksum manifest"),
                ("unknown-request", "unlisted", (), None, "Invalid Node.js version request"),
                ("unavailable-exact", "28.0.0", (), None, "Node.js checksum manifest"),
                ("requires-review", "19.7.2", (), None, "Failed to review installed Node.js runtime"),
                ("file-exact", None, ((".nvmrc", "# release\nv24.15.9\n"),), "24.15.9", None),
                ("file-alias", None, ((".nvmrc", "vendor # release\n"),), "24.15.3", None),
                ("file-lts", None, ((".nvmrc", "lts/*\n"),), "24.15.9", None),
                ("file-range", None, ((".nvmrc", ">=24.15.0 <24.16.0\n"),), "24.15.9", None),
                ("file-priority", None, ((".node-version", "24.15.9"), (".nvmrc", "24.16.2")), "24.15.9", None),
                ("parent-file", None, (("../.nvmrc", "24.15\n"),), "24.15.9", None),
                ("tool-versions", None, ((".tool-versions", "node 24.15\n"),), "24.15.9", None),
                ("package-engines", None,
                 (("package.json", '{"engines":{"node":">=24.15.0 <24.16.0"}}'),), "24.15.9", None),
                ("mise-tools", None, (("mise.toml", "[tools]\nnode = '24.15'\n"),), "24.15.9", None),
                ("invalid-file", None, ((".nvmrc", "24.15.9\n24.16.2\n"),), None, "Invalid .nvmrc"),
                ("missing-pin", None, (), None, "No version specified and none detected"),
                ("latest-requires-review", "latest", (), None, "Failed to review installed Node.js runtime"),
            )
            for label, request, files, expected, failure in cases:
                if label == "latest-requires-review":
                    seed_unreviewed("28.0.2")
                project = here / f"use-{label}" / "work"
                project.mkdir(parents=True)
                for name, value in files:
                    (project / name).write_text(value)
                if current.is_symlink():
                    current.unlink()
                current.symlink_to(initial)
                os.lchown(current, account.pw_uid, account.pw_gid)
                args = [cli, "use", "node"]
                if request is not None:
                    args.append(request)
                result = subprocess.run(args, cwd=project, env=env, stdin=subprocess.DEVNULL,
                                        capture_output=True, text=True, timeout=8, **ordinary)
                active = current.resolve(strict=True)
                if expected is None:
                    passed = result.returncode != 0 and active == initial and failure in result.stderr
                else:
                    passed = (result.returncode == 0 and active == current.with_name(expected)
                              and "Now using Node.js" in result.stdout and "Downloading" not in result.stdout)
                checks.append(dict(phase=phase, case=label, status=result.returncode, passed=passed,
                                   active=active.name, expected=expected,
                                   diagnostic=(result.stdout + result.stderr)[-1300:]))


    def inspect_python_project_constraints():
        releases = ("3.11.9", "3.12.0", "3.12.7", "3.12.9", "3.13.0", "3.13.8", "3.14.1")
        seed = r"""
import importlib.util, json, sys
from pathlib import Path
helper, directory, releases = sys.argv[1:]
spec = importlib.util.spec_from_file_location("runtime_advisory_fixture", helper)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
home = Path(directory)
config = Path(fixture.fixture_cli_environment(home)["OMG_CONFIG_DIR"])
for version in json.loads(releases):
    root = home / "data" / "versions/python" / version
    executable = root / "bin/python3"
    executable.parent.mkdir(parents=True)
    executable.write_text(f'''#!/bin/sh
if [ "$1" = --version ]; then
    printf '%s\\n' 'Python {version}'
    exit
fi
printf 'fixture python {version}|<%s>\\n' "$@"
''')
    executable.chmod(0o755)
    fixture.seed_runtime_advisory_fixture(root, "python", version, config)
"""
        cases = (
            ("bounded", ">=3.12,<3.13", None, None, "3.12.9"),
            ("compatible-minor", "~=3.12.5", None, None, "3.12.9"),
            ("compatible-major", "~=3.12", None, None, "3.14.1"),
            ("equal-wildcard", "==3.12.*", None, None, "3.12.9"),
            ("equal-padding", "== 3.12", None, None, "3.12.0"),
            ("exclude-patch", ">=3.12,<3.13,!=3.12.9", None, None, "3.12.7"),
            ("exclude-series", ">=3.12,<3.14,!=3.13.*", None, None, "3.12.9"),
            ("exclusive", ">3.12.7, <3.13", None, None, "3.12.9"),
            ("parent-project", None, ("pyproject.toml", "~=3.12.5"), None, "3.12.9"),
            ("nearest-project", "~=3.12.5", (".python-version", "3.14.1"), None, "3.12.9"),
            ("dedicated-pin", ">=,3.12", None, "3.11.9", "3.11.9"),
            ("invalid-specifier", ">=,3.12", (".python-version", "3.14.1"), None, None),
            ("unavailable", ">=4", None, None, None),
        )
        version_pins = (
            ("lower-prefix-exact", None, None, "v3.12.7", "3.12.7"),
            ("upper-prefix-exact", None, None, "V3.12.7", "3.12.7"),
            ("lower-prefix-minor", None, None, "v3.12", "3.12.9"),
            ("upper-prefix-minor", None, None, "V3.12", "3.12.9"),
            ("lower-prefix-major", None, None, "v3", "3.14.1"),
            ("upper-prefix-major", None, None, "V3", "3.14.1"),
            ("tool-versions-exact", None, (".tool-versions", "python V3.12.7"), None, "3.12.7"),
            ("tool-versions-minor", None, (".tool-versions", "python V3.12"), None, "3.12.9"),
            ("parent-dedicated", None, (".python-version", "V3.13.0"), None, "3.13.0"),
            ("nearest-dedicated", None, (".python-version", "3.14.1"), "V3.12.7", "3.12.7"),
            ("plain-exact", None, None, "3.12.7", "3.12.7"),
            ("plain-minor", None, None, "3.12", "3.12.9"),
        )
        with tempfile.TemporaryDirectory(prefix="python-project-constraints-", dir=work) as directory:
            here = Path(directory)
            os.chown(here, account.pw_uid, account.pw_gid)
            checked([sys.executable, "-I", "-B", "-c", seed, runtime_advisory_fixture, here, json.dumps(releases)],
                    dict(disabled, HOME=str(here)), ordinary)
            data = here / "data"
            env = dict(disabled, HOME=str(here), OMG_DATA_DIR=str(data),
                       OMG_CONFIG_DIR=str(here/"config"/"omg"), OMG_NATIVE_TEST_DATA_DIR="1",
                       XDG_CONFIG_HOME=str(here/"config"), XDG_DATA_HOME=str(here/"xdg-data"),
                       XDG_CACHE_HOME=str(here/"cache"), XDG_STATE_HOME=str(here/"state"))
            versions = data / "versions/python"
            current = versions / "current"
            initial = versions / "3.11.9"
            paths = [str(versions / release / "bin") for release in releases]

            def write_pin(folder, filename, value):
                text = f"[project]\nrequires-python = {json.dumps(value)}\n" if filename == "pyproject.toml" else value
                (folder / filename).write_text(text)

            pin_labels = {case[0] for case in version_pins}
            for label, constraint, parent, dedicated, expected in cases + version_pins:
                phase = "python-version-pins" if label in pin_labels else "python-project-constraints"
                family = here / label
                project = family / "project"
                project.mkdir(parents=True)
                if constraint is not None:
                    write_pin(project, "pyproject.toml", constraint)
                if parent is not None:
                    write_pin(family, *parent)
                if dedicated is not None:
                    write_pin(project, ".python-version", dedicated)
                if current.is_symlink():
                    current.unlink()
                current.symlink_to(initial)
                os.lchown(current, account.pw_uid, account.pw_gid)
                for mode, args in (
                    ("hook", ("hook-env", "--shell", "bash")),
                    ("task", ("run", "python3", "--", "two words")),
                    ("use", ("use", "python")),
                ):
                    result = subprocess.run([cli, *args], cwd=project, env=env, stdin=subprocess.DEVNULL,
                                            capture_output=True, text=True, timeout=8, **ordinary)
                    active = current.resolve(strict=True)
                    output = [line for line in result.stdout.splitlines() if line.startswith("fixture python ")]
                    if mode == "hook":
                        hook_release = "3.14.1" if label == "invalid-specifier" else expected
                        matching = str(versions / hook_release / "bin") if hook_release else None
                        emitted = [path for path in paths if f"'{path}'" in result.stdout]
                        passed = result.returncode == 0 and emitted == ([matching] if matching else []) and active == initial
                    elif label == "invalid-specifier":
                        passed = (result.returncode != 0 and not output and active == initial
                                  and "Invalid requires-python" in result.stderr)
                    elif label == "unavailable":
                        diagnostic = "Interactive confirmation required:" if mode == "task" else "Failed to fetch"
                        passed = result.returncode != 0 and not output and active == initial and diagnostic in result.stderr
                    elif mode == "task":
                        passed = (result.returncode == 0 and active == initial
                                  and output == [f"fixture python {expected}|<two words>"])
                    else:
                        passed = (result.returncode == 0 and active == versions / expected
                                  and "Now using Python" in result.stdout and "Downloading" not in result.stdout)
                    checks.append(dict(phase=phase, case=f"{label}-{mode}", status=result.returncode,
                                       passed=passed, active=active.name, expected=expected,
                                       diagnostic=(result.stdout + result.stderr)[-1200:]))


    def inspect_python_virtualenv_launch():
        phase = "python-virtualenv-launch"
        seed = r"""
import importlib.util, json, shutil, sys
from pathlib import Path
helper, directory = sys.argv[1:]
spec = importlib.util.spec_from_file_location("runtime_advisory_fixture", helper)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
home = Path(directory)
config = Path(fixture.fixture_cli_environment(home)["OMG_CONFIG_DIR"])
version = ".".join(map(str, sys.version_info[:3]))
minor = ".".join(map(str, sys.version_info[:2]))
root = home / "data" / "versions" / "python" / version
binary = root / "bin/python3"
binary.parent.mkdir(parents=True)
shutil.copy2(Path("/proc/self/exe").resolve(strict=True), binary)
for name in ("python", f"python{minor}"):
    (binary.parent / name).symlink_to(binary.name)
fixture.seed_runtime_advisory_fixture(root, "python", version, config)
print(json.dumps({"exe": str(binary), "version": version, "minor": minor}))
"""
        create = """
import sys, venv
sys._base_executable = sys.argv[1]
venv.EnvBuilder(with_pip=False, symlinks=sys.argv[3] == "link").create(sys.argv[2])
"""
        program = r"""
import json, os, sys
from pathlib import Path
try:
    import omg_venv_observation
except ModuleNotFoundError:
    local = None
else:
    local = omg_venv_observation.VALUE
print("fixture python " + json.dumps({
    "exe": os.readlink("/proc/self/exe"),
    "prefix": sys.prefix,
    "venv": os.getenv("VIRTUAL_ENV"),
    "home": os.getenv("PYTHONHOME"),
    "local": local,
    "args": sys.argv[1:],
}))
"""
        layouts = (
            ("base-only", None, None, None),
            ("dot-link", ".venv", "link", None),
            ("dot-copy", ".venv", "copy", None),
            ("bare-link-with-dot-file", "venv", "link", "file"),
            ("bare-copy-with-empty-dot-dir", "venv", "copy", "directory"),
            ("both-venvs", ".venv", "copy", "other-venv"),
        )
        with tempfile.TemporaryDirectory(prefix="python-virtualenv-launch-", dir=work) as directory:
            here = Path(directory)
            os.chown(here, account.pw_uid, account.pw_gid)
            definition = json.loads(checked(
                [sys.executable, "-I", "-B", "-c", seed, runtime_advisory_fixture, here],
                dict(disabled, HOME=str(here)), ordinary,
            ))
            binary = Path(definition["exe"])
            version = definition["version"]
            minor = definition["minor"]
            environment = dict(
                disabled, HOME=str(here), OMG_DATA_DIR=str(here/"data"),
                OMG_CONFIG_DIR=str(here/"config"/"omg"), OMG_NATIVE_TEST_DATA_DIR="1",
                XDG_CONFIG_HOME=str(here/"config"), XDG_DATA_HOME=str(here/"xdg-data"),
                XDG_CACHE_HOME=str(here/"cache"), XDG_STATE_HOME=str(here/"state"),
                PATH=f"{binary.parent}:{base_env['PATH']}",
            )
            probe_environment = dict(environment, PYTHONHOME=str(here/"unused-python-home"))
            base_prefix = checked([binary, "-I", "-B", "-c", "import sys; print(sys.prefix)"],
                                  environment, ordinary).strip()
            original_image = hashlib.sha256(binary.read_bytes()).hexdigest()

            def make_venv(path, mode):
                checked([binary, "-I", "-B", "-c", create, binary, path, mode],
                        environment, ordinary)
                packages = path / "lib" / f"python{minor}" / "site-packages"
                assert packages.is_dir(), packages
                (packages / "omg_venv_observation.py").write_text(f"VALUE = {path.name!r}\n")
                alias = path / "bin" / f"python{minor}"
                assert alias.is_file(), alias
                assert alias.samefile(binary) == (mode == "link"), alias

            for label, name, layout, placeholder in layouts:
                for pin in ("path", "constraint"):
                    project = here / f"{label}-{pin}"
                    project.mkdir()
                    os.chown(project, account.pw_uid, account.pw_gid)
                    if pin == "constraint":
                        (project / "pyproject.toml").write_text(
                            f'[project]\nrequires-python = "=={version}"\n'
                        )
                    if placeholder == "file":
                        (project / ".venv").write_text("ordinary unactivated placeholder\n")
                    elif placeholder == "directory":
                        (project / ".venv").mkdir()
                    elif placeholder == "other-venv":
                        make_venv(project / "venv", "link")
                    venv = project / name if name else None
                    if venv:
                        make_venv(venv, layout)
                    expected = {
                        "exe": str(binary),
                        "prefix": str(venv) if venv else base_prefix,
                        "venv": str(venv) if venv else None,
                        "home": None if venv else probe_environment["PYTHONHOME"],
                        "local": name,
                        "args": ["two words", "--literal"],
                    }
                    for command_name in ("python", "python3", f"python{minor}"):
                        case = f"{label}-{pin}-{command_name}"
                        result = subprocess.run(
                            [cli, "run", command_name, "--", "-I", "-B", "-c",
                             program, *expected["args"]],
                            cwd=project, env=probe_environment, stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, timeout=8, **ordinary,
                        )
                        output = [json.loads(line.removeprefix("fixture python "))
                                  for line in result.stdout.splitlines()
                                  if line.startswith("fixture python ")]
                        checks.append(dict(
                            phase=phase, case=case, status=result.returncode,
                            passed=result.returncode == 0 and output == [expected],
                            observed=output, expected=expected,
                            diagnostic=(result.stdout + result.stderr)[-1100:],
                        ))
            assert hashlib.sha256(binary.read_bytes()).hexdigest() == original_image


    def inspect_python_inventory_and_removal():
        phase = "python-inventory-removal"
        version = "3.12.7"
        sibling = "3.11.9"
        cases = (
            ("relative-active", True, True, True),
            ("absolute-active", True, True, True),
            ("no-selection", True, False, False),
            ("sibling-active", True, False, False),
            ("dangling-selection", True, False, False),
            ("foreign-selection", True, False, False),
            ("directory-selection", True, False, False),
            ("missing-version", False, False, True),
        )
        with tempfile.TemporaryDirectory(prefix="python-inventory-removal-", dir=work) as directory:
            here = Path(directory)
            os.chown(here, account.pw_uid, account.pw_gid)
            for label, installed, selected, refuse in cases:
                home = here / label
                home.mkdir()
                os.chown(home, account.pw_uid, account.pw_gid)
                data = home / "data"
                versions = data / "versions/python"
                destination = versions / version
                current = versions / "current"
                outside = home / "outside" / version
                outside.mkdir(parents=True)
                (outside / "owner-file").write_text("outside file\n")
                for release in (sibling, version) if installed else (sibling,):
                    runtime = versions / release
                    runtime.mkdir(parents=True)
                    (runtime / ".omg-install-complete").write_text(f"{release}\n")
                    (runtime / "owner-file").write_text(f"{release}\n")

                target = {
                    "relative-active": version,
                    "absolute-active": destination,
                    "sibling-active": sibling,
                    "dangling-selection": home / "missing" / version,
                    "foreign-selection": outside,
                }.get(label)
                if target is not None:
                    current.symlink_to(target)
                elif label == "directory-selection":
                    current.mkdir()
                for path in (data, *data.rglob("*")):
                    os.chown(path, account.pw_uid, account.pw_gid, follow_symlinks=False)
                expected_active = version if selected else sibling if label == "sibling-active" else None
                before = [version, sibling] if installed else [sibling]
                after = before if refuse else [sibling]
                env = dict(disabled, HOME=str(home), OMG_DATA_DIR=str(data),
                           OMG_CONFIG_DIR=str(home/"config"/"omg"), OMG_NATIVE_TEST_DATA_DIR="1",
                           XDG_CONFIG_HOME=str(home/"config"), XDG_DATA_HOME=str(home/"xdg-data"),
                           XDG_CACHE_HOME=str(home/"cache"), XDG_STATE_HOME=str(home/"state"))

                for mode, args in (
                    ("list", ("--json", "list", "python")),
                    ("alias-list", ("--json", "list", "python3")),
                    ("which", ("which", "python")),
                    ("remove", ("use", "python", version, "--uninstall")),
                    ("list-after", ("--json", "list", "python")),
                ):
                    result = subprocess.run([cli, *args], cwd=home, env=env, stdin=subprocess.DEVNULL,
                                            capture_output=True, text=True, timeout=8, **ordinary)
                    if mode in ("list", "alias-list", "list-after"):
                        expected = dict(runtime="python", current=expected_active,
                                        installed=after if mode == "list-after" else before)
                        try:
                            observed = json.loads(result.stdout)
                        except json.JSONDecodeError:
                            observed = None
                        passed = result.returncode == 0 and observed == expected
                    elif mode == "which":
                        if expected_active is None:
                            passed = result.returncode != 0 and "no version set" in result.stderr
                        else:
                            passed = result.returncode == 0 and result.stdout.strip() == f"python {expected_active}"
                    else:
                        diagnostic = "active; switch" if selected else "not installed"
                        passed = (result.returncode != 0 and diagnostic in result.stderr) if refuse else (
                            result.returncode == 0 and f"Removed python {version}" in result.stdout)
                        passed &= destination.is_dir() == (version in after)

                    # A removal may change only the requested local version's tree.
                    if target is not None:
                        current_unchanged = current.is_symlink() and os.readlink(current) == str(target)
                    elif label == "directory-selection":
                        current_unchanged = current.is_dir() and not current.is_symlink()
                    else:
                        current_unchanged = not current.exists() and not current.is_symlink()
                    passed &= (current_unchanged
                               and (outside/"owner-file").read_text() == "outside file\n"
                               and (versions/sibling/"owner-file").read_text() == f"{sibling}\n")
                    checks.append(dict(
                        phase=phase, case=f"{label}-{mode}", status=result.returncode, passed=passed,
                        current=expected_active,
                        diagnostic=(result.stdout + result.stderr)[-1100:],
                    ))


    def inspect_python_tool_prerequisites():
        phase = "python-tool-prerequisites"
        tools = ("black", "glances", "httpie", "mypy", "pipx",
                 "poetry", "rich-cli", "ruff", "yt-dlp")
        layouts = ("fresh", "other-runtime", "unselected", "dangling")
        with tempfile.TemporaryDirectory(prefix="python-tool-prerequisites-", dir=work) as directory:
            here = Path(directory)
            os.chown(here, account.pw_uid, account.pw_gid)
            for tool in tools:
                for layout in layouts:
                    home = here / f"{layout}-{tool}"
                    home.mkdir()
                    os.chown(home, account.pw_uid, account.pw_gid)
                    data = home / "data"
                    data.mkdir()
                    versions = data / "versions"
                    python = versions / "python"
                    if layout == "other-runtime":
                        (versions / "node").mkdir(parents=True)
                    elif layout in ("unselected", "dangling"):
                        python.mkdir(parents=True)
                        if layout == "dangling":
                            (python / "current").symlink_to("3.12.7")
                    previous = data / "tools" / "pip" / tool
                    previous.mkdir(parents=True)
                    marker = previous / "owner-file"
                    marker.write_text("previous tool state\n")
                    bin_dir = data / "bin"
                    bin_dir.mkdir()
                    entry = bin_dir / tool
                    entry.symlink_to(marker)
                    for path in (data, *data.rglob("*")):
                        os.chown(path, account.pw_uid, account.pw_gid, follow_symlinks=False)
                    env = dict(disabled, HOME=str(home), OMG_DATA_DIR=str(data),
                               OMG_CONFIG_DIR=str(home/"config"/"omg"), OMG_NATIVE_TEST_DATA_DIR="1",
                               XDG_CONFIG_HOME=str(home/"config"), XDG_DATA_HOME=str(home/"xdg-data"),
                               XDG_CACHE_HOME=str(home/"cache"), XDG_STATE_HOME=str(home/"state"))
                    result = subprocess.run([cli, "tool", "install", tool], cwd=home, env=env,
                                            stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                            timeout=8, **ordinary)
                    current = python / "current"
                    selection_unchanged = (
                        current.is_symlink() and os.readlink(current) == "3.12.7"
                        if layout == "dangling" else not current.is_symlink()
                    )
                    preserved = (
                        marker.read_text() == "previous tool state\n" and entry.is_symlink()
                        and os.readlink(entry) == str(marker) and selection_unchanged
                        and sorted(path.name for path in previous.parent.iterdir()) == [tool]
                        and (layout != "fresh" or not versions.exists())
                        and (layout != "other-runtime" or not python.exists())
                    )
                    diagnostic = "Package installation requires a selected OMG-managed python"
                    checks.append(dict(
                        phase=phase, case=f"{layout}-{tool}", status=result.returncode,
                        passed=(result.returncode != 0 and diagnostic in result.stderr
                                and "omg use python <version>" in result.stderr
                                and "Found in registry:" in result.stdout and preserved),
                        preserved=preserved, diagnostic=(result.stdout + result.stderr)[-1100:],
                    ))


    def inspect_managed_tool_inventory():
        phase = "managed-tool-inventory"
        cases = (
            ("healthy-pip", "pip", "black", "black", "bin/black", "absolute"),
            ("legacy-cargo", "cargo", "diesel", "diesel_cli", "bin/diesel", "relative"),
            ("npm-shim", "npm", "typescript", "typescript", "node_modules/.bin/tsc", "npm"),
            ("unlinked", "pip", "black", "black", "bin/black", "unlinked"),
            ("empty-registered", "pip", "black", "black", None, "empty"),
            ("dangling-link", "pip", "black", "black", None, "dangling"),
            ("foreign-link", "pip", "black", "black", None, "foreign"),
            ("staging-link", "pip", "black", ".black.staging-fixture", "bin/black", "staging"),
            ("incomplete-link", "pip", "black", "black", "bin/black", "incomplete"),
        )
        with tempfile.TemporaryDirectory(prefix="managed-tool-inventory-", dir=work) as directory:
            here = Path(directory)
            os.chown(here, account.pw_uid, account.pw_gid)
            for label, manager, tool, install_name, launcher, mode in cases:
                home = here / label
                home.mkdir()
                os.chown(home, account.pw_uid, account.pw_gid)
                data = home / "data"
                bin_dir = data / "bin"
                bin_dir.mkdir(parents=True)
                install = data / "tools" / manager / install_name
                install.mkdir(parents=True)
                outside = home / "ordinary-file"
                outside.write_text("user-owned file\n")
                if mode == "incomplete":
                    (install / ".omg-installing").write_text("incomplete tool publication\n")
                target = install / launcher if launcher else install / "bin" / tool
                if launcher:
                    target.parent.mkdir(parents=True)
                    if mode == "npm":
                        implementation = install / "node_modules/typescript/bin/tsc"
                        implementation.parent.mkdir(parents=True)
                        implementation.write_text("#!/bin/sh\nprintf 'fixture tool\\n'\n")
                        implementation.chmod(0o755)
                        target.symlink_to("../typescript/bin/tsc")
                    else:
                        target.write_text("#!/bin/sh\nprintf 'fixture tool\\n'\n")
                        target.chmod(0o755)
                link = bin_dir / target.name
                if mode == "foreign":
                    linked = outside
                elif mode == "relative":
                    linked = Path(os.path.relpath(target, bin_dir))
                else:
                    linked = target
                if mode not in ("unlinked", "empty"):
                    link.symlink_to(linked)
                for path in (data, *data.rglob("*")):
                    os.chown(path, account.pw_uid, account.pw_gid, follow_symlinks=False)
                installed = mode in ("absolute", "relative", "npm", "unlinked")
                listed = installed and mode != "unlinked"
                env = dict(disabled, HOME=str(home), OMG_DATA_DIR=str(data),
                           OMG_CONFIG_DIR=str(home/"config"/"omg"), OMG_NATIVE_TEST_DATA_DIR="1",
                           XDG_CONFIG_HOME=str(home/"config"), XDG_DATA_HOME=str(home/"xdg-data"),
                           XDG_CACHE_HOME=str(home/"cache"), XDG_STATE_HOME=str(home/"state"))

                def run(case, args, inspect):
                    result = subprocess.run([cli, *args], cwd=home, env=env, stdin=subprocess.DEVNULL,
                                            capture_output=True, text=True, timeout=8, **ordinary)
                    checks.append(dict(
                        phase=phase, case=f"{label}-{case}", status=result.returncode,
                        passed=(inspect(result) and outside.read_text() == "user-owned file\n"),
                        diagnostic=(result.stdout + result.stderr)[-1100:],
                    ))

                def list_matches(result):
                    if listed:
                        return (result.returncode == 0 and "Installed Tools:" in result.stdout
                                and f"  {link.name} points to -> {linked}" in result.stdout.splitlines())
                    message = ("No managed tool commands are linked." if installed
                               else "No tools installed via omg tool.")
                    return result.returncode == 0 and message in result.stdout

                def update_matches(result):
                    unchanged = install.is_dir() and (not launcher or target.is_file())
                    unchanged &= (not link.is_symlink() if mode in ("unlinked", "empty")
                                  else link.is_symlink() and os.readlink(link) == str(linked))
                    unchanged &= sorted(path.name for path in install.parent.iterdir()) == [install_name]
                    if installed:
                        return unchanged and result.returncode != 0 and f"Updating {tool}" in result.stdout
                    return unchanged and result.returncode == 0 and "No tools installed." in result.stdout

                run("list", ("tool", "list"), list_matches)
                for verb in ("remove", "update"):
                    run(f"complete-{verb}", ("complete", "--shell", "bash", "--current", tool,
                                             "--last", verb, "--full", f"omg tool {verb} {tool}"),
                        lambda result: result.returncode == 0
                        and result.stdout.splitlines() == ([tool] if installed else []))
                run("update-all", ("tool", "update", "all"), update_matches)
                if installed:
                    run("remove", ("tool", "remove", tool),
                        lambda result: result.returncode == 0 and "Removal complete" in result.stdout
                        and not install.exists() and not link.is_symlink())


    def inspect_fedora_system_tool_registry():
        phase = "fedora-system-tool-registry"
        cases = (
            ("fd", "fd-find", "search"),
            ("dust", "du-dust", "system"),
            ("rg", "ripgrep", "search"),
            ("ripgrep", "ripgrep", "search"),
            ("delta", "git-delta", "git"),
            ("procs", "procs", "system"),
            ("jq", "jq", "data"),
            ("duf", "duf", "system"),
        )
        with tempfile.TemporaryDirectory(prefix="system-tool-registry-", dir=root) as directory:
            owner = Path(directory)
            owner.chmod(0o755)
            home = owner / "home"
            home.mkdir()
            os.chown(home, account.pw_uid, account.pw_gid)
            witness = owner / "selected-package"
            wrapper = owner / "observe-system-tool"
            wrapper.write_text(f"""#!/bin/bash
set -eu
printf '%s\\n' "$@" > {shlex.quote(str(witness))}
printf 'Controlled registry probe stopped before the DNF operation\\n' >&2
exit 95
""")
            wrapper.chmod(0o755)
            native = Path(dnf).resolve(strict=True)
            env = dict(disabled, HOME=str(home), OMG_DATA_DIR=str(home/"data"),
                       OMG_CONFIG_DIR=str(home/"config"/"omg"), OMG_NATIVE_TEST_DATA_DIR="1",
                       XDG_CONFIG_HOME=str(home/"config"), XDG_DATA_HOME=str(home/"xdg-data"),
                       XDG_CACHE_HOME=str(home/"cache"), XDG_STATE_HOME=str(home/"state"))
            (owner/"root-data").mkdir(mode=0o700)
            root_env = dict(base_env, HOME=str(owner), OMG_DISABLE_DAEMON="1",
                            OMG_DISABLE_TELEMETRY="1", NO_COLOR="1",
                            OMG_DATA_DIR=str(owner/"root-data"), OMG_NATIVE_TEST_DATA_DIR="1",
                            OMG_CONFIG_DIR=str(owner/"root-config"/"omg"),
                            XDG_CONFIG_HOME=str(owner/"root-config"),
                            XDG_DATA_HOME=str(owner/"root-xdg-data"),
                            XDG_CACHE_HOME=str(owner/"root-cache"),
                            XDG_STATE_HOME=str(owner/"root-state"))

            def run(label, args, inspect, *, privileged=False):
                witness.unlink(missing_ok=True)
                result = subprocess.run([cli, *args], cwd=home,
                                        env=root_env if privileged else env,
                                        stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                        timeout=8, **({} if privileged else ordinary))
                selected = witness.read_text().splitlines() if witness.exists() else []
                checks.append(dict(
                    phase=phase, case=label, status=result.returncode,
                    passed=inspect(result, selected), native_args=selected,
                    diagnostic=(result.stdout + result.stderr)[-1200:],
                ))

            checked(["/usr/bin/mount", "--bind", wrapper, native])
            try:
                for name, package_name, category in cases:
                    run(f"{name}-search", ("tool", "search", name),
                        lambda result, selected: result.returncode == 0 and not selected
                        and f"  {name} [{category}] via dnf" in result.stdout.splitlines())
                    run(f"{name}-install", ("tool", "install", name),
                        lambda result, selected: result.returncode != 0 and not selected
                        and f"Found in registry: {package_name} (dnf)" in result.stdout
                        and "Use --yes for non-interactive package installation" in result.stderr)
                    run(f"{name}-update", ("tool", "update", name),
                        lambda result, selected: result.returncode != 0 and not selected
                        and f"System package {package_name} via dnf" in result.stdout
                        and "Use --yes for non-interactive package installation" in result.stderr)
                    run(f"{name}-remove", ("tool", "remove", name),
                        lambda result, selected: result.returncode != 0 and selected.count(package_name) == 1
                        and "remove" in selected and any(arg.startswith("--store") for arg in selected)
                        and (name == package_name or name not in selected), privileged=True)

                run("registry", ("tool", "registry"),
                    lambda result, selected: result.returncode == 0 and not selected
                    and all(f"    {name} (dnf) -" in result.stdout for name, _, _ in cases))
                for name, category, manager in (("black", "python", "pip"), ("diesel", "rust", "cargo"),
                                                ("typescript", "node", "npm")):
                    run(f"{manager}-registry-control", ("tool", "search", name),
                        lambda result, selected: result.returncode == 0 and not selected
                        and f"  {name} [{category}] via {manager}" in result.stdout.splitlines())
            finally:
                checked(["/usr/bin/umount", native])


    def inspect_named_tool_updates():
        import errno
        import pty
        import select

        phase = "named-tool-updates"
        tools = (
            ("black", "pip", "black", "python"),
            ("glances", "pip", "glances", "python"),
            ("httpie", "pip", "httpie", "python"),
            ("ruff", "pip", "ruff", "python"),
            ("yt-dlp", "pip", "yt-dlp", "python"),
            ("rich-cli", "pip", "rich-cli", "python"),
            ("diesel", "cargo", "diesel_cli", "rust"),
        )
        layouts = ("missing", "empty", "incomplete", "installed")
        system_tools = ("fd", "dust", "rg", "delta", "jq", "procs", "ripgrep", "duf")
        with tempfile.TemporaryDirectory(prefix="named-tool-updates-", dir=work) as directory:
            here = Path(directory)
            os.chown(here, account.pw_uid, account.pw_gid)

            def owned_environment(home):
                home.mkdir()
                os.chown(home, account.pw_uid, account.pw_gid)
                return dict(disabled, HOME=str(home), OMG_DATA_DIR=str(home/"data"),
                            OMG_CONFIG_DIR=str(home/"config"/"omg"), OMG_NATIVE_TEST_DATA_DIR="1",
                            XDG_CONFIG_HOME=str(home/"config"), XDG_DATA_HOME=str(home/"xdg-data"),
                            XDG_CACHE_HOME=str(home/"cache"), XDG_STATE_HOME=str(home/"state"),
                            TERM="xterm", OMG_NO_UPDATE_CHECK="1")

            for tool, manager, installed_name, runtime in tools:
                for layout in layouts:
                    home = here / f"{tool}-{layout}"
                    env = owned_environment(home)
                    data = home / "data"
                    current = data / "tools" / manager / installed_name
                    command_link = data / "bin" / tool
                    executable = current / "bin" / tool
                    if layout != "missing":
                        current.mkdir(parents=True)
                    if layout in ("incomplete", "installed"):
                        executable.parent.mkdir()
                        executable.write_text("#!/bin/sh\nprintf 'previous tool\\n'\n")
                        executable.chmod(0o755)
                        command_link.parent.mkdir()
                        command_link.symlink_to(executable)
                    if layout == "incomplete":
                        (current / ".omg-installing").write_text("publication incomplete\n")
                    if data.exists():
                        for path in (data, *data.rglob("*")):
                            os.chown(path, account.pw_uid, account.pw_gid, follow_symlinks=False)
                    snapshot = sorted((str(path.relative_to(data)), path.is_symlink(),
                                       os.readlink(path) if path.is_symlink() else
                                       path.read_bytes() if path.is_file() else None)
                                      for path in data.rglob("*") if not path.name.startswith(".omg-tool"))
                    result = subprocess.run([cli, "tool", "update", tool], cwd=home, env=env,
                                            stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                            timeout=8, **ordinary)
                    after = sorted((str(path.relative_to(data)), path.is_symlink(),
                                    os.readlink(path) if path.is_symlink() else
                                    path.read_bytes() if path.is_file() else None)
                                   for path in data.rglob("*") if not path.name.startswith(".omg-tool"))
                    preserved = all(item in after for item in snapshot) and not any(
                        ".staging-" in item[0] for item in after)
                    expected = (f"requires a selected OMG-managed {runtime}" if layout == "installed"
                                else f"Tool '{tool}' is not installed")
                    checks.append(dict(
                        phase=phase, case=f"{tool}-{layout}", status=result.returncode,
                        passed=(result.returncode != 0 and expected in result.stderr and preserved
                                and "Update complete!" not in result.stdout),
                        preserved=preserved, diagnostic=(result.stdout + result.stderr)[-1200:],
                    ))

            def decline_system_update(name):
                home = here / f"system-{name}"
                env = owned_environment(home)
                pid, descriptor = pty.fork()
                if pid == 0:
                    os.chown(os.ttyname(0), account.pw_uid, account.pw_gid)
                    os.setgroups([])
                    os.setgid(account.pw_gid)
                    os.setuid(account.pw_uid)
                    os.chdir(home)
                    os.execve(cli, [str(cli), "tool", "update", name], env)
                transcript = bytearray()
                declined = False
                status = None
                try:
                    deadline = time.monotonic() + 8
                    while time.monotonic() < deadline:
                        if not select.select([descriptor], [], [], 0.05)[0]:
                            continue
                        try:
                            chunk = os.read(descriptor, 4096)
                        except OSError as error:
                            if error.errno == errno.EIO:
                                break
                            raise
                        if not chunk:
                            break
                        transcript.extend(chunk)
                        assert len(transcript) <= 65536, name
                        if not declined and b"Proceed with installation of 1 package(s)?" in transcript:
                            os.write(descriptor, b"n\n")
                            declined = True
                    while time.monotonic() < deadline:
                        child, completed = os.waitpid(pid, os.WNOHANG)
                        if child == pid:
                            status = os.waitstatus_to_exitcode(completed)
                            break
                        time.sleep(0.01)
                finally:
                    os.close(descriptor)
                    if status is None:
                        try:
                            os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        os.waitpid(pid, 0)
                text = transcript.decode(errors="replace")
                checks.append(dict(
                    phase=phase, case=f"{name}-cancelled", status=status,
                    passed=(declined and status == 0 and "Installation cancelled" in text
                            and "Update complete!" not in text),
                    diagnostic=text[-1200:],
                ))

            for tool in system_tools:
                decline_system_update(tool)


    def inspect_install_picker():
        import errno
        import pty
        import select
        import struct
        import termios

        phase = "fedora-install-picker"
        identity = f"{package}.noarch"
        queries = (
            ("name", package, "install", True),
            ("alias", package, "i", True),
            ("info", package, "info", True),
            ("uppercase", package.upper(), "install", True),
            ("qualified", identity, "install", True),
            ("prefix", "^omg-observer", "install", True),
            ("suffix", "observer-fixture.noarch$", "install", True),
            ("absent", "no-such-fixture-zz", "install", False),
        )

        with tempfile.TemporaryDirectory(prefix="install-picker-", dir=root) as directory:
            here = Path(directory)
            here.chmod(0o755)
            target = Path(dnf).resolve(strict=True)
            native = here / target.name
            shutil.copy2(target, native)
            witness = here / "queries"
            witness.touch(mode=0o600)
            os.chown(witness, account.pw_uid, account.pw_gid)
            tracker = here / "dnf-track"
            tracker.write_text(f"""#!/usr/bin/bash
available=0
format=
for argument in "$@"; do
    case "$argument" in
        --available) available=1 ;;
        '%{{name}}.%{{arch}}'*) format="$argument" ;;
    esac
done
if [[ "$available" == 1 && -n "$format" ]]; then
    if [[ "$format" == '%{{name}}.%{{arch}}'$'\\036' ]]; then
        printf 'names\\n' >> {shlex.quote(str(witness))}
    else
        printf 'rich\\n' >> {shlex.quote(str(witness))}
    fi
fi
exec {shlex.quote(str(native))} "$@"
""")
            tracker.chmod(0o755)
            terminal_env = dict(disabled, TERM="xterm-256color", OMG_NO_UPDATE_CHECK="1")

            def run_picker(keys, expect_selection, wait_for_no_match):
                child, master = pty.fork()
                if child == 0:
                    fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 100, 0, 0))
                    os.chown(os.ttyname(0), account.pw_uid, account.pw_gid)
                    os.setgroups([])
                    os.setgid(account.pw_gid)
                    os.setuid(account.pw_uid)
                    os.chdir(work)
                    os.execve(cli, [str(cli), "install", "--dry-run"], terminal_env)

                output = bytearray()
                sent = False
                cancelled_empty_result = False
                status = None
                try:
                    deadline = time.monotonic() + 10
                    while time.monotonic() < deadline:
                        if not select.select([master], [], [], 0.05)[0]:
                            continue
                        try:
                            chunk = os.read(master, 8192)
                        except OSError as error:
                            if error.errno == errno.EIO:
                                break
                            raise
                        if not chunk:
                            break
                        output.extend(chunk)
                        assert len(output) <= 262144
                        if not sent and b"\x1b[?25l" in output:
                            os.write(master, keys)
                            sent = True
                        if (wait_for_no_match and not cancelled_empty_result
                                and re.search(rb"No(?:\x1b\[[0-9;]*H| )matching(?:\x1b\[[0-9;]*H| )packages", output)):
                            os.write(master, b"\x1b")
                            cancelled_empty_result = True
                    while time.monotonic() < deadline:
                        reaped, result = os.waitpid(child, os.WNOHANG)
                        if reaped == child:
                            status = os.waitstatus_to_exitcode(result)
                            break
                        time.sleep(0.01)
                finally:
                    os.close(master)
                    if status is None:
                        try:
                            os.kill(child, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        os.waitpid(child, 0)
                text = output.decode(errors="replace")
                restored = b"\x1b[?1049l" in output
                if expect_selection:
                    outcome = ("Install Preview" in text and identity in text
                               and "No changes will be made (dry run)" in text)
                else:
                    outcome = ("Installation cancelled" in text and "Install Preview" not in text
                               and (not wait_for_no_match or cancelled_empty_result))
                return status, restored, status == 0 and sent and restored and outcome, text

            checked(["/usr/bin/mount", "--bind", tracker, target])
            try:
                for label, configuration, repository, visible in (
                    ("host", host_config, repo_config, True),
                    ("installroot", alternate_config, repo_config, True),
                    ("excluded", host_config, repo_config + f"excludepkgs={package}\n", False),
                ):
                    config.write_text(configuration)
                    repo_file.write_text(repository)
                    refresh_fixture()

                    for name, query, command_name, has_match in queries:
                        cursor = len(witness.read_text().splitlines())
                        result = command([cli, "complete", "--shell", "bash", "--current", query,
                                          "--last", command_name, "--full", f"omg {command_name}"],
                                         disabled, ordinary)
                        evidence = witness.read_text().splitlines()[cursor:]
                        expected = [identity] if visible and has_match else []
                        correct = result.returncode == 0 and result.stdout.splitlines() == expected
                        checks.append(dict(phase=phase, case=f"{label}-complete-{name}",
                                           status=result.returncode, behavior=correct, queries=evidence,
                                           passed=correct and evidence == ["names"],
                                           diagnostic=(result.stdout + result.stderr)[-1000:]))

                    typed = package.encode()
                    for name, keys, may_select in (
                        ("escape", b"\x1b", False),
                        ("interrupt", typed + b"\x03", False),
                        ("dry-run", typed + b"\r", True),
                        ("backspace-dry-run", typed + b"z\x7f\r", True),
                    ):
                        cursor = len(witness.read_text().splitlines())
                        status, restored, correct, output = run_picker(keys, visible and may_select,
                                                                      not visible and may_select)
                        evidence = witness.read_text().splitlines()[cursor:]
                        checks.append(dict(phase=phase, case=f"{label}-tty-{name}", status=status,
                                           behavior=correct, restored=restored, queries=evidence,
                                           passed=correct and evidence[:1] == ["names"]
                                           and evidence.count("names") == 1,
                                           diagnostic=output[-1600:]))
            finally:
                checked(["/usr/bin/umount", target])
                config.write_text(host_config)
                repo_file.write_text(repo_config)
                refresh_fixture()


    def inspect_config_files():
        phase = "fedora-config-files"
        original = b"# keep local choices\ntelemetry_enabled = true\n\n[aur]\nbuild_concurrency = 2\n"
        max_size = 1024 * 1024

        with tempfile.TemporaryDirectory(prefix="config-files-", dir=work) as directory:
            here = Path(directory)
            os.chown(here, account.pw_uid, account.pw_gid)

            def settings(label, contents=original, mode=0o600, *, non_utf8=False):
                home = here / label
                config_dir = home / (os.fsdecode(b"config-\xff") if non_utf8 else "config")
                config_dir.mkdir(parents=True)
                os.chown(home, account.pw_uid, account.pw_gid)
                os.chown(config_dir, account.pw_uid, account.pw_gid)
                file = config_dir / "config.toml"
                if contents is not None:
                    file.write_bytes(contents)
                    file.chmod(mode)
                    os.chown(file, account.pw_uid, account.pw_gid)
                env = dict(disabled, HOME=str(home), OMG_CONFIG_DIR=str(config_dir),
                           OMG_DATA_DIR=str(home/"data"), XDG_CONFIG_HOME=str(home/"xdg-config"),
                           XDG_DATA_HOME=str(home/"xdg-data"), XDG_CACHE_HOME=str(home/"cache"),
                           XDG_STATE_HOME=str(home/"state"))
                return file, env

            def run(label, args, env, expect_status, expect_text, verify, *, exclude_text=None):
                result = command([cli, "config", *args], env, ordinary, timeout=8)
                transcript = result.stdout + result.stderr
                persisted = verify()
                checks.append(dict(
                    phase=phase, case=label, status=result.returncode, persisted=persisted,
                    passed=(result.returncode == expect_status and expect_text in transcript
                            and (exclude_text is None or exclude_text not in transcript) and persisted),
                    diagnostic=transcript[-1600:],
                ))

            def unchanged(file, contents=original, mode=0o600):
                return (file.read_bytes() == contents and stat.S_IMODE(file.stat().st_mode) == mode
                        and not file.with_suffix(".toml.backup").exists())

            def rewritten(file):
                data = file.read_bytes()
                parsed = tomllib.loads(data.decode())
                return (parsed.get("telemetry_enabled") is False and parsed["aur"]["build_concurrency"] == 2
                        and data.startswith(b"# keep local choices\n")
                        and stat.S_IMODE(file.stat().st_mode) == 0o600)

            def reset_to_defaults(file, contents):
                backup = file.with_suffix(".toml.backup")
                if not file.is_file() or not backup.is_file():
                    return False
                parsed = tomllib.loads(file.read_text())
                return (parsed.get("telemetry_enabled") is False and parsed["aur"]["build_concurrency"] == 1
                        and stat.S_IMODE(file.stat().st_mode) == 0o600
                        and stat.S_IMODE(backup.stat().st_mode) == 0o600
                        and backup.read_bytes() == contents)

            for mode in (0o600, 0o644, 0o664):
                label = f"set-{mode:o}"
                file, env = settings(label, mode=mode)
                run(label, ["set", "telemetry.enabled", "false"], env, 0, "Set telemetry.enabled = false",
                    lambda: rewritten(file))
                label = f"reset-{mode:o}"
                file, env = settings(label, mode=mode)
                run(label, ["reset", "--yes"], env, 0, "Configuration reset to defaults",
                    lambda: reset_to_defaults(file, original))
                label = f"validate-{mode:o}"
                file, env = settings(label, mode=mode)
                expected = "Configuration is valid!" if mode == 0o600 else f"loose permissions ({mode:o})"
                run(label, ["validate"], env, int(mode != 0o600), expected,
                    lambda: unchanged(file, mode=mode))

            file, env = settings("private")
            run("private-path", ["path"], env, 0, str(file), lambda: unchanged(file))
            run("private-get", ["get", "telemetry.enabled"], env, 0, "true\n", lambda: unchanged(file))
            run("private-list", ["list"], env, 0, "telemetry.enabled = true", lambda: unchanged(file))

            file, env = settings("inaccessible")
            file.parent.chmod(0)
            try:
                for label, args in (
                    ("get-telemetry", ["get", "telemetry.enabled"]),
                    ("get-build", ["get", "aur.build_concurrency"]),
                    ("list", ["list"]),
                    ("default", []),
                    ("validate", ["validate"]),
                    ("reset", ["reset", "--yes"]),
                ):
                    run(f"inaccessible-{label}", args, env, 1, "Permission denied",
                        lambda: unchanged(file), exclude_text="using defaults")
            finally:
                file.parent.chmod(0o755)

            for label, args, expected in (
                ("get", ["get", "aur.build_concurrency"], "1\n"),
                ("validate", ["validate"], "Configuration is valid (using defaults)"),
                ("reset", ["reset", "--yes"], "No config file exists"),
            ):
                file, env = settings(f"missing-{label}", contents=None)
                run(f"missing-{label}", args, env, 0, expected,
                    lambda: not file.exists() and not list(file.parent.iterdir()))

            for label, contents, expected_status, expected_text in (
                ("invalid-syntax", b"[aur\n", 1, "TOML syntax error"),
                ("invalid-schema", b"[aur]\nbuild_concurrency = 'two'\n", 1, "Failed to load configuration"),
                ("legacy-concurrency", b"[aur]\nbuild_concurrency = 9\n", 0, "unusually high (9)"),
            ):
                file, env = settings(label, contents)
                run(label, ["validate"], env, expected_status, expected_text,
                    lambda: unchanged(file, contents))

            invalid_utf8 = b"# local configuration \xff\n"
            file, env = settings("reset-invalid-utf8", invalid_utf8)
            run("reset-invalid-utf8", ["reset", "--yes"], env, 0, "Configuration reset to defaults",
                lambda: reset_to_defaults(file, invalid_utf8))

            oversized = b"#" + b"x" * max_size
            for label, args in (("get", ["get", "telemetry.enabled"]), ("validate", ["validate"]),
                                ("reset", ["reset", "--yes"])):
                file, env = settings(f"oversize-{label}", oversized)
                run(f"oversize-{label}", args, env, 1, "1048576",
                    lambda: unchanged(file, oversized), exclude_text="TOML syntax is valid")

            at_limit = original + b"#" + b"x" * (max_size - len(original) - 1)
            file, env = settings("at-limit-get", at_limit)
            run("at-limit-get", ["get", "telemetry.enabled"], env, 0, "true\n",
                lambda: unchanged(file, at_limit))
            file, env = settings("at-limit-set", at_limit)
            run("at-limit-set", ["set", "telemetry.enabled", "false"], env, 1, "1048576",
                lambda: unchanged(file, at_limit))

            file, env = settings("native-path", non_utf8=True)
            run("native-path-get", ["get", "telemetry.enabled"], env, 0, "true\n", lambda: unchanged(file))
            run("native-path-validate", ["validate"], env, 0, "Configuration is valid!",
                lambda: unchanged(file), exclude_text="using defaults")
            run("native-path-reset", ["reset", "--yes"], env, 0, "Configuration reset to defaults",
                lambda: reset_to_defaults(file, original))

            file, env = settings("directory-entry", contents=None)
            file.mkdir()
            os.chown(file, account.pw_uid, account.pw_gid)
            for label, args in (("get", ["get", "telemetry.enabled"]), ("validate", ["validate"]),
                                ("reset", ["reset", "--yes"])):
                run(f"directory-entry-{label}", args, env, 1, "must be a regular file",
                    lambda: file.is_dir() and not list(file.iterdir())
                    and not file.with_suffix(".toml.backup").exists())

            file, env = settings("locked")
            lock = file.with_suffix(".lock")
            with lock.open("x") as lease:
                lock.chmod(0o600)
                os.chown(lock, account.pw_uid, account.pw_gid)
                fcntl.flock(lease, fcntl.LOCK_EX)
                for label, args in (("set", ["set", "telemetry.enabled", "false"]),
                                    ("reset", ["reset", "--yes"])):
                    run(f"locked-{label}", args, env, 1, "Another configuration mutation",
                        lambda: unchanged(file))


    def inspect_fedora_output_admission():
        import errno
        import pty
        import shlex
        import shutil

        phase = "fedora-output-admission"
        clean = ["clean", "--cache", "--dry-run"]
        tip = "Prime sudo credentials for prompt-light package operations"
        preview = "No changes made (dry run)"

        with tempfile.TemporaryDirectory(prefix="output-admission-", dir=work) as directory:
            here = Path(directory)
            os.chown(here, account.pw_uid, account.pw_gid)

            def environment(label):
                home = here / label
                home.mkdir()
                data = home / "data"
                data.mkdir(mode=0o700)
                for owned in (home, data):
                    os.chown(owned, account.pw_uid, account.pw_gid)
                return dict(disabled, HOME=str(home), OMG_DATA_DIR=str(data),
                            OMG_CONFIG_DIR=str(home/"config"), XDG_CONFIG_HOME=str(home/"config"),
                            XDG_DATA_HOME=str(home/"xdg-data"), XDG_STATE_HOME=str(home/"state"),
                            XDG_CACHE_HOME=str(home/"cache"), XDG_RUNTIME_DIR=str(home/"run"),
                            TERM="xterm", OMG_NO_UPDATE_CHECK="1")

            def invoke(args, env, tty=()):
                if not tty:
                    result = command([cli, *args], env, ordinary, timeout=10)
                    return result.returncode, result.stdout, result.stderr, ""
                master, terminal = pty.openpty()
                try:
                    try:
                        result = subprocess.run([cli, *args], cwd=env["HOME"], env=env, timeout=10,
                                                stdin=terminal if "in" in tty else subprocess.DEVNULL,
                                                stdout=terminal if "out" in tty else subprocess.PIPE,
                                                stderr=terminal if "err" in tty else subprocess.PIPE,
                                                **ordinary)
                    finally:
                        os.close(terminal)
                    captured = bytearray()
                    os.set_blocking(master, False)
                    while True:
                        try:
                            chunk = os.read(master, 4096)
                        except BlockingIOError:
                            break
                        except OSError as error:
                            if error.errno != errno.EIO:
                                raise
                            break
                        if not chunk:
                            break
                        captured.extend(chunk)
                        assert len(captured) <= 16384
                    return (result.returncode, (result.stdout or b"").decode(),
                            (result.stderr or b"").decode(), captured.decode())
                finally:
                    os.close(master)

            def marker(env):
                path = Path(env["OMG_DATA_DIR"]) / ".turbo_hint_shown"
                if not path.is_file():
                    return "absent"
                if (stat.S_IMODE(path.stat().st_mode) == 0o600 and
                        path.stat().st_uid == account.pw_uid and path.read_bytes() == b"1"):
                    return "private"
                return "unexpected"

            def record(label, result, passes, marker_state, **evidence):
                status, stdout, stderr, terminal = result
                checks.append(dict(
                    phase=phase, case=label, status=status, marker=marker_state,
                    passed=passes, stdout=stdout[-1200:], stderr=stderr[-1200:],
                    terminal=terminal[-1200:], **evidence,
                ))

            for name, args in (
                ("install", ["install", "--dry-run", "bash"]),
                ("remove", ["remove", "--recursive", "--dry-run", "bash"]),
                ("update", ["update", "--dry-run"]),
                ("clean", clean),
                ("sync", ["sync"]),
                ("tool", ["tool", "list"]),
            ):
                for placement in ("prefix", "suffix"):
                    label = f"json-refused-{name}-{placement}"
                    env = environment(label)
                    argv = ["--json", *args] if placement == "prefix" else [*args, "--json"]
                    result = invoke(argv, env)
                    status, stdout, stderr, _ = result
                    marker_state = marker(env)
                    record(label, result, status == 1 and not stdout and marker_state == "absent"
                           and f"--json is not supported for \x60{name}\x60" in stderr
                           and tip not in stderr and "sudo:" not in stderr, marker_state)

            native_sudo = Path(shutil.which("sudo")).resolve(strict=True)
            witness = here / "sudo-attempts"
            witness.touch(mode=0o600)
            os.chown(witness, account.pw_uid, account.pw_gid)
            inactive_sudo = here / "inactive-sudo"
            inactive_sudo.write_text(
                "#!/usr/bin/bash\nprintf 'attempted\\n' >> " + shlex.quote(str(witness)) + "\nexit 1\n"
            )
            inactive_sudo.chmod(0o755)
            subprocess.run(["/usr/bin/mount", "--bind", inactive_sudo, native_sudo], check=True)
            try:
                for placement in ("prefix", "suffix"):
                    label = f"json-refused-before-sudo-{placement}"
                    env = environment(label)
                    args = ["remove", "--dry-run", "--yes", "bash"]
                    argv = ["--json", *args] if placement == "prefix" else [*args, "--json"]
                    previous = witness.read_bytes().count(b"\n")
                    result = invoke(argv, env)
                    status, stdout, stderr, _ = result
                    marker_state = marker(env)
                    sudo_attempts = witness.read_bytes().count(b"\n") - previous
                    record(label, result, status == 1 and not stdout and marker_state == "absent"
                           and "--json is not supported for \x60remove\x60" in stderr
                           and sudo_attempts == 0, marker_state, sudo_attempts=sudo_attempts)
            finally:
                subprocess.run(["/usr/bin/umount", native_sudo], check=True)

            for label, args in (
                ("plain", clean),
                ("quiet", ["--quiet", *clean]),
                ("quiet-short", ["-q", *clean]),
                ("verbose", ["-v", *clean]),
                ("quiet-trailing", [*clean, "--quiet"]),
                ("verbose-trailing", [*clean, "--verbose"]),
            ):
                env = environment(f"piped-{label}")
                result = invoke(args, env)
                status, stdout, stderr, _ = result
                marker_state = marker(env)
                record(f"piped-{label}", result, status == 0 and preview in stdout
                       and tip not in stderr and marker_state == "absent", marker_state)

            def terminal_case(label, args, env, tty, expect_hint, expect_marker):
                result = invoke(args, env, tty)
                status, stdout, stderr, terminal = result
                marker_state = marker(env)
                all_output = stdout + stderr + terminal
                record(label, result, status == 0 and preview in all_output
                       and all_output.count(tip) == int(expect_hint)
                       and marker_state == expect_marker, marker_state)

            attended = ("in", "out", "err")
            shared = environment("attended-repeat")
            terminal_case("attended-first", clean, shared, attended, True, "private")
            terminal_case("attended-repeat", clean, shared, attended, False, "private")
            shared = environment("quiet-then-attended")
            terminal_case("attended-quiet", ["--quiet", *clean], shared, attended, False, "absent")
            terminal_case("attended-after-quiet", clean, shared, attended, True, "private")
            for label, args, tty, expect_hint in (
                ("attended-short-quiet", ["-q", *clean], attended, False),
                ("attended-verbose", ["-v", *clean], attended, True),
                ("redirect-stdout", clean, ("in", "err"), False),
                ("redirect-stderr", clean, ("in", "out"), False),
                ("redirect-stdin", clean, ("out", "err"), False),
                ("redirect-both-outputs", clean, ("in",), False),
                ("only-stderr-tty", clean, ("err",), False),
                ("only-stdout-tty", clean, ("out",), False),
            ):
                terminal_case(label, args, environment(label), tty, expect_hint,
                              "private" if expect_hint else "absent")

            for name, args, expected in (
                ("list", ["list", "node"], (list, dict)),
                ("status", ["status", "--fast"], (dict,)),
                ("stats", ["stats"], (dict,)),
            ):
                for placement in ("prefix", "suffix"):
                    label = f"json-result-{name}-{placement}"
                    env = environment(label)
                    argv = ["--json", *args] if placement == "prefix" else [*args, "--json"]
                    result = invoke(argv, env)
                    status, stdout, stderr, _ = result
                    try:
                        parsed = json.loads(stdout)
                    except ValueError:
                        parsed = None
                    marker_state = marker(env)
                    record(label, result, status == 0 and isinstance(parsed, expected)
                           and not stderr and marker_state == "absent", marker_state)


    def inspect_man_pages():
        phase = "fedora-man-pages"
        commands = (
            ("config",), ("config", "get"), ("config", "set"), ("config", "validate"), ("config", "reset"),
            ("privacy",), ("privacy", "opt-in"), ("privacy", "export"),
            ("tool",), ("tool", "search"), ("tool", "remove"), ("tool", "registry"),
            ("install",), ("remove",), ("update",), ("info",), ("search",),
            ("env",), ("env", "export"), ("env", "plan"),
            ("team",), ("team", "golden-path"), ("team", "golden-path", "create"),
            ("workspace", "diff"), ("snapshot", "restore"), ("audit", "log"),
            ("migrate", "import"), ("generate-man",), ("clean",), ("run",), ("use",),
        )
        common_options = {"--verbose", "--quiet", "--json", "--help"}
        global_options = common_options | {"--all-commands", "--version"}

        with tempfile.TemporaryDirectory(prefix="man-pages-", dir=work) as directory:
            here = Path(directory)
            os.chown(here, account.pw_uid, account.pw_gid)

            def environment(label, native_home=False):
                parent = here / label
                home = parent / (os.fsdecode(b"home-\xff") if native_home else "home")
                home.mkdir(parents=True)
                os.chown(home, account.pw_uid, account.pw_gid)
                return home, dict(disabled, HOME=str(home), OMG_DATA_DIR=str(home/"data"),
                                  OMG_CONFIG_DIR=str(home/"config"), XDG_CONFIG_HOME=str(home/"config"),
                                  XDG_DATA_HOME=str(home/"xdg-data"), XDG_CACHE_HOME=str(home/"cache"),
                                  XDG_STATE_HOME=str(home/"state"), OMG_NO_UPDATE_CHECK="1")

            def generate(label, env, output, args, check_existing=None):
                result = command([cli, "generate-man", *args], env, ordinary, timeout=12)
                pages = list(output.glob("omg*.1")) if output.is_dir() else []
                count = re.search(r"Generated (\d+) man pages", result.stdout)
                correct = (result.returncode == 0 and count is not None
                           and int(count.group(1)) == len(pages) == 140
                           and all(page.is_file() and not page.is_symlink() and page.stat().st_size > 0 for page in pages)
                           and not (Path(env["HOME"]) / "~").exists()
                           and (check_existing is None or check_existing()))
                checks.append(dict(phase=phase, case=label, status=result.returncode, passed=correct,
                                   pages=len(pages), diagnostic=(result.stdout + result.stderr)[-1100:]))
                return result

            home, env = environment("content")
            archive = home / "manual files"
            generate("explicit-output", env, archive, ["--output", archive])

            def unroff(text):
                return re.sub(r"\\f[BRI]", "", text).replace(r"\-", "-")

            for argv in commands:
                invocation = "omg " + " ".join(argv)
                name = "omg-" + "-".join(argv)
                result = command([cli, *argv, "--help"], env, ordinary, timeout=8)
                page = archive / f"{name}.1"
                man = unroff(page.read_text()) if page.is_file() else ""
                title = re.search(r"(?m)^\.TH\s+(\S+) 1(?:\s|$)", man)
                names = re.search(r"(?m)^\.SH NAME\n([^\n]+)", man)
                synopsis = re.search(r"(?m)^\.SH SYNOPSIS\n([^\n]+)", man)
                help_path = re.search(r"(?m)^Usage: (.+)$", result.stdout)
                options = set(re.findall(r"(?<![\w-])--[a-z][a-z0-9-]*", man))
                help_options = set(re.findall(r"(?<![\w-])--[a-z][a-z0-9-]*", result.stdout))
                references = re.findall(r"(?m)^(omg-[\w-]+)\(1\)$", man)
                full_path = (title is not None and title[1] == name
                             and names is not None and (names[1] == name or names[1].startswith(name + " - "))
                             and synopsis is not None and synopsis[1].startswith(invocation + " "))
                correct = (result.returncode == 0 and help_path is not None
                           and help_path[1].startswith(invocation)
                           and full_path and common_options <= help_options
                           and options & global_options == help_options & global_options
                           and all((archive / f"{reference}.1").is_file() for reference in references))
                checks.append(dict(phase=phase, case=f"help-{name}", status=result.returncode,
                                   passed=correct, title=title[1] if title else None,
                                   synopsis=synopsis[1] if synopsis else None,
                                   missing_globals=sorted((help_options & global_options) - options),
                                   unexpected_globals=sorted((options & global_options) - help_options),
                                   diagnostic=(result.stdout + result.stderr)[-1100:]))

            home, env = environment("default-xdg")
            generate("default-xdg", env, home/"xdg-data/man/man1", [])
            home, env = environment("default-home")
            env.pop("XDG_DATA_HOME")
            generate("default-home", env, home/".local/share/man/man1", [])

            for label, argument, relative, native_home in (
                ("relative-output", "custom pages", "custom pages", False),
                ("tilde-output", "~/man", "man", False),
                ("tilde-redundant-separator", "~//man", "man", False),
                ("tilde-home", "~", "", False),
                ("tilde-native-home", "~/manuals", "manuals", True),
            ):
                home, env = environment(label, native_home=native_home)
                generate(label, env, home/relative, ["--output", argument])

            home, env = environment("replace")
            output = home / "existing"
            output.mkdir()
            page = output / "omg.1"
            page.write_bytes(b"previous generated page\n")
            page.chmod(0o640)
            unrelated = output / "notes.txt"
            unrelated.write_bytes(b"preserve local notes\n")
            for path in (output, page, unrelated):
                os.chown(path, account.pw_uid, account.pw_gid)
            generate("replace-preserves-local-files", env, output, ["--output", output],
                     lambda: (page.read_bytes() != b"previous generated page\n"
                              and stat.S_IMODE(page.stat().st_mode) == 0o640
                              and unrelated.read_bytes() == b"preserve local notes\n"))

            home, env = environment("obstructed")
            output = home / "not-a-directory"
            output.write_bytes(b"unchanged\n")
            os.chown(output, account.pw_uid, account.pw_gid)
            result = command([cli, "generate-man", "--output", output], env, ordinary, timeout=8)
            checks.append(dict(phase=phase, case="obstructed-output", status=result.returncode, pages=0,
                               passed=(result.returncode != 0 and "Failed to create directory" in result.stderr
                                       and "Generated" not in result.stdout and output.read_bytes() == b"unchanged\n"),
                               diagnostic=(result.stdout + result.stderr)[-1100:]))


    def inspect_migration():
        phase = "fedora-migration"
        with tempfile.TemporaryDirectory(prefix="migration-", dir=work) as directory:
            files = Path(directory)
            os.chown(files, account.pw_uid, account.pw_gid)

            data = files / "omg-data"
            node = data / "versions/node"
            release = node / "22.0.0"
            release.mkdir(parents=True)
            marker = release / ".omg-install-complete"
            marker.write_text("22.0.0\n")
            current = node / "current"
            current.symlink_to(release.name)
            for path in (data, node.parent, node, release, marker):
                os.chown(path, account.pw_uid, account.pw_gid)
            migration_env = dict(disabled, OMG_DATA_DIR=str(data))

            def run(label, args, verify):
                result = command([cli, "migrate", *args], migration_env, ordinary, timeout=10)
                checks.append(dict(phase=phase, case=label, passed=verify(result),
                                   status=result.returncode, diagnostic=(result.stdout[-700:],
                                                                          result.stderr[-700:])))

            def package_row(name):
                return dict(original_name=name, category="application", description=None,
                            alternatives=[])

            def write_manifest(label, *, names=(), runtimes=None, distro="fedora", version="1.0"):
                path = files / f"{label}.json"
                path.write_text(json.dumps(dict(version=version, source_distro=distro, created_at=0,
                                                packages=[package_row(name) for name in names],
                                                runtimes=runtimes or {})))
                return path

            def preview(result, packages, runtimes, expected=""):
                return (result.returncode == 0 and not result.stderr
                        and f"{packages} package installation(s), {runtimes} runtime installation(s)"
                        in result.stdout and "No changes made (dry run)" in result.stdout
                        and expected in result.stdout)

            def refused(result, expected):
                return (result.returncode != 0 and expected.lower() in result.stderr.lower()
                        and "Mutation summary" not in result.stdout and "Applying..." not in result.stdout
                        and "No changes made (dry run)" not in result.stdout)

            explicit_query = [dnf, "--cacheonly", "--setopt=disable_excludes=*",
                              "repoquery", "--userinstalled", "--qf", r"%{name}\n"]
            original_config = config.read_text()
            config.write_text(alternate_config)
            try:
                expected_packages = sorted(set(ordinary_control(explicit_query).splitlines()))
                assert expected_packages == [package], expected_packages
                exported = files / "Fedora user's export.json"

                def command_hint(stdout):
                    hints = [line[line.index("omg migrate import"):] for line in stdout.splitlines()
                             if "omg migrate import" in line]
                    if len(hints) != 1:
                        return False
                    try:
                        argv = shlex.split(hints[0])
                    except ValueError:
                        return False
                    return argv == ["omg", "migrate", "import", "--", str(exported)]

                def matches_inventory(result):
                    if result.returncode != 0 or not exported.is_file():
                        return False
                    value = json.loads(exported.read_text())
                    return (value["version"] == "1.0" and value["source_distro"] == "fedora"
                            and value["created_at"] > 0 and value["runtimes"] == {"node": "22.0.0"}
                            and [row["original_name"] for row in value["packages"]] == expected_packages
                            and f"Packages: {len(expected_packages)}" in result.stdout
                            and command_hint(result.stdout))

                run("export-native-inventory", ["export", "--output", exported], matches_inventory)
                first_inode = exported.stat().st_ino if exported.is_file() else None
                run("export-replaces-atomically", ["export", "-o", exported],
                    lambda result: matches_inventory(result) and exported.stat().st_ino != first_inode)
                run("export-import-round-trip", ["import", "--dry-run", "--", exported],
                    lambda result: preview(result, len(expected_packages), 1, "node @ 22.0.0")
                    and command_hint(result.stdout))
                run("export-directory-error", ["export", "--output", files],
                    lambda result: result.returncode != 0 and "Exported to" not in result.stdout)

                for label, names, runtimes, distro, count, runtime_count, expected in (
                    ("native-rpm-name", (package,), {}, "fedora", 1, 0, package),
                    ("fedora-arch-selector", ("glibc.x86_64", "glibc.i686"), {}, "fedora", 2, 0, "glibc.i686"),
                    ("arch-portable-fallback", ("git", "curl"), {}, "arch", 2, 0, "Source: arch"),
                    ("debian-portable-fallback", ("git",), {}, "debian", 1, 0, "Source: debian"),
                    ("empty", (), {}, "fedora", 0, 0, ""),
                    ("node-lts", (), {"node": "lts/*"}, "fedora", 0, 1, "node @ lts/*"),
                    ("python-constraint", (), {"python": ">=3.13,<3.14"}, "fedora", 0, 1, "python @ >=3.13,<3.14"),
                    ("managed-tool", (), {"ripgrep": "14.1.1"}, "fedora", 0, 1, "ripgrep @ 14.1.1"),
                    ("runtime-alias", (), {"nodejs": "22"}, "fedora", 0, 1, "node @ 22"),
                    ("same-runtime-aliases", (), {"node": "22", "nodejs": "22"}, "fedora", 0, 1, "node @ 22"),
                    ("duplicate-packages", (package, package, "git", "git"), {}, "fedora", 2, 0, "git"),
                    ("unknown-source-distro", ("git",), {}, "custom-linux", 1, 0, "Source: custom-linux"),
                ):
                    path = write_manifest(label, names=names, runtimes=runtimes, distro=distro)
                    run(label, ["import", path, "--dry-run"],
                        lambda result: preview(result, count, runtime_count, expected))

                for label, names, runtimes, version, expected in (
                    ("empty-package", ("",), {}, "1.0", "package"),
                    ("name-with-spaces", ("two words",), {"node": "22"}, "1.0", "package"),
                    ("empty-runtime", (), {"": "22"}, "1.0", "runtime"),
                    ("empty-runtime-version", (), {"node": ""}, "1.0", "version"),
                    ("unknown-runtime", (), {"unknown-example-runtime": "22"}, "1.0", "unsupported runtime"),
                    ("conflicting-runtime-aliases", (), {"node": "22", "nodejs": "24"}, "1.0", "conflicting versions"),
                    ("future-manifest", (), {}, "2.0", "unsupported migration manifest version"),
                ):
                    path = write_manifest(label, names=names, runtimes=runtimes, version=version)
                    for suffix, options in (("preview", ["--dry-run"]), ("apply", [])):
                        run(f"{label}-{suffix}", ["import", path, *options],
                            lambda result: refused(result, expected))

                valid = write_manifest("valid", names=(package,), runtimes={"node": "22"})
                run("unattended-apply", ["import", valid],
                    lambda result: result.returncode != 0 and "interactive terminal" in result.stderr
                    and "Applying..." not in result.stdout)
                run("empty-unattended-apply", ["import", write_manifest("empty-apply")],
                    lambda result: result.returncode == 0 and "Migration complete!" in result.stdout)
                run("directory-manifest", ["import", files, "--dry-run"],
                    lambda result: refused(result, "regular file"))
                run("missing-manifest", ["import", files / "missing.json", "--dry-run"],
                    lambda result: refused(result, "migration manifest"))
                malformed = files / "malformed.json"
                malformed.write_text('{"version":')
                run("invalid-json", ["import", malformed, "--dry-run"],
                    lambda result: refused(result, "JSON"))
                oversized = write_manifest("oversized")
                with oversized.open("ab") as stream:
                    for _ in range(16):
                        stream.write(b" " * (1024 * 1024))
                run("oversized-manifest", ["import", oversized, "--dry-run"],
                    lambda result: refused(result, "byte limit"))
                assert sorted(set(ordinary_control(explicit_query).splitlines())) == expected_packages
                assert list(node.parent.iterdir()) == [node]
                assert set(node.iterdir()) == {release, current}
                assert current.readlink() == Path(release.name)
                assert list(release.iterdir()) == [marker] and marker.read_text() == "22.0.0\n"
            finally:
                config.write_text(original_config)


    def inspect_snapshots():
        phase = "fedora-snapshots"
        with tempfile.TemporaryDirectory(prefix="snapshots-", dir=work) as directory:
            data = Path(directory)
            os.chown(data, account.pw_uid, account.pw_gid)
            snapshots = data / "snapshots"
            index = snapshots / "index.json"
            settings = data / "config/omg"
            snapshot_env = dict(disabled, OMG_DATA_DIR=str(data), OMG_CONFIG_DIR=str(settings),
                                OMG_NATIVE_TEST_DATA_DIR="1")
            node = data / "versions/node"
            versions = ("22.0.0", "24.0.0")
            seed = """
import importlib.util, pathlib, sys
helper, directory, *versions = sys.argv[1:]
spec = importlib.util.spec_from_file_location("runtime_advisory_fixture", helper)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
data = pathlib.Path(directory)
config = pathlib.Path(fixture.fixture_cli_environment(data)["OMG_CONFIG_DIR"])
for version in versions:
    release = data / "versions/node" / version
    launcher = release / "bin/node"
    launcher.parent.mkdir(parents=True)
    launcher.write_text(f"#!/bin/sh\\nprintf '%s\\\\n' 'v{version}'\\n")
    launcher.chmod(0o755)
    fixture.seed_runtime_advisory_fixture(release, "node", version, config)
"""
            checked([sys.executable, "-I", "-B", "-c", seed, runtime_advisory_fixture, data, *versions],
                    snapshot_env, ordinary)
            current = node / "current"
            current.symlink_to(versions[0])

            def run(label, args, verify):
                result = command([cli, "snapshot", *args], snapshot_env, ordinary, timeout=12)
                checks.append(dict(phase=phase, case=label, passed=verify(result),
                                   status=result.returncode, diagnostic=(result.stdout[-950:],
                                                                          result.stderr[-950:])))

            def succeeded(result, message):
                return result.returncode == 0 and message in result.stdout and not result.stderr

            def refused(result, message):
                return (result.returncode != 0 and message.lower() in result.stderr.lower()
                        and "Changes to apply:" not in result.stdout
                        and "Applying changes..." not in result.stdout)

            def state_hash(state):
                result = hashlib.sha256()
                for name, version in sorted(state["runtimes"].items()):
                    result.update(f"{name}:{version};".encode())
                for name in sorted(set(state["packages"])):
                    result.update(f"{name};".encode())
                return result.hexdigest()

            query = [dnf, "--cacheonly", "--setopt=disable_excludes=*",
                     "repoquery", "--userinstalled", "--qf", r"%{name}\n"]
            config.write_text(alternate_config)
            try:
                expected = sorted(set(ordinary_control(query).splitlines()))
                assert expected == [package], expected
                run("list-empty", ["list"], lambda result: succeeded(result, "No snapshots found")
                    and not snapshots.exists())

                def created(result, message, count):
                    if not succeeded(result, "Snapshot created!") or not index.is_file():
                        return False
                    rows = json.loads(index.read_bytes())["snapshots"]
                    if len(rows) != count:
                        return False
                    latest = rows[-1]
                    path = snapshots / f'{latest["id"]}.json'
                    record = json.loads(path.read_bytes())
                    return (record["id"] == latest["id"] and record["id"] in result.stdout
                            and record["message"] == message == latest["message"]
                            and record["created_at"] == latest["created_at"]
                            and record["state"]["schema_version"] == 1
                            and record["state"]["packages"] == expected
                            and record["state"]["runtimes"] == {"node": versions[0]}
                            and record["state"]["hash"] == state_hash(record["state"]) == latest["hash"]
                            and stat.S_IMODE(path.stat().st_mode) == 0o600)

                run("create-native-state", ["create", "-m", "native state"],
                    lambda result: created(result, "native state", 1))
                first = json.loads(index.read_bytes())["snapshots"][0]["id"]
                saved = snapshots / f"{first}.json"
                original = saved.read_bytes()
                run("create-without-message", ["create"], lambda result: created(result, None, 2))
                second = json.loads(index.read_bytes())["snapshots"][-1]["id"]
                run("list-newest-first", ["list"], lambda result: succeeded(result, "2 snapshots total")
                    and first in result.stdout and second in result.stdout
                    and result.stdout.index(second) < result.stdout.index(first))
                run("create-message-limit", ["create", "-m", "a" * 1001],
                    lambda result: refused(result, "message too long"))
                run("restore-matching", ["restore", first, "--dry-run"],
                    lambda result: succeeded(result, "Environment already matches snapshot"))
                index_bytes = index.read_bytes()
                with (snapshots / ".index.lock").open("r+b") as lock:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    run("create-held-lock", ["create"], lambda result: refused(result, "mutation is running"))
                    run("delete-held-lock", ["delete", first], lambda result: refused(result, "mutation is running"))
                assert index.read_bytes() == index_bytes and saved.read_bytes() == original

                def replace_active(version):
                    current.unlink()
                    current.symlink_to(version)

                replace_active(versions[1])
                run("preview-runtime-diff", ["restore", first, "--dry-run"],
                    lambda result: succeeded(result, f"node {versions[1]} → {versions[0]}")
                    and "No changes made" in result.stdout and current.readlink().name == versions[1])
                run("apply-installed-runtime", ["restore", first],
                    lambda result: succeeded(result, "Snapshot restore complete")
                    and current.resolve() == node / versions[0])
                run("repeat-runtime-restore", ["restore", first],
                    lambda result: succeeded(result, "Environment already matches snapshot"))

                mark("dependency")
                try:
                    assert ordinary_control(query).splitlines() == []
                    run("preview-native-install", ["restore", first, "--dry-run"],
                        lambda result: succeeded(result, "Packages to install (1)") and package in result.stdout
                        and "No changes made" in result.stdout)
                    run("unattended-native-install", ["restore", first],
                        lambda result: result.returncode != 0 and "--yes" in result.stderr
                        and "Applying changes..." not in result.stdout)
                    run("create-dependency-only-inventory", ["create", "-m", "no explicitly installed packages"],
                        lambda result: succeeded(result, "Packages: 0"))
                    dependency_id = json.loads(index.read_bytes())["snapshots"][-1]["id"]
                    dependency_snapshot = snapshots / f"{dependency_id}.json"
                    assert checks[-1]["passed"], checks[-1]
                    assert json.loads(dependency_snapshot.read_bytes())["state"]["packages"] == []
                finally:
                    mark("user")
                run("preview-native-removal", ["restore", dependency_id, "--dry-run"],
                    lambda result: succeeded(result, "Packages to remove (1)") and package in result.stdout
                    and "No changes made" in result.stdout)
                run("unattended-native-removal", ["restore", dependency_id],
                    lambda result: result.returncode != 0 and "--yes" in result.stderr
                    and "Applying changes..." not in result.stdout)
                assert sorted(set(ordinary_control(query).splitlines())) == expected

                def edit_record(change, *, rehash=False):
                    value = json.loads(original)
                    change(value)
                    if rehash:
                        value["state"]["hash"] = state_hash(value["state"])
                    saved.write_bytes(json.dumps(value).encode())

                for label, change, rehash, expected_error in (
                    ("snapshot-id-mismatch", lambda value: value.update(id=second), False, "snapshot ID"),
                    ("future-state-version", lambda value: value["state"].update(schema_version=2), False,
                     "schema version 2"),
                    ("inventory-hash-mismatch", lambda value: value["state"].update(packages=[]), False,
                     "integrity check failed"),
                    ("unknown-runtime", lambda value: value["state"]["runtimes"].update(
                        {"unknown-example-runtime": "1.0"}), True, "unsupported runtime"),
                    ("blank-runtime-version", lambda value: value["state"]["runtimes"].update(node=""),
                     True, "invalid version"),
                    ("invalid-package-name", lambda value: value["state"].update(packages=["two words"]),
                     True, "package"),
                ):
                    edit_record(change, rehash=rehash)
                    run(label, ["restore", first, "--dry-run"],
                        lambda result: refused(result, expected_error))
                edit_record(lambda value: value["state"].pop("schema_version"))
                run("legacy-state-without-version", ["restore", first, "--dry-run"],
                    lambda result: succeeded(result, "Environment already matches snapshot"))
                candidates = [f"snapshot-example-{n:02d}" for n in range(12)]
                edit_record(lambda value: value["state"].update(packages=expected + candidates[::-1]), rehash=True)
                for attempt in range(3):
                    run(f"ordered-preview-{attempt}", ["restore", first, "--dry-run"],
                        lambda result: succeeded(result, "Packages to install (12)")
                        and [line.strip()[2:] for line in result.stdout.splitlines()
                             if line.strip().startswith("+ ")] == candidates[:10]
                        and "and 2 more" in result.stdout)
                saved.write_bytes(original)
                with saved.open("ab") as output:
                    for _ in range(16):
                        output.write(b" " * (1024 * 1024))
                run("oversized-state", ["restore", first, "--dry-run"], lambda result: refused(result, "byte limit"))
                saved.write_bytes(b'{"id":')
                run("invalid-state-json", ["restore", first, "--dry-run"],
                    lambda result: refused(result, "parse snapshot"))
                saved.write_bytes(original)
                before_damage = index.read_bytes()
                index.write_bytes(b'{"snapshots":')
                run("invalid-index-list", ["list"], lambda result: refused(result, "parse snapshot index"))
                run("invalid-index-delete", ["delete", first], lambda result: refused(result, "parse snapshot index")
                    and saved.read_bytes() == original)
                index.write_bytes(before_damage)
                with index.open("ab") as output:
                    for _ in range(16):
                        output.write(b" " * (1024 * 1024))
                run("oversized-index-list", ["list"], lambda result: refused(result, "byte limit"))
                index.write_bytes(before_damage)
                run("delete-other-snapshot", ["delete", second], lambda result: succeeded(result, f"Deleted snapshot {second}")
                    and not (snapshots / f"{second}.json").exists() and saved.read_bytes() == original)
                run("delete-dependency-only-snapshot", ["delete", dependency_id],
                    lambda result: succeeded(result, f"Deleted snapshot {dependency_id}") and not dependency_snapshot.exists())
                run("list-preserved-snapshot", ["list"], lambda result: succeeded(result, "1 snapshots total")
                    and first in result.stdout and second not in result.stdout and dependency_id not in result.stdout)
                run("restore-deleted-snapshot", ["restore", second, "--dry-run"],
                    lambda result: refused(result, "not found"))
                run("delete-unknown-snapshot", ["delete", "unknown-snapshot"],
                    lambda result: refused(result, "not found"))
                run("delete-final-snapshot", ["delete", first], lambda result: succeeded(result, f"Deleted snapshot {first}")
                    and not saved.exists() and json.loads(index.read_bytes()) == {"snapshots": []})
                assert sorted(set(ordinary_control(query).splitlines())) == expected
            finally:
                config.write_text(alternate_config)


    def inspect_snapshot_recovery():
        phase = "fedora-snapshot-recovery"
        query = [dnf, "--cacheonly", "--setopt=disable_excludes=*",
                 "repoquery", "--userinstalled", "--qf", r"%{name}\n"]
        expected = sorted(set(ordinary_control(query).splitlines()))
        assert expected == [package], expected
        checksum = hashlib.sha256((";".join(expected) + ";").encode()).hexdigest()
        state = dict(schema_version=1, runtimes={}, packages=expected, timestamp=0, hash=checksum)

        def record(identifier, message):
            return dict(id=identifier, message=message, created_at=0, state=state)

        def metadata(snapshot):
            return dict(id=snapshot["id"], message=snapshot["message"],
                        created_at=snapshot["created_at"], hash=checksum)

        def write(path, value):
            path.write_bytes(json.dumps(value).encode())
            path.chmod(0o600)
            os.chown(path, account.pw_uid, account.pw_gid)

        @contextmanager
        def arrange(action, step):
            with tempfile.TemporaryDirectory(prefix="snapshot-recovery-", dir=work) as directory:
                data = Path(directory)
                os.chown(data, account.pw_uid, account.pw_gid)
                snapshots = data / "snapshots"
                snapshots.mkdir(mode=0o700)
                os.chown(snapshots, account.pw_uid, account.pw_gid)
                index = snapshots / "index.json"
                keep, target = record("keep", "keep snapshot"), record("target", "recovered snapshot")
                write(snapshots / "keep.json", keep)
                prepared = snapshots / f".{action}.pending"
                stored = snapshots / "target.json"
                if step != "finished":
                    write(prepared, target if action == "create" else {"id": "target"})
                if action == "create" and step != "prepared":
                    if prepared.exists():
                        os.link(prepared, stored)
                    else:
                        write(stored, target)
                if action == "delete" and step == "prepared":
                    write(stored, target)
                rows = [metadata(keep)]
                if (action == "create" and step in ("index-updated", "finished")
                        or action == "delete" and step in ("prepared", "file-updated")):
                    rows.append(metadata(target))
                write(index, {"snapshots": rows})
                return_env = dict(disabled, OMG_DATA_DIR=str(data))
                yield snapshots, index, prepared, stored, target, return_env

        operations = (
            ("list", ["list"]),
            ("restore", ["restore", "target", "--dry-run"]),
            ("create", ["create", "-m", "next snapshot"]),
            ("delete", ["delete", "keep"]),
        )

        for action in ("create", "delete"):
            for step in ("prepared", "file-updated", "index-updated", "finished"):
                for operation, args in operations:
                    with arrange(action, step) as (snapshots, index, prepared, stored, target, recovery_env):
                        result = command([cli, "snapshot", *args], recovery_env, ordinary, timeout=12)
                        rows = json.loads(index.read_bytes())["snapshots"]
                        ids = [row["id"] for row in rows]
                        count = (operation != "delete") + (operation == "create") + (action == "create")
                        expected_output = {
                            "list": f"{count} snapshots total",
                            "restore": "Environment already matches snapshot",
                            "create": "Snapshot created!",
                            "delete": "Deleted snapshot keep",
                        }[operation]
                        success = (result.returncode == 0 and expected_output in result.stdout
                                   and not result.stderr)
                        if operation == "list":
                            success = success and ("recovered snapshot" in result.stdout) == (action == "create")
                        if operation == "restore" and action == "delete":
                            success = result.returncode != 0 and "not found" in result.stderr
                        if action == "create":
                            target_ok = (stored.is_file() and json.loads(stored.read_bytes()) == target
                                         and any(row == metadata(target) for row in rows))
                        else:
                            target_ok = not stored.exists() and "target" not in ids
                        observed = {entry.stem for entry in snapshots.glob("*.json") if entry != index}
                        consistent = (observed == set(ids) and len(ids) == count
                                      and ("keep" in ids) == (operation != "delete"))
                        checks.append(dict(phase=phase, case=f"{action}-{step}-{operation}",
                                           passed=success and target_ok and consistent and not prepared.exists(),
                                           status=result.returncode, diagnostic=(result.stdout[-600:],
                                               result.stderr[-700:], ids, sorted(observed), prepared.exists())))

        for action in ("create", "delete"):
            for operation, args in operations[:2]:
                with arrange(action, "prepared") as (snapshots, index, prepared, stored, _, recovery_env):
                    lock_path = snapshots / ".index.lock"
                    lock_path.touch()
                    os.chown(lock_path, account.pw_uid, account.pw_gid)
                    original = index.read_bytes(), prepared.read_bytes(), stored.exists()
                    with lock_path.open("r+b") as lock:
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        result = command([cli, "snapshot", *args], recovery_env, ordinary, timeout=12)
                    unchanged = original == (index.read_bytes(), prepared.read_bytes(), stored.exists())
                    checks.append(dict(phase=phase, case=f"{action}-held-lock-{operation}",
                                       passed=result.returncode != 0 and "mutation is running" in result.stderr
                                       and unchanged, status=result.returncode,
                                       diagnostic=(result.stdout[-600:], result.stderr[-700:])))

        with arrange("create", "prepared") as (snapshots, index, prepared, stored, target, recovery_env):
            write(stored, dict(target, message="different complete snapshot"))
            original = index.read_bytes(), prepared.read_bytes(), stored.read_bytes()
            result = command([cli, "snapshot", "list"], recovery_env, ordinary, timeout=12)
            unchanged = original == (index.read_bytes(), prepared.read_bytes(), stored.read_bytes())
            checks.append(dict(phase=phase, case="create-conflict-preserves-both-files",
                               passed=result.returncode != 0 and "conflict" in result.stderr.lower() and unchanged,
                               status=result.returncode, diagnostic=(result.stdout[-600:], result.stderr[-700:])))

        with arrange("create", "prepared") as (snapshots, index, prepared, _, _, recovery_env):
            deletion = snapshots / ".delete.pending"
            write(deletion, {"id": "keep"})
            original = index.read_bytes(), prepared.read_bytes(), deletion.read_bytes()
            result = command([cli, "snapshot", "list"], recovery_env, ordinary, timeout=12)
            unchanged = original == (index.read_bytes(), prepared.read_bytes(), deletion.read_bytes())
            checks.append(dict(phase=phase, case="ambiguous-recovery-preserves-both-records",
                               passed=result.returncode != 0 and "multiple pending" in result.stderr.lower() and unchanged,
                               status=result.returncode, diagnostic=(result.stdout[-600:], result.stderr[-700:])))

        for operation, args in (("restore", ["restore", "index", "--dry-run"]),
                                ("delete", ["delete", "index"])):
            with arrange("create", "finished") as (_, index, _, stored, _, recovery_env):
                original = index.read_bytes(), stored.read_bytes()
                result = command([cli, "snapshot", *args], recovery_env, ordinary, timeout=12)
                checks.append(dict(phase=phase, case=f"reserved-id-{operation}",
                                   passed=result.returncode != 0 and "Invalid snapshot ID" in result.stderr
                                   and original == (index.read_bytes(), stored.read_bytes()),
                                   status=result.returncode, diagnostic=(result.stdout[-600:],
                                                                        result.stderr[-700:])))

        assert sorted(set(ordinary_control(query).splitlines())) == expected


    def inspect_privacy_commands():
        phase = "fedora-privacy"

        @contextmanager
        def arrange():
            with tempfile.TemporaryDirectory(prefix="privacy-", dir=work) as directory:
                home = Path(directory)
                parent = home / "data"
                settings = home / "config"
                for path in (home, parent, settings):
                    path.mkdir(exist_ok=True)
                    os.chown(path, account.pw_uid, account.pw_gid)
                    path.chmod(0o700)
                selected = dict(disabled, HOME=str(home), OMG_DATA_DIR=str(parent), OMG_CONFIG_DIR=str(settings),
                                XDG_CONFIG_HOME=str(home/"xdg-config"), XDG_DATA_HOME=str(home/"xdg-data"),
                                XDG_STATE_HOME=str(home/"state"), XDG_CACHE_HOME=str(home/"cache"),
                                CI="1", OMG_NO_UPDATE_CHECK="1")
                yield home, parent, settings / "config.toml", selected

        def write(path, value, mode=0o600):
            if not path.parent.is_dir():
                path.parent.mkdir(parents=True)
                os.chown(path.parent, account.pw_uid, account.pw_gid)
            path.write_bytes(value)
            os.chown(path, account.pw_uid, account.pw_gid)
            path.chmod(mode)

        def run(label, args, chosen, verify, *, surface="privacy"):
            result = command([cli, surface, *args], chosen, ordinary, timeout=12)
            checks.append(dict(phase=phase, case=label, passed=verify(result),
                               status=result.returncode, diagnostic=(result.stdout[-850:],
                                                                      result.stderr[-850:])))

        def success(result, text):
            return result.returncode == 0 and text in result.stdout

        def refused(result, text):
            return result.returncode == 1 and text.lower() in result.stderr.lower() and "Data exported to" not in result.stdout

        def valid_export(path, expected):
            if not path.is_file() or stat.S_IMODE(path.stat().st_mode) != 0o600:
                return False
            value = json.loads(path.read_bytes())
            return (set(value) == {"exported_at", "local", "scope"} and value["scope"] == "local"
                    and bool(value["exported_at"]) and value["local"] == expected)

        with arrange() as (home, data, config, chosen):
            run("status-empty", ["status"], chosen, lambda result: success(result, "Telemetry: Disabled")
                and not config.exists())
            run("status-default-subcommand", [], chosen, lambda result: success(result, "OMG Privacy Settings")
                and "Telemetry: Disabled" in result.stdout and not config.exists())
            path = home / "empty.json"
            run("export-empty", ["export", "--output", path], chosen,
                lambda result: success(result, "Data exported to") and valid_export(path, {}))
            run("export-default-name", ["export"], chosen,
                lambda result: success(result, "Data exported to")
                and len(paths := list(home.glob("omg-data-export-????-??-??.json"))) == 1
                and valid_export(paths[0], {}))

            archive = '{"id":"older"}\n{"id":"newer"}\n'
            clock_fixture = str(int(time.time()) + 3600)
            for file, value in (
                (data/"usage.json", b'{"total_commands":7}'),
                (data/"telemetry_queue.json", b'{"format_version":1,"events":[]}'),
                (data/"telemetry_session.json", b'{"session_id":"local-session"}'),
                (data/"history.json", b'[{"id":"latest"}]'),
                (data/"completion-cache.json", b'{"packages":["git"]}'),
                (data/".installed", b'{"install_id":"local-identifier"}'),
                (data/"history.json.archive.jsonl", archive.encode()),
                (data/"machine-id", b"machine-fixture"),
                (data/"license-clock.highwater", clock_fixture.encode()),
                (data/"license.json", b'{"key":"inert-key","tier":"pro","features":["sbom"],'
                 b'"customer":"fixture@example.invalid","expires_at":null,"validated_at":1700000000,'
                 b'"token":"inert-token","machine_id":"fixture-machine"}'),
                (data/"audit/audit.jsonl", b'current audit\n'),
                (data/"audit/audit.jsonl.1", b'archived audit\n'),
                (data/"audit/notes.txt", b'ordinary note\n'),
                (data/"sbom/a.json", b'{"name":"sbom-a"}'),
                (data/"sbom/z.json", b'{"name":"sbom-z"}'),
                (data/"snapshots/index.json", b'{"snapshots":[]}'),
                (data/"snapshots/one.json", b'{"id":"one"}'),
                (data/"snapshots/.create.pending", b'{"id":"prepared"}'),
                (config, b'telemetry_enabled = false\n'),
            ):
                write(file, value)
            expected = {
                "usage.json": {"total_commands": 7},
                "telemetry_queue.json": {"format_version": 1, "events": []},
                "telemetry_session.json": {"session_id": "local-session"},
                "history.json": [{"id": "latest"}],
                "completion-cache.json": {"packages": ["git"]},
                ".installed": {"install_id": "local-identifier"},
                "history.json.archive.jsonl": archive,
                "machine-id": "machine-fixture",
                "license-clock.highwater": clock_fixture,
                "license.json": {"tier": "pro", "features": ["sbom"], "customer": "fixture@example.invalid",
                                 "expires_at": None, "validated_at": 1700000000, "machine_id": "fixture-machine"},
                "audit": {"audit.jsonl": "current audit\n", "audit.jsonl.1": "archived audit\n"},
                "sbom": {"a.json": {"name": "sbom-a"}, "z.json": {"name": "sbom-z"}},
                "snapshots": {"index.json": {"snapshots": []}, "one.json": {"id": "one"}},
                "config.toml": "telemetry_enabled = false\n",
            }
            before = {file: file.read_bytes() for file in data.rglob("*") if file.is_file()}
            full = home / "local report.json"
            run("export-all-durable-categories", ["export", "--output", full], chosen,
                lambda result: success(result, str(full)) and valid_export(full, expected))
            run("export-relative-path", ["export", "--output", "relative.json"], chosen,
                lambda result: success(result, "relative.json") and valid_export(home/"relative.json", expected))
            permissive = home / "replace.json"
            write(permissive, b"old export", 0o644)
            inode = permissive.stat().st_ino
            run("export-replaces-permissive-file", ["export", "--output", permissive], chosen,
                lambda result: success(result, str(permissive)) and valid_export(permissive, expected)
                and permissive.stat().st_ino != inode)
            shared = home / "other name.txt"
            linked = home / "linked export.json"
            write(shared, b"previous local data", 0o644)
            os.link(shared, linked)
            run("export-replaces-only-output-inode", ["export", "--output", linked], chosen,
                lambda result: success(result, str(linked)) and valid_export(linked, expected)
                and shared.read_bytes() == b"previous local data"
                and stat.S_IMODE(shared.stat().st_mode) == 0o644
                and shared.stat().st_ino != linked.stat().st_ino)
            assert all(file.read_bytes() == value for file, value in before.items())
            as_directory = home / "output-directory"
            as_directory.mkdir()
            run("export-folder-destination", ["export", "--output", as_directory], chosen,
                lambda result: refused(result, "Failed to replace") and as_directory.is_dir())

        for label, relative, contents, error in (
            ("invalid-source-json", "usage.json", b'{', "Failed to parse"),
            ("invalid-license-json", "license.json", b'{"tier":null}', "Failed to parse"),
            ("invalid-audit-text", "audit/audit.jsonl", b'\xff\n', "valid UTF-8"),
            ("source-directory-in-file-slot", "history.json", None, "regular file"),
            ("source-file-in-directory-slot", "snapshots", b'{}', "regular directory"),
        ):
            with arrange() as (home, data, config, chosen):
                source = data / relative
                if contents is None:
                    source.mkdir()
                else:
                    write(source, contents)
                output = home / "prior.json"
                write(output, b"prior export", 0o644)
                original = output.stat().st_ino
                run(label, ["export", "--output", output], chosen,
                    lambda result: refused(result, error) and output.read_bytes() == b"prior export"
                    and output.stat().st_ino == original and stat.S_IMODE(output.stat().st_mode) == 0o644)

        with arrange() as (home, data, config, chosen):
            oversized = data / "usage.json"
            write(oversized, b'{}')
            with oversized.open("r+b") as stream:
                stream.truncate(64 * 1024 * 1024 + 1)
            output = home / "prior.json"
            write(output, b"prior export")
            run("individual-source-limit", ["export", "--output", output], chosen,
                lambda result: refused(result, "byte limit") and output.read_bytes() == b"prior export")
            oversized.unlink()
            for name in ("usage.json", "history.json", "completion-cache.json"):
                source = data / name
                write(source, b'{}')
                with source.open("ab") as stream:
                    for _ in range(44):
                        stream.write(b" " * (1024 * 1024))
            run("combined-source-limit", ["export", "--output", output], chosen,
                lambda result: refused(result, "combined source byte limit") and output.read_bytes() == b"prior export")

        with arrange() as (home, data, config, chosen):
            queue = data / "telemetry_queue.json"
            queued = b'{"format_version":1,"events":[]}'
            write(config, b"telemetry_enabled = true\n# preserved preference\n")
            write(queue, queued)
            run("opt-out-clears-queue", ["opt-out"], chosen,
                lambda result: success(result, "Telemetry disabled locally") and not queue.exists()
                and tomllib.loads(config.read_text())["telemetry_enabled"] is False
                and "# preserved preference" in config.read_text())
            run("status-after-opt-out", ["status"], chosen, lambda result: success(result, "Telemetry: Disabled"))
            run("opt-out-idempotent", ["opt-out"], chosen,
                lambda result: success(result, "Telemetry disabled locally") and not queue.exists()
                and tomllib.loads(config.read_text())["telemetry_enabled"] is False)
            write(queue, queued)
            run("opt-in-purges-leftover-disabled-queue", ["opt-in"], chosen,
                lambda result: success(result, "environment override keeps telemetry disabled")
                and not queue.exists() and tomllib.loads(config.read_text())["telemetry_enabled"] is True)
            write(queue, queued)
            run("repeated-opt-in-keeps-consented-queue", ["opt-in"], chosen,
                lambda result: success(result, "environment override keeps telemetry disabled")
                and queue.read_bytes() == queued and tomllib.loads(config.read_text())["telemetry_enabled"] is True)
            run("status-disable-override", ["status"], chosen, lambda result: success(result, "Telemetry: Disabled"))
            chosen = {key: value for key, value in chosen.items() if key != "OMG_DISABLE_TELEMETRY"}
            for label, override in (
                ("off", {"OMG_TELEMETRY": "OFF"}),
                ("no", {"OMG_TELEMETRY": "no"}),
                ("yes-disable", {"OMG_DISABLE_TELEMETRY": "YES"}),
            ):
                overlay = dict(chosen, **override)
                run(f"status-{label}", ["status"], overlay,
                    lambda result: success(result, "Telemetry: Disabled"))
                run(f"opt-in-{label}", ["opt-in"], overlay,
                    lambda result: success(result, "environment override keeps telemetry disabled")
                    and tomllib.loads(config.read_text())["telemetry_enabled"] is True)
            run("status-enabled-without-override", ["status"], chosen,
                lambda result: success(result, "Telemetry: Enabled"))

        with arrange() as (home, data, config, chosen):
            queue = data / "telemetry_queue.json"
            queue.mkdir()
            write(config, b"telemetry_enabled = true\n")
            run("opt-out-purge-failure-persists-disabled", ["opt-out"], chosen,
                lambda result: refused(result, "Failed to purge queued telemetry")
                and tomllib.loads(config.read_text())["telemetry_enabled"] is False and queue.is_dir())
            run("opt-in-blocked-by-unpurged-queue", ["opt-in"], chosen,
                lambda result: refused(result, "Failed to purge queued telemetry")
                and tomllib.loads(config.read_text())["telemetry_enabled"] is False and queue.is_dir())
            queue.rmdir()
            run("opt-in-after-purge-obstruction-removed", ["opt-in"], chosen,
                lambda result: success(result, "environment override keeps telemetry disabled")
                and tomllib.loads(config.read_text())["telemetry_enabled"] is True)
            write(config, b"telemetry_enabled = [")
            for operation in ("status", "opt-in", "opt-out"):
                run(f"corrupt-config-{operation}", [operation], chosen,
                    lambda result: refused(result, "Failed to load OMG settings")
                    and config.read_bytes() == b"telemetry_enabled = [")


        with arrange() as (home, data, config, chosen):
            queue = data / "telemetry_queue.json"
            queue.mkdir()
            write(config, b"telemetry_enabled = false\n")
            run("config-opt-in-blocked-by-unpurged-queue", ["set", "telemetry.enabled", "true"], chosen,
                lambda result: refused(result, "Failed to purge queued telemetry")
                and tomllib.loads(config.read_text())["telemetry_enabled"] is False, surface="config")
            queue.rmdir()
            write(queue, b'{"format_version":1,"events":[]}')
            write(config, b"telemetry_enabled = false\n")
            run("config-opt-in-clears-disabled-queue", ["set", "telemetry.enabled", "true"], chosen,
                lambda result: success(result, "Set telemetry.enabled = true") and not queue.exists()
                and tomllib.loads(config.read_text())["telemetry_enabled"] is True, surface="config")
            write(queue, b'{"format_version":1,"events":[]}')
            run("config-opt-out-purges-queue", ["set", "telemetry.enabled", "false"], chosen,
                lambda result: success(result, "Set telemetry.enabled = false") and not queue.exists()
                and tomllib.loads(config.read_text())["telemetry_enabled"] is False, surface="config")


    def inspect_telemetry_storage():
        phase = "fedora-telemetry-storage"

        @contextmanager
        def telemetry_fixture():
            with tempfile.TemporaryDirectory(prefix="telemetry-", dir=work) as directory:
                home = Path(directory)
                data, config = home / "data", home / "config"
                for path in (home, data, config):
                    path.mkdir(exist_ok=True)
                    path.chmod(0o700)
                    os.chown(path, account.pw_uid, account.pw_gid)
                chosen = {key: value for key, value in disabled.items()
                          if key != "OMG_DISABLE_TELEMETRY"}
                chosen.update(HOME=str(home), OMG_DATA_DIR=str(data), OMG_CONFIG_DIR=str(config),
                              XDG_CONFIG_HOME=str(home/"xdg-config"), XDG_DATA_HOME=str(home/"xdg-data"),
                              XDG_STATE_HOME=str(home/"state"), XDG_CACHE_HOME=str(home/"cache"),
                              CI="1", OMG_NO_UPDATE_CHECK="1", RUST_LOG="warn")
                settings = config / "config.toml"
                lock = config / "config.lock"
                for path, contents in ((settings, b"telemetry_enabled = true\n"),
                                       (data/".installed", b"{}"), (lock, b"")):
                    write(path, contents)
                yield data, settings, lock, chosen

        def write(path, contents):
            path.write_bytes(contents)
            path.chmod(0o600)
            os.chown(path, account.pw_uid, account.pw_gid)

        def invoke(case, args, chosen, expected_code, verify):
            result = command([cli, "privacy", *args], chosen, ordinary, timeout=12)
            checks.append(dict(phase=phase, case=case, passed=result.returncode == expected_code and verify(result),
                               status=result.returncode, diagnostic=(result.stdout[-650:], result.stderr[-1100:])))

        def enabled(result):
            return "Telemetry: Enabled" in result.stdout

        def prior(path):
            return hashlib.sha256(path.read_bytes()).digest() if path.is_file() else None

        for kind in ("queue", "session"):
            for stage in ("missing", "current", "malformed", "future", "oversized", "overfull"):
                for locked in (False, True):
                    with telemetry_fixture() as (data, settings, lock, chosen):
                        queue = data / "telemetry_queue.json"
                        session = data / "telemetry_session.json"
                        focus = queue if kind == "queue" else session
                        payload = ({"format_version": 1, "events": []} if kind == "queue" else
                                   {"format_version": 1, "session_id": "fixture-session",
                                    "started_at": "2026-10-01T01:02:03Z", "commands_run": 7,
                                    "last_activity": int(time.time())})
                        if stage == "future":
                            payload["format_version"] = 999
                        if stage == "overfull":
                            if kind == "queue":
                                payload["events"] = [
                                    dict(type="performance", metric_type="fixture-event", duration_ms=n)
                                    for n in range(6000)
                                ]
                            else:
                                payload["last_activity"] = -(2**63)
                        if stage != "missing":
                            write(focus, b"{" if stage == "malformed" else json.dumps(payload).encode())
                        if stage == "oversized":
                            budget = 8 * 1024 * 1024 if kind == "queue" else 64 * 1024
                            with focus.open("ab") as stream:
                                for _ in range(budget // (64 * 1024) + 1):
                                    stream.write(b" " * (64 * 1024))
                        old_queue, old_session = prior(queue), prior(session)
                        file_before = prior(focus)

                        def verify(result):
                            if not enabled(result):
                                return False
                            if locked and (prior(queue), prior(session)) != (old_queue, old_session):
                                return False
                            if stage in ("malformed", "future", "oversized"):
                                expected = {"malformed": f"Malformed telemetry {kind}",
                                            "future": f"Unsupported telemetry {kind} format",
                                            "oversized": "byte limit"}[stage]
                                return expected in result.stderr and prior(focus) == file_before
                            if "panicked" in result.stderr:
                                return False
                            if not locked and stage == "overfull":
                                if kind == "queue":
                                    events = json.loads(queue.read_bytes())["events"]
                                    retained = [row["duration_ms"] for row in events
                                                if row.get("metric_type") == "fixture-event"]
                                    return len(events) <= 5000 and 5999 in retained and 0 not in retained
                                saved = json.loads(session.read_bytes())
                                return saved["session_id"] != "fixture-session" and saved["last_activity"] > 0
                            return True

                        with lock.open("r+b") as writer:
                            if locked:
                                fcntl.flock(writer, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            policy = "writer-held" if locked else "no-writer"
                            invoke(f"{kind}-{stage}-{policy}", ["status"], chosen, 0, verify)

        with telemetry_fixture() as (data, settings, lock, chosen):
            queue = data / "telemetry_queue.json"
            original = b'{"format_version":1,"events":[]}'
            write(queue, original)
            with lock.open("r+b") as reader:
                fcntl.flock(reader, fcntl.LOCK_SH | fcntl.LOCK_NB)
                invoke("opt-out-respects-live-consent-lease", ["opt-out"], dict(chosen, OMG_TELEMETRY="0"), 1,
                       lambda result: "retry" in result.stderr
                       and tomllib.loads(settings.read_text())["telemetry_enabled"] is True)
                invoke("status-override-during-lease", ["status"], dict(chosen, OMG_TELEMETRY="0"), 0,
                       lambda result: "Telemetry: Disabled" in result.stdout and queue.read_bytes() == original)
            invoke("opt-out-after-lease-release", ["opt-out"], chosen, 0,
                   lambda result: "Telemetry disabled locally" in result.stdout and not queue.exists()
                   and tomllib.loads(settings.read_text())["telemetry_enabled"] is False)
            invoke("status-disabled-after-release", ["status"], chosen, 0,
                   lambda result: "Telemetry: Disabled" in result.stdout and not queue.exists())
            invoke("opt-in-after-lease-release", ["opt-in"], dict(chosen, OMG_TELEMETRY="0"), 0,
                   lambda result: "environment override keeps telemetry disabled" in result.stdout
                   and tomllib.loads(settings.read_text())["telemetry_enabled"] is True)
            invoke("status-enabled-after-release", ["status"], chosen, 0, enabled)


    def inspect_telemetry_queue_overlap():
        phase = "fedora-telemetry-queue-overlap"

        def write(path, data, mode=0o600):
            path.write_bytes(data)
            path.chmod(mode)
            os.chown(path, account.pw_uid, account.pw_gid)

        for initial in (0, 1, 2):
            for first in ("left", "right"):
                for existing_ids in (False, True):
                    with tempfile.TemporaryDirectory(prefix="queue-overlap-", dir=work) as directory:
                        home = Path(directory)
                        data, config = home/"data", home/"config"
                        for path in (home, data, config):
                            path.mkdir(exist_ok=True)
                            path.chmod(0o700)
                            os.chown(path, account.pw_uid, account.pw_gid)
                        write(config/"config.toml", b"telemetry_enabled = true\n")
                        write(data/".installed", b"{}")
                        seed = [{"type":"performance","metric_type":"existing-fixture","duration_ms":7}
                                for _ in range(initial)]
                        if existing_ids:
                            for index, row in enumerate(seed):
                                row["queue_id"] = f"01234567-89ab-4cde-8f01-{index:012d}"
                        queue = data/"telemetry_queue.json"
                        write(queue, json.dumps({"format_version":1,"events":seed}).encode())
                        write(data/"telemetry_session.json", json.dumps({
                            "format_version":1,"session_id":"shared-fixture-session",
                            "started_at":"2026-10-01T01:02:03Z","commands_run":0,
                            "last_activity":int(time.time())}).encode())
                        write(home/"Makefile", b"""left right:
	@touch ready-$@
	@i=0; while [ ! -f release-$@ ] && [ $$i -lt 300 ]; do i=$$((i+1)); sleep 0.02; done
	@test -f release-$@
	@printf '%s finished\\n' $@
""")
                        chosen = {name:value for name,value in disabled.items() if name != "OMG_DISABLE_TELEMETRY"}
                        chosen.update(HOME=str(home), OMG_DATA_DIR=str(data), OMG_CONFIG_DIR=str(config),
                                      XDG_CONFIG_HOME=str(home/"xdg-config"), XDG_DATA_HOME=str(home/"xdg-data"),
                                      XDG_STATE_HOME=str(home/"state"), XDG_CACHE_HOME=str(home/"cache"),
                                      CI="1", OMG_NO_UPDATE_CHECK="1")
                        children = {}
                        try:
                            for key in ("left","right"):
                                children[key] = subprocess.Popen([str(cli),"run",key], cwd=home, env=chosen,
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, **ordinary)

                            deadline = time.monotonic() + 12
                            while not all((home/f"ready-{key}").is_file() for key in children):
                                assert all(child.poll() is None for child in children.values()), {
                                    key: child.communicate() if child.poll() is not None else None
                                    for key, child in children.items()}
                                assert time.monotonic() < deadline, "both telemetry commands must reach the task barrier"
                                time.sleep(0.02)
                            second = "right" if first == "left" else "left"
                            for consumed, key in enumerate((first,second), 1):
                                (home/f"release-{key}").touch()
                                status_text, warnings = children[key].communicate(timeout=12)
                                value = json.loads(queue.read_bytes())
                                events = value["events"]
                                commands = [event for event in events if event["type"] == "command"]
                                retained = [event for event in events if event.get("metric_type")=="existing-fixture"]
                                identity = [event.get("queue_id") for event in events]
                                native = (len(commands) == consumed and all(event["command"] == "run" for event in commands)
                                          and len(retained)==initial and all(row["duration_ms"] == 7 for row in retained))
                                stable = (all(isinstance(value, str) and len(value)==36 for value in identity)
                                          and len(set(identity))==len(identity)
                                          and (not existing_ids or {row["queue_id"] for row in seed} <= set(identity)))
                                checks.append(dict(phase=phase,
                                    case=f"seed-{initial}-{first}-ids-{existing_ids}-{consumed}",
                                    passed=children[key].returncode==0 and f"{key} finished" in status_text
                                    and value["format_version"]==1 and native and stable,
                                    status=children[key].returncode, diagnostic=(status_text[-430:], warnings[-500:],
                                        len(commands),len(retained),len(events),sum(value is not None for value in identity))))
                        finally:
                            for child in children.values():
                                if child.poll() is None:
                                    child.kill()
                                child.wait()

        for initial in range(6):
            with tempfile.TemporaryDirectory(prefix="queue-control-", dir=work) as directory:
                home = Path(directory)
                os.chown(home, account.pw_uid, account.pw_gid)
                queue = home/"telemetry_queue.json"
                rows = [{"type":"performance","metric_type":"disabled-control","duration_ms":index}
                        for index in range(initial)]
                original = json.dumps({"format_version":1,"events":rows}).encode()
                write(queue, original)
                chosen = dict(disabled, HOME=str(home), OMG_DATA_DIR=str(home), OMG_CONFIG_DIR=str(home/"config"))
                result = command([cli,"privacy","status"], chosen, ordinary, timeout=12)
                checks.append(dict(phase=phase, case=f"disabled-{initial}",
                    passed=result.returncode==0 and "Telemetry: Disabled" in result.stdout
                    and queue.read_bytes()==original, status=result.returncode,
                    diagnostic=(result.stdout[-430:], result.stderr[-500:])))


    def inspect_telemetry_consent_transitions():
        phase = "fedora-telemetry-consent-transition"
        opt_out = ("privacy", "opt-out")
        opt_in = ("privacy", "opt-in")
        config_off = ("config", "set", "telemetry.enabled", "false")
        config_on = ("config", "set", "telemetry.enabled", "true")
        unrelated = ("config", "set", "aur.build_concurrency", "2")

        for label, mutations, revoked, separate_data in (
            ("privacy", (opt_out, opt_in), True, False),
            ("config", (config_off, config_on), True, False),
            ("privacy-then-config", (opt_out, config_on), True, True),
            ("config-then-privacy", (config_off, opt_in), True, True),
            ("repeated-opt-in", (opt_in, config_on), False, False),
            ("unrelated-setting", (unrelated, opt_in), False, False),
        ):
            with tempfile.TemporaryDirectory(prefix="consent-transition-", dir=work) as directory:
                home = Path(directory)
                data, config = home/"data", home/"config"
                preference_data = home/"preference-data" if separate_data else data
                for path in (home, data, config, preference_data):
                    path.mkdir(exist_ok=True)
                    path.chmod(0o700)
                    os.chown(path, account.pw_uid, account.pw_gid)

                def write(path, value):
                    path.write_text(value)
                    path.chmod(0o600)
                    os.chown(path, account.pw_uid, account.pw_gid)

                session = data/"telemetry_session.json"
                old_session = "before-consent-transition"
                write(config/"config.toml", "telemetry_enabled = true\n")
                write(data/".installed", "{}")
                write(session, json.dumps({
                    "format_version":1,"session_id":old_session,"started_at":"2026-10-01T01:02:03Z",
                    "commands_run":40,"last_activity":int(time.time())}))
                write(home/"Makefile", """held:
\t@touch ready
\t@i=0; while [ ! -f release ] && [ $$i -lt 350 ]; do i=$$((i+1)); sleep 0.02; done
\t@test -f release
\t@printf 'held command finished\\n'
fresh:
\t@printf 'fresh command finished\\n'
""")
                queue = data/"telemetry_queue.json"
                prior = {"type":"performance","metric_type":"old-consent-fixture","duration_ms":4}
                write(queue, json.dumps({"format_version":1,"events":[prior]}))
                original_session = session.read_bytes()
                chosen = {name:value for name,value in disabled.items() if name != "OMG_DISABLE_TELEMETRY"}
                chosen.update(HOME=str(home), OMG_DATA_DIR=str(data), OMG_CONFIG_DIR=str(config),
                              XDG_CONFIG_HOME=str(home/"xdg-config"), XDG_DATA_HOME=str(home/"xdg-data"),
                              XDG_STATE_HOME=str(home/"state"), XDG_CACHE_HOME=str(home/"cache"),
                              CI="1", OMG_NO_UPDATE_CHECK="1")
                silent = dict(chosen, OMG_DISABLE_TELEMETRY="1", OMG_DATA_DIR=str(preference_data))

                def record(case, status, passed, *diagnostic):
                    checks.append(dict(phase=phase, case=f"{label}-{case}", passed=status == 0 and bool(passed),
                                       status=status, diagnostic=diagnostic))

                child = subprocess.Popen([str(cli), "run", "held"], cwd=home, env=chosen,
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, **ordinary)
                try:
                    deadline = time.monotonic() + 12
                    while not (home/"ready").is_file():
                        assert child.poll() is None, child.communicate()
                        assert time.monotonic() < deadline, "command must reach the consent barrier"
                        time.sleep(0.02)

                    for index, args in enumerate(mutations):
                        result = command([cli, *args], silent, ordinary, timeout=8)
                        enabled = tomllib.loads((config/"config.toml").read_text())["telemetry_enabled"]
                        record(f"change-{index+1}", result.returncode,
                               enabled is (not revoked or index==1),
                               result.stdout[-400:], result.stderr[-400:], enabled)

                    result = command([cli, "config", "get", "telemetry.enabled"], silent, ordinary, timeout=8)
                    record("inspect-opt-in", result.returncode, result.stdout.strip()=="true",
                           result.stdout[-400:], result.stderr[-400:])

                    (home/"release").touch()
                    output, errors = child.communicate(timeout=12)
                    held = json.loads(queue.read_text())["events"] if queue.is_file() else []
                    held_runs = sum(row.get("command")=="run" for row in held)
                    held_ids = [row["session_id"] for row in held if row["type"]=="session"]
                    stopped = (held == [prior] and session.read_bytes() == original_session) if separate_data else not held and not session.exists()
                    record("finish-held", child.returncode,
                           "held command finished" in output
                           and (stopped if revoked
                                else held_runs==1 and held_ids and set(held_ids)=={old_session}),
                           output[-400:], errors[-400:], held_runs, held_ids, session.exists())

                    result = subprocess.run([str(cli), "run", "fresh"], cwd=home, env=chosen, timeout=12,
                        stdin=subprocess.DEVNULL, capture_output=True, text=True, **ordinary)
                    fresh = json.loads(queue.read_text())["events"] if queue.is_file() else []
                    fresh_runs = sum(row.get("command")=="run" for row in fresh)
                    fresh_ids = [row["session_id"] for row in fresh if row["type"]=="session"]
                    counters = [row["commands_run"] for row in fresh
                                if row["type"]=="session" and row["event_type"]=="end"]
                    old_metrics = [row for row in fresh if row.get("metric_type")=="old-consent-fixture"]
                    record("finish-fresh", result.returncode,
                           "fresh command finished" in result.stdout and fresh_ids
                           and ((fresh_runs==1 and old_session not in fresh_ids and counters==[1] and not old_metrics) if revoked
                                else fresh_runs==2 and old_session in fresh_ids and counters and counters[0]==41 and old_metrics),
                           result.stdout[-400:], result.stderr[-400:], fresh_runs, fresh_ids, counters)
                finally:
                    if child.poll() is None:
                        child.kill()
                    child.wait()


    def inspect_install_telemetry_admission():
        phase = "fedora-install-telemetry"
        operations = (
            ("privacy", "status"),
            ("config", "get", "telemetry.enabled"),
            ("run", "probe"),
            ("config", "list"),
            ("privacy", "status"),
        )

        for scenario in ("first-use", "settings-held", "install-held", "default-off",
                         "environment-off", "explicit-opt-out"):
            with tempfile.TemporaryDirectory(prefix="install-telemetry-", dir=work) as directory:
                home = Path(directory)
                data, config = home/"data", home/"config"
                for path in (home, data, config):
                    path.mkdir(exist_ok=True)
                    path.chmod(0o700)
                    os.chown(path, account.pw_uid, account.pw_gid)

                def write(path, value):
                    path.write_text(value)
                    path.chmod(0o600)
                    os.chown(path, account.pw_uid, account.pw_gid)

                write(home/"Makefile", "probe:\n\t@printf 'install telemetry probe finished\\n'\n")
                marker = data/".installed"
                flag = "false" if scenario=="default-off" else "true"
                write(config/"config.toml", f"telemetry_enabled = {flag}\n")
                held_path = data/".installed.lock" if scenario=="install-held" else config/"config.lock"
                write(held_path, "")
                chosen = {name:value for name,value in disabled.items() if name != "OMG_DISABLE_TELEMETRY"}
                chosen.update(HOME=str(home), OMG_DATA_DIR=str(data), OMG_CONFIG_DIR=str(config),
                              XDG_CONFIG_HOME=str(home/"xdg-config"), XDG_DATA_HOME=str(home/"xdg-data"),
                              XDG_STATE_HOME=str(home/"state"), XDG_CACHE_HOME=str(home/"cache"),
                              CI="1", OMG_NO_UPDATE_CHECK="1", RUST_LOG="omg_lib::core::telemetry=debug")
                if scenario=="environment-off":
                    chosen["OMG_DISABLE_TELEMETRY"] = "1"

                pending = ("settings-held", "install-held")
                expect_creation = 2 if scenario in pending else 0 if scenario=="first-use" else None
                original = None
                with held_path.open("r+b") as lock:
                    if scenario in pending:
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    for index, args in enumerate(operations):
                        if scenario in pending and index==2:
                            fcntl.flock(lock, fcntl.LOCK_UN)
                        if scenario=="explicit-opt-out" and index==0:
                            args = ("privacy", "opt-out")
                        result = command([cli, *args], chosen, ordinary, timeout=12)
                        ran = ("Telemetry disabled locally" in result.stdout if args==("privacy", "opt-out")
                               else result.stdout.strip() == ("false" if scenario in ("default-off", "explicit-opt-out") else "true")
                               if args[0:2]==("config", "get")
                               else "install telemetry probe finished" in result.stdout if args[0]=="run"
                               else bool(result.stdout))
                        contents = marker.read_bytes() if marker.is_file() else None
                        dispatches = result.stderr.count("Install telemetry ping ")
                        if index==expect_creation and contents:
                            original = contents
                            document = json.loads(contents)
                            valid = (uuid.UUID(document["install_id"]).version==4
                                     and bool(document["timestamp"]) and bool(document["version"]))
                        else:
                            valid = True
                        expected = expect_creation is not None and index>=expect_creation
                        gate = (valid and contents is not None and contents==original
                                if expected else contents is None)
                        actual_flag = tomllib.loads((config/"config.toml").read_text())["telemetry_enabled"]
                        checks.append(dict(phase=phase, case=f"{scenario}-{index+1}",
                            passed=bool(result.returncode==0 and ran and gate and
                                         dispatches==int(index==expect_creation) and
                                         actual_flag is (scenario not in ("default-off", "explicit-opt-out"))),
                            status=result.returncode, diagnostic=(result.stdout[-420:],result.stderr[-550:],
                                                                 contents is not None,dispatches,actual_flag)))


    def inspect_usage_dispatch_admission():
        phase = "fedora-usage-dispatch"
        operations = (
            ("privacy", "status"), ("config", "get", "telemetry.enabled"),
            ("run", "probe"), ("config", "list"), ("privacy", "status"),
        )
        for scenario, enabled, env_override, held, license_contents, warnings in (
            ("local-off", False, False, False, b"{", 0),
            ("environment-off", True, True, False, b"{", 0),
            ("settings-held", True, False, True, b"{", 0),
            ("enabled-malformed", True, False, False, b"{", 2),
            ("enabled-unlinked", True, False, False, None, 0),
            ("off-unlinked", False, False, False, None, 0),
        ):
            with tempfile.TemporaryDirectory(prefix="usage-dispatch-", dir=work) as directory:
                home = Path(directory)
                data, config = home/"data", home/"config"
                for path in (home, data, config):
                    path.mkdir(exist_ok=True)
                    path.chmod(0o700)
                    os.chown(path, account.pw_uid, account.pw_gid)

                def write(path, value):
                    path.write_bytes(value)
                    path.chmod(0o600)
                    os.chown(path, account.pw_uid, account.pw_gid)

                write(config/"config.toml", f"telemetry_enabled = {str(enabled).lower()}\n".encode())
                write(config/"config.lock", b"")
                write(data/".installed", b"{}")
                write(home/"Makefile", b"probe:\n\t@printf 'usage dispatch probe finished\\n'\n")
                license_path = data/"license.json"
                if license_contents is not None:
                    write(license_path, license_contents)

                stats = data/"usage.json"
                usage = json.dumps({
                    "total_commands":7, "commands":{"search":7}, "time_saved_ms":889,
                    "queries_today":7, "queries_this_month":7, "last_query_date":"2026-11-25",
                    "last_month":"2026-11", "achievements":["FirstStep"],
                })
                write(stats, usage.encode())
                prior = json.dumps({"format_version":1,"events":[
                    {"type":"performance","metric_type":"usage-dispatch-fixture","duration_ms":n}
                    for n in range(12)]}).encode()
                queue = data/"telemetry_queue.json"
                write(queue, prior)
                chosen = {name:value for name,value in disabled.items() if name != "OMG_DISABLE_TELEMETRY"}
                chosen.update(HOME=str(home), OMG_DATA_DIR=str(data), OMG_CONFIG_DIR=str(config),
                              XDG_CONFIG_HOME=str(home/"xdg-config"), XDG_DATA_HOME=str(home/"xdg-data"),
                              XDG_STATE_HOME=str(home/"state"), XDG_CACHE_HOME=str(home/"cache"),
                              CI="1", OMG_NO_UPDATE_CHECK="1", RUST_LOG="warn")
                if env_override:
                    chosen["OMG_DISABLE_TELEMETRY"]="1"
                effective = enabled and not env_override
                with (config/"config.lock").open("r+b") as lock:
                    if held:
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    for index, args in enumerate(operations, 1):
                        queue.write_bytes(prior)
                        result = command([cli, *args], chosen, ordinary, timeout=12)
                        markers = {
                            ("privacy","status"):f"Telemetry: {'Enabled' if effective else 'Disabled'}",
                            ("config","get"):str(enabled).lower(),
                            ("run","probe"):"usage dispatch probe finished",
                            ("config","list"):f"telemetry.enabled = {str(enabled).lower()}",
                        }
                        count = result.stderr.count("Discarding malformed license file")
                        remains = queue.read_bytes()
                        events = json.loads(remains)["events"]
                        logged = sum(row.get("type")=="command" for row in events)
                        retained = [row["duration_ms"] for row in events
                                    if row.get("metric_type")=="usage-dispatch-fixture"]
                        durable = (logged==1 and retained==list(range(12)) if effective and not held
                                   else remains==prior)
                        untouched = stats.read_bytes()==usage.encode() and (
                            not license_path.exists() if license_contents is None
                            else license_path.read_bytes()==license_contents)
                        checks.append(dict(phase=phase, case=f"{scenario}-{index}",
                            passed=bool(result.returncode==0 and markers[args[:2]] in result.stdout
                                        and count==warnings and durable and untouched),
                            status=result.returncode,
                            diagnostic=(result.stdout[-250:],result.stderr[-430:],
                                        count,logged,len(retained),untouched)))


    def inspect_saved_usage_stats():
        phase = "fedora-usage-storage"
        limit = 16 * 1024 * 1024
        maximum = (1 << 64) - 1
        today = datetime.datetime.now(datetime.timezone.utc).date()
        version = "24.15.3"
        helper = runtime_advisory_fixture
        seed = r"""
import runpy, sys
from pathlib import Path
helper, directory, version = sys.argv[1:]
home = Path(directory)
fixture = runpy.run_path(helper)
root = home/"data/versions/node"/version
program = root/"bin/node"
program.parent.mkdir(parents=True)
program.write_text("#!/bin/sh\nprintf 'v" + version + "\\n'\n")
program.chmod(0o755)
config = Path(fixture["fixture_cli_environment"](home)["OMG_CONFIG_DIR"])
fixture["seed_runtime_advisory_fixture"](root, "node", version, config)
"""

        with tempfile.TemporaryDirectory(prefix="usage-storage-", dir=work) as directory:
            home = Path(directory)
            os.chown(home, account.pw_uid, account.pw_gid)
            checked([sys.executable, "-I", "-B", "-c", seed, helper, home, version],
                    dict(disabled, HOME=str(home)), ordinary)
            data = home/"data"
            chosen = dict(disabled, HOME=str(home), OMG_DATA_DIR=str(data), OMG_CONFIG_DIR=str(home/"config/omg"),
                          OMG_NATIVE_TEST_DATA_DIR="1", XDG_CONFIG_HOME=str(home/"config"),
                          XDG_DATA_HOME=str(home/"xdg-data"), XDG_CACHE_HOME=str(home/"cache"),
                          XDG_STATE_HOME=str(home/"state"), TZ="UTC", CI="1", OMG_NO_UPDATE_CHECK="1")
            path = data/"usage.json"
            target = data/"historic-usage.json"
            current = data/"versions/node/current"
            normal = {
                "total_commands":7,"commands":{"runtime_switch":7},"time_saved_ms":1036,
                "queries_today":7,"queries_this_month":7,"last_query_date":today.isoformat(),
                "last_month":today.isoformat()[:7],"last_sync":0,"current_streak":2,
                "longest_streak":3,"runtimes_today":7,"time_saved_today_ms":1036,
                "runtime_usage_counts":{"node":7},
            }
            high = dict(normal,total_commands=maximum,time_saved_ms=maximum)
            high_map = dict(normal,commands={"runtime_switch":maximum},runtime_usage_counts={"node":maximum})
            high_daily = dict(normal,queries_today=maximum,queries_this_month=maximum,
                              runtimes_today=maximum,time_saved_today_ms=maximum)
            previous = today-datetime.timedelta(days=1)
            prior_month = today.replace(day=1)-datetime.timedelta(days=1)
            future = today+datetime.timedelta(days=1)
            later_month = (today.replace(day=28)+datetime.timedelta(days=4)).replace(day=1)
            ties = dict(normal, commands={f"fixture-{n:02d}":17 for n in reversed(range(48))})
            cases = (
                ("missing", None),
                ("current", normal),
                ("previous-day", dict(normal,last_query_date=previous.isoformat(),
                                      last_month=previous.isoformat()[:7])),
                ("previous-month", dict(normal,last_query_date=prior_month.isoformat(),
                                        last_month=prior_month.isoformat()[:7])),
                ("legacy", {k:v for k,v in normal.items() if k not in
                            ("runtime_usage_counts","runtimes_today","time_saved_today_ms")}),
                ("total-saturation", high),
                ("map-saturation", high_map),
                ("daily-saturation", high_daily),
                ("future-day", dict(normal,last_query_date=future.isoformat(),last_month=future.isoformat()[:7])),
                ("future-month", dict(normal,last_query_date=later_month.isoformat(),
                                      last_month=later_month.isoformat()[:7])),
                ("ties", ties),
                ("size-boundary", normal),
                ("size-excess", normal),
                ("regular-symlink", normal),
                ("malformed", b"{"),
            )

            def write(destination, value):
                destination.write_bytes(value)
                destination.chmod(0o600)
                os.chown(destination, account.pw_uid, account.pw_gid)

            for label, initial in cases:
                path.unlink(missing_ok=True)
                raw = json.dumps(initial).encode() if isinstance(initial, dict) else initial
                if label in ("size-boundary", "size-excess"):
                    raw = raw.ljust(limit + int(label=="size-excess"))
                if label=="regular-symlink":
                    write(target, raw)
                    path.symlink_to(target.name)
                elif initial is not None:
                    write(path, raw)
                rejected = {"size-excess":"byte limit","malformed":"Malformed usage stats"}.get(label)
                shown = command([cli, "stats"] if label=="ties" else [cli, "--json", "stats"], chosen, ordinary, timeout=8)
                unchanged = path.read_bytes()==raw if raw is not None else not path.exists()
                if rejected:
                    shown_ok = shown.returncode != 0 and not shown.stdout and rejected in shown.stderr
                elif label=="ties":
                    order = re.findall(r"fixture-\d{2}", shown.stdout)
                    shown_ok = shown.returncode==0 and order==[f"fixture-{n:02d}" for n in range(5)]
                else:
                    shown_ok = (shown.returncode==0 and json.loads(shown.stdout)["total_commands"]==
                                (initial["total_commands"] if initial else 0))
                checks.append(dict(phase=phase, case=f"{label}-read", status=shown.returncode,
                    passed=bool(shown_ok and unchanged), diagnostic=(shown.stdout[-560:],shown.stderr[-550:],unchanged)))

                result = command([cli, "use", "node", version], chosen, ordinary, timeout=12)
                acquired = (result.returncode==0 and "Now using Node.js" in result.stdout
                            and "Downloading" not in result.stdout and current.resolve().name==version)
                if rejected:
                    updated = path.is_file() and path.read_bytes()==raw and rejected in result.stderr
                    detail = rejected
                else:
                    prior = initial or {}
                    try:
                        stored = json.loads(path.read_bytes())
                    except (OSError, ValueError):
                        stored = {}
                    day = (dt if (dt := prior.get("last_query_date","")) >= today.isoformat()
                           else today.isoformat())
                    month = day[:7]
                    same_day = prior.get("last_query_date")==day
                    same_month = prior.get("last_month")==month
                    expected = {
                        "total_commands":min(maximum,prior.get("total_commands",0)+1),
                        "time_saved_ms":min(maximum,prior.get("time_saved_ms",0)+148),
                        "last_query_date":day,"last_month":month,
                        "queries_today":min(maximum,(prior.get("queries_today",0) if same_day else 0)+1),
                        "queries_this_month":min(maximum,(prior.get("queries_this_month",0) if same_month else 0)+1),
                        "time_saved_today_ms":min(maximum,(prior.get("time_saved_today_ms",0) if same_day else 0)+148),
                        "runtimes_today":min(maximum,(prior.get("runtimes_today",0) if same_day else 0)+1),
                    }
                    detail = {key:(stored.get(key),value) for key,value in expected.items() if stored.get(key)!=value}
                    updated = (not detail
                               and stored.get("commands",{}).get("runtime_switch")==min(
                                    maximum,prior.get("commands",{}).get("runtime_switch",0)+1)
                               and stored.get("runtime_usage_counts",{}).get("node")==min(
                                    maximum,prior.get("runtime_usage_counts",{}).get("node",0)+1)
                               and (label!="regular-symlink" or
                                    not path.is_symlink() and target.read_bytes()==raw))
                checks.append(dict(phase=phase, case=f"{label}-record", status=result.returncode,
                    passed=bool(acquired and updated), diagnostic=(result.stdout[-400:],result.stderr[-650:],detail)))


    def inspect_account_storage():
        phase = "fedora-account-storage"
        limit = 16 * 1024 * 1024
        for case in ("missing", "tokenless", "malformed", "invalid-utf8", "credential-symlink",
                     "dangling-symlink", "directory", "size-boundary", "size-excess",
                     "clock-current", "clock-advances", "clock-malformed", "clock-excess",
                     "clock-symlink", "clock-lock-directory"):
            with tempfile.TemporaryDirectory(prefix="account-storage-", dir=work) as directory:
                home = Path(directory)
                data, config = home/"data", home/"config"
                for path in (home,data,config):
                    path.mkdir(exist_ok=True)
                    path.chmod(0o700)
                    os.chown(path, account.pw_uid, account.pw_gid)

                def write(path, value):
                    path.write_bytes(value)
                    path.chmod(0o600)
                    os.chown(path, account.pw_uid, account.pw_gid)

                write(config/"config.toml", b"telemetry_enabled = false\n")
                credential = data/"license.json"
                target = data/"separate-account.json"
                clock = data/"license-clock.highwater"
                clock_target = data/"separate-clock"
                clock_lock = data/"license-clock.lock"
                clock_before = None
                credentials = {"key":"synthetic-unlinked-record","tier":"free","features":[],"validated_at":0}
                now = int(time.time())
                if case.startswith("clock-"):
                    credentials["token"] = "invalid-local-token-fixture"
                    value = str(now + 600).encode()
                    if case=="clock-advances":
                        value = b"1"
                    elif case=="clock-malformed":
                        value = b"no timestamp"
                    elif case=="clock-excess":
                        value = value.ljust(65)
                    elif case=="clock-symlink":
                        write(clock_target, value)
                        clock.symlink_to(clock_target.name)
                    if case=="clock-lock-directory":
                        clock_lock.mkdir()
                        os.chown(clock_lock, account.pw_uid, account.pw_gid)
                    if not clock.is_symlink():
                        write(clock, value)
                    clock_before = value

                raw = json.dumps(credentials).encode()
                if case=="malformed":
                    raw = b"{"
                elif case=="invalid-utf8":
                    raw = b"\xff"
                elif case in ("size-boundary","size-excess"):
                    raw = raw.ljust(limit + int(case=="size-excess"))
                if case=="credential-symlink":
                    write(target, raw)
                    credential.symlink_to(target.name)
                elif case=="dangling-symlink":
                    credential.symlink_to(target.name)
                elif case=="directory":
                    credential.mkdir()
                    os.chown(credential, account.pw_uid, account.pw_gid)
                elif case!="missing":
                    write(credential, raw)

                env = dict(disabled, HOME=str(home), OMG_DATA_DIR=str(data), OMG_CONFIG_DIR=str(config),
                           XDG_CONFIG_HOME=str(home/"xdg-config"), XDG_DATA_HOME=str(home/"xdg-data"),
                           XDG_STATE_HOME=str(home/"state"), XDG_CACHE_HOME=str(home/"cache"),
                           CI="1", OMG_NO_UPDATE_CHECK="1", RUST_LOG="warn")
                status = command([cli,"account","status"], env, ordinary, timeout=8)
                absent = {"missing","malformed","invalid-utf8","credential-symlink","dangling-symlink","directory","size-excess"}
                warning = {
                    "malformed":"Discarding malformed license file",
                    "invalid-utf8":"Failed to read license file",
                    "credential-symlink":"regular file",
                    "dangling-symlink":"regular file",
                    "directory":"regular file",
                    "size-excess":"byte limit",
                    "clock-malformed":"Malformed license clock watermark",
                    "clock-excess":"byte limit",
                    "clock-symlink":"regular file",
                    "clock-lock-directory":"Failed to open license clock lock",
                }.get(case)
                status_text = "Status: Not linked" if case in absent else "Status: Stored token is invalid or expired"
                clock_ok = (int(clock.read_text()) >= now if case=="clock-advances"
                            else clock.read_bytes()==clock_before if clock_before is not None
                            else not clock.exists())
                valid = (status.returncode==0 and status_text in status.stdout
                         and (warning in status.stderr if warning else not status.stderr)
                         and clock_ok and "synthetic-unlinked-record" not in status.stdout+status.stderr
                         and "invalid-local-token-fixture" not in status.stdout+status.stderr)
                if case=="credential-symlink":
                    valid = valid and credential.is_symlink() and target.read_bytes()==raw
                elif case=="dangling-symlink":
                    valid = valid and credential.is_symlink() and not target.exists()
                elif case not in ("missing","directory"):
                    valid = valid and credential.read_bytes()==raw
                if case=="clock-symlink":
                    valid = valid and clock.is_symlink() and clock_target.read_bytes()==clock_before
                checks.append(dict(phase=phase, case=f"{case}-status",status=status.returncode,
                    passed=bool(valid),diagnostic=(status.stdout[-480:],status.stderr[-580:],clock_ok)))

                preserved_clock = clock.read_bytes() if clock.is_file() else None
                unlink = command([cli,"account","unlink"], env, ordinary, timeout=8)
                if case=="directory":
                    removed = unlink.returncode!=0 and credential.is_dir() and "unlinked." not in unlink.stdout
                else:
                    removed = (unlink.returncode==0 and "Dashboard account unlinked." in unlink.stdout
                               and not credential.exists() and not credential.is_symlink())
                if case=="credential-symlink":
                    removed = removed and target.read_bytes()==raw
                if preserved_clock is not None:
                    removed = removed and clock.read_bytes()==preserved_clock
                checks.append(dict(phase=phase,case=f"{case}-unlink",status=unlink.returncode,
                    passed=bool(removed),diagnostic=(unlink.stdout[-380:],unlink.stderr[-550:])))


    def inspect_machine_identity():
        phase = "fedora-machine-identity"
        system_path = Path("/etc/machine-id")
        valid_system = b"13579bdf2468ace00000000000000099\n"
        legacy = b"already-linked-fixture\n"
        for case, system, stored in (
            ("system-valid", valid_system, legacy),
            ("system-first-boot", b"uninitialized\n", legacy),
            ("system-oversized", valid_system.ljust(129), legacy),
            ("fallback-existing", b"", legacy),
            ("fallback-create", b"", None),
            ("fallback-repair", b"", b" \n"),
            ("fallback-oversized", b"", legacy.ljust(129)),
            ("fallback-symlink", b"", legacy),
        ):
            with tempfile.TemporaryDirectory(prefix="machine-identity-", dir=work) as directory:
                home = Path(directory)
                data, config = home/"data", home/"config"
                for path in (home,data,config):
                    path.mkdir(exist_ok=True)
                    path.chmod(0o700)
                    os.chown(path, account.pw_uid, account.pw_gid)

                def write(path, value, mode=0o600):
                    path.write_bytes(value)
                    path.chmod(mode)
                    os.chown(path, account.pw_uid, account.pw_gid)

                system_fixture = home/"system-id"
                write(system_fixture,system,0o644)
                write(config/"config.toml",b"telemetry_enabled = false\n")
                identity_path = data/"machine-id"
                target = data/"separate-id"
                lock_path = data/"machine-id.lock"
                if case=="fallback-symlink":
                    write(target,stored)
                    identity_path.symlink_to(target.name)
                elif stored is not None:
                    write(identity_path,stored)
                held = case in ("fallback-existing","fallback-create","fallback-repair")
                waits = case in ("fallback-create","fallback-repair")
                if held:
                    write(lock_path,b"")
                chosen = dict(disabled, HOME=str(home), OMG_DATA_DIR=str(data), OMG_CONFIG_DIR=str(config),
                              XDG_CONFIG_HOME=str(home/"xdg-config"), XDG_DATA_HOME=str(home/"xdg-data"),
                              XDG_STATE_HOME=str(home/"state"), XDG_CACHE_HOME=str(home/"cache"),
                              CI="1", OMG_NO_UPDATE_CHECK="1", RUST_LOG="omg_lib::core::license=debug")
                lock = None
                children = []
                checked(["/usr/bin/mount","--bind",system_fixture,system_path])
                try:
                    if held:
                        lock = lock_path.open("r+b")
                        fcntl.flock(lock,fcntl.LOCK_EX | fcntl.LOCK_NB)
                    for index in range(4):
                        stdout, stderr = home/f"stdout-{index}", home/f"stderr-{index}"
                        with stdout.open("w") as output, stderr.open("w") as errors:
                            process = subprocess.Popen([str(cli),"account","link","--token-stdin"],
                                cwd=home,env=chosen,stdin=subprocess.PIPE,stdout=output,
                                stderr=errors,text=True,**ordinary)
                        process.stdin.write("qa-identity-example\n")
                        process.stdin.close()
                        children.append((process,stdout,stderr))
                    lease_ok = True
                    if waits:
                        deadline = time.monotonic()+8
                        while not all("Validating token..." in out.read_text() for _,out,_ in children):
                            assert time.monotonic()<deadline, "account callers must reach validation"
                            time.sleep(0.02)
                        time.sleep(0.25)
                        before = identity_path.read_bytes() if identity_path.is_file() else None
                        lease_ok = (before==stored and all(child.poll() is None for child,_,_ in children)
                                    and all("Generated machine ID fingerprint" not in err.read_text()
                                            for _,_,err in children))
                        fcntl.flock(lock,fcntl.LOCK_UN)
                    for child,_,_ in children:
                        child.wait(timeout=12)

                    observed = identity_path.read_bytes() if identity_path.is_file() else None
                    rejected = case in ("fallback-oversized","fallback-symlink")
                    if waits:
                        durable = observed is not None and observed!=stored
                        if durable:
                            try:
                                durable = (uuid.UUID(observed.decode()).version==4 and
                                           identity_path.stat().st_mode & 0o777==0o600)
                            except (UnicodeError,ValueError):
                                durable = False
                    else:
                        durable = observed==stored
                    if case=="fallback-symlink":
                        durable = durable and identity_path.is_symlink() and target.read_bytes()==stored
                    raw_id = system if case=="system-valid" else observed
                    expected = hashlib.sha256(raw_id.strip()).hexdigest()[:16] if raw_id else None
                    for index,(child,out,err) in enumerate(children,1):
                        logs = err.read_text()
                        fingerprints = re.findall(r"Generated machine ID fingerprint: ([a-f0-9]{16})",logs)
                        if rejected:
                            reason = "byte limit" if case=="fallback-oversized" else "regular file"
                            correct = len(fingerprints)==1 and fingerprints[0]!=expected and reason in logs
                        else:
                            correct = fingerprints==[expected]
                        offline = (child.returncode==1 and "Failed to connect to dashboard" in logs
                                   and "Dashboard account linked." not in out.read_text())
                        checks.append(dict(phase=phase,case=f"{case}-{index}",status=child.returncode,
                            passed=bool(offline and correct and durable and lease_ok),
                            diagnostic=(fingerprints,expected,durable,lease_ok,offline)))
                finally:
                    if lock is not None:
                        lock.close()
                    for child,_,_ in children:
                        if child.poll() is None:
                            child.kill()
                        child.wait()
                    checked(["/usr/bin/umount",system_path])


    def inspect_dashboard_token_admission():
        phase = "fedora-dashboard-token-admission"
        token = b"QZ7FixtureKey-48F"
        cases = (
            ("ordinary",token,"transport"),
            ("short",b"QZ7","transport"),
            ("maximum",token.ljust(128,b"X"),"transport"),
            ("newline",token+b"\r\n","transport"),
            ("trailing-whitespace",token+b" \t\n","transport"),
            ("input-boundary",token.ljust(16384,b" "),"transport"),
            ("empty",b"","empty"),
            ("whitespace-only",b" \t\n","empty"),
            ("leading-whitespace",b" "+token,"format"),
            ("embedded-whitespace",token[:8]+b" "+token[8:],"format"),
            ("non-ascii",token+b"\xc3\xa9","format"),
            ("punctuation",token+b"/","format"),
            ("overlong-token",token.ljust(129,b"X"),"format"),
            ("input-limit",token.ljust(16385,b" "),"limit"),
            ("invalid-utf8",token+b"\xff","encoding"),
        )
        reasons = {"empty":"Dashboard token is empty","format":"Invalid dashboard token format",
                   "limit":"Dashboard token exceeds the input limit"}
        for name, raw, expectation in cases:
            with tempfile.TemporaryDirectory(prefix="dashboard-token-", dir=work) as directory:
                home = Path(directory)
                data, config = home/"data", home/"config"
                for path in (home,data,config):
                    path.mkdir(exist_ok=True)
                    path.chmod(0o700)
                    os.chown(path,account.pw_uid,account.pw_gid)
                settings = config/"config.toml"
                settings.write_bytes(b"telemetry_enabled = false\n")
                saved = data/"license.json"
                prior = b'{"key":"previous-credential-fixture","tier":"free","features":[],"validated_at":0}'
                saved.write_bytes(prior)
                for path in (settings,saved):
                    path.chmod(0o600)
                    os.chown(path,account.pw_uid,account.pw_gid)
                env = dict(disabled,HOME=str(home),OMG_DATA_DIR=str(data),OMG_CONFIG_DIR=str(config),
                           XDG_CONFIG_HOME=str(home/"xdg-config"),XDG_DATA_HOME=str(home/"xdg-data"),
                           XDG_STATE_HOME=str(home/"state"),XDG_CACHE_HOME=str(home/"cache"),
                           CI="1",OMG_NO_UPDATE_CHECK="1",RUST_LOG="omg_lib::core::license=debug")
                for mode in ("stdin","environment"):
                    chosen = env.copy()
                    args = [str(cli),"account","link"]
                    if mode=="stdin":
                        args += ["--token-stdin"]
                        input_data = raw
                    else:
                        chosen["OMG_DASHBOARD_TOKEN"] = os.fsdecode(raw)
                        input_data = b""
                    result = subprocess.run(args,cwd=home,env=chosen,input=input_data,
                                            capture_output=True,timeout=12,**ordinary)
                    output = result.stdout.decode(errors="replace")
                    errors = result.stderr.decode(errors="replace")
                    log = output+errors
                    surfaced_secret = any(piece in log for piece in ("QZ7Fixture","QZ7Fixtu","QZ7"))
                    entered = "Validating token..." in output
                    offline = "Failed to connect to dashboard" in errors
                    if expectation=="transport":
                        gate = entered and offline
                    elif expectation=="encoding":
                        gate = not entered and not offline and "UTF-8" in errors if mode=="stdin" else (
                            not entered and not offline and "unicode" in errors.lower())
                    else:
                        gate = not entered and not offline and reasons[expectation] in errors
                    preserved = saved.read_bytes()==prior and "Dashboard account linked." not in output
                    checks.append(dict(phase=phase,case=f"{name}-{mode}",status=result.returncode,
                        passed=bool(result.returncode==1 and gate and not surfaced_secret and preserved),
                        diagnostic=(expectation,entered,offline,surfaced_secret,preserved,
                                    "input limit" in errors,"format" in errors,"empty" in errors)))


    def inspect_task_environment_bytes():
        phase = "task-environment-bytes"
        raw = b"test-\xff-value"
        opaque_key = b"OMG_FIXTURE_KEY_\xfe"
        system_path = os.fsencode(base_env["PATH"])
        with tempfile.TemporaryDirectory(prefix="task-environment-bytes-", dir=work) as directory:
            here = Path(directory)
            here.chmod(0o755)
            bin_dir = here / "bin"
            bin_dir.mkdir()
            tool = bin_dir / "fixture-environment"
            tool.write_text("""#!/usr/bin/python3
import json, os, sys
keys = (b"OMG_FIXTURE_RAW", b"OMG_FIXTURE_OUT", b"OMG_FIXTURE_KEY_\\xfe", b"PATH")
values = {key.hex(): value.hex() for key in keys if (value := os.environb.get(key)) is not None}
print("fixture environment " + json.dumps({"values": values, "args": sys.argv[1:]}))
""")
            tool.chmod(0o755)
            opaque_bin = here / os.fsdecode(b"bin-\xff")
            opaque_bin.mkdir()
            os.link(tool, opaque_bin / tool.name)
            default_path = os.fsencode(bin_dir) + b":" + system_path
            opaque_path = os.fsencode(opaque_bin) + b":" + system_path
            raw_key = b"OMG_FIXTURE_RAW"
            result_key = b"OMG_FIXTURE_OUT"
            path_key = b"PATH"
            template_file = "[env._]\nfile = { path = 'fixture.env', expand = true }\n"
            source_config = "[env._]\nsource = 'source.sh'\n"
            path_config = "[env._]\npath = ['tooling']\n"
            task = """[tasks.fixture]
run = 'fixture-environment "$@"'
"""
            task_env = "[tasks.fixture.env]\n"
            task_source = "[tasks.fixture.env._]\nsource = 'source.sh'\n"

            def observe_config_opens(args, project, env, requested):
                import ctypes
                import struct

                def execute():
                    return subprocess.run(args, cwd=project, env=env, stdin=subprocess.DEVNULL,
                                          capture_output=True, timeout=8, **ordinary)

                if requested is None:
                    return execute(), {}
                libc = ctypes.CDLL(None, use_errno=True)
                libc.inotify_init1.argtypes = [ctypes.c_int]
                libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
                in_open, in_close_nowrite = 0x20, 0x10
                notice = struct.Struct("iIII")
                fd = libc.inotify_init1(os.O_CLOEXEC | os.O_NONBLOCK)
                assert fd >= 0, ctypes.get_errno()
                try:
                    watched = {}
                    counts = dict.fromkeys(requested, 0)
                    for name in requested:
                        path = project / name
                        watch = libc.inotify_add_watch(fd, os.fsencode(path), in_open | in_close_nowrite)
                        assert watch >= 0 and watch not in watched, (name, ctypes.get_errno())
                        watched[watch] = name
                    result = execute()
                    try:
                        events = os.read(fd, 65536)
                    except BlockingIOError:
                        events = b""
                    offset = 0
                    while offset < len(events):
                        watch, flags, _, length = notice.unpack_from(events, offset)
                        counts[watched[watch]] += bool(flags & in_open)
                        offset += notice.size + length
                    return result, counts
                finally:
                    os.close(fd)

            def run(label, *, env=None, conf=None, files=(), parent_conf=None, parent_files=(),
                    expected=None, error=None, opaque_root=False, native_task=False, local_tool=False,
                    child_name="project", writable=(), reads=None, diagnostic_excludes=()):
                parent = here / label
                parent.mkdir()
                os.chown(parent, account.pw_uid, account.pw_gid)
                name = os.fsdecode(b"project-\xff") if opaque_root else child_name
                project = parent / name
                project.mkdir()
                if conf is not None:
                    (project / "mise.toml").write_text(conf)
                if parent_conf is not None:
                    (parent / "mise.toml").write_text(parent_conf)
                for root, inputs in ((project, files), (parent, parent_files)):
                    for filename, value in inputs:
                        path = root / filename
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_text(value)
                for filename in writable:
                    os.chown(project / filename, account.pw_uid, account.pw_gid)
                if local_tool:
                    (project / "tooling").mkdir()
                    os.link(tool, project / "tooling" / tool.name)
                launch = {os.fsencode(key): os.fsencode(value) for key, value in disabled.items()}
                launch.update({
                    b"HOME": os.fsencode(parent), b"PATH": default_path,
                    b"XDG_CONFIG_HOME": os.fsencode(parent/"config"), b"XDG_DATA_HOME": os.fsencode(parent/"data"),
                    b"XDG_CACHE_HOME": os.fsencode(parent/"cache"), b"XDG_STATE_HOME": os.fsencode(parent/"state"),
                })
                for key, value in (env or {}).items():
                    if value is None:
                        launch.pop(key, None)
                    else:
                        launch[key] = value(project) if callable(value) else value
                try:
                    args = [cli, "run", "fixture" if native_task else tool.name, "--", "one value", "--flag"]
                    result, opened = observe_config_opens(args, project, launch, reads)
                    output = result.stdout.decode(errors="replace")
                    diagnostic = result.stderr.decode(errors="replace")
                    marker = "fixture environment "
                    results = [line[len(marker):] for line in output.splitlines() if line.startswith(marker)]
                    if error:
                        passed = result.returncode != 0 and not results and error in diagnostic and "panicked" not in diagnostic
                    else:
                        wanted = expected(project) if callable(expected) else (expected or {})
                        payload = json.loads(results[0]) if len(results) == 1 else {}
                        values = payload.get("values", {})
                        passed = (result.returncode == 0 and payload.get("args") == ["one value", "--flag"]
                                  and all(values.get(key.hex()) == (value.hex() if value is not None else None)
                                          for key, value in wanted.items()))
                    passed &= not any(value in output or value in diagnostic for value in diagnostic_excludes)
                    behavior_ok = passed
                    passed &= reads is None or opened == reads
                    checks.append(dict(phase=phase, case=label, passed=passed, status=result.returncode,
                                       behavior_ok=behavior_ok, reported_reads=opened, expected_reads=reads,
                                       diagnostic=(output + diagnostic)[-1300:]))
                except subprocess.TimeoutExpired:
                    checks.append(dict(phase=phase, case=label, passed=False, status=None,
                                       diagnostic="task exceeded deadline"))

            run("inherited-text", env={raw_key: b"ordinary"}, expected={raw_key: b"ordinary"})
            run("inherited-opaque-value", env={raw_key: raw}, expected={raw_key: raw})
            run("inherited-opaque-key", env={opaque_key: b"extra"}, expected={opaque_key: b"extra"})
            run("inherited-opaque-path", env={path_key: opaque_path}, expected={path_key: opaque_path})
            run("toml-overrides-opaque-value", env={raw_key: raw}, conf="[env]\nOMG_FIXTURE_RAW = 'configured'\n",
                expected={raw_key: b"configured"})
            run("toml-removes-opaque-value", env={raw_key: raw}, conf="[env]\nOMG_FIXTURE_RAW = false\n",
                expected={raw_key: None})
            run("default-keeps-opaque-nonempty", env={raw_key: raw},
                conf="[env]\nOMG_FIXTURE_RAW = { default = 'fallback' }\n", expected={raw_key: raw})
            run("required-accepts-opaque-nonempty", env={raw_key: raw},
                conf="[env]\nOMG_FIXTURE_RAW = { required = true }\n", expected={raw_key: raw})
            run("template-refuses-opaque-reference", env={raw_key: raw},
                conf="[env]\nOMG_FIXTURE_OUT = '{{env.OMG_FIXTURE_RAW}}'\n",
                error="Environment variable OMG_FIXTURE_RAW is not UTF-8")
            run("template-reads-text-reference", env={raw_key: b"text"},
                conf="[env]\nOMG_FIXTURE_OUT = '{{env.OMG_FIXTURE_RAW}}'\n", expected={result_key: b"text"})
            run("dotenv-refuses-opaque-reference", env={raw_key: raw}, conf=template_file,
                files=(("fixture.env", "OMG_FIXTURE_OUT=$OMG_FIXTURE_RAW\n"),),
                error="Environment variable OMG_FIXTURE_RAW is not UTF-8")
            run("dotenv-missing-expands-empty", conf=template_file,
                files=(("fixture.env", "OMG_FIXTURE_OUT=base$OMG_FIXTURE_RAW\n"),),
                expected={result_key: b"base"})
            run("dotenv-plain-opaque-inheritance", env={raw_key: raw}, conf="[env._]\nfile = 'fixture.env'\n",
                files=(("fixture.env", "OMG_FIXTURE_OUT=plain\n"),),
                expected={result_key: b"plain", raw_key: raw})
            run("source-copies-opaque-value", env={raw_key: raw}, conf=source_config,
                files=(("source.sh", 'export OMG_FIXTURE_OUT="$OMG_FIXTURE_RAW"\n'),),
                expected={result_key: raw, raw_key: raw})
            run("source-exports-opaque-value", env={result_key: b"before"}, conf=source_config,
                files=(("source.sh", "export OMG_FIXTURE_OUT=$(printf '\\377')\n"),),
                expected={result_key: b"\xff"})
            run("source-unsets-opaque-value", env={raw_key: raw}, conf=source_config,
                files=(("source.sh", "unset OMG_FIXTURE_RAW\n"),), expected={raw_key: None})
            run("source-keeps-opaque-inherited-key", env={opaque_key: b"extra"}, conf=source_config,
                files=(("source.sh", "export OMG_FIXTURE_OUT=ready\n"),),
                expected={opaque_key: b"extra", result_key: b"ready"})
            run("mise-path-preserves-opaque-component", env={path_key: opaque_path}, conf=path_config,
                expected=lambda cwd: {path_key: os.fsencode(cwd/"tooling") + b":" + opaque_path})
            run("source-path-preserves-opaque-component", env={path_key: opaque_path}, conf=source_config,
                files=(("source.sh", 'export PATH="$PATH:/source-fixture"\n'),),
                expected={path_key: opaque_path + b":/source-fixture"})
            run("mise-path-from-opaque-project-root", env={path_key: system_path}, conf=path_config,
                opaque_root=True, local_tool=True,
                expected=lambda cwd: {path_key: os.fsencode(cwd/"tooling") + b":" + system_path})
            run("template-refuses-opaque-project-root", opaque_root=True,
                conf="[env]\nOMG_FIXTURE_OUT = '{{config_root}}'\n", error="Mise config root is not UTF-8")
            run("path-entry-with-colon-refused", conf="[env._]\npath = ['dir:with-colon']\n",
                error="Cannot prepend directories to PATH")
            run("empty-path-overlay", env={path_key: b""}, conf=path_config, local_tool=True,
                expected=lambda cwd: {path_key: os.fsencode(cwd/"tooling")})
            run("unset-path-overlay", env={path_key: None}, conf=path_config, local_tool=True,
                expected=lambda cwd: {path_key: os.fsencode(cwd/"tooling")})
            run("nonempty-path-retains-explicit-empty-segments", env={path_key: b":" + opaque_path + b":"},
                conf=path_config,
                expected=lambda cwd: {path_key: os.fsencode(cwd/"tooling") + b"::" + opaque_path + b":"})
            run("opaque-mise-selection-refused", env={b"MISE_ENV": b"test-\xff"},
                error="Environment variable MISE_ENV is not UTF-8")
            run("selected-mise-layer-works-with-opaque-inheritance", env={b"MISE_ENV": b"test", raw_key: raw},
                files=(("mise.test.toml", "[env]\nOMG_FIXTURE_OUT = 'selected'\n"),),
                expected={result_key: b"selected", raw_key: raw})
            run("layered-parent-source-final-child-override", env={raw_key: raw}, parent_conf=source_config,
                parent_files=(("source.sh", 'export OMG_FIXTURE_OUT="$OMG_FIXTURE_RAW"\n'),),
                conf="[env]\nOMG_FIXTURE_OUT = 'child'\n", expected={result_key: b"child", raw_key: raw})
            run("layered-path-order-with-opaque-component", env={path_key: opaque_path},
                parent_conf="[env._]\npath = ['parent-bin']\n", conf=path_config,
                expected=lambda cwd: {path_key: b":".join(
                    (os.fsencode(cwd/"tooling"), os.fsencode(cwd.parent/"parent-bin"), opaque_path))})
            run("native-task-overrides-opaque-value", native_task=True, env={raw_key: raw},
                conf=task + task_env + "OMG_FIXTURE_RAW = 'task'\n", expected={raw_key: b"task"})
            run("native-task-source-reads-opaque-value", native_task=True, env={raw_key: raw},
                conf=task + task_source, files=(("source.sh", 'export OMG_FIXTURE_OUT="$OMG_FIXTURE_RAW"\n'),),
                expected={result_key: raw, raw_key: raw})
            run("native-task-finds-opaque-path", native_task=True, env={path_key: opaque_path}, conf=task,
                expected={path_key: opaque_path})

            phase = "task-mise-documents"
            value = "[env]\nOMG_FIXTURE_OUT = 'ready'\n"
            older = "[env]\nOMG_FIXTURE_OUT = 'older'\n"
            chosen = {result_key: b"ready"}
            root_value = "[env]\nOMG_FIXTURE_OUT = '{{config_root}}'\n"
            for index, filename in enumerate((
                "mise.toml", ".mise.toml", "mise/config.toml", ".mise/config.toml",
                ".config/mise/config.toml", ".config/mise/mise.toml", ".config/mise.toml",
                ".config/mise/conf.d/main.toml", ".mise/conf.d/main.toml", "mise/conf.d/main.toml",
            )):
                run(f"base-location-{index}", files=((filename, value),), expected=chosen, reads={filename: 2})
            run("fragments-sort-within-layer",
                files=(("mise/conf.d/90-final.toml", value), ("mise/conf.d/10-base.toml", older)),
                expected=chosen, reads={"mise/conf.d/10-base.toml": 2, "mise/conf.d/90-final.toml": 2})
            for index, filename in enumerate(("mise.local.toml", ".mise.local.toml",
                                               "mise/config.local.toml", ".config/mise/mise.local.toml")):
                plain = filename.replace(".local.toml", ".toml")
                run(f"local-over-default-{index}", files=((plain, older), (filename, value)),
                    expected=chosen, reads={plain: 2, filename: 2})
            run("selected-overlay", env={b"MISE_ENV": b"dev"}, conf=older,
                files=(("mise.dev.toml", value),), expected=chosen, reads={"mise.toml": 2, "mise.dev.toml": 2})
            run("selected-local-overlay", env={b"MISE_ENV": b"dev"},
                files=((".mise.dev.toml", older), (".mise.dev.local.toml", value)),
                expected=chosen, reads={".mise.dev.toml": 2, ".mise.dev.local.toml": 2})
            run("last-selected-overlay-wins", env={b"MISE_ENV": b"dev,stage"},
                files=(("mise.dev.toml", older), ("mise.stage.toml", value)), expected=chosen,
                reads={"mise.dev.toml": 2, "mise.stage.toml": 2})
            run("unselected-overlay-is-never-opened", conf=value, files=(("mise.dev.toml", older),),
                expected=chosen, reads={"mise.toml": 2, "mise.dev.toml": 0})
            run("parent-only-configuration", parent_conf=value,
                expected=chosen, reads={"../mise.toml": 2})
            run("child-after-parent", conf=value, parent_conf=older,
                expected=chosen, reads={"mise.toml": 2, "../mise.toml": 2})
            run("parent-env-expands-in-child",
                parent_conf="[env]\nOMG_FIXTURE_RAW = 'ready'\n",
                conf="[env]\nOMG_FIXTURE_OUT = '{{env.OMG_FIXTURE_RAW}}'\n",
                expected={**chosen, raw_key: b"ready"}, reads={"mise.toml": 2, "../mise.toml": 2})
            run("selected-parent-before-child", env={b"MISE_ENV": b"stage"}, conf=value,
                parent_files=((".mise.stage.toml", older),), expected=chosen,
                reads={"mise.toml": 2, "../.mise.stage.toml": 2})
            run("grouped-dotenv-declaring-root", files=(
                    (".config/mise/config.toml", "[env._]\nfile = 'fixture.env'\n"),
                    ("fixture.env", "OMG_FIXTURE_OUT=ready\n"),
                ), expected=chosen, reads={".config/mise/config.toml": 2})
            run("legacy-dotenv-declaring-root", files=(
                    (".config/mise/mise.toml", "[env._]\nfile = 'fixture.env'\n"),
                    (".config/mise/fixture.env", "OMG_FIXTURE_OUT=ready\n"),
                ), expected=chosen, reads={".config/mise/mise.toml": 2})
            run("legacy-config-root-template", files=((".config/mise/mise.toml", root_value),),
                expected=lambda cwd: {result_key: os.fsencode(cwd/".config/mise")},
                reads={".config/mise/mise.toml": 2})
            run("overlapping-layer-uses-parent-source-once", child_name=".config", files=(
                    ("mise/config.toml", source_config),
                ), parent_files=(
                    ("source.sh", 'export OMG_FIXTURE_OUT="${OMG_FIXTURE_OUT-}once"\n'),
                ), expected={result_key: b"once"}, reads={"mise/config.toml": 3})
            run("native-mise-base", native_task=True, conf=task + value,
                expected=chosen, reads={"mise.toml": 3})
            run("native-mise-selected", native_task=True, env={b"MISE_ENV": b"stage"}, conf=task + older,
                files=(("mise.stage.toml", value),), expected=chosen,
                reads={"mise.toml": 3, "mise.stage.toml": 3})
            run("native-mise-parent-env", native_task=True, conf=task, parent_conf=value,
                expected=chosen, reads={"mise.toml": 3, "../mise.toml": 3})
            refresh = task + """depends = ["prepare"]
[tasks.prepare]
run = "cp next.toml mise.local.toml"
"""
            run("native-mise-refreshes-project-env", native_task=True, conf=refresh,
                files=(("mise.local.toml", older), ("next.toml", value)),
                writable=("mise.local.toml",), expected=chosen)
            run("native-mise-rejects-malformed-refreshed-config", native_task=True, conf=refresh,
                files=(("mise.local.toml", older), ("next.toml", "[env")),
                writable=("mise.local.toml",), error="Failed to parse mise configuration")

            phase = "mise-dotenv-values"
            dotenv = "[env._]\nfile = 'fixture.env'\n"
            expanded = "[env._]\nfile = { path = 'fixture.env', expand = true }\n"

            def value_case(label, assignment, value, *, expand=False, prefix="", parent=False):
                run(label, conf=None if parent else (expanded if expand else dotenv),
                    parent_conf=(expanded if expand else dotenv) if parent else None,
                    files=() if parent else (("fixture.env", prefix + assignment),),
                    parent_files=(("fixture.env", prefix + assignment),) if parent else (),
                    expected={result_key: value})

            def out(spec):
                return "OMG_FIXTURE_OUT=" + spec + "\n"

            for name, spec, expected in [
                ("unquoted-words", "two words", b"two words"),
                ("unquoted-extra-equals", "left=right", b"left=right"),
                ("unquoted-embedded-hash", "socket#name", b"socket#name"),
                ("unquoted-space-comment", "ready # comment", b"ready"),
                ("unquoted-tab-comment", "ready\t# comment", b"ready"),
                ("unquoted-empty-before-comment", " # comment", b""),
                ("unquoted-leading-hash", "#literal", b"#literal"),
                ("single-quoted-comment", "'first # second' # trailing", b"first # second"),
                ("double-quoted-comment", '"first # second" # trailing', b"first # second"),
                ("quoted-space-preserved", '"  ready  " \t# outside', b"  ready  "),
                ("quoted-empty-before-comment", "'' # trailing", b""),
                ("quoted-unicode", '"føø # 水" # outside', "føø # 水".encode()),
                ("double-quoted-escaped-quote", r'"say \"ready\" # inside" # outside', b'say "ready" # inside'),
                ("double-quoted-escaped-controls", r'"first\nsecond\rthird\tlast"', b"first\nsecond\rthird\tlast"),
                ("double-quoted-escaped-backslash", r'"left\\right"', b"left\\right"),
                ("double-quoted-unknown-escape", r'"left\qright"', b"left\\qright"),
                ("single-quoted-escapes-stay-literal", r"'first\nsecond'", b"first\\nsecond"),
                ("double-quoted-multiline", '"first\n# second\n third" # outside', b"first\n# second\n third"),
                ("single-quoted-multiline", "'first\n# second\n third' # outside", b"first\n# second\n third"),
                ("inactive-expansion", '"$OMG_FIXTURE_RAW"', b"$OMG_FIXTURE_RAW"),
            ]:
                value_case(name, out(spec), expected)

            value_case("export-tab-prefix", "export\t" + out("ready"), b"ready")
            value_case("windows-line-endings", "export " + out("'ready # value' # outside").replace("\n", "\r\n"),
                       b"ready # value", parent=True)
            for name, spec, expected in [
                ("expand-unquoted", "$OMG_FIXTURE_RAW/${OMG_FIXTURE_RAW}", b"seed/seed"),
                ("expand-double-quoted", '"$OMG_FIXTURE_RAW # inside" # outside', b"seed # inside"),
                ("keep-single-quoted-expansion-literal", "'$OMG_FIXTURE_RAW/${OMG_FIXTURE_RAW}'",
                 b"$OMG_FIXTURE_RAW/${OMG_FIXTURE_RAW}"),
                ("keep-double-quoted-escaped-dollars-literal", r'"\$OMG_FIXTURE_RAW/\${OMG_FIXTURE_RAW}/$OMG_FIXTURE_RAW"',
                 b"$OMG_FIXTURE_RAW/${OMG_FIXTURE_RAW}/seed"),
                ("expand-after-escaped-backslash", r'"\\$OMG_FIXTURE_RAW"', b"\\seed"),
                ("keep-unquoted-escaped-dollar-literal", r"\$OMG_FIXTURE_RAW/$OMG_FIXTURE_RAW",
                 b"$OMG_FIXTURE_RAW/seed"),
                ("missing-expansion-remains-empty", "before$OMG_FIXTURE_MISSING/after", b"before/after"),
            ]:
                value_case(name, out(spec), expected, expand=True, prefix="OMG_FIXTURE_RAW=seed\n")

            value_case("later-assignment-sees-earlier-value", out("$OMG_FIXTURE_OUT/last"), b"first/last",
                       expand=True, prefix=out("first"))
            run("later-dotenv-file-sees-earlier-file",
                conf="[env._]\nfile = ['first.env', { path = 'second.env', expand = true }]\n",
                files=(("first.env", "OMG_FIXTURE_RAW=seed\n"), ("second.env", out('"$OMG_FIXTURE_RAW # ready" # outside'))),
                expected={result_key: b"seed # ready"})
            run("task-local-dotenv-uses-same-value-rules", native_task=True,
                conf=task + "[env]\nOMG_FIXTURE_RAW = 'global'\n" +
                     "[tasks.fixture.env._]\nfile = { path = 'fixture.env', expand = true }\n",
                files=(("fixture.env", out('"$OMG_FIXTURE_RAW # local" # outside')),),
                expected={result_key: b"global # local"})
            for name, assignment in [
                ("unterminated-single-quote", out("'private-fixture-value")),
                ("unterminated-double-quote", out('"private-fixture-value')),
                ("characters-after-closed-quote", out('"ready" trailing')),
                ("missing-assignment-delimiter", "NO_EQUALS\n"),
            ]:
                run(name, conf=dotenv, files=(("fixture.env", "# first line\n" + assignment),),
                    error="Malformed line 2", diagnostic_excludes=("private-fixture-value",))
            run("json-file-expansion-preserved",
                conf="[env._]\nfile = { path = 'fixture.json', expand = true }\n",
                files=(("fixture.json", '{"OMG_FIXTURE_OUT":"$OMG_FIXTURE_RAW"}'),),
                env={raw_key: b"seed"}, expected={result_key: b"seed"})
            run("toml-file-expansion-preserved",
                conf="[env._]\nfile = { path = 'fixture.toml', expand = true }\n",
                files=(("fixture.toml", "OMG_FIXTURE_OUT = '$OMG_FIXTURE_RAW'\n"),),
                env={raw_key: b"seed"}, expected={result_key: b"seed"})

            phase = "mise-source-snapshot"
            ready = "export OMG_FIXTURE_OUT=ready\n"

            def source_case(label, script, *, expected=None, error=None, diagnostic_excludes=(),
                            env=None, file="source.sh", local=False, opaque=False):
                selected = f"source = '{file}'\n"
                configuration = (task + "[tasks.fixture.env._]\n" if local else "[env._]\n") + selected
                run(label, conf=configuration, files=() if script is None else ((file, script),),
                    expected=expected, error=error, env=env, native_task=local,
                    opaque_root=opaque, diagnostic_excludes=diagnostic_excludes)

            for label, script, result in [
                ("exports-value", ready, b"ready"),
                ("inherits-unchanged-value", "# no edits\n", b"before"),
                ("unsets-value", "unset OMG_FIXTURE_OUT\n", None),
                ("keeps-empty-export", "export OMG_FIXTURE_OUT=''\n", b""),
                ("keeps-equals-and-spaces", "export OMG_FIXTURE_OUT='hello = world'\n", b"hello = world"),
                ("keeps-multiline-export", "export OMG_FIXTURE_OUT='first\nsecond'\n", b"first\nsecond"),
                ("unexported-local-not-imported", "OMG_FIXTURE_OUT=unexported\nunset OMG_FIXTURE_OUT\nOMG_FIXTURE_OUT=local\n", None),
                ("explicit-return-zero", ready + "return 0\n", b"ready"),
                ("uses-ordinary-last-command-status", "false\n" + ready, b"ready"),
                ("handles-conditional-failure", "false || :\n" + ready, b"ready"),
                ("changes-positional-arguments", "set -- changed arguments\n" + ready, b"ready"),
                ("source-starts-with-no-positional-arguments", 'export OMG_FIXTURE_OUT="$#"\n', b"0"),
            ]:
                source_case(label, script, env={result_key: b"before"}, expected={result_key: result})
            source_case("source-logs-stay-private",
                        "printf 'source-private-out\\n'; printf 'source-private-err\\n' >&2\n" + ready,
                        expected={result_key: b"ready"}, diagnostic_excludes=("source-private-out", "source-private-err"))
            source_case("source-file-path-with-space", ready, file="my source.sh", expected={result_key: b"ready"})
            source_case("source-in-opaque-project", ready, opaque=True, expected={result_key: b"ready"})
            source_case("source-task-local", ready, local=True, expected={result_key: b"ready"})
            source_case("source-preserves-opaque-export", "export OMG_FIXTURE_OUT=$(printf '\\377')\n",
                        expected={result_key: b"\xff"})
            source_case("source-not-found", None, error="failed while sourcing")
            source_case("source-return-failure", ready + "return 7\n", error="failed while sourcing")
            source_case("source-shell-explicit-failure", ready + "exit 9\n", error="failed while sourcing")
            source_case("source-explicit-errexit", ready + "set -e\nfalse\nexport OMG_FIXTURE_OUT=unexpected\n",
                        error="failed while sourcing")
            source_case("source-early-zero-exit", ready + "exit 0\n", error="Incomplete environment snapshot")
            source_case("source-early-replacement", ready + "exec /usr/bin/true\n", error="Incomplete environment snapshot")
            source_case("task-local-source-early-exit", "exit 0\n", local=True, error="Incomplete environment snapshot")

            run("source-path-change-keeps-collector",
                conf=source_config,
                files=(("source.sh", f'export PATH="$PWD/tooling"\n{ready}'),), local_tool=True,
                expected=lambda cwd: {result_key: b"ready", path_key: os.fsencode(cwd/"tooling")})
            run("configured-path-keeps-source-shell",
                conf="[env]\nPATH = '{{config_root}}/tooling'\n" + source_config,
                files=(("source.sh", ready),), local_tool=True,
                expected=lambda cwd: {result_key: b"ready", path_key: os.fsencode(cwd/"tooling")})
            run("ordered-sources-share-resolved-environment",
                conf="[env._]\nsource = ['one.sh', 'two.sh']\n",
                files=(("one.sh", "export OMG_FIXTURE_RAW=first\n"),
                       ("two.sh", 'export OMG_FIXTURE_OUT="$OMG_FIXTURE_RAW-second"\n')),
                expected={result_key: b"first-second", raw_key: b"first"})
            run("task-source-sees-project-source",
                native_task=True, conf=task + source_config + "[tasks.fixture.env._]\nsource = 'local.sh'\n",
                files=(("source.sh", "export OMG_FIXTURE_RAW=project\n"),
                       ("local.sh", 'export OMG_FIXTURE_OUT="$OMG_FIXTURE_RAW-local"\n')),
                expected={result_key: b"project-local", raw_key: b"project"})
            run("startup-runs-once-per-source",
                conf=source_config,
                env={b"BASH_ENV": lambda cwd: os.fsencode(cwd/"startup.sh"),
                     b"OMG_FIXTURE_STARTS": lambda cwd: os.fsencode(cwd.parent/"starts")},
                files=(("startup.sh", 'printf "start\\n" >> "$OMG_FIXTURE_STARTS"\n'),
                       ("source.sh", 'export OMG_FIXTURE_OUT=$(wc -l < "$OMG_FIXTURE_STARTS")\n')),
                expected={result_key: b"1"})
            run("startup-output-does-not-obscure-snapshot",
                conf=source_config, env={b"BASH_ENV": lambda cwd: os.fsencode(cwd/"startup.sh")},
                files=(("startup.sh", 'printf "startup-private-noise\\n"\n'), ("source.sh", ready)),
                expected={result_key: b"ready"}, diagnostic_excludes=("startup-private-noise",))

            for name, suffix, value in [
                ("json-nested-object-diagnostic", "json", '{"OMG_FIXTURE_OUT":{"probe":"fixture-private-object"}}'),
                ("json-array-diagnostic", "json", '{"OMG_FIXTURE_OUT":["fixture-private-object"]}'),
                ("toml-nested-table-diagnostic", "toml", '[OMG_FIXTURE_OUT]\nprobe = "fixture-private-object"\n'),
                ("toml-array-diagnostic", "toml", 'OMG_FIXTURE_OUT = ["fixture-private-object"]\n'),
            ]:
                filename = f"fixture.{suffix}"
                run(name, conf=f"[env._]\nfile = '{filename}'\n", files=((filename, value),),
                    error="Non-scalar value for OMG_FIXTURE_OUT", diagnostic_excludes=("fixture-private-object",))

            phase = "mise-env-options"
            assignment = "OMG_FIXTURE_OUT"
            env_prefix = "[env]\n"
            directive_prefix = "[env._]\n"
            success = {result_key: b"ready"}
            ordinary_file = (("fixture.env", assignment + "=ready\n"), ("other.env", assignment + "=other\n"))
            ordinary_script = (("source.sh", "export OMG_FIXTURE_OUT=ready\n"),
                               ("other.sh", "export OMG_FIXTURE_OUT=other\n"))
            private = ("fixture-private-option",)

            for label, conf, diagnostic in [
                ("env-string-is-invalid", "env = 'no'\n", "env must be a table"),
                ("env-array-is-invalid", 'env = [{ MODE = "ready" }]\n', "env must be a table"),
                ("redactions-string-is-invalid", "redactions = 'MODE'\n", "redactions must be an array"),
                ("redactions-elements-checked-without-env", "redactions = [7]\n", "redactions entries must be strings"),
            ]:
                run(label, conf=conf, error=diagnostic)

            for label, spec, diagnostic in [
                ("entry-tools-needs-boolean", "{ value = 'ready', tools = 'yes' }", "tools must be a boolean"),
                ("entry-redact-needs-boolean", "{ value = 'ready', redact = 'yes' }", "redact must be a boolean"),
                ("entry-required-needs-boolean", "{ value = 'ready', required = 'yes' }", "required must be a boolean"),
                ("entry-rejects-value-and-default", "{ value = 'ready', default = 'other' }", "exactly one"),
                ("entry-rejects-required-and-default", "{ required = true, default = 'ready' }", "exactly one"),
                ("entry-rejects-required-and-value", "{ required = true, value = 'other' }", "exactly one"),
                ("unsupported-entry-value-is-private", "['fixture-private-option']", "Unsupported value"),
                ("unsupported-default-is-private", "{ default = ['fixture-private-option'] }", "Unsupported default value"),
                ("unsupported-object-value-is-private", "{ value = ['fixture-private-option'] }", "Unsupported value"),
            ]:
                run(label, env={result_key: b"existing"}, conf=env_prefix + f"{assignment} = {spec}\n",
                    error=diagnostic, diagnostic_excludes=private)

            for label, spec, diagnostic in [
                ("file-expand-needs-boolean", "{ path = 'fixture.env', expand = 'true' }", "expand must be a boolean"),
                ("file-tools-needs-boolean", "{ path = 'fixture.env', tools = 'true' }", "tools must be a boolean"),
                ("file-redact-needs-boolean", "{ path = 'fixture.env', redact = 'true' }", "redact must be a boolean"),
                ("file-rejects-two-path-keys", "{ path = 'fixture.env', value = 'other.env' }", "one path spelling"),
                ("file-rejected-type-is-private", "[['fixture-private-option']]", "Unsupported _.file entry"),
            ]:
                run(label, conf=directive_prefix + f"file = {spec}\n", files=ordinary_file,
                    error=diagnostic, diagnostic_excludes=private)

            for label, spec, diagnostic in [
                ("path-tools-needs-boolean", "{ path = 'bin', tools = 'yes' }", "tools must be a boolean"),
                ("path-append-is-unsupported", "{ path = 'bin', position = 'append' }", "_.path position must be 'prepend'"),
                ("path-redact-is-unsupported", "{ path = 'bin', redact = true }", 'Unknown option "redact" in _.path'),
                ("path-rejects-two-path-keys", "{ path = 'bin', values = ['more'] }", "one path spelling"),
                ("path-rejected-type-is-private", "[['fixture-private-option']]", "Unsupported _.path entry"),
            ]:
                run(label, conf=directive_prefix + f"path = {spec}\n", error=diagnostic,
                    diagnostic_excludes=private)

            for label, spec, diagnostic in [
                ("source-unknown-option-fails", "{ path = 'source.sh', expand = true }", 'Unknown option "expand" in _.source'),
                ("source-tools-needs-boolean", "{ path = 'source.sh', tools = 'yes' }", "tools must be a boolean"),
                ("source-redact-needs-boolean", "{ path = 'source.sh', redact = 'yes' }", "redact must be a boolean"),
                ("source-rejects-two-path-keys", "{ path = 'source.sh', value = 'other.sh' }", "one path spelling"),
                ("source-rejected-type-is-private", "[['fixture-private-option']]", "Unsupported _.source entry"),
            ]:
                run(label, conf=directive_prefix + f"source = {spec}\n", files=ordinary_script,
                    error=diagnostic, diagnostic_excludes=private)
            run("task-env-value-type-rejected", native_task=True,
                conf=task + "env.OMG_FIXTURE_OUT = { value = 'ready', tools = 'yes' }\n",
                error="tools must be a boolean")
            run("task-env-container-checked", native_task=True, conf=task + "env = 'no'\n",
                error="env must be a table")

            for label, spec, existing, expected in [
                ("entry-string", "'ready'", None, b"ready"),
                ("entry-integer", "41", None, b"41"),
                ("entry-false-unsets", "false", b"before", None),
                ("entry-true-is-text", "true", None, b"true"),
                ("entry-explicit-required-false-with-value", "{ required = false, value = 'ready' }", None, b"ready"),
                ("entry-explicit-required-false-with-default", "{ required = false, default = 'ready' }", None, b"ready"),
                ("entry-default-keeps-present", "{ default = 'different', tools = false }", b"ready", b"ready"),
                ("entry-required-validates-present", "{ required = true, redact = true }", b"ready", b"ready"),
            ]:
                run(label, env={result_key: existing}, conf=env_prefix + f"{assignment} = {spec}\n",
                    expected={result_key: expected})

            run("file-deprecated-value-alias", conf=directive_prefix + "file = { value = 'fixture.env' }\n",
                files=ordinary_file, expected=success)
            run("file-deprecated-values-alias", conf=directive_prefix + "file = { values = 'fixture.env' }\n",
                files=ordinary_file, expected=success)
            run("path-deprecated-alias-and-prepend",
                conf=directive_prefix + "path = { values = ['bin', 'more'], tools = false, position = 'prepend' }\n",
                expected=lambda cwd: {path_key: b":".join((os.fsencode(cwd/"bin"),
                                                           os.fsencode(cwd/"more"), default_path))})
            run("source-redact-and-deprecated-alias",
                conf=directive_prefix + "source = { value = 'source.sh', redact = true, tools = false }\n",
                files=ordinary_script, expected=success)
            run("task-local-valid-flags", native_task=True,
                conf=task + "env.OMG_FIXTURE_OUT = { value = 'ready', tools = true, redact = false }\n",
                expected=success)

            phase = "mise-env-required"
            required = "[env]\nOMG_FIXTURE_OUT = { required = true }\n"
            ready = "[env]\nOMG_FIXTURE_OUT = 'ready'\n"
            unset = "[env]\nOMG_FIXTURE_OUT = false\n"
            empty = "[env]\nOMG_FIXTURE_OUT = ''\n"
            fallback = "[env]\nOMG_FIXTURE_OUT = { default = 'ready' }\n"
            env_file = "[env._]\nfile = 'fixture.env'\n"
            tool_file = "[env._]\nfile = { path = 'fixture.env', tools = true }\n"
            late_source = "[env._]\nsource = { path = 'source.sh', tools = true }\n"
            export_ready = ("source.sh", "export OMG_FIXTURE_OUT=ready\n")
            clear_value = ("source.sh", "unset OMG_FIXTURE_OUT\n")
            export_empty = ("source.sh", "export OMG_FIXTURE_OUT=''\n")
            env_ready = ("fixture.env", "OMG_FIXTURE_OUT=ready\n")
            expected_ready = {result_key: b"ready"}
            missing_value = "Required environment variable OMG_FIXTURE_OUT is not set"

            for label, value, error in [
                ("inherited-required-present", b"caller", None),
                ("inherited-required-opaque", raw, None),
                ("inherited-required-space", b" ", None),
                ("inherited-required-empty", b"", missing_value),
                ("inherited-required-missing", None, missing_value),
            ]:
                run(label, conf=required, env={result_key: value}, expected={result_key: value}, error=error)

            run("file-in-same-layer-satisfies-required", conf=required + env_file,
                files=(env_ready,), expected=expected_ready)
            run("late-file-in-same-layer-satisfies-required", conf=required + tool_file,
                files=(env_ready,), expected=expected_ready)
            run("source-in-same-layer-satisfies-required", conf=required + source_config,
                files=(export_ready,), expected=expected_ready)
            run("late-source-in-same-layer-satisfies-required", conf=required + late_source,
                files=(export_ready,), expected=expected_ready)
            run("same-layer-source-can-replace-required", conf=required + source_config,
                files=(export_ready,), env={result_key: b"caller"}, expected=expected_ready)
            run("same-layer-source-unsets-required", conf=required + source_config,
                files=(clear_value,), env={result_key: b"caller"}, error=missing_value)
            run("late-source-unsets-file-provided-required",
                conf=required + "[env._]\nfile = 'fixture.env'\nsource = { path = 'source.sh', tools = true }\n",
                files=(env_ready, clear_value), error=missing_value)
            run("same-layer-source-empties-required", conf=required + source_config,
                files=(export_empty,), env={result_key: b"caller"}, error=missing_value)
            run("missing-file-error-still-propagates", conf=required + env_file,
                error="Env file not found")
            run("failed-source-error-still-propagates", conf=required + source_config,
                files=(("source.sh", "return 7\n"),), error="failed while sourcing")

            run("child-assignment-satisfies-parent-required", conf=ready, parent_conf=required,
                expected=expected_ready)
            run("ancestor-value-satisfies-child-required", conf=required, parent_conf=ready,
                expected=expected_ready)
            run("child-default-satisfies-parent-required", conf=fallback, parent_conf=required,
                expected=expected_ready)
            run("child-file-satisfies-parent-required", conf=env_file, parent_conf=required,
                files=(env_ready,), expected=expected_ready)
            run("selective-layer-satisfies-required", conf=required, env={b"MISE_ENV": b"test"},
                files=(("mise.test.toml", ready),), expected=expected_ready)
            run("local-layer-satisfies-required", conf=required, files=(("mise.local.toml", ready),),
                expected=expected_ready)
            run("child-unset-overrides-required-inherited-value", conf=unset, parent_conf=required,
                env={result_key: b"caller"}, error=missing_value)
            run("selected-empty-override-fails-required", conf=required, env={
                    result_key: b"caller", b"MISE_ENV": b"test",
                }, files=(("mise.test.toml", empty),), error=missing_value)
            run("parent-source-unset-then-child-restores", conf=ready, parent_conf=required + source_config,
                parent_files=(clear_value,), env={result_key: b"caller"}, expected=expected_ready)
            run("child-source-can-satisfy-parent-and-child-required", conf=required + source_config,
                parent_conf=required, files=(export_ready,), expected=expected_ready)
            run("missing-required-keeps-first-declaration-order",
                parent_conf="[env]\nOMG_FIXTURE_RAW = { required = true }\n", conf=required,
                error="Required environment variable OMG_FIXTURE_RAW is not set")

            task_required = task + "[tasks.fixture.env]\nOMG_FIXTURE_OUT = { required = true }\n"
            task_value = task + "[tasks.fixture.env]\nOMG_FIXTURE_OUT = 'ready'\n"
            task_unset = task + "[tasks.fixture.env]\nOMG_FIXTURE_OUT = false\n"
            task_empty = task + "[tasks.fixture.env]\nOMG_FIXTURE_OUT = ''\n"
            run("task-value-satisfies-project-required", conf=required + task_value, native_task=True,
                expected=expected_ready)
            run("task-value-satisfies-ancestor-required", conf=task_value, parent_conf=required, native_task=True,
                expected=expected_ready)
            run("task-required-sees-project-assignment", conf=ready + task_required, native_task=True,
                expected=expected_ready)
            run("task-required-sees-local-source", conf=task_required + task_source, native_task=True,
                files=(export_ready,), expected=expected_ready)
            run("task-required-sees-local-file", conf=task_required + "[tasks.fixture.env._]\nfile = 'fixture.env'\n",
                native_task=True, files=(env_ready,), expected=expected_ready)
            run("task-local-source-satisfies-project-required", conf=required + task + task_source,
                native_task=True, files=(export_ready,), expected=expected_ready)
            run("task-unset-invalidates-project-required", conf=required + task_unset, native_task=True,
                env={result_key: b"caller"}, error=missing_value)
            run("task-empty-invalidates-project-required", conf=required + task_empty, native_task=True,
                env={result_key: b"caller"}, error=missing_value)
            run("task-required-fails-after-its-local-source-unsets", conf=ready + task_required + task_source,
                native_task=True, files=(clear_value,), error=missing_value)
            run("task-late-file-satisfies-required", conf=task_required +
                "[tasks.fixture.env._]\nfile = { path = 'fixture.env', tools = true }\n",
                native_task=True, files=(env_ready,), expected=expected_ready)
            run("unused-task-requirement-is-independent", conf=task +
                "[tasks.unused]\nrun = 'true'\nenv.OMG_FIXTURE_OUT = { required = true }\n",
                native_task=True, expected={result_key: None})


    def inspect_task_package_metadata():
        import ctypes
        import struct
        import time

        phase = "task-package-metadata"
        helper = runtime_advisory_fixture
        versions = {"node": ("24.22.3", "24.23.5"), "bun": ("1.2.20", "1.2.21")}
        with tempfile.TemporaryDirectory(prefix="task-package-metadata-", dir=work) as directory:
            home = Path(directory)
            os.chown(home, account.pw_uid, account.pw_gid)
            seed = """
import importlib.util, json, sys
from pathlib import Path
helper, home, definitions = sys.argv[1:]
spec = importlib.util.spec_from_file_location("runtime_advisory_fixture", helper)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
home = Path(home)
config = Path(fixture.fixture_cli_environment(home)["OMG_CONFIG_DIR"])
for name, versions in json.loads(definitions).items():
    for version in versions:
        root = home / "data" / "versions" / name / version
        executable = root / ("bin/node" if name == "node" else "bun")
        executable.parent.mkdir(parents=True)
        reported = "v" + version if name == "node" else version
        executable.write_text(f'''#!/bin/sh
if [ "$1" = --version ]; then
    printf '%s\\n' '{reported}'
    exit
fi
printf 'fixture package {name} {reported}'
for arg in "$@"; do printf '|<%s>' "$arg"; done
printf '\\n'
''')
        executable.chmod(0o755)
        fixture.seed_runtime_advisory_fixture(root, name, version, config)
bin_dir = home / "bin"
bin_dir.mkdir()
for manager in ("npm", "pnpm", "yarn"):
    executable = bin_dir / manager
    executable.write_text(f'''#!/bin/sh
version=$(node --version) || exit
printf 'fixture package {manager} %s' "$version"
for arg in "$@"; do printf '|<%s>' "$arg"; done
printf '\\n'
''')
    executable.chmod(0o755)
"""
            checked([sys.executable, "-I", "-B", "-c", seed, helper, home, json.dumps(versions)],
                    dict(disabled, HOME=str(home)), ordinary)
            env = dict(disabled, HOME=str(home), OMG_DATA_DIR=str(home/"data"),
                       OMG_CONFIG_DIR=str(home/"config"/"omg"), OMG_NATIVE_TEST_DATA_DIR="1",
                       XDG_CONFIG_HOME=str(home/"config"), XDG_DATA_HOME=str(home/"xdg-data"),
                       XDG_CACHE_HOME=str(home/"cache"), XDG_STATE_HOME=str(home/"state"),
                       PATH=f"{home/'bin'}:{base_env['PATH']}")
            libc = ctypes.CDLL(None, use_errno=True)
            libc.inotify_init1.argtypes = [ctypes.c_int]
            libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
            in_open, in_close_nowrite = 0x20, 0x10
            notice = struct.Struct("iIII")
            node, next_node = versions["node"]
            bun, next_bun = versions["bun"]
            script = {"fixture-js": "echo fixture"}
            task = """[tasks.fixture]
run = 'node "$@"'
"""
            provided = object()

            def encoded(manifest):
                return json.dumps(manifest) if isinstance(manifest, dict) else manifest

            def run(label, *, metadata=provided, parent=None, pins=(), markers=(), mise=None,
                    replacement=None, manager="npm", version=node, error=None, opens=2,
                    project_name="project", files=(), parent_files=(), writable=(), initial_args=()):
                outer = home / label
                outer.mkdir()
                project = outer / project_name
                project.mkdir()
                os.chown(project, account.pw_uid, account.pw_gid)
                manifest = project / "package.json"
                if metadata is provided:
                    metadata = {"engines": {"node": node, "bun": bun}, "scripts": script}
                if isinstance(metadata, dict):
                    metadata = {"scripts": script, **metadata}
                if metadata is not None:
                    manifest.write_text(encoded(metadata))
                if parent is not None:
                    (outer / "package.json").write_text(encoded(parent))
                for filename, value in pins:
                    (project / filename).write_text(value)
                for filename in markers:
                    (project / filename).touch()
                if mise is not None:
                    (project / "mise.toml").write_text(mise)
                if replacement is not None:
                    os.chown(manifest, account.pw_uid, account.pw_gid)
                    (project / "replacement.json").write_text(encoded(replacement))
                for root, items in ((project, files), (outer, parent_files)):
                    for filename, value in items:
                        (root / filename).write_text(value)
                for filename in writable:
                    os.chown(project / filename, account.pw_uid, account.pw_gid)
                fd = libc.inotify_init1(os.O_CLOEXEC | os.O_NONBLOCK)
                assert fd >= 0, ctypes.get_errno()
                try:
                    if metadata is not None:
                        watch_id = libc.inotify_add_watch(fd, os.fsencode(manifest), in_open | in_close_nowrite)
                        assert watch_id >= 0, (manifest, ctypes.get_errno())
                    args = [cli, "run", "fixture" if mise is not None else "fixture-js", "--", "two words", "--literal"]
                    started = time.monotonic_ns()
                    result = subprocess.run(args, cwd=project, env=env, stdin=subprocess.DEVNULL,
                                            capture_output=True, text=True, timeout=10, **ordinary)
                    elapsed_ns = time.monotonic_ns() - started
                    try:
                        events = os.read(fd, 65536)
                    except BlockingIOError:
                        events = b""
                    reads = offset = 0
                    while offset < len(events):
                        _, kind, _, length = notice.unpack_from(events, offset)
                        reads += bool(kind & in_open)
                        offset += notice.size + length
                    lines = [line for line in result.stdout.splitlines() if line.startswith("fixture package ")]
                    values = [*initial_args, "two words", "--literal"]
                    if mise is None:
                        values[:0] = ["run", "fixture-js"] + (["--"] if manager in ("npm", "pnpm", "yarn") else [])
                    reported = version if manager == "bun" else f"v{version}"
                    expected = f"fixture package {manager} {reported}" + "".join(f"|<{arg}>" for arg in values)
                    passed = (result.returncode != 0 and not lines and error in result.stderr) if error else (
                        result.returncode == 0 and lines == [expected] and (opens is None or reads == opens))
                    checks.append(dict(phase=phase, case=label, status=result.returncode, passed=passed,
                                       reported_reads=reads, expected_reads=opens, expected_output=expected,
                                       elapsed_ns=elapsed_ns, diagnostic=(result.stdout + result.stderr)[-1200:]))
                except subprocess.TimeoutExpired:
                    checks.append(dict(phase=phase, case=label, status=None, passed=False,
                                       diagnostic="package task did not finish"))
                finally:
                    os.close(fd)

            run("default-npm")
            run("engines-node-over-volta", metadata={"engines": {"node": node}, "volta": {"node": next_node}})
            run("volta-node", metadata={"volta": {"node": next_node}}, version=next_node)
            run("engines-bun-over-volta", metadata={"packageManager": "bun", "engines": {"bun": bun},
                                                   "volta": {"bun": next_bun}}, manager="bun", version=bun)
            run("volta-bun", metadata={"packageManager": "bun", "volta": {"bun": next_bun}},
                manager="bun", version=next_bun)
            run("independent-volta-fallback", metadata={"engines": {"bun": bun}, "volta": {"node": next_node}},
                version=next_node)
            run("trimmed-runtime-pin", metadata={"engines": {"node": f" {next_node} "}}, version=next_node)
            run("node-version-precedence", pins=((".node-version", next_node),), version=next_node)
            run("nvmrc-precedence", pins=((".nvmrc", next_node),), version=next_node)
            run("tool-versions-precedence", pins=((".tool-versions", f"nodejs {next_node}\n"),), version=next_node)
            run("bun-version-precedence", pins=((".bun-version", next_bun),),
                markers=("bun.lockb",), manager="bun", version=next_bun)
            run("manifest-precedes-same-directory-mise", mise=f"[tools]\nnode = '{next_node}'\n" + task,
                manager="node")
            run("child-package-over-parent", parent={"engines": {"node": next_node}})
            run("parent-pin-ignores-unrelated-fields", metadata={"packageManager": None},
                parent={"packageManager": False, "scripts": [], "engines": {"node": next_node}}, version=next_node)
            run("native-mise-without-manifest", metadata=None, mise=task, pins=((".node-version", node),),
                manager="node", opens=0)
            run("explicit-npm-before-bun", metadata={"packageManager": "npm@11.2.0", "engines": {"node": node}},
                markers=("bun.lockb",))
            run("explicit-pnpm", metadata={"packageManager": "pnpm@10.1.0", "engines": {"node": node}},
                manager="pnpm")
            run("explicit-yarn", metadata={"packageManager": "yarn@4.6.0", "engines": {"node": node}},
                markers=("pnpm-lock.yaml",), manager="yarn")
            run("explicit-bun", metadata={"packageManager": "bun@1.2.20", "engines": {"bun": bun}},
                markers=("yarn.lock",), manager="bun", version=bun)
            run("pnpm-lock", markers=("pnpm-lock.yaml",), manager="pnpm")
            run("yarn-lock", markers=("yarn.lock",), manager="yarn")
            run("pnpm-lock-over-yarn", markers=("pnpm-lock.yaml", "yarn.lock"), manager="pnpm")
            run("legacy-bun-lock-over-pnpm", markers=("bun.lockb", "pnpm-lock.yaml"), manager="bun", version=bun)
            run("text-bun-lock", markers=("bun.lock",), manager="bun", version=bun)
            run("text-bun-lock-over-pnpm", markers=("bun.lock", "pnpm-lock.yaml"), manager="bun", version=bun)
            run("explicit-npm-before-text-bun", metadata={"packageManager": "npm", "engines": {"node": node}},
                markers=("bun.lock",))
            run("malformed-syntax", metadata="{", error="Failed to parse", opens=None)
            run("malformed-engines", metadata={"engines": False}, error="Failed to parse", opens=None)
            run("malformed-volta", metadata={"volta": []}, error="Failed to parse", opens=None)
            run("malformed-scripts", metadata={"scripts": {"fixture-js": 1}}, error="Failed to parse", opens=None)
            run("malformed-manager", metadata={"packageManager": False}, error="Failed to parse", opens=None)
            run("native-mise-refreshes-after-dependency", manager="node", version=next_node, opens=None,
                mise=task + """depends = ["prepare"]
[tasks.prepare]
run = "cp replacement.json package.json"
""", metadata={"engines": {"node": node}},
                replacement={"engines": {"node": next_node}, "scripts": script})

            phase = "task-mise-runtime-coherence"
            run("overlapping-mise-pins-keep-nearest-precedence", metadata=None, manager="node", opens=0,
                project_name=".config", parent_files=((".node-version", node),), version=next_node,
                mise=f"[tools]\nnode = '{next_node}'\n" + task)
            graph = '''[tasks.fixture]
depends = ["prepare"]
run = 'node "$OMG_FIXTURE_OUT" "$OMG_FIXTURE_TASK" "$@"'
env.OMG_FIXTURE_TASK = "planned"
[tasks.prepare]
run = "cp next.toml mise.local.toml"
'''
            old_settings = f"[tools]\nnode = '{node}'\n[env]\nOMG_FIXTURE_OUT = 'older'\n"
            new_settings = f"[tools]\nnode = '{next_node}'\n[env]\nOMG_FIXTURE_OUT = 'ready'\n"
            new_settings += '''[tasks.fixture]
run = "node unexpected"
env.OMG_FIXTURE_TASK = "changed"
'''
            run("fresh-mise-pins-and-env-keep-planned-command", metadata=None, manager="node", opens=0,
                mise=graph, files=(("mise.local.toml", old_settings), ("next.toml", new_settings)),
                writable=("mise.local.toml",), initial_args=("ready", "planned"), version=next_node)


    def inspect_mise_task_execution():
        phase = "mise-task-execution"
        ok = "printf '%s\\n' 'fixture:target'"
        forbidden = "touch unexpected; printf '%s\\n' 'fixture:unexpected'"
        failed = 'Mise task "fixture" failed'

        def task(label, steps):
            value = json.dumps(steps, ensure_ascii=False)
            return f"[tasks.{label}]\nrun = {value}\n"

        def dependency(label, names, steps=None):
            return (task(label, steps) if steps is not None else f"[tasks.{label}]\n") + (
                "depends = " + json.dumps(names) + "\n")

        with tempfile.TemporaryDirectory(prefix="mise-task-execution-", dir=work) as directory:
            home = Path(directory)
            os.chown(home, account.pw_uid, account.pw_gid)
            env = dict(disabled, HOME=str(home), XDG_CONFIG_HOME=str(home/"config"),
                       XDG_DATA_HOME=str(home/"data"), XDG_CACHE_HOME=str(home/"cache"),
                       XDG_RUNTIME_DIR=str(home/"run"), XDG_STATE_HOME=str(home/"state"))
            (home / "run").mkdir(mode=0o700)
            os.chown(home / "run", account.pw_uid, account.pw_gid)

            def run(case, content, *, expected=(), error=None, parent=None, files=(),
                    args=(), name="fixture", overlay=None):
                outer = home / case
                outer.mkdir()
                project = outer / "project"
                project.mkdir()
                os.chown(project, account.pw_uid, account.pw_gid)
                if parent is not None:
                    (outer / "mise.toml").write_text(parent)
                (project / "mise.toml").write_text(content)
                launch = env
                if overlay is not None:
                    (project / "mise.test.toml").write_text(overlay)
                    launch = dict(env, MISE_ENV="test")
                for subdir in files:
                    path = project / subdir
                    path.mkdir(parents=True)
                    os.chown(path, account.pw_uid, account.pw_gid)
                result = subprocess.run([cli, "run", name, "--using", "mise", "--", *args],
                                        cwd=project, env=launch, stdin=subprocess.DEVNULL,
                                        text=True, capture_output=True, timeout=10, **ordinary)
                output = [line.removeprefix("fixture:") for line in result.stdout.splitlines()
                          if line.startswith("fixture:")]
                still_clean = not (project / "unexpected").exists() and not (outer / "unexpected").exists()
                status_ok = (result.returncode == 0 if error is None else
                             result.returncode != 0 and error in result.stderr)
                checks.append(dict(phase=phase, case=case, status=result.returncode,
                                   passed=(status_ok and output == list(expected) and still_clean),
                                   output=output, expected_output=list(expected), unexpected_write=not still_clean,
                                   diagnostic=(result.stdout + result.stderr)[-1000:]))

            for label, steps, output in [
                ("single-multiline-failure", "false\n" + forbidden, ()),
                ("single-semicolon-failure", "false; " + forbidden, ()),
                ("single-shell-group-failure", "{ false; " + forbidden + "; }", ()),
                ("single-function-failure", "step() { return 7; }\nstep\n" + forbidden, ()),
                ("single-subshell-failure", "(exit 9)\n" + forbidden, ()),
                ("single-pipeline-failure", "true | false\n" + forbidden, ()),
                ("first-array-step-failure", ["false\n" + forbidden, forbidden], ()),
                ("middle-array-step-failure", [ok, "false\n" + forbidden, forbidden], ("target",)),
                ("last-array-step-failure", [ok, "false\n" + forbidden], ("target",)),
                ("explicit-exit-failure", ["exit 27", forbidden], ()),
                ("array-short-circuit-status", ["false && true", forbidden], ()),
                ("array-errexit-disabled-status", ["set +e\nfalse", forbidden], ()),
            ]:
                run(label, task("fixture", steps), expected=output, error=failed)

            for label, steps in [
                ("explicit-recovery", "false || true\n" + ok),
                ("conditional-test", "if false; then " + forbidden + "; else " + ok + "; fi"),
                ("negated-command", "! false\n" + ok),
                ("pipeline-last-command-wins", "false | true\n" + ok),
                ("early-short-circuit-is-handled", "false && { " + forbidden + "; }\n" + ok),
                ("explicit-errexit-opt-out", "set +e\nfalse\n" + ok),
                ("empty-array-entry", ["", ok]),
                ("comment-array-entry", ["# explicit no-op", ok]),
            ]:
                run(label, task("fixture", steps), expected=("target",))

            run("comment-only-task", task("fixture", "# no work"))
            run("explicit-successful-exit", task("fixture", ["exit 0", forbidden]))

            setup = task("setup", "printf 'fixture:setup:%s:%s\\n' \"$#\" \"${TASK_LOCAL-unset}\"")
            left = dependency("left", "setup", "printf '%s\\n' 'fixture:left'")
            right = dependency("right", ["setup"], "printf '%s\\n' 'fixture:right'")
            run("diamond-with-args-only-on-root",
                setup + left + right + dependency("fixture", ["left", "right"],
                    "printf 'fixture:args:%s:%s:%s\\n' \"$0\" \"$1\" \"$2\"") +
                    "env.TASK_LOCAL = 'root-only'\n",
                expected=("setup:0:unset", "left", "right", "args:fixture:two words:--literal"),
                args=("two words", "--literal"))
            run("dependency-only-root", setup + left + right + dependency("fixture", ["right", "left"]),
                expected=("setup:0:unset", "right", "left"))
            run("repeated-direct-dependency", setup + dependency("fixture", ["setup", "setup"], ok),
                expected=("setup:0:unset", "target"))
            run("array-shares-shell-state", task("fixture", [
                    "export TASK_LOCAL=kept; cd child", "printf 'fixture:%s:%s\\n' \"$TASK_LOCAL\" \"${PWD##*/}\"",
                ]), expected=("kept:child",), files=("child",))
            run("parent-declaring-root",
                "", parent=task("fixture", "printf 'fixture:%s\\n' \"${PWD##*/}\""),
                expected=("parent-declaring-root",))
            run("dependency-creates-target-directory",
                task("setup", "mkdir built") + dependency("fixture", ["setup"],
                    "printf 'fixture:%s\\n' \"${PWD##*/}\"") + "dir = 'built'\n",
                expected=("built",))
            run("selected-task-replaces-whole-declaration",
                dependency("fixture", ["missing"], forbidden) + "env.TASK_LOCAL = 'older'\n",
                overlay=task("fixture", "printf 'fixture:%s\\n' \"${TASK_LOCAL-unset}\""),
                expected=("unset",))
            run("colon-task-name", '[tasks."fixture:colon"]\nrun = ' + json.dumps(ok) + "\n",
                name="fixture:colon", expected=("target",))
            run("missing-dependency-invalidates-whole-graph",
                task("setup", forbidden) + dependency("fixture", ["setup", "absent"], forbidden),
                error="Missing mise task dependency: absent")
            run("cycle-invalidates-whole-graph",
                task("setup", forbidden) + dependency("other", "fixture", forbidden) +
                dependency("fixture", ["setup", "other"], forbidden),
                error="Mise task dependency cycle at fixture")
            run("failed-dependency-stops-dependent",
                task("setup", "false\n" + forbidden) + dependency("fixture", ["setup"], forbidden),
                error='Mise task "setup" failed')
            run("invalid-later-shell-syntax-runs-no-step", task("fixture", [forbidden, "if"]),
                error=failed)
            run("unsupported-task-property-invalidates-graph",
                task("setup", forbidden) + dependency("fixture", "setup", forbidden) + "shell = 'sh -c'\n",
                error="Unsupported mise task property: shell")
            run("invalid-dependency-shape-runs-no-task",
                task("setup", forbidden) + dependency("fixture", ["setup", "different task"], forbidden),
                error="expected a plain task name")


    def inspect_environment_lockfiles():
        phase = "environment-lockfiles"
        with tempfile.TemporaryDirectory(prefix="environment-locks-", dir=work) as directory:
            here = Path(directory)
            os.chown(here, account.pw_uid, account.pw_gid)
            isolated = dict(disabled, HOME=str(here), XDG_DATA_HOME=str(here/"data"),
                            XDG_CONFIG_HOME=str(here/"config"), XDG_CACHE_HOME=str(here/"cache"),
                            XDG_STATE_HOME=str(here/"state"))
            lock = here / "omg.lock"
            native = sorted(set(checked([dnf, "--cacheonly", "--setopt=disable_excludes=*",
                                         "repoquery", "--userinstalled", "--qf", r"%{name}\n"],
                                        isolated, ordinary).splitlines()))
            assert len(native) >= 2

            def checksum(packages, runtimes):
                canonical = "".join(f"{name}:{version};" for name, version in sorted(runtimes.items()))
                canonical += "".join(f"{name};" for name in sorted({p.strip() for p in packages if p.strip()}))
                return hashlib.sha256(canonical.encode()).hexdigest()

            def body(packages, runtimes=None, schema="1", digest=None, timestamp=1_700_000_000):
                runtimes = runtimes or {}
                digest = digest if digest is not None else checksum(packages, runtimes)
                prefix = "" if schema is None else f"schema_version = {schema}\n"
                rows = [f"packages = {json.dumps(packages, ensure_ascii=False)}",
                        f"timestamp = {timestamp}", f"hash = {json.dumps(digest)}", "[runtimes]"]
                rows.extend(f"{json.dumps(name)} = {json.dumps(version)}" for name, version in runtimes.items())
                return prefix + "\n".join((*rows, ""))

            def run(label, args, markers=(), *, fails=False, inspect=None, forbidden=()):
                result = command([cli, *args], isolated, ordinary)
                text = result.stdout + result.stderr
                try:
                    matches = (
                        (result.returncode != 0) == fails
                        and all(marker in text for marker in markers)
                        and all(marker not in text for marker in forbidden)
                        and (inspect is None or inspect(result))
                    )
                except (OSError, ValueError, KeyError, TypeError):
                    matches = False
                checks.append(dict(phase=phase, case=label, passed=matches, status=result.returncode,
                                   diagnostic=text[-1200:]))

            def captured(_):
                state = tomllib.loads(lock.read_text())
                return (state["schema_version"] == 1 and state["packages"] == native
                        and state["hash"] == checksum(state["packages"], state["runtimes"])
                        and lock.stat().st_mode & 0o777 == 0o600)

            def exported(result):
                state = tomllib.loads(result.stdout)["environment"]
                return (state["schema_version"] == 1
                        and state["packages"]["fedora-x86_64"] == {name: name for name in native})

            def team_state(in_sync):
                status = json.loads((here/".omg/team-status.json").read_text())
                member, = status["members"]
                return (member["in_sync"] == in_sync and
                        (member["drift_summary"] is None) == in_sync)

            run("capture", ("env", "capture"), ("Environment state captured",), inspect=captured)
            original = lock.read_text()
            original_hash = tomllib.loads(original)["hash"]
            run("check-capture", ("env", "check"), ("Environment is in sync",))
            run("ci-capture", ("ci", "validate"), ("Environment matches omg.lock",))
            run("export-capture", ("env", "export", "--source-target", "fedora-x86_64"), inspect=exported)
            run("diff-current", ("diff", "omg.lock"), ("Environments are identical",))
            run("diff-self", ("diff", "--from", "omg.lock", "omg.lock"), ("Environments are identical",))
            run("recapture", ("env", "capture"), ("Environment state captured",),
                inspect=lambda result: captured(result) and tomllib.loads(lock.read_text())["hash"] == original_hash)

            runtimes = tomllib.loads(original)["runtimes"]
            legacy = body(native, runtimes, schema=None)
            lock.write_text(legacy)
            run("check-unversioned", ("env", "check"), ("Environment is in sync",))
            run("ci-unversioned", ("ci", "validate"), ("Environment matches omg.lock",))
            (here/"captured.lock").write_text(original)
            run("diff-unversioned", ("diff", "--from", "omg.lock", "captured.lock"), ("Environments are identical",))
            reordered = body([" " + item + " " for item in reversed(native)] + [native[0]], runtimes)
            lock.write_text(reordered)
            run("check-normalized", ("env", "check"), ("Environment is in sync",))
            run("ci-normalized", ("ci", "validate"), ("Environment matches omg.lock",))

            lock.write_text(body([*native, "fixture-expected-package"], runtimes))
            run("ci-real-drift", ("ci", "validate"), ("Environment drift detected",), fails=True)
            run("check-real-drift", ("env", "check"), ("Environment drift detected", "fixture-expected-package"),
                fails=True)
            lock.write_text(original)
            run("team-init", ("team", "init", "fixture/fedora"), ("fixture/fedora",),
                inspect=lambda _: (here/".omg/team.toml").is_file())
            run("team-matches", ("team", "status"), inspect=lambda _: team_state(True))

            (here/"two.lock").write_text(body(["fixture-a", "fixture-b"]))
            (here/"one.lock").write_text(body(["fixture-a;fixture-b"]))
            run("diff-checksum-equal-inventories-differ", ("diff", "--from", "two.lock", "one.lock"),
                ("Package differences", "1 packages added", "2 packages removed"),
                forbidden=("Environments are identical",))
            run("diff-checksum-equal-reversed", ("diff", "--from", "one.lock", "two.lock"),
                ("Package differences", "2 packages added", "1 packages removed"),
                forbidden=("Environments are identical",))
            joined = [";".join(native[:2]), *native[2:]]
            assert checksum(joined, runtimes) == original_hash
            lock.write_text(body(joined, runtimes))
            run("diff-checksum-equal-current", ("diff", "omg.lock"), ("Package differences",),
                forbidden=("Environments are identical",))
            run("ci-checksum-equal-current", ("ci", "validate"), ("Environment drift detected",), fails=True)
            run("team-checksum-equal-current", ("team", "status"), inspect=lambda _: team_state(False))
            run("check-checksum-equal-current", ("env", "check"), ("Environment drift detected",), fails=True)

            (here/"runtime.lock").write_text(body([], {"fixture": "17"}))
            (here/"native.lock").write_text(body(["fixture:17"]))
            run("diff-checksum-equal-runtime-versus-package", ("diff", "--from", "runtime.lock", "native.lock"),
                ("Runtime differences", "Package differences"), forbidden=("Environments are identical",))
            (here/"plain.lock").write_text(body([]))
            (here/"control.lock").write_text(body(["fixture-package\ncontinued"]))
            run("diff-sanitizes-package-row", ("diff", "--from", "plain.lock", "control.lock"),
                ("fixture-package", "continued"), forbidden=("fixture-package\ncontinued",))
            (here/"control.lock").write_text(body([], {"fixture-runtime": "v1\ncontinued"}))
            run("diff-sanitizes-runtime-row", ("diff", "--from", "plain.lock", "control.lock"),
                ("fixture-runtime", "continued"), forbidden=("v1\ncontinued",))

            lock.unlink()
            run("missing-env", ("env", "check"), ("No omg.lock file found",), fails=True)
            run("missing-ci", ("ci", "validate"), ("No omg.lock found",), fails=True)
            run("missing-export", ("env", "export", "--source-target", "fedora-x86_64"),
                ("Failed to inspect lockfile",), fails=True)
            lock.write_text("packages = [\n")
            run("invalid-toml", ("env", "check"), ("Failed to parse lockfile",), fails=True)
            lock.write_bytes(b"\xff\xfe")
            run("invalid-utf8", ("env", "check"), ("Lockfile is not UTF-8",), fails=True)
            lock.write_text(body(native, runtimes, digest="0" * 64))
            run("incorrect-checksum", ("env", "check"), ("Lockfile integrity check failed",), fails=True)
            lock.write_text(body(native, runtimes, schema="99"))
            run("future-schema", ("env", "check"), ("newer omg", "99"), fails=True)
            lock.write_text("schema_version = 99\nfuture = true\n")
            run("future-schema-different-layout", ("env", "check"), ("newer omg", "99"), fails=True)
            lock.write_text(body(native, runtimes, schema='"1"'))
            run("wrong-schema-type", ("env", "check"), ("Failed to parse lockfile",), fails=True)
            lock.unlink()
            lock.symlink_to("captured.lock")
            run("symlink-lock", ("env", "check"), ("not a regular file",), fails=True)
            lock.unlink()
            lock.mkdir()
            run("directory-lock", ("env", "check"), ("not a regular file",), fails=True)

    def inspect_artifact_signature_inputs():
        phase = "artifact-signature-inputs"
        identity_args = ("--certificate-identity", "signer@example.invalid")
        issuer_args = ("--certificate-oidc-issuer", "https://issuer.example.invalid")
        network_failure = "Failed to query Rekor"
        not_regular = "not a regular file"

        with tempfile.TemporaryDirectory(prefix="artifact-signature-", dir=work) as directory:
            scope = Path(directory)
            scope.chmod(0o755)
            invocation = dict(disabled, HOME=str(scope), HTTPS_PROXY="http://127.0.0.1:1", NO_PROXY="")

            def run(label, artifact, expected, *, signer=identity_args, issuer=issuer_args, help_only=False):
                if help_only:
                    args = [cli, "audit", "slsa", "--help"]
                else:
                    args = [cli, "audit", "slsa"]
                    if artifact is not None:
                        args.append(artifact)
                    args.extend((*signer, *issuer))
                try:
                    result = command(args, invocation, ordinary, timeout=2)
                except subprocess.TimeoutExpired:
                    checks.append(dict(phase=phase, case=label, passed=False, status=None,
                                       diagnostic="command exceeded its local input deadline"))
                    return

                combined = result.stdout + result.stderr
                reached_request = network_failure in combined
                unverified = "Artifact signature verified" not in result.stdout
                passed = (
                    (result.returncode == 0 if help_only else result.returncode != 0)
                    and expected in combined
                    and reached_request == (expected == network_failure)
                    and unverified
                )
                checks.append(dict(phase=phase, case=label, passed=passed,
                                   status=result.returncode, diagnostic=combined[-1000:]))

            for size in (0, 1, 8191, 8192, 8193, 65535, 65536, 65537):
                name = f"payload-{size}.rpm"
                (scope / name).write_bytes((b"\x00\xef\xfd\n" * (size // 4 + 1))[:size])
                run(f"regular-{size}-bytes", name, network_failure)
            target = scope / "payload-1.rpm"
            nested = scope / "nested"
            nested.mkdir()
            (nested / "package.rpm").write_bytes(b"nested fixture")
            run("nested-file", "nested/package.rpm", network_failure)
            run("dot-prefixed-file", "./payload-1.rpm", network_failure)
            (scope / "linked.rpm").symlink_to(target.name)
            run("file-symlink", "linked.rpm", network_failure)
            (scope / "café.rpm").write_bytes(b"utf-8 path fixture")
            run("utf8-filename", "café.rpm", network_failure)

            run("missing-file", "missing.rpm", "File not found")
            run("absolute-path", str(target), "Absolute paths not allowed")
            run("parent-path", "../missing.rpm", "Path traversal detected")
            run("empty-path", "", "Path cannot be empty")
            run("repeated-slash", "nested//package.rpm", "Suspicious path pattern")
            run("trailing-slash-on-file", "payload-1.rpm/", "File not found")
            run("overlong-path", "a" * 4097, "Path too long")
            (scope / "dangling.rpm").symlink_to("missing.rpm")
            run("dangling-symlink", "dangling.rpm", "File not found")

            run("directory", "nested", not_regular)
            run("working-directory", ".", not_regular)
            (scope / "directory-link").symlink_to("nested", target_is_directory=True)
            run("directory-symlink", "directory-link", not_regular)
            os.mkfifo(scope / "artifact.pipe")
            run("fifo", "artifact.pipe", not_regular)
            (scope / "fifo-link").symlink_to("artifact.pipe")
            run("fifo-symlink", "fifo-link", not_regular)
            # Bound to a short relative name to stay within the Unix socket path limit.
            sock_path = scope / "input.sock"
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(sock_path))
                run("socket", "input.sock", not_regular)
                (scope / "socket-link").symlink_to("input.sock")
                run("socket-symlink", "socket-link", not_regular)
            unreadable = scope / "unreadable.rpm"
            unreadable.write_bytes(b"owned fixture")
            unreadable.chmod(0)
            run("unreadable-file", unreadable.name, "Permission denied")

            run("missing-artifact-argument", None, "<PACKAGE>")
            run("missing-signer-argument", target.name, "--certificate-identity", signer=())
            run("missing-issuer-argument", target.name, "--certificate-oidc-issuer", issuer=())
            run("blank-signer", target.name, "An exact --certificate-identity is required",
                signer=("--certificate-identity", " \t "))
            run("blank-issuer", target.name, "An exact --certificate-oidc-issuer is required",
                issuer=("--certificate-oidc-issuer", " \t "))
            run("help", None, "Verify an artifact signature against a trusted Sigstore identity", help_only=True)
            run("empty-signer", target.name, "An exact --certificate-identity is required",
                signer=("--certificate-identity", ""))
            run("empty-issuer", target.name, "An exact --certificate-oidc-issuer is required",
                issuer=("--certificate-oidc-issuer", ""))

    def inspect_secret_scan():
        phase = "secret-scan"
        with tempfile.TemporaryDirectory(prefix="secret-scan-", dir=work) as directory:
            scope = Path(directory)
            scope.chmod(0o755)
            pem = "-----BEGIN PRIVATE KEY-----"
            another_pem = "-----BEGIN ENCRYPTED PRIVATE KEY-----"
            high_token = "npm_" + "Qw7gTR1c5p" * 3 + "B9xNK2"
            other_high_token = "npm_" + "kcR4pW9s8m" * 3 + "TX1uz7"
            medium_line = "password = 'fixture-value-one'"
            other_medium_line = "password = 'fixture-value-two'"
            placeholder = "password = 'placeholder_for_example'"
            labels = ("CRITICAL", "HIGH", "MEDIUM")

            def write(name, text):
                path = scope / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(text if isinstance(text, bytes) else text.encode())
                return path

            def run(label, path=None, *, counts=None, lines=(), arguments=(),
                    error=None, cwd=None, hidden=(), message=None):
                command_env = dict(disabled, HOME=str(cwd)) if cwd else disabled
                args = [cli, "audit", "secrets", *arguments]
                if path is not None:
                    args.extend(("--path", path))
                result = command(args, command_env, ordinary)
                output = result.stdout
                combined = output + result.stderr
                if error is not None:
                    passed = (result.returncode != 0 and error.lower() in combined.lower()
                              and "No secrets detected" not in output)
                elif counts is None:
                    passed = result.returncode == 0 and message in output
                elif not sum(counts):
                    passed = result.returncode == 0 and "No secrets detected." in output
                else:
                    critical = counts[0]
                    summary = dict(zip(labels, counts, strict=True))
                    breakdown = {name: int(count) for count, name
                                 in re.findall(r"(?m)^\s*● (\d+) (CRITICAL|HIGH|MEDIUM)\s*$", output)}
                    finding_lines = re.findall(r"(?m)^\s*\[(?:CRITICAL|HIGH|MEDIUM)\].*:(\d+)\s*$", output)
                    overflow = max(sum(counts) - 20, 0)
                    passed = (
                        (result.returncode != 0) == bool(critical)
                        and (f"{critical} critical secret finding(s) require remediation" in combined) == bool(critical)
                        and f"Found {sum(counts)} potential secrets:" in output
                        and breakdown == {name: count for name, count in summary.items() if count}
                        and len(finding_lines) == min(sum(counts), 20)
                        and (not lines or list(map(int, finding_lines)) == list(lines))
                        and (f"... and {overflow} more" in output if overflow else "... and " not in output)
                    )
                checks.append(dict(phase=phase, case=label,
                                   passed=passed and all(value not in combined for value in hidden),
                                   status=result.returncode, diagnostic=combined[-1000:]))

            run("clean-file", write("clean.txt", "no credentials here"), counts=(0, 0, 0))
            default = write("default/file.txt", "no credentials here").parent
            run("clean-default-directory", cwd=default, counts=(0, 0, 0))
            run("empty-file", write("empty.txt", ""), counts=(0, 0, 0))
            run("single-high", write("high.txt", high_token), counts=(0, 1, 0), lines=(1,),
                hidden=(high_token,))
            run("single-critical", write("critical.txt", pem), counts=(1, 0, 0), lines=(1,), hidden=(pem,))
            run("mixed-severities", write("mixed.txt", "\n".join((pem, high_token, medium_line))),
                counts=(1, 1, 1), lines=(1, 2, 3), hidden=(pem, high_token, "fixture-value-one"))

            run("same-line-critical", write("critical-line.txt", f"{pem} {another_pem}"),
                counts=(2, 0, 0), lines=(1, 1))
            run("same-line-high", write("high-line.txt", f"{high_token}, {other_high_token}"),
                counts=(0, 2, 0), lines=(1, 1), hidden=(high_token, other_high_token))
            run("same-line-medium", write("medium-line.txt", f"{medium_line}; {other_medium_line}"),
                counts=(0, 0, 2), lines=(1, 1))
            run("placeholder-before-finding", write("placeholder-first.txt", f"{placeholder}; {medium_line}"),
                counts=(0, 0, 1), lines=(1,))
            run("placeholder-after-finding", write("placeholder-last.txt", f"{medium_line}; {placeholder}"),
                counts=(0, 0, 1), lines=(1,))
            run("distinct-patterns-same-line", write("multiple-patterns.txt", f"{medium_line}; {high_token}; {pem}"),
                counts=(1, 1, 1), lines=(1, 1, 1), hidden=(pem, high_token))
            run("separate-lines", write("separate-lines.txt", f"{pem}\nplain\n{another_pem}\n"),
                counts=(2, 0, 0), lines=(1, 3))
            run("repeated-credential-occurrences", write("repeat.txt", f"{medium_line}; {medium_line}"),
                counts=(0, 0, 2), lines=(1, 1))

            run("twenty-visible", write("twenty.txt", (medium_line + "\n") * 20),
                counts=(0, 0, 20), lines=range(1, 21))
            run("twenty-one-overflow", write("twenty-one.txt", (medium_line + "\n") * 21),
                counts=(0, 0, 21), lines=range(1, 21))
            run("many-critical-same-line", write("many-critical.txt", (pem + " ") * 25),
                counts=(25, 0, 0), lines=[1] * 20, hidden=(pem,))
            run("critical-after-display-limit", write("hidden-critical.txt", (medium_line + "\n") * 20 + pem),
                counts=(1, 0, 20), lines=range(1, 21), hidden=(pem,))
            unicode_value = "áéb四五六七八九十"
            run("multibyte-redaction", write("unicode.txt", f"password = '{unicode_value}'"),
                counts=(0, 0, 1), lines=(1,), hidden=(unicode_value,))
            run("placeholder-only", write("placeholder.txt", placeholder), counts=(0, 0, 0))

            file_limit = 10 * 1024 * 1024
            boundary = write("boundary.txt", " " * (file_limit - len(pem) - 1) + "\n" + pem)
            run("exact-file-limit", boundary, counts=(1, 0, 0), lines=(2,))
            with boundary.open("ab") as file:
                file.write(b"\n")
            run("above-file-limit", boundary, error="exceeds the maximum secret-scan size")
            run("invalid-utf8-file", write("non-utf8.txt", b"\xff\xfe"), error="failed to read")
            unreadable = write("unreadable.txt", pem)
            unreadable.chmod(0)
            run("unreadable-file", unreadable, error="permission denied")
            fifo = scope / "stream.txt"
            os.mkfifo(fifo)
            run("fifo-refused", fifo, error="not a directory")
            run("missing-path", scope / "missing.txt", error="no such file or directory")

            recursive = write("recursive/sub/deeper/find.txt", medium_line).parents[2]
            run("nested-file", recursive, counts=(0, 0, 1), lines=(1,))
            excluded = write("excluded/target/sample.txt", pem).parents[1]
            write("excluded/node_modules/sample.txt", pem)
            write("excluded/.git/sample.txt", pem)
            run("skip-excluded-directories", excluded, counts=(0, 0, 0))
            material = write("materials/id_ed25519", pem).parent
            run("extensionless-key", material, counts=(1, 0, 0), lines=(1,))
            symlinks = scope / "symlinks"
            symlinks.mkdir()
            linked_file = symlinks / "example.txt"
            linked_file.symlink_to(scope / "critical.txt")
            run("skip-child-file-symlink", symlinks, counts=(0, 0, 0))
            linked_dir = symlinks / "examples"
            linked_dir.symlink_to(material, target_is_directory=True)
            run("skip-child-directory-symlink", symlinks, counts=(0, 0, 0))
            run("refuse-directory-symlink-root", linked_dir, error="not a directory")

            run("refuse-file-symlink-root", linked_file, error="not a regular file")
            dangling = scope / "dangling.txt"
            dangling.symlink_to(scope / "missing.txt")
            run("dangling-symlink", dangling, error="not a directory")
            run("path-value-required", arguments=("--path",), error="a value is required")
            run("help", arguments=("--help",), message="Scan for leaked secrets and credentials")

    def inspect_daemon_audit_recovery():
        layouts = ("healthy", "archive-only", "damaged", "missing-hash", "marked-damaged", "damaged-with-archive")

        def record(layout, label, result, passed):
            checks.append(dict(phase="daemon-audit-recovery", case=f"{layout}-{label}",
                               passed=passed, status=result.returncode,
                               diagnostic=(result.stdout + result.stderr)[-1000:]))

        def verified(result, count):
            return (result.returncode == 0 and "Local audit chain consistency verified" in result.stdout
                    and f"Total: {count} entries" in result.stdout and f"Valid: {count} entries" in result.stdout)

        for layout in layouts:
            home = Path(tempfile.mkdtemp(prefix=f"audit-recovery-{layout}-", dir=work))
            os.chown(home, account.pw_uid, account.pw_gid)
            run = home / "run"
            data = home / "data"
            directory = data / "audit"
            for path in (run, data, directory):
                path.mkdir(mode=0o700)
                os.chown(path, account.pw_uid, account.pw_gid)
            audit = directory / "audit.jsonl"
            marker = directory / "incomplete"
            entries = audit_fixture_segment("recover", 2)
            archive = directory / "audit.jsonl.1"
            with_archive = layout in ("archive-only", "damaged-with-archive")
            if with_archive:
                write_audit_fixture_segment(archive, entries)
            if layout != "archive-only":
                if layout == "missing-hash":
                    entries[-1].pop("hash")
                write_audit_fixture_segment(audit, entries)
                if layout in ("damaged", "marked-damaged", "damaged-with-archive"):
                    with audit.open("ab") as file:
                        file.write(b"{unfinished event\n")
            if layout == "marked-damaged":
                marker.write_bytes(b"existing loss marker\n")
                marker.chmod(0o600)
                os.chown(marker, account.pw_uid, account.pw_gid)
            mode = dict(env, HOME=str(home), XDG_RUNTIME_DIR=str(run), OMG_SOCKET_PATH=str(run / "omg.sock"),
                        OMG_DATA_DIR=str(data), OMG_DAEMON_DATA_DIR=str(data))
            direct = dict(mode, OMG_DISABLE_DAEMON="1")
            needs_recovery = layout not in ("healthy", "archive-only")
            before = audit.read_bytes() if audit.exists() else None
            original_archive = archive.read_bytes() if archive.exists() else None
            original_marker = marker.read_bytes() if marker.exists() else None
            initial = command([cli, "audit", "verify"], direct, ordinary)
            if needs_recovery:
                expected = {"missing-hash": "missing hash", "marked-damaged": "Audit collection is incomplete"}
                before_ok = initial.returncode == 1 and expected.get(layout, "Corrupt audit log") in initial.stderr
            else:
                before_ok = verified(initial, 2)
            record(layout, "verify-before", initial, before_ok)
            initial = command([cli, "audit", "log", "--limit", "0"], direct, ordinary)
            if needs_recovery:
                error = "missing hash" if layout == "missing-hash" else "Corrupt audit log"
                before_ok = initial.returncode == 1 and error in initial.stderr
            else:
                before_ok = initial.returncode == 0 and "No audit entries found." in initial.stdout
            record(layout, "read-before", initial, before_ok)

            def scan_written():
                return audit.is_file() and b'"event_type":"security_audit"' in audit.read_bytes()

            with (home / "daemon-output").open("w+") as log:
                with subprocess.Popen([server], cwd=home, env=mode, stdout=log, stderr=subprocess.STDOUT,
                                      stdin=subprocess.DEVNULL, **ordinary) as process:
                    try:
                        wait_for(lambda: (run / "omg.status").exists()
                                 and (data / "status-cache.json").exists() and scan_written(), process)
                        assert stat.S_ISSOCK((run / "omg.sock").stat().st_mode)
                        result = command([cli, "metrics"], mode, ordinary)
                        record(layout, "live-daemon", result, result.returncode == 0
                               and re.search(r"(?m)^omg_requests_total [0-9]+$", result.stdout) is not None)
                    except Exception as error:
                        log.seek(0)
                        raise AssertionError((layout, log.read()[-2500:])) from error
                    finally:
                        if process.poll() is None:
                            process.send_signal(signal.SIGTERM)
                            try:
                                process.wait(8)
                            except subprocess.TimeoutExpired:
                                process.kill()
                                process.wait(4)
                log.seek(0)
                assert process.returncode == 0, (layout, process.returncode, log.read()[-2500:])

            quarantined = sorted(directory.glob("audit.jsonl.corrupt-*"))
            active_bytes = audit.read_bytes()
            active_rows = [json.loads(row) for row in active_bytes.splitlines()]
            if needs_recovery:
                assert len(quarantined) == 1 and quarantined[0].read_bytes() == before
                assert marker.is_file() and stat.S_IMODE(marker.stat().st_mode) == 0o600
                if original_marker is not None:
                    assert marker.read_bytes() == original_marker
            else:
                assert not quarantined and not marker.exists()
            if layout == "healthy":
                assert active_bytes.startswith(before) and active_rows[:2] == entries
                scans = active_rows[2:]
            else:
                assert active_rows[0]["prev_hash"] == "genesis"
                scans = active_rows
            assert scans and all(row["event_type"] == "security_audit" for row in scans)
            assert (archive.read_bytes() if archive.exists() else None) == original_archive

            result = command([cli, "audit", "verify"], direct, ordinary)
            verify_ok = (result.returncode == 1 and "Audit collection is incomplete" in result.stderr
                         if needs_recovery else verified(result, len(active_rows) + (2 if with_archive else 0)))
            record(layout, "verify-recovered", result, verify_ok)
            result = command([cli, "audit", "log", "--limit", "1"], direct, ordinary)
            record(layout, "read-recovered", result, result.returncode == 0
                   and active_rows[-1]["description"] in result.stdout and "SecurityAudit" in result.stdout)
            export = home / "audit.json"
            result = command([cli, "audit", "log", "--limit", "1", "--export", export], direct, ordinary)
            record(layout, "export-recovered", result, result.returncode == 0 and export.is_file()
                   and stat.S_IMODE(export.stat().st_mode) == 0o600
                   and json.loads(export.read_text()) == active_rows[-1:])

    def inspect_audit_record_windows():
        phases = ("short", "large", "long-record", "crlf", "separator-window", "missing-hash")
        cases = (
            ("text-one", ["log", "--limit", "1"], 1, None, False),
            ("text-recent", ["log"], 20, None, False),
            ("text-error", ["log", "--severity", "error", "--limit", "2"], 2, "error", False),
            ("json-one", ["log", "--limit", "1"], 1, None, True),
            ("json-error", ["log", "--severity", "error", "--limit", "2"], 2, "error", True),
            ("verify", ["verify"], 0, None, False),
        )
        for phase in phases:
            data = Path(tempfile.mkdtemp(prefix=f"audit-record-window-{phase}-", dir=work))
            os.chown(data, account.pw_uid, account.pw_gid)
            directory = data / "audit"
            directory.mkdir(mode=0o700)
            os.chown(directory, account.pw_uid, account.pw_gid)
            active = directory / "audit.jsonl"
            count = 24 if phase in ("large", "crlf") else 4
            severities = ["error" if index % 3 == 1 else "info" for index in range(count)]
            entries = audit_fixture_segment("window", count, severities=severities,
                                            description_size=4000 if phase == "long-record" else 0)
            if phase == "missing-hash":
                del entries[-1]["hash"]
            write_audit_fixture_segment(active, entries)
            if phase == "crlf":
                active.write_bytes(active.read_bytes().replace(b"\n", b"\r\n"))
            if phase == "separator-window":
                with active.open("ab") as file:
                    file.write(b"\n" * (128 * 1024 + 12))
            before = active.read_bytes()
            if phase == "short":
                assert len(before) < 4096
            elif phase in ("large", "long-record", "crlf"):
                assert 4096 < len(before) < 128 * 1024
            if phase == "long-record":
                assert len(before.splitlines()[-1]) > 4096
            mode = dict(disabled, OMG_DATA_DIR=str(data))
            rejected = {"separator-window": "trailing audit entry exceeds",
                        "missing-hash": "missing hash"}
            for label, args, limit, severity, exported in cases:
                output = data / f"{label}.json"
                result = command([cli, "audit", *args, *(["--export", output] if exported else [])], mode, ordinary)
                if phase in rejected:
                    passed = (result.returncode == 1 and rejected[phase] in result.stderr
                              and "Local audit chain consistency verified" not in result.stdout
                              and "No audit entries found." not in result.stdout and not output.exists())
                elif label == "verify":
                    passed = (result.returncode == 0 and f"Total: {count} entries" in result.stdout
                              and f"Valid: {count} entries" in result.stdout
                              and "Local audit chain consistency verified" in result.stdout)
                else:
                    expected = [item for item in reversed(entries)
                                if severity is None or item["severity"] == severity][:limit]
                    if exported:
                        try:
                            passed = (result.returncode == 0 and stat.S_IMODE(output.stat().st_mode) == 0o600
                                      and json.loads(output.read_text()) == expected)
                        except (OSError, ValueError):
                            passed = False
                    else:
                        actual = re.findall(r"(?m)^\s*Resource: (window-\d+)\s*$", result.stdout)
                        passed = result.returncode == 0 and actual == [item["resource"] for item in expected]
                assert active.read_bytes() == before
                checks.append(dict(phase="audit-record-window", case=f"{phase}-{label}", passed=passed,
                                   status=result.returncode, diagnostic=(result.stdout + result.stderr)[-1000:]))

    def inspect_audit_marker_snapshot():
        layout_counts = {"empty": 0, "active": 1, "archived": 2, "mixed": 3, "sparse": 4, "malformed": 4}
        phases = ("unmarked", "marked-first", "late-record", "late-empty", "late-directory", "late-dangling")

        def publish_marker(marker, phase):
            if phase == "late-directory":
                marker.mkdir()
            elif phase == "late-dangling":
                marker.symlink_to("missing-marker-target")
            else:
                with marker.open("xb") as handle:
                    if phase != "late-empty":
                        handle.write(b"Fixture event loss recorded.\n")
                    handle.flush()
                    os.fsync(handle.fileno())
            parent = os.open(marker.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)

        for layout, count in layout_counts.items():
            for phase in phases:
                data = Path(tempfile.mkdtemp(prefix=f"audit-marker-{layout}-{phase}-", dir=work))
                os.chown(data, account.pw_uid, account.pw_gid)
                directory = data / "audit"
                directory.mkdir(mode=0o700)
                os.chown(directory, account.pw_uid, account.pw_gid)
                active = directory / "audit.jsonl"
                if layout in ("active", "mixed", "sparse", "malformed"):
                    write_audit_fixture_segment(active, audit_fixture_segment("active", 1))
                if layout in ("archived", "mixed", "sparse", "malformed"):
                    first = directory / "audit.jsonl.1"
                    write_audit_fixture_segment(first, audit_fixture_segment("archived", 2, legacy=True))
                    if layout == "malformed":
                        with first.open("ab") as file:
                            file.write(b"{malformed\n")
                if layout == "sparse":
                    write_audit_fixture_segment(directory / "audit.jsonl.5", audit_fixture_segment("older", 1))
                marker = directory / "incomplete"
                previous = {path.name: path.read_bytes() for path in directory.iterdir()}
                mode = dict(disabled, OMG_DATA_DIR=str(data))
                if phase == "marked-first":
                    publish_marker(marker, phase)
                if phase.startswith("late-"):
                    lock = directory / "audit.lock"
                    with lock.open("xb") as handle:
                        lock.chmod(0o600)
                        os.chown(lock, account.pw_uid, account.pw_gid)
                        fcntl.flock(handle, fcntl.LOCK_EX)
                        with subprocess.Popen([cli, "audit", "verify"], env=mode, cwd=work, text=True,
                                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                              stderr=subprocess.PIPE, **ordinary) as verifier:
                            try:
                                blocked = re.compile(rf"\s-> FLOCK\s+ADVISORY\s+READ\s+{verifier.pid}\s")
                                deadline = time.monotonic() + 8
                                while time.monotonic() < deadline:
                                    assert verifier.poll() is None, (layout, phase, verifier.returncode)
                                    if blocked.search(Path("/proc/locks").read_text()):
                                        break
                                    time.sleep(0.005)
                                else:
                                    raise AssertionError((layout, phase, "verifier never waited for the shared lock"))
                                publish_marker(marker, phase)
                            except BaseException:
                                verifier.kill()
                                raise
                            finally:
                                fcntl.flock(handle, fcntl.LOCK_UN)
                            try:
                                stdout, stderr = verifier.communicate(timeout=12)
                            except subprocess.TimeoutExpired:
                                verifier.kill()
                                verifier.communicate()
                                raise
                            status = verifier.returncode
                else:
                    result = command([cli, "audit", "verify"], mode, ordinary)
                    stdout, stderr, status = result.stdout, result.stderr, result.returncode
                verified = "Local audit chain consistency verified" in stdout
                empty = "No audit log exists yet." in stdout
                if phase != "unmarked":
                    passed = status == 1 and not verified and not empty and "Audit collection is incomplete" in stderr
                elif layout == "empty":
                    passed = status == 0 and empty and not verified
                elif layout == "malformed":
                    passed = (status == 1 and not verified and "Total: 4 entries" in stdout
                              and "audit.jsonl.1: line_3" in stdout and "Audit log integrity FAILED" in stderr)
                else:
                    passed = (status == 0 and verified and f"Total: {count} entries" in stdout
                              and f"Valid: {count} entries" in stdout)
                assert {name: (directory / name).read_bytes() for name in previous} == previous
                checks.append(dict(phase="audit-marker-snapshot", case=f"{layout}-{phase}", passed=passed,
                                   status=status, diagnostic=(stdout + stderr)[-1100:]))

    def inspect_audit_log_selection():
        import csv

        severities = ("debug", "error", "info", "critical", "warning", "error", "info", "critical")
        entries = audit_fixture_segment("selection", len(severities), severities=severities)
        cases = (
            ("text-all", ["--limit", "40"], range(7, -1, -1), None),
            ("text-zero", ["--limit", "0"], [], None),
            ("text-two", ["--limit", "2"], [7, 6], None),
            ("text-error", ["--severity", "error"], [7, 5, 3, 1], None),
            ("text-warn-two", ["--severity", "warning", "--limit", "2"], [7, 5], None),
            ("text-critical-one", ["--severity", "critical", "--limit", "1"], [7], None),
            ("json-all", [], range(7, -1, -1), "json"),
            ("json-zero", ["--limit", "0"], [], "json"),
            ("json-error-two", ["--severity", "error", "--limit", "2"], [7, 5], "json"),
            ("json-critical-all", ["--severity", "critical"], [7, 3], "json"),
            ("csv-three", ["--limit", "3"], [7, 6, 5], "csv"),
            ("csv-warn-all", ["--severity", "warning"], [7, 5, 4, 3, 1], "csv"),
        )
        for kind in ("valid", "missing", "corrupt-prefix"):
            data = Path(tempfile.mkdtemp(prefix=f"audit-log-selection-{kind}-", dir=work))
            os.chown(data, account.pw_uid, account.pw_gid)
            directory = data / "audit"
            directory.mkdir(mode=0o700)
            os.chown(directory, account.pw_uid, account.pw_gid)
            active = directory / "audit.jsonl"
            if kind != "missing":
                write_audit_fixture_segment(active, entries)
            if kind == "corrupt-prefix":
                active.write_bytes(b"{incomplete event\n" + active.read_bytes())
            prior = active.read_bytes() if active.exists() else None
            mode = dict(disabled, OMG_DATA_DIR=str(data))
            for label, args, indices, extension in cases:
                export = data / f"{label}.{extension}" if extension is not None else None
                flags = [*args, "--export", export] if export is not None else args
                result = command([cli, "audit", "log", *flags], mode, ordinary)
                expected = [entries[index] for index in indices] if kind == "valid" else []
                try:
                    if kind == "corrupt-prefix":
                        correct = (result.returncode == 1 and "Corrupt audit log" in result.stderr
                                   and "No audit entries found." not in result.stdout
                                   and (export is None or not export.exists()))
                    elif extension == "json":
                        assert stat.S_IMODE(export.stat().st_mode) == 0o600
                        correct = result.returncode == 0 and json.loads(export.read_text()) == expected
                    elif extension == "csv":
                        assert stat.S_IMODE(export.stat().st_mode) == 0o600
                        with export.open() as stream:
                            actual = list(csv.reader(stream))
                        header = ["Timestamp", "Severity", "Event", "Description", "Resource"]
                        expected_csv = [header] + [[item["timestamp"], item["severity"].upper(),
                                                    "PolicyViolation", item["description"], item["resource"]]
                                                   for item in expected]
                        correct = result.returncode == 0 and actual == expected_csv
                    else:
                        actual = re.findall(r"(?m)^\s*Resource: (selection-\d+)\s*$", result.stdout)
                        correct = (result.returncode == 0 and actual == [item["resource"] for item in expected]
                                   and ("No audit entries found." in result.stdout) == (not expected))
                except (AssertionError, OSError, ValueError):
                    correct = False
                assert (active.read_bytes() if active.exists() else None) == prior
                checks.append(dict(phase="audit-log-selection", case=f"{kind}-{label}",
                                   passed=correct, status=result.returncode,
                                   diagnostic=(result.stdout + result.stderr)[-1200:]))

    def inspect_history_locks():
        phase = "history-lock"
        def transaction(label, day, kind, name, success=True):
            changes = [] if name is None else [
                dict(name=name, old_version="1-1" if kind != "Install" else None,
                     new_version="2-1" if kind != "Remove" else None, source="fedora")
            ]
            return dict(id=label, timestamp=f"2026-01-{day:02}T12:00:00Z",
                        transaction_type=kind, changes=changes, success=success)

        installed = transaction("archived-install", 1, "Install", "alpha")
        removed = transaction("archived-remove", 3, "Remove", "Beta")
        updated = transaction("live-update", 5, "Update", "alpha")
        synced = transaction("live-sync", 7, "Sync", None)
        failed = transaction("live-remove", 9, "Remove", "alpha-agent", False)
        live = [updated, synced, failed]
        archived = [installed, removed, updated]
        cases = (
            ("all", [], [failed, synced, updated, removed, installed]),
            ("limit", ["--limit", "2"], [failed, synced]),
            ("empty-limit", ["--limit", "0"], []),
            ("search", ["--search", "ALPHA"], [failed, updated, installed]),
            ("type", ["--type", "remove"], [failed, removed]),
            ("date", ["--from", "2026-01-03", "--to", "2026-01-07"], [synced, updated, removed]),
            ("combined", ["--search", "BETA", "--type", "remove", "--limit", "1"], [removed]),
            ("outside-dates", ["--from", "2026-01-10"], []),
        )
        for kind in ("regular", "absent", "fifo", "symlink", "directory"):
            for label, args, expected in cases:
                sandbox = Path(tempfile.mkdtemp(prefix=f"{phase}-{kind}-{label}-", dir=work))
                os.chown(sandbox, account.pw_uid, account.pw_gid)
                live_file = sandbox / "history.json"
                archive = sandbox / "history.json.archive.jsonl"
                lock = sandbox / "history.lock"
                target = sandbox / "untouched"
                live_file.write_text(json.dumps(live))
                archive.write_text("".join(json.dumps(row) + "\n" for row in archived))
                if kind == "regular":
                    lock.touch(mode=0o600)
                    os.chown(lock, account.pw_uid, account.pw_gid)
                elif kind == "fifo":
                    os.mkfifo(lock, 0o600)
                    os.chown(lock, account.pw_uid, account.pw_gid)
                elif kind == "symlink":
                    target.write_text("keep")
                    lock.symlink_to(target.name)
                elif kind == "directory":
                    lock.mkdir()
                fingerprints = (live_file.read_bytes(), archive.read_bytes())
                mode = dict(disabled, OMG_DATA_DIR=str(sandbox), TZ="UTC")
                result = command([cli, "--json", "history", *args], mode, ordinary)
                if kind in ("regular", "absent"):
                    try:
                        correct = (result.returncode == 0 and json.loads(result.stdout) == expected
                                   and stat.S_ISREG(lock.lstat().st_mode)
                                   and stat.S_IMODE(lock.lstat().st_mode) == 0o600)
                    except (ValueError, OSError):
                        correct = False
                else:
                    diagnostic = "Package history lock must be a regular file" if kind == "fifo" else "Failed to open history lock"
                    correct = result.returncode == 1 and not result.stdout.strip() and diagnostic in result.stderr
                assert fingerprints == (live_file.read_bytes(), archive.read_bytes())
                if kind == "symlink":
                    assert lock.is_symlink() and target.read_text() == "keep"
                checks.append(dict(phase=phase, case=f"{kind}-{label}", passed=correct,
                                   status=result.returncode, diagnostic=(result.stderr or result.stdout)[-800:]))

    def inspect_read_only_updates(phase, update_count):
        cases = (
            ("outdated-json", ["--json", "outdated"]),
            ("outdated-text", ["outdated"]),
            ("counter-json", ["--json", "uc"]),
            ("status-json", ["--json", "status"]),
            ("check-text", ["update", "--check"]),
            ("history-json", ["--json", "history"]),
        )
        native = ordinary_control([dnf, "--cacheonly", "repoquery", "--upgrades",
                                   "--qf", "%{name}\t%{evr}\\n", package])
        matches = [tuple(row.split("\t")) for row in native.splitlines()]
        assert len(matches) == update_count
        installed = ordinary_control([dnf, "--cacheonly", "repoquery", "--installed",
                                      "--qf", r"%{evr}\n", package]).splitlines()
        assert len(installed) == 1, installed
        sandbox = Path(tempfile.mkdtemp(prefix=f"{phase}-", dir=work))
        os.chown(sandbox, account.pw_uid, account.pw_gid)
        blocked_data = sandbox / "unavailable-history"
        blocked_data.write_text("ordinary file")
        policy = sandbox / "config/omg/policy.toml"
        policy.parent.mkdir(parents=True)
        policy.write_text("blocked = [")
        os.chown(policy, account.pw_uid, account.pw_gid)
        policy.chmod(0o600)
        environments = (
            ("default", disabled),
            ("invalid-policy", dict(disabled, XDG_CONFIG_HOME=str(sandbox / "config"))),
            ("blocked-history", dict(disabled, OMG_DATA_DIR=str(blocked_data))),
        )
        for role, mode in environments:
            for label, args in cases:
                result = command([cli, *args], mode, ordinary)
                try:
                    if label == "outdated-json":
                        value = json.loads(result.stdout)
                        rows = [(row["name"], row["new_version"]) for row in value]
                        correct = rows == matches and all(row["current_version"] == installed[0] for row in value)
                    elif label == "outdated-text":
                        if update_count:
                            correct = all(f"{name} {installed[0]} → {evr}" in result.stdout for name, evr in matches)
                        else:
                            correct = "up to date" in result.stdout.lower()
                    elif label == "counter-json":
                        value = json.loads(result.stdout)
                        correct = (isinstance(value, dict) and type(value.get("count")) is int
                                   and value == {"count": update_count})
                    elif label == "status-json":
                        status = json.loads(result.stdout)
                        correct = (type(status["updates_available"]) is int and status["updates_available"] == update_count
                                   and type(status["total_packages"]) is int and status["total_packages"] == 1)
                    elif label == "check-text":
                        if update_count:
                            correct = "1 update available" in result.stdout and package in result.stdout
                        else:
                            correct = "System is up to date" in result.stdout
                    elif role == "blocked-history":
                        correct = (result.returncode == 1 and not result.stdout.strip()
                                   and "Failed to create package history directory" in result.stderr)
                    else:
                        correct = isinstance(json.loads(result.stdout), list)
                except (ValueError, KeyError, TypeError):
                    correct = False
                expected_status = int(label == "history-json" and role == "blocked-history")
                checks.append(dict(phase=phase, case=f"{role}-{label}", passed=correct and result.returncode == expected_status,
                                   status=result.returncode, diagnostic=(result.stderr or result.stdout)[-900:]))
        assert blocked_data.read_text() == "ordinary file"
        assert policy.read_text() == "blocked = ["

    def inspect_independent_counters(phase, expected_orphans, expected_updates):
        for option, expected in (("--unneeded", expected_orphans), ("--upgrades", expected_updates)):
            packages = ordinary_control([dnf, "--cacheonly", "repoquery", option, "--qf", r"%{name}\n"])
            assert packages.splitlines() == [package] * expected, (phase, option, packages)
        for blocked in ("--unneeded", "--upgrades"):
            with reject_native_selection(blocked):
                for label, args, matching_option, expected in (
                    ("json-oc", ["--json", "oc"], "--unneeded", {"count": expected_orphans}),
                    ("text-oc", ["oc"], "--unneeded", expected_orphans),
                    ("json-uc", ["--json", "uc"], "--upgrades", {"count": expected_updates}),
                    ("text-uc", ["uc"], "--upgrades", expected_updates),
                    ("full-status", ["--json", "status"], blocked, None),
                ):
                    result = command([cli, *args], disabled, ordinary)
                    diagnostic = "Unexpected DNF selection subprocess" in result.stderr
                    if blocked == matching_option:
                        passed = result.returncode != 0 and not result.stdout.strip() and diagnostic
                    else:
                        try:
                            if isinstance(expected, dict):
                                actual = json.loads(result.stdout)
                                correct = (isinstance(actual, dict) and type(actual.get("count")) is int
                                           and actual == expected)
                            else:
                                correct = result.stdout == f"{expected}\n"
                        except ValueError:
                            correct = False
                        passed = result.returncode == 0 and not diagnostic and correct
                    checks.append(dict(phase=phase, case=f"{label}-without-{blocked[2:]}",
                                       passed=passed, status=result.returncode,
                                       diagnostic=(result.stderr or result.stdout)[-750:]))

    def inspect_fast_status_modes(phase, explicit_count):
        ready = json.loads(checked([cli, "--json", "status"], env, ordinary))
        assert ready["updates_available"] == 1 and ready["explicit_packages"] == explicit_count
        assert ready["orphan_packages"] == 1 - explicit_count

        variants = (
            ("long-text", ["status", "--fast"], False),
            ("short-text", ["status", "-f"], False),
            ("long-json", ["--json", "status", "--fast"], True),
            ("short-json", ["--json", "status", "-f"], True),
        )
        for option in ("--upgrades", "--unneeded"):
            with reject_native_selection(option):
                for role, mode in (("daemon-ready", env), ("direct", disabled)):
                    before = request_counters()
                    for label, args, as_json in variants:
                        result = command([cli, *args], mode, ordinary)
                        try:
                            if as_json:
                                data = json.loads(result.stdout)
                                counts = tuple(data[key] for key in ("total_packages", "explicit_packages",
                                                                      "orphan_packages", "updates_available"))
                                matched = counts == (1, explicit_count, 0, 0)
                            else:
                                matched = (
                                    f"1 packages installed · {explicit_count} explicit" in result.stdout
                                    and "Updates and orphans not checked" in result.stdout
                                    and "Advisory coverage unreported" in result.stdout
                                    and not re.search(r"(?m)^\s*(Orphans|Updates)\s+\d+\s*$", result.stdout)
                                )
                        except (TypeError, ValueError, KeyError):
                            matched = False
                        checks.append(dict(phase=phase, case=f"{role}-{option[2:]}-{label}",
                                           passed=matched and result.returncode == 0 and not result.stderr,
                                           status=result.returncode, value=result.stdout[-600:],
                                           diagnostic=result.stderr[-700:]))
                    after = request_counters()
                    calls = (after[0] - before[0] - 1, after[1] - before[1])
                    checks.append(dict(phase=phase, case=f"{role}-{option[2:]}-ipc",
                                       passed=calls == (0, 0), value=calls))

    def inspect_enterprise_inventory():
        import csv

        phase = "enterprise-native-inventory"
        query = [rpm, "--root", alternate, "-qa", "--qf",
                 r"%{NAME}\t%{EPOCHNUM}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{DESCRIPTION}\t%{LICENSE}\n"]
        native_before = checked(query)
        name, epoch, release, architecture, description, license = native_before.rstrip("\n").split("\t")
        version = f"{epoch}:{release}"
        identity = f"{name}.{architecture}"

        def verify(case, passed, **details):
            checks.append(dict(phase=phase, case=case, passed=bool(passed), **details))

        def json_file(path, fallback=None):
            if path is None or not path.is_file():
                return fallback
            try:
                return json.loads(path.read_text())
            except ValueError:
                return fallback

        def csv_file(path):
            if path is None or not path.is_file():
                return []
            with path.open(newline="") as stream:
                return list(csv.reader(stream))

        def private(path):
            return path is not None and path.is_file() and path.stat().st_uid == account.pw_uid \
                and stat.S_IMODE(path.stat().st_mode) == 0o600

        with tempfile.TemporaryDirectory(prefix="enterprise-inventory-", dir=work) as directory:
            scope = Path(directory)
            os.chown(scope, account.pw_uid, account.pw_gid)
            output = scope / "evidence"
            mode = dict(disabled, HOME=str(scope))
            with reject_native_selection("-qa", executable=rpm):
                result = command([cli, "enterprise", "audit-export", "--output", output.name], mode, ordinary)
                verify("export-exit", result.returncode == 0, status=result.returncode,
                       diagnostic=result.stderr[-600:])
                expected_files = {
                    "limitations.json", "change-log.json", "policy-enforcement.json",
                    "installed-packages.csv", "sbom-inventory.json",
                }
                files = {path.name for path in output.iterdir()} if output.is_dir() else set()
                verify("export-file-set", files == expected_files, value=sorted(files))
                for file in sorted(expected_files):
                    verify(f"private-{file}", private(output / file))
                limits = json_file(output / "limitations.json", {})
                verify("limitations-state", any(row.get("artifact") == "access-control-matrix"
                      for row in limits.get("unavailable_evidence", [])))
                verify("change-log-shape", isinstance(json_file(output / "change-log.json"), list))
                verify("policy-shape", isinstance(json_file(output / "policy-enforcement.json"), dict))
                rows = csv_file(output / "installed-packages.csv")
                verify("csv-header", rows[:1] == [["package", "version", "description"]])
                verify("csv-installed-count", len(rows) == 2)
                row = rows[1] if len(rows) == 2 else []
                verify("csv-identity", row[:1] == [identity])
                verify("csv-native-version", row[1:2] == [version])
                verify("csv-native-description", row[2:] == [description])

                sbom = json_file(output / "sbom-inventory.json", {})
                components = sbom.get("components", [])
                component = components[0] if len(components) == 1 else {}
                verify("sbom-format", sbom.get("bomFormat") == "CycloneDX")
                verify("sbom-installed-count", len(components) == 1)
                verify("sbom-name", component.get("name") == name)
                verify("sbom-native-version", component.get("version") == version)
                verify("sbom-native-description", component.get("description") == description)
                verify("sbom-native-purl", component.get("purl") ==
                       f"pkg:rpm/fedora/{name}@{release}?arch={architecture}&epoch={epoch}")
                verify("sbom-native-license", [entry.get("license", {}).get("name") for entry in
                                              component.get("licenses", [])] == [license])
                verify("sbom-advisory-scope", {"name": "omg:advisory-coverage", "value": "not-performed"}
                       in component.get("properties", []))
                verify("exports-share-inventory", row == [identity, component.get("version"), component.get("description")])

                result = command([cli, "enterprise", "license-scan", "--export", "json"], mode, ordinary)
                verify("license-json-exit", result.returncode == 0, status=result.returncode,
                       diagnostic=result.stderr[-600:])
                files = list(scope.glob("license-scan-*.json"))
                verify("license-json-file", len(files) == 1)
                artifact = files[0] if len(files) == 1 else None
                verify("license-json-private", private(artifact))
                scan = json_file(artifact, {})
                verify("license-json-total", scan.get("total") == 1)
                verify("license-json-license", scan.get("by_license") == {license: 1})
                for key in ("violations", "unknown", "unresolved_review"):
                    verify(f"license-json-{key}", scan.get(key) == [])

                result = command([cli, "enterprise", "license-scan", "--export", "csv"], mode, ordinary)
                verify("license-csv-exit", result.returncode == 0, status=result.returncode,
                       diagnostic=result.stderr[-600:])
                files = list(scope.glob("license-scan-*.csv"))
                verify("license-csv-file", len(files) == 1)
                artifact = files[0] if len(files) == 1 else None
                verify("license-csv-private", private(artifact))
                rows = csv_file(artifact)
                verify("license-csv-header", rows[:1] == [["license", "count", "unresolved_review"]])
                verify("license-csv-assignment", rows[1:] == [[license, "1", "false"]])

                db_path = Path(checked([rpm, "--root", alternate, "--eval", "%{_dbpath}"]).strip())
                database = alternate / db_path.relative_to("/") / "rpmdb.sqlite"
                invalid = scope / "unreadable-inventory.sqlite"
                with closing(sqlite3.connect(invalid)) as db:
                    db.execute("CREATE TABLE Unrelated (name TEXT)")
                    db.commit()
                invalid.chmod(0o644)
                original_reports = set(scope.glob("license-scan-*"))
                checked(["/usr/bin/mount", "--bind", invalid, database])
                try:
                    for label, args in (
                        ("export", ("audit-export", "--output", "invalid-evidence")),
                        ("json", ("license-scan", "--export", "json")),
                        ("csv", ("license-scan", "--export", "csv")),
                    ):
                        result = command([cli, "enterprise", *args], mode, ordinary)
                        verify(f"invalid-inventory-{label}", result.returncode != 0
                               and "no such table: Packages" in result.stderr
                               and not (scope / "invalid-evidence").exists()
                               and set(scope.glob("license-scan-*")) == original_reports,
                               status=result.returncode, diagnostic=result.stderr[-600:])
                finally:
                    checked(["/usr/bin/umount", database])
        verify("native-inventory-unchanged", checked(query) == native_before)

    def inspect_audit_licenses():
        import csv
        import io

        phase = "audit-license-inventory"
        query = [rpm, "--root", alternate, "-qa", "--qf",
                 r"%{NAME}\t%{EPOCHNUM}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{LICENSE}\n"]
        before = checked(query)
        name, epoch, release, architecture, license = before.rstrip("\n").split("\t")
        assert license == "MIT", before
        identity = f"{name}.{architecture}"
        version = f"{epoch}:{release}"
        row = dict(name=identity, version=version, license=license, category="Permissive",
                   unresolved_review=False)
        csv_header = ["Package", "Version", "License", "Category", "UnresolvedReview"]
        csv_row = [identity, version, license, "Permissive", "false"]

        def verify(case, passed, **details):
            checks.append(dict(phase=phase, case=case, passed=bool(passed), **details))

        def parse_json(text):
            try:
                return json.loads(text)
            except ValueError:
                return None

        def matches_report(format, report, visible):
            if format == "json":
                return parse_json(report) == ([row] if visible else [])
            if format == "csv":
                return list(csv.reader(io.StringIO(report))) == [csv_header, *([csv_row] if visible else [])]
            if format == "table":
                return ("License Summary" in report and (identity in report) == visible
                        and f"Permissive: {int(visible)}" in report)
            raise AssertionError(format)

        with tempfile.TemporaryDirectory(prefix="audit-license-inventory-", dir=work) as directory:
            scope = Path(directory)
            os.chown(scope, account.pw_uid, account.pw_gid)
            mode = dict(disabled, HOME=str(scope), OMG_CONFIG_DIR=str(scope))
            audit = [cli, "audit", "licenses"]
            with reject_native_selection("-qa", executable=rpm):
                for format in ("json", "csv", "table"):
                    for label, filters, visible in (
                        ("all", [], True),
                        ("exact", ["--filter", "mit"], True),
                        ("list", ["--filter", "Apache-2.0, MIT"], True),
                        ("nonmatch", ["--filter", "Apache-2.0"], False),
                    ):
                        result = command([*audit, "--format", format, *filters], mode, ordinary)
                        verify(f"{format}-{label}", result.returncode == 0 and not result.stderr
                               and matches_report(format, result.stdout, visible),
                               status=result.returncode, diagnostic=result.stderr[-600:])

                policy = scope / "policy.toml"
                policy.write_text('allowed_licenses = ["MIT"]\n')
                os.chown(policy, account.pw_uid, account.pw_gid)
                policy.chmod(0o600)
                for format in ("json", "csv", "table"):
                    result = command([*audit, "--format", format, "--check-policy"], mode, ordinary)
                    verify(f"{format}-allows-verified-license", result.returncode == 0
                           and not result.stderr and matches_report(format, result.stdout, True)
                           and (format != "table" or "Policy checked all 1 installed packages." in result.stdout),
                           status=result.returncode, diagnostic=result.stderr[-600:])

                policy.write_text('allowed_licenses = ["Apache-2.0"]\n')
                for format in ("json", "csv", "table"):
                    for label, filters, visible in (
                        ("visible", ["--filter", "MIT"], True),
                        ("hidden", ["--filter", "Apache-2.0"], False),
                    ):
                        result = command([*audit, "--format", format, "--check-policy", *filters], mode, ordinary)
                        display = (result.stdout.split("Packages", 1)[-1]
                                   if format == "table" else result.stdout)
                        correct_table = ("Policy checked all 1 installed packages." in result.stdout
                                         and f"{identity} ({license}) - Not in allowed list" in result.stdout
                                         and (identity in display) == visible)
                        expected_report = correct_table if format == "table" else matches_report(
                            format, result.stdout, visible)
                        verify(f"{format}-denies-{label}", result.returncode == 1 and expected_report
                               and "License policy check found 1 violation(s)" in result.stderr,
                               status=result.returncode, diagnostic=result.stderr[-600:])

                for format in ("json", "csv", "table"):
                    for label, options, status in (
                        ("export", [], 0),
                        ("export-policy-refusal",
                         ["--check-policy", "--filter", "Apache-2.0"], 1),
                    ):
                        path = scope / f"license-{label}.{format}"
                        path.write_text("superseded report")
                        os.chown(path, account.pw_uid, account.pw_gid)
                        path.chmod(0o644)
                        result = command([*audit, "--format", format, "--export", path, *options],
                                         mode, ordinary)
                        verify(f"{format}-{label}-status", result.returncode == status
                               and (not result.stderr if status == 0 else
                                    "License policy check found 1 violation(s)" in result.stderr),
                               status=result.returncode, diagnostic=result.stderr[-600:])
                        verify(f"{format}-{label}-private", path.is_file()
                               and path.stat().st_uid == account.pw_uid
                               and stat.S_IMODE(path.stat().st_mode) == 0o600)
                        artifact = path.read_text() if path.is_file() else ""
                        if format == "table":
                            header = "Package\tVersion\tLicense\tCategory\tUnresolvedReview\n"
                            correct = artifact == header + ("\t".join(csv_row) + "\n" if status == 0 else "")
                        else:
                            correct = matches_report(format, artifact, status == 0)
                        verify(f"{format}-{label}-content", correct, output=artifact[-350:])

                for format in ("json", "csv", "table"):
                    with open("/dev/full", "wb") as sink:
                        result = subprocess.run([str(cli), "audit", "licenses", "--format", format],
                                                cwd=scope, stdin=subprocess.DEVNULL, stdout=sink,
                                                stderr=subprocess.PIPE, text=True, env=mode,
                                                timeout=30, **ordinary)
                    verify(f"{format}-stdout-failure", result.returncode == 1
                           and "No space left on device" in result.stderr
                           and "panicked" not in result.stderr,
                           status=result.returncode, diagnostic=result.stderr[-600:])

                result = command([*audit, "--help"], mode, ordinary)
                verify("help-names-supported-backends", result.returncode == 0
                       and "Fedora" in result.stdout and "Arch" in result.stdout)
                result = command([*audit, "--format", "xml"], mode, ordinary)
                verify("unsupported-format", result.returncode == 2 and not result.stdout
                       and "invalid value 'xml'" in result.stderr, status=result.returncode)

                db_path = Path(checked([rpm, "--root", alternate, "--eval", "%{_dbpath}"]).strip())
                database = alternate / db_path.relative_to("/") / "rpmdb.sqlite"
                invalid = scope / "invalid-inventory.sqlite"
                with closing(sqlite3.connect(invalid)) as db:
                    db.execute("CREATE TABLE Unrelated (name TEXT)")
                invalid.chmod(0o644)
                checked(["/usr/bin/mount", "--bind", invalid, database])
                try:
                    for format, options in (("json", []), ("csv", ["--export", "invalid.csv"])):
                        result = command([*audit, "--format", format, *options], mode, ordinary)
                        verify(f"{format}-invalid-inventory", result.returncode == 1
                               and "no such table: Packages" in result.stderr
                               and (format != "json" or not result.stdout)
                               and not (scope / "invalid.csv").exists(),
                               status=result.returncode, diagnostic=result.stderr[-600:])
                finally:
                    checked(["/usr/bin/umount", database])
        verify("native-inventory-unchanged", checked(query) == before)

    def inspect_dashboard_terminal():
        import pty
        import select
        import termios
        from threading import Thread

        enter = b"\x1b[?1049h"
        leave = b"\x1b[?1049l"
        hide = b"\x1b[?25l"
        show = b"\x1b[?25h"
        report = b"\x1b[6n"
        def read_frame(reader):
            header = reader.read(4)
            assert len(header) == 4, header
            length = int.from_bytes(header, "big")
            assert 0 < length <= 10 * 1024 * 1024, length
            body = reader.read(length)
            assert len(body) == length, (len(body), length)
            return header + body

        def relay_status(listener, upstream, events):
            try:
                for available in (True, False, True):
                    with listener.accept()[0] as peer:
                        peer.settimeout(8)
                        with peer.makefile("rb") as reader:
                            request = read_frame(reader)
                        if available:
                            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as daemon_stream:
                                daemon_stream.settimeout(8)
                                daemon_stream.connect(upstream)
                                daemon_stream.sendall(request)
                                with daemon_stream.makefile("rb") as reader:
                                    peer.sendall(read_frame(reader))
                        events.append("forwarded" if available else "closed-before-reply")
            except (OSError, AssertionError) as error:
                events.append(str(error))

        cases = (
            ("quit", (b"q",), 1, {}),
            ("interrupt", (b"\x03",), 1, {}),
            ("cancel-search", (b"2", b"/", b"q", b"\x1b", b"q"), 1, {}),
            ("interrupt-search", (b"2", b"/", b"\x03"), 1, {}),
            ("cancel-update", (b"u", b"\x1b", b"q"), 1, {0: b"Install all available package updates"}),
            ("cancel-clean", (b"c", b"\x1b", b"q"), 1, {0: b"Clean Package Caches"}),
            ("cancel-orphans", (b"o", b"\x1b", b"q"), 1, {0: b"Remove every orphaned package"}),
            ("resume-after-error", (b"c", b"\r", b"q"), 2, {1: b"clean cache failed"}),
            ("search-debounce", (b"2", b"/", b"vim-enhanced", b"\r", b"q"), 1, {2: b"Text editor"}),
            ("search-enter", (b"2", b"/", b"git\r", b"q"), 1, {2: b"Version control"}),
            ("search-replace", (b"2", b"/", b"vim-enhanced\r", b"/", b"git\r", b"\r", b"\x1b", b"q"), 1,
             {2: b"Text editor", 4: b"Version control", 5: b"Install git?"}),
            ("daemon-transitions", (b"q",), 1, {}),
        )
        for label, keys, sessions, markers in cases:
            master, slave = pty.openpty()
            code = None
            output = bytearray()
            replies = 0
            observed = []
            attributes = None
            transitions = []
            relay_events = []
            before = termios.tcgetattr(slave)

            def attach_tty():
                fcntl.ioctl(0, termios.TIOCSCTTY, 0)

            def read_terminal(deadline, finished):
                nonlocal replies
                while time.monotonic() < deadline and not finished():
                    if not select.select([master], [], [], 0.03)[0]:
                        continue
                    chunk = os.read(master, 8192)
                    if not chunk:
                        break
                    output.extend(chunk)
                    assert len(output) <= 524288
                    for _ in range(output.count(report) - replies):
                        os.write(master, b"\x1b[1;1R")
                        replies += 1

            try:
                termios.tcsetwinsize(slave, (28, 112))
                os.chown(os.ttyname(slave), account.pw_uid, account.pw_gid)
                mode = dict(disabled, TERM="xterm-256color", OMG_NO_UPDATE_CHECK="1")
                if label == "resume-after-error" or label.startswith("search-"):
                    mode.update(OMG_TEST_MODE="1", OMG_TEST_DISTRO="fedora")
                with ExitStack() as stack:
                    if label == "daemon-transitions":
                        upstream = env["OMG_SOCKET_PATH"]
                        relay_path = Path(upstream).with_name("dashboard-forward.sock")
                        listener = stack.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
                        listener.bind(str(relay_path))
                        stack.callback(relay_path.unlink)
                        os.chmod(relay_path, 0o600)
                        os.chown(relay_path, account.pw_uid, account.pw_gid)
                        listener.listen()
                        listener.settimeout(16)
                        mode.pop("OMG_DISABLE_DAEMON")
                        mode["OMG_SOCKET_PATH"] = str(relay_path)
                    process = stack.enter_context(subprocess.Popen(
                        [str(cli), "dash"], cwd=work, env=mode, stdin=slave,
                        stdout=slave, stderr=slave, start_new_session=True,
                        preexec_fn=attach_tty, **ordinary))
                    try:
                        read_terminal(time.monotonic() + 8,
                                      lambda: hide in output or process.poll() is not None)
                        if label == "daemon-transitions":
                            relay = Thread(target=relay_status, args=(listener, upstream, relay_events), daemon=True)
                            relay.start()
                            def observe(marker, offset, seconds=8):
                                read_terminal(time.monotonic() + seconds,
                                              lambda: marker in output[offset:] or process.poll() is not None)
                                return output.find(marker, offset)

                            live = observe(b"Connected", 0)
                            lost = observe(b"Offline", live + len(b"Connected")) if live >= 0 else -1
                            cleared = -1
                            if lost >= 0 and process.poll() is None:
                                offset = len(output)
                                os.write(master, b"3")
                                cleared = observe(b"Daemon status unavailable", offset, seconds=3)
                                os.write(master, b"1")
                            recovered = observe(b"Connected", len(output)) if lost >= 0 else -1
                            transitions = [live >= 0, lost >= 0 and cleared >= 0, recovered >= 0]
                            relay.join(timeout=4)
                        for index, key in enumerate(keys):
                            if process.poll() is not None:
                                break
                            os.write(master, key)
                            if index + 1 < len(keys):
                                read_terminal(time.monotonic() + 0.24,
                                              lambda: process.poll() is not None)
                            if marker := markers.get(index):
                                read_terminal(time.monotonic() + 5,
                                              lambda: marker in output or process.poll() is not None)
                                if marker in output:
                                    observed.append(marker.decode())
                        read_terminal(time.monotonic() + 8, lambda: process.poll() is not None)
                        code = process.poll()
                        read_terminal(time.monotonic() + 0.15, lambda: False)
                        attributes = termios.tcgetattr(slave)
                    finally:
                        if process.poll() is None:
                            process.kill()
                            process.wait(3)
            finally:
                os.close(master)
                os.close(slave)

            last_exit = output.rfind(leave)
            restored = output[last_exit + len(leave):] if last_exit >= 0 else b""
            checks.extend((
                dict(phase="dashboard-terminal", case=f"{label}-process",
                     passed=code == 0 and len(observed) == len(markers), status=code,
                     value=observed,
                     diagnostic=output[-500:].decode(errors="replace")),
                dict(phase="dashboard-terminal", case=f"{label}-termios",
                     passed=attributes == before),
                dict(phase="dashboard-terminal", case=f"{label}-screen",
                     passed=output.count(enter) == output.count(leave) == sessions
                     and not re.search(rb"\x1b\[[23]J", restored) and report not in output,
                     value={"enters":output.count(enter), "leaves":output.count(leave),
                            "cursor_queries":output.count(report),
                            "after_exit":restored[-140:].decode(errors="replace")}),
                dict(phase="dashboard-terminal", case=f"{label}-cursor",
                     passed=last_exit >= 0 and restored.rfind(show) > restored.rfind(hide)),
            ))

            if label == "daemon-transitions":
                for index, state in enumerate(("live", "unavailable", "recovered")):
                    checks.append(dict(phase="dashboard-terminal", case=f"{label}-{state}",
                                       passed=index < len(transitions) and transitions[index]
                                       and relay_events == ["forwarded", "closed-before-reply", "forwarded"],
                                       value=relay_events, diagnostic=output[-2000:].decode(errors="replace")))

    def inspect_info_json_writes():
        cases = (
            ("name", package, "No space left on device"),
            ("nevra", f"{package}-0:1-1.noarch", "No space left on device"),
            ("missing", "omg-fixture-name-absent", "not found"),
            ("invalid", f"../{package}", "Package name cannot start with '.'"),
        )
        for role, mode in (("daemon", env), ("direct", disabled)):
            for label, selector, expected in cases:
                with open("/dev/full", "wb") as sink:
                    result = subprocess.run([str(cli), "--json", "info", selector], cwd=work,
                                            env=mode, stdout=sink, stderr=subprocess.PIPE,
                                            text=True, timeout=30, **ordinary)
                error = result.stderr
                checks.append(dict(phase="info-unwritable-output", case=f"{role}-{label}",
                                   passed=result.returncode == 1 and expected in error
                                   and "panicked" not in error, status=result.returncode,
                                   diagnostic=error[-900:]))

    def inspect_status_write_failures():
        for label, args in (("json", ["--json", "status"]), ("fast-json", ["--json", "status", "--fast"])):
            with open("/dev/full", "wb") as sink:
                result = subprocess.run([str(cli), *args], cwd=work, env=disabled, stdout=sink,
                                        stderr=subprocess.PIPE, text=True, timeout=30, **ordinary)
            error = result.stderr
            checks.append(dict(phase="status-unwritable-output", case=label,
                               passed=result.returncode == 1 and "No space left on device" in error
                               and "panicked" not in error, status=result.returncode,
                               diagnostic=error[-750:]))

    def inspect_advisory_details(phase, matches_installed):
        with reject_native_selection("info", after="advisory"):
            result = command([cli, "audit", "scan", "--fail-on-findings"], disabled, ordinary)
        blocked = "Unexpected DNF selection subprocess" in result.stderr
        if matches_installed:
            passed = result.returncode == 1 and blocked and "Failed to query native security advisories" in result.stderr
        else:
            passed = (result.returncode == 0 and not blocked
                      and "Advisory scope: 0 assessed package(s), 1 package(s) with unknown coverage" in result.stdout
                      and "No findings were reported; advisory coverage is incomplete." in result.stdout)
        checks.append(dict(phase=phase, case="advisory-details-guard", passed=passed,
                           status=result.returncode, diagnostic=(result.stdout + result.stderr)[-1800:]))

    def inspect_security_inventory(phase, expected_count=None):
        native = ordinary_control([dnf, "--cacheonly", "--setopt=disable_excludes=*",
                                   "repoquery", "--installed", "--qf",
                                   "%{name}\t%{arch}\t%{epoch}:%{version}-%{release}\\n"])
        expected = sorted(tuple(row.split("\t")) for row in native.splitlines())
        if expected_count is None:
            assert len(expected) > 25, (phase, len(expected))
        else:
            assert len(expected) == expected_count, (phase, expected_count, len(expected))

        def inspect(mode):
            output = work / f"inventory-{phase}-{mode}.json"
            started = time.monotonic()
            result = command([cli, "audit", "sbom", "--inventory-only", "--output", output], disabled, ordinary)
            elapsed_ms = round((time.monotonic() - started) * 1000, 2)
            actual = []
            passed = False
            diagnostic = result.stderr[-900:]
            try:
                report = json.loads(output.read_text())
                assert report["bomFormat"] == "CycloneDX" and report["specVersion"] == "1.5"
                properties = {entry["name"]: entry["value"]
                              for entry in report["metadata"]["component"]["properties"]}
                for item in report["components"]:
                    assert item["bom-ref"] == item["purl"]
                    queries = parse_qs(item["purl"].partition("?")[2], strict_parsing=True)
                    assert queries["epoch"] == [item["version"].split(":", 1)[0]]
                    actual.append((item["name"], queries["arch"][0], item["version"]))
                passed = (result.returncode == 0 and sorted(actual) == expected
                          and properties["omg:advisory-scan"] == "not-performed"
                          and not report.get("vulnerabilities")
                          and stat.S_IMODE(output.stat().st_mode) == 0o600)
            except (AssertionError, KeyError, OSError, ValueError) as error:
                if not diagnostic:
                    diagnostic = f"{type(error).__name__}: {error}"
            checks.append(dict(phase=phase, case=f"sbom-inventory-{mode}", passed=passed,
                               status=result.returncode, expected_count=len(expected),
                               actual_count=len(actual), elapsed_ms=elapsed_ms,
                               diagnostic=diagnostic))

        inspect("ordinary")
        with reject_native_selection("--installed"):
            inspect("without-dnf-inventory")

    def inspect_explicit_without_query(phase, expected=None):
        control = ordinary_control([dnf, "--cacheonly", "--setopt=disable_excludes=*",
                                    "repoquery", "--userinstalled", "--qf", r"%{name}\n"])
        names = sorted(set(control.splitlines()))
        if expected is None:
            assert len(names) > 25, (phase, names)
        else:
            assert names == expected, (phase, names, expected)

        with reject_native_selection("--userinstalled"):
            for label, args, predicate in [
                ("explicit-rust-list", ["explicit"], lambda value: value == {"count": len(names), "packages": names}),
                ("explicit-rust-count", ["explicit", "--count"], lambda value: value == {"count": len(names)}),
                ("explicit-rust-shortcut", ["ec"], lambda value: value == {"count": len(names)}),
                ("status-rust-explicit", ["status", "--fast"], lambda value: value["explicit_packages"] == len(names)),
            ]:
                result = command([cli, "--json", *args], disabled, ordinary)
                try:
                    passed = result.returncode == 0 and predicate(json.loads(result.stdout))
                except (KeyError, TypeError, ValueError):
                    passed = False
                checks.append(dict(phase=phase, case=label, passed=passed, status=result.returncode,
                                   diagnostic=(result.stderr or result.stdout)[-600:]))

    def inspect_dotted_install_reasons(state):
        prefix = "omg-observer-dotted"
        dotted = f"{prefix}.part.extra"
        build = root / "dotted-rpm"
        build.mkdir()
        spec = build / "observer.spec"
        spec.write_text((fixture / "observer-fixture.spec").read_text().replace(package, dotted))
        checked(["/usr/bin/rpmbuild", "--define", f"_topdir {build}", "-bb", spec])
        checked([rpm, "--root", alternate, "-U", "--nosignature", build / f"RPMS/noarch/{dotted}-1-1.noarch.rpm"])
        packages_state, groups_state = state / "packages.toml", state / "groups.toml"
        saved_packages, saved_groups = packages_state.read_bytes(), groups_state.read_bytes()
        cases = (
            ("dependency-without-group", "Dependency", [], []),
            ("dependency-exact-group", "Dependency", [dotted], []),
            ("dependency-prefix-group", "Dependency", [prefix], [dotted]),
            ("dependency-prefix-and-exact", "Dependency", [prefix, dotted], [dotted]),
            ("weak-exact-group", "Weak Dependency", [dotted], []),
            ("weak-prefix-group", "Weak Dependency", [prefix], [dotted]),
            ("weak-later-prefix-group", "Weak Dependency", [f"{prefix}.part"], []),
            ("user-exact-group", "User", [dotted], [dotted]),
        )
        try:
            for label, reason, members, expected in cases:
                packages_state.write_text(
                    'version = "1.0"\n'
                    f'[packages."{package}.noarch"]\nreason = "Dependency"\n'
                    f'[packages."{dotted}.noarch"]\nreason = "{reason}"\n'
                )
                groups_state.write_text(
                    'version = "1.0"\n'
                    '[groups.omg-dotted-fixture]\nuserinstalled = false\n'
                    f'packages = {json.dumps(members)}\npackage_types = ["mandatory"]\n'
                )
                inspect_explicit_without_query(f"explicit-dotted-{label}", expected)
        finally:
            packages_state.write_bytes(saved_packages)
            groups_state.write_bytes(saved_groups)
            checked([rpm, "--root", alternate, "-e", dotted])

    def inspect_explicit_refusal(phase, reason, expected_failure=None):
        result = command([cli, "--json", "status", "--fast"], disabled, ordinary)
        passed = (result.returncode != 0 and not result.stdout.strip()
                  and "Could not load DNF install reasons" in result.stderr
                  and (expected_failure is None or expected_failure in result.stderr))
        checks.append(dict(phase=phase, case=reason, passed=passed, status=result.returncode,
                           diagnostic=(result.stderr or result.stdout)[-850:]))

    def inspect_upgrade_review(old_rpm):
        # Only a disposable DNF root and a private mount receive transaction writes.
        # The repository manifest remains signed. Its inert package is a fixture.
        alternate_repo.write_text(repo_config.replace("gpgcheck=1\nrepo_gpgcheck=1", "gpgcheck=0\nrepo_gpgcheck=1"))
        profile = root / "review-home"
        state = root / "review-state"
        (state / "omg").mkdir(parents=True, mode=0o700)
        profile.mkdir(mode=0o700)
        root_env = dict(base_env, HOME=str(profile), XDG_CONFIG_HOME=str(profile/"config"),
                        OMG_DISABLE_DAEMON="1", OMG_DISABLE_TELEMETRY="1", NO_COLOR="1")
        history = state / "omg/history.json"
        native_command = [dnf, "history", "info", "last", "--json"]
        rpm_query = [rpm, "--root", alternate, "-q", "--qf", "%{VERSION}", package]
        update = [cli, "update", "--no-sync", "--yes"]
        oracle = [sys.executable, "-I", "-B", consent_oracle, "--native", "--timeout", "22"]

        def record(case, passed, detail):
            checks.append(dict(phase="reviewed-upgrade", case=case, passed=passed, diagnostic=detail))

        checked(["/usr/bin/mount", "--bind", state, "/var/lib"])
        try:
            checked([dnf, "--cacheonly", "--disable-repo=*", "--assumeyes", "remove", package], root_env)
            checked([rpm, "--root", alternate, "-U", "--nosignature", old_rpm], root_env)
            checked([dnf, "--refresh", "--assumeyes", "makecache"], root_env)
            assert checked(rpm_query, root_env) == "0"
            native_before = checked(native_command, root_env)
            denied = command([*oracle, "--deny-only", "--", *update], root_env)
            record("nonterminal-refusal",
                   denied.returncode == 0 and checked(rpm_query, root_env) == "0"
                   and checked(native_command, root_env) == native_before, denied.stderr[-900:])
            refused_history = json.loads(history.read_text())
            record("refusal-history",
                   len(refused_history) == 1 and refused_history[0]["success"] is False
                   and refused_history[0]["changes"] == [], str(refused_history)[-600:])

            accepted = command([*oracle, "--accept-only", "--require-review", "--", *update], root_env)
            plain = re.sub(r"\x1b\[[0-9;]*m", "", accepted.stdout)
            preview = plain.partition("SECURITY WARNING:")[2].partition("Type ")[0]
            installed = checked(rpm_query, root_env)
            native_after = checked(native_command, root_env)
            completed = json.loads(native_after)
            expected_old = f"{package}-0:0-1.noarch"
            expected_new = f"{package}-0:1-1.noarch"
            record("exact-replacement-before-consent",
                   accepted.returncode == 0 and "Type " in plain
                   and f"Replaced: {expected_old}" in [line.strip(" │|") for line in preview.splitlines()],
                   plain[-1300:])
            record("exact-native-commit",
                   accepted.returncode == 0 and installed == "1" and len(completed) == 1
                   and completed[0]["status"] == "Ok" and "replay" in completed[0]["description"].split()
                   and {(row["action"], row["nevra"]) for row in completed[0]["packages"]}
                   == {("Replaced", expected_old), ("Upgrade", expected_new)},
                   native_after[-1000:])
            committed_history = history.read_bytes()
            entries = json.loads(committed_history)
            expected_change = {"name": package, "old_version": "0:0-1", "new_version": "0:1-1", "source": "dnf"}
            record("exact-omg-commit",
                   len(entries) == 2 and entries[0] == refused_history[0]
                   and entries[1]["success"] is True and entries[1]["transaction_type"] == "Update"
                   and entries[1]["changes"] == [expected_change], str(entries)[-1000:])

            repeat = command(update, root_env)
            record("successful-no-op",
                   repeat.returncode == 0 and checked(rpm_query, root_env) == "1"
                   and checked(native_command, root_env) == native_after
                   and history.read_bytes() == committed_history,
                   (repeat.stdout + repeat.stderr)[-900:])
        finally:
            checked(["/usr/bin/umount", "/var/lib"])

    def inspect_removal_replay():
        # Fedora's default RPM database and DNF journal live under sysimage.
        # Bind fresh state at their actual paths so DNF sees a default root.
        removal = root / "review-removal"
        removal.mkdir()
        repo_dirs = (Path("/etc/yum.repos.d"), Path("/etc/distro.repos.d"),
                     Path("/usr/share/dnf5/repos.d"))
        offline_repo = ("[offline-fixture]\nname=Unavailable local test repository\n"
                        "baseurl=file:///nonexistent-omg-fixture\n"
                        "enabled=1\nskip_if_unavailable=false\n")
        root_env = dict(base_env, HOME=str(removal), OMG_DISABLE_DAEMON="1",
                        OMG_DISABLE_TELEMETRY="1", NO_COLOR="1")
        main_before = config.read_bytes()
        rpm_link = Path("/var/lib/rpm").readlink()
        try:
            with ExitStack() as mounts:
                for target in (Path("/var/lib"), Path("/usr/lib/sysimage"), *repo_dirs):
                    if target in repo_dirs and not target.exists():
                        continue
                    source = removal / target.name
                    source.mkdir()
                    checked(["/usr/bin/mount", "--bind", source, target])
                    mounts.callback(checked, ["/usr/bin/umount", target])
                    assert os.path.samefile(source, target), target
                assert os.path.samefile(removal / "sysimage", "/usr/lib/sysimage")
                assert os.path.samefile(removal / "lib", "/var/lib")
                assert os.path.samefile(removal / "yum.repos.d", "/etc/yum.repos.d")
                Path("/var/lib/rpm").symlink_to(rpm_link)
                Path("/usr/lib/sysimage/rpm").mkdir()
                Path("/usr/lib/sysimage/libdnf5").mkdir()
                history = Path("/var/lib/omg/history.json")
                default_repo = repo_dirs[0] / "offline-fixture.repo"
                custom_repos = removal / "repos"
                custom_repos.mkdir()
                (custom_repos / default_repo.name).write_text(offline_repo)
                for layout in ("standard", "empty", "custom"):
                    settings = "[main]\nplugins=0\n"
                    if layout == "standard":
                        default_repo.write_text(offline_repo)
                    else:
                        default_repo.unlink(missing_ok=True)
                    if layout == "custom":
                        settings += f"reposdir={custom_repos}\n"
                    config.write_text(settings)
                    repo_options = ["--disable-repo=*"] if layout != "empty" else []
                    checked([dnf, "--releasever=44", *repo_options, "--setopt=localpkg_gpgcheck=0",
                             "--assumeyes", "install", fixture / "observer-fixture.rpm"], root_env)
                    native_history = [dnf, "history", "info", "last", "--json"]
                    baseline = checked(native_history, root_env)
                    assert checked([rpm, "-q", package], root_env).strip() == f"{package}-1-1.noarch"
                    invoke = [cli, "remove", "--yes", package]
                    with reject_native_selection("list", after="repo"):
                        result = command(invoke, root_env)
                    blocked = "Unexpected DNF selection subprocess" in result.stderr
                    detail = (result.stdout + result.stderr)[-1100:]
                    if layout == "standard":
                        probe_passed = result.returncode == 0 and not blocked
                    else:
                        probe_passed = (result.returncode != 0 and blocked
                                        and checked(native_history, root_env) == baseline
                                        and checked([rpm, "-q", package], root_env).strip() == f"{package}-1-1.noarch"
                                        and not history.exists())
                        result = command(invoke, root_env)
                    checks.append(dict(phase=f"removal-{layout}", case="repository-probe",
                                       passed=probe_passed, diagnostic=detail))
                    finished = json.loads(checked(native_history, root_env))
                    native_ok = (len(finished) == 1 and finished[0]["status"] == "Ok"
                                 and (finished[0]["description"].split().count("--disable-repo=*")
                                      == int(bool(repo_options)))
                                 and {(row["nevra"], row["action"]) for row in finished[0]["packages"]}
                                 == {(f"{package}-0:1-1.noarch", "Remove")})
                    removed = command([rpm, "-q", package], root_env)
                    checks.append(dict(phase=f"removal-{layout}", case="native-replay",
                                       passed=result.returncode == 0 and removed.returncode == 1 and native_ok,
                                       diagnostic=(result.stdout + result.stderr + str(finished))[-1400:]))
                    entries = json.loads(history.read_text()) if history.exists() else []
                    expected = dict(name=package, old_version="0:1-1", new_version=None, source="dnf")
                    checks.append(dict(phase=f"removal-{layout}", case="omg-journal",
                                       passed=len(entries) == 1 and entries[0]["success"] is True
                                       and entries[0]["transaction_type"] == "Remove"
                                       and entries[0]["changes"] == [expected], diagnostic=str(entries)[-900:]))
                    history.unlink(missing_ok=True)
                    if removed.returncode == 0:
                        checked([rpm, "-e", package], root_env)
        finally:
            config.write_bytes(main_before)

    def status_during(change, *, args=("daemon-status",), mode=env):
        # Pause the real counts query before libdnf5 takes any database locks.
        # The wrapper and native executable are confined to this mount namespace.
        target = Path(dnf).resolve(strict=True)
        with tempfile.TemporaryDirectory(prefix="status-query-", dir=root) as directory:
            gate = Path(directory)
            gate.chmod(0o755)
            handoff = gate / "handoff"
            handoff.mkdir(mode=0o700)
            os.chown(handoff, account.pw_uid, account.pw_gid)
            native = gate / target.name
            shutil.copy2(target, native)
            arrived, resume = handoff / "arrived", handoff / "resume"
            wrapper = gate / "hold-dnf"
            wrapper.write_text(f"""#!/usr/bin/bash
for argument in "$@"; do
    if [[ "$argument" == --upgrades ]]; then
        : > {shlex.quote(str(handoff / "upgrades"))}
        break
    fi
    if [[ "$argument" == --unneeded ]]; then
        : > {shlex.quote(str(arrived))}
        for ((attempt=0; attempt<240; attempt++)); do
            [[ ! -f {shlex.quote(str(resume))} ]] || break
            sleep 0.05
        done
        [[ -f {shlex.quote(str(resume))} ]] || exit 197
        break
    fi
done
exec {shlex.quote(str(native))} "$@"
""")
            wrapper.chmod(0o755)
            checked(["/usr/bin/mount", "--bind", wrapper, target])
            try:
                with subprocess.Popen([str(cli), *args], cwd=work, env=mode,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      stdin=subprocess.DEVNULL, text=True, **ordinary) as status:
                    try:
                        wait_for(arrived.exists, status)
                        change(handoff)
                        resume.touch()
                        stdout, stderr = status.communicate(timeout=25)
                        return status.returncode, stdout, stderr
                    finally:
                        if status.poll() is None:
                            status.kill()
                            status.wait(4)
            finally:
                checked(["/usr/bin/umount", target])

    def inspect_status_inventory_scope(phase, expected_updates, state, *, native_reasons=False):
        native_identity = ordinary_control([dnf, "--cacheonly", "repoquery", "--installed",
                                            "--qf", r"%{name}\n"]).splitlines()
        assert native_identity == [package]
        assert native_explicit() == [package]
        nevras = tomllib.loads((state / "nevras.toml").read_text())["nevras"]
        # Empty NEVRA state also checks legacy history when the direct reader can proceed.
        expected_dumps = 1 + int(not nevras and not native_reasons)
        target = Path(dnf).resolve(strict=True)
        with tempfile.TemporaryDirectory(prefix="status-inventory-", dir=root) as directory:
            gate = Path(directory)
            gate.chmod(0o755)
            witness = gate / "effective-config"
            witness.touch(mode=0o600)
            os.chown(witness, account.pw_uid, account.pw_gid)
            native = gate / target.name
            shutil.copy2(target, native)
            wrapper = gate / "track-dnf"
            wrapper.write_text(f"""#!/usr/bin/bash
for argument in "$@"; do
    case "$argument" in
        --dump-main-config) printf 'config\\n' >> {shlex.quote(str(witness))} ;;
        --userinstalled) printf 'reasons\\n' >> {shlex.quote(str(witness))} ;;
    esac
done
exec {shlex.quote(str(native))} "$@"
""")
            wrapper.chmod(0o755)
            checked(["/usr/bin/mount", "--bind", wrapper, target])
            try:
                for label, args, updates in (
                    ("fast-status-inventory-scope", ["--fast"], 0),
                    ("status-inventory-scope", [], expected_updates),
                ):
                    count_before = len(witness.read_text().splitlines())
                    result = command([cli, "--json", "status", *args], disabled, ordinary)
                    probes = witness.read_text().splitlines()[count_before:]
                    observed_dumps = probes.count("config")
                    reason_queries = probes.count("reasons")
                    try:
                        value = json.loads(result.stdout)
                        counts = tuple(value[key] for key in ("total_packages", "explicit_packages",
                                                             "orphan_packages", "updates_available"))
                    except (TypeError, ValueError, KeyError):
                        counts = ()
                    checks.append(dict(phase=phase, case=label,
                                       passed=result.returncode == 0 and counts == (1, 1, 0, updates)
                                       and observed_dumps == expected_dumps
                                       and reason_queries == int(native_reasons), status=result.returncode,
                                       config_dumps=observed_dumps, expected_dumps=expected_dumps,
                                       native_reasons=reason_queries,
                                       counts=counts, diagnostic=result.stderr[-900:]))
            finally:
                checked(["/usr/bin/umount", target])

    def inspect_overlapping_status(phase, expected_updates):
        native_orphans = ordinary_control([dnf, "--cacheonly", "repoquery", "--unneeded",
                                           "--qf", r"%{name}\n"]).splitlines()
        expected = {
            "total_packages": 1,
            "explicit_packages": 1,
            "orphan_packages": len(native_orphans),
            "updates_available": expected_updates,
        }
        labels = {
            "Total packages:": "total_packages", "Explicit packages:": "explicit_packages",
            "Orphan packages:": "orphan_packages", "Updates available:": "updates_available",
        }
        for label, args, mode in (
            ("parallel-direct-status", ("--json", "status"), disabled),
            ("parallel-daemon-status", ("daemon-status",), env),
        ):
            started_upgrades = False

            def inspect_while_orphans_wait(handoff):
                nonlocal started_upgrades
                deadline = time.monotonic() + 1.5
                started_upgrades = (handoff / "upgrades").exists()
                while not started_upgrades and time.monotonic() < deadline:
                    time.sleep(0.02)
                    started_upgrades = (handoff / "upgrades").exists()

            status, stdout, stderr = status_during(inspect_while_orphans_wait, args=args, mode=mode)
            if mode is disabled:
                value = json.loads(stdout) if status == 0 else {}
                counts = {key: value.get(key) for key in expected}
            else:
                counts = {labels[name]: int(count) for name, count in
                          re.findall(r"(?m)^\s*(Total packages:|Explicit packages:|Orphan packages:|Updates available:)\s*([0-9]+)\s*$", stdout)}
            checks.append(dict(phase=phase, case=label,
                               passed=status == 0 and started_upgrades and counts == expected,
                               status=status, started_upgrades=started_upgrades, counts=counts,
                               diagnostic=stderr[-900:]))

    @contextmanager
    def running_daemon(log):
        with subprocess.Popen([str(server)], cwd=work, env=env, stdout=log, stderr=subprocess.STDOUT,
                              stdin=subprocess.DEVNULL, **ordinary) as process:
            try:
                wait_for(lambda: fast.exists() and persisted.exists(), process)
                assert stat.S_IMODE((runtime/"omg.sock").stat().st_mode) == 0o600
                yield process
                assert process.poll() is None
            finally:
                if process.poll() is None:
                    process.send_signal(signal.SIGTERM)
                    try:
                        process.wait(8)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(4)

    def native_installed():
        return checked([rpm, "--root", alternate, "-qa", "--qf", "%{NAME}\n"]).splitlines()

    def native_explicit():
        return ordinary_control([dnf, "--cacheonly", "--setopt=disable_excludes=*",
                                 "repoquery", "--userinstalled", "--qf", r"%{name}\n"]).splitlines()

    def mark(reason):
        checked([dnf, "--cacheonly", "--disable-repo=*", "-y", "mark", reason, package])

    with (root / "daemon.log").open("w+") as log:
        try:
            checked([*gpg, "--quick-generate-key", "OMG Fedora status fixture <fixture@example.invalid>", "rsa2048", "sign", "1d"])
            manifest = repo / "repodata/repomd.xml"
            public.write_text(checked([*gpg, "--armor", "--export"]))
            def sign_manifest():
                signature = manifest.with_suffix(".xml.asc")
                signature.unlink(missing_ok=True)
                checked([*gpg, "--armor", "--detach-sign", "--output", signature, manifest])
            sign_manifest()
            advisory_cache = work / "cache/omg/dnf-security"
            advisory_options = [f"--setopt=cachedir={advisory_cache}", f"--setopt=system_cachedir={advisory_cache}"]
            def refresh_fixture():
                for args in ([], advisory_options):
                    ordinary_control([dnf, *args, "--refresh", "-y", "makecache"])

            def publish_test_summary(original, summary, name):
                from compression import zstd

                primary_ns = "{http://linux.duke.edu/metadata/common}"
                primary = zstd.decompress((repo/"repodata/primary.xml.zst").read_bytes()).decode()
                original_summary = ET.fromstring(primary).findtext(f"{primary_ns}package/{primary_ns}summary")
                assert original_summary
                previous = f"<summary>{original_summary}</summary>"
                assert primary.count(previous) == 1
                primary = primary.replace(previous, f"<summary>{summary}</summary>").encode()
                modified = ET.fromstring(original)
                modified.remove(next(row for row in modified.findall(f"{repo_ns}data")
                                     if row.attrib["type"] == "primary"))
                append_metadata(modified, "primary", f"repodata/primary-{name}.xml.gz", primary)
                manifest.write_bytes(ET.tostring(modified))
                sign_manifest()
                return original_summary

            def restore_test_summary(original):
                manifest.write_bytes(original)
                sign_manifest()
                ordinary_control([dnf, "clean", "metadata"])
                refresh_fixture()

            def native_test_summary(options, summary):
                native = ordinary_control([dnf, *options, "repoquery", "--available", "--latest-limit=1",
                                           "--queryformat", "%{name}.%{arch}\t%{evr}\t%{summary}\x1e", package])
                assert native == f"{package}.noarch\t1-1\t{summary}\x1e", repr(native)

            def inspect_summary_results(phase, summary, queries, missed_query, roles):
                identity = f"{package}.noarch"
                for role, mode in roles:
                    requests_before = request_counters()
                    for query in queries:
                        result = command([cli, "--json", "search", "--limit", "1", query], mode, ordinary)
                        value = None
                        try:
                            value = json.loads(result.stdout)
                            row, = value
                            matched = (row["name"], row["version"], row["description"]) == (
                                identity, "1-1", summary)
                        except (ValueError, KeyError, TypeError):
                            matched = False
                        if query == missed_query:
                            matched = value == []
                        checks.append(dict(phase=phase, case=f"{role}-{query}",
                                           passed=result.returncode == 0 and matched,
                                           value=value, diagnostic=result.stderr[-650:]))
                    result = command([cli, "--json", "info", package], mode, ordinary)
                    try:
                        value = json.loads(result.stdout)
                        matched = value["name"] == identity and value["version"] == "1-1" \
                            and value["description"] == summary and value["installed"] is False
                    except (ValueError, KeyError, TypeError):
                        value, matched = result.stdout[-650:], False
                    checks.append(dict(phase=phase, case=f"{role}-info",
                                       passed=result.returncode == 0 and matched,
                                       value=value, diagnostic=result.stderr[-650:]))
                    total, failed = request_counters()
                    calls = total - requests_before[0] - 1
                    failures = failed - requests_before[1]
                    expected_calls = len(queries) + 1 if role == "daemon" else 0
                    checks.append(dict(phase=phase, case=f"{role}-ipc",
                                       passed=calls == expected_calls and failures == 0,
                                       value={"calls": calls, "failures": failures}))

            def inspect_multiline_summary(original):
                summary = "Fixture-QZ First Line\nFixture-QZ\tÄquator Catalogue ΩΣ"
                try:
                    publish_test_summary(original, summary, "multiline")
                    ordinary_control([dnf, "clean", "metadata"])
                    refresh_fixture()
                    native_test_summary(["--cacheonly"], summary)
                    queries = (
                        package, f"{package}.noarch", "OMG-OBSERVER", "observer-fixture", "Fixture-QZ", "FIXTURE-QZ",
                        "fixture-qz first line", "QZ FIRST", "QZ FIRST LINE",
                        "ÄQUATOR", "äquator catalogue", "catalogue ΩΣ", "CATALOGUE ως", "fixture-qz absent",
                    )

                    inspect_summary_results("repository-multiline", summary, queries, "fixture-qz absent",
                                            (("direct", disabled), ("daemon", env)))
                finally:
                    restore_test_summary(original)

            def inspect_expired_catalog(phase, original, cache):
                cached, = cache.glob("signed-fixture-*/repodata/repomd.xml")
                marker = cached.parent.parent/"attrs/expired"
                cached_before = cached.read_bytes()
                assert cached_before == original and not marker.exists()
                updated = "Catalog-QZ Expired Generation ΩΣ"
                oracle = work/"expiry-control"
                try:
                    old_summary = publish_test_summary(original, updated, "expiry")
                    seeded = checked([cli, "--json", "search", "--limit", "1", package], env, ordinary)
                    row, = json.loads(seeded)
                    assert row["description"] == old_summary
                    native_test_summary([f"--setopt=signed-fixture.cachedir={oracle}",
                                         f"--setopt=system_cachedir={oracle}", "--refresh", "-y"], updated)
                    assert cached.read_bytes() == cached_before and not marker.exists()
                    ordinary_control([dnf, f"--setopt=cachedir={cache}", "clean", "expire-cache"])
                    assert cached.read_bytes() == cached_before and marker.is_file()
                    queries = (
                        package, f"{package}.noarch", "OMG-OBSERVER", "observer-fixture",
                        "Catalog-QZ", "CATALOG-QZ", "qz expired", "expired generation",
                        "catalog-qz expired generation", "QZ EXPIRED GENERATION", "generation ΩΣ",
                        "GENERATION ως", "catalog-qz expired generation ΩΣ", "catalog-qz absent",
                    )
                    # The daemon is exercised before any direct lookup can refresh its metadata.
                    inspect_summary_results(phase, updated, queries, "catalog-qz absent",
                                            (("daemon", env), ("direct", disabled)))
                finally:
                    restore_test_summary(original)

            def inspect_aged_catalog(phase, original, ttl):
                cache = work/f"{phase}-cache"
                oracle = work/f"{phase}-control"
                old_summary = "Catalog-QZ Fresh Generation ΩΣ"
                updated = "Catalog-QZ Elapsed Generation ΩΣ"
                try:
                    repo_file.write_text(repo_config + f"cachedir={cache}\nmetadata_expire={ttl}\n")
                    publish_test_summary(original, old_summary, "age-initial")
                    refresh_fixture()
                    cached, = cache.glob("signed-fixture-*/repodata/repomd.xml")
                    primary = cached.with_name("primary-age-initial.xml.gz")
                    marker = cached.parent.parent/"attrs/expired"
                    seeded = checked([cli, "--json", "search", "--limit", "1", package], env, ordinary)
                    row, = json.loads(seeded)
                    assert row["description"] == old_summary
                    modified = primary.stat()
                    deadline = int(modified.st_mtime) + ttl
                    assert (ttl == 0 or time.time() < deadline) and not marker.exists()
                    if ttl:
                        requests_before = request_counters()
                        with reject_native_selection("--available"):
                            reused = command([cli, "--json", "search", "--limit", "1", package], env, ordinary)
                        total, failed = request_counters()
                        checks.append(dict(phase=phase, case="reuse-before-deadline",
                                           passed=reused.returncode == 0 and reused.stdout == seeded
                                                  and total - requests_before[0] == 2
                                                  and failed == requests_before[1],
                                           value=reused.stdout, diagnostic=reused.stderr[-650:]))
                        assert time.time() < deadline
                    before = cached.read_bytes()
                    publish_test_summary(original, updated, "age-elapsed")
                    native_test_summary([f"--setopt=signed-fixture.cachedir={oracle}",
                                         f"--setopt=system_cachedir={oracle}", "--refresh", "-y"], updated)
                    while time.time() < deadline + 0.05:
                        time.sleep(0.05)
                    # Only elapsed time can invalidate this in-place snapshot.
                    assert primary.stat() == modified and cached.read_bytes() == before and not marker.exists()
                    queries = (
                        package, f"{package}.noarch", "OMG-OBSERVER", "observer-fixture",
                        "Catalog-QZ", "CATALOG-QZ", "qz elapsed", "elapsed generation",
                        "catalog-qz elapsed generation", "QZ ELAPSED GENERATION", "generation ΩΣ",
                        "GENERATION ως", "catalog-qz elapsed generation ΩΣ", "catalog-qz absent",
                    )
                    inspect_summary_results(phase, updated, queries, "catalog-qz absent",
                                            (("daemon", env), ("direct", disabled)))
                finally:
                    repo_file.write_text(repo_config)
                    restore_test_summary(original)

            def inspect_cached_age_policy(original, policy):
                phase = f"repository-age-{policy}"
                cache = work/f"{phase}-cache"
                old_summary = "Catalog-QZ Persisted Generation ΩΣ"
                try:
                    ttl = -1 if policy == "never" else 3
                    repo_file.write_text(repo_config + f"cachedir={cache}\nmetadata_expire={ttl}\n")
                    publish_test_summary(original, old_summary, f"{policy}-prepared")
                    refresh_fixture()
                    manifest_in_cache, = cache.glob("signed-fixture-*/repodata/repomd.xml")
                    primary = manifest_in_cache.with_name(f"primary-{policy}-prepared.xml.gz")
                    modified = primary.stat()
                    os.utime(primary, ns=(modified.st_atime_ns, modified.st_mtime_ns - 60_000_000_000))
                    if policy != "never":
                        config.write_text(host_config + f"cacheonly={policy}\n")
                    identity = f"{package}.noarch"
                    control = checked([cli, "--json", "search", "--limit", "1", package], env, ordinary)
                    assert [row["description"] for row in json.loads(control)] == [old_summary]
                    publish_test_summary(original, "Catalog-QZ Future Generation ΩΣ", f"{policy}-changed")
                    native_test_summary([], old_summary)
                    queries = (
                        package, identity, "catalog-qz", "persisted generation",
                        "CATALOG-QZ PERSISTED", "generation ΩΣ", "GENERATION ως", "future generation",
                    )
                    requests_before = request_counters()
                    with reject_native_selection("--available"):
                        for query in queries:
                            result = command([cli, "--json", "search", "--limit", "1", query], env, ordinary)
                            value = None
                            try:
                                value = json.loads(result.stdout)
                                if query == queries[-1]:
                                    matched = value == []
                                else:
                                    row, = value
                                    matched = (row["name"], row["description"]) == (identity, old_summary)
                            except (ValueError, KeyError, TypeError):
                                matched = False
                            checks.append(dict(phase=phase, case=f"daemon-{query}",
                                               passed=result.returncode == 0 and matched,
                                               value=value, diagnostic=result.stderr[-650:]))
                    total, failed = request_counters()
                    calls = total - requests_before[0] - 1
                    failures = failed - requests_before[1]
                    checks.append(dict(phase=phase, case="daemon-ipc",
                                       passed=calls == len(queries) and failures == 0,
                                       value={"calls": calls, "failures": failures}))
                finally:
                    config.write_text(host_config)
                    repo_file.write_text(repo_config)
                    restore_test_summary(original)

            def inspect_direct_catalog_cache(original):
                phase = "direct-catalog-cache"
                native_cache = work/"direct-catalog-native-cache"
                catalog = work/"cache/omg/dnf-search-v1.bin"
                drop = work/"count-available-catalog"
                drop.touch(mode=0o600)
                os.chown(drop, account.pw_uid, account.pw_gid)
                target = Path(dnf).resolve(strict=True)
                binary = bin_dir/"real-dnf"
                trace = bin_dir/"track-dnf"
                shutil.copy2(target, binary)
                trace.write_text(f"""#!/usr/bin/bash
repoquery=0
available=0
for arg in "$@"; do
    case "$arg" in
        repoquery) repoquery=1 ;;
        --available) available=1 ;;
    esac
done
if [[ "$repoquery" == 1 && "$available" == 1 ]]; then
    printf 'catalog\\n' >> {shlex.quote(str(drop))}
fi
exec {shlex.quote(str(binary))} "$@"
""")
                trace.chmod(0o755)
                identity = f"{package}.noarch"
                initial = "Catalog-QZ Direct Generation ΩΣ"
                updated = "Catalog-QZ Revalidated Generation ΩΣ"

                def search(label, query, summary, calls, mode=disabled):
                    before = drop.read_bytes().count(b"\n")
                    started = time.perf_counter_ns()
                    result = command([cli, "--json", "search", "--limit", "1", query], mode, ordinary)
                    duration_ms = (time.perf_counter_ns() - started) / 1_000_000
                    observed = drop.read_bytes().count(b"\n") - before
                    value = None
                    try:
                        value = json.loads(result.stdout)
                        if summary is None:
                            exact = value == []
                        else:
                            row, = value
                            exact = (row["name"], row["version"], row["description"]) == (
                                identity, "1-1", summary)
                    except (ValueError, TypeError, KeyError):
                        exact = False
                    checks.append(dict(phase=phase, case=label, passed=result.returncode == 0 and exact
                                       and observed == calls, value={"calls": observed, "rows": value}, duration_ms=duration_ms,
                                       diagnostic=result.stderr[-800:]))

                unsigned = repo_config.replace("repo_gpgcheck=1", "repo_gpgcheck=0") + f"cachedir={native_cache}\n"
                fixture_config = host_config + "check_config_file_age=0\n"
                checked(["/usr/bin/mount", "--bind", trace, target])
                try:
                    config.write_text(fixture_config)
                    repo_file.write_text(unsigned)
                    publish_test_summary(original, initial, "direct-initial")
                    refresh_fixture()
                    native_test_summary([], initial)
                    search("seed", package, initial, 1)
                    for query in (
                        package, identity, "OMG-OBSERVER", "observer-fixture", "catalog-qz", "CATALOG-QZ",
                        "qz direct", "direct generation", "catalog-qz direct generation",
                        "QZ DIRECT GENERATION", "generation ΩΣ", "GENERATION ως",
                        "catalog-qz direct generation ΩΣ", "catalog-qz absent",
                    ):
                        search(f"warm-{query}", query, None if query == "catalog-qz absent" else initial, 0)

                    encoded = catalog.read_bytes()
                    catalog.write_bytes(encoded[:-1] + bytes([encoded[-1] ^ 1]))
                    search("corrupt-cache", identity, initial, 1)
                    search("rewarmed-after-corruption", identity, initial, 0)
                    catalog.chmod(0o644)
                    search("shared-cache", identity, initial, 1)
                    checks.append(dict(phase=phase, case="private-replacement",
                                       passed=catalog.stat().st_mode & 0o777 == 0o600))
                    search("rewarmed-after-permissions", identity, initial, 0)

                    repo_file.write_text(unsigned + f"excludepkgs={package}\n")
                    search("excluded-native", identity, None, 1)
                    search("excluded-cached", identity, None, 0)
                    repo_file.write_text(unsigned)
                    search("exclusion-removed-native", identity, initial, 1)
                    search("exclusion-removed-cached", identity, initial, 0)

                    config.write_text(fixture_config + "cacheonly=all\n")
                    search("cacheonly-policy-native", identity, initial, 1)
                    config.write_text(fixture_config)
                    repo_file.write_text(unsigned.replace("repo_gpgcheck=0", "repo_gpgcheck=1"))
                    refresh_fixture()
                    search("repository-signature-native", identity, initial, 1)
                    repo_file.write_text(unsigned)
                    refresh_fixture()
                    search("reseed-before-expiration", identity, initial, 1)

                    publish_test_summary(original, updated, "direct-updated")
                    ordinary_control([dnf, f"--setopt=cachedir={native_cache}", "clean", "expire-cache"])
                    search("expired-native", identity, updated, 1)
                    search("refreshed-seed", identity, updated, 1)
                    search("refreshed-reuse", identity, updated, 0)

                    empty_plugins = root / "empty-dnf-plugins"
                    empty_plugins.mkdir()
                    for variable in ("DNF5_PLUGINS_DIR", "LIBDNF_PLUGINS_CONFIG_DIR"):
                        mode = dict(disabled, **{variable: str(empty_plugins)})
                        search(f"warm-with-{variable}", identity, updated, 0, mode)

                    requests_before = request_counters()
                    search("daemon-seed", identity, updated, 1, env)
                    search("daemon-warm", identity, updated, 0, env)
                    cached_manifest, = native_cache.glob("signed-fixture-*/repodata/repomd.xml")
                    primary = cached_manifest.with_name("primary-direct-updated.xml.gz")
                    original_primary = primary.stat()
                    original_manifest = cached_manifest.stat()
                    replacement = primary.with_suffix(".replacement")
                    shutil.copy2(primary, replacement)
                    os.chown(replacement, original_primary.st_uid, original_primary.st_gid)
                    replacement.replace(primary)
                    assert primary.stat().st_ino != original_primary.st_ino
                    assert primary.stat().st_mtime_ns == original_primary.st_mtime_ns
                    assert cached_manifest.stat() == original_manifest
                    search("daemon-native-after-primary-replacement", identity, updated, 1, env)
                    search("daemon-warm-after-primary-replacement", identity, updated, 0, env)
                    total, failed = request_counters()
                    calls = (total - requests_before[0] - 1, failed - requests_before[1])
                    checks.append(dict(phase=phase, case="daemon-payload-ipc",
                                       passed=calls == (4, 0), value=calls))

                    rpm_path = Path(checked([rpm, "--eval", "%{_dbpath}"]).strip()).resolve(strict=True)
                    snapshot = work / "direct-catalog-rpmdb"
                    snapshot.mkdir()
                    database = snapshot / "rpmdb.sqlite"
                    source_database = (rpm_path / database.name).as_uri() + "?mode=ro"
                    with (closing(sqlite3.connect(source_database, uri=True)) as original_db,
                          closing(sqlite3.connect(database)) as snapshot_db):
                        original_db.backup(snapshot_db)
                        assert snapshot_db.execute("PRAGMA journal_mode=DELETE").fetchone() == ("delete",)

                    wal = snapshot / "rpmdb.sqlite-wal"
                    checked(["/usr/bin/mount", "--bind", snapshot, rpm_path])
                    try:
                        search("isolated-rpmdb-seed", identity, updated, 1)
                        for cycle in range(8):
                            assert not wal.exists()
                            wal.touch(mode=0o644)
                            search(f"empty-wal-{cycle}-created", identity, updated, 0)
                            assert wal.stat().st_size == 0
                            stat_before = wal.stat()
                            os.utime(wal, ns=(stat_before.st_atime_ns, stat_before.st_mtime_ns + 1_000_000_000))
                            search(f"empty-wal-{cycle}-mtime", identity, updated, 0)
                            wal.chmod(0o640)
                            search(f"empty-wal-{cycle}-permissions", identity, updated, 0)
                            wal.unlink()
                            search(f"empty-wal-{cycle}-removed", identity, updated, 0)
                    finally:
                        checked(["/usr/bin/umount", rpm_path])
                finally:
                    checked(["/usr/bin/umount", target])
                    config.write_text(host_config)
                    repo_file.write_text(repo_config)
                    restore_test_summary(original)

            refresh_fixture()
            if consent_oracle is not None:
                inspect_install_picker()
            host_explicit = len(set(ordinary_control([dnf, "--cacheonly", "--setopt=disable_excludes=*",
                                                      "repoquery", "--userinstalled", "--qf", r"%{name}\n"]).splitlines()))
            assert host_count > 1 and host_explicit > 1
            with running_daemon(log):
                assert json.loads(persisted.read_text())["status"]["total_packages"] == host_count
                initial_status = persisted.read_bytes()
                inspect("initial-host", host_count, host_explicit, host=True)
                mark_progress("initial host inventory")
                if consent_oracle is not None:
                    inspect_daemon_metrics()
                    inspect_history_locks()
                    inspect_audit_segments()
                    inspect_audit_log_selection()
                    inspect_audit_marker_snapshot()
                    inspect_audit_record_windows()
                    inspect_daemon_audit_recovery()
                    inspect_secret_scan()
                    inspect_artifact_signature_inputs()
                    inspect_environment_lockfiles()
                    mark_progress("audit and lockfiles")
                    inspect_team_storage()
                    inspect_team_commands()
                    inspect_team_push_publication()
                    inspect_git_workflow()
                    inspect_scaffold_publication()
                    inspect_workspace_lifecycle()
                    inspect_workspace_graph_and_diff()
                    mark_progress("team and workspace")
                    inspect_task_selection()
                    inspect_task_watch()
                    mark_progress("task selection and watch")
                    runtime_advisory_fixture = stage_runtime_fixture(root)
                    inspect_task_runtime_admissions()
                    inspect_task_version_requirements()
                    inspect_node_alias_selection()
                    inspect_python_project_constraints()
                    inspect_python_virtualenv_launch()
                    inspect_python_inventory_and_removal()
                    inspect_python_tool_prerequisites()
                    inspect_managed_tool_inventory()
                    inspect_fedora_system_tool_registry()
                    inspect_named_tool_updates()
                    inspect_config_files()
                    inspect_fedora_output_admission()
                    inspect_man_pages()
                    mark_progress("runtime selection and Python environments")
                    inspect_task_environment_bytes()
                    inspect_task_package_metadata()
                    inspect_mise_task_execution()
                    mark_progress("task environment and mise")
                config.write_text(alternate_config)
                refresh_fixture()
                expected = ordinary_control([dnf, "--cacheonly", "repoquery",
                                             "--installed", "--qf", r"%{name}\n"]).splitlines()
                assert expected == [package], expected
                assert persisted.read_bytes() == initial_status
                inspect("switched-alternate", 1, 1, fixture_explicit=True)
                if consent_oracle is not None:
                    inspect_enterprise_inventory()
                    inspect_audit_licenses()
                    inspect_info_attempts()
                    inspect_info_json_writes()
                    inspect_dashboard_terminal()
                    inspect_migration()
                    inspect_snapshots()
                    inspect_snapshot_recovery()
                    inspect_privacy_commands()
                    inspect_telemetry_storage()
                    inspect_telemetry_queue_overlap()
                    inspect_telemetry_consent_transitions()
                    inspect_install_telemetry_admission()
                    inspect_usage_dispatch_admission()
                    inspect_saved_usage_stats()
                    inspect_account_storage()
                    inspect_machine_identity()
                    inspect_dashboard_token_admission()
                config.write_text(host_config)
                inspect("returned-host", host_count, host_explicit, host=True)
                mark_progress("root switch and return")
                if consent_oracle is not None:
                    inspect_epoch_read_paths()
                original_manifest = manifest.read_bytes()
                inspect_repository("repository-initial", True)
                repo_file.write_text(repo_config.replace("enabled=1", "enabled=0"))
                inspect_repository("repository-disabled", False)
                repo_file.write_text(repo_config)
                refresh_fixture()
                inspect_repository("repository-enabled-again", True)
                overrides = private_dnf / "repos.override.d"
                overrides.mkdir(exist_ok=True)
                override = overrides / "99-omg-fixture.repo"
                override.write_text("[signed-fixture]\nenabled=0\n")
                inspect_repository("repository-override-disabled", False)
                override.unlink()
                refresh_fixture()
                inspect_repository("repository-override-removed", True)
                repo_file.write_text(repo_config + f"excludepkgs={package}\n")
                refresh_fixture()
                inspect_repository("repository-excluded", False)
                repo_file.write_text(repo_config)
                refresh_fixture()
                inspect_repository("repository-exclusion-removed", True)

                # Publish an empty signed catalogue at the original repo URL.
                new_manifest = ET.fromstring(original_manifest)
                for data in list(new_manifest.findall(f"{repo_ns}data")):
                    new_manifest.remove(data)
                empty = b'<metadata xmlns="http://linux.duke.edu/metadata/common" packages="0"/>'
                append_metadata(new_manifest, "primary", "repodata/primary-empty.xml.gz", empty)
                manifest.write_bytes(ET.tostring(new_manifest))
                sign_manifest()
                ordinary_control([dnf, "clean", "metadata"])
                refresh_fixture()
                inspect_repository("repository-metadata-empty", False)
                manifest.write_bytes(original_manifest)
                sign_manifest()
                ordinary_control([dnf, "clean", "metadata"])
                refresh_fixture()
                inspect_repository("repository-metadata-restored", True)
                if consent_oracle is not None:
                    inspect_native_report_deadlines()
                    inspect_multiline_summary(original_manifest)
                    inspect_expired_catalog("repository-expiry", original_manifest, work/"custom-dnf-cache")

                    per_repo_cache = work/"per repository cache"
                    try:
                        repo_file.write_text(repo_config + f"cachedir={per_repo_cache}\n")
                        refresh_fixture()
                        inspect_expired_catalog("repository-expiry-custom", original_manifest, per_repo_cache)
                    finally:
                        repo_file.write_text(repo_config)
                        refresh_fixture()
                    inspect_aged_catalog("repository-aged", original_manifest, 6)
                    inspect_aged_catalog("repository-age-zero", original_manifest, 0)
                    for policy in ("never", "all", "metadata"):
                        inspect_cached_age_policy(original_manifest, policy)
                    inspect_direct_catalog_cache(original_manifest)

            fast.unlink(missing_ok=True)
            persisted.unlink(missing_ok=True)
            state_option = "/var/lib/omg-fixture-dnf-state"
            custom_state = alternate / Path(state_option).relative_to("/")
            custom_state.mkdir(parents=True)
            os.chown(custom_state, account.pw_uid, account.pw_gid)
            custom_config = alternate_config.replace("plugins=0\n", f"plugins=0\nsystem_state_dir={state_option}\n")
            (alternate / "etc/dnf/dnf.conf").write_text(custom_config)
            config.write_text(custom_config)
            database_directory = checked([rpm, "--eval", "%{_dbpath}"]).strip()
            database = alternate / Path(database_directory).relative_to("/") / "rpmdb.sqlite"
            identity = database.stat().st_dev, database.stat().st_ino
            mark("user")
            assert native_installed() == [package] and native_explicit() == [package]
            with running_daemon(log):
                cached = json.loads(persisted.read_text())["status"]
                assert cached["total_packages"] == 1 and cached["explicit_packages"] == 1
                inspect("same-root-initial", 1, 1, fixture_explicit=True)
                reasons_before = (custom_state / "packages.toml").read_bytes()
                mark("dependency")
                assert (custom_state / "packages.toml").read_bytes() != reasons_before
                assert native_installed() == [package] and native_explicit() == []
                assert (database.stat().st_dev, database.stat().st_ino) == identity
                inspect("same-root-dependency", 1, 0)
                checked([rpm, "--root", alternate, "-e", package])
                assert native_installed() == [] and native_explicit() == []
                assert (database.stat().st_dev, database.stat().st_ino) == identity
                inspect("same-root-erased", 0, 0)
                checked([rpm, "--root", alternate, "-U", "--nosignature", fixture/"observer-fixture.rpm"])
                mark("user")
                assert native_installed() == [package] and native_explicit() == [package]
                assert (database.stat().st_dev, database.stat().st_ino) == identity
                inspect("same-root-reinstalled", 1, 1, fixture_explicit=True)

            fast.unlink(missing_ok=True)
            persisted.unlink(missing_ok=True)
            old_build = root / "old-rpm"
            old_build.mkdir()
            old_spec = old_build / "observer.spec"
            spec = (fixture / "observer-fixture.spec").read_text()
            assert spec.count("Version: 1\n") == 1
            old_spec.write_text(spec.replace("Version: 1\n", "Version: 0\n"))
            checked(["/usr/bin/rpmbuild", "--define", f"_topdir {old_build}", "-bb", old_spec])
            old_rpm = old_build / f"RPMS/noarch/{package}-0-1.noarch.rpm"
            checked([rpm, "--root", alternate, "-U", "--oldpackage", "--nosignature", old_rpm])
            mark("user")
            assert native_explicit() == [package]
            version = checked([rpm, "--root", alternate, "-q", "--qf", "%{VERSION}", package])
            assert version == "0"
            metadata = ET.fromstring(original_manifest)
            advisory_metadata(metadata)
            manifest.write_bytes(ET.tostring(metadata))
            sign_manifest()
            ordinary_control([dnf, "clean", "metadata"])
            ordinary_control([dnf, *advisory_options, "clean", "metadata"])
            refresh_fixture()

            def native_advisories(expected):
                output = ordinary_control([dnf, *advisory_options, "--cacheonly", "advisory", "list",
                                            "--security", "--available", "--json"])
                assert [row["name"] for row in json.loads(output)] == expected

            def cached_manifests(cache):
                return {str(path.relative_to(cache)): (path.stat().st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest())
                        for path in cache.glob("*/repodata/repomd.xml")}

            normal_cache = alternate / work.relative_to("/") / ".cache/libdnf5"
            native_advisories([advisory_id])
            ordinary_control([dnf, *advisory_options, "clean", "metadata"])
            assert not cached_manifests(advisory_cache)
            with reject_native_selection("%{lua:", executable=rpm, prefix=True), running_daemon(log):
                snapshot = json.loads(persisted.read_text())["status"]
                findings = snapshot["security_vulnerabilities"]
                updates = snapshot["updates_available"]
                checks.append(dict(phase="status-repository-initial", case="advisory-without-rpm-version-process",
                                   passed=findings == 1 and updates == 1, findings=findings, updates=updates,
                                   diagnostic=(root / "daemon.log").read_text(errors="replace")[-1200:]
                                   if findings != 1 or updates != 1 else None))
                inspect_update_status("status-repository-initial", 1, True)
                inspect_advisory_details("with-matching-advisories", True)
                normal_manifests = cached_manifests(normal_cache)
                advisory_manifests = cached_manifests(advisory_cache)
                assert normal_manifests and advisory_manifests

                # Change the dedicated advisory cache while holding the package
                # query cache, RPM database and repo configuration fixed.
                manifest.write_bytes(original_manifest)
                sign_manifest()
                ordinary_control([dnf, *advisory_options, "clean", "metadata"])
                ordinary_control([dnf, *advisory_options, "--refresh", "-y", "makecache"])
                native_advisories([])
                inspect_advisory_details("without-matching-advisories", False)
                assert cached_manifests(normal_cache) == normal_manifests
                assert cached_manifests(advisory_cache) != advisory_manifests
                inspect_update_status("status-advisory-only", 1, False)
                advisory_manifests = cached_manifests(advisory_cache)

                def refresh_advisory_while_counting(_handoff):
                    distinct = ET.fromstring(original_manifest)
                    distinct.find(f"{repo_ns}revision").text = str(time.time_ns())
                    manifest.write_bytes(ET.tostring(distinct))
                    sign_manifest()
                    ordinary_control([dnf, *advisory_options, "clean", "metadata"])
                    ordinary_control([dnf, *advisory_options, "--refresh", "-y", "makecache"])
                    assert cached_manifests(normal_cache) == normal_manifests
                    assert cached_manifests(advisory_cache) != advisory_manifests

                exit_code, stdout, stderr = status_during(refresh_advisory_while_counting)
                counts = [line.split()[2] for line in stdout.splitlines()
                          if line.split()[:2] == ["Updates", "available:"]]
                checks.append(dict(phase="status-advisory-during-count", case="daemon-status",
                                   passed=exit_code == 0 and counts == ["1"]
                                   and "Advisory coverage:  unreported" in stdout,
                                   status=exit_code, value=(stdout + stderr)[-1200:]))
                advisory_manifests = cached_manifests(advisory_cache)

                def refresh_packages_while_counting(_handoff):
                    manifest.write_bytes(ET.tostring(new_manifest))
                    sign_manifest()
                    ordinary_control([dnf, "clean", "metadata"])
                    ordinary_control([dnf, "--refresh", "-y", "makecache"])
                    assert cached_manifests(advisory_cache) == advisory_manifests
                    assert cached_manifests(normal_cache) != normal_manifests

                exit_code, stdout, stderr = status_during(refresh_packages_while_counting)
                checks.append(dict(phase="status-package-change-during-count", case="daemon-status",
                                   passed=exit_code != 0 and "Package Cache" not in stdout
                                   and "Package status inputs changed during the query" in stderr,
                                   status=exit_code, value=(stdout + stderr)[-1200:]))
                inspect_update_status("status-metadata-only", 0, False)
                if consent_oracle is not None:
                    inspect_update_query_refusal("update-empty-native-installed", "--installed", True)
                    inspect_update_query_refusal("update-empty-native-upgrades", "--upgrades", False)
                    inspect_overlapping_status("status-metadata-only", 0)
                    inspect_status_inventory_scope("status-metadata-only", 0, custom_state)
                    inspect_independent_counters("independent-counters-empty", 0, 0)
                    inspect_read_only_updates("update-read-no-upgrades", 0)

                manifest.write_bytes(original_manifest)
                sign_manifest()
                ordinary_control([dnf, "clean", "metadata"])
                ordinary_control([dnf, "--refresh", "-y", "makecache"])
                inspect_update_status("status-metadata-restored", 1, False)
                if consent_oracle is not None:
                    inspect_update_query_refusal("update-present-native-installed", "--installed", False)
                    inspect_overlapping_status("status-metadata-restored", 1)
                    inspect_status_inventory_scope("status-metadata-restored", 1, custom_state)
                    inspect_fast_status_modes("fast-status-with-upgrade", 1)
                    inspect_status_write_failures()
                    mark("dependency")
                    try:
                        inspect_independent_counters("independent-counters-populated", 1, 1)
                        inspect_fast_status_modes("fast-status-with-upgrade-and-orphan", 0)
                        inspect_read_only_updates("update-read-upgrades", 1)
                    finally:
                        mark("user")
                    pending = custom_state / "omg-fixture.new"
                    pending.touch(exist_ok=False)
                    try:
                        inspect_status_inventory_scope("status-inventory-native-fallback", 1, custom_state,
                                                       native_reasons=True)
                        assert pending.is_file()
                    finally:
                        pending.unlink()
                normal_manifests = cached_manifests(normal_cache)

                def disable_repository_while_counting(_handoff):
                    alternate_repo.write_text(repo_config.replace("enabled=1", "enabled=0"))
                    assert cached_manifests(normal_cache) == normal_manifests
                    assert cached_manifests(advisory_cache) == advisory_manifests

                exit_code, stdout, stderr = status_during(disable_repository_while_counting)
                checks.append(dict(phase="status-repo-config-during-count", case="daemon-status",
                                   passed=exit_code != 0 and "Package Cache" not in stdout
                                   and "Package status inputs changed during the query" in stderr,
                                   status=exit_code, value=(stdout + stderr)[-1200:]))
                inspect_update_status("status-repository-disabled", 0, False)
                assert checked([rpm, "--root", alternate, "-q", "--qf", "%{VERSION}", package]) == "0"

            inspect_security_inventory("inventory-alternate-old", 1)
            checked([rpm, "--root", alternate, "-e", package])
            inspect_security_inventory("inventory-alternate-empty", 0)
            checked([rpm, "--root", alternate, "-U", "--nosignature", fixture/"observer-fixture.rpm"])
            inspect_security_inventory("inventory-alternate-restored", 1)

            if consent_oracle is not None:
                mark("user")
                inspect_explicit_without_query("explicit-native-user", [package])
                mark("dependency")
                inspect_explicit_without_query("explicit-native-dependency", [])
                groups = custom_state / "groups.toml"
                packages_state = custom_state / "packages.toml"
                initial_groups = groups.read_bytes()
                initial_packages = packages_state.read_bytes()
                try:
                    packages_state.write_bytes(initial_packages.replace(b'"Dependency"', b'"Weak Dependency"'))
                    assert packages_state.read_bytes() != initial_packages
                    inspect_explicit_without_query("explicit-native-weak-dependency", [])
                    packages_state.write_bytes(initial_packages)
                    with groups.open("a") as group_file:
                        group_file.write(f'\n[groups.omg-fixture]\nuserinstalled = false\n'
                                         f'packages = ["{package}"]\npackage_types = ["mandatory"]\n')
                    inspect_explicit_without_query("explicit-native-group", [package])
                    groups.write_bytes(initial_groups)
                    packages_state.write_text('version = "1.0"\n[packages]\n')
                    inspect_explicit_without_query("explicit-native-external", [package])
                    packages_state.write_text("[packages")
                    inspect_explicit_refusal("explicit-unsupported-state", "malformed-reasons", "packages.toml")
                    packages_state.write_bytes(initial_packages)
                    with (custom_state / "system-repo.lock").open("r+") as lock:
                        fcntl.lockf(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        with reject_native_selection("--userinstalled"):
                            inspect_explicit_refusal("explicit-locked-state", "native-fallback",
                                                     "Unexpected DNF selection subprocess")
                    legacy_dir = alternate / "var/lib/omg-fixture-legacy"
                    legacy_dir.mkdir()
                    (legacy_dir / "history.sqlite").touch()
                    legacy_config = custom_config.replace("plugins=0\n",
                                                          "plugins=0\npersistdir=/var/lib/omg-fixture-legacy\n")
                    config.write_text(legacy_config)
                    (alternate / "etc/dnf/dnf.conf").write_text(legacy_config)
                    try:
                        with reject_native_selection("--userinstalled"):
                            inspect_explicit_refusal("explicit-legacy-history", "native-fallback",
                                                     "Unexpected DNF selection subprocess")
                    finally:
                        config.write_text(custom_config)
                        (alternate / "etc/dnf/dnf.conf").write_text(custom_config)
                finally:
                    groups.write_bytes(initial_groups)
                    packages_state.write_bytes(initial_packages)
                inspect_dotted_install_reasons(custom_state)
                inspect_upgrade_review(old_rpm)
                inspect_removal_replay()
                mark_progress("native install and removal")
            config.write_text(host_config)
            inspect_security_inventory("inventory-host")
            if consent_oracle is not None:
                inspect_explicit_without_query("explicit-native-host")
        except Exception:
            log.seek(0)
            print(log.read()[-4500:], file=sys.stderr)
            raise
        finally:
            checked(["/usr/bin/gpgconf", "--homedir", keys, "--kill", "gpg-agent"])
            for path in ("/var/log", "/var/cache", "/etc/dnf"):
                checked(["/usr/bin/umount", path])

assert config.read_bytes() == config_before
assert inventory() == before
mark_progress("completed with host inventory unchanged")
report = dict(binaries=binaries, checks=checks, total=len(checks),
              passed=sum(entry["passed"] for entry in checks), host_unchanged=True)
print(json.dumps(report))
expected_checks = 303 if consent_oracle is None else 3011
if report["passed"] != report["total"] or report["total"] != expected_checks:
    sys.exit(4)
