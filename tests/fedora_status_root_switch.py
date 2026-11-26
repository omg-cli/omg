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
            ("status-fast-json", ["--json", "status", "--fast"], env, lambda value: json.loads(value)["updates_available"] == expected_updates),
            ("direct-status-json", ["--json", "status"], disabled, lambda value: json.loads(value)["updates_available"] == expected_updates),
            ("tc", ["--json", "tc"], env, lambda value: json.loads(value) == {"count": 1}),
            ("ec", ["--json", "ec"], env, lambda value: json.loads(value) == {"count": 1}),
            ("advisory-status", ["status", "--fast"], env, lambda value: advisory_status(value, expected_findings)),
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

                def search(label, query, summary, calls):
                    before = drop.read_bytes().count(b"\n")
                    started = time.perf_counter_ns()
                    result = command([cli, "--json", "search", "--limit", "1", query], disabled, ordinary)
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
            host_explicit = len(set(ordinary_control([dnf, "--cacheonly", "--setopt=disable_excludes=*",
                                                      "repoquery", "--userinstalled", "--qf", r"%{name}\n"]).splitlines()))
            assert host_count > 1 and host_explicit > 1
            with running_daemon(log):
                assert json.loads(persisted.read_text())["status"]["total_packages"] == host_count
                initial_status = persisted.read_bytes()
                inspect("initial-host", host_count, host_explicit, host=True)
                if consent_oracle is not None:
                    inspect_history_locks()
                    inspect_audit_segments()
                    inspect_audit_log_selection()
                    inspect_audit_marker_snapshot()
                    inspect_audit_record_windows()
                    inspect_daemon_audit_recovery()
                    inspect_secret_scan()
                    inspect_artifact_signature_inputs()
                    inspect_environment_lockfiles()
                    inspect_team_storage()
                    inspect_team_commands()
                    inspect_team_push_publication()
                    inspect_git_workflow()
                    inspect_scaffold_publication()
                config.write_text(alternate_config)
                refresh_fixture()
                expected = ordinary_control([dnf, "--cacheonly", "repoquery",
                                             "--installed", "--qf", r"%{name}\n"]).splitlines()
                assert expected == [package], expected
                assert persisted.read_bytes() == initial_status
                inspect("switched-alternate", 1, 1, fixture_explicit=True)
                if consent_oracle is not None:
                    inspect_info_attempts()
                config.write_text(host_config)
                inspect("returned-host", host_count, host_explicit, host=True)
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
                    mark("dependency")
                    try:
                        inspect_independent_counters("independent-counters-populated", 1, 1)
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
                inspect_upgrade_review(old_rpm)
                inspect_removal_replay()
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
report = dict(binaries=binaries, checks=checks, total=len(checks),
              passed=sum(entry["passed"] for entry in checks), host_unchanged=True)
print(json.dumps(report))
expected_checks = 303 if consent_oracle is None else 1220
if report["passed"] != report["total"] or report["total"] != expected_checks:
    sys.exit(4)
