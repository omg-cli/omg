#!/usr/bin/env python3
"""Verify live Fedora caches across repository, advisory, installroot, and inventory changes.

Run as root in private mount and network namespaces without network routes.
The arguments are the inert Fedora fixture directory and the built omg and
omgd binaries. All RPM writes go to a disposable installroot.
"""
from contextlib import ExitStack, contextmanager
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
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

def command(args, env=base_env, identity=None):
    return subprocess.run([str(part) for part in args], cwd=env.get("HOME", "/"),
                          stdin=subprocess.DEVNULL, capture_output=True, text=True,
                          env=env, timeout=30, **(identity or {}))

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
        for label, args, verify in cases:
            counters_before = request_counters() if label == "status-json" else None
            result = command([cli, *args], env, ordinary)
            if counters_before is not None:
                requests, failures = request_counters()
                # The second metrics call contributes one request alongside Status.
                requests -= counters_before[0] + 1
                failures -= counters_before[1]
                checks.append(dict(phase=phase, case="status-ipc", passed=requests == 1 and failures == 0,
                                   value=dict(requests=requests, failures=failures)))
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

    def status_during(change):
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
                with subprocess.Popen([str(cli), "daemon-status"], cwd=work, env=env,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      stdin=subprocess.DEVNULL, text=True, **ordinary) as status:
                    try:
                        wait_for(arrived.exists, status)
                        change()
                        resume.touch()
                        stdout, stderr = status.communicate(timeout=25)
                        return status.returncode, stdout, stderr
                    finally:
                        if status.poll() is None:
                            status.kill()
                            status.wait(4)
            finally:
                checked(["/usr/bin/umount", target])

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
                    result = command([cli, "--json", "search", "--limit", "1", query], disabled, ordinary)
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
                                       and observed == calls, value={"calls": observed, "rows": value},
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
                config.write_text(alternate_config)
                refresh_fixture()
                expected = ordinary_control([dnf, "--cacheonly", "repoquery",
                                             "--installed", "--qf", r"%{name}\n"]).splitlines()
                assert expected == [package], expected
                assert persisted.read_bytes() == initial_status
                inspect("switched-alternate", 1, 1, fixture_explicit=True)
                config.write_text(host_config)
                inspect("returned-host", host_count, host_explicit, host=True)
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

                def refresh_advisory_while_counting():
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

                def refresh_packages_while_counting():
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

                manifest.write_bytes(original_manifest)
                sign_manifest()
                ordinary_control([dnf, "clean", "metadata"])
                ordinary_control([dnf, "--refresh", "-y", "makecache"])
                inspect_update_status("status-metadata-restored", 1, False)
                if consent_oracle is not None:
                    inspect_update_query_refusal("update-present-native-installed", "--installed", False)
                normal_manifests = cached_manifests(normal_cache)

                def disable_repository_while_counting():
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
expected_checks = 303 if consent_oracle is None else 572
if report["passed"] != report["total"] or report["total"] != expected_checks:
    sys.exit(4)
