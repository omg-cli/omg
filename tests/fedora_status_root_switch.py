#!/usr/bin/env python3
"""Verify a live Fedora daemon across a DNF installroot switch.

Run as root in private mount and network namespaces without network routes.
The arguments are the inert Fedora fixture directory and the built omg and
omgd binaries. All RPM writes go to a disposable installroot.
"""
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

if not __debug__ or len(sys.argv) != 4:
    raise SystemExit("requires assertions and arguments FIXTURE_DIR OMG OMGD")
fixture, candidate, daemon = (Path(value).resolve(strict=True) for value in sys.argv[1:])
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
        "enabled=1\ngpgcheck=1\nrepo_gpgcheck=1\nskip_if_unavailable=false\n"
        f"gpgkey={public.as_uri()}\n"
    )
    main = "[main]\nplugins=0\nreposdir=\n"
    host_config = main + repo_config
    alternate_config = main + f"installroot={alternate}\n" + repo_config
    (alternate / "etc/dnf/dnf.conf").write_text(alternate_config)
    config.write_text(host_config)
    fast = runtime / "omg.status"
    persisted = work / "daemon-data/status-cache.json"

    native_env = {key: value for key, value in env.items() if not key.startswith("XDG_")}

    def ordinary_control(command_line):
        return checked(command_line, native_env, ordinary)

    def request_counters():
        counters = dict(line.split() for line in checked([cli, "metrics"], env, ordinary).splitlines()
                        if line.startswith(("omg_requests_total ", "omg_requests_failed_total ")))
        return int(counters["omg_requests_total"]), int(counters["omg_requests_failed_total"])

    def inspect(phase, expected_total, expected_explicit, expected_bash):
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
            ("explicit", ["--json", "explicit"], lambda value: len(value["packages"]) == expected_explicit and (package in value["packages"]) != expected_bash),
            ("explicit-count", ["--json", "explicit", "--count"], lambda value: value["count"] == expected_explicit),
            ("ec-json", ["--json", "ec"], lambda value: value["count"] == expected_explicit),
            ("ec-text", ["ec"], lambda value: value == expected_explicit),
            ("search", ["--json", "search", "bash"], lambda value: any(item["name"] == f"bash.{os.uname().machine}" for item in value) == expected_bash),
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

    with (root / "daemon.log").open("w+") as log:
        try:
            checked([*gpg, "--quick-generate-key", "OMG Fedora status fixture <fixture@example.invalid>", "rsa2048", "sign", "1d"])
            manifest = repo / "repodata/repomd.xml"
            public.write_text(checked([*gpg, "--armor", "--export"]))
            checked([*gpg, "--armor", "--detach-sign", "--output", manifest.with_suffix(".xml.asc"), manifest])
            advisory_cache = work / "cache/omg/dnf-security"
            def refresh_fixture():
                for args in ([], [f"--setopt=cachedir={advisory_cache}", f"--setopt=system_cachedir={advisory_cache}"]):
                    ordinary_control([dnf, *args, "--refresh", "-y", "makecache"])
            refresh_fixture()
            host_explicit = len(set(ordinary_control([dnf, "--cacheonly", "--setopt=disable_excludes=*",
                                                      "repoquery", "--userinstalled", "--qf", r"%{name}\n"]).splitlines()))
            assert host_count > 1 and host_explicit > 1
            with subprocess.Popen([str(server)], cwd=work, env=env, stdout=log, stderr=subprocess.STDOUT,
                                  stdin=subprocess.DEVNULL, **ordinary) as process:
                try:
                    wait_for(lambda: fast.exists() and persisted.exists(), process)
                    assert stat.S_IMODE((runtime/"omg.sock").stat().st_mode) == 0o600
                    assert json.loads(persisted.read_text())["status"]["total_packages"] == host_count
                    initial_status = persisted.read_bytes()
                    inspect("initial-host", host_count, host_explicit, True)
                    config.write_text(alternate_config)
                    refresh_fixture()
                    expected = sorted(ordinary_control([dnf, "--cacheonly", "repoquery",
                                                        "--installed", "--qf", r"%{name}\n"]).splitlines())
                    assert expected == [package], expected
                    assert persisted.read_bytes() == initial_status
                    inspect("switched-alternate", 1, 1, False)
                    config.write_text(host_config)
                    inspect("returned-host", host_count, host_explicit, True)
                    assert process.poll() is None
                finally:
                    if process.poll() is None:
                        process.send_signal(signal.SIGTERM)
                        try:
                            process.wait(8)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(4)
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
if report["passed"] != report["total"] or report["total"] != 48:
    sys.exit(4)
