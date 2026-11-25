#!/usr/bin/env python3
"""Verify live Fedora caches across repository, advisory, installroot, and inventory changes.

Run as root in private mount and network namespaces without network routes.
The arguments are the inert Fedora fixture directory and the built omg and
omgd binaries. All RPM writes go to a disposable installroot.
"""
from contextlib import contextmanager
import gzip
import hashlib
import json
import os
from pathlib import Path
import pwd
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
        target = Path(dnf).resolve(strict=True)
        with tempfile.TemporaryDirectory(prefix="dnf-inventory-", dir=root) as directory:
            gate = Path(directory)
            gate.chmod(0o755)
            native_dnf = gate / target.name
            shutil.copy2(target, native_dnf)
            wrapper = gate / "detect-inventory"
            wrapper.write_text(f"""#!/usr/bin/bash
installed=false
query=false
for argument in "$@"; do
    if [[ "$argument" == --installed ]]; then installed=true; fi
    if [[ "$argument" == repoquery ]]; then query=true; fi
done
if "$installed" && "$query"; then
    printf '%s\\n' 'Unexpected DNF inventory subprocess' >&2
    exit 197
fi
exec {shlex.quote(str(native_dnf))} "$@"
""")
            wrapper.chmod(0o755)
            checked(["/usr/bin/mount", "--bind", wrapper, target])
            try:
                inspect("without-dnf-inventory")
            finally:
                checked(["/usr/bin/umount", target])

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
            with running_daemon(log):
                snapshot = json.loads(persisted.read_text())["status"]
                assert snapshot["security_vulnerabilities"] == 1 and snapshot["updates_available"] == 1
                inspect_update_status("status-repository-initial", 1, True)
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

                manifest.write_bytes(original_manifest)
                sign_manifest()
                ordinary_control([dnf, "clean", "metadata"])
                ordinary_control([dnf, "--refresh", "-y", "makecache"])
                inspect_update_status("status-metadata-restored", 1, False)
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
            config.write_text(host_config)
            inspect_security_inventory("inventory-host")
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
if report["passed"] != report["total"] or report["total"] != 264:
    sys.exit(4)
