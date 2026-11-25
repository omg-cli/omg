#!/usr/bin/env python3
"""Check Fedora sync against independently observable caller and system caches."""
from contextlib import contextmanager
import gzip
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

assert __debug__ and os.getuid() == 0 and len(sys.argv) == 4
assert Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()[4] == "0"
fixture, binary, daemon = (Path(argument).resolve(strict=True) for argument in sys.argv[1:])
assert all(os.readlink(f"/proc/self/ns/{kind}") != os.readlink(f"/proc/1/ns/{kind}")
           for kind in ("mnt", "net"))
assert json.loads(subprocess.check_output(["/usr/bin/ip", "-j", "route", "show", "table", "all"])) == []
account = pwd.getpwnam("nobody")
ordinary = dict(user=account.pw_uid, group=account.pw_gid, extra_groups=[])
base = dict(PATH="/usr/sbin:/usr/bin:/sbin:/bin", LC_ALL="C.UTF-8")
native_dnf = Path("/usr/bin/dnf").resolve(strict=True)
rpm = "/usr/bin/rpm"
sudo = "/usr/bin/sudo"
package = "omg-observer-fixture"
repo_id = "omg-sync-fixture"
checks = []

def run(argv, env=base, identity=None):
    return subprocess.run([str(value) for value in argv], env=env, cwd=env.get("HOME", "/"),
                          stdin=subprocess.DEVNULL, capture_output=True, text=True,
                          timeout=25, **(identity or {}))

def checked(argv, env=base, identity=None):
    result = run(argv, env, identity)
    assert result.returncode == 0, (argv, result.returncode, result.stdout[-900:], result.stderr[-1200:])
    return result.stdout

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def host_fingerprint():
    inventory = checked([rpm, "-qa", "--qf", "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n"])
    reasons = {str(path): digest(path) for path in Path("/usr/lib/sysimage/libdnf5").glob("*.toml")}
    paths = [Path(value) for value in (
        "/etc/dnf/dnf.conf", "/etc/sudoers", "/var/lib/omg/history.json", "/var/lib/omg/audit/audit.jsonl"
    )]
    return sorted(inventory.splitlines()), reasons, {str(path): digest(path) for path in paths if path.is_file()}

def verify(name, condition, value):
    checks.append(dict(case=name, passed=bool(condition), value=value))

@contextmanager
def private_mounts(entries):
    mounted = []
    try:
        for source, target in entries:
            assert Path(target).resolve(strict=True) == Path(target)
            checked(["/usr/bin/mount", "--bind", source, target])
            mounted.append(target)
        yield
    finally:
        for target in reversed(mounted):
            checked(["/usr/bin/umount", target])

before = host_fingerprint()
assert not any(line.startswith(package + "-") for line in before[0])
with tempfile.TemporaryDirectory(prefix="omg-fedora-sync-audit-", dir="/tmp") as workspace:
    root = Path(workspace)
    root.chmod(0o755)
    private_dnf = root / "dnf"
    shutil.copytree("/etc/dnf", private_dnf, symlinks=True)
    host_dirs = ("/opt", "/var/cache", "/var/log", "/var/lib/omg")
    for target in host_dirs:
        (root / Path(target).name).mkdir(mode=0o755)
    policy = root / "sudoers"
    policy.touch(mode=0o440)
    sudo_log = root / "sudo.log"
    mounts = [(root / Path(target).name, target) for target in host_dirs]
    mounts.extend([(private_dnf, "/etc/dnf"), (policy, "/etc/sudoers")])

    with private_mounts(mounts):
        cli = Path("/opt/omg")
        server = Path("/opt/omgd")
        shutil.copy2(binary, cli)
        shutil.copy2(daemon, server)
        home, root_home = root / "ordinary", root / "privileged"
        for path in (home, root_home, home / "run"):
            path.mkdir(mode=0o700)
            if path != root_home:
                os.chown(path, account.pw_uid, account.pw_gid)
        env = dict(base, HOME=str(home), XDG_RUNTIME_DIR=str(home/"run"),
                   OMG_SOCKET_PATH=str(home/"run/omg.sock"), OMG_DAEMON_DATA_DIR=str(home/"daemon"),
                   OMG_DISABLE_TELEMETRY="1", NO_COLOR="1")
        root_env = dict(base, HOME=str(root_home), OMG_DISABLE_TELEMETRY="1",
                        OMG_DISABLE_DAEMON="1", NO_COLOR="1")
        repo = root / "repo"
        shutil.copytree(fixture, repo)
        keys = root / "keys"
        keys.mkdir(mode=0o700)
        gpg = ["/usr/bin/gpg", "--homedir", keys, "--batch", "--pinentry-mode", "loopback", "--passphrase", ""]
        key = root / "fixture.asc"
        config = Path("/etc/dnf/dnf.conf")
        config.write_text("[main]\nplugins=0\nreposdir=\n" +
                          f"[{repo_id}]\nname=Fedora sync fixture\nbaseurl={repo.as_uri()}\n" +
                          f"enabled=1\ngpgcheck=1\nrepo_gpgcheck=1\ngpgkey={key.as_uri()}\n" +
                          "build_cache=0\nskip_if_unavailable=false\n")
        manifest = repo / "repodata/repomd.xml"
        original = manifest.read_bytes()
        ns = "{http://linux.duke.edu/metadata/repo}"
        ET.register_namespace("", ns[1:-1])
        empty = ET.fromstring(original)
        for entry in empty.findall(f"{ns}data"):
            empty.remove(entry)
        payload = b'<metadata xmlns="http://linux.duke.edu/metadata/common" packages="0"/>'
        compressed = gzip.compress(payload, mtime=0)
        (repo / "repodata/primary-empty.xml.gz").write_bytes(compressed)
        primary = ET.SubElement(empty, f"{ns}data", type="primary")
        for name, content in (("checksum", compressed), ("open-checksum", payload)):
            ET.SubElement(primary, f"{ns}{name}", type="sha256").text = hashlib.sha256(content).hexdigest()
        ET.SubElement(primary, f"{ns}location", href="repodata/primary-empty.xml.gz")
        for name, value in (("timestamp", 1), ("size", len(compressed)), ("open-size", len(payload))):
            ET.SubElement(primary, f"{ns}{name}").text = str(value)

        def set_policy(allow):
            stamp = root / "sudo-timestamps"
            stamp.mkdir(exist_ok=True, mode=0o700)
            # This policy is visible solely inside the isolated namespace.
            content = (f"Defaults !use_pty, timestamp_timeout=0, timestampdir={stamp}, logfile={sudo_log}\n"
                       "root ALL=(root) ALL\n")
            if allow:
                content += (f"nobody ALL=(root) NOPASSWD: {cli} __omg_elevated sync, "
                            f"{native_dnf} --refresh makecache -y\n")
            policy.write_text(content)
            checked(["/usr/sbin/visudo", "-c", "-f", "/etc/sudoers"])
            return run([sudo, "-n", "-v"], env, ordinary).returncode

        def publish(available):
            tree = ET.fromstring(original) if available else empty
            tree.find(f"{ns}revision").text = str(time.time_ns())
            manifest.write_bytes(ET.tostring(tree))
            signature = manifest.with_suffix(".xml.asc")
            signature.unlink(missing_ok=True)
            checked([*gpg, "--armor", "--detach-sign", "--output", signature, manifest])
            return digest(manifest)

        def cache_revision(directory):
            matches = list(directory.glob(f"{repo_id}-*/repodata/repomd.xml"))
            assert len(matches) == 1, (directory, matches)
            return digest(matches[0])

        caller_cache, system_cache = home / ".cache/libdnf5", Path("/var/cache/libdnf5")

        def assert_cache(label, path, expected):
            actual = cache_revision(path)
            verify(label, actual == expected, actual)

        def native_query(which_env, identity):
            return checked([native_dnf, "--cacheonly", "repoquery", "--available", "--qf",
                            r"%{name}.%{arch}\n", package], which_env, identity).splitlines()

        def verify_query(label, which_env, identity, expected):
            actual = native_query(which_env, identity)
            verify(label, actual == expected, actual)

        def update_native():
            checked([native_dnf, "--refresh", "makecache", "-y"], root_env)
            checked([native_dnf, "--refresh", "makecache", "-y"], env, ordinary)

        def observed_requests():
            output = checked([cli, "metrics"], env, ordinary)
            values = dict(line.split() for line in output.splitlines()
                          if line.startswith(("omg_requests_total ", "omg_requests_failed_total ")))
            return tuple(int(values[name]) for name in ("omg_requests_total", "omg_requests_failed_total"))

        def product_sync(label, command_env, identity, expected_result, expected_refresh=None):
            initial = observed_requests()
            result = run([cli, "sync"], command_env, identity)
            final = observed_requests()
            verify(label + "-exit", (result.returncode == 0) == expected_result,
                   dict(code=result.returncode, stdout=result.stdout[-1000:], stderr=result.stderr[-1000:]))
            if expected_refresh is not None:
                verify(label + "-ipc", final[0] - initial[0] - 1 == expected_refresh and final[1] == initial[1],
                       [final[0] - initial[0] - 1, final[1] - initial[1]])

        with (root / "daemon.log").open("w+") as log:
            process = None
            try:
                checked([*gpg, "--quick-generate-key", "OMG Fedora sync fixture <fixture@example.invalid>", "rsa2048", "sign", "1d"])
                key.write_text(checked([*gpg, "--armor", "--export"]))
                initial_empty = publish(False)
                update_native()
                assert_cache("initial-caller-manifest", caller_cache, initial_empty)
                assert_cache("initial-system-manifest", system_cache, initial_empty)
                verify_query("initial-caller-query", env, ordinary, [])
                verify_query("initial-system-query", root_env, None, [])
                assert set_policy(False) != 0
                process = subprocess.Popen([server], cwd=home, env=env, stdout=log, stderr=subprocess.STDOUT,
                                           stdin=subprocess.DEVNULL, **ordinary)
                deadline = time.monotonic() + 20
                while not (home / "run/omg.sock").is_socket():
                    assert process.poll() is None and time.monotonic() < deadline
                    time.sleep(0.1)
                observed_requests()
                full = publish(True)
                product_sync("denied", env, ordinary, False, 0)
                assert_cache("denied-caller-refreshed", caller_cache, full)
                assert_cache("denied-system-unchanged", system_cache, initial_empty)
                verify_query("denied-native-caller-query", env, ordinary, [package + ".noarch"])

                empty_again = publish(False)
                update_native()
                assert_cache("reset-caller-manifest", caller_cache, empty_again)
                assert_cache("reset-system-manifest", system_cache, empty_again)
                assert set_policy(True) == 0
                accepted_full = publish(True)
                product_sync("approved", env, ordinary, True, 1)
                assert_cache("approved-caller-refreshed", caller_cache, accepted_full)
                assert_cache("approved-system-refreshed", system_cache, accepted_full)
                verify_query("approved-native-caller-query", env, ordinary, [package + ".noarch"])
                verify_query("approved-native-system-query", root_env, None, [package + ".noarch"])
                warm = json.loads(checked([cli, "--json", "search", package], env, ordinary))
                verify("approved-daemon-search", [row["name"] for row in warm] == [package + ".noarch"], warm)

                product_sync("repeat", env, ordinary, True, 1)
                assert_cache("repeat-caller-manifest", caller_cache, accepted_full)
                assert_cache("repeat-system-manifest", system_cache, accepted_full)
                final_empty = publish(False)
                product_sync("root-only", root_env, None, True, 0)
                assert_cache("root-only-caller-unchanged", caller_cache, accepted_full)
                assert_cache("root-only-system-refreshed", system_cache, final_empty)
                verify_query("root-only-native-system-query", root_env, None, [])
                verify("daemon-remains-running", process.poll() is None, process.poll())
                verify("no-package-transaction-history", not Path("/var/lib/omg/history.json").exists(), "absent")
            except Exception:
                log.seek(0)
                print(log.read()[-5000:], file=sys.stderr)
                raise
            finally:
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(8)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(4)
                checked(["/usr/bin/gpgconf", "--homedir", keys, "--kill", "gpg-agent"])

after = host_fingerprint()
for label, wanted, observed in zip(("package-inventory", "install-reasons", "protected-files"), before, after):
    verify("host-" + label + "-unchanged", observed == wanted, observed == wanted)
report = dict(schema_version=1, binaries={"omg": digest(binary), "omgd": digest(daemon)}, checks=checks,
              total=len(checks), passed=sum(row["passed"] for row in checks), host_unchanged=before == after)
print(json.dumps(report))
if report["total"] != 32 or report["passed"] != report["total"]:
    sys.exit(4)
