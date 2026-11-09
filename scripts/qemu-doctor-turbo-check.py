#!/usr/bin/env python3
"""Exercise Doctor turbo against real sudo and file capabilities in a guest.

Exit 0: all product behavior passed. Exit 1: product behavior failed.
Exit 120: fixture/preflight failed. Exit 121: fixture cleanup failed.
"""

import argparse
import errno
import hashlib
import os
import pty
import pwd
import re
import secrets
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path


class FixtureError(Exception):
    pass


class CleanupError(FixtureError):
    pass


class ProductError(Exception):
    pass


LEGACY_CAPABILITIES = "cap_chown,cap_dac_override,cap_fowner+ep"


def native_program(name):
    path = shutil.which(name, path="/usr/sbin:/usr/bin:/sbin:/bin")
    if path is None:
        raise FixtureError(f"missing native guest tool: {name}")
    path = Path(path).resolve(strict=True)
    for part in (path, *path.parents):
        mode = part.stat()
        if mode.st_uid != 0 or mode.st_mode & 0o022:
            raise FixtureError(f"native tool has writable or non-root path: {path}")
    if not path.is_file() or not os.access(path, os.X_OK):
        raise FixtureError(f"native tool is not executable: {path}")
    return str(path)


def run_fixture(argv, *, input_bytes=None):
    result = subprocess.run(argv, input=input_bytes, capture_output=True, timeout=20, check=False)
    if result.returncode != 0:
        diagnostic = result.stderr.decode("utf-8", "replace").strip()
        raise FixtureError(f"fixture command {argv[0]} failed ({result.returncode}): {diagnostic}")
    return result.stdout


def capability_xattr(path):
    try:
        return os.getxattr(path, "security.capability")
    except OSError as error:
        if error.errno == errno.ENODATA:
            return None
        raise FixtureError(f"cannot inspect security.capability: {error}") from error


def assert_file_identity(path, initial):
    current = path.stat()
    actual = (current.st_uid, current.st_gid, stat.S_IMODE(current.st_mode),
              hashlib.sha256(path.read_bytes()).hexdigest())
    if actual != initial:
        raise ProductError("Doctor changed the private binary content, owner, or mode")


def install_legacy_capabilities(path, setcap, getcap):
    run_fixture([setcap, LEGACY_CAPABILITIES, str(path)])
    attribute = capability_xattr(path)
    description = run_fixture([getcap, str(path)]).decode("utf-8", "replace").strip()
    if (not attribute or not all(name in description for name in
                                 ("cap_chown", "cap_dac_override", "cap_fowner")) or
            "=ep" not in description):
        raise FixtureError(f"nonempty legacy capability preflight failed: {description}")
    return attribute, description


def sudoers_rule(username, permitted_command, setcap=None, binary=None,
                 *, timestamp_timeout=None):
    defaults = (f'Defaults:{username} timestamp_type=tty, verifypw=all, '
                'passprompt="OMG_QEMU_PASSWORD:"')
    if timestamp_timeout is not None:
        defaults += f", timestamp_timeout={timestamp_timeout}"
    lines = [
        defaults,
        f"{username} ALL=(root) PASSWD: {permitted_command}",
    ]
    if setcap is not None:
        lines.append(f"{username} ALL=(root) PASSWD: {setcap} -r {binary}")
    return "\n".join(lines) + "\n"


def configure_sudoers(path, contents, visudo):
    # sudoers @includedir ignores names containing '.', so an incomplete
    # staging file cannot alter policy before visudo validates it.
    staging = path.with_name("." + path.name + ".tmp")
    try:
        with staging.open("x", encoding="ascii") as stream:
            stream.write(contents)
        staging.chmod(0o440)
        run_fixture([visudo, "-cf", str(staging)])
        staging.replace(path)
        run_fixture([visudo, "-cf", "/etc/sudoers"])
    finally:
        staging.unlink(missing_ok=True)


def run_pty_case(username, password, binary, sudo, permitted_command, label,
                 *, cache_expected=True):
    account = pwd.getpwnam(username)
    child, master = pty.fork()
    if child == 0:
        os.setgroups([])
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)
        os.environ.clear()
        os.environ.update({"HOME": account.pw_dir, "USER": username, "LOGNAME": username,
                           "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "TERM": "dumb",
                           "LC_ALL": "C", "NO_COLOR": "1", "OMG_TEST_MODE": "0"})
        if cache_expected is not None:
            cleared = subprocess.run([sudo, "-K"], stdin=subprocess.DEVNULL,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     check=False).returncode
            validated = subprocess.run([sudo, "-S", "-v"],
                                       input=(password + "\n").encode(),
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       check=False).returncode
            observed = subprocess.run([sudo, "-Nnv"], stdin=subprocess.DEVNULL,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                      check=False).returncode
            authorize_args = ([sudo, "-n", "--", permitted_command] if cache_expected else
                              [sudo, "-S", "-k", "--", permitted_command])
            authorized = subprocess.run(authorize_args,
                                        input=None if cache_expected else (password + "\n").encode(),
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                        check=False).returncode
            invalidated = subprocess.run([sudo, "-K"], stdin=subprocess.DEVNULL,
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                         check=False).returncode
            print(f"OMG_TURBO_PREFLIGHT:{cleared}:{validated}:{observed}:{authorized}:{invalidated}",
                  flush=True)
            if (any(code != 0 for code in (cleared, validated, authorized, invalidated)) or
                    (observed == 0) != cache_expected):
                os._exit(0)
        subprocess.run([sudo, "-k"], stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        before = subprocess.run([sudo, "-Nnv"], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                check=False).returncode
        print(f"OMG_TURBO_BEFORE:{before}", flush=True)
        product = subprocess.run([str(binary), "doctor", "--turbo"], check=False).returncode
        print(f"OMG_TURBO_PRODUCT:{product}", flush=True)
        after = subprocess.run([sudo, "-Nnv"], stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               check=False).returncode
        print(f"OMG_TURBO_AFTER:{after}", flush=True)
        os._exit(0)

    transcript = bytearray()
    answered_confirmation = False
    answered_password = False
    deadline = time.monotonic() + 45
    waited = False
    child_status = None
    eof = False
    completed = False
    try:
        while time.monotonic() < deadline:
            ready = []
            if not eof:
                ready, _, _ = select.select([master], [], [], 0.2)
            if ready:
                try:
                    data = os.read(master, 4096)
                except OSError as error:
                    if error.errno == errno.EIO:
                        data = b""
                    else:
                        raise
                if not data:
                    eof = True
                else:
                    transcript.extend(data)
                    if len(transcript) > 65536:
                        raise FixtureError(f"{label} PTY transcript exceeded 64 KiB")
                    if not answered_confirmation and b"Run `sudo setcap -r`" in transcript:
                        os.write(master, b"y\n")
                        answered_confirmation = True
                    if not answered_password and b"OMG_QEMU_PASSWORD:" in transcript:
                        os.write(master, password.encode() + b"\n")
                        answered_password = True
            if not waited:
                done, status = os.waitpid(child, os.WNOHANG)
                if done:
                    waited = True
                    child_status = status
            if eof and waited:
                completed = True
                break
        else:
            if cache_expected is not None and b"OMG_TURBO_PREFLIGHT:" not in transcript:
                raise FixtureError(f"{label} sudo policy preflight exceeded 45 seconds")
            raise ProductError(f"{label} Doctor interaction exceeded 45 seconds")
    finally:
        os.close(master)
        if not completed:
            try:
                os.killpg(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if not waited:
            os.waitpid(child, 0)

    if child_status is None or not os.WIFEXITED(child_status) or os.WEXITSTATUS(child_status) != 0:
        raise FixtureError(f"{label} PTY child failed before producing a receipt")

    output = bytes(transcript).replace(password.encode(), b"[redacted]").decode("utf-8", "replace")
    if cache_expected is not None:
        preflight_results = re.findall(rb"OMG_TURBO_PREFLIGHT:(\d+):(\d+):(\d+):(\d+):(\d+)",
                                       transcript)
        if len(preflight_results) != 1:
            raise FixtureError(f"{label} sudo policy preflight missing: {output[-3000:]}")
        cleared, validated, observed, authorized, invalidated = preflight_results[0]
        if (any(code != b"0" for code in (cleared, validated, authorized, invalidated)) or
                (observed == b"0") != cache_expected):
            raise FixtureError(f"{label} sudo policy preflight failed: {output[-3000:]}")
    fields = {}
    for name in ("BEFORE", "PRODUCT", "AFTER"):
        values = re.findall(rf"OMG_TURBO_{name}:(-?\d+)".encode(), transcript)
        if len(values) != 1:
            raise FixtureError(f"{label} missing or repeated {name} receipt: {output[-3000:]}")
        fields[name.lower()] = int(values[0])
    if fields["before"] == 0:
        raise FixtureError(f"{label} sudo credentials were already valid before Doctor")
    return fields, output


def verify_product(label, fields, output, expected_success):
    if expected_success:
        if fields["product"] != 0 or fields["after"] != 0:
            raise ProductError(f"{label} did not validate sudo: {fields}; {output[-3000:]}")
        if "Sudo credentials validated" not in output:
            raise ProductError(f"{label} lacked a validated sudo success verdict: {output[-3000:]}")
    elif fields["product"] == 0 or fields["after"] == 0 or "Sudo credentials validated" in output:
        raise ProductError(f"{label} reported success without sudo authorization: {fields}; {output[-3000:]}")


def main(binary):
    if os.geteuid() != 0:
        raise FixtureError("Doctor turbo guest fixture must run as root")
    binary = binary.resolve(strict=True)
    if not binary.is_file():
        raise FixtureError("release OMG binary is missing")
    tools = {name: native_program(name) for name in
             ("sudo", "setcap", "getcap", "visudo", "useradd", "userdel", "chpasswd", "true")}
    run_fixture([tools["sudo"], "-Nnv"])
    suffix = secrets.token_hex(4)
    username = f"omgtd{suffix}"
    try:
        pwd.getpwnam(username)
    except KeyError:
        pass
    else:
        raise FixtureError("temporary probe user already exists")

    sudoers = Path("/etc/sudoers.d") / f"99-omg-doctor-turbo-{suffix}"
    if sudoers.exists() or sudoers.is_symlink():
        raise FixtureError("temporary sudoers fixture already exists")
    private = Path(tempfile.mkdtemp(prefix="omg-doctor-turbo-", dir="/var/lib"))
    created_user = False
    created_sudoers = False
    failure = None
    try:
        copy = private / "omg"
        shutil.copyfile(binary, copy)
        copy.chmod(0o755)
        private.chmod(0o755)
        initial = (copy.stat().st_uid, copy.stat().st_gid, 0o755,
                   hashlib.sha256(copy.read_bytes()).hexdigest())
        if capability_xattr(copy) is not None:
            raise FixtureError("fresh private binary already has file capabilities")
        created_user = True
        run_fixture([tools["useradd"], "-m", "-s", "/bin/sh", username])
        password = secrets.token_urlsafe(25)
        run_fixture([tools["chpasswd"]], input_bytes=f"{username}:{password}\n".encode())
        sudoers.touch(mode=0o440, exist_ok=False)
        created_sudoers = True

        configure_sudoers(sudoers, sudoers_rule(username, tools["true"]), tools["visudo"])
        fields, output = run_pty_case(username, password, copy, tools["sudo"],
                                      tools["true"], "no-capability")
        verify_product("no-capability", fields, output, True)
        if capability_xattr(copy) is not None:
            raise ProductError("Doctor added a capability to a clean binary")
        assert_file_identity(copy, initial)

        run_fixture([tools["setcap"], "=", str(copy)])
        if not capability_xattr(copy) or b"=" not in run_fixture([tools["getcap"], str(copy)]):
            raise FixtureError("empty capability xattr preflight did not persist")
        configure_sudoers(sudoers, sudoers_rule(username, tools["true"],
                                               tools["setcap"], copy), tools["visudo"])
        fields, output = run_pty_case(username, password, copy, tools["sudo"],
                                      tools["true"], "legacy-cleanup")
        verify_product("legacy-cleanup", fields, output, True)
        if capability_xattr(copy) is not None or run_fixture([tools["getcap"], str(copy)]).strip():
            raise ProductError("Doctor left the legacy capability xattr on its binary")
        assert_file_identity(copy, initial)

        install_legacy_capabilities(copy, tools["setcap"], tools["getcap"])
        configure_sudoers(sudoers, sudoers_rule(username, tools["true"],
                                               tools["setcap"], copy), tools["visudo"])
        fields, output = run_pty_case(username, password, copy, tools["sudo"],
                                      tools["true"], "nonempty-legacy-cleanup")
        verify_product("nonempty-legacy-cleanup", fields, output, True)
        if capability_xattr(copy) is not None or run_fixture([tools["getcap"], str(copy)]).strip():
            raise ProductError("Doctor left nonempty legacy capabilities on its binary")
        assert_file_identity(copy, initial)

        legacy_attribute, legacy_description = install_legacy_capabilities(
            copy, tools["setcap"], tools["getcap"])
        configure_sudoers(sudoers, sudoers_rule(username, tools["true"]), tools["visudo"])
        fields, output = run_pty_case(username, password, copy, tools["sudo"],
                                      tools["true"], "cleanup-denied")
        if fields["product"] == 0 or fields["after"] != 0 or "Sudo credentials validated" in output:
            raise ProductError(f"Doctor reported success or missed sudo validation when setcap was denied: {fields}; {output[-3000:]}")
        if "Legacy capability cleanup failed" not in output:
            raise ProductError(f"Doctor did not report denied capability cleanup: {output[-3000:]}")
        if (capability_xattr(copy) != legacy_attribute or
                run_fixture([tools["getcap"], str(copy)]).decode("utf-8", "replace").strip()
                != legacy_description):
            raise ProductError("Doctor changed capabilities despite the denied cleanup policy")
        assert_file_identity(copy, initial)
        run_fixture([tools["setcap"], "-r", str(copy)])

        configure_sudoers(sudoers, sudoers_rule(username, tools["true"],
                                               timestamp_timeout=0), tools["visudo"])
        fields, output = run_pty_case(username, password, copy, tools["sudo"],
                                      tools["true"], "zero-cache", cache_expected=False)
        verify_product("zero-cache", fields, output, False)
        if "Sudo credentials are not cached" not in output:
            raise ProductError(f"Doctor did not report the zero-cache policy: {output[-3000:]}")
        assert_file_identity(copy, initial)

        sudoers.unlink()
        created_sudoers = False
        fields, output = run_pty_case(username, password, copy, tools["sudo"],
                                      tools["true"], "denied-sudo", cache_expected=None)
        verify_product("denied-sudo", fields, output, False)
        if "sudo credential validation failed" not in output:
            raise ProductError(f"Doctor did not report denied sudo validation: {output[-3000:]}")
        assert_file_identity(copy, initial)
    except (FixtureError, ProductError) as error:
        failure = error
    except (OSError, subprocess.TimeoutExpired) as error:
        failure = FixtureError(str(error))
    finally:
        cleanup = []
        if created_sudoers:
            try:
                sudoers.unlink()
            except OSError as error:
                cleanup.append(f"sudoers: {error}")
        if created_user:
            try:
                account = pwd.getpwnam(username)

                def drop_to_probe():
                    os.setgroups([])
                    os.setgid(account.pw_gid)
                    os.setuid(account.pw_uid)

                invalidate = subprocess.run([tools["sudo"], "-K"], preexec_fn=drop_to_probe,
                                            capture_output=True, timeout=20, check=False)
                if invalidate.returncode != 0:
                    cleanup.append("temporary sudo cache could not be invalidated")
                # shadow-utils reports exit 8 while a just-finished sudo/PAM
                # process still owns the account. Wait only for that documented
                # transient state; other cleanup errors remain fatal.
                for attempt in range(10):
                    result = subprocess.run([tools["userdel"], "-r", username],
                                            capture_output=True, timeout=20, check=False)
                    if result.returncode != 8 or attempt == 9:
                        break
                    time.sleep(0.2)
                if result.returncode != 0:
                    detail = result.stderr.decode("utf-8", "replace").strip()
                    cleanup.append(f"temporary user could not be deleted ({result.returncode}): {detail}")
            except KeyError:
                pass
            except (OSError, subprocess.TimeoutExpired) as error:
                cleanup.append(f"temporary user: {error}")
        try:
            shutil.rmtree(private)
        except OSError as error:
            cleanup.append(f"private binary: {error}")
        if cleanup:
            raise CleanupError("cleanup failed: " + "; ".join(cleanup)) from failure
    if failure is not None:
        raise failure
    print("OMG_QEMU_DOCTOR_TURBO:verified")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    arguments = parser.parse_args()
    try:
        main(arguments.binary)
    except ProductError as error:
        print(f"PRODUCT_FAIL: {error}", file=sys.stderr)
        sys.exit(1)
    except CleanupError as error:
        print(f"HARNESS_ERROR: {error}", file=sys.stderr)
        sys.exit(121)
    except FixtureError as error:
        print(f"HARNESS_ERROR: {error}", file=sys.stderr)
        sys.exit(120)
    except (OSError, subprocess.TimeoutExpired) as error:
        print(f"HARNESS_ERROR: {error}", file=sys.stderr)
        sys.exit(120)
