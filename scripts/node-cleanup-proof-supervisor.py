"""UNRUN hosted Darwin single-command supervisor; no build or test at import."""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def digest(path):
    with open(path, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def census(sid, uid):
    found = []
    raw = subprocess.run(["/bin/ps", "-axo", "pid=,pgid=,uid=,stat="],
                         capture_output=True, timeout=2, check=True).stdout
    if len(raw) > 2 * 1024**2:
        raise ValueError("oversized process metadata")
    lines = raw.decode("ascii").splitlines()
    if len(lines) > 32768:
        raise ValueError("process census capacity")
    for line in lines:
        pid, pgid, owner, state = line.split()
        pid, pgid, owner = int(pid), int(pgid), int(owner)
        if owner != uid:
            continue
        try:
            observed = os.getsid(pid)
        except ProcessLookupError:
            continue
        if observed == sid:
            found.append(dict(pid=pid, pgid=pgid, uid=owner, state=state))
    return sorted(found, key=lambda row: row["pid"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--deadline", required=True, type=int)
    parser.add_argument("--expected-exit", required=True, type=int)
    parser.add_argument("--require", action="append", default=[])
    parser.add_argument("--forbid", action="append", default=[])
    parser.add_argument("argv", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
    if sys.platform != "darwin" or not all(hasattr(os, x) for x in ("waitid", "WNOWAIT", "WNOHANG", "P_PID", "getsid")):
        raise ValueError("Darwin nonreaping wait/session provider qualification missing")
    if os.getuid() == 0 or os.getuid() != os.geteuid() or not command or not 1 <= args.deadline <= 600:
        raise ValueError("ordinary actor/command/deadline admission")
    if digest(args.source) != args.source_sha256:
        raise ValueError("source input mismatch")
    args.out.mkdir(exist_ok=False, parents=True)
    record = dict(state="HOLD", argv=command, uid=os.getuid(), euid=os.geteuid(),
                  gid=os.getgid(), egid=os.getegid(), groups=os.getgroups(),
                  source_path=str(args.source), source_sha256=args.source_sha256,
                  session_closed=False, errors=[], observations=[], stop_disappearances=[])
    child = None
    status = None
    sid = None
    terminal = False
    reason = "unknown"
    start = time.monotonic()
    flags = os.WEXITED | os.WNOHANG | os.WNOWAIT
    try:
        record["python_sha256"] = digest(sys.executable)
        record["ps_sha256"] = digest("/bin/ps")
        executable = Path(command[0]).resolve(strict=True)
        record["executable_sha256"] = digest(executable)
        with (args.out / "stdout").open("xb") as stdout, (args.out / "stderr").open("xb") as stderr:
            child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stdout,
                                     stderr=stderr, start_new_session=True)
            sid = child.pid
            if os.getsid(sid) != sid or os.getpgid(sid) != sid:
                raise ValueError("fresh session identity mismatch")
            record["owned_session"] = sid
            while True:
                observation = os.waitid(os.P_PID, sid, flags)
                terminal = observation is not None
                if terminal:
                    reason = "leader-terminal"
                    break
                if stdout.tell() > 4 * 1024**2 or stderr.tell() > 4 * 1024**2:
                    reason = "channel-cap"
                    break
                if time.monotonic() - start >= args.deadline:
                    reason = "deadline"
                    break
                time.sleep(0.01)
    except BaseException as error:
        record["errors"].append(type(error).__name__ + ": " + str(error))
    finally:
        # Never poll/wait/reap the session leader before session retirement.
        if child is not None and sid is not None:
            end = time.monotonic() + 5
            try:
                while True:
                    rows = census(sid, os.getuid())
                    record["observations"].append(rows)
                    remaining = [row for row in rows if row["pid"] != sid]
                    terminal = os.waitid(os.P_PID, sid, flags) is not None
                    if not remaining and terminal:
                        child.wait(timeout=2)
                        status = child.returncode
                        record["session_closed"] = True
                        break
                    if time.monotonic() >= end:
                        raise TimeoutError("owned session retirement unknown; no next command")
                    for pgid in sorted({row["pgid"] for row in rows if not row["state"].startswith("Z")}):
                        # A gone/unqueryable group leader is unknown ownership. Never guess.
                        if os.getsid(pgid) != sid or os.getpgid(pgid) != pgid:
                            raise ValueError("group ownership changed before exact stop")
                        try:
                            os.killpg(pgid, signal.SIGKILL)
                        except ProcessLookupError:
                            record["stop_disappearances"].append(pgid)
                        except PermissionError:
                            # Permission refusal is never classified as successful stop.
                            raise
                    time.sleep(0.01)
            except BaseException as error:
                record["errors"].append(type(error).__name__ + ": " + str(error))
        record["reason"] = reason
        record["exit"] = status
        record["elapsed_seconds"] = time.monotonic() - start
        bounded_channels = {}
        for channel in ("stdout", "stderr"):
            path = args.out / channel
            if path.exists():
                size = path.stat().st_size
                with path.open("rb") as stream:
                    prefix = stream.read(4 * 1024**2 + 1)
                complete = record["session_closed"] and len(prefix) == size and size <= 4 * 1024**2
                bounded_channels[channel] = prefix[:4 * 1024**2]
                record[channel] = dict(observed_bytes=size, prefix_bytes=len(bounded_channels[channel]),
                                       prefix_sha256=hashlib.sha256(bounded_channels[channel]).hexdigest(),
                                       complete_retired_channel=complete)
        try:
            record["source_after_sha256"] = digest(args.source)
            record["executable_after_sha256"] = digest(executable)
            raw = b"\n".join(bounded_channels[channel] for channel in ("stdout", "stderr"))
            text = raw.decode("utf-8", "replace")
            accepted = (record["session_closed"] and not record["errors"] and reason == "leader-terminal"
                        and status == args.expected_exit and record["source_after_sha256"] == args.source_sha256
                        and record["executable_after_sha256"] == record["executable_sha256"]
                        and all(record[channel]["complete_retired_channel"] for channel in ("stdout", "stderr"))
                        and all(value in text for value in args.require)
                        and all(value not in text for value in args.forbid))
            if accepted:
                record["state"] = "EXACT_COMMAND_OUTCOME_AND_OWNED_SESSION_RETIREMENT_RECORDED"
        except BaseException as error:
            record["errors"].append(type(error).__name__ + ": " + str(error))
        with (args.out / "receipt.json").open("x", encoding="utf-8") as stream:
            json.dump(record, stream, indent=2)
            stream.write("\n")
    print(json.dumps({"state": record["state"], "receipt": str(args.out / "receipt.json")}))
    return 0 if record["state"] == "EXACT_COMMAND_OUTCOME_AND_OWNED_SESSION_RETIREMENT_RECORDED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
