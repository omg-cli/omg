#!/usr/bin/env bash
# Read controller-owned state before teardown; never signal or repair the guest.
set -euo pipefail
cd "${1:-/work/guest}"
printf 'observed_utc=%s\n' "$(date -u +%FT%TZ)"
pid=unavailable
if [[ -f qemu.pid && ! -L qemu.pid ]]; then
  read -r pid < qemu.pid || pid=unavailable
fi
printf 'qemu_pid=%s\n' "$pid"
if [[ "$pid" =~ ^[0-9]+$ && -r "/proc/$pid/status" ]]; then
  # Docker OOMKilled describes the controller; preserve the child's own state.
  awk '/^(Name|State|Pid|PPid|Uid|Gid|VmRSS|Threads|CapEff|NoNewPrivs|Seccomp):/' "/proc/$pid/status" || printf 'qemu_process_status=vanished_during_read\n'
else
  printf 'qemu_process_status=unavailable\n'
fi
# Keep argument boundaries and reject a PID replacement during this observation.
python3 - "$pid" <<'IDENTITY'
import json
import os
import sys
from pathlib import Path

pid = int(sys.argv[1]) if sys.argv[1].isdecimal() else None
identity = {"state": "unavailable", "pid": pid}
try:
    if pid is not None:
        proc = Path(f"/proc/{pid}")
        def starttime():
            with (proc / "stat").open("rb") as stream:
                return stream.read(8192).rsplit(b") ", 1)[1].split()[19].decode("ascii")
        started = starttime()
        exe = os.readlink(proc / "exe")
        with (proc / "cmdline").open("rb") as stream:
            raw = stream.read(8193)
        truncated = len(raw) > 8192
        bounded = raw[:8192]
        argv = bounded.split(b"\0")[:-1]
        if starttime() == started:
            identity = {"state": "observed", "pid": pid, "starttime_ticks": started,
                        "exe": exe, "argv": [os.fsdecode(arg) for arg in argv],
                        "argv_truncated": truncated}
except (OSError, ValueError, IndexError):
    identity = {"state": "unavailable", "pid": pid}
print("qemu_identity=" + json.dumps(identity, ensure_ascii=True))
IDENTITY
printf 'hostfwd_tcp_2222:\n'
# proc/net/tcp encodes LISTEN as 0A and port 2222 as 08AE. Report only
# this local port, avoiding unrelated connections and requiring no ss package.
awk '$2 ~ /:08AE$/ && $4 == "0A" {print "listener=" $2 " inode=" $10; found=1}
     END {if (!found) print "listener=absent"}' /proc/net/tcp
printf 'controller_memory_events:\n'
if [[ -r /sys/fs/cgroup/memory.events ]]; then
  head -n 32 /sys/fs/cgroup/memory.events
else
  printf 'memory_events=unavailable\n'
fi
printf 'qemu_startup_tail:\n'
if [[ -f qemu-startup.log && ! -L qemu-startup.log ]]; then
  tail -c 8192 qemu-startup.log
else
  printf 'qemu_startup=unavailable\n'
fi
