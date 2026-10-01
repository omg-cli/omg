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
