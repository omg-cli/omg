#!/usr/bin/env python3
"""Collect bounded guest health and reject crash evidence before QEMU admission.

Only kernel messages and selected coredump identity fields are queried. Never
collect core files, process environments, command lines or arbitrary journals.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import tempfile

LIMIT = 1024 * 1024
FATAL = re.compile(
    r"(?:Kernel panic - not syncing:|BUG: (?:unable to handle|kernel NULL|soft lockup)|"
    r"Oops:|watchdog: BUG: soft lockup|NMI watchdog: Watchdog detected hard LOCKUP|"
    r"Out of memory: Killed process|Memory cgroup out of memory: Killed process|"
    r"(?:omg|omgd)\[[0-9]+\]: (?:segfault|general protection fault)|"
    # Linux x86 show_signal emits comm[pid] trap description without a colon.
    # Require the known identity and IP field; publish no addresses or VMA path.
    r"(?<![\w.-])(?:omg|omgd)\[[0-9]+\] trap (?:invalid opcode|divide error)(?= ip:[0-9a-f]))"
)
BOOT_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
CORE_PATTERN = re.compile(
    r"\|(/(?:usr/)?lib(?:64)?/systemd/systemd-coredump)"
    # Debian's vendor configuration replaces %c with this exact RLIMIT value.
    # Preserve the same handler and positional ABI; arbitrary literals refuse.
    r" %P %u %g %s %t (?:%c|9223372036854775808) %h(?: %d(?: %F(?: %I)?)?)?"
)
CAPABILITY_PROPERTIES = "Id,LoadState,ActiveState,SubState,Result,UnitFileState"


SOCKET_PATTERN = "@@/run/systemd/coredumpd/kernel"
SOCKET_NAME = "/run/systemd/coredumpd/kernel"
MANAGER_PROPERTIES = ("Id,LoadState,ActiveState,SubState,Result,UnitFileState,MainPID,ControlGroup,"
                      "PrivateNetwork,ExecMainStartTimestampMonotonic,ConditionResult,AssertResult,Upholds")
REGISTRATION_PROPERTIES = ("Id,LoadState,ActiveState,SubState,Result,UnitFileState,ExecMainCode,ExecMainStatus,"
                           "ExecMainStartTimestampMonotonic,ConditionResult,AssertResult,BindsTo,"
                           "RefuseManualStart,RefuseManualStop")
SOCKET_OBSERVER_PROGRAM = r'''
import json, os, re, socket, stat, struct, sys, time
from pathlib import Path
def require(ok):
    if not ok: raise ValueError("invalid bounded manager observation")
def read(path):
    with open(path, "rb") as f: data = f.read(1048577)
    require(len(data) <= 1048576)
    return data.decode("utf-8", "strict")
require(len(sys.argv) == 5 and all(re.fullmatch(r"0|[1-9][0-9]*", x) for x in sys.argv[1:]))
pid, low, high, sequence = map(int, sys.argv[1:])
require(0 < pid <= 2147483647 and 0 < sequence <= 0xffffffff and 0 <= low <= 0xffffffff and 0 <= high <= 0xffffffff)
base = "/proc/" + str(pid)
name = "/run/systemd/coredumpd/kernel"
def identity():
    text = read(base + "/stat")
    close = text.rfind(")")
    require(close > 0 and text[:text.find("(")].strip() == str(pid))
    fields = text[close + 1:].split()
    require(len(fields) >= 20)
    start = int(fields[19])
    status = read(base + "/status")
    uids = [line.split()[1:] for line in status.splitlines() if line.startswith("Uid:")]
    require(uids == [["0", "0", "0", "0"]])
    require(read(base + "/cgroup").strip() == "0::/system.slice/systemd-coredumpd.service")
    namespace = os.stat(base + "/ns/net").st_ino
    require(namespace == os.stat("/proc/self/ns/net").st_ino)
    cg = Path("/sys/fs/cgroup/system.slice/systemd-coredumpd.service")
    subgroups = 0
    for number, entry in enumerate(cg.iterdir(), 1):
        require(number <= 256)
        subgroups += entry.is_dir()
    raw_pids = read(str(cg / "cgroup.procs")).split()
    require(len(raw_pids) <= 64 and all(re.fullmatch(r"[1-9][0-9]*", x) for x in raw_pids))
    cgroup_pids = sorted(map(int, raw_pids))
    require(cgroup_pids == [pid] and subgroups == 0)
    executable = os.readlink(base + "/exe")
    require(executable in ("/usr/lib/systemd/systemd-coredump", "/usr/lib64/systemd/systemd-coredump", "/lib/systemd/systemd-coredump", "/lib64/systemd/systemd-coredump"))
    ex = os.stat(base + "/exe")
    require(stat.S_ISREG(ex.st_mode) and ex.st_uid == 0 and ex.st_mode & 0o111 and not ex.st_mode & 0o022)
    parents = [os.lstat(p) for p in ("/run", "/run/systemd", "/run/systemd/coredumpd")]
    require(all(stat.S_ISDIR(p.st_mode) and p.st_uid == 0 and not p.st_mode & 0o022 for p in parents))
    vfs = os.lstat(name)
    require(stat.S_ISSOCK(vfs.st_mode) and vfs.st_uid == 0 and 0 < vfs.st_ino <= 0xffffffff)
    table = read(base + "/net/unix").splitlines()
    require(table and table[0].split() == ["Num", "RefCount", "Protocol", "Flags", "Type", "St", "Inode", "Path"] and len(table) <= 4097)
    endpoint = []
    listener = []
    for line in table[1:]:
        row = line.split(None, 7)
        require(len(row) in (7, 8))
        if len(row) == 8 and row[7] == name:
            require(re.fullmatch(r"[0-9]+", row[6]) is not None)
            inode = int(row[6])
            endpoint.append(inode)
            if int(row[4], 16) == 1 and int(row[3], 16) == 0x10000:
                listener.append(inode)
    require(len(endpoint) == 1 and endpoint == listener and 0 < listener[0] <= 0xffffffff)
    socket_fds = []
    for number, fd in enumerate(Path(base + "/fd").iterdir(), 1):
        require(number <= 1024)
        require(re.fullmatch(r"0|[1-9][0-9]*", fd.name) is not None)
        if os.readlink(fd) == "socket:[" + str(listener[0]) + "]": socket_fds.append(int(fd.name))
    require(socket_fds)
    return dict(pid=pid, start_ticks=start, namespace_inode=namespace, cgroup_pids=cgroup_pids,
                subgroup_count=subgroups, executable=executable, executable_uid=ex.st_uid, executable_mode=ex.st_mode,
                socket_inode=listener[0], socket_fds=sorted(socket_fds), vfs_inode=vfs.st_ino,
                vfs_major=os.major(vfs.st_dev), vfs_minor=os.minor(vfs.st_dev), socket_uid=vfs.st_uid,
                parent_uids=[p.st_uid for p in parents], parent_modes=[p.st_mode for p in parents],
                endpoint_socket_inodes=endpoint)
before = identity()
with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 4) as netlink:
    netlink.bind((0, 0))
    port, groups = netlink.getsockname()
    require(0 < port <= 0xffffffff and groups == 0)
    request = struct.pack("=IHHIIBBHIIIII", 40, 20, 1, sequence, port, 1, 0, 0, 1024, before["socket_inode"], 83, low, high)
    deadline = time.monotonic() + 1
    netlink.settimeout(1)
    require(netlink.sendto(request, (0, 0)) == 40)
    remaining = deadline - time.monotonic()
    require(remaining > 0)
    netlink.settimeout(remaining)
    data, ancillary, flags, sender = netlink.recvmsg(65536, 256)
    require(time.monotonic() <= deadline)
after = identity()
require(before == after)
result = dict(identity=before, request_hex=request.hex(), reply_hex=data.hex(), sender=list(sender),
              msg_flags=flags, ancillary_count=len(ancillary), port_id=port, sequence=sequence, namespace_inode=before["namespace_inode"])
encoded = json.dumps(result, separators=(",", ":"))
require(len(encoded) <= 1048576)
print(encoded)
'''


def socket_unit_properties(unit, properties):
    fields = {}
    for line in query(["systemctl", "show", "--all", "--property=" + properties, unit]).splitlines():
        key, separator, value = line.partition("=")
        if not separator or key not in properties.split(",") or key in fields:
            raise ValueError("invalid manager unit evidence")
        fields[key] = value
    if set(fields) != set(properties.split(",")):
        raise ValueError("incomplete manager unit evidence")
    return fields


def validate_socket_channel(channel, boot_id):
    if (set(channel) != {"kind", "boot_id", "core_pattern", "manager", "registration", "identity", "listener", "manager_warning_count"}
            or channel["kind"] != "systemd-coredump-kernel-socket" or channel["boot_id"] != boot_id
            or channel["core_pattern"] != SOCKET_PATTERN):
        raise ValueError("invalid kernel socket channel")
    if type(channel["manager_warning_count"]) is not int or channel["manager_warning_count"] != 0:
        raise ValueError("invalid manager warning history witness")
    manager, registration = channel["manager"], channel["registration"]
    for fields, properties, unit, substate in (
        (manager, MANAGER_PROPERTIES, "systemd-coredumpd.service", "running"),
        (registration, REGISTRATION_PROPERTIES, "systemd-coredump-register.service", "exited"),
    ):
        if (not isinstance(fields, dict) or set(fields) != set(properties.split(","))
                or any(not isinstance(v, str) for v in fields.values())
                or fields["Id"] != unit or fields["LoadState"] != "loaded"
                or fields["ActiveState"] != "active" or fields["SubState"] != substate
                or fields["Result"] != "success" or fields["ConditionResult"] != "yes" or fields["AssertResult"] != "yes"
                or fields["UnitFileState"] not in ("enabled", "enabled-runtime", "static")
                or not re.fullmatch(r"[1-9][0-9]*", fields["ExecMainStartTimestampMonotonic"])):
            raise ValueError("manager or registration absent, pending or failed")
    if (not re.fullmatch(r"[1-9][0-9]*", manager["MainPID"])
            or int(manager["MainPID"]) > 2147483647
            or manager["ControlGroup"] != "/system.slice/systemd-coredumpd.service" or manager["PrivateNetwork"] != "yes"
            or "systemd-coredump-register.service" not in manager["Upholds"].split()
            or "systemd-coredumpd.service" not in registration["BindsTo"].split()
            or registration["RefuseManualStart"] != "yes" or registration["RefuseManualStop"] != "yes"
            or registration["ExecMainCode"] != "1" or registration["ExecMainStatus"] != "0"
            or int(registration["ExecMainStartTimestampMonotonic"]) < int(manager["ExecMainStartTimestampMonotonic"])):
        raise ValueError("invalid manager registration identity")
    identity = channel["identity"]
    integer_fields = {"pid", "start_ticks", "namespace_inode", "subgroup_count", "executable_uid", "executable_mode",
                      "socket_inode", "vfs_inode", "vfs_major", "vfs_minor", "socket_uid"}
    array_fields = {"cgroup_pids", "socket_fds", "parent_uids", "parent_modes", "endpoint_socket_inodes"}
    if (not isinstance(identity, dict) or set(identity) != integer_fields | array_fields | {"executable"}
            or any(type(identity[k]) is not int or identity[k] < 0 for k in integer_fields)
            or any(not isinstance(identity[k], list) or len(identity[k]) > 1024
                   or any(type(v) is not int or v < 0 for v in identity[k]) for k in array_fields)):
        raise ValueError("invalid bounded manager identity")
    if (identity["pid"] != int(manager["MainPID"]) or identity["start_ticks"] <= 0 or identity["namespace_inode"] <= 0
            or identity["cgroup_pids"] != [identity["pid"]] or identity["subgroup_count"] != 0
            or identity["executable"] not in ("/usr/lib/systemd/systemd-coredump", "/usr/lib64/systemd/systemd-coredump",
                                              "/lib/systemd/systemd-coredump", "/lib64/systemd/systemd-coredump")
            or identity["executable_uid"] != 0 or not stat.S_ISREG(identity["executable_mode"])
            or not identity["executable_mode"] & 0o111 or identity["executable_mode"] & 0o022
            or not 0 < identity["socket_inode"] <= 0xFFFFFFFF or not 0 < identity["vfs_inode"] <= 0xFFFFFFFF
            or identity["socket_uid"] != 0 or not identity["socket_fds"]
            or identity["socket_fds"] != sorted(set(identity["socket_fds"]))
            or identity["endpoint_socket_inodes"] != [identity["socket_inode"]]
            or identity["parent_uids"] != [0, 0, 0] or len(identity["parent_modes"]) != 3
            or any(not stat.S_ISDIR(v) or v & 0o022 for v in identity["parent_modes"])):
        raise ValueError("manager worker, endpoint or identity is unsafe")
    listener = channel["listener"]
    if (not isinstance(listener, dict)
            or set(listener) != {"inode", "cookie", "name", "vfs_inode", "vfs_major", "vfs_minor", "rqueue", "wqueue", "uid", "shutdown"}
            or any(type(listener[k]) is not int or listener[k] < 0 for k in listener if k not in ("cookie", "name"))
            or not isinstance(listener["cookie"], list) or len(listener["cookie"]) != 2
            or any(type(v) is not int or not 0 <= v <= 0xFFFFFFFF for v in listener["cookie"])
            or tuple(listener["cookie"]) in ((0, 0), (0xFFFFFFFF, 0xFFFFFFFF))
            or listener["name"] != SOCKET_NAME or listener["inode"] != identity["socket_inode"]
            or any(listener[k] != identity[k] for k in ("vfs_inode", "vfs_major", "vfs_minor"))
            or listener["uid"] != 0 or listener["rqueue"] != 0 or listener["wqueue"] <= 0 or listener["shutdown"] != 0):
        raise ValueError("kernel socket listener is pending or invalid")


def socket_transport_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate socket transport field")
        result[key] = value
    return result


def observe_socket_transport(pid, cookie, sequence):
    text = query(["/usr/bin/nsenter", "--target", str(pid), "--net", "--", "/usr/bin/python3", "-I", "-B", "-c",
                  SOCKET_OBSERVER_PROGRAM, str(pid), str(cookie[0]), str(cookie[1]), str(sequence)])
    if len(text.encode()) > LIMIT:
        raise ValueError("oversized socket transport")
    record = json.loads(text, object_pairs_hook=socket_transport_object)
    if (not isinstance(record, dict)
            or set(record) != {"identity", "request_hex", "reply_hex", "sender", "msg_flags", "ancillary_count", "port_id", "sequence", "namespace_inode"}
            or record["sequence"] != sequence or type(record["sequence"]) is not int
            or type(record["port_id"]) is not int or not 0 < record["port_id"] <= 0xFFFFFFFF
            or type(record["namespace_inode"]) is not int
            or not isinstance(record["identity"], dict)
            or record["namespace_inode"] != record["identity"].get("namespace_inode")
            or record["sender"] != [0, 0] or any(type(v) is not int for v in record["sender"])
            or type(record["msg_flags"]) is not int or record["msg_flags"] != 0
            or type(record["ancillary_count"]) is not int or record["ancillary_count"] != 0):
        raise ValueError("invalid socket transport boundary")
    for key, size in (("request_hex", 80), ("reply_hex", 131072)):
        if not isinstance(record[key], str) or not 0 < len(record[key]) <= size or len(record[key]) % 2 or re.fullmatch(r"[0-9a-f]+", record[key]) is None:
            raise ValueError("invalid socket wire encoding")
    request, reply = bytes.fromhex(record["request_hex"]), bytes.fromhex(record["reply_hex"])
    inode = record["identity"].get("socket_inode")
    if type(inode) is not int or not 0 < inode <= 0xFFFFFFFF:
        raise ValueError("invalid socket request inode")
    expected = struct.pack("=IHHIIBBHIIIII", 40, 20, 1, sequence, record["port_id"], 1, 0, 0, 1024, inode, 83, *cookie)
    if request != expected:
        raise ValueError("socket request differs")
    return record, request, reply


def kernel_socket_channel(boot_id, pattern):
    manager = socket_unit_properties("systemd-coredumpd.service", MANAGER_PROPERTIES)
    registration = socket_unit_properties("systemd-coredump-register.service", REGISTRATION_PROPERTIES)
    if not re.fullmatch(r"[1-9][0-9]*", manager["MainPID"]) or int(manager["MainPID"]) > 2147483647:
        raise ValueError("invalid manager PID")
    pid = int(manager["MainPID"])
    first, _, discovery = observe_socket_transport(pid, (0xFFFFFFFF, 0xFFFFFFFF), 1)
    if len(discovery) < 32:
        raise ValueError("short unqualified cookie discovery")
    inode = first["identity"].get("socket_inode")
    if (struct.unpack_from("=IHHII", discovery) != (len(discovery), 20, 0, 1, first["port_id"])
            or struct.unpack_from("=BBBBI", discovery, 16) != (1, 1, 10, 0, inode)):
        raise ValueError("unqualified discovery identity differs")
    cookie = struct.unpack_from("=II", discovery, 24)
    if cookie in ((0, 0), (0xFFFFFFFF, 0xFFFFFFFF)):
        raise ValueError("unusable discovery cookie")
    exact, request, reply = observe_socket_transport(pid, cookie, 2)
    if exact["identity"] != first["identity"]:
        raise ValueError("manager identity changed during socket observation")
    listener = decode_socket_reply(reply, sender=tuple(exact["sender"]), msg_flags=exact["msg_flags"], seq=2,
                                   port_id=exact["port_id"], inode=inode, cookie=cookie, name=SOCKET_NAME.encode(), request=request)
    listener["cookie"] = list(listener["cookie"])
    listener["name"] = listener["name"].decode("ascii")
    history = query(["journalctl", "--boot=" + boot_id.replace("-", ""), "--quiet", "--no-pager", "--output=json",
                     "--output-fields=_BOOT_ID,_SYSTEMD_UNIT,PRIORITY", "--priority=warning",
                     "_SYSTEMD_UNIT=systemd-coredumpd.service"])
    if history.strip():
        raise ValueError("manager warning history prevents health admission")
    channel = {"kind": "systemd-coredump-kernel-socket", "boot_id": boot_id, "core_pattern": pattern,
               "manager": manager, "registration": registration, "identity": exact["identity"], "listener": listener, "manager_warning_count": 0}
    validate_socket_channel(channel, boot_id)
    if (socket_unit_properties("systemd-coredumpd.service", MANAGER_PROPERTIES) != manager
            or socket_unit_properties("systemd-coredump-register.service", REGISTRATION_PROPERTIES) != registration):
        raise ValueError("manager registration changed during socket observation")
    return channel


def decode_socket_reply(data, *, sender, msg_flags, seq, port_id, inode, cookie, name, request):
    if sender != (0, 0) or msg_flags != 0 or not 16 <= len(data) <= 65536:
        raise ValueError("invalid receive boundary")
    length, kind, flags, observed_seq, observed_port = struct.unpack_from("=IHHII", data)
    if length != len(data) or observed_seq != seq or observed_port != port_id:
        raise ValueError("reply identity or length mismatch")
    if len(request) != 40:
        raise ValueError("unexpected request length")
    request_header = struct.unpack_from("=IHHII", request)
    request_body = struct.unpack_from("=BBHIIIII", request, 16)
    if (request_header != (40, 20, 1, seq, port_id)
            or request_body != (1, 0, 0, 1024, inode, 83, *cookie)
            or not 0 < inode <= 0xFFFFFFFF
            or cookie in ((0, 0), (0xFFFFFFFF, 0xFFFFFFFF))):
        raise ValueError("unqualified request identity")
    if kind == 2:
        if flags not in (0, 0x100) or len(data) < 36:
            raise ValueError("invalid error reply")
        error = struct.unpack_from("=i", data, 16)[0]
        expected_echo = request[:16] if flags == 0x100 else request
        if data[20:] != expected_echo or not -4095 <= error < 0:
            raise ValueError("invalid error code or request echo")
        raise OSError(-error, "UNIX diagnostic kernel error")
    if kind != 20 or flags != 0 or len(data) < 32:
        raise ValueError("unexpected diagnostic message")
    family, socket_type, state, pad, found_inode, low, high = struct.unpack_from("=BBBBIII", data, 16)
    if (family, socket_type, state, pad, found_inode, low, high) != (1, 1, 10, 0, inode, *cookie):
        raise ValueError("socket identity or listener state mismatch")
    attributes = {}
    offset = 32
    while offset < len(data):
        if len(data) - offset < 4:
            raise ValueError("truncated attribute header")
        size, attribute_type = struct.unpack_from("=HH", data, offset)
        aligned_size = (size + 3) & ~3
        if size < 4 or offset + aligned_size > len(data):
            raise ValueError("truncated attribute payload or padding")
        if attribute_type not in (0, 1, 4, 6, 7) or attribute_type in attributes:
            raise ValueError("unknown, flagged or duplicate attribute")
        attributes[attribute_type] = data[offset + 4:offset + size]
        offset += aligned_size
    if set(attributes) != {0, 1, 4, 6, 7}:
        raise ValueError("missing required attribute")
    if attributes[0] != name + b"\0" or not name or b"\0" in name or not name.startswith(b"/"):
        raise ValueError("unexpected filesystem socket name")
    if any(len(attributes[key]) != size for key, size in ((1, 8), (4, 8), (6, 1), (7, 4))):
        raise ValueError("invalid attribute size")
    vfs_inode, device = struct.unpack("=II", attributes[1])
    rqueue, wqueue = struct.unpack("=II", attributes[4])
    uid = struct.unpack("=I", attributes[7])[0]
    return {
        "inode": found_inode, "cookie": (low, high), "name": name,
        "vfs_inode": vfs_inode, "vfs_major": device >> 20,
        "vfs_minor": device & 0xFFFFF, "rqueue": rqueue, "wqueue": wqueue,
        "uid": uid, "shutdown": attributes[6][0],
    }


def validate_crash_channel(channel, boot_id):
    if isinstance(channel, dict) and channel.get("kind") == "systemd-coredump-kernel-socket":
        return validate_socket_channel(channel, boot_id)
    if (not isinstance(channel, dict)
            or channel.get("kind") != "systemd-coredump-pipe"
            or channel.get("boot_id") != boot_id
            or not isinstance(channel.get("core_pattern"), str)
            or not CORE_PATTERN.fullmatch(channel["core_pattern"])
            or channel.get("handler_executable") is not True):
        raise ValueError("missing or unsupported crash channel capability")
    for name, identity, active, substate in (
        ("socket", "systemd-coredump.socket", "active", "listening"),
        ("processor", "systemd-coredump@omg-health.service", "inactive", "dead"),
    ):
        fields = channel.get(name)
        if (not isinstance(fields, dict)
                or set(fields) != set(CAPABILITY_PROPERTIES.split(","))
                or fields["Id"] != identity or fields["LoadState"] != "loaded"
                or fields["ActiveState"] != active or fields["SubState"] != substate
                or fields["Result"] != "success"
                or fields["UnitFileState"] not in ("static", "enabled", "enabled-runtime")):
            raise ValueError("crash channel is absent, disabled, pending or failed")


def crash_channel_capability(boot_id):
    pattern = query(["cat", "/proc/sys/kernel/core_pattern"]).strip()
    if pattern == SOCKET_PATTERN:
        return kernel_socket_channel(boot_id, pattern)
    match = CORE_PATTERN.fullmatch(pattern)
    if not match:
        encoded = pattern.encode("utf-8")
        raise ValueError("unsupported kernel crash handler: "
                         f"bytes={len(encoded)} sha256={hashlib.sha256(encoded).hexdigest()}")
    # Check executable availability without invoking the handler or reading cores.
    query(["test", "-x", match[1]])
    channel = {"kind": "systemd-coredump-pipe", "boot_id": boot_id,
               "core_pattern": pattern, "handler_executable": True}
    for name, unit in (("socket", "systemd-coredump.socket"),
                       ("processor", "systemd-coredump@omg-health.service")):
        # An inert instance loads the template without starting a processor.
        evidence = query(["systemctl", "show", "--all",
                          "--property=" + CAPABILITY_PROPERTIES, unit])
        fields = {}
        for line in evidence.splitlines():
            key, separator, value = line.partition("=")
            if not separator or key not in CAPABILITY_PROPERTIES.split(",") or key in fields:
                raise ValueError("invalid crash channel capability evidence")
            fields[key] = value
        channel[name] = fields
    validate_crash_channel(channel, boot_id)
    return channel


def bounded_file(path, errors="strict"):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > LIMIT:
            raise ValueError("invalid or oversized health evidence")
        data = stream.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ValueError("health evidence grew beyond limit")
    return data.decode("utf-8", errors=errors)


def query(argv):
    # File-backed capture bounds Python memory even if a guest is very noisy.
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        completed = subprocess.run(argv, stdout=output, stderr=errors,
                                   timeout=15, check=False)
        if completed.returncode != 0 or output.tell() > LIMIT:
            errors.seek(0)
            detail = errors.read(4096).decode("utf-8", errors="replace")
            detail = re.sub(r"[^a-zA-Z0-9 ._:/=()\n-]", "?", detail)
            kind = "kernel" if "--dmesg" in argv else "crash"
            raise ValueError(f"{kind} health query failed: exit={completed.returncode}, bytes={output.tell()}: {detail}")
        output.seek(0)
        return output.read(LIMIT + 1).decode("utf-8", errors="strict")


def crash_signatures(text):
    # Publish only the matched signature, never adjacent potentially sensitive text.
    return sorted(set(match.group(0) for match in FATAL.finditer(text)))


def refuse_pending_crash_processing():
    properties = {"Id", "ActiveState", "SubState", "Result"}
    evidence = query(["systemctl", "show", "--all",
                      "--property=Id,ActiveState,SubState,Result", "systemd-coredump@*.service"])
    for block in evidence.strip().split("\n\n"):
        if not block:
            continue
        fields = {}
        for line in block.splitlines():
            key, separator, value = line.partition("=")
            if not separator or key not in properties or key in fields:
                raise ValueError("invalid coredump processing evidence")
            fields[key] = value
        if (set(fields) != properties
                or not fields["Id"].startswith("systemd-coredump@")
                or not fields["Id"].endswith(".service")
                or not fields["SubState"]):
            raise ValueError("invalid coredump processing evidence")
        if fields["ActiveState"] != "inactive" or fields["Result"] != "success":
            raise ValueError("coredump processor is active or failed")


def collect():
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if not BOOT_ID.fullmatch(boot_id):
        raise ValueError("invalid guest boot identity")
    # /proc uses UUID hyphens; journalctl's boot descriptor requires 32 hex digits.
    journal_boot = boot_id.replace("-", "")
    channel = crash_channel_capability(boot_id)
    refuse_pending_crash_processing()
    kernel = query(["journalctl", "--boot=" + journal_boot, "--dmesg", "--quiet", "--no-pager", "--output=cat"])
    if not kernel.strip() or kernel.strip() == "-- No entries --":
        raise ValueError("missing boot kernel evidence")
    cores = query(["journalctl", "--boot=" + journal_boot, "--quiet", "--no-pager", "--output=json",
                   "--output-fields=COREDUMP_COMM,COREDUMP_EXE,COREDUMP_SIGNAL",
                   "MESSAGE_ID=fc2e22bc6ee647b6b90729ab34a250b1"])
    crashes = []
    for line in cores.splitlines():
        row = json.loads(line)
        executable = row.get("COREDUMP_EXE", "")
        process = Path(executable).name if isinstance(executable, str) else ""
        if process not in ("omg", "omgd"):
            process = row.get("COREDUMP_COMM")
        if process in ("omg", "omgd"):
            signal = row.get("COREDUMP_SIGNAL")
            if not isinstance(signal, str) or not re.fullmatch(r"[0-9]{1,3}", signal):
                raise ValueError("invalid crash signal")
            crashes.append({"process": process, "signal": int(signal)})
    refuse_pending_crash_processing()
    if (crash_channel_capability(boot_id) != channel
            or Path("/proc/sys/kernel/random/boot_id").read_text().strip() != boot_id):
        raise ValueError("crash channel or guest boot changed during collection")
    return {"schema_version": 2, "complete": True, "boot_id": boot_id,
            "crash_channel": channel,
            "kernel_bytes": len(kernel.encode()), "fatal_signatures": crash_signatures(kernel),
            "product_crashes": crashes}


def verify_guest(guest, serial, boot_id=None):
    payload = json.loads(bounded_file(guest))
    if (not isinstance(payload, dict) or payload.get("schema_version") != 2
            or payload.get("complete") is not True
            or not isinstance(payload.get("boot_id"), str)
            or not BOOT_ID.fullmatch(payload["boot_id"])
            or type(payload.get("kernel_bytes")) is not int
            or not 0 < payload["kernel_bytes"] <= LIMIT
            or payload.get("fatal_signatures") != []
            or payload.get("product_crashes") != []):
        raise ValueError("guest crash or incomplete health evidence")
    validate_crash_channel(payload.get("crash_channel"), payload["boot_id"])
    # Serial consoles are byte streams, not a UTF-8 protocol. A torn terminal
    # glyph must not invalidate otherwise complete health evidence. Preserve
    # invalid bytes as escapes; never discard surrounding crash signatures.
    serial_text = bounded_file(serial, errors="backslashreplace")
    if not serial_text.strip() or crash_signatures(serial_text):
        raise ValueError("missing serial evidence or fatal guest signature")
    if boot_id is not None and payload["boot_id"] != boot_id:
        raise ValueError("health evidence belongs to a different trial boot")
    return 0


def verify(guest, serial, controller, boot_id=None):
    verify_guest(guest, serial, boot_id)
    state = json.loads(bounded_file(controller))
    if (not isinstance(state, dict) or state.get("Running") is not True
            or state.get("OOMKilled") is not False
            or type(state.get("ExitCode")) is not int or state["ExitCode"] != 0):
        raise ValueError("controller stopped or was OOM killed")
    return 0


def verify_preparations(root):
    boots = set()
    for operation in ("remove", "install"):
        prefix = root / "transactions" / f"prepare-{operation}"
        boot_id = bounded_file(Path(str(prefix) + "-boot-id.txt")).strip()
        if not BOOT_ID.fullmatch(boot_id) or boot_id in boots:
            raise ValueError("invalid or repeated preparation boot identity")
        boots.add(boot_id)
        serial = (root / "guest" / "serial.log" if operation == "remove"
                  else Path(str(prefix) + "-serial.log"))
        verify_guest(Path(str(prefix) + "-health.json"), serial, boot_id)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("collect")
    preparations = commands.add_parser("verify-preparations")
    preparations.add_argument("--root", type=Path, required=True)
    trial = commands.add_parser("verify-trial")
    trial.add_argument("--guest", type=Path, required=True)
    trial.add_argument("--serial", type=Path, required=True)
    trial.add_argument("--boot-id", required=True)
    admission = commands.add_parser("verify")
    admission.add_argument("--boot-id", required=True)
    for name in ("guest", "serial", "controller"):
        admission.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "collect":
            print(json.dumps(collect()))
            return 0
        if args.command == "verify-trial":
            return verify_guest(args.guest, args.serial, args.boot_id)
        if args.command == "verify-preparations":
            return verify_preparations(args.root)
        return verify(args.guest, args.serial, args.controller, args.boot_id)
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"QEMU health evidence failed admission: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
