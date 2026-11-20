#!/usr/bin/env python3
"""Native Arch advisory oracle; synthetic feed, never an invented CVSS score.

Feed format: https://security.archlinux.org/issues/all.json
Native version identities: https://man.archlinux.org/man/pacman.8.en
"""
import re
from datetime import datetime, timedelta, timezone

ARCH_HOST = "omg-advisories.latham.workers.dev"
ARCH_PATH = "/v1/arch/advisories"
ARCH_UPSTREAM = "https://security.archlinux.org/issues/all.json"
SNAPSHOT_REFUSALS = {
    "tampered-payload": "Arch snapshot SHA-256 mismatch",
    "stale-snapshot": "invalid or stale Arch snapshot timestamps",
    "future-snapshot": "invalid or stale Arch snapshot timestamps",
    "reversed-times": "invalid or stale Arch snapshot timestamps",
}


def arch_feed(version):
    assert isinstance(version, str) and version and not any(c.isspace() for c in version)
    common = {"packages": ["glibc"], "severity": "Critical", "affected": version,
              "issues": ["CVE-OMG-QEMU-616"], "type": "synthetic fixture"}
    return [dict(common, name="AVG-OMG-QEMU-616", status="Vulnerable", fixed=None),
            dict(common, name="AVG-OMG-QEMU-FIXED", status="Fixed", fixed=version),
            dict(common, name="AVG-OMG-QEMU-NOT-AFFECTED", status="Not affected", fixed=None)]


def verify_native_result(result, fail=False, *, expected_possible=False):
    assert type(expected_possible) is bool, "expected applicability mode must be boolean"
    assert result.returncode == int(fail), "wrong actual native audit exit"
    text = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout)
    assert re.findall(r"^  (\S+) \(1 issues\):$", text, re.M) == ["glibc"]
    assert "Found 1 vulnerabilities (1 high severity)" in text
    suffix = r" \[possible match; applicability unverified\]" if expected_possible else ""
    assert re.findall(r"^    → (\S+) - .*\[Advisory severity: (\S+)\]" + suffix + r"$", text, re.M) == [("AVG-OMG-QEMU-616", "Critical")]
    if expected_possible:
        scopes = re.findall(r"^  ⚠ Advisory scope: 0 assessed package\(s\), ([1-9][0-9]*) package\(s\) with unknown coverage; absence of findings does not establish safety\.$", text, re.M)
        assert len(scopes) == 1, "installed Unknown inventory requires its explicit incomplete coverage warning"
        assert text.count("Advisory scope:") == 1, "ambiguous advisory scope warning"
    else:
        assert "[possible match; applicability unverified]" not in text, "unexpected possible applicability"
        assert "Advisory scope:" not in text, "unexpected incomplete advisory scope"
    assert "[Score:" not in text and "AVG-OMG-QEMU-FIXED" not in text and "AVG-OMG-QEMU-NOT-AFFECTED" not in text
    assert result.stderr.strip() == ("Error: Vulnerability scan found 1 finding(s)" if fail else "")


def utc_timestamp(value):
    assert isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", value), "missing UTC request observation"
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    return parsed


def iso_timestamp(value):
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def arch_snapshot(version, observed_at, mode="valid"):
    observed = utc_timestamp(observed_at)
    payload = json.dumps(arch_feed(version), ensure_ascii=False, indent=2) + "\n"
    envelope = {"schema_version": 1, "source": "arch-security", "source_url": ARCH_UPSTREAM,
                "fetched_at": observed_at, "checked_at": observed_at, "complete": True,
                "payload_sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest(), "payload_json": payload}
    if mode == "tampered-payload":
        envelope["payload_json"] += " "
    elif mode == "stale-snapshot":
        envelope["fetched_at"] = envelope["checked_at"] = iso_timestamp(observed - timedelta(minutes=31))
    elif mode == "future-snapshot":
        envelope["fetched_at"] = envelope["checked_at"] = iso_timestamp(observed + timedelta(minutes=5))
    elif mode == "reversed-times":
        envelope["fetched_at"] = iso_timestamp(observed + timedelta(seconds=1))
    else:
        assert mode == "valid", "unknown snapshot control"
    return envelope


def snapshot_response(host, path, version, observed_at, mode="valid"):
    if host != ARCH_HOST or path != ARCH_PATH:
        return 404, {"error": "unexpected native snapshot destination"}
    return 200, arch_snapshot(version, observed_at, mode)


def verify_snapshot_refusal(result, mode):
    assert type(result.returncode) is int and result.returncode == 1, "invalid snapshot did not fail closed"
    assert isinstance(result.stdout, str) and isinstance(result.stderr, str), "snapshot refusal output missing"
    assert "Failed to query native security advisories" in result.stderr
    assert SNAPSHOT_REFUSALS[mode] in result.stderr, "wrong snapshot refusal reason"
    assert "No vulnerabilities found" not in result.stdout and "Found 1 vulnerabilities" not in result.stdout
    assert "Vulnerability scan found" not in result.stderr


def verify_arch_requests(events, version, minimum, maximum, mode="valid"):
    assert minimum <= len(events) <= maximum, "native snapshot request phase incomplete or repeated"
    for event in events:
        observed = event.get("observed_at")
        expected = {"kind": "request", "method": "GET", "host": ARCH_HOST, "path": ARCH_PATH,
                    "status": 200, "observed_at": observed, "response": arch_snapshot(version, observed, mode)}
        actual_json = json.dumps(event, sort_keys=True, ensure_ascii=False, allow_nan=False)
        expected_json = json.dumps(expected, sort_keys=True, ensure_ascii=False, allow_nan=False)
        assert actual_json == expected_json, "native snapshot transport, provenance or byte integrity mismatch"
    return len(events)


def private_hosts(text):
    assert not re.search(r"(^|\s)" + re.escape(ARCH_HOST) + r"(\s|$)", text), "snapshot hostname already mapped"
    return text + "\n127.0.0.1 " + ARCH_HOST + "\n"

import hashlib
import http.server
import json
import os
import pathlib
import signal
import ssl
import subprocess
import threading
import time
import argparse

def private_hosts_nss(text):
    result, count = re.subn(r"^hosts:[^\n]*$", "hosts: files", text, flags=re.M)
    assert count == 1, "native NSS must have exactly one hosts service row"
    return result


def main():
    import pwd
    parser = argparse.ArgumentParser(description='Verify native production Arch advisory in an isolated disposable QEMU guest.')
    parser.add_argument('--binary', type=pathlib.Path, required=True)
    parser.add_argument('--daemon', type=pathlib.Path, required=True)
    parser.add_argument('--fixture-root', type=pathlib.Path, required=True)
    parser.add_argument('--archive-sha256')
    args = parser.parse_args()
    assert args.archive_sha256 is None or re.fullmatch("[0-9a-f]{64}", args.archive_sha256), "invalid native archive identity"
    virtual = subprocess.run(['systemd-detect-virt', '--vm'], capture_output=True, text=True, timeout=10)
    assert os.getuid() == 0 and virtual.returncode == 0 and (virtual.stdout.strip() in ('qemu', 'kvm')), 'requires disposable QEMU guest'
    assert all((os.readlink('/proc/self/ns/' + kind) != os.readlink('/proc/1/ns/' + kind) for kind in ('mnt', 'net'))), 'requires private mount and network namespaces'
    links = json.loads(subprocess.check_output(['ip', '-j', 'link'], text=True))
    assert [x['ifname'] for x in links] == ['lo']
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True, timeout=10, capture_output=True)
    account = pwd.getpwnam('bench')
    assert account.pw_uid != 0
    uid = account.pw_uid
    gid = account.pw_gid
    binary = str(args.binary.resolve(strict=True))
    daemon_binary = str(args.daemon.resolve(strict=True))
    assert all((pathlib.Path(p).is_relative_to(pathlib.Path(account.pw_dir)) for p in (binary, daemon_binary)))
    root = args.fixture_root.resolve()
    assert root.parent == pathlib.Path('/tmp') and root.name.startswith('omg-arch-advisory-qemu-')
    root.mkdir(mode=0o755, exist_ok=False)
    logs = root / 'evidence'
    logs.mkdir(mode=0o755)
    private = root / 'user'
    private.mkdir(mode=0o700)
    os.chown(private, uid, gid)
    hosts = pathlib.Path('/etc/hosts')
    bundle = pathlib.Path('/etc/ssl/certs/ca-certificates.crt')
    nss = pathlib.Path('/etc/nsswitch.conf')
    assert hosts.is_file() and bundle.is_file() and nss.is_file()
    original_files = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (hosts, bundle, nss)}
    (root / 'hosts').write_text(private_hosts(hosts.read_text()))
    subprocess.run(['mount', '--bind', str(root / 'hosts'), str(hosts)], check=True, timeout=10, capture_output=True)
    # nss-resolve reaches the parent service through an AF_UNIX socket.
    # Confine hostname resolution to the private hosts file before any lookup.
    # https://man.archlinux.org/man/nss-resolve.8.en
    (logs / 'native-nss-before.conf').write_bytes(nss.read_bytes())
    private_nss = root / 'nsswitch.conf'
    private_nss.write_text(private_hosts_nss(nss.read_text()))
    subprocess.run(['mount', '--bind', str(private_nss), str(nss)], check=True, timeout=10, capture_output=True)
    (logs / 'private-nss.conf').write_bytes(nss.read_bytes())
    import socket
    resolved = {row[4][0] for row in socket.getaddrinfo(ARCH_HOST, 443, type=socket.SOCK_STREAM)}
    (logs / 'dns-isolation.json').write_text(json.dumps({'hostname': ARCH_HOST, 'resolved_addresses': sorted(resolved)}) + '\n')
    assert resolved == {'127.0.0.1'}, ('fixture hostname must resolve exclusively to local IPv4 loopback', sorted(resolved))
    routes = json.loads(subprocess.check_output(['ip', '-j', 'route', 'show', 'table', 'all'], text=True))
    assert all((row.get('dev') == 'lo' for row in routes)), 'fixture namespace must have no external route'
    native = subprocess.check_output(['pacman', '-Q'], text=True)
    packages = dict(line.split(' ', 1) for line in native.splitlines())
    assert 'glibc' in packages and all(packages.values())
    version = packages['glibc']
    targets = ['glibc']
    (logs / 'native-query.tsv').write_text(native)
    (logs / 'os-release').write_bytes(pathlib.Path('/etc/os-release').read_bytes())
    assert any(line == 'ID=arch' for line in pathlib.Path('/etc/os-release').read_text().splitlines())
    def state():
        local = pathlib.Path('/var/lib/pacman/local')
        metadata = {}
        for entry in sorted(local.rglob('*')):
            assert not entry.is_symlink(), 'native pacman database must not contain links'
            if entry.is_file():
                metadata[str(entry.relative_to(local))] = hashlib.sha256(entry.read_bytes()).hexdigest()
        assert metadata
        return {'installed': subprocess.check_output(['pacman', '-Q'], text=True),
                'explicit': subprocess.check_output(['pacman', '-Qe'], text=True), 'database_sha256': metadata}
    before = state()
    feed = arch_feed(version)
    (logs / 'native-feed.json').write_text(json.dumps(feed, indent=2) + '\n')
    fixture_id = "AVG-OMG-QEMU-616"
    key = root / 'server.key'
    ca = root / 'ca.crt'
    cert = root / 'server.crt'

    def setup(command):
        r = subprocess.run(command, capture_output=True, timeout=30)
        assert r.returncode == 0, r.stderr.decode(errors='replace')
    setup(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=OMG Arch advisory fixture CA', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-keyout', str(root / 'ca.key'), '-out', str(ca)])
    setup(['openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=' + ARCH_HOST, '-keyout', str(key), '-out', str(root / 'server.csr')])
    (root / 'server.ext').write_text('subjectAltName=DNS:' + ARCH_HOST + '\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
    setup(['openssl', 'x509', '-req', '-in', str(root / 'server.csr'), '-CA', str(ca), '-CAkey', str(root / 'ca.key'), '-CAcreateserial', '-days', '1', '-extfile', str(root / 'server.ext'), '-out', str(cert)])
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    events = []
    snapshot_mode = 'valid'
    lock = threading.Lock()

    def event(value):
        with lock:
            events.append(value)

    class Server(http.server.ThreadingHTTPServer):
        daemon_threads = True

        def get_request(self):
            stream, address = super().get_request()
            stream.settimeout(5)
            try:
                return (context.wrap_socket(stream, server_side=True), address)
            except ssl.SSLError as error:
                event({'kind': 'tls-error', 'error': str(error)})
                stream.close()
                raise

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, *args):
            return

        def do_GET(self):
            assert self.client_address[0] == '127.0.0.1', 'fixture peer must stay local'
            observed = iso_timestamp(datetime.now(timezone.utc))
            host = self.headers.get('Host')
            status, response = snapshot_response(host, self.path, version, observed, snapshot_mode)
            encoded = json.dumps(response).encode()
            event({'kind': 'request', 'method': 'GET', 'host': host, 'path': self.path, 'status': status, 'observed_at': observed, 'response': response})
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
    server = Server(('127.0.0.1', 443), Handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    env = {k: v for k, v in os.environ.items() if k.lower() not in ('http_proxy', 'https_proxy', 'all_proxy', 'no_proxy') and k not in ('SSL_CERT_FILE', 'SSL_CERT_DIR')}
    env.pop('OMG_TEST_DISTRO', None)
    env.pop('OMG_TEST_BACKEND', None)
    env.update(HOME=str(private), XDG_RUNTIME_DIR=str(private), NO_COLOR='1', NO_PROXY=ARCH_HOST + ',127.0.0.1', OMG_TEST_MODE='0', OMG_DISABLE_TELEMETRY='1', OMG_DISABLE_DAEMON='1', OMG_DATA_DIR=str(private / 'data'), OMG_CACHE_DIR=str(private / 'cache'), OMG_CONFIG_DIR=str(private / 'config'), OMG_DAEMON_DATA_DIR=str(private / 'daemon'), OMG_SOCKET_PATH=str(private / 'omg.sock'))

    def run(label, args, environment=None, expected=0, embedded=False):
        r = subprocess.run([binary] + args, env=env if environment is None else environment, user=uid, group=gid, extra_groups=[], capture_output=True, text=True, timeout=60)
        result = {'argv': args, 'exit_code': r.returncode}
        if embedded:
            receipt['snapshot_controls'][label] = dict(result, stdout=r.stdout, stderr=r.stderr)
        else:
            (logs / (label + '.stdout')).write_text(r.stdout)
            (logs / (label + '.stderr')).write_text(r.stderr)
            receipt['product_results'][label] = result
        assert r.returncode == expected, (label, r.returncode, r.stderr[-1000:])
        assert state() == before
        return r

    daemon = None
    receipt = {'schema_version': 1, 'scope': 'local native Arch advisory experiment; not hosted inventory acceptance', 'source_sha': os.environ.get('OMG_CONTRACT_SOURCE_SHA'), 'boot_id': pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'fixture_sha256': hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(), 'omg_sha256': hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest(), 'omgd_sha256': hashlib.sha256(pathlib.Path(daemon_binary).read_bytes()).hexdigest(), 'ordinary_user_uid': uid, 'isolated_vm_mount_and_network': True, 'original_system_files': original_files, 'native_glibc_version': version, 'affected_binaries': targets, 'fixture_id': fixture_id, 'expected_native_severity': 'Critical', 'accepted': False, 'native_archive_sha256': args.archive_sha256, 'native_state_before': before, 'product_results': {}, 'snapshot_controls': {}}
    try:
        untrusted = run('untrusted-tls', ['audit', 'scan'], expected=1)
        assert 'Failed to query native security advisories' in untrusted.stderr and 'No vulnerabilities found' not in untrusted.stdout and ('Vulnerability scan found' not in untrusted.stderr)
        assert any((e['kind'] == 'tls-error' for e in events)) and (not any((e['kind'] == 'request' for e in events)))
        trusted_bundle = root / 'trusted-ca-bundle.crt'
        trusted_bundle.write_bytes(bundle.read_bytes() + b'\n' + ca.read_bytes())
        os.chmod(trusted_bundle, 0o644)
        setup(['mount', '--bind', str(trusted_bundle), str(bundle)])
        for snapshot_mode in SNAPSHOT_REFUSALS:
            start = len(events)
            result = run(snapshot_mode, ['audit', 'scan'], expected=1, embedded=True)
            verify_snapshot_refusal(result, snapshot_mode)
            receipt['snapshot_controls'][snapshot_mode]['requests'] = verify_arch_requests(events[start:], version, 1, 1, snapshot_mode)
        snapshot_mode = 'valid'
        for label, args, expected in [('direct-plain', ['audit', 'scan'], 0), ('direct-findings', ['audit', 'scan', '--fail-on-findings'], 1)]:
            start = len(events)
            result = run(label, args, expected=expected)
            verify_native_result(result, expected == 1, expected_possible=True)
            receipt[label + '_requests'] = verify_arch_requests(events[start:], version, 1, 1)
        daemon_env = dict(env)
        daemon_env.pop('OMG_DISABLE_DAEMON')
        # The production background worker may scan before the first metrics call.
        # Count the entire daemon lifetime, including that initial cache warmup.
        start = len(events)
        with (logs / 'daemon.log').open('wb') as out:
            daemon = subprocess.Popen([daemon_binary], env=daemon_env, user=uid, group=gid, extra_groups=[], stdout=out, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                assert daemon.poll() is None, 'daemon exited before readiness'
                if pathlib.Path(env['OMG_SOCKET_PATH']).exists():
                    break
                time.sleep(0.2)
            assert pathlib.Path(env['OMG_SOCKET_PATH']).is_socket(), 'daemon readiness failed'
            socket = pathlib.Path(env['OMG_SOCKET_PATH']).stat()
            assert socket.st_uid == uid and socket.st_mode & 0o777 == 0o600

            def counter(label):
                result = run(label, ['metrics'], environment=daemon_env)
                values = re.findall('^omg_security_audit_requests_total (\\d+)$', result.stdout, re.M)
                assert len(values) == 1
                return int(values[0])
            initial = counter('daemon-before')
            for label, args, expected in [('daemon-plain', ['audit', 'scan'], 0), ('daemon-findings', ['audit', 'scan', '--fail-on-findings'], 1)]:
                result = run(label, args, environment=daemon_env, expected=expected)
                verify_native_result(result, expected == 1, expected_possible=True)
            final = counter('daemon-after')
            assert final - initial == 2
            receipt['daemon_requests_delta'] = final - initial
            receipt['daemon_fixture_requests'] = verify_arch_requests(events[start:], version, 2, 3)
        receipt['native_state_after'] = state()
        receipt['native_state_unchanged'] = receipt['native_state_after'] == before
        receipt['accepted'] = True
    finally:
        if daemon is not None and daemon.poll() is None:
            daemon.send_signal(signal.SIGINT)
            try:
                daemon.wait(timeout=5)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait(timeout=5)
                raise
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()
        (logs / 'fixture-events.json').write_text(json.dumps(events, indent=2) + '\n')
        (logs / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt), flush=True)
if __name__ == '__main__':
    main()
