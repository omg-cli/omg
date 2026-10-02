#!/usr/bin/env python3
"""Exercise production OSV HTTPS in an isolated disposable QEMU guest.

Query fields: https://google.github.io/osv.dev/post-v1-query/
Advisory format: https://ossf.github.io/osv-schema/
Private namespaces: https://manpages.debian.org/trixie/util-linux/unshare.1.en.html
Native source identities: https://manpages.debian.org/trixie/dpkg/dpkg-query.1.en.html
"""
import collections
import hashlib
import http.server
import json
import os
import pathlib
import re
import signal
import ssl
import subprocess
import threading
import time
import argparse

FIXTURE_ID = "x_OMG-QEMU-616"
CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def response_for_query(path, body, identities, ecosystem):
    refusal = (400, {"error": "query does not match a native installed source identity"})
    if path != "/v1/query" or not isinstance(body, dict) or set(body) != {"package", "version"}:
        return refusal
    package = body["package"]
    version = body["version"]
    if not isinstance(package, dict) or set(package) != {"name", "ecosystem"}:
        return refusal
    if not isinstance(package["name"], str) or not isinstance(version, str):
        return refusal
    identity = (package["name"], version)
    if package["ecosystem"] != ecosystem or identity not in identities:
        return refusal
    if identity[0] != "glibc":
        return 200, {"vulns": []}
    advisory = {
        "schema_version": "1.9.1",
        "id": FIXTURE_ID,
        "modified": "2026-10-02T00:00:00Z",
        "summary": "Synthetic fixture advisory",
        "severity": [{"type": "CVSS_V3", "score": CVSS_VECTOR}],
        "affected": [{"package": dict(package), "versions": [version]}],
    }
    return 200, {"vulns": [advisory]}


def verify_result(result, targets, fail=False):
    assert result.returncode == (1 if fail else 0), "unexpected product exit status"
    text = re.sub('\\x1b\\[[0-9;]*m', '', result.stdout)
    found = re.findall('^  (\\S+) \\(1 issues\\):$', text, re.M)
    assert sorted(found) == targets, (found, targets)
    assert text.count(FIXTURE_ID) == len(targets) and text.count('[Score: 9.8]') == len(targets)
    assert f'Found {len(targets)} vulnerabilities ({len(targets)} high severity)' in text
    assert result.stderr.strip() == (f'Error: Vulnerability scan found {len(targets)} finding(s)' if fail else '')


def verify_requests(events, identities, ecosystem):
    requests = [e for e in events if e['kind'] == 'request']
    for entry in requests:
        status, response = response_for_query(entry["path"], entry["body"], identities, ecosystem)
        assert status == 200 and entry["response"] == response, "native query or advisory evidence mismatch"
    assert all((e['status'] == 200 for e in requests))
    actual = collections.Counter(((e['body']['package']['name'], e['body']['version']) for e in requests))
    assert actual == collections.Counter({identity: 1 for identity in identities}), (len(actual), len(identities))
    return len(requests)

def main():
    import pwd
    parser = argparse.ArgumentParser(description='Verify native production OSV in an isolated disposable QEMU guest.')
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
    assert root.parent == pathlib.Path('/tmp') and root.name.startswith('omg-osv-qemu-')
    root.mkdir(mode=0o755, exist_ok=False)
    logs = root / 'evidence'
    logs.mkdir(mode=0o755)
    private = root / 'user'
    private.mkdir(mode=0o700)
    os.chown(private, uid, gid)
    hosts = pathlib.Path('/etc/hosts')
    bundle = pathlib.Path('/etc/ssl/certs/ca-certificates.crt')
    assert hosts.is_file() and bundle.is_file()
    original_files = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (hosts, bundle)}
    assert not re.search('(^|\\s)api\\.osv\\.dev(\\s|$)', hosts.read_text())
    (root / 'hosts').write_bytes(hosts.read_bytes() + b'\n127.0.0.1 api.osv.dev\n')
    subprocess.run(['mount', '--bind', str(root / 'hosts'), str(hosts)], check=True, timeout=10, capture_output=True)
    import socket
    resolved = {row[4][0] for row in socket.getaddrinfo('api.osv.dev', 443, type=socket.SOCK_STREAM)}
    assert resolved == {'127.0.0.1'}, 'fixture hostname must resolve exclusively to local IPv4 loopback'
    routes = json.loads(subprocess.check_output(['ip', '-j', 'route', 'show', 'table', 'all'], text=True))
    assert all((row.get('dev') == 'lo' for row in routes)), 'fixture namespace must have no external route'
    query_format = '${Package}\t${source:Package}\t${source:Version}\t${db:Status-Status}\n'
    native = subprocess.check_output(['dpkg-query', '-W', '-f', query_format], text=True)
    rows = [line.split('\t') for line in native.splitlines()]
    rows = [r for r in rows if r[-1] == 'installed']
    assert all((len(r) == 4 and r[0] and r[1] and r[2] for r in rows))
    identities = {(r[1], r[2]) for r in rows}
    targets = sorted((r[0] for r in rows if r[1] == 'glibc'))
    assert len(targets) > 1
    os_release = pathlib.Path('/etc/os-release').read_text()
    (logs / 'os-release').write_text(os_release)
    release_values = {k: v.strip(chr(34)) for k, v in (line.split('=', 1) for line in os_release.splitlines() if '=' in line)}
    assert release_values['ID'] in ('debian', 'ubuntu')
    ecosystem = ('Debian:' if release_values['ID'] == 'debian' else 'Ubuntu:') + release_values['VERSION_ID']
    ecosystem += ':LTS' if release_values['ID'] == 'ubuntu' and 'LTS' in release_values.get('VERSION', '') else ''
    state_paths = [pathlib.Path('/var/lib/dpkg/status'), pathlib.Path('/var/lib/apt/extended_states')]
    state = lambda: {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in state_paths if p.exists()}
    before = state()
    (logs / 'native-query.tsv').write_text(native)
    fixture_id = FIXTURE_ID
    key = root / 'server.key'
    ca = root / 'ca.crt'
    cert = root / 'server.crt'

    def setup(command):
        r = subprocess.run(command, capture_output=True, timeout=30)
        assert r.returncode == 0, r.stderr.decode(errors='replace')
    setup(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=OMG OSV fixture CA', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-keyout', str(root / 'ca.key'), '-out', str(ca)])
    setup(['openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=api.osv.dev', '-keyout', str(key), '-out', str(root / 'server.csr')])
    (root / 'server.ext').write_text('subjectAltName=DNS:api.osv.dev\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
    setup(['openssl', 'x509', '-req', '-in', str(root / 'server.csr'), '-CA', str(ca), '-CAkey', str(root / 'ca.key'), '-CAcreateserial', '-days', '1', '-extfile', str(root / 'server.ext'), '-out', str(cert)])
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    events = []
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

        def do_POST(self):
            size = int(self.headers.get('Content-Length', '0'))
            assert 0 < size <= 65536
            body = json.loads(self.rfile.read(size))
            status, response = response_for_query(self.path, body, identities, ecosystem)
            assert self.client_address[0] == '127.0.0.1', 'fixture client must be local to the isolated guest namespace'
            encoded = json.dumps(response).encode()
            event({'kind': 'request', 'path': self.path, 'body': body, 'status': status, 'response': response})
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
    env.update(HOME=str(private), XDG_RUNTIME_DIR=str(private), NO_COLOR='1', NO_PROXY='api.osv.dev,127.0.0.1', OMG_TEST_MODE='0', OMG_DISABLE_TELEMETRY='1', OMG_DISABLE_DAEMON='1', OMG_DATA_DIR=str(private / 'data'), OMG_CACHE_DIR=str(private / 'cache'), OMG_CONFIG_DIR=str(private / 'config'), OMG_DAEMON_DATA_DIR=str(private / 'daemon'), OMG_SOCKET_PATH=str(private / 'omg.sock'))

    def run(label, args, environment=None, expected=0):
        r = subprocess.run([binary] + args, env=env if environment is None else environment, user=uid, group=gid, extra_groups=[], capture_output=True, text=True, timeout=60)
        (logs / (label + '.stdout')).write_text(r.stdout)
        (logs / (label + '.stderr')).write_text(r.stderr)
        receipt['product_results'][label] = {'argv': args, 'exit_code': r.returncode}
        assert r.returncode == expected, (label, r.returncode, r.stderr[-1000:])
        assert state() == before
        return r

    daemon = None
    receipt = {'schema_version': 1, 'scope': 'isolated native QEMU OSV lifecycle sub-contract; inventory selection is unchanged', 'source_sha': os.environ.get('OMG_CONTRACT_SOURCE_SHA'), 'boot_id': pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'fixture_sha256': hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(), 'omg_sha256': hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest(), 'omgd_sha256': hashlib.sha256(pathlib.Path(daemon_binary).read_bytes()).hexdigest(), 'ordinary_user_uid': uid, 'isolated_vm_mount_and_network': True, 'original_system_files': original_files, 'ecosystem': ecosystem, 'affected_binaries': targets, 'source_identities': len(identities), 'fixture_id': fixture_id, 'expected_score': 9.8, 'accepted': False, 'native_archive_sha256': args.archive_sha256, 'native_state_before': before, 'product_results': {}}
    try:
        untrusted = run('untrusted-tls', ['audit', 'scan'], expected=1)
        assert 'Failed to scan package' in untrusted.stderr and 'No vulnerabilities found' not in untrusted.stdout and ('Vulnerability scan found' not in untrusted.stderr)
        assert any((e['kind'] == 'tls-error' for e in events)) and (not any((e['kind'] == 'request' for e in events)))
        trusted_bundle = root / 'trusted-ca-bundle.crt'
        trusted_bundle.write_bytes(bundle.read_bytes() + b'\n' + ca.read_bytes())
        os.chmod(trusted_bundle, 0o644)
        setup(['mount', '--bind', str(trusted_bundle), str(bundle)])
        for label, args, expected in [('direct-plain', ['audit', 'scan'], 0), ('direct-findings', ['audit', 'scan', '--fail-on-findings'], 1)]:
            start = len(events)
            result = run(label, args, expected=expected)
            verify_result(result, targets, expected == 1)
            receipt[label + '_requests'] = verify_requests(events[start:], identities, ecosystem)
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
                verify_result(result, targets, expected == 1)
            final = counter('daemon-after')
            assert final - initial == 2
            receipt['daemon_requests_delta'] = final - initial
            receipt['daemon_fixture_requests'] = verify_requests(events[start:], identities, ecosystem)
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
