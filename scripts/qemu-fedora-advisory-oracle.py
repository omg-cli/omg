#!/usr/bin/env python3
"""Native Fedora advisory fixture; metadata authentication remains mandatory.

Selection: https://dnf5.readthedocs.io/en/latest/commands/advisory.8.html
Authentication: https://dnf5.readthedocs.io/en/latest/dnf5.conf.5.html
"""
import re
import xml.etree.ElementTree as ET


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def updateinfo(identity):
    if (not isinstance(identity, dict) or set(identity) != {"name", "epoch", "version", "release", "arch"}
            or identity["name"] != "glibc" or identity["arch"] not in ("x86_64", "aarch64")
            or not isinstance(identity["epoch"], str) or not re.fullmatch(r"[0-9]+", identity["epoch"])
            or any(not isinstance(identity[key], str) or not re.fullmatch(r"[a-zA-Z0-9._+~^]+", identity[key]) for key in ("version", "release"))):
        raise ValueError("complete native glibc NEVRA is required")
    rows = (("OMG-QEMU-FEDORA-616", dict(identity, release=identity["release"] + ".omgqemu616")),
            ("OMG-QEMU-FEDORA-FIXED", identity),
            ("OMG-QEMU-FEDORA-FOREIGN", dict(identity, release=identity["release"] + ".omgqemu616", arch="aarch64" if identity["arch"] == "x86_64" else "x86_64")))
    root = ET.Element("updates")
    for name, package in rows:
        row = ET.SubElement(root, "update", {"from": "omg-qemu-fixture.invalid", "status": "stable", "type": "security", "version": "1"})
        for tag, value in (("id", name), ("title", "Synthetic native DNF advisory"), ("severity", "Important"),
                           ("description", "Synthetic local test; not a published vulnerability.")):
            ET.SubElement(row, tag).text = value
        ET.SubElement(row, "issued", {"date": "2026-10-02 00:00:00"})
        ET.SubElement(row, "updated", {"date": "2026-10-02 00:00:00"})
        refs = ET.SubElement(row, "references")
        ET.SubElement(refs, "reference", {"href": "https://example.invalid/omg-qemu-616", "id": "CVE-OMG-QEMU-616", "type": "cve", "title": "Synthetic fixture"})
        collection = ET.SubElement(ET.SubElement(row, "pkglist"), "collection", {"short": "omg-qemu"})
        ET.SubElement(collection, "name").text = "Signed local advisory fixture"
        ET.SubElement(collection, "package", package)
    return ET.tostring(root, encoding="unicode", xml_declaration=True) + "\n"


def verify_native_result(result, fail=False):
    _require(result.returncode == int(fail), "wrong actual native audit exit")
    text = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout)
    _require(re.findall(r"^  (\S+) \(1 issues\):$", text, re.M) == ["glibc"], 'native Fedora advisory fixture check failed')
    _require("Found 1 vulnerabilities (1 high severity)" in text, 'native Fedora advisory fixture check failed')
    _require(re.findall(r"^    → (\S+) - .*\[Advisory severity: (\S+)\]$", text, re.M) == [("OMG-QEMU-FEDORA-616", "Important")], 'native Fedora advisory fixture check failed')
    _require("[Score:" not in text and "OMG-QEMU-FEDORA-FIXED" not in text and "OMG-QEMU-FEDORA-FOREIGN" not in text, 'native Fedora advisory fixture check failed')
    _require(result.stderr.strip() == ("Error: Vulnerability scan found 1 finding(s)" if fail else ""), 'native Fedora advisory fixture check failed')

import argparse
import configparser
import hashlib
import json
import os
import pathlib
import signal
import subprocess
import time


def main():
    import pwd

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=pathlib.Path, required=True)
    parser.add_argument('--daemon', type=pathlib.Path, required=True)
    parser.add_argument('--fixture-root', type=pathlib.Path, required=True)
    parser.add_argument('--archive-sha256', required=True)
    args = parser.parse_args()
    _require(re.fullmatch(r'[0-9a-f]{64}', args.archive_sha256), 'native Fedora advisory fixture check failed')
    virtual = subprocess.run(['systemd-detect-virt', '--vm'], capture_output=True, text=True, timeout=10)
    _require(os.getuid() == 0 and virtual.returncode == 0 and virtual.stdout.strip() in ('qemu', 'kvm'), 'requires disposable QEMU guest')
    _require(all(os.readlink('/proc/self/ns/' + kind) != os.readlink('/proc/1/ns/' + kind) for kind in ('mnt', 'net')), 'requires private mount and network namespaces')
    links = json.loads(subprocess.check_output(['ip', '-j', 'link'], text=True))
    _require([row['ifname'] for row in links] == ['lo'], 'native Fedora advisory fixture check failed')
    _require(all(row.get('dev') == 'lo' for row in json.loads(subprocess.check_output(['ip', '-j', 'route', 'show', 'table', 'all'], text=True))), 'native Fedora advisory fixture check failed')
    account = pwd.getpwnam('bench'); uid, gid = account.pw_uid, account.pw_gid
    _require(uid != 0, 'native Fedora advisory fixture check failed')
    binary, daemon_binary = (str(p.resolve(strict=True)) for p in (args.binary, args.daemon))
    _require(all(pathlib.Path(p).is_relative_to(pathlib.Path(account.pw_dir)) for p in (binary, daemon_binary)), 'native Fedora advisory fixture check failed')
    root = args.fixture_root.resolve()
    _require(root.parent == pathlib.Path('/tmp') and root.name.startswith('omg-fedora-advisory-qemu-'), 'native Fedora advisory fixture check failed')
    root.mkdir(mode=0o755, exist_ok=False)
    logs = root / 'evidence'; logs.mkdir(mode=0o755)
    private = root / 'user'; private.mkdir(mode=0o700); os.chown(private, uid, gid)
    repo = root / 'repo'; repo.mkdir()
    repoconf = root / 'repos'; repoconf.mkdir()
    keydir = root / 'keys'; keydir.mkdir(mode=0o700)
    (logs / 'os-release').write_bytes(pathlib.Path('/etc/os-release').read_bytes())
    _require('ID=fedora' in pathlib.Path('/etc/os-release').read_text().splitlines(), 'native Fedora advisory fixture check failed')
    config = pathlib.Path('/etc/dnf/dnf.conf'); _require(config.is_file() and not config.is_symlink(), 'native Fedora advisory fixture check failed')
    original_config = hashlib.sha256(config.read_bytes()).hexdigest()
    (logs/'native-dnf-before.conf').write_bytes(config.read_bytes())
    native_format = '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n'
    native = subprocess.check_output(['rpm', '-qa', '--qf', native_format], text=True)
    rows = [dict(zip(('name', 'epoch', 'version', 'release', 'arch'), line.split('\t'))) for line in native.splitlines()]
    architecture = os.uname().machine
    identity = next(row for row in rows if row['name'] == 'glibc' and row['arch'] == architecture)
    foreign = 'aarch64' if architecture == 'x86_64' else 'x86_64'
    _require(not any(row['name'] == 'glibc' and row['arch'] == foreign for row in rows), 'native Fedora advisory fixture check failed')
    (logs / 'native-query.tsv').write_text(native)
    old = identity['epoch'] + ':' + identity['version'] + '-' + identity['release']
    newer = old + '.omgqemu616'
    comparison_env = dict(os.environ, OMG_LEFT_EVR=old, OMG_RIGHT_EVR=newer)
    comparison = subprocess.run(['rpm', '--eval', '%{lua:print(rpm.vercmp(os.getenv("OMG_LEFT_EVR"), os.getenv("OMG_RIGHT_EVR")))}'], env=comparison_env, capture_output=True, text=True, timeout=10, check=True)
    _require(comparison.stdout.strip() == '-1', 'native Fedora advisory fixture check failed')
    (logs / 'native-version-comparison.txt').write_text(comparison.stdout)
    env = {key: value for key, value in os.environ.items() if key.lower() not in ('http_proxy', 'https_proxy', 'all_proxy', 'no_proxy') and key not in ('GNUPGHOME', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'OMG_TEST_DISTRO', 'OMG_TEST_BACKEND')}
    env.update(HOME=str(private), XDG_RUNTIME_DIR=str(private), NO_COLOR='1', OMG_TEST_MODE='0', OMG_DISABLE_TELEMETRY='1', OMG_DISABLE_DAEMON='1', OMG_DATA_DIR=str(private/'data'), OMG_CACHE_DIR=str(private/'cache'), OMG_CONFIG_DIR=str(private/'config'), OMG_DAEMON_DATA_DIR=str(private/'daemon'), OMG_SOCKET_PATH=str(private/'omg.sock'))
    commands = {}

    def command(label, argv, ordinary=False, expected=0):
        kwargs = {'user': uid, 'group': gid, 'extra_groups': [], 'env': env} if ordinary else {}
        result = subprocess.run(argv, capture_output=True, text=True, timeout=60, **kwargs)
        (logs/(label+'.stdout')).write_text(result.stdout); (logs/(label+'.stderr')).write_text(result.stderr)
        commands[label] = {'argv': argv, 'exit_code': result.returncode}
        _require(result.returncode == expected, (label, result.returncode, result.stderr[-1600:]))
        return result

    def state():
        installed = subprocess.check_output(['rpm', '-qa', '--qf', native_format], text=True)
        explicit = subprocess.check_output(['dnf', '--cacheonly', '--disable-repo=*', '--setopt=disable_excludes=*', 'repoquery', '--userinstalled', '--qf', '%{name}\n'], text=True, stderr=subprocess.PIPE)
        reason_root = pathlib.Path('/usr/lib/sysimage/libdnf5')
        reason = {}
        for path in sorted(reason_root.rglob('*.toml')):
            _require(path.is_file() and not path.is_symlink(), 'native Fedora advisory fixture check failed')
            reason[str(path.relative_to(reason_root))] = hashlib.sha256(path.read_bytes()).hexdigest()
        _require('packages.toml' in reason, 'native Fedora advisory fixture check failed')
        return {'installed': '\n'.join(sorted(installed.splitlines()))+'\n', 'explicit': '\n'.join(sorted(explicit.splitlines()))+'\n', 'reason_sha256': reason}

    before = state()
    keyargs = ['gpg', '--homedir', str(keydir), '--batch', '--pinentry-mode', 'loopback', '--passphrase', '']
    command('keygen', keyargs+['--quick-generate-key', 'OMG QEMU advisory fixture <fixture@example.invalid>', 'rsa2048', 'sign', '1d'])
    keylist = command('keylist', keyargs+['--with-colons', '--list-keys']).stdout
    fingerprint = next(line.split(':')[9] for line in keylist.splitlines() if line.startswith('fpr:'))
    public = command('keyexport', keyargs+['--armor', '--export', fingerprint]).stdout
    key = root/'fixture-key.asc'; key.write_text(public); (logs/'fixture-key.asc').write_text(public)
    xml = root/'updateinfo.xml'; xml.write_text(updateinfo(identity)); (logs/'updateinfo.xml').write_bytes(xml.read_bytes())
    command('createrepo', ['createrepo_c', str(repo)])
    command('modifyrepo', ['modifyrepo_c', '--compress-type', 'gz', '--mdtype', 'updateinfo', str(xml), str(repo/'repodata')])
    repomd = repo/'repodata/repomd.xml'
    command('sign', keyargs+['--armor', '--detach-sign', '--output', str(repomd)+'.asc', str(repomd)])
    command('verify', keyargs+['--verify', str(repomd)+'.asc', str(repomd)])
    (logs/'repomd.xml').write_bytes(repomd.read_bytes()); (logs/'repomd.xml.asc').write_bytes(pathlib.Path(str(repomd)+'.asc').read_bytes())
    configuration = configparser.ConfigParser(interpolation=None); configuration.read(config)
    _require(configuration.has_section('main'), 'native Fedora advisory fixture check failed')
    configuration.set('main', 'reposdir', str(repoconf))
    isolated_config = root/'dnf.conf'
    with isolated_config.open('w') as stream: configuration.write(stream)
    (logs/'private-dnf.conf').write_bytes(isolated_config.read_bytes())
    command('private-config', ['mount', '--bind', str(isolated_config), str(config)])
    repo_text = '[omg-qemu-616]\nname=Signed local advisory fixture\nbaseurl=file://'+str(repo)+'\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=1\nlocalpkg_gpgcheck=1\ngpgkey=file://'+str(key)+'\nskip_if_unavailable=false\n'
    (repoconf/'fixture.repo').write_text(repo_text); (logs/'fixture.repo').write_text(repo_text)
    cache = private/'cache/dnf-security'
    common = ['dnf', '--setopt=cachedir='+str(cache), '--setopt=system_cachedir='+str(cache), '--setopt=cacheonly=none', '--setopt=*.skip_if_unavailable=false']
    command('dnf-key-admission', common+['--refresh', '-y', 'makecache'], ordinary=True)
    # DNF stores repository trust separately for each cache, including the default
    # catalogue cache used at daemon startup. Import through native DNF in both.
    # https://dnf5.readthedocs.io/en/latest/dnf5.conf.5.html#repo-gpgcheck
    command('dnf-default-key-admission', ['dnf', '--setopt=*.skip_if_unavailable=false', '--refresh', '-y', 'makecache'], ordinary=True)
    metadata = ET.fromstring(repomd.read_bytes()).find("{http://linux.duke.edu/metadata/repo}data[@type='updateinfo']")
    location = metadata.find('{http://linux.duke.edu/metadata/repo}location').attrib['href']
    compressed = (repo/location).resolve(strict=True)
    _require(compressed.is_relative_to(repo.resolve()) and compressed.name.endswith('-updateinfo.xml.gz'), 'native Fedora advisory fixture check failed')
    (logs/'updateinfo.xml.gz').write_bytes(compressed.read_bytes())
    original_repomd = repomd.read_bytes()
    new_nevra = 'glibc-'+(identity['epoch']+':' if identity['epoch']!='0' else '')+identity['version']+'-'+identity['release']+'.omgqemu616.'+identity['arch']
    selected = command('native-advisory-list', common+['--refresh', 'advisory', 'list', '--available', '--security', '--json'], ordinary=True)
    selected_rows = json.loads(selected.stdout)
    _require(len(selected_rows)==1 and all(selected_rows[0][key]==value for key,value in {'name':'OMG-QEMU-FEDORA-616','type':'security','severity':'Important','nevra':new_nevra}.items()), selected_rows)
    command('native-advisory-info', common+['--cacheonly', 'advisory', 'info', '--available', '--security', '--json'], ordinary=True)
    command('native-repository', common+['--cacheonly', 'repo', 'info', '--enabled', '--json'], ordinary=True)
    # Keep all product scans under an ordinary package-selection exclusion.
    # The native control must demonstrate that it hides an installed advisory;
    # security scans must override this without changing installed packages.
    configuration.set('main', 'excludepkgs', 'glibc*')
    with isolated_config.open('w') as stream: configuration.write(stream)
    (logs/'excluded-dnf.conf').write_bytes(isolated_config.read_bytes())
    hidden = command('native-excluded-default-list', common+['--cacheonly', 'advisory', 'list', '--available', '--security', '--json'], ordinary=True)
    _require(json.loads(hidden.stdout) == [], 'native package exclusion did not hide the installed advisory control')
    for operation in ('list', 'info'):
        restored = command('native-excluded-override-'+operation, common+['--setopt=disable_excludes=*', '--cacheonly', 'advisory', operation, '--available', '--security', '--json'], ordinary=True)
        original = json.loads((logs/('native-advisory-'+operation+'.stdout')).read_text())
        _require(json.loads(restored.stdout) == original, 'native exclusion override changed installed advisory applicability')
    _require(state()==before, 'native Fedora advisory fixture check failed')
    receipt = {'schema_version':1, 'scope':'native signed metadata-only advisory lifecycle; no package upgrade/download claim', 'source_sha':os.environ.get('OMG_CONTRACT_SOURCE_SHA'), 'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'fixture_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(), 'native_archive_sha256':args.archive_sha256, 'omg_sha256':hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest(), 'omgd_sha256':hashlib.sha256(pathlib.Path(daemon_binary).read_bytes()).hexdigest(), 'ordinary_user_uid':uid, 'isolated_vm_mount_and_network':True, 'original_dnf_config_sha256':original_config, 'native_glibc_identity':identity, 'newer_advisory_nevra':new_nevra, 'native_rpm_comparison':comparison.stdout.strip(), 'fixture_id':'OMG-QEMU-FEDORA-616', 'expected_native_severity':'Important', 'key_fingerprint':fingerprint, 'native_state_before':before, 'product_results':{}, 'accepted':False}
    receipt['excluded_installed_advisory_scope'] = True
    (logs/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    daemon = None

    def product(label, argv, expected=0, environment=None):
        result = subprocess.run([binary]+argv, env=env if environment is None else environment, user=uid, group=gid, extra_groups=[], capture_output=True, text=True, timeout=60)
        (logs/(label+'.stdout')).write_text(result.stdout); (logs/(label+'.stderr')).write_text(result.stderr)
        receipt['product_results'][label]={'argv':argv,'exit_code':result.returncode}
        _require(result.returncode==expected, (label,result.returncode,result.stderr[-1400:]))
        _require(state()==before, 'native Fedora advisory fixture check failed')
        return result

    try:
        repomd.write_bytes(original_repomd+b'\n<!-- invalidates exact detached signature -->\n')
        rejected = product('untrusted-metadata', ['audit','scan'], 1)
        _require('Failed to query native security advisories' in rejected.stderr and 'signature' in rejected.stderr.lower() and 'No vulnerabilities found' not in rejected.stdout, 'native Fedora advisory fixture check failed')
        repomd.write_bytes(original_repomd)
        for label, argv, code in [('direct-plain',['audit','scan'],0),('direct-findings',['audit','scan','--fail-on-findings'],1)]:
            verify_native_result(product(label,argv,code),code==1)
        daemon_env = dict(env); daemon_env.pop('OMG_DISABLE_DAEMON')
        with (logs/'daemon.log').open('wb') as output:
            daemon = subprocess.Popen([daemon_binary], env=daemon_env, user=uid, group=gid, extra_groups=[], stdout=output, stderr=subprocess.STDOUT)
            deadline=time.monotonic()+30
            while time.monotonic()<deadline:
                _require(daemon.poll() is None, 'daemon exited before readiness')
                if pathlib.Path(env['OMG_SOCKET_PATH']).exists(): break
                time.sleep(0.2)
            path=pathlib.Path(env['OMG_SOCKET_PATH']); _require(path.is_socket(), 'native Fedora advisory fixture check failed')
            metadata=path.stat(); _require(metadata.st_uid==uid and metadata.st_mode & 0o777==0o600, 'native Fedora advisory fixture check failed')
            def counter(label):
                result=product(label,['metrics'],environment=daemon_env)
                values=re.findall(r'^omg_security_audit_requests_total (\d+)$',result.stdout,re.M)
                _require(len(values)==1, 'native Fedora advisory fixture check failed')
                return int(values[0])
            initial=counter('daemon-before')
            for label,argv,code in [('daemon-plain',['audit','scan'],0),('daemon-findings',['audit','scan','--fail-on-findings'],1)]:
                verify_native_result(product(label,argv,code,daemon_env),code==1)
            receipt['daemon_requests_delta']=counter('daemon-after')-initial
            _require(receipt['daemon_requests_delta']==2, 'native Fedora advisory fixture check failed')
        receipt['native_state_after']=state(); receipt['native_state_unchanged']=receipt['native_state_after']==before
        receipt['accepted']=True
    finally:
        repomd.write_bytes(original_repomd)
        if daemon is not None and daemon.poll() is None:
            daemon.send_signal(signal.SIGINT)
            try:
                _require(daemon.wait(timeout=5) == 0, 'native audit daemon did not shut down successfully')
                _require(not pathlib.Path(env['OMG_SOCKET_PATH']).exists(), 'native audit daemon retained its socket')
                receipt['daemon_shutdown'] = True
            except subprocess.TimeoutExpired:
                daemon.kill(); daemon.wait(timeout=5); raise
        command('key-agent-cleanup',['gpgconf','--homedir',str(keydir),'--kill','gpg-agent'])
        (logs/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
        (logs/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({key:receipt[key] for key in ('accepted','boot_id','ordinary_user_uid','native_glibc_identity','daemon_requests_delta','native_state_unchanged')}),flush=True)


if __name__ == '__main__':
    main()
